//! Candidate reconciliation layer for cross-candidate grouping and arbitration.
//!
//! The verifier main loop processes candidates independently: each candidate
//! gets its own verdict and is emitted on its own. This module introduces a
//! **reconciliation stage** that groups candidates by resource identity and
//! arbitrates between them using orthogonal fault classes.
//!
//! # Three pillars
//!
//! 1. **ResourceKey** — resource identity, basis for cross-candidate grouping.
//! 2. **FaultClass** — orthogonal classification axis, unit of arbitration.
//! 3. **subsumes matrix** — declarative "who subsumes whom" table.
//!
//! # Design principle
//!
//! All arbitration rules live at the `FaultClass` level. Adding a new
//! `IssueCandidateKind` only requires one line in `FaultClass::of`; the
//! `subsumes` matrix and `reconcile_group` logic stay untouched.

use omniscope_core::IssueCandidate;
use omniscope_types::{IssueCandidateKind, VerifierVerdict};
use std::collections::{HashMap, HashSet};

// ── Pillar 1: Resource identity ──────────────────────────────────────

/// Resource identity key — the basis for cross-candidate grouping.
///
/// Generic: depends only on a resource instance or allocation site,
/// never on any language/family special case.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) enum ResourceKey {
    /// Preferred: MemoryGraph resource instance ID (most precise).
    Instance(u64),
    /// Fallback: allocation-site identity (caller, alloc_fn, location).
    /// Used when a candidate has no `resource_id`, so grouping always works.
    AllocSite {
        caller: String,
        alloc_fn: String,
        location: Option<(String, u32)>,
    },
}

impl ResourceKey {
    /// Generic extraction: every `IssueCandidate` maps to a key.
    ///
    /// `resource_id` first (most precise), otherwise alloc-site fallback.
    pub(crate) fn from_candidate(c: &IssueCandidate) -> ResourceKey {
        if let Some(rid) = c.resource_id {
            ResourceKey::Instance(rid)
        } else {
            ResourceKey::AllocSite {
                caller: c
                    .alloc_caller
                    .clone()
                    .unwrap_or_else(|| c.alloc_function.clone()),
                alloc_fn: c.alloc_function.clone(),
                location: c
                    .alloc_location
                    .as_ref()
                    .map(|loc| (loc.file.to_string_lossy().into_owned(), loc.line)),
            }
        }
    }
}

// ── Pillar 2: Fault classification axis ──────────────────────────────

/// Orthogonal fault classes — the real unit of arbitration.
///
/// This is the core of genericity: rules are defined between `FaultClass`
/// values, and a kind is merely a member of a `FaultClass`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum FaultClass {
    /// Release operation itself is wrong.
    /// → CrossFamilyFree, CrossLanguageFree, InvalidBorrowedFree
    WrongRelease,
    /// Released twice (or use after release).
    /// → DoubleRelease, DoubleReclaim, UseAfterFree, UseAfterRelease
    DoubleRelease,
    /// Not released.
    /// → ConditionalLeak, DefiniteLeak, OwnershipEscapeLeak
    Leak,
    /// Boundary / null misuse.
    /// → UncheckedFfiReturn, NullDereference, BorrowEscape, CallbackEscape
    BoundaryMisuse,
    /// Needs a model annotation — unknown family or cleanup.
    /// → NeedsModel
    Unmodeled,
}

impl FaultClass {
    /// Single mapping point. Adding an `IssueCandidateKind` only edits here.
    pub(crate) fn of(kind: IssueCandidateKind) -> FaultClass {
        match kind {
            // WrongRelease family
            IssueCandidateKind::CrossFamilyFree
            | IssueCandidateKind::CrossLanguageFree
            | IssueCandidateKind::InvalidBorrowedFree => FaultClass::WrongRelease,
            // DoubleRelease family
            IssueCandidateKind::DoubleRelease
            | IssueCandidateKind::DoubleReclaim
            | IssueCandidateKind::UseAfterFree
            | IssueCandidateKind::UseAfterRelease => FaultClass::DoubleRelease,
            // Leak family
            IssueCandidateKind::ConditionalLeak
            | IssueCandidateKind::DefiniteLeak
            | IssueCandidateKind::OwnershipEscapeLeak => FaultClass::Leak,
            // BoundaryMisuse family
            IssueCandidateKind::UncheckedFfiReturn
            | IssueCandidateKind::NullDereference
            | IssueCandidateKind::BorrowEscape
            | IssueCandidateKind::CallbackEscape => FaultClass::BoundaryMisuse,
            // Unmodeled
            IssueCandidateKind::NeedsModel => FaultClass::Unmodeled,
        }
    }
}

// ── Grouping ─────────────────────────────────────────────────────────

/// Candidates under the same `ResourceKey`.
pub(crate) struct FindingGroup {
    /// Shared resource identity for this group (auditable).
    #[allow(dead_code)]
    pub key: ResourceKey,
    /// Indices into the source candidates array (zero-copy reference).
    pub members: Vec<usize>,
}

// ── Pillar 3: Arbitration ────────────────────────────────────────────

/// Arbitration decision: tag each candidate rather than delete it
/// (preserve auditability).
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum ReconcileAction {
    /// Emit the candidate as-is.
    Keep,
    /// Suppressed by a root-cause candidate on the same resource.
    SubsumedBy { class: FaultClass, by_idx: usize },
    /// Same-class dedup: another candidate in the same group is kept instead.
    DuplicateOf(usize),
}

/// Declarative subsumption matrix.
///
/// Returns `true` when the `cause` fault class should subsume the `symptom`
/// fault class on the same resource. This is the only "business rule", and
/// it is a 5×5 class-level matrix independent of concrete kinds / projects.
pub(crate) fn subsumes(cause: FaultClass, symptom: FaultClass) -> bool {
    use FaultClass::*;
    matches!(
        (cause, symptom),
        // A wrong release hides the legitimate release from the leak
        // detector → the leak is its symptom.
        (WrongRelease, Leak)
        // Double release similarly: on the second-release path the resource
        // has "disappeared", easily misjudged as a leak.
        | (DoubleRelease, Leak)
        // A boundary null-deref makes later paths unreachable; the leak
        // is noise.
        | (BoundaryMisuse, Leak)
    )
    // Note: WrongRelease and DoubleRelease do NOT subsume each other
    //       (they may be two real bugs).
    //       Same-class collisions are handled by dedup, not here.
}

// ── Grouping function ────────────────────────────────────────────────

/// Groups candidates by `ResourceKey`, preserving order within each group.
///
/// Candidates sharing the same resource identity (instance ID or alloc
/// site) end up in the same `FindingGroup`. The group order follows the
/// first appearance of each key in the input array.
pub(crate) fn group_candidates(candidates: &[IssueCandidate]) -> Vec<FindingGroup> {
    let mut key_to_group_idx: HashMap<ResourceKey, usize> = HashMap::new();
    let mut groups: Vec<FindingGroup> = Vec::new();

    for (idx, candidate) in candidates.iter().enumerate() {
        let key = ResourceKey::from_candidate(candidate);
        match key_to_group_idx.get(&key) {
            Some(&group_idx) => {
                groups[group_idx].members.push(idx);
            }
            None => {
                let group_idx = groups.len();
                key_to_group_idx.insert(key.clone(), group_idx);
                groups.push(FindingGroup {
                    key,
                    members: vec![idx],
                });
            }
        }
    }

    groups
}

// ── Reconciliation engine ────────────────────────────────────────────

/// Runs cross-candidate reconciliation on all verified candidates.
///
/// 1. Groups candidates by `ResourceKey`.
/// 2. Within each group, applies the `subsumes` matrix and same-class dedup.
/// 3. Returns a `ReconcileAction` per candidate (indexed by original position).
///
/// Candidates not in any multi-member group are always `Keep`.
///
/// # Reportability gate
///
/// The `reportable_set` parameter controls which candidates are allowed to
/// **subsume** others. Only candidates that will actually be emitted (i.e.
/// are in the reportable set) may suppress symptoms via subsumption.
/// When `None`, every candidate is considered reportable — this is the
/// default for unit tests that don't model verdicts, and preserves
/// backward compatibility.
///
/// This gate prevents a TP→FN regression where a non-reportable cause
/// (e.g. `ExplainedSafe` `CrossFamilyFree`) would subsume a reportable
/// symptom (e.g. `ConfirmedIssue` `ConditionalLeak`): the cause itself
/// won't be emitted *and* it suppresses the symptom that would have been.
pub(crate) fn reconcile_candidates(
    candidates: &[IssueCandidate],
    reportable_set: Option<&HashSet<usize>>,
) -> Vec<ReconcileAction> {
    let groups = group_candidates(candidates);
    let mut actions = vec![ReconcileAction::Keep; candidates.len()];

    for group in &groups {
        if group.members.len() < 2 {
            // Singleton group — no arbitration needed.
            continue;
        }
        reconcile_group(candidates, &group.members, &mut actions, reportable_set);
    }

    actions
}

/// Returns a numeric confidence rank for a candidate's verdict.
///
/// Higher value = more confident. Used by same-class dedup to pick
/// the best candidate when multiple share a FaultClass.
fn verdict_confidence(candidate: &IssueCandidate) -> u8 {
    match &candidate.verdict {
        Some(VerifierVerdict::ConfirmedIssue) => 4,
        Some(VerifierVerdict::ProbableIssue) => 3,
        Some(VerifierVerdict::Diagnostic) => 2,
        Some(VerifierVerdict::ExplainedSafe) => 1,
        None => 0,
    }
}

/// Arbitrates within a single group of candidates sharing the same resource.
///
/// Two rules:
/// 1. **Subsumption**: if a `cause` FaultClass subsumes a `symptom`
///    FaultClass on the same resource, the symptom is tagged `SubsumedBy`.
/// 2. **Dedup**: multiple candidates of the same FaultClass → keep the
///    one with highest confidence, tag the rest `DuplicateOf`.
fn reconcile_group(
    candidates: &[IssueCandidate],
    members: &[usize],
    actions: &mut [ReconcileAction],
    reportable_set: Option<&HashSet<usize>>,
) {
    // ── Rule 1: subsumption ──
    // Collect the FaultClass for each member.
    let classes: Vec<FaultClass> = members
        .iter()
        .map(|&idx| FaultClass::of(candidates[idx].kind))
        .collect();

    // For each member, check if any other member subsumes it.
    for (i, &member_idx) in members.iter().enumerate() {
        let symptom_class = classes[i];
        // Search for a cause that subsumes this symptom.
        for (j, &cause_idx) in members.iter().enumerate() {
            if i == j {
                continue;
            }
            let cause_class = classes[j];
            // Reportability gate: only candidates that will actually be emitted
            // may subsume (suppress) others. A non-reportable cause (e.g.
            // ExplainedSafe CrossFamilyFree) must not suppress a reportable
            // symptom (e.g. ConfirmedIssue ConditionalLeak), because that would
            // cause a TP→FN regression — neither candidate gets emitted.
            if subsumes(cause_class, symptom_class)
                && reportable_set.map_or(true, |s| s.contains(&cause_idx))
            {
                actions[member_idx] = ReconcileAction::SubsumedBy {
                    class: cause_class,
                    by_idx: cause_idx,
                };
                break; // first cause wins; no double-tagging
            }
        }
    }

    // ── Rule 2: same-class dedup (keep highest confidence) ──
    // Among members that are still Keep, if multiple share the same FaultClass,
    // keep the one with the highest verdict-based confidence and mark rest DuplicateOf.
    let mut class_members: HashMap<FaultClass, Vec<usize>> = HashMap::new();
    for (i, &member_idx) in members.iter().enumerate() {
        if !matches!(actions[member_idx], ReconcileAction::Keep) {
            continue;
        }
        let class = classes[i];
        class_members.entry(class).or_default().push(member_idx);
    }

    for (_class, indices) in class_members {
        if indices.len() < 2 {
            continue;
        }
        // Find index with highest confidence (verdict-based).
        // Tiebreak: lower index wins (stable — preserves first-seen order).
        let &best_idx = indices
            .iter()
            .max_by(|&&a, &&b| {
                verdict_confidence(&candidates[a])
                    .cmp(&verdict_confidence(&candidates[b]))
                    .then_with(|| b.cmp(&a)) // lower index wins on tie
            })
            .expect("non-empty");

        for &idx in &indices {
            if idx != best_idx {
                actions[idx] = ReconcileAction::DuplicateOf(best_idx);
            }
        }
    }
}

// ── Phase A: default reconcile (all Keep, zero behavior change) ──────

/// Produces a `ReconcileAction::Keep` for every candidate.
///
/// Retained for testing; production code uses `reconcile_candidates`.
#[allow(dead_code)]
pub(crate) fn reconcile_all_keep(len: usize) -> Vec<ReconcileAction> {
    vec![ReconcileAction::Keep; len]
}

#[cfg(test)]
mod tests;
