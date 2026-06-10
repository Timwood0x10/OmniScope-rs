//! Unit tests for the reconcile module.
//!
//! Covers: `ResourceKey::from_candidate`, `FaultClass::of`,
//! `group_candidates`, `subsumes` matrix, and `reconcile_all_keep`.

use super::*;
use omniscope_core::issue::IssueLocation;
use omniscope_types::{FamilyId, VerifierVerdict};
use std::path::PathBuf;

// ── Helpers ──────────────────────────────────────────────────────────

/// Builds a minimal `IssueCandidate` with the given kind and `resource_id`.
fn make_candidate(id: u64, kind: IssueCandidateKind, resource_id: Option<u64>) -> IssueCandidate {
    let mut c = IssueCandidate::new(id, kind, FamilyId::custom("C_HEAP"), "malloc");
    c.resource_id = resource_id;
    c
}

/// Builds a candidate with alloc-site fields but no `resource_id`.
fn make_alloc_site_candidate(
    id: u64,
    kind: IssueCandidateKind,
    alloc_fn: &str,
    caller: Option<&str>,
    location: Option<(&str, u32)>,
) -> IssueCandidate {
    let mut c = IssueCandidate::new(id, kind, FamilyId::custom("C_HEAP"), alloc_fn);
    c.alloc_caller = caller.map(String::from);
    c.alloc_location = location.map(|(f, l)| IssueLocation::new(PathBuf::from(f), l));
    c
}

// ── ResourceKey::from_candidate ──────────────────────────────────────

/// Objective: Verify that a candidate with `resource_id` produces an
/// `Instance` key.
/// Invariants: `resource_id` is preferred over alloc-site fields.
#[test]
fn test_resource_key_prefers_instance() {
    let c = make_candidate(1, IssueCandidateKind::DefiniteLeak, Some(42));
    let key = ResourceKey::from_candidate(&c);
    assert_eq!(
        key,
        ResourceKey::Instance(42),
        "resource_id must produce Instance key"
    );
}

/// Objective: Verify that a candidate without `resource_id` falls back
/// to `AllocSite`.
/// Invariants: `alloc_caller` is used when present; `alloc_function` is
/// the fallback for the caller field.
#[test]
fn test_resource_key_falls_back_to_alloc_site() {
    let c = make_alloc_site_candidate(
        2,
        IssueCandidateKind::CrossFamilyFree,
        "malloc",
        Some("my_alloc"),
        Some(("test.c", 10)),
    );
    let key = ResourceKey::from_candidate(&c);
    match key {
        ResourceKey::AllocSite {
            caller,
            alloc_fn,
            location,
        } => {
            assert_eq!(caller, "my_alloc", "caller must match alloc_caller");
            assert_eq!(alloc_fn, "malloc", "alloc_fn must match alloc_function");
            assert_eq!(
                location,
                Some(("test.c".to_string(), 10u32)),
                "location must match alloc_location"
            );
        }
        ResourceKey::Instance(_) => panic!("expected AllocSite, got Instance"),
    }
}

/// Objective: When no `alloc_caller`, `alloc_function` is used as caller.
/// Invariants: The fallback chain always produces a valid key.
#[test]
fn test_resource_key_alloc_site_no_caller() {
    let c = make_alloc_site_candidate(3, IssueCandidateKind::DefiniteLeak, "calloc", None, None);
    let key = ResourceKey::from_candidate(&c);
    match key {
        ResourceKey::AllocSite {
            caller,
            alloc_fn,
            location,
        } => {
            assert_eq!(caller, "calloc", "caller falls back to alloc_function");
            assert_eq!(alloc_fn, "calloc");
            assert!(location.is_none(), "no alloc_location → None");
        }
        ResourceKey::Instance(_) => panic!("expected AllocSite, got Instance"),
    }
}

// ── FaultClass::of ───────────────────────────────────────────────────

/// Objective: Verify every `IssueCandidateKind` maps to the correct
/// `FaultClass` and that the mapping is exhaustive.
/// Invariants: Adding a new kind without updating `FaultClass::of` is
/// a compile error.
#[test]
fn test_fault_class_mapping_exhaustive() {
    use FaultClass::*;
    // WrongRelease
    for kind in [
        IssueCandidateKind::CrossFamilyFree,
        IssueCandidateKind::CrossLanguageFree,
        IssueCandidateKind::InvalidBorrowedFree,
    ] {
        assert_eq!(
            FaultClass::of(kind),
            WrongRelease,
            "{kind:?} must map to WrongRelease"
        );
    }
    // DoubleRelease
    for kind in [
        IssueCandidateKind::DoubleRelease,
        IssueCandidateKind::DoubleReclaim,
    ] {
        assert_eq!(
            FaultClass::of(kind),
            DoubleRelease,
            "{kind:?} must map to DoubleRelease"
        );
    }
    // UseAfterRelease (split from DoubleRelease/BoundaryMisuse)
    for kind in [
        IssueCandidateKind::UseAfterFree,
        IssueCandidateKind::UseAfterRelease,
        IssueCandidateKind::CallbackEscape,
    ] {
        assert_eq!(
            FaultClass::of(kind),
            UseAfterRelease,
            "{kind:?} must map to UseAfterRelease"
        );
    }
    // Leak
    for kind in [
        IssueCandidateKind::ConditionalLeak,
        IssueCandidateKind::DefiniteLeak,
        IssueCandidateKind::OwnershipEscapeLeak,
    ] {
        assert_eq!(FaultClass::of(kind), Leak, "{kind:?} must map to Leak");
    }
    // BoundaryMisuse (excluding CallbackEscape which is now UseAfterRelease)
    for kind in [
        IssueCandidateKind::UncheckedFfiReturn,
        IssueCandidateKind::NullDereference,
        IssueCandidateKind::BorrowEscape,
    ] {
        assert_eq!(
            FaultClass::of(kind),
            BoundaryMisuse,
            "{kind:?} must map to BoundaryMisuse"
        );
    }
    // Unmodeled
    assert_eq!(
        FaultClass::of(IssueCandidateKind::NeedsModel),
        Unmodeled,
        "NeedsModel must map to Unmodeled"
    );
}

// ── group_candidates ─────────────────────────────────────────────────

/// Objective: Candidates with the same `resource_id` end up in one group.
/// Invariants: Group key is `Instance(rid)`, both candidates appear in
/// `members`.
#[test]
fn test_group_same_resource_id() {
    let c1 = make_candidate(1, IssueCandidateKind::CrossFamilyFree, Some(100));
    let c2 = make_candidate(2, IssueCandidateKind::ConditionalLeak, Some(100));
    let groups = group_candidates(&[c1, c2]);
    assert_eq!(groups.len(), 1, "same resource_id → one group");
    assert_eq!(
        groups[0].members,
        vec![0, 1],
        "both candidates in the group"
    );
    assert_eq!(groups[0].key, ResourceKey::Instance(100));
}

/// Objective: Candidates with different `resource_id`s form separate groups.
/// Invariants: Each group has exactly one member.
#[test]
fn test_group_different_resource_ids() {
    let c1 = make_candidate(1, IssueCandidateKind::DefiniteLeak, Some(10));
    let c2 = make_candidate(2, IssueCandidateKind::DefiniteLeak, Some(20));
    let groups = group_candidates(&[c1, c2]);
    assert_eq!(groups.len(), 2, "different resource_ids → two groups");
    assert_eq!(groups[0].members, vec![0]);
    assert_eq!(groups[1].members, vec![1]);
}

/// Objective: Candidates without `resource_id` are grouped by alloc site.
/// Invariants: Same alloc-site fields → same group.
#[test]
fn test_group_alloc_site_fallback() {
    let c1 = make_alloc_site_candidate(
        1,
        IssueCandidateKind::DefiniteLeak,
        "malloc",
        Some("main"),
        Some(("a.c", 1)),
    );
    let c2 = make_alloc_site_candidate(
        2,
        IssueCandidateKind::CrossFamilyFree,
        "malloc",
        Some("main"),
        Some(("a.c", 1)),
    );
    let groups = group_candidates(&[c1, c2]);
    assert_eq!(groups.len(), 1, "same alloc site → one group");
    assert_eq!(groups[0].members, vec![0, 1]);
}

/// Objective: Empty input produces no groups.
/// Invariants: No panic, empty vec.
#[test]
fn test_group_empty() {
    let groups: Vec<FindingGroup> = group_candidates(&[]);
    assert!(groups.is_empty(), "empty input → no groups");
}

/// Objective: Mixed Instance and AllocSite keys are correctly separated.
/// Invariants: Instance-keyed and AllocSite-keyed candidates never merge.
#[test]
fn test_group_mixed_keys() {
    let c1 = make_candidate(1, IssueCandidateKind::DefiniteLeak, Some(5));
    let c2 = make_alloc_site_candidate(
        2,
        IssueCandidateKind::CrossFamilyFree,
        "malloc",
        Some("main"),
        None,
    );
    let c3 = make_candidate(3, IssueCandidateKind::ConditionalLeak, Some(5));
    let groups = group_candidates(&[c1, c2, c3]);
    assert_eq!(
        groups.len(),
        2,
        "Instance(5) grouped together, AllocSite separate"
    );
    // First group: c1 and c3 share Instance(5)
    assert_eq!(groups[0].members, vec![0, 2]);
    // Second group: c2 alone with AllocSite
    assert_eq!(groups[1].members, vec![1]);
}

// ── subsumes matrix ──────────────────────────────────────────────────

/// Objective: Verify that the declared subsumption pairs are correct.
/// Invariants: Only the three declared (cause, symptom) pairs return true.
#[test]
fn test_subsumes_known_pairs() {
    use FaultClass::*;
    // Declared pairs
    assert!(subsumes(WrongRelease, Leak), "WrongRelease subsumes Leak");
    assert!(subsumes(DoubleRelease, Leak), "DoubleRelease subsumes Leak");
    assert!(
        subsumes(BoundaryMisuse, Leak),
        "BoundaryMisuse subsumes Leak"
    );
    // Non-subsumption pairs (selected)
    assert!(
        !subsumes(WrongRelease, DoubleRelease),
        "WrongRelease does NOT subsume DoubleRelease"
    );
    assert!(
        !subsumes(DoubleRelease, WrongRelease),
        "DoubleRelease does NOT subsume WrongRelease"
    );
    assert!(
        !subsumes(Leak, WrongRelease),
        "Leak does NOT subsume WrongRelease"
    );
    assert!(
        !subsumes(Unmodeled, Leak),
        "Unmodeled does NOT subsume Leak"
    );
}

// ── reconcile_all_keep ───────────────────────────────────────────────

/// Objective: Verify that `reconcile_all_keep` produces Keep for every
/// candidate.
/// Invariants: Length matches input; every action is `Keep`.
#[test]
fn test_reconcile_all_keep() {
    let actions = reconcile_all_keep(3);
    assert_eq!(actions.len(), 3, "must produce one action per candidate");
    for (i, action) in actions.iter().enumerate() {
        assert_eq!(*action, ReconcileAction::Keep, "action[{i}] must be Keep");
    }
}

// ── reconcile_candidates (end-to-end) ────────────────────────────────

/// Objective: WrongRelease + Leak on same resource → Leak is SubsumedBy.
/// Invariants: CrossFamilyFree (WrongRelease) is Keep;
/// ConditionalLeak (Leak) is SubsumedBy { class: WrongRelease, by_idx: 0 }.
#[test]
fn test_reconcile_wrong_release_subsumes_leak() {
    let c1 = make_candidate(1, IssueCandidateKind::CrossFamilyFree, Some(100));
    let c2 = make_candidate(2, IssueCandidateKind::ConditionalLeak, Some(100));
    let actions = reconcile_candidates(&[c1, c2], None);
    assert_eq!(
        actions[0],
        ReconcileAction::Keep,
        "CrossFamilyFree (cause) must be Keep"
    );
    match &actions[1] {
        ReconcileAction::SubsumedBy { class, by_idx } => {
            assert_eq!(*class, FaultClass::WrongRelease, "subsumed by WrongRelease");
            assert_eq!(*by_idx, 0, "subsumed by candidate at index 0");
        }
        other => panic!("expected SubsumedBy, got {other:?}"),
    }
}

/// Objective: DoubleRelease + Leak on same resource → Leak is SubsumedBy.
/// Invariants: DoubleRelease is Keep; Leak is SubsumedBy.
#[test]
fn test_reconcile_double_release_subsumes_leak() {
    let c1 = make_candidate(1, IssueCandidateKind::DoubleRelease, Some(50));
    let c2 = make_candidate(2, IssueCandidateKind::DefiniteLeak, Some(50));
    let actions = reconcile_candidates(&[c1, c2], None);
    assert_eq!(
        actions[0],
        ReconcileAction::Keep,
        "DoubleRelease must be Keep"
    );
    match &actions[1] {
        ReconcileAction::SubsumedBy { class, .. } => {
            assert_eq!(
                *class,
                FaultClass::DoubleRelease,
                "subsumed by DoubleRelease"
            );
        }
        other => panic!("expected SubsumedBy, got {other:?}"),
    }
}

/// Objective: WrongRelease + DoubleRelease on same resource → both Keep.
/// Invariants: Neither subsumes the other (they may be two real bugs).
#[test]
fn test_reconcile_wrong_release_and_double_release_both_keep() {
    let c1 = make_candidate(1, IssueCandidateKind::CrossFamilyFree, Some(100));
    let c2 = make_candidate(2, IssueCandidateKind::DoubleRelease, Some(100));
    let actions = reconcile_candidates(&[c1, c2], None);
    assert_eq!(
        actions[0],
        ReconcileAction::Keep,
        "WrongRelease must be Keep"
    );
    assert_eq!(
        actions[1],
        ReconcileAction::Keep,
        "DoubleRelease must be Keep"
    );
}

/// Objective: Two candidates of same FaultClass on same resource → dedup.
/// Invariants: When both have equal confidence (no verdict), the first
/// candidate seen is kept as the canonical representative; later ones are
/// marked DuplicateOf.
#[test]
fn test_reconcile_same_class_dedup() {
    let c1 = make_candidate(1, IssueCandidateKind::ConditionalLeak, Some(100));
    let c2 = make_candidate(2, IssueCandidateKind::DefiniteLeak, Some(100));
    let actions = reconcile_candidates(&[c1, c2], None);
    assert_eq!(
        actions[0],
        ReconcileAction::Keep,
        "first Leak candidate is Keep"
    );
    match &actions[1] {
        ReconcileAction::DuplicateOf(kept_idx) => {
            assert_eq!(*kept_idx, 0, "second Leak is duplicate of index 0");
        }
        other => panic!("expected DuplicateOf, got {other:?}"),
    }
}

/// Objective: Independent resources → no reconciliation.
/// Invariants: Both candidates are Keep.
#[test]
fn test_reconcile_independent_resources() {
    let c1 = make_candidate(1, IssueCandidateKind::CrossFamilyFree, Some(10));
    let c2 = make_candidate(2, IssueCandidateKind::ConditionalLeak, Some(20));
    let actions = reconcile_candidates(&[c1, c2], None);
    assert_eq!(
        actions[0],
        ReconcileAction::Keep,
        "independent resource 1 is Keep"
    );
    assert_eq!(
        actions[1],
        ReconcileAction::Keep,
        "independent resource 2 is Keep"
    );
}

/// Objective: BoundaryMisuse + Leak on same resource → Leak is SubsumedBy.
/// Invariants: UncheckedFfiReturn (BoundaryMisuse) is Keep;
/// DefiniteLeak (Leak) is SubsumedBy.
#[test]
fn test_reconcile_boundary_misuse_subsumes_leak() {
    let c1 = make_candidate(1, IssueCandidateKind::UncheckedFfiReturn, Some(200));
    let c2 = make_candidate(2, IssueCandidateKind::DefiniteLeak, Some(200));
    let actions = reconcile_candidates(&[c1, c2], None);
    assert_eq!(actions[0], ReconcileAction::Keep, "BoundaryMisuse is Keep");
    match &actions[1] {
        ReconcileAction::SubsumedBy { class, .. } => {
            assert_eq!(
                *class,
                FaultClass::BoundaryMisuse,
                "subsumed by BoundaryMisuse"
            );
        }
        other => panic!("expected SubsumedBy, got {other:?}"),
    }
}

// ── Verdict-aware reconciliation (regression: non-reportable cause) ──

/// Objective: A non-reportable cause (ExplainedSafe) MUST NOT subsume a
/// reportable symptom on the same resource.
/// Invariants:
///   - Candidate 0 (CrossFamilyFree/WrongRelease) has `ExplainedSafe` → not reportable
///   - Candidate 1 (ConditionalLeak/Leak) has `ConfirmedIssue` → reportable
///   - Candidate 1 is **Keep** (NOT SubsumedBy), because the cause isn't reportable
///   - Candidate 0 is also Keep (but would be filtered at emit time)
#[test]
fn test_reconcile_non_reportable_cause_does_not_subsume() {
    let mut c0 = make_candidate(0, IssueCandidateKind::CrossFamilyFree, Some(100));
    c0.verdict = Some(VerifierVerdict::ExplainedSafe);
    let mut c1 = make_candidate(1, IssueCandidateKind::ConditionalLeak, Some(100));
    c1.verdict = Some(VerifierVerdict::ConfirmedIssue);

    // Only index 1 is reportable; index 0 (ExplainedSafe) must not subsume it.
    let reportable: std::collections::HashSet<usize> = std::collections::HashSet::from([1]);
    let actions = reconcile_candidates(&[c0, c1], Some(&reportable));
    assert_eq!(
        actions[0],
        ReconcileAction::Keep,
        "non-reportable cause (ExplainedSafe CrossFamilyFree) must be Keep"
    );
    assert_eq!(
        actions[1],
        ReconcileAction::Keep,
        "reportable symptom (ConfirmedIssue ConditionalLeak) must NOT be subsumed by non-reportable cause"
    );
}

/// Objective: When BOTH candidates are reportable, normal subsumption applies.
/// Invariants:
///   - Both candidates have `ConfirmedIssue` → both reportable
///   - CrossFamilyFree (WrongRelease) DOES subsume ConditionalLeak (Leak)
#[test]
fn test_reconcile_both_reportable_normal_subsumption() {
    let mut c0 = make_candidate(0, IssueCandidateKind::CrossFamilyFree, Some(100));
    c0.verdict = Some(VerifierVerdict::ConfirmedIssue);
    let mut c1 = make_candidate(1, IssueCandidateKind::ConditionalLeak, Some(100));
    c1.verdict = Some(VerifierVerdict::ConfirmedIssue);

    // Both indices are reportable → normal subsumption applies.
    let reportable: std::collections::HashSet<usize> = std::collections::HashSet::from([0, 1]);
    let actions = reconcile_candidates(&[c0, c1], Some(&reportable));
    assert_eq!(
        actions[0],
        ReconcileAction::Keep,
        "reportable cause (CrossFamilyFree) must be Keep"
    );
    match &actions[1] {
        ReconcileAction::SubsumedBy { class, by_idx } => {
            assert_eq!(*class, FaultClass::WrongRelease, "subsumed by WrongRelease");
            assert_eq!(*by_idx, 0, "subsumed by candidate at index 0");
        }
        other => panic!("expected SubsumedBy when both are reportable, got {other:?}"),
    }
}

// ── UseAfterRelease subsumption ───────────────────────────────────────

/// Objective: UseAfterRelease (UAF) subsumes DoubleRelease on the same
/// resource — UAF is more specific and informative than "released twice".
/// Invariants:
///   - Candidate 0: UseAfterFree → UseAfterRelease class, Keep
///   - Candidate 1: DoubleRelease → DoubleRelease class, SubsumedBy UseAfterRelease
#[test]
fn test_reconcile_use_after_release_subsumes_double_release() {
    let mut c0 = make_candidate(0, IssueCandidateKind::UseAfterFree, Some(50));
    c0.verdict = Some(VerifierVerdict::ConfirmedIssue);
    let mut c1 = make_candidate(1, IssueCandidateKind::DoubleRelease, Some(50));
    c1.verdict = Some(VerifierVerdict::ConfirmedIssue);

    let reportable: std::collections::HashSet<usize> = std::collections::HashSet::from([0, 1]);
    let actions = reconcile_candidates(&[c0, c1], Some(&reportable));

    assert_eq!(
        actions[0],
        ReconcileAction::Keep,
        "UAF (cause) must be Keep"
    );
    match &actions[1] {
        ReconcileAction::SubsumedBy { class, .. } => {
            assert_eq!(
                *class,
                FaultClass::UseAfterRelease,
                "DoubleRelease must be subsumed by UseAfterRelease"
            );
        }
        other => panic!("expected SubsumedBy, got {other:?}"),
    }
}

// ── Same-alloc-function leak dedup (Rule 2b) ─────────────────────────

/// Objective: Two Leak candidates for the same resource AND same alloc
/// function are deduplicated — only one is kept.
/// Invariants:
///   - Two Leak candidates with same resource_id and default alloc_function ("malloc")
///   - Exactly one Keep, one DuplicateOf
#[test]
fn test_reconcile_same_alloc_leak_dedup() {
    let c1 = make_candidate(1, IssueCandidateKind::ConditionalLeak, Some(100));
    let c2 = make_candidate(2, IssueCandidateKind::DefiniteLeak, Some(100));
    // Both use "malloc" as alloc_function from make_candidate

    let actions = reconcile_candidates(&[c1, c2], None);

    let keep_count = actions
        .iter()
        .filter(|a| **a == ReconcileAction::Keep)
        .count();
    let dup_count = actions
        .iter()
        .filter(|a| matches!(a, ReconcileAction::DuplicateOf(_)))
        .count();
    assert_eq!(
        keep_count, 1,
        "only one leak kept for same resource + same alloc function"
    );
    assert_eq!(
        dup_count, 1,
        "one leak marked as DuplicateOf for same alloc function dedup"
    );
}
