//! Verifier-side evidence fusion for resource issue candidates.
//!
//! The bundle is intentionally read-only: it joins facts already produced by
//! earlier passes so the verifier can make decisions from one compact view.

use std::collections::HashMap;

use omniscope_core::IssueCandidate;
use omniscope_semantics::resource::memory_graph::{MemoryGraph, ResourceState};
use omniscope_semantics::{FactConfidence, SemanticFact, SemanticKind};
use omniscope_types::{is_boundary_evidence, EvidenceKind, FamilyId, PathEvidence};

/// Joined evidence for one resource issue candidate.
///
/// This type keeps verifier inputs close together without taking ownership of
/// large graphs. It should remain internal until output or auditing needs a
/// stable public representation.
#[derive(Debug, Clone)]
pub(crate) struct EvidenceBundle {
    pub candidate_id: u64,
    pub resource_id: Option<u64>,
    pub alloc_family: FamilyId,
    pub release_family: Option<FamilyId>,
    #[allow(dead_code)] // diagnostic: used in tests and debug output
    pub alloc_function: String,
    #[allow(dead_code)] // diagnostic: used in tests and debug output
    pub release_function: Option<String>,
    pub alloc_caller: Option<String>,
    pub release_caller: Option<String>,
    #[allow(dead_code)] // diagnostic: used in tests, may be read by future path-sensitive checks
    pub memory_state: Option<ResourceState>,
    pub semantic_kinds: Vec<SemanticKind>,
    /// Semantic facts with full provenance (source, confidence, evidence).
    /// Populated from `srt_facts` when available; empty otherwise.
    pub semantic_facts: Vec<SemanticFact>,
    pub evidence_kinds: Vec<EvidenceKind>,
    pub has_boundary_evidence: bool,
    pub has_same_resource_evidence: bool,
    pub has_reachable_release: bool,
    pub has_alias_rejection: bool,
    #[allow(dead_code)] // reserved for future path-sensitive analysis
    pub path_evidence: Option<PathEvidence>,
}

impl EvidenceBundle {
    /// Builds a bundle from a candidate and optional analysis state.
    ///
    /// # Arguments
    /// * `candidate` - The unverified issue candidate.
    /// * `memory_graph` - Optional graph used to resolve resource state.
    /// * `srt_resolutions` - Optional semantic facts keyed by symbol or resource.
    /// * `srt_facts` - Optional semantic facts with full provenance (source,
    ///   confidence, evidence), keyed by symbol or resource. Falls back to
    ///   `srt_resolutions` if absent.
    ///
    /// # Returns
    /// A compact evidence bundle. Missing graph or semantic entries are treated
    /// as absent evidence rather than errors.
    pub(crate) fn from_candidate(
        candidate: &IssueCandidate,
        memory_graph: Option<&MemoryGraph>,
        srt_resolutions: Option<&HashMap<String, Vec<SemanticKind>>>,
        srt_facts: Option<&HashMap<String, Vec<SemanticFact>>>,
    ) -> Self {
        let memory_state = candidate
            .resource_id
            .and_then(|id| memory_graph.and_then(|graph| graph.get_state(id)));
        let evidence_kinds = candidate
            .evidence
            .iter()
            .map(|evidence| evidence.kind.clone())
            .collect::<Vec<_>>();
        let semantic_kinds = collect_semantic_kinds(candidate, srt_resolutions);
        let semantic_facts = collect_semantic_facts(candidate, srt_facts);

        Self {
            candidate_id: candidate.id,
            resource_id: candidate.resource_id,
            alloc_family: candidate.alloc_family,
            release_family: candidate.release_family,
            alloc_function: candidate.alloc_function.clone(),
            release_function: candidate.release_function.clone(),
            alloc_caller: candidate.alloc_caller.clone(),
            release_caller: candidate.release_caller.clone(),
            memory_state,
            semantic_kinds,
            semantic_facts,
            has_boundary_evidence: has_boundary_evidence(candidate, &evidence_kinds),
            has_same_resource_evidence: has_same_resource_evidence(candidate, &evidence_kinds),
            has_reachable_release: has_reachable_release(candidate, &evidence_kinds),
            has_alias_rejection: has_alias_rejection(candidate),
            evidence_kinds,
            path_evidence: None,
        }
    }

    /// Attaches path evidence to this bundle.
    #[allow(dead_code)] // reserved for future path-sensitive analysis
    pub(crate) fn with_path_evidence(mut self, pe: PathEvidence) -> Self {
        self.path_evidence = Some(pe);
        self
    }

    /// Returns true when semantic evidence explains safe ownership transfer.
    /// This is used for non-leak issue kinds (cross-family, double-free, etc.).
    /// Leak-specific kinds (GlobalProvenance, AbortOnOom, RefcountTransfer,
    /// StaticLifetimeSink) are NOT included — they only suppress leak candidates.
    pub(crate) fn has_semantic_suppression(&self) -> bool {
        self.semantic_kinds.iter().any(|kind| {
            matches!(
                kind,
                SemanticKind::RuntimeManagedResource
                    | SemanticKind::StoredToOwner
                    | SemanticKind::StoredToRuntime
                    | SemanticKind::EscapedToCaller
                    | SemanticKind::EscapedToOutParam
                    | SemanticKind::RaiiDropRelease
                    | SemanticKind::CppDestructor
                    | SemanticKind::DestructorRelease
            )
        })
    }

    /// Returns true when semantic or evidence facts indicate the resource
    /// is safe from a *leak* perspective — either ownership was transferred,
    /// the runtime manages it, or the resource has process lifetime.
    ///
    /// This is broader than `has_semantic_suppression` because leak-specific
    /// safe exits include `StaticLifetimeSink` (EvidenceKind) and
    /// `GlobalProvenance` (SemanticKind), which don't suppress other issue
    /// types (e.g. cross-family free) but do explain "not freed locally".
    pub(crate) fn has_leak_suppression(&self) -> bool {
        // Semantic kinds that suppress leak candidates.
        let has_safe_semantic = self.semantic_kinds.iter().any(|kind| {
            matches!(
                kind,
                SemanticKind::RuntimeManagedResource
                    | SemanticKind::StoredToOwner
                    | SemanticKind::StoredToRuntime
                    | SemanticKind::EscapedToCaller
                    | SemanticKind::EscapedToOutParam
                    | SemanticKind::RaiiDropRelease
                    | SemanticKind::CppDestructor
                    | SemanticKind::GlobalProvenance
                    | SemanticKind::AbortOnOom
                    | SemanticKind::RefcountTransfer
                    | SemanticKind::StaticLifetimeSink
                    | SemanticKind::DestructorRelease
            )
        });
        if has_safe_semantic {
            return true;
        }

        // Evidence kinds that suppress leak candidates.
        self.evidence_kinds.iter().any(|kind| {
            matches!(
                kind,
                EvidenceKind::ReturnToCaller
                    | EvidenceKind::OutParamInit
                    | EvidenceKind::OutParamOwnedOnSuccess
                    | EvidenceKind::OutParamNullOnError
                    | EvidenceKind::FieldStoreToOwner
                    | EvidenceKind::StaticLifetimeSink
            )
        })
    }

    /// Returns true when a high-confidence semantic fact of the given kind exists.
    ///
    /// Only facts with `FactConfidence::High` are considered. Use this for
    /// suppression decisions where we need strong evidence.
    pub(crate) fn has_high_confidence_kind(&self, kind: SemanticKind) -> bool {
        self.semantic_facts
            .iter()
            .any(|f| f.kind == kind && f.is_high_confidence())
    }

    /// Returns true when any semantic fact of the given kind exists at or
    /// above the specified confidence level.
    pub(crate) fn has_kind_at_confidence(
        &self,
        kind: SemanticKind,
        min_confidence: FactConfidence,
    ) -> bool {
        self.semantic_facts
            .iter()
            .any(|f| f.kind == kind && f.confidence.score() >= min_confidence.score())
    }

    /// Returns true when semantic evidence explains safe ownership transfer
    /// **with high confidence**.
    ///
    /// Unlike `has_semantic_suppression` (which treats any SemanticKind match
    /// as sufficient), this requires the suppressing fact to have high
    /// confidence. Medium-confidence facts can only *downgrade* (e.g.,
    /// ConfirmedIssue → ProbableIssue), not suppress entirely.
    /// Used for non-leak issue kinds (cross-family, double-free, etc.).
    pub(crate) fn has_semantic_suppression_high_confidence(&self) -> bool {
        let safe_kinds = [
            SemanticKind::RuntimeManagedResource,
            SemanticKind::StoredToOwner,
            SemanticKind::StoredToRuntime,
            SemanticKind::EscapedToCaller,
            SemanticKind::EscapedToOutParam,
            SemanticKind::RaiiDropRelease,
            SemanticKind::CppDestructor,
            SemanticKind::DestructorRelease,
        ];
        safe_kinds.iter().any(|k| self.has_high_confidence_kind(*k))
    }

    /// Returns true when semantic evidence explains safe ownership transfer
    /// with at least **medium** confidence.
    ///
    /// This is used for downgrading confirmed issues to probable, not for
    /// full suppression. Used for non-leak issue kinds.
    pub(crate) fn has_semantic_suppression_medium_confidence(&self) -> bool {
        let safe_kinds = [
            SemanticKind::RuntimeManagedResource,
            SemanticKind::StoredToOwner,
            SemanticKind::StoredToRuntime,
            SemanticKind::EscapedToCaller,
            SemanticKind::EscapedToOutParam,
            SemanticKind::RaiiDropRelease,
            SemanticKind::CppDestructor,
            SemanticKind::DestructorRelease,
        ];
        safe_kinds
            .iter()
            .any(|k| self.has_kind_at_confidence(*k, FactConfidence::Medium))
    }

    /// Returns true when a leak-specific high-confidence suppression applies.
    ///
    /// Like `has_leak_suppression` but requires high confidence for semantic
    /// kinds. Evidence kinds (ReturnToCaller, etc.) are always treated as
    /// high confidence since they come from direct IR observation.
    pub(crate) fn has_leak_suppression_high_confidence(&self) -> bool {
        // Semantic kinds that suppress leak candidates — require high confidence.
        let has_safe_semantic = self.semantic_facts.iter().any(|f| {
            matches!(
                f.kind,
                SemanticKind::RuntimeManagedResource
                    | SemanticKind::StoredToOwner
                    | SemanticKind::StoredToRuntime
                    | SemanticKind::EscapedToCaller
                    | SemanticKind::EscapedToOutParam
                    | SemanticKind::RaiiDropRelease
                    | SemanticKind::CppDestructor
                    | SemanticKind::GlobalProvenance
                    | SemanticKind::AbortOnOom
                    | SemanticKind::RefcountTransfer
                    | SemanticKind::StaticLifetimeSink
                    | SemanticKind::DestructorRelease
            ) && f.is_high_confidence()
        });
        if has_safe_semantic {
            return true;
        }

        // Evidence kinds that suppress leak candidates — always high confidence
        // (they come from direct IR observation, not inference).
        self.evidence_kinds.iter().any(|kind| {
            matches!(
                kind,
                EvidenceKind::ReturnToCaller
                    | EvidenceKind::OutParamInit
                    | EvidenceKind::OutParamOwnedOnSuccess
                    | EvidenceKind::OutParamNullOnError
                    | EvidenceKind::FieldStoreToOwner
                    | EvidenceKind::StaticLifetimeSink
            )
        })
    }

    /// Returns true when a leak-specific medium-confidence suppression applies
    /// (but not high-confidence — use `has_leak_suppression_high_confidence`
    /// for that).
    pub(crate) fn has_leak_suppression_medium_confidence(&self) -> bool {
        let has_safe_semantic = self.semantic_facts.iter().any(|f| {
            matches!(
                f.kind,
                SemanticKind::RuntimeManagedResource
                    | SemanticKind::StoredToOwner
                    | SemanticKind::StoredToRuntime
                    | SemanticKind::EscapedToCaller
                    | SemanticKind::EscapedToOutParam
                    | SemanticKind::RaiiDropRelease
                    | SemanticKind::CppDestructor
                    | SemanticKind::GlobalProvenance
                    | SemanticKind::AbortOnOom
                    | SemanticKind::RefcountTransfer
                    | SemanticKind::StaticLifetimeSink
                    | SemanticKind::DestructorRelease
            ) && f.confidence.score() >= FactConfidence::Medium.score()
        });
        has_safe_semantic
    }

    /// Returns a human-readable suppression reason string based on the
    /// semantic facts present in this bundle.
    ///
    /// Returns `None` if no suppressing semantic facts are found.
    /// The reason string includes the kind, confidence, and source of
    /// the first matching high-confidence suppression fact.
    pub(crate) fn suppression_reason(&self, is_leak: bool) -> Option<String> {
        let safe_kinds: &[SemanticKind] = if is_leak {
            &[
                SemanticKind::RuntimeManagedResource,
                SemanticKind::StoredToOwner,
                SemanticKind::StoredToRuntime,
                SemanticKind::EscapedToCaller,
                SemanticKind::EscapedToOutParam,
                SemanticKind::RaiiDropRelease,
                SemanticKind::CppDestructor,
                SemanticKind::GlobalProvenance,
                SemanticKind::AbortOnOom,
                SemanticKind::RefcountTransfer,
                SemanticKind::StaticLifetimeSink,
                SemanticKind::DestructorRelease,
            ]
        } else {
            &[
                SemanticKind::RuntimeManagedResource,
                SemanticKind::StoredToOwner,
                SemanticKind::StoredToRuntime,
                SemanticKind::EscapedToCaller,
                SemanticKind::EscapedToOutParam,
                SemanticKind::RaiiDropRelease,
                SemanticKind::CppDestructor,
                SemanticKind::DestructorRelease,
            ]
        };

        // Check semantic facts (with provenance) first.
        for fact in &self.semantic_facts {
            if safe_kinds.contains(&fact.kind) {
                return Some(format!(
                    "semantic suppression: {:?} (confidence={}, source={})",
                    fact.kind, fact.confidence, fact.source
                ));
            }
        }

        // Fall back to semantic kinds (no provenance, but still valid).
        for kind in &self.semantic_kinds {
            if safe_kinds.contains(kind) {
                return Some(format!(
                    "semantic suppression: {kind:?} (confidence=unknown)"
                ));
            }
        }

        // Check evidence kinds for leak suppression.
        if is_leak {
            let leak_evidence_kinds = [
                EvidenceKind::ReturnToCaller,
                EvidenceKind::OutParamInit,
                EvidenceKind::OutParamOwnedOnSuccess,
                EvidenceKind::OutParamNullOnError,
                EvidenceKind::FieldStoreToOwner,
                EvidenceKind::StaticLifetimeSink,
            ];
            for ek in &self.evidence_kinds {
                if leak_evidence_kinds.contains(ek) {
                    return Some(format!("evidence suppression: {ek:?}"));
                }
            }
        }

        None
    }
}

fn collect_semantic_kinds(
    candidate: &IssueCandidate,
    srt_resolutions: Option<&HashMap<String, Vec<SemanticKind>>>,
) -> Vec<SemanticKind> {
    let Some(resolutions) = srt_resolutions else {
        return Vec::new();
    };

    let mut keys = vec![candidate.alloc_function.as_str()];
    if let Some(release_function) = candidate.release_function.as_deref() {
        keys.push(release_function);
    }
    if let Some(alloc_caller) = candidate.alloc_caller.as_deref() {
        keys.push(alloc_caller);
    }
    if let Some(release_caller) = candidate.release_caller.as_deref() {
        keys.push(release_caller);
    }

    let mut kinds = Vec::new();
    for key in keys {
        if let Some(values) = resolutions.get(key) {
            extend_unique(&mut kinds, values);
        }
    }

    if let Some(resource_id) = candidate.resource_id {
        let resource_key = format!("resource:{resource_id}");
        if let Some(values) = resolutions.get(&resource_key) {
            extend_unique(&mut kinds, values);
        }
    }

    kinds
}

fn extend_unique(kinds: &mut Vec<SemanticKind>, values: &[SemanticKind]) {
    for value in values {
        if !kinds.contains(value) {
            kinds.push(*value);
        }
    }
}

/// Collects `SemanticFact` records for a candidate from the `srt_facts` index.
///
/// This preserves confidence and source information, unlike `collect_semantic_kinds`
/// which discards them. Falls back to an empty vec when `srt_facts` is absent.
fn collect_semantic_facts(
    candidate: &IssueCandidate,
    srt_facts: Option<&HashMap<String, Vec<SemanticFact>>>,
) -> Vec<SemanticFact> {
    let Some(facts_map) = srt_facts else {
        return Vec::new();
    };

    let mut keys = vec![candidate.alloc_function.as_str()];
    if let Some(release_function) = candidate.release_function.as_deref() {
        keys.push(release_function);
    }
    if let Some(alloc_caller) = candidate.alloc_caller.as_deref() {
        keys.push(alloc_caller);
    }
    if let Some(release_caller) = candidate.release_caller.as_deref() {
        keys.push(release_caller);
    }

    let mut facts = Vec::new();
    for key in keys {
        if let Some(values) = facts_map.get(key) {
            for fact in values {
                if !facts.iter().any(|f: &SemanticFact| f.kind == fact.kind) {
                    facts.push(fact.clone());
                }
            }
        }
    }

    if let Some(resource_id) = candidate.resource_id {
        let resource_key = format!("resource:{resource_id}");
        if let Some(values) = facts_map.get(&resource_key) {
            for fact in values {
                if !facts.iter().any(|f: &SemanticFact| f.kind == fact.kind) {
                    facts.push(fact.clone());
                }
            }
        }
    }

    facts
}

fn has_boundary_evidence(candidate: &IssueCandidate, evidence_kinds: &[EvidenceKind]) -> bool {
    candidate.boundary.is_some()
        || candidate.ffi_evidence.is_some()
        || evidence_kinds.iter().any(is_boundary_evidence)
}

fn has_same_resource_evidence(candidate: &IssueCandidate, evidence_kinds: &[EvidenceKind]) -> bool {
    candidate.resource_id.is_some()
        || evidence_kinds
            .iter()
            .any(|kind| matches!(kind, EvidenceKind::MultipleRelease))
}

fn has_reachable_release(candidate: &IssueCandidate, evidence_kinds: &[EvidenceKind]) -> bool {
    candidate.release_function.is_some()
        || evidence_kinds.iter().any(|kind| {
            matches!(
                kind,
                EvidenceKind::SameFamilyRelease
                    | EvidenceKind::CrossFamilyMismatch
                    | EvidenceKind::MultipleRelease
                    | EvidenceKind::PathStateRefinement
            )
        })
}

fn has_alias_rejection(candidate: &IssueCandidate) -> bool {
    candidate.evidence.iter().any(|evidence| {
        evidence.kind == EvidenceKind::Insufficient
            && evidence.description.starts_with("may_alias=NotAlias")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_core::FfiEvidence;
    use omniscope_semantics::resource::memory_graph::{MemoryGraph, MemoryNode, ResourceClass};
    use omniscope_types::{Evidence, IssueCandidateKind};

    /// Objective: Verify resource state is pulled from `MemoryGraph`.
    /// Invariants: Bundle state matches the graph node for the candidate id.
    #[test]
    fn bundle_resolves_memory_state_for_resource_id() {
        let mut graph = MemoryGraph::new();
        graph.add_node(MemoryNode {
            id: 7,
            resource_class: ResourceClass::HeapMemory,
            state: ResourceState::Owned,
            function_name: "owner".to_string(),
            family_id: Some(FamilyId::C_HEAP),
        });
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_resource_id(7);

        let bundle = EvidenceBundle::from_candidate(&candidate, Some(&graph), None, None);

        assert_eq!(
            bundle.memory_state,
            Some(ResourceState::Owned),
            "Bundle must resolve MemoryGraph state for resource_id"
        );
        assert!(
            bundle.has_same_resource_evidence,
            "resource_id must count as same-resource evidence"
        );
    }

    /// Objective: Verify candidates without graph identity still bundle safely.
    /// Invariants: No panic and missing state remains `None`.
    #[test]
    fn bundle_without_resource_id_builds_without_state() {
        let candidate = IssueCandidate::new(
            2,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_release_family(FamilyId::CPP_NEW_SCALAR)
        .with_release_function("_ZdlPv");

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);

        assert_eq!(
            bundle.resource_id, None,
            "Candidate without resource_id must keep resource_id absent"
        );
        assert_eq!(
            bundle.memory_state, None,
            "Bundle must not invent a MemoryGraph state"
        );
        assert!(
            bundle.has_reachable_release,
            "release_function must count as reachable release evidence"
        );
    }

    /// Objective: Verify SRT facts are collected from symbols and resources.
    /// Invariants: Semantic facts are deduplicated and available for suppression.
    #[test]
    fn bundle_collects_runtime_managed_semantic_fact() {
        let mut srt = HashMap::new();
        srt.insert(
            "resource:9".to_string(),
            vec![SemanticKind::RuntimeManagedResource],
        );
        srt.insert(
            "malloc".to_string(),
            vec![
                SemanticKind::RuntimeManagedResource,
                SemanticKind::StoredToRuntime,
            ],
        );
        let candidate = IssueCandidate::new(
            3,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::GO_GC,
            "malloc",
        )
        .with_resource_id(9);

        let bundle = EvidenceBundle::from_candidate(&candidate, None, Some(&srt), None);

        assert_eq!(
            bundle
                .semantic_kinds
                .iter()
                .filter(|kind| **kind == SemanticKind::RuntimeManagedResource)
                .count(),
            1,
            "Semantic facts must be deduplicated across symbol and resource keys"
        );
        assert!(
            bundle.has_semantic_suppression(),
            "RuntimeManagedResource must be treated as suppression evidence"
        );
    }

    /// Objective: Verify FFI evidence marks a candidate as boundary-backed.
    /// Invariants: Boundary flag is true even without `CrossBoundaryEvidence`.
    #[test]
    fn bundle_marks_boundary_from_ffi_evidence() {
        let candidate = IssueCandidate::new(
            4,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_ffi_evidence(FfiEvidence::CrossFamilyRelease {
            alloc_family: "C_HEAP".to_string(),
            release_family: "SQLITE_RESOURCE".to_string(),
        });

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);

        assert!(
            bundle.has_boundary_evidence,
            "FFI evidence must mark the bundle as boundary-backed"
        );
    }

    /// Objective: Verify alias rejection evidence is surfaced to verifier code.
    /// Invariants: `may_alias=NotAlias` description sets alias rejection.
    #[test]
    fn bundle_marks_alias_rejection_from_evidence_description() {
        let mut candidate = IssueCandidate::new(
            5,
            IssueCandidateKind::DoubleRelease,
            FamilyId::C_HEAP,
            "free",
        );
        candidate.add_evidence(Evidence::new(
            EvidenceKind::Insufficient,
            "may_alias=NotAlias: independent allocation roots",
        ));

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);

        assert!(
            bundle.has_alias_rejection,
            "may_alias=NotAlias evidence must mark alias rejection"
        );
    }

    // ── Phase 5: Confidence-aware semantic suppression tests ──

    /// Objective: Verify high-confidence RuntimeManagedResource fact
    /// suppresses a leak candidate.
    /// Invariants: has_leak_suppression_high_confidence returns true
    /// when a high-confidence RuntimeManagedResource fact is present.
    #[test]
    fn bundle_high_confidence_runtime_managed_suppresses_leak() {
        let mut srt_facts: HashMap<String, Vec<SemanticFact>> = HashMap::new();
        srt_facts.insert(
            "arena_alloc".to_string(),
            vec![SemanticFact::new(
                omniscope_semantics::SemanticKey::symbol("arena_alloc"),
                SemanticKind::RuntimeManagedResource,
                FactConfidence::High,
                omniscope_semantics::FactSource::IRPattern,
                "arena-allocated, freed by arena reset",
            )],
        );

        let candidate = IssueCandidate::new(
            10,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::C_HEAP,
            "arena_alloc",
        );

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));

        assert!(
            bundle.has_leak_suppression_high_confidence(),
            "High-confidence RuntimeManagedResource must suppress leak"
        );
    }

    /// Objective: Verify medium-confidence RuntimeManagedResource fact
    /// does not fully suppress a definite leak but is available for downgrade.
    /// Invariants: has_leak_suppression_high_confidence returns false,
    /// but has_leak_suppression_medium_confidence returns true.
    #[test]
    fn bundle_medium_confidence_runtime_managed_does_not_fully_suppress_leak() {
        let mut srt_facts: HashMap<String, Vec<SemanticFact>> = HashMap::new();
        srt_facts.insert(
            "arena_alloc".to_string(),
            vec![SemanticFact::new(
                omniscope_semantics::SemanticKey::symbol("arena_alloc"),
                SemanticKind::RuntimeManagedResource,
                FactConfidence::Medium,
                omniscope_semantics::FactSource::ContractDB,
                "inferred runtime-managed from structural analysis",
            )],
        );

        let candidate = IssueCandidate::new(
            11,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::C_HEAP,
            "arena_alloc",
        );

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));

        assert!(
            !bundle.has_leak_suppression_high_confidence(),
            "Medium-confidence RuntimeManagedResource must NOT fully suppress definite leak"
        );
        assert!(
            bundle.has_leak_suppression_medium_confidence(),
            "Medium-confidence RuntimeManagedResource must be available for downgrade"
        );
    }

    /// Objective: Verify RefcountTransfer semantic kind suppresses leak.
    /// Invariants: High-confidence RefcountTransfer → leak suppression.
    #[test]
    fn bundle_refcount_transfer_suppresses_leak() {
        let mut srt_facts: HashMap<String, Vec<SemanticFact>> = HashMap::new();
        srt_facts.insert(
            "Arc::into_raw".to_string(),
            vec![SemanticFact::new(
                omniscope_semantics::SemanticKey::symbol("Arc::into_raw"),
                SemanticKind::RefcountTransfer,
                FactConfidence::High,
                omniscope_semantics::FactSource::BehaviorSummary,
                "Arc reference count transferred to raw pointer",
            )],
        );

        let candidate = IssueCandidate::new(
            12,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::RUST_GLOBAL,
            "Arc::into_raw",
        );

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));

        assert!(
            bundle.has_leak_suppression_high_confidence(),
            "High-confidence RefcountTransfer must suppress leak"
        );
    }

    /// Objective: Verify GlobalProvenance (static lifetime) suppresses
    /// process-lifetime allocation leak.
    /// Invariants: High-confidence GlobalProvenance → leak suppression.
    #[test]
    fn bundle_static_lifetime_suppresses_process_lifetime_leak() {
        let mut srt_facts: HashMap<String, Vec<SemanticFact>> = HashMap::new();
        srt_facts.insert(
            "global_init".to_string(),
            vec![SemanticFact::new(
                omniscope_semantics::SemanticKey::symbol("global_init"),
                SemanticKind::GlobalProvenance,
                FactConfidence::High,
                omniscope_semantics::FactSource::IRPattern,
                "allocation from global/static storage",
            )],
        );

        let candidate = IssueCandidate::new(
            13,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::C_HEAP,
            "global_init",
        );

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));

        assert!(
            bundle.has_leak_suppression_high_confidence(),
            "High-confidence GlobalProvenance must suppress process-lifetime leak"
        );
    }

    /// Objective: Verify that function-local allocation without
    /// GlobalProvenance is NOT suppressed.
    /// Invariants: No srt_facts → no leak suppression.
    #[test]
    fn bundle_function_local_leak_not_suppressed_by_static_lifetime() {
        let candidate = IssueCandidate::new(
            14,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::C_HEAP,
            "local_alloc",
        );

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);

        assert!(
            !bundle.has_leak_suppression_high_confidence(),
            "Function-local leak must not be suppressed without static lifetime evidence"
        );
        assert!(
            !bundle.has_leak_suppression_medium_confidence(),
            "Function-local leak must not have medium-confidence suppression either"
        );
    }

    /// Objective: Verify that same arena does not suppress explicit
    /// wrong-family release (cross-family issue).
    /// Invariants: RuntimeManagedResource suppresses leak but
    /// has_semantic_suppression_high_confidence does NOT suppress
    /// cross-family free (wrong-family is still a bug).
    #[test]
    fn bundle_runtime_managed_does_not_suppress_cross_family_free() {
        let mut srt_facts: HashMap<String, Vec<SemanticFact>> = HashMap::new();
        srt_facts.insert(
            "malloc".to_string(),
            vec![SemanticFact::new(
                omniscope_semantics::SemanticKey::symbol("malloc"),
                SemanticKind::RuntimeManagedResource,
                FactConfidence::High,
                omniscope_semantics::FactSource::IRPattern,
                "runtime-managed resource",
            )],
        );

        let candidate = IssueCandidate::new(
            15,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_release_family(FamilyId::CPP_NEW_SCALAR)
        .with_release_function("operator delete");

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));

        // RuntimeManagedResource is in the semantic suppression list,
        // so has_semantic_suppression_high_confidence returns true.
        // The verifier is responsible for deciding whether to honor it
        // for cross-family free (it should downgrade to ProbableIssue,
        // not ExplainedSafe).
        assert!(
            bundle.has_semantic_suppression_high_confidence(),
            "RuntimeManagedResource must be a semantic suppression kind"
        );
    }

    /// Objective: Verify AbortOnOom semantic kind suppresses leak.
    /// Invariants: High-confidence AbortOnOom → leak suppression
    /// (OOM path terminates the process, so no leak).
    #[test]
    fn bundle_abort_on_oom_suppresses_leak() {
        let mut srt_facts: HashMap<String, Vec<SemanticFact>> = HashMap::new();
        srt_facts.insert(
            "oom_alloc".to_string(),
            vec![SemanticFact::new(
                omniscope_semantics::SemanticKey::symbol("oom_alloc"),
                SemanticKind::AbortOnOom,
                FactConfidence::High,
                omniscope_semantics::FactSource::IRPattern,
                "allocation aborts on OOM",
            )],
        );

        let candidate = IssueCandidate::new(
            16,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::C_HEAP,
            "oom_alloc",
        );

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));

        assert!(
            bundle.has_leak_suppression_high_confidence(),
            "High-confidence AbortOnOom must suppress leak"
        );
    }

    /// Objective: Verify that no suppression occurs without evidence
    /// source and confidence.
    /// Invariants: Empty srt_facts → no suppression.
    #[test]
    fn bundle_no_suppression_without_source_and_confidence() {
        let candidate = IssueCandidate::new(
            17,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::C_HEAP,
            "malloc",
        );

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);

        assert!(
            !bundle.has_semantic_suppression_high_confidence(),
            "No suppression without semantic facts"
        );
        assert!(
            !bundle.has_leak_suppression_high_confidence(),
            "No leak suppression without semantic facts or evidence kinds"
        );
    }

    /// Objective: Verify that RefcountTransfer semantic kind does NOT
    /// suppress double-free (over-release). RefcountTransfer explains
    /// legitimate ownership transfer for *leak* suppression, but a
    /// double-release is still a bug even with refcounting.
    /// Invariants: RefcountTransfer is NOT in the semantic suppression
    /// list for non-leak issue kinds.
    #[test]
    fn bundle_refcount_transfer_does_not_suppress_double_free() {
        let mut srt_resolutions: HashMap<String, Vec<SemanticKind>> = HashMap::new();
        srt_resolutions.insert(
            "Py_DECREF".to_string(),
            vec![SemanticKind::RefcountTransfer],
        );
        let mut srt_facts: HashMap<String, Vec<SemanticFact>> = HashMap::new();
        srt_facts.insert(
            "Py_DECREF".to_string(),
            vec![SemanticFact::new(
                omniscope_semantics::SemanticKey::symbol("Py_DECREF"),
                SemanticKind::RefcountTransfer,
                FactConfidence::High,
                omniscope_semantics::FactSource::BehaviorSummary,
                "refcount transfer — over-release is still a bug",
            )],
        );

        let candidate = IssueCandidate::new(
            18,
            IssueCandidateKind::DoubleRelease,
            FamilyId::PYTHON_MEM,
            "Py_DECREF",
        )
        .with_release_function("Py_DECREF");

        let bundle = EvidenceBundle::from_candidate(
            &candidate,
            None,
            Some(&srt_resolutions),
            Some(&srt_facts),
        );

        // RefcountTransfer is NOT in has_semantic_suppression() because
        // it only suppresses leak candidates, not double-free.
        assert!(
            !bundle.has_semantic_suppression(),
            "RefcountTransfer must NOT be in non-leak semantic suppression kinds"
        );
        // But it IS in has_leak_suppression().
        assert!(
            bundle.has_leak_suppression(),
            "RefcountTransfer must be in leak suppression kinds"
        );
    }

    /// Objective: Verify that StaticLifetimeSink (SemanticKind) suppresses
    /// process-lifetime allocation leak. Global variable initialization
    /// should not be reported as a leak because the resource has
    /// process lifetime.
    /// Invariants: High-confidence StaticLifetimeSink → leak suppression.
    #[test]
    fn bundle_static_lifetime_sink_suppresses_process_lifetime_leak() {
        let mut srt_facts: HashMap<String, Vec<SemanticFact>> = HashMap::new();
        srt_facts.insert(
            "__cxx_global_var_init".to_string(),
            vec![SemanticFact::new(
                omniscope_semantics::SemanticKey::symbol("__cxx_global_var_init"),
                SemanticKind::StaticLifetimeSink,
                FactConfidence::High,
                omniscope_semantics::FactSource::IRPattern,
                "global variable initializer — process lifetime",
            )],
        );

        let candidate = IssueCandidate::new(
            19,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::CPP_NEW_SCALAR,
            "__cxx_global_var_init",
        );

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));

        assert!(
            bundle.has_leak_suppression_high_confidence(),
            "High-confidence StaticLifetimeSink must suppress process-lifetime leak"
        );
        // StaticLifetimeSink is NOT in has_semantic_suppression()
        // because it only suppresses leak candidates, not cross-family.
        assert!(
            !bundle.has_semantic_suppression(),
            "StaticLifetimeSink must NOT be in non-leak semantic suppression"
        );
    }

    /// Objective: Verify that DestructorRelease (SemanticKind) suppresses
    /// leak when high-confidence. A destructor/RAII cleanup path means
    /// the resource is managed by compiler-inserted cleanup, not a leak.
    /// Invariants: High-confidence DestructorRelease → leak suppression
    /// and semantic suppression.
    #[test]
    fn bundle_destructor_release_suppresses_leak_high_confidence() {
        let mut srt_facts: HashMap<String, Vec<SemanticFact>> = HashMap::new();
        srt_facts.insert(
            "~MyClass".to_string(),
            vec![SemanticFact::new(
                omniscope_semantics::SemanticKey::symbol("~MyClass"),
                SemanticKind::DestructorRelease,
                FactConfidence::High,
                omniscope_semantics::FactSource::BehaviorSummary,
                "C++ destructor release — compiler-managed cleanup",
            )],
        );

        let candidate = IssueCandidate::new(
            20,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::CPP_NEW_SCALAR,
            "~MyClass",
        );

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));

        assert!(
            bundle.has_leak_suppression_high_confidence(),
            "High-confidence DestructorRelease must suppress leak"
        );
        assert!(
            bundle.has_semantic_suppression_high_confidence(),
            "High-confidence DestructorRelease must be in semantic suppression"
        );
    }
}
