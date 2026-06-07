//! Verifier-side evidence fusion for resource issue candidates.
//!
//! The bundle is intentionally read-only: it joins facts already produced by
//! earlier passes so the verifier can make decisions from one compact view.

use std::collections::HashMap;

use omniscope_core::IssueCandidate;
use omniscope_semantics::resource::memory_graph::{MemoryGraph, ResourceState};
use omniscope_semantics::SemanticKind;
use omniscope_types::{is_boundary_evidence, EvidenceKind, FamilyId};

/// Joined evidence for one resource issue candidate.
///
/// This type keeps verifier inputs close together without taking ownership of
/// large graphs. It should remain internal until output or auditing needs a
/// stable public representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvidenceBundle {
    pub candidate_id: u64,
    pub resource_id: Option<u64>,
    pub alloc_family: FamilyId,
    pub release_family: Option<FamilyId>,
    pub alloc_function: String,
    pub release_function: Option<String>,
    pub alloc_caller: Option<String>,
    pub release_caller: Option<String>,
    pub memory_state: Option<ResourceState>,
    pub semantic_kinds: Vec<SemanticKind>,
    pub evidence_kinds: Vec<EvidenceKind>,
    pub has_boundary_evidence: bool,
    pub has_same_resource_evidence: bool,
    pub has_reachable_release: bool,
    pub has_alias_rejection: bool,
}

impl EvidenceBundle {
    /// Builds a bundle from a candidate and optional analysis state.
    ///
    /// # Arguments
    /// * `candidate` - The unverified issue candidate.
    /// * `memory_graph` - Optional graph used to resolve resource state.
    /// * `srt_resolutions` - Optional semantic facts keyed by symbol or resource.
    ///
    /// # Returns
    /// A compact evidence bundle. Missing graph or semantic entries are treated
    /// as absent evidence rather than errors.
    pub(crate) fn from_candidate(
        candidate: &IssueCandidate,
        memory_graph: Option<&MemoryGraph>,
        srt_resolutions: Option<&HashMap<String, Vec<SemanticKind>>>,
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
            has_boundary_evidence: has_boundary_evidence(candidate, &evidence_kinds),
            has_same_resource_evidence: has_same_resource_evidence(candidate, &evidence_kinds),
            has_reachable_release: has_reachable_release(candidate, &evidence_kinds),
            has_alias_rejection: has_alias_rejection(candidate),
            evidence_kinds,
        }
    }

    /// Returns true when semantic evidence explains safe ownership transfer.
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
            )
        })
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

fn has_boundary_evidence(candidate: &IssueCandidate, evidence_kinds: &[EvidenceKind]) -> bool {
    candidate.boundary.is_some()
        || candidate.ffi_evidence.is_some()
        || evidence_kinds.iter().any(is_boundary_evidence)
}

fn has_same_resource_evidence(candidate: &IssueCandidate, evidence_kinds: &[EvidenceKind]) -> bool {
    candidate.resource_id.is_some()
        || evidence_kinds.iter().any(|kind| {
            matches!(
                kind,
                EvidenceKind::MultipleRelease | EvidenceKind::UseAfterFree
            )
        })
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

        let bundle = EvidenceBundle::from_candidate(&candidate, Some(&graph), None);

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

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None);

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

        let bundle = EvidenceBundle::from_candidate(&candidate, None, Some(&srt));

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

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None);

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

        let bundle = EvidenceBundle::from_candidate(&candidate, None, None);

        assert!(
            bundle.has_alias_rejection,
            "may_alias=NotAlias evidence must mark alias rejection"
        );
    }
}
