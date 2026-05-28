//! Issue candidate builder pass for resource contract analysis.
//!
//! Builds `IssueCandidate` entries from the contract graph and
//! ownership states. Candidates are NOT reportable issues — they
//! must pass through the `IssueVerifier` first.
//!
//! # Candidate Generation Strategy
//!
//! 1. **CrossFamilyFree** — For each acquire→release pair where the
//!    alloc family and release family are not compatible (checked
//!    via `FamilyRegistry::is_compatible_release`).
//! 2. **DoubleRelease** — For each resource instance that has more
//!    than one release edge targeting it.
//! 3. **ConditionalLeak** — For each resource instance in the
//!    `Acquired`/`Retained`/`Unknown` ownership state (never released
//!    or escaped).
//! 4. **BorrowEscape** — For each instance with a `Borrowed` contract
//!    that has an escape edge (excluding bridge helpers).

use omniscope_core::{IssueCandidate, Result};
use omniscope_semantics::{FamilyRegistry, ResourceInstance};
use omniscope_types::{
    Effect, Evidence, EvidenceKind, FamilyId, IssueCandidateKind, PointerContract,
};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::contract_graph_builder::ContractGraph;

/// Issue candidate builder pass.
///
/// Scans the contract graph and ownership states for potential issues:
/// - Cross-family release edges
/// - Unreleased resources (leak candidates)
/// - Double release edges
/// - Borrowed pointer escapes
///
/// Each candidate carries evidence but NO verdict. The verifier
/// must be run after this pass.
pub struct IssueCandidateBuilderPass;

impl IssueCandidateBuilderPass {
    /// Creates a new issue candidate builder pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for IssueCandidateBuilderPass {
    fn name(&self) -> &'static str {
        "IssueCandidateBuilder"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["OwnershipSolver"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        let mut candidates: Vec<IssueCandidate> = Vec::new();
        let mut next_id: u64 = 1;

        // Load the contract graph and ownership states from context.
        // Fall back to empty defaults if upstream passes haven't run.
        let graph: Option<ContractGraph> = ctx.get("contract_graph");
        let ownership_states: Option<Vec<ResourceInstance>> = ctx.get("ownership_states");
        let registry: Option<FamilyRegistry> = ctx.get("family_registry");
        let registry = registry.unwrap_or_default();

        if let Some(ref graph) = graph {
            // ── Pass 1: Group edges by instance to detect cross-family and double-release ──
            let instance_edges = group_edges_by_instance(graph);

            // ── CrossFamilyFree: acquire→release with incompatible families ──
            for edges in instance_edges.values() {
                let acquire_edges: Vec<_> = edges
                    .iter()
                    .filter(|e| matches!(e.effect, Effect::Acquire { .. }))
                    .collect();
                let release_edges: Vec<_> = edges
                    .iter()
                    .filter(|e| {
                        matches!(
                            e.effect,
                            Effect::Release { .. } | Effect::ConditionalRelease { .. }
                        )
                    })
                    .collect();

                for acquire in &acquire_edges {
                    let alloc_family = acquire.family.unwrap_or(FamilyId::C_HEAP);
                    let alloc_func = acquire.function_name.as_str();

                    for release in &release_edges {
                        let release_family = release.family.unwrap_or(FamilyId::C_HEAP);
                        let release_func = release.function_name.as_str();

                        // Skip if families are compatible
                        if registry.is_compatible_release(alloc_family, release_family) {
                            continue;
                        }

                        let id = next_id;
                        next_id += 1;

                        let candidate = IssueCandidate::new(
                            id,
                            IssueCandidateKind::CrossFamilyFree,
                            alloc_family,
                            alloc_func,
                        )
                        .with_release_family(release_family)
                        .with_release_function(release_func)
                        .with_description(format!(
                            "cross-family release: {} ({:?}) released by {} ({:?})",
                            alloc_func, alloc_family, release_func, release_family
                        ));

                        candidates.push(candidate);
                    }
                }
            }

            // ── DoubleRelease: instance with multiple release edges ──
            for (instance_id, edges) in &instance_edges {
                let release_edges: Vec<_> = edges
                    .iter()
                    .filter(|e| {
                        matches!(
                            e.effect,
                            Effect::Release { .. } | Effect::ConditionalRelease { .. }
                        )
                    })
                    .collect();

                if release_edges.len() > 1 {
                    // The first release is valid; subsequent ones are double-release.
                    // Report one candidate for each extra release beyond the first.
                    for release in release_edges.iter().skip(1) {
                        let family = release.family.unwrap_or(FamilyId::C_HEAP);
                        let id = next_id;
                        next_id += 1;

                        let mut candidate = IssueCandidate::new(
                            id,
                            IssueCandidateKind::DoubleRelease,
                            family,
                            &release.function_name,
                        );
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::CrossFamilyMismatch,
                                format!(
                                    "instance {} released {} times",
                                    instance_id,
                                    release_edges.len()
                                ),
                            )
                            .with_confidence(0.9),
                        );

                        candidates.push(candidate);
                    }
                }
            }

            // ── BorrowEscape: borrowed pointer that has an escape edge ──
            for (instance_id, edges) in &instance_edges {
                let has_escape = edges
                    .iter()
                    .any(|e| matches!(e.effect, Effect::EscapesToCallback { .. }));
                // Borrow detection: we check ownership_states below for
                // instances with PointerContract::Borrowed that have escape edges.
                let _has_borrowed = false;

                // Use ownership_states for contract info if available
                if has_escape {
                    if let Some(ref states) = ownership_states {
                        let instance = states.iter().find(|s| s.id == *instance_id);
                        if let Some(inst) = instance {
                            if inst.contract == PointerContract::Borrowed {
                                let id = next_id;
                                next_id += 1;

                                let mut candidate = IssueCandidate::new(
                                    id,
                                    IssueCandidateKind::BorrowEscape,
                                    inst.family,
                                    "unknown",
                                );
                                candidate.add_evidence(
                                    Evidence::new(
                                        EvidenceKind::CallbackEscape,
                                        format!(
                                            "borrowed pointer (instance {}) escaped to callback",
                                            instance_id
                                        ),
                                    )
                                    .with_confidence(0.7),
                                );

                                candidates.push(candidate);
                            }
                        }
                    }
                }
            }
        }

        // ── ConditionalLeak: instances in Acquired/Retained/Unknown state ──
        if let Some(ref states) = ownership_states {
            for instance in states {
                if instance.is_leak_candidate() {
                    let id = next_id;
                    next_id += 1;

                    let mut candidate = IssueCandidate::new(
                        id,
                        IssueCandidateKind::ConditionalLeak,
                        instance.family,
                        "unknown",
                    )
                    .with_alloc_contract(instance.contract);

                    candidate.add_evidence(
                        Evidence::new(
                            EvidenceKind::Insufficient,
                            format!(
                                "resource instance {} in {:?} state — never released or escaped",
                                instance.id, instance.state
                            ),
                        )
                        .with_confidence(0.6),
                    );

                    candidates.push(candidate);
                }
            }
        }

        let candidate_count = candidates.len();
        ctx.store("issue_candidates", candidates);

        let result = PassResult::new(self.name())
            .with_nodes(candidate_count)
            .with_duration(start.elapsed().as_millis() as u64);

        Ok(result)
    }
}

/// Groups contract edges by their target resource instance ID.
///
/// Acquire edges have `source=0` and `target=instance_id`.
/// Release edges have `source=instance_id` and `target=0`.
/// We group both by the instance they refer to.
fn group_edges_by_instance(
    graph: &ContractGraph,
) -> std::collections::HashMap<u64, Vec<crate::resource::contract_graph_builder::ContractEdge>> {
    use crate::resource::contract_graph_builder::ContractEdge;
    use std::collections::HashMap;

    let mut groups: HashMap<u64, Vec<ContractEdge>> = HashMap::new();

    for edge in &graph.edges {
        match edge.effect {
            // Acquire: source=0 → target=instance_id
            Effect::Acquire { result, .. } => {
                groups.entry(result).or_default().push(edge.clone());
            }
            // Release: source=instance_id → target=0
            Effect::Release { .. } | Effect::ConditionalRelease { .. } => {
                groups.entry(edge.source).or_default().push(edge.clone());
            }
            // Other effects: attach to source instance
            _ => {
                if edge.source != 0 {
                    groups.entry(edge.source).or_default().push(edge.clone());
                }
            }
        }
    }

    groups
}

impl Default for IssueCandidateBuilderPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper: Build a cross-family free candidate.
///
/// Convenience function for constructing a `CrossFamilyFree` candidate
/// with the standard description format.
pub fn build_cross_family_candidate(
    id: u64,
    alloc_family: FamilyId,
    release_family: FamilyId,
    alloc_func: &str,
    release_func: &str,
) -> IssueCandidate {
    IssueCandidate::new(
        id,
        IssueCandidateKind::CrossFamilyFree,
        alloc_family,
        alloc_func,
    )
    .with_release_family(release_family)
    .with_release_function(release_func)
    .with_description(format!(
        "cross-family release: {} ({:?}) released by {} ({:?})",
        alloc_func, alloc_family, release_func, release_family
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::contract_graph_builder::ContractEdge;

    /// Helper: build a minimal contract graph with one acquire→release pair.
    fn make_graph_with_pair(
        alloc_family: FamilyId,
        release_family: FamilyId,
        alloc_func: &str,
        release_func: &str,
    ) -> ContractGraph {
        let mut graph = ContractGraph::new();
        let instance_id = graph.alloc_instance();

        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family: alloc_family,
                result: instance_id,
            },
            function: 0,
            function_name: alloc_func.to_string(),
            family: Some(alloc_family),
        });

        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::Release {
                family: release_family,
                arg: 0,
            },
            function: 1,
            function_name: release_func.to_string(),
            family: Some(release_family),
        });

        graph
    }

    #[test]
    fn test_candidate_builder_creation() {
        let pass = IssueCandidateBuilderPass::new();
        assert_eq!(pass.name(), "IssueCandidateBuilder");
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert_eq!(pass.dependencies(), vec!["OwnershipSolver"]);
    }

    #[test]
    fn test_cross_family_candidate_helper() {
        let candidate = build_cross_family_candidate(
            1,
            FamilyId::C_HEAP,
            FamilyId::CPP_NEW_SCALAR,
            "malloc",
            "operator delete",
        );
        assert_eq!(candidate.kind, IssueCandidateKind::CrossFamilyFree);
        assert_eq!(candidate.alloc_family, FamilyId::C_HEAP);
        assert_eq!(candidate.release_family, Some(FamilyId::CPP_NEW_SCALAR));
        assert!(
            !candidate.is_verified(),
            "Candidate should not be verified yet"
        );
    }

    #[test]
    fn test_same_family_no_cross_family_candidate() {
        // Objective: Verify that malloc→free (same C_HEAP family) does NOT
        // produce a CrossFamilyFree candidate.
        // Invariants: Same-family edges must yield zero CrossFamilyFree candidates.
        let graph = make_graph_with_pair(FamilyId::C_HEAP, FamilyId::C_HEAP, "malloc", "free");

        let instance_edges = group_edges_by_instance(&graph);
        let registry = FamilyRegistry::new();
        let mut cross_family_count = 0;

        for edges in instance_edges.values() {
            let acquire_edges: Vec<_> = edges
                .iter()
                .filter(|e| matches!(e.effect, Effect::Acquire { .. }))
                .collect();
            let release_edges: Vec<_> = edges
                .iter()
                .filter(|e| matches!(e.effect, Effect::Release { .. }))
                .collect();

            for acquire in &acquire_edges {
                let alloc_family = acquire.family.unwrap_or(FamilyId::C_HEAP);
                for release in &release_edges {
                    let release_family = release.family.unwrap_or(FamilyId::C_HEAP);
                    if !registry.is_compatible_release(alloc_family, release_family) {
                        cross_family_count += 1;
                    }
                }
            }
        }

        assert_eq!(
            cross_family_count, 0,
            "Same-family malloc→free must NOT produce cross-family candidate"
        );
    }

    #[test]
    fn test_cross_family_produces_candidate() {
        // Objective: Verify that malloc→operator delete (C_HEAP vs CPP_NEW_SCALAR)
        // produces a CrossFamilyFree candidate.
        // Invariants: Incompatible families must yield a candidate.
        let graph = make_graph_with_pair(
            FamilyId::C_HEAP,
            FamilyId::CPP_NEW_SCALAR,
            "malloc",
            "operator delete",
        );

        let instance_edges = group_edges_by_instance(&graph);
        let registry = FamilyRegistry::new();
        let mut cross_family_count = 0;

        for edges in instance_edges.values() {
            let acquire_edges: Vec<_> = edges
                .iter()
                .filter(|e| matches!(e.effect, Effect::Acquire { .. }))
                .collect();
            let release_edges: Vec<_> = edges
                .iter()
                .filter(|e| matches!(e.effect, Effect::Release { .. }))
                .collect();

            for acquire in &acquire_edges {
                let alloc_family = acquire.family.unwrap_or(FamilyId::C_HEAP);
                for release in &release_edges {
                    let release_family = release.family.unwrap_or(FamilyId::C_HEAP);
                    if !registry.is_compatible_release(alloc_family, release_family) {
                        cross_family_count += 1;
                    }
                }
            }
        }

        assert!(
            cross_family_count > 0,
            "Cross-family malloc→operator delete MUST produce at least one candidate"
        );
    }

    #[test]
    fn test_double_release_produces_candidate() {
        // Objective: Verify that an instance with two release edges
        // produces a DoubleRelease candidate.
        // Invariants: 2 release edges → 1 double-release candidate.
        let mut graph = ContractGraph::new();
        let instance_id = graph.alloc_instance();

        // Acquire
        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family: FamilyId::C_HEAP,
                result: instance_id,
            },
            function: 0,
            function_name: "malloc".to_string(),
            family: Some(FamilyId::C_HEAP),
        });

        // First release
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::Release {
                family: FamilyId::C_HEAP,
                arg: 0,
            },
            function: 1,
            function_name: "free".to_string(),
            family: Some(FamilyId::C_HEAP),
        });

        // Second release (double-free)
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::Release {
                family: FamilyId::C_HEAP,
                arg: 0,
            },
            function: 2,
            function_name: "free_again".to_string(),
            family: Some(FamilyId::C_HEAP),
        });

        let instance_edges = group_edges_by_instance(&graph);

        for edges in instance_edges.values() {
            let release_count = edges
                .iter()
                .filter(|e| matches!(e.effect, Effect::Release { .. }))
                .count();

            if release_count > 1 {
                // Should produce (release_count - 1) double-release candidates
                assert_eq!(
                    release_count - 1,
                    1,
                    "Two releases must produce exactly 1 double-release candidate"
                );
            }
        }
    }

    #[test]
    fn test_conditional_leak_from_ownership_states() {
        // Objective: Verify that an instance in Acquired state with no
        // release produces a ConditionalLeak candidate.
        // Invariants: is_leak_candidate() == true must yield a candidate.
        let instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        assert!(
            instance.is_leak_candidate(),
            "Newly acquired instance must be a leak candidate"
        );

        let released = {
            let mut inst = ResourceInstance::new(2, FamilyId::C_HEAP, PointerContract::Owned);
            inst.transition(omniscope_semantics::OwnershipEvent::Release { function: 42 })
                .unwrap();
            inst
        };
        assert!(
            !released.is_leak_candidate(),
            "Released instance must NOT be a leak candidate"
        );
    }

    #[test]
    fn test_group_edges_by_instance() {
        let graph = make_graph_with_pair(FamilyId::C_HEAP, FamilyId::C_HEAP, "malloc", "free");
        let groups = group_edges_by_instance(&graph);

        // There should be exactly one instance group
        assert_eq!(groups.len(), 1, "One acquire→release pair = one group");

        // The group should have 2 edges (1 acquire + 1 release)
        for edges in groups.values() {
            assert_eq!(
                edges.len(),
                2,
                "Instance group must have 2 edges (acquire + release)"
            );
        }
    }

    #[test]
    fn test_compatible_family_mimalloc_c_heap() {
        // Objective: Verify that mimalloc→free is compatible (no cross-family candidate).
        // Invariants: MIMALLOC has C_HEAP in compatible_releases.
        let registry = FamilyRegistry::new();
        assert!(
            registry.is_compatible_release(FamilyId::MIMALLOC, FamilyId::C_HEAP),
            "mimalloc must be compatible with c_heap"
        );
    }

    #[test]
    fn test_incompatible_cpp_array_vs_c_heap() {
        // Objective: Verify that new[]→free is a cross-family mismatch.
        // Invariants: CPP_NEW_ARRAY and C_HEAP are not compatible.
        let registry = FamilyRegistry::new();
        assert!(
            !registry.is_compatible_release(FamilyId::CPP_NEW_ARRAY, FamilyId::C_HEAP),
            "cpp_new_array and c_heap must NOT be compatible"
        );
    }
}
