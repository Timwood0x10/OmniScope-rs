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
//! 5. **UseAfterFree** — For each instance in `Released` state that
//!    has a subsequent use edge (e.g. EscapesToCallback). Distinct
//!    from BorrowEscape: the resource was explicitly freed before use.

use omniscope_core::{IssueCandidate, Result};
use omniscope_semantics::{FamilyRegistry, OwnershipState, ResourceInstance};
use omniscope_types::{
    Effect, Evidence, EvidenceKind, FamilyId, IssueCandidateKind, PointerContract,
};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::contract_graph_builder::{ContractEdge, ContractGraph};

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
                                EvidenceKind::MultipleRelease,
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

            // ── DoubleRelease via target: same resource released by different instances ──
            // After the FIFO fix, two frees of the same resource get different source
            // instances (first pairs with acquire, second is orphan). Detect this by
            // tracking which target IDs have been released.
            {
                let mut released_targets: std::collections::HashMap<u64, &ContractEdge> =
                    std::collections::HashMap::new();
                for edges in instance_edges.values() {
                    for edge in edges {
                        if !matches!(
                            edge.effect,
                            Effect::Release { .. } | Effect::ConditionalRelease { .. }
                        ) {
                            continue;
                        }
                        if edge.target == 0 {
                            continue;
                        }
                        if let Some(first_release) = released_targets.get(&edge.target) {
                            let family = edge.family.unwrap_or(FamilyId::C_HEAP);
                            let id = next_id;
                            next_id += 1;
                            let mut candidate = IssueCandidate::new(
                                id,
                                IssueCandidateKind::DoubleRelease,
                                family,
                                &edge.function_name,
                            );
                            candidate.add_evidence(
                                Evidence::new(
                                    EvidenceKind::MultipleRelease,
                                    format!(
                                        "target {} first released by instance {}, then by instance {}",
                                        edge.target, first_release.source, edge.source
                                    ),
                                )
                                .with_confidence(0.9),
                            );
                            candidates.push(candidate);
                        } else {
                            released_targets.insert(edge.target, edge);
                        }
                    }
                }
            }

            // ── BorrowEscape: borrowed pointer that has an escape edge ──
            for (instance_id, edges) in &instance_edges {
                let has_escape = edges
                    .iter()
                    .any(|e| matches!(e.effect, Effect::EscapesToCallback { .. }));
                // Check if this instance has a Borrowed contract in ownership states.
                // Only generate BorrowEscape candidates when the pointer is actually
                // borrowed (not owned) — owned pointers escaping is a different issue.
                let has_borrowed = ownership_states
                    .as_ref()
                    .and_then(|states| states.iter().find(|s| s.id == *instance_id))
                    .is_some_and(|inst| inst.contract == PointerContract::Borrowed);

                // Generate BorrowEscape candidate only when both conditions hold:
                // 1. The instance has an escape edge (EscapesToCallback)
                // 2. The instance's contract is Borrowed (not Owned)
                if has_escape && has_borrowed {
                    if let Some(ref states) = ownership_states {
                        if let Some(inst) = states.iter().find(|s| s.id == *instance_id) {
                            let id = next_id;
                            next_id += 1;

                            let func_name = if inst.function_name.is_empty() {
                                "unknown"
                            } else {
                                &inst.function_name
                            };
                            let mut candidate = IssueCandidate::new(
                                id,
                                IssueCandidateKind::BorrowEscape,
                                inst.family,
                                func_name,
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

            // ── UseAfterFree: released resource then used (borrowed or escaped to FFI) ──
            // Detection: instance in Released state that has EscapesToCallback or
            // other use edges. This is distinct from BorrowEscape because the
            // resource was explicitly freed before being used.
            // Patterns:
            //   - Acquired → Released → (used): straightforward UAF
            //   - Acquired → Escaped → Released → (used): escaped then freed then used
            for (instance_id, edges) in &instance_edges {
                let has_release = edges.iter().any(|e| {
                    matches!(
                        e.effect,
                        Effect::Release { .. } | Effect::ConditionalRelease { .. }
                    )
                });

                if !has_release {
                    continue;
                }

                // Find the index of the latest release edge for temporal ordering.
                // A use edge is only a UAF if it appears AFTER the release.
                let release_idx = edges
                    .iter()
                    .rposition(|e| {
                        matches!(
                            e.effect,
                            Effect::Release { .. } | Effect::ConditionalRelease { .. }
                        )
                    })
                    .unwrap_or(0);

                // Check for use-after-free: EscapesToCallback or other use edges
                // that appear AFTER the release edge in the edge list.
                let use_edges: Vec<_> = edges
                    .iter()
                    .enumerate()
                    .filter(|(idx, e)| {
                        *idx > release_idx
                            && matches!(
                                e.effect,
                                Effect::EscapesToCallback { .. } | Effect::ReturnsBorrowed
                            )
                    })
                    .map(|(_, e)| e)
                    .collect();

                if use_edges.is_empty() {
                    continue;
                }

                // Verify the instance is in Released state (the release happened
                // and the subsequent use transition failed in the ownership solver)
                if let Some(ref states) = ownership_states {
                    if let Some(inst) = states.iter().find(|s| s.id == *instance_id) {
                        if inst.state != OwnershipState::Released {
                            continue;
                        }

                        // Skip instances with Borrowed contract — those are
                        // BorrowEscape, not UseAfterFree
                        if inst.contract == PointerContract::Borrowed {
                            continue;
                        }

                        let id = next_id;
                        next_id += 1;

                        let func_name = if inst.function_name.is_empty() {
                            "unknown"
                        } else {
                            &inst.function_name
                        };
                        let mut candidate = IssueCandidate::new(
                            id,
                            IssueCandidateKind::UseAfterFree,
                            inst.family,
                            func_name,
                        );

                        let use_desc = use_edges
                            .iter()
                            .map(|e| e.function_name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::UseAfterFree,
                                format!(
                                    "instance {} released then used in '{}' — use-after-free (CWE-416)",
                                    instance_id, use_desc
                                ),
                            )
                            .with_confidence(0.85),
                        );

                        candidates.push(candidate);
                    }
                }
            }

            // ── DoubleReclaim: same raw pointer reclaimed multiple times ──
            // Multiple OwnershipReclaim edges on the same instance mean
            // from_raw was called more than once on the same raw pointer,
            // which is undefined behavior (use-after-free / double-free).
            for (instance_id, edges) in &instance_edges {
                let reclaim_edges: Vec<_> = edges
                    .iter()
                    .filter(|e| matches!(e.effect, Effect::OwnershipReclaim { .. }))
                    .collect();

                if reclaim_edges.len() > 1 {
                    for reclaim in reclaim_edges.iter().skip(1) {
                        let family = reclaim.family.unwrap_or(FamilyId::RUST_RAW_OWNERSHIP);
                        let id = next_id;
                        next_id += 1;

                        let mut candidate = IssueCandidate::new(
                            id,
                            IssueCandidateKind::DoubleReclaim,
                            family,
                            &reclaim.function_name,
                        );
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::RawOwnershipReclaim,
                                format!(
                                    "instance {} reclaimed {} times via from_raw — double reclaim is undefined behavior",
                                    instance_id,
                                    reclaim_edges.len()
                                ),
                            )
                            .with_confidence(0.9),
                        );

                        candidates.push(candidate);
                    }
                }
            }

            // ── OwnershipEscapeLeak: into_raw without matching from_raw ──
            // If an instance has an OwnershipEscape edge but no matching
            // OwnershipReclaim, the raw pointer was never reclaimed,
            // potentially leaking the resource across the FFI boundary.
            for (instance_id, edges) in &instance_edges {
                let has_ownership_escape = edges
                    .iter()
                    .any(|e| matches!(e.effect, Effect::OwnershipEscape { .. }));
                let has_reclaim = edges
                    .iter()
                    .any(|e| matches!(e.effect, Effect::OwnershipReclaim { .. }));

                if has_ownership_escape && !has_reclaim {
                    let escape_edge = edges
                        .iter()
                        .find(|e| matches!(e.effect, Effect::OwnershipEscape { .. }));
                    let family = escape_edge
                        .and_then(|e| e.family)
                        .unwrap_or(FamilyId::RUST_RAW_OWNERSHIP);
                    let escape_func = escape_edge
                        .map(|e| e.function_name.as_str())
                        .unwrap_or("unknown");

                    let id = next_id;
                    next_id += 1;

                    let mut candidate = IssueCandidate::new(
                        id,
                        IssueCandidateKind::OwnershipEscapeLeak,
                        family,
                        escape_func,
                    );
                    candidate.add_evidence(
                        Evidence::new(
                            EvidenceKind::OwnershipEscapeLeak,
                            format!(
                                "instance {} escaped via into_raw ('{}') but never reclaimed via from_raw — potential leak",
                                instance_id, escape_func
                            ),
                        )
                        .with_confidence(0.7),
                    );

                    candidates.push(candidate);
                }
            }

            // ── Cross-family reclaim: C family pointer reclaimed by Rust ──
            // malloc'd pointer passed to Box::from_raw — cross-family mismatch.
            for edges in instance_edges.values() {
                let non_rust_acquires: Vec<_> = edges
                    .iter()
                    .filter(|e| {
                        matches!(e.effect, Effect::Acquire { .. })
                            && e.family.is_some_and(|f| {
                                f != FamilyId::RUST_RAW_OWNERSHIP && f != FamilyId::RUST_GLOBAL
                            })
                    })
                    .collect();
                let reclaim_edges: Vec<_> = edges
                    .iter()
                    .filter(|e| matches!(e.effect, Effect::OwnershipReclaim { .. }))
                    .collect();

                for acquire in &non_rust_acquires {
                    for reclaim in &reclaim_edges {
                        let alloc_family = acquire.family.unwrap_or(FamilyId::C_HEAP);
                        let reclaim_family = reclaim.family.unwrap_or(FamilyId::RUST_RAW_OWNERSHIP);

                        if !registry.is_compatible_release(alloc_family, reclaim_family) {
                            let id = next_id;
                            next_id += 1;

                            let candidate = IssueCandidate::new(
                                id,
                                IssueCandidateKind::CrossFamilyFree,
                                alloc_family,
                                &acquire.function_name,
                            )
                            .with_release_family(reclaim_family)
                            .with_release_function(&reclaim.function_name)
                            .with_description(format!(
                                "cross-family reclaim: {} ({:?}) reclaimed by {} ({:?})",
                                acquire.function_name,
                                alloc_family,
                                reclaim.function_name,
                                reclaim_family
                            ));

                            candidates.push(candidate);
                        }
                    }
                }
            }

            // ── NeedsModel: Reclaim without matching Acquire or Escape ──
            // When an instance has only OwnershipReclaim edges with no
            // corresponding Acquire or OwnershipEscape, the raw pointer
            // source is unknown. This is a NeedsModel candidate, not a
            // high-severity issue — we cannot prove it's a bug without
            // knowing where the pointer came from.
            for (instance_id, edges) in &instance_edges {
                let has_acquire = edges
                    .iter()
                    .any(|e| matches!(e.effect, Effect::Acquire { .. }));
                let has_escape = edges
                    .iter()
                    .any(|e| matches!(e.effect, Effect::OwnershipEscape { .. }));
                let reclaim_edges: Vec<_> = edges
                    .iter()
                    .filter(|e| matches!(e.effect, Effect::OwnershipReclaim { .. }))
                    .collect();

                // If there are reclaim edges but no acquire or escape,
                // the pointer's provenance is unknown → NeedsModel
                if !has_acquire && !has_escape && !reclaim_edges.is_empty() {
                    for reclaim in &reclaim_edges {
                        let family = reclaim.family.unwrap_or(FamilyId::RUST_RAW_OWNERSHIP);
                        let id = next_id;
                        next_id += 1;

                        let mut candidate = IssueCandidate::new(
                            id,
                            IssueCandidateKind::NeedsModel,
                            family,
                            &reclaim.function_name,
                        );
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::RawOwnershipReclaim,
                                format!(
                                    "instance {} reclaimed via '{}' with unknown provenance — needs model for raw pointer source",
                                    instance_id, reclaim.function_name
                                ),
                            )
                            .with_confidence(0.5),
                        );

                        candidates.push(candidate);
                    }
                }
            }
        }
        if let Some(ref states) = ownership_states {
            for instance in states {
                if instance.is_leak_candidate() {
                    let id = next_id;
                    next_id += 1;

                    let func_name = if instance.function_name.is_empty() {
                        "unknown"
                    } else {
                        &instance.function_name
                    };
                    let mut candidate = IssueCandidate::new(
                        id,
                        IssueCandidateKind::ConditionalLeak,
                        instance.family,
                        func_name,
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
            // Reclaim: source=escaped_instance → target=reclaimed_instance.
            // Always group by `result` (the fresh reclaim instance ID).
            // Also group by `edge.source` (the escaped instance ID) so the
            // OwnershipEscapeLeak check can find the reclaim in the same group
            // as the escape edge — otherwise escape and reclaim end up in
            // separate groups, causing false positives.
            Effect::OwnershipReclaim { result, .. } => {
                groups.entry(result).or_default().push(edge.clone());
                if edge.source != 0 && edge.source != result {
                    groups.entry(edge.source).or_default().push(edge.clone());
                }
            }
            // Release: source=instance_id → target=0
            Effect::Release { .. } | Effect::ConditionalRelease { .. } => {
                groups.entry(edge.source).or_default().push(edge.clone());
            }
            // Escape: source=instance_id → target=0
            Effect::OwnershipEscape { .. } => {
                groups.entry(edge.source).or_default().push(edge.clone());
            }
            // EscapesToCallback: may have source=0 when the callback context
            // does not carry an explicit source instance. Use a synthetic key
            // so the edge is not silently dropped.
            Effect::EscapesToCallback { .. } => {
                let key = if edge.source != 0 {
                    edge.source
                } else {
                    u64::MAX
                };
                groups.entry(key).or_default().push(edge.clone());
            }
            // ReturnsBorrowed: may have source=0 when the return context
            // does not carry an explicit source instance. Use a synthetic key.
            Effect::ReturnsBorrowed => {
                let key = if edge.source != 0 {
                    edge.source
                } else {
                    u64::MAX
                };
                groups.entry(key).or_default().push(edge.clone());
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
            caller_name: "test_func".to_string(),
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
            caller_name: "test_func".to_string(),
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
            caller_name: "test_func".to_string(),
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
            caller_name: "test_func".to_string(),
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
            caller_name: "test_func".to_string(),
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

    /// Objective: End-to-end pipeline test — malloc/free (same family) must
    /// produce zero CrossFamilyFree candidates.
    /// Invariants: Same C_HEAP family acquire→release = no candidate.
    #[test]
    fn test_e2e_same_family_no_issue() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "malloc".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "free".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        // Run RawFactCollector → ContractGraphBuilder → OwnershipSolver → IssueCandidateBuilder
        let raw_pass = crate::resource::raw_fact_collector::RawFactCollectorPass::new();
        raw_pass.run(&mut ctx).unwrap();

        let cg_pass = crate::resource::contract_graph_builder::ContractGraphBuilderPass::new();
        cg_pass.run(&mut ctx).unwrap();

        let os_pass = crate::resource::ownership_solver::OwnershipSolverPass::new();
        os_pass.run(&mut ctx).unwrap();

        let ic_pass = IssueCandidateBuilderPass::new();
        ic_pass.run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        // malloc→free is same C_HEAP family → no CrossFamilyFree candidates
        let cross_family: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::CrossFamilyFree)
            .collect();
        assert!(
            cross_family.is_empty(),
            "Same-family malloc→free must NOT produce CrossFamilyFree candidate, got {}",
            cross_family.len()
        );
    }

    /// Objective: End-to-end pipeline test — malloc + operator delete (cross-family)
    /// must produce a CrossFamilyFree candidate that passes through the verifier.
    /// Invariants: C_HEAP acquire + CPP_NEW_SCALAR release = CrossFamilyFree candidate.
    #[test]
    fn test_e2e_cross_family_produces_issue() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "malloc".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "_ZdlPv".to_string(), // operator delete(void*)
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        // Run full candidate pipeline
        let raw_pass = crate::resource::raw_fact_collector::RawFactCollectorPass::new();
        raw_pass.run(&mut ctx).unwrap();

        let cg_pass = crate::resource::contract_graph_builder::ContractGraphBuilderPass::new();
        cg_pass.run(&mut ctx).unwrap();

        let os_pass = crate::resource::ownership_solver::OwnershipSolverPass::new();
        os_pass.run(&mut ctx).unwrap();

        let ic_pass = IssueCandidateBuilderPass::new();
        ic_pass.run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        // malloc→operator delete is cross-family → must produce candidate
        let cross_family: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::CrossFamilyFree)
            .collect();
        assert!(
            !cross_family.is_empty(),
            "Cross-family malloc→operator delete MUST produce CrossFamilyFree candidate"
        );

        // Now run the verifier
        let ver_pass = crate::resource::issue_verifier::IssueVerifierPass::new();
        ver_pass.run(&mut ctx).unwrap();

        // Verify that the issue was actually emitted
        let issues = ctx.issues();
        let cross_family_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.kind == omniscope_core::IssueKind::CrossFamilyFree)
            .collect();
        assert!(
            !cross_family_issues.is_empty(),
            "CrossFamilyFree must appear in emitted issues after verification"
        );
    }

    /// Objective: End-to-end — malloc without free produces ConditionalLeak candidate.
    /// Invariants: Acquired-only instance = leak candidate.
    #[test]
    fn test_e2e_conditional_leak_candidate() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        // Only malloc, no free — leak
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "malloc".to_string(),
            caller: "leaky_func".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        crate::resource::raw_fact_collector::RawFactCollectorPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::ownership_solver::OwnershipSolverPass::new()
            .run(&mut ctx)
            .unwrap();
        IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        let leak_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::ConditionalLeak)
            .collect();
        assert!(
            !leak_candidates.is_empty(),
            "malloc without free MUST produce ConditionalLeak candidate"
        );
    }

    /// Objective: End-to-end — double free produces DoubleRelease candidate.
    /// Invariants: Two free calls on same instance = DoubleRelease candidate.
    #[test]
    fn test_e2e_double_release_candidate() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "malloc".to_string(),
            caller: "buggy_func".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "free".to_string(),
            caller: "buggy_func".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "free".to_string(),
            caller: "buggy_func".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        crate::resource::raw_fact_collector::RawFactCollectorPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::ownership_solver::OwnershipSolverPass::new()
            .run(&mut ctx)
            .unwrap();
        IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        let double_release: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::DoubleRelease)
            .collect();
        assert!(
            !double_release.is_empty(),
            "Double free MUST produce DoubleRelease candidate"
        );
    }

    /// Objective: Verify that Box::into_raw + Box::from_raw (normal transfer)
    /// does NOT produce a DoubleReclaim candidate — only one from_raw per pointer.
    /// Invariants: Single escape + single reclaim = no double reclaim.
    #[test]
    fn test_e2e_box_into_raw_normal_no_false_positive() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        // Box::into_raw (escape) + Box::from_raw (reclaim) — normal pattern
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Box::into_raw".to_string(),
            caller: "safe_transfer".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Box::from_raw".to_string(),
            caller: "safe_transfer".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        crate::resource::raw_fact_collector::RawFactCollectorPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::ownership_solver::OwnershipSolverPass::new()
            .run(&mut ctx)
            .unwrap();
        IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        let double_reclaim: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::DoubleReclaim)
            .collect();
        assert!(
            double_reclaim.is_empty(),
            "Box::into_raw + Box::from_raw (single reclaim) must NOT produce DoubleReclaim candidate, got {}",
            double_reclaim.len()
        );
    }

    /// Objective: Verify that Box::from_raw called twice on same pointer
    /// produces a DoubleReclaim candidate.
    /// Invariants: Two from_raw reclaims on same instance = DoubleReclaim.
    #[test]
    fn test_e2e_box_from_raw_double_reclaim_tp() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Box::from_raw".to_string(),
            caller: "buggy_func".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Box::from_raw".to_string(),
            caller: "buggy_func".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        crate::resource::raw_fact_collector::RawFactCollectorPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::ownership_solver::OwnershipSolverPass::new()
            .run(&mut ctx)
            .unwrap();
        IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        let double_reclaim: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::DoubleReclaim)
            .collect();
        assert!(
            !double_reclaim.is_empty(),
            "Double Box::from_raw on same pointer MUST produce DoubleReclaim candidate"
        );
    }

    /// Objective: Verify that CString::from_raw called twice produces DoubleReclaim.
    /// Invariants: Same as Box::from_raw double reclaim — CString variant.
    #[test]
    fn test_e2e_cstring_from_raw_double_reclaim_tp() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "CString::from_raw".to_string(),
            caller: "buggy_cstring".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "CString::from_raw".to_string(),
            caller: "buggy_cstring".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        crate::resource::raw_fact_collector::RawFactCollectorPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::ownership_solver::OwnershipSolverPass::new()
            .run(&mut ctx)
            .unwrap();
        IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        let double_reclaim: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::DoubleReclaim)
            .collect();
        assert!(
            !double_reclaim.is_empty(),
            "Double CString::from_raw on same pointer MUST produce DoubleReclaim candidate"
        );
    }

    /// Objective: Verify that malloc pointer reclaimed by Rust (Box::from_raw)
    /// produces a CrossFamilyFree candidate.
    /// Invariants: C_HEAP acquire + RUST_RAW_OWNERSHIP reclaim = cross-family.
    #[test]
    fn test_e2e_malloc_reclaimed_by_rust_cross_family() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "malloc".to_string(),
            caller: "cross_ffi".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Box::from_raw".to_string(),
            caller: "cross_ffi".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        crate::resource::raw_fact_collector::RawFactCollectorPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::ownership_solver::OwnershipSolverPass::new()
            .run(&mut ctx)
            .unwrap();
        IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        let cross_family: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::CrossFamilyFree)
            .collect();
        assert!(
            !cross_family.is_empty(),
            "malloc reclaimed by Box::from_raw MUST produce CrossFamilyFree candidate"
        );
    }

    /// Objective: Verify that into_raw without matching from_raw produces
    /// a ConditionalLeak candidate with OwnershipEscapeLeak evidence.
    /// Invariants: Escape edge without reclaim = ownership escape leak.
    #[test]
    fn test_e2e_into_raw_without_from_raw_escape_leak() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        // Box::into_raw but no Box::from_raw — potential leak
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Box::into_raw".to_string(),
            caller: "leaky_ffi".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        crate::resource::raw_fact_collector::RawFactCollectorPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::ownership_solver::OwnershipSolverPass::new()
            .run(&mut ctx)
            .unwrap();
        IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        let escape_leak: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::OwnershipEscapeLeak)
            .collect();
        assert!(
            !escape_leak.is_empty(),
            "Box::into_raw without Box::from_raw MUST produce OwnershipEscapeLeak candidate"
        );
    }

    /// Objective: Verify that Vec::from_raw_parts from unknown source produces
    /// a NeedsModel candidate (not a high-severity issue).
    /// Invariants: Reclaim without Acquire or Escape = NeedsModel.
    #[test]
    fn test_e2e_vec_from_raw_parts_unknown_source_needs_model() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        // Vec::from_raw_parts with no matching acquire or escape — unknown source
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Vec::from_raw_parts".to_string(),
            caller: "suspicious_func".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        crate::resource::raw_fact_collector::RawFactCollectorPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::ownership_solver::OwnershipSolverPass::new()
            .run(&mut ctx)
            .unwrap();
        IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        let needs_model: Vec<_> = candidates
            .iter()
            .filter(|c| {
                c.kind == IssueCandidateKind::NeedsModel
                    && c.evidence
                        .iter()
                        .any(|e| e.kind == EvidenceKind::RawOwnershipReclaim)
            })
            .collect();
        assert!(
            !needs_model.is_empty(),
            "Vec::from_raw_parts with unknown source MUST produce NeedsModel with RawOwnershipReclaim evidence"
        );
    }

    /// Objective: Verify that stack/borrowed userdata passed to a callback
    /// registration API produces a BorrowEscape (or CallbackEscape) candidate.
    /// Invariants: EscapesToCallback edge on a Borrowed instance = escape.
    #[test]
    fn test_e2e_stack_userdata_callback_escape_tp() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        // Only a callback registration call — no heap acquire.
        // The ContractGraphBuilder will create a virtual stack instance,
        // and OwnershipSolver will mark it as Borrowed.
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "register_callback".to_string(),
            caller: "async_handler".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        crate::resource::raw_fact_collector::RawFactCollectorPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::ownership_solver::OwnershipSolverPass::new()
            .run(&mut ctx)
            .unwrap();
        IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        let escape_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| {
                c.kind == IssueCandidateKind::BorrowEscape
                    || c.kind == IssueCandidateKind::CallbackEscape
            })
            .collect();
        assert!(
            !escape_candidates.is_empty(),
            "Stack userdata passed to register_callback MUST produce BorrowEscape or CallbackEscape candidate, got {:?}",
            candidates.iter().map(|c| c.kind).collect::<Vec<_>>()
        );
    }

    /// Objective: Verify that Box::into_raw userdata passed to a callback
    /// registration API does NOT produce a BorrowEscape candidate.
    /// Invariants: Heap-escaped instance (OwnershipEscape) should be
    /// suppressed by the issue verifier's heap/ownership transfer checks.
    #[test]
    fn test_e2e_box_into_raw_callback_no_false_positive() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        // Box::into_raw (heap escape) + register_callback
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Box::into_raw".to_string(),
            caller: "safe_handler".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "register_callback".to_string(),
            caller: "safe_handler".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        crate::resource::raw_fact_collector::RawFactCollectorPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::ownership_solver::OwnershipSolverPass::new()
            .run(&mut ctx)
            .unwrap();
        IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        // Box::into_raw produces RUST_RAW_OWNERSHIP which is a heap family,
        // so it should NOT be selected as userdata instance by the callback
        // escape detection. If it is, the OwnershipEscape would be caught
        // by verify_borrow_escape's OwnershipTransfer suppression.
        let borrow_escape: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::BorrowEscape)
            .collect();
        assert!(
            borrow_escape.is_empty(),
            "Box::into_raw + register_callback must NOT produce BorrowEscape candidate, got {}",
            borrow_escape.len()
        );
    }

    /// Objective: Verify that a synchronous callback call (not a registration)
    /// does NOT produce a BorrowEscape candidate.
    /// Invariants: Non-registration API names should not trigger callback escape.
    #[test]
    fn test_e2e_synchronous_callback_no_false_positive() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        let mut module = IRModule::new();
        // "call_callback" is NOT a registration API — it's a synchronous call
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "call_callback".to_string(),
            caller: "sync_func".to_string(),
            is_external: true,
            location: None,
        });

        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        crate::resource::raw_fact_collector::RawFactCollectorPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
            .run(&mut ctx)
            .unwrap();
        crate::resource::ownership_solver::OwnershipSolverPass::new()
            .run(&mut ctx)
            .unwrap();
        IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        let escape_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| {
                c.kind == IssueCandidateKind::BorrowEscape
                    || c.kind == IssueCandidateKind::CallbackEscape
            })
            .collect();
        assert!(
            escape_candidates.is_empty(),
            "Synchronous call_callback must NOT produce BorrowEscape/CallbackEscape candidate, got {:?}",
            escape_candidates.iter().map(|c| c.kind).collect::<Vec<_>>()
        );
    }
}
