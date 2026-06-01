//! Tests for the issue candidate builder pass.

use super::*;
use crate::resource::contract_graph_builder::ContractEdge;
use grouping::InstanceEdgeGroups;
use omniscope_semantics::FamilyRegistry;
use omniscope_types::FamilyId;

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
    assert_eq!(
        pass.name(),
        "IssueCandidateBuilder",
        "Expected values to be equal"
    );
    assert_eq!(
        pass.kind(),
        PassKind::Analysis,
        "Expected values to be equal"
    );
    assert_eq!(
        pass.dependencies(),
        vec!["OwnershipSolver"],
        "Expected values to be equal"
    );
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
    assert_eq!(
        candidate.kind,
        IssueCandidateKind::CrossFamilyFree,
        "Expected values to be equal"
    );
    assert_eq!(
        candidate.alloc_family,
        FamilyId::C_HEAP,
        "Expected values to be equal"
    );
    assert_eq!(
        candidate.release_family,
        Some(FamilyId::CPP_NEW_SCALAR),
        "Expected values to be equal"
    );
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

    let groups = InstanceEdgeGroups::new(&graph);
    let registry = FamilyRegistry::new();
    let mut cross_family_count = 0;

    for instance_id in groups.instance_ids() {
        let edge_indices = groups.edges_of(*instance_id);
        let acquire_indices: Vec<usize> = edge_indices
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Acquire { .. }))
            .collect();
        let release_indices: Vec<usize> = edge_indices
            .iter()
            .copied()
            .filter(|&idx| {
                matches!(
                    graph.edges[idx].effect,
                    Effect::Release { .. } | Effect::ConditionalRelease { .. }
                )
            })
            .collect();

        for ai in &acquire_indices {
            let alloc_family = graph.edges[*ai].family.unwrap_or(FamilyId::C_HEAP);
            for ri in &release_indices {
                let release_family = graph.edges[*ri].family.unwrap_or(FamilyId::C_HEAP);
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

    let groups = InstanceEdgeGroups::new(&graph);
    let registry = FamilyRegistry::new();
    let mut cross_family_count = 0;

    for instance_id in groups.instance_ids() {
        let edge_indices = groups.edges_of(*instance_id);
        let acquire_indices: Vec<usize> = edge_indices
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Acquire { .. }))
            .collect();
        let release_indices: Vec<usize> = edge_indices
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Release { .. }))
            .collect();

        for ai in &acquire_indices {
            let alloc_family = graph.edges[*ai].family.unwrap_or(FamilyId::C_HEAP);
            for ri in &release_indices {
                let release_family = graph.edges[*ri].family.unwrap_or(FamilyId::C_HEAP);
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

    let groups = InstanceEdgeGroups::new(&graph);

    for instance_id in groups.instance_ids() {
        let edge_indices = groups.edges_of(*instance_id);
        let release_count = edge_indices
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Release { .. }))
            .count();

        if release_count > 1 {
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
    let groups = InstanceEdgeGroups::new(&graph);

    // There should be exactly one instance group
    assert_eq!(
        groups.instance_ids().len(),
        1,
        "One acquire→release pair = one group"
    );

    // The group should have 2 edges (1 acquire + 1 release)
    for instance_id in groups.instance_ids() {
        assert_eq!(
            groups.edges_of(*instance_id).len(),
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

/// Objective: End-to-end — double free is detectable in the contract graph.
/// Invariants: Two free calls on same resource produce two release edges.
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

    // Verify contract graph has two release edges
    let graph = ctx.get_ref::<ContractGraph>("contract_graph");
    let graph = graph.expect("contract_graph must be present");
    let release_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| {
            matches!(
                e.effect,
                Effect::Release { .. } | Effect::ConditionalRelease { .. }
            )
        })
        .collect();
    assert!(
        release_edges.len() >= 2,
        "Double free MUST produce at least 2 release edges in contract graph, got {}",
        release_edges.len()
    );

    // The releases should have different source instances (FIFO fix)
    let release_sources: std::collections::HashSet<u64> =
        release_edges.iter().map(|e| e.source).collect();
    assert!(
        release_sources.len() >= 2,
        "Frees must have different source instances after FIFO fix, got {}",
        release_sources.len()
    );
}

/// Objective: Verify that Box::into_raw + Box::from_raw (normal transfer)
/// does NOT produce a DoubleReclaim candidate.
/// Invariants: Single escape + single reclaim = no double reclaim.
#[test]
fn test_e2e_box_into_raw_normal_no_false_positive() {
    use crate::pass::PassContext;
    use omniscope_ir::IRModule;

    let mut module = IRModule::new();
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

/// Objective: Verify that Box::from_raw called twice produces DoubleReclaim.
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

/// Objective: Verify that malloc pointer reclaimed by Rust produces CrossFamilyFree.
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
/// an OwnershipEscapeLeak candidate.
/// Invariants: Escape edge without reclaim = ownership escape leak.
#[test]
fn test_e2e_into_raw_without_from_raw_escape_leak() {
    use crate::pass::PassContext;
    use omniscope_ir::IRModule;

    let mut module = IRModule::new();
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
/// a NeedsModel candidate.
/// Invariants: Reclaim without Acquire or Escape = NeedsModel.
#[test]
fn test_e2e_vec_from_raw_parts_unknown_source_needs_model() {
    use crate::pass::PassContext;
    use omniscope_ir::IRModule;

    let mut module = IRModule::new();
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
/// does NOT produce a BorrowEscape candidate.
/// Invariants: Heap-escaped instance should not trigger BorrowEscape.
#[test]
fn test_e2e_box_into_raw_callback_no_false_positive() {
    use crate::pass::PassContext;
    use omniscope_ir::IRModule;

    let mut module = IRModule::new();
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
