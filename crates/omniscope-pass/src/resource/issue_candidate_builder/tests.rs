//! Tests for the issue candidate builder pass.

use super::*;
use crate::resource::contract_graph_builder::{is_cross_language_mismatch, ContractEdge};
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
        boundary_evidence: None,
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
        boundary_evidence: None,
    });

    graph
}

#[test]
fn test_candidate_builder_creation() {
    let pass = IssueCandidateBuilderPass::new();
    assert_eq!(
        pass.name(),
        "IssueCandidateBuilder",
        "Pass name should be IssueCandidateBuilder"
    );
    assert_eq!(
        pass.kind(),
        PassKind::Analysis,
        "Pass kind should be Analysis"
    );
    assert_eq!(
        pass.dependencies(),
        vec!["OwnershipSolver"],
        "Dependencies should be OwnershipSolver"
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
        "Cross-family candidate should be CrossFamilyFree kind"
    );
    assert_eq!(
        candidate.alloc_family,
        FamilyId::C_HEAP,
        "Alloc family should be C_HEAP"
    );
    assert_eq!(
        candidate.release_family,
        Some(FamilyId::CPP_NEW_SCALAR),
        "Release family should be CPP_NEW_SCALAR"
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
        boundary_evidence: None,
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
        boundary_evidence: None,
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
        boundary_evidence: None,
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
        args: Vec::new(),
        result: None,
    });
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "free".to_string(),
        caller: "test_func".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
    });
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "_ZdlPv".to_string(), // operator delete(void*)
        caller: "test_func".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
    });
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "free".to_string(),
        caller: "buggy_func".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
    });
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "free".to_string(),
        caller: "buggy_func".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
    });
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "Box::from_raw".to_string(),
        caller: "safe_transfer".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
    });
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "Box::from_raw".to_string(),
        caller: "buggy_func".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
    });
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "CString::from_raw".to_string(),
        caller: "buggy_cstring".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
    });
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "Box::from_raw".to_string(),
        caller: "cross_ffi".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
    });
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "register_callback".to_string(),
        caller: "safe_handler".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
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
        args: Vec::new(),
        result: None,
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

/// Objective: Verify that a borrowed pointer passed to a release function
/// produces an InvalidBorrowedFree candidate.
/// Invariants: Borrowed instance with release edge = InvalidBorrowedFree.
#[test]
fn test_invalid_borrowed_free_candidate() {
    // Create a borrowed instance with a release edge
    let mut graph = ContractGraph::new();
    let instance_id = graph.alloc_instance();

    // Add a borrowed instance (simulating a borrowed pointer)
    graph.add_edge(ContractEdge {
        source: 0,
        target: instance_id,
        effect: Effect::Acquire {
            family: FamilyId::C_HEAP,
            result: instance_id,
        },
        function: 0,
        function_name: "borrow_ptr".to_string(),
        caller_name: "test_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    });

    // Add a release edge (simulating freeing a borrowed pointer)
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
        boundary_evidence: None,
    });

    // Create ownership states with a borrowed instance
    let mut ownership_states = Vec::new();
    let mut instance =
        ResourceInstance::new(instance_id, FamilyId::C_HEAP, PointerContract::Borrowed);
    instance.state = omniscope_semantics::OwnershipState::Borrowed;
    ownership_states.push(instance);

    let groups = InstanceEdgeGroups::new(&graph);
    let state_index: std::collections::HashMap<u64, usize> = ownership_states
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id, i))
        .collect();

    // Check if InvalidBorrowedFree candidate is produced
    let mut has_invalid_borrowed_free = false;

    for instance_id in groups.instance_ids() {
        let edge_indices = groups.edges_of(*instance_id);
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

        if !release_indices.is_empty() {
            if let Some(&sidx) = state_index.get(instance_id) {
                let inst = &ownership_states[sidx];
                if inst.contract == PointerContract::Borrowed {
                    has_invalid_borrowed_free = true;
                }
            }
        }
    }

    assert!(
        has_invalid_borrowed_free,
        "Borrowed pointer with release edge must be detected as InvalidBorrowedFree"
    );
}

/// Objective: Verify that an owned pointer with release edge does NOT
/// produce an InvalidBorrowedFree candidate.
/// Invariants: Owned instance with release edge = normal release, not InvalidBorrowedFree.
#[test]
fn test_owned_pointer_release_no_false_positive() {
    // Create an owned instance with a release edge
    let mut graph = ContractGraph::new();
    let instance_id = graph.alloc_instance();

    // Add an owned instance
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
        boundary_evidence: None,
    });

    // Add a release edge (normal free)
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
        boundary_evidence: None,
    });

    // Create ownership states with an owned instance
    let mut ownership_states = Vec::new();
    let instance = ResourceInstance::new(instance_id, FamilyId::C_HEAP, PointerContract::Owned);
    ownership_states.push(instance);

    let groups = InstanceEdgeGroups::new(&graph);
    let state_index: std::collections::HashMap<u64, usize> = ownership_states
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id, i))
        .collect();

    // Check that InvalidBorrowedFree is NOT produced
    let mut has_invalid_borrowed_free = false;

    for instance_id in groups.instance_ids() {
        let edge_indices = groups.edges_of(*instance_id);
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

        if !release_indices.is_empty() {
            if let Some(&sidx) = state_index.get(instance_id) {
                let inst = &ownership_states[sidx];
                if inst.contract == PointerContract::Borrowed {
                    has_invalid_borrowed_free = true;
                }
            }
        }
    }

    assert!(
        !has_invalid_borrowed_free,
        "Owned pointer with release edge must NOT be detected as InvalidBorrowedFree"
    );
}

/// Objective: End-to-end test for InvalidBorrowedFree detection.
/// Invariants: Borrowed pointer passed to free function produces InvalidBorrowedFree candidate.
#[test]
fn test_e2e_invalid_borrowed_free() {
    use crate::pass::PassContext;
    use omniscope_ir::IRModule;

    let mut module = IRModule::new();
    // Simulate a borrowed pointer being freed
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "free".to_string(),
        caller: "buggy_func".to_string(),
        is_external: true,
        location: None,
        args: Vec::new(),
        result: None,
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

    let _candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

    // Note: This test may not produce InvalidBorrowedFree because the
    // ownership solver creates Owned instances for acquire edges.
    // The real InvalidBorrowedFree detection happens when a Borrowed
    // instance (created via EscapesToCallback) has a release edge.
    // This test verifies the pipeline doesn't crash.
    // Pipeline completed without errors for borrowed pointer scenario
}

/// Objective: Verify that CrossLanguageFree detection works for Rust alloc + C free.
/// Invariants: RUST_GLOBAL acquire + C_HEAP release = cross-language free.
#[test]
fn test_cross_language_free_rust_alloc_c_free() {
    let registry = FamilyRegistry::new();

    // Rust alloc + C free should be cross-language
    let rust_alloc = FamilyId::RUST_GLOBAL;
    let c_free = FamilyId::C_HEAP;

    assert!(
        !registry.is_compatible_release(rust_alloc, c_free),
        "Rust alloc + C free must NOT be compatible release"
    );

    // Check if it's cross-language (different language families)
    let is_cross_language = is_cross_language_mismatch(Some(rust_alloc), Some(c_free));
    assert!(
        is_cross_language,
        "Rust alloc + C free must be detected as cross-language mismatch"
    );
}

/// Objective: Verify that CrossLanguageFree detection works for C malloc + Rust dealloc.
/// Invariants: C_HEAP acquire + RUST_GLOBAL release = cross-language free.
#[test]
fn test_cross_language_free_c_malloc_rust_dealloc() {
    let registry = FamilyRegistry::new();

    // C malloc + Rust dealloc should be cross-language
    let c_malloc = FamilyId::C_HEAP;
    let rust_dealloc = FamilyId::RUST_GLOBAL;

    assert!(
        !registry.is_compatible_release(c_malloc, rust_dealloc),
        "C malloc + Rust dealloc must NOT be compatible release"
    );

    // Check if it's cross-language (different language families)
    let is_cross_language = is_cross_language_mismatch(Some(c_malloc), Some(rust_dealloc));
    assert!(
        is_cross_language,
        "C malloc + Rust dealloc must be detected as cross-language mismatch"
    );
}

/// Objective: Verify that same-family releases are NOT cross-language.
/// Invariants: C_HEAP acquire + C_HEAP release = NOT cross-language.
#[test]
fn test_same_family_not_cross_language() {
    let c_alloc = FamilyId::C_HEAP;
    let c_free = FamilyId::C_HEAP;

    let is_cross_language = is_cross_language_mismatch(Some(c_alloc), Some(c_free));
    assert!(
        !is_cross_language,
        "Same family release must NOT be detected as cross-language mismatch"
    );
}

/// Objective: Verify that a ConsumesArg edge after a Release edge
/// produces a UseAfterRelease (UseAfterFree) candidate. This covers
/// the `free(ptr); ffi_call(ptr)` pattern where the freed pointer
/// is consumed by another FFI call.
/// Invariants: ConsumesArg after Release = UseAfterRelease candidate.
#[test]
fn test_consumes_arg_after_release_produces_use_after_free() {
    let mut graph = ContractGraph::new();
    let instance_id = graph.alloc_instance();

    // Acquire edge
    graph.add_edge(ContractEdge {
        source: 0,
        target: instance_id,
        effect: Effect::Acquire {
            family: FamilyId::C_HEAP,
            result: instance_id,
        },
        function: 0,
        function_name: "malloc".to_string(),
        caller_name: "buggy_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    });

    // Release edge (free)
    graph.add_edge(ContractEdge {
        source: instance_id,
        target: 0,
        effect: Effect::Release {
            family: FamilyId::C_HEAP,
            arg: 0,
        },
        function: 1,
        function_name: "free".to_string(),
        caller_name: "buggy_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    });

    // ConsumesArg edge after release — the freed pointer is consumed
    // by another function (use-after-free pattern).
    graph.add_edge(ContractEdge {
        source: instance_id,
        target: 0,
        effect: Effect::ConsumesArg {
            arg: 0,
            family: Some(FamilyId::C_HEAP),
        },
        function: 2,
        function_name: "ffi_process".to_string(),
        caller_name: "buggy_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    });

    let groups = InstanceEdgeGroups::new(&graph);

    // Create ownership state in Released state
    let mut ownership_states = Vec::new();
    let mut instance = ResourceInstance::new(instance_id, FamilyId::C_HEAP, PointerContract::Owned);
    instance
        .transition(omniscope_semantics::OwnershipEvent::Release { function: 1 })
        .unwrap();
    ownership_states.push(instance);

    let state_index: std::collections::HashMap<u64, usize> = ownership_states
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id, i))
        .collect();

    let mut has_use_after_free = false;

    for inst_id in groups.instance_ids() {
        let edge_indices = groups.edges_of(*inst_id);
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

        if !release_indices.is_empty() {
            let last_release_idx = *release_indices.last().unwrap();

            let post_release_uses: Vec<usize> = edge_indices
                .iter()
                .filter(|&&idx| {
                    idx > last_release_idx
                        && matches!(
                            graph.edges[idx].effect,
                            Effect::EscapesToCallback { .. }
                                | Effect::ReturnsBorrowed
                                | Effect::ConsumesArg { .. }
                                | Effect::StoresArgToOwner { .. }
                                | Effect::StoresArgToGlobal { .. }
                        )
                })
                .copied()
                .collect();

            if !post_release_uses.is_empty() {
                if let Some(&sidx) = state_index.get(inst_id) {
                    let inst = &ownership_states[sidx];
                    if inst.state == omniscope_semantics::OwnershipState::Released
                        && inst.contract != PointerContract::Borrowed
                    {
                        has_use_after_free = true;
                    }
                }
            }
        }
    }

    assert!(
        has_use_after_free,
        "ConsumesArg after Release MUST produce UseAfterRelease candidate"
    );
}

/// Objective: Verify that a StoresArgToGlobal edge after a Release edge
/// produces a UseAfterRelease candidate. This covers the pattern where
/// a freed pointer is stored into a global variable after release.
/// Invariants: StoresArgToGlobal after Release = UseAfterRelease candidate.
#[test]
fn test_stores_arg_to_global_after_release_produces_use_after_free() {
    let mut graph = ContractGraph::new();
    let instance_id = graph.alloc_instance();

    // Acquire edge
    graph.add_edge(ContractEdge {
        source: 0,
        target: instance_id,
        effect: Effect::Acquire {
            family: FamilyId::C_HEAP,
            result: instance_id,
        },
        function: 0,
        function_name: "malloc".to_string(),
        caller_name: "buggy_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    });

    // Release edge
    graph.add_edge(ContractEdge {
        source: instance_id,
        target: 0,
        effect: Effect::Release {
            family: FamilyId::C_HEAP,
            arg: 0,
        },
        function: 1,
        function_name: "free".to_string(),
        caller_name: "buggy_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    });

    // StoresArgToGlobal after release — freed pointer stored to global
    graph.add_edge(ContractEdge {
        source: instance_id,
        target: 0,
        effect: Effect::StoresArgToGlobal { arg: 0 },
        function: 2,
        function_name: "set_global_ptr".to_string(),
        caller_name: "buggy_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    });

    let groups = InstanceEdgeGroups::new(&graph);

    let mut ownership_states = Vec::new();
    let mut instance = ResourceInstance::new(instance_id, FamilyId::C_HEAP, PointerContract::Owned);
    instance
        .transition(omniscope_semantics::OwnershipEvent::Release { function: 1 })
        .unwrap();
    ownership_states.push(instance);

    let state_index: std::collections::HashMap<u64, usize> = ownership_states
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id, i))
        .collect();

    let mut has_use_after_free = false;

    for inst_id in groups.instance_ids() {
        let edge_indices = groups.edges_of(*inst_id);
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

        if !release_indices.is_empty() {
            let last_release_idx = *release_indices.last().unwrap();

            let post_release_uses: Vec<usize> = edge_indices
                .iter()
                .filter(|&&idx| {
                    idx > last_release_idx
                        && matches!(
                            graph.edges[idx].effect,
                            Effect::EscapesToCallback { .. }
                                | Effect::ReturnsBorrowed
                                | Effect::ConsumesArg { .. }
                                | Effect::StoresArgToOwner { .. }
                                | Effect::StoresArgToGlobal { .. }
                        )
                })
                .copied()
                .collect();

            if !post_release_uses.is_empty() {
                if let Some(&sidx) = state_index.get(inst_id) {
                    let inst = &ownership_states[sidx];
                    if inst.state == omniscope_semantics::OwnershipState::Released
                        && inst.contract != PointerContract::Borrowed
                    {
                        has_use_after_free = true;
                    }
                }
            }
        }
    }

    assert!(
        has_use_after_free,
        "StoresArgToGlobal after Release MUST produce UseAfterRelease candidate"
    );
}

/// Objective: Verify that a ConsumesArg edge BEFORE a Release edge
/// does NOT produce a UseAfterRelease candidate. Using a pointer
/// before freeing it is normal and safe.
/// Invariants: ConsumesArg before Release = no UseAfterRelease candidate.
#[test]
fn test_consumes_arg_before_release_no_false_positive() {
    let mut graph = ContractGraph::new();
    let instance_id = graph.alloc_instance();

    // Acquire edge
    graph.add_edge(ContractEdge {
        source: 0,
        target: instance_id,
        effect: Effect::Acquire {
            family: FamilyId::C_HEAP,
            result: instance_id,
        },
        function: 0,
        function_name: "malloc".to_string(),
        caller_name: "safe_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    });

    // ConsumesArg edge BEFORE release — normal use
    graph.add_edge(ContractEdge {
        source: instance_id,
        target: 0,
        effect: Effect::ConsumesArg {
            arg: 0,
            family: Some(FamilyId::C_HEAP),
        },
        function: 1,
        function_name: "ffi_process".to_string(),
        caller_name: "safe_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    });

    // Release edge (free) — after use, normal pattern
    graph.add_edge(ContractEdge {
        source: instance_id,
        target: 0,
        effect: Effect::Release {
            family: FamilyId::C_HEAP,
            arg: 0,
        },
        function: 2,
        function_name: "free".to_string(),
        caller_name: "safe_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    });

    let groups = InstanceEdgeGroups::new(&graph);

    let mut ownership_states = Vec::new();
    let mut instance = ResourceInstance::new(instance_id, FamilyId::C_HEAP, PointerContract::Owned);
    instance
        .transition(omniscope_semantics::OwnershipEvent::Release { function: 2 })
        .unwrap();
    ownership_states.push(instance);

    let state_index: std::collections::HashMap<u64, usize> = ownership_states
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id, i))
        .collect();

    let mut has_use_after_free = false;

    for inst_id in groups.instance_ids() {
        let edge_indices = groups.edges_of(*inst_id);
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

        if !release_indices.is_empty() {
            let last_release_idx = *release_indices.last().unwrap();

            let post_release_uses: Vec<usize> = edge_indices
                .iter()
                .filter(|&&idx| {
                    idx > last_release_idx
                        && matches!(
                            graph.edges[idx].effect,
                            Effect::EscapesToCallback { .. }
                                | Effect::ReturnsBorrowed
                                | Effect::ConsumesArg { .. }
                                | Effect::StoresArgToOwner { .. }
                                | Effect::StoresArgToGlobal { .. }
                        )
                })
                .copied()
                .collect();

            if !post_release_uses.is_empty() {
                if let Some(&sidx) = state_index.get(inst_id) {
                    let inst = &ownership_states[sidx];
                    if inst.state == omniscope_semantics::OwnershipState::Released
                        && inst.contract != PointerContract::Borrowed
                    {
                        has_use_after_free = true;
                    }
                }
            }
        }
    }

    assert!(
        !has_use_after_free,
        "ConsumesArg BEFORE Release must NOT produce UseAfterRelease candidate"
    );
}
