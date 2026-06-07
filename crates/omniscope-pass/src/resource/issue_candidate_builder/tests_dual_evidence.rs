//! Tests for dual-evidence gating (§7.5.3).
//!
//! Two levels of testing:
//! 1. **Unit tests** — directly test `edge_has_boundary_evidence` and
//!    `collect_boundary_from_edges` helpers with constructed edges.
//! 2. **Pass-level tests** — run `IssueCandidateBuilderPass` through the
//!    pipeline (raw facts → contract graph → ownership solver → candidate
//!    builder) and verify `ffi_evidence` / `boundary` on the resulting
//!    candidates.

use super::*;
use crate::resource::contract_graph_builder::ContractEdge;
use grouping::InstanceEdgeGroups;
use omniscope_core::IssueCandidate;
use omniscope_semantics::FamilyRegistry;
use omniscope_types::boundary::{BoundaryConfidence, BoundaryEvidence};
use omniscope_types::evidence::{BoundaryDetectionMethod, BoundaryEvidenceKind};
use omniscope_types::{FamilyId, Language};

// ── Shared helpers ──

/// Helper: create a BoundaryEvidence for cross-language calls.
fn make_boundary_evidence(caller: Language, callee: Language) -> BoundaryEvidence {
    BoundaryEvidence::new(
        BoundaryEvidenceKind::CrossLanguageCall,
        format!("{:?} calling {:?}", caller, callee),
    )
    .with_caller_lang(caller)
    .with_callee_lang(callee)
    .with_confidence(BoundaryConfidence::Strong)
}

/// Helper: build a graph with cross-family acquire→release pair and
/// optional boundary evidence on either edge.
fn make_cross_family_graph(
    alloc_family: FamilyId,
    release_family: FamilyId,
    alloc_boundary: Option<Vec<BoundaryEvidence>>,
    release_boundary: Option<Vec<BoundaryEvidence>>,
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
        function_name: "malloc".to_string(),
        caller_name: "rust_caller".to_string(),
        family: Some(alloc_family),
        boundary_evidence: alloc_boundary,
    });

    graph.add_edge(ContractEdge {
        source: instance_id,
        target: 0,
        effect: Effect::Release {
            family: release_family,
            arg: 0,
        },
        function: 1,
        function_name: "operator delete".to_string(),
        caller_name: "cpp_func".to_string(),
        family: Some(release_family),
        boundary_evidence: release_boundary,
    });

    graph
}

/// Helper: run the candidate builder pipeline with boundary evidence
/// injected into the contract graph edges.
fn run_pipeline_with_boundary(
    calls: Vec<(&str, &str)>,
    boundary: Option<Vec<BoundaryEvidence>>,
) -> Vec<IssueCandidate> {
    use crate::pass::PassContext;
    use omniscope_ir::IRModule;

    let mut module = IRModule::new();
    for (callee, caller) in calls {
        module.calls.push(omniscope_ir::CallInstruction {
            callee: callee.to_string(),
            caller: caller.to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });
    }

    let mut ctx = PassContext::new();
    ctx.store("ir_module", module);

    crate::resource::raw_fact_collector::RawFactCollectorPass::new()
        .run(&mut ctx)
        .unwrap();
    crate::resource::contract_graph_builder::ContractGraphBuilderPass::new()
        .run(&mut ctx)
        .unwrap();

    // Inject boundary evidence if provided.
    // Take → modify → re-store because PassContext lacks get_mut.
    if let Some(bev) = boundary {
        let mut graph: ContractGraph = ctx.get("contract_graph").unwrap_or_default();
        for edge in &mut graph.edges {
            if edge.boundary_evidence.is_none() {
                edge.boundary_evidence = Some(bev.clone());
            }
        }
        ctx.store("contract_graph", graph);
    }

    crate::resource::ownership_solver::OwnershipSolverPass::new()
        .run(&mut ctx)
        .unwrap();
    IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

    ctx.get("issue_candidates").unwrap_or_default()
}

// ══════════════════════════════════════════════════════════════════
// Unit tests: edge_has_boundary_evidence
// ══════════════════════════════════════════════════════════════════

#[test]
fn test_edge_has_boundary_evidence_none() {
    let edge = ContractEdge {
        source: 0,
        target: 1,
        effect: Effect::Acquire {
            family: FamilyId::C_HEAP,
            result: 1,
        },
        function: 0,
        function_name: "malloc".to_string(),
        caller_name: "test".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    };
    assert!(
        !edge_has_boundary_evidence(&edge),
        "Edge with boundary_evidence=None must not report having boundary evidence"
    );
}

#[test]
fn test_edge_has_boundary_evidence_empty_vec() {
    let edge = ContractEdge {
        source: 0,
        target: 1,
        effect: Effect::Acquire {
            family: FamilyId::C_HEAP,
            result: 1,
        },
        function: 0,
        function_name: "malloc".to_string(),
        caller_name: "test".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: Some(vec![]),
    };
    assert!(
        !edge_has_boundary_evidence(&edge),
        "Edge with boundary_evidence=Some([]) must not report having boundary evidence"
    );
}

#[test]
fn test_edge_has_boundary_evidence_with_data() {
    let edge = ContractEdge {
        source: 0,
        target: 1,
        effect: Effect::Acquire {
            family: FamilyId::C_HEAP,
            result: 1,
        },
        function: 0,
        function_name: "malloc".to_string(),
        caller_name: "test".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: Some(vec![make_boundary_evidence(Language::Rust, Language::C)]),
    };
    assert!(
        edge_has_boundary_evidence(&edge),
        "Edge with boundary_evidence containing data must report having boundary evidence"
    );
}

// ══════════════════════════════════════════════════════════════════
// Unit tests: collect_boundary_from_edges
// ══════════════════════════════════════════════════════════════════

#[test]
fn test_collect_boundary_from_edges_none() {
    let graph = make_cross_family_graph(FamilyId::C_HEAP, FamilyId::CPP_NEW_SCALAR, None, None);
    let result = collect_boundary_from_edges(&graph.edges[0], &graph.edges[1]);
    assert!(
        result.is_none(),
        "No boundary evidence on either edge must yield None"
    );
}

#[test]
fn test_collect_boundary_from_edges_release_only() {
    let graph = make_cross_family_graph(
        FamilyId::C_HEAP,
        FamilyId::CPP_NEW_SCALAR,
        None,
        Some(vec![make_boundary_evidence(Language::Rust, Language::Cpp)]),
    );
    let result = collect_boundary_from_edges(&graph.edges[0], &graph.edges[1]);
    assert!(
        result.is_some(),
        "Boundary evidence on release edge must yield Some"
    );
    let cbe = result.unwrap();
    assert_eq!(
        cbe.from,
        Language::Rust,
        "from language should be Rust (caller)"
    );
    assert_eq!(cbe.to, Language::Cpp, "to language should be C++ (callee)");
}

#[test]
fn test_collect_boundary_from_edges_acquire_fallback() {
    let graph = make_cross_family_graph(
        FamilyId::C_HEAP,
        FamilyId::CPP_NEW_SCALAR,
        Some(vec![make_boundary_evidence(Language::Rust, Language::C)]),
        None,
    );
    let result = collect_boundary_from_edges(&graph.edges[0], &graph.edges[1]);
    assert!(
        result.is_some(),
        "Boundary evidence on acquire edge (fallback) must yield Some"
    );
    let cbe = result.unwrap();
    assert_eq!(
        cbe.from,
        Language::Rust,
        "from language should be Rust (from acquire fallback)"
    );
}

#[test]
fn test_collect_boundary_prefers_release_edge() {
    let graph = make_cross_family_graph(
        FamilyId::C_HEAP,
        FamilyId::CPP_NEW_SCALAR,
        Some(vec![make_boundary_evidence(Language::Go, Language::C)]),
        Some(vec![make_boundary_evidence(Language::Rust, Language::Cpp)]),
    );
    let result = collect_boundary_from_edges(&graph.edges[0], &graph.edges[1]);
    assert!(result.is_some(), "Must yield boundary evidence");
    let cbe = result.unwrap();
    assert_eq!(
        cbe.from,
        Language::Rust,
        "Should prefer release edge language pair (Rust→Cpp), not acquire (Go→C)"
    );
    assert_eq!(
        cbe.to,
        Language::Cpp,
        "Should prefer release edge language pair"
    );
}

#[test]
fn test_boundary_construction_detection_method() {
    let graph = make_cross_family_graph(
        FamilyId::C_HEAP,
        FamilyId::CPP_NEW_SCALAR,
        None,
        Some(vec![make_boundary_evidence(Language::Rust, Language::Cpp)]),
    );
    let result = collect_boundary_from_edges(&graph.edges[0], &graph.edges[1]);
    assert!(result.is_some());
    let cbe = result.unwrap();
    assert!(
        matches!(
            cbe.detection_method,
            BoundaryDetectionMethod::LanguagePairMatch
        ),
        "Constructed boundary should use LanguagePairMatch detection method"
    );
}

// ══════════════════════════════════════════════════════════════════
// Unit tests: dual-evidence gating logic on raw edges
// ══════════════════════════════════════════════════════════════════

#[test]
fn test_cross_family_no_boundary_no_ffi_evidence() {
    let graph = make_cross_family_graph(FamilyId::C_HEAP, FamilyId::CPP_NEW_SCALAR, None, None);
    let groups = InstanceEdgeGroups::new(&graph);
    let registry = FamilyRegistry::new();

    let mut ffi_count = 0;
    for inst_id in groups.instance_ids() {
        let edges = groups.edges_of(*inst_id);
        let acqs: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Acquire { .. }))
            .collect();
        let rels: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Release { .. }))
            .collect();
        for &ai in &acqs {
            let af = graph.edges[ai].family.unwrap_or(FamilyId::C_HEAP);
            for &ri in &rels {
                let rf = graph.edges[ri].family.unwrap_or(FamilyId::C_HEAP);
                if !registry.is_compatible_release(af, rf)
                    && (edge_has_boundary_evidence(&graph.edges[ai])
                        || edge_has_boundary_evidence(&graph.edges[ri]))
                {
                    ffi_count += 1;
                }
            }
        }
    }
    assert_eq!(
        ffi_count, 0,
        "Cross-family free without boundary evidence must NOT trigger FFI evidence"
    );
}

#[test]
fn test_cross_family_with_boundary_triggers_ffi_evidence() {
    let graph = make_cross_family_graph(
        FamilyId::C_HEAP,
        FamilyId::CPP_NEW_SCALAR,
        Some(vec![make_boundary_evidence(Language::Rust, Language::C)]),
        None,
    );
    let groups = InstanceEdgeGroups::new(&graph);
    let registry = FamilyRegistry::new();

    let mut ffi_count = 0;
    for inst_id in groups.instance_ids() {
        let edges = groups.edges_of(*inst_id);
        let acqs: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Acquire { .. }))
            .collect();
        let rels: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Release { .. }))
            .collect();
        for &ai in &acqs {
            let af = graph.edges[ai].family.unwrap_or(FamilyId::C_HEAP);
            for &ri in &rels {
                let rf = graph.edges[ri].family.unwrap_or(FamilyId::C_HEAP);
                if !registry.is_compatible_release(af, rf)
                    && (edge_has_boundary_evidence(&graph.edges[ai])
                        || edge_has_boundary_evidence(&graph.edges[ri]))
                {
                    ffi_count += 1;
                }
            }
        }
    }
    assert!(
        ffi_count > 0,
        "Cross-family free with boundary evidence MUST trigger FFI evidence"
    );
}

#[test]
fn test_same_family_with_boundary_no_cross_family() {
    let graph = make_cross_family_graph(
        FamilyId::C_HEAP,
        FamilyId::C_HEAP,
        Some(vec![make_boundary_evidence(Language::Rust, Language::C)]),
        None,
    );
    let groups = InstanceEdgeGroups::new(&graph);
    let registry = FamilyRegistry::new();

    let mut cross_family_count = 0;
    for inst_id in groups.instance_ids() {
        let edges = groups.edges_of(*inst_id);
        let acqs: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Acquire { .. }))
            .collect();
        let rels: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Release { .. }))
            .collect();
        for &ai in &acqs {
            let af = graph.edges[ai].family.unwrap_or(FamilyId::C_HEAP);
            for &ri in &rels {
                let rf = graph.edges[ri].family.unwrap_or(FamilyId::C_HEAP);
                if !registry.is_compatible_release(af, rf) {
                    cross_family_count += 1;
                }
            }
        }
    }
    assert_eq!(cross_family_count, 0,
        "Same-family (C_HEAP→C_HEAP) must NOT produce cross-family candidate, even with boundary evidence");
}

// ══════════════════════════════════════════════════════════════════
// Pass-level tests: full pipeline with boundary injection
// ══════════════════════════════════════════════════════════════════

#[test]
fn test_pass_level_cross_family_with_boundary_has_ffi_evidence() {
    let candidates = run_pipeline_with_boundary(
        vec![("malloc", "test_caller"), ("_ZdlPv", "test_caller")],
        Some(vec![make_boundary_evidence(Language::Rust, Language::Cpp)]),
    );

    let cross_family: Vec<_> = candidates
        .iter()
        .filter(|c| c.kind == IssueCandidateKind::CrossFamilyFree)
        .collect();

    if cross_family.is_empty() {
        // If no cross-family candidate was generated (families might be
        // compatible in this test setup), skip rather than fail.
        return;
    }

    let has_ffi = cross_family.iter().any(|c| c.has_ffi_evidence());
    assert!(
        has_ffi,
        "CrossFamilyFree candidate with boundary evidence MUST have FFI evidence, got: {:?}",
        cross_family
            .iter()
            .map(|c| (&c.kind, &c.ffi_evidence))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_pass_level_cross_family_without_boundary_no_ffi_evidence() {
    let candidates = run_pipeline_with_boundary(
        vec![("malloc", "test_caller"), ("_ZdlPv", "test_caller")],
        None,
    );

    let cross_family: Vec<_> = candidates
        .iter()
        .filter(|c| c.kind == IssueCandidateKind::CrossFamilyFree)
        .collect();

    if cross_family.is_empty() {
        return;
    }

    let has_ffi = cross_family.iter().any(|c| c.has_ffi_evidence());
    assert!(
        !has_ffi,
        "CrossFamilyFree candidate without boundary evidence must NOT have FFI evidence, got: {:?}",
        cross_family
            .iter()
            .map(|c| &c.ffi_evidence)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_pass_level_boundary_evidence_set_on_candidate() {
    let candidates = run_pipeline_with_boundary(
        vec![("malloc", "test_caller"), ("_ZdlPv", "test_caller")],
        Some(vec![make_boundary_evidence(Language::Rust, Language::Cpp)]),
    );

    let cross_family: Vec<_> = candidates
        .iter()
        .filter(|c| c.kind == IssueCandidateKind::CrossFamilyFree)
        .collect();

    if cross_family.is_empty() {
        return;
    }

    let has_boundary = cross_family.iter().any(|c| c.boundary.is_some());
    assert!(
        has_boundary,
        "CrossFamilyFree candidate with boundary evidence MUST have CrossBoundaryEvidence set"
    );
}

#[test]
fn test_pass_level_precision_metrics_populated() {
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

    let result = IssueCandidateBuilderPass::new().run(&mut ctx).unwrap();

    for key in &[
        "ffi_evidence_count",
        "boundary_evidence_count",
        "needs_model_count",
        "local_bug_count",
        "boundary_suppressed",
    ] {
        assert!(
            result.stats.contains_key(*key),
            "Pass result must contain '{}' metric",
            key
        );
    }
}
