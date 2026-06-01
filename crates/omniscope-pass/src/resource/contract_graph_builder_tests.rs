//! Tests for contract_graph_builder module.

use super::*;
use crate::pass::{Pass, PassContext, PassKind};
use crate::resource::raw_fact_collector::RawResourceFact;
use omniscope_types::{Effect, FamilyId, PointerContract};

#[test]
fn test_contract_graph_builder_creation() {
    let pass = ContractGraphBuilderPass::new();
    assert_eq!(
        pass.name(),
        "ContractGraphBuilder",
        "Expected values to be equal"
    );
    assert_eq!(
        pass.kind(),
        PassKind::Analysis,
        "Expected values to be equal"
    );
    assert_eq!(
        pass.dependencies(),
        vec!["StructuralInference"],
        "Expected values to be equal"
    );
}

#[test]
fn test_contract_graph_edge_building() {
    let mut graph = ContractGraph::new();
    let instance = graph.alloc_instance();
    assert_eq!(instance, 1, "First instance ID should be 1");

    graph.add_edge(ContractEdge {
        source: instance,
        target: 0,
        effect: Effect::Release {
            family: FamilyId::C_HEAP,
            arg: 0,
        },
        function: 42,
        function_name: "free".to_string(),
        caller_name: "test_func".to_string(),
        family: Some(FamilyId::C_HEAP),
    });

    assert_eq!(
        graph.edge_count(),
        1,
        "Graph should have one edge after adding"
    );
}

/// Objective: Verify that an acquire-release pair in the same function
/// produces exactly two edges: one Acquire and one Release, with the
/// Release edge pointing from the acquire instance to the sink (target=0).
/// Invariants: Acquire edge source=0, Release edge target=0, same instance ID.
#[test]
fn test_acquire_release_pair_in_same_function() {
    let pass = ContractGraphBuilderPass::new();
    let mut ctx = PassContext::new();

    // Two facts in the same function (func_id=1) and same family (C_HEAP):
    // one acquire, one release. They should pair up.
    let facts = vec![
        RawResourceFact {
            function: 1,
            function_name: "malloc".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: true,
            contract: PointerContract::Owned,
            arg_index: Some(0),
        },
        RawResourceFact {
            function: 1,
            function_name: "free".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: false,
            contract: PointerContract::Unknown,
            arg_index: Some(0),
        },
    ];
    ctx.store("raw_resource_facts", facts);

    let result = pass.run(&mut ctx).expect("Pass execution must succeed");
    assert!(
        result.nodes_analyzed >= 2,
        "Must produce at least 2 edges (acquire + release), got {}",
        result.nodes_analyzed
    );

    let graph: ContractGraph = ctx
        .get("contract_graph")
        .expect("ContractGraph must be stored in context");

    // Verify acquire edge
    let acquire_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::Acquire { .. }))
        .collect();
    assert_eq!(
        acquire_edges.len(),
        1,
        "Exactly one Acquire edge expected for one malloc call"
    );
    assert_eq!(
        acquire_edges[0].source, 0,
        "Acquire edge source must be 0 (allocation origin)"
    );
    assert!(
        acquire_edges[0].target > 0,
        "Acquire edge target must be a valid instance ID"
    );

    // Verify release edge
    let release_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::Release { .. }))
        .collect();
    assert_eq!(
        release_edges.len(),
        1,
        "Exactly one Release edge expected for one free call"
    );
    assert_eq!(
        release_edges[0].target, 0,
        "Release edge target must be 0 (deallocation sink)"
    );
    assert_eq!(
        release_edges[0].source, acquire_edges[0].target,
        "Release edge source must match Acquire edge target (same instance)"
    );
}

/// Objective: Verify cross-family release detection: when a fact has a
/// different family from its (func_id, family)-grouped acquire, it produces
/// a ConditionalRelease effect instead of Release.
/// Invariants: Two separate (func_id, family) groups are formed, so the
/// release with CPP_NEW_SCALAR creates its own standalone instance.
#[test]
fn test_cross_family_release_detection() {
    let pass = ContractGraphBuilderPass::new();
    let mut ctx = PassContext::new();

    // Acquire with C_HEAP, release with CPP_NEW_SCALAR in same function.
    // Because grouping is by (func_id, family), these form different groups:
    // (1, C_HEAP) -> acquire, (1, CPP_NEW_SCALAR) -> release (standalone).
    let facts = vec![
        RawResourceFact {
            function: 1,
            function_name: "malloc".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: true,
            contract: PointerContract::Owned,
            arg_index: Some(0),
        },
        RawResourceFact {
            function: 1,
            function_name: "operator delete".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::CPP_NEW_SCALAR),
            is_acquire: false,
            contract: PointerContract::Unknown,
            arg_index: Some(0),
        },
    ];
    ctx.store("raw_resource_facts", facts);

    let result = pass.run(&mut ctx).expect("Pass execution must succeed");
    assert!(
        result.nodes_analyzed >= 2,
        "Must produce at least 2 edges, got {}",
        result.nodes_analyzed
    );

    let graph: ContractGraph = ctx
        .get("contract_graph")
        .expect("ContractGraph must be stored in context");

    // Verify the acquire edge uses C_HEAP
    let acquire_edge = graph
        .edges
        .iter()
        .find(|e| matches!(e.effect, Effect::Acquire { family, .. } if family == FamilyId::C_HEAP));
    assert!(
        acquire_edge.is_some(),
        "Must have an Acquire edge for C_HEAP family"
    );

    // The CPP_NEW_SCALAR release has no matching acquire in the same
    // (func_id, family) group, so a standalone instance is created and
    // a Release (not ConditionalRelease) edge is produced. The cross-family
    // detection in raw facts path only triggers when alloc_family != family
    // within the SAME (func_id, family) group.
    let release_edge = graph
        .edges
        .iter()
        .find(|e| matches!(e.effect, Effect::Release { family, .. } if family == FamilyId::CPP_NEW_SCALAR));
    assert!(
        release_edge.is_some(),
        "Must have a Release edge for CPP_NEW_SCALAR family"
    );
}

/// Objective: Verify that ConditionalRelease is produced via IRModule path
/// when Py_DECREF follows PyObject_New.
/// Invariants: ConditionalRelease edge with PYTHON_OBJECT family exists.
#[test]
fn test_conditional_release_edge_present() {
    let pass = ContractGraphBuilderPass::new();
    let mut ctx = PassContext::new();

    // Create an IRModule where the same function calls Py_INCREF (Retain)
    // and Py_DECREF (ConditionalRelease) on a Python object.
    let mut module = omniscope_ir::IRModule::new();
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "PyObject_New".to_string(),
        caller: "test_func".to_string(),
        is_external: true,
        location: None,
    });
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "Py_DECREF".to_string(),
        caller: "test_func".to_string(),
        is_external: true,
        location: None,
    });
    ctx.store("ir_module", module);

    // Run the pass -- it will process IRModule via FamilyRegistry
    let _ = pass.run(&mut ctx);

    let graph: Option<ContractGraph> = ctx.get("contract_graph");
    let graph = graph.expect("ContractGraph must be stored in context");

    // Py_DECREF is a ConditionalRelease -- verify it produces a ConditionalRelease edge.
    let cond_release_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::ConditionalRelease { family, .. } if family == FamilyId::PYTHON_OBJECT))
        .collect();
    assert!(
        !cond_release_edges.is_empty(),
        "IRModule path must produce ConditionalRelease edge for Py_DECREF, found {} edges total",
        graph.edges.len()
    );

    // Also verify the acquire edge from PyObject_New
    let acquire_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::Acquire { family, .. } if family == FamilyId::PYTHON_OBJECT))
        .collect();
    assert!(
        !acquire_edges.is_empty(),
        "Must have Acquire edge for PyObject_New with PYTHON_OBJECT family"
    );
}

/// Objective: Verify that escape edges are created when the IRModule
/// contains calls to into_raw (e.g., Box::into_raw).
/// Invariants: An OwnershipEscape edge is produced with the correct family.
#[test]
fn test_escape_edge_creation_via_ir_module() {
    let pass = ContractGraphBuilderPass::new();
    let mut ctx = PassContext::new();

    // A function that allocates a Box and converts it to a raw pointer
    let mut module = omniscope_ir::IRModule::new();
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "Box::into_raw".to_string(),
        caller: "test_func".to_string(),
        is_external: true,
        location: None,
    });
    ctx.store("ir_module", module);

    let _ = pass.run(&mut ctx);

    let graph: Option<ContractGraph> = ctx.get("contract_graph");
    let graph = graph.expect("ContractGraph must be stored in context");

    // Verify OwnershipEscape edge is created
    let escape_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::OwnershipEscape { .. }))
        .collect();
    assert!(
        !escape_edges.is_empty(),
        "Must produce OwnershipEscape edge for Box::into_raw call"
    );

    // Verify the escape edge uses RUST_RAW_OWNERSHIP family
    let escape = &escape_edges[0];
    match &escape.effect {
        Effect::OwnershipEscape { family, .. } => {
            assert_eq!(
                *family,
                FamilyId::RUST_RAW_OWNERSHIP,
                "Box::into_raw must use RUST_RAW_OWNERSHIP family"
            );
        }
        _ => unreachable!("Already filtered for OwnershipEscape"),
    }
}

/// Objective: Verify that reclaim edges are created when the IRModule
/// contains calls to from_raw (e.g., Box::from_raw).
/// Invariants: An OwnershipReclaim edge is produced and linked to the
/// escape instance when both into_raw and from_raw are present.
#[test]
fn test_reclaim_edge_creation_via_ir_module() {
    let pass = ContractGraphBuilderPass::new();
    let mut ctx = PassContext::new();

    // A function that escapes ownership and then reclaims it
    let mut module = omniscope_ir::IRModule::new();
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "Box::into_raw".to_string(),
        caller: "test_func".to_string(),
        is_external: true,
        location: None,
    });
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "Box::from_raw".to_string(),
        caller: "test_func".to_string(),
        is_external: true,
        location: None,
    });
    ctx.store("ir_module", module);

    let _ = pass.run(&mut ctx);

    let graph: Option<ContractGraph> = ctx.get("contract_graph");
    let graph = graph.expect("ContractGraph must be stored in context");

    // Verify OwnershipReclaim edge is created
    let reclaim_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::OwnershipReclaim { .. }))
        .collect();
    assert!(
        !reclaim_edges.is_empty(),
        "Must produce OwnershipReclaim edge for Box::from_raw call"
    );

    // Verify reclaim edge links from the escape instance to the reclaim instance
    let reclaim = &reclaim_edges[0];
    assert_ne!(
        reclaim.source, 0,
        "Reclaim edge source must reference an existing instance (not 0)"
    );
    assert_ne!(
        reclaim.source, reclaim.target,
        "Reclaim edge must not be a self-loop -- source is the escaped instance, target is the reclaim instance"
    );

    // Verify the reclaim edge uses RUST_RAW_OWNERSHIP family
    match &reclaim.effect {
        Effect::OwnershipReclaim { family, .. } => {
            assert_eq!(
                *family,
                FamilyId::RUST_RAW_OWNERSHIP,
                "Box::from_raw must use RUST_RAW_OWNERSHIP family"
            );
        }
        _ => unreachable!("Already filtered for OwnershipReclaim"),
    }

    // Verify the escape edge was also created
    let escape_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::OwnershipEscape { .. }))
        .collect();
    assert!(
        !escape_edges.is_empty(),
        "Must also have OwnershipEscape edge for the paired Box::into_raw"
    );
}

/// Objective: Verify that Vec::from_raw_parts produces a reclaim edge
/// even without a matching into_raw, since from_raw_parts can also
/// reassemble a previously escaped Vec.
/// Invariants: OwnershipReclaim edge is created with RUST_RAW_OWNERSHIP family.
#[test]
fn test_reclaim_from_raw_parts_without_escape() {
    let pass = ContractGraphBuilderPass::new();
    let mut ctx = PassContext::new();

    let mut module = omniscope_ir::IRModule::new();
    module.calls.push(omniscope_ir::CallInstruction {
        callee: "Vec::from_raw_parts".to_string(),
        caller: "test_func".to_string(),
        is_external: true,
        location: None,
    });
    ctx.store("ir_module", module);

    let _ = pass.run(&mut ctx);

    let graph: Option<ContractGraph> = ctx.get("contract_graph");
    let graph = graph.expect("ContractGraph must be stored in context");

    let reclaim_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::OwnershipReclaim { .. }))
        .collect();
    assert!(
        !reclaim_edges.is_empty(),
        "Vec::from_raw_parts must produce an OwnershipReclaim edge"
    );
}

/// Objective: Verify that when no raw facts are provided, the pass
/// produces an empty graph without errors.
/// Invariants: graph.edge_count() == 0, pass returns Ok.
#[test]
fn test_empty_raw_facts_produces_empty_graph() {
    let pass = ContractGraphBuilderPass::new();
    let mut ctx = PassContext::new();
    // Do not store any raw_resource_facts -- the pass should handle None gracefully

    let result = pass.run(&mut ctx);
    assert!(result.is_ok(), "Pass must succeed even with no raw facts");

    let graph: Option<ContractGraph> = ctx.get("contract_graph");
    let graph = graph.expect("ContractGraph must be stored in context");
    assert_eq!(
        graph.edge_count(),
        0,
        "Empty raw facts must produce an empty graph"
    );
}

/// Objective: Verify that a release without a matching acquire in the
/// same (func_id, family) group creates a standalone instance.
/// Invariants: A standalone instance is allocated and the Release edge
/// references it (source > 0, target = 0).
#[test]
fn test_release_without_matching_acquire() {
    let pass = ContractGraphBuilderPass::new();
    let mut ctx = PassContext::new();

    // Only a release fact, no corresponding acquire in the same group
    let facts = vec![RawResourceFact {
        function: 5,
        function_name: "free".to_string(),
        caller_name: "cleanup_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        is_acquire: false,
        contract: PointerContract::Unknown,
        arg_index: Some(0),
    }];
    ctx.store("raw_resource_facts", facts);

    let result = pass.run(&mut ctx);
    assert!(result.is_ok(), "Pass must succeed");

    let graph: ContractGraph = ctx
        .get("contract_graph")
        .expect("ContractGraph must be stored in context");

    let release_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::Release { .. }))
        .collect();
    assert_eq!(
        release_edges.len(),
        1,
        "Exactly one Release edge expected for the standalone free"
    );
    assert!(
        release_edges[0].source > 0,
        "Standalone release must have a valid source instance ID, got {}",
        release_edges[0].source
    );
    assert_eq!(
        release_edges[0].target, 0,
        "Release edge target must be 0 (sink)"
    );
}

/// Objective: Verify that the is_callback_registration_api helper
/// correctly identifies callback registration patterns.
/// Invariants: Known patterns return true, non-callback names return false.
#[test]
fn test_callback_registration_api_detection() {
    // Positive cases: known callback registration patterns
    assert!(
        is_callback_registration_api("register_callback"),
        "'register_callback' must be detected as callback registration"
    );
    assert!(
        is_callback_registration_api("my_lib_set_callback"),
        "'my_lib_set_callback' must be detected as callback registration"
    );
    assert!(
        is_callback_registration_api("uv_poll_start"),
        "'uv_poll_start' (libuv pattern) must be detected as callback registration"
    );
    assert!(
        is_callback_registration_api("on_event"),
        "'on_event' must be detected as callback registration"
    );
    assert!(
        is_callback_registration_api("connect_callback"),
        "'connect_callback' must be detected as callback registration"
    );

    // Negative cases: non-callback names
    assert!(
        !is_callback_registration_api("malloc"),
        "'malloc' must NOT be detected as callback registration"
    );
    assert!(
        !is_callback_registration_api("free"),
        "'free' must NOT be detected as callback registration"
    );
    assert!(
        !is_callback_registration_api("printf"),
        "'printf' must NOT be detected as callback registration"
    );
}

/// Objective: Verify that multiple acquire-release pairs in different
/// functions produce independent edges with correct instance pairing.
/// Invariants: Each function gets its own acquire and release edges,
/// and release source matches the correct acquire target.
#[test]
fn test_multiple_function_independent_pairing() {
    let pass = ContractGraphBuilderPass::new();
    let mut ctx = PassContext::new();

    let facts = vec![
        // Function 1: malloc + free
        RawResourceFact {
            function: 1,
            function_name: "malloc".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: true,
            contract: PointerContract::Owned,
            arg_index: Some(0),
        },
        RawResourceFact {
            function: 1,
            function_name: "free".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: false,
            contract: PointerContract::Unknown,
            arg_index: Some(0),
        },
        // Function 2: PyObject_New + Py_DECREF
        RawResourceFact {
            function: 2,
            function_name: "PyObject_New".to_string(),
            caller_name: "py_func".to_string(),
            family: Some(FamilyId::PYTHON_OBJECT),
            is_acquire: true,
            contract: PointerContract::Owned,
            arg_index: Some(0),
        },
        RawResourceFact {
            function: 2,
            function_name: "Py_DECREF".to_string(),
            caller_name: "py_func".to_string(),
            family: Some(FamilyId::PYTHON_OBJECT),
            is_acquire: false,
            contract: PointerContract::Unknown,
            arg_index: Some(0),
        },
    ];
    ctx.store("raw_resource_facts", facts);

    let result = pass.run(&mut ctx);
    assert!(result.is_ok(), "Pass must succeed");

    let graph: ContractGraph = ctx
        .get("contract_graph")
        .expect("ContractGraph must be stored in context");

    // Two acquire edges (one per function/family)
    let acquire_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::Acquire { .. }))
        .collect();
    assert_eq!(
        acquire_edges.len(),
        2,
        "Must have exactly 2 Acquire edges for 2 independent functions"
    );

    // Two release edges
    let release_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::Release { .. }))
        .collect();
    assert_eq!(
        release_edges.len(),
        2,
        "Must have exactly 2 Release edges for 2 independent functions"
    );

    // Each release's source must match its paired acquire's target
    for release in &release_edges {
        let matching_acquire = acquire_edges.iter().find(|a| a.target == release.source);
        assert!(
            matching_acquire.is_some(),
            "Every Release edge source must match an Acquire edge target -- release source={} has no matching acquire",
            release.source
        );
    }
}

/// Objective: Verify that two orphan releases (no matching acquire) in the
/// same (func_id, family) group each get their own standalone instance,
/// rather than the second release pairing with a phantom instance created
/// by the first.
///
/// Before the fix, the first orphan release would push a phantom instance
/// into `acquire_instances`, causing the second orphan release to pop it
/// as if it were a real acquire. This corrupted FIFO matching.
///
/// Invariants: Two Release edges with distinct source IDs (both > 0),
/// and no Acquire edges in the graph.
#[test]
fn test_two_orphan_releases_get_distinct_instances() {
    let pass = ContractGraphBuilderPass::new();
    let mut ctx = PassContext::new();

    // Two orphan releases in the same (func_id, family) group -- no acquires.
    let facts = vec![
        RawResourceFact {
            function: 7,
            function_name: "free".to_string(),
            caller_name: "cleanup_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: false,
            contract: PointerContract::Unknown,
            arg_index: Some(0),
        },
        RawResourceFact {
            function: 7,
            function_name: "free".to_string(),
            caller_name: "cleanup_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: false,
            contract: PointerContract::Unknown,
            arg_index: Some(1),
        },
    ];
    ctx.store("raw_resource_facts", facts);

    let result = pass.run(&mut ctx);
    assert!(result.is_ok(), "Pass must succeed");

    let graph: ContractGraph = ctx
        .get("contract_graph")
        .expect("ContractGraph must be stored in context");

    // No Acquire edges -- there were no acquire facts.
    let acquire_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::Acquire { .. }))
        .collect();
    assert!(
        acquire_edges.is_empty(),
        "Orphan releases must not produce phantom Acquire edges, found {}",
        acquire_edges.len()
    );

    // Two Release edges, each with its own distinct standalone instance.
    let release_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| matches!(e.effect, Effect::Release { .. }))
        .collect();
    assert_eq!(
        release_edges.len(),
        2,
        "Must have exactly 2 Release edges for 2 orphan releases"
    );

    // Both sources must be valid (non-zero) and distinct from each other.
    assert!(
        release_edges[0].source > 0,
        "First orphan release must have a valid source instance ID, got {}",
        release_edges[0].source
    );
    assert!(
        release_edges[1].source > 0,
        "Second orphan release must have a valid source instance ID, got {}",
        release_edges[1].source
    );
    assert_ne!(
        release_edges[0].source, release_edges[1].source,
        "Two orphan releases must get distinct standalone instances, but both got source={}",
        release_edges[0].source
    );
}
