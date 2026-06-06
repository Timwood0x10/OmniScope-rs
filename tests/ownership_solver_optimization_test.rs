//! Test for ownership solver optimization with Union-Find.
//!
//! This test verifies that the ownership solver correctly handles
//! escape-reclaim cycles with the new Union-Find optimization.

use omniscope_pass::resource::contract_graph_builder::ContractGraph;
use omniscope_pass::resource::ownership_solver::OwnershipSolverPass;
use omniscope_pass::resource::union_find::OwnershipCycleDetector;
use omniscope_pass::{ContractEdge, Pass, PassContext};
use omniscope_semantics::ResourceInstance;
use omniscope_types::{Effect, FamilyId};

/// Objective: Verify that ownership solver correctly handles escape-reclaim cycles.
/// Invariants: After escape-reclaim cycle, instance is in Released state.
#[test]
fn test_ownership_solver_escape_reclaim_optimization() {
    let mut ctx = PassContext::new();

    // Build a contract graph with escape-reclaim cycle
    let mut graph = ContractGraph::new();
    let acquire_id = graph.alloc_instance();
    let escape_id = graph.alloc_instance();
    let reclaim_id = graph.alloc_instance();

    // Acquire
    graph.add_edge(ContractEdge {
        source: 0,
        target: acquire_id,
        effect: Effect::Acquire {
            family: FamilyId::RUST_GLOBAL,
            result: acquire_id,
        },
        function: 1,
        function_name: "__rust_alloc".to_string(),
        caller_name: "box_new".to_string(),
        family: Some(FamilyId::RUST_GLOBAL),
        boundary_evidence: None,
    });

    // Escape (into_raw)
    graph.add_edge(ContractEdge {
        source: acquire_id,
        target: 0,
        effect: Effect::OwnershipEscape {
            family: FamilyId::RUST_GLOBAL,
            result: escape_id,
        },
        function: 2,
        function_name: "into_raw".to_string(),
        caller_name: "box_new".to_string(),
        family: Some(FamilyId::RUST_GLOBAL),
        boundary_evidence: None,
    });

    // Reclaim (from_raw)
    graph.add_edge(ContractEdge {
        source: acquire_id,
        target: reclaim_id,
        effect: Effect::OwnershipReclaim {
            family: FamilyId::RUST_GLOBAL,
            result: reclaim_id,
        },
        function: 3,
        function_name: "from_raw".to_string(),
        caller_name: "box_new".to_string(),
        family: Some(FamilyId::RUST_GLOBAL),
        boundary_evidence: None,
    });

    // Final release of reclaimed instance
    graph.add_edge(ContractEdge {
        source: reclaim_id,
        target: 0,
        effect: Effect::Release {
            family: FamilyId::RUST_GLOBAL,
            arg: 0,
        },
        function: 4,
        function_name: "__rust_dealloc".to_string(),
        caller_name: "box_new".to_string(),
        family: Some(FamilyId::RUST_GLOBAL),
        boundary_evidence: None,
    });

    ctx.store("contract_graph", graph);

    // Run the solver
    let pass = OwnershipSolverPass::new();
    let result = pass.run(&mut ctx).unwrap();

    // Verify results
    assert_eq!(
        result.nodes_analyzed, 2,
        "Must have 2 instances (original + reclaimed)"
    );

    let states = ctx
        .get_ref::<Vec<ResourceInstance>>("ownership_states")
        .expect("ownership_states must be stored");

    // Find the original and reclaimed instances
    let original = states
        .iter()
        .find(|i| i.id == acquire_id)
        .expect("Original instance must exist");
    let reclaimed = states
        .iter()
        .find(|i| i.id == reclaim_id)
        .expect("Reclaimed instance must exist");

    // Original should be Released (after reclaim)
    assert_eq!(
        original.state,
        omniscope_semantics::OwnershipState::Released,
        "Original instance must be Released after reclaim"
    );

    // Reclaimed should be Released (after final release)
    assert_eq!(
        reclaimed.state,
        omniscope_semantics::OwnershipState::Released,
        "Reclaimed instance must be Released after final release"
    );
}

/// Objective: Verify that Union-Find cycle detector correctly tracks escape-reclaim cycles.
/// Invariants: After escape-reclaim, instances are connected.
#[test]
fn test_union_find_cycle_detection() {
    let mut detector = OwnershipCycleDetector::new();

    // Register instances
    detector.register_instance(1);
    detector.register_instance(2);

    // Record escape: instance 1 escapes to raw pointer 100
    detector.record_escape(1, 100);
    assert!(
        detector.is_in_cycle(&1),
        "Instance 1 must be in cycle after escape"
    );

    // Record reclaim: instance 1 reclaimed as instance 2
    detector.record_reclaim(1, 2);
    assert!(
        detector.is_in_cycle(&2),
        "Instance 2 must be in cycle after reclaim"
    );

    // Instances must be connected
    assert!(
        detector.are_connected(1, 2),
        "Instances must be connected through escape-reclaim"
    );
}

/// Objective: Verify that ownership solver handles multiple escape-reclaim cycles efficiently.
/// Invariants: All cycles are processed correctly.
#[test]
fn test_ownership_solver_multiple_escape_reclaim_cycles() {
    let mut ctx = PassContext::new();

    // Build a contract graph with multiple escape-reclaim cycles
    let mut graph = ContractGraph::new();

    for _ in 0..10 {
        let acquire_id = graph.alloc_instance();
        let escape_id = graph.alloc_instance();
        let reclaim_id = graph.alloc_instance();

        // Acquire
        graph.add_edge(ContractEdge {
            source: 0,
            target: acquire_id,
            effect: Effect::Acquire {
                family: FamilyId::RUST_GLOBAL,
                result: acquire_id,
            },
            function: 1,
            function_name: "__rust_alloc".to_string(),
            caller_name: "box_new".to_string(),
            family: Some(FamilyId::RUST_GLOBAL),
            boundary_evidence: None,
        });

        // Escape (into_raw)
        graph.add_edge(ContractEdge {
            source: acquire_id,
            target: 0,
            effect: Effect::OwnershipEscape {
                family: FamilyId::RUST_GLOBAL,
                result: escape_id,
            },
            function: 2,
            function_name: "into_raw".to_string(),
            caller_name: "box_new".to_string(),
            family: Some(FamilyId::RUST_GLOBAL),
            boundary_evidence: None,
        });

        // Reclaim (from_raw)
        graph.add_edge(ContractEdge {
            source: acquire_id,
            target: reclaim_id,
            effect: Effect::OwnershipReclaim {
                family: FamilyId::RUST_GLOBAL,
                result: reclaim_id,
            },
            function: 3,
            function_name: "from_raw".to_string(),
            caller_name: "box_new".to_string(),
            family: Some(FamilyId::RUST_GLOBAL),
            boundary_evidence: None,
        });

        // Final release of reclaimed instance
        graph.add_edge(ContractEdge {
            source: reclaim_id,
            target: 0,
            effect: Effect::Release {
                family: FamilyId::RUST_GLOBAL,
                arg: 0,
            },
            function: 4,
            function_name: "__rust_dealloc".to_string(),
            caller_name: "box_new".to_string(),
            family: Some(FamilyId::RUST_GLOBAL),
            boundary_evidence: None,
        });
    }

    ctx.store("contract_graph", graph);

    // Run the solver
    let pass = OwnershipSolverPass::new();
    let result = pass.run(&mut ctx).unwrap();

    // Verify results
    assert_eq!(
        result.nodes_analyzed, 20,
        "Must have 20 instances (10 original + 10 reclaimed)"
    );

    let states = ctx
        .get_ref::<Vec<ResourceInstance>>("ownership_states")
        .expect("ownership_states must be stored");

    // All instances should be Released
    for instance in states {
        assert_eq!(
            instance.state,
            omniscope_semantics::OwnershipState::Released,
            "Instance {} must be Released",
            instance.id
        );
    }
}
