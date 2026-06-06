//! Tests for dual-evidence gating (§7.5.3).
//!
//! Verifies that FFI evidence is only set when BOTH boundary evidence AND
//! resource evidence exist. Cross-family mismatch alone → no FFI evidence;
//! boundary evidence alone → no FFI evidence; both → FFI evidence set.

use super::*;
use crate::resource::contract_graph_builder::ContractEdge;
use grouping::InstanceEdgeGroups;
use omniscope_semantics::FamilyRegistry;
use omniscope_types::boundary::{BoundaryConfidence, BoundaryEvidence};
use omniscope_types::evidence::{BoundaryDetectionMethod, BoundaryEvidenceKind};
use omniscope_types::{FamilyId, Language};

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

// ── edge_has_boundary_evidence unit tests ──

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

// ── collect_boundary_from_edges unit tests ──

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
fn test_collect_boundary_from_edges_acquire_only() {
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

// ── Dual-evidence gating: CrossFamilyFree ──

#[test]
fn test_cross_family_no_boundary_no_ffi_evidence() {
    // Cross-family free WITHOUT boundary evidence → no FFI evidence
    let graph = make_cross_family_graph(FamilyId::C_HEAP, FamilyId::CPP_NEW_SCALAR, None, None);
    let groups = InstanceEdgeGroups::new(&graph);
    let registry = FamilyRegistry::new();

    let mut ffi_count = 0;
    for inst_id in groups.instance_ids() {
        let edges = groups.edges_of(*inst_id);
        let acquire_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Acquire { .. }))
            .collect();
        let release_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Release { .. }))
            .collect();

        for &ai in &acquire_indices {
            let alloc_family = graph.edges[ai].family.unwrap_or(FamilyId::C_HEAP);
            for &ri in &release_indices {
                let release_family = graph.edges[ri].family.unwrap_or(FamilyId::C_HEAP);
                if !registry.is_compatible_release(alloc_family, release_family) {
                    let has_boundary = edge_has_boundary_evidence(&graph.edges[ai])
                        || edge_has_boundary_evidence(&graph.edges[ri]);
                    if has_boundary {
                        ffi_count += 1;
                    }
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
    // Cross-family free WITH boundary evidence → FFI evidence should be set
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
        let acquire_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Acquire { .. }))
            .collect();
        let release_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Release { .. }))
            .collect();

        for &ai in &acquire_indices {
            let alloc_family = graph.edges[ai].family.unwrap_or(FamilyId::C_HEAP);
            for &ri in &release_indices {
                let release_family = graph.edges[ri].family.unwrap_or(FamilyId::C_HEAP);
                if !registry.is_compatible_release(alloc_family, release_family) {
                    let has_boundary = edge_has_boundary_evidence(&graph.edges[ai])
                        || edge_has_boundary_evidence(&graph.edges[ri]);
                    if has_boundary {
                        ffi_count += 1;
                    }
                }
            }
        }
    }

    assert!(
        ffi_count > 0,
        "Cross-family free with boundary evidence MUST trigger FFI evidence"
    );
}

// ── Dual-evidence gating: CrossFamilyReclaim ──

#[test]
fn test_cross_family_reclaim_no_boundary_no_ffi_evidence() {
    // Non-Rust acquire + Rust reclaim WITHOUT boundary → no FFI evidence
    let mut graph = ContractGraph::new();
    let instance_id = graph.alloc_instance();

    // Acquire from C family (malloc)
    graph.add_edge(ContractEdge {
        source: 0,
        target: instance_id,
        effect: Effect::Acquire {
            family: FamilyId::C_HEAP,
            result: instance_id,
        },
        function: 0,
        function_name: "malloc".to_string(),
        caller_name: "c_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
    });

    // Ownership reclaim by Rust: source=instance_id so it groups with the acquire
    graph.add_edge(ContractEdge {
        source: instance_id,
        target: 0,
        effect: Effect::OwnershipReclaim {
            family: FamilyId::RUST_RAW_OWNERSHIP,
            result: instance_id + 1,
        },
        function: 1,
        function_name: "Box::from_raw".to_string(),
        caller_name: "rust_func".to_string(),
        family: Some(FamilyId::RUST_RAW_OWNERSHIP),
        boundary_evidence: None,
    });

    let groups = InstanceEdgeGroups::new(&graph);
    let registry = FamilyRegistry::new();

    for inst_id in groups.instance_ids() {
        let edges = groups.edges_of(*inst_id);
        let acquire_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Acquire { .. }))
            .collect();
        let reclaim_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::OwnershipReclaim { .. }))
            .collect();

        for &ai in &acquire_indices {
            let alloc_family = graph.edges[ai].family.unwrap_or(FamilyId::C_HEAP);
            for &ri in &reclaim_indices {
                let reclaim_family = graph.edges[ri]
                    .family
                    .unwrap_or(FamilyId::RUST_RAW_OWNERSHIP);
                if !registry.is_compatible_release(alloc_family, reclaim_family) {
                    let has_boundary = edge_has_boundary_evidence(&graph.edges[ai])
                        || edge_has_boundary_evidence(&graph.edges[ri]);
                    assert!(
                        !has_boundary,
                        "Cross-family reclaim without boundary evidence must NOT have FFI signal"
                    );
                }
            }
        }
    }
}

#[test]
fn test_cross_family_reclaim_with_boundary_triggers_ffi_evidence() {
    // Non-Rust acquire + Rust reclaim WITH boundary → FFI evidence
    let mut graph = ContractGraph::new();
    let instance_id = graph.alloc_instance();

    graph.add_edge(ContractEdge {
        source: 0,
        target: instance_id,
        effect: Effect::Acquire {
            family: FamilyId::C_HEAP,
            result: instance_id,
        },
        function: 0,
        function_name: "malloc".to_string(),
        caller_name: "c_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: Some(vec![make_boundary_evidence(Language::C, Language::Rust)]),
    });

    // Ownership reclaim by Rust: source=instance_id so it groups with the acquire
    graph.add_edge(ContractEdge {
        source: instance_id,
        target: 0,
        effect: Effect::OwnershipReclaim {
            family: FamilyId::RUST_RAW_OWNERSHIP,
            result: instance_id + 1,
        },
        function: 1,
        function_name: "Box::from_raw".to_string(),
        caller_name: "rust_func".to_string(),
        family: Some(FamilyId::RUST_RAW_OWNERSHIP),
        boundary_evidence: None,
    });

    let groups = InstanceEdgeGroups::new(&graph);
    let registry = FamilyRegistry::new();

    let mut found_ffi_signal = false;
    for inst_id in groups.instance_ids() {
        let edges = groups.edges_of(*inst_id);
        let acquire_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Acquire { .. }))
            .collect();
        let reclaim_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::OwnershipReclaim { .. }))
            .collect();

        for &ai in &acquire_indices {
            let alloc_family = graph.edges[ai].family.unwrap_or(FamilyId::C_HEAP);
            for &ri in &reclaim_indices {
                let reclaim_family = graph.edges[ri]
                    .family
                    .unwrap_or(FamilyId::RUST_RAW_OWNERSHIP);
                if !registry.is_compatible_release(alloc_family, reclaim_family) {
                    let has_boundary = edge_has_boundary_evidence(&graph.edges[ai])
                        || edge_has_boundary_evidence(&graph.edges[ri]);
                    if has_boundary {
                        found_ffi_signal = true;
                    }
                }
            }
        }
    }

    assert!(
        found_ffi_signal,
        "Cross-family reclaim with boundary evidence MUST trigger FFI evidence"
    );
}

// ── Dual-evidence gating: OwnershipEscapeLeak ──

#[test]
fn test_ownership_escape_no_boundary_no_ffi_evidence() {
    // into_raw WITHOUT boundary → no FFI evidence (OwnershipTransfer)
    let mut graph = ContractGraph::new();
    let instance_id = graph.alloc_instance();

    graph.add_edge(ContractEdge {
        source: 0,
        target: instance_id,
        effect: Effect::Acquire {
            family: FamilyId::RUST_RAW_OWNERSHIP,
            result: instance_id,
        },
        function: 0,
        function_name: "Box::new".to_string(),
        caller_name: "rust_func".to_string(),
        family: Some(FamilyId::RUST_RAW_OWNERSHIP),
        boundary_evidence: None,
    });

    graph.add_edge(ContractEdge {
        source: instance_id,
        target: 0,
        effect: Effect::OwnershipEscape {
            family: FamilyId::RUST_RAW_OWNERSHIP,
            result: 0,
        },
        function: 1,
        function_name: "Box::into_raw".to_string(),
        caller_name: "rust_func".to_string(),
        family: Some(FamilyId::RUST_RAW_OWNERSHIP),
        boundary_evidence: None,
    });

    let groups = InstanceEdgeGroups::new(&graph);

    for inst_id in groups.instance_ids() {
        let edges = groups.edges_of(*inst_id);
        let escape_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::OwnershipEscape { .. }))
            .collect();

        for &ei in &escape_indices {
            let has_boundary = edge_has_boundary_evidence(&graph.edges[ei]);
            assert!(
                !has_boundary,
                "OwnershipEscape without boundary evidence must NOT have FFI signal"
            );
        }
    }
}

#[test]
fn test_ownership_escape_with_boundary_triggers_ffi_evidence() {
    // into_raw WITH boundary evidence → FFI evidence (OwnershipTransfer)
    let mut graph = ContractGraph::new();
    let instance_id = graph.alloc_instance();

    graph.add_edge(ContractEdge {
        source: 0,
        target: instance_id,
        effect: Effect::Acquire {
            family: FamilyId::RUST_RAW_OWNERSHIP,
            result: instance_id,
        },
        function: 0,
        function_name: "Box::new".to_string(),
        caller_name: "rust_func".to_string(),
        family: Some(FamilyId::RUST_RAW_OWNERSHIP),
        boundary_evidence: None,
    });

    graph.add_edge(ContractEdge {
        source: instance_id,
        target: 0,
        effect: Effect::OwnershipEscape {
            family: FamilyId::RUST_RAW_OWNERSHIP,
            result: 0,
        },
        function: 1,
        function_name: "Box::into_raw".to_string(),
        caller_name: "ffi_bridge".to_string(),
        family: Some(FamilyId::RUST_RAW_OWNERSHIP),
        boundary_evidence: Some(vec![make_boundary_evidence(Language::Rust, Language::C)]),
    });

    let groups = InstanceEdgeGroups::new(&graph);

    let mut found_ffi_signal = false;
    for inst_id in groups.instance_ids() {
        let edges = groups.edges_of(*inst_id);
        let escape_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::OwnershipEscape { .. }))
            .collect();

        for &ei in &escape_indices {
            let has_boundary = edge_has_boundary_evidence(&graph.edges[ei]);
            if has_boundary {
                found_ffi_signal = true;
            }
        }
    }

    assert!(
        found_ffi_signal,
        "OwnershipEscape with boundary evidence MUST trigger FFI evidence"
    );
}

// ── Same-family with boundary: no resource evidence, no FFI ──

#[test]
fn test_same_family_with_boundary_no_cross_family() {
    // Same family WITH boundary → NOT a cross-family issue at all
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
        let acquire_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Acquire { .. }))
            .collect();
        let release_indices: Vec<usize> = edges
            .iter()
            .copied()
            .filter(|&idx| matches!(graph.edges[idx].effect, Effect::Release { .. }))
            .collect();

        for &ai in &acquire_indices {
            let alloc_family = graph.edges[ai].family.unwrap_or(FamilyId::C_HEAP);
            for &ri in &release_indices {
                let release_family = graph.edges[ri].family.unwrap_or(FamilyId::C_HEAP);
                if !registry.is_compatible_release(alloc_family, release_family) {
                    cross_family_count += 1;
                }
            }
        }
    }

    assert_eq!(
        cross_family_count, 0,
        "Same-family (C_HEAP→C_HEAP) must NOT produce cross-family candidate, even with boundary evidence"
    );
}

// ── Boundary evidence on both edges ──

#[test]
fn test_collect_boundary_prefers_release_edge() {
    // When both acquire and release edges have boundary evidence,
    // collect_boundary_from_edges should prefer the release edge.
    let graph = make_cross_family_graph(
        FamilyId::C_HEAP,
        FamilyId::CPP_NEW_SCALAR,
        Some(vec![make_boundary_evidence(Language::Go, Language::C)]),
        Some(vec![make_boundary_evidence(Language::Rust, Language::Cpp)]),
    );
    let result = collect_boundary_from_edges(&graph.edges[0], &graph.edges[1]);
    assert!(result.is_some(), "Must yield boundary evidence");
    let cbe = result.unwrap();
    // Should prefer release edge: Rust→Cpp
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

// ── CrossBoundaryEvidence construction from edges ──

#[test]
fn test_boundary_construction_detection_method() {
    let result = collect_boundary_from_edges(
        &ContractEdge {
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
        },
        &ContractEdge {
            source: 1,
            target: 0,
            effect: Effect::Release {
                family: FamilyId::CPP_NEW_SCALAR,
                arg: 0,
            },
            function: 1,
            function_name: "operator delete".to_string(),
            caller_name: "test".to_string(),
            family: Some(FamilyId::CPP_NEW_SCALAR),
            boundary_evidence: Some(vec![make_boundary_evidence(Language::Rust, Language::Cpp)]),
        },
    );
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
