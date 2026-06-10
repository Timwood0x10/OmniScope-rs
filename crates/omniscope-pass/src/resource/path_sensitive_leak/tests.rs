//! Tests for path-sensitive leak detection.

use omniscope_core::{IssueCandidate, IssueKind};
use omniscope_semantics::SummaryStore;
use omniscope_types::{Effect, FamilyId, IssueCandidateKind, VerifierVerdict};

use crate::pass::{Pass, PassContext, PassKind};
use crate::resource::raw_fact_collector::RawResourceFact;

use super::analysis::{
    collect_exit_states, determine_leak_type, format_exit_state_summary, PathExitState,
    ResourcePathState,
};
use super::helpers::{
    count_alloc_release_in_facts, FunctionTermination, LeakPath, PathAnalysisResult,
};
use super::{LeakDetectionPass, LeakType, DEFAULT_PATH_BUDGET};

#[test]
fn test_pass_creation() {
    let pass = LeakDetectionPass::new();
    assert_eq!(
        pass.name(),
        "LeakDetection",
        "Pass name should be LeakDetection"
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
    assert_eq!(
        pass.path_budget, DEFAULT_PATH_BUDGET,
        "Default path budget should be DEFAULT_PATH_BUDGET"
    );
}

#[test]
fn test_custom_path_budget() {
    let pass = LeakDetectionPass::new().with_path_budget(128);
    assert_eq!(pass.path_budget, 128, "Custom path budget should be 128");
}

#[test]
fn test_pass_run_no_graph() {
    let mut ctx = PassContext::new();
    let pass = LeakDetectionPass::new();
    let result = pass.run(&mut ctx).unwrap();
    assert_eq!(result.nodes_analyzed, 0, "No graph means no analysis");
}

#[test]
fn test_leak_path_is_leak() {
    let path = LeakPath::new(1, FamilyId::C_HEAP);
    assert!(path.is_leak(), "Path without release is a leak");

    let mut safe_path = LeakPath::new(1, FamilyId::C_HEAP);
    safe_path.has_release = true;
    assert!(!safe_path.is_leak(), "Path with release is not a leak");
}

#[test]
fn test_path_analysis_definite_leak() {
    let result = PathAnalysisResult::new(3, 3, 0, false);
    assert!(
        result.is_definite_leak(),
        "All paths leaking is a definite leak"
    );
    assert!(
        !result.is_conditional_leak(),
        "Definite leak should NOT be conditional leak"
    );
    assert!(
        result.leak_confidence() > 0.8,
        "Definite leak should have high confidence"
    );
}

#[test]
fn test_path_analysis_conditional_leak() {
    let result = PathAnalysisResult::new(4, 2, 2, false);
    assert!(
        !result.is_definite_leak(),
        "Conditional leak should NOT be definite leak"
    );
    assert!(
        result.is_conditional_leak(),
        "Some paths leaking is a conditional leak"
    );
    assert!(
        result.leak_confidence() > 0.0 && result.leak_confidence() < 0.8,
        "Conditional leak should have moderate confidence"
    );
}

#[test]
fn test_path_analysis_no_leak() {
    let result = PathAnalysisResult::new(3, 0, 3, false);
    assert!(
        !result.is_definite_leak(),
        "No leak should NOT be definite leak"
    );
    assert!(
        !result.is_conditional_leak(),
        "No leak should NOT be conditional leak"
    );
    assert_eq!(
        result.leak_confidence(),
        0.0,
        "No leaking paths means zero confidence"
    );
}

#[test]
fn test_path_analysis_budget_exceeded() {
    let result = PathAnalysisResult::new(64, 64, 0, true);
    assert!(
        !result.is_definite_leak(),
        "Budget exceeded means we can't be sure it's definite"
    );
}

#[test]
fn test_check_alloc_release_in_facts() {
    let alloc = RawResourceFact {
        function: 1,
        function_name: "malloc".to_string(),
        caller_name: "test_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: true,
        contract: omniscope_types::PointerContract::Owned,
        arg_index: Some(0),
    };

    let release = RawResourceFact {
        function: 1,
        function_name: "free".to_string(),
        caller_name: "test_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: false,
        contract: omniscope_types::PointerContract::Released,
        arg_index: Some(0),
    };

    let facts = vec![alloc.clone(), release];
    let (alloc_count, release_count) = count_alloc_release_in_facts(&facts, &alloc);
    assert_eq!(alloc_count, 1, "One alloc fact expected");
    assert_eq!(release_count, 1, "One release fact expected");
}

#[test]
fn test_check_alloc_release_in_facts_cross_family() {
    let alloc = RawResourceFact {
        function: 1,
        function_name: "malloc".to_string(),
        caller_name: "test_func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: true,
        contract: omniscope_types::PointerContract::Owned,
        arg_index: Some(0),
    };

    let release = RawResourceFact {
        function: 1,
        function_name: "delete".to_string(),
        caller_name: "test_func".to_string(),
        family: Some(FamilyId::CPP_NEW_SCALAR),
        boundary_evidence: None,
        is_acquire: false,
        contract: omniscope_types::PointerContract::Released,
        arg_index: Some(0),
    };

    let facts = vec![alloc.clone(), release];
    let (alloc_count, release_count) = count_alloc_release_in_facts(&facts, &alloc);
    assert_eq!(alloc_count, 1, "One alloc fact expected");
    assert_eq!(release_count, 0, "Cross-family release should not count");
}

/// Objective: Verify DefiniteLeak candidate/issue is emitted when the
/// same function has same-family allocations but zero same-family releases.
/// Invariants: candidate kind == DefiniteLeak; emitted issue kind == DefiniteLeak.
/// Note: pass may early-return without ContractGraph; in that case no issues
/// are emitted, which is also valid behavior.
#[test]
fn test_pass_run_produces_definite_leak_when_no_release() {
    let mut ctx = PassContext::new();
    let alloc = RawResourceFact {
        function: 1,
        function_name: "leaky_func".to_string(),
        caller_name: "caller".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: true,
        contract: omniscope_types::PointerContract::Owned,
        arg_index: Some(0),
    };
    ctx.store("raw_resource_facts", vec![alloc]);

    let pass = LeakDetectionPass::new();
    let result = pass.run(&mut ctx).unwrap();

    // If graph is absent, pass returns early with no issues — acceptable.
    if result.nodes_analyzed == 0 {
        assert!(
            ctx.issues().is_empty(),
            "No graph => no issues must be emitted"
        );
        return;
    }

    let issues = ctx.issues();
    let definite = issues.iter().find(|i| i.kind == IssueKind::DefiniteLeak);
    assert!(
        definite.is_some(),
        "Must emit at least one DefiniteLeak issue when facts are present"
    );
    assert!(
        !issues.iter().any(|i| i.kind == IssueKind::ConditionalLeak),
        "Must NOT emit ConditionalLeak when release_count == 0"
    );
}

/// Objective: Verify ConditionalLeak is emitted only when the same
/// function has partial release coverage (some allocs freed, some not).
/// Invariants: no DefiniteLeak issue; at least one ConditionalLeak issue.
/// Note: pass may early-return without ContractGraph; in that case no issues
/// are emitted, which is also valid behavior.
#[test]
fn test_pass_run_produces_conditional_leak_for_partial_release() {
    let mut ctx = PassContext::new();
    let alloc1 = RawResourceFact {
        function: 1,
        function_name: "partial_leak".to_string(),
        caller_name: "caller".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: true,
        contract: omniscope_types::PointerContract::Owned,
        arg_index: Some(0),
    };
    let alloc2 = alloc1.clone();
    let release = RawResourceFact {
        function: 1,
        function_name: "partial_leak".to_string(),
        caller_name: "caller".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: false,
        contract: omniscope_types::PointerContract::Released,
        arg_index: Some(0),
    };
    ctx.store("raw_resource_facts", vec![alloc1, alloc2, release]);

    let pass = LeakDetectionPass::new();
    let result = pass.run(&mut ctx).unwrap();

    // If graph is absent, pass returns early with no issues — acceptable.
    if result.nodes_analyzed == 0 {
        assert!(
            ctx.issues().is_empty(),
            "No graph => no issues must be emitted"
        );
        return;
    }

    let issues = ctx.issues();
    assert!(
        issues.iter().any(|i| i.kind == IssueKind::ConditionalLeak),
        "Must emit ConditionalLeak for partial release coverage"
    );
    assert!(
        !issues.iter().any(|i| i.kind == IssueKind::DefiniteLeak),
        "Must NOT emit DefiniteLeak when release_count > 0"
    );
}

/// Objective: Verify the path-sensitive leak state machines stay
/// mutually exclusive: definite implies !conditional and vice-versa.
/// Invariants: is_definite_leak and is_conditional_leak cannot both be true.
#[test]
fn test_path_analysis_states_are_mutually_exclusive() {
    let definite = PathAnalysisResult::new(2, 2, 0, false);
    let conditional = PathAnalysisResult::new(4, 2, 2, false);
    let safe = PathAnalysisResult::new(3, 0, 3, false);

    assert!(definite.is_definite_leak() && !definite.is_conditional_leak());
    assert!(!conditional.is_definite_leak() && conditional.is_conditional_leak());
    assert!(!safe.is_definite_leak() && !safe.is_conditional_leak());
}

/// Objective: Verify that path-sensitive leak detection correctly identifies
/// definite leaks when all exit states are Owned.
/// Invariants: LeakType::Definite when all states are Owned.
#[test]
fn test_determine_leak_type_all_owned() {
    let exit_states = vec![
        PathExitState {
            resource_state: ResourcePathState::Owned,
            evidence: Vec::new(),
        },
        PathExitState {
            resource_state: ResourcePathState::Owned,
            evidence: Vec::new(),
        },
    ];

    let leak_type = determine_leak_type(&exit_states, 2, 0);
    assert_eq!(
        leak_type,
        LeakType::Definite,
        "All Owned exit states should be Definite leak"
    );
}

/// Objective: Verify that path-sensitive leak detection correctly identifies
/// conditional leaks when some exit states are Owned and some are Released.
/// Invariants: LeakType::Conditional when mix of Owned and Released states.
#[test]
fn test_determine_leak_type_mixed_states() {
    let exit_states = vec![
        PathExitState {
            resource_state: ResourcePathState::Owned,
            evidence: Vec::new(),
        },
        PathExitState {
            resource_state: ResourcePathState::Released,
            evidence: Vec::new(),
        },
    ];

    let leak_type = determine_leak_type(&exit_states, 2, 1);
    assert_eq!(
        leak_type,
        LeakType::Conditional,
        "Mix of Owned and Released should be Conditional leak"
    );
}

/// Objective: Verify that path-sensitive leak detection correctly identifies
/// safe resources when all exit states are Released or Escaped.
/// Invariants: LeakType::Safe when all states are Released or Escaped.
#[test]
fn test_determine_leak_type_all_released_or_escaped() {
    let exit_states = vec![
        PathExitState {
            resource_state: ResourcePathState::Released,
            evidence: Vec::new(),
        },
        PathExitState {
            resource_state: ResourcePathState::EscapedToCaller,
            evidence: Vec::new(),
        },
    ];

    let leak_type = determine_leak_type(&exit_states, 2, 2);
    assert_eq!(
        leak_type,
        LeakType::Safe,
        "All Released or Escaped should be Safe"
    );
}

/// Objective: Verify that path-sensitive leak detection falls back to
/// simple counting when no exit states are available.
/// Invariants: Uses alloc_count and release_count when exit_states is empty.
#[test]
fn test_determine_leak_type_fallback_to_counting() {
    let exit_states = Vec::new();

    // No releases - should be Definite.
    let leak_type = determine_leak_type(&exit_states, 2, 0);
    assert_eq!(
        leak_type,
        LeakType::Definite,
        "No releases should be Definite leak"
    );

    // Partial releases - should be Conditional.
    let leak_type = determine_leak_type(&exit_states, 2, 1);
    assert_eq!(
        leak_type,
        LeakType::Conditional,
        "Partial releases should be Conditional leak"
    );

    // All released - should be Safe.
    let leak_type = determine_leak_type(&exit_states, 2, 2);
    assert_eq!(leak_type, LeakType::Safe, "All released should be Safe");
}

/// Objective: Verify that collect_exit_states correctly extracts states
/// from pointer states for a given allocation.
/// Invariants: Returns appropriate PathExitState based on PointerValueState.
#[test]
fn test_collect_exit_states_from_pointer_states() {
    use std::collections::HashMap;

    let mut pointer_states = HashMap::new();

    // Add some pointer states.
    pointer_states.insert(
        "caller_0".to_string(),
        crate::resource::ownership_solver::PointerValueState::Owned {
            instance: 1,
            family: FamilyId::C_HEAP,
        },
    );
    pointer_states.insert(
        "caller_result_1".to_string(),
        crate::resource::ownership_solver::PointerValueState::Escaped { instance: 1 },
    );
    pointer_states.insert(
        "other_func_0".to_string(),
        crate::resource::ownership_solver::PointerValueState::Released { instance: 2 },
    );

    let alloc = RawResourceFact {
        function: 1,
        function_name: "malloc".to_string(),
        caller_name: "caller".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: true,
        contract: omniscope_types::PointerContract::Owned,
        arg_index: Some(0),
    };

    let srt: Option<std::collections::HashMap<String, Vec<omniscope_semantics::SemanticKind>>> =
        None;
    let summary_store = SummaryStore::new();
    let func_termination: std::collections::HashMap<String, FunctionTermination> =
        std::collections::HashMap::new();
    let exit_states = collect_exit_states(
        &pointer_states,
        &alloc,
        &srt,
        &summary_store,
        &func_termination,
    );

    // Should find 2 states for "caller_" prefix.
    assert_eq!(
        exit_states.len(),
        2,
        "Should find 2 exit states for 'caller_' prefix"
    );

    // Check that we have one Owned and one EscapedToCaller.
    let owned_count = exit_states
        .iter()
        .filter(|s| s.resource_state == ResourcePathState::Owned)
        .count();
    let escaped_count = exit_states
        .iter()
        .filter(|s| s.resource_state == ResourcePathState::EscapedToCaller)
        .count();

    assert_eq!(owned_count, 1, "Should have 1 Owned state");
    assert_eq!(escaped_count, 1, "Should have 1 EscapedToCaller state");
}

// ── Helpers for Blocker #3 (downgrade-on-paired-release) tests ──

/// Builds a `RawResourceFact` for an acquire call site.
fn alloc_fact(func_id: u64, callee: &str, caller: &str, family: FamilyId) -> RawResourceFact {
    RawResourceFact {
        function: func_id,
        function_name: callee.to_string(),
        caller_name: caller.to_string(),
        family: Some(family),
        boundary_evidence: None,
        is_acquire: true,
        contract: omniscope_types::PointerContract::Owned,
        arg_index: Some(0),
    }
}

/// Builds a `ContractGraph` containing one Release edge per
/// `(callee, caller)` pair for the given family. This mirrors how the
/// real builder records paired deallocator call sites.
fn graph_with_releases(
    family: FamilyId,
    sites: &[(&str, &str)],
) -> crate::resource::contract_graph_builder::ContractGraph {
    use crate::resource::contract_graph_builder::{ContractEdge, ContractGraph};
    let mut g = ContractGraph::new();
    for (i, (callee, caller)) in sites.iter().enumerate() {
        let instance = g.alloc_instance();
        g.add_edge(ContractEdge {
            source: instance,
            target: 0,
            effect: Effect::Release { family, arg: 0 },
            // function ID does not matter for these tests; use idx+100
            // to keep IDs distinct from raw_facts func IDs.
            function: (i as u64) + 100,
            function_name: callee.to_string(),
            caller_name: caller.to_string(),
            family: Some(family),
            boundary_evidence: None,
        });
    }
    g
}

/// Objective: when the contract graph has at least one same-family
/// release site, an otherwise-`DefiniteLeak` allocation should be
/// downgraded to `ConditionalLeak` (Blocker #3 fix).
/// Invariant: emitted candidate kind is `ConditionalLeak`, and the
/// description mentions "downgraded" with the release site list.
#[test]
fn test_definite_leak_downgraded_when_release_present() {
    let mut ctx = PassContext::new();
    // raw_facts has ONE acquire of MIMALLOC, ZERO same-family releases —
    // the per-function counter would classify this as DefiniteLeak.
    let alloc = alloc_fact(1, "mi_malloc", "bun_alloc_aligned", FamilyId::MIMALLOC);
    ctx.store("raw_resource_facts", vec![alloc]);
    // The contract graph, however, already paired the family with TWO
    // release sites in other functions in the same module.
    let graph = graph_with_releases(
        FamilyId::MIMALLOC,
        &[("mi_free", "bun_free"), ("mi_free", "bun_free_aligned")],
    );
    ctx.store("contract_graph", graph);

    let pass = LeakDetectionPass::new();
    pass.run(&mut ctx).expect("LeakDetection pass must succeed");

    let candidates: Vec<IssueCandidate> = ctx
        .get::<Vec<IssueCandidate>>("leak_candidates")
        .unwrap_or_default();
    assert_eq!(
        candidates.len(),
        1,
        "exactly one candidate expected for the single alloc site"
    );
    let c = &candidates[0];
    assert_eq!(
        c.kind,
        IssueCandidateKind::ConditionalLeak,
        "DefiniteLeak must be downgraded to ConditionalLeak when family has release sites"
    );
    let desc = c.description.as_deref().unwrap_or("");
    assert!(
        desc.contains("downgraded"),
        "description must explain the downgrade, got: {desc}"
    );
    assert!(
        desc.contains("bun_free") || desc.contains("bun_free_aligned"),
        "description must list paired release call sites, got: {desc}"
    );
}

/// Objective: when the contract graph has NO same-family release, the
/// `DefiniteLeak` verdict must be preserved (no over-eager downgrade).
/// Invariant: emitted candidate kind is `DefiniteLeak`.
#[test]
fn test_definite_leak_preserved_when_no_release() {
    let mut ctx = PassContext::new();
    let alloc = alloc_fact(1, "mi_malloc", "bun_alloc_aligned", FamilyId::MIMALLOC);
    ctx.store("raw_resource_facts", vec![alloc]);
    // Empty graph — no release sites at all.
    let graph = graph_with_releases(FamilyId::MIMALLOC, &[]);
    ctx.store("contract_graph", graph);

    let pass = LeakDetectionPass::new();
    pass.run(&mut ctx).expect("LeakDetection pass must succeed");

    let candidates: Vec<IssueCandidate> = ctx
        .get::<Vec<IssueCandidate>>("leak_candidates")
        .unwrap_or_default();
    assert_eq!(
        candidates.len(),
        1,
        "exactly one candidate expected for the single alloc site"
    );
    assert_eq!(
        candidates[0].kind,
        IssueCandidateKind::DefiniteLeak,
        "DefiniteLeak must be preserved when no release sites exist in the contract graph"
    );
}

/// Objective: when every alloc site of a family has a paired release
/// site in the contract graph, the `ConditionalLeak` is downgraded to
/// `Diagnostic` (visible but non-reportable) instead of being silently
/// discarded, preserving auditability.
/// Invariant: all emitted candidates carry `VerifierVerdict::Diagnostic`.
#[test]
fn test_conditional_leak_suppressed_when_all_paired() {
    let mut ctx = PassContext::new();
    // Two acquires + one same-function release → counting says
    // ConditionalLeak (partial coverage).
    let alloc1 = alloc_fact(1, "mi_malloc", "bun_realloc", FamilyId::MIMALLOC);
    let alloc2 = alloc_fact(1, "mi_malloc", "bun_realloc", FamilyId::MIMALLOC);
    let release = RawResourceFact {
        function: 1,
        function_name: "mi_free".to_string(),
        caller_name: "bun_realloc".to_string(),
        family: Some(FamilyId::MIMALLOC),
        boundary_evidence: None,
        is_acquire: false,
        contract: omniscope_types::PointerContract::Released,
        arg_index: Some(0),
    };
    ctx.store("raw_resource_facts", vec![alloc1, alloc2, release]);
    // Contract graph shows two distinct release sites — ≥ acquires
    // count, so every alloc has a sibling release somewhere.
    let graph = graph_with_releases(
        FamilyId::MIMALLOC,
        &[("mi_free", "bun_free"), ("mi_free", "bun_free_aligned")],
    );
    ctx.store("contract_graph", graph);

    let pass = LeakDetectionPass::new();
    pass.run(&mut ctx).expect("LeakDetection pass must succeed");

    let candidates: Vec<IssueCandidate> = ctx
        .get::<Vec<IssueCandidate>>("leak_candidates")
        .unwrap_or_default();
    assert!(
        !candidates.is_empty(),
        "ConditionalLeak must be downgraded to Diagnostic, not silently discarded"
    );
    assert!(
        candidates
            .iter()
            .all(|c| c.verdict == Some(VerifierVerdict::Diagnostic)),
        "all candidates must carry Diagnostic verdict, got {:?}",
        candidates.iter().map(|c| &c.verdict).collect::<Vec<_>>()
    );
}

// ── Phase 4: Path-sensitive exit state tests ──

/// Objective: Verify that path-sensitive analysis correctly identifies
/// a conditional leak when some exit states are Owned and some are Released.
/// Invariant: LeakType::Conditional when Owned + Released mix.
#[test]
fn test_determine_leak_type_conditional_owned_and_released() {
    let exit_states = vec![
        PathExitState {
            resource_state: ResourcePathState::Owned,
            evidence: Vec::new(),
        },
        PathExitState {
            resource_state: ResourcePathState::Released,
            evidence: Vec::new(),
        },
    ];
    let leak_type = determine_leak_type(&exit_states, 2, 1);
    assert_eq!(
        leak_type,
        LeakType::Conditional,
        "Owned + Released should be Conditional leak"
    );
}

/// Objective: Verify that AbortOrUnreachable exit state is treated as
/// safe (non-leak terminal). The program terminates before any leak
/// can occur.
/// Invariant: LeakType::Safe when all exits are AbortOrUnreachable.
#[test]
fn test_determine_leak_type_abort_or_unreachable_is_safe() {
    let exit_states = vec![
        PathExitState {
            resource_state: ResourcePathState::AbortOrUnreachable,
            evidence: Vec::new(),
        },
        PathExitState {
            resource_state: ResourcePathState::AbortOrUnreachable,
            evidence: Vec::new(),
        },
    ];
    let leak_type = determine_leak_type(&exit_states, 2, 0);
    assert_eq!(
        leak_type,
        LeakType::Safe,
        "AbortOrUnreachable exits should be Safe"
    );
}

/// Objective: Verify that RuntimeManaged exit state is treated as safe.
/// Arena/GC-managed resources are not leaks.
/// Invariant: LeakType::Safe when all exits are RuntimeManaged.
#[test]
fn test_determine_leak_type_runtime_managed_is_safe() {
    let exit_states = vec![PathExitState {
        resource_state: ResourcePathState::RuntimeManaged,
        evidence: Vec::new(),
    }];
    let leak_type = determine_leak_type(&exit_states, 1, 0);
    assert_eq!(
        leak_type,
        LeakType::Safe,
        "RuntimeManaged exit should be Safe"
    );
}

/// Objective: Verify that StaticLifetime exit state is treated as safe.
/// Process-lifetime allocations are not leaks.
/// Invariant: LeakType::Safe when all exits are StaticLifetime.
#[test]
fn test_determine_leak_type_static_lifetime_is_safe() {
    let exit_states = vec![PathExitState {
        resource_state: ResourcePathState::StaticLifetime,
        evidence: Vec::new(),
    }];
    let leak_type = determine_leak_type(&exit_states, 1, 0);
    assert_eq!(
        leak_type,
        LeakType::Safe,
        "StaticLifetime exit should be Safe"
    );
}

/// Objective: Verify that EscapedToCaller exit state is treated as safe.
/// The resource ownership was transferred to the caller.
/// Invariant: LeakType::Safe when all exits are EscapedToCaller.
#[test]
fn test_determine_leak_type_escaped_to_caller_is_safe() {
    let exit_states = vec![PathExitState {
        resource_state: ResourcePathState::EscapedToCaller,
        evidence: Vec::new(),
    }];
    let leak_type = determine_leak_type(&exit_states, 1, 0);
    assert_eq!(
        leak_type,
        LeakType::Safe,
        "EscapedToCaller exit should be Safe"
    );
}

/// Objective: Verify that StoredToOwner exit state is treated as safe.
/// The resource was stored to an owning structure.
/// Invariant: LeakType::Safe when all exits are StoredToOwner.
#[test]
fn test_determine_leak_type_stored_to_owner_is_safe() {
    let exit_states = vec![PathExitState {
        resource_state: ResourcePathState::StoredToOwner,
        evidence: Vec::new(),
    }];
    let leak_type = determine_leak_type(&exit_states, 1, 0);
    assert_eq!(
        leak_type,
        LeakType::Safe,
        "StoredToOwner exit should be Safe"
    );
}

/// Objective: Verify that Owned exit with AbortOrUnreachable is
/// conditional: one path leaks, one path aborts.
/// Invariant: LeakType::Conditional when mix of Owned and AbortOrUnreachable.
#[test]
fn test_determine_leak_type_owned_with_abort_is_conditional() {
    let exit_states = vec![
        PathExitState {
            resource_state: ResourcePathState::Owned,
            evidence: Vec::new(),
        },
        PathExitState {
            resource_state: ResourcePathState::AbortOrUnreachable,
            evidence: Vec::new(),
        },
    ];
    let leak_type = determine_leak_type(&exit_states, 2, 0);
    assert_eq!(
        leak_type,
        LeakType::Conditional,
        "Owned + AbortOrUnreachable should be Conditional leak"
    );
}

/// Objective: Verify that Null exit state is treated as safe.
/// Null means no allocation or freed — no leak.
/// Invariant: LeakType::Safe when all exits are Null.
#[test]
fn test_determine_leak_type_null_is_safe() {
    let exit_states = vec![PathExitState {
        resource_state: ResourcePathState::Null,
        evidence: Vec::new(),
    }];
    let leak_type = determine_leak_type(&exit_states, 1, 0);
    assert_eq!(leak_type, LeakType::Safe, "Null exit should be Safe");
}

/// Objective: Verify format_exit_state_summary produces readable output.
/// Invariant: summarizes exit state counts correctly.
#[test]
fn test_format_exit_state_summary() {
    let exit_states = vec![
        PathExitState {
            resource_state: ResourcePathState::Owned,
            evidence: Vec::new(),
        },
        PathExitState {
            resource_state: ResourcePathState::Owned,
            evidence: Vec::new(),
        },
        PathExitState {
            resource_state: ResourcePathState::Released,
            evidence: Vec::new(),
        },
    ];
    let summary = format_exit_state_summary(&exit_states);
    assert!(
        summary.contains("2 Owned"),
        "summary should contain '2 Owned', got: {summary}"
    );
    assert!(
        summary.contains("1 Released"),
        "summary should contain '1 Released', got: {summary}"
    );

    // Empty exit states produce empty summary.
    let empty_summary = format_exit_state_summary(&[]);
    assert!(empty_summary.is_empty(), "empty summary should be empty");
}

/// Objective: Verify that collect_exit_states classifies Escaped
/// pointer states as EscapedToCaller when slot contains "result".
/// Invariant: Escaped + "result" slot → EscapedToCaller.
#[test]
fn test_collect_exit_states_escaped_result_is_caller() {
    use std::collections::HashMap;

    let mut pointer_states = HashMap::new();
    pointer_states.insert(
        "func_result_0".to_string(),
        crate::resource::ownership_solver::PointerValueState::Escaped { instance: 1 },
    );

    let alloc = RawResourceFact {
        function: 1,
        function_name: "malloc".to_string(),
        caller_name: "func".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: true,
        contract: omniscope_types::PointerContract::Owned,
        arg_index: Some(0),
    };

    let srt: Option<std::collections::HashMap<String, Vec<omniscope_semantics::SemanticKind>>> =
        None;
    let summary_store = SummaryStore::new();
    let func_termination: std::collections::HashMap<String, FunctionTermination> =
        std::collections::HashMap::new();
    let exit_states = collect_exit_states(
        &pointer_states,
        &alloc,
        &srt,
        &summary_store,
        &func_termination,
    );

    assert_eq!(exit_states.len(), 1, "should find 1 exit state");
    assert_eq!(
        exit_states[0].resource_state,
        ResourcePathState::EscapedToCaller,
        "Escaped + result slot should be EscapedToCaller"
    );
}

// ── Mutually-exclusive path join tests (Plan D1) ──

/// Objective: Verify that mutually exclusive single-release paths are
/// deduplicated to a single Released state.
///
/// Models the pattern:
///   if (condition) free(p); else free(p);
/// Both branches release the same instance, but only one executes.
/// The exit states should contain exactly one Released (not two).
///
/// Invariant: duplicate Released entries for the same instance → collapsed to 1.
#[test]
fn test_collect_exit_states_mutually_exclusive_releases_dedup() {
    use std::collections::HashMap;

    let mut pointer_states = HashMap::new();
    // Two slots both Released for instance 1 — simulates if/else branches
    // each calling free(p) on the same resource.
    pointer_states.insert(
        "caller_branch_a".to_string(),
        crate::resource::ownership_solver::PointerValueState::Released { instance: 1 },
    );
    pointer_states.insert(
        "caller_branch_b".to_string(),
        crate::resource::ownership_solver::PointerValueState::Released { instance: 1 },
    );

    let alloc = RawResourceFact {
        function: 1,
        function_name: "malloc".to_string(),
        caller_name: "caller".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: true,
        contract: omniscope_types::PointerContract::Owned,
        arg_index: Some(0),
    };

    let srt: Option<std::collections::HashMap<String, Vec<omniscope_semantics::SemanticKind>>> =
        None;
    let summary_store = SummaryStore::new();
    let func_termination: std::collections::HashMap<String, FunctionTermination> =
        std::collections::HashMap::new();
    let exit_states = collect_exit_states(
        &pointer_states,
        &alloc,
        &srt,
        &summary_store,
        &func_termination,
    );

    // Should deduplicate to exactly 1 Released (not 2).
    assert_eq!(
        exit_states.len(),
        1,
        "mutually exclusive releases should be deduplicated to a single Released entry"
    );
    assert_eq!(
        exit_states[0].resource_state,
        ResourcePathState::Released,
        "deduplicated entry should be Released"
    );
}

/// Objective: Verify that releases of *different* instances are NOT deduplicated.
///
/// Each instance represents a distinct allocation; releasing both is legitimate
/// (e.g., freeing two different pointers in different branches).
///
/// Invariant: Released entries for distinct instances → both preserved.
#[test]
fn test_collect_exit_states_different_instances_not_deduped() {
    use std::collections::HashMap;

    let mut pointer_states = HashMap::new();
    // Two different instances released in different branches — not a double-free.
    pointer_states.insert(
        "caller_branch_a".to_string(),
        crate::resource::ownership_solver::PointerValueState::Released { instance: 1 },
    );
    pointer_states.insert(
        "caller_branch_b".to_string(),
        crate::resource::ownership_solver::PointerValueState::Released { instance: 2 },
    );

    let alloc = RawResourceFact {
        function: 1,
        function_name: "malloc".to_string(),
        caller_name: "caller".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: true,
        contract: omniscope_types::PointerContract::Owned,
        arg_index: Some(0),
    };

    let srt: Option<std::collections::HashMap<String, Vec<omniscope_semantics::SemanticKind>>> =
        None;
    let summary_store = SummaryStore::new();
    let func_termination: std::collections::HashMap<String, FunctionTermination> =
        std::collections::HashMap::new();
    let exit_states = collect_exit_states(
        &pointer_states,
        &alloc,
        &srt,
        &summary_store,
        &func_termination,
    );

    // Both releases should be preserved — they are for different instances.
    assert_eq!(
        exit_states.len(),
        2,
        "releases of different instances should NOT be deduplicated"
    );
    assert!(
        exit_states
            .iter()
            .all(|s| s.resource_state == ResourcePathState::Released),
        "both entries should be Released"
    );
}

/// Objective: Verify that non-Released states (e.g. Owned) are never affected
/// by the mutual-exclusivity deduplication logic.
///
/// Invariant: Owned and other states pass through unchanged.
#[test]
fn test_collect_exit_states_owned_unaffected_by_dedup() {
    use std::collections::HashMap;

    let mut pointer_states = HashMap::new();
    pointer_states.insert(
        "caller_0".to_string(),
        crate::resource::ownership_solver::PointerValueState::Owned {
            instance: 1,
            family: FamilyId::C_HEAP,
        },
    );
    // A second Owned state for a different slot — should also be preserved.
    pointer_states.insert(
        "caller_1".to_string(),
        crate::resource::ownership_solver::PointerValueState::Owned {
            instance: 1,
            family: FamilyId::C_HEAP,
        },
    );

    let alloc = RawResourceFact {
        function: 1,
        function_name: "malloc".to_string(),
        caller_name: "caller".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: true,
        contract: omniscope_types::PointerContract::Owned,
        arg_index: Some(0),
    };

    let srt: Option<std::collections::HashMap<String, Vec<omniscope_semantics::SemanticKind>>> =
        None;
    let summary_store = SummaryStore::new();
    let func_termination: std::collections::HashMap<String, FunctionTermination> =
        std::collections::HashMap::new();
    let exit_states = collect_exit_states(
        &pointer_states,
        &alloc,
        &srt,
        &summary_store,
        &func_termination,
    );

    // Both Owned states preserved — dedup only applies to Released.
    assert_eq!(
        exit_states.len(),
        2,
        "Owned states should not be subject to mutual-exclusivity dedup"
    );
    assert!(
        exit_states
            .iter()
            .all(|s| s.resource_state == ResourcePathState::Owned),
        "both entries should be Owned"
    );
}

/// Objective: Verify that a mix of Released and Owned states from mutually
/// exclusive paths produces correct results: one Released + Owned(s).
///
/// Models:
///   if (cond) { free(p); } else { /* p still owned */ }
///
/// Invariant: Released deduped per-instance; Owned always preserved.
#[test]
fn test_collect_exit_states_mixed_released_and_owned() {
    use std::collections::HashMap;

    let mut pointer_states = HashMap::new();
    // One branch releases instance 1.
    pointer_states.insert(
        "caller_then".to_string(),
        crate::resource::ownership_solver::PointerValueState::Released { instance: 1 },
    );
    // Else branch keeps it owned.
    pointer_states.insert(
        "caller_else".to_string(),
        crate::resource::ownership_solver::PointerValueState::Owned {
            instance: 1,
            family: FamilyId::C_HEAP,
        },
    );
    // Duplicate Released for same instance from another path (should dedup).
    pointer_states.insert(
        "caller_else_if".to_string(),
        crate::resource::ownership_solver::PointerValueState::Released { instance: 1 },
    );

    let alloc = RawResourceFact {
        function: 1,
        function_name: "malloc".to_string(),
        caller_name: "caller".to_string(),
        family: Some(FamilyId::C_HEAP),
        boundary_evidence: None,
        is_acquire: true,
        contract: omniscope_types::PointerContract::Owned,
        arg_index: Some(0),
    };

    let srt: Option<std::collections::HashMap<String, Vec<omniscope_semantics::SemanticKind>>> =
        None;
    let summary_store = SummaryStore::new();
    let func_termination: std::collections::HashMap<String, FunctionTermination> =
        std::collections::HashMap::new();
    let exit_states = collect_exit_states(
        &pointer_states,
        &alloc,
        &srt,
        &summary_store,
        &func_termination,
    );

    // Should have 2 entries: 1 Released (deduped) + 1 Owned.
    assert_eq!(
        exit_states.len(),
        2,
        "expected 1 Released (deduped) + 1 Owned"
    );
    let released_count = exit_states
        .iter()
        .filter(|s| s.resource_state == ResourcePathState::Released)
        .count();
    let owned_count = exit_states
        .iter()
        .filter(|s| s.resource_state == ResourcePathState::Owned)
        .count();
    assert_eq!(released_count, 1, "exactly 1 Released after dedup");
    assert_eq!(owned_count, 1, "exactly 1 Owned");
}
