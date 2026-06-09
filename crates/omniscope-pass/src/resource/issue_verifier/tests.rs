//! Tests for the issue verifier pass.

use super::*;
use omniscope_core::FfiEvidence;
use omniscope_types::{Evidence, FamilyId};

#[test]
fn test_verifier_creation() {
    let pass = IssueVerifierPass::new();
    assert_eq!(
        pass.name(),
        "IssueVerifier",
        "Pass name should be IssueVerifier"
    );
    assert_eq!(
        pass.kind(),
        PassKind::Analysis,
        "Pass kind should be Analysis"
    );
    assert_eq!(
        pass.dependencies(),
        vec!["IssueCandidateBuilder", "FfiReturnCheck", "LeakDetection"],
        "Dependencies should be IssueCandidateBuilder, FfiReturnCheck, and LeakDetection"
    );
}

#[test]
fn test_verify_cross_family_confirmed() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_SCALAR)
    .with_release_function("operator delete");

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "Cross-family free should be confirmed issue"
    );
}

#[test]
fn test_verify_same_family_explained_safe() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::C_HEAP)
    .with_release_function("free");

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Same-family release is not an issue"
    );
}

#[test]
fn test_verify_needs_model_is_diagnostic() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::NeedsModel,
        FamilyId::C_HEAP,
        "custom_alloc",
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::Diagnostic,
        "NeedsModel should be a diagnostic, not an error"
    );
}

#[test]
fn test_verify_double_release_confirmed() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "Double release should be confirmed issue"
    );
}

#[test]
fn test_declaration_only_double_release_suppressed() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    )
    .with_release_function("free");

    let user_defined = std::collections::HashSet::new();
    let declared = std::collections::HashSet::from(["free".to_string()]);

    assert!(
        is_declaration_only_candidate(&candidate, &user_defined, &declared),
        "extern declaration-only free must not become an executable double-free"
    );
}

#[test]
fn test_user_defined_free_not_declaration_only_suppressed() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    )
    .with_release_function("free")
    .with_alloc_caller("double_free_demo")
    .with_release_caller("double_free_demo");

    let user_defined =
        std::collections::HashSet::from(["free".to_string(), "double_free_demo".to_string()]);
    let declared = std::collections::HashSet::from(["free".to_string()]);

    assert!(
        !is_declaration_only_candidate(&candidate, &user_defined, &declared),
        "a user-defined wrapper or user caller must remain eligible for double-free reporting"
    );
}

#[test]
fn test_declaration_only_double_release_not_suppressed_with_user_release_caller() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    )
    .with_release_function("free")
    .with_release_caller("double_free_demo");

    let user_defined = std::collections::HashSet::from(["double_free_demo".to_string()]);
    let declared = std::collections::HashSet::from(["free".to_string()]);

    assert!(
        !is_declaration_only_candidate(&candidate, &user_defined, &declared),
        "extern free called from user code can still represent a real double-free"
    );
}

#[test]
fn test_declaration_only_gate_ignores_non_double_release() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "free",
    )
    .with_release_function("free");

    let user_defined = std::collections::HashSet::new();
    let declared = std::collections::HashSet::from(["free".to_string()]);

    assert!(
        !is_declaration_only_candidate(&candidate, &user_defined, &declared),
        "declaration-only suppressor must not affect non-double-release candidates"
    );
}

#[test]
fn test_same_language_allocator_wrapper_noise_suppressed() {
    use omniscope_ir::IRModule;

    let ir = r#"
        declare ptr @mi_malloc(i64)
        declare void @mi_free(ptr)

        define ptr @_RNvCs_allocator_wrapper(i64 %n) {
            %p = call ptr @mi_malloc(i64 %n)
            ret ptr %p
        }

        define void @_RNvCs_allocator_release(ptr %p) {
            call void @mi_free(ptr %p)
            ret void
        }
    "#;
    let module = IRModule::parse_from_text(ir);
    let index = crate::module_index::ModuleIndex::build(&module);
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossLanguageFree,
        FamilyId::RUST_GLOBAL,
        "_RNvCs_allocator_wrapper",
    )
    .with_release_family(FamilyId::MIMALLOC)
    .with_release_function("_RNvCs_allocator_release")
    .with_alloc_caller("_RNvCs_allocator_wrapper")
    .with_release_caller("_RNvCs_allocator_release");

    assert!(
        is_same_language_allocator_wrapper_noise(&candidate, &index),
        "same-language allocator wrappers around C allocator thunks are design intent, not cross-language free"
    );
}

#[test]
fn test_cross_language_wrapper_not_suppressed() {
    use omniscope_ir::IRModule;

    let ir = r#"
        declare ptr @malloc(i64)
        declare void @_RNvCs_rust_dealloc(ptr)

        define ptr @c_alloc(i64 %n) {
            %p = call ptr @malloc(i64 %n)
            ret ptr %p
        }

        define void @_RNvCs_release(ptr %p) {
            call void @_RNvCs_rust_dealloc(ptr %p)
            ret void
        }
    "#;
    let module = IRModule::parse_from_text(ir);
    let index = crate::module_index::ModuleIndex::build(&module);
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossLanguageFree,
        FamilyId::C_HEAP,
        "c_alloc",
    )
    .with_release_family(FamilyId::RUST_GLOBAL)
    .with_release_function("_RNvCs_rust_dealloc")
    .with_alloc_caller("c_alloc")
    .with_release_caller("_RNvCs_release");

    assert!(
        !is_same_language_allocator_wrapper_noise(&candidate, &index),
        "genuine C-to-Rust release path must not be suppressed by wrapper-noise gate"
    );
}

#[test]
fn test_same_language_wrapper_gate_does_not_suppress_plain_cross_family_without_wrapper() {
    use omniscope_ir::IRModule;

    let ir = r#"
        declare ptr @malloc(i64)
        declare void @_ZdaPv(ptr)

        define void @plain_user(ptr %p) {
            call void @_ZdaPv(ptr %p)
            ret void
        }
    "#;
    let module = IRModule::parse_from_text(ir);
    let index = crate::module_index::ModuleIndex::build(&module);
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_ARRAY)
    .with_release_function("_ZdaPv")
    .with_release_caller("plain_user");

    assert!(
        !is_same_language_allocator_wrapper_noise(&candidate, &index),
        "plain cross-family C heap -> C++ delete without allocator-wrapper evidence must not be suppressed"
    );
}

#[test]
fn test_same_language_wrapper_gate_ignores_double_release() {
    use omniscope_ir::IRModule;

    let ir = r#"
        declare void @mi_free(ptr)

        define void @_RNvCs_allocator_release(ptr %p) {
            call void @mi_free(ptr %p)
            ret void
        }
    "#;
    let module = IRModule::parse_from_text(ir);
    let index = crate::module_index::ModuleIndex::build(&module);
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DoubleRelease,
        FamilyId::MIMALLOC,
        "_RNvCs_allocator_release",
    )
    .with_release_function("_RNvCs_allocator_release")
    .with_alloc_caller("_RNvCs_allocator_release")
    .with_release_caller("_RNvCs_allocator_release");

    assert!(
        !is_same_language_allocator_wrapper_noise(&candidate, &index),
        "same-language wrapper gate must not suppress generic double-release candidates"
    );
}

#[test]
fn test_verify_destructor_release_explained_safe() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::RUST_GLOBAL,
        "__rust_alloc",
    )
    .with_release_family(FamilyId::C_HEAP)
    .with_release_function("drop");

    // Attach destructor release evidence
    candidate.add_evidence(
        Evidence::new(EvidenceKind::DestructorRelease, "Rust Drop calling C free")
            .with_confidence(0.9),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Destructor-mediated release should be explained safe"
    );
}

#[test]
fn test_verify_conditional_leak_with_return_escape() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::C_HEAP,
        "malloc",
    );

    // Attach return-to-caller evidence
    candidate.add_evidence(
        Evidence::new(EvidenceKind::ReturnToCaller, "pointer returned to caller")
            .with_confidence(0.95),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Return-to-caller escape should explain the leak"
    );
}

#[test]
fn test_verify_conditional_leak_with_static_lifetime() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::C_HEAP,
        "__cxx_global_var_init",
    );

    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::StaticLifetimeSink,
            "global variable initialization",
        )
        .with_confidence(0.95),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Static-lifetime sink should explain the leak"
    );
}

#[test]
fn test_verify_borrow_escape_with_bridge_evidence() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::BorrowEscape,
        FamilyId::C_HEAP,
        "as_ptr",
    );

    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::BridgeHelper,
            "as_ptr returns borrowed pointer",
        )
        .with_confidence(0.95),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Bridge helper should explain the borrow escape"
    );
}

#[test]
fn test_verify_callback_escape_diagnostic() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CallbackEscape,
        FamilyId::C_HEAP,
        "register_callback",
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::Diagnostic,
        "Callback escape should be diagnostic"
    );
}

#[test]
fn test_verify_cross_family_unknown_release_family() {
    let registry = FamilyRegistry::new();
    // No release family specified — probable issue
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "Unknown release family should be probable issue"
    );
}

#[test]
fn test_verify_definite_leak_without_escape_is_confirmed() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "malloc",
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "Definite leak without valid escape must be confirmed issue"
    );
}

#[test]
fn test_verify_definite_leak_with_ownership_escape_is_confirmed() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "into_raw_wrapper",
    );
    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::OwnershipEscapeLeak,
            "Box::into_raw without matching from_raw",
        )
        .with_confidence(0.95),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "Definite leak with OwnershipEscapeLeak evidence must still be confirmed"
    );
}

#[test]
fn test_verdict_description_definite_leak() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "malloc",
    );

    let desc = build_verdict_description(&candidate, VerifierVerdict::ConfirmedIssue);
    assert!(
        desc.contains("definite leak"),
        "Description must mention definite leak"
    );
    assert!(
        desc.contains("no release on any analyzed path"),
        "Description must mention no release on any analyzed path"
    );
}

#[test]
fn test_verdict_description_conditional_leak() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::C_HEAP,
        "malloc",
    );

    let desc = build_verdict_description(&candidate, VerifierVerdict::ProbableIssue);
    assert!(
        desc.contains("conditional leak"),
        "Description must mention conditional leak"
    );
    assert!(
        desc.contains("may not be freed on all paths"),
        "Description must mention partial release coverage"
    );
}

#[test]
fn test_verdict_description_cross_family() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_SCALAR)
    .with_release_function("operator delete");

    let desc = build_verdict_description(&candidate, VerifierVerdict::ConfirmedIssue);
    assert!(
        desc.contains("cross-family free"),
        "Description must mention cross-family free"
    );
    assert!(
        desc.contains("confirmed"),
        "Description must mention verdict"
    );
}

#[test]
fn test_verdict_description_needs_model() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::NeedsModel,
        FamilyId::C_HEAP,
        "custom_alloc",
    );

    let desc = build_verdict_description(&candidate, VerifierVerdict::Diagnostic);
    assert!(
        desc.contains("needs model"),
        "Description must mention needs model"
    );
    assert!(
        desc.contains("diagnostic"),
        "Description must mention verdict"
    );
}

/// Objective: Verify that null-guard alone does NOT suppress double-free.
#[test]
fn test_verify_double_release_with_null_guard_evidence() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    );

    candidate.add_evidence(
        Evidence::new(EvidenceKind::NullGuardedRelease, "free(NULL) is safe in C")
            .with_confidence(0.9),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "Null-guarded release without path analysis should still be confirmed issue"
    );
}

#[test]
fn test_verify_double_release_with_all_evidence() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    );

    candidate.add_evidence(
        Evidence::new(EvidenceKind::NullGuardedRelease, "free(NULL) is safe in C")
            .with_confidence(0.9),
    );
    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::NullStoreAfterRelease,
            "NULL stored after release",
        )
        .with_confidence(0.8),
    );
    candidate.add_evidence(
        Evidence::new(EvidenceKind::PathStateRefinement, "control flow analyzed")
            .with_confidence(0.85),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Double release with null guard, null store, and path refinement should be explained safe"
    );
}

#[test]
fn test_verify_double_release_without_evidence() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "Double release without evidence should be confirmed issue"
    );
}

#[test]
fn test_verify_definite_leak_with_out_param_evidence() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "malloc",
    );

    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::OutParamOwnedOnSuccess,
            "resource returned via out-param on success",
        )
        .with_confidence(0.9),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Definite leak with out-param escape should be explained safe"
    );
}

#[test]
fn test_verify_definite_leak_with_return_evidence() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "malloc",
    );

    candidate.add_evidence(
        Evidence::new(EvidenceKind::ReturnToCaller, "resource returned to caller")
            .with_confidence(0.95),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Definite leak with return escape should be explained safe"
    );
}

#[test]
fn test_verify_conditional_leak_with_out_param_on_success() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::C_HEAP,
        "malloc",
    );

    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::OutParamOwnedOnSuccess,
            "resource returned via out-param on success",
        )
        .with_confidence(0.9),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Conditional leak with out-param on success should be explained safe"
    );
}

#[test]
fn test_verify_conditional_leak_with_out_param_null_on_error() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::C_HEAP,
        "malloc",
    );

    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::OutParamNullOnError,
            "out-param set to NULL on error path",
        )
        .with_confidence(0.9),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Conditional leak with out-param null on error should be explained safe"
    );
}

#[test]
fn test_verify_conditional_leak_with_path_refinement() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::C_HEAP,
        "malloc",
    );

    candidate.add_evidence(
        Evidence::new(EvidenceKind::PathStateRefinement, "control flow analyzed")
            .with_confidence(0.85),
    );

    let verdict = verify_candidate(&candidate, &registry, None, None);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "Conditional leak with path refinement should be probable issue"
    );
}

// ── Phase 2: verify_cross_family_with_bundle tests ──

/// Objective: Verify bundle-based CrossFamily TP confirms when families
/// are incompatible and no semantic suppression exists.
#[test]
fn test_verify_cross_family_with_bundle_confirmed() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_SCALAR)
    .with_release_function("operator delete");

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_cross_family_with_bundle(&bundle, &registry);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "Incompatible families without semantic suppression must be confirmed"
    );
}

/// Objective: Verify bare family mismatch does not confirm without
/// release-flow or same-resource evidence.
#[test]
fn test_verify_cross_family_with_bundle_requires_reachable_release() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        7,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_SCALAR);

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    assert!(
        !bundle.has_reachable_release,
        "missing release_function/evidence must not count as reachable release"
    );
    let verdict = verify_cross_family_with_bundle(&bundle, &registry);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "Bare family mismatch must not be confirmed"
    );
}

/// Objective: Verify CrossLanguageFree is reportable as CrossFamilyFree
/// only when the family pair is incompatible.
#[test]
fn test_should_report_cross_language_as_cross_family_on_family_mismatch() {
    let registry = FamilyRegistry::new();
    let mismatch = IssueCandidate::new(
        8,
        IssueCandidateKind::CrossLanguageFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_SCALAR)
    .with_release_function("_ZdlPv");
    let compatible = IssueCandidate::new(
        9,
        IssueCandidateKind::CrossLanguageFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::C_HEAP)
    .with_release_function("free");

    assert!(
        should_report_as_cross_family(&mismatch, &registry),
        "incompatible CrossLanguageFree must be promoted to CrossFamilyFree"
    );
    assert!(
        !should_report_as_cross_family(&compatible, &registry),
        "compatible CrossLanguageFree must not be promoted"
    );
}

/// Objective: Verify bundle-based CrossFamily returns ExplainedSafe when
/// families are compatible.
#[test]
fn test_verify_cross_family_with_bundle_same_family_safe() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        2,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::C_HEAP)
    .with_release_function("free");

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_cross_family_with_bundle(&bundle, &registry);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Same family must be ExplainedSafe"
    );
}

/// Objective: Verify bundle-based CrossFamily is suppressed when semantic
/// facts explain safe ownership (e.g., RuntimeManagedResource).
#[test]
fn test_verify_cross_family_with_bundle_semantic_suppression() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        3,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_SCALAR)
    .with_release_function("operator delete");

    let mut srt = std::collections::HashMap::new();
    srt.insert(
        "malloc".to_string(),
        vec![SemanticKind::RuntimeManagedResource],
    );

    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "malloc".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("malloc"),
            SemanticKind::RuntimeManagedResource,
            omniscope_semantics::FactConfidence::High,
            omniscope_semantics::FactSource::IRPattern,
            "test: runtime-managed resource",
        )],
    );

    let bundle = EvidenceBundle::from_candidate(&candidate, None, Some(&srt), Some(&srt_facts));
    assert!(
        bundle.has_semantic_suppression(),
        "RuntimeManagedResource must set semantic suppression flag"
    );
    assert!(
        bundle.has_semantic_suppression_high_confidence(),
        "High-confidence RuntimeManagedResource fact must set high-confidence suppression"
    );
    let verdict = verify_cross_family_with_bundle(&bundle, &registry);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "High-confidence semantic suppression must downgrade cross-family free to ProbableIssue (not fully suppress)"
    );
}

/// Objective: Verify cross-language evidence remains attached as a
/// secondary fact.
#[test]
fn test_cross_language_evidence_remains_secondary() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        4,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::SQLITE_RESOURCE)
    .with_release_function("sqlite3_free")
    .with_ffi_evidence(FfiEvidence::CrossFamilyRelease {
        alloc_family: "C_HEAP".to_string(),
        release_family: "SQLITE_RESOURCE".to_string(),
    });

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    assert!(
        bundle.has_boundary_evidence,
        "FFI evidence must mark boundary flag"
    );

    let verdict = verify_cross_family_with_bundle(&bundle, &registry);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "Cross-family with FFI evidence must confirm CrossFamilyFree"
    );

    assert_eq!(
        candidate.kind,
        IssueCandidateKind::CrossFamilyFree,
        "Primary issue kind must remain CrossFamilyFree; cross-language is secondary"
    );
}

/// Objective: Verify destructor evidence suppresses CrossFamilyFree
/// in the bundle-based path.
#[test]
fn test_verify_cross_family_with_bundle_destructor_safe() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        5,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::RUST_GLOBAL,
        "__rust_alloc",
    )
    .with_release_family(FamilyId::C_HEAP)
    .with_release_function("drop");
    candidate.add_evidence(
        Evidence::new(EvidenceKind::DestructorRelease, "Rust Drop calling C free")
            .with_confidence(0.9),
    );

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_cross_family_with_bundle(&bundle, &registry);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "Destructor-mediated release must be ExplainedSafe in bundle path"
    );
}

/// Objective: Verify escape evidence downgrades CrossFamilyFree to
/// ProbableIssue in the bundle-based path.
#[test]
fn test_verify_cross_family_with_bundle_escape_downgrades() {
    let registry = FamilyRegistry::new();
    let mut candidate = IssueCandidate::new(
        6,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_SCALAR)
    .with_release_function("operator delete");
    candidate.add_evidence(
        Evidence::new(EvidenceKind::ReturnToCaller, "pointer returned to caller")
            .with_confidence(0.95),
    );

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_cross_family_with_bundle(&bundle, &registry);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "Escape evidence must downgrade to ProbableIssue in bundle path"
    );
}

// ── Phase 3: verify_double_release_with_bundle tests ──

#[test]
fn test_verify_double_release_with_bundle_same_instance_confirmed() {
    let candidate = IssueCandidate::new(
        10,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    )
    .with_resource_id(42);

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    assert!(
        bundle.has_same_resource_evidence,
        "resource_id must count as same-resource evidence"
    );
    let verdict = verify_double_release_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "Same-instance DoubleFree without alias rejection must be confirmed"
    );
}

#[test]
fn test_verify_double_release_with_bundle_multiple_release_confirmed() {
    let mut candidate = IssueCandidate::new(
        11,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    );
    candidate.add_evidence(Evidence::new(
        EvidenceKind::MultipleRelease,
        "same pointer released twice",
    ));

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_double_release_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "MultipleRelease evidence must confirm DoubleFree"
    );
}

#[test]
fn test_verify_double_release_with_bundle_no_instance_downgraded() {
    let candidate = IssueCandidate::new(
        12,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    );

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    assert!(
        !bundle.has_same_resource_evidence,
        "No resource_id must mean no same-resource evidence"
    );
    let verdict = verify_double_release_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "No same-instance evidence must downgrade DoubleFree to ProbableIssue"
    );
}

#[test]
fn test_verify_double_release_with_bundle_use_after_free_not_same_instance_proof() {
    let mut candidate = IssueCandidate::new(
        16,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    );
    candidate.add_evidence(Evidence::new(
        EvidenceKind::UseAfterFree,
        "released resource was later used",
    ));

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    assert!(
        !bundle.has_same_resource_evidence,
        "UseAfterFree evidence alone must not count as DoubleFree same-instance proof"
    );
    let verdict = verify_double_release_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "DoubleFree requires resource_id or MultipleRelease positive evidence"
    );
}

#[test]
fn test_verify_double_release_with_bundle_alias_rejection_downgraded() {
    let mut candidate = IssueCandidate::new(
        13,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    )
    .with_resource_id(42);
    candidate.add_evidence(Evidence::new(
        EvidenceKind::Insufficient,
        "may_alias=NotAlias: independent allocation roots",
    ));

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    assert!(
        bundle.has_alias_rejection,
        "may_alias=NotAlias must set alias rejection"
    );
    let verdict = verify_double_release_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "Alias rejection must downgrade DoubleFree to ProbableIssue"
    );
}

#[test]
fn test_verify_double_release_with_bundle_user_wrapper() {
    let candidate = IssueCandidate::new(
        14,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    )
    .with_release_function("free")
    .with_alloc_caller("user_cleanup")
    .with_release_caller("user_cleanup")
    .with_resource_id(99);

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_double_release_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "User-defined wrapper calling extern free must report DoubleFree with same-instance evidence"
    );
}

#[test]
fn test_verify_double_release_with_bundle_null_safe_requires_all_three() {
    let mut candidate = IssueCandidate::new(
        15,
        IssueCandidateKind::DoubleRelease,
        FamilyId::C_HEAP,
        "free",
    )
    .with_resource_id(50);
    candidate.add_evidence(Evidence::new(
        EvidenceKind::NullGuardedRelease,
        "free(NULL) is safe",
    ));
    candidate.add_evidence(Evidence::new(
        EvidenceKind::NullStoreAfterRelease,
        "NULL stored after release",
    ));
    // Missing: PathStateRefinement

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_double_release_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "Null-guard + null-store without path refinement must NOT suppress double-free"
    );
}

// ── Phase 4: verify_definite_leak_with_bundle / verify_conditional_leak_with_bundle tests ──

#[test]
fn test_verify_definite_leak_with_bundle_confirmed() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "malloc",
    );
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_definite_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "DefiniteLeak without suppression must be ConfirmedIssue"
    );
}

#[test]
fn test_verify_definite_leak_with_bundle_runtime_managed_safe() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "malloc",
    );
    let mut srt: std::collections::HashMap<String, Vec<SemanticKind>> =
        std::collections::HashMap::new();
    srt.insert(
        "malloc".to_string(),
        vec![SemanticKind::RuntimeManagedResource],
    );

    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "malloc".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("malloc"),
            SemanticKind::RuntimeManagedResource,
            omniscope_semantics::FactConfidence::High,
            omniscope_semantics::FactSource::IRPattern,
            "test: runtime-managed resource",
        )],
    );

    let bundle = EvidenceBundle::from_candidate(&candidate, None, Some(&srt), Some(&srt_facts));
    let verdict = verify_definite_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "DefiniteLeak with high-confidence RuntimeManagedResource must be ExplainedSafe"
    );
}

#[test]
fn test_verify_definite_leak_with_bundle_return_to_caller_safe() {
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "malloc",
    );
    candidate.add_evidence(Evidence::new(
        EvidenceKind::ReturnToCaller,
        "pointer returned to caller",
    ));
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_definite_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "DefiniteLeak with ReturnToCaller must be ExplainedSafe"
    );
}

#[test]
fn test_verify_definite_leak_with_bundle_ownership_escape_confirmed() {
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "into_raw",
    );
    candidate.add_evidence(Evidence::new(
        EvidenceKind::OwnershipEscapeLeak,
        "into_raw without from_raw",
    ));
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_definite_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "DefiniteLeak with OwnershipEscapeLeak must be ConfirmedIssue"
    );
}

#[test]
fn test_verify_conditional_leak_with_bundle_probable() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::C_HEAP,
        "malloc",
    );
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_conditional_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "ConditionalLeak without suppression must be ProbableIssue"
    );
}

#[test]
fn test_verify_conditional_leak_with_bundle_static_lifetime_safe() {
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::C_HEAP,
        "malloc",
    );
    candidate.add_evidence(Evidence::new(
        EvidenceKind::StaticLifetimeSink,
        "process-lifetime allocation",
    ));
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_conditional_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "ConditionalLeak with StaticLifetimeSink must be ExplainedSafe"
    );
}

#[test]
fn test_verify_conditional_leak_with_bundle_stored_to_owner_safe() {
    let mut candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::C_HEAP,
        "malloc",
    );
    candidate.add_evidence(Evidence::new(
        EvidenceKind::FieldStoreToOwner,
        "stored in owner field",
    ));
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, None);
    let verdict = verify_conditional_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "ConditionalLeak with FieldStoreToOwner must be ExplainedSafe"
    );
}

#[test]
fn test_verify_conditional_leak_with_bundle_global_provenance_safe() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::C_HEAP,
        "malloc",
    );
    let mut srt: std::collections::HashMap<String, Vec<SemanticKind>> =
        std::collections::HashMap::new();
    srt.insert("malloc".to_string(), vec![SemanticKind::GlobalProvenance]);
    let bundle = EvidenceBundle::from_candidate(&candidate, None, Some(&srt), None);
    let verdict = verify_conditional_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "ConditionalLeak with GlobalProvenance must be ExplainedSafe"
    );
}

// ── Phase 5: Confidence-aware verifier tests ──

#[test]
fn test_phase5_definite_leak_high_confidence_runtime_managed_safe() {
    let candidate = IssueCandidate::new(
        100,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "arena_alloc",
    );
    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "arena_alloc".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("arena_alloc"),
            SemanticKind::RuntimeManagedResource,
            omniscope_semantics::FactConfidence::High,
            omniscope_semantics::FactSource::IRPattern,
            "arena-allocated, freed by arena reset",
        )],
    );
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));
    let verdict = verify_definite_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "DefiniteLeak with high-confidence RuntimeManagedResource must be ExplainedSafe"
    );
}

#[test]
fn test_phase5_definite_leak_medium_confidence_downgraded() {
    let candidate = IssueCandidate::new(
        101,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "arena_alloc",
    );
    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "arena_alloc".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("arena_alloc"),
            SemanticKind::RuntimeManagedResource,
            omniscope_semantics::FactConfidence::Medium,
            omniscope_semantics::FactSource::ContractDB,
            "inferred runtime-managed from structural analysis",
        )],
    );
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));
    let verdict = verify_definite_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "DefiniteLeak with medium-confidence RuntimeManagedResource must be downgraded to ProbableIssue"
    );
}

#[test]
fn test_phase5_refcount_transfer_suppresses_leak() {
    let candidate = IssueCandidate::new(
        102,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::RUST_GLOBAL,
        "Arc::into_raw",
    );
    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "Arc::into_raw".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("Arc::into_raw"),
            SemanticKind::RefcountTransfer,
            omniscope_semantics::FactConfidence::High,
            omniscope_semantics::FactSource::BehaviorSummary,
            "Arc reference count transferred to raw pointer",
        )],
    );
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));
    let verdict = verify_conditional_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "ConditionalLeak with high-confidence RefcountTransfer must be ExplainedSafe"
    );
}

#[test]
fn test_phase5_cross_family_high_confidence_semantic_suppressed() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        103,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_SCALAR)
    .with_release_function("operator delete");

    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "malloc".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("malloc"),
            SemanticKind::RuntimeManagedResource,
            omniscope_semantics::FactConfidence::High,
            omniscope_semantics::FactSource::IRPattern,
            "runtime-managed resource",
        )],
    );

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));
    let verdict = verify_cross_family_with_bundle(&bundle, &registry);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "Cross-family free with high-confidence semantic suppression must be downgraded to ProbableIssue (not fully suppressed)"
    );
}

#[test]
fn test_phase5_cross_family_medium_confidence_downgraded() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        104,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_SCALAR)
    .with_release_function("operator delete");

    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "malloc".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("malloc"),
            SemanticKind::RuntimeManagedResource,
            omniscope_semantics::FactConfidence::Medium,
            omniscope_semantics::FactSource::ContractDB,
            "inferred runtime-managed",
        )],
    );

    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));
    let verdict = verify_cross_family_with_bundle(&bundle, &registry);
    assert_eq!(
        verdict,
        VerifierVerdict::ProbableIssue,
        "Cross-family free with medium-confidence semantic suppression must be ProbableIssue"
    );
}

#[test]
fn test_phase5_abort_on_oom_suppresses_leak() {
    let candidate = IssueCandidate::new(
        105,
        IssueCandidateKind::ConditionalLeak,
        FamilyId::C_HEAP,
        "oom_alloc",
    );
    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "oom_alloc".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("oom_alloc"),
            SemanticKind::AbortOnOom,
            omniscope_semantics::FactConfidence::High,
            omniscope_semantics::FactSource::IRPattern,
            "allocation aborts on OOM",
        )],
    );
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));
    let verdict = verify_conditional_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "ConditionalLeak with high-confidence AbortOnOom must be ExplainedSafe"
    );
}

#[test]
fn test_phase5_ownership_escape_overrides_medium_confidence_suppression() {
    let mut candidate = IssueCandidate::new(
        106,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "into_raw",
    );
    candidate.add_evidence(Evidence::new(
        EvidenceKind::OwnershipEscapeLeak,
        "into_raw without from_raw",
    ));
    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "into_raw".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("into_raw"),
            SemanticKind::RuntimeManagedResource,
            omniscope_semantics::FactConfidence::Medium,
            omniscope_semantics::FactSource::ContractDB,
            "inferred runtime-managed",
        )],
    );
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));
    let verdict = verify_definite_leak_with_bundle(&bundle);
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "OwnershipEscapeLeak must override medium-confidence semantic suppression"
    );
}

/// Objective: Verify that StaticLifetimeSink (SemanticKind) suppresses
/// process-lifetime DefiniteLeak via the verifier route.
/// Invariants: High-confidence StaticLifetimeSink → ExplainedSafe for leak.
#[test]
fn test_phase5_static_lifetime_sink_suppresses_process_lifetime_leak() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        107,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::CPP_NEW_SCALAR,
        "__cxx_global_var_init",
    );
    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "__cxx_global_var_init".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("__cxx_global_var_init"),
            SemanticKind::StaticLifetimeSink,
            omniscope_semantics::FactConfidence::High,
            omniscope_semantics::FactSource::IRPattern,
            "global variable initializer — process lifetime",
        )],
    );
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));
    let verdict = verify_candidate_inner(&candidate, &registry, None, None, Some(&bundle));
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "DefiniteLeak with high-confidence StaticLifetimeSink must be ExplainedSafe"
    );
}

/// Objective: Verify that DestructorRelease (SemanticKind) suppresses
/// leak via the verifier route with high confidence.
/// Invariants: High-confidence DestructorRelease → ExplainedSafe for leak.
#[test]
fn test_phase5_destructor_release_suppresses_leak() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        108,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::CPP_NEW_SCALAR,
        "~MyClass",
    );
    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "~MyClass".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("~MyClass"),
            SemanticKind::DestructorRelease,
            omniscope_semantics::FactConfidence::High,
            omniscope_semantics::FactSource::BehaviorSummary,
            "C++ destructor release — compiler-managed cleanup",
        )],
    );
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));
    let verdict = verify_candidate_inner(&candidate, &registry, None, None, Some(&bundle));
    assert_eq!(
        verdict,
        VerifierVerdict::ExplainedSafe,
        "DefiniteLeak with high-confidence DestructorRelease must be ExplainedSafe"
    );
}

/// Objective: Verify that function-local leak without StaticLifetimeSink
/// is NOT suppressed even when StaticLifetimeSink is present on a
/// different symbol. A global init function having static lifetime
/// should not suppress a local_malloc leak.
/// Invariants: Semantic fact for different symbol → no suppression.
#[test]
fn test_phase5_static_lifetime_does_not_suppress_function_local_leak() {
    let registry = FamilyRegistry::new();
    let candidate = IssueCandidate::new(
        109,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::C_HEAP,
        "local_malloc",
    );
    // StaticLifetimeSink fact is for a *different* function.
    let mut srt_facts: std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>> =
        std::collections::HashMap::new();
    srt_facts.insert(
        "__cxx_global_var_init".to_string(),
        vec![omniscope_semantics::SemanticFact::new(
            omniscope_semantics::SemanticKey::symbol("__cxx_global_var_init"),
            SemanticKind::StaticLifetimeSink,
            omniscope_semantics::FactConfidence::High,
            omniscope_semantics::FactSource::IRPattern,
            "global variable initializer",
        )],
    );
    let bundle = EvidenceBundle::from_candidate(&candidate, None, None, Some(&srt_facts));
    // Bundle should not find suppression for local_malloc.
    assert!(
        !bundle.has_leak_suppression_high_confidence(),
        "StaticLifetimeSink for different symbol must not suppress local_malloc leak"
    );
    let verdict = verify_candidate_inner(&candidate, &registry, None, None, Some(&bundle));
    assert_eq!(
        verdict,
        VerifierVerdict::ConfirmedIssue,
        "Function-local DefiniteLeak without StaticLifetimeSink must remain ConfirmedIssue"
    );
}
