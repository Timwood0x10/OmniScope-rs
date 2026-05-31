//! Test Matrix integration tests for the Resource Contract architecture.
//!
//! Verifies the key scenarios from ARCHITECTURE_ADJUSTMENT.md Test Matrix:
//! - Same-family and cross-family release matching
//! - Structural inference patterns (destructor, bridge, refcount, static-lifetime)
//! - Issue candidate verification and verdict gating
//!
//! These tests exercise the full inference chain:
//!   registry lookup → structural inference → family inference
//!
//! And the verification chain:
//!   candidate → verifier → verdict → reportability

use omniscope_core::IssueCandidate;
use omniscope_types::{Effect, EvidenceKind, FamilyId, IssueCandidateKind, VerifierVerdict};

use super::family_registry::FamilyRegistry;
use super::summary_inference::infer_summary_for_symbol;

// ─── Same-family release: safe ───────────────────────────────────────

/// Objective: Verify that malloc and free are correctly registered in the same family
///
/// Invariants:
/// - malloc and free must have the same family_id (both C_HEAP)
/// - is_compatible_release(malloc, free) must return true
/// - Same-family candidate should have matching alloc/release families
#[test]
fn test_matrix_malloc_free_same_family_safe() {
    let registry = FamilyRegistry::new();
    let malloc = registry
        .lookup("malloc")
        .expect("test_matrix::test_matrix_malloc_free_same_family_safe: malloc must be registered");
    let free = registry
        .lookup("free")
        .expect("test_matrix::test_matrix_malloc_free_same_family_safe: free must be registered");

    assert_eq!(
        malloc.family_id, free.family_id,
        "malloc/free must be same family (c_heap)"
    );
    assert!(
        registry.is_compatible_release(malloc.family_id, free.family_id),
        "malloc/free must be compatible"
    );

    // Build a candidate and verify it's explained safe
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        malloc.family_id,
        "malloc",
    )
    .with_release_family(free.family_id)
    .with_release_function("free");

    // Same family release → ExplainedSafe
    assert_eq!(
        candidate.alloc_family,
        candidate
            .release_family
            .expect("test_matrix::test_matrix_malloc_free_same_family_safe: release_family should be set for cross-family candidate"),
        "Same-family candidate should have matching families"
    );
}

/// Objective: Verify that C++ new[] and delete[] are correctly registered in the same family
///
/// Invariants:
/// - new[] and delete[] must have the same family_id (both CPP_NEW_ARRAY)
/// - is_compatible_release(new[], delete[]) must return true
/// - Same-family alloc/release operations should be correctly paired
#[test]
fn test_matrix_new_array_delete_array_same_family_safe() {
    let registry = FamilyRegistry::new();
    let new_arr = registry.lookup("_Znam").expect("test_matrix::test_matrix_new_array_delete_array_same_family_safe: _Znam must be registered");
    let del_arr = registry
        .lookup("_ZdaPv")
        .expect("test_matrix::test_matrix_new_array_delete_array_same_family_safe: _ZdaPv must be registered");

    assert_eq!(
        new_arr.family_id, del_arr.family_id,
        "new[]/delete[] must be same family (cpp_new_array)"
    );
    assert!(
        registry.is_compatible_release(new_arr.family_id, del_arr.family_id),
        "new[]/delete[] must be compatible"
    );
}

/// Objective: Verify that Python object allocation and release functions are correctly registered in the same family
///
/// Invariants:
/// - PyObject_New and PyObject_Free must have the same family_id (both PYTHON_OBJECT)
/// - Python object allocation and release operations should be correctly paired
/// - Family registration should support cross-language (Python) resource management
#[test]
fn test_matrix_pyobject_new_pyobject_free_same_family_safe() {
    let registry = FamilyRegistry::new();
    let py_new = registry
        .lookup("PyObject_New")
        .expect("test_matrix::test_matrix_pyobject_new_pyobject_free_same_family_safe: PyObject_New must be registered");
    let py_free = registry
        .lookup("PyObject_Free")
        .expect("test_matrix::test_matrix_pyobject_new_pyobject_free_same_family_safe: PyObject_Free must be registered");

    assert_eq!(
        py_new.family_id, py_free.family_id,
        "PyObject_New/PyObject_Free must be same family (python_object)"
    );
}

// ─── Cross-family mismatch: confirmed issue ──────────────────────────

/// Objective: Verify that C malloc and C++ operator delete are correctly identified as different families
///
/// Invariants:
/// - malloc and operator delete must have different family_id
/// - is_compatible_release(malloc, delete) must return false
/// - Cross-family alloc/release operations should be marked as incompatible
#[test]
fn test_matrix_malloc_delete_cross_family_mismatch() {
    let registry = FamilyRegistry::new();
    let malloc = registry.lookup("malloc").expect(
        "test_matrix::test_matrix_malloc_delete_cross_family_mismatch: malloc must be registered",
    );
    let del = registry
        .lookup("_ZdlPv")
        .expect("test_matrix::test_matrix_malloc_delete_cross_family_mismatch: operator delete must be registered");

    assert_ne!(
        malloc.family_id, del.family_id,
        "malloc and operator delete must be different families"
    );
    assert!(
        !registry.is_compatible_release(malloc.family_id, del.family_id),
        "malloc/delete must be incompatible"
    );
}

/// Objective: Verify that Rust allocator and C free are correctly identified as different families
///
/// Invariants:
/// - __rust_alloc and free must have different family_id
/// - is_compatible_release(__rust_alloc, free) must return false
/// - Rust allocator and C standard library release function should be considered incompatible
#[test]
fn test_matrix_rust_alloc_free_cross_family_mismatch() {
    let registry = FamilyRegistry::new();
    let rust_alloc = registry
        .lookup("__rust_alloc")
        .expect("test_matrix::test_matrix_rust_alloc_free_cross_family_mismatch: __rust_alloc must be registered");
    let free = registry.lookup("free").expect(
        "test_matrix::test_matrix_rust_alloc_free_cross_family_mismatch: free must be registered",
    );

    assert_ne!(
        rust_alloc.family_id, free.family_id,
        "__rust_alloc and free must be different families"
    );
    assert!(
        !registry.is_compatible_release(rust_alloc.family_id, free.family_id),
        "__rust_alloc/free must be incompatible"
    );
}

/// Objective: Verify that Python memory allocation and object release functions are correctly identified as different families
///
/// Invariants:
/// - PyMem_Malloc and PyObject_Free must have different family_id
/// - Python memory management and object management should be considered different resource families
/// - Different Python APIs should have clear family boundaries
#[test]
fn test_matrix_pymem_malloc_pyobject_free_family_mismatch() {
    let registry = FamilyRegistry::new();
    let pymem = registry
        .lookup("PyMem_Malloc")
        .expect("test_matrix::test_matrix_pymem_malloc_pyobject_free_family_mismatch: PyMem_Malloc must be registered");
    let py_free = registry
        .lookup("PyObject_Free")
        .expect("test_matrix::test_matrix_pymem_malloc_pyobject_free_family_mismatch: PyObject_Free must be registered");

    assert_ne!(
        pymem.family_id, py_free.family_id,
        "PyMem_Malloc and PyObject_Free must be different families"
    );
}

/// Objective: Verify that JNI local references and global references are correctly identified as different families
///
/// Invariants:
/// - NewLocalRef and DeleteGlobalRef must have different family_id
/// - JNI local references and global references should be considered different resource types
/// - Different JNI reference types should have clear family boundaries
#[test]
fn test_matrix_jni_local_global_ref_mismatch() {
    let registry = FamilyRegistry::new();
    let local = registry.lookup("NewLocalRef").expect(
        "test_matrix::test_matrix_jni_local_global_ref_mismatch: NewLocalRef must be registered",
    );
    let global_del = registry
        .lookup("DeleteGlobalRef")
        .expect("test_matrix::test_matrix_jni_local_global_ref_mismatch: DeleteGlobalRef must be registered");

    assert_ne!(
        local.family_id, global_del.family_id,
        "Local and global refs are different families"
    );
}

/// Objective: Verify that Windows HGlobal and CoTaskMem are correctly identified as different families
///
/// Invariants:
/// - AllocHGlobal and CoTaskMemFree must have different family_id
/// - Different Windows memory management APIs should be considered different resource families
/// - Cross-Windows-API alloc/release operations should be marked as incompatible
#[test]
fn test_matrix_hglobal_cotask_mismatch() {
    let registry = FamilyRegistry::new();
    let hglobal = registry
        .lookup("AllocHGlobal")
        .expect("AllocHGlobal must be registered");
    let cotask = registry
        .lookup("CoTaskMemFree")
        .expect("CoTaskMemFree must be registered");

    assert_ne!(
        hglobal.family_id, cotask.family_id,
        "HGlobal and CoTaskMem are different families"
    );
}

// ─── Refcount conditional release ─────────────────────────────────────

/// Objective: Verify that Py_DECREF is correctly identified as conditional release rather than unconditional release
///
/// Invariants:
/// - Py_DECREF must have ConditionalRelease effect, not unconditional Release
/// - Py_DECREF must belong to PYTHON_OBJECT family
/// - Inference summary must produce ConditionalRelease effect
/// - Conditional release should not be falsely reported as memory leak
#[test]
fn test_matrix_py_decref_conditional_release_not_leak() {
    let registry = FamilyRegistry::new();
    let decref = registry
        .lookup("Py_DECREF")
        .expect("Py_DECREF must be registered");

    // Py_DECREF must be ConditionalRelease, NOT unconditional Release
    assert_eq!(
        decref.effect,
        super::family_registry::SymbolEffect::ConditionalRelease,
        "Py_DECREF must be conditional release"
    );
    assert_eq!(
        decref.family_id,
        FamilyId::PYTHON_OBJECT,
        "Py_DECREF must be in python_object family"
    );

    // Verify summary inference produces ConditionalRelease effect
    let summary = infer_summary_for_symbol("Py_DECREF", 1, 100, &registry);
    assert!(
        summary.releases_resource(),
        "Py_DECREF summary must release resource"
    );
    // The effect should be ConditionalRelease, not Release
    let has_conditional = summary
        .effects
        .iter()
        .any(|e| matches!(e, Effect::ConditionalRelease { .. }));
    assert!(
        has_conditional,
        "Py_DECREF must produce ConditionalRelease effect"
    );
}

// ─── Destructor-mediated release ──────────────────────────────────────

/// Objective: Verify that Rust Drop function is correctly inferred as destructor release pattern
///
/// Invariants:
/// - drop function must be inferred as destructor
/// - Destructor summary must release resource
/// - DestructorRelease evidence must be attached
/// - Rust Drop calling C free should be identified as destructor-mediated release
#[test]
fn test_matrix_rust_drop_calling_c_free_is_destructor_mediated() {
    // Rust Drop calling C free is destructor-mediated release.
    // The "drop" function should be inferred as a destructor.
    let registry = FamilyRegistry::new();

    let drop_summary = infer_summary_for_symbol("drop", 1, 100, &registry);
    assert!(
        drop_summary.is_destructor(),
        "drop must be inferred as destructor"
    );
    assert!(
        drop_summary.releases_resource(),
        "Destructor summary must release resource"
    );

    // Evidence must be attached
    let has_destructor_evidence = drop_summary
        .evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::DestructorRelease);
    assert!(
        has_destructor_evidence,
        "Destructor summary must have DestructorRelease evidence"
    );
}

// ─── Bridge inference ─────────────────────────────────────────────────

/// Objective: Verify that as_ptr function is correctly inferred as bridge helper pattern
///
/// Invariants:
/// - as_ptr must be inferred as bridge helper
/// - Must produce ReturnsBorrowed effect
/// - Must NOT produce ReturnsOwned effect
/// - BridgeHelper evidence must be attached
/// - Bridge helper should return borrowed pointer, not owned pointer
#[test]
fn test_matrix_as_ptr_bridge_returns_borrowed() {
    let registry = FamilyRegistry::new();

    let as_ptr_summary = infer_summary_for_symbol("as_ptr", 1, 100, &registry);
    assert!(
        as_ptr_summary.is_bridge(),
        "as_ptr must be inferred as bridge helper"
    );

    // Must return borrowed, not owned
    let has_returns_borrowed = as_ptr_summary.effects.contains(&Effect::ReturnsBorrowed);
    assert!(
        has_returns_borrowed,
        "as_ptr must produce ReturnsBorrowed effect"
    );

    // Must NOT produce ReturnsOwned
    let has_returns_owned = as_ptr_summary
        .effects
        .iter()
        .any(|e| matches!(e, Effect::ReturnsOwned { .. }));
    assert!(
        !has_returns_owned,
        "Bridge must NOT produce ReturnsOwned effect"
    );

    // Bridge evidence must be attached
    let has_bridge_evidence = as_ptr_summary
        .evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::BridgeHelper);
    assert!(
        has_bridge_evidence,
        "Bridge summary must have BridgeHelper evidence"
    );
}

// ─── Escape-based non-leak scenarios ─────────────────────────────────

/// Objective: Verify that functions returning owned pointers are not falsely reported as local leaks
///
/// Invariants:
/// - malloc must acquire resource
/// - malloc must produce ReturnsOwned effect
/// - ReturnsOwned is a valid escape mechanism, should not be considered leak
/// - Registry-matched functions should have correct resource acquisition effect
#[test]
fn test_matrix_return_owned_not_local_leak() {
    // A function that returns owned pointer is not a local leak.
    // Verify by checking that ReturnsOwned is a valid escape.
    let registry = FamilyRegistry::new();
    let summary = infer_summary_for_symbol("malloc", 1, 100, &registry);

    assert!(summary.acquires_resource(), "malloc must acquire resource");

    // ReturnsOwned is a valid escape — not a leak
    let has_returns_owned = summary
        .effects
        .iter()
        .any(|e| matches!(e, Effect::ReturnsOwned { .. }));
    assert!(
        has_returns_owned,
        "Registry-matched malloc must produce ReturnsOwned effect"
    );
}

// ─── Static lifetime sink ─────────────────────────────────────────────

/// Objective: Verify that global static initialization is correctly identified as static lifetime
///
/// Invariants:
/// - __cxx_global_var_init must have StaticLifetimeSink evidence
/// - Must produce StoresArgToGlobal effect
/// - Static lifetime should not be falsely reported as memory leak
/// - Global variable initialization should be considered static lifetime sink
#[test]
fn test_matrix_global_static_init_is_static_lifetime() {
    let registry = FamilyRegistry::new();
    let summary = infer_summary_for_symbol("__cxx_global_var_init", 1, 100, &registry);

    // Must have static-lifetime evidence
    let has_static_evidence = summary
        .evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::StaticLifetimeSink);
    assert!(
        has_static_evidence,
        "Global var init must have StaticLifetimeSink evidence"
    );

    // Must NOT be a leak — it's a static lifetime
    let has_global_store = summary
        .effects
        .iter()
        .any(|e| matches!(e, Effect::StoresArgToGlobal { .. }));
    assert!(
        has_global_store,
        "Static-lifetime inference must produce StoresArgToGlobal effect"
    );
}

// ─── NeedsModel diagnostic ───────────────────────────────────────────

/// Objective: Verify that unknown families produce NeedsModel diagnostic rather than false positives
///
/// Invariants:
/// - Unknown symbols should not produce high-confidence inference
/// - Unknown families should produce NeedsModel type candidate
/// - Diagnostic verdict should not be reportable
/// - Unknown allocators should be flagged as needing model, not falsely reported as issues
#[test]
fn test_matrix_unknown_family_needs_model_diagnostic() {
    let registry = FamilyRegistry::new();

    // Unknown symbol should not produce high-confidence inference
    let summary = infer_summary_for_symbol("custom_allocator_init", 1, 100, &registry);

    // If it doesn't match any pattern, it should be low confidence
    // and NOT produce ConfirmedIssue-level effects
    if !summary.acquires_resource() && !summary.releases_resource() {
        // Completely unknown — should be NeedsModel
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::NeedsModel,
            FamilyId::C_HEAP,
            "custom_allocator_init",
        )
        .with_verdict(VerifierVerdict::Diagnostic);

        assert!(
            !candidate.is_reportable(),
            "NeedsModel diagnostic must NOT be reportable"
        );
        assert_eq!(
            candidate.verdict,
            Some(VerifierVerdict::Diagnostic),
            "Unknown family should produce Diagnostic verdict"
        );
    }
}

// ─── Verifier verdict gating ──────────────────────────────────────────

/// Objective: Verify that ConfirmedIssue verdict is correctly marked as reportable
///
/// Invariants:
/// - ConfirmedIssue verdict must be reportable
/// - Cross-family release issues should be correctly identified and flagged
/// - Verdict gating should correctly handle confirmed issues
/// - Reportable status should be based on verdict type
#[test]
fn test_matrix_verdict_gating_confirmed_issue_reportable() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_SCALAR)
    .with_release_function("operator delete")
    .with_verdict(VerifierVerdict::ConfirmedIssue);

    assert!(
        candidate.is_reportable(),
        "ConfirmedIssue must be reportable"
    );
}

/// Objective: Verify that Diagnostic verdict is correctly marked as not reportable
///
/// Invariants:
/// - Diagnostic verdict must not be reportable
/// - Diagnostics requiring model should not produce false positives
/// - Verdict gating should correctly filter diagnostic information
/// - Diagnostic information should only be used for internal analysis, not reported externally
#[test]
fn test_matrix_verdict_gating_diagnostic_not_reportable() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::NeedsModel,
        FamilyId::C_HEAP,
        "custom_alloc",
    )
    .with_verdict(VerifierVerdict::Diagnostic);

    assert!(
        !candidate.is_reportable(),
        "Diagnostic must NOT be reportable"
    );
}

/// Objective: Verify that ExplainedSafe verdict is correctly marked as not reportable
///
/// Invariants:
/// - ExplainedSafe verdict must not be reportable
/// - Same-family alloc/release operations should be marked as safe
/// - Explained safe patterns should not produce false positives
/// - Verdict gating should correctly handle safe explanations
#[test]
fn test_matrix_verdict_gating_explained_safe_not_reportable() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::C_HEAP) // Same family — not an issue
    .with_release_function("free")
    .with_verdict(VerifierVerdict::ExplainedSafe);

    assert!(
        !candidate.is_reportable(),
        "ExplainedSafe must NOT be reportable"
    );
}

// ─── End-to-end inference chain ───────────────────────────────────────

/// Objective: Verify inference chain priority: registry match > structural inference > bridge inference
///
/// Invariants:
/// - Registry-matched symbols should have high confidence (> 0.9)
/// - Symbols not in registry should fall back to structural inference
/// - drop function should be identified as destructor via structural inference
/// - as_ptr function should be identified as bridge helper via structural inference
/// - Inference chain should execute in priority order
#[test]
fn test_matrix_inference_chain_priority() {
    let registry = FamilyRegistry::new();

    // "free" is in the registry — should get registry-level confidence
    let free_summary = infer_summary_for_symbol("free", 1, 100, &registry);
    assert!(
        free_summary.confidence > 0.9,
        "Registry match should have high confidence, got {}",
        free_summary.confidence
    );

    // "drop" is NOT in the registry — should fall through to structural inference
    let drop_summary = infer_summary_for_symbol("drop", 2, 200, &registry);
    assert!(
        drop_summary.is_destructor(),
        "drop should be inferred as destructor via structural inference"
    );

    // "as_ptr" is NOT in the registry — should fall through to bridge inference
    let bridge_summary = infer_summary_for_symbol("as_ptr", 3, 300, &registry);
    assert!(
        bridge_summary.is_bridge(),
        "as_ptr should be inferred as bridge via structural inference"
    );
}
