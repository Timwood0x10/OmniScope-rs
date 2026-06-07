//! Boundary tests for TP evidence preservation.
//!
//! These tests use small LLVM IR fixtures to verify that family-mismatch
//! true positives remain visible as `CrossFamilyFree` and are not hidden by
//! cross-language or same-language wrapper suppression logic.

use omniscope_core::IssueKind;
use omniscope_ir::IRModule;
use omniscope_pipeline::Pipeline;

fn run_inline_ir(ir: &str) -> omniscope_pipeline::PipelineResult {
    let module = IRModule::parse_from_text(ir);
    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_ir_module(module);
    pipeline
        .run()
        .expect("inline IR pipeline run should succeed")
}

fn issue_kinds(result: &omniscope_pipeline::PipelineResult) -> Vec<IssueKind> {
    result.issues().iter().map(|issue| issue.kind).collect()
}

fn assert_has_kind(result: &omniscope_pipeline::PipelineResult, kind: IssueKind, context: &str) {
    assert!(
        result.issues().iter().any(|issue| issue.kind == kind),
        "{context}: expected {kind:?}, got {:?}",
        issue_kinds(result)
    );
}

fn assert_no_kind(result: &omniscope_pipeline::PipelineResult, kind: IssueKind, context: &str) {
    assert!(
        !result.issues().iter().any(|issue| issue.kind == kind),
        "{context}: did not expect {kind:?}, got {:?}",
        issue_kinds(result)
    );
}

/// Objective: Verify a C library-family mismatch remains a resource-family TP.
/// Invariants: `malloc -> sqlite3_free` must report `CrossFamilyFree`.
#[test]
fn test_c_malloc_sqlite_free_reports_cross_family() {
    let ir = r#"
        define void @library_family_mismatch(i64 %len) {
        entry:
          %buf = call ptr @malloc(i64 %len)
          call void @sqlite3_free(ptr %buf)
          ret void
        }

        declare ptr @malloc(i64)
        declare void @sqlite3_free(ptr)
    "#;

    let result = run_inline_ir(ir);

    assert_has_kind(
        &result,
        IssueKind::CrossFamilyFree,
        "C malloc memory released by sqlite3_free",
    );
}

/// Objective: Verify C++ array/scalar delete mismatch remains a TP.
/// Invariants: `_Znam -> _ZdlPv` must report `CrossFamilyFree`.
#[test]
fn test_cpp_array_new_scalar_delete_reports_cross_family() {
    let ir = r#"
        define void @array_new_scalar_delete(i64 %n) {
        entry:
          %arr = call ptr @_Znam(i64 %n)
          call void @_ZdlPv(ptr %arr)
          ret void
        }

        declare ptr @_Znam(i64)
        declare void @_ZdlPv(ptr)
    "#;

    let result = run_inline_ir(ir);

    assert_has_kind(
        &result,
        IssueKind::CrossFamilyFree,
        "C++ new[] memory released by scalar delete",
    );
}

/// Objective: Verify Python allocator mismatch remains a resource-family TP.
/// Invariants: `PyMem_Malloc -> free` must report `CrossFamilyFree`.
#[test]
fn test_python_pymem_malloc_free_reports_cross_family() {
    let ir = r#"
        define void @python_allocator_mismatch(i64 %size) {
        entry:
          %ptr = call ptr @PyMem_Malloc(i64 %size)
          call void @free(ptr %ptr)
          ret void
        }

        declare ptr @PyMem_Malloc(i64)
        declare void @free(ptr)
    "#;

    let result = run_inline_ir(ir);

    assert_has_kind(
        &result,
        IssueKind::CrossFamilyFree,
        "Python PyMem allocation released by C free",
    );
}

/// Objective: Verify Go/cgo allocator mismatch remains a resource-family TP.
/// Invariants: `_cgo_allocate -> free` must report `CrossFamilyFree`.
#[test]
fn test_go_cgo_allocate_free_reports_cross_family() {
    let ir = r#"
        define void @go_cgo_family_mismatch(i64 %size) {
        entry:
          %ptr = call ptr @_cgo_allocate(i64 %size)
          call void @free(ptr %ptr)
          ret void
        }

        declare ptr @_cgo_allocate(i64)
        declare void @free(ptr)
    "#;

    let result = run_inline_ir(ir);

    assert_has_kind(
        &result,
        IssueKind::CrossFamilyFree,
        "Go cgo allocation released by C free",
    );
}

/// Objective: Verify strict wrapper suppression does not create clean-pair FPs.
/// Invariants: `malloc -> free` must not report `CrossFamilyFree`.
#[test]
fn test_c_malloc_free_clean_pair_does_not_report_cross_family() {
    let ir = r#"
        define void @clean_malloc_free(i64 %size) {
        entry:
          %ptr = call ptr @malloc(i64 %size)
          call void @free(ptr %ptr)
          ret void
        }

        declare ptr @malloc(i64)
        declare void @free(ptr)
    "#;

    let result = run_inline_ir(ir);

    assert_no_kind(
        &result,
        IssueKind::CrossFamilyFree,
        "C malloc memory released by matching free",
    );
}

/// Objective: Verify repeated release of the same SSA pointer is a TP.
/// Invariants: `free(p); free(p);` must report `DoubleFree`.
#[test]
fn test_same_pointer_double_free_reports_double_free() {
    let ir = r#"
        define void @same_pointer_double_free(ptr %p) {
        entry:
          call void @free(ptr %p)
          call void @free(ptr %p)
          ret void
        }

        declare void @free(ptr)
    "#;

    let result = run_inline_ir(ir);

    assert_has_kind(
        &result,
        IssueKind::DoubleFree,
        "same pointer released twice",
    );
}

/// Objective: Verify branch-dependent repeated release remains a TP.
/// Invariants: `free(p); if (err) free(p);` must report `DoubleFree`.
#[test]
fn test_conditional_same_pointer_double_free_reports_double_free() {
    let ir = r#"
        define void @conditional_double_free(ptr %p, i1 %err) {
        entry:
          call void @free(ptr %p)
          br i1 %err, label %error, label %ok
        error:
          call void @free(ptr %p)
          ret void
        ok:
          ret void
        }

        declare void @free(ptr)
    "#;

    let result = run_inline_ir(ir);

    assert_has_kind(
        &result,
        IssueKind::DoubleFree,
        "same pointer released on an error branch after unconditional release",
    );
}

/// Objective: Verify independent allocations are not collapsed into DoubleFree.
/// Invariants: `free(a); free(b);` must not report `DoubleFree`.
#[test]
fn test_independent_allocations_do_not_report_double_free() {
    let ir = r#"
        define void @independent_allocations(i64 %size) {
        entry:
          %a = call ptr @malloc(i64 %size)
          %b = call ptr @malloc(i64 %size)
          call void @free(ptr %a)
          call void @free(ptr %b)
          ret void
        }

        declare ptr @malloc(i64)
        declare void @free(ptr)
    "#;

    let result = run_inline_ir(ir);

    assert_no_kind(
        &result,
        IssueKind::DoubleFree,
        "independent allocations released once each",
    );
}
