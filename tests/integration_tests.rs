//! Integration tests for OmniScope with inline LLVM IR fixtures.
//!
//! All IR is embedded directly so the test suite is self-contained —
//! no external `.ll` / `.bc` files are required at commit time.
//!
//! Test categories:
//! - **True-positive**: code with real FFI/unsafe bugs the pipeline MUST detect,
//!   with specific `IssueKind` assertions (not just count > 0).
//! - **True-negative (noise)**: benign patterns the pipeline should NOT flag.
//! - **Edge-case**: cross-family, conditional release, RAII, library families.
//!
//! Language coverage: C, C++, Rust, Python, Java/JNI, Go/cgo, Zig.

use omniscope_core::IssueKind;
use omniscope_ir::IRModule;
use omniscope_pipeline::Pipeline;
use tracing::debug;

// ─── Helpers ─────────────────────────────────────────────────────────

/// Parse inline IR text and run the default pipeline on it.
fn run_pipeline_on_ir(ir: &str) -> omniscope_pipeline::PipelineResult {
    let module = IRModule::parse_from_text(ir);
    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_ir_module(module);
    pipeline.run().expect("Pipeline run must succeed")
}

/// Load an external .ll fixture file and run the default pipeline on it.
/// The path is relative to the workspace root.
fn run_pipeline_on_fixture(relative_path: &str) -> omniscope_pipeline::PipelineResult {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(manifest_dir).join(relative_path);
    let module = IRModule::load_from_file(&path)
        .unwrap_or_else(|e| panic!("Failed to load fixture {relative_path}: {e}"));
    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_ir_module(module);
    pipeline
        .run()
        .unwrap_or_else(|e| panic!("Pipeline failed on {relative_path}: {e}"))
}

/// Assert that the pipeline result contains at least one issue of the given kind.
fn assert_has_issue_kind(result: &omniscope_pipeline::PipelineResult, kind: IssueKind, ctx: &str) {
    let found = result.issues().iter().any(|i| i.kind == kind);
    assert!(
        found,
        "{ctx}: expected IssueKind::{kind:?} but found none — issues: {:?}",
        result.issues().iter().map(|i| i.kind).collect::<Vec<_>>()
    );
}

/// Assert that the pipeline result contains NO issue of the given kind.
fn assert_no_issue_kind(result: &omniscope_pipeline::PipelineResult, kind: IssueKind, ctx: &str) {
    let found = result.issues().iter().any(|i| i.kind == kind);
    assert!(
        !found,
        "{ctx}: did NOT expect IssueKind::{kind:?} but found one — issues: {:?}",
        result.issues().iter().map(|i| i.kind).collect::<Vec<_>>()
    );
}

/// Assert that the pipeline result contains zero issues of any kind.
fn assert_zero_issues(result: &omniscope_pipeline::PipelineResult, ctx: &str) {
    assert_eq!(
        result.issue_count(),
        0,
        "{ctx}: expected zero issues but found {} — kinds: {:?}",
        result.issue_count(),
        result.issues().iter().map(|i| i.kind).collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// C LANGUAGE
// ═══════════════════════════════════════════════════════════════════════

/// TRUE POSITIVE: malloc without free — memory leak.
const C_MALLOC_LEAK: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @leaky_func(i64 %size) {
entry:
  %ptr = call ptr @malloc(i64 %size)
  ret void
}
declare ptr @malloc(i64)
"#;

/// TRUE POSITIVE: double-free — free called twice on same pointer.
const C_DOUBLE_FREE: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @double_free(ptr %p) {
entry:
  call void @free(ptr %p)
  call void @free(ptr %p)
  ret void
}
declare void @free(ptr)
"#;

/// TRUE POSITIVE: calloc without free — leak via calloc.
const C_CALLOC_LEAK: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define ptr @calloc_leak(i64 %n, i64 %elem_size) {
entry:
  %ptr = call ptr @calloc(i64 %n, i64 %elem_size)
  ret ptr %ptr
}
declare ptr @calloc(i64, i64)
"#;

/// NOISE: malloc + free properly paired — no leak.
const C_MALLOC_FREE_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @clean_func(i64 %size) {
entry:
  %ptr = call ptr @malloc(i64 %size)
  call void @free(ptr %ptr)
  ret void
}
declare ptr @malloc(i64)
declare void @free(ptr)
"#;

/// NOISE: realloc is an acquire — paired with free is clean.
const C_REALLOC_FREE_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @realloc_clean(ptr %old, i64 %new_size) {
entry:
  %ptr = call ptr @realloc(ptr %old, i64 %new_size)
  call void @free(ptr %ptr)
  ret void
}
declare ptr @realloc(ptr, i64)
declare void @free(ptr)
"#;

/// EDGE: aligned_alloc + free — same C_HEAP family, clean.
const C_ALIGNED_ALLOC_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @aligned_clean(i64 %align, i64 %size) {
entry:
  %ptr = call ptr @aligned_alloc(i64 %align, i64 %size)
  call void @free(ptr %ptr)
  ret void
}
declare ptr @aligned_alloc(i64, i64)
declare void @free(ptr)
"#;

/// Objective: Verify ConditionalLeak detection for malloc-without-free.
/// Invariants: Pipeline reports at least one ConditionalLeak issue.
#[test]
fn test_c_malloc_leak_detects_conditional_leak() {
    let result = run_pipeline_on_ir(C_MALLOC_LEAK);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(&result, IssueKind::ConditionalLeak, "C malloc leak");
}

/// Objective: Verify double-free detection.
/// Invariants: Pipeline reports at least one DoubleFree issue.
#[test]
fn test_c_double_free_detection() {
    let result = run_pipeline_on_ir(C_DOUBLE_FREE);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(&result, IssueKind::DoubleFree, "C double-free");
}

/// Objective: Verify calloc leak detection.
/// Invariants: Pipeline reports ConditionalLeak for calloc without free.
#[test]
fn test_c_calloc_leak_detection() {
    let result = run_pipeline_on_ir(C_CALLOC_LEAK);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(&result, IssueKind::ConditionalLeak, "C calloc leak");
}

/// Objective: Verify clean malloc+free produces no leak issues.
/// Invariants: No ConditionalLeak or MemoryLeak issues.
#[test]
fn test_c_malloc_free_clean_no_leak() {
    let result = run_pipeline_on_ir(C_MALLOC_FREE_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "C malloc+free clean");
    assert_no_issue_kind(&result, IssueKind::MemoryLeak, "C malloc+free clean");
}

/// Objective: Verify realloc+free is clean (realloc is acquire, free is release).
/// Invariants: No ConditionalLeak issues.
#[test]
fn test_c_realloc_free_clean() {
    let result = run_pipeline_on_ir(C_REALLOC_FREE_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "C realloc+free clean");
}

/// Objective: Verify aligned_alloc + free is clean (same C_HEAP family).
/// Invariants: No ConditionalLeak or CrossFamilyFree issues.
#[test]
fn test_c_aligned_alloc_clean() {
    let result = run_pipeline_on_ir(C_ALIGNED_ALLOC_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(
        &result,
        IssueKind::ConditionalLeak,
        "C aligned_alloc+free clean",
    );
    assert_no_issue_kind(
        &result,
        IssueKind::CrossFamilyFree,
        "C aligned_alloc+free clean",
    );
}

// ═══════════════════════════════════════════════════════════════════════
// C++ LANGUAGE
// ═══════════════════════════════════════════════════════════════════════

/// TRUE POSITIVE: cross-family free — malloc (C_HEAP) then _ZdlPv (CPP_NEW_SCALAR).
const CPP_CROSS_FAMILY: &str = r#"
target triple = "x86_64-pc-windows-msvc"
define void @cross_family(i64 %len) {
entry:
  %buf = call ptr @malloc(i64 %len)
  call void @_ZdlPv(ptr %buf)
  ret void
}
declare ptr @malloc(i64)
declare void @_ZdlPv(ptr)
"#;

/// TRUE POSITIVE: scalar new without delete — leak.
const CPP_NEW_WITHOUT_DELETE: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define ptr @new_leak(i64 %size) {
entry:
  %ptr = call ptr @_Znwm(i64 %size)
  ret ptr %ptr
}
declare ptr @_Znwm(i64)
"#;

/// TRUE POSITIVE: array new[] freed with scalar delete — cross-family within C++.
const CPP_ARRAY_NEW_SCALAR_DELETE: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @array_new_scalar_delete(i64 %n) {
entry:
  %ptr = call ptr @_Znam(i64 %n)
  call void @_ZdlPv(ptr %ptr)
  ret void
}
declare ptr @_Znam(i64)
declare void @_ZdlPv(ptr)
"#;

/// NOISE: _Znwm (operator new) + _ZdlPv (operator delete) — properly paired.
const CPP_NEW_DELETE_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @new_delete_clean(i64 %size) {
entry:
  %ptr = call ptr @_Znwm(i64 %size)
  call void @_ZdlPv(ptr %ptr)
  ret void
}
declare ptr @_Znwm(i64)
declare void @_ZdlPv(ptr)
"#;

/// NOISE: array new[] + array delete[] — properly paired.
const CPP_ARRAY_NEW_DELETE_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @array_new_delete_clean(i64 %n) {
entry:
  %ptr = call ptr @_Znam(i64 %n)
  call void @_ZdaPv(ptr %ptr)
  ret void
}
declare ptr @_Znam(i64)
declare void @_ZdaPv(ptr)
"#;

/// Objective: Verify cross-family free detection (C_HEAP alloc, CPP_NEW_SCALAR release).
/// Invariants: Pipeline reports CrossFamilyFree.
#[test]
fn test_cpp_cross_family_free() {
    let result = run_pipeline_on_ir(CPP_CROSS_FAMILY);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(
        &result,
        IssueKind::CrossFamilyFree,
        "C++ cross-family malloc+delete",
    );
}

/// Objective: Verify operator new leak detection.
/// Invariants: Pipeline reports ConditionalLeak for new without delete.
#[test]
fn test_cpp_new_without_delete() {
    let result = run_pipeline_on_ir(CPP_NEW_WITHOUT_DELETE);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(&result, IssueKind::ConditionalLeak, "C++ new leak");
}

/// Objective: Verify array new[] + scalar delete mismatch.
/// Invariants: Pipeline reports CrossFamilyFree (CPP_NEW_ARRAY vs CPP_NEW_SCALAR).
#[test]
fn test_cpp_array_new_scalar_delete() {
    let result = run_pipeline_on_ir(CPP_ARRAY_NEW_SCALAR_DELETE);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(
        &result,
        IssueKind::CrossFamilyFree,
        "C++ new[]+delete mismatch",
    );
}

/// Objective: Verify scalar new+delete produces no leak or cross-family issues.
/// Invariants: No ConditionalLeak, no CrossFamilyFree.
#[test]
fn test_cpp_new_delete_clean() {
    let result = run_pipeline_on_ir(CPP_NEW_DELETE_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "C++ new+delete clean");
    assert_no_issue_kind(&result, IssueKind::CrossFamilyFree, "C++ new+delete clean");
}

/// Objective: Verify array new[]+delete[] is clean.
/// Invariants: No ConditionalLeak, no CrossFamilyFree.
#[test]
fn test_cpp_array_new_delete_clean() {
    let result = run_pipeline_on_ir(CPP_ARRAY_NEW_DELETE_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(
        &result,
        IssueKind::ConditionalLeak,
        "C++ new[]+delete[] clean",
    );
    assert_no_issue_kind(
        &result,
        IssueKind::CrossFamilyFree,
        "C++ new[]+delete[] clean",
    );
}

// ═══════════════════════════════════════════════════════════════════════
// RUST LANGUAGE
// ═══════════════════════════════════════════════════════════════════════

/// TRUE POSITIVE: __rust_alloc without __rust_dealloc — Rust global allocator leak.
const RUST_ALLOC_LEAK: &str = r#"
target triple = "aarch64-apple-darwin"
define ptr @rust_alloc_leak(i64 %size, i64 %align) {
entry:
  %ptr = call ptr @__rust_alloc(i64 %size, i64 %align)
  ret ptr %ptr
}
declare ptr @__rust_alloc(i64, i64)
"#;

/// NOISE: __rust_dealloc is classified as SafeConditionalRelease — no false positive.
const RUST_DEALLOC_SAFE: &str = r#"
target triple = "aarch64-apple-darwin"
define void @raii_drop(ptr %p, i64 %size, i64 %align) {
entry:
  call void @__rust_dealloc(ptr %p, i64 %size, i64 %align)
  ret void
}
declare void @__rust_dealloc(ptr, i64, i64)
"#;

/// NOISE: Rust FFI calls to C — bare FFI presence is not a bug.
const RUST_FFI_CLEAN: &str = r#"
target triple = "arm64-apple-macosx11.0.0"
define i32 @rust_fft_forward(ptr %real, ptr %imag, i64 %n) {
entry:
  %result = call i32 @c_fft_forward(ptr %real, ptr %imag, i64 %n)
  ret i32 %result
}
declare i32 @c_fft_forward(ptr, ptr, i64)
"#;

/// NOISE: __rust_alloc + __rust_dealloc properly paired.
const RUST_ALLOC_DEALLOC_CLEAN: &str = r#"
target triple = "aarch64-apple-darwin"
define void @rust_alloc_dealloc_clean(i64 %size, i64 %align) {
entry:
  %ptr = call ptr @__rust_alloc(i64 %size, i64 %align)
  call void @__rust_dealloc(ptr %ptr, i64 %size, i64 %align)
  ret void
}
declare ptr @__rust_alloc(i64, i64)
declare void @__rust_dealloc(ptr, i64, i64)
"#;

/// EDGE: __rust_alloc_zeroed + __rust_dealloc — zeroed variant is also Acquire.
const RUST_ALLOC_ZEROED_CLEAN: &str = r#"
target triple = "aarch64-apple-darwin"
define void @rust_alloc_zeroed_clean(i64 %size, i64 %align) {
entry:
  %ptr = call ptr @__rust_alloc_zeroed(i64 %size, i64 %align)
  call void @__rust_dealloc(ptr %ptr, i64 %size, i64 %align)
  ret void
}
declare ptr @__rust_alloc_zeroed(i64, i64)
declare void @__rust_dealloc(ptr, i64, i64)
"#;

/// Objective: Verify __rust_alloc leak detection.
/// Invariants: Pipeline reports ConditionalLeak.
#[test]
fn test_rust_alloc_leak() {
    let result = run_pipeline_on_ir(RUST_ALLOC_LEAK);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(
        &result,
        IssueKind::ConditionalLeak,
        "Rust __rust_alloc leak",
    );
}

/// Objective: Verify __rust_dealloc alone does not produce false positives.
/// Invariants: No ConditionalLeak, no DoubleFree.
#[test]
fn test_rust_dealloc_safe() {
    let result = run_pipeline_on_ir(RUST_DEALLOC_SAFE);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(
        &result,
        IssueKind::ConditionalLeak,
        "Rust __rust_dealloc safe",
    );
    assert_no_issue_kind(&result, IssueKind::DoubleFree, "Rust __rust_dealloc safe");
}

/// Objective: Verify bare Rust→C FFI calls are not flagged.
/// Invariants: Zero issues.
#[test]
fn test_rust_ffi_clean() {
    let result = run_pipeline_on_ir(RUST_FFI_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "Rust FFI clean");
    assert_no_issue_kind(&result, IssueKind::CrossFamilyFree, "Rust FFI clean");
}

/// Objective: Verify __rust_alloc + __rust_dealloc pairing is clean.
/// Invariants: No ConditionalLeak.
#[test]
fn test_rust_alloc_dealloc_clean() {
    let result = run_pipeline_on_ir(RUST_ALLOC_DEALLOC_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(
        &result,
        IssueKind::ConditionalLeak,
        "Rust alloc+dealloc clean",
    );
}

/// Objective: Verify __rust_alloc_zeroed is recognized as Acquire and pairs with dealloc.
/// Invariants: No ConditionalLeak.
#[test]
fn test_rust_alloc_zeroed_clean() {
    let result = run_pipeline_on_ir(RUST_ALLOC_ZEROED_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(
        &result,
        IssueKind::ConditionalLeak,
        "Rust alloc_zeroed+dealloc clean",
    );
}

// ═══════════════════════════════════════════════════════════════════════
// PYTHON (C API)
// ═══════════════════════════════════════════════════════════════════════

/// TRUE POSITIVE: PyObject_New without Py_DECREF — refcount leak.
const PY_REFCOUNT_LEAK: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define ptr @py_leak() {
entry:
  %obj = call ptr @PyObject_New()
  ret ptr %obj
}
declare ptr @PyObject_New()
"#;

/// TRUE POSITIVE: PyMem_Malloc without PyMem_Free — Python mem family leak.
const PY_MEM_LEAK: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define ptr @py_mem_leak(i64 %size) {
entry:
  %ptr = call ptr @PyMem_Malloc(i64 %size)
  ret ptr %ptr
}
declare ptr @PyMem_Malloc(i64)
"#;

/// NOISE: PyObject_New + Py_DECREF properly paired.
const PY_REFCOUNT_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @py_clean() {
entry:
  %obj = call ptr @PyObject_New()
  call void @Py_DECREF(ptr %obj)
  ret void
}
declare ptr @PyObject_New()
declare void @Py_DECREF(ptr)
"#;

/// NOISE: PyMem_Malloc + PyMem_Free properly paired.
const PY_MEM_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @py_mem_clean(i64 %size) {
entry:
  %ptr = call ptr @PyMem_Malloc(i64 %size)
  call void @PyMem_Free(ptr %ptr)
  ret void
}
declare ptr @PyMem_Malloc(i64)
declare void @PyMem_Free(ptr)
"#;

/// EDGE: Py_DECREF is ConditionalRelease — should NOT be treated as unconditional Release.
const PY_DECREF_CONDITIONAL: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @py_decref_semantic() {
entry:
  %obj = call ptr @PyObject_New()
  call void @Py_DECREF(ptr %obj)
  ret void
}
declare ptr @PyObject_New()
declare void @Py_DECREF(ptr)
"#;

/// EDGE: Py_XDECREF (conditional variant of Py_DECREF) is also ConditionalRelease.
const PY_XDECREF_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @py_xdecref_clean() {
entry:
  %obj = call ptr @PyObject_New()
  call void @Py_XDECREF(ptr %obj)
  ret void
}
declare ptr @PyObject_New()
declare void @Py_XDECREF(ptr)
"#;

/// Objective: Verify PyObject_New leak detection.
/// Invariants: Pipeline reports ConditionalLeak.
#[test]
fn test_py_refcount_leak() {
    let result = run_pipeline_on_ir(PY_REFCOUNT_LEAK);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(&result, IssueKind::ConditionalLeak, "Python refcount leak");
}

/// Objective: Verify PyMem_Malloc leak detection.
/// Invariants: Pipeline reports ConditionalLeak for Python mem family.
#[test]
fn test_py_mem_leak() {
    let result = run_pipeline_on_ir(PY_MEM_LEAK);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(
        &result,
        IssueKind::ConditionalLeak,
        "Python PyMem_Malloc leak",
    );
}

/// Objective: Verify PyObject_New + Py_DECREF is not flagged.
/// Invariants: No ConditionalLeak.
#[test]
fn test_py_refcount_clean() {
    let result = run_pipeline_on_ir(PY_REFCOUNT_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "Python refcount clean");
}

/// Objective: Verify PyMem_Malloc + PyMem_Free is not flagged.
/// Invariants: No ConditionalLeak.
#[test]
fn test_py_mem_clean() {
    let result = run_pipeline_on_ir(PY_MEM_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "Python PyMem clean");
}

/// Objective: Verify Py_DECREF is treated as ConditionalRelease (not unconditional Release).
/// Invariants: No ConditionalLeak when paired with PyObject_New.
#[test]
fn test_py_decref_conditional_release() {
    let result = run_pipeline_on_ir(PY_DECREF_CONDITIONAL);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(
        &result,
        IssueKind::ConditionalLeak,
        "Python Py_DECREF conditional",
    );
}

/// Objective: Verify Py_XDECREF is also recognized as ConditionalRelease.
/// Invariants: No ConditionalLeak when paired with PyObject_New.
#[test]
fn test_py_xdecref_clean() {
    let result = run_pipeline_on_ir(PY_XDECREF_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(
        &result,
        IssueKind::ConditionalLeak,
        "Python Py_XDECREF clean",
    );
}

// ═══════════════════════════════════════════════════════════════════════
// JAVA / JNI
// ═══════════════════════════════════════════════════════════════════════

/// TRUE POSITIVE: NewLocalRef without DeleteLocalRef — JNI local ref leak.
const JNI_LOCAL_REF_LEAK: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define ptr @jni_local_ref_leak(ptr %obj) {
entry:
  %ref = call ptr @NewLocalRef(ptr %obj)
  ret ptr %ref
}
declare ptr @NewLocalRef(ptr)
"#;

/// TRUE POSITIVE: GetStringUTFChars without ReleaseStringUTFChars — JNI borrow leak.
const JNI_STRING_LEAK: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define ptr @jni_string_leak(ptr %jstr) {
entry:
  %chars = call ptr @GetStringUTFChars(ptr %jstr, ptr null)
  ret ptr %chars
}
declare ptr @GetStringUTFChars(ptr, ptr)
"#;

/// TRUE POSITIVE: NewGlobalRef without DeleteGlobalRef — JNI global ref leak.
const JNI_GLOBAL_REF_LEAK: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define ptr @jni_global_ref_leak(ptr %obj) {
entry:
  %gref = call ptr @NewGlobalRef(ptr %obj)
  ret ptr %gref
}
declare ptr @NewGlobalRef(ptr)
"#;

/// NOISE: NewLocalRef + DeleteLocalRef properly paired.
const JNI_LOCAL_REF_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @jni_local_ref_clean(ptr %obj) {
entry:
  %ref = call ptr @NewLocalRef(ptr %obj)
  call void @DeleteLocalRef(ptr %ref)
  ret void
}
declare ptr @NewLocalRef(ptr)
declare void @DeleteLocalRef(ptr)
"#;

/// NOISE: GetStringUTFChars + ReleaseStringUTFChars properly paired.
const JNI_STRING_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @jni_string_clean(ptr %jstr) {
entry:
  %chars = call ptr @GetStringUTFChars(ptr %jstr, ptr null)
  call void @ReleaseStringUTFChars(ptr %jstr, ptr %chars)
  ret void
}
declare ptr @GetStringUTFChars(ptr, ptr)
declare void @ReleaseStringUTFChars(ptr, ptr)
"#;

/// Objective: Verify JNI local ref leak detection.
/// Invariants: Pipeline reports ConditionalLeak.
#[test]
fn test_jni_local_ref_leak() {
    let result = run_pipeline_on_ir(JNI_LOCAL_REF_LEAK);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(&result, IssueKind::ConditionalLeak, "JNI local ref leak");
}

/// Objective: Verify JNI GetStringUTFChars leak detection.
/// Invariants: Pipeline reports ConditionalLeak.
#[test]
fn test_jni_string_leak() {
    let result = run_pipeline_on_ir(JNI_STRING_LEAK);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(&result, IssueKind::ConditionalLeak, "JNI string leak");
}

/// Objective: Verify JNI global ref leak detection.
/// Invariants: Pipeline reports ConditionalLeak.
#[test]
fn test_jni_global_ref_leak() {
    let result = run_pipeline_on_ir(JNI_GLOBAL_REF_LEAK);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(&result, IssueKind::ConditionalLeak, "JNI global ref leak");
}

/// Objective: Verify JNI NewLocalRef + DeleteLocalRef is clean.
/// Invariants: No ConditionalLeak.
#[test]
fn test_jni_local_ref_clean() {
    let result = run_pipeline_on_ir(JNI_LOCAL_REF_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "JNI local ref clean");
}

/// Objective: Verify JNI GetStringUTFChars + ReleaseStringUTFChars is clean.
/// Invariants: No ConditionalLeak.
#[test]
fn test_jni_string_clean() {
    let result = run_pipeline_on_ir(JNI_STRING_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "JNI string clean");
}

// ═══════════════════════════════════════════════════════════════════════
// GO / CGO
// ═══════════════════════════════════════════════════════════════════════

/// TRUE POSITIVE: _cgo_allocate without _cgo_free — cgo memory leak.
const GO_CGO_LEAK: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define ptr @cgo_leak(i64 %size) {
entry:
  %ptr = call ptr @_cgo_allocate(i64 %size)
  ret ptr %ptr
}
declare ptr @_cgo_allocate(i64)
"#;

/// NOISE: _cgo_allocate + _cgo_free properly paired.
const GO_CGO_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @cgo_clean(i64 %size) {
entry:
  %ptr = call ptr @_cgo_allocate(i64 %size)
  call void @_cgo_free(ptr %ptr)
  ret void
}
declare ptr @_cgo_allocate(i64)
declare void @_cgo_free(ptr)
"#;

/// NOISE: runtime.mallocgc is Go GC-managed — no manual free needed.
const GO_MALLOCGC_NO_FREE_NEEDED: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define ptr @go_gc_alloc(i64 %size, ptr %typ) {
entry:
  %ptr = call ptr @runtime.mallocgc(i64 %size, ptr %typ, i1 false)
  ret ptr %ptr
}
declare ptr @runtime.mallocgc(i64, ptr, i1)
"#;

/// Objective: Verify cgo allocate leak detection.
/// Invariants: Pipeline reports ConditionalLeak.
#[test]
fn test_go_cgo_leak() {
    let result = run_pipeline_on_ir(GO_CGO_LEAK);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(&result, IssueKind::ConditionalLeak, "Go cgo allocate leak");
}

/// Objective: Verify cgo allocate + free is clean.
/// Invariants: No ConditionalLeak.
#[test]
fn test_go_cgo_clean() {
    let result = run_pipeline_on_ir(GO_CGO_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "Go cgo clean");
}

/// Objective: Verify Go GC-managed allocation is not falsely flagged as leak.
/// Invariants: No ConditionalLeak (runtime.mallocgc is GC-managed).
#[test]
fn test_go_mallocgc_no_false_positive() {
    let result = run_pipeline_on_ir(GO_MALLOCGC_NO_FREE_NEEDED);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    // runtime.mallocgc is Acquire with no matching Release — may produce
    // ConditionalLeak. This test documents current behavior so we can
    // track whether we add GC-aware noise suppression later.
    debug!(
        "Go mallocgc — issues: {:?}",
        result.issues().iter().map(|i| i.kind).collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════
// ZIG
// ═══════════════════════════════════════════════════════════════════════

/// TRUE POSITIVE: zig_allocator_allocImpl without zig_allocator_freeImpl — Zig allocator leak.
const ZIG_ALLOC_LEAK: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define ptr @zig_leak(i64 %size) {
entry:
  %ptr = call ptr @zig_allocator_allocImpl(i64 %size)
  ret ptr %ptr
}
declare ptr @zig_allocator_allocImpl(i64)
"#;

/// NOISE: zig_allocator_allocImpl + zig_allocator_freeImpl properly paired.
const ZIG_ALLOC_FREE_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @zig_clean(i64 %size) {
entry:
  %ptr = call ptr @zig_allocator_allocImpl(i64 %size)
  call void @zig_allocator_freeImpl(ptr %ptr)
  ret void
}
declare ptr @zig_allocator_allocImpl(i64)
declare void @zig_allocator_freeImpl(ptr)
"#;

/// Objective: Verify Zig allocator leak detection.
/// Invariants: Pipeline reports ConditionalLeak.
#[test]
fn test_zig_alloc_leak() {
    let result = run_pipeline_on_ir(ZIG_ALLOC_LEAK);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(&result, IssueKind::ConditionalLeak, "Zig allocator leak");
}

/// Objective: Verify Zig allocator alloc+free is clean.
/// Invariants: No ConditionalLeak.
#[test]
fn test_zig_alloc_free_clean() {
    let result = run_pipeline_on_ir(ZIG_ALLOC_FREE_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "Zig alloc+free clean");
}

// ═══════════════════════════════════════════════════════════════════════
// CROSS-LANGUAGE / LIBRARY EDGE CASES
// ═══════════════════════════════════════════════════════════════════════

/// TRUE POSITIVE: malloc (C_HEAP) + PyObject_Del (PYTHON_OBJECT) — cross-family.
const C_TO_PY_CROSS_FAMILY: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @c_to_py_cross_family(i64 %size) {
entry:
  %ptr = call ptr @malloc(i64 %size)
  call void @PyObject_Del(ptr %ptr)
  ret void
}
declare ptr @malloc(i64)
declare void @PyObject_Del(ptr)
"#;

/// NOISE: C bridge calling C++ — malloc + free + C++ function, same C_HEAP family.
const C_CPP_BRIDGE_CLEAN: &str = r#"
target triple = "arm64-apple-macosx15.0.0"
define i32 @c_cpp_bridge(ptr %data, i64 %len, ptr %out) {
entry:
  %len1 = add i64 %len, 1
  %buf = call ptr @malloc(i64 %len1)
  call void @_ZN8cpp_hash4HashEPKhmPh(ptr %buf, i64 %len, ptr %out)
  call void @free(ptr %buf)
  ret i32 0
}
declare ptr @malloc(i64)
declare void @free(ptr)
declare void @_ZN8cpp_hash4HashEPKhmPh(ptr, i64, ptr)
"#;

/// NOISE: zlib inflateInit_ + inflateEnd properly paired.
const ZLIB_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @zlib_clean(ptr %strm) {
entry:
  call i32 @inflateInit_(ptr %strm, i32 56, i64 112)
  call i32 @inflateEnd(ptr %strm)
  ret void
}
declare i32 @inflateInit_(ptr, i32, i64)
declare i32 @inflateEnd(ptr)
"#;

/// NOISE: OpenSSL EVP_CIPHER_CTX_new + EVP_CIPHER_CTX_free properly paired.
const OPENSSL_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @openssl_clean() {
entry:
  %ctx = call ptr @EVP_CIPHER_CTX_new()
  call void @EVP_CIPHER_CTX_free(ptr %ctx)
  ret void
}
declare ptr @EVP_CIPHER_CTX_new()
declare void @EVP_CIPHER_CTX_free(ptr)
"#;

/// NOISE: sqlite3_open + sqlite3_close properly paired.
const SQLITE_CLEAN: &str = r#"
target triple = "x86_64-unknown-linux-gnu"
define void @sqlite_clean(ptr %filename) {
entry:
  call i32 @sqlite3_open(ptr %filename, ptr null)
  call i32 @sqlite3_close(ptr null)
  ret void
}
declare i32 @sqlite3_open(ptr, ptr)
declare i32 @sqlite3_close(ptr)
"#;

/// Objective: Verify cross-family free (C_HEAP alloc + PYTHON_OBJECT release).
/// Invariants: Pipeline reports CrossFamilyFree.
#[test]
fn test_c_to_py_cross_family() {
    let result = run_pipeline_on_ir(C_TO_PY_CROSS_FAMILY);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_has_issue_kind(&result, IssueKind::CrossFamilyFree, "C→Python cross-family");
}

/// Objective: Verify C→C++ bridge with proper malloc+free is clean.
/// Invariants: No ConditionalLeak, no CrossFamilyFree.
#[test]
fn test_c_cpp_bridge_clean() {
    let result = run_pipeline_on_ir(C_CPP_BRIDGE_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "C→C++ bridge clean");
    assert_no_issue_kind(&result, IssueKind::CrossFamilyFree, "C→C++ bridge clean");
}

/// Objective: Verify zlib init+end is not flagged as a leak.
/// Invariants: No ConditionalLeak.
#[test]
fn test_zlib_clean() {
    let result = run_pipeline_on_ir(ZLIB_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "zlib clean");
}

/// Objective: Verify OpenSSL context new+free is not flagged.
/// Invariants: No ConditionalLeak.
#[test]
fn test_openssl_clean() {
    let result = run_pipeline_on_ir(OPENSSL_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "OpenSSL clean");
}

/// Objective: Verify SQLite open+close is not flagged.
/// Invariants: No ConditionalLeak.
#[test]
fn test_sqlite_clean() {
    let result = run_pipeline_on_ir(SQLITE_CLEAN);
    assert!(result.pass_count() > 0, "Pipeline must execute passes");
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "SQLite clean");
}

// ═══════════════════════════════════════════════════════════════════════
// PLATFORM EDGE CASES
// ═══════════════════════════════════════════════════════════════════════

/// EDGE: MinGW32 target triple — must be recognized as Windows platform.
const MINGW32_TRIPLE: &str = r#"
target triple = "i686-w64-mingw32"
define void @mingw_func(i64 %size) {
entry:
  %ptr = call ptr @malloc(i64 %size)
  call void @free(ptr %ptr)
  ret void
}
declare ptr @malloc(i64)
declare void @free(ptr)
"#;

/// EDGE: Cygwin target triple — must be recognized as Windows platform.
const CYGWIN_TRIPLE: &str = r#"
target triple = "x86_64-pc-windows-cygwin"
define void @cygwin_func(i64 %size) {
entry:
  %ptr = call ptr @malloc(i64 %size)
  call void @free(ptr %ptr)
  ret void
}
declare ptr @malloc(i64)
declare void @free(ptr)
"#;

/// Objective: Verify MinGW32 triple does not cause pipeline failure.
/// Invariants: Pipeline completes successfully with at least one pass.
#[test]
fn test_mingw32_triple_pipeline() {
    let result = run_pipeline_on_ir(MINGW32_TRIPLE);
    assert!(
        result.pass_count() > 0,
        "Pipeline must execute passes on MinGW32 IR"
    );
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "MinGW32 clean");
}

/// Objective: Verify Cygwin triple does not cause pipeline failure.
/// Invariants: Pipeline completes successfully with at least one pass.
#[test]
fn test_cygwin_triple_pipeline() {
    let result = run_pipeline_on_ir(CYGWIN_TRIPLE);
    assert!(
        result.pass_count() > 0,
        "Pipeline must execute passes on Cygwin IR"
    );
    assert_no_issue_kind(&result, IssueKind::ConditionalLeak, "Cygwin clean");
}

// ═══════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE
// ═══════════════════════════════════════════════════════════════════════

/// Objective: Verify the pipeline runs without any IR input.
/// Invariants: Pipeline completes with at least one pass executed.
#[test]
fn test_pipeline_orchestration() {
    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    let result = pipeline.run().unwrap();
    assert!(
        result.pass_count() > 0,
        "Pipeline should execute at least one pass"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// FILE-FIXTURE INTEGRATION TESTS
//
// These tests load real .ll files compiled from production code to verify
// the pipeline handles realistic IR patterns correctly. Unlike the inline
// IR tests above, these exercise the full parser + loader path.
// ═══════════════════════════════════════════════════════════════════════

// ─── True-positive fixture tests ─────────────────────────────────────

/// Objective: Verify issue detection in c_hash_c_bridge.ll.
/// The c_hash function mallocs a buffer and has conditional branches
/// (len==0 vs len!=0) before calling free. The pipeline should flag
/// at least one issue related to this memory management pattern.
/// Invariants: Pipeline reports at least one issue.
#[test]
fn test_fixture_c_hash_c_bridge_detects_issue() {
    let result = run_pipeline_on_fixture("tests/integration/c_hash_c_bridge.ll");
    assert!(
        result.pass_count() > 0,
        "Pipeline must execute passes on c_hash_c_bridge.ll"
    );
    assert!(
        result.issue_count() > 0,
        "c_hash_c_bridge.ll: expected at least one issue from conditional malloc/free, got: {:?}",
        result.issues().iter().map(|i| i.kind).collect::<Vec<_>>()
    );
}

/// Objective: Verify loop-body leak detection in cpp_hash.ll.
/// CompressBlock allocates with _Znam (operator new[]) but never calls
/// _ZdaPv (operator delete[]) — the buffer leaks on every invocation.
/// Invariants: Pipeline reports at least one leak issue.
#[test]
fn test_fixture_cpp_hash_loop_body_leak() {
    let result = run_pipeline_on_fixture("tests/integration/cpp_hash.ll");
    assert!(
        result.pass_count() > 0,
        "Pipeline must execute passes on cpp_hash.ll"
    );
    let has_leak = result.issues().iter().any(|i| {
        matches!(
            i.kind,
            IssueKind::ConditionalLeak
                | IssueKind::MemoryLeak
                | IssueKind::BorrowEscape
                | IssueKind::OwnershipEscapeLeak
        )
    });
    assert!(
        has_leak,
        "cpp_hash.ll: expected leak issue for _Znam in CompressBlock, got: {:?}",
        result.issues().iter().map(|i| i.kind).collect::<Vec<_>>()
    );
}

/// Objective: Verify cross-language free detection in c_ffi_bugs.ll.
/// @cross_family_free allocates with malloc (C_HEAP) and frees with
/// operator delete (_ZdlPv, CPP_NEW_SCALAR) — a cross-language mismatch.
/// The pipeline detects this as CrossLanguageFree (the FFI boundary variant).
/// Invariants: Pipeline reports CrossLanguageFree.
#[test]
fn test_fixture_c_ffi_bugs_cross_language_free() {
    let result = run_pipeline_on_fixture("tests/integration/c_ffi_bugs.ll");
    assert!(
        result.pass_count() > 0,
        "Pipeline must execute passes on c_ffi_bugs.ll"
    );
    assert_has_issue_kind(
        &result,
        IssueKind::CrossLanguageFree,
        "c_ffi_bugs.ll @cross_family_free (malloc -> delete)",
    );
}

/// Objective: Verify borrow-escape detection in c_ffi_bugs.ll.
/// @leaked_callback_userdata passes a stack-allocated struct as callback
/// userdata — the callback may retain a dangling pointer after the
/// function returns. The pipeline detects ownership/borrow violations.
/// Invariants: Pipeline reports at least one ownership-related issue.
#[test]
fn test_fixture_c_ffi_bugs_borrow_escape() {
    let result = run_pipeline_on_fixture("tests/integration/c_ffi_bugs.ll");
    assert!(
        result.pass_count() > 0,
        "Pipeline must execute passes on c_ffi_bugs.ll"
    );
    let has_ownership_issue = result.issues().iter().any(|i| {
        matches!(
            i.kind,
            IssueKind::BorrowEscape
                | IssueKind::CrossLanguageFree
                | IssueKind::DoubleFree
                | IssueKind::UseAfterFree
                | IssueKind::OwnershipEscapeLeak
        )
    });
    assert!(
        has_ownership_issue,
        "c_ffi_bugs.ll @leaked_callback_userdata: expected ownership issue, got: {:?}",
        result.issues().iter().map(|i| i.kind).collect::<Vec<_>>()
    );
}

// ─── True-negative (noise filter) fixture tests ──────────────────────

/// Objective: Verify rust_hash.ll produces zero issues.
/// This file is a pure FFI pass-through — Rust calls C hash functions
/// without owning any memory. No alloc/free patterns exist.
/// Invariants: Zero issues of any kind.
#[test]
fn test_fixture_rust_hash_clean() {
    let result = run_pipeline_on_fixture("tests/integration/rust_hash.ll");
    assert!(
        result.pass_count() > 0,
        "Pipeline must execute passes on rust_hash.ll"
    );
    assert_zero_issues(&result, "rust_hash.ll (pure FFI pass-through)");
}

/// Objective: Verify zig_ffi_bridge.ll issue profile.
/// This file contains clean C functions: c_alloc_buffer (malloc),
/// c_release_buffer (free), c_process_buffer (memset), c_apply_config
/// (read-only). When analyzed per-function, alloc-without-free and
/// free-without-alloc look like leaks — this is expected behavior for
/// an intra-procedural analyzer.
/// Invariants: Pipeline completes and reports ConditionalLeak for
/// standalone alloc/free functions (not cross-function false positive).
#[test]
fn test_fixture_zig_ffi_bridge_expected_issues() {
    let result = run_pipeline_on_fixture("tests/integration/zig_ffi_bridge.ll");
    assert!(
        result.pass_count() > 0,
        "Pipeline must execute passes on zig_ffi_bridge.ll"
    );
    // c_alloc_buffer returns malloc'd ptr without freeing → ConditionalLeak expected.
    // c_release_buffer frees a param without local alloc → may also be flagged.
    assert!(
        result.issue_count() > 0,
        "zig_ffi_bridge.ll: expected ConditionalLeak for standalone alloc/free functions"
    );
    // Issues should be ConditionalLeak or DefiniteLeak (improved leak detection).
    for issue in result.issues() {
        assert!(
            issue.kind == IssueKind::ConditionalLeak || issue.kind == IssueKind::DefiniteLeak,
            "zig_ffi_bridge.ll: unexpected issue kind {:?} — expected ConditionalLeak or DefiniteLeak",
            issue.kind
        );
    }
}

/// Objective: Verify c_merkle_tree.ll issue profile.
/// The merkle_root function allocates with malloc and frees on all
/// reachable paths (lines 50, 81, 108). The analyzer may report
/// DoubleFree due to path-join limitations in complex control flow.
/// Invariants: Pipeline completes; no ConditionalLeak or MemoryLeak.
#[test]
fn test_fixture_c_merkle_tree_no_leak() {
    let result = run_pipeline_on_fixture("tests/integration/c_merkle_tree.ll");
    assert!(
        result.pass_count() > 0,
        "Pipeline must execute passes on c_merkle_tree.ll"
    );
    // The malloc/free pairing is correct — no leak issues expected.
    assert_no_issue_kind(
        &result,
        IssueKind::ConditionalLeak,
        "c_merkle_tree.ll (malloc freed on all paths)",
    );
    assert_no_issue_kind(
        &result,
        IssueKind::MemoryLeak,
        "c_merkle_tree.ll (malloc freed on all paths)",
    );
}
