//! Integration tests for the llvm-sys C API adapter.
//!
//! These tests parse a real .ll file using the LLVM C API and verify that
//! the `IRModule` is populated correctly with function bodies, type info,
//! and instruction metadata.
//!
//! Run with:
//! ```bash
//! LLVM_SYS_221_PREFIX=/opt/homebrew/opt/llvm@22 cargo test --test llvm_sys_test --features llvm-backend
//! ```

// Only compile when the llvm-backend feature is active.
#![cfg(feature = "llvm-backend")]

use std::path::Path;
use std::sync::Once;

use omniscope_ir::llvm_sys_adapter::{is_available, parse_with_llvm_sys};
use omniscope_ir::{IRInstructionKind, IRModule};

/// Path to the test .ll file (created lazily by the test harness).
fn test_ll_path() -> &'static Path {
    Path::new("/tmp/test_llvm_sys.ll")
}

fn ensure_fixture_exists() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let content = r#"target triple = "arm64-apple-darwin24.6.0"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128-Fn32"

declare void @external_func(i32)

define i32 @test_function(i64 %n, ptr %p) {
entry:
  %cmp = icmp sgt i64 %n, 0
  br i1 %cmp, label %then, label %else

then:
  %val = load i32, ptr %p
  call void @external_func(i32 %val)
  br label %exit

else:
  store i32 42, ptr %p
  br label %exit

exit:
  ret i32 0
}
"#;
        std::fs::write(test_ll_path(), content)
            .expect("Failed to write test fixture /tmp/test_llvm_sys.ll");
    });
}

// ──────────────────────────────────────────────────────────────────────────
// Basic availability
// ──────────────────────────────────────────────────────────────────────────

/// Objective: Verify the llvm-sys backend is linked and callable.
/// Invariants: `is_available()` must return true when the feature is active.
#[test]
fn test_llvm_sys_is_available() {
    assert!(
        is_available(),
        "llvm-sys backend should be available when the feature is enabled"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Module-level metadata
// ──────────────────────────────────────────────────────────────────────────

/// Objective: Verify module-level metadata is parsed correctly.
/// Invariants: target triple contains host arch, data layout starts with
/// endianness marker, and little_endian flag is set.
#[test]
fn test_module_metadata() {
    ensure_fixture_exists();
    let module = parse_with_llvm_sys(test_ll_path()).expect("Failed to parse test .ll file");

    let triple = module
        .data_layout
        .target_triple
        .as_deref()
        .expect("target_triple should be populated");
    assert!(
        triple.contains("arm64-apple-darwin"),
        "target_triple should contain arm64-apple-darwin, got: {}",
        triple
    );

    let layout = module
        .data_layout
        .data_layout
        .as_deref()
        .expect("data_layout should be populated");
    assert!(
        layout.starts_with('e'),
        "data_layout should start with 'e' (little-endian), got: {}",
        layout
    );

    assert_eq!(
        module.data_layout.little_endian,
        Some(true),
        "Should be little-endian"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Functions and declarations
// ──────────────────────────────────────────────────────────────────────────

/// Objective: Verify the function and declaration counts match the fixture.
/// Invariants: Exactly one defined function (`test_function`) and one
/// external declaration (`external_func`) must be present.
#[test]
fn test_function_count() {
    ensure_fixture_exists();
    let module = parse_with_llvm_sys(test_ll_path()).expect("Failed to parse");

    assert_eq!(
        module.functions.len(),
        1,
        "Should have exactly 1 defined function (test_function), got: {:?}",
        module.functions.keys().collect::<Vec<_>>()
    );

    assert_eq!(
        module.declarations.len(),
        1,
        "Should have exactly 1 declaration (external_func), got: {:?}",
        module.declarations.keys().collect::<Vec<_>>()
    );

    assert!(
        module.functions.contains_key("test_function"),
        "test_function should be in the functions map"
    );

    assert!(
        module.declarations.contains_key("external_func"),
        "external_func should be in the declarations map"
    );
}

/// Objective: Verify the instruction count and kind distribution in the
/// function body matches the fixture.
/// Invariants: The fixture defines 8 instructions: 1 icmp, 3 branches,
/// 1 load, 1 call, 1 store, 1 ret.
#[test]
fn test_function_body_instructions() {
    ensure_fixture_exists();
    let module = parse_with_llvm_sys(test_ll_path()).expect("Failed to parse");

    let body = module
        .function_bodies
        .get("test_function")
        .expect("test_function should have a body");

    assert_eq!(
        body.instructions.len(),
        8,
        "test_function should have 8 instructions, got {}: {:#?}",
        body.instructions.len(),
        body.instructions
    );

    assert_eq!(
        body.count_kind(IRInstructionKind::Icmp),
        1,
        "Should have 1 icmp"
    );
    assert_eq!(
        body.count_kind(IRInstructionKind::Branch),
        3,
        "Should have 3 branches"
    );
    assert_eq!(
        body.count_kind(IRInstructionKind::Load),
        1,
        "Should have 1 load"
    );
    assert_eq!(
        body.count_kind(IRInstructionKind::Call),
        1,
        "Should have 1 call"
    );
    assert_eq!(
        body.count_kind(IRInstructionKind::Store),
        1,
        "Should have 1 store"
    );
    assert_eq!(
        body.count_kind(IRInstructionKind::Ret),
        1,
        "Should have 1 ret"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Call target verification
// ──────────────────────────────────────────────────────────────────────────

/// Objective: Verify the call instruction correctly records its callee.
/// Invariants: The single call in `test_function` must target
/// `external_func` (without the `@` prefix).
#[test]
fn test_call_target() {
    ensure_fixture_exists();
    let module = parse_with_llvm_sys(test_ll_path()).expect("Failed to parse");

    let call_insts = module
        .function_bodies
        .get("test_function")
        .expect("test_function should have a body")
        .call_instructions();

    assert_eq!(
        call_insts.len(),
        1,
        "Should have exactly 1 call instruction"
    );

    let call = call_insts[0];
    assert_eq!(
        call.callee.as_deref(),
        Some("external_func"),
        "Call should target external_func, got: {:?}",
        call.callee
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Type information (result_type must NOT be None)
// ──────────────────────────────────────────────────────────────────────────

/// Objective: Verify `result_type` is populated for instructions that
/// produce values (icmp, load, call returning non-void).
/// Invariants: icmp must have `i1`, load must have `i32`, call must have
/// a non-None result type.
#[test]
fn test_result_type_populated() {
    ensure_fixture_exists();
    let module = parse_with_llvm_sys(test_ll_path()).expect("Failed to parse");

    let body = module
        .function_bodies
        .get("test_function")
        .expect("test_function should have a body");

    let icmp_insts = body.instructions_of_kind(IRInstructionKind::Icmp);
    assert_eq!(icmp_insts.len(), 1, "Should have 1 icmp");
    assert!(
        icmp_insts[0].result_type.is_some(),
        "icmp instruction must have result_type populated (not None), raw: {}",
        icmp_insts[0].raw_text
    );
    let icmp_ty = icmp_insts[0].result_type.as_ref().unwrap();
    assert!(
        icmp_ty.contains("i1"),
        "icmp result type should be i1, got: {}",
        icmp_ty
    );

    let load_insts = body.instructions_of_kind(IRInstructionKind::Load);
    assert_eq!(load_insts.len(), 1, "Should have 1 load");
    assert!(
        load_insts[0].result_type.is_some(),
        "load instruction must have result_type populated (not None), raw: {}",
        load_insts[0].raw_text
    );
    let load_ty = load_insts[0].result_type.as_ref().unwrap();
    assert!(
        load_ty.contains("i32"),
        "load result type should be i32, got: {}",
        load_ty
    );

    let call_insts = body.instructions_of_kind(IRInstructionKind::Call);
    assert_eq!(call_insts.len(), 1, "Should have 1 call");
    assert!(
        call_insts[0].result_type.is_some(),
        "call instruction must have result_type populated (not None), raw: {}",
        call_insts[0].raw_text
    );

    let ret_insts = body.instructions_of_kind(IRInstructionKind::Ret);
    assert_eq!(ret_insts.len(), 1, "Should have 1 ret");
}

// ──────────────────────────────────────────────────────────────────────────
// Element type verification
// ──────────────────────────────────────────────────────────────────────────

/// Objective: Verify `element_type` is populated for load/store instructions.
/// Invariants: load must report `i32` element type, store must also report
/// `i32` element type derived from the pointer operand.
#[test]
fn test_element_type_populated() {
    ensure_fixture_exists();
    let module = parse_with_llvm_sys(test_ll_path()).expect("Failed to parse");

    let body = module
        .function_bodies
        .get("test_function")
        .expect("test_function should have a body");

    let load_insts = body.instructions_of_kind(IRInstructionKind::Load);
    assert_eq!(load_insts.len(), 1, "Should have 1 load");
    assert!(
        load_insts[0].element_type.is_some(),
        "load instruction must have element_type populated, raw: {}",
        load_insts[0].raw_text
    );
    let elem_ty = load_insts[0].element_type.as_ref().unwrap();
    assert!(
        elem_ty.contains("i32"),
        "load element type should be i32, got: {}",
        elem_ty
    );

    let store_insts = body.instructions_of_kind(IRInstructionKind::Store);
    assert_eq!(store_insts.len(), 1, "Should have 1 store");
    assert!(
        store_insts[0].element_type.is_some(),
        "store instruction must have element_type populated, raw: {}",
        store_insts[0].raw_text
    );
}

// ──────────────────────────────────────────────────────────────────────────
// ICMP predicate verification
// ──────────────────────────────────────────────────────────────────────────

/// Objective: Verify the ICMP predicate string is extracted correctly.
/// Invariants: The icmp `sgt` (signed greater-than) predicate must be
/// present in the parsed instruction.
#[test]
fn test_icmp_predicate() {
    ensure_fixture_exists();
    let module = parse_with_llvm_sys(test_ll_path()).expect("Failed to parse");

    let body = module
        .function_bodies
        .get("test_function")
        .expect("test_function should have a body");

    let icmp_insts = body.instructions_of_kind(IRInstructionKind::Icmp);
    assert_eq!(icmp_insts.len(), 1, "Should have 1 icmp");

    assert_eq!(
        icmp_insts[0].icmp_pred.as_deref(),
        Some("sgt"),
        "icmp predicate should be 'sgt' (signed greater than), got: {:?}",
        icmp_insts[0].icmp_pred
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Empty module
// ──────────────────────────────────────────────────────────────────────────

/// Objective: Verify parsing an empty .ll file produces a valid empty module.
/// Invariants: All collections (functions, declarations, calls, bodies) must
/// be empty after parsing a minimal module with no definitions.
#[test]
fn test_empty_module() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut tmpfile = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(
        tmpfile,
        r#"target triple = "arm64-apple-darwin24.6.0"
"#
    )
    .expect("Failed to write temp file");

    let module = parse_with_llvm_sys(tmpfile.path()).expect("Failed to parse empty module");

    assert!(
        module.functions.is_empty(),
        "Empty module should have no functions"
    );
    assert!(
        module.declarations.is_empty(),
        "Empty module should have no declarations"
    );
    assert!(module.calls.is_empty(), "Empty module should have no calls");
    assert!(
        module.function_bodies.is_empty(),
        "Empty module should have no function bodies"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Cross-validation with text parser
// ──────────────────────────────────────────────────────────────────────────

/// Objective: Verify the llvm-sys adapter produces results consistent with
/// the text parser (same function names, declaration names, and instruction
/// counts for each kind).
/// Invariants: Both parsers must agree on function count, declaration count,
/// and per-kind instruction counts for `test_function`.
#[test]
fn test_cross_validate_with_text_parser() {
    ensure_fixture_exists();
    let ll_content = std::fs::read_to_string(test_ll_path()).expect("Failed to read .ll file");

    let text_module = IRModule::parse_from_text(&ll_content);
    let llvm_module = parse_with_llvm_sys(test_ll_path()).expect("Failed to parse with llvm-sys");

    assert_eq!(
        text_module.functions.len(),
        llvm_module.functions.len(),
        "Function count should match between text parser and llvm-sys"
    );

    assert_eq!(
        text_module.declarations.len(),
        llvm_module.declarations.len(),
        "Declaration count should match between text parser and llvm-sys"
    );

    for name in text_module.functions.keys() {
        assert!(
            llvm_module.functions.contains_key(name),
            "Function '{}' from text parser should exist in llvm-sys output",
            name
        );
    }

    for name in text_module.declarations.keys() {
        assert!(
            llvm_module.declarations.contains_key(name),
            "Declaration '{}' from text parser should exist in llvm-sys output",
            name
        );
    }

    let text_body = text_module
        .function_bodies
        .get("test_function")
        .expect("text parser should find test_function body");
    let llvm_body = llvm_module
        .function_bodies
        .get("test_function")
        .expect("llvm-sys should find test_function body");

    assert_eq!(
        text_body.instructions.len(),
        llvm_body.instructions.len(),
        "Instruction count for test_function should match: text={}, llvm-sys={}",
        text_body.instructions.len(),
        llvm_body.instructions.len()
    );

    for kind in &[
        IRInstructionKind::Icmp,
        IRInstructionKind::Branch,
        IRInstructionKind::Load,
        IRInstructionKind::Call,
        IRInstructionKind::Store,
        IRInstructionKind::Ret,
    ] {
        assert_eq!(
            text_body.count_kind(kind.clone()),
            llvm_body.count_kind(kind.clone()),
            "Count for {:?} should match between text parser and llvm-sys",
            kind
        );
    }
}
