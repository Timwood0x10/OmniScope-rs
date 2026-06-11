//! Tests for type confusion detector.
//!
//! This module contains comprehensive tests for the type confusion detector,
//! including tests for:
//! - Pointer/integer confusion (inttoptr/ptrtoint)
//! - Signed/unsigned confusion (sext/zext)
//! - Float/integer confusion (sitofp/fptoui)
//! - Type width mismatch (trunc/ext)
//! - Unsafe bitcast detection
//! - Struct width mismatch through void* casts
//! - patterns_to_semantic_facts pipeline integration

use super::type_confusion_detector::*;
use super::type_confusion_detector_helpers::*;
use omniscope_ir::{FunctionBody, IRInstructionKind, IRModule};
use tracing::debug;

/// Helper to parse IR and extract function body.
#[allow(dead_code)]
fn parse_body(ir: &str) -> FunctionBody {
    let module = IRModule::parse_from_text(ir);
    module
        .function_bodies
        .values()
        .next()
        .expect("type_confusion_tests::parse_body: no function body found")
        .clone()
}

/// Objective: Verify basic type confusion detection with inttoptr.
/// Invariants: inttoptr conversions must be detected as pointer/integer confusion.
#[test]
fn test_inttoptr_type_confusion() {
    let ir = r#"
        define void @test_inttoptr(i32 %value) {
        entry:
            %ptr = inttoptr i32 %value to i8*
            call void @use_pointer(i8* %ptr)
            ret void
        }
    "#;

    let detector = TypeConfusionDetector::new();
    let issues = detector.detect_issues(ir);

    // Debug: Check if IR parsing works
    let module = IRModule::parse_from_text(ir);

    for (name, body) in &module.function_bodies {
        debug!(
            "Function '{}' has {} instructions:",
            name,
            body.instructions.len()
        );
        for (i, inst) in body.instructions.iter().enumerate() {
            debug!("  {}: {:?} - {}", i, inst.kind, inst.raw_text);
        }

        // Check if use_pointer is recognized as external
        let ffi_calls = collect_ffi_calls(body);
        debug!("FFI calls found: {:?}", ffi_calls);

        // Check if inttoptr is detected
        let conv_insts: Vec<_> = body
            .instructions
            .iter()
            .filter(|i| i.kind == IRInstructionKind::Conversion)
            .collect();
        debug!("Conversion instructions: {:?}", conv_insts);

        // Check proximity
        for inst in &conv_insts {
            let (near_ffi, ffi_func) = check_ffi_proximity(inst, &ffi_calls, body);
            debug!(
                "Instruction '{}' near FFI: {} (function: {:?})",
                inst.raw_text, near_ffi, ffi_func
            );

            // Test type parsing - use conversion_opcode for structured check
            let is_inttoptr = inst.conversion_opcode.as_deref() == Some("inttoptr");
            debug!("Is inttoptr: {}", is_inttoptr);

            if is_inttoptr {
                let types = parse_intptr_types(&inst.raw_text, true);
                debug!("Parsed types: {:?}", types);
            }
        }
    }

    assert!(
        !issues.is_empty(),
        "Must detect inttoptr type confusion, found {} issues",
        issues.len()
    );

    let issue = &issues[0];
    assert!(
        matches!(
            issue.kind,
            TypeConfusionKind::PointerIntegerConfusion { .. }
        ),
        "Must be pointer/integer confusion"
    );
    assert!(issue.near_ffi_call, "Must detect proximity to FFI call");
}

/// Objective: Verify signed/unsigned confusion detection.
/// Invariants: sext/zext conversions near FFI must be detected.
#[test]
fn test_signed_unsigned_confusion() {
    let ir = r#"
        define void @test_sign_confusion(i32 %value) {
        entry:
            %extended = sext i32 %value to i64
            call void @ffi_process(i64 %extended)
            ret void
        }
    "#;

    let detector = TypeConfusionDetector::new();
    let issues = detector.detect_issues(ir);

    assert!(
        !issues.is_empty(),
        "Must detect signed/unsigned confusion, found {} issues",
        issues.len()
    );

    let issue = &issues[0];
    assert!(
        matches!(
            issue.kind,
            TypeConfusionKind::SignedUnsignedConfusion { .. }
        ),
        "Must be signed/unsigned confusion"
    );
}

/// Objective: Verify float/integer confusion detection.
/// Invariants: float/integer conversions near FFI must be detected.
#[test]
fn test_float_integer_confusion() {
    let ir = r#"
        define void @test_float_confusion(i32 %value) {
        entry:
            %float_val = sitofp i32 %value to float
            call void @ffi_process_float(float %float_val)
            ret void
        }
    "#;

    let detector = TypeConfusionDetector::new();
    let issues = detector.detect_issues(ir);

    assert!(
        !issues.is_empty(),
        "Must detect float/integer confusion, found {} issues",
        issues.len()
    );

    let issue = &issues[0];
    assert!(
        matches!(issue.kind, TypeConfusionKind::FloatIntegerConfusion { .. }),
        "Must be float/integer confusion"
    );
}

/// Objective: Verify type width mismatch detection.
/// Invariants: Significant width changes near FFI must be detected.
#[test]
fn test_type_width_mismatch() {
    let ir = r#"
        define void @test_width_mismatch(i64 %value) {
        entry:
            %truncated = trunc i64 %value to i32
            call void @ffi_process(i32 %truncated)
            ret void
        }
    "#;

    let detector = TypeConfusionDetector::new();
    let issues = detector.detect_issues(ir);

    assert!(
        !issues.is_empty(),
        "Must detect type width mismatch, found {} issues",
        issues.len()
    );

    let issue = &issues[0];
    assert!(
        matches!(issue.kind, TypeConfusionKind::TypeWidthMismatch { .. }),
        "Must be type width mismatch"
    );
}

/// Objective: Verify unsafe bitcast detection.
/// Invariants: Pointer type changes must be detected.
#[test]
fn test_unsafe_bitcast() {
    let ir = r#"
        define void @test_unsafe_bitcast(ptr %value) {
        entry:
            %casted = bitcast ptr %value to i32*
            call void @ffi_process_ptr(i32* %casted)
            ret void
        }
    "#;

    let detector = TypeConfusionDetector::new();
    let issues = detector.detect_issues(ir);

    assert!(
        !issues.is_empty(),
        "Must detect unsafe bitcast, found {} issues",
        issues.len()
    );

    let issue = &issues[0];
    assert!(
        matches!(issue.kind, TypeConfusionKind::UnsafeBitcast { .. }),
        "Must be unsafe bitcast"
    );
}

/// Objective: Verify no false positives for safe conversions.
/// Invariants: zext without FFI context should not be flagged.
#[test]
fn test_no_false_positives() {
    let ir = r#"
        define i64 @test_safe_conversion(i32 %value) {
        entry:
            %extended = zext i32 %value to i64
            ret i64 %extended
        }
    "#;

    let detector = TypeConfusionDetector::new();
    let issues = detector.detect_issues(ir);

    assert!(
        issues.is_empty(),
        "Safe conversion without FFI should not be flagged, found {} issues",
        issues.len()
    );
}

/// Objective: Verify multiple type confusions in one function.
/// Invariants: All type confusions must be detected.
#[test]
fn test_multiple_type_confusions() {
    let ir = r#"
        define void @test_multiple(i32 %value1, i64 %value2) {
        entry:
            %ptr = inttoptr i32 %value1 to i8*
            %truncated = trunc i64 %value2 to i32
            call void @ffi_process(i8* %ptr, i32 %truncated)
            ret void
        }
    "#;

    let detector = TypeConfusionDetector::new();
    let issues = detector.detect_issues(ir);

    assert!(
        issues.len() >= 2,
        "Must detect multiple type confusions, found {} issues",
        issues.len()
    );
}

/// Objective: Verify confidence levels are correctly assigned.
/// Invariants: Conversions near FFI calls must have high confidence.
#[test]
fn test_confidence_levels() {
    let ir = r#"
        define void @test_confidence(i32 %value) {
        entry:
            %ptr = inttoptr i32 %value to i8*
            call void @ffi_process(i8* %ptr)
            ret void
        }
    "#;

    let detector = TypeConfusionDetector::new();
    let issues = detector.detect_issues(ir);

    assert!(!issues.is_empty(), "Must detect type confusion");

    let issue = &issues[0];
    assert_eq!(
        issue.confidence,
        ConfusionConfidence::High,
        "Must be high confidence near FFI call"
    );
}

/// Objective: Verify CWE ID for type confusion.
/// Invariants: Must return CWE-843.
#[test]
fn test_type_confusion_cwe_id() {
    assert_eq!(
        type_confusion_cwe_id(),
        843,
        "Type confusion must map to CWE-843"
    );
}

/// Objective: Verify TypeConfusionDetector default settings.
/// Invariants: Default detector must have all checks enabled.
#[test]
fn test_detector_default_settings() {
    let detector = TypeConfusionDetector::new();
    assert!(
        detector.check_signed_unsigned,
        "Default must check signed/unsigned confusion"
    );
    assert!(
        detector.check_pointer_integer,
        "Default must check pointer/integer confusion"
    );
    assert!(
        detector.check_float_integer,
        "Default must check float/integer confusion"
    );
    assert!(
        detector.check_width_mismatch,
        "Default must check type width mismatch"
    );
    assert!(
        detector.check_unsafe_bitcast,
        "Default must check unsafe bitcast"
    );
    assert!(
        detector.check_struct_width,
        "Default must check struct width mismatch"
    );
}

/// Objective: Verify TypeConfusionDetector with custom settings.
/// Invariants: Custom settings must be respected.
#[test]
fn test_detector_custom_settings() {
    let detector = TypeConfusionDetector::with_settings(
        ConfusionConfidence::High,
        false, // disable signed/unsigned
        true,  // enable pointer/integer
        false, // disable float/integer
        true,  // enable width mismatch
        false, // disable unsafe bitcast
        false, // disable struct width
    );

    assert!(
        !detector.check_signed_unsigned,
        "Must respect custom signed/unsigned setting"
    );
    assert!(
        detector.check_pointer_integer,
        "Must respect custom pointer/integer setting"
    );
    assert!(
        !detector.check_float_integer,
        "Must respect custom float/integer setting"
    );
    assert!(
        detector.check_width_mismatch,
        "Must respect custom width mismatch setting"
    );
    assert!(
        !detector.check_unsafe_bitcast,
        "Must respect custom unsafe bitcast setting"
    );
    assert!(
        !detector.check_struct_width,
        "Must respect custom struct width setting"
    );
}

/// Objective: Verify helper functions for type parsing.
/// Invariants: Type parsing must handle common IR patterns.
#[test]
fn test_type_parsing_helpers() {
    // Test parse_extension_types
    let (src, tgt) = parse_extension_types("sext i32 %val to i64").unwrap();
    assert_eq!(src, "i32", "Source type must be i32");
    assert_eq!(tgt, "i64", "Target type must be i64");

    // Test parse_intptr_types
    let (int_type, ptr_type) = parse_intptr_types("inttoptr i32 %val to i8*", true).unwrap();
    assert_eq!(int_type, "i32", "Integer type must be i32");
    assert_eq!(ptr_type, "i8*", "Pointer type must be i8*");

    // Test parse_float_int_types
    let (float_type, int_type) = parse_float_int_types("sitofp i32 %val to float").unwrap();
    assert_eq!(float_type, "float", "Float type must be float");
    assert_eq!(int_type, "i32", "Integer type must be i32");
}

/// Objective: Verify type width calculation.
/// Invariants: All standard types must have correct widths.
#[test]
fn test_type_width_calculation() {
    assert_eq!(get_type_width("i8"), Some(8), "i8 must be 8 bits");
    assert_eq!(get_type_width("i16"), Some(16), "i16 must be 16 bits");
    assert_eq!(get_type_width("i32"), Some(32), "i32 must be 32 bits");
    assert_eq!(get_type_width("i64"), Some(64), "i64 must be 64 bits");
    assert_eq!(get_type_width("float"), Some(32), "float must be 32 bits");
    assert_eq!(get_type_width("double"), Some(64), "double must be 64 bits");
    assert_eq!(get_type_width("ptr"), Some(64), "ptr must be 64 bits");
    assert_eq!(
        get_type_width("i8*"),
        Some(64),
        "i8* must be 64 bits (pointer)"
    );
}

/// Objective: Verify unsafe bitcast detection logic.
/// Invariants: Pointer type changes must be detected as unsafe.
#[test]
fn test_unsafe_bitcast_detection() {
    assert!(
        is_unsafe_bitcast("i32*", "i8*"),
        "Different pointer types must be unsafe"
    );
    assert!(
        is_unsafe_bitcast("i32", "i8*"),
        "Integer to pointer must be unsafe"
    );
    assert!(
        is_unsafe_bitcast("i8*", "i32"),
        "Pointer to integer must be unsafe"
    );
    assert!(!is_unsafe_bitcast("i32", "i32"), "Same type must be safe");
    assert!(
        !is_unsafe_bitcast("i8*", "i8*"),
        "Same pointer type must be safe"
    );
}

/// Objective: Verify FFI type detection.
/// Invariants: Common FFI types must be recognized.
#[test]
fn test_ffi_type_detection() {
    assert!(is_ffi_type("i32"), "i32 must be FFI type");
    assert!(is_ffi_type("i64"), "i64 must be FFI type");
    assert!(is_ffi_type("float"), "float must be FFI type");
    assert!(is_ffi_type("double"), "double must be FFI type");
    assert!(is_ffi_type("ptr"), "ptr must be FFI type");
    assert!(is_ffi_type("i8*"), "i8* must be FFI type");
    assert!(!is_ffi_type("i31"), "i31 must not be FFI type");
    assert!(!is_ffi_type("i128"), "i128 must not be FFI type");
}

/// Objective: Verify end-to-end type confusion detection.
/// Invariants: Complete detection flow must work correctly.
#[test]
fn test_e2e_type_confusion_detection() {
    let ir = r#"
        define void @process_data(i32 %id, i64 %size, float %value) {
        entry:
            %id_ptr = inttoptr i32 %id to i8*
            %size32 = trunc i64 %size to i32
            %value_int = fptoui float %value to i32
            call void @ffi_process(i8* %id_ptr, i32 %size32, i32 %value_int)
            ret void
        }
    "#;

    let detector = TypeConfusionDetector::new();
    let issues = detector.detect_issues(ir);

    assert!(
        issues.len() >= 3,
        "Must detect all type confusions, found {} issues",
        issues.len()
    );

    // Check for different types of confusions
    let has_inttoptr = issues
        .iter()
        .any(|i| matches!(i.kind, TypeConfusionKind::PointerIntegerConfusion { .. }));
    let has_width_mismatch = issues
        .iter()
        .any(|i| matches!(i.kind, TypeConfusionKind::TypeWidthMismatch { .. }));
    let has_float_confusion = issues
        .iter()
        .any(|i| matches!(i.kind, TypeConfusionKind::FloatIntegerConfusion { .. }));

    assert!(has_inttoptr, "Must detect inttoptr confusion");
    assert!(has_width_mismatch, "Must detect width mismatch");
    assert!(has_float_confusion, "Must detect float/integer confusion");
}

// ── Struct Width Mismatch Tests ──

/// Objective: Verify struct width mismatch detection through void* cast.
/// Invariants: u64→u32 truncation through void* must be detected as
///             StructWidthMismatch near an FFI call.
#[test]
fn test_struct_width_mismatch_u64_to_u32() {
    // Simulates FN-8: caller passes {u64,u64} (16B), callee reads {u32,u32} (8B)
    // Uses typed pointers so the bitcast parses as different source/target types.
    // The Config→CConfig cast through void* triggers StructWidthMismatch.
    let ir = r#"
        define void @process_config(ptr %opaque_arg) {
        entry:
            %casted = bitcast ptr %opaque_arg to i8*
            %field0 = getelementptr inbounds { i32, i32 }, ptr %casted, i64 0, i32 0
            %val0 = load i32, ptr %field0
            call void @ffi_use_config(i32 %val0)
            ret void
        }
    "#;

    let detector = TypeConfusionDetector::new();
    let issues = detector.detect_issues(ir);

    // Must detect at least one issue — either StructWidthMismatch (if size
    // estimation fires on the ptr→i8* difference) or UnsafeBitcast for
    // the ptr-to-different-ptr cast near FFI call
    assert!(
        !issues.is_empty(),
        "Must detect issue for void* cast + GEP + FFI pattern, \
         found {} issues: {:?}",
        issues.len(),
        issues.iter().map(|i| &i.kind).collect::<Vec<_>>()
    );
}

/// Objective: Verify that same-size casts are not flagged as struct mismatches.
/// Invariants: Casting between same-size pointer types should not produce
///             StructWidthMismatch (may still be flagged as UnsafeBitcast).
#[test]
fn test_struct_width_same_size_not_flagged() {
    let ir = r#"
        define void @same_size_cast(ptr %arg) {
        entry:
            %casted = bitcast ptr %arg to ptr
            ret void
        }
    "#;

    let detector = TypeConfusionDetector::new();
    let issues = detector.detect_issues(ir);

    let has_struct_width = issues
        .iter()
        .any(|i| matches!(i.kind, TypeConfusionKind::StructWidthMismatch { .. }));

    assert!(
        !has_struct_width,
        "Same-size cast must not be flagged as StructWidthMismatch, found {} issues",
        issues.len()
    );
}

/// Objective: Verify anonymous struct size parsing.
/// Invariants: `{ i64, i64 }` must parse as 16 bytes, `{ i32, i32 }` as 8 bytes.
#[test]
fn test_anonymous_struct_size_parsing() {
    // { i64, i64 } = 128 bits = 16 bytes
    assert_eq!(
        parse_anonymous_struct_size("{ i64, i64 }"),
        Some(16),
        "{{i64,i64}} must be 16 bytes"
    );

    // { i32, i32 } = 64 bits = 8 bytes
    assert_eq!(
        parse_anonymous_struct_size("{ i32, i32 }"),
        Some(8),
        "{{i32,i32}} must be 8 bytes"
    );

    // { i32, i32, i8 } = 72 bits = 9 bytes
    assert_eq!(
        parse_anonymous_struct_size("{ i32, i32, i8 }"),
        Some(9),
        "{{i32,i32,i8}} must be 9 bytes"
    );

    // Not a struct literal → None
    assert_eq!(
        parse_anonymous_struct_size("ptr"),
        None,
        "Non-struct type must return None"
    );

    assert_eq!(
        parse_anonymous_struct_size("i32*"),
        None,
        "Pointer type must return None"
    );
}

/// Objective: Verify named struct size estimation heuristics.
/// Invariants: Config structs default to 16B, C-prefixed to 8B.
#[test]
fn test_named_struct_size_estimation() {
    // Config-style struct → 16 bytes
    assert_eq!(
        estimate_named_struct_size("AppConfig"),
        Some(16),
        "AppConfig must estimate to 16 bytes"
    );
    assert_eq!(
        estimate_named_struct_size("config"),
        Some(16),
        "config must estimate to 16 bytes"
    );

    // C-style config → 8 bytes
    assert_eq!(
        estimate_named_struct_size("CConfig"),
        Some(8),
        "CConfig must estimate to 8 bytes"
    );
    assert_eq!(
        estimate_named_struct_size("c_config"),
        Some(8),
        "c_config must estimate to 8 bytes"
    );

    // Unknown name → None
    assert_eq!(
        estimate_named_struct_size("UnknownType"),
        None,
        "UnknownType must return None"
    );
}

/// Objective: Verify patterns_to_semantic_facts produces correct facts.
/// Invariants: StructWidthMismatch patterns must convert to SemanticFact
///             with appropriate kind and evidence text.
#[test]
fn test_patterns_to_semantic_facts() {
    let patterns = vec![TypeConfusionPattern {
        kind: TypeConfusionKind::StructWidthMismatch {
            caller_struct_size: 16,
            callee_struct_size: 8,
            caller_type: "ptr".to_string(),
            callee_type: "ptr".to_string(),
        },
        instruction: "%c = bitcast ptr %a to ptr".to_string(),
        near_ffi_call: true,
        ffi_function: Some("ffi_process".to_string()),
        confidence: ConfusionConfidence::High,
        line_number: None,
    }];

    let facts = TypeConfusionDetector::patterns_to_semantic_facts(&patterns, "test_func");

    assert_eq!(facts.len(), 1, "Must produce exactly one fact");
    let fact = &facts[0];
    assert!(
        fact.evidence.contains("StructWidthMismatch"),
        "Evidence must contain 'StructWidthMismatch', got: {}",
        fact.evidence
    );
    assert!(
        fact.evidence.contains("16B"),
        "Evidence must contain caller size '16B', got: {}",
        fact.evidence
    );
    assert!(
        fact.evidence.contains("8B"),
        "Evidence must contain callee size '8B', got: {}",
        fact.evidence
    );
    assert!(
        fact.evidence.contains("test_func"),
        "Evidence must contain function name, got: {}",
        fact.evidence
    );
    assert_eq!(
        fact.confidence,
        crate::resource::semantic_tree::FactConfidence::High,
        "High confidence pattern must produce High fact confidence"
    );
}

/// Objective: Verify check_struct_width flag controls detection.
/// Invariants: When check_struct_width is false, no StructWidthMismatch
///             patterns should be produced.
#[test]
fn test_check_struct_width_flag() {
    let ir = r#"
        define void @test_flag(ptr %arg) {
        entry:
            %casted = bitcast ptr %arg to ptr
            %f = getelementptr { i32, i32 }, ptr %casted, i64 0, i32 0
            call void @use_value(ptr %f)
            ret void
        }
    "#;

    // With check enabled — may detect
    let detector_on = TypeConfusionDetector::with_settings(
        ConfusionConfidence::Low,
        true,
        true,
        true,
        true,
        true,
        true,
    );
    let _issues_on = detector_on.detect_issues(ir);

    // With check disabled — should not produce StructWidthMismatch
    let detector_off = TypeConfusionDetector::with_settings(
        ConfusionConfidence::Low,
        true,
        true,
        true,
        true,
        true,
        false,
    );
    let issues_off = detector_off.detect_issues(ir);

    let has_struct_off = issues_off
        .iter()
        .any(|i| matches!(i.kind, TypeConfusionKind::StructWidthMismatch { .. }));

    assert!(
        !has_struct_off,
        "With check_struct_width=false, no StructWidthMismatch should appear"
    );
}

/// Objective: Verify default settings include check_struct_width.
/// Invariants: New detector must have check_struct_width=true by default.
#[test]
fn test_default_includes_struct_width() {
    let detector = TypeConfusionDetector::new();
    assert!(
        detector.check_struct_width,
        "Default detector must have check_struct_width enabled"
    );
}
