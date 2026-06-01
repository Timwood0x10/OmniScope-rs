//! Tests for length truncation detector.
//!
//! This module contains comprehensive tests for the length truncation detector,
//! including tests for risk factor detection such as:
//! - Signed/unsigned conversion
//! - Missing range checks
//! - Boundary conditions
//! - Potential overflow

use super::length_truncation_detector::*;
use omniscope_ir::{FunctionBody, IRModule};

/// Helper to parse IR and extract function body.
fn parse_body(ir: &str) -> FunctionBody {
    let module = IRModule::parse_from_text(ir);
    module
        .function_bodies
        .values()
        .next()
        .expect("length_truncation_tests::parse_body: no function body found")
        .clone()
}

/// Objective: Verify 64-bit to 32-bit truncation detection.
/// Invariants: Truncation from i64 to i32 must be detected as size truncation.
#[test]
fn test_detect_i64_to_i32_truncation() {
    let ir = r#"
        define void @process(i64 %size) {
        entry:
            %truncated = trunc i64 %size to i32
            call void @ffi_process(i32 %truncated)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        !analysis.patterns.is_empty(),
        "Must detect i64 to i32 truncation, found {} patterns",
        analysis.patterns.len()
    );

    let pattern = &analysis.patterns[0];
    assert_eq!(
        pattern.source_width,
        TypeWidth::Bits64,
        "Source width must be 64-bit"
    );
    assert_eq!(
        pattern.target_width,
        TypeWidth::Bits32,
        "Target width must be 32-bit"
    );
    assert!(pattern.near_ffi_call, "Must detect proximity to FFI call");
}

/// Objective: Verify truncation detection with multiple truncations.
/// Invariants: All truncation patterns must be detected.
#[test]
fn test_detect_multiple_truncations() {
    let ir = r#"
        define void @process(i64 %len, i64 %count) {
        entry:
            %len32 = trunc i64 %len to i32
            %count16 = trunc i64 %count to i16
            call void @ffi_process(i32 %len32, i16 %count16)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert_eq!(
        analysis.patterns.len(),
        2,
        "Must detect both truncations, found {}",
        analysis.patterns.len()
    );
}

/// Objective: Verify non-size truncation is ignored.
/// Invariants: i32 to i31 truncation should not be flagged.
#[test]
fn test_ignore_non_size_truncation() {
    let ir = r#"
        define i31 @convert(i32 %val) {
        entry:
            %result = trunc i32 %val to i31
            ret i31 %result
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        analysis.patterns.is_empty(),
        "Non-size truncation (i32 to i31) should not be flagged, found {} patterns",
        analysis.patterns.len()
    );
}

/// Objective: Verify FFI proximity detection.
/// Invariants: Truncation within 5 instructions of FFI call is high confidence.
#[test]
fn test_ffi_proximity_detection() {
    let ir = r#"
        define void @process(i64 %size) {
        entry:
            %truncated = trunc i64 %size to i32
            %extended = zext i32 %truncated to i64
            call void @malloc(i64 %extended)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        !analysis.patterns.is_empty(),
        "Must detect truncation before malloc"
    );

    let pattern = &analysis.patterns[0];
    assert!(
        pattern.near_ffi_call,
        "Must detect proximity to FFI call (malloc)"
    );
    assert!(
        pattern.ffi_function.is_some(),
        "Must identify FFI function name"
    );
    assert_eq!(
        pattern.confidence,
        TruncationConfidence::High,
        "Must be high confidence near FFI call"
    );
}

/// Objective: Verify TypeWidth can_hold logic.
/// Invariants: 64-bit can hold 32-bit, but not vice versa.
#[test]
fn test_type_width_can_hold() {
    assert!(
        TypeWidth::Bits64.can_hold(&TypeWidth::Bits32),
        "64-bit must be able to hold 32-bit value"
    );
    assert!(
        !TypeWidth::Bits32.can_hold(&TypeWidth::Bits64),
        "32-bit must NOT be able to hold 64-bit value"
    );
    assert!(
        TypeWidth::Bits64.can_hold(&TypeWidth::Bits64),
        "64-bit must be able to hold 64-bit value"
    );
}

/// Objective: Verify TypeWidth from_bits conversion.
/// Invariants: All standard widths must be correctly converted.
#[test]
fn test_type_width_from_bits() {
    assert_eq!(
        TypeWidth::from_bits(64),
        TypeWidth::Bits64,
        "64 bits must convert to Bits64"
    );
    assert_eq!(
        TypeWidth::from_bits(32),
        TypeWidth::Bits32,
        "32 bits must convert to Bits32"
    );
    assert_eq!(
        TypeWidth::from_bits(16),
        TypeWidth::Bits16,
        "16 bits must convert to Bits16"
    );
    assert_eq!(
        TypeWidth::from_bits(8),
        TypeWidth::Bits8,
        "8 bits must convert to Bits8"
    );
    assert_eq!(
        TypeWidth::from_bits(31),
        TypeWidth::Unknown,
        "31 bits must convert to Unknown"
    );
}

/// Objective: Verify truncation description generation.
/// Invariants: Description must include register and width information.
#[test]
fn test_truncation_description() {
    let pattern = TruncationPattern {
        source_width: TypeWidth::Bits64,
        target_width: TypeWidth::Bits32,
        truncated_register: "%size".to_string(),
        near_ffi_call: true,
        ffi_function: Some("malloc".to_string()),
        confidence: TruncationConfidence::High,
        risk_factors: Vec::new(),
    };

    let desc = describe_truncation(&pattern);
    assert!(
        desc.contains("%size"),
        "Description must contain register name"
    );
    assert!(
        desc.contains("64-bit"),
        "Description must contain source width"
    );
    assert!(
        desc.contains("32-bit"),
        "Description must contain target width"
    );
    assert!(
        desc.contains("malloc"),
        "Description must contain FFI function name"
    );
}

/// Objective: Verify CWE ID for truncation.
/// Invariants: Must return CWE-197.
#[test]
fn test_truncation_cwe_id() {
    assert_eq!(truncation_cwe_id(), 197, "Truncation must map to CWE-197");
}

/// Objective: Verify external function detection for C library.
/// Invariants: Common C functions must be recognized as external.
#[test]
fn test_external_function_detection() {
    assert!(is_external_function("malloc"), "malloc must be external");
    assert!(is_external_function("free"), "free must be external");
    assert!(is_external_function("memcpy"), "memcpy must be external");
    assert!(is_external_function("strlen"), "strlen must be external");
    assert!(is_external_function("printf"), "printf must be external");
    assert!(
        is_external_function("_Z7my_funcv"),
        "C++ mangled name must be external"
    );
}

/// Objective: Verify Rust functions are not detected as external.
/// Invariants: Rust mangled names must not be external.
#[test]
fn test_rust_function_not_external() {
    assert!(
        !is_external_function("_ZN4core3ptr9drop_in_place"),
        "Rust mangled name must not be external"
    );
    assert!(
        !is_external_function("_RINvNtC"),
        "Rust mangled name must not be external"
    );
}

/// Objective: Verify truncation in function without FFI calls.
/// Invariants: Must be detected with low confidence.
#[test]
fn test_truncation_without_ffi() {
    let ir = r#"
        define i32 @convert(i64 %size) {
        entry:
            %result = trunc i64 %size to i32
            ret i32 %result
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        !analysis.patterns.is_empty(),
        "Must detect truncation even without FFI calls"
    );

    let pattern = &analysis.patterns[0];
    assert!(
        !pattern.near_ffi_call,
        "Must not detect FFI proximity without FFI calls"
    );
    assert_eq!(
        pattern.confidence,
        TruncationConfidence::Low,
        "Must be low confidence without FFI calls"
    );
}

/// Objective: Verify 32-bit to 16-bit truncation detection.
/// Invariants: Must detect i32 to i16 truncation.
#[test]
fn test_detect_i32_to_i16_truncation() {
    let ir = r#"
        define void @process(i32 %count) {
        entry:
            %truncated = trunc i32 %count to i16
            call void @ffi_process(i16 %truncated)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        !analysis.patterns.is_empty(),
        "Must detect i32 to i16 truncation"
    );

    let pattern = &analysis.patterns[0];
    assert_eq!(
        pattern.source_width,
        TypeWidth::Bits32,
        "Source width must be 32-bit"
    );
    assert_eq!(
        pattern.target_width,
        TypeWidth::Bits16,
        "Target width must be 16-bit"
    );
}

/// Objective: Verify register extraction from truncation instruction.
/// Invariants: Must correctly extract register names.
#[test]
fn test_register_extraction() {
    let raw1 = "  %size = trunc i64 %arg0 to i32";
    assert_eq!(
        extract_truncated_register(raw1),
        Some("%arg0".to_string()),
        "Must extract %arg0 from truncation"
    );

    let raw2 = "  %len = trunc i64 @global to i32";
    assert_eq!(
        extract_truncated_register(raw2),
        Some("@global".to_string()),
        "Must extract @global from truncation"
    );

    let raw3 = "  %val = add i32 %a, %b";
    assert_eq!(
        extract_truncated_register(raw3),
        None,
        "Must return None for non-truncation instruction"
    );
}

/// Objective: Verify truncation width parsing.
/// Invariants: Must correctly parse source and target widths.
#[test]
fn test_width_parsing() {
    let raw1 = "trunc i64 %size to i32";
    let (src, tgt) = parse_truncation_widths(raw1).unwrap();
    assert_eq!(src, TypeWidth::Bits64, "Source must be 64-bit");
    assert_eq!(tgt, TypeWidth::Bits32, "Target must be 32-bit");

    let raw2 = "trunc i32 %val to i8";
    let (src, tgt) = parse_truncation_widths(raw2).unwrap();
    assert_eq!(src, TypeWidth::Bits32, "Source must be 32-bit");
    assert_eq!(tgt, TypeWidth::Bits8, "Target must be 8-bit");
}

/// Objective: Verify end-to-end truncation detection with FFI.
/// Invariants: Complete detection flow must work correctly.
#[test]
fn test_e2e_truncation_with_ffi() {
    let ir = r#"
        define void @process_buffer(ptr %data, i64 %len) {
        entry:
            %len32 = trunc i64 %len to i32
            call void @C_process(ptr %data, i32 %len32)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        !analysis.patterns.is_empty(),
        "Must detect truncation in buffer processing"
    );
    assert!(analysis.has_ffi_calls, "Must detect FFI calls");

    let pattern = &analysis.patterns[0];
    assert!(pattern.near_ffi_call, "Truncation must be near FFI call");
    assert_eq!(
        pattern.confidence,
        TruncationConfidence::High,
        "Must be high confidence"
    );
}

/// Objective: Verify no false positives for non-truncation conversions.
/// Invariants: zext and sext must not be flagged.
#[test]
fn test_no_false_positives_for_extensions() {
    let ir = r#"
        define i64 @extend(i32 %val) {
        entry:
            %extended = zext i32 %val to i64
            ret i64 %extended
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        analysis.patterns.is_empty(),
        "zext must not be flagged as truncation"
    );
}

/// Objective: Verify signed/unsigned conversion detection.
/// Invariants: Truncation followed by sext must be detected as risk.
#[test]
fn test_signed_unsigned_conversion_detection() {
    let ir = r#"
        define void @process(i64 %size) {
        entry:
            %truncated = trunc i64 %size to i32
            %extended = sext i32 %truncated to i64
            call void @ffi_process(i64 %extended)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        !analysis.patterns.is_empty(),
        "Must detect truncation with signed/unsigned conversion"
    );

    let pattern = &analysis.patterns[0];
    assert!(
        pattern
            .risk_factors
            .contains(&TruncationRisk::SignedUnsignedConversion),
        "Must detect signed/unsigned conversion risk"
    );
}

/// Objective: Verify missing range check detection.
/// Invariants: Truncation without range check must be detected as risk.
#[test]
fn test_missing_range_check_detection() {
    let ir = r#"
        define void @process(i64 %size) {
        entry:
            %truncated = trunc i64 %size to i32
            call void @ffi_process(i32 %truncated)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        !analysis.patterns.is_empty(),
        "Must detect truncation without range check"
    );

    let pattern = &analysis.patterns[0];
    assert!(
        pattern
            .risk_factors
            .contains(&TruncationRisk::MissingRangeCheck),
        "Must detect missing range check risk"
    );
}

/// Objective: Verify boundary condition detection.
/// Invariants: Truncation followed by icmp must be detected as risk.
#[test]
fn test_boundary_condition_detection() {
    let ir = r#"
        define void @process(i64 %size) {
        entry:
            %truncated = trunc i64 %size to i32
            %cmp = icmp ult i32 %truncated, 1024
            call void @ffi_process(i32 %truncated)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        !analysis.patterns.is_empty(),
        "Must detect truncation with boundary condition"
    );

    let pattern = &analysis.patterns[0];
    assert!(
        pattern
            .risk_factors
            .contains(&TruncationRisk::BoundaryCondition),
        "Must detect boundary condition risk"
    );
}

/// Objective: Verify potential overflow detection.
/// Invariants: Large to small truncation without validation must be detected.
#[test]
fn test_potential_overflow_detection() {
    let ir = r#"
        define void @process(i64 %size) {
        entry:
            %truncated = trunc i64 %size to i8
            call void @ffi_process(i8 %truncated)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        !analysis.patterns.is_empty(),
        "Must detect potential overflow truncation"
    );

    let pattern = &analysis.patterns[0];
    assert!(
        pattern
            .risk_factors
            .contains(&TruncationRisk::PotentialOverflow),
        "Must detect potential overflow risk"
    );
}

/// Objective: Verify range check prevents missing range check risk.
/// Invariants: Truncation with range check must not flag missing range check.
#[test]
fn test_range_check_prevents_risk() {
    let ir = r#"
        define void @process(i64 %size) {
        entry:
            %cmp = icmp ult i64 %size, 4294967296
            br i1 %cmp, label %valid, label %invalid
        valid:
            %truncated = trunc i64 %size to i32
            call void @ffi_process(i32 %truncated)
            ret void
        invalid:
            call void @error_handler()
            ret void
        }
    "#;

    let body = parse_body(ir);
    let analysis = extract_truncation_patterns(&body);

    assert!(
        !analysis.patterns.is_empty(),
        "Must detect truncation with range check"
    );

    let pattern = &analysis.patterns[0];
    assert!(
        !pattern
            .risk_factors
            .contains(&TruncationRisk::MissingRangeCheck),
        "Must not flag missing range check when range check exists"
    );
}

/// Objective: Verify risk factors in description.
/// Invariants: Description must include risk factors when present.
#[test]
fn test_risk_factors_in_description() {
    let pattern = TruncationPattern {
        source_width: TypeWidth::Bits64,
        target_width: TypeWidth::Bits32,
        truncated_register: "%size".to_string(),
        near_ffi_call: true,
        ffi_function: Some("malloc".to_string()),
        confidence: TruncationConfidence::High,
        risk_factors: vec![
            TruncationRisk::MissingRangeCheck,
            TruncationRisk::PotentialOverflow,
        ],
    };

    let desc = describe_truncation(&pattern);
    assert!(
        desc.contains("missing range check"),
        "Description must contain missing range check risk"
    );
    assert!(
        desc.contains("potential overflow"),
        "Description must contain potential overflow risk"
    );
}

/// Objective: Verify no risk factors in description when empty.
/// Invariants: Description must not contain risk factors when empty.
#[test]
fn test_no_risk_factors_in_description() {
    let pattern = TruncationPattern {
        source_width: TypeWidth::Bits64,
        target_width: TypeWidth::Bits32,
        truncated_register: "%size".to_string(),
        near_ffi_call: true,
        ffi_function: Some("malloc".to_string()),
        confidence: TruncationConfidence::High,
        risk_factors: Vec::new(),
    };

    let desc = describe_truncation(&pattern);
    assert!(
        !desc.contains("["),
        "Description must not contain risk factors when empty"
    );
}
