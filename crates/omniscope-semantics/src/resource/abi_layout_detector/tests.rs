//! Tests for ABI layout detector.

use super::*;
use std::collections::HashMap;

/// Objective: Verify basic struct padding detection
/// Invariants: Padding bytes must be identified for misaligned fields
#[test]
fn test_struct_padding_detection() {
    let ir = r#"
        %struct.MyStruct = type { i8, i32 }
        define void @test_padding() {
          %s = alloca %struct.MyStruct
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let issues = detector.detect_issues(ir);

    // Should detect padding between i8 and i32
    assert!(
        issues.iter().any(|issue| matches!(
            issue,
            AbiIssue::StructPadding {
                padding_bytes: 3,
                ..
            }
        )),
        "Should detect 3 bytes padding between i8 and i32"
    );
}

/// Objective: Verify struct with no padding is correctly handled
/// Invariants: Well-aligned structs should not trigger padding issues
#[test]
fn test_no_padding_detection() {
    let ir = r#"
        %struct.Aligned = type { i32, i32, i64 }
        define void @test_no_padding() {
          %s = alloca %struct.Aligned
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let issues = detector.detect_issues(ir);

    // Should not detect padding issues
    assert!(
        !issues
            .iter()
            .any(|issue| matches!(issue, AbiIssue::StructPadding { .. })),
        "Well-aligned struct should not have padding issues"
    );
}

/// Objective: Verify field ordering detection
/// Invariants: Suboptimal field ordering should be detected
#[test]
fn test_field_ordering_detection() {
    let ir = r#"
        %struct.Suboptimal = type { i8, i64, i8, i64 }
        define void @test_ordering() {
          %s = alloca %struct.Suboptimal
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let issues = detector.detect_issues(ir);

    // Should detect field ordering issue
    assert!(
        issues
            .iter()
            .any(|issue| matches!(issue, AbiIssue::FieldOrdering { .. })),
        "Should detect suboptimal field ordering"
    );
}

/// Objective: Verify excessive padding detection
/// Invariants: Structs with >50% padding should be flagged
#[test]
fn test_excessive_padding_detection() {
    let ir = r#"
        %struct.Wasteful = type { i8, i64, i8, i64, i8 }
        define void @test_excessive() {
          %s = alloca %struct.Wasteful
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let issues = detector.detect_issues(ir);

    // Should detect excessive padding
    assert!(
        issues.iter().any(|issue| matches!(issue,
            AbiIssue::ExcessivePadding { padding_ratio, .. } if *padding_ratio > 0.5
        )),
        "Should detect excessive padding (>50%)"
    );
}

/// Objective: Verify empty struct detection
/// Invariants: Empty structs should be flagged as issues
#[test]
fn test_empty_struct_detection() {
    let ir = r#"
        %struct.Empty = type {}
        define void @test_empty() {
          %s = alloca %struct.Empty
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let issues = detector.detect_issues(ir);

    // Should detect empty struct
    assert!(
        issues
            .iter()
            .any(|issue| matches!(issue, AbiIssue::EmptyStruct { .. })),
        "Should detect empty struct"
    );
}

/// Objective: Verify packed struct handling
/// Invariants: Packed structs should not trigger padding issues
#[test]
fn test_packed_struct_handling() {
    let ir = r#"
        %struct.Packed = type <{ i8, i32 }>
        define void @test_packed() {
          %s = alloca %struct.Packed
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let issues = detector.detect_issues(ir);

    // Should not detect padding issues for packed structs
    assert!(
        !issues
            .iter()
            .any(|issue| matches!(issue, AbiIssue::StructPadding { .. })),
        "Packed structs should not have padding issues"
    );
}

/// Objective: Verify multiple struct analysis
/// Invariants: Multiple structs should be analyzed independently
#[test]
fn test_multiple_struct_analysis() {
    let ir = r#"
        %struct.Good = type { i32, i32 }
        %struct.Bad = type { i8, i64 }
        define void @test_multiple() {
          %s1 = alloca %struct.Good
          %s2 = alloca %struct.Bad
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let issues = detector.detect_issues(ir);

    // Should detect issues only in Bad struct
    assert!(
        issues.iter().any(|issue| match issue {
            AbiIssue::StructPadding { struct_name, .. } => struct_name == "struct.Bad",
            _ => false,
        }),
        "Should detect padding in Bad struct"
    );
}

/// Objective: Verify struct cache functionality
/// Invariants: Cached layouts should be retrievable
#[test]
fn test_struct_cache() {
    let ir = r#"
        %struct.Cached = type { i32, i64 }
        define void @test_cache() {
          %s = alloca %struct.Cached
          ret void
        }
    "#;

    let mut detector = AbiLayoutDetector::new();
    let structs = detector.parse_struct_definitions(ir);

    // Cache the struct
    for (_, layout) in structs {
        detector.cache_struct_layout(layout);
    }

    // Verify cache
    assert!(
        detector.get_cached_layout("struct.Cached").is_some(),
        "Struct should be in cache"
    );
    assert!(
        detector.get_cached_layout("struct.NonExistent").is_none(),
        "Non-existent struct should not be in cache"
    );

    // Clear cache
    detector.clear_cache();
    assert!(
        detector.get_cached_layout("struct.Cached").is_none(),
        "Cache should be empty after clearing"
    );
}

/// Objective: Verify cross-language ABI analysis
/// Invariants: Language-specific rules should be applied
#[test]
fn test_cross_language_abi_analysis() {
    let ir = r#"
        %struct.CrossLang = type { i32, i64 }
        define void @test_cross_lang() {
          %s = alloca %struct.CrossLang
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let structs = detector.parse_struct_definitions(ir);
    let layout = structs.get("struct.CrossLang").unwrap();

    // Test C vs Rust - should detect field ordering rules difference
    let issue = detector.analyze_cross_language_abi(layout, "c", "rust");
    assert!(
        issue.is_some(),
        "C and Rust should have ABI differences due to field ordering rules"
    );

    // Test C vs C (same language, should be compatible)
    let issue = detector.analyze_cross_language_abi(layout, "c", "c");
    assert!(issue.is_none(), "Same language should be ABI compatible");

    // Test Rust vs Rust (same language, should be compatible)
    let issue = detector.analyze_cross_language_abi(layout, "rust", "rust");
    assert!(issue.is_none(), "Same language should be ABI compatible");
}

/// Objective: Verify type parsing for various LLVM IR types
/// Invariants: All common LLVM IR types should be parsed correctly
#[test]
fn test_type_parsing() {
    let detector = AbiLayoutDetector::new();

    // Test integer types
    let (size, align) = detector.get_type_info("i32");
    assert_eq!(size, 4, "i32 should be 4 bytes");
    assert_eq!(align, 4, "i32 should have 4-byte alignment");

    // Test pointer type
    let (size, align) = detector.get_type_info("ptr");
    assert_eq!(size, 8, "Pointer should be 8 bytes");
    assert_eq!(align, 8, "Pointer should have 8-byte alignment");

    // Test array type
    let (size, align) = detector.get_type_info("[10 x i32]");
    assert_eq!(size, 40, "Array of 10 i32 should be 40 bytes");
    assert_eq!(align, 4, "Array alignment should match element alignment");

    // Test unknown type
    let (size, align) = detector.get_type_info("unknown_type");
    assert_eq!(size, 0, "Unknown type should have 0 size");
    assert_eq!(align, 1, "Unknown type should have 1-byte alignment");
}

/// Objective: Verify struct layout calculation
/// Invariants: Struct size should include proper padding
#[test]
fn test_struct_layout_calculation() {
    let detector = AbiLayoutDetector::new();

    // Test struct with padding
    let fields = vec![
        StructField {
            name: "a".to_string(),
            type_str: "i8".to_string(),
            size: 1,
            alignment: 1,
            offset: None,
        },
        StructField {
            name: "b".to_string(),
            type_str: "i32".to_string(),
            size: 4,
            alignment: 4,
            offset: None,
        },
    ];

    let alignment = detector.calculate_struct_alignment(&fields);
    assert_eq!(alignment, 4, "Struct alignment should be 4");

    let size = detector.calculate_struct_size(&fields, alignment, false);
    assert_eq!(size, Some(8), "Struct size should be 8 (1 + 3 padding + 4)");
}

/// Objective: Verify issue display formatting
/// Invariants: All issue types should have meaningful display messages
#[test]
fn test_issue_display() {
    let issue = AbiIssue::StructPadding {
        struct_name: "test.Struct".to_string(),
        padding_bytes: 3,
        field_before: "field_i8".to_string(),
        field_after: "field_i32".to_string(),
        offset: 1,
    };

    let display = format!("{}", issue);
    assert!(
        display.contains("3 bytes padding"),
        "Display should mention padding bytes"
    );
    assert!(
        display.contains("test.Struct"),
        "Display should mention struct name"
    );
}

/// Objective: Verify detector with custom language rules
/// Invariants: Custom rules should override defaults
#[test]
fn test_custom_language_rules() {
    let mut rules = HashMap::new();
    rules.insert(
        "custom".to_string(),
        LanguageAbiRules {
            pointer_alignment: 4, // 32-bit
            default_packed: true,
            allow_field_reordering: false,
        },
    );

    let detector = AbiLayoutDetector::with_language_rules(rules);
    assert!(
        detector.language_rules.contains_key("custom"),
        "Custom rules should be stored"
    );
}

/// Objective: Verify endianness issue detection
/// Invariants: Multi-byte fields should be flagged for endianness issues
#[test]
fn test_endianness_issue_detection() {
    let ir = r#"
        %struct.EndianTest = type { i16, i32, i64 }
        define void @test_endian() {
          %s = alloca %struct.EndianTest
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let issues = detector.detect_issues(ir);

    // Should detect endianness issues for multi-byte fields
    assert!(
        issues
            .iter()
            .any(|issue| matches!(issue, AbiIssue::EndiannessIssue { .. })),
        "Should detect endianness issues for multi-byte fields"
    );
}

/// Objective: Verify packed struct endianness issue detection
/// Invariants: Packed structs with multi-byte fields should have alignment issues
#[test]
fn test_packed_struct_endianness_issues() {
    let ir = r#"
        %struct.PackedEndian = type <{ i16, i32 }>
        define void @test_packed_endian() {
          %s = alloca %struct.PackedEndian
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let issues = detector.detect_issues(ir);

    // Should detect alignment issues in packed structs
    assert!(
        issues.iter().any(|issue| matches!(issue,
            AbiIssue::EndiannessIssue {
                issue_details, ..
            } if issue_details.contains("alignment issues")
        )),
        "Should detect alignment issues in packed structs"
    );
}

/// Objective: Verify bitfield layout issue detection
/// Invariants: Packed structs with small integer fields should have bitfield issues
#[test]
fn test_bitfield_layout_issue_detection() {
    let ir = r#"
        %struct.BitfieldTest = type <{ i8, i8, i8 }>
        define void @test_bitfield() {
          %s = alloca %struct.BitfieldTest
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let issues = detector.detect_issues(ir);

    // Should detect bitfield layout issues in packed structs
    assert!(
        issues
            .iter()
            .any(|issue| matches!(issue, AbiIssue::BitfieldLayoutIssue { .. })),
        "Should detect bitfield layout issues in packed structs"
    );
}

/// Objective: Verify no false positives for non-packed structs
/// Invariants: Non-packed structs should not trigger bitfield issues
#[test]
fn test_no_false_positives_for_non_packed_structs() {
    let ir = r#"
        %struct.Normal = type { i8, i8, i8 }
        define void @test_normal() {
          %s = alloca %struct.Normal
          ret void
        }
    "#;

    let detector = AbiLayoutDetector::new();
    let issues = detector.detect_issues(ir);

    // Should not detect bitfield layout issues for non-packed structs
    assert!(
        !issues
            .iter()
            .any(|issue| matches!(issue, AbiIssue::BitfieldLayoutIssue { .. })),
        "Non-packed structs should not trigger bitfield issues"
    );
}
