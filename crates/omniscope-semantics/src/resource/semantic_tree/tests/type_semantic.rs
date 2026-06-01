//! Tests for TypeSemantic classification.

use super::super::*;

/// Objective: Verify that Rust mangled names for interior mutability types are correctly detected.
///
/// Invariants:
/// - Mangled name for std::sync::mutex::Mutex should be detected as InteriorMutability
#[test]
fn test_type_semantic_interior_mutability() {
    // Real mangled name from bun_core: std::sync::mutex::Mutex
    let name = "_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std3sys3pal4unix4sync5mutexNtB2_5Mutex4lock";
    assert_eq!(
        TypeSemantic::from_mangled_name(name),
        TypeSemantic::InteriorMutability,
        "Mutex mangled name must be classified as InteriorMutability"
    );
}

/// Objective: Verify that Rust mangled names for Once types are correctly detected.
///
/// Invariants:
/// - Mangled name for OnceBox should be detected as Once
#[test]
fn test_type_semantic_once() {
    let name = "_RINvMNtNtNtCsg1bLsEOY8ZL_3std3sys4sync8once_boxINtB3_7OnceBox";
    assert_eq!(
        TypeSemantic::from_mangled_name(name),
        TypeSemantic::Once,
        "OnceBox mangled name must be classified as Once"
    );
}

/// Objective: Verify that Rust mangled names for drop_in_place are correctly detected.
///
/// Invariants:
/// - Mangled name for drop_in_place should be detected as Drop
#[test]
fn test_type_semantic_drop() {
    let name = "_RINvNtCsgXhsEb1m4tm_4core3ptr13drop_in_place";
    assert_eq!(
        TypeSemantic::from_mangled_name(name),
        TypeSemantic::Drop,
        "drop_in_place mangled name must be classified as Drop"
    );
}

/// Objective: Verify that non-Rust mangled names are correctly detected as Unknown.
///
/// Invariants:
/// - Non-Rust mangled names like "Bun__atexit" should be detected as Unknown
#[test]
fn test_type_semantic_non_rust() {
    assert_eq!(
        TypeSemantic::from_mangled_name("Bun__atexit"),
        TypeSemantic::Unknown,
        "Non-Rust mangled name must be classified as Unknown"
    );
}
