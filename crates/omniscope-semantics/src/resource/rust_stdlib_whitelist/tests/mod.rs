//! Test module for rust_stdlib_whitelist
//!
//! This module contains comprehensive tests for the Rust standard library
//! function whitelist, organized by test category.

mod stdlib_tests;
mod third_party_tests;
mod trie_tests;

use super::*;

/// Objective: Verify whitelist creation succeeds and contains expected functions
/// Invariants: Whitelist should not be empty and contain core stdlib functions
#[test]
fn test_whitelist_creation() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        !whitelist.is_empty(),
        "Whitelist should contain at least one function"
    );
    assert!(
        whitelist.len() > 50,
        "Whitelist should contain more than 50 functions, got {}",
        whitelist.len()
    );
}

/// Objective: Verify category retrieval works correctly
/// Invariants: Whitelisted functions should return correct categories
#[test]
fn test_category_retrieval() {
    let whitelist = RustStdlibWhitelist::new();

    assert_eq!(
        whitelist.get_category("_ZN3vec3Vec3new"),
        Some(WhitelistCategory::Container),
        "Vec::new() should be in Container category"
    );

    assert_eq!(
        whitelist.get_category("_ZN3arc3Arc3new"),
        Some(WhitelistCategory::SmartPointer),
        "Arc::new() should be in SmartPointer category"
    );

    assert_eq!(
        whitelist.get_category("_ZN5tokio4task5spawn"),
        Some(WhitelistCategory::AsyncRuntime),
        "tokio::task::spawn() should be in AsyncRuntime category"
    );

    // Unknown function should return None
    assert_eq!(
        whitelist.get_category("unknown_function"),
        None,
        "Unknown function should return None category"
    );
}

/// Objective: Verify ownership flag is correctly set
/// Invariants: into_raw should involve ownership, new should not
#[test]
fn test_ownership_flags() {
    let whitelist = RustStdlibWhitelist::new();

    let box_new = whitelist.get_details("_ZN3box3Box3new");
    assert!(box_new.is_some(), "Box::new() should be in whitelist");
    assert!(
        !box_new.unwrap().involves_ownership,
        "Box::new() should not involve ownership transfer"
    );

    let box_into_raw = whitelist.get_details("_ZN3box3Box8into_raw");
    assert!(
        box_into_raw.is_some(),
        "Box::into_raw() should be in whitelist"
    );
    assert!(
        box_into_raw.unwrap().involves_ownership,
        "Box::into_raw() should involve ownership transfer"
    );
}

/// Objective: Verify pattern matching works for common Rust patterns
/// Invariants: Functions matching common patterns should be whitelisted
#[test]
fn test_pattern_matching() {
    let whitelist = RustStdlibWhitelist::new();

    // Test pattern matching for Rust mangled names
    assert!(
        whitelist.is_whitelisted("_RNvNtC...3Vec3new"),
        "Should match Vec::new() pattern in Rust mangled name"
    );

    assert!(
        whitelist.is_whitelisted("_RNvNtC...3Arc3new"),
        "Should match Arc::new() pattern in Rust mangled name"
    );
}

/// Objective: Verify unknown functions are not whitelisted
/// Invariants: Random function names should not be whitelisted
#[test]
fn test_unknown_functions_not_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        !whitelist.is_whitelisted("unknown_function_xyz"),
        "Unknown function should not be whitelisted"
    );

    assert!(
        !whitelist.is_whitelisted("_ZN9unknown_crate9SomeType10some_method"),
        "Unknown mangled name should not be whitelisted"
    );
}

/// Objective: Verify default implementation works
/// Invariants: Default whitelist should be identical to new()
#[test]
fn test_default_implementation() {
    let whitelist1 = RustStdlibWhitelist::new();
    let whitelist2 = RustStdlibWhitelist::default();

    assert_eq!(
        whitelist1.len(),
        whitelist2.len(),
        "Default whitelist should have same length as new()"
    );
}

/// Objective: Verify function details are accessible
/// Invariants: Details should contain all required information
#[test]
fn test_function_details() {
    let whitelist = RustStdlibWhitelist::new();

    let details = whitelist.get_details("_ZN3vec3Vec3new");
    assert!(details.is_some(), "Vec::new() should have details");

    let details = details.unwrap();
    assert_eq!(details.name, "_ZN3vec3Vec3new", "Name should match");
    assert_eq!(
        details.category,
        WhitelistCategory::Container,
        "Category should be Container"
    );
    assert!(
        !details.description.is_empty(),
        "Description should not be empty"
    );
}

/// Objective: Verify all stdlib categories are represented
/// Invariants: Each category should have at least one function
#[test]
fn test_all_categories_represented() {
    let whitelist = RustStdlibWhitelist::new();

    let categories = [
        WhitelistCategory::Container,
        WhitelistCategory::SmartPointer,
        WhitelistCategory::StringOps,
        WhitelistCategory::ThreadSync,
        WhitelistCategory::Iterator,
        WhitelistCategory::ErrorHandling,
        WhitelistCategory::Utility,
        WhitelistCategory::Serialization,
        WhitelistCategory::AsyncRuntime,
    ];

    for category in &categories {
        let has_function = whitelist.details.iter().any(|f| f.category == *category);
        assert!(
            has_function,
            "Category {:?} should have at least one whitelisted function",
            category
        );
    }
}

/// Objective: Verify mixed mangled and demangled name lookups
/// Invariants: Both name formats should work for same function
#[test]
fn test_mixed_name_formats() {
    let whitelist = RustStdlibWhitelist::new();

    // Both mangled and demangled should work
    assert!(
        whitelist.is_whitelisted("_ZN3vec3Vec3new"),
        "Mangled Vec::new() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("Vec::new"),
        "Demangled Vec::new() should be whitelisted"
    );

    // Verify they return same category
    let cat1 = whitelist.get_category("_ZN3vec3Vec3new");
    let cat2 = whitelist.get_category("Vec::new");
    assert_eq!(cat1, cat2, "Both name formats should return same category");
}

/// Objective: Verify memory utility functions are whitelisted
/// Invariants: std::mem functions should be recognized
#[test]
fn test_memory_utilities_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN3mem4swap"),
        "std::mem::swap() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN3mem7replace"),
        "std::mem::replace() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN3mem4drop"),
        "std::mem::drop() should be whitelisted"
    );
}

/// Objective: Verify slice operations are whitelisted
/// Invariants: Common slice operations should be recognized
#[test]
fn test_slice_operations_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("slice::get"),
        "slice::get() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("slice::index"),
        "slice::index() should be whitelisted"
    );
}
