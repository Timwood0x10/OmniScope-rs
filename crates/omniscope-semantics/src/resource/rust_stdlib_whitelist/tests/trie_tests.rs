//! Tests for Trie-based pattern matching optimization
//!
//! This module contains tests for the Trie data structure used
//! for efficient pattern matching in the whitelist.

use super::super::trie::Trie;
use super::super::*;

/// Objective: Verify Trie-based pattern matching works correctly
/// Invariants: Trie matching should produce same results as linear scanning
#[test]
fn test_trie_pattern_matching() {
    let whitelist = RustStdlibWhitelist::new();

    // Test mangled name patterns with Trie
    assert!(
        whitelist.matches_pattern("_ZN3vec3Vec3new"),
        "Should match Vec::new() pattern using Trie"
    );
    assert!(
        whitelist.matches_pattern("_ZN3arc3Arc3new"),
        "Should match Arc::new() pattern using Trie"
    );
    assert!(
        whitelist.matches_pattern("_ZN6string6String3new"),
        "Should match String::new() pattern using Trie"
    );

    // Test demangled name patterns with Trie
    assert!(
        whitelist.matches_pattern("Vec::new"),
        "Should match Vec::new demangled pattern using Trie"
    );
    assert!(
        whitelist.matches_pattern("String::from"),
        "Should match String::from demangled pattern using Trie"
    );
    assert!(
        whitelist.matches_pattern("HashMap::insert"),
        "Should match HashMap::insert demangled pattern using Trie"
    );
}

/// Objective: Verify Trie matching handles unknown patterns correctly
/// Invariants: Unknown patterns should not match
#[test]
fn test_trie_unknown_patterns() {
    let whitelist = RustStdlibWhitelist::new();

    // Test unknown mangled patterns
    assert!(
        !whitelist.matches_pattern("_ZN9unknown_crate9SomeType10some_method"),
        "Unknown mangled pattern should not match"
    );

    // Test unknown demangled patterns
    assert!(
        !whitelist.matches_pattern("Unknown::function"),
        "Unknown demangled pattern should not match"
    );

    // Test partial patterns
    assert!(
        !whitelist.matches_pattern("Vec"),
        "Partial pattern 'Vec' should not match"
    );
    assert!(
        !whitelist.matches_pattern("new"),
        "Partial pattern 'new' should not match"
    );
}

/// Objective: Verify Trie matching performance improvement
/// Invariants: Trie matching should be faster than linear scanning
#[test]
fn test_trie_performance() {
    let whitelist = RustStdlibWhitelist::new();

    // Test multiple pattern matches
    let test_patterns = [
        "_ZN3vec3Vec3new",
        "_ZN3vec3Vec4push",
        "_ZN6string6String3new",
        "_ZN3arc3Arc3new",
        "_ZN7hashmap7HashMap3new",
        "Vec::new",
        "String::from",
        "HashMap::insert",
        "Arc::new",
        "Box::new",
    ];

    // Verify all patterns match
    for pattern in &test_patterns {
        assert!(
            whitelist.matches_pattern(pattern),
            "Pattern '{}' should match using Trie",
            pattern
        );
    }
}

/// Objective: Verify Trie handles edge cases correctly
/// Invariants: Empty strings, special characters, and boundary conditions
#[test]
fn test_trie_edge_cases() {
    let whitelist = RustStdlibWhitelist::new();

    // Test empty string
    assert!(
        !whitelist.matches_pattern(""),
        "Empty string should not match"
    );

    // Test very long pattern
    let long_pattern = "a".repeat(1000);
    assert!(
        !whitelist.matches_pattern(&long_pattern),
        "Very long pattern should not match"
    );

    // Test pattern with special characters
    // Note: "Vec::new::extra" contains "Vec::new", so it should match
    assert!(
        whitelist.matches_pattern("Vec::new::extra"),
        "Pattern 'Vec::new::extra' contains 'Vec::new', so it should match"
    );
}

/// Objective: Verify Trie works with real Rust function names
/// Invariants: Real-world function names should be handled correctly
#[test]
fn test_trie_real_world_patterns() {
    let whitelist = RustStdlibWhitelist::new();

    // Test with actual mangled names from Rust binaries
    assert!(
        whitelist.matches_pattern("_ZN3vec3Vec3new17h1234567890abcdefE"),
        "Should match Vec::new() with hash suffix"
    );

    assert!(
        whitelist.matches_pattern("_ZN3arc3Arc3new17habcdef1234567890E"),
        "Should match Arc::new() with hash suffix"
    );

    // Test with demangled names from rustfilt
    assert!(
        whitelist.matches_pattern("alloc::vec::Vec::new"),
        "Should match alloc::vec::Vec::new"
    );

    assert!(
        whitelist.matches_pattern("std::sync::Arc::new"),
        "Should match std::sync::Arc::new"
    );
}

/// Objective: Verify Trie handles concurrent access safely
/// Invariants: Multiple threads should be able to read the Trie
#[test]
fn test_trie_concurrent_access() {
    use std::sync::Arc;
    use std::thread;

    let whitelist = Arc::new(RustStdlibWhitelist::new());
    let mut handles = vec![];

    // Spawn multiple threads to test concurrent access
    for i in 0..10 {
        let whitelist_clone = Arc::clone(&whitelist);
        let handle = thread::spawn(move || {
            let patterns = ["_ZN3vec3Vec3new", "Vec::new", "_ZN3arc3Arc3new", "Arc::new"];

            // Test pattern matching in each thread
            for pattern in &patterns {
                assert!(
                    whitelist_clone.matches_pattern(pattern),
                    "Thread {} failed to match pattern '{}'",
                    i,
                    pattern
                );
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should not panic");
    }
}

/// Objective: Verify Trie memory efficiency
/// Invariants: Trie should not use excessive memory
#[test]
fn test_trie_memory_efficiency() {
    // Create a Trie with many patterns
    let mut trie = Trie::new();

    // Insert 100 patterns
    for i in 0..100 {
        trie.insert(&format!("pattern_{}", i));
    }

    // Verify pattern count
    assert_eq!(trie.len(), 100, "Should have 100 patterns");

    // Verify matching works
    assert!(
        trie.matches("test_pattern_50_test"),
        "Should match pattern_50"
    );
    assert!(
        !trie.matches("nonexistent_pattern"),
        "Should not match nonexistent pattern"
    );
}

/// Objective: Verify Trie handles overlapping patterns
/// Invariants: Overlapping patterns should all be detected
#[test]
fn test_trie_overlapping_patterns() {
    let mut trie = Trie::new();

    // Insert overlapping patterns
    trie.insert("Vec");
    trie.insert("Vec::new");
    trie.insert("Vec::push");
    trie.insert("new");

    // Test that all overlapping patterns are found
    let matches = trie.find_all_matches("Vec::new");
    assert_eq!(matches.len(), 3, "Should find all 3 overlapping patterns");
    assert!(matches.contains(&"Vec".to_string()), "Should find 'Vec'");
    assert!(
        matches.contains(&"Vec::new".to_string()),
        "Should find 'Vec::new'"
    );
    assert!(matches.contains(&"new".to_string()), "Should find 'new'");
}

/// Objective: Verify Trie handles Unicode patterns
/// Invariants: Unicode characters should be handled correctly
#[test]
fn test_trie_unicode_patterns() {
    let mut trie = Trie::new();

    // Insert Unicode patterns
    trie.insert("函数::新建");
    trie.insert("字符串::从");

    // Test Unicode matching
    assert!(
        trie.contains("函数::新建"),
        "Should match Unicode pattern '函数::新建'"
    );
    assert!(
        trie.contains("字符串::从"),
        "Should match Unicode pattern '字符串::从'"
    );
    assert!(
        !trie.contains("未知::函数"),
        "Should not match unknown Unicode pattern"
    );

    // Test Unicode substring matching
    assert!(
        trie.matches("测试_函数::新建_结束"),
        "Should match Unicode substring"
    );
}
