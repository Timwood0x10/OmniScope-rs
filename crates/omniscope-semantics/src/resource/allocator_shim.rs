//! Allocator shim detector for filtering false positives from custom allocators.
//!
//! This module identifies common allocator shims (mimalloc, jemalloc, tcmalloc)
//! and system/Rust allocators to prevent false positives in resource leak detection.
//!
//! # Detection Strategy
//!
//! 1. **Prefix matching** for known allocator libraries (mi_, je_, tc_)
//! 2. **Exact matching** for system allocators (malloc, free, etc.)
//! 3. **Exact matching** for Rust allocators (__rust_alloc, etc.)
//!
//! # Usage
//!
//! ```rust
//! use omniscope_semantics::resource::allocator_shim::AllocatorShimDetector;
//!
//! let detector = AllocatorShimDetector::new();
//! assert!(detector.is_allocator_shim("mi_malloc"));
//! assert!(!detector.is_allocator_shim("my_custom_function"));
//! ```

use std::collections::HashSet;

/// Detector for identifying allocator shims and system allocators.
///
/// Contains precompiled sets of known allocator prefixes and function names
/// for efficient O(1) lookups during analysis.
pub struct AllocatorShimDetector {
    /// Known allocator prefixes (e.g., "mi_", "je_", "tc_").
    known_prefixes: HashSet<String>,
    /// Known allocator function names (exact matches).
    known_functions: HashSet<String>,
}

impl AllocatorShimDetector {
    /// Creates a new detector with all known allocator patterns.
    ///
    /// Initializes with:
    /// - Common allocator library prefixes
    /// - System allocator functions
    /// - Rust allocator functions
    pub fn new() -> Self {
        let known_prefixes: HashSet<String> = [
            "mi_".to_string(),       // mimalloc
            "je_".to_string(),       // jemalloc
            "tc_".to_string(),       // tcmalloc
            "mi".to_string(),        // mimalloc (alternative prefix)
            "je".to_string(),        // jemalloc (alternative prefix)
            "tc".to_string(),        // tcmalloc (alternative prefix)
            "jemalloc_".to_string(), // jemalloc (full name)
            "tcmalloc_".to_string(), // tcmalloc (full name)
            "mimalloc_".to_string(), // mimalloc (full name)
        ]
        .into_iter()
        .collect();

        let mut known_functions = HashSet::new();

        // System allocators (C standard library)
        known_functions.extend([
            "malloc".to_string(),
            "calloc".to_string(),
            "realloc".to_string(),
            "free".to_string(),
            "aligned_alloc".to_string(),
            "posix_memalign".to_string(),
            "valloc".to_string(),
            "pvalloc".to_string(),
            "memalign".to_string(),
            "aligned_free".to_string(),
            // Windows allocators
            "HeapAlloc".to_string(),
            "HeapFree".to_string(),
            "HeapReAlloc".to_string(),
            "LocalAlloc".to_string(),
            "LocalFree".to_string(),
            "LocalReAlloc".to_string(),
            "GlobalAlloc".to_string(),
            "GlobalFree".to_string(),
            "GlobalReAlloc".to_string(),
            "VirtualAlloc".to_string(),
            "VirtualFree".to_string(),
        ]);

        // Rust allocators (compiler intrinsics)
        known_functions.extend([
            "__rust_alloc".to_string(),
            "__rust_dealloc".to_string(),
            "__rust_realloc".to_string(),
            "__rust_alloc_zeroed".to_string(),
            // Rust global allocator API
            "alloc::alloc::alloc".to_string(),
            "alloc::alloc::dealloc".to_string(),
            "alloc::alloc::realloc".to_string(),
            "alloc::alloc::alloc_zeroed".to_string(),
            // Common Rust allocator wrappers
            "std::alloc::alloc".to_string(),
            "std::alloc::dealloc".to_string(),
            "std::alloc::realloc".to_string(),
            "std::alloc::alloc_zeroed".to_string(),
        ]);

        // Common allocator library functions
        known_functions.extend([
            // mimalloc
            "mi_malloc".to_string(),
            "mi_free".to_string(),
            "mi_calloc".to_string(),
            "mi_realloc".to_string(),
            "mi_zalloc".to_string(),
            "mi_malloc_aligned".to_string(),
            "mi_free_aligned".to_string(),
            "mi_realloc_aligned".to_string(),
            // jemalloc
            "je_malloc".to_string(),
            "je_free".to_string(),
            "je_calloc".to_string(),
            "je_realloc".to_string(),
            "je_mallocx".to_string(),
            "je_dallocx".to_string(),
            "je_rallocx".to_string(),
            "je_xallocx".to_string(),
            "je_sallocx".to_string(),
            "je_dallocx".to_string(),
            // tcmalloc
            "tc_malloc".to_string(),
            "tc_free".to_string(),
            "tc_calloc".to_string(),
            "tc_realloc".to_string(),
            "tc_malloc_skip_new_handler".to_string(),
            "tc_malloc_nothrow".to_string(),
            "tc_new".to_string(),
            "tc_delete".to_string(),
            "tc_newarray".to_string(),
            "tc_deletearray".to_string(),
            // dlmalloc
            "dlmalloc".to_string(),
            "dlfree".to_string(),
            "dlcalloc".to_string(),
            "dlrealloc".to_string(),
            "dlmemalign".to_string(),
            // nedmalloc
            "nedmalloc".to_string(),
            "nedfree".to_string(),
            "nedcalloc".to_string(),
            "nedrealloc".to_string(),
            "nedmemalign".to_string(),
            // rpmalloc
            "rpmalloc".to_string(),
            "rpfree".to_string(),
            "rpcalloc".to_string(),
            "rprealloc".to_string(),
            "rpmemalign".to_string(),
            // snmalloc
            "sn_malloc".to_string(),
            "sn_free".to_string(),
            "sn_calloc".to_string(),
            "sn_realloc".to_string(),
        ]);

        Self {
            known_prefixes,
            known_functions,
        }
    }

    /// Checks if a function name is an allocator shim.
    ///
    /// Returns true if the function matches any known allocator pattern
    /// (prefix or exact match).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use omniscope_semantics::resource::allocator_shim::AllocatorShimDetector;
    ///
    /// let detector = AllocatorShimDetector::new();
    /// assert!(detector.is_allocator_shim("mi_malloc"));
    /// assert!(detector.is_allocator_shim("malloc"));
    /// assert!(!detector.is_allocator_shim("my_custom_function"));
    /// ```
    pub fn is_allocator_shim(&self, func_name: &str) -> bool {
        // Check exact matches first (O(1) lookup)
        if self.known_functions.contains(func_name) {
            return true;
        }

        // Check prefix matches using optimized approach
        // Extract short prefixes (2-3 chars) for fast lookup
        let func_len = func_name.len();

        // Check 2-character prefixes
        if func_len >= 2 {
            let short_prefix = &func_name[..2];
            if self.known_prefixes.contains(short_prefix) {
                return true;
            }
        }

        // Check 3-character prefixes (most common: "mi_", "je_", "tc_")
        if func_len >= 3 {
            let medium_prefix = &func_name[..3];
            if self.known_prefixes.contains(medium_prefix) {
                return true;
            }
        }

        // Check longer prefixes for full names (jemalloc_, tcmalloc_, mimalloc_)
        for prefix in &self.known_prefixes {
            let prefix_len = prefix.len();
            if prefix_len > 3 && func_len >= prefix_len && func_name.starts_with(prefix.as_str()) {
                return true;
            }
        }

        false
    }

    /// Checks if a function name is a system allocator.
    ///
    /// Returns true only for standard system allocators (malloc, free, etc.)
    /// and Windows heap functions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use omniscope_semantics::resource::allocator_shim::AllocatorShimDetector;
    ///
    /// let detector = AllocatorShimDetector::new();
    /// assert!(detector.is_system_allocator("malloc"));
    /// assert!(detector.is_system_allocator("HeapAlloc"));
    /// assert!(!detector.is_system_allocator("mi_malloc"));
    /// ```
    pub fn is_system_allocator(&self, func_name: &str) -> bool {
        matches!(
            func_name,
            "malloc"
                | "calloc"
                | "realloc"
                | "free"
                | "aligned_alloc"
                | "posix_memalign"
                | "valloc"
                | "pvalloc"
                | "memalign"
                | "aligned_free"
                | "HeapAlloc"
                | "HeapFree"
                | "HeapReAlloc"
                | "LocalAlloc"
                | "LocalFree"
                | "LocalReAlloc"
                | "GlobalAlloc"
                | "GlobalFree"
                | "GlobalReAlloc"
                | "VirtualAlloc"
                | "VirtualFree"
        )
    }

    /// Checks if a function name is a Rust allocator.
    ///
    /// Returns true for Rust compiler intrinsics and standard library
    /// allocator functions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use omniscope_semantics::resource::allocator_shim::AllocatorShimDetector;
    ///
    /// let detector = AllocatorShimDetector::new();
    /// assert!(detector.is_rust_allocator("__rust_alloc"));
    /// assert!(detector.is_rust_allocator("std::alloc::alloc"));
    /// assert!(!detector.is_rust_allocator("malloc"));
    /// ```
    pub fn is_rust_allocator(&self, func_name: &str) -> bool {
        matches!(
            func_name,
            "__rust_alloc"
                | "__rust_dealloc"
                | "__rust_realloc"
                | "__rust_alloc_zeroed"
                | "alloc::alloc::alloc"
                | "alloc::alloc::dealloc"
                | "alloc::alloc::realloc"
                | "alloc::alloc::alloc_zeroed"
                | "std::alloc::alloc"
                | "std::alloc::dealloc"
                | "std::alloc::realloc"
                | "std::alloc::alloc_zeroed"
        )
    }

    /// Checks if a function name is a custom allocator shim.
    ///
    /// Returns true for known third-party allocator libraries
    /// (mimalloc, jemalloc, tcmalloc, etc.).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use omniscope_semantics::resource::allocator_shim::AllocatorShimDetector;
    ///
    /// let detector = AllocatorShimDetector::new();
    /// assert!(detector.is_custom_allocator_shim("mi_malloc"));
    /// assert!(detector.is_custom_allocator_shim("je_free"));
    /// assert!(!detector.is_custom_allocator_shim("malloc"));
    /// ```
    pub fn is_custom_allocator_shim(&self, func_name: &str) -> bool {
        // Check if it's a custom allocator (not system or Rust)
        self.is_allocator_shim(func_name)
            && !self.is_system_allocator(func_name)
            && !self.is_rust_allocator(func_name)
    }

    /// Gets the allocator type for a function name.
    ///
    /// Returns a string describing the allocator type, or None if not an allocator.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use omniscope_semantics::resource::allocator_shim::AllocatorShimDetector;
    ///
    /// let detector = AllocatorShimDetector::new();
    /// assert_eq!(detector.get_allocator_type("malloc"), Some("system"));
    /// assert_eq!(detector.get_allocator_type("__rust_alloc"), Some("rust"));
    /// assert_eq!(detector.get_allocator_type("mi_malloc"), Some("custom"));
    /// assert_eq!(detector.get_allocator_type("my_func"), None);
    /// ```
    pub fn get_allocator_type(&self, func_name: &str) -> Option<&'static str> {
        if self.is_system_allocator(func_name) {
            Some("system")
        } else if self.is_rust_allocator(func_name) {
            Some("rust")
        } else if self.is_custom_allocator_shim(func_name) {
            Some("custom")
        } else {
            None
        }
    }
}

impl Default for AllocatorShimDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Objective: Verify system allocator detection works correctly.
    /// Invariants: All standard C allocators and Windows allocators are recognized.
    #[test]
    fn test_system_allocator_detection() {
        let detector = AllocatorShimDetector::new();

        // Standard C allocators
        assert!(
            detector.is_system_allocator("malloc"),
            "malloc should be recognized as system allocator"
        );
        assert!(
            detector.is_system_allocator("calloc"),
            "calloc should be recognized as system allocator"
        );
        assert!(
            detector.is_system_allocator("realloc"),
            "realloc should be recognized as system allocator"
        );
        assert!(
            detector.is_system_allocator("free"),
            "free should be recognized as system allocator"
        );
        assert!(
            detector.is_system_allocator("aligned_alloc"),
            "aligned_alloc should be recognized as system allocator"
        );

        // Windows allocators
        assert!(
            detector.is_system_allocator("HeapAlloc"),
            "HeapAlloc should be recognized as system allocator"
        );
        assert!(
            detector.is_system_allocator("HeapFree"),
            "HeapFree should be recognized as system allocator"
        );
        assert!(
            detector.is_system_allocator("VirtualAlloc"),
            "VirtualAlloc should be recognized as system allocator"
        );

        // Negative cases
        assert!(
            !detector.is_system_allocator("mi_malloc"),
            "mi_malloc should not be recognized as system allocator"
        );
        assert!(
            !detector.is_system_allocator("__rust_alloc"),
            "__rust_alloc should not be recognized as system allocator"
        );
    }

    /// Objective: Verify Rust allocator detection works correctly.
    /// Invariants: All Rust compiler intrinsics and std allocators are recognized.
    #[test]
    fn test_rust_allocator_detection() {
        let detector = AllocatorShimDetector::new();

        // Compiler intrinsics
        assert!(
            detector.is_rust_allocator("__rust_alloc"),
            "__rust_alloc should be recognized as Rust allocator"
        );
        assert!(
            detector.is_rust_allocator("__rust_dealloc"),
            "__rust_dealloc should be recognized as Rust allocator"
        );
        assert!(
            detector.is_rust_allocator("__rust_realloc"),
            "__rust_realloc should be recognized as Rust allocator"
        );
        assert!(
            detector.is_rust_allocator("__rust_alloc_zeroed"),
            "__rust_alloc_zeroed should be recognized as Rust allocator"
        );

        // Standard library allocators
        assert!(
            detector.is_rust_allocator("std::alloc::alloc"),
            "std::alloc::alloc should be recognized as Rust allocator"
        );
        assert!(
            detector.is_rust_allocator("alloc::alloc::dealloc"),
            "alloc::alloc::dealloc should be recognized as Rust allocator"
        );

        // Negative cases
        assert!(
            !detector.is_rust_allocator("malloc"),
            "malloc should not be recognized as Rust allocator"
        );
        assert!(
            !detector.is_rust_allocator("mi_malloc"),
            "mi_malloc should not be recognized as Rust allocator"
        );
    }

    /// Objective: Verify custom allocator shim detection works correctly.
    /// Invariants: All known third-party allocators are recognized.
    #[test]
    fn test_custom_allocator_shim_detection() {
        let detector = AllocatorShimDetector::new();

        // mimalloc
        assert!(
            detector.is_custom_allocator_shim("mi_malloc"),
            "mi_malloc should be recognized as custom allocator shim"
        );
        assert!(
            detector.is_custom_allocator_shim("mi_free"),
            "mi_free should be recognized as custom allocator shim"
        );
        assert!(
            detector.is_custom_allocator_shim("mi_calloc"),
            "mi_calloc should be recognized as custom allocator shim"
        );

        // jemalloc
        assert!(
            detector.is_custom_allocator_shim("je_malloc"),
            "je_malloc should be recognized as custom allocator shim"
        );
        assert!(
            detector.is_custom_allocator_shim("je_free"),
            "je_free should be recognized as custom allocator shim"
        );

        // tcmalloc
        assert!(
            detector.is_custom_allocator_shim("tc_malloc"),
            "tc_malloc should be recognized as custom allocator shim"
        );
        assert!(
            detector.is_custom_allocator_shim("tc_free"),
            "tc_free should be recognized as custom allocator shim"
        );

        // Negative cases
        assert!(
            !detector.is_custom_allocator_shim("malloc"),
            "malloc should not be recognized as custom allocator shim"
        );
        assert!(
            !detector.is_custom_allocator_shim("__rust_alloc"),
            "__rust_alloc should not be recognized as custom allocator shim"
        );
    }

    /// Objective: Verify general allocator shim detection works correctly.
    /// Invariants: All allocator types are recognized by is_allocator_shim.
    #[test]
    fn test_general_allocator_shim_detection() {
        let detector = AllocatorShimDetector::new();

        // System allocators
        assert!(
            detector.is_allocator_shim("malloc"),
            "malloc should be recognized as allocator shim"
        );
        assert!(
            detector.is_allocator_shim("free"),
            "free should be recognized as allocator shim"
        );

        // Rust allocators
        assert!(
            detector.is_allocator_shim("__rust_alloc"),
            "__rust_alloc should be recognized as allocator shim"
        );

        // Custom allocators
        assert!(
            detector.is_allocator_shim("mi_malloc"),
            "mi_malloc should be recognized as allocator shim"
        );
        assert!(
            detector.is_allocator_shim("je_malloc"),
            "je_malloc should be recognized as allocator shim"
        );
        assert!(
            detector.is_allocator_shim("tc_malloc"),
            "tc_malloc should be recognized as allocator shim"
        );

        // Negative cases
        assert!(
            !detector.is_allocator_shim("my_custom_function"),
            "my_custom_function should not be recognized as allocator shim"
        );
        assert!(
            !detector.is_allocator_shim("process_data"),
            "process_data should not be recognized as allocator shim"
        );
    }

    /// Objective: Verify allocator type classification works correctly.
    /// Invariants: get_allocator_type returns correct categories.
    #[test]
    fn test_allocator_type_classification() {
        let detector = AllocatorShimDetector::new();

        // System allocators
        assert_eq!(
            detector.get_allocator_type("malloc"),
            Some("system"),
            "malloc should be classified as system allocator"
        );
        assert_eq!(
            detector.get_allocator_type("HeapAlloc"),
            Some("system"),
            "HeapAlloc should be classified as system allocator"
        );

        // Rust allocators
        assert_eq!(
            detector.get_allocator_type("__rust_alloc"),
            Some("rust"),
            "__rust_alloc should be classified as Rust allocator"
        );
        assert_eq!(
            detector.get_allocator_type("std::alloc::alloc"),
            Some("rust"),
            "std::alloc::alloc should be classified as Rust allocator"
        );

        // Custom allocators
        assert_eq!(
            detector.get_allocator_type("mi_malloc"),
            Some("custom"),
            "mi_malloc should be classified as custom allocator"
        );
        assert_eq!(
            detector.get_allocator_type("je_free"),
            Some("custom"),
            "je_free should be classified as custom allocator"
        );
        assert_eq!(
            detector.get_allocator_type("tc_malloc"),
            Some("custom"),
            "tc_malloc should be classified as custom allocator"
        );

        // Non-allocators
        assert_eq!(
            detector.get_allocator_type("my_function"),
            None,
            "my_function should not be classified as allocator"
        );
    }

    /// Objective: Verify prefix matching works for allocator shims.
    /// Invariants: Functions with known prefixes are recognized.
    #[test]
    fn test_prefix_matching() {
        let detector = AllocatorShimDetector::new();

        // Test prefix-based detection
        assert!(
            detector.is_allocator_shim("mi_custom_function"),
            "mi_custom_function should be recognized via mi_ prefix"
        );
        assert!(
            detector.is_allocator_shim("je_custom_function"),
            "je_custom_function should be recognized via je_ prefix"
        );
        assert!(
            detector.is_allocator_shim("tc_custom_function"),
            "tc_custom_function should be recognized via tc_ prefix"
        );
        assert!(
            detector.is_allocator_shim("jemalloc_custom"),
            "jemalloc_custom should be recognized via jemalloc_ prefix"
        );
        assert!(
            detector.is_allocator_shim("tcmalloc_custom"),
            "tcmalloc_custom should be recognized via tcmalloc_ prefix"
        );
        assert!(
            detector.is_allocator_shim("mimalloc_custom"),
            "mimalloc_custom should be recognized via mimalloc_ prefix"
        );

        // Negative cases
        assert!(
            !detector.is_allocator_shim("my_custom_function"),
            "my_custom_function should not be recognized"
        );
    }

    /// Objective: Verify default implementation works correctly.
    /// Invariants: Default::default() creates a fully functional detector.
    #[test]
    fn test_default_implementation() {
        let detector = AllocatorShimDetector::default();

        // Should work the same as new()
        assert!(
            detector.is_allocator_shim("malloc"),
            "Default detector should recognize malloc"
        );
        assert!(
            detector.is_allocator_shim("mi_malloc"),
            "Default detector should recognize mi_malloc"
        );
        assert!(
            detector.is_allocator_shim("__rust_alloc"),
            "Default detector should recognize __rust_alloc"
        );
    }

    /// Objective: Verify edge cases and empty strings.
    /// Invariants: Empty strings and special characters are handled gracefully.
    #[test]
    fn test_edge_cases() {
        let detector = AllocatorShimDetector::new();

        // Empty string
        assert!(
            !detector.is_allocator_shim(""),
            "Empty string should not be recognized as allocator"
        );
        assert!(
            !detector.is_system_allocator(""),
            "Empty string should not be recognized as system allocator"
        );
        assert!(
            !detector.is_rust_allocator(""),
            "Empty string should not be recognized as Rust allocator"
        );
        assert!(
            !detector.is_custom_allocator_shim(""),
            "Empty string should not be recognized as custom allocator"
        );
        assert_eq!(
            detector.get_allocator_type(""),
            None,
            "Empty string should have no allocator type"
        );

        // Whitespace
        assert!(
            !detector.is_allocator_shim(" "),
            "Whitespace should not be recognized as allocator"
        );

        // Partial matches
        assert!(
            !detector.is_allocator_shim("mallo"),
            "Partial match 'mallo' should not be recognized"
        );
        assert!(
            !detector.is_allocator_shim("alloc"),
            "Partial match 'alloc' should not be recognized"
        );
    }

    // === Property-based tests using proptest ===

    proptest! {
        /// Objective: Verify is_allocator_shim never panics for arbitrary string inputs
        ///
        /// Invariants:
        /// - For arbitrary string inputs, is_allocator_shim should return a boolean value
        /// - Should not throw exceptions or panic
        #[test]
        fn prop_is_allocator_shim_never_panics(
            func_name in "[a-zA-Z0-9_:/~]{0,100}"
        ) {
            // Property: is_allocator_shim should never panic for any string
            let detector = AllocatorShimDetector::new();
            let _result = detector.is_allocator_shim(&func_name);
            // The property is that this doesn't panic
        }

        /// Objective: Verify is_system_allocator never panics for arbitrary string inputs
        ///
        /// Invariants:
        /// - For arbitrary string inputs, is_system_allocator should return a boolean value
        /// - Should not throw exceptions or panic
        #[test]
        fn prop_is_system_allocator_never_panics(
            func_name in "[a-zA-Z0-9_:/~]{0,100}"
        ) {
            // Property: is_system_allocator should never panic for any string
            let detector = AllocatorShimDetector::new();
            let _result = detector.is_system_allocator(&func_name);
            // The property is that this doesn't panic
        }

        /// Objective: Verify is_rust_allocator never panics for arbitrary string inputs
        ///
        /// Invariants:
        /// - For arbitrary string inputs, is_rust_allocator should return a boolean value
        /// - Should not throw exceptions or panic
        #[test]
        fn prop_is_rust_allocator_never_panics(
            func_name in "[a-zA-Z0-9_:/~]{0,100}"
        ) {
            // Property: is_rust_allocator should never panic for any string
            let detector = AllocatorShimDetector::new();
            let _result = detector.is_rust_allocator(&func_name);
            // The property is that this doesn't panic
        }

        /// Objective: Verify get_allocator_type never panics for arbitrary string inputs
        ///
        /// Invariants:
        /// - For arbitrary string inputs, get_allocator_type should return Option<AllocatorType>
        /// - Should not throw exceptions or panic
        #[test]
        fn prop_get_allocator_type_never_panics(
            func_name in "[a-zA-Z0-9_:/~]{0,100}"
        ) {
            // Property: get_allocator_type should never panic for any string
            let detector = AllocatorShimDetector::new();
            let _result = detector.get_allocator_type(&func_name);
            // The property is that this doesn't panic
        }

        /// Objective: Verify when get_allocator_type returns Some, is_allocator_shim must be true
        ///
        /// Invariants:
        /// - If get_allocator_type returns Some(type), then is_allocator_shim must return true
        /// - Ensure consistency between type detection and shim detection
        #[test]
        fn prop_allocator_type_consistency(
            func_name in "[a-zA-Z0-9_:/~]{0,100}"
        ) {
            // Property: if get_allocator_type returns Some, then is_allocator_shim must be true
            let detector = AllocatorShimDetector::new();
            if let Some(allocator_type) = detector.get_allocator_type(&func_name) {
                prop_assert!(
                    detector.is_allocator_shim(&func_name),
                    "Function '{}' has allocator type '{}' but is not recognized as allocator shim",
                    func_name,
                    allocator_type
                );
            }
        }

        /// Objective: Verify that a function can only belong to one allocator category
        ///
        /// Invariants:
        /// - A function cannot be simultaneously a system allocator, Rust allocator, and custom allocator
        /// - Allocator categories must be mutually exclusive
        #[test]
        fn prop_allocator_categories_are_exclusive(
            func_name in "[a-zA-Z0-9_:/~]{0,100}"
        ) {
            // Property: a function can only be in one allocator category
            let detector = AllocatorShimDetector::new();
            let is_system = detector.is_system_allocator(&func_name);
            let is_rust = detector.is_rust_allocator(&func_name);
            let is_custom = detector.is_custom_allocator_shim(&func_name);

            let category_count = [is_system, is_rust, is_custom]
                .iter()
                .filter(|&&x| x)
                .count();

            prop_assert!(
                category_count <= 1,
                "Function '{}' is in multiple allocator categories: system={}, rust={}, custom={}",
                func_name,
                is_system,
                is_rust,
                is_custom
            );
        }

        /// Objective: Verify functions with known allocator prefixes are correctly identified as custom allocators
        ///
        /// Invariants:
        /// - Functions starting with mi_, je_, tc_, jemalloc_, tcmalloc_, mimalloc_ should be recognized as allocators
        /// - These functions should be classified as custom allocators, not system or Rust allocators
        #[test]
        fn prop_prefix_based_functions_are_custom(
            prefix in "(mi|je|tc|jemalloc_|tcmalloc_|mimalloc_)",
            suffix in "[a-zA-Z0-9_]{1,20}"
        ) {
            // Property: functions with known allocator prefixes should be custom allocators
            let func_name = format!("{}{}", prefix, suffix);
            let detector = AllocatorShimDetector::new();

            // These should be recognized as allocator shims
            prop_assert!(
                detector.is_allocator_shim(&func_name),
                "Function '{}' with known prefix should be recognized as allocator shim",
                func_name
            );

            // These should be custom allocators (not system or Rust)
            prop_assert!(
                detector.is_custom_allocator_shim(&func_name),
                "Function '{}' with known prefix should be recognized as custom allocator",
                func_name
            );
        }

        /// Objective: Verify system allocators are not misidentified as custom allocators
        ///
        /// Invariants:
        /// - System allocators (malloc, calloc, free, etc.) must be recognized as system allocators
        /// - System allocators cannot be recognized as custom allocators
        #[test]
        fn prop_system_allocators_are_not_custom(
            func_name in "(malloc|calloc|realloc|free|aligned_alloc|posix_memalign|valloc|pvalloc|memalign|aligned_free|HeapAlloc|HeapFree|HeapReAlloc|LocalAlloc|LocalFree|LocalReAlloc|GlobalAlloc|GlobalFree|GlobalReAlloc|VirtualAlloc|VirtualFree)"
        ) {
            // Property: system allocators should not be recognized as custom allocators
            let detector = AllocatorShimDetector::new();

            prop_assert!(
                detector.is_system_allocator(&func_name),
                "Function '{}' should be recognized as system allocator",
                func_name
            );

            prop_assert!(
                !detector.is_custom_allocator_shim(&func_name),
                "Function '{}' should not be recognized as custom allocator",
                func_name
            );
        }

        /// Objective: Verify Rust allocators are not misidentified as custom allocators
        ///
        /// Invariants:
        /// - Rust allocators (__rust_alloc, etc.) must be recognized as Rust allocators
        /// - Rust allocators cannot be recognized as custom allocators
        #[test]
        fn prop_rust_allocators_are_not_custom(
            func_name in "(__rust_alloc|__rust_dealloc|__rust_realloc|__rust_alloc_zeroed|alloc::alloc::alloc|alloc::alloc::dealloc|alloc::alloc::realloc|alloc::alloc::alloc_zeroed|std::alloc::alloc|std::alloc::dealloc|std::alloc::realloc|std::alloc::alloc_zeroed)"
        ) {
            // Property: Rust allocators should not be recognized as custom allocators
            let detector = AllocatorShimDetector::new();

            prop_assert!(
                detector.is_rust_allocator(&func_name),
                "Function '{}' should be recognized as Rust allocator",
                func_name
            );

            prop_assert!(
                !detector.is_custom_allocator_shim(&func_name),
                "Function '{}' should not be recognized as custom allocator",
                func_name
            );
        }

        /// Objective: Verify random function names are not misidentified as allocators
        ///
        /// Invariants:
        /// - Random function names not matching known patterns should not be recognized as allocators
        /// - Known functions and prefixes should be excluded from the check
        #[test]
        fn prop_random_non_allocator_functions(
            func_name in "[a-zA-Z_][a-zA-Z0-9_]{0,20}"
        ) {
            // Property: random function names (not matching known patterns) should not be allocators
            let detector = AllocatorShimDetector::new();

            // Skip known prefixes and functions
            let known_prefixes = ["mi_", "je_", "tc_", "mi", "je", "tc", "jemalloc_", "tcmalloc_", "mimalloc_"];
            let known_functions = [
                "malloc", "calloc", "realloc", "free", "aligned_alloc", "posix_memalign", "valloc", "pvalloc", "memalign", "aligned_free",
                "HeapAlloc", "HeapFree", "HeapReAlloc", "LocalAlloc", "LocalFree", "LocalReAlloc", "GlobalAlloc", "GlobalFree", "GlobalReAlloc", "VirtualAlloc", "VirtualFree",
                "__rust_alloc", "__rust_dealloc", "__rust_realloc", "__rust_alloc_zeroed",
                "alloc::alloc::alloc", "alloc::alloc::dealloc", "alloc::alloc::realloc", "alloc::alloc::alloc_zeroed",
                "std::alloc::alloc", "std::alloc::dealloc", "std::alloc::realloc", "std::alloc::alloc_zeroed",
                "mi_malloc", "mi_free", "mi_calloc", "mi_realloc", "mi_zalloc", "mi_malloc_aligned", "mi_free_aligned", "mi_realloc_aligned",
                "je_malloc", "je_free", "je_calloc", "je_realloc", "je_mallocx", "je_dallocx", "je_rallocx", "je_xallocx", "je_sallocx",
                "tc_malloc", "tc_free", "tc_calloc", "tc_realloc", "tc_malloc_skip_new_handler", "tc_malloc_nothrow", "tc_new", "tc_delete", "tc_newarray", "tc_deletearray",
                "dlmalloc", "dlfree", "dlcalloc", "dlrealloc", "dlmemalign",
                "nedmalloc", "nedfree", "nedcalloc", "nedrealloc", "nedmemalign",
                "rpmalloc", "rpfree", "rpcalloc", "rprealloc", "rpmemalign",
                "sn_malloc", "sn_free", "sn_calloc", "sn_realloc",
            ];

            // Check if this is a known function or has a known prefix
            let is_known = known_functions.contains(&func_name.as_str()) ||
                known_prefixes.iter().any(|prefix| func_name.starts_with(prefix));

            if !is_known {
                // Random function names should not be allocators
                prop_assert!(
                    !detector.is_allocator_shim(&func_name),
                    "Random function '{}' should not be recognized as allocator shim",
                    func_name
                );
            }
        }
    }
}
