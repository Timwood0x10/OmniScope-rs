//! Pattern matching logic for function name detection
//!
//! This module contains the pattern matching logic for detecting
//! whitelisted functions using both mangled and demangled name patterns.
//! It provides fallback matching when exact names don't match.

use super::RustStdlibWhitelist;

impl RustStdlibWhitelist {
    /// Checks if a function name matches any known patterns.
    ///
    /// # Objective
    /// Provide pattern-based matching as a fallback when exact name matching
    /// fails. This handles both Rust mangled names (starting with "_R" or "_ZN")
    /// and demangled names (e.g., "Vec::new"). The pattern matching uses
    /// substring containment to detect known safe function patterns.
    ///
    /// # Invariants
    /// - Mangled name patterns are checked first for "_R" or "_ZN" prefixed names.
    /// - Demangled name patterns are checked as fallback.
    /// - Pattern matching uses substring containment (contains()).
    /// - Returns false if no pattern matches.
    /// - Patterns cover Vec, String, Box, Arc, Rc, HashMap, BTreeMap, HashSet,
    ///   Mutex, RwLock, Condvar, Option, Result, Iterator, and memory utilities.
    ///
    /// # Arguments
    ///
    /// * `name` - The function name to check against patterns
    ///
    /// # Returns
    ///
    /// `true` if the name matches any known safe pattern
    pub fn matches_pattern(&self, name: &str) -> bool {
        // Rust mangled name patterns: these are suffixes that appear in
        // Rust's name mangling scheme (e.g., "_ZN3vec3Vec3new" for Vec::new)
        if name.starts_with("_R") || name.starts_with("_ZN") {
            // Common Rust stdlib patterns for mangled names
            // Each pattern corresponds to a known safe standard library function
            let safe_patterns = [
                // Vec operations
                "3Vec3new",
                "3Vec7with_capacity",
                "3Vec4push",
                "3Vec3pop",
                "3Vec6insert",
                "3Vec6remove",
                "3Vec5clear",
                "3Vec7reserve",
                "3Vec13shrink_to_fit",
                "3Vec6as_ptr",
                "3Vec9as_mut_ptr",
                // String operations
                "6String3new",
                "6String7with_capacity",
                "6String4push",
                "6String9push_str",
                "6String4from",
                // Box operations
                "3Box3new",
                "3Box8into_raw",
                "3Box9from_raw",
                // Arc operations
                "3Arc3new",
                "3Arc5clone",
                "3Arc4drop",
                "3Arc9into_raw",
                // Rc operations
                "2Rc3new",
                "2Rc5clone",
                "2Rc4drop",
                // HashMap operations
                "7HashMap3new",
                "7HashMap7with_capacity",
                "7HashMap6insert",
                "7HashMap6remove",
                "7HashMap3get",
                // BTreeMap operations
                "8BTreeMap3new",
                "8BTreeMap6insert",
                "8BTreeMap6remove",
                // HashSet operations
                "7HashSet3new",
                "7HashSet6insert",
                // Mutex operations
                "5Mutex3new",
                "5Mutex4lock",
                "5Mutex6unlock",
                // RwLock operations
                "6RwLock3new",
                "6RwLock5write",
                "6RwLock4read",
                // Condvar operations
                "7Condvar3new",
                "7Condvar4wait",
                // Option operations
                "6Option4unwrap",
                "6Option9unwrap_or",
                "6Option3map",
                "6Option7and_then",
                // Result operations
                "6Result4unwrap",
                "6Result9unwrap_or",
                "6Result3map",
                "6Result7and_then",
                "6Result9map_err",
                // Iterator operations
                "8Iterator4map",
                "8Iterator6filter",
                "8Iterator7collect",
                "8Iterator4fold",
                "8Iterator8for_each",
                // Memory utilities
                "4swap",
                "7replace",
                "4take",
                "7size_of",
                "8align_of",
                "4drop",
                // Slice operations
                "3get",
                "5index",
                // Thread spawn
                "5spawn",
                "14spawn_blocking",
            ];

            // Check if any safe pattern is contained in the function name
            for pattern in &safe_patterns {
                if name.contains(pattern) {
                    return true;
                }
            }
        }

        // Demangled name patterns: these match human-readable Rust function names
        // (e.g., "Vec::new", "String::from"). This is the fallback matching
        // when IR analysis provides demangled names instead of mangled ones.
        let demangled_patterns = [
            // Vec operations - safe container management
            "Vec::new",
            "Vec::with_capacity",
            "Vec::push",
            "Vec::pop",
            "Vec::insert",
            "Vec::remove",
            "Vec::clear",
            "Vec::reserve",
            "Vec::shrink_to_fit",
            "Vec::as_ptr",
            "Vec::as_mut_ptr",
            // String operations - safe string manipulation
            "String::new",
            "String::with_capacity",
            "String::push",
            "String::push_str",
            "String::from",
            // Box operations
            "Box::new",
            "Box::into_raw",
            "Box::from_raw",
            // Arc operations
            "Arc::new",
            "Arc::clone",
            "Arc::drop",
            // Rc operations
            "Rc::new",
            "Rc::clone",
            "Rc::drop",
            // HashMap operations
            "HashMap::new",
            "HashMap::with_capacity",
            "HashMap::insert",
            "HashMap::remove",
            "HashMap::get",
            // BTreeMap operations
            "BTreeMap::new",
            "BTreeMap::insert",
            "BTreeMap::remove",
            // HashSet operations
            "HashSet::new",
            "HashSet::insert",
            // Mutex operations
            "Mutex::new",
            "Mutex::lock",
            "Mutex::unlock",
            // RwLock operations
            "RwLock::new",
            "RwLock::write",
            "RwLock::read",
            // Option operations
            "Option::unwrap",
            "Option::unwrap_or",
            "Option::map",
            "Option::and_then",
            // Result operations
            "Result::unwrap",
            "Result::unwrap_or",
            "Result::map",
            "Result::and_then",
            "Result::map_err",
            // Iterator operations
            "Iterator::map",
            "Iterator::filter",
            "Iterator::collect",
            "Iterator::fold",
            "Iterator::for_each",
            // Memory utilities
            "std::mem::swap",
            "std::mem::replace",
            "std::mem::take",
            "std::mem::size_of",
            "std::mem::align_of",
            // Slice operations
            "slice::get",
            "slice::index",
            // Serde operations
            "serde::Serialize",
            "serde::Deserialize",
            // Tokio operations
            "tokio::task::spawn",
            "tokio::task::spawn_blocking",
            // Anyhow operations
            "anyhow::Error",
            "anyhow::Result",
        ];

        // Check if any demangled pattern is contained in the function name
        for pattern in &demangled_patterns {
            if name.contains(pattern) {
                return true;
            }
        }

        // No pattern matched
        false
    }
}
