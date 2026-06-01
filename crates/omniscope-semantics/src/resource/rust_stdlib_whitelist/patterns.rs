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
    /// Trie-based substring matching for O(m) performance.
    ///
    /// # Invariants
    /// - Mangled name patterns are checked first for "_R" or "_ZN" prefixed names.
    /// - Demangled name patterns are checked as fallback.
    /// - Uses Trie-based matching instead of linear scanning.
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
        // Rust mangled name patterns: check if name starts with "_R" or "_ZN"
        if name.starts_with("_R") || name.starts_with("_ZN") {
            // Use mangled_trie for efficient pattern matching
            if self.mangled_trie.matches(name) {
                return true;
            }
        }

        // Demangled name patterns: use pattern_trie for efficient matching
        if self.pattern_trie.matches(name) {
            return true;
        }

        // No pattern matched
        false
    }
}
