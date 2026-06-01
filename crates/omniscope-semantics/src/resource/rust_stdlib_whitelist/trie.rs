//! Trie-based pattern matching for efficient whitelist lookup.
//!
//! This module provides a Trie data structure optimized for substring
//! matching in function names. It replaces the linear scanning approach
//! with O(m) pattern matching where m is the pattern length.
//!
//! # Design Principles
//!
//! 1. **Efficient Matching**: O(m) pattern matching using Trie traversal
//! 2. **Memory Optimized**: Shared prefixes reduce memory usage
//! 3. **Substring Support**: Handles both exact and substring matching
//! 4. **Generic Interface**: Works with both mangled and demangled names

use std::collections::HashMap;

/// Represents a node in the Trie data structure.
///
/// Each node contains a map of children nodes keyed by character,
/// and optionally stores a pattern value if this node marks the end
/// of a valid pattern.
#[derive(Debug, Clone)]
pub struct TrieNode {
    /// Children nodes indexed by character
    children: HashMap<char, TrieNode>,
    /// Whether this node represents the end of a pattern
    is_end: bool,
    /// Optional value stored at this node (the pattern itself)
    value: Option<String>,
}

impl TrieNode {
    /// Creates a new empty Trie node.
    ///
    /// # Objective
    /// Initialize a new node with no children and no stored value.
    ///
    /// # Invariants
    /// - Node starts with empty children map
    /// - is_end is false by default
    /// - value is None by default
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            is_end: false,
            value: None,
        }
    }
}

/// Trie data structure for efficient pattern matching.
///
/// The Trie supports both exact matching and substring matching.
/// For substring matching, it uses a sliding window approach
/// to check if any substring of the input matches a pattern.
///
/// # Performance
///
/// - **Insertion**: O(m) where m is pattern length
/// - **Exact Match**: O(m) where m is input length
/// - **Substring Match**: O(n * m) where n is input length, m is average pattern length
/// - **Memory**: O(ALPHABET_SIZE * m * k) where k is number of patterns
///
/// # Examples
///
/// ```rust
/// use omniscope_semantics::resource::rust_stdlib_whitelist::trie::Trie;
///
/// let mut trie = Trie::new();
/// trie.insert("Vec::new");
/// trie.insert("String::push");
///
/// assert!(trie.matches("Vec::new"));
/// assert!(trie.contains("String::push"));
/// ```
pub struct Trie {
    root: TrieNode,
    /// Count of patterns stored
    pattern_count: usize,
}

impl Trie {
    /// Creates a new empty Trie.
    ///
    /// # Objective
    /// Initialize a new Trie with an empty root node.
    ///
    /// # Invariants
    /// - Root node has no children
    /// - Pattern count starts at zero
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
            pattern_count: 0,
        }
    }

    /// Inserts a pattern into the Trie.
    ///
    /// # Objective
    /// Add a new pattern to the Trie for later matching.
    ///
    /// # Invariants
    /// - Pattern is stored character by character
    /// - Last node of pattern is marked as end
    /// - Pattern count is incremented
    /// - Duplicate patterns are allowed (count increases)
    ///
    /// # Arguments
    ///
    /// * `pattern` - The pattern string to insert
    pub fn insert(&mut self, pattern: &str) {
        let mut current = &mut self.root;

        // Traverse or create nodes for each character
        for ch in pattern.chars() {
            current = current.children.entry(ch).or_insert_with(TrieNode::new);
        }

        // Mark the end of pattern and store the value
        current.is_end = true;
        current.value = Some(pattern.to_string());
        self.pattern_count += 1;
    }

    /// Checks if a pattern exists in the Trie (exact match).
    ///
    /// # Objective
    /// Verify if the exact pattern is stored in the Trie.
    ///
    /// # Invariants
    /// - Returns true only if entire input matches a pattern
    /// - Returns false for partial matches
    /// - O(m) time complexity where m is input length
    ///
    /// # Arguments
    ///
    /// * `input` - The exact pattern to search for
    ///
    /// # Returns
    ///
    /// `true` if the exact pattern exists in the Trie
    pub fn contains(&self, input: &str) -> bool {
        let mut current = &self.root;

        // Traverse the Trie following the input characters
        for ch in input.chars() {
            match current.children.get(&ch) {
                Some(node) => current = node,
                None => return false,
            }
        }

        // Check if we reached a complete pattern
        current.is_end
    }

    /// Checks if any pattern is contained as a substring in the input.
    ///
    /// # Objective
    /// Perform substring matching to find if any pattern appears
    /// anywhere in the input string. This is the primary matching
    /// method for function name pattern detection.
    ///
    /// # Invariants
    /// - Checks all possible substrings of the input
    /// - Returns true if any substring matches a pattern
    /// - Uses sliding window approach for efficiency
    /// - O(n * m) time complexity where n is input length
    ///
    /// # Arguments
    ///
    /// * `input` - The string to search for patterns
    ///
    /// # Returns
    ///
    /// `true` if any pattern is found as a substring
    pub fn matches(&self, input: &str) -> bool {
        // Handle empty input
        if input.is_empty() {
            return false;
        }

        // Try matching from each starting position
        let chars: Vec<char> = input.chars().collect();
        for start_pos in 0..chars.len() {
            if self.matches_from_position(&chars, start_pos) {
                return true;
            }
        }

        false
    }

    /// Checks if any pattern matches starting from a specific position.
    ///
    /// # Objective
    /// Helper function for substring matching that checks patterns
    /// starting from a given position in the character array.
    ///
    /// # Invariants
    /// - Only checks characters from start_pos onward
    /// - Returns true if any pattern matches from this position
    /// - Stops early if no children match
    ///
    /// # Arguments
    ///
    /// * `chars` - The character array to search in
    /// * `start_pos` - Starting position for matching
    ///
    /// # Returns
    ///
    /// `true` if a pattern matches starting from start_pos
    fn matches_from_position(&self, chars: &[char], start_pos: usize) -> bool {
        let mut current = &self.root;

        // Traverse the Trie from start_pos using iterator
        for ch in chars.iter().skip(start_pos) {
            match current.children.get(ch) {
                Some(node) => {
                    current = node;
                    // Check if we found a complete pattern
                    if current.is_end {
                        return true;
                    }
                }
                None => return false,
            }
        }

        false
    }

    /// Returns the number of patterns stored in the Trie.
    ///
    /// # Objective
    /// Get the total count of patterns inserted into the Trie.
    ///
    /// # Returns
    ///
    /// The number of patterns stored
    pub fn len(&self) -> usize {
        self.pattern_count
    }

    /// Checks if the Trie is empty.
    ///
    /// # Objective
    /// Quick check if the Trie contains any patterns.
    ///
    /// # Returns
    ///
    /// `true` if no patterns are stored
    pub fn is_empty(&self) -> bool {
        self.pattern_count == 0
    }

    /// Collects all patterns that match as substrings in the input.
    ///
    /// # Objective
    /// Find all patterns that appear as substrings in the input.
    /// Useful for debugging and pattern analysis.
    ///
    /// # Invariants
    /// - Returns all matching patterns, not just the first one
    /// - Preserves insertion order of patterns
    /// - May contain duplicates if same pattern matches multiple times
    ///
    /// # Arguments
    ///
    /// * `input` - The string to search for patterns
    ///
    /// # Returns
    ///
    /// Vector of all matching patterns
    pub fn find_all_matches(&self, input: &str) -> Vec<String> {
        let mut matches = Vec::new();

        if input.is_empty() {
            return matches;
        }

        let chars: Vec<char> = input.chars().collect();
        for start_pos in 0..chars.len() {
            self.collect_matches_from_position(&chars, start_pos, &mut matches);
        }

        matches
    }

    /// Collects all patterns matching from a specific position.
    ///
    /// # Objective
    /// Helper function that collects all matching patterns
    /// starting from a given position.
    ///
    /// # Arguments
    ///
    /// * `chars` - Character array to search in
    /// * `start_pos` - Starting position
    /// * `matches` - Vector to collect matches into
    fn collect_matches_from_position(
        &self,
        chars: &[char],
        start_pos: usize,
        matches: &mut Vec<String>,
    ) {
        let mut current = &self.root;

        // Use iterator to traverse from start_pos
        for ch in chars.iter().skip(start_pos) {
            match current.children.get(ch) {
                Some(node) => {
                    current = node;
                    // Collect all patterns found at this position
                    if current.is_end {
                        if let Some(ref value) = current.value {
                            matches.push(value.clone());
                        }
                    }
                }
                None => return,
            }
        }
    }
}

impl Default for Trie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify basic Trie insertion and exact matching
    /// Invariants: Inserted patterns must be found, non-inserted must not
    #[test]
    fn test_insert_and_contains() {
        let mut trie = Trie::new();
        trie.insert("Vec::new");
        trie.insert("String::push");
        trie.insert("Box::into_raw");

        assert!(
            trie.contains("Vec::new"),
            "Vec::new should be found in Trie"
        );
        assert!(
            trie.contains("String::push"),
            "String::push should be found in Trie"
        );
        assert!(
            trie.contains("Box::into_raw"),
            "Box::into_raw should be found in Trie"
        );
        assert!(
            !trie.contains("Vec::pop"),
            "Vec::pop should not be found in Trie"
        );
        assert!(
            !trie.contains("Vec"),
            "Vec should not be found as exact match"
        );
    }

    /// Objective: Verify substring matching functionality
    /// Invariants: Patterns appearing as substrings must be detected
    #[test]
    fn test_substring_matching() {
        let mut trie = Trie::new();
        trie.insert("Vec::new");
        trie.insert("String::from");
        trie.insert("HashMap::insert");

        // Test substring matches with demangled names
        assert!(
            trie.matches("std::vec::Vec::new"),
            "Should match Vec::new in demangled name"
        );
        assert!(
            trie.matches("String::from_str"),
            "Should match String::from as substring"
        );
        assert!(
            trie.matches("HashMap::insert_or_default"),
            "Should match HashMap::insert as substring"
        );

        // Test non-matches
        assert!(!trie.matches("Vec::pop"), "Should not match Vec::pop");
        assert!(
            !trie.matches("BTreeMap::new"),
            "Should not match BTreeMap::new"
        );
    }

    /// Objective: Verify Trie statistics and empty state
    /// Invariants: Length and emptiness checks must be accurate
    #[test]
    fn test_trie_statistics() {
        let mut trie = Trie::new();
        assert!(trie.is_empty(), "New Trie should be empty");
        assert_eq!(trie.len(), 0, "New Trie should have length 0");

        trie.insert("Vec::new");
        trie.insert("String::push");
        assert_eq!(trie.len(), 2, "Trie should have length 2 after two inserts");
        assert!(!trie.is_empty(), "Trie should not be empty after inserts");

        // Test duplicate insertion
        trie.insert("Vec::new");
        assert_eq!(trie.len(), 3, "Duplicate insert should increase count");
    }

    /// Objective: Verify find_all_matches functionality
    /// Invariants: All matching patterns must be returned
    #[test]
    fn test_find_all_matches() {
        let mut trie = Trie::new();
        trie.insert("Vec");
        trie.insert("Vec::new");
        trie.insert("new");

        let matches = trie.find_all_matches("Vec::new");
        assert_eq!(matches.len(), 3, "Should find all 3 matching patterns");
        assert!(matches.contains(&"Vec".to_string()), "Should find 'Vec'");
        assert!(
            matches.contains(&"Vec::new".to_string()),
            "Should find 'Vec::new'"
        );
        assert!(matches.contains(&"new".to_string()), "Should find 'new'");
    }

    /// Objective: Verify Trie handles empty and edge cases
    /// Invariants: Empty inputs must not cause panics or incorrect results
    #[test]
    fn test_edge_cases() {
        let mut trie = Trie::new();
        trie.insert("test");

        // Empty input tests
        assert!(!trie.matches(""), "Empty input should not match");
        assert!(
            trie.find_all_matches("").is_empty(),
            "Empty input should return no matches"
        );

        // Single character patterns
        trie.insert("a");
        assert!(trie.matches("ba"), "Should match single character 'a'");
        assert!(trie.contains("a"), "Should contain single character 'a'");

        // Special characters
        trie.insert("::");
        assert!(trie.matches("Vec::new"), "Should match '::' in Vec::new");
    }

    /// Objective: Verify Trie performance with many patterns
    /// Invariants: Large pattern sets must not cause performance degradation
    #[test]
    fn test_large_pattern_set() {
        let mut trie = Trie::new();

        // Insert 1000 patterns
        for i in 0..1000 {
            trie.insert(&format!("pattern_{}", i));
        }

        assert_eq!(trie.len(), 1000, "Should have 1000 patterns");

        // Test matching performance
        assert!(
            trie.matches("test_pattern_500_test"),
            "Should match pattern_500"
        );
        assert!(
            !trie.matches("nonexistent_pattern"),
            "Should not match nonexistent pattern"
        );
    }

    /// Objective: Verify Trie default implementation
    /// Invariants: Default Trie must be empty
    #[test]
    fn test_default_implementation() {
        let trie = Trie::default();
        assert!(trie.is_empty(), "Default Trie should be empty");
        assert_eq!(trie.len(), 0, "Default Trie should have length 0");
    }

    /// Objective: Verify Trie with real Rust function patterns
    /// Invariants: Must handle actual Rust mangled and demangled names
    #[test]
    fn test_real_rust_patterns() {
        let mut trie = Trie::new();

        // Insert real Rust patterns
        trie.insert("Vec::new");
        trie.insert("Vec::push");
        trie.insert("String::from");
        trie.insert("Box::new");
        trie.insert("Arc::new");

        // Test with demangled names
        assert!(
            trie.matches("alloc::vec::Vec::new"),
            "Should match Vec::new in demangled name"
        );
        assert!(
            trie.matches("std::string::String::from"),
            "Should match String::from in demangled name"
        );

        // Test with mixed patterns
        assert!(
            trie.matches("test_Vec::new_function"),
            "Should match Vec::new in mixed pattern"
        );
    }
}
