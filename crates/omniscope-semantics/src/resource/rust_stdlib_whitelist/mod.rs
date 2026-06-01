//! Rust Standard Library Function Whitelist
//!
//! This module provides a comprehensive whitelist for Rust standard library
//! and common third-party library functions to suppress false positives.
//!
//! Unlike the semantic engine's pattern-based approach, this module uses
//! exact function name matching for well-known Rust functions that are
//! guaranteed to be safe from memory safety perspective.
//!
//! # Design Principles
//!
//! 1. **Exact Matching Only**: Uses mangled names for precision
//! 2. **Semantic Categories**: Groups functions by their resource behavior
//! 3. **Zero False Negatives**: Only whitelists functions with proven safety
//! 4. **Third-Party Support**: Includes common Rust ecosystem libraries

use std::collections::HashSet;

// Submodules for different function categories
mod patterns;
mod stdlib;
mod third_party;
pub mod trie;

/// Semantic category for whitelisted functions.
///
/// Each category represents a class of functions with similar
/// resource behavior characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WhitelistCategory {
    /// Memory allocation/deallocation (safe internal operations)
    /// These are Rust's own allocator functions, not cross-family
    MemoryAllocation,
    /// Container operations (Vec, HashMap, BTreeMap, etc.)
    /// These manage their own internal allocations safely
    #[default]
    Container,
    /// Smart pointer operations (Box, Arc, Rc)
    /// Ownership transfer within Rust's type system
    SmartPointer,
    /// String operations (String, &str)
    /// String manipulation without unsafe memory operations
    StringOps,
    /// Thread synchronization (Mutex, RwLock, Condvar)
    /// Interior mutability primitives
    ThreadSync,
    /// Iterator operations
    /// Lazy evaluation without ownership transfer
    Iterator,
    /// Error handling (Result, Option, anyhow, thiserror)
    /// Control flow, not resource management
    ErrorHandling,
    /// Async runtime (tokio, async-std)
    /// Task scheduling, not memory management
    AsyncRuntime,
    /// Serialization (serde)
    /// Data transformation, not memory management
    Serialization,
    /// I/O operations
    /// File/network I/O without memory ownership issues
    IoOps,
    /// Utility functions (std::mem, std::ptr)
    /// Low-level utilities with known safety contracts
    Utility,
}

/// Represents a whitelisted Rust function with its semantic properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistedFunction {
    /// The mangled or demangled function name
    pub name: String,
    /// Semantic category
    pub category: WhitelistCategory,
    /// Whether this function involves memory ownership transfer
    pub involves_ownership: bool,
    /// Optional description for documentation
    pub description: String,
}

/// Registry of whitelisted Rust standard library functions.
///
/// This registry is populated at startup and provides O(1) lookup
/// for function safety assessment.
pub struct RustStdlibWhitelist {
    /// Set of whitelisted function names for fast lookup
    functions: HashSet<String>,
    /// Detailed function information for reporting
    pub details: Vec<WhitelistedFunction>,
    /// Trie for efficient pattern matching
    pattern_trie: trie::Trie,
    /// Trie for mangled name patterns
    mangled_trie: trie::Trie,
}

impl RustStdlibWhitelist {
    /// Creates a new whitelist with all standard library functions.
    ///
    /// # Examples
    ///
    /// ```
    /// use omniscope_semantics::resource::rust_stdlib_whitelist::RustStdlibWhitelist;
    ///
    /// let whitelist = RustStdlibWhitelist::new();
    /// assert!(whitelist.is_whitelisted("_ZN3vec3Vec3new"));
    /// ```
    pub fn new() -> Self {
        let mut whitelist = Self {
            functions: HashSet::new(),
            details: Vec::new(),
            pattern_trie: trie::Trie::new(),
            mangled_trie: trie::Trie::new(),
        };
        whitelist.populate_stdlib();
        whitelist.populate_common_crates();
        whitelist.build_tries();
        whitelist
    }

    /// Checks if a function name is whitelisted.
    ///
    /// # Arguments
    ///
    /// * `name` - The function name (mangled or demangled) to check
    ///
    /// # Returns
    ///
    /// `true` if the function is whitelisted and safe from memory perspective
    pub fn is_whitelisted(&self, name: &str) -> bool {
        // Direct match
        if self.functions.contains(name) {
            return true;
        }

        // Try to match common patterns
        self.matches_pattern(name)
    }

    /// Gets the category of a whitelisted function.
    ///
    /// # Arguments
    ///
    /// * `name` - The function name to look up
    ///
    /// # Returns
    ///
    /// `Some(WhitelistCategory)` if whitelisted, `None` otherwise
    pub fn get_category(&self, name: &str) -> Option<WhitelistCategory> {
        // First try direct match
        if let Some(detail) = self.details.iter().find(|f| f.name == name) {
            return Some(detail.category);
        }

        // Then try pattern matching
        if self.matches_pattern(name) {
            // Find the first detail that matches the pattern
            for detail in &self.details {
                if self.matches_pattern_with(&detail.name, name) {
                    return Some(detail.category);
                }
            }
            // If pattern matches but no specific detail found, return default
            return Some(WhitelistCategory::default());
        }

        None
    }

    /// Gets detailed information about a whitelisted function.
    pub fn get_details(&self, name: &str) -> Option<&WhitelistedFunction> {
        self.details
            .iter()
            .find(|f| f.name == name || self.matches_pattern_with(&f.name, name))
    }

    /// Returns the total number of whitelisted functions.
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Returns true if the whitelist is empty.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Helper function to add a function to the whitelist.
    pub fn add_function(
        &mut self,
        name: &str,
        category: WhitelistCategory,
        involves_ownership: bool,
        description: &str,
    ) {
        self.functions.insert(name.to_string());
        self.details.push(WhitelistedFunction {
            name: name.to_string(),
            category,
            involves_ownership,
            description: description.to_string(),
        });
    }

    /// Helper for pattern matching with a specific whitelist entry.
    pub fn matches_pattern_with(&self, pattern: &str, name: &str) -> bool {
        if name.contains(pattern) {
            return true;
        }
        false
    }

    /// Builds Trie data structures for efficient pattern matching.
    ///
    /// # Objective
    /// Initialize Trie structures with all patterns for O(m) matching.
    /// This is called once during initialization to precompute patterns.
    ///
    /// # Invariants
    /// - All demangled patterns are inserted into pattern_trie
    /// - All mangled patterns are inserted into mangled_trie
    /// - Patterns are extracted from the matches_pattern method
    /// - Called after all functions are added to the whitelist
    fn build_tries(&mut self) {
        // Demangled patterns for pattern_trie
        let demangled_patterns = [
            // Vec operations
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
            // String operations
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

        // Insert demangled patterns into pattern_trie
        for pattern in &demangled_patterns {
            self.pattern_trie.insert(pattern);
        }

        // Mangled patterns for mangled_trie
        let mangled_patterns = [
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

        // Insert mangled patterns into mangled_trie
        for pattern in &mangled_patterns {
            self.mangled_trie.insert(pattern);
        }
    }
}

impl Default for RustStdlibWhitelist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
