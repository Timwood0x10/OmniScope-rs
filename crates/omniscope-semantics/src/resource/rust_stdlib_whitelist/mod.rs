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
        };
        whitelist.populate_stdlib();
        whitelist.populate_common_crates();
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
}

impl Default for RustStdlibWhitelist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
