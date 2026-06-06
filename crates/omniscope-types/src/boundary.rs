//! Boundary context for FFI boundary detection.
//!
//! Provides a unified context for querying FFI boundaries across passes.
//! This context is used by `FFIBoundaryPass` and `IssueVerifier` to
//! determine if a function is in a declared FFI boundary.
//!
//! Supports both exact function name matching and wildcard pattern matching
//! for flexible boundary declaration (e.g., `c_*`, `*_init`, `*malloc*`).

use crate::config::{FFIBoundaryConfig, Language};
use crate::evidence::BoundaryEvidenceKind;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::trace;

/// A cross-language boundary declaration with support for exact and pattern matching.
#[derive(Debug, Clone)]
pub struct CrossBoundary {
    /// Source language.
    pub from: Language,
    /// Target language.
    pub to: Language,
    /// Specific functions (if any).
    pub functions: Vec<String>,
    /// Function name pattern (if any).
    ///
    /// Supports wildcards:
    /// - `*` matches any sequence of characters
    /// - `c_*` matches all functions starting with `c_`
    /// - `*_init` matches all functions ending with `_init`
    /// - `*malloc*` matches all functions containing `malloc`
    /// - `c_fft_*` matches all functions starting with `c_fft_`
    pub pattern: Option<String>,
}

/// Boundary context for FFI boundary detection.
///
/// Provides a unified interface for querying FFI boundaries.
/// This context is built from `FFIBoundaryConfig` entries and
/// provides fast lookup for exact boundary functions and pattern-based matching.
#[derive(Debug, Clone, Default)]
pub struct BoundaryContext {
    /// Map from exact function name to (from_language, to_language).
    function_boundaries: HashMap<String, (Language, Language)>,
    /// Set of all declared boundary functions for quick membership check.
    boundary_functions: HashSet<String>,
    /// List of cross-boundary entries with optional patterns.
    declared_edges: Vec<CrossBoundary>,
}

impl BoundaryContext {
    /// Creates a new empty boundary context.
    pub fn new() -> Self {
        Self {
            function_boundaries: HashMap::new(),
            boundary_functions: HashSet::new(),
            declared_edges: Vec::new(),
        }
    }

    /// Creates a boundary context from FFI boundary configurations.
    ///
    /// # Arguments
    /// * `boundaries` - Slice of FFI boundary configurations.
    ///
    /// # Returns
    /// A new `BoundaryContext` containing all declared boundaries.
    pub fn from_config(boundaries: &[FFIBoundaryConfig]) -> Self {
        let mut context = Self::new();
        for boundary in boundaries {
            context.add_boundary(boundary);
        }
        context
    }

    /// Adds a single FFI boundary configuration to the context.
    ///
    /// Both exact function names and patterns are stored for later matching.
    ///
    /// # Arguments
    /// * `boundary` - The FFI boundary configuration to add.
    pub fn add_boundary(&mut self, boundary: &FFIBoundaryConfig) {
        // Add exact functions to the fast-lookup maps.
        for function in &boundary.functions {
            self.function_boundaries
                .insert(function.clone(), (boundary.from, boundary.to));
            self.boundary_functions.insert(function.clone());
        }

        // Store the boundary entry for pattern matching.
        self.declared_edges.push(CrossBoundary {
            from: boundary.from,
            to: boundary.to,
            functions: boundary.functions.clone(),
            pattern: boundary.pattern.clone(),
        });
    }

    /// Adds a `CrossBoundary` directly to the context.
    ///
    /// # Arguments
    /// * `edge` - The cross-boundary entry to add.
    pub fn add_cross_boundary(&mut self, edge: CrossBoundary) {
        // Add exact functions to the fast-lookup maps.
        for function in &edge.functions {
            self.function_boundaries
                .insert(function.clone(), (edge.from, edge.to));
            self.boundary_functions.insert(function.clone());
        }

        // Store the boundary entry for pattern matching.
        self.declared_edges.push(edge);
    }

    /// Checks if a function is in a declared FFI boundary.
    ///
    /// First checks exact function name matches, then falls back to pattern matching.
    ///
    /// # Arguments
    /// * `function` - The function name to check.
    ///
    /// # Returns
    /// `Some((from, to))` if the function is in a declared boundary,
    /// `None` otherwise.
    pub fn is_declared_boundary(&self, function: &str) -> Option<(Language, Language)> {
        // Strip '@' prefix if present (common in LLVM IR).
        let clean_func = function.trim_start_matches('@');

        // Fast path: check exact function name match.
        if let Some(&(from, to)) = self.function_boundaries.get(clean_func) {
            return Some((from, to));
        }

        // Slow path: check each declared edge for pattern match.
        for edge in &self.declared_edges {
            // Check specific functions (redundant with fast path, but consistent).
            if edge
                .functions
                .iter()
                .any(|f| f.trim_start_matches('@') == clean_func)
            {
                return Some((edge.from, edge.to));
            }

            // Check pattern.
            if let Some(pattern) = &edge.pattern {
                if matches_pattern(clean_func, pattern) {
                    trace!(
                        function = clean_func,
                        pattern = pattern.as_str(),
                        "Function matched via pattern"
                    );
                    return Some((edge.from, edge.to));
                }
            }
        }
        None
    }

    /// Checks if a function is in any declared FFI boundary.
    ///
    /// # Arguments
    /// * `function` - The function name to check.
    ///
    /// # Returns
    /// `true` if the function is in a declared boundary, `false` otherwise.
    pub fn is_boundary_function(&self, function: &str) -> bool {
        self.is_declared_boundary(function).is_some()
    }

    /// Check if a call between two languages crosses a declared boundary.
    ///
    /// This is used when functions list is empty (wildcard mode),
    /// meaning "any function from language A to language B is a boundary".
    ///
    /// # Arguments
    /// * `caller_lang` - The language of the caller function.
    /// * `callee_lang` - The language of the callee function.
    ///
    /// # Returns
    /// `true` if the call crosses a declared boundary.
    pub fn matches_call(&self, caller_lang: Language, callee_lang: Language) -> bool {
        for edge in &self.declared_edges {
            // Empty functions list means match all functions for this language pair
            if edge.functions.is_empty()
                && edge.pattern.is_none()
                && edge.from == caller_lang
                && edge.to == callee_lang
            {
                return true;
            }
        }
        false
    }

    /// Check if a function is a boundary function.
    ///
    /// Supports:
    /// 1. Explicit function list
    /// 2. Pattern matching
    /// 3. Language pair matching (when functions is empty)
    ///
    /// # Arguments
    /// * `function` - The function name to check.
    /// * `caller_lang` - The language of the caller function.
    /// * `callee_lang` - The language of the callee function.
    ///
    /// # Returns
    /// `true` if the function is a boundary function.
    pub fn is_boundary_function_with_lang(
        &self,
        function: &str,
        caller_lang: Language,
        callee_lang: Language,
    ) -> bool {
        // Check explicit function list and pattern match first
        if self.is_declared_boundary(function).is_some() {
            return true;
        }

        // Then check language pair match
        self.matches_call(caller_lang, callee_lang)
    }

    /// Returns the number of declared boundary functions (exact matches only).
    pub fn boundary_count(&self) -> usize {
        self.boundary_functions.len()
    }

    /// Returns all declared boundary functions (exact matches only).
    pub fn boundary_functions(&self) -> &HashSet<String> {
        &self.boundary_functions
    }

    /// Returns all function boundaries with their language pairs.
    pub fn function_boundaries(&self) -> &HashMap<String, (Language, Language)> {
        &self.function_boundaries
    }

    /// Returns all declared cross-boundary edges.
    pub fn declared_edges(&self) -> &[CrossBoundary] {
        &self.declared_edges
    }

    /// Merges another boundary context into this one.
    ///
    /// # Arguments
    /// * `other` - The other boundary context to merge.
    pub fn merge(&mut self, other: &BoundaryContext) {
        for (function, (from, to)) in &other.function_boundaries {
            self.function_boundaries
                .insert(function.clone(), (*from, *to));
            self.boundary_functions.insert(function.clone());
        }

        for edge in &other.declared_edges {
            self.declared_edges.push(edge.clone());
        }
    }

    /// Returns true if the context has no declared boundaries.
    pub fn is_empty(&self) -> bool {
        self.boundary_functions.is_empty() && self.declared_edges.is_empty()
    }
}

/// Check if a function name matches a pattern.
///
/// Pattern syntax:
/// - `*` matches any sequence of characters
/// - `c_*` matches functions starting with `c_`
/// - `*_init` matches functions ending with `_init`
/// - `*malloc*` matches functions containing `malloc`
/// - `c_fft_*` matches functions starting with `c_fft_`
///
/// # Arguments
/// * `function` - The function name to test.
/// * `pattern` - The pattern to match against.
///
/// # Returns
/// `true` if the function matches the pattern.
pub fn matches_pattern(function: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Handle prefix match: pattern ends with `*`.
    if let Some(prefix) = pattern.strip_suffix('*') {
        if prefix.is_empty() {
            return true; // Pure `*` matches everything.
        }
        if let Some(middle) = prefix.strip_prefix('*') {
            // Contains match: `*xxx*`
            return function.contains(middle);
        }
        // Prefix match: `xxx*`
        return function.starts_with(prefix);
    }

    // Handle suffix match: pattern starts with `*`.
    if let Some(suffix) = pattern.strip_prefix('*') {
        return function.ends_with(suffix);
    }

    // Exact match (no wildcards).
    function == pattern
}

/// Confidence level for boundary evidence.
///
/// Strong: direct, unambiguous evidence (e.g., cross-language call with
/// both languages known, user-configured boundary, C++ Itanium symbol
/// called from C).
///
/// Weak: indirect or heuristic evidence (e.g., same-language FFI contract
/// symbol, dangerous libc inside a wrapper, runtime bridge connected to
/// a user boundary flow).
///
/// None: no evidence or explicit suppression (e.g., LLVM intrinsic,
/// compiler glue with no user boundary path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum BoundaryConfidence {
    /// Strong, unambiguous evidence of a cross-language boundary.
    Strong,
    /// Indirect or heuristic evidence of a boundary.
    Weak,
    /// No evidence or explicitly suppressed.
    #[default]
    None,
}

/// A single piece of evidence supporting an FFI boundary classification.
///
/// Each `BoundaryEvidence` captures *why* a particular call or function
/// was classified as an FFI boundary. Multiple evidence items can be
/// attached to a single call site, enabling downstream passes to make
/// informed decisions about issue severity and suppression.
///
/// # Example
///
/// ```
/// use omniscope_types::boundary::{BoundaryConfidence, BoundaryEvidence};
/// use omniscope_types::evidence::BoundaryEvidenceKind;
/// use omniscope_types::config::Language;
///
/// let evidence = BoundaryEvidence {
///     kind: BoundaryEvidenceKind::CrossLanguageCall,
///     caller_lang: Some(Language::Rust),
///     callee_lang: Some(Language::C),
///     confidence: BoundaryConfidence::Strong,
///     reason: "Rust calling C via extern \"C\"".to_string(),
/// };
/// assert_eq!(evidence.confidence, BoundaryConfidence::Strong);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BoundaryEvidence {
    /// What kind of boundary evidence this is.
    pub kind: BoundaryEvidenceKind,
    /// Inferred language of the caller function (if known).
    pub caller_lang: Option<Language>,
    /// Inferred language of the callee function (if known).
    pub callee_lang: Option<Language>,
    /// Confidence level for this evidence.
    pub confidence: BoundaryConfidence,
    /// Human-readable explanation of why this evidence was produced.
    pub reason: String,
}

impl BoundaryEvidence {
    /// Creates a new boundary evidence with the given kind and reason.
    pub fn new(kind: BoundaryEvidenceKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            caller_lang: None,
            callee_lang: None,
            confidence: BoundaryConfidence::None,
            reason: reason.into(),
        }
    }

    /// Sets the caller language.
    pub fn with_caller_lang(mut self, lang: Language) -> Self {
        self.caller_lang = Some(lang);
        self
    }

    /// Sets the callee language.
    pub fn with_callee_lang(mut self, lang: Language) -> Self {
        self.callee_lang = Some(lang);
        self
    }

    /// Sets the confidence level.
    pub fn with_confidence(mut self, confidence: BoundaryConfidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Returns true if this evidence is strong-confidence.
    pub fn is_strong(&self) -> bool {
        self.confidence == BoundaryConfidence::Strong
    }

    /// Returns true if this evidence is weak-confidence.
    pub fn is_weak(&self) -> bool {
        self.confidence == BoundaryConfidence::Weak
    }
}

/// Metadata for FFI slice membership — how a function or call site
/// belongs to the expanded FFI slice around a boundary seed.
///
/// The FFI slice is the set of functions/calls that are "near" an
/// FFI boundary (within N hops). Functions inside the slice are
/// candidates for ownership tracking; functions outside are not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfiSliceInfo {
    /// Distance from the nearest strong seed (0 = seed itself, 1 = 1 hop, etc.).
    /// `None` means not yet computed or outside the slice.
    pub ffi_slice_depth: Option<u32>,
    /// Relevance to the FFI boundary (Strong = seed or 1-hop, Weak = 2-hop,
    /// None = outside the slice).
    pub ffi_relevance: BoundaryConfidence,
    /// Short explainable reason why this function/call is in the slice.
    pub ffi_reason: Option<String>,
}

impl FfiSliceInfo {
    /// Creates an FfiSliceInfo indicating the item is outside the slice.
    pub fn outside() -> Self {
        Self {
            ffi_slice_depth: None,
            ffi_relevance: BoundaryConfidence::None,
            ffi_reason: None,
        }
    }

    /// Creates an FfiSliceInfo for a boundary seed (depth 0, strong relevance).
    pub fn seed(reason: impl Into<String>) -> Self {
        Self {
            ffi_slice_depth: Some(0),
            ffi_relevance: BoundaryConfidence::Strong,
            ffi_reason: Some(reason.into()),
        }
    }

    /// Creates an FfiSliceInfo for an expanded node at the given depth.
    pub fn expanded(depth: u32, relevance: BoundaryConfidence, reason: impl Into<String>) -> Self {
        Self {
            ffi_slice_depth: Some(depth),
            ffi_relevance: relevance,
            ffi_reason: Some(reason.into()),
        }
    }

    /// Returns true if this item is inside the FFI slice.
    pub fn is_in_slice(&self) -> bool {
        self.ffi_slice_depth.is_some()
    }
}

/// Classification of a boundary seed — why a call is a boundary seed.
///
/// Seeds are the starting points for FFI slice expansion. They are
/// classified as strong (definite boundary), weak (possible boundary),
/// or suppression (should be excluded from boundary analysis).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SeedClassification {
    /// Strong seed: definite cross-language boundary.
    Strong,
    /// Weak seed: possible boundary with indirect evidence.
    Weak,
    /// Suppression seed: should be excluded from boundary analysis.
    Suppression,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify BoundaryContext creation from empty config.
    /// Invariants: Empty config produces empty context.
    #[test]
    fn test_boundary_context_from_empty_config() {
        let config = vec![];
        let context = BoundaryContext::from_config(&config);
        assert!(
            context.is_empty(),
            "Empty config should produce empty context"
        );
        assert_eq!(
            context.boundary_count(),
            0,
            "Empty context should have 0 boundaries"
        );
    }

    /// Objective: Verify BoundaryContext creation from valid config.
    /// Invariants: Functions are correctly mapped to language pairs.
    #[test]
    fn test_boundary_context_from_config() {
        let config = vec![
            FFIBoundaryConfig {
                from: Language::C,
                to: Language::Cpp,
                functions: vec!["c_func1".to_string(), "c_func2".to_string()],
                pattern: None,
                description: Some("C to C++ boundary".to_string()),
            },
            FFIBoundaryConfig {
                from: Language::Rust,
                to: Language::C,
                functions: vec!["rust_func".to_string()],
                pattern: None,
                description: None,
            },
        ];

        let context = BoundaryContext::from_config(&config);
        assert_eq!(
            context.boundary_count(),
            3,
            "Should have 3 boundary functions"
        );
        assert!(!context.is_empty(), "Context should not be empty");

        // Check specific functions.
        assert_eq!(
            context.is_declared_boundary("c_func1"),
            Some((Language::C, Language::Cpp)),
            "c_func1 should be C->Cpp boundary"
        );
        assert_eq!(
            context.is_declared_boundary("c_func2"),
            Some((Language::C, Language::Cpp)),
            "c_func2 should be C->Cpp boundary"
        );
        assert_eq!(
            context.is_declared_boundary("rust_func"),
            Some((Language::Rust, Language::C)),
            "rust_func should be Rust->C boundary"
        );
        assert_eq!(
            context.is_declared_boundary("unknown_func"),
            None,
            "unknown_func should not be a boundary"
        );
    }

    /// Objective: Verify BoundaryContext handles '@' prefix correctly.
    /// Invariants: Functions with '@' prefix are correctly identified.
    #[test]
    fn test_boundary_context_at_prefix() {
        let config = vec![FFIBoundaryConfig {
            from: Language::C,
            to: Language::Cpp,
            functions: vec!["c_func".to_string()],
            pattern: None,
            description: None,
        }];

        let context = BoundaryContext::from_config(&config);

        // Test with '@' prefix.
        assert_eq!(
            context.is_declared_boundary("@c_func"),
            Some((Language::C, Language::Cpp)),
            "Should handle '@' prefix"
        );

        // Test without '@' prefix.
        assert_eq!(
            context.is_declared_boundary("c_func"),
            Some((Language::C, Language::Cpp)),
            "Should work without '@' prefix"
        );

        // Test is_boundary_function with '@' prefix.
        assert!(
            context.is_boundary_function("@c_func"),
            "is_boundary_function should handle '@' prefix"
        );
    }

    /// Objective: Verify BoundaryContext merge functionality.
    /// Invariants: Merged contexts contain all boundaries from both.
    #[test]
    fn test_boundary_context_merge() {
        let config1 = vec![FFIBoundaryConfig {
            from: Language::C,
            to: Language::Cpp,
            functions: vec!["c_func".to_string()],
            pattern: None,
            description: None,
        }];

        let config2 = vec![FFIBoundaryConfig {
            from: Language::Rust,
            to: Language::C,
            functions: vec!["rust_func".to_string()],
            pattern: None,
            description: None,
        }];

        let mut context1 = BoundaryContext::from_config(&config1);
        let context2 = BoundaryContext::from_config(&config2);

        context1.merge(&context2);
        assert_eq!(
            context1.boundary_count(),
            2,
            "Merged context should have 2 boundaries"
        );

        assert_eq!(
            context1.is_declared_boundary("c_func"),
            Some((Language::C, Language::Cpp)),
            "c_func should be in merged context"
        );
        assert_eq!(
            context1.is_declared_boundary("rust_func"),
            Some((Language::Rust, Language::C)),
            "rust_func should be in merged context"
        );
    }

    /// Objective: Verify BoundaryContext handles duplicate functions.
    /// Invariants: Later boundaries override earlier ones for same function.
    #[test]
    fn test_boundary_context_duplicates() {
        let config = vec![
            FFIBoundaryConfig {
                from: Language::C,
                to: Language::Cpp,
                functions: vec!["shared_func".to_string()],
                pattern: None,
                description: None,
            },
            FFIBoundaryConfig {
                from: Language::Rust,
                to: Language::C,
                functions: vec!["shared_func".to_string()],
                pattern: None,
                description: None,
            },
        ];

        let context = BoundaryContext::from_config(&config);
        assert_eq!(
            context.boundary_count(),
            1,
            "Duplicate functions should be merged"
        );

        // The last one wins.
        assert_eq!(
            context.is_declared_boundary("shared_func"),
            Some((Language::Rust, Language::C)),
            "Last boundary should win for duplicate functions"
        );
    }

    /// Objective: Verify BoundaryContext returns correct references.
    /// Invariants: boundary_functions() and function_boundaries() return correct data.
    #[test]
    fn test_boundary_context_references() {
        let config = vec![FFIBoundaryConfig {
            from: Language::C,
            to: Language::Cpp,
            functions: vec!["c_func".to_string()],
            pattern: None,
            description: None,
        }];

        let context = BoundaryContext::from_config(&config);

        // Test boundary_functions().
        let functions = context.boundary_functions();
        assert_eq!(functions.len(), 1, "Should have 1 boundary function");
        assert!(functions.contains("c_func"), "Should contain c_func");

        // Test function_boundaries().
        let boundaries = context.function_boundaries();
        assert_eq!(boundaries.len(), 1, "Should have 1 function boundary");
        assert_eq!(
            boundaries.get("c_func"),
            Some(&(Language::C, Language::Cpp)),
            "Should have correct language pair"
        );
    }

    /// Objective: Verify prefix pattern matching.
    /// Invariants: `c_*` should match functions starting with `c_`.
    #[test]
    fn test_prefix_pattern() {
        assert!(
            matches_pattern("c_fft_forward", "c_*"),
            "c_* should match c_fft_forward"
        );
        assert!(matches_pattern("c_hash", "c_*"), "c_* should match c_hash");
        assert!(
            !matches_pattern("cpp_func", "c_*"),
            "c_* should not match cpp_func"
        );
        assert!(
            !matches_pattern("my_c_func", "c_*"),
            "c_* should not match my_c_func"
        );
    }

    /// Objective: Verify suffix pattern matching.
    /// Invariants: `*_init` should match functions ending with `_init`.
    #[test]
    fn test_suffix_pattern() {
        assert!(
            matches_pattern("module_init", "*_init"),
            "*_init should match module_init"
        );
        assert!(
            matches_pattern("system_init", "*_init"),
            "*_init should match system_init"
        );
        assert!(
            !matches_pattern("init", "*_init"),
            "*_init should not match bare init"
        );
        assert!(
            !matches_pattern("initialize", "*_init"),
            "*_init should not match initialize"
        );
    }

    /// Objective: Verify contains pattern matching.
    /// Invariants: `*malloc*` should match functions containing `malloc`.
    #[test]
    fn test_contains_pattern() {
        assert!(
            matches_pattern("malloc", "*malloc*"),
            "*malloc* should match malloc"
        );
        assert!(
            matches_pattern("my_malloc", "*malloc*"),
            "*malloc* should match my_malloc"
        );
        assert!(
            matches_pattern("malloc_init", "*malloc*"),
            "*malloc* should match malloc_init"
        );
        assert!(
            !matches_pattern("alloc", "*malloc*"),
            "*malloc* should not match alloc"
        );
    }

    /// Objective: Verify wildcard matching.
    /// Invariants: `*` should match everything.
    #[test]
    fn test_wildcard_pattern() {
        assert!(
            matches_pattern("any_function", "*"),
            "* should match any_function"
        );
        assert!(matches_pattern("", "*"), "* should match empty string");
    }

    /// Objective: Verify exact matching.
    /// Invariants: Exact match should work without wildcards.
    #[test]
    fn test_exact_pattern() {
        assert!(
            matches_pattern("malloc", "malloc"),
            "exact match should work"
        );
        assert!(
            !matches_pattern("malloc_init", "malloc"),
            "exact match should not match longer string"
        );
    }

    /// Objective: Verify BoundaryContext with patterns.
    /// Invariants: Pattern boundaries should be correctly identified.
    #[test]
    fn test_boundary_context_with_pattern() {
        let mut ctx = BoundaryContext::new();

        ctx.add_cross_boundary(CrossBoundary {
            from: Language::C,
            to: Language::Cpp,
            functions: vec!["exact_func".to_string()],
            pattern: Some("c_*".to_string()),
        });

        // Exact match.
        assert!(
            ctx.is_declared_boundary("exact_func").is_some(),
            "exact_func should match via exact name"
        );

        // Pattern match.
        assert!(
            ctx.is_declared_boundary("c_fft_forward").is_some(),
            "c_fft_forward should match via c_* pattern"
        );
        assert!(
            ctx.is_declared_boundary("c_hash").is_some(),
            "c_hash should match via c_* pattern"
        );

        // Non-match.
        assert!(
            ctx.is_declared_boundary("cpp_func").is_none(),
            "cpp_func should not match c_* pattern"
        );
    }

    /// Objective: Verify suffix pattern in BoundaryContext.
    /// Invariants: `*_init` patterns should match functions ending with `_init`.
    #[test]
    fn test_boundary_context_suffix_pattern() {
        let mut ctx = BoundaryContext::new();

        ctx.add_cross_boundary(CrossBoundary {
            from: Language::Rust,
            to: Language::C,
            functions: vec![],
            pattern: Some("*_init".to_string()),
        });

        assert!(
            ctx.is_declared_boundary("module_init").is_some(),
            "module_init should match *_init pattern"
        );
        assert!(
            ctx.is_declared_boundary("system_init").is_some(),
            "system_init should match *_init pattern"
        );
        assert!(
            ctx.is_declared_boundary("init").is_none(),
            "init should not match *_init pattern (missing underscore prefix)"
        );
        assert!(
            ctx.is_declared_boundary("initialize").is_none(),
            "initialize should not match *_init pattern"
        );
    }

    /// Objective: Verify contains pattern in BoundaryContext.
    /// Invariants: `*malloc*` patterns should match functions containing `malloc`.
    #[test]
    fn test_boundary_context_contains_pattern() {
        let mut ctx = BoundaryContext::new();

        ctx.add_cross_boundary(CrossBoundary {
            from: Language::C,
            to: Language::Cpp,
            functions: vec![],
            pattern: Some("*malloc*".to_string()),
        });

        assert!(
            ctx.is_declared_boundary("malloc").is_some(),
            "malloc should match *malloc* pattern"
        );
        assert!(
            ctx.is_declared_boundary("my_malloc").is_some(),
            "my_malloc should match *malloc* pattern"
        );
        assert!(
            ctx.is_declared_boundary("alloc").is_none(),
            "alloc should not match *malloc* pattern"
        );
    }

    /// Objective: Verify is_boundary_function with patterns.
    /// Invariants: is_boundary_function should delegate to is_declared_boundary.
    #[test]
    fn test_is_boundary_function_with_pattern() {
        let config = vec![FFIBoundaryConfig {
            from: Language::C,
            to: Language::Cpp,
            functions: vec![],
            pattern: Some("c_*".to_string()),
            description: None,
        }];

        let context = BoundaryContext::from_config(&config);

        assert!(
            context.is_boundary_function("c_func"),
            "is_boundary_function should match via pattern"
        );
        assert!(
            !context.is_boundary_function("rust_func"),
            "is_boundary_function should not match non-pattern functions"
        );
    }
}
