//! Node.js/N-API language adapter for semantic analysis.
//!
//! Provides Node.js-specific semantic analysis for N-API (node-addon-api)
//! function calls, resource management patterns, and memory leak detection.
//!
//! # N-API Memory Model
//!
//! Node.js native addons built with N-API interact with the JavaScript heap
//! through a set of C functions prefixed with `napi_`. Key patterns:
//!
//! 1. **Value creation** (`napi_create_*`) — creates JS values on the heap.
//! 2. **Reference management** (`napi_create_reference` / `napi_delete_reference`)
//!    — manages persistent references to JS objects.
//! 3. **Async work** (`napi_create_async_work` / `napi_delete_async_work`)
//!    — manages async work items that may leak if not cleaned up.
//! 4. **Threadsafe functions** (`napi_create_threadsafe_function` /
//!    `napi_release_threadsafe_function`) — cross-thread JS callbacks.
//! 5. **Object wrap** (`napi_wrap` / `napi_unwrap`) — C++ object lifecycle
//!    tied to JS object lifetime.

use omniscope_ir::{FunctionBody, IRInstructionKind};
use omniscope_types::Language;

use crate::resource::semantic_tree::{
    FactConfidence, FactSource, SemanticFact, SemanticKey, SemanticKind,
};

/// Node.js N-API-specific semantic patterns derived from IR analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NapiSemanticPattern {
    /// napi_create_* (creating JavaScript values, arrays, objects, strings, etc.)
    NapiCreateValue,
    /// napi_get_* (getting JavaScript values, properties, array elements)
    NapiGetValue,
    /// napi_call_* (calling JavaScript functions / constructors)
    NapiCallFunction,
    /// napi_create_reference (creating persistent reference to a JS value)
    NapiCreateReference,
    /// napi_delete_reference (deleting a persistent reference)
    NapiDeleteReference,
    /// napi_create_async_work (creating async work item)
    NapiCreateAsyncWork,
    /// napi_delete_async_work (deleting async work item)
    NapiDeleteAsyncWork,
    /// napi_create_threadsafe_function (creating threadsafe function)
    NapiCreateThreadsafeFunction,
    /// napi_release_threadsafe_function / napi_unref_threadsafe_function
    NapiReleaseThreadsafeFunction,
    /// napi_throw_* (throwing JavaScript errors)
    NapiThrowError,
    /// napi_wrap / napi_unwrap (wrapping C++ objects in JS objects)
    NapiObjectWrap,
    /// napi_set_* (setting JavaScript properties, named/typed arrays, elements)
    NapiSetProperty,
    /// napi_remove_wrap / napi_remove_ref (cleanup operations)
    NapiCleanup,
    /// napi_ref / napi_unref (reference counting for threadsafe functions)
    NapiRefCount,
    /// napi_get_and_clear_last_exception / napi_is_exception_pending (error state)
    NapiErrorHandling,
    /// N-API callback function (napi_callback, napi_threadsafe_function_call_js)
    NapiCallback,
    /// N-API class / property descriptor definition
    NapiClassDefinition,
    /// Unknown N-API pattern
    Unknown,
}

/// Analysis result for a Node.js/N-API function.
#[derive(Debug, Clone)]
pub struct NapiFunctionAnalysis {
    /// The function name analyzed
    pub function_name: String,
    /// Detected N-API semantic patterns
    pub patterns: Vec<NapiSemanticPattern>,
    /// Whether this function is an N-API callback
    pub is_napi_callback: bool,
    /// Whether this function manages persistent references
    pub manages_references: bool,
    /// Whether this function manages async work
    pub manages_async_work: bool,
    /// Recommended FFI safety assessment
    pub ffi_safety: NapiFFISafety,
}

impl NapiFunctionAnalysis {
    /// Convert N-API analysis results into SemanticFact records.
    pub fn to_semantic_facts(&self) -> Vec<SemanticFact> {
        let key = SemanticKey::Symbol(self.function_name.clone());
        let mut facts = Vec::new();

        for pattern in &self.patterns {
            match pattern {
                NapiSemanticPattern::NapiCreateValue => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RuntimeManagedResource,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("NapiAdapter: create JS value in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiCreateReference => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::HeapProvenance,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("NapiAdapter: create reference in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiDeleteReference => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RaiiDropRelease,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!("NapiAdapter: delete reference in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiCreateAsyncWork => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::HeapProvenance,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("NapiAdapter: create async work in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiDeleteAsyncWork => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RaiiDropRelease,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!("NapiAdapter: delete async work in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiCreateThreadsafeFunction => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::HeapProvenance,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!(
                            "NapiAdapter: create threadsafe fn in {}",
                            self.function_name
                        ),
                    ));
                }
                NapiSemanticPattern::NapiReleaseThreadsafeFunction => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RaiiDropRelease,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!(
                            "NapiAdapter: release threadsafe fn in {}",
                            self.function_name
                        ),
                    ));
                }
                NapiSemanticPattern::NapiObjectWrap => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::DeclaredCrossBoundary,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!("NapiAdapter: object wrap in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiCallback => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::DeclaredCrossBoundary,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("NapiAdapter: callback in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiCleanup => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RaiiDropRelease,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!("NapiAdapter: cleanup in {}", self.function_name),
                    ));
                }
                _ => {}
            }
        }

        if !self.ffi_safety.is_safe() {
            facts.push(SemanticFact::new(
                key,
                SemanticKind::Unknown,
                FactConfidence::Low,
                FactSource::LanguageAdapter,
                format!(
                    "NapiAdapter: FFI safety concern {:?} in {}",
                    self.ffi_safety, self.function_name
                ),
            ));
        }

        facts
    }
}

/// FFI safety assessment for Node.js/N-API functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NapiFFISafety {
    /// Safe: pure N-API internal, no resource management concerns
    SafeInternal,
    /// Safe: proper reference/async-work lifecycle management
    SafeResourceManaged,
    /// Concern: reference leak (create without delete)
    ConcernReferenceLeak,
    /// Concern: async work leak (create without delete)
    ConcernAsyncWorkLeak,
    /// Concern: threadsafe function leak (create without release)
    ConcernThreadsafeLeak,
    /// Unknown: cannot determine safety
    Unknown,
}

impl NapiFFISafety {
    /// Returns true if this assessment indicates a safe pattern.
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            NapiFFISafety::SafeInternal | NapiFFISafety::SafeResourceManaged
        )
    }

    /// Returns the safety score (0.0 = dangerous, 1.0 = safe).
    pub fn safety_score(&self) -> f32 {
        match self {
            NapiFFISafety::SafeInternal => 0.95,
            NapiFFISafety::SafeResourceManaged => 0.85,
            NapiFFISafety::ConcernReferenceLeak => 0.3,
            NapiFFISafety::ConcernAsyncWorkLeak => 0.25,
            NapiFFISafety::ConcernThreadsafeLeak => 0.2,
            NapiFFISafety::Unknown => 0.5,
        }
    }
}

/// Node.js/N-API adapter for semantic analysis.
///
/// This adapter provides N-API-specific semantic analysis by combining
/// function name pattern matching with IR body instruction analysis.
/// It detects N-API function call patterns, resource management
/// operations, and potential memory leak patterns.
///
/// # N-API Resource Categories
///
/// 1. **Persistent references** (`napi_create_reference` /
///    `napi_delete_reference`): Must be paired to avoid leaking JS objects.
/// 2. **Async work** (`napi_create_async_work` / `napi_delete_async_work`):
///    Must be paired to avoid leaking async work items.
/// 3. **Threadsafe functions** (`napi_create_threadsafe_function` /
///    `napi_release_threadsafe_function`): Must be paired to avoid
///    leaking callbacks across threads.
pub struct NapiAdapter {
    /// Language hint for Node.js, used to identify the source language
    language: Language,
}

impl NapiAdapter {
    /// Creates a new N-API adapter with NodeJs language hint.
    pub fn new() -> Self {
        Self {
            language: Language::NodeJs,
        }
    }

    /// Returns the language hint for this adapter.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Analyzes a Node.js/N-API function from its IR body and name.
    pub fn analyze_function(
        &self,
        function_name: &str,
        body: Option<&FunctionBody>,
    ) -> NapiFunctionAnalysis {
        // Collect all detected patterns from both name and IR body analysis
        let mut patterns = Vec::new();

        // Step 1: Analyze function name to detect N-API patterns
        // This is the primary detection mechanism for known function names
        let name_patterns = self.analyze_function_name(function_name);
        patterns.extend(name_patterns);

        // Step 2: Analyze IR body for instruction-level evidence
        // This complements name-based analysis with actual call targets
        if let Some(body) = body {
            let body_patterns = self.analyze_function_body(body);
            patterns.extend(body_patterns);
        }

        // Step 3: Determine resource management flags from collected patterns
        // Reference management: napi_create_reference / napi_delete_reference
        let manages_references = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiCreateReference));

        // Async work management: napi_create_async_work / napi_delete_async_work
        let manages_async_work = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiCreateAsyncWork));

        // Callback detection
        let is_napi_callback = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiCallback));

        // Step 4: Compute FFI safety assessment based on all evidence
        let ffi_safety = self.determine_ffi_safety(function_name, &patterns, body);

        // Assemble final analysis result
        NapiFunctionAnalysis {
            function_name: function_name.to_string(),
            patterns,
            is_napi_callback,
            manages_references,
            manages_async_work,
            ffi_safety,
        }
    }

    /// Analyzes function name to detect N-API semantic patterns.
    fn analyze_function_name(&self, function_name: &str) -> Vec<NapiSemanticPattern> {
        let mut patterns = Vec::new();

        // N-API value creation functions: napi_create_*
        // These create JavaScript values (objects, arrays, strings, buffers, etc.)
        if function_name.starts_with("napi_create_") {
            patterns.push(NapiSemanticPattern::NapiCreateValue);

            // napi_create_reference is a special case of reference management
            if function_name == "napi_create_reference" {
                patterns.push(NapiSemanticPattern::NapiCreateReference);
            } else if function_name == "napi_create_async_work" {
                patterns.push(NapiSemanticPattern::NapiCreateAsyncWork);
            } else if function_name == "napi_create_threadsafe_function" {
                patterns.push(NapiSemanticPattern::NapiCreateThreadsafeFunction);
            }
        }

        // N-API get operations: napi_get_*
        // These retrieve JavaScript values and properties
        if function_name.starts_with("napi_get_") {
            patterns.push(NapiSemanticPattern::NapiGetValue);
        }

        // N-API call operations: napi_call_*
        // These call JavaScript functions and constructors
        if function_name.starts_with("napi_call_") {
            patterns.push(NapiSemanticPattern::NapiCallFunction);
        }

        // N-API set operations: napi_set_*
        // These set JavaScript properties and elements
        if function_name.starts_with("napi_set_") {
            patterns.push(NapiSemanticPattern::NapiSetProperty);
        }

        // N-API delete operations
        if function_name == "napi_delete_reference" {
            patterns.push(NapiSemanticPattern::NapiDeleteReference);
        } else if function_name == "napi_delete_async_work" {
            patterns.push(NapiSemanticPattern::NapiDeleteAsyncWork);
        }

        // Threadsafe function release
        if function_name == "napi_release_threadsafe_function"
            || function_name == "napi_unref_threadsafe_function"
        {
            patterns.push(NapiSemanticPattern::NapiReleaseThreadsafeFunction);
        }

        // Object wrap / unwrap
        if function_name == "napi_wrap" || function_name == "napi_unwrap" {
            patterns.push(NapiSemanticPattern::NapiObjectWrap);
        }

        // Remove wrap / remove ref (cleanup)
        if function_name == "napi_remove_wrap" || function_name == "napi_remove_ref" {
            patterns.push(NapiSemanticPattern::NapiCleanup);
        }

        // Reference counting operations
        if function_name == "napi_ref" || function_name == "napi_unref" {
            patterns.push(NapiSemanticPattern::NapiRefCount);
        }

        // N-API throw operations: napi_throw_*
        if function_name.starts_with("napi_throw_") {
            patterns.push(NapiSemanticPattern::NapiThrowError);
        }

        // N-API error handling
        if function_name == "napi_get_and_clear_last_exception"
            || function_name == "napi_is_exception_pending"
        {
            patterns.push(NapiSemanticPattern::NapiErrorHandling);
        }

        // N-API callback patterns: function types passed as callbacks
        if function_name == "napi_create_function"
            || function_name.contains("napi_callback")
            || function_name.contains("napi_threadsafe_function_call_js")
        {
            patterns.push(NapiSemanticPattern::NapiCallback);
        }

        // N-API class / property descriptor definitions
        if function_name == "napi_define_class" || function_name == "napi_define_properties" {
            patterns.push(NapiSemanticPattern::NapiClassDefinition);
        }

        patterns
    }

    /// Analyzes function body to detect N-API semantic patterns from IR instructions.
    fn analyze_function_body(&self, body: &FunctionBody) -> Vec<NapiSemanticPattern> {
        let mut patterns = Vec::new();

        // Scan all instructions for call patterns that indicate N-API usage
        for instruction in &body.instructions {
            if let IRInstructionKind::Call = instruction.kind {
                if let Some(ref callee) = instruction.callee {
                    // N-API value creation functions
                    if callee.starts_with("napi_create_") {
                        patterns.push(NapiSemanticPattern::NapiCreateValue);

                        if callee == "napi_create_reference" {
                            patterns.push(NapiSemanticPattern::NapiCreateReference);
                        } else if callee == "napi_create_async_work" {
                            patterns.push(NapiSemanticPattern::NapiCreateAsyncWork);
                        } else if callee == "napi_create_threadsafe_function" {
                            patterns.push(NapiSemanticPattern::NapiCreateThreadsafeFunction);
                        }
                    }
                    // N-API get operations
                    else if callee.starts_with("napi_get_") {
                        patterns.push(NapiSemanticPattern::NapiGetValue);
                    }
                    // N-API call operations
                    else if callee.starts_with("napi_call_") {
                        patterns.push(NapiSemanticPattern::NapiCallFunction);
                    }
                    // N-API set operations
                    else if callee.starts_with("napi_set_") {
                        patterns.push(NapiSemanticPattern::NapiSetProperty);
                    }
                    // N-API delete operations
                    else if callee == "napi_delete_reference" {
                        patterns.push(NapiSemanticPattern::NapiDeleteReference);
                    } else if callee == "napi_delete_async_work" {
                        patterns.push(NapiSemanticPattern::NapiDeleteAsyncWork);
                    }
                    // Threadsafe function release
                    else if callee == "napi_release_threadsafe_function"
                        || callee == "napi_unref_threadsafe_function"
                    {
                        patterns.push(NapiSemanticPattern::NapiReleaseThreadsafeFunction);
                    }
                    // Object wrap / unwrap
                    else if callee == "napi_wrap" || callee == "napi_unwrap" {
                        patterns.push(NapiSemanticPattern::NapiObjectWrap);
                    }
                    // Cleanup operations
                    else if callee == "napi_remove_wrap" || callee == "napi_remove_ref" {
                        patterns.push(NapiSemanticPattern::NapiCleanup);
                    }
                    // Reference counting
                    else if callee == "napi_ref" || callee == "napi_unref" {
                        patterns.push(NapiSemanticPattern::NapiRefCount);
                    }
                    // N-API throw operations
                    else if callee.starts_with("napi_throw_") {
                        patterns.push(NapiSemanticPattern::NapiThrowError);
                    }
                    // N-API error handling
                    else if callee == "napi_get_and_clear_last_exception"
                        || callee == "napi_is_exception_pending"
                    {
                        patterns.push(NapiSemanticPattern::NapiErrorHandling);
                    }
                    // N-API callback patterns
                    else if callee == "napi_create_function"
                        || callee.contains("napi_callback")
                        || callee.contains("napi_threadsafe_function_call_js")
                    {
                        patterns.push(NapiSemanticPattern::NapiCallback);
                    }
                    // N-API class / property descriptor definitions
                    else if callee == "napi_define_class" || callee == "napi_define_properties" {
                        patterns.push(NapiSemanticPattern::NapiClassDefinition);
                    }
                }
            }
        }

        patterns
    }

    /// Determines FFI safety for a Node.js/N-API function based on detected patterns.
    fn determine_ffi_safety(
        &self,
        _function_name: &str,
        patterns: &[NapiSemanticPattern],
        _body: Option<&FunctionBody>,
    ) -> NapiFFISafety {
        // Priority 1: Reference leak detection
        let has_ref_create = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiCreateReference));
        let has_ref_delete = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiDeleteReference));

        if has_ref_create && !has_ref_delete {
            return NapiFFISafety::ConcernReferenceLeak;
        }

        // Priority 2: Async work leak detection
        let has_async_create = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiCreateAsyncWork));
        let has_async_delete = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiDeleteAsyncWork));

        if has_async_create && !has_async_delete {
            return NapiFFISafety::ConcernAsyncWorkLeak;
        }

        // Priority 3: Threadsafe function leak detection
        let has_tsfn_create = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiCreateThreadsafeFunction));
        let has_tsfn_release = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiReleaseThreadsafeFunction));

        if has_tsfn_create && !has_tsfn_release {
            return NapiFFISafety::ConcernThreadsafeLeak;
        }

        // Priority 4: Balanced resource management
        let has_any_alloc = has_ref_create || has_async_create || has_tsfn_create;
        let has_any_release = has_ref_delete || has_async_delete || has_tsfn_release;

        if has_any_alloc && has_any_release {
            return NapiFFISafety::SafeResourceManaged;
        }

        // Priority 5: Pure N-API internal (no resource management)
        if !patterns.is_empty() {
            // Functions that only create/get/call/set values without
            // managing persistent resources are considered safe internal
            return NapiFFISafety::SafeInternal;
        }

        // Default: insufficient information for assessment
        NapiFFISafety::Unknown
    }

    /// Detects potential reference leaks in N-API calls.
    ///
    /// # Objective
    /// Analyze whether a function creates persistent references without
    /// deleting them, which would cause JavaScript objects to leak.
    ///
    /// # Invariants
    /// - Returns `true` if `napi_create_reference` is present without
    ///   `napi_delete_reference`.
    /// - Returns `false` otherwise.
    ///
    /// # Arguments
    /// * `patterns` - The detected N-API semantic patterns for the function.
    ///
    /// # Returns
    /// `true` if a reference leak risk is detected, `false` otherwise.
    pub fn detect_reference_leak(&self, patterns: &[NapiSemanticPattern]) -> bool {
        let has_create = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiCreateReference));
        let has_delete = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiDeleteReference));
        has_create && !has_delete
    }

    /// Detects potential async work leaks.
    ///
    /// # Objective
    /// Analyze whether a function creates async work items without
    /// deleting them, which can cause resource leaks.
    ///
    /// # Invariants
    /// - Returns `true` if `napi_create_async_work` is present without
    ///   `napi_delete_async_work`.
    /// - Returns `false` otherwise.
    ///
    /// # Arguments
    /// * `patterns` - The detected N-API semantic patterns for the function.
    ///
    /// # Returns
    /// `true` if an async work leak risk is detected, `false` otherwise.
    pub fn detect_async_work_leak(&self, patterns: &[NapiSemanticPattern]) -> bool {
        let has_create = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiCreateAsyncWork));
        let has_delete = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiDeleteAsyncWork));
        has_create && !has_delete
    }
}

impl Default for NapiAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

    /// Objective: Verify napi_create_* function analysis
    /// Invariants: napi_create_string_utf8 must be detected as NapiCreateValue
    #[test]
    fn test_napi_create_value_analysis() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_create_string_utf8", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCreateValue),
            "napi_create_string_utf8 must be detected as NapiCreateValue, got {:?}",
            analysis.patterns
        );
        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::SafeInternal,
            "napi_create_string_utf8 must be SafeInternal"
        );
    }

    /// Objective: Verify napi_create_reference function analysis
    /// Invariants: napi_create_reference must be detected as reference management
    #[test]
    fn test_napi_create_reference_analysis() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_create_reference", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCreateValue),
            "napi_create_reference must be detected as NapiCreateValue"
        );
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCreateReference),
            "napi_create_reference must be detected as NapiCreateReference"
        );
        assert!(
            analysis.manages_references,
            "napi_create_reference must manage references"
        );
        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::ConcernReferenceLeak,
            "napi_create_reference without delete must have ConcernReferenceLeak"
        );
    }

    /// Objective: Verify napi_get_* function analysis
    /// Invariants: napi_get_named_property must be detected as NapiGetValue
    #[test]
    fn test_napi_get_value_analysis() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_get_named_property", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiGetValue),
            "napi_get_named_property must be detected as NapiGetValue, got {:?}",
            analysis.patterns
        );
    }

    /// Objective: Verify napi_call_* function analysis
    /// Invariants: napi_call_function must be detected as NapiCallFunction
    #[test]
    fn test_napi_call_function_analysis() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_call_function", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCallFunction),
            "napi_call_function must be detected as NapiCallFunction, got {:?}",
            analysis.patterns
        );
    }

    /// Objective: Verify napi_throw_* function analysis
    /// Invariants: napi_throw_error must be detected as NapiThrowError
    #[test]
    fn test_napi_throw_error_analysis() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_throw_error", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiThrowError),
            "napi_throw_error must be detected as NapiThrowError, got {:?}",
            analysis.patterns
        );
    }

    /// Objective: Verify napi_wrap function analysis
    /// Invariants: napi_wrap must be detected as NapiObjectWrap
    #[test]
    fn test_napi_object_wrap_analysis() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_wrap", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiObjectWrap),
            "napi_wrap must be detected as NapiObjectWrap, got {:?}",
            analysis.patterns
        );
    }

    /// Objective: Verify napi_create_async_work without delete detection
    /// Invariants: Must be detected as ConcernAsyncWorkLeak
    #[test]
    fn test_napi_async_work_leak_concern() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_create_async_work", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCreateAsyncWork),
            "napi_create_async_work must be detected as NapiCreateAsyncWork"
        );
        assert!(
            analysis.manages_async_work,
            "napi_create_async_work must manage async work"
        );
        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::ConcernAsyncWorkLeak,
            "napi_create_async_work without delete must have ConcernAsyncWorkLeak"
        );
    }

    /// Objective: Verify napi_delete_async_work function analysis
    /// Invariants: Must be detected as NapiDeleteAsyncWork
    #[test]
    fn test_napi_delete_async_work_analysis() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_delete_async_work", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiDeleteAsyncWork),
            "napi_delete_async_work must be detected as NapiDeleteAsyncWork"
        );
    }

    /// Objective: Verify napi_create_threadsafe_function without release detection
    /// Invariants: Must be detected as ConcernThreadsafeLeak
    #[test]
    fn test_napi_threadsafe_leak_concern() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_create_threadsafe_function", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCreateThreadsafeFunction),
            "napi_create_threadsafe_function must be detected as NapiCreateThreadsafeFunction"
        );
        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::ConcernThreadsafeLeak,
            "napi_create_threadsafe_function without release must have ConcernThreadsafeLeak"
        );
    }

    /// Objective: Verify napi_delete_reference function analysis
    /// Invariants: Must be detected as NapiDeleteReference
    #[test]
    fn test_napi_delete_reference_analysis() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_delete_reference", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiDeleteReference),
            "napi_delete_reference must be detected as NapiDeleteReference"
        );
    }

    /// Objective: Verify napi_callback detection
    /// Invariants: napi_create_function must be detected as NapiCallback
    #[test]
    fn test_napi_callback_detection() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_create_function", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCallback),
            "napi_create_function must be detected as NapiCallback"
        );
        assert!(
            analysis.is_napi_callback,
            "napi_create_function must be flagged as callback"
        );
    }

    /// Objective: Verify reference leak detection helper
    /// Invariants: detect_reference_leak must correctly identify unpaired create
    #[test]
    fn test_detect_reference_leak() {
        let adapter = NapiAdapter::new();

        // Test with only create reference
        let analysis = adapter.analyze_function("napi_create_reference", None);
        assert!(
            adapter.detect_reference_leak(&analysis.patterns),
            "create_reference without delete must be detected as leak"
        );

        // Test with delete reference only
        let analysis_delete = adapter.analyze_function("napi_delete_reference", None);
        assert!(
            !adapter.detect_reference_leak(&analysis_delete.patterns),
            "delete_reference alone must not be detected as leak"
        );

        // Test with balanced create+delete
        let mut patterns = vec![
            NapiSemanticPattern::NapiCreateReference,
            NapiSemanticPattern::NapiDeleteReference,
        ];
        assert!(
            !adapter.detect_reference_leak(&patterns),
            "balanced create+delete must not be detected as leak"
        );

        // Test empty patterns
        patterns.clear();
        assert!(
            !adapter.detect_reference_leak(&patterns),
            "empty patterns must not be detected as leak"
        );
    }

    /// Objective: Verify async work leak detection helper
    /// Invariants: detect_async_work_leak must correctly identify unpaired create
    #[test]
    fn test_detect_async_work_leak() {
        let adapter = NapiAdapter::new();

        // Test with only create async work
        let analysis = adapter.analyze_function("napi_create_async_work", None);
        assert!(
            adapter.detect_async_work_leak(&analysis.patterns),
            "create_async_work without delete must be detected as leak"
        );

        // Test with balanced create+delete
        let mut patterns = vec![
            NapiSemanticPattern::NapiCreateAsyncWork,
            NapiSemanticPattern::NapiDeleteAsyncWork,
        ];
        assert!(
            !adapter.detect_async_work_leak(&patterns),
            "balanced create+delete must not be detected as leak"
        );

        // Test empty patterns
        patterns.clear();
        assert!(
            !adapter.detect_async_work_leak(&patterns),
            "empty patterns must not be detected as leak"
        );
    }

    /// Objective: Verify N-API call semantics using embedded IR
    /// Invariants: IR body with napi calls must be correctly detected
    #[test]
    fn test_napi_call_semantics_with_ir() {
        let adapter = NapiAdapter::new();

        // Create a function body with N-API calls
        let body = FunctionBody {
            name: "test_napi_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%env".to_string()),
                    operands: vec!["i8*".to_string()],
                    callee: Some("napi_get_cb_info".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%env = call i8* @napi_get_cb_info()".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%str".to_string()),
                    operands: vec!["i8*".to_string(), "i8*".to_string()],
                    callee: Some("napi_create_string_utf8".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%str = call i8* @napi_create_string_utf8(i8* %env, i8* \"hello\")"
                        .to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%ref".to_string()),
                    operands: vec!["i8*".to_string(), "i8*".to_string(), "%str".to_string()],
                    callee: Some("napi_create_reference".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%ref = call i8* @napi_create_reference(i8* %env, i8* %str)"
                        .to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: None,
                    operands: vec!["i8*".to_string(), "i8*".to_string(), "%ref".to_string()],
                    callee: Some("napi_delete_reference".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "call void @napi_delete_reference(i8* %env, i8* %ref)".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Ret,
                    dest: None,
                    operands: vec![],
                    callee: None,
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "ret void".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("test_napi_function", Some(&body));

        // Verify N-API patterns are detected from IR body
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCreateValue),
            "napi_create_string_utf8 must be detected from IR body"
        );
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiGetValue),
            "napi_get_cb_info must be detected from IR body"
        );
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCreateReference),
            "napi_create_reference must be detected from IR body"
        );
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiDeleteReference),
            "napi_delete_reference must be detected from IR body"
        );

        // Verify resource management flags
        assert!(
            analysis.manages_references,
            "Function with napi_create_reference must manage references"
        );

        // Verify FFI safety assessment (balanced reference management)
        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::SafeResourceManaged,
            "N-API with balanced reference create/delete must be SafeResourceManaged"
        );
    }

    /// Objective: Verify napi_wrap + napi_unwrap with IR body
    /// Invariants: Both must be detected from IR body
    #[test]
    fn test_napi_object_wrap_with_ir() {
        let adapter = NapiAdapter::new();

        let body = FunctionBody {
            name: "test_object_wrap".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%result".to_string()),
                    operands: vec![
                        "i8*".to_string(),
                        "i8*".to_string(),
                        "%obj".to_string(),
                        "%native".to_string(),
                    ],
                    callee: Some("napi_wrap".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%result = call i32 @napi_wrap(i8* %env, i8* %obj, i8* %native)"
                        .to_string(),
                    result_type: Some("i32".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Ret,
                    dest: None,
                    operands: vec![],
                    callee: None,
                    raw_text: "ret void".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                    atomic_op: None,
                    icmp_pred: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("test_object_wrap", Some(&body));

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiObjectWrap),
            "napi_wrap must be detected from IR body"
        );
    }

    /// Objective: Verify napi_set_* detection with IR body
    /// Invariants: napi_set_named_property must be detected from IR body
    #[test]
    fn test_napi_set_property_with_ir() {
        let adapter = NapiAdapter::new();

        let body = FunctionBody {
            name: "test_set_property".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%result".to_string()),
                    operands: vec!["i8*".to_string(), "%obj".to_string(), "%key".to_string()],
                    callee: Some("napi_set_named_property".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text:
                        "%result = call i32 @napi_set_named_property(i8* %env, i8* %obj, i8* %key)"
                            .to_string(),
                    result_type: Some("i32".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Ret,
                    dest: None,
                    operands: vec![],
                    callee: None,
                    raw_text: "ret void".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                    atomic_op: None,
                    icmp_pred: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("test_set_property", Some(&body));

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiSetProperty),
            "napi_set_named_property must be detected from IR body"
        );
    }

    /// Objective: Verify napi_create_async_work + napi_delete_async_work with IR
    /// Invariants: Balanced async work must be SafeResourceManaged
    #[test]
    fn test_async_work_balanced_with_ir() {
        let adapter = NapiAdapter::new();

        let body = FunctionBody {
            name: "test_async_work".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%work".to_string()),
                    operands: vec!["i8*".to_string()],
                    callee: Some("napi_create_async_work".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%work = call i8* @napi_create_async_work()".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: None,
                    operands: vec!["i8*".to_string(), "%work".to_string()],
                    callee: Some("napi_delete_async_work".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "call void @napi_delete_async_work(i8* %work)".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Ret,
                    dest: None,
                    operands: vec![],
                    callee: None,
                    raw_text: "ret void".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                    atomic_op: None,
                    icmp_pred: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("test_async_work", Some(&body));

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCreateAsyncWork),
            "napi_create_async_work must be detected from IR body"
        );
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiDeleteAsyncWork),
            "napi_delete_async_work must be detected from IR body"
        );
        assert!(
            analysis.manages_async_work,
            "Function with async work must flag manages_async_work"
        );
        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::SafeResourceManaged,
            "Balanced async work must be SafeResourceManaged"
        );
    }

    /// Objective: Verify SemanticFact conversion for napi_create_value
    /// Invariants: NapiCreateValue must produce RuntimeManagedResource fact
    #[test]
    fn test_to_semantic_facts_create_value() {
        let analysis = NapiFunctionAnalysis {
            function_name: "napi_create_string_utf8".to_string(),
            patterns: vec![NapiSemanticPattern::NapiCreateValue],
            is_napi_callback: false,
            manages_references: false,
            manages_async_work: false,
            ffi_safety: NapiFFISafety::SafeInternal,
        };

        let facts = analysis.to_semantic_facts();

        let has_value_create = facts.iter().any(|f| {
            f.kind == SemanticKind::RuntimeManagedResource
                && f.confidence == FactConfidence::High
                && matches!(&f.key, SemanticKey::Symbol(name) if name == "napi_create_string_utf8")
        });

        assert!(
            has_value_create,
            "NapiCreateValue must produce RuntimeManagedResource fact"
        );
    }

    /// Objective: Verify SemanticFact conversion for napi_create_reference
    /// Invariants: NapiCreateReference must produce HeapProvenance fact
    #[test]
    fn test_to_semantic_facts_create_reference() {
        let analysis = NapiFunctionAnalysis {
            function_name: "napi_create_reference".to_string(),
            patterns: vec![NapiSemanticPattern::NapiCreateReference],
            is_napi_callback: false,
            manages_references: true,
            manages_async_work: false,
            ffi_safety: NapiFFISafety::ConcernReferenceLeak,
        };

        let facts = analysis.to_semantic_facts();

        let has_heap_provenance = facts.iter().any(|f| {
            f.kind == SemanticKind::HeapProvenance
                && f.confidence == FactConfidence::High
                && matches!(&f.key, SemanticKey::Symbol(name) if name == "napi_create_reference")
        });

        let has_safety_concern = facts.iter().any(|f| {
            f.kind == SemanticKind::Unknown
                && f.confidence == FactConfidence::Low
                && f.source == FactSource::LanguageAdapter
        });

        assert!(
            has_heap_provenance,
            "NapiCreateReference must produce HeapProvenance fact"
        );
        assert!(
            has_safety_concern,
            "ConcernReferenceLeak must produce safety concern fact"
        );
    }

    /// Objective: Verify napi_create_threadsafe_function + release detection
    /// Invariants: Balanced threadsafe function must be SafeResourceManaged
    #[test]
    fn test_threadsafe_function_balanced_with_patterns() {
        let adapter = NapiAdapter::new();

        let patterns = vec![
            NapiSemanticPattern::NapiCreateThreadsafeFunction,
            NapiSemanticPattern::NapiReleaseThreadsafeFunction,
        ];

        let ffi_safety = adapter.determine_ffi_safety("test_tsfn", &patterns, None);

        assert_eq!(
            ffi_safety,
            NapiFFISafety::SafeResourceManaged,
            "Balanced threadsafe function must be SafeResourceManaged"
        );

        // Also verify with pattern-based analysis
        let mut analysis = adapter.analyze_function("napi_create_threadsafe_function", None);
        analysis
            .patterns
            .push(NapiSemanticPattern::NapiReleaseThreadsafeFunction);

        let ffi_safety_combined =
            adapter.determine_ffi_safety("test_tsfn", &analysis.patterns, None);
        assert_eq!(
            ffi_safety_combined,
            NapiFFISafety::SafeResourceManaged,
            "Combined create+release must be SafeResourceManaged"
        );
    }

    /// Objective: Verify napi_define_class detection
    /// Invariants: napi_define_class must be detected as NapiClassDefinition
    #[test]
    fn test_napi_class_definition_analysis() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_define_class", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiClassDefinition),
            "napi_define_class must be detected as NapiClassDefinition, got {:?}",
            analysis.patterns
        );
    }

    /// Objective: Verify napi_remove_wrap cleanup detection
    /// Invariants: napi_remove_wrap must be detected as NapiCleanup
    #[test]
    fn test_napi_cleanup_analysis() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("napi_remove_wrap", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCleanup),
            "napi_remove_wrap must be detected as NapiCleanup, got {:?}",
            analysis.patterns
        );
    }

    /// Objective: Verify mixed N-API patterns with IR body
    /// Invariants: Multiple patterns from a single function must all be detected
    #[test]
    fn test_mixed_napi_patterns_with_ir() {
        let adapter = NapiAdapter::new();

        let body = FunctionBody {
            name: "mixed_napi_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%env".to_string()),
                    operands: vec!["i8*".to_string()],
                    callee: Some("napi_get_cb_info".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%env = call i8* @napi_get_cb_info()".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%result".to_string()),
                    operands: vec!["i8*".to_string(), "i8*".to_string()],
                    callee: Some("napi_call_function".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%result = call i8* @napi_call_function(i8* %env, i8* %cb)"
                        .to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: None,
                    operands: vec!["i8*".to_string(), "i8*".to_string()],
                    callee: Some("napi_throw_error".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "call void @napi_throw_error(i8* %env, i8* %msg)".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Ret,
                    dest: None,
                    operands: vec![],
                    callee: None,
                    raw_text: "ret void".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                    atomic_op: None,
                    icmp_pred: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("mixed_napi_function", Some(&body));

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiGetValue),
            "napi_get_cb_info must be detected from IR body"
        );
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiCallFunction),
            "napi_call_function must be detected from IR body"
        );
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiThrowError),
            "napi_throw_error must be detected from IR body"
        );

        // No resource management → SafeInternal
        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::SafeInternal,
            "Mixed N-API without resource management must be SafeInternal"
        );
    }

    /// Objective: Verify unknown function analysis
    /// Invariants: Unrecognized functions must have empty patterns and Unknown safety
    #[test]
    fn test_unknown_function() {
        let adapter = NapiAdapter::new();
        let analysis = adapter.analyze_function("some_unknown_function", None);

        assert!(
            analysis.patterns.is_empty(),
            "Unknown function must have no patterns, got {:?}",
            analysis.patterns
        );
        assert!(
            !analysis.is_napi_callback,
            "Unknown function must not be a callback"
        );
        assert!(
            !analysis.manages_references,
            "Unknown function must not manage references"
        );
        assert!(
            !analysis.manages_async_work,
            "Unknown function must not manage async work"
        );
        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::Unknown,
            "Unknown function must have Unknown safety"
        );
    }
}
