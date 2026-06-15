//! Node.js/napi language adapter for semantic analysis.
//!
//! Detects napi_* function call patterns from Node.js native addons and
//! identifies memory management patterns, reference cycles, and handle
//! scope violations.
//!
//! # N-API Memory Model
//!
//! Node.js N-API (node-addon-api) provides a C API for building native
//! addons. Key memory management concepts:
//!
//! - **Handle scopes**: `napi_open_handle_scope` / `napi_close_handle_scope`
//!   manage local reference lifetimes. Unclosed scopes cause memory leaks.
//! - **References**: `napi_create_reference` / `napi_delete_reference`
//!   manage persistent references. Unreleased references prevent GC.
//! - **Object wrapping**: `napi_wrap` links a C++ instance to a JS object.
//!   Must be paired with a finalizer or `napi_remove_wrap`.
//! - **Async work**: `napi_create_async_work` must be paired with
//!   `napi_delete_async_work` to avoid leaking native resources.

use omniscope_ir::{FunctionBody, IRInstructionKind};
use omniscope_types::Language;

use crate::resource::semantic_tree::{
    FactConfidence, FactSource, SemanticFact, SemanticKey, SemanticKind,
};

/// Node.js/napi-specific semantic patterns derived from IR analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NapiSemanticPattern {
    /// napi value creation (napi_create_string_utf8, napi_create_object, etc.)
    NapiValueCreation,
    /// napi buffer/arraybuffer creation (napi_create_buffer, napi_create_arraybuffer)
    NapiBufferCreation,
    /// napi function call (napi_call_function)
    NapiFunctionCall,
    /// napi handle scope open (napi_open_handle_scope)
    NapiHandleScopeOpen,
    /// napi handle scope close (napi_close_handle_scope)
    NapiHandleScopeClose,
    /// napi reference creation (napi_create_reference)
    NapiReferenceCreate,
    /// napi reference deletion (napi_delete_reference)
    NapiReferenceDelete,
    /// napi object wrap (napi_wrap)
    NapiObjectWrap,
    /// napi object unwrap (napi_unwrap)
    NapiObjectUnwrap,
    /// napi async work (napi_create_async_work)
    NapiAsyncWorkCreate,
    /// napi async work deletion (napi_delete_async_work)
    NapiAsyncWorkDelete,
    /// napi callback registration (napi_create_function, JS callback)
    NapiCallbackRegistration,
    /// napi property descriptor (napi_define_properties, napi_set_property)
    NapiPropertyAccess,
    /// napi type checking (napi_instanceof, napi_typeof)
    NapiTypeCheck,
    /// napi error/exception handling (napi_throw_error, napi_throw_type_error)
    NapiErrorHandling,
    /// napi environment lifecycle (napi_get_env, process exit)
    NapiEnvLifecycle,
    /// Unknown napi pattern
    Unknown,
}

/// Analysis result for a Node.js/napi function.
#[derive(Debug, Clone)]
pub struct NapiFunctionAnalysis {
    /// The function name analyzed
    pub function_name: String,
    /// Detected semantic patterns
    pub patterns: Vec<NapiSemanticPattern>,
    /// Whether this function creates references (potential leak if unbalanced)
    pub creates_references: bool,
    /// Whether this function deletes references
    pub deletes_references: bool,
    /// Whether this function manages handle scopes
    pub manages_handle_scopes: bool,
    /// Recommended FFI safety assessment
    pub ffi_safety: NapiFFISafety,
}

impl NapiFunctionAnalysis {
    /// Convert napi analysis results into SemanticFact records.
    pub fn to_semantic_facts(&self) -> Vec<SemanticFact> {
        let key = SemanticKey::Symbol(self.function_name.clone());
        let mut facts = Vec::new();

        for pattern in &self.patterns {
            match pattern {
                NapiSemanticPattern::NapiValueCreation => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::HeapProvenance,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("NodeAdapter: napi value creation in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiBufferCreation => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::HeapProvenance,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!(
                            "NodeAdapter: napi buffer creation in {}",
                            self.function_name
                        ),
                    ));
                }
                NapiSemanticPattern::NapiHandleScopeOpen
                | NapiSemanticPattern::NapiHandleScopeClose => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RuntimeManagedResource,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!(
                            "NodeAdapter: handle scope operation in {}",
                            self.function_name
                        ),
                    ));
                }
                NapiSemanticPattern::NapiReferenceCreate => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RuntimeManagedResource,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("NodeAdapter: reference creation in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiReferenceDelete => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RaiiDropRelease,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("NodeAdapter: reference deletion in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiObjectWrap => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::CppUniquePtr,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!("NodeAdapter: object wrap in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiAsyncWorkCreate => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RuntimeManagedResource,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("NodeAdapter: async work creation in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiAsyncWorkDelete => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RaiiDropRelease,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("NodeAdapter: async work deletion in {}", self.function_name),
                    ));
                }
                NapiSemanticPattern::NapiFunctionCall => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::DeclaredCrossBoundary,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!("NodeAdapter: napi function call in {}", self.function_name),
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
                    "NodeAdapter: FFI safety concern {:?} in {}",
                    self.ffi_safety, self.function_name
                ),
            ));
        }

        facts
    }
}

/// FFI safety assessment for Node.js/napi functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NapiFFISafety {
    /// Safe: no napi operations, pure computation
    SafeNoNapi,
    /// Safe: balanced handle scope usage
    SafeHandleScope,
    /// Safe: balanced reference management
    SafeReferenceManaged,
    /// Concern: unclosed handle scope (memory leak)
    ConcernUnclosedHandleScope,
    /// Concern: unreleased reference (memory leak)
    ConcernUnreleasedReference,
    /// Concern: object wrap without finalizer
    ConcernWrapWithoutFinalizer,
    /// Unknown: cannot determine safety
    Unknown,
}

impl NapiFFISafety {
    /// Returns true if this assessment indicates a safe pattern.
    ///
    /// # Objective
    /// Determine whether the FFI safety assessment indicates that the analyzed
    /// napi function is safe from memory safety perspective.
    ///
    /// # Invariants
    /// - `SafeNoNapi`, `SafeHandleScope`, and `SafeReferenceManaged` are safe.
    /// - All `Concern*` variants and `Unknown` are unsafe.
    ///
    /// # Returns
    /// `true` if the assessment indicates a safe pattern, `false` otherwise.
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            NapiFFISafety::SafeNoNapi
                | NapiFFISafety::SafeHandleScope
                | NapiFFISafety::SafeReferenceManaged
        )
    }

    /// Returns the safety score (0.0 = dangerous, 1.0 = safe).
    ///
    /// # Objective
    /// Provide a numeric safety score for risk assessment.
    ///
    /// # Invariants
    /// - Score range is always between 0.0 and 1.0.
    /// - Safe variants score >= 0.85.
    /// - Concern variants score <= 0.3.
    /// - Unknown scores exactly 0.5.
    ///
    /// # Returns
    /// A `f32` value between 0.0 and 1.0.
    pub fn safety_score(&self) -> f32 {
        match self {
            NapiFFISafety::SafeNoNapi => 0.95,
            NapiFFISafety::SafeHandleScope => 0.9,
            NapiFFISafety::SafeReferenceManaged => 0.85,
            NapiFFISafety::ConcernUnclosedHandleScope => 0.3,
            NapiFFISafety::ConcernUnreleasedReference => 0.2,
            NapiFFISafety::ConcernWrapWithoutFinalizer => 0.15,
            NapiFFISafety::Unknown => 0.5,
        }
    }
}

/// Node.js/napi adapter for semantic analysis.
///
/// This adapter provides napi-specific semantic analysis by combining
/// function name pattern matching with IR body instruction analysis.
pub struct NodeAdapter {
    /// Language hint for Node.js, used to identify the source language
    language: Language,
}

impl NodeAdapter {
    /// Creates a new Node.js adapter.
    ///
    /// # Objective
    /// Initialize the Node.js adapter with the correct language identifier
    /// for use in the semantic engine pipeline.
    ///
    /// # Invariants
    /// - Language is always set to `Language::NodeJs`.
    /// - The adapter is ready to use immediately after creation.
    ///
    /// # Returns
    /// A new `NodeAdapter` instance ready for semantic analysis.
    pub fn new() -> Self {
        Self {
            language: Language::NodeJs,
        }
    }

    /// Returns the language hint for this adapter.
    ///
    /// # Objective
    /// Provide the language identifier for this adapter.
    ///
    /// # Returns
    /// The `Language::NodeJs` enum variant.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Analyzes a Node.js/napi function from its IR body and name.
    ///
    /// # Objective
    /// Perform comprehensive semantic analysis of a napi function by
    /// combining function name pattern matching with IR instruction
    /// analysis. This determines memory management behavior and FFI
    /// safety assessment.
    ///
    /// # Invariants
    /// - The function name is always stored in the result.
    /// - Patterns from name and body are combined.
    /// - FFI safety assessment covers all detected patterns.
    ///
    /// # Arguments
    /// * `function_name` - The name of the function to analyze.
    /// * `body` - Optional IR body containing instruction-level data.
    ///
    /// # Returns
    /// A `NapiFunctionAnalysis` with all detected patterns and safety assessment.
    pub fn analyze_function(
        &self,
        function_name: &str,
        body: Option<&FunctionBody>,
    ) -> NapiFunctionAnalysis {
        // Collect all detected patterns from both name and IR body analysis
        let mut patterns = Vec::new();

        // Step 1: Analyze function name to detect napi patterns
        let name_patterns = self.analyze_function_name(function_name);
        patterns.extend(name_patterns);

        // Step 2: Analyze IR body for instruction-level evidence
        if let Some(body) = body {
            let body_patterns = self.analyze_function_body(body);
            patterns.extend(body_patterns);
        }

        // Step 3: Determine memory management flags
        let creates_references = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiReferenceCreate));
        let deletes_references = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiReferenceDelete));
        let manages_handle_scopes = patterns.iter().any(|p| {
            matches!(
                p,
                NapiSemanticPattern::NapiHandleScopeOpen
                    | NapiSemanticPattern::NapiHandleScopeClose
            )
        });

        // Step 4: Compute FFI safety assessment
        let ffi_safety = self.determine_ffi_safety(function_name, &patterns, body);

        // Assemble final analysis result
        NapiFunctionAnalysis {
            function_name: function_name.to_string(),
            patterns,
            creates_references,
            deletes_references,
            manages_handle_scopes,
            ffi_safety,
        }
    }

    /// Analyzes function name to detect napi semantic patterns.
    ///
    /// # Objective
    /// Detect napi-specific semantic patterns from the function name using
    /// prefix-based pattern matching.
    ///
    /// # Invariants
    /// - Functions starting with `napi_` are always detected as napi patterns.
    /// - Functions with `node_api_` prefix are also detected.
    ///
    /// # Arguments
    /// * `function_name` - The function name to analyze for napi patterns.
    ///
    /// # Returns
    /// A Vec of `NapiSemanticPattern` detected from the function name.
    fn analyze_function_name(&self, function_name: &str) -> Vec<NapiSemanticPattern> {
        let mut patterns = Vec::new();

        // Only process functions that look like napi functions
        if !function_name.starts_with("napi_") && !function_name.starts_with("node_api_") {
            return patterns;
        }

        // napi value creation functions
        if function_name.starts_with("napi_create_string")
            || function_name.starts_with("napi_create_object")
            || function_name.starts_with("napi_create_array")
            || function_name.starts_with("napi_create_function")
            || function_name.starts_with("napi_create_error")
            || function_name.starts_with("napi_create_symbol")
            || function_name.starts_with("napi_create_external")
            || function_name.starts_with("napi_create_dataview")
            || function_name.starts_with("napi_create_typedarray")
            || function_name.starts_with("napi_create_promise")
            || function_name.starts_with("napi_create_bigint")
            || function_name.starts_with("napi_create_date")
        {
            patterns.push(NapiSemanticPattern::NapiValueCreation);
        }

        // napi buffer/arraybuffer creation
        if function_name.starts_with("napi_create_buffer")
            || function_name.starts_with("napi_create_arraybuffer")
            || function_name.starts_with("napi_create_external_buffer")
        {
            patterns.push(NapiSemanticPattern::NapiBufferCreation);
        }

        // napi function calls
        if function_name.starts_with("napi_call_function") {
            patterns.push(NapiSemanticPattern::NapiFunctionCall);
        }

        // napi handle scope management
        if function_name.starts_with("napi_open_handle_scope") {
            patterns.push(NapiSemanticPattern::NapiHandleScopeOpen);
        }
        if function_name.starts_with("napi_close_handle_scope") {
            patterns.push(NapiSemanticPattern::NapiHandleScopeClose);
        }
        if function_name.starts_with("napi_open_escapable_handle_scope") {
            patterns.push(NapiSemanticPattern::NapiHandleScopeOpen);
        }
        if function_name.starts_with("napi_close_escapable_handle_scope") {
            patterns.push(NapiSemanticPattern::NapiHandleScopeClose);
        }

        // napi reference management
        if function_name.starts_with("napi_create_reference") {
            patterns.push(NapiSemanticPattern::NapiReferenceCreate);
        }
        if function_name.starts_with("napi_delete_reference") {
            patterns.push(NapiSemanticPattern::NapiReferenceDelete);
        }
        if function_name.starts_with("napi_reference_ref")
            || function_name.starts_with("napi_reference_unref")
        {
            patterns.push(NapiSemanticPattern::NapiReferenceCreate);
        }

        // napi object wrapping
        if function_name.starts_with("napi_wrap") {
            patterns.push(NapiSemanticPattern::NapiObjectWrap);
        }
        if function_name.starts_with("napi_unwrap") || function_name.starts_with("napi_remove_wrap")
        {
            patterns.push(NapiSemanticPattern::NapiObjectUnwrap);
        }

        // napi async work
        if function_name.starts_with("napi_create_async_work") {
            patterns.push(NapiSemanticPattern::NapiAsyncWorkCreate);
        }
        if function_name.starts_with("napi_delete_async_work") {
            patterns.push(NapiSemanticPattern::NapiAsyncWorkDelete);
        }
        if function_name.starts_with("napi_queue_async_work")
            || function_name.starts_with("napi_cancel_async_work")
        {
            // These are async work lifecycle operations
            patterns.push(NapiSemanticPattern::NapiAsyncWorkCreate);
        }

        // napi callback registration
        if function_name.starts_with("napi_create_function") {
            patterns.push(NapiSemanticPattern::NapiCallbackRegistration);
        }
        if function_name.starts_with("napi_get_cb_info")
            || function_name.starts_with("napi_get_new_target")
        {
            patterns.push(NapiSemanticPattern::NapiCallbackRegistration);
        }

        // napi property access
        if function_name.starts_with("napi_get_property")
            || function_name.starts_with("napi_set_property")
            || function_name.starts_with("napi_define_properties")
            || function_name.starts_with("napi_has_property")
            || function_name.starts_with("napi_delete_property")
            || function_name.starts_with("napi_get_named_property")
            || function_name.starts_with("napi_set_named_property")
        {
            patterns.push(NapiSemanticPattern::NapiPropertyAccess);
        }

        // napi type checking
        if function_name.starts_with("napi_typeof")
            || function_name.starts_with("napi_instanceof")
            || function_name.starts_with("napi_is_array")
            || function_name.starts_with("napi_is_error")
            || function_name.starts_with("napi_is_dataview")
            || function_name.starts_with("napi_is_typedarray")
            || function_name.starts_with("napi_is_promise")
            || function_name.starts_with("napi_is_external")
            || function_name.starts_with("napi_strict_equals")
        {
            patterns.push(NapiSemanticPattern::NapiTypeCheck);
        }

        // napi error handling
        if function_name.starts_with("napi_throw_error")
            || function_name.starts_with("napi_throw_type_error")
            || function_name.starts_with("napi_throw_range_error")
            || function_name.starts_with("napi_is_error")
        {
            patterns.push(NapiSemanticPattern::NapiErrorHandling);
        }

        // napi environment lifecycle
        if function_name.starts_with("napi_get_env")
            || function_name.starts_with("napi_get_global")
            || function_name.starts_with("napi_get_undefined")
            || function_name.starts_with("napi_get_null")
            || function_name.starts_with("napi_get_boolean")
            || function_name.starts_with("napi_run_script")
            || function_name.starts_with("napi_get_version")
            || function_name.starts_with("napi_get_node_version")
        {
            patterns.push(NapiSemanticPattern::NapiEnvLifecycle);
        }

        patterns
    }

    /// Analyzes function body to detect napi patterns from IR instructions.
    ///
    /// # Objective
    /// Scan IR instructions within a function body to detect napi-specific
    /// semantic patterns by examining call instruction callees.
    ///
    /// # Invariants
    /// - Only `Call` instructions are analyzed.
    /// - Each callee is checked against known napi patterns.
    ///
    /// # Arguments
    /// * `body` - The IR function body containing instructions to analyze.
    ///
    /// # Returns
    /// A Vec of `NapiSemanticPattern` detected from IR instructions.
    fn analyze_function_body(&self, body: &FunctionBody) -> Vec<NapiSemanticPattern> {
        let mut patterns = Vec::new();

        // Scan all instructions for call patterns that indicate napi usage
        for instruction in &body.instructions {
            if let IRInstructionKind::Call = instruction.kind {
                if let Some(ref callee) = instruction.callee {
                    // napi value creation
                    if callee.starts_with("napi_create_string")
                        || callee.starts_with("napi_create_object")
                        || callee.starts_with("napi_create_array")
                        || callee.starts_with("napi_create_function")
                        || callee.starts_with("napi_create_error")
                        || callee.starts_with("napi_create_symbol")
                        || callee.starts_with("napi_create_external")
                        || callee.starts_with("napi_create_dataview")
                        || callee.starts_with("napi_create_typedarray")
                        || callee.starts_with("napi_create_promise")
                        || callee.starts_with("napi_create_bigint")
                        || callee.starts_with("napi_create_date")
                    {
                        patterns.push(NapiSemanticPattern::NapiValueCreation);
                    }
                    // napi buffer creation
                    else if callee.starts_with("napi_create_buffer")
                        || callee.starts_with("napi_create_arraybuffer")
                        || callee.starts_with("napi_create_external_buffer")
                    {
                        patterns.push(NapiSemanticPattern::NapiBufferCreation);
                    }
                    // napi handle scope
                    else if callee.starts_with("napi_open_handle_scope")
                        || callee.starts_with("napi_open_escapable_handle_scope")
                    {
                        patterns.push(NapiSemanticPattern::NapiHandleScopeOpen);
                    } else if callee.starts_with("napi_close_handle_scope")
                        || callee.starts_with("napi_close_escapable_handle_scope")
                    {
                        patterns.push(NapiSemanticPattern::NapiHandleScopeClose);
                    }
                    // napi reference management
                    else if callee.starts_with("napi_create_reference")
                        || callee.starts_with("napi_reference_ref")
                    {
                        patterns.push(NapiSemanticPattern::NapiReferenceCreate);
                    } else if callee.starts_with("napi_delete_reference")
                        || callee.starts_with("napi_reference_unref")
                    {
                        patterns.push(NapiSemanticPattern::NapiReferenceDelete);
                    }
                    // napi object wrapping
                    else if callee.starts_with("napi_wrap") {
                        patterns.push(NapiSemanticPattern::NapiObjectWrap);
                    } else if callee.starts_with("napi_unwrap")
                        || callee.starts_with("napi_remove_wrap")
                    {
                        patterns.push(NapiSemanticPattern::NapiObjectUnwrap);
                    }
                    // napi async work
                    else if callee.starts_with("napi_create_async_work")
                        || callee.starts_with("napi_queue_async_work")
                    {
                        patterns.push(NapiSemanticPattern::NapiAsyncWorkCreate);
                    } else if callee.starts_with("napi_delete_async_work")
                        || callee.starts_with("napi_cancel_async_work")
                    {
                        patterns.push(NapiSemanticPattern::NapiAsyncWorkDelete);
                    }
                    // napi callback
                    else if callee.starts_with("napi_create_function") {
                        patterns.push(NapiSemanticPattern::NapiCallbackRegistration);
                    }
                    // napi function call
                    else if callee.starts_with("napi_call_function") {
                        patterns.push(NapiSemanticPattern::NapiFunctionCall);
                    }
                    // napi property
                    else if callee.starts_with("napi_get_property")
                        || callee.starts_with("napi_set_property")
                        || callee.starts_with("napi_define_properties")
                    {
                        patterns.push(NapiSemanticPattern::NapiPropertyAccess);
                    }
                    // napi type check
                    else if callee.starts_with("napi_typeof")
                        || callee.starts_with("napi_instanceof")
                        || callee.starts_with("napi_is_array")
                    {
                        patterns.push(NapiSemanticPattern::NapiTypeCheck);
                    }
                    // napi error handling
                    else if callee.starts_with("napi_throw_error")
                        || callee.starts_with("napi_throw_type_error")
                        || callee.starts_with("napi_throw_range_error")
                    {
                        patterns.push(NapiSemanticPattern::NapiErrorHandling);
                    }
                    // napi environment
                    else if callee.starts_with("napi_get_global")
                        || callee.starts_with("napi_get_undefined")
                        || callee.starts_with("napi_run_script")
                        || callee.starts_with("napi_get_version")
                    {
                        patterns.push(NapiSemanticPattern::NapiEnvLifecycle);
                    }
                }
            }
        }

        patterns
    }

    /// Determines FFI safety for a napi function based on detected patterns.
    ///
    /// # Objective
    /// Compute the FFI safety assessment by analyzing the combination of
    /// detected patterns. This detects potential memory leaks in napi
    /// native addon functions.
    ///
    /// # Invariants
    /// - Balanced handle scope open/close indicates `SafeHandleScope`.
    /// - Balanced reference create/delete indicates `SafeReferenceManaged`.
    /// - Handle scope open without close indicates `ConcernUnclosedHandleScope`.
    /// - Reference create without delete indicates `ConcernUnreleasedReference`.
    /// - Object wrap without unwrap indicates `ConcernWrapWithoutFinalizer`.
    /// - No napi patterns returns `SafeNoNapi`.
    ///
    /// # Arguments
    /// * `_function_name` - The function name (reserved for heuristic analysis).
    /// * `patterns` - The detected napi semantic patterns.
    /// * `_body` - Optional IR body (reserved for future analysis).
    ///
    /// # Returns
    /// A `NapiFFISafety` assessment for the function.
    fn determine_ffi_safety(
        &self,
        _function_name: &str,
        patterns: &[NapiSemanticPattern],
        _body: Option<&FunctionBody>,
    ) -> NapiFFISafety {
        // Priority 1: Handle scope leak detection
        let has_scope_open = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiHandleScopeOpen));
        let has_scope_close = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiHandleScopeClose));

        if has_scope_open && !has_scope_close {
            return NapiFFISafety::ConcernUnclosedHandleScope;
        }

        // Priority 2: Reference leak detection
        let has_ref_create = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiReferenceCreate));
        let has_ref_delete = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiReferenceDelete));

        if has_ref_create && !has_ref_delete {
            return NapiFFISafety::ConcernUnreleasedReference;
        }

        // Priority 3: Object wrap without cleanup
        let has_wrap = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiObjectWrap));
        let has_unwrap = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiObjectUnwrap));

        if has_wrap && !has_unwrap {
            return NapiFFISafety::ConcernWrapWithoutFinalizer;
        }

        // Priority 4: Balanced patterns
        if has_scope_open && has_scope_close {
            return NapiFFISafety::SafeHandleScope;
        }
        if has_ref_create && has_ref_delete {
            return NapiFFISafety::SafeReferenceManaged;
        }

        // Priority 5: No napi patterns
        if patterns.is_empty() {
            return NapiFFISafety::SafeNoNapi;
        }

        // Default: insufficient information
        NapiFFISafety::Unknown
    }

    /// Detects potential memory leak in async work.
    ///
    /// # Objective
    /// Check if async work is created but not deleted, which would
    /// cause a native resource leak.
    ///
    /// # Arguments
    /// * `patterns` - The detected napi semantic patterns.
    ///
    /// # Returns
    /// `true` if async work leak is detected, `false` otherwise.
    pub fn detect_async_work_leak(&self, patterns: &[NapiSemanticPattern]) -> bool {
        let has_create = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiAsyncWorkCreate));
        let has_delete = patterns
            .iter()
            .any(|p| matches!(p, NapiSemanticPattern::NapiAsyncWorkDelete));
        has_create && !has_delete
    }
}

impl Default for NodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

    /// Objective: Verify napi value creation detection from function name
    /// Invariants: napi_create_* functions must be detected as NapiValueCreation
    #[test]
    fn test_napi_value_creation_detection() {
        let adapter = NodeAdapter::new();
        let analysis = adapter.analyze_function("napi_create_string_utf8", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiValueCreation),
            "napi_create_string_utf8 must be detected as NapiValueCreation"
        );
    }

    /// Objective: Verify napi buffer creation detection
    /// Invariants: napi_create_buffer must be detected as NapiBufferCreation
    #[test]
    fn test_napi_buffer_creation_detection() {
        let adapter = NodeAdapter::new();
        let analysis = adapter.analyze_function("napi_create_buffer", None);

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiBufferCreation),
            "napi_create_buffer must be detected as NapiBufferCreation"
        );
    }

    /// Objective: Verify handle scope detection
    /// Invariants: napi_open_handle_scope / napi_close_handle_scope must be detected
    #[test]
    fn test_handle_scope_detection() {
        let adapter = NodeAdapter::new();

        let analysis = adapter.analyze_function("napi_open_handle_scope", None);
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiHandleScopeOpen),
            "napi_open_handle_scope must be detected as NapiHandleScopeOpen"
        );

        let analysis = adapter.analyze_function("napi_close_handle_scope", None);
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiHandleScopeClose),
            "napi_close_handle_scope must be detected as NapiHandleScopeClose"
        );
    }

    /// Objective: Verify reference management detection
    /// Invariants: napi_create_reference / napi_delete_reference must be detected
    #[test]
    fn test_reference_management_detection() {
        let adapter = NodeAdapter::new();

        let analysis = adapter.analyze_function("napi_create_reference", None);
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiReferenceCreate),
            "napi_create_reference must be detected as NapiReferenceCreate"
        );
        assert!(
            analysis.creates_references,
            "napi_create_reference must set creates_references"
        );

        let analysis = adapter.analyze_function("napi_delete_reference", None);
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiReferenceDelete),
            "napi_delete_reference must be detected as NapiReferenceDelete"
        );
        assert!(
            analysis.deletes_references,
            "napi_delete_reference must set deletes_references"
        );
    }

    /// Objective: Verify object wrap detection
    /// Invariants: napi_wrap must be detected as NapiObjectWrap
    #[test]
    fn test_object_wrap_detection() {
        let adapter = NodeAdapter::new();

        let analysis = adapter.analyze_function("napi_wrap", None);
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiObjectWrap),
            "napi_wrap must be detected as NapiObjectWrap"
        );

        let analysis = adapter.analyze_function("napi_unwrap", None);
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiObjectUnwrap),
            "napi_unwrap must be detected as NapiObjectUnwrap"
        );
    }

    /// Objective: Verify unclosed handle scope leak detection
    /// Invariants: Only open_handle_scope without close must be ConcernUnclosedHandleScope
    #[test]
    fn test_unclosed_handle_scope_leak() {
        let adapter = NodeAdapter::new();
        let analysis = adapter.analyze_function("napi_open_handle_scope", None);

        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::ConcernUnclosedHandleScope,
            "Unclosed handle scope must be ConcernUnclosedHandleScope"
        );
    }

    /// Objective: Verify unreleased reference leak detection
    /// Invariants: Only create_reference without delete must be ConcernUnreleasedReference
    #[test]
    fn test_unreleased_reference_leak() {
        let adapter = NodeAdapter::new();
        let analysis = adapter.analyze_function("napi_create_reference", None);

        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::ConcernUnreleasedReference,
            "Unreleased reference must be ConcernUnreleasedReference"
        );
    }

    /// Objective: Verify balanced handle scope is safe
    /// Invariants: Both open and close handle scope must be SafeHandleScope
    #[test]
    fn test_balanced_handle_scope() {
        let adapter = NodeAdapter::new();
        let mut analysis = adapter.analyze_function("napi_open_handle_scope", None);
        analysis
            .patterns
            .push(NapiSemanticPattern::NapiHandleScopeClose);

        let ffi_safety =
            adapter.determine_ffi_safety("napi_open_handle_scope", &analysis.patterns, None);

        assert_eq!(
            ffi_safety,
            NapiFFISafety::SafeHandleScope,
            "Balanced handle scope must be SafeHandleScope"
        );
    }

    /// Objective: Verify balanced reference management is safe
    /// Invariants: Both create and delete reference must be SafeReferenceManaged
    #[test]
    fn test_balanced_reference_management() {
        let adapter = NodeAdapter::new();
        let mut analysis = adapter.analyze_function("napi_create_reference", None);
        analysis
            .patterns
            .push(NapiSemanticPattern::NapiReferenceDelete);

        let ffi_safety =
            adapter.determine_ffi_safety("napi_create_reference", &analysis.patterns, None);

        assert_eq!(
            ffi_safety,
            NapiFFISafety::SafeReferenceManaged,
            "Balanced reference management must be SafeReferenceManaged"
        );
    }

    /// Objective: Verify regular function without napi patterns is safe
    /// Invariants: Non-napi function must have SafeNoNapi and empty patterns
    #[test]
    fn test_non_napi_function() {
        let adapter = NodeAdapter::new();
        let analysis = adapter.analyze_function("my_custom_function", None);

        assert!(
            analysis.patterns.is_empty(),
            "Non-napi function must have no patterns"
        );
        assert!(
            !analysis.creates_references,
            "Non-napi function must not create references"
        );
        assert!(
            !analysis.manages_handle_scopes,
            "Non-napi function must not manage handle scopes"
        );
        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::SafeNoNapi,
            "Non-napi function must be SafeNoNapi"
        );
    }

    /// Objective: Verify async work leak detection
    /// Invariants: Created async work without deletion must be detected as leak
    #[test]
    fn test_async_work_leak_detection() {
        let adapter = NodeAdapter::new();

        // Only create, no delete
        let analysis = adapter.analyze_function("napi_create_async_work", None);
        assert!(
            adapter.detect_async_work_leak(&analysis.patterns),
            "Async work without deletion must be detected as leak"
        );

        // Balanced create and delete
        let patterns = vec![
            NapiSemanticPattern::NapiAsyncWorkCreate,
            NapiSemanticPattern::NapiAsyncWorkDelete,
        ];
        assert!(
            !adapter.detect_async_work_leak(&patterns),
            "Async work with deletion must not be detected as leak"
        );
    }

    /// Objective: Verify napi function call semantics using embedded IR
    /// Invariants: napi call patterns in IR body must be detected
    #[test]
    fn test_napi_call_semantics_with_ir() {
        let adapter = NodeAdapter::new();

        let body = FunctionBody {
            name: "test_napi_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%env".to_string()),
                    operands: vec![],
                    callee: Some("napi_get_global".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%env = call i8* @napi_get_global()".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%str".to_string()),
                    operands: vec!["i8*".to_string(), "%env".to_string(), "i8*".to_string()],
                    callee: Some("napi_create_string_utf8".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%str = call i8* @napi_create_string_utf8(i8* %env, i8* %input)"
                        .to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Ret,
                    dest: None,
                    operands: vec!["i8* %str".to_string()],
                    callee: None,
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "ret i8* %str".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("test_napi_function", Some(&body));

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiValueCreation),
            "napi_create_string_utf8 must be detected from IR body"
        );
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiEnvLifecycle),
            "napi_get_global must be detected from IR body"
        );
    }

    /// Objective: Verify SemanticFact conversion for napi patterns
    /// Invariants: napi patterns must produce correct SemanticFacts
    #[test]
    fn test_napi_semantic_facts() {
        let adapter = NodeAdapter::new();

        // Value creation produces HeapProvenance fact
        let analysis = adapter.analyze_function("napi_create_string_utf8", None);
        let facts = analysis.to_semantic_facts();
        let has_value_fact = facts.iter().any(|f| {
            f.kind == SemanticKind::HeapProvenance
                && f.confidence == FactConfidence::High
                && f.source == FactSource::LanguageAdapter
        });
        assert!(
            has_value_fact,
            "napi value creation must produce HeapProvenance fact"
        );

        // Reference creation produces RuntimeManagedResource fact
        let analysis = adapter.analyze_function("napi_create_reference", None);
        let facts = analysis.to_semantic_facts();
        let has_ref_fact = facts.iter().any(|f| {
            f.kind == SemanticKind::RuntimeManagedResource
                && f.confidence == FactConfidence::High
                && f.source == FactSource::LanguageAdapter
        });
        assert!(
            has_ref_fact,
            "napi_create_reference must produce RuntimeManagedResource fact"
        );

        // Reference deletion produces RaiiDropRelease fact
        let analysis = adapter.analyze_function("napi_delete_reference", None);
        let facts = analysis.to_semantic_facts();
        let has_delete_fact = facts.iter().any(|f| {
            f.kind == SemanticKind::RaiiDropRelease
                && f.confidence == FactConfidence::High
                && f.source == FactSource::LanguageAdapter
        });
        assert!(
            has_delete_fact,
            "napi_delete_reference must produce RaiiDropRelease fact"
        );
    }

    /// Objective: Verify object wrap without cleanup detection
    /// Invariants: napi_wrap without napi_unwrap must be ConcernWrapWithoutFinalizer
    #[test]
    fn test_object_wrap_without_cleanup() {
        let adapter = NodeAdapter::new();
        let analysis = adapter.analyze_function("napi_wrap", None);

        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::ConcernWrapWithoutFinalizer,
            "napi_wrap without napi_remove_wrap must be ConcernWrapWithoutFinalizer"
        );
    }

    /// Objective: Verify napi adapter creation
    /// Invariants: Adapter must be created with correct language setting
    #[test]
    fn test_node_adapter_creation() {
        let adapter = NodeAdapter::new();
        assert_eq!(
            adapter.language(),
            Language::NodeJs,
            "Node adapter must have NodeJs language setting"
        );
    }

    /// Objective: Verify safety score correctness
    /// Invariants: Safe patterns must have higher scores than concerning patterns
    #[test]
    fn test_ffi_safety_scores() {
        assert!(
            NapiFFISafety::SafeNoNapi.safety_score() > NapiFFISafety::Unknown.safety_score(),
            "SafeNoNapi must have higher score than Unknown"
        );
        assert!(
            NapiFFISafety::SafeHandleScope.safety_score()
                > NapiFFISafety::ConcernUnclosedHandleScope.safety_score(),
            "SafeHandleScope must have higher score than ConcernUnclosedHandleScope"
        );
        assert!(
            NapiFFISafety::ConcernUnreleasedReference.safety_score()
                < NapiFFISafety::Unknown.safety_score(),
            "ConcernUnreleasedReference must have lower score than Unknown"
        );
    }

    /// Objective: Verify function with handle scope and reference management
    /// Invariants: Balanced scope and reference is properly assessed
    #[test]
    fn test_mixed_napi_patterns() {
        let adapter = NodeAdapter::new();

        use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

        let body = FunctionBody {
            name: "test_mixed_napi".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%scope".to_string()),
                    operands: vec!["i8*".to_string(), "%env".to_string()],
                    callee: Some("napi_open_handle_scope".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%scope = call i8* @napi_open_handle_scope(i8* %env)".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%val".to_string()),
                    operands: vec!["i8*".to_string(), "%env".to_string(), "i8*".to_string()],
                    callee: Some("napi_create_string_utf8".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%val = call i8* @napi_create_string_utf8(i8* %env, i8* %input)"
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
                    operands: vec!["i8*".to_string(), "%env".to_string(), "%scope".to_string()],
                    callee: Some("napi_close_handle_scope".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "call void @napi_close_handle_scope(i8* %env, i8* %scope)"
                        .to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Ret,
                    dest: None,
                    operands: vec!["i8* %val".to_string()],
                    callee: None,
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "ret i8* %val".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("test_mixed_napi", Some(&body));

        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiHandleScopeOpen),
            "Handle scope open must be detected"
        );
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiHandleScopeClose),
            "Handle scope close must be detected"
        );
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiValueCreation),
            "Value creation must be detected"
        );
        assert!(
            analysis.manages_handle_scopes,
            "Function must manage handle scopes"
        );
        assert_eq!(
            analysis.ffi_safety,
            NapiFFISafety::SafeHandleScope,
            "Balanced handle scope must be SafeHandleScope"
        );
    }

    /// Objective: Verify escapable handle scope detection
    /// Invariants: Escapable handle scope functions must be detected
    #[test]
    fn test_escapable_handle_scope_detection() {
        let adapter = NodeAdapter::new();

        let analysis = adapter.analyze_function("napi_open_escapable_handle_scope", None);
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiHandleScopeOpen),
            "napi_open_escapable_handle_scope must be detected as NapiHandleScopeOpen"
        );

        let analysis = adapter.analyze_function("napi_close_escapable_handle_scope", None);
        assert!(
            analysis
                .patterns
                .contains(&NapiSemanticPattern::NapiHandleScopeClose),
            "napi_close_escapable_handle_scope must be detected as NapiHandleScopeClose"
        );
    }
}
