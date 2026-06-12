//! WebAssembly/JavaScript FFI language adapter for semantic analysis.
//!
//! Provides WASM/JS-specific semantic analysis for linear memory management,
//! JS import/export wrappers, Emscripten runtime functions, emval operations,
//! and asyncify patterns. This adapter handles the unique FFI patterns
//! that arise when WebAssembly modules interact with JavaScript hosts.

use omniscope_ir::{FunctionBody, IRInstructionKind};
use omniscope_types::Language;

use crate::resource::semantic_tree::{
    FactConfidence, FactSource, SemanticFact, SemanticKey, SemanticKind,
};

/// WASM/JS-specific semantic patterns derived from IR analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasSemanticPattern {
    /// WASM linear memory allocation (malloc/free in WASM).
    /// Memory allocated from the WASM linear memory region via dlmalloc or similar.
    WasmLinearMemory,
    /// JavaScript call wrapper (EM_JS, EM_ASM).
    /// Inline JavaScript code embedded in C/C++ via Emscripten macros.
    JsCallWrapper,
    /// JS import function (WebAssembly.import).
    /// A function imported from the JavaScript environment into the WASM module.
    JsImportFunction,
    /// JS export function (WebAssembly.export).
    /// A function exported from the WASM module for JavaScript consumption.
    JsExportFunction,
    /// Emscripten runtime function (emscripten_*).
    /// Runtime management functions provided by the Emscripten toolchain.
    EmscriptenRuntime,
    /// emval operation (emscripten_val_*).
    /// Operations that manage JavaScript values from WASM via the emval library.
    EmvalOperation,
    /// WASM global variable set.
    /// Setting a WASM global variable, often used for JS/WASM communication.
    WasmGlobalSet,
    /// WASM function table set.
    /// Modifying the WASM function table (indirect call table).
    WasmTableSet,
    /// Asyncify operation (async to sync conversion).
    /// Emscripten asyncify transformations for async JS calls from sync WASM.
    AsyncifyOperation,
    /// WASM memory.grow operation.
    /// Expanding the WASM linear memory size.
    MemoryGrow,
    /// Unknown WASM/JS pattern.
    Unknown,
}

/// Analysis result for a WASM/JS function.
#[derive(Debug, Clone)]
pub struct WasFunctionAnalysis {
    /// The function name analyzed.
    pub function_name: String,
    /// Detected semantic patterns.
    pub patterns: Vec<WasSemanticPattern>,
    /// Whether this function is a JS FFI boundary.
    pub is_js_ffi_boundary: bool,
    /// Whether this function manages WASM linear memory.
    pub manages_wasm_memory: bool,
    /// Recommended FFI safety assessment.
    pub ffi_safety: WasFFISafety,
}

impl WasFunctionAnalysis {
    /// Convert WASM/JS analysis results into SemanticFact records.
    ///
    /// Maps WASM-specific patterns (linear memory, JS wrappers, Emscripten
    /// runtime, emval operations) to SemanticKind variants for unified
    /// downstream consumption.
    pub fn to_semantic_facts(&self) -> Vec<SemanticFact> {
        let key = SemanticKey::Symbol(self.function_name.clone());
        let mut facts = Vec::new();

        for pattern in &self.patterns {
            match pattern {
                WasSemanticPattern::WasmLinearMemory => {
                    // WASM linear memory allocations come from dlmalloc or similar
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::WasmMemoryAlloc,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("WasAdapter: linear memory op in {}", self.function_name),
                    ));
                }
                WasSemanticPattern::JsCallWrapper => {
                    // EM_JS / EM_ASM inline JS wrappers cross the WASM-JS boundary
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::DeclaredCrossBoundary,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("WasAdapter: JS call wrapper in {}", self.function_name),
                    ));
                }
                WasSemanticPattern::JsImportFunction => {
                    // Functions imported from JS via WebAssembly.import
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::JsImportWrapper,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("WasAdapter: JS import in {}", self.function_name),
                    ));
                }
                WasSemanticPattern::JsExportFunction => {
                    // Functions exported to JS via WebAssembly.export
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::JsExportWrapper,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("WasAdapter: JS export in {}", self.function_name),
                    ));
                }
                WasSemanticPattern::EmscriptenRuntime => {
                    // Emscripten runtime management functions
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::EmScriptenRuntimeOp,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("WasAdapter: Emscripten runtime in {}", self.function_name),
                    ));
                }
                WasSemanticPattern::EmvalOperation => {
                    // emval handles for JS value management
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::EmvalHandle,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("WasAdapter: emval operation in {}", self.function_name),
                    ));
                }
                WasSemanticPattern::WasmGlobalSet => {
                    // WASM global variable set — runtime-managed
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RuntimeManagedResource,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!("WasAdapter: global set in {}", self.function_name),
                    ));
                }
                WasSemanticPattern::WasmTableSet => {
                    // WASM table modification — FFI boundary operation
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::DeclaredCrossBoundary,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!("WasAdapter: table set in {}", self.function_name),
                    ));
                }
                WasSemanticPattern::AsyncifyOperation => {
                    // Asyncify operations convert async JS to sync WASM
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RuntimeInternal,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("WasAdapter: asyncify op in {}", self.function_name),
                    ));
                }
                WasSemanticPattern::MemoryGrow => {
                    // WASM memory.grow — runtime-managed memory expansion
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RuntimeManagedResource,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!("WasAdapter: memory grow in {}", self.function_name),
                    ));
                }
                WasSemanticPattern::Unknown => {
                    // Unknown pattern — no fact emitted
                }
            }
        }

        if !self.ffi_safety.is_safe() {
            facts.push(SemanticFact::new(
                key,
                SemanticKind::Unknown,
                FactConfidence::Low,
                FactSource::LanguageAdapter,
                format!(
                    "WasAdapter: FFI safety concern {:?} in {}",
                    self.ffi_safety, self.function_name
                ),
            ));
        }

        facts
    }
}

/// FFI safety assessment for WASM/JS functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasFFISafety {
    /// Safe: pure WASM internal function, no JS boundary interaction.
    SafeInternal,
    /// Safe: JS boundary interaction with proper memory management.
    SafeJsBoundary,
    /// Concern: WASM memory ownership transfer without clear lifecycle.
    ConcernMemoryOwnership,
    /// Concern: emval resources may leak (missing val_decref or similar).
    ConcernEmvalLeak,
    /// Unknown: cannot determine safety.
    Unknown,
}

impl WasFFISafety {
    /// Returns true if this assessment indicates a safe pattern.
    ///
    /// # Objective
    /// Determine whether the FFI safety assessment indicates that the analyzed
    /// WASM function is safe from a memory safety perspective. This is used to
    /// filter out false positives in WASM/JS FFI analysis.
    ///
    /// # Invariants
    /// - `SafeInternal` and `SafeJsBoundary` are considered safe.
    /// - All `Concern*` variants and `Unknown` are considered unsafe.
    /// - The result is deterministic for a given variant.
    ///
    /// # Returns
    /// `true` if the assessment indicates a safe pattern, `false` otherwise.
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            WasFFISafety::SafeInternal | WasFFISafety::SafeJsBoundary
        )
    }

    /// Returns the safety score (0.0 = dangerous, 1.0 = safe).
    ///
    /// # Objective
    /// Provide a numeric safety score for risk assessment and comparison.
    /// Higher scores indicate safer patterns. The scores are calibrated based
    /// on the severity of potential memory safety issues in each category.
    ///
    /// # Invariants
    /// - Score range is always between 0.0 and 1.0.
    /// - Safe variants score >= 0.85.
    /// - Concern variants score <= 0.3.
    /// - Unknown scores exactly 0.5 (neutral).
    ///
    /// # Returns
    /// A `f32` value between 0.0 (dangerous) and 1.0 (safe).
    pub fn safety_score(&self) -> f32 {
        match self {
            // SafeInternal: pure WASM code with no JS boundary concerns
            WasFFISafety::SafeInternal => 0.95,
            // SafeJsBoundary: JS boundary with proper memory management
            WasFFISafety::SafeJsBoundary => 0.85,
            // ConcernMemoryOwnership: potential memory leak in WASM linear memory
            WasFFISafety::ConcernMemoryOwnership => 0.3,
            // ConcernEmvalLeak: emval resources without proper cleanup
            WasFFISafety::ConcernEmvalLeak => 0.2,
            // Unknown: insufficient information for assessment
            WasFFISafety::Unknown => 0.5,
        }
    }
}

/// WASM/JS adapter for semantic analysis.
///
/// This adapter provides WASM/JS-specific semantic analysis by combining
/// function name pattern matching with IR body instruction analysis.
/// It detects Emscripten runtime functions, JS import/export wrappers,
/// linear memory operations, emval operations, and asyncify patterns.
///
/// # WASM Memory Model
///
/// WebAssembly uses a linear memory model where memory is a contiguous
/// array of bytes. This creates unique FFI patterns:
///
/// 1. **Linear memory allocation**: WASM modules often include a bundled
///    malloc/free implementation (dlmalloc) operating on the linear memory.
/// 2. **JS import/export wrappers**: Functions imported from or exported to
///    JavaScript form the WASM-JS FFI boundary.
/// 3. **Emscripten runtime**: The Emscripten toolchain adds runtime functions
///    (emscripten_*) for memory management, stack operations, etc.
/// 4. **emval operations**: Emscripten's emval library manages JavaScript
///    values from WASM code, creating resource handle concerns.
/// 5. **Asyncify**: Emscripten's asyncify transforms async JS calls into
///    synchronous WASM operations.
pub struct WasAdapter {
    /// Language hint, used to identify the source language context.
    language: Language,
}

impl WasAdapter {
    /// Creates a new WASM adapter.
    ///
    /// # Objective
    /// Initialize the WASM adapter with a language hint for use in the
    /// semantic engine pipeline.
    ///
    /// # Invariants
    /// - Language is set to `Language::Unknown` since WASM is a compilation
    ///   target and the source language is determined by other means.
    /// - The adapter is ready to use immediately after creation.
    ///
    /// # Returns
    /// A new `WasAdapter` instance ready for semantic analysis.
    pub fn new() -> Self {
        Self {
            language: Language::Unknown,
        }
    }

    /// Returns the language hint for this adapter.
    ///
    /// # Objective
    /// Provide the language identifier for this adapter. WASM modules can
    /// be compiled from many source languages, so the hint is `Unknown`.
    ///
    /// # Invariants
    /// - Always returns `Language::Unknown`.
    /// - The value never changes after adapter creation.
    ///
    /// # Returns
    /// The `Language::Unknown` enum variant.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Analyzes a WASM/JS function from its IR body and name.
    ///
    /// # Objective
    /// Perform comprehensive semantic analysis of a WASM/JS function by
    /// combining function name pattern matching with IR instruction
    /// analysis. This determines the function's memory management
    /// behavior and FFI safety assessment.
    ///
    /// # Invariants
    /// - The function name is always stored in the result.
    /// - Patterns from name and body are combined (not deduplicated).
    /// - JS FFI boundary detection is always performed.
    /// - WASM linear memory management flag is always computed.
    /// - FFI safety assessment covers all detected patterns.
    ///
    /// # Arguments
    /// * `function_name` - The name of the WASM/JS function to analyze.
    /// * `body` - Optional IR body containing instruction-level analysis data.
    ///
    /// # Returns
    /// A `WasFunctionAnalysis` containing all detected patterns and safety assessment.
    pub fn analyze_function(
        &self,
        function_name: &str,
        body: Option<&FunctionBody>,
    ) -> WasFunctionAnalysis {
        // Collect all detected patterns from both name and IR body analysis
        let mut patterns = Vec::new();

        // Step 1: Analyze function name to detect WASM/JS patterns
        // This is the primary detection mechanism for known function names
        let name_patterns = self.analyze_function_name(function_name);
        patterns.extend(name_patterns);

        // Step 2: Analyze IR body for instruction-level evidence
        // This complements name-based analysis with actual call targets
        if let Some(body) = body {
            let body_patterns = self.analyze_function_body(body);
            patterns.extend(body_patterns);
        }

        // Step 3: Determine if this is a JS FFI boundary from patterns
        let is_js_ffi_boundary = patterns.iter().any(|p| {
            matches!(
                p,
                WasSemanticPattern::JsCallWrapper
                    | WasSemanticPattern::JsImportFunction
                    | WasSemanticPattern::JsExportFunction
                    | WasSemanticPattern::WasmTableSet
            )
        });

        // Step 4: Determine memory management flag from collected patterns
        // WASM linear memory: malloc/free in WASM
        let manages_wasm_memory = patterns.iter().any(|p| {
            matches!(
                p,
                WasSemanticPattern::WasmLinearMemory | WasSemanticPattern::MemoryGrow
            )
        });

        // Step 5: Compute FFI safety assessment based on all evidence
        let ffi_safety = self.determine_ffi_safety(function_name, &patterns, body);

        // Assemble final analysis result
        WasFunctionAnalysis {
            function_name: function_name.to_string(),
            patterns,
            is_js_ffi_boundary,
            manages_wasm_memory,
            ffi_safety,
        }
    }

    /// Analyzes function name to detect WASM/JS semantic patterns.
    ///
    /// # Objective
    /// Detect WASM/JS-specific semantic patterns from the function name using
    /// prefix and substring pattern matching. This handles Emscripten runtime,
    /// emval, WASM memory, asyncify, and JS wrapper functions.
    ///
    /// # Invariants
    /// - Emscripten runtime functions are detected by the `emscripten_` prefix.
    /// - emval operations are detected by the `emscripten_val_` prefix.
    /// - WASM linear memory functions match the `wasm_` prefix with `memory`.
    /// - Asyncify operations match the `__asyncify` prefix.
    /// - JS call wrappers match `EM_JS_` and `EM_ASM_` substrings.
    /// - JS import/export wrappers match `__import_` and `__export_` prefixes.
    /// - An empty Vec is returned for unrecognized function names.
    ///
    /// # Arguments
    /// * `function_name` - The function name to analyze for WASM/JS patterns.
    ///
    /// # Returns
    /// A Vec of `WasSemanticPattern` detected from the function name.
    fn analyze_function_name(&self, function_name: &str) -> Vec<WasSemanticPattern> {
        let mut patterns = Vec::new();

        // Emscripten runtime functions: prefixed with "emscripten_"
        // These are provided by the Emscripten toolchain for runtime management.
        // Must be checked before emval since emscripten_val_ is a subset.
        if function_name.starts_with("emscripten_") {
            if function_name.starts_with("emscripten_val_") {
                // emval operations manage JS values from WASM code
                patterns.push(WasSemanticPattern::EmvalOperation);
            } else {
                // General Emscripten runtime management functions
                patterns.push(WasSemanticPattern::EmscriptenRuntime);
            }
        }

        // WASM call constructors: __wasm_call_ctors
        // These are Emscripten-generated constructor initialization functions
        if function_name.contains("__wasm_call_ctors") {
            patterns.push(WasSemanticPattern::EmscriptenRuntime);
        }

        // Node.js N-API functions: emnapi_ prefix
        // These provide Node.js native addon API support for WASM
        if function_name.starts_with("emnapi_") {
            patterns.push(WasSemanticPattern::JsImportFunction);
        }

        // JS import functions: __import_ prefix
        // Functions imported from JavaScript into the WASM module
        if function_name.starts_with("__import_") {
            patterns.push(WasSemanticPattern::JsImportFunction);
        }

        // JS export functions: __export_ prefix
        // Functions exported from WASM to be callable from JavaScript
        if function_name.starts_with("__export_") {
            patterns.push(WasSemanticPattern::JsExportFunction);
        }

        // WASM linear memory functions: wasm_*memory*
        // These manage the WASM linear memory region
        if function_name.starts_with("wasm_") && function_name.contains("memory") {
            patterns.push(WasSemanticPattern::WasmLinearMemory);
        }

        // Memory grow operations
        if function_name.contains("memory.grow") || function_name.contains("__memory_grow") {
            patterns.push(WasSemanticPattern::MemoryGrow);
        }

        // Asyncify operations: __asyncify prefix
        // Emscripten's asyncify transforms async JS calls into sync WASM
        if function_name.contains("__asyncify") {
            patterns.push(WasSemanticPattern::AsyncifyOperation);
        }

        // JS call wrappers: EM_JS_ or EM_ASM_ prefix
        // Inline JavaScript code in C/C++ via Emscripten macros
        if function_name.contains("EM_JS_") || function_name.contains("EM_ASM_") {
            patterns.push(WasSemanticPattern::JsCallWrapper);
        }

        patterns
    }

    /// Analyzes function body to detect WASM/JS semantic patterns from IR instructions.
    ///
    /// # Objective
    /// Scan IR instructions within a function body to detect WASM/JS-specific
    /// semantic patterns by examining call instruction callees. This
    /// complements name-based analysis with instruction-level evidence.
    ///
    /// # Invariants
    /// - Only `Call` instructions are analyzed.
    /// - Each callee is checked against known WASM and JS FFI patterns.
    /// - Multiple patterns may be detected from a single instruction.
    /// - An empty Vec is returned if no WASM/JS patterns are found.
    ///
    /// # Arguments
    /// * `body` - The IR function body containing instructions to analyze.
    ///
    /// # Returns
    /// A Vec of `WasSemanticPattern` detected from IR instructions.
    fn analyze_function_body(&self, body: &FunctionBody) -> Vec<WasSemanticPattern> {
        let mut patterns = Vec::new();

        // Scan all instructions for call patterns that indicate WASM or JS FFI usage
        for instruction in &body.instructions {
            if let IRInstructionKind::Call = instruction.kind {
                // Extract called function name from instruction's callee field
                if let Some(ref callee) = instruction.callee {
                    // JS import functions: __import_* prefix
                    // These are functions imported from JavaScript via WebAssembly.import
                    if callee.starts_with("__import_") || callee.starts_with("env.") {
                        patterns.push(WasSemanticPattern::JsImportFunction);
                    }
                    // JS export functions: __export_* prefix
                    // These are functions exported to JavaScript via WebAssembly.export
                    else if callee.starts_with("__export_") {
                        patterns.push(WasSemanticPattern::JsExportFunction);
                    }
                    // Emscripten runtime functions
                    else if callee.starts_with("emscripten_") {
                        if callee.starts_with("emscripten_val_") {
                            patterns.push(WasSemanticPattern::EmvalOperation);
                        } else {
                            patterns.push(WasSemanticPattern::EmscriptenRuntime);
                        }
                    }
                    // WASM linear memory operations
                    else if callee.starts_with("wasm_") && callee.contains("memory") {
                        patterns.push(WasSemanticPattern::WasmLinearMemory);
                    }
                    // Memory grow operations
                    else if callee.contains("memory.grow") || callee == "__memory_grow" {
                        patterns.push(WasSemanticPattern::MemoryGrow);
                    }
                    // Asyncify operations
                    else if callee.contains("__asyncify") {
                        patterns.push(WasSemanticPattern::AsyncifyOperation);
                    }
                    // JS call wrappers
                    else if callee.contains("EM_JS_") || callee.contains("EM_ASM_") {
                        patterns.push(WasSemanticPattern::JsCallWrapper);
                    }
                    // WASM global set
                    else if callee.starts_with("__wasm_globals_set")
                        || callee.starts_with("__global_set")
                    {
                        patterns.push(WasSemanticPattern::WasmGlobalSet);
                    }
                    // WASM function table operations
                    else if callee.starts_with("__wasm_table_set")
                        || callee.starts_with("__table_set")
                    {
                        patterns.push(WasSemanticPattern::WasmTableSet);
                    }
                    // Node.js N-API functions via emnapi
                    else if callee.starts_with("emnapi_") {
                        patterns.push(WasSemanticPattern::JsImportFunction);
                    }
                }
            }
        }

        patterns
    }

    /// Determines FFI safety for a WASM/JS function based on detected patterns.
    ///
    /// # Objective
    /// Compute the FFI safety assessment by analyzing the combination of
    /// detected patterns and function name. This determines whether the
    /// function poses memory safety risks at the WASM/JS boundary.
    ///
    /// # Invariants
    /// - Pure WASM internal patterns indicate `SafeInternal`.
    /// - JS boundary with no emval or memory concerns indicates `SafeJsBoundary`.
    /// - WASM memory operations without clear lifecycle indicate `ConcernMemoryOwnership`.
    /// - emval operations without proper cleanup indicate `ConcernEmvalLeak`.
    /// - All other functions return `Unknown`.
    ///
    /// # Arguments
    /// * `_function_name` - The function name for heuristic-based assessment.
    /// * `patterns` - The detected WASM/JS semantic patterns.
    /// * `_body` - Optional IR body (reserved for future analysis).
    ///
    /// # Returns
    /// A `WasFFISafety` assessment for the function.
    fn determine_ffi_safety(
        &self,
        _function_name: &str,
        patterns: &[WasSemanticPattern],
        _body: Option<&FunctionBody>,
    ) -> WasFFISafety {
        // Priority 1: emval operations without proper cleanup
        // emval resources (emscripten_val_*) must be released with val_decref
        // to avoid leaking JavaScript values from the WASM side.
        let has_emval_operation = patterns
            .iter()
            .any(|p| matches!(p, WasSemanticPattern::EmvalOperation));

        // Priority 2: WASM linear memory operations
        // Memory allocated from WASM linear memory needs to be tracked for
        // ownership transfer concerns at the JS boundary.
        let has_memory_operation = patterns.iter().any(|p| {
            matches!(
                p,
                WasSemanticPattern::WasmLinearMemory | WasSemanticPattern::MemoryGrow
            )
        });

        // Priority 3: JS FFI boundary patterns
        // Functions that cross the WASM-JS boundary need special handling.
        let has_js_boundary = patterns.iter().any(|p| {
            matches!(
                p,
                WasSemanticPattern::JsCallWrapper
                    | WasSemanticPattern::JsImportFunction
                    | WasSemanticPattern::JsExportFunction
                    | WasSemanticPattern::WasmTableSet
            )
        });

        // Check for emval leak risk
        if has_emval_operation {
            // emval operations without val_decref or similar cleanup
            // indicate potential JavaScript value leaks
            return WasFFISafety::ConcernEmvalLeak;
        }

        // Check for memory ownership concerns
        if has_memory_operation && has_js_boundary {
            // WASM memory passed across the JS boundary without clear
            // ownership transfer mechanism
            return WasFFISafety::ConcernMemoryOwnership;
        }

        // Pure WASM internal with memory operations only
        if has_memory_operation && !has_js_boundary {
            return WasFFISafety::SafeInternal;
        }

        // JS boundary with no memory or emval concerns
        if has_js_boundary {
            return WasFFISafety::SafeJsBoundary;
        }

        // Pure WASM internal patterns (Emscripten runtime, asyncify)
        if patterns.iter().any(|p| {
            matches!(
                p,
                WasSemanticPattern::EmscriptenRuntime | WasSemanticPattern::AsyncifyOperation
            )
        }) {
            return WasFFISafety::SafeInternal;
        }

        // Default: insufficient information for assessment
        WasFFISafety::Unknown
    }

    /// Detects potential emval resource leaks.
    ///
    /// # Objective
    /// Analyze whether a function using emval operations might leak JavaScript
    /// value handles. emval creates references to JS values that must be
    /// explicitly released with `emscripten_val_decref`.
    ///
    /// # Invariants
    /// - Returns `true` if emval operations are detected.
    /// - Returns `false` if no emval operations are present.
    /// - This is a heuristic that may have false positives for functions
    ///   that properly manage emval lifecycle elsewhere.
    ///
    /// # Arguments
    /// * `patterns` - The detected WASM/JS semantic patterns for the function.
    ///
    /// # Returns
    /// `true` if emval leak risk is detected, `false` otherwise.
    pub fn detect_emval_leak_risk(&self, patterns: &[WasSemanticPattern]) -> bool {
        patterns
            .iter()
            .any(|p| matches!(p, WasSemanticPattern::EmvalOperation))
    }

    /// Detects WASM memory ownership concerns.
    ///
    /// # Objective
    /// Identify functions that might have memory ownership issues when
    /// WASM linear memory is exposed to JavaScript. This is a common
    /// source of bugs in Emscripten applications.
    ///
    /// # Invariants
    /// - Returns `true` if the function combines memory operations with
    ///   JS boundary patterns.
    /// - Returns `false` otherwise.
    /// - This is a heuristic-based detection that might have false positives.
    ///
    /// # Arguments
    /// * `patterns` - The detected WASM/JS semantic patterns for the function.
    ///
    /// # Returns
    /// `true` if WASM memory ownership concern is detected, `false` otherwise.
    pub fn detect_memory_ownership_concern(&self, patterns: &[WasSemanticPattern]) -> bool {
        let has_memory = patterns
            .iter()
            .any(|p| matches!(p, WasSemanticPattern::WasmLinearMemory));
        let has_js_boundary = patterns.iter().any(|p| {
            matches!(
                p,
                WasSemanticPattern::JsCallWrapper
                    | WasSemanticPattern::JsImportFunction
                    | WasSemanticPattern::JsExportFunction
            )
        });

        has_memory && has_js_boundary
    }
}

impl Default for WasAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

    /// Objective: Verify Emscripten runtime function analysis
    /// Invariants: emscripten_memcpy must be detected as EmscriptenRuntime
    #[test]
    fn test_emscripten_runtime_analysis() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("emscripten_memcpy", None);

        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::EmscriptenRuntime),
            "emscripten_memcpy must be detected as EmscriptenRuntime, got {:?}",
            analysis.patterns
        );
        assert!(
            !analysis.is_js_ffi_boundary,
            "emscripten_memcpy must not be a JS FFI boundary"
        );
        assert!(
            !analysis.manages_wasm_memory,
            "emscripten_memcpy must not manage WASM memory"
        );
        assert_eq!(
            analysis.ffi_safety,
            WasFFISafety::SafeInternal,
            "emscripten_memcpy must be SafeInternal"
        );
    }

    /// Objective: Verify emval function analysis
    /// Invariants: emscripten_val_create must be detected as EmvalOperation
    #[test]
    fn test_emval_operation_analysis() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("emscripten_val_create", None);

        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::EmvalOperation),
            "emscripten_val_create must be detected as EmvalOperation, got {:?}",
            analysis.patterns
        );
        assert!(
            !analysis
                .patterns
                .contains(&WasSemanticPattern::EmscriptenRuntime),
            "emscripten_val_create must not be detected as EmscriptenRuntime"
        );
        assert_eq!(
            analysis.ffi_safety,
            WasFFISafety::ConcernEmvalLeak,
            "emval operations must have ConcernEmvalLeak safety"
        );
    }

    /// Objective: Verify WASM linear memory function analysis
    /// Invariants: wasm_malloc must be detected as WasmLinearMemory
    #[test]
    fn test_wasm_linear_memory_analysis() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("wasm_memory_alloc", None);

        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::WasmLinearMemory),
            "wasm_memory_alloc must be detected as WasmLinearMemory, got {:?}",
            analysis.patterns
        );
        assert!(
            analysis.manages_wasm_memory,
            "wasm_memory_alloc must manage WASM memory"
        );
        assert_eq!(
            analysis.ffi_safety,
            WasFFISafety::SafeInternal,
            "Pure WASM memory operations must be SafeInternal"
        );
    }

    /// Objective: Verify memory grow detection
    /// Invariants: __memory_grow must be detected as MemoryGrow
    #[test]
    fn test_memory_grow_analysis() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("__memory_grow", None);

        assert!(
            analysis.patterns.contains(&WasSemanticPattern::MemoryGrow),
            "__memory_grow must be detected as MemoryGrow, got {:?}",
            analysis.patterns
        );
        assert!(
            analysis.manages_wasm_memory,
            "__memory_grow must manage WASM memory"
        );
    }

    /// Objective: Verify JS import function name analysis
    /// Invariants: Functions starting with emnapi_ must be detected as JsImportFunction
    #[test]
    fn test_js_import_emnapi_analysis() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("emnapi_create_string", None);

        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::JsImportFunction),
            "emnapi_create_string must be detected as JsImportFunction, got {:?}",
            analysis.patterns
        );
        assert!(
            analysis.is_js_ffi_boundary,
            "emnapi functions must be JS FFI boundaries"
        );
    }

    /// Objective: Verify JS call wrapper detection
    /// Invariants: Functions containing EM_JS_ must be detected as JsCallWrapper
    #[test]
    fn test_js_call_wrapper_analysis() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("EM_JS_console_log", None);

        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::JsCallWrapper),
            "EM_JS_console_log must be detected as JsCallWrapper, got {:?}",
            analysis.patterns
        );
        assert!(
            analysis.is_js_ffi_boundary,
            "EM_JS functions must be JS FFI boundaries"
        );
    }

    /// Objective: Verify asyncify function detection
    /// Invariants: __asyncify functions must be detected as AsyncifyOperation
    #[test]
    fn test_asyncify_analysis() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("__asyncify_js_call", None);

        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::AsyncifyOperation),
            "__asyncify_js_call must be detected as AsyncifyOperation, got {:?}",
            analysis.patterns
        );
        assert_eq!(
            analysis.ffi_safety,
            WasFFISafety::SafeInternal,
            "Asyncify operations must be SafeInternal"
        );
    }

    /// Objective: Verify __wasm_call_ctors detection
    /// Invariants: __wasm_call_ctors must be detected as EmscriptenRuntime
    #[test]
    fn test_wasm_call_ctors_analysis() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("__wasm_call_ctors", None);

        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::EmscriptenRuntime),
            "__wasm_call_ctors must be detected as EmscriptenRuntime, got {:?}",
            analysis.patterns
        );
    }

    /// Objective: Verify WASM memory with JS boundary analysis
    /// Invariants: Functions combining memory and JS boundary must have ConcernMemoryOwnership
    #[test]
    fn test_memory_with_js_boundary_concern() {
        let adapter = WasAdapter::new();

        // Simulate a function that combines memory and JS boundary patterns
        let mut analysis = adapter.analyze_function("wasm_memory_alloc", None);
        analysis.patterns.push(WasSemanticPattern::JsImportFunction);

        let ffi_safety =
            adapter.determine_ffi_safety("wasm_memory_alloc", &analysis.patterns, None);

        assert_eq!(
            ffi_safety,
            WasFFISafety::ConcernMemoryOwnership,
            "Combined memory and JS boundary must have ConcernMemoryOwnership"
        );
    }

    /// Objective: Verify JS import semantics using embedded IR
    /// Invariants: IR body with __import_ prefix must be detected as JsImportFunction
    #[test]
    fn test_js_import_semantics_with_ir() {
        let adapter = WasAdapter::new();

        // Create a function body with JS import calls
        let body = FunctionBody {
            name: "test_wasm_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%result".to_string()),
                    operands: vec!["i32".to_string(), "i32 42".to_string()],
                    callee: Some("__import_console_log".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%result = call i32 @__import_console_log(i32 42)".to_string(),
                    result_type: Some("i32".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: None,
                    operands: vec!["void".to_string(), "%result".to_string()],
                    callee: Some("env.doSomething".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "call void @env.doSomething(i32 %result)".to_string(),
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

        let analysis = adapter.analyze_function("test_wasm_function", Some(&body));

        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::JsImportFunction),
            "IR body with __import_console_log must be detected as JsImportFunction"
        );
        assert!(
            analysis.is_js_ffi_boundary,
            "Function with JS imports must be a JS FFI boundary"
        );
    }

    /// Objective: Verify JS export semantics using embedded IR
    /// Invariants: IR body with __export_ prefix must be detected as JsExportFunction
    #[test]
    fn test_js_export_semantics_with_ir() {
        let adapter = WasAdapter::new();

        // Create a function body with JS export calls
        let body = FunctionBody {
            name: "test_export_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%ret".to_string()),
                    operands: vec!["i32".to_string(), "i32 0".to_string()],
                    callee: Some("__export_main".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%ret = call i32 @__export_main(i32 0)".to_string(),
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
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "ret i32 %ret".to_string(),
                    result_type: Some("i32".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("test_export_function", Some(&body));

        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::JsExportFunction),
            "IR body with __export_main must be detected as JsExportFunction"
        );
        assert!(
            analysis.is_js_ffi_boundary,
            "Function with JS exports must be a JS FFI boundary"
        );
    }

    /// Objective: Verify mixed WASM patterns
    /// Invariants: Functions with multiple patterns must be correctly analyzed
    #[test]
    fn test_mixed_wasm_patterns() {
        let adapter = WasAdapter::new();

        // Create a function body with mixed WASM patterns
        let body = FunctionBody {
            name: "mixed_wasm_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%ptr".to_string()),
                    operands: vec!["i32".to_string(), "i32 100".to_string()],
                    callee: Some("wasm_memory_alloc".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%ptr = call i8* @wasm_memory_alloc(i32 100)".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%result".to_string()),
                    operands: vec!["i32".to_string(), "%ptr".to_string()],
                    callee: Some("__import_process".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%result = call i32 @__import_process(i8* %ptr)".to_string(),
                    result_type: Some("i32".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: None,
                    operands: vec!["void".to_string(), "%ptr".to_string()],
                    callee: Some("wasm_memory_free".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "call void @wasm_memory_free(i8* %ptr)".to_string(),
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

        let analysis = adapter.analyze_function("mixed_wasm_function", Some(&body));

        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::WasmLinearMemory),
            "WASM linear memory must be detected from IR body"
        );
        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::JsImportFunction),
            "JS import must be detected from IR body"
        );
        assert!(
            analysis.manages_wasm_memory,
            "Function with WASM memory operations must manage WASM memory"
        );
        assert!(
            analysis.is_js_ffi_boundary,
            "Function with JS imports must be a JS FFI boundary"
        );

        // Combined memory and JS boundary should be ConcernMemoryOwnership
        assert_eq!(
            analysis.ffi_safety,
            WasFFISafety::ConcernMemoryOwnership,
            "Mixed memory and JS boundary must be ConcernMemoryOwnership"
        );
    }

    /// Objective: Verify emval leak risk detection
    /// Invariants: Functions with emval pattern must be detected as leak risk
    #[test]
    fn test_emval_leak_risk_detection() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("emscripten_val_create", None);

        assert!(
            adapter.detect_emval_leak_risk(&analysis.patterns),
            "Functions with emval pattern must be detected as potential emval leak risk"
        );

        // Test with a function that does not have emval
        let analysis_no_emval = adapter.analyze_function("emscripten_memcpy", None);
        assert!(
            !adapter.detect_emval_leak_risk(&analysis_no_emval.patterns),
            "Functions without emval pattern must not be detected as leak risk"
        );
    }

    /// Objective: Verify WASM memory ownership concern detection
    /// Invariants: Functions with both memory and JS boundary must be detected
    #[test]
    fn test_memory_ownership_concern_detection() {
        let adapter = WasAdapter::new();

        // Test with a function that has both memory and JS boundary
        let body = FunctionBody {
            name: "test_ownership_concern".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%ptr".to_string()),
                    operands: vec!["i32".to_string(), "i32 64".to_string()],
                    callee: Some("wasm_memory_alloc".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%ptr = call i8* @wasm_memory_alloc(i32 64)".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                    conversion_opcode: None,
                    binary_opcode: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: None,
                    operands: vec!["void".to_string(), "%ptr".to_string()],
                    callee: Some("__import_process".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "call void @__import_process(i8* %ptr)".to_string(),
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

        let analysis = adapter.analyze_function("test_ownership_concern", Some(&body));

        assert!(
            adapter.detect_memory_ownership_concern(&analysis.patterns),
            "Functions with both memory and JS boundary must be detected as ownership concern"
        );

        // Test with a function that has only memory
        let analysis_only_memory = adapter.analyze_function("wasm_memory_alloc", None);
        assert!(
            !adapter.detect_memory_ownership_concern(&analysis_only_memory.patterns),
            "Functions with only memory must not be detected as ownership concern"
        );
    }

    /// Objective: Verify EM_ASM pattern detection
    /// Invariants: EM_ASM functions must be detected as JsCallWrapper and FFI boundary
    #[test]
    fn test_em_asm_pattern() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("EM_ASM_alert_message", None);

        assert!(
            analysis
                .patterns
                .contains(&WasSemanticPattern::JsCallWrapper),
            "EM_ASM_alert_message must be detected as JsCallWrapper, got {:?}",
            analysis.patterns
        );
        assert!(
            analysis.is_js_ffi_boundary,
            "EM_ASM functions must be JS FFI boundaries"
        );
    }

    /// Objective: Verify JS boundary with no memory concern -> SafeJsBoundary
    /// Invariants: Pure JS boundary functions without memory must be SafeJsBoundary
    #[test]
    fn test_js_boundary_no_memory_concern() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("__import_console_log", None);

        assert_eq!(
            analysis.ffi_safety,
            WasFFISafety::SafeJsBoundary,
            "Pure JS import without memory must be SafeJsBoundary"
        );
    }

    /// Objective: Verify unknown function analysis
    /// Invariants: Unrecognized functions must have empty patterns and Unknown safety
    #[test]
    fn test_unknown_function() {
        let adapter = WasAdapter::new();
        let analysis = adapter.analyze_function("some_unknown_function", None);

        assert!(
            analysis.patterns.is_empty(),
            "Unknown function must have no patterns, got {:?}",
            analysis.patterns
        );
        assert!(
            !analysis.is_js_ffi_boundary,
            "Unknown function must not be a JS FFI boundary"
        );
        assert!(
            !analysis.manages_wasm_memory,
            "Unknown function must not manage WASM memory"
        );
        assert_eq!(
            analysis.ffi_safety,
            WasFFISafety::Unknown,
            "Unknown function must have Unknown safety"
        );
    }

    /// Objective: Verify SemanticFact conversion for linear memory
    /// Invariants: WasmLinearMemory pattern must produce WasmMemoryAlloc fact
    #[test]
    fn test_to_semantic_facts_linear_memory() {
        let analysis = WasFunctionAnalysis {
            function_name: "wasm_malloc".to_string(),
            patterns: vec![WasSemanticPattern::WasmLinearMemory],
            is_js_ffi_boundary: false,
            manages_wasm_memory: true,
            ffi_safety: WasFFISafety::SafeInternal,
        };

        let facts = analysis.to_semantic_facts();

        let has_memory_alloc = facts.iter().any(|f| {
            f.kind == SemanticKind::WasmMemoryAlloc
                && f.confidence == FactConfidence::High
                && matches!(&f.key, SemanticKey::Symbol(name) if name == "wasm_malloc")
        });

        assert!(
            has_memory_alloc,
            "WasmLinearMemory must produce WasmMemoryAlloc fact"
        );
    }

    /// Objective: Verify SemanticFact conversion for emval operations
    /// Invariants: EmvalOperation pattern must produce EmvalHandle fact
    #[test]
    fn test_to_semantic_facts_emval() {
        let analysis = WasFunctionAnalysis {
            function_name: "emscripten_val_get".to_string(),
            patterns: vec![WasSemanticPattern::EmvalOperation],
            is_js_ffi_boundary: false,
            manages_wasm_memory: false,
            ffi_safety: WasFFISafety::ConcernEmvalLeak,
        };

        let facts = analysis.to_semantic_facts();

        let has_emval_handle = facts.iter().any(|f| {
            f.kind == SemanticKind::EmvalHandle
                && f.confidence == FactConfidence::High
                && matches!(&f.key, SemanticKey::Symbol(name) if name == "emscripten_val_get")
        });

        let has_safety_concern = facts.iter().any(|f| {
            f.kind == SemanticKind::Unknown
                && f.confidence == FactConfidence::Low
                && f.source == FactSource::LanguageAdapter
        });

        assert!(
            has_emval_handle,
            "EmvalOperation must produce EmvalHandle fact"
        );
        assert!(
            has_safety_concern,
            "ConcernEmvalLeak must produce safety concern fact"
        );
    }

    /// Objective: Verify SemanticFact conversion for JS import
    /// Invariants: JsImportFunction pattern must produce JsImportWrapper fact
    #[test]
    fn test_to_semantic_facts_js_import() {
        let analysis = WasFunctionAnalysis {
            function_name: "__import_console".to_string(),
            patterns: vec![WasSemanticPattern::JsImportFunction],
            is_js_ffi_boundary: true,
            manages_wasm_memory: false,
            ffi_safety: WasFFISafety::SafeJsBoundary,
        };

        let facts = analysis.to_semantic_facts();

        let has_js_import = facts.iter().any(|f| {
            f.kind == SemanticKind::JsImportWrapper
                && f.confidence == FactConfidence::High
                && matches!(&f.key, SemanticKey::Symbol(name) if name == "__import_console")
        });

        assert!(
            has_js_import,
            "JsImportFunction must produce JsImportWrapper fact"
        );
    }
}
