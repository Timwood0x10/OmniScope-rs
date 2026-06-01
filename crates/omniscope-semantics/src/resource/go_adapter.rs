//! Go/CGO language adapter for semantic analysis.
//!
//! This module provides Go-specific semantic analysis, including:
//! - Go memory management (GC vs C heap)
//! - CGO call conventions and pointer passing rules
//! - Go-specific function patterns (runtime, cgo)
//!
//! # Go Memory Model
//!
//! Go has two memory domains:
//! 1. **Go heap**: Managed by Go GC, allocated via `runtime.mallocgc` or `runtime.alloc`
//! 2. **C heap**: Managed by C malloc/free, used in CGO calls
//!
//! The key insight for CGO analysis: Go pointers cannot be passed to C functions
//! directly. Go uses "pinned" memory or C-allocated memory for CGO calls.
//!
//! # CGO Call Patterns
//!
//! ```text
//! Go code ──→ cgo_* functions ──→ C functions
//!           ──→ _Cfunc_* functions ──→ C functions
//!           ──→ runtime.mallocgc ──→ Go GC heap
//!           ──→ _cgo_allocate ──→ C heap (for CGO)
//! ```

use omniscope_ir::{FunctionBody, IRInstructionKind};
use omniscope_types::Language;

/// Go-specific semantic patterns derived from IR analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoSemanticPattern {
    /// Go GC allocation (runtime.mallocgc or runtime.alloc)
    GoGCAllocation,
    /// CGO memory allocation (_cgo_allocate, _Cfunc_GoMalloc)
    CGOAllocation,
    /// CGO memory deallocation (_cgo_free, _Cfunc_GoFree)
    CGODesallocation,
    /// Go runtime internal function (runtime.*)
    RuntimeInternal,
    /// CGO bridge function (_cgo_*, _Cfunc_*)
    CGOBridge,
    /// Go panic/throw (runtime.gopanic, runtime.throw)
    PanicOrThrow,
    /// Go goroutine management (runtime.newproc, runtime.goexit)
    GoroutineManagement,
    /// Go channel operations (runtime.chanrecv, runtime.chansend)
    ChannelOperation,
    /// Go map operations (runtime.mapassign, runtime.mapaccess)
    MapOperation,
    /// Go slice operations (runtime.growslice, runtime.makeslice)
    SliceOperation,
    /// Go string operations (runtime.slicebytetostring, runtime.stringtoslicebyte)
    StringOperation,
    /// Go interface operations (runtime.convT2I, runtime.assertI2I)
    InterfaceOperation,
    /// Go type reflection (runtime.reflect.*)
    Reflection,
    /// Unknown Go pattern
    Unknown,
}

/// Analysis result for a Go function.
#[derive(Debug, Clone)]
pub struct GoFunctionAnalysis {
    /// The function name analyzed
    pub function_name: String,
    /// Detected semantic patterns
    pub patterns: Vec<GoSemanticPattern>,
    /// Whether this function is a CGO bridge
    pub is_cgo_bridge: bool,
    /// Whether this function manages Go GC memory
    pub manages_go_gc_memory: bool,
    /// Whether this function manages C heap memory
    pub manages_c_heap_memory: bool,
    /// Recommended FFI safety assessment
    pub ffi_safety: GoFFISafety,
}

/// FFI safety assessment for Go functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoFFISafety {
    /// Safe: pure Go internal, no FFI concerns
    SafeInternal,
    /// Safe: CGO bridge with proper memory management
    SafeCGOBridge,
    /// Concern: CGO call with potential memory ownership transfer
    ConcernCGOOwnershipTransfer,
    /// Concern: Go GC memory passed to C (violation of Go pointer rules)
    ConcernGoPointerToC,
    /// Unknown: cannot determine safety
    Unknown,
}

impl GoFFISafety {
    /// Returns true if this assessment indicates a safe pattern.
    ///
    /// # Objective
    /// Determine whether the FFI safety assessment indicates that the analyzed
    /// Go function is safe from memory safety perspective. This is used to
    /// filter out false positives in CGO-related analysis.
    ///
    /// # Invariants
    /// - `SafeInternal` and `SafeCGOBridge` are considered safe.
    /// - All `Concern*` variants and `Unknown` are considered unsafe.
    /// - The result is deterministic for a given variant.
    ///
    /// # Returns
    /// `true` if the assessment indicates a safe pattern, `false` otherwise.
    pub fn is_safe(&self) -> bool {
        // SafeInternal: pure Go runtime code with no FFI boundary
        // SafeCGOBridge: CGO call with balanced alloc/dealloc
        matches!(self, GoFFISafety::SafeInternal | GoFFISafety::SafeCGOBridge)
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
            // SafeInternal: pure Go code, no cross-boundary concerns
            GoFFISafety::SafeInternal => 0.95,
            // SafeCGOBridge: CGO with proper memory management
            GoFFISafety::SafeCGOBridge => 0.85,
            // ConcernCGOOwnershipTransfer: potential memory leak or double-free
            GoFFISafety::ConcernCGOOwnershipTransfer => 0.3,
            // ConcernGoPointerToC: Go GC pointer passed to C (UB in Go)
            GoFFISafety::ConcernGoPointerToC => 0.2,
            // Unknown: insufficient information for assessment
            GoFFISafety::Unknown => 0.5,
        }
    }
}

/// Go/CGO adapter for semantic analysis.
///
/// This adapter provides Go-specific semantic analysis by combining
/// function name pattern matching with IR body instruction analysis.
/// It detects Go runtime functions, CGO bridge functions, and
/// categorizes their memory management behavior.
pub struct GoAdapter {
    /// Language hint for Go, used to identify the source language
    language: Language,
}

impl GoAdapter {
    /// Creates a new Go adapter with Go language hint.
    ///
    /// # Objective
    /// Initialize the Go adapter with the correct language identifier
    /// so it can be used for Go-specific semantic analysis in the
    /// semantic engine pipeline.
    ///
    /// # Invariants
    /// - Language is always set to `Language::Go`.
    /// - The adapter is ready to use immediately after creation.
    ///
    /// # Returns
    /// A new `GoAdapter` instance ready for semantic analysis.
    ///
    /// # Examples
    /// ```
    /// use omniscope_semantics::resource::go_adapter::GoAdapter;
    /// use omniscope_types::Language;
    ///
    /// let adapter = GoAdapter::new();
    /// assert_eq!(adapter.language(), Language::Go);
    /// ```
    pub fn new() -> Self {
        Self {
            language: Language::Go,
        }
    }

    /// Returns the language hint for this adapter.
    ///
    /// # Objective
    /// Provide the language identifier for this adapter, which is used
    /// by the semantic engine to route analysis requests to the correct
    /// language-specific adapter.
    ///
    /// # Invariants
    /// - Always returns `Language::Go`.
    /// - The value never changes after adapter creation.
    ///
    /// # Returns
    /// The `Language::Go` enum variant.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Analyzes a Go function from its IR body and name.
    ///
    /// # Objective
    /// Perform comprehensive semantic analysis of a Go function by
    /// combining function name pattern matching with IR instruction
    /// analysis. This determines the function's memory management
    /// behavior and FFI safety assessment.
    ///
    /// # Invariants
    /// - The function name is always stored in the result.
    /// - Patterns from name and body are combined (not deduplicated).
    /// - CGO bridge detection is always performed.
    /// - FFI safety assessment covers all detected patterns.
    ///
    /// # Arguments
    /// * `function_name` - The name of the Go function to analyze.
    /// * `body` - Optional IR body containing instruction-level analysis data.
    ///
    /// # Returns
    /// A `GoFunctionAnalysis` containing all detected patterns and safety assessment.
    pub fn analyze_function(
        &self,
        function_name: &str,
        body: Option<&FunctionBody>,
    ) -> GoFunctionAnalysis {
        // Collect all detected patterns from both name and IR body analysis
        let mut patterns = Vec::new();

        // Step 1: Analyze function name to detect Go runtime and CGO patterns
        // This is the primary detection mechanism for known function names
        let name_patterns = self.analyze_function_name(function_name);
        patterns.extend(name_patterns);

        // Step 2: Check if the function serves as a CGO bridge
        // CGO bridges connect Go and C memory domains
        let is_cgo_bridge = self.is_cgo_bridge_function(function_name);

        // Step 3: Analyze IR body for instruction-level evidence
        // This complements name-based analysis with actual call targets
        if let Some(body) = body {
            let body_patterns = self.analyze_function_body(body);
            patterns.extend(body_patterns);
        }

        // Step 4: Determine memory management flags from collected patterns
        // Go GC memory: runtime.mallocgc or runtime.alloc
        let manages_go_gc_memory = patterns
            .iter()
            .any(|p| matches!(p, GoSemanticPattern::GoGCAllocation));
        // C heap memory: CGO allocation or deallocation functions
        let manages_c_heap_memory = patterns.iter().any(|p| {
            matches!(
                p,
                GoSemanticPattern::CGOAllocation | GoSemanticPattern::CGODesallocation
            )
        });

        // Step 5: Compute FFI safety assessment based on all evidence
        let ffi_safety = self.determine_ffi_safety(function_name, &patterns, body);

        // Assemble final analysis result
        GoFunctionAnalysis {
            function_name: function_name.to_string(),
            patterns,
            is_cgo_bridge,
            manages_go_gc_memory,
            manages_c_heap_memory,
            ffi_safety,
        }
    }

    /// Analyzes function name to detect Go semantic patterns.
    ///
    /// # Objective
    /// Detect Go-specific semantic patterns from the function name using
    /// prefix-based pattern matching. This handles Go runtime functions,
    /// CGO bridge functions, and main package functions.
    ///
    /// # Invariants
    /// - Runtime functions always get `RuntimeInternal` pattern.
    /// - CGO functions always get `CGOBridge` pattern.
    /// - Specific patterns are derived from function name prefixes.
    /// - An empty Vec is returned for unrecognized function names.
    ///
    /// # Arguments
    /// * `function_name` - The function name to analyze for Go patterns.
    ///
    /// # Returns
    /// A Vec of `GoSemanticPattern` detected from the function name.
    fn analyze_function_name(&self, function_name: &str) -> Vec<GoSemanticPattern> {
        let mut patterns = Vec::new();

        // Go runtime functions: all functions starting with "runtime."
        // These are internal Go runtime functions compiled into every Go binary
        if function_name.starts_with("runtime.") {
            // All runtime.* functions are internal Go runtime operations
            patterns.push(GoSemanticPattern::RuntimeInternal);

            // Classify specific runtime functions by their memory behavior:
            // - GC allocation: runtime.mallocgc, runtime.alloc
            // - Error handling: runtime.gopanic, runtime.throw
            // - Goroutine lifecycle: runtime.newproc, runtime.goexit
            // - Channel communication: runtime.chanrecv, runtime.chansend
            // - Map operations: runtime.mapassign, runtime.mapaccess
            // - Slice growth: runtime.growslice, runtime.makeslice
            // - String conversion: runtime.slicebytetostring, runtime.stringtoslicebyte
            // - Interface operations: runtime.convT2I, runtime.assertI2I
            // - Reflection: runtime.reflect.*
            if function_name.starts_with("runtime.mallocgc")
                || function_name.starts_with("runtime.alloc")
            {
                // GC-managed heap allocation, safe within Go runtime
                patterns.push(GoSemanticPattern::GoGCAllocation);
            } else if function_name.starts_with("runtime.gopanic")
                || function_name.starts_with("runtime.throw")
            {
                // Unrecoverable error, terminates goroutine
                patterns.push(GoSemanticPattern::PanicOrThrow);
            } else if function_name.starts_with("runtime.newproc")
                || function_name.starts_with("runtime.goexit")
            {
                // Goroutine lifecycle management
                patterns.push(GoSemanticPattern::GoroutineManagement);
            } else if function_name.starts_with("runtime.chanrecv")
                || function_name.starts_with("runtime.chansend")
            {
                // Channel communication primitives
                patterns.push(GoSemanticPattern::ChannelOperation);
            } else if function_name.starts_with("runtime.mapassign")
                || function_name.starts_with("runtime.mapaccess")
            {
                // Map read/write operations
                patterns.push(GoSemanticPattern::MapOperation);
            } else if function_name.starts_with("runtime.growslice")
                || function_name.starts_with("runtime.makeslice")
            {
                // Slice allocation and growth
                patterns.push(GoSemanticPattern::SliceOperation);
            } else if function_name.starts_with("runtime.slicebytetostring")
                || function_name.starts_with("runtime.stringtoslicebyte")
            {
                // String/byte slice conversions
                patterns.push(GoSemanticPattern::StringOperation);
            } else if function_name.starts_with("runtime.convT2I")
                || function_name.starts_with("runtime.assertI2I")
            {
                // Interface type assertions and conversions
                patterns.push(GoSemanticPattern::InterfaceOperation);
            } else if function_name.starts_with("runtime.reflect.") {
                // Reflection API operations
                patterns.push(GoSemanticPattern::Reflection);
            }
        }

        // CGO bridge functions: _cgo_* and _Cfunc_* prefixed functions
        // These are the boundary between Go and C code, generated by the cgo tool
        if function_name.starts_with("_cgo_") || function_name.starts_with("_Cfunc_") {
            // Mark as CGO bridge for FFI safety assessment
            patterns.push(GoSemanticPattern::CGOBridge);

            // Classify CGO functions by their memory allocation behavior:
            // - CGO allocation: _cgo_allocate, _Cfunc_GoMalloc
            // - CGO deallocation: _cgo_free, _Cfunc_GoFree
            if function_name == "_cgo_allocate" || function_name == "_Cfunc_GoMalloc" {
                // C-side allocation for CGO pointer passing
                patterns.push(GoSemanticPattern::CGOAllocation);
            } else if function_name == "_cgo_free" || function_name == "_Cfunc_GoFree" {
                // C-side deallocation for CGO pointer passing
                patterns.push(GoSemanticPattern::CGODesallocation);
            }
        }

        // Go main package functions are entry points, always safe
        if function_name.starts_with("main.") {
            // No specific pattern needed, treated as SafeInternal by determine_ffi_safety
        }

        patterns
    }

    /// Analyzes function body to detect Go semantic patterns from IR instructions.
    ///
    /// # Objective
    /// Scan IR instructions within a function body to detect Go-specific
    /// semantic patterns by examining call instruction callees. This
    /// complements name-based analysis with instruction-level evidence.
    ///
    /// # Invariants
    /// - Only `Call` instructions are analyzed.
    /// - Each callee is checked against known Go runtime and CGO functions.
    /// - Multiple patterns may be detected from a single instruction.
    /// - An empty Vec is returned if no Go patterns are found.
    ///
    /// # Arguments
    /// * `body` - The IR function body containing instructions to analyze.
    ///
    /// # Returns
    /// A Vec of `GoSemanticPattern` detected from IR instructions.
    fn analyze_function_body(&self, body: &FunctionBody) -> Vec<GoSemanticPattern> {
        let mut patterns = Vec::new();

        // Scan all instructions for call patterns that indicate Go runtime or CGO usage
        for instruction in &body.instructions {
            if let IRInstructionKind::Call = instruction.kind {
                // Extract called function name from instruction's callee field
                if let Some(ref callee) = instruction.callee {
                    // Go GC allocation functions
                    if callee == "runtime.mallocgc" || callee == "runtime.alloc" {
                        patterns.push(GoSemanticPattern::GoGCAllocation);
                        patterns.push(GoSemanticPattern::RuntimeInternal);
                    }
                    // CGO allocation functions
                    else if callee == "_cgo_allocate" || callee == "_Cfunc_GoMalloc" {
                        patterns.push(GoSemanticPattern::CGOAllocation);
                        patterns.push(GoSemanticPattern::CGOBridge);
                    }
                    // CGO deallocation functions
                    else if callee == "_cgo_free" || callee == "_Cfunc_GoFree" {
                        patterns.push(GoSemanticPattern::CGODesallocation);
                        patterns.push(GoSemanticPattern::CGOBridge);
                    }
                    // Go runtime internal functions
                    else if callee.starts_with("runtime.") {
                        patterns.push(GoSemanticPattern::RuntimeInternal);
                    }
                    // CGO bridge functions
                    else if callee.starts_with("_cgo_") || callee.starts_with("_Cfunc_") {
                        patterns.push(GoSemanticPattern::CGOBridge);
                    }
                }
            }
        }

        patterns
    }

    /// Checks if a function is a CGO bridge function.
    ///
    /// # Objective
    /// Determine whether a function serves as a bridge between Go and C code
    /// in the CGO calling convention. CGO bridge functions facilitate the
    /// transition between Go's memory model and C's memory model.
    ///
    /// # Invariants
    /// - Functions prefixed with `_cgo_` are always CGO bridges.
    /// - Functions prefixed with `_Cfunc_` are always CGO bridges.
    /// - Functions containing `_C2func_`, `_GoStringToC`, etc. are CGO bridges.
    /// - Standard Go functions without CGO prefixes return false.
    ///
    /// # Arguments
    /// * `function_name` - The function name to check for CGO bridge patterns.
    ///
    /// # Returns
    /// `true` if the function is identified as a CGO bridge, `false` otherwise.
    fn is_cgo_bridge_function(&self, function_name: &str) -> bool {
        function_name.starts_with("_cgo_")
            || function_name.starts_with("_Cfunc_")
            || function_name.starts_with("cgo_")
            || function_name.contains("_C2func_")
            || function_name.contains("_GoStringToC")
            || function_name.contains("_GoBytesToC")
            || function_name.contains("_CGoString")
            || function_name.contains("_CGoBytes")
    }

    /// Determines FFI safety for a Go function based on detected patterns.
    ///
    /// # Objective
    /// Compute the FFI safety assessment by analyzing the combination of
    /// detected patterns and function name. This determines whether the
    /// function poses memory safety risks at the Go/C boundary.
    ///
    /// # Invariants
    /// - CGO bridges with balanced alloc/dealloc are `SafeCGOBridge`.
    /// - CGO bridges with only alloc or only dealloc are `ConcernCGOOwnershipTransfer`.
    /// - Go runtime internal functions are always `SafeInternal`.
    /// - `_Cfunc_*` and `cgo_*` functions are treated as `ConcernCGOOwnershipTransfer`.
    /// - `main.*` functions are treated as `SafeInternal`.
    /// - All other functions return `Unknown`.
    ///
    /// # Arguments
    /// * `function_name` - The function name for heuristic-based assessment.
    /// * `patterns` - The detected Go semantic patterns.
    /// * `_body` - Optional IR body (reserved for future analysis).
    ///
    /// # Returns
    /// A `GoFFISafety` assessment for the function.
    fn determine_ffi_safety(
        &self,
        function_name: &str,
        patterns: &[GoSemanticPattern],
        _body: Option<&FunctionBody>,
    ) -> GoFFISafety {
        // Priority 1: CGO bridge analysis
        // If it's a CGO bridge, check for balanced memory management
        if patterns
            .iter()
            .any(|p| matches!(p, GoSemanticPattern::CGOBridge))
        {
            // Check if it has both allocation and deallocation (balanced)
            // Balanced CGO means proper memory lifecycle management
            let has_allocation = patterns
                .iter()
                .any(|p| matches!(p, GoSemanticPattern::CGOAllocation));
            let has_deallocation = patterns
                .iter()
                .any(|p| matches!(p, GoSemanticPattern::CGODesallocation));

            if has_allocation && has_deallocation {
                // Both alloc and dealloc present: memory lifecycle is balanced
                return GoFFISafety::SafeCGOBridge;
            } else if has_allocation {
                // Only allocation, no deallocation - potential memory leak
                return GoFFISafety::ConcernCGOOwnershipTransfer;
            } else if has_deallocation {
                // Only deallocation, no allocation - potential double-free
                return GoFFISafety::ConcernCGOOwnershipTransfer;
            }
            // Only CGOBridge without alloc/dealloc details - insufficient info
            return GoFFISafety::Unknown;
        }

        // Priority 2: Go runtime internal functions
        // These are managed by Go's runtime and are inherently safe
        if patterns
            .iter()
            .any(|p| matches!(p, GoSemanticPattern::RuntimeInternal))
        {
            return GoFFISafety::SafeInternal;
        }

        // Priority 3: Heuristic-based analysis for C functions called from Go
        // Check for Go GC memory being passed to C (violation of Go pointer rules)
        // This would require more sophisticated analysis of pointer passing
        // For now, we'll use heuristics based on function names
        if function_name.starts_with("_Cfunc_") || function_name.starts_with("cgo_") {
            // These are C functions called from Go, potential memory ownership concern
            return GoFFISafety::ConcernCGOOwnershipTransfer;
        }

        // Priority 4: Go main package functions are entry points
        // If it's a Go main package function (entry point)
        if function_name.starts_with("main.") {
            return GoFFISafety::SafeInternal;
        }

        // Default: insufficient information for assessment
        GoFFISafety::Unknown
    }
}

impl Default for GoAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

    /// Objective: Verify Go adapter creation and basic functionality
    /// Invariants: Adapter must be created with correct language setting
    #[test]
    fn test_go_adapter_creation() {
        let adapter = GoAdapter::new();
        assert_eq!(
            adapter.language(),
            Language::Go,
            "Go adapter must have Go language setting"
        );
    }

    /// Objective: Verify Go runtime function analysis
    /// Invariants: runtime.mallocgc must be detected as GoGCAllocation
    #[test]
    fn test_go_runtime_mallocgc_analysis() {
        let adapter = GoAdapter::new();
        let analysis = adapter.analyze_function("runtime.mallocgc", None);

        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::GoGCAllocation),
            "runtime.mallocgc must be detected as GoGCAllocation"
        );
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::RuntimeInternal),
            "runtime.mallocgc must be detected as RuntimeInternal"
        );
        assert!(
            analysis.manages_go_gc_memory,
            "runtime.mallocgc must manage Go GC memory"
        );
        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::SafeInternal,
            "runtime.mallocgc must be SafeInternal"
        );
    }

    /// Objective: Verify CGO allocation function analysis
    /// Invariants: _cgo_allocate must be detected as CGOAllocation and CGOBridge
    #[test]
    fn test_cgo_allocate_analysis() {
        let adapter = GoAdapter::new();
        let analysis = adapter.analyze_function("_cgo_allocate", None);

        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::CGOAllocation),
            "_cgo_allocate must be detected as CGOAllocation"
        );
        assert!(
            analysis.patterns.contains(&GoSemanticPattern::CGOBridge),
            "_cgo_allocate must be detected as CGOBridge"
        );
        assert!(analysis.is_cgo_bridge, "_cgo_allocate must be a CGO bridge");
        assert!(
            analysis.manages_c_heap_memory,
            "_cgo_allocate must manage C heap memory"
        );
    }

    /// Objective: Verify CGO deallocation function analysis
    /// Invariants: _cgo_free must be detected as CGODesallocation and CGOBridge
    #[test]
    fn test_cgo_free_analysis() {
        let adapter = GoAdapter::new();
        let analysis = adapter.analyze_function("_cgo_free", None);

        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::CGODesallocation),
            "_cgo_free must be detected as CGODesallocation"
        );
        assert!(
            analysis.patterns.contains(&GoSemanticPattern::CGOBridge),
            "_cgo_free must be detected as CGOBridge"
        );
        assert!(analysis.is_cgo_bridge, "_cgo_free must be a CGO bridge");
        assert!(
            analysis.manages_c_heap_memory,
            "_cgo_free must manage C heap memory"
        );
    }

    /// Objective: Verify Go main package function analysis
    /// Invariants: main.main must be detected as SafeInternal
    #[test]
    fn test_go_main_function_analysis() {
        let adapter = GoAdapter::new();
        let analysis = adapter.analyze_function("main.main", None);

        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::SafeInternal,
            "main.main must be SafeInternal"
        );
        assert!(
            !analysis.is_cgo_bridge,
            "main.main must not be a CGO bridge"
        );
    }

    /// Objective: Verify Go panic/throw analysis
    /// Invariants: runtime.gopanic must be detected as PanicOrThrow
    #[test]
    fn test_go_panic_analysis() {
        let adapter = GoAdapter::new();
        let analysis = adapter.analyze_function("runtime.gopanic", None);

        assert!(
            analysis.patterns.contains(&GoSemanticPattern::PanicOrThrow),
            "runtime.gopanic must be detected as PanicOrThrow"
        );
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::RuntimeInternal),
            "runtime.gopanic must be detected as RuntimeInternal"
        );
        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::SafeInternal,
            "runtime.gopanic must be SafeInternal"
        );
    }

    /// Objective: Verify Go channel operation analysis
    /// Invariants: runtime.chanrecv must be detected as ChannelOperation
    #[test]
    fn test_go_channel_analysis() {
        let adapter = GoAdapter::new();
        let analysis = adapter.analyze_function("runtime.chanrecv", None);

        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::ChannelOperation),
            "runtime.chanrecv must be detected as ChannelOperation"
        );
        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::SafeInternal,
            "runtime.chanrecv must be SafeInternal"
        );
    }

    /// Objective: Verify Go slice operation analysis
    /// Invariants: runtime.growslice must be detected as SliceOperation
    #[test]
    fn test_go_slice_analysis() {
        let adapter = GoAdapter::new();
        let analysis = adapter.analyze_function("runtime.growslice", None);

        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::SliceOperation),
            "runtime.growslice must be detected as SliceOperation"
        );
        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::SafeInternal,
            "runtime.growslice must be SafeInternal"
        );
    }

    /// Objective: Verify CGO bridge with balanced allocation/deallocation
    /// Invariants: Function with both allocation and deallocation must be SafeCGOBridge
    #[test]
    fn test_cgo_bridge_balanced() {
        let adapter = GoAdapter::new();
        // Simulate a function that does both allocation and deallocation
        let mut analysis = adapter.analyze_function("_cgo_allocate", None);
        // Manually add deallocation pattern to simulate balanced memory management
        analysis.patterns.push(GoSemanticPattern::CGODesallocation);

        let ffi_safety = adapter.determine_ffi_safety("_cgo_allocate", &analysis.patterns, None);

        assert_eq!(
            ffi_safety,
            GoFFISafety::SafeCGOBridge,
            "CGO bridge with balanced allocation/deallocation must be SafeCGOBridge"
        );
    }

    /// Objective: Verify FFI safety score calculation
    /// Invariants: Safe patterns must have higher scores than concerning patterns
    #[test]
    fn test_ffi_safety_scores() {
        assert!(
            GoFFISafety::SafeInternal.safety_score() > GoFFISafety::Unknown.safety_score(),
            "SafeInternal must have higher score than Unknown"
        );
        assert!(
            GoFFISafety::SafeCGOBridge.safety_score()
                > GoFFISafety::ConcernCGOOwnershipTransfer.safety_score(),
            "SafeCGOBridge must have higher score than ConcernCGOOwnershipTransfer"
        );
        assert!(
            GoFFISafety::ConcernGoPointerToC.safety_score() < GoFFISafety::Unknown.safety_score(),
            "ConcernGoPointerToC must have lower score than Unknown"
        );
    }

    /// Objective: Verify Go language detection from function names
    /// Invariants: Go patterns must be correctly identified
    #[test]
    fn test_go_language_patterns() {
        let adapter = GoAdapter::new();

        // Test various Go function patterns
        let test_cases = vec![
            ("runtime.mallocgc", true, "Go runtime allocation"),
            ("_cgo_allocate", true, "CGO allocation"),
            ("main.main", false, "Go main package"),
            ("runtime.gopanic", true, "Go panic"),
            ("runtime.chanrecv", true, "Go channel"),
            ("runtime.growslice", true, "Go slice"),
            ("runtime.convT2I", true, "Go interface"),
            ("runtime.reflect.Value", true, "Go reflection"),
            ("C.malloc", false, "C function called from Go"),
        ];

        for (func_name, should_be_runtime, description) in test_cases {
            let analysis = adapter.analyze_function(func_name, None);
            let is_runtime = analysis
                .patterns
                .contains(&GoSemanticPattern::RuntimeInternal)
                || analysis.patterns.contains(&GoSemanticPattern::CGOBridge);

            if should_be_runtime {
                assert!(
                    is_runtime,
                    "{}: {} should be detected as Go runtime/CGO pattern",
                    description, func_name
                );
            }
        }
    }

    /// Objective: Verify Go adapter handles unknown functions gracefully
    /// Invariants: Unknown functions must return Unknown safety
    #[test]
    fn test_unknown_function_handling() {
        let adapter = GoAdapter::new();
        let analysis = adapter.analyze_function("unknown_function", None);

        assert!(
            analysis.patterns.is_empty(),
            "Unknown function should have no patterns"
        );
        assert!(
            !analysis.is_cgo_bridge,
            "Unknown function should not be a CGO bridge"
        );
        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::Unknown,
            "Unknown function must have Unknown safety"
        );
    }

    /// Objective: Verify CGO call semantics using embedded IR
    /// Invariants: CGO calls must follow C calling convention and be properly analyzed
    #[test]
    fn test_cgo_call_semantics_with_ir() {
        let adapter = GoAdapter::new();

        // Create a function body with CGO allocation and deallocation calls
        let body = FunctionBody {
            name: "test_cgo_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%ptr".to_string()),
                    operands: vec!["i8*".to_string(), "i64 100".to_string()],
                    callee: Some("_cgo_allocate".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%ptr = call i8* @_cgo_allocate(i64 100)".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: None,
                    operands: vec!["i8*".to_string(), "%ptr".to_string()],
                    callee: Some("_cgo_free".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "call void @_cgo_free(i8* %ptr)".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
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
                },
            ],
        };

        let analysis = adapter.analyze_function("test_cgo_function", Some(&body));

        // Verify CGO patterns are detected
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::CGOAllocation),
            "CGO allocation must be detected from IR body"
        );
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::CGODesallocation),
            "CGO deallocation must be detected from IR body"
        );

        // Verify memory management flags
        assert!(
            analysis.manages_c_heap_memory,
            "Function with CGO calls must manage C heap memory"
        );
        assert!(
            !analysis.manages_go_gc_memory,
            "Function with only CGO calls must not manage Go GC memory"
        );

        // Verify FFI safety assessment
        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::SafeCGOBridge,
            "CGO bridge with balanced allocation/deallocation must be SafeCGOBridge"
        );
    }

    /// Objective: Verify Go GC allocation semantics using embedded IR
    /// Invariants: Go GC allocations must be properly detected
    #[test]
    fn test_go_gc_allocation_with_ir() {
        let adapter = GoAdapter::new();

        // Create a function body with Go GC allocation
        let body = FunctionBody {
            name: "test_go_gc_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%obj".to_string()),
                    operands: vec!["i64 64".to_string(), "i64 0".to_string()],
                    callee: Some("runtime.mallocgc".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%obj = call i8* @runtime.mallocgc(i64 64, i64 0)".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Ret,
                    dest: None,
                    operands: vec!["i8* %obj".to_string()],
                    callee: None,
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "ret i8* %obj".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("test_go_gc_function", Some(&body));

        // Verify Go GC allocation pattern is detected
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::GoGCAllocation),
            "Go GC allocation must be detected from IR body"
        );
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::RuntimeInternal),
            "runtime.mallocgc must be detected as RuntimeInternal"
        );

        // Verify memory management flags
        assert!(
            analysis.manages_go_gc_memory,
            "Function with runtime.mallocgc must manage Go GC memory"
        );
        assert!(
            !analysis.manages_c_heap_memory,
            "Function with only Go GC calls must not manage C heap memory"
        );

        // Verify FFI safety assessment
        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::SafeInternal,
            "Go GC allocation function must be SafeInternal"
        );
    }

    /// Objective: Verify CGO bridge detection with IR body
    /// Invariants: CGO bridge functions must be correctly identified
    #[test]
    fn test_cgo_bridge_detection_with_ir() {
        let adapter = GoAdapter::new();

        // Create a function body with CGO bridge pattern
        let body = FunctionBody {
            name: "_Cfunc_my_c_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%result".to_string()),
                    operands: vec!["i8*".to_string(), "%arg".to_string()],
                    callee: Some("C.my_function".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%result = call i8* @C.my_function(i8* %arg)".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Ret,
                    dest: None,
                    operands: vec!["i8* %result".to_string()],
                    callee: None,
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "ret i8* %result".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                },
            ],
        };

        let analysis = adapter.analyze_function("_Cfunc_my_c_function", Some(&body));

        // Verify CGO bridge detection
        assert!(
            analysis.is_cgo_bridge,
            "_Cfunc_my_c_function must be detected as CGO bridge"
        );
        assert!(
            analysis.patterns.contains(&GoSemanticPattern::CGOBridge),
            "_Cfunc_my_c_function must have CGOBridge pattern"
        );

        // Verify FFI safety assessment
        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::Unknown,
            "CGO bridge without balanced allocation/deallocation must be Unknown"
        );
    }

    /// Objective: Verify mixed Go and CGO patterns
    /// Invariants: Functions with both Go and CGO patterns must be correctly analyzed
    #[test]
    fn test_mixed_go_cgo_patterns() {
        let adapter = GoAdapter::new();

        // Create a function body with mixed Go and CGO patterns
        let body = FunctionBody {
            name: "mixed_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%go_obj".to_string()),
                    operands: vec!["i64 32".to_string(), "i64 0".to_string()],
                    callee: Some("runtime.mallocgc".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%go_obj = call i8* @runtime.mallocgc(i64 32, i64 0)".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%c_ptr".to_string()),
                    operands: vec!["i8*".to_string(), "i64 100".to_string()],
                    callee: Some("_cgo_allocate".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%c_ptr = call i8* @_cgo_allocate(i64 100)".to_string(),
                    result_type: Some("i8*".to_string()),
                    element_type: None,
                    function_signature: None,
                },
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: None,
                    operands: vec!["i8*".to_string(), "%c_ptr".to_string()],
                    callee: Some("_cgo_free".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "call void @_cgo_free(i8* %c_ptr)".to_string(),
                    result_type: Some("void".to_string()),
                    element_type: None,
                    function_signature: None,
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
                },
            ],
        };

        let analysis = adapter.analyze_function("mixed_function", Some(&body));

        // Verify both Go and CGO patterns are detected
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::GoGCAllocation),
            "Go GC allocation must be detected"
        );
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::CGOAllocation),
            "CGO allocation must be detected"
        );
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::CGODesallocation),
            "CGO deallocation must be detected"
        );

        // Verify memory management flags
        assert!(
            analysis.manages_go_gc_memory,
            "Function with Go GC allocation must manage Go GC memory"
        );
        assert!(
            analysis.manages_c_heap_memory,
            "Function with CGO calls must manage C heap memory"
        );

        // Verify FFI safety assessment
        // Mixed Go and CGO patterns with balanced CGO allocation/deallocation
        // should be SafeCGOBridge because CGO calls are properly managed
        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::SafeCGOBridge,
            "Mixed Go and CGO patterns with balanced CGO calls must be SafeCGOBridge"
        );
    }
}
