//! Go/CGO language adapter for semantic analysis.
//!
//! Provides Go-specific semantic analysis for memory management (GC vs C heap),
//! CGO call conventions, defer/finalizer patterns, and pointer safety rules.

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
    /// Go defer mechanism for resource cleanup (runtime.deferproc)
    DeferCleanup,
    /// Go finalizer for delayed resource release (runtime.SetFinalizer)
    Finalizer,
    /// Go pointer passed to C function (violation of Go pointer rules)
    PointerViolation,
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
    pub fn is_safe(&self) -> bool {
        // SafeInternal: pure Go runtime code with no FFI boundary
        // SafeCGOBridge: CGO call with balanced alloc/dealloc
        matches!(self, GoFFISafety::SafeInternal | GoFFISafety::SafeCGOBridge)
    }

    /// Returns the safety score (0.0 = dangerous, 1.0 = safe).
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
    pub fn new() -> Self {
        Self {
            language: Language::Go,
        }
    }

    /// Returns the language hint for this adapter.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Analyzes a Go function from its IR body and name.
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
            } else if function_name.starts_with("runtime.deferproc") {
                // Defer mechanism for resource cleanup
                patterns.push(GoSemanticPattern::DeferCleanup);
            } else if function_name.starts_with("runtime.SetFinalizer") {
                // Finalizer for delayed resource release
                patterns.push(GoSemanticPattern::Finalizer);
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
                    // Defer mechanism for resource cleanup
                    else if callee.starts_with("runtime.deferproc") {
                        patterns.push(GoSemanticPattern::DeferCleanup);
                        patterns.push(GoSemanticPattern::RuntimeInternal);
                    }
                    // Finalizer for delayed resource release
                    else if callee.starts_with("runtime.SetFinalizer") {
                        patterns.push(GoSemanticPattern::Finalizer);
                        patterns.push(GoSemanticPattern::RuntimeInternal);
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

    /// Detects potential delayed release issues with finalizers.
    ///
    /// # Objective
    /// Analyze whether a function using `runtime.SetFinalizer` might cause
    /// delayed resource release. Finalizers are executed by the garbage collector
    /// at an unspecified time, which can lead to resource exhaustion if
    /// critical resources are not released promptly.
    ///
    /// # Invariants
    /// - Returns `true` if the function uses finalizers for resource cleanup.
    /// - Returns `false` if the function does not use finalizers.
    /// - The analysis is based on the presence of `Finalizer` pattern.
    ///
    /// # Arguments
    /// * `patterns` - The detected Go semantic patterns for the function.
    ///
    /// # Returns
    /// `true` if finalizer usage might cause delayed release, `false` otherwise.
    pub fn detect_finalizer_delayed_release(&self, patterns: &[GoSemanticPattern]) -> bool {
        // Check if the function uses finalizers for resource cleanup
        patterns
            .iter()
            .any(|p| matches!(p, GoSemanticPattern::Finalizer))
    }

    /// Detects Go pointer violations in CGO calls.
    ///
    /// # Objective
    /// Identify functions that might pass Go GC-managed pointers to C functions,
    /// which violates Go's pointer safety rules. This can lead to dangling
    /// pointers if the Go garbage collector moves the memory while C is using it.
    ///
    /// # Invariants
    /// - Returns `true` if the function has both Go GC allocation and CGO bridge patterns.
    /// - Returns `false` otherwise.
    /// - This is a heuristic-based detection that might have false positives.
    ///
    /// # Arguments
    /// * `patterns` - The detected Go semantic patterns for the function.
    ///
    /// # Returns
    /// `true` if Go pointer violation is detected, `false` otherwise.
    pub fn detect_go_pointer_violation(&self, patterns: &[GoSemanticPattern]) -> bool {
        // Check for combination of Go GC allocation and CGO bridge patterns
        // This indicates that Go-managed memory might be passed to C functions
        let has_go_gc_allocation = patterns
            .iter()
            .any(|p| matches!(p, GoSemanticPattern::GoGCAllocation));
        let has_cgo_bridge = patterns
            .iter()
            .any(|p| matches!(p, GoSemanticPattern::CGOBridge));

        // If both patterns are present, there's a risk of Go pointer violation
        has_go_gc_allocation && has_cgo_bridge
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

    /// Objective: Verify defer mechanism tracking detection
    /// Invariants: runtime.deferproc must be detected as DeferCleanup
    #[test]
    fn test_defer_mechanism_tracking() {
        let adapter = GoAdapter::new();
        let analysis = adapter.analyze_function("runtime.deferproc", None);

        assert!(
            analysis.patterns.contains(&GoSemanticPattern::DeferCleanup),
            "runtime.deferproc must be detected as DeferCleanup"
        );
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::RuntimeInternal),
            "runtime.deferproc must be detected as RuntimeInternal"
        );
        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::SafeInternal,
            "runtime.deferproc must be SafeInternal"
        );
    }

    /// Objective: Verify finalizer detection
    /// Invariants: runtime.SetFinalizer must be detected as Finalizer
    #[test]
    fn test_finalizer_detection() {
        let adapter = GoAdapter::new();
        let analysis = adapter.analyze_function("runtime.SetFinalizer", None);

        assert!(
            analysis.patterns.contains(&GoSemanticPattern::Finalizer),
            "runtime.SetFinalizer must be detected as Finalizer"
        );
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::RuntimeInternal),
            "runtime.SetFinalizer must be detected as RuntimeInternal"
        );
        assert_eq!(
            analysis.ffi_safety,
            GoFFISafety::SafeInternal,
            "runtime.SetFinalizer must be SafeInternal"
        );
    }

    /// Objective: Verify finalizer delayed release detection
    /// Invariants: Functions with finalizer pattern must be detected as potential delayed release
    #[test]
    fn test_finalizer_delayed_release_detection() {
        let adapter = GoAdapter::new();
        let analysis = adapter.analyze_function("runtime.SetFinalizer", None);

        assert!(
            adapter.detect_finalizer_delayed_release(&analysis.patterns),
            "Functions with finalizer pattern must be detected as potential delayed release"
        );

        // Test with a function that doesn't have finalizer
        let analysis_no_finalizer = adapter.analyze_function("runtime.mallocgc", None);
        assert!(
            !adapter.detect_finalizer_delayed_release(&analysis_no_finalizer.patterns),
            "Functions without finalizer pattern must not be detected as delayed release"
        );
    }

    /// Objective: Verify Go pointer violation detection
    /// Invariants: Functions with both Go GC allocation and CGO bridge must be detected as pointer violation
    #[test]
    fn test_go_pointer_violation_detection() {
        let adapter = GoAdapter::new();

        // Test with a function that has both Go GC allocation and CGO bridge
        let body = FunctionBody {
            name: "test_pointer_violation".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%go_ptr".to_string()),
                    operands: vec!["i64 64".to_string(), "i64 0".to_string()],
                    callee: Some("runtime.mallocgc".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%go_ptr = call i8* @runtime.mallocgc(i64 64, i64 0)".to_string(),
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

        let analysis = adapter.analyze_function("test_pointer_violation", Some(&body));

        assert!(
            adapter.detect_go_pointer_violation(&analysis.patterns),
            "Functions with both Go GC allocation and CGO bridge must be detected as pointer violation"
        );

        // Test with a function that has only Go GC allocation
        let analysis_only_go = adapter.analyze_function("runtime.mallocgc", None);
        assert!(
            !adapter.detect_go_pointer_violation(&analysis_only_go.patterns),
            "Functions with only Go GC allocation must not be detected as pointer violation"
        );

        // Test with a function that has only CGO bridge
        let analysis_only_cgo = adapter.analyze_function("_cgo_allocate", None);
        assert!(
            !adapter.detect_go_pointer_violation(&analysis_only_cgo.patterns),
            "Functions with only CGO bridge must not be detected as pointer violation"
        );
    }

    /// Objective: Verify defer mechanism with IR body analysis
    /// Invariants: IR body with runtime.deferproc call must be detected as DeferCleanup
    #[test]
    fn test_defer_mechanism_with_ir_body() {
        let adapter = GoAdapter::new();

        // Create a function body with defer call
        let body = FunctionBody {
            name: "test_defer_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%defer".to_string()),
                    operands: vec!["i64 0".to_string(), "i64 0".to_string()],
                    callee: Some("runtime.deferproc".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "%defer = call i8* @runtime.deferproc(i64 0, i64 0)".to_string(),
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

        let analysis = adapter.analyze_function("test_defer_function", Some(&body));

        assert!(
            analysis.patterns.contains(&GoSemanticPattern::DeferCleanup),
            "IR body with runtime.deferproc call must be detected as DeferCleanup"
        );
        assert!(
            analysis
                .patterns
                .contains(&GoSemanticPattern::CGODesallocation),
            "IR body with _cgo_free call must be detected as CGODesallocation"
        );
    }

    /// Objective: Verify finalizer with IR body analysis
    /// Invariants: IR body with runtime.SetFinalizer call must be detected as Finalizer
    #[test]
    fn test_finalizer_with_ir_body() {
        let adapter = GoAdapter::new();

        // Create a function body with finalizer call
        let body = FunctionBody {
            name: "test_finalizer_function".to_string(),
            instructions: vec![
                IRInstruction {
                    kind: IRInstructionKind::Call,
                    dest: Some("%finalizer".to_string()),
                    operands: vec![
                        "i8*".to_string(),
                        "%obj".to_string(),
                        "i8*".to_string(),
                        "%cleanup".to_string(),
                    ],
                    callee: Some("runtime.SetFinalizer".to_string()),
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text: "call void @runtime.SetFinalizer(i8* %obj, i8* %cleanup)".to_string(),
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

        let analysis = adapter.analyze_function("test_finalizer_function", Some(&body));

        assert!(
            analysis.patterns.contains(&GoSemanticPattern::Finalizer),
            "IR body with runtime.SetFinalizer call must be detected as Finalizer"
        );
        assert!(
            adapter.detect_finalizer_delayed_release(&analysis.patterns),
            "Function with finalizer must be detected as potential delayed release"
        );
    }
}
