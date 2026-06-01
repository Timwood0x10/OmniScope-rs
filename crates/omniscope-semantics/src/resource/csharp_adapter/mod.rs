//! C# language adapter for semantic analysis.
//!
//! This module provides C#-specific semantic analysis, including:
//! - P/Invoke call conventions and memory management
//! - .NET garbage collection interactions
//! - IDisposable pattern and SafeHandle usage
//! - C#-specific FFI patterns
//!
//! # C# Memory Model
//!
//! C# uses a managed heap with garbage collection, but can interact with
//! native code through P/Invoke (Platform Invocation Services). This creates
//! two memory domains:
//!
//! 1. **Managed heap**: Managed by .NET GC, allocated via `new` or `GC.Allocate`
//! 2. **Native heap**: Managed by C/C++ malloc/free, used in P/Invoke calls
//!
//! The key concern for P/Invoke analysis: memory allocated in one domain
//! must not be freed in the other domain unless using proper marshaling.
//!
//! # P/Invoke Call Patterns
//!
//! ```text
//! C# code ──→ P/Invoke ──→ Native C functions
//!         ──→ Marshal.AllocHGlobal ──→ Native heap
//!         ──→ Marshal.FreeHGlobal ──→ Native heap
//!         ──→ GCHandle.Alloc ──→ Managed heap pinning
//!         ──→ SafeHandle ──→ Native resource management
//! ```

pub mod dispose;
pub mod gc;
pub mod pinvoke;

#[cfg(test)]
pub mod tests;

use omniscope_ir::{FunctionBody, IRInstructionKind};
use omniscope_types::Language;

/// C#-specific semantic patterns derived from IR analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CSharpSemanticPattern {
    /// P/Invoke call to native function
    PInvokeCall,
    /// Marshal memory allocation (Marshal.AllocHGlobal, Marshal.AllocCoTaskMem)
    MarshalAllocation,
    /// Marshal memory deallocation (Marshal.FreeHGlobal, Marshal.FreeCoTaskMem)
    MarshalDeallocation,
    /// GCHandle allocation (pinning managed objects)
    GCHandleAllocation,
    /// GCHandle deallocation
    GCHandleDeallocation,
    /// SafeHandle usage (critical handle)
    SafeHandleUsage,
    /// IDisposable pattern
    IDisposablePattern,
    /// .NET GC allocation (new object)
    ManagedAllocation,
    /// .NET GC collection
    GCOperation,
    /// COM interop
    COMInterop,
    /// Reflection usage
    Reflection,
    /// Async/Task pattern
    AsyncPattern,
    /// Unknown C# pattern
    Unknown,
}

/// Analysis result for a C# function.
#[derive(Debug, Clone)]
pub struct CSharpFunctionAnalysis {
    /// The function name analyzed
    pub function_name: String,
    /// Detected semantic patterns
    pub patterns: Vec<CSharpSemanticPattern>,
    /// Whether this function is a P/Invoke wrapper
    pub is_pinvoke_wrapper: bool,
    /// Whether this function manages native memory
    pub manages_native_memory: bool,
    /// Whether this function manages managed memory
    pub manages_managed_memory: bool,
    /// Recommended FFI safety assessment
    pub ffi_safety: CSharpFFISafety,
}

/// FFI safety assessment for C# functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpFFISafety {
    /// Safe: pure managed code, no FFI concerns
    SafeManaged,
    /// Safe: P/Invoke with proper memory management (SafeHandle)
    SafePInvoke,
    /// Safe: Marshal operations with balanced alloc/dealloc
    SafeMarshal,
    /// Concern: P/Invoke without proper resource management
    ConcernPInvokeResource,
    /// Concern: Mixed managed/native memory without proper marshaling
    ConcernMixedMemory,
    /// Concern: GCHandle leak (pinning without release)
    ConcernGCHandleLeak,
    /// Unknown: cannot determine safety
    Unknown,
}

impl CSharpFFISafety {
    /// Returns true if this assessment indicates a safe pattern.
    ///
    /// # Objective
    /// Determine whether the FFI safety assessment indicates that the analyzed
    /// C# function is safe from memory safety perspective. This is used to
    /// filter out false positives in P/Invoke-related analysis.
    ///
    /// # Invariants
    /// - `SafeManaged`, `SafePInvoke`, and `SafeMarshal` are considered safe.
    /// - All `Concern*` variants and `Unknown` are considered unsafe.
    /// - The result is deterministic for a given variant.
    ///
    /// # Returns
    /// `true` if the assessment indicates a safe pattern, `false` otherwise.
    pub fn is_safe(&self) -> bool {
        // SafeManaged: pure C# code with no FFI boundary
        // SafePInvoke: P/Invoke with SafeHandle or proper resource management
        // SafeMarshal: Marshal operations with balanced alloc/dealloc
        matches!(
            self,
            CSharpFFISafety::SafeManaged
                | CSharpFFISafety::SafePInvoke
                | CSharpFFISafety::SafeMarshal
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
            // SafeManaged: pure C# code, no cross-boundary concerns
            CSharpFFISafety::SafeManaged => 0.95,
            // SafePInvoke: P/Invoke with SafeHandle (proper resource management)
            CSharpFFISafety::SafePInvoke => 0.9,
            // SafeMarshal: Marshal operations with balanced alloc/dealloc
            CSharpFFISafety::SafeMarshal => 0.85,
            // ConcernPInvokeResource: P/Invoke without SafeHandle (potential leak)
            CSharpFFISafety::ConcernPInvokeResource => 0.3,
            // ConcernMixedMemory: mixing managed and native memory (potential leak/corruption)
            CSharpFFISafety::ConcernMixedMemory => 0.2,
            // ConcernGCHandleLeak: GCHandle without release (memory pinning leak)
            CSharpFFISafety::ConcernGCHandleLeak => 0.1,
            // Unknown: insufficient information for assessment
            CSharpFFISafety::Unknown => 0.5,
        }
    }
}

/// C# adapter for semantic analysis.
///
/// This adapter provides C#-specific semantic analysis by combining
/// function name pattern matching with IR body instruction analysis.
/// It detects P/Invoke patterns, Marshal operations, and .NET GC
/// interactions.
pub struct CSharpAdapter {
    /// Language hint for C#, used to identify the source language
    language: Language,
}

impl CSharpAdapter {
    /// Creates a new C# adapter with CSharp language hint.
    ///
    /// # Objective
    /// Initialize the C# adapter with the correct language identifier
    /// so it can be used for C#-specific semantic analysis in the
    /// semantic engine pipeline.
    ///
    /// # Invariants
    /// - Language is always set to `Language::CSharp`.
    /// - The adapter is ready to use immediately after creation.
    ///
    /// # Returns
    /// A new `CSharpAdapter` instance ready for semantic analysis.
    ///
    /// # Examples
    /// ```
    /// use omniscope_semantics::resource::csharp_adapter::CSharpAdapter;
    /// use omniscope_types::Language;
    ///
    /// let adapter = CSharpAdapter::new();
    /// assert_eq!(adapter.language(), Language::CSharp);
    /// ```
    pub fn new() -> Self {
        Self {
            language: Language::CSharp,
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
    /// - Always returns `Language::CSharp`.
    /// - The value never changes after adapter creation.
    ///
    /// # Returns
    /// The `Language::CSharp` enum variant.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Analyzes a C# function from its IR body and name.
    ///
    /// # Objective
    /// Perform comprehensive semantic analysis of a C# function by
    /// combining function name pattern matching with IR instruction
    /// analysis. This determines the function's memory management
    /// behavior and FFI safety assessment.
    ///
    /// # Invariants
    /// - The function name is always stored in the result.
    /// - Patterns from name and body are combined (not deduplicated).
    /// - P/Invoke wrapper detection is always performed.
    /// - FFI safety assessment covers all detected patterns.
    ///
    /// # Arguments
    /// * `function_name` - The name of the C# function to analyze.
    /// * `body` - Optional IR body containing instruction-level analysis data.
    ///
    /// # Returns
    /// A `CSharpFunctionAnalysis` containing all detected patterns and safety assessment.
    pub fn analyze_function(
        &self,
        function_name: &str,
        body: Option<&FunctionBody>,
    ) -> CSharpFunctionAnalysis {
        // Collect all detected patterns from both name and IR body analysis
        let mut patterns = Vec::new();

        // Step 1: Analyze function name to detect C# P/Invoke and Marshal patterns
        // This is the primary detection mechanism for known function names
        let name_patterns = self.analyze_function_name(function_name);
        patterns.extend(name_patterns);

        // Step 2: Check if the function is a P/Invoke wrapper
        // P/Invoke wrappers bridge managed and native code
        let is_pinvoke_wrapper = self.is_pinvoke_wrapper(function_name);

        // Step 3: Analyze IR body for instruction-level evidence
        // This complements name-based analysis with actual call targets
        if let Some(body) = body {
            let body_patterns = self.analyze_function_body(body);
            patterns.extend(body_patterns);
        }

        // Step 4: Determine memory management flags from collected patterns
        // Native memory: Marshal allocation/deallocation
        let manages_native_memory = patterns.iter().any(|p| {
            matches!(
                p,
                CSharpSemanticPattern::MarshalAllocation
                    | CSharpSemanticPattern::MarshalDeallocation
            )
        });
        // Managed memory: .NET GC allocation
        let manages_managed_memory = patterns
            .iter()
            .any(|p| matches!(p, CSharpSemanticPattern::ManagedAllocation));

        // Step 5: Compute FFI safety assessment based on all evidence
        let ffi_safety = self.determine_ffi_safety(function_name, &patterns, body);

        // Assemble final analysis result
        CSharpFunctionAnalysis {
            function_name: function_name.to_string(),
            patterns,
            is_pinvoke_wrapper,
            manages_native_memory,
            manages_managed_memory,
            ffi_safety,
        }
    }

    /// Analyzes function name to detect C# semantic patterns.
    ///
    /// # Objective
    /// Detect C#-specific semantic patterns from the function name using
    /// prefix-based pattern matching. This handles P/Invoke patterns,
    /// Marshal operations, and .NET runtime functions.
    ///
    /// # Invariants
    /// - P/Invoke functions always get `PInvokeCall` pattern.
    /// - Marshal functions always get appropriate allocation/deallocation pattern.
    /// - SafeHandle functions always get `SafeHandleUsage` pattern.
    /// - An empty Vec is returned for unrecognized function names.
    ///
    /// # Arguments
    /// * `function_name` - The function name to analyze for C# patterns.
    ///
    /// # Returns
    /// A Vec of `CSharpSemanticPattern` detected from the function name.
    fn analyze_function_name(&self, function_name: &str) -> Vec<CSharpSemanticPattern> {
        let mut patterns = Vec::new();

        // P/Invoke patterns: functions called via DllImport
        // These are native functions imported into C# code
        if function_name.contains("P/Invoke") || function_name.contains("DllImport") {
            patterns.push(CSharpSemanticPattern::PInvokeCall);
        }

        // Marshal memory operations
        // These handle memory allocation/deallocation for interop
        if function_name.contains("Marshal.AllocHGlobal")
            || function_name.contains("Marshal.AllocCoTaskMem")
        {
            patterns.push(CSharpSemanticPattern::MarshalAllocation);
        } else if function_name.contains("Marshal.FreeHGlobal")
            || function_name.contains("Marshal.FreeCoTaskMem")
        {
            patterns.push(CSharpSemanticPattern::MarshalDeallocation);
        }

        // GCHandle operations
        // These pin managed objects for native code access
        if function_name.contains("GCHandle.Alloc") {
            patterns.push(CSharpSemanticPattern::GCHandleAllocation);
        } else if function_name.contains("GCHandle.Free") {
            patterns.push(CSharpSemanticPattern::GCHandleDeallocation);
        }

        // SafeHandle usage
        // These are critical handles for native resource management
        if function_name.contains("SafeHandle") || function_name.contains("CriticalHandle") {
            patterns.push(CSharpSemanticPattern::SafeHandleUsage);
        }

        // IDisposable pattern
        // This indicates proper resource cleanup implementation
        if function_name.contains("IDisposable") || function_name.contains(".Dispose()") {
            patterns.push(CSharpSemanticPattern::IDisposablePattern);
        }

        // .NET GC operations
        // These interact with the garbage collector
        if function_name.contains("GC.Collect")
            || function_name.contains("GC.WaitForPendingFinalizers")
        {
            patterns.push(CSharpSemanticPattern::GCOperation);
        }

        // COM interop
        // These handle COM object interactions
        if function_name.contains("Marshal.GetIUnknownForObject")
            || function_name.contains("Marshal.GetObjectForIUnknown")
            || function_name.contains("ComVisible")
        {
            patterns.push(CSharpSemanticPattern::COMInterop);
        }

        patterns
    }

    /// Analyzes function body to detect C# semantic patterns from IR instructions.
    ///
    /// # Objective
    /// Scan IR instructions within a function body to detect C#-specific
    /// semantic patterns by examining call instruction callees. This
    /// complements name-based analysis with instruction-level evidence.
    ///
    /// # Invariants
    /// - Only `Call` instructions are analyzed.
    /// - Each callee is checked against known C# runtime and P/Invoke functions.
    /// - Multiple patterns may be detected from a single instruction.
    /// - An empty Vec is returned if no C# patterns are found.
    ///
    /// # Arguments
    /// * `body` - The IR function body containing instructions to analyze.
    ///
    /// # Returns
    /// A Vec of `CSharpSemanticPattern` detected from IR instructions.
    fn analyze_function_body(&self, body: &FunctionBody) -> Vec<CSharpSemanticPattern> {
        let mut patterns = Vec::new();

        // Scan all instructions for call patterns that indicate C# runtime or P/Invoke usage
        for instruction in &body.instructions {
            if let IRInstructionKind::Call = instruction.kind {
                // Extract called function name from instruction's callee field
                if let Some(ref callee) = instruction.callee {
                    // Marshal memory allocation functions
                    if callee.contains("Marshal.AllocHGlobal")
                        || callee.contains("Marshal.AllocCoTaskMem")
                    {
                        patterns.push(CSharpSemanticPattern::MarshalAllocation);
                    }
                    // Marshal memory deallocation functions
                    else if callee.contains("Marshal.FreeHGlobal")
                        || callee.contains("Marshal.FreeCoTaskMem")
                    {
                        patterns.push(CSharpSemanticPattern::MarshalDeallocation);
                    }
                    // GCHandle allocation
                    else if callee.contains("GCHandle.Alloc") {
                        patterns.push(CSharpSemanticPattern::GCHandleAllocation);
                    }
                    // GCHandle deallocation
                    else if callee.contains("GCHandle.Free") {
                        patterns.push(CSharpSemanticPattern::GCHandleDeallocation);
                    }
                    // SafeHandle usage
                    else if callee.contains("SafeHandle") || callee.contains("CriticalHandle") {
                        patterns.push(CSharpSemanticPattern::SafeHandleUsage);
                    }
                    // IDisposable pattern
                    else if callee.contains("IDisposable") || callee.contains(".Dispose()") {
                        patterns.push(CSharpSemanticPattern::IDisposablePattern);
                    }
                    // P/Invoke calls
                    else if callee.contains("P/Invoke") || callee.contains("DllImport") {
                        patterns.push(CSharpSemanticPattern::PInvokeCall);
                    }
                    // COM interop
                    else if callee.contains("Marshal.GetIUnknownForObject")
                        || callee.contains("Marshal.GetObjectForIUnknown")
                    {
                        patterns.push(CSharpSemanticPattern::COMInterop);
                    }
                }
            }
        }

        patterns
    }

    /// Checks if a function is a P/Invoke wrapper.
    ///
    /// # Objective
    /// Determine whether a function serves as a wrapper for P/Invoke calls
    /// that bridge managed C# code and native C/C++ functions.
    ///
    /// # Invariants
    /// - Functions containing "P/Invoke" are always P/Invoke wrappers.
    /// - Functions containing "DllImport" are always P/Invoke wrappers.
    /// - Functions containing "Marshal" may be P/Invoke related.
    /// - Standard C# functions without P/Invoke patterns return false.
    ///
    /// # Arguments
    /// * `function_name` - The function name to check for P/Invoke wrapper patterns.
    ///
    /// # Returns
    /// `true` if the function is identified as a P/Invoke wrapper, `false` otherwise.
    fn is_pinvoke_wrapper(&self, function_name: &str) -> bool {
        function_name.contains("P/Invoke")
            || function_name.contains("DllImport")
            || function_name.contains("extern")
    }

    /// Determines FFI safety for a C# function based on detected patterns.
    ///
    /// # Objective
    /// Compute the FFI safety assessment by analyzing the combination of
    /// detected patterns and function name. This determines whether the
    /// function poses memory safety risks at the managed/native boundary.
    ///
    /// # Invariants
    /// - SafeHandle usage indicates `SafePInvoke`.
    /// - Balanced Marshal alloc/dealloc indicates `SafeMarshal`.
    /// - Only Marshal alloc or only dealloc indicates `ConcernPInvokeResource`.
    /// - GCHandle leak indicates `ConcernGCHandleLeak`.
    /// - Pure managed code returns `SafeManaged`.
    /// - All other functions return `Unknown`.
    ///
    /// # Arguments
    /// * `function_name` - The function name for heuristic-based assessment.
    /// * `patterns` - The detected C# semantic patterns.
    /// * `_body` - Optional IR body (reserved for future analysis).
    ///
    /// # Returns
    /// A `CSharpFFISafety` assessment for the function.
    fn determine_ffi_safety(
        &self,
        _function_name: &str,
        patterns: &[CSharpSemanticPattern],
        _body: Option<&FunctionBody>,
    ) -> CSharpFFISafety {
        // Priority 1: SafeHandle usage
        // SafeHandle provides deterministic resource cleanup
        if patterns
            .iter()
            .any(|p| matches!(p, CSharpSemanticPattern::SafeHandleUsage))
        {
            return CSharpFFISafety::SafePInvoke;
        }

        // Priority 2: IDisposable pattern
        // IDisposable indicates proper resource cleanup implementation
        if patterns
            .iter()
            .any(|p| matches!(p, CSharpSemanticPattern::IDisposablePattern))
        {
            return CSharpFFISafety::SafeManaged;
        }

        // Priority 3: Marshal operations analysis
        // Check for balanced memory management
        let has_marshal_alloc = patterns
            .iter()
            .any(|p| matches!(p, CSharpSemanticPattern::MarshalAllocation));
        let has_marshal_dealloc = patterns
            .iter()
            .any(|p| matches!(p, CSharpSemanticPattern::MarshalDeallocation));

        if has_marshal_alloc && has_marshal_dealloc {
            // Both alloc and dealloc present: memory lifecycle is balanced
            return CSharpFFISafety::SafeMarshal;
        } else if has_marshal_alloc {
            // Only allocation, no deallocation - potential memory leak
            return CSharpFFISafety::ConcernPInvokeResource;
        } else if has_marshal_dealloc {
            // Only deallocation, no allocation - potential double-free
            return CSharpFFISafety::ConcernPInvokeResource;
        }

        // Priority 4: GCHandle leak detection
        // GCHandle without release indicates memory pinning leak
        let has_gc_handle_alloc = patterns
            .iter()
            .any(|p| matches!(p, CSharpSemanticPattern::GCHandleAllocation));
        let has_gc_handle_dealloc = patterns
            .iter()
            .any(|p| matches!(p, CSharpSemanticPattern::GCHandleDeallocation));

        if has_gc_handle_alloc && !has_gc_handle_dealloc {
            // GCHandle allocation without release - potential leak
            return CSharpFFISafety::ConcernGCHandleLeak;
        }

        // Priority 5: Pure managed code
        // If no FFI patterns detected, it's pure managed code
        if patterns.is_empty() {
            return CSharpFFISafety::SafeManaged;
        }

        // Default: insufficient information for assessment
        CSharpFFISafety::Unknown
    }
}

impl Default for CSharpAdapter {
    fn default() -> Self {
        Self::new()
    }
}
