//! C++ language adapter for semantic analysis.
//!
//! This module provides C++-specific semantic analysis, including:
//! - RAII (Resource Acquisition Is Initialization) patterns
//! - Smart pointers (unique_ptr, shared_ptr, weak_ptr)
//! - Move semantics (std::move, rvalue references)
//! - Virtual functions and polymorphism
//! - Exception handling (try/catch)
//! - Template instantiation
//!
//! # C++ Memory Model
//!
//! C++ supports multiple memory management strategies:
//! 1. **Stack allocation**: Automatic lifetime, RAII cleanup
//! 2. **Heap allocation**: Manual (new/delete) or smart pointer managed
//! 3. **Placement new**: Construct objects in pre-allocated memory
//!
//! The key insight for C++ analysis: RAII ensures deterministic cleanup,
//! but raw pointers and manual memory management can lead to leaks.
//!
//! # C++ FFI Patterns
//!
//! ```text
//! C++ code ──→ extern "C" functions ──→ C ABI
//!          ──→ JNI/JNA ──→ Java interop
//!          ──→ pybind11 ──→ Python interop
//!          ──→ COM interfaces ──→ Windows interop
//! ```

pub mod exception;
pub mod raii;
pub mod smart_pointer;
pub mod template;

#[cfg(test)]
pub mod tests;

use omniscope_ir::{FunctionBody, IRInstructionKind};
use omniscope_types::Language;

/// C++-specific semantic patterns derived from IR analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppSemanticPattern {
    // === RAII Patterns ===
    /// Constructor call (Class::Class, _ZN*CI*)
    Constructor,
    /// Destructor call (Class::~Class, _ZN*DI*)
    Destructor,
    /// RAII guard object (lock_guard, unique_lock, scoped_lock)
    RaiiGuard,

    // === Smart Pointer Patterns ===
    /// unique_ptr creation (std::unique_ptr::unique_ptr, _ZNSt10unique_ptr)
    UniquePtrCreation,
    /// shared_ptr creation (std::shared_ptr::shared_ptr, _ZNSt10shared_ptr)
    SharedPtrCreation,
    /// weak_ptr creation (std::weak_ptr::weak_ptr, _ZNSt10weak_ptr)
    WeakPtrCreation,
    /// Smart pointer release/reset
    SmartPtrRelease,
    /// Reference count increment (shared_ptr copy)
    RefCountIncrement,
    /// Reference count decrement (shared_ptr destroy)
    RefCountDecrement,

    // === Move Semantics ===
    /// Move constructor (Class::Class&&, _ZN*CI*OS*)
    MoveConstructor,
    /// Move assignment operator (operator=&&, _ZN*aSEOS*)
    MoveAssignment,
    /// std::move call
    StdMove,

    // === Virtual Functions ===
    /// Virtual function call (through vtable)
    VirtualCall,
    /// Pure virtual function (abstract class indicator)
    PureVirtual,
    /// Virtual destructor
    VirtualDestructor,

    // === Exception Handling ===
    /// try block
    TryBlock,
    /// catch block
    CatchBlock,
    /// throw expression
    ThrowExpression,
    /// noexcept function
    Noexcept,

    // === Template Instantiation ===
    /// Template instantiation (_ZN*I*E, _ZN*IL*EE)
    TemplateInstantiation,
    /// STL container (std::vector, std::map, etc.)
    StlContainer,
    /// STL algorithm (std::sort, std::find, etc.)
    StlAlgorithm,

    // === Memory Management ===
    /// Raw new expression
    RawNew,
    /// Raw delete expression
    RawDelete,
    /// Placement new
    PlacementNew,
    /// Custom allocator
    CustomAllocator,

    // === C++ FFI ===
    /// extern "C" function
    ExternC,
    /// C++ name mangling present
    MangledName,

    /// Unknown C++ pattern
    Unknown,
}

/// Analysis result for a C++ function.
#[derive(Debug, Clone)]
pub struct CppFunctionAnalysis {
    /// The function name analyzed
    pub function_name: String,
    /// Detected semantic patterns
    pub patterns: Vec<CppSemanticPattern>,
    /// Whether this function uses RAII
    pub uses_raii: bool,
    /// Whether this function uses smart pointers
    pub uses_smart_pointers: bool,
    /// Whether this function uses exception handling
    pub uses_exceptions: bool,
    /// Whether this function is an extern "C" wrapper
    pub is_extern_c: bool,
    /// Recommended FFI safety assessment
    pub ffi_safety: CppFFISafety,
}

/// FFI safety assessment for C++ functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppFFISafety {
    /// Safe: RAII with proper resource management
    SafeRAII,
    /// Safe: Smart pointer usage (deterministic cleanup)
    SafeSmartPointer,
    /// Safe: extern "C" wrapper with proper marshaling
    SafeExternC,
    /// Safe: noexcept function with no resource concerns
    SafeNoexcept,
    /// Concern: Raw new/delete without RAII (potential leak)
    ConcernRawAllocation,
    /// Concern: Virtual destructor missing (potential slicing)
    ConcernVirtualDestructor,
    /// Concern: Exception unsafe code (throw without cleanup)
    ConcernExceptionUnsafe,
    /// Concern: Mixed ownership (raw + smart pointer)
    ConcernMixedOwnership,
    /// Unknown: cannot determine safety
    Unknown,
}

impl CppFFISafety {
    /// Returns true if this assessment indicates a safe pattern.
    ///
    /// # Objective
    /// Determine whether the FFI safety assessment indicates that the analyzed
    /// C++ function is safe from memory safety perspective. This is used to
    /// filter out false positives in C++ interop analysis.
    ///
    /// # Invariants
    /// - `SafeRAII`, `SafeSmartPointer`, `SafeExternC`, and `SafeNoexcept` are safe.
    /// - All `Concern*` variants and `Unknown` are considered unsafe.
    /// - The result is deterministic for a given variant.
    ///
    /// # Returns
    /// `true` if the assessment indicates a safe pattern, `false` otherwise.
    pub fn is_safe(&self) -> bool {
        // SafeRAII: deterministic cleanup via destructors
        // SafeSmartPointer: automatic memory management
        // SafeExternC: C ABI boundary with proper marshaling
        // SafeNoexcept: no exception propagation concerns
        matches!(
            self,
            CppFFISafety::SafeRAII
                | CppFFISafety::SafeSmartPointer
                | CppFFISafety::SafeExternC
                | CppFFISafety::SafeNoexcept
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
    /// - Concern variants score <= 0.4.
    /// - Unknown scores exactly 0.5 (neutral).
    ///
    /// # Returns
    /// A `f32` value between 0.0 (dangerous) and 1.0 (safe).
    pub fn safety_score(&self) -> f32 {
        match self {
            // SafeRAII: deterministic cleanup, highest safety
            CppFFISafety::SafeRAII => 0.95,
            // SafeSmartPointer: automatic memory management
            CppFFISafety::SafeSmartPointer => 0.9,
            // SafeExternC: C ABI boundary, well-defined behavior
            CppFFISafety::SafeExternC => 0.85,
            // SafeNoexcept: no exception concerns
            CppFFISafety::SafeNoexcept => 0.85,
            // ConcernRawAllocation: potential memory leak
            CppFFISafety::ConcernRawAllocation => 0.4,
            // ConcernVirtualDestructor: potential object slicing
            CppFFISafety::ConcernVirtualDestructor => 0.3,
            // ConcernExceptionUnsafe: exception safety violation
            CppFFISafety::ConcernExceptionUnsafe => 0.2,
            // ConcernMixedOwnership: ambiguous ownership semantics
            CppFFISafety::ConcernMixedOwnership => 0.2,
            // Unknown: insufficient information for assessment
            CppFFISafety::Unknown => 0.5,
        }
    }
}

/// C++ adapter for semantic analysis.
///
/// This adapter provides C++-specific semantic analysis by combining
/// function name pattern matching with IR body instruction analysis.
/// It detects RAII patterns, smart pointer usage, and C++ FFI
/// interactions.
pub struct CppAdapter {
    /// Language hint for C++, used to identify the source language
    language: Language,
}

impl CppAdapter {
    /// Creates a new C++ adapter with Cpp language hint.
    ///
    /// # Objective
    /// Initialize the C++ adapter with the correct language identifier
    /// so it can be used for C++-specific semantic analysis in the
    /// semantic engine pipeline.
    ///
    /// # Invariants
    /// - Language is always set to `Language::Cpp`.
    /// - The adapter is ready to use immediately after creation.
    ///
    /// # Returns
    /// A new `CppAdapter` instance ready for semantic analysis.
    ///
    /// # Examples
    /// ```
    /// use omniscope_semantics::resource::cpp_adapter::CppAdapter;
    /// use omniscope_types::Language;
    ///
    /// let adapter = CppAdapter::new();
    /// assert_eq!(adapter.language(), Language::Cpp);
    /// ```
    pub fn new() -> Self {
        Self {
            language: Language::Cpp,
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
    /// - Always returns `Language::Cpp`.
    /// - The value never changes after adapter creation.
    ///
    /// # Returns
    /// The `Language::Cpp` enum variant.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Analyzes a C++ function from its IR body and name.
    ///
    /// # Objective
    /// Perform comprehensive semantic analysis of a C++ function by
    /// combining function name pattern matching with IR instruction
    /// analysis. This determines the function's memory management
    /// behavior and FFI safety assessment.
    ///
    /// # Invariants
    /// - The function name is always stored in the result.
    /// - Patterns from name and body are combined (not deduplicated).
    /// - RAII and smart pointer detection is always performed.
    /// - FFI safety assessment covers all detected patterns.
    ///
    /// # Arguments
    /// * `function_name` - The name of the C++ function to analyze.
    /// * `body` - Optional IR body containing instruction-level analysis data.
    ///
    /// # Returns
    /// A `CppFunctionAnalysis` containing all detected patterns and safety assessment.
    pub fn analyze_function(
        &self,
        function_name: &str,
        body: Option<&FunctionBody>,
    ) -> CppFunctionAnalysis {
        // Collect all detected patterns from both name and IR body analysis
        let mut patterns = Vec::new();

        // Step 1: Analyze function name to detect C++ patterns
        // This is the primary detection mechanism for mangled C++ names
        let name_patterns = self.analyze_function_name(function_name);
        patterns.extend(name_patterns);

        // Step 2: Check if the function is an extern "C" wrapper
        // extern "C" functions use C ABI and bypass name mangling
        let is_extern_c = self.is_extern_c_function(function_name);

        // Step 3: Analyze IR body for instruction-level evidence
        // This complements name-based analysis with actual call targets
        if let Some(body) = body {
            let body_patterns = self.analyze_function_body(body);
            patterns.extend(body_patterns);
        }

        // Step 4: Determine feature flags from collected patterns
        // RAII: constructors, destructors, guard objects
        let uses_raii = patterns.iter().any(|p| {
            matches!(
                p,
                CppSemanticPattern::Constructor
                    | CppSemanticPattern::Destructor
                    | CppSemanticPattern::RaiiGuard
            )
        });
        // Smart pointers: unique_ptr, shared_ptr, weak_ptr
        let uses_smart_pointers = patterns.iter().any(|p| {
            matches!(
                p,
                CppSemanticPattern::UniquePtrCreation
                    | CppSemanticPattern::SharedPtrCreation
                    | CppSemanticPattern::WeakPtrCreation
            )
        });
        // Exception handling: try/catch/throw
        let uses_exceptions = patterns.iter().any(|p| {
            matches!(
                p,
                CppSemanticPattern::TryBlock
                    | CppSemanticPattern::CatchBlock
                    | CppSemanticPattern::ThrowExpression
            )
        });

        // Step 5: Compute FFI safety assessment based on all evidence
        let ffi_safety = self.determine_ffi_safety(function_name, &patterns, body);

        // Assemble final analysis result
        CppFunctionAnalysis {
            function_name: function_name.to_string(),
            patterns,
            uses_raii,
            uses_smart_pointers,
            uses_exceptions,
            is_extern_c,
            ffi_safety,
        }
    }

    /// Analyzes function name to detect C++ semantic patterns.
    ///
    /// # Objective
    /// Detect C++-specific semantic patterns from the function name using
    /// pattern matching on mangled names and known C++ identifiers.
    /// This handles constructors, destructors, smart pointers, and STL.
    ///
    /// # Invariants
    /// - Mangled names starting with `_Z` are always detected as MangledName.
    /// - Constructor patterns (`C1`, `C2`, `CI`) are detected as Constructor.
    /// - Destructor patterns (`D0`, `D1`, `D2`) are detected as Destructor.
    /// - STL patterns are detected as appropriate StlContainer/StlAlgorithm.
    /// - An empty Vec is returned for unrecognized function names.
    ///
    /// # Arguments
    /// * `function_name` - The function name to analyze for C++ patterns.
    ///
    /// # Returns
    /// A Vec of `CppSemanticPattern` detected from the function name.
    fn analyze_function_name(&self, function_name: &str) -> Vec<CppSemanticPattern> {
        let mut patterns = Vec::new();

        // Detect mangled C++ names (Itanium ABI mangling scheme)
        // All mangled names start with "_Z" in the Itanium C++ ABI
        if function_name.starts_with("_Z") || function_name.starts_with("__Z") {
            patterns.push(CppSemanticPattern::MangledName);

            // Detect constructors: C1 (complete), C2 (base), CI (in-charge)
            // Pattern: _ZN...CI... or _ZN...C1... or _ZN...C2...
            if function_name.contains("C1E")
                || function_name.contains("C2E")
                || function_name.contains("CI")
            {
                patterns.push(CppSemanticPattern::Constructor);

                // Check for move constructor: takes rvalue reference parameter
                // Move constructors have "OS" (other source) or "OE" in parameter
                if function_name.contains("EOS") || function_name.contains("OE") {
                    patterns.push(CppSemanticPattern::MoveConstructor);
                }
            }

            // Detect destructors: D0 (deleting), D1 (complete), D2 (base)
            // Pattern: _ZN...D0... or _ZN...D1... or _ZN...D2...
            if function_name.contains("D0E")
                || function_name.contains("D1E")
                || function_name.contains("D2E")
            {
                patterns.push(CppSemanticPattern::Destructor);

                // Virtual destructor: often in classes with virtual functions
                // This is a heuristic - virtual destructors are common in polymorphic classes
                if function_name.contains("D0Ev") || function_name.contains("D1Ev") {
                    patterns.push(CppSemanticPattern::VirtualDestructor);
                }
            }

            // Detect move assignment: operator=&&
            // Pattern: _ZN...aSE... (operator= with move semantics)
            if function_name.contains("aSEOS") || function_name.contains("aSEO") {
                patterns.push(CppSemanticPattern::MoveAssignment);
            }

            // Detect smart pointer operations
            // unique_ptr: _ZNSt10unique_ptr
            if function_name.contains("10unique_ptr") {
                patterns.push(CppSemanticPattern::UniquePtrCreation);
            }
            // shared_ptr: _ZNSt10shared_ptr
            if function_name.contains("10shared_ptr") {
                patterns.push(CppSemanticPattern::SharedPtrCreation);
            }
            // weak_ptr: _ZNSt10weak_ptr
            if function_name.contains("10weak_ptr") {
                patterns.push(CppSemanticPattern::WeakPtrCreation);
            }

            // Detect reference count operations
            // Increments: __add_ref, _M_add_ref
            if function_name.contains("_M_add_ref") || function_name.contains("__add_ref") {
                patterns.push(CppSemanticPattern::RefCountIncrement);
            }
            // Decrements: __release, _M_release
            if function_name.contains("_M_release") || function_name.contains("__release") {
                patterns.push(CppSemanticPattern::RefCountDecrement);
            }

            // Detect STL containers
            // vector: _ZNSt6vector, deque: _ZNSt5deque, list: _ZNSt4list
            // map: _ZNSt3map, set: _ZNSt3set, unordered_map: _ZNSt13unordered_map
            if function_name.contains("6vector")
                || function_name.contains("5deque")
                || function_name.contains("4list")
                || function_name.contains("3map")
                || function_name.contains("3set")
                || function_name.contains("13unordered_map")
                || function_name.contains("13unordered_set")
            {
                patterns.push(CppSemanticPattern::StlContainer);
            }

            // Detect STL algorithms
            // sort: _ZNSt4sort, find: _ZNSt4find, transform: _ZNSt9transform
            if function_name.contains("4sort")
                || function_name.contains("4find")
                || function_name.contains("9transform")
                || function_name.contains("6for_each")
            {
                patterns.push(CppSemanticPattern::StlAlgorithm);
            }

            // Detect template instantiation
            // Templates have nested name indicators: _ZN...I...E
            if (function_name.contains('I') && function_name.contains('E'))
                || function_name.contains("IL")
            {
                patterns.push(CppSemanticPattern::TemplateInstantiation);
            }
        }

        // Detect non-mangled C++ patterns
        // RAII guard objects
        if function_name.contains("lock_guard")
            || function_name.contains("unique_lock")
            || function_name.contains("scoped_lock")
            || function_name.contains("RAII")
        {
            patterns.push(CppSemanticPattern::RaiiGuard);
        }

        // Detect std::move
        if function_name.contains("std::move") || function_name.contains("4move") {
            patterns.push(CppSemanticPattern::StdMove);
        }

        // Detect placement new
        if function_name.contains("placement") || function_name.contains("placenew") {
            patterns.push(CppSemanticPattern::PlacementNew);
        }

        // Detect virtual calls (vtable access patterns)
        if function_name.contains("_vptr") || function_name.contains("vtable") {
            patterns.push(CppSemanticPattern::VirtualCall);
        }

        // Detect pure virtual functions
        if function_name.contains("__cxa_pure_virtual") || function_name.contains("pure_virtual") {
            patterns.push(CppSemanticPattern::PureVirtual);
        }

        // Detect exception handling
        if function_name.contains("__cxa_throw") || function_name.contains("__cxa_rethrow") {
            patterns.push(CppSemanticPattern::ThrowExpression);
        }
        if function_name.contains("__cxa_begin_catch") || function_name.contains("__cxa_end_catch")
        {
            patterns.push(CppSemanticPattern::CatchBlock);
        }
        if function_name.contains("__cxa_begin_cleanup") {
            patterns.push(CppSemanticPattern::TryBlock);
        }

        // Detect noexcept
        if function_name.contains("noexcept") || function_name.contains("DnE") {
            patterns.push(CppSemanticPattern::Noexcept);
        }

        // Detect raw new/delete (non-mangled)
        if function_name == "_Znwj" || function_name == "_Znwm" || function_name == "operator new" {
            patterns.push(CppSemanticPattern::RawNew);
        }
        if function_name == "_ZdlPv"
            || function_name == "_ZdaPv"
            || function_name == "operator delete"
        {
            patterns.push(CppSemanticPattern::RawDelete);
        }

        patterns
    }

    /// Analyzes function body to detect C++ semantic patterns from IR instructions.
    ///
    /// # Objective
    /// Scan IR instructions within a function body to detect C++-specific
    /// semantic patterns by examining call instruction callees. This
    /// complements name-based analysis with instruction-level evidence.
    ///
    /// # Invariants
    /// - Only `Call` instructions are analyzed.
    /// - Each callee is checked against known C++ runtime and STL functions.
    /// - Multiple patterns may be detected from a single instruction.
    /// - An empty Vec is returned if no C++ patterns are found.
    ///
    /// # Arguments
    /// * `body` - The IR function body containing instructions to analyze.
    ///
    /// # Returns
    /// A Vec of `CppSemanticPattern` detected from IR instructions.
    fn analyze_function_body(&self, body: &FunctionBody) -> Vec<CppSemanticPattern> {
        let mut patterns = Vec::new();

        // Scan all instructions for call patterns that indicate C++ runtime usage
        for instruction in &body.instructions {
            if let IRInstructionKind::Call = instruction.kind {
                // Extract called function name from instruction's callee field
                if let Some(ref callee) = instruction.callee {
                    // Smart pointer operations
                    if callee.contains("unique_ptr") {
                        patterns.push(CppSemanticPattern::UniquePtrCreation);
                    }
                    if callee.contains("shared_ptr") {
                        patterns.push(CppSemanticPattern::SharedPtrCreation);
                    }
                    if callee.contains("weak_ptr") {
                        patterns.push(CppSemanticPattern::WeakPtrCreation);
                    }

                    // Reference count operations
                    if callee.contains("_M_add_ref") || callee.contains("__add_ref") {
                        patterns.push(CppSemanticPattern::RefCountIncrement);
                    }
                    if callee.contains("_M_release") || callee.contains("__release") {
                        patterns.push(CppSemanticPattern::RefCountDecrement);
                    }

                    // RAII guard objects
                    if callee.contains("lock_guard")
                        || callee.contains("unique_lock")
                        || callee.contains("scoped_lock")
                    {
                        patterns.push(CppSemanticPattern::RaiiGuard);
                    }

                    // std::move
                    if callee.contains("std::move") || callee.contains("4move") {
                        patterns.push(CppSemanticPattern::StdMove);
                    }

                    // Exception handling
                    if callee.contains("__cxa_throw") || callee.contains("__cxa_rethrow") {
                        patterns.push(CppSemanticPattern::ThrowExpression);
                    }
                    if callee.contains("__cxa_begin_catch") || callee.contains("__cxa_end_catch") {
                        patterns.push(CppSemanticPattern::CatchBlock);
                    }

                    // Raw new/delete
                    if callee == "_Znwj"
                        || callee == "_Znwm"
                        || callee == "operator new"
                        || callee.contains("malloc")
                    {
                        patterns.push(CppSemanticPattern::RawNew);
                    }
                    if callee == "_ZdlPv"
                        || callee == "_ZdaPv"
                        || callee == "operator delete"
                        || callee.contains("free")
                    {
                        patterns.push(CppSemanticPattern::RawDelete);
                    }

                    // Constructor/destructor calls
                    if callee.contains("C1E") || callee.contains("C2E") {
                        patterns.push(CppSemanticPattern::Constructor);
                    }
                    if callee.contains("D1E") || callee.contains("D2E") {
                        patterns.push(CppSemanticPattern::Destructor);
                    }

                    // Virtual calls (through vtable)
                    if callee.contains("_vptr") || callee.contains("vtable") {
                        patterns.push(CppSemanticPattern::VirtualCall);
                    }
                }
            }
        }

        patterns
    }

    /// Checks if a function is an extern "C" wrapper.
    ///
    /// # Objective
    /// Determine whether a function uses C linkage (extern "C") which
    /// bypasses C++ name mangling and uses the C ABI. This is common
    /// for FFI boundaries.
    ///
    /// # Invariants
    /// - Functions starting with "c_" or "C_" are treated as extern "C".
    /// - Functions without mangling that look like C functions are extern "C".
    /// - Mangled C++ names are never extern "C".
    ///
    /// # Arguments
    /// * `function_name` - The function name to check for extern "C" patterns.
    ///
    /// # Returns
    /// `true` if the function is identified as extern "C", `false` otherwise.
    fn is_extern_c_function(&self, function_name: &str) -> bool {
        // extern "C" functions don't have C++ name mangling
        // They typically have simple C-style names
        if function_name.starts_with("_Z") || function_name.starts_with("__Z") {
            // Mangled C++ name - not extern "C"
            return false;
        }

        // Common extern "C" patterns
        function_name.starts_with("c_")
            || function_name.starts_with("C_")
            || function_name.starts_with("ffi_")
            || function_name.starts_with("JNI_")
            // Simple C-style names (no namespace:: class:: indicators)
            || (!function_name.contains("::") && !function_name.contains("__"))
    }

    /// Determines FFI safety for a C++ function based on detected patterns.
    ///
    /// # Objective
    /// Compute the FFI safety assessment by analyzing the combination of
    /// detected patterns and function name. This determines whether the
    /// function poses memory safety risks at the C++ FFI boundary.
    ///
    /// # Invariants
    /// - RAII with balanced construction/destruction is `SafeRAII`.
    /// - Smart pointer usage is `SafeSmartPointer`.
    /// - extern "C" functions are `SafeExternC`.
    /// - Raw new without delete is `ConcernRawAllocation`.
    /// - Missing virtual destructor is `ConcernVirtualDestructor`.
    /// - Exception unsafe code is `ConcernExceptionUnsafe`.
    /// - Mixed ownership is `ConcernMixedOwnership`.
    /// - All other functions return `Unknown`.
    ///
    /// # Arguments
    /// * `_function_name` - The function name for heuristic-based assessment.
    /// * `patterns` - The detected C++ semantic patterns.
    /// * `_body` - Optional IR body (reserved for future analysis).
    ///
    /// # Returns
    /// A `CppFFISafety` assessment for the function.
    fn determine_ffi_safety(
        &self,
        _function_name: &str,
        patterns: &[CppSemanticPattern],
        _body: Option<&FunctionBody>,
    ) -> CppFFISafety {
        // Priority 1: RAII analysis
        // RAII with balanced construction/destruction is the safest pattern
        let has_constructor = patterns
            .iter()
            .any(|p| matches!(p, CppSemanticPattern::Constructor));
        let has_destructor = patterns
            .iter()
            .any(|p| matches!(p, CppSemanticPattern::Destructor));
        let has_raii_guard = patterns
            .iter()
            .any(|p| matches!(p, CppSemanticPattern::RaiiGuard));

        if has_constructor && has_destructor {
            // Balanced RAII: constructor and destructor present
            return CppFFISafety::SafeRAII;
        }
        if has_raii_guard {
            // RAII guard object (lock_guard, etc.)
            return CppFFISafety::SafeRAII;
        }

        // Priority 2: Smart pointer analysis
        // Smart pointers provide automatic memory management
        let has_smart_ptr = patterns.iter().any(|p| {
            matches!(
                p,
                CppSemanticPattern::UniquePtrCreation
                    | CppSemanticPattern::SharedPtrCreation
                    | CppSemanticPattern::WeakPtrCreation
            )
        });
        let has_raw_alloc = patterns
            .iter()
            .any(|p| matches!(p, CppSemanticPattern::RawNew));
        let has_raw_dealloc = patterns
            .iter()
            .any(|p| matches!(p, CppSemanticPattern::RawDelete));

        if has_smart_ptr && !has_raw_alloc {
            // Only smart pointers, no raw allocation
            return CppFFISafety::SafeSmartPointer;
        }

        // Priority 3: extern "C" analysis
        // extern "C" functions use C ABI
        let is_extern_c = patterns
            .iter()
            .any(|p| matches!(p, CppSemanticPattern::ExternC));
        if is_extern_c {
            return CppFFISafety::SafeExternC;
        }

        // Priority 4: noexcept analysis
        // noexcept functions don't throw exceptions
        let is_noexcept = patterns
            .iter()
            .any(|p| matches!(p, CppSemanticPattern::Noexcept));
        if is_noexcept && !has_raw_alloc {
            return CppFFISafety::SafeNoexcept;
        }

        // Priority 5: Concern detection
        // Mixed ownership: smart pointer + raw pointer (most concerning)
        if has_smart_ptr && has_raw_alloc {
            return CppFFISafety::ConcernMixedOwnership;
        }

        // Raw new without delete - potential memory leak
        if has_raw_alloc && !has_raw_dealloc {
            return CppFFISafety::ConcernRawAllocation;
        }

        // Virtual destructor missing: potential object slicing
        let has_virtual_call = patterns
            .iter()
            .any(|p| matches!(p, CppSemanticPattern::VirtualCall));
        let has_virtual_destructor = patterns
            .iter()
            .any(|p| matches!(p, CppSemanticPattern::VirtualDestructor));
        if has_virtual_call && !has_virtual_destructor {
            return CppFFISafety::ConcernVirtualDestructor;
        }

        // Exception unsafe: throw without proper cleanup
        let has_throw = patterns
            .iter()
            .any(|p| matches!(p, CppSemanticPattern::ThrowExpression));
        let has_catch = patterns
            .iter()
            .any(|p| matches!(p, CppSemanticPattern::CatchBlock));
        if has_throw && !has_catch {
            return CppFFISafety::ConcernExceptionUnsafe;
        }

        // Default: insufficient information for assessment
        CppFFISafety::Unknown
    }
}

impl Default for CppAdapter {
    fn default() -> Self {
        Self::new()
    }
}
