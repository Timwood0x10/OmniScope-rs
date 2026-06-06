//! Python C API semantic adapter.
//!
//! This module provides semantic analysis for Python C extension code,
//! focusing on Python-specific memory management patterns:
//!
//! - Reference counting (Py_INCREF/Py_DECREF)
//! - Object lifecycle (creation, borrowing, stealing)
//! - GIL (Global Interpreter Lock) management
//! - Python-specific FFI patterns
//!
//! # Architecture
//!
//! ```text
//! LLVM IR ──→ PythonAdapter ──→ PythonSemantic
//!           ──→ analyze_refcount_pattern()
//!           ──→ detect_steal_reference()
//!           ──→ classify_gil_usage()
//!           ──→ analyze_function_body()
//! ```

// Re-export submodules
pub mod exception;
pub mod gil;
pub mod memory;
pub mod patterns;
pub mod refcount;

#[cfg(test)]
mod tests;

use omniscope_ir::{FunctionBody, IRInstructionKind};
use omniscope_types::FamilyId;

use crate::resource::semantic_tree::{
    FactConfidence, FactSource, SemanticFact, SemanticKey, SemanticKind,
};

/// Python semantic analysis result.
#[derive(Debug, Clone, PartialEq)]
pub struct PythonSemantic {
    /// The function being analyzed
    pub function_name: String,
    /// The Python semantic pattern detected
    pub pattern: PythonPattern,
    /// Whether the pattern is safe
    pub is_safe: bool,
    /// Confidence level (0.0-1.0)
    pub confidence: f32,
    /// Human-readable reasoning
    pub reasoning: String,
}

impl PythonSemantic {
    /// Convert a PythonSemantic into a SemanticFact.
    ///
    /// Maps Python-specific patterns (refcount, GIL, reference types)
    /// to SemanticKind variants for unified downstream consumption.
    pub fn to_semantic_fact(&self) -> SemanticFact {
        let key = SemanticKey::Symbol(self.function_name.clone());
        let (kind, confidence) = match &self.pattern {
            PythonPattern::NewReference => (SemanticKind::PythonOwnedRef, FactConfidence::High),
            PythonPattern::BorrowedReference => {
                (SemanticKind::PythonBorrowedRef, FactConfidence::High)
            }
            PythonPattern::StolenReference => {
                (SemanticKind::PythonOwnedRef, FactConfidence::Medium)
            }
            PythonPattern::RefCountOp { is_increment, .. } => {
                if *is_increment {
                    (SemanticKind::PythonRefcountInc, FactConfidence::High)
                } else {
                    (SemanticKind::PythonRefcountDec, FactConfidence::High)
                }
            }
            PythonPattern::GILAcquire | PythonPattern::GILRelease => {
                (SemanticKind::PythonGilProtected, FactConfidence::Medium)
            }
            PythonPattern::ObjectDestruction => {
                (SemanticKind::RaiiDropRelease, FactConfidence::Medium)
            }
            PythonPattern::MemoryAllocation => (SemanticKind::HeapProvenance, FactConfidence::High),
            PythonPattern::MemoryDeallocation => {
                (SemanticKind::RaiiDropRelease, FactConfidence::Medium)
            }
            PythonPattern::ExceptionHandling { .. } => {
                (SemanticKind::CppExceptionPath, FactConfidence::Low)
            }
            PythonPattern::Unknown => (SemanticKind::Unknown, FactConfidence::Low),
        };

        SemanticFact::new(
            key,
            kind,
            confidence,
            FactSource::LanguageAdapter,
            format!("PythonAdapter: {}", self.reasoning),
        )
    }
}

/// Python-specific semantic patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonPattern {
    /// Object creation with new reference
    NewReference,
    /// Borrowed reference (caller must not decrement)
    BorrowedReference,
    /// Stolen reference (caller must not decrement after call)
    StolenReference,
    /// Reference counting operation
    RefCountOp {
        /// Whether it's increment or decrement
        is_increment: bool,
        /// Whether it's NULL-safe variant (XINCREF/XDECREF)
        is_null_safe: bool,
    },
    /// GIL acquisition
    GILAcquire,
    /// GIL release
    GILRelease,
    /// Python object destruction
    ObjectDestruction,
    /// Python memory allocation (PyMem_Malloc, etc.)
    MemoryAllocation,
    /// Python memory deallocation (PyMem_Free, etc.)
    MemoryDeallocation,
    /// Exception handling (PyErr_SetString, PyErr_Format, etc.)
    ExceptionHandling {
        /// Whether this function sets an exception (PyErr_SetString, PyErr_Format)
        is_setter: bool,
        /// Whether this function clears an exception (PyErr_Clear, PyErr_Print)
        is_clearer: bool,
    },
    /// Unknown Python pattern
    Unknown,
}

/// FFI safety assessment for Python functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonFFISafety {
    /// Safe: reference counting operation (balanced INCREF/DECREF)
    SafeRefCount,
    /// Safe: new reference creation (caller must DECREF)
    SafeNewReference,
    /// Safe: borrowed reference (caller must NOT DECREF)
    SafeBorrowedReference,
    /// Safe: GIL management operation
    SafeGIL,
    /// Concern: reference leak detected (INCREF without matching DECREF)
    ConcernRefLeak,
    /// Concern: over-release detected (DECREF without matching INCREF)
    ConcernOverRelease,
    /// Concern: mixing Python and C memory domains
    ConcernMixedMemory,
    /// Concern: exception path resource leak (PyErr_SetString without cleanup)
    ConcernExceptionLeak,
    /// Unknown: cannot determine safety
    Unknown,
}

impl PythonFFISafety {
    /// Returns true if this assessment indicates a safe pattern.
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            PythonFFISafety::SafeRefCount
                | PythonFFISafety::SafeNewReference
                | PythonFFISafety::SafeBorrowedReference
                | PythonFFISafety::SafeGIL
        )
    }

    /// Returns the safety score (0.0 = dangerous, 1.0 = safe).
    pub fn safety_score(&self) -> f32 {
        match self {
            PythonFFISafety::SafeRefCount => 0.95,
            PythonFFISafety::SafeNewReference => 0.9,
            PythonFFISafety::SafeBorrowedReference => 0.85,
            PythonFFISafety::SafeGIL => 0.9,
            PythonFFISafety::ConcernRefLeak => 0.3,
            PythonFFISafety::ConcernOverRelease => 0.2,
            PythonFFISafety::ConcernMixedMemory => 0.25,
            PythonFFISafety::ConcernExceptionLeak => 0.15,
            PythonFFISafety::Unknown => 0.5,
        }
    }
}

/// Python C API function with semantic information.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PythonFunction {
    /// Function name
    name: String,
    /// Semantic pattern
    pattern: PythonPattern,
    /// Whether it's safe
    is_safe: bool,
    /// Family ID
    family: FamilyId,
}

/// Analysis result for a Python function from IR.
#[derive(Debug, Clone)]
pub struct PythonFunctionAnalysis {
    /// The function name analyzed
    pub function_name: String,
    /// Detected semantic patterns from name
    pub name_patterns: Vec<PythonPattern>,
    /// Detected semantic patterns from IR body
    pub body_patterns: Vec<PythonPattern>,
    /// Whether this function manages Python objects (refcount ops)
    pub manages_refcount: bool,
    /// Whether this function manages GIL
    pub manages_gil: bool,
    /// Whether this function creates new references
    pub creates_new_ref: bool,
    /// Whether this function uses borrowed references
    pub uses_borrowed_ref: bool,
    /// Recommended FFI safety assessment
    pub ffi_safety: PythonFFISafety,
}

impl PythonFunctionAnalysis {
    /// Convert Python analysis results into SemanticFact records.
    ///
    /// Each detected PythonPattern maps to a SemanticFact with appropriate
    /// SemanticKind, confidence, and evidence text.
    pub fn to_semantic_facts(&self) -> Vec<SemanticFact> {
        let key = SemanticKey::Symbol(self.function_name.clone());
        let mut facts = Vec::new();

        let all_patterns: Vec<&PythonPattern> = self
            .name_patterns
            .iter()
            .chain(self.body_patterns.iter())
            .collect();

        for pattern in &all_patterns {
            match pattern {
                PythonPattern::NewReference => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::PythonOwnedRef,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("PythonAdapter: new reference in {}", self.function_name),
                    ));
                }
                PythonPattern::BorrowedReference => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::PythonBorrowedRef,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!(
                            "PythonAdapter: borrowed reference in {}",
                            self.function_name
                        ),
                    ));
                }
                PythonPattern::StolenReference => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::PythonOwnedRef,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!("PythonAdapter: stolen reference in {}", self.function_name),
                    ));
                }
                PythonPattern::RefCountOp { is_increment, .. } => {
                    let kind = if *is_increment {
                        SemanticKind::PythonRefcountInc
                    } else {
                        SemanticKind::PythonRefcountDec
                    };
                    facts.push(SemanticFact::new(
                        key.clone(),
                        kind,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("PythonAdapter: refcount op in {}", self.function_name),
                    ));
                }
                PythonPattern::GILAcquire | PythonPattern::GILRelease => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::PythonGilProtected,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!("PythonAdapter: GIL management in {}", self.function_name),
                    ));
                }
                PythonPattern::ObjectDestruction => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RaiiDropRelease,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!(
                            "PythonAdapter: object destruction in {}",
                            self.function_name
                        ),
                    ));
                }
                PythonPattern::MemoryAllocation => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::HeapProvenance,
                        FactConfidence::High,
                        FactSource::LanguageAdapter,
                        format!("PythonAdapter: memory allocation in {}", self.function_name),
                    ));
                }
                PythonPattern::MemoryDeallocation => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::RaiiDropRelease,
                        FactConfidence::Medium,
                        FactSource::LanguageAdapter,
                        format!(
                            "PythonAdapter: memory deallocation in {}",
                            self.function_name
                        ),
                    ));
                }
                PythonPattern::ExceptionHandling { .. } => {
                    facts.push(SemanticFact::new(
                        key.clone(),
                        SemanticKind::CppExceptionPath,
                        FactConfidence::Low,
                        FactSource::LanguageAdapter,
                        format!(
                            "PythonAdapter: exception handling in {}",
                            self.function_name
                        ),
                    ));
                }
                PythonPattern::Unknown => {}
            }
        }

        // Emit FFI safety concern if assessment is unsafe
        if !self.ffi_safety.is_safe() {
            facts.push(SemanticFact::new(
                key,
                SemanticKind::Unknown,
                FactConfidence::Low,
                FactSource::LanguageAdapter,
                format!(
                    "PythonAdapter: FFI safety concern {:?} in {}",
                    self.ffi_safety, self.function_name
                ),
            ));
        }

        facts
    }
}

/// Python adapter for semantic analysis.
///
/// Provides comprehensive Python C API semantic analysis by combining
/// function name pattern matching with IR instruction-level analysis.
/// Supports reference counting, GIL management, and memory operations.
pub struct PythonAdapter {
    /// Known Python C API functions for exact matching
    known_functions: Vec<PythonFunction>,
}

impl PythonAdapter {
    /// Creates a new Python adapter with known Python C API functions.
    ///
    /// # Objective
    /// Initialize the Python adapter with a pre-built list of known
    /// Python C API functions. This provides O(1) lookup for common
    /// Python extension functions like Py_INCREF, PyList_New, etc.
    ///
    /// # Invariants
    /// - The adapter is ready to use immediately after creation.
    /// - Known functions include reference counting, GIL, and memory operations.
    /// - The function list is built at construction time (no lazy loading).
    ///
    /// # Returns
    /// A new `PythonAdapter` instance with known Python C API functions.
    ///
    /// # Examples
    /// ```
    /// use omniscope_semantics::resource::python_adapter::PythonAdapter;
    ///
    /// let adapter = PythonAdapter::new();
    /// let result = adapter.analyze_function("Py_INCREF");
    /// assert!(result.is_some());
    /// ```
    pub fn new() -> Self {
        Self {
            known_functions: Self::build_known_functions(),
        }
    }

    /// Analyzes Python-specific semantics from function name.
    ///
    /// # Objective
    /// Detect Python C API patterns from function names, providing
    /// semantic analysis for Python extension code. This is the primary
    /// analysis method for simple name-based pattern detection.
    ///
    /// # Invariants
    /// - Known functions are checked first for exact match (O(n) scan).
    /// - Pattern-based analysis is used as fallback for unknown functions.
    /// - Returns `None` if no Python pattern is detected.
    /// - Confidence is 0.95 for known functions, 0.9 for pattern matches.
    ///
    /// # Arguments
    /// * `function_name` - The Python C API function name to analyze.
    ///
    /// # Returns
    /// `Some(PythonSemantic)` if a Python pattern is detected, `None` otherwise.
    pub fn analyze_function(&self, function_name: &str) -> Option<PythonSemantic> {
        // Check known functions first for exact match
        // This provides the highest confidence results
        for func in &self.known_functions {
            if func.name == function_name {
                return Some(PythonSemantic {
                    function_name: function_name.to_string(),
                    pattern: func.pattern.clone(),
                    is_safe: func.is_safe,
                    confidence: 0.95,
                    reasoning: format!("Known Python C API function: {}", function_name),
                });
            }
        }

        // Pattern-based analysis for unknown functions
        // Uses prefix/suffix matching to detect Python API patterns
        self.analyze_pattern(function_name)
    }

    /// Analyzes a Python function from its IR body and name.
    ///
    /// # Objective
    /// Provide comprehensive analysis combining both name-based patterns
    /// and IR-level instruction analysis. This gives the most complete
    /// picture of a function's Python semantic behavior.
    ///
    /// # Invariants
    /// - Name patterns are always analyzed first.
    /// - IR body patterns supplement name patterns when available.
    /// - All detected patterns are combined for FFI safety assessment.
    /// - The result always contains the function name.
    ///
    /// # Arguments
    /// * `function_name` - The Python function name to analyze.
    /// * `body` - Optional IR body for instruction-level analysis.
    ///
    /// # Returns
    /// A `PythonFunctionAnalysis` with all detected patterns and safety info.
    pub fn analyze_function_with_ir(
        &self,
        function_name: &str,
        body: Option<&FunctionBody>,
    ) -> PythonFunctionAnalysis {
        let mut name_patterns = Vec::new();
        let mut body_patterns = Vec::new();

        // Step 1: Analyze function name for Python C API patterns
        if let Some(semantic) = self.analyze_function(function_name) {
            name_patterns.push(semantic.pattern);
        }

        // Step 2: Analyze IR body for instruction-level evidence
        // Scans call instructions for known Python API callees
        if let Some(body) = body {
            body_patterns = self.analyze_function_body(body);
        }

        // Step 3: Combine all patterns for comprehensive analysis
        let all_patterns: Vec<&PythonPattern> =
            name_patterns.iter().chain(body_patterns.iter()).collect();

        // Step 4: Determine specific Python behaviors from combined patterns
        // Reference counting operations (Py_INCREF/DECREF, new/borrowed/stolen refs)
        let manages_refcount = all_patterns
            .iter()
            .any(|p| refcount::is_refcount_pattern(p));

        // GIL management operations (PyGILState_Ensure/Release)
        let manages_gil = all_patterns.iter().any(|p| gil::is_gil_pattern(p));

        // New reference creation (caller must DECREF)
        let creates_new_ref = all_patterns
            .iter()
            .any(|p| matches!(p, PythonPattern::NewReference));

        // Borrowed reference usage (caller must NOT DECREF)
        let uses_borrowed_ref = all_patterns
            .iter()
            .any(|p| matches!(p, PythonPattern::BorrowedReference));

        // Step 5: Compute FFI safety assessment from all evidence
        let ffi_safety = self.determine_ffi_safety(function_name, &all_patterns, body);

        // Assemble final analysis result
        PythonFunctionAnalysis {
            function_name: function_name.to_string(),
            name_patterns,
            body_patterns,
            manages_refcount,
            manages_gil,
            creates_new_ref,
            uses_borrowed_ref,
            ffi_safety,
        }
    }

    /// Analyzes function body to detect Python semantic patterns from IR.
    ///
    /// # Objective
    /// Scan IR instructions within a function body to detect Python C API
    /// semantic patterns by examining call instruction callees. Each callee
    /// is checked against all Python pattern analyzers in priority order.
    ///
    /// # Invariants
    /// - Only `Call` instructions are analyzed.
    /// - Pattern analyzers are tried in priority order: refcount, object creation,
    ///   borrowed reference, stolen reference, GIL, memory.
    /// - First matching analyzer wins (early exit with `continue`).
    /// - Multiple patterns may be detected from different instructions.
    /// - An empty Vec is returned if no Python patterns are found.
    ///
    /// # Arguments
    /// * `body` - The IR function body containing instructions to analyze.
    ///
    /// # Returns
    /// A Vec of `PythonPattern` detected from IR instructions.
    fn analyze_function_body(&self, body: &FunctionBody) -> Vec<PythonPattern> {
        let mut patterns = Vec::new();

        // Scan all instructions for Python C API call patterns
        for instruction in &body.instructions {
            if let IRInstructionKind::Call = instruction.kind {
                if let Some(ref callee) = instruction.callee {
                    // Priority 1: Reference counting operations (Py_INCREF, Py_DECREF, etc.)
                    // These are the most common Python C API calls
                    if let Some(pattern) = refcount::analyze_refcount_from_ir(callee) {
                        patterns.push(pattern);
                        continue;
                    }

                    // Priority 2: Object creation functions (PyList_New, PyTuple_New, etc.)
                    // These create new references that callers must manage
                    if let Some(pattern) = patterns::analyze_object_creation_from_ir(callee) {
                        patterns.push(pattern);
                        continue;
                    }

                    // Priority 3: Borrowed reference functions (PyList_GetItem, etc.)
                    // These return borrowed references; callers must NOT DECREF
                    if let Some(pattern) = patterns::analyze_borrowed_reference_from_ir(callee) {
                        patterns.push(pattern);
                        continue;
                    }

                    // Priority 4: Stolen reference functions (PyTuple_SetItem, etc.)
                    // These steal references; callers must NOT DECREF after call
                    if let Some(pattern) = patterns::analyze_stolen_reference_from_ir(callee) {
                        patterns.push(pattern);
                        continue;
                    }

                    // Priority 5: GIL management operations (PyGILState_Ensure, etc.)
                    // These manage the Global Interpreter Lock
                    if let Some(pattern) = gil::analyze_gil_from_ir(callee) {
                        patterns.push(pattern);
                        continue;
                    }

                    // Priority 6: Memory management operations (PyMem_Malloc, etc.)
                    // These handle Python memory allocation/deallocation
                    if let Some(pattern) = memory::analyze_memory_from_ir(callee) {
                        patterns.push(pattern);
                        continue;
                    }

                    // Priority 7: Exception handling operations (PyErr_SetString, PyErr_Format, etc.)
                    // These manage Python exceptions and may indicate error paths
                    if let Some(pattern) = exception::analyze_exception_from_ir(callee) {
                        patterns.push(pattern);
                    }
                }
            }
        }

        patterns
    }

    /// Determines FFI safety based on detected patterns and IR body.
    ///
    /// # Objective
    /// Compute the FFI safety assessment by delegating to specialized
    /// safety analyzers in priority order. Each analyzer examines a
    /// specific aspect of Python memory safety.
    ///
    /// # Invariants
    /// - GIL safety has highest priority (thread safety is critical).
    /// - Refcount safety is checked second (reference balance is essential).
    /// - Memory safety is checked third (allocation/deallocation balance).
    /// - Pattern safety is the final fallback (structural analysis).
    /// - Returns `Unknown` if no analyzer can determine safety.
    ///
    /// # Arguments
    /// * `_function_name` - The function name (reserved for future use).
    /// * `patterns` - The detected Python patterns to assess.
    /// * `_body` - Optional IR body (reserved for future analysis).
    ///
    /// # Returns
    /// A `PythonFFISafety` assessment for the function.
    fn determine_ffi_safety(
        &self,
        _function_name: &str,
        patterns: &[&PythonPattern],
        _body: Option<&FunctionBody>,
    ) -> PythonFFISafety {
        // Priority 1: GIL safety (thread safety is highest priority)
        if let Some(safety) = gil::determine_gil_safety(patterns) {
            return safety;
        }

        // Priority 2: Reference counting safety (balanced INCREF/DECREF)
        let refcount_safety = refcount::determine_refcount_safety(patterns);
        if refcount_safety != PythonFFISafety::Unknown {
            return refcount_safety;
        }

        // Priority 3: Memory management safety (balanced alloc/dealloc)
        let memory_safety = memory::determine_memory_safety(patterns);
        if memory_safety != PythonFFISafety::Unknown {
            return memory_safety;
        }

        // Priority 4: Exception handling safety (setter without clearer)
        let exception_safety = exception::determine_exception_safety(patterns);
        if exception_safety != PythonFFISafety::Unknown {
            return exception_safety;
        }

        // Priority 5: Pattern-based safety (structural analysis)
        patterns::determine_pattern_safety(patterns)
    }

    /// Analyzes Python-specific patterns from function name.
    ///
    /// # Objective
    /// Detect Python C API patterns from function names using specialized
    /// analyzers for refcount, GIL, memory, and general patterns.
    /// This is the fallback when exact name matching fails.
    ///
    /// # Invariants
    /// - Analyzers are tried in priority order: refcount, GIL, memory, general.
    /// - First matching analyzer wins (early return).
    /// - Returns `None` if no pattern is detected.
    ///
    /// # Arguments
    /// * `function_name` - The function name to analyze for Python patterns.
    ///
    /// # Returns
    /// `Some(PythonSemantic)` if a pattern is detected, `None` otherwise.
    fn analyze_pattern(&self, function_name: &str) -> Option<PythonSemantic> {
        // Priority 1: Reference counting patterns (Py_INCREF, Py_DECREF, etc.)
        if let Some(semantic) = refcount::analyze_refcount_pattern(function_name) {
            return Some(semantic);
        }

        // Priority 2: GIL management patterns (PyGILState_Ensure, etc.)
        if let Some(semantic) = gil::analyze_gil_pattern(function_name) {
            return Some(semantic);
        }

        // Priority 3: Memory management patterns (PyObject_Del, etc.)
        if let Some(semantic) = memory::analyze_memory_pattern(function_name) {
            return Some(semantic);
        }

        // Priority 4: Exception handling patterns (PyErr_SetString, PyErr_Format, etc.)
        if let Some(semantic) = exception::analyze_exception_pattern(function_name) {
            return Some(semantic);
        }

        // Priority 5: General patterns (object creation, borrowed refs, etc.)
        patterns::analyze_pattern(function_name)
    }

    /// Builds the list of known Python C API functions.
    fn build_known_functions() -> Vec<PythonFunction> {
        let family = FamilyId::PYTHON_OBJECT;
        vec![
            // Object creation
            PythonFunction {
                name: "PyObject_New".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyObject_NewVar".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyType_GenericAlloc".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            // String/bytes creation
            PythonFunction {
                name: "PyBytes_FromStringAndSize".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyBytes_FromString".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyUnicode_FromString".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyUnicode_FromStringAndSize".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            // Collection creation
            PythonFunction {
                name: "PyList_New".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyTuple_New".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyDict_New".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PySet_New".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            // Reference counting
            PythonFunction {
                name: "Py_DECREF".to_string(),
                pattern: PythonPattern::RefCountOp {
                    is_increment: false,
                    is_null_safe: false,
                },
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "Py_XDECREF".to_string(),
                pattern: PythonPattern::RefCountOp {
                    is_increment: false,
                    is_null_safe: true,
                },
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "Py_INCREF".to_string(),
                pattern: PythonPattern::RefCountOp {
                    is_increment: true,
                    is_null_safe: false,
                },
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "Py_XINCREF".to_string(),
                pattern: PythonPattern::RefCountOp {
                    is_increment: true,
                    is_null_safe: true,
                },
                is_safe: true,
                family,
            },
            // Borrowed references
            PythonFunction {
                name: "PyList_GetItem".to_string(),
                pattern: PythonPattern::BorrowedReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyTuple_GetItem".to_string(),
                pattern: PythonPattern::BorrowedReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyDict_GetItem".to_string(),
                pattern: PythonPattern::BorrowedReference,
                is_safe: true,
                family,
            },
            // New references
            PythonFunction {
                name: "PyList_GetItemRef".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyDict_GetItemRef".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            // Steal references
            PythonFunction {
                name: "PyTuple_SetItem".to_string(),
                pattern: PythonPattern::StolenReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyList_SetItem".to_string(),
                pattern: PythonPattern::StolenReference,
                is_safe: true,
                family,
            },
            // Object destruction
            PythonFunction {
                name: "PyObject_Del".to_string(),
                pattern: PythonPattern::ObjectDestruction,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyObject_Free".to_string(),
                pattern: PythonPattern::ObjectDestruction,
                is_safe: true,
                family,
            },
            // Value creation
            PythonFunction {
                name: "Py_BuildValue".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            // Long/integer creation
            PythonFunction {
                name: "PyLong_FromLong".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyLong_FromUnsignedLong".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyLong_FromLongLong".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyLong_FromDouble".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            // Float creation
            PythonFunction {
                name: "PyFloat_FromDouble".to_string(),
                pattern: PythonPattern::NewReference,
                is_safe: true,
                family,
            },
            // GIL management
            PythonFunction {
                name: "PyGILState_Ensure".to_string(),
                pattern: PythonPattern::GILAcquire,
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyGILState_Release".to_string(),
                pattern: PythonPattern::GILRelease,
                is_safe: true,
                family,
            },
            // Exception handling
            PythonFunction {
                name: "PyErr_SetString".to_string(),
                pattern: PythonPattern::ExceptionHandling {
                    is_setter: true,
                    is_clearer: false,
                },
                is_safe: false,
                family,
            },
            PythonFunction {
                name: "PyErr_Format".to_string(),
                pattern: PythonPattern::ExceptionHandling {
                    is_setter: true,
                    is_clearer: false,
                },
                is_safe: false,
                family,
            },
            PythonFunction {
                name: "PyErr_Occurred".to_string(),
                pattern: PythonPattern::ExceptionHandling {
                    is_setter: false,
                    is_clearer: false,
                },
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyErr_Clear".to_string(),
                pattern: PythonPattern::ExceptionHandling {
                    is_setter: false,
                    is_clearer: true,
                },
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyErr_Print".to_string(),
                pattern: PythonPattern::ExceptionHandling {
                    is_setter: false,
                    is_clearer: true,
                },
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyErr_ExceptionMatches".to_string(),
                pattern: PythonPattern::ExceptionHandling {
                    is_setter: false,
                    is_clearer: false,
                },
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyErr_GivenExceptionMatches".to_string(),
                pattern: PythonPattern::ExceptionHandling {
                    is_setter: false,
                    is_clearer: false,
                },
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyErr_NewException".to_string(),
                pattern: PythonPattern::ExceptionHandling {
                    is_setter: false,
                    is_clearer: false,
                },
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyErr_NewExceptionWithDoc".to_string(),
                pattern: PythonPattern::ExceptionHandling {
                    is_setter: false,
                    is_clearer: false,
                },
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyErr_Fetch".to_string(),
                pattern: PythonPattern::ExceptionHandling {
                    is_setter: false,
                    is_clearer: false,
                },
                is_safe: true,
                family,
            },
            PythonFunction {
                name: "PyErr_Restore".to_string(),
                pattern: PythonPattern::ExceptionHandling {
                    is_setter: false,
                    is_clearer: false,
                },
                is_safe: true,
                family,
            },
        ]
    }
}

impl Default for PythonAdapter {
    fn default() -> Self {
        Self::new()
    }
}
