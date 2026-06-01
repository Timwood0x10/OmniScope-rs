//! Pattern analysis for Python C API.
//!
//! This module provides analysis for Python-specific patterns,
//! including object creation, borrowed references, stolen references,
//! and other semantic patterns.

use super::{PythonFFISafety, PythonPattern, PythonSemantic};

/// Analyzes Python patterns from function name.
///
/// # Arguments
///
/// * `function_name` - The function name to analyze
///
/// # Returns
///
/// Returns `Some(PythonSemantic)` if a Python pattern is detected,
/// `None` otherwise.
pub fn analyze_pattern(function_name: &str) -> Option<PythonSemantic> {
    let name = function_name;

    // Object creation functions
    if name.starts_with("Py")
        && (name.ends_with("_New")
            || name.ends_with("_FromString")
            || name.ends_with("_FromStringAndSize")
            || name.ends_with("_FromDouble")
            || name.ends_with("_FromLong")
            || name.ends_with("_FromUnsignedLong")
            || name.ends_with("_FromLongLong"))
    {
        return Some(PythonSemantic {
            function_name: name.to_string(),
            pattern: PythonPattern::NewReference,
            is_safe: true,
            confidence: 0.9,
            reasoning: "Python object creation with new reference".to_string(),
        });
    }

    // Borrowed reference functions
    if name.starts_with("Py") && name.ends_with("_GetItem") {
        return Some(PythonSemantic {
            function_name: name.to_string(),
            pattern: PythonPattern::BorrowedReference,
            is_safe: true,
            confidence: 0.9,
            reasoning: "Returns borrowed reference; caller must not decrement".to_string(),
        });
    }

    // Steal reference functions
    if name.starts_with("Py") && name.ends_with("_SetItem") {
        return Some(PythonSemantic {
            function_name: name.to_string(),
            pattern: PythonPattern::StolenReference,
            is_safe: true,
            confidence: 0.9,
            reasoning: "Steals reference; caller must not decrement after call".to_string(),
        });
    }

    None
}

/// Analyzes object creation patterns from IR instruction callees.
///
/// # Arguments
///
/// * `callee` - The callee function name from IR instruction
///
/// # Returns
///
/// Returns `Some(PythonPattern::NewReference)` if the callee creates a new reference,
/// `None` otherwise.
pub fn analyze_object_creation_from_ir(callee: &str) -> Option<PythonPattern> {
    // Check for object creation (new reference) — covers both
    // pattern-suffixed functions (Py*_FromLong, Py*_New, etc.)
    // and explicitly listed collection/value constructors.
    if (callee.starts_with("Py")
        && (callee.ends_with("_New")
            || callee.ends_with("_FromString")
            || callee.ends_with("_FromStringAndSize")
            || callee.ends_with("_FromDouble")
            || callee.ends_with("_FromLong")
            || callee.ends_with("_FromUnsignedLong")
            || callee.ends_with("_FromLongLong")))
        || matches!(
            callee,
            "PyList_New"
                | "PyTuple_New"
                | "PyDict_New"
                | "PySet_New"
                | "PyObject_New"
                | "PyObject_NewVar"
                | "PyType_GenericAlloc"
                | "PyBytes_FromStringAndSize"
                | "PyBytes_FromString"
                | "PyUnicode_FromString"
                | "PyUnicode_FromStringAndSize"
                | "Py_BuildValue"
        )
    {
        return Some(PythonPattern::NewReference);
    }

    None
}

/// Analyzes borrowed reference patterns from IR instruction callees.
///
/// # Arguments
///
/// * `callee` - The callee function name from IR instruction
///
/// # Returns
///
/// Returns `Some(PythonPattern::BorrowedReference)` if the callee returns a borrowed reference,
/// `None` otherwise.
pub fn analyze_borrowed_reference_from_ir(callee: &str) -> Option<PythonPattern> {
    // Check for borrowed references
    if callee.starts_with("Py") && callee.ends_with("_GetItem") {
        return Some(PythonPattern::BorrowedReference);
    }

    None
}

/// Analyzes stolen reference patterns from IR instruction callees.
///
/// # Arguments
///
/// * `callee` - The callee function name from IR instruction
///
/// # Returns
///
/// Returns `Some(PythonPattern::StolenReference)` if the callee steals a reference,
/// `None` otherwise.
pub fn analyze_stolen_reference_from_ir(callee: &str) -> Option<PythonPattern> {
    // Check for stolen references
    if callee.starts_with("Py") && callee.ends_with("_SetItem") {
        return Some(PythonPattern::StolenReference);
    }

    None
}

/// Determines FFI safety based on pattern analysis.
///
/// # Arguments
///
/// * `patterns` - List of detected Python patterns
///
/// # Returns
///
/// Returns `PythonFFISafety` assessment based on pattern analysis.
pub fn determine_pattern_safety(patterns: &[&PythonPattern]) -> PythonFFISafety {
    // Check for stolen references (transfer ownership) — higher priority
    // than new references because stolen indicates ownership transfer.
    let has_stolen = patterns
        .iter()
        .any(|p| matches!(p, PythonPattern::StolenReference));
    if has_stolen {
        return PythonFFISafety::SafeRefCount;
    }

    // Check for new reference creation (caller must DECREF)
    let has_new_ref = patterns
        .iter()
        .any(|p| matches!(p, PythonPattern::NewReference));
    if has_new_ref {
        return PythonFFISafety::SafeNewReference;
    }

    // Check for borrowed references
    let has_borrowed = patterns
        .iter()
        .any(|p| matches!(p, PythonPattern::BorrowedReference));
    if has_borrowed {
        return PythonFFISafety::SafeBorrowedReference;
    }

    PythonFFISafety::Unknown
}

/// Checks if a pattern is related to object lifecycle.
///
/// # Arguments
///
/// * `pattern` - The Python pattern to check
///
/// # Returns
///
/// Returns `true` if the pattern is related to object lifecycle.
pub fn is_object_lifecycle_pattern(pattern: &PythonPattern) -> bool {
    matches!(
        pattern,
        PythonPattern::NewReference
            | PythonPattern::BorrowedReference
            | PythonPattern::StolenReference
    )
}
