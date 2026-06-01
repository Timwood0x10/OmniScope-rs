//! Reference counting analysis for Python C API.
//!
//! This module provides analysis for Python reference counting operations,
//! including Py_INCREF, Py_DECREF, Py_XINCREF, Py_XDECREF, and related
//! reference management patterns.

use super::{PythonFFISafety, PythonPattern, PythonSemantic};

/// Analyzes Python reference counting patterns from function name.
///
/// # Arguments
///
/// * `function_name` - The function name to analyze
///
/// # Returns
///
/// Returns `Some(PythonSemantic)` if the function is a reference counting operation,
/// `None` otherwise.
pub fn analyze_refcount_pattern(function_name: &str) -> Option<PythonSemantic> {
    let name = function_name;

    // Reference counting operations
    if name == "Py_INCREF" || name == "Py_XINCREF" {
        return Some(PythonSemantic {
            function_name: name.to_string(),
            pattern: PythonPattern::RefCountOp {
                is_increment: true,
                is_null_safe: name == "Py_XINCREF",
            },
            is_safe: true,
            confidence: 0.99,
            reasoning: "Python reference count increment".to_string(),
        });
    }

    if name == "Py_DECREF" || name == "Py_XDECREF" {
        return Some(PythonSemantic {
            function_name: name.to_string(),
            pattern: PythonPattern::RefCountOp {
                is_increment: false,
                is_null_safe: name == "Py_XDECREF",
            },
            is_safe: true,
            confidence: 0.99,
            reasoning: "Python reference count decrement (conditional release)".to_string(),
        });
    }

    None
}

/// Analyzes reference counting operations from IR instruction callees.
///
/// # Arguments
///
/// * `callee` - The callee function name from IR instruction
///
/// # Returns
///
/// Returns `Some(PythonPattern::RefCountOp)` if the callee is a reference counting operation,
/// `None` otherwise.
pub fn analyze_refcount_from_ir(callee: &str) -> Option<PythonPattern> {
    // Check for reference counting operations
    if callee == "Py_INCREF" || callee == "Py_XINCREF" {
        return Some(PythonPattern::RefCountOp {
            is_increment: true,
            is_null_safe: callee == "Py_XINCREF",
        });
    }

    if callee == "Py_DECREF" || callee == "Py_XDECREF" {
        return Some(PythonPattern::RefCountOp {
            is_increment: false,
            is_null_safe: callee == "Py_XDECREF",
        });
    }

    None
}

/// Determines FFI safety based on reference counting patterns.
///
/// # Arguments
///
/// * `patterns` - List of detected Python patterns
///
/// # Returns
///
/// Returns `PythonFFISafety` assessment based on reference counting balance.
pub fn determine_refcount_safety(patterns: &[&PythonPattern]) -> PythonFFISafety {
    // Count refcount operations by type
    let inc_count = patterns
        .iter()
        .filter(|p| {
            matches!(
                p,
                PythonPattern::RefCountOp {
                    is_increment: true,
                    ..
                }
            )
        })
        .count();
    let dec_count = patterns
        .iter()
        .filter(|p| {
            matches!(
                p,
                PythonPattern::RefCountOp {
                    is_increment: false,
                    ..
                }
            )
        })
        .count();

    // Check for balanced refcount
    if inc_count > 0 && dec_count > 0 {
        if inc_count == dec_count {
            return PythonFFISafety::SafeRefCount;
        }
        if inc_count > dec_count {
            return PythonFFISafety::ConcernRefLeak;
        }
        return PythonFFISafety::ConcernOverRelease;
    }

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

/// Checks if a pattern is related to reference counting operations.
///
/// # Arguments
///
/// * `pattern` - The Python pattern to check
///
/// # Returns
///
/// Returns `true` if the pattern is related to reference counting.
pub fn is_refcount_pattern(pattern: &PythonPattern) -> bool {
    matches!(
        pattern,
        PythonPattern::RefCountOp { .. }
            | PythonPattern::NewReference
            | PythonPattern::BorrowedReference
            | PythonPattern::StolenReference
    )
}
