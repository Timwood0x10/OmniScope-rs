//! GIL (Global Interpreter Lock) analysis for Python C API.
//!
//! This module provides analysis for Python GIL management operations,
//! including PyGILState_Ensure, PyGILState_Release, and related patterns.

use super::{PythonFFISafety, PythonPattern, PythonSemantic};

/// Analyzes Python GIL management patterns from function name.
///
/// # Arguments
///
/// * `function_name` - The function name to analyze
///
/// # Returns
///
/// Returns `Some(PythonSemantic)` if the function is a GIL management operation,
/// `None` otherwise.
pub fn analyze_gil_pattern(function_name: &str) -> Option<PythonSemantic> {
    let name = function_name;

    // GIL management
    if name == "PyGILState_Ensure" {
        return Some(PythonSemantic {
            function_name: name.to_string(),
            pattern: PythonPattern::GILAcquire,
            is_safe: true,
            confidence: 0.95,
            reasoning: "Python GIL acquisition".to_string(),
        });
    }

    if name == "PyGILState_Release" {
        return Some(PythonSemantic {
            function_name: name.to_string(),
            pattern: PythonPattern::GILRelease,
            is_safe: true,
            confidence: 0.95,
            reasoning: "Python GIL release".to_string(),
        });
    }

    None
}

/// Analyzes GIL management operations from IR instruction callees.
///
/// # Arguments
///
/// * `callee` - The callee function name from IR instruction
///
/// # Returns
///
/// Returns `Some(PythonPattern)` if the callee is a GIL management operation,
/// `None` otherwise.
pub fn analyze_gil_from_ir(callee: &str) -> Option<PythonPattern> {
    // Check for GIL management
    if callee == "PyGILState_Ensure" {
        return Some(PythonPattern::GILAcquire);
    }

    if callee == "PyGILState_Release" {
        return Some(PythonPattern::GILRelease);
    }

    None
}

/// Determines FFI safety based on GIL management patterns.
///
/// # Arguments
///
/// * `patterns` - List of detected Python patterns
///
/// # Returns
///
/// Returns `PythonFFISafety::SafeGIL` if GIL management is detected,
/// `None` otherwise.
pub fn determine_gil_safety(patterns: &[&PythonPattern]) -> Option<PythonFFISafety> {
    // Check for GIL management
    let has_gil = patterns
        .iter()
        .any(|p| matches!(p, PythonPattern::GILAcquire | PythonPattern::GILRelease));

    if has_gil {
        return Some(PythonFFISafety::SafeGIL);
    }

    None
}

/// Checks if a pattern is related to GIL management.
///
/// # Arguments
///
/// * `pattern` - The Python pattern to check
///
/// # Returns
///
/// Returns `true` if the pattern is related to GIL management.
pub fn is_gil_pattern(pattern: &PythonPattern) -> bool {
    matches!(
        pattern,
        PythonPattern::GILAcquire | PythonPattern::GILRelease
    )
}
