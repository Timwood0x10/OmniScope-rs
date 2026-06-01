//! Memory management analysis for Python C API.
//!
//! This module provides analysis for Python memory management operations,
//! including PyMem_Malloc, PyMem_Free, PyObject_Del, and related patterns.

use super::{PythonFFISafety, PythonPattern, PythonSemantic};

/// Analyzes Python memory management patterns from function name.
///
/// # Arguments
///
/// * `function_name` - The function name to analyze
///
/// # Returns
///
/// Returns `Some(PythonSemantic)` if the function is a memory management operation,
/// `None` otherwise.
pub fn analyze_memory_pattern(function_name: &str) -> Option<PythonSemantic> {
    let name = function_name;

    // Object destruction
    if name == "PyObject_Del" || name == "PyObject_Free" {
        return Some(PythonSemantic {
            function_name: name.to_string(),
            pattern: PythonPattern::ObjectDestruction,
            is_safe: true,
            confidence: 0.9,
            reasoning: "Python object destruction".to_string(),
        });
    }

    None
}

/// Analyzes memory management operations from IR instruction callees.
///
/// # Arguments
///
/// * `callee` - The callee function name from IR instruction
///
/// # Returns
///
/// Returns `Some(PythonPattern)` if the callee is a memory management operation,
/// `None` otherwise.
pub fn analyze_memory_from_ir(callee: &str) -> Option<PythonPattern> {
    // Check for object destruction
    if matches!(callee, "PyObject_Del" | "PyObject_Free") {
        return Some(PythonPattern::ObjectDestruction);
    }

    // Check for memory allocation
    if matches!(callee, "PyMem_Malloc" | "PyMem_Calloc" | "PyMem_Realloc") {
        return Some(PythonPattern::MemoryAllocation);
    }

    // Check for memory deallocation
    if callee == "PyMem_Free" {
        return Some(PythonPattern::MemoryDeallocation);
    }

    None
}

/// Determines FFI safety based on memory management patterns.
///
/// # Arguments
///
/// * `patterns` - List of detected Python patterns
///
/// # Returns
///
/// Returns `PythonFFISafety` assessment based on memory management balance.
pub fn determine_memory_safety(patterns: &[&PythonPattern]) -> PythonFFISafety {
    // Check for object destruction
    let has_destruction = patterns
        .iter()
        .any(|p| matches!(p, PythonPattern::ObjectDestruction));
    if has_destruction {
        return PythonFFISafety::SafeRefCount;
    }

    // Check for memory operations
    let has_mem_alloc = patterns
        .iter()
        .any(|p| matches!(p, PythonPattern::MemoryAllocation));
    let has_mem_dealloc = patterns
        .iter()
        .any(|p| matches!(p, PythonPattern::MemoryDeallocation));
    if has_mem_alloc && has_mem_dealloc {
        return PythonFFISafety::SafeRefCount;
    }

    PythonFFISafety::Unknown
}

/// Checks if a pattern is related to memory management.
///
/// # Arguments
///
/// * `pattern` - The Python pattern to check
///
/// # Returns
///
/// Returns `true` if the pattern is related to memory management.
pub fn is_memory_pattern(pattern: &PythonPattern) -> bool {
    matches!(
        pattern,
        PythonPattern::ObjectDestruction
            | PythonPattern::MemoryAllocation
            | PythonPattern::MemoryDeallocation
    )
}
