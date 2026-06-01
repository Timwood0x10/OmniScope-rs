//! Tests for memory management analysis.
//!
//! This module contains tests for Python memory management operations,
//! including PyMem_Malloc, PyMem_Free, PyObject_Del, and related patterns.

use super::super::memory;
use super::super::{PythonFFISafety, PythonPattern};

/// Objective: Verify Python object destruction semantics for PyObject_Del
///
/// Invariants:
/// - PyObject_Del must be recognized as object destruction
/// - Must be marked as safe
/// - Confidence should be high (0.9)
#[test]
fn test_py_object_del_semantics() {
    let result = memory::analyze_memory_pattern("PyObject_Del");
    assert!(
        result.is_some(),
        "test_py_object_del_semantics: PyObject_Del should be recognized"
    );

    let semantic = result.unwrap();
    assert_eq!(
        semantic.pattern,
        PythonPattern::ObjectDestruction,
        "PyObject_Del should be recognized as object destruction"
    );
    assert!(semantic.is_safe, "PyObject_Del should be marked as safe");
    assert!(
        semantic.confidence > 0.8,
        "PyObject_Del confidence should be high, got {}",
        semantic.confidence
    );
}

/// Objective: Verify Python object destruction semantics for PyObject_Free
///
/// Invariants:
/// - PyObject_Free must be recognized as object destruction
/// - Must be marked as safe
/// - Confidence should be high (0.9)
#[test]
fn test_py_object_free_semantics() {
    let result = memory::analyze_memory_pattern("PyObject_Free");
    assert!(
        result.is_some(),
        "test_py_object_free_semantics: PyObject_Free should be recognized"
    );

    let semantic = result.unwrap();
    assert_eq!(
        semantic.pattern,
        PythonPattern::ObjectDestruction,
        "PyObject_Free should be recognized as object destruction"
    );
    assert!(semantic.is_safe, "PyObject_Free should be marked as safe");
    assert!(
        semantic.confidence > 0.8,
        "PyObject_Free confidence should be high, got {}",
        semantic.confidence
    );
}

/// Objective: Verify non-memory functions return None
///
/// Invariants:
/// - Non-memory functions should return None
/// - No panics or errors for unknown functions
#[test]
fn test_non_memory_functions() {
    let result = memory::analyze_memory_pattern("PyList_New");
    assert!(
        result.is_none(),
        "test_non_memory_functions: Non-memory function should return None"
    );

    let result = memory::analyze_memory_pattern("malloc");
    assert!(
        result.is_none(),
        "test_non_memory_functions: Non-Python function should return None"
    );
}

/// Objective: Verify memory patterns from IR analysis
///
/// Invariants:
/// - PyObject_Del from IR must be recognized as object destruction
/// - PyObject_Free from IR must be recognized as object destruction
/// - PyMem_Malloc from IR must be recognized as memory allocation
/// - PyMem_Calloc from IR must be recognized as memory allocation
/// - PyMem_Realloc from IR must be recognized as memory allocation
/// - PyMem_Free from IR must be recognized as memory deallocation
#[test]
fn test_memory_from_ir() {
    // Test PyObject_Del from IR
    let result = memory::analyze_memory_from_ir("PyObject_Del");
    assert!(
        result.is_some(),
        "test_memory_from_ir: PyObject_Del should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::ObjectDestruction,
        "PyObject_Del from IR should be recognized as object destruction"
    );

    // Test PyObject_Free from IR
    let result = memory::analyze_memory_from_ir("PyObject_Free");
    assert!(
        result.is_some(),
        "test_memory_from_ir: PyObject_Free should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::ObjectDestruction,
        "PyObject_Free from IR should be recognized as object destruction"
    );

    // Test PyMem_Malloc from IR
    let result = memory::analyze_memory_from_ir("PyMem_Malloc");
    assert!(
        result.is_some(),
        "test_memory_from_ir: PyMem_Malloc should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::MemoryAllocation,
        "PyMem_Malloc from IR should be recognized as memory allocation"
    );

    // Test PyMem_Calloc from IR
    let result = memory::analyze_memory_from_ir("PyMem_Calloc");
    assert!(
        result.is_some(),
        "test_memory_from_ir: PyMem_Calloc should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::MemoryAllocation,
        "PyMem_Calloc from IR should be recognized as memory allocation"
    );

    // Test PyMem_Realloc from IR
    let result = memory::analyze_memory_from_ir("PyMem_Realloc");
    assert!(
        result.is_some(),
        "test_memory_from_ir: PyMem_Realloc should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::MemoryAllocation,
        "PyMem_Realloc from IR should be recognized as memory allocation"
    );

    // Test PyMem_Free from IR
    let result = memory::analyze_memory_from_ir("PyMem_Free");
    assert!(
        result.is_some(),
        "test_memory_from_ir: PyMem_Free should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::MemoryDeallocation,
        "PyMem_Free from IR should be recognized as memory deallocation"
    );
}

/// Objective: Verify memory safety assessment
///
/// Invariants:
/// - Object destruction must produce SafeRefCount
/// - Balanced memory allocation/deallocation must produce SafeRefCount
/// - Unbalanced memory operations must produce Unknown
#[test]
fn test_memory_safety_assessment() {
    // Test object destruction produces SafeRefCount
    let patterns = [PythonPattern::ObjectDestruction];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = memory::determine_memory_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::SafeRefCount,
        "Object destruction must produce SafeRefCount"
    );

    // Test balanced memory allocation/deallocation
    let patterns = [
        PythonPattern::MemoryAllocation,
        PythonPattern::MemoryDeallocation,
    ];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = memory::determine_memory_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::SafeRefCount,
        "Balanced memory allocation/deallocation must produce SafeRefCount"
    );

    // Test unbalanced memory operations (only allocation)
    let patterns = [PythonPattern::MemoryAllocation];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = memory::determine_memory_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::Unknown,
        "Unbalanced memory allocation must produce Unknown"
    );

    // Test unbalanced memory operations (only deallocation)
    let patterns = [PythonPattern::MemoryDeallocation];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = memory::determine_memory_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::Unknown,
        "Unbalanced memory deallocation must produce Unknown"
    );
}

/// Objective: Verify is_memory_pattern function
///
/// Invariants:
/// - ObjectDestruction must be recognized as memory pattern
/// - MemoryAllocation must be recognized as memory pattern
/// - MemoryDeallocation must be recognized as memory pattern
/// - Other patterns must not be recognized as memory pattern
#[test]
fn test_is_memory_pattern() {
    // Test ObjectDestruction
    let pattern = PythonPattern::ObjectDestruction;
    assert!(
        memory::is_memory_pattern(&pattern),
        "ObjectDestruction must be recognized as memory pattern"
    );

    // Test MemoryAllocation
    let pattern = PythonPattern::MemoryAllocation;
    assert!(
        memory::is_memory_pattern(&pattern),
        "MemoryAllocation must be recognized as memory pattern"
    );

    // Test MemoryDeallocation
    let pattern = PythonPattern::MemoryDeallocation;
    assert!(
        memory::is_memory_pattern(&pattern),
        "MemoryDeallocation must be recognized as memory pattern"
    );

    // Test non-memory patterns
    let pattern = PythonPattern::NewReference;
    assert!(
        !memory::is_memory_pattern(&pattern),
        "NewReference must not be recognized as memory pattern"
    );

    let pattern = PythonPattern::GILAcquire;
    assert!(
        !memory::is_memory_pattern(&pattern),
        "GILAcquire must not be recognized as memory pattern"
    );
}
