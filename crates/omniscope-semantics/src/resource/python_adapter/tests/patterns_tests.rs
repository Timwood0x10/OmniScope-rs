//! Tests for pattern analysis.
//!
//! This module contains tests for Python-specific patterns,
//! including object creation, borrowed references, stolen references,
//! and other semantic patterns.

use super::super::patterns;
use super::super::{PythonFFISafety, PythonPattern};

/// Objective: Verify Python object creation semantics for PyLong_FromLong
///
/// Invariants:
/// - PyLong_FromLong must be recognized as new reference creation
/// - Must be marked as safe
/// - Confidence should be high (0.9)
#[test]
fn test_py_long_from_long_semantics() {
    let result = patterns::analyze_pattern("PyLong_FromLong");
    assert!(
        result.is_some(),
        "test_py_long_from_long_semantics: PyLong_FromLong should be recognized"
    );

    let semantic = result.unwrap();
    assert_eq!(
        semantic.pattern,
        PythonPattern::NewReference,
        "PyLong_FromLong should be recognized as new reference creation"
    );
    assert!(semantic.is_safe, "PyLong_FromLong should be marked as safe");
    assert!(
        semantic.confidence > 0.8,
        "PyLong_FromLong confidence should be high, got {}",
        semantic.confidence
    );
}

/// Objective: Verify Python borrowed reference semantics for PyList_GetItem
///
/// Invariants:
/// - PyList_GetItem must be recognized as borrowed reference
/// - Must be marked as safe
/// - Confidence should be high (0.9)
#[test]
fn test_py_list_get_item_semantics() {
    let result = patterns::analyze_pattern("PyList_GetItem");
    assert!(
        result.is_some(),
        "test_py_list_get_item_semantics: PyList_GetItem should be recognized"
    );

    let semantic = result.unwrap();
    assert_eq!(
        semantic.pattern,
        PythonPattern::BorrowedReference,
        "PyList_GetItem should be recognized as borrowed reference"
    );
    assert!(semantic.is_safe, "PyList_GetItem should be marked as safe");
    assert!(
        semantic.confidence > 0.8,
        "PyList_GetItem confidence should be high, got {}",
        semantic.confidence
    );
}

/// Objective: Verify Python stolen reference semantics for PyTuple_SetItem
///
/// Invariants:
/// - PyTuple_SetItem must be recognized as stolen reference
/// - Must be marked as safe
/// - Confidence should be high (0.9)
#[test]
fn test_py_tuple_set_item_semantics() {
    let result = patterns::analyze_pattern("PyTuple_SetItem");
    assert!(
        result.is_some(),
        "test_py_tuple_set_item_semantics: PyTuple_SetItem should be recognized"
    );

    let semantic = result.unwrap();
    assert_eq!(
        semantic.pattern,
        PythonPattern::StolenReference,
        "PyTuple_SetItem should be recognized as stolen reference"
    );
    assert!(semantic.is_safe, "PyTuple_SetItem should be marked as safe");
    assert!(
        semantic.confidence > 0.8,
        "PyTuple_SetItem confidence should be high, got {}",
        semantic.confidence
    );
}

/// Objective: Verify non-pattern functions return None
///
/// Invariants:
/// - Non-pattern functions should return None
/// - No panics or errors for unknown functions
#[test]
fn test_non_pattern_functions() {
    let result = patterns::analyze_pattern("PyGILState_Ensure");
    assert!(
        result.is_none(),
        "test_non_pattern_functions: Non-pattern function should return None"
    );

    let result = patterns::analyze_pattern("malloc");
    assert!(
        result.is_none(),
        "test_non_pattern_functions: Non-Python function should return None"
    );
}

/// Objective: Verify object creation patterns from IR analysis
///
/// Invariants:
/// - Various Python object creation functions must be recognized
/// - Collection creation functions must be recognized
/// - String/bytes creation functions must be recognized
#[test]
fn test_object_creation_from_ir() {
    // Test collection creation
    let result = patterns::analyze_object_creation_from_ir("PyList_New");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyList_New should be recognized"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::NewReference,
        "PyList_New must be recognized as new reference"
    );

    let result = patterns::analyze_object_creation_from_ir("PyTuple_New");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyTuple_New should be recognized"
    );

    let result = patterns::analyze_object_creation_from_ir("PyDict_New");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyDict_New should be recognized"
    );

    let result = patterns::analyze_object_creation_from_ir("PySet_New");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PySet_New should be recognized"
    );

    // Test object creation
    let result = patterns::analyze_object_creation_from_ir("PyObject_New");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyObject_New should be recognized"
    );

    let result = patterns::analyze_object_creation_from_ir("PyObject_NewVar");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyObject_NewVar should be recognized"
    );

    let result = patterns::analyze_object_creation_from_ir("PyType_GenericAlloc");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyType_GenericAlloc should be recognized"
    );

    // Test string/bytes creation
    let result = patterns::analyze_object_creation_from_ir("PyBytes_FromStringAndSize");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyBytes_FromStringAndSize should be recognized"
    );

    let result = patterns::analyze_object_creation_from_ir("PyBytes_FromString");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyBytes_FromString should be recognized"
    );

    let result = patterns::analyze_object_creation_from_ir("PyUnicode_FromString");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyUnicode_FromString should be recognized"
    );

    let result = patterns::analyze_object_creation_from_ir("PyUnicode_FromStringAndSize");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyUnicode_FromStringAndSize should be recognized"
    );

    // Test value creation
    let result = patterns::analyze_object_creation_from_ir("Py_BuildValue");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: Py_BuildValue should be recognized"
    );

    // Test pattern-suffixed functions
    let result = patterns::analyze_object_creation_from_ir("PyLong_FromLong");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyLong_FromLong should be recognized"
    );

    let result = patterns::analyze_object_creation_from_ir("PyFloat_FromDouble");
    assert!(
        result.is_some(),
        "test_object_creation_from_ir: PyFloat_FromDouble should be recognized"
    );
}

/// Objective: Verify borrowed reference patterns from IR analysis
///
/// Invariants:
/// - PyList_GetItem must be recognized as borrowed reference
/// - PyTuple_GetItem must be recognized as borrowed reference
/// - PyDict_GetItem must be recognized as borrowed reference
#[test]
fn test_borrowed_reference_from_ir() {
    // Test PyList_GetItem
    let result = patterns::analyze_borrowed_reference_from_ir("PyList_GetItem");
    assert!(
        result.is_some(),
        "test_borrowed_reference_from_ir: PyList_GetItem should be recognized"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::BorrowedReference,
        "PyList_GetItem must be recognized as borrowed reference"
    );

    // Test PyTuple_GetItem
    let result = patterns::analyze_borrowed_reference_from_ir("PyTuple_GetItem");
    assert!(
        result.is_some(),
        "test_borrowed_reference_from_ir: PyTuple_GetItem should be recognized"
    );

    // Test PyDict_GetItem
    let result = patterns::analyze_borrowed_reference_from_ir("PyDict_GetItem");
    assert!(
        result.is_some(),
        "test_borrowed_reference_from_ir: PyDict_GetItem should be recognized"
    );
}

/// Objective: Verify stolen reference patterns from IR analysis
///
/// Invariants:
/// - PyTuple_SetItem must be recognized as stolen reference
/// - PyList_SetItem must be recognized as stolen reference
#[test]
fn test_stolen_reference_from_ir() {
    // Test PyTuple_SetItem
    let result = patterns::analyze_stolen_reference_from_ir("PyTuple_SetItem");
    assert!(
        result.is_some(),
        "test_stolen_reference_from_ir: PyTuple_SetItem should be recognized"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::StolenReference,
        "PyTuple_SetItem must be recognized as stolen reference"
    );

    // Test PyList_SetItem
    let result = patterns::analyze_stolen_reference_from_ir("PyList_SetItem");
    assert!(
        result.is_some(),
        "test_stolen_reference_from_ir: PyList_SetItem should be recognized"
    );
}

/// Objective: Verify pattern safety assessment
///
/// Invariants:
/// - Stolen references must produce SafeRefCount
/// - New references must produce SafeNewReference
/// - Borrowed references must produce SafeBorrowedReference
/// - Other patterns must produce Unknown
#[test]
fn test_pattern_safety_assessment() {
    // Test stolen references produce SafeRefCount
    let patterns = [PythonPattern::StolenReference];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = patterns::determine_pattern_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::SafeRefCount,
        "Stolen references must produce SafeRefCount"
    );

    // Test new references produce SafeNewReference
    let patterns = [PythonPattern::NewReference];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = patterns::determine_pattern_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::SafeNewReference,
        "New references must produce SafeNewReference"
    );

    // Test borrowed references produce SafeBorrowedReference
    let patterns = [PythonPattern::BorrowedReference];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = patterns::determine_pattern_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::SafeBorrowedReference,
        "Borrowed references must produce SafeBorrowedReference"
    );

    // Test other patterns produce Unknown
    let patterns = [PythonPattern::GILAcquire];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = patterns::determine_pattern_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::Unknown,
        "Other patterns must produce Unknown"
    );
}

/// Objective: Verify is_object_lifecycle_pattern function
///
/// Invariants:
/// - NewReference must be recognized as object lifecycle pattern
/// - BorrowedReference must be recognized as object lifecycle pattern
/// - StolenReference must be recognized as object lifecycle pattern
/// - Other patterns must not be recognized as object lifecycle pattern
#[test]
fn test_is_object_lifecycle_pattern() {
    // Test NewReference
    let pattern = PythonPattern::NewReference;
    assert!(
        patterns::is_object_lifecycle_pattern(&pattern),
        "NewReference must be recognized as object lifecycle pattern"
    );

    // Test BorrowedReference
    let pattern = PythonPattern::BorrowedReference;
    assert!(
        patterns::is_object_lifecycle_pattern(&pattern),
        "BorrowedReference must be recognized as object lifecycle pattern"
    );

    // Test StolenReference
    let pattern = PythonPattern::StolenReference;
    assert!(
        patterns::is_object_lifecycle_pattern(&pattern),
        "StolenReference must be recognized as object lifecycle pattern"
    );

    // Test non-lifecycle patterns
    let pattern = PythonPattern::GILAcquire;
    assert!(
        !patterns::is_object_lifecycle_pattern(&pattern),
        "GILAcquire must not be recognized as object lifecycle pattern"
    );

    let pattern = PythonPattern::ObjectDestruction;
    assert!(
        !patterns::is_object_lifecycle_pattern(&pattern),
        "ObjectDestruction must not be recognized as object lifecycle pattern"
    );
}
