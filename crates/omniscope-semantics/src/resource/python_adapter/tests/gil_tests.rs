//! Tests for GIL (Global Interpreter Lock) analysis.
//!
//! This module contains tests for Python GIL management operations,
//! including PyGILState_Ensure, PyGILState_Release, and related patterns.

use super::super::gil;
use super::super::{PythonFFISafety, PythonPattern};

/// Objective: Verify Python GIL acquisition semantics for PyGILState_Ensure
///
/// Invariants:
/// - PyGILState_Ensure must be recognized as GIL acquisition
/// - Must be marked as safe
/// - Confidence should be high (0.95)
#[test]
fn test_py_gil_state_ensure_semantics() {
    let result = gil::analyze_gil_pattern("PyGILState_Ensure");
    assert!(
        result.is_some(),
        "test_py_gil_state_ensure_semantics: PyGILState_Ensure should be recognized"
    );

    let semantic = result.unwrap();
    assert_eq!(
        semantic.pattern,
        PythonPattern::GILAcquire,
        "PyGILState_Ensure should be recognized as GIL acquisition"
    );
    assert!(
        semantic.is_safe,
        "PyGILState_Ensure should be marked as safe"
    );
    assert!(
        semantic.confidence > 0.9,
        "PyGILState_Ensure confidence should be high, got {}",
        semantic.confidence
    );
}

/// Objective: Verify Python GIL release semantics for PyGILState_Release
///
/// Invariants:
/// - PyGILState_Release must be recognized as GIL release
/// - Must be marked as safe
/// - Confidence should be high (0.95)
#[test]
fn test_py_gil_state_release_semantics() {
    let result = gil::analyze_gil_pattern("PyGILState_Release");
    assert!(
        result.is_some(),
        "test_py_gil_state_release_semantics: PyGILState_Release should be recognized"
    );

    let semantic = result.unwrap();
    assert_eq!(
        semantic.pattern,
        PythonPattern::GILRelease,
        "PyGILState_Release should be recognized as GIL release"
    );
    assert!(
        semantic.is_safe,
        "PyGILState_Release should be marked as safe"
    );
    assert!(
        semantic.confidence > 0.9,
        "PyGILState_Release confidence should be high, got {}",
        semantic.confidence
    );
}

/// Objective: Verify non-GIL functions return None
///
/// Invariants:
/// - Non-GIL functions should return None
/// - No panics or errors for unknown functions
#[test]
fn test_non_gil_functions() {
    let result = gil::analyze_gil_pattern("PyList_New");
    assert!(
        result.is_none(),
        "test_non_gil_functions: Non-GIL function should return None"
    );

    let result = gil::analyze_gil_pattern("malloc");
    assert!(
        result.is_none(),
        "test_non_gil_functions: Non-Python function should return None"
    );
}

/// Objective: Verify GIL patterns from IR analysis
///
/// Invariants:
/// - PyGILState_Ensure from IR must be recognized as GIL acquisition
/// - PyGILState_Release from IR must be recognized as GIL release
#[test]
fn test_gil_from_ir() {
    // Test PyGILState_Ensure from IR
    let result = gil::analyze_gil_from_ir("PyGILState_Ensure");
    assert!(
        result.is_some(),
        "test_gil_from_ir: PyGILState_Ensure should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::GILAcquire,
        "PyGILState_Ensure from IR should be recognized as GIL acquisition"
    );

    // Test PyGILState_Release from IR
    let result = gil::analyze_gil_from_ir("PyGILState_Release");
    assert!(
        result.is_some(),
        "test_gil_from_ir: PyGILState_Release should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::GILRelease,
        "PyGILState_Release from IR should be recognized as GIL release"
    );
}

/// Objective: Verify GIL safety assessment
///
/// Invariants:
/// - GIL patterns must produce SafeGIL safety assessment
/// - Non-GIL patterns must not produce SafeGIL
#[test]
fn test_gil_safety_assessment() {
    // Test GIL patterns produce SafeGIL
    let patterns = [PythonPattern::GILAcquire, PythonPattern::GILRelease];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = gil::determine_gil_safety(&pattern_refs);
    assert!(
        safety.is_some(),
        "test_gil_safety_assessment: GIL patterns should produce safety assessment"
    );
    assert_eq!(
        safety.unwrap(),
        PythonFFISafety::SafeGIL,
        "GIL patterns must produce SafeGIL safety assessment"
    );

    // Test non-GIL patterns don't produce SafeGIL
    let patterns = [PythonPattern::NewReference];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = gil::determine_gil_safety(&pattern_refs);
    assert!(
        safety.is_none(),
        "test_gil_safety_assessment: Non-GIL patterns should not produce SafeGIL"
    );
}

/// Objective: Verify is_gil_pattern function
///
/// Invariants:
/// - GILAcquire must be recognized as GIL pattern
/// - GILRelease must be recognized as GIL pattern
/// - Other patterns must not be recognized as GIL pattern
#[test]
fn test_is_gil_pattern() {
    // Test GILAcquire
    let pattern = PythonPattern::GILAcquire;
    assert!(
        gil::is_gil_pattern(&pattern),
        "GILAcquire must be recognized as GIL pattern"
    );

    // Test GILRelease
    let pattern = PythonPattern::GILRelease;
    assert!(
        gil::is_gil_pattern(&pattern),
        "GILRelease must be recognized as GIL pattern"
    );

    // Test non-GIL patterns
    let pattern = PythonPattern::NewReference;
    assert!(
        !gil::is_gil_pattern(&pattern),
        "NewReference must not be recognized as GIL pattern"
    );

    let pattern = PythonPattern::RefCountOp {
        is_increment: true,
        is_null_safe: false,
    };
    assert!(
        !gil::is_gil_pattern(&pattern),
        "RefCountOp must not be recognized as GIL pattern"
    );
}
