//! Tests for reference counting analysis.
//!
//! This module contains tests for Python reference counting operations,
//! including Py_INCREF, Py_DECREF, Py_XINCREF, Py_XDECREF, and related patterns.

use super::super::refcount;
use super::super::{PythonFFISafety, PythonPattern};

/// Objective: Verify Python reference counting semantics for Py_INCREF
///
/// Invariants:
/// - Py_INCREF must be recognized as reference count increment
/// - Must not be NULL-safe
/// - Must be marked as safe
/// - Confidence should be high (0.99)
#[test]
fn test_py_incref_semantics() {
    let result = refcount::analyze_refcount_pattern("Py_INCREF");
    assert!(
        result.is_some(),
        "test_py_incref_semantics: Py_INCREF should be recognized"
    );

    let semantic = result.unwrap();
    assert_eq!(
        semantic.pattern,
        PythonPattern::RefCountOp {
            is_increment: true,
            is_null_safe: false,
        },
        "Py_INCREF should be recognized as reference count increment"
    );
    assert!(semantic.is_safe, "Py_INCREF should be marked as safe");
    assert!(
        semantic.confidence > 0.9,
        "Py_INCREF confidence should be high, got {}",
        semantic.confidence
    );
}

/// Objective: Verify Python reference counting semantics for Py_DECREF
///
/// Invariants:
/// - Py_DECREF must be recognized as reference count decrement
/// - Must not be NULL-safe
/// - Must be marked as safe
/// - Confidence should be high (0.99)
#[test]
fn test_py_decref_semantics() {
    let result = refcount::analyze_refcount_pattern("Py_DECREF");
    assert!(
        result.is_some(),
        "test_py_decref_semantics: Py_DECREF should be recognized"
    );

    let semantic = result.unwrap();
    assert_eq!(
        semantic.pattern,
        PythonPattern::RefCountOp {
            is_increment: false,
            is_null_safe: false,
        },
        "Py_DECREF should be recognized as reference count decrement"
    );
    assert!(semantic.is_safe, "Py_DECREF should be marked as safe");
}

/// Objective: Verify Python NULL-safe reference counting semantics for Py_XINCREF
///
/// Invariants:
/// - Py_XINCREF must be recognized as NULL-safe increment
/// - Must be marked as safe
#[test]
fn test_py_xincref_semantics() {
    let result = refcount::analyze_refcount_pattern("Py_XINCREF");
    assert!(
        result.is_some(),
        "test_py_xincref_semantics: Py_XINCREF should be recognized"
    );

    let semantic = result.unwrap();
    assert_eq!(
        semantic.pattern,
        PythonPattern::RefCountOp {
            is_increment: true,
            is_null_safe: true,
        },
        "Py_XINCREF should be recognized as NULL-safe increment"
    );
    assert!(semantic.is_safe, "Py_XINCREF should be marked as safe");
}

/// Objective: Verify Python NULL-safe reference counting semantics for Py_XDECREF
///
/// Invariants:
/// - Py_XDECREF must be recognized as NULL-safe decrement
/// - Must be marked as safe
#[test]
fn test_py_xdecref_semantics() {
    let result = refcount::analyze_refcount_pattern("Py_XDECREF");
    assert!(
        result.is_some(),
        "test_py_xdecref_semantics: Py_XDECREF should be recognized"
    );

    let semantic = result.unwrap();
    assert_eq!(
        semantic.pattern,
        PythonPattern::RefCountOp {
            is_increment: false,
            is_null_safe: true,
        },
        "Py_XDECREF should be recognized as NULL-safe decrement"
    );
    assert!(semantic.is_safe, "Py_XDECREF should be marked as safe");
}

/// Objective: Verify non-reference counting functions return None
///
/// Invariants:
/// - Non-reference counting functions should return None
/// - No panics or errors for unknown functions
#[test]
fn test_non_refcount_functions() {
    let result = refcount::analyze_refcount_pattern("PyList_New");
    assert!(
        result.is_none(),
        "test_non_refcount_functions: Non-refcount function should return None"
    );

    let result = refcount::analyze_refcount_pattern("malloc");
    assert!(
        result.is_none(),
        "test_non_refcount_functions: Non-Python function should return None"
    );
}

/// Objective: Verify reference counting patterns from IR analysis
///
/// Invariants:
/// - Py_INCREF from IR must be recognized as increment
/// - Py_DECREF from IR must be recognized as decrement
/// - Py_XINCREF from IR must be recognized as NULL-safe increment
/// - Py_XDECREF from IR must be recognized as NULL-safe decrement
#[test]
fn test_refcount_from_ir() {
    // Test Py_INCREF from IR
    let result = refcount::analyze_refcount_from_ir("Py_INCREF");
    assert!(
        result.is_some(),
        "test_refcount_from_ir: Py_INCREF should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::RefCountOp {
            is_increment: true,
            is_null_safe: false,
        },
        "Py_INCREF from IR should be recognized as increment"
    );

    // Test Py_DECREF from IR
    let result = refcount::analyze_refcount_from_ir("Py_DECREF");
    assert!(
        result.is_some(),
        "test_refcount_from_ir: Py_DECREF should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::RefCountOp {
            is_increment: false,
            is_null_safe: false,
        },
        "Py_DECREF from IR should be recognized as decrement"
    );

    // Test Py_XINCREF from IR
    let result = refcount::analyze_refcount_from_ir("Py_XINCREF");
    assert!(
        result.is_some(),
        "test_refcount_from_ir: Py_XINCREF should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::RefCountOp {
            is_increment: true,
            is_null_safe: true,
        },
        "Py_XINCREF from IR should be recognized as NULL-safe increment"
    );

    // Test Py_XDECREF from IR
    let result = refcount::analyze_refcount_from_ir("Py_XDECREF");
    assert!(
        result.is_some(),
        "test_refcount_from_ir: Py_XDECREF should be recognized from IR"
    );
    let pattern = result.unwrap();
    assert_eq!(
        pattern,
        PythonPattern::RefCountOp {
            is_increment: false,
            is_null_safe: true,
        },
        "Py_XDECREF from IR should be recognized as NULL-safe decrement"
    );
}

/// Objective: Verify balanced reference counting safety assessment
///
/// Invariants:
/// - Balanced INCREF/DECREF must produce SafeRefCount
/// - More INCREF than DECREF must produce ConcernRefLeak
/// - More DECREF than INCREF must produce ConcernOverRelease
/// - Stolen references must produce SafeRefCount
/// - New references must produce SafeNewReference
/// - Borrowed references must produce SafeBorrowedReference
#[test]
fn test_refcount_safety_assessment() {
    // Test balanced refcount
    let patterns = [
        PythonPattern::RefCountOp {
            is_increment: true,
            is_null_safe: false,
        },
        PythonPattern::RefCountOp {
            is_increment: false,
            is_null_safe: false,
        },
    ];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = refcount::determine_refcount_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::SafeRefCount,
        "Balanced INCREF/DECREF must produce SafeRefCount"
    );

    // Test refcount leak (more INCREF than DECREF)
    let patterns = [
        PythonPattern::RefCountOp {
            is_increment: true,
            is_null_safe: false,
        },
        PythonPattern::RefCountOp {
            is_increment: true,
            is_null_safe: false,
        },
        PythonPattern::RefCountOp {
            is_increment: false,
            is_null_safe: false,
        },
    ];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = refcount::determine_refcount_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::ConcernRefLeak,
        "2 INCREF vs 1 DECREF must produce ConcernRefLeak"
    );

    // Test over-release (more DECREF than INCREF)
    let patterns = [
        PythonPattern::RefCountOp {
            is_increment: true,
            is_null_safe: false,
        },
        PythonPattern::RefCountOp {
            is_increment: false,
            is_null_safe: false,
        },
        PythonPattern::RefCountOp {
            is_increment: false,
            is_null_safe: false,
        },
    ];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = refcount::determine_refcount_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::ConcernOverRelease,
        "1 INCREF vs 2 DECREF must produce ConcernOverRelease"
    );

    // Test stolen references
    let patterns = [PythonPattern::StolenReference];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = refcount::determine_refcount_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::SafeRefCount,
        "Stolen references must produce SafeRefCount"
    );

    // Test new references
    let patterns = [PythonPattern::NewReference];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = refcount::determine_refcount_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::SafeNewReference,
        "New references must produce SafeNewReference"
    );

    // Test borrowed references
    let patterns = [PythonPattern::BorrowedReference];
    let pattern_refs: Vec<&PythonPattern> = patterns.iter().collect();
    let safety = refcount::determine_refcount_safety(&pattern_refs);
    assert_eq!(
        safety,
        PythonFFISafety::SafeBorrowedReference,
        "Borrowed references must produce SafeBorrowedReference"
    );
}

/// Objective: Verify is_refcount_pattern function
///
/// Invariants:
/// - RefCountOp must be recognized as refcount pattern
/// - NewReference must be recognized as refcount pattern
/// - BorrowedReference must be recognized as refcount pattern
/// - StolenReference must be recognized as refcount pattern
/// - Other patterns must not be recognized as refcount pattern
#[test]
fn test_is_refcount_pattern() {
    // Test RefCountOp
    let pattern = PythonPattern::RefCountOp {
        is_increment: true,
        is_null_safe: false,
    };
    assert!(
        refcount::is_refcount_pattern(&pattern),
        "RefCountOp must be recognized as refcount pattern"
    );

    // Test NewReference
    let pattern = PythonPattern::NewReference;
    assert!(
        refcount::is_refcount_pattern(&pattern),
        "NewReference must be recognized as refcount pattern"
    );

    // Test BorrowedReference
    let pattern = PythonPattern::BorrowedReference;
    assert!(
        refcount::is_refcount_pattern(&pattern),
        "BorrowedReference must be recognized as refcount pattern"
    );

    // Test StolenReference
    let pattern = PythonPattern::StolenReference;
    assert!(
        refcount::is_refcount_pattern(&pattern),
        "StolenReference must be recognized as refcount pattern"
    );

    // Test non-refcount patterns
    let pattern = PythonPattern::GILAcquire;
    assert!(
        !refcount::is_refcount_pattern(&pattern),
        "GILAcquire must not be recognized as refcount pattern"
    );

    let pattern = PythonPattern::ObjectDestruction;
    assert!(
        !refcount::is_refcount_pattern(&pattern),
        "ObjectDestruction must not be recognized as refcount pattern"
    );
}
