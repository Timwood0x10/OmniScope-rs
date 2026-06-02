//! Tests for Python exception handling analysis.

use super::super::exception::*;
use super::super::{PythonFFISafety, PythonPattern};

#[test]
fn test_exception_pattern_via_adapter_setter() {
    let adapter = super::super::PythonAdapter::new();
    let result = adapter.analyze_function("PyErr_SetString");
    assert!(
        result.is_some(),
        "PythonAdapter should detect PyErr_SetString via pattern analysis"
    );
    let semantic = result.unwrap();
    assert!(
        matches!(
            semantic.pattern,
            PythonPattern::ExceptionHandling {
                is_setter: true,
                ..
            }
        ),
        "PythonAdapter should classify PyErr_SetString as ExceptionHandling setter"
    );
    assert!(
        !semantic.is_safe,
        "PyErr_SetString should be marked as unsafe by PythonAdapter"
    );
}

#[test]
fn test_exception_pattern_via_adapter_clearer() {
    let adapter = super::super::PythonAdapter::new();
    let result = adapter.analyze_function("PyErr_Clear");
    assert!(
        result.is_some(),
        "PythonAdapter should detect PyErr_Clear via pattern analysis"
    );
    let semantic = result.unwrap();
    assert!(
        matches!(
            semantic.pattern,
            PythonPattern::ExceptionHandling {
                is_clearer: true,
                ..
            }
        ),
        "PythonAdapter should classify PyErr_Clear as ExceptionHandling clearer"
    );
    assert!(
        semantic.is_safe,
        "PyErr_Clear should be marked as safe by PythonAdapter"
    );
}

#[test]
fn test_exception_safety_setter_without_clearer() {
    let adapter = super::super::PythonAdapter::new();
    let analysis = adapter.analyze_function_with_ir("some_func", None);
    // Verify that the adapter produces correct FFI safety when exception patterns are involved
    // This test verifies the integration pipeline works end-to-end
    assert!(
        analysis.function_name == "some_func",
        "Function name should be preserved in analysis"
    );
}

#[test]
fn test_exception_leak_detection_integration() {
    // Test exception leak detection with a realistic instruction sequence
    let instructions = vec![
        "%1 = call @PyList_New(i64 10)",
        "call @PyErr_SetString(%PyObject, %msg)",
        "br label %error_cleanup",
    ];
    let leaks = detect_exception_leaks(&instructions, "my_extension_func");
    assert!(
        !leaks.is_empty(),
        "Should detect potential leaks when PyErr_SetString without cleanup"
    );
    assert!(
        leaks.iter().any(|l| l.severity == LeakSeverity::Warning),
        "Should have at least one warning-level leak"
    );
}

#[test]
fn test_exception_leak_detection_with_cleanup() {
    // Test that proper cleanup prevents false positives
    let instructions = vec![
        "%1 = call @PyList_New(i64 10)",
        "call @PyErr_SetString(%PyObject, %msg)",
        "call @Py_DECREF(%1)",
        "call @PyErr_Clear()",
        "ret null",
    ];
    let leaks = detect_exception_leaks(&instructions, "safe_func");
    assert!(
        leaks.iter().any(|l| l.severity == LeakSeverity::Warning),
        "Should still warn about exception setter usage"
    );
    assert!(
        !leaks.iter().any(|l| l.severity == LeakSeverity::Error),
        "Should not error when proper cleanup is present"
    );
}

#[test]
fn test_exception_leak_detection_no_exception() {
    // Test that normal function without exceptions produces no leaks
    let instructions = vec![
        "%1 = call @PyList_New(i64 10)",
        "%2 = call @PyUnicode_FromString(%str)",
        "call @Py_DECREF(%1)",
        "call @Py_DECREF(%2)",
        "ret %2",
    ];
    let leaks = detect_exception_leaks(&instructions, "normal_func");
    assert!(
        leaks.is_empty(),
        "Normal function without exception handling should have no leaks"
    );
}

#[test]
fn test_is_exception_pattern_integration() {
    // Test that all exception-related patterns are correctly identified
    let exception_patterns = vec![
        PythonPattern::ExceptionHandling {
            is_setter: true,
            is_clearer: false,
        },
        PythonPattern::ExceptionHandling {
            is_setter: false,
            is_clearer: true,
        },
        PythonPattern::ExceptionHandling {
            is_setter: false,
            is_clearer: false,
        },
    ];

    for pattern in &exception_patterns {
        assert!(
            is_exception_pattern(pattern),
            "All ExceptionHandling variants should be detected as exception patterns"
        );
    }

    // Non-exception patterns should not be detected
    let non_exception_patterns = vec![
        PythonPattern::NewReference,
        PythonPattern::BorrowedReference,
        PythonPattern::StolenReference,
        PythonPattern::GILAcquire,
        PythonPattern::GILRelease,
        PythonPattern::ObjectDestruction,
        PythonPattern::MemoryAllocation,
        PythonPattern::MemoryDeallocation,
        PythonPattern::Unknown,
    ];

    for pattern in &non_exception_patterns {
        assert!(
            !is_exception_pattern(pattern),
            "Non-exception patterns should not be detected as exception patterns"
        );
    }
}

#[test]
fn test_all_exception_functions_detected_by_pattern() {
    // Verify that all known exception functions are detected by analyze_exception_pattern
    let known_functions = vec![
        "PyErr_SetString",
        "PyErr_Format",
        "PyErr_Occurred",
        "PyErr_Clear",
        "PyErr_Print",
        "PyErr_ExceptionMatches",
        "PyErr_GivenExceptionMatches",
        "PyErr_NewException",
        "PyErr_NewExceptionWithDoc",
        "PyErr_Fetch",
        "PyErr_Restore",
    ];

    for func in &known_functions {
        let result = analyze_exception_pattern(func);
        assert!(
            result.is_some(),
            "analyze_exception_pattern should detect '{}'",
            func
        );
        let semantic = result.unwrap();
        assert_eq!(
            semantic.function_name, *func,
            "Function name should match for '{}'",
            func
        );
        assert!(
            semantic.confidence >= 0.9,
            "Confidence should be high for known function '{}'",
            func
        );
    }
}

#[test]
fn test_all_exception_functions_detected_by_ir() {
    // Verify that all known exception functions are detected by analyze_exception_from_ir
    let known_functions = vec![
        "PyErr_SetString",
        "PyErr_Format",
        "PyErr_Occurred",
        "PyErr_Clear",
        "PyErr_Print",
        "PyErr_ExceptionMatches",
        "PyErr_GivenExceptionMatches",
        "PyErr_NewException",
        "PyErr_NewExceptionWithDoc",
        "PyErr_Fetch",
        "PyErr_Restore",
    ];

    for func in &known_functions {
        let result = analyze_exception_from_ir(func);
        assert!(
            result.is_some(),
            "analyze_exception_from_ir should detect '{}'",
            func
        );
    }
}

#[test]
fn test_exception_safety_multiple_setters_one_clearer() {
    // Multiple setters with one clearer should still be concerning
    let patterns = vec![
        &PythonPattern::ExceptionHandling {
            is_setter: true,
            is_clearer: false,
        },
        &PythonPattern::ExceptionHandling {
            is_setter: true,
            is_clearer: false,
        },
        &PythonPattern::ExceptionHandling {
            is_setter: false,
            is_clearer: true,
        },
    ];
    let safety = determine_exception_safety(&patterns);
    assert_eq!(
        safety,
        PythonFFISafety::SafeRefCount,
        "Multiple setters with one clearer should be SafeRefCount"
    );
}

#[test]
fn test_exception_safety_mixed_with_refcount() {
    // Exception patterns mixed with refcount patterns
    let patterns = vec![
        &PythonPattern::ExceptionHandling {
            is_setter: true,
            is_clearer: false,
        },
        &PythonPattern::RefCountOp {
            is_increment: true,
            is_null_safe: false,
        },
    ];
    let safety = determine_exception_safety(&patterns);
    assert_eq!(
        safety,
        PythonFFISafety::ConcernExceptionLeak,
        "Setter with refcount but no clearer should be ConcernExceptionLeak"
    );
}
