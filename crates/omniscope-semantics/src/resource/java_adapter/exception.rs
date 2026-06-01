//! JNI exception handling pattern detection for Java.
//!
//! This module provides JNI exception handling-specific semantic analysis, including:
//! - Exception occurrence detection
//! - Exception clearing detection
//! - Exception throwing detection
//! - Exception handling assessment

use super::JavaSemanticPattern;

/// Checks if a function name indicates JNI exception handling.
///
/// # Objective
/// Detect JNI exception handling patterns in Java function names. JNI exception
/// handling includes ExceptionOccurred, ExceptionClear, ExceptionCheck, Throw,
/// and ThrowNew.
///
/// # Invariants
/// - Returns true for ExceptionOccurred, ExceptionClear, ExceptionCheck, Throw, or ThrowNew.
/// - Returns false for non-exception handling patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for exception handling.
///
/// # Returns
/// `true` if the function is identified as exception handling, `false` otherwise.
pub fn is_exception_handling(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("ExceptionOccurred")
            || function_name.contains("ExceptionClear")
            || function_name.contains("ExceptionCheck")
            || function_name.contains("Throw")
            || function_name.contains("ThrowNew"))
}

/// Checks if a function name indicates JNI exception occurrence.
///
/// # Objective
/// Detect JNI exception occurrence patterns in Java function names. Exception
/// occurrence is identified by ExceptionOccurred patterns.
///
/// # Invariants
/// - Returns true for ExceptionOccurred patterns.
/// - Returns false for non-exception occurrence patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for exception occurrence.
///
/// # Returns
/// `true` if the function is identified as exception occurrence, `false` otherwise.
pub fn is_exception_occurrence(function_name: &str) -> bool {
    is_jni_call(function_name) && function_name.contains("ExceptionOccurred")
}

/// Checks if a function name indicates JNI exception clearing.
///
/// # Objective
/// Detect JNI exception clearing patterns in Java function names. Exception
/// clearing is identified by ExceptionClear patterns.
///
/// # Invariants
/// - Returns true for ExceptionClear patterns.
/// - Returns false for non-exception clearing patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for exception clearing.
///
/// # Returns
/// `true` if the function is identified as exception clearing, `false` otherwise.
pub fn is_exception_clearing(function_name: &str) -> bool {
    is_jni_call(function_name) && function_name.contains("ExceptionClear")
}

/// Checks if a function name indicates JNI exception checking.
///
/// # Objective
/// Detect JNI exception checking patterns in Java function names. Exception
/// checking is identified by ExceptionCheck patterns.
///
/// # Invariants
/// - Returns true for ExceptionCheck patterns.
/// - Returns false for non-exception checking patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for exception checking.
///
/// # Returns
/// `true` if the function is identified as exception checking, `false` otherwise.
pub fn is_exception_checking(function_name: &str) -> bool {
    is_jni_call(function_name) && function_name.contains("ExceptionCheck")
}

/// Checks if a function name indicates JNI exception throwing.
///
/// # Objective
/// Detect JNI exception throwing patterns in Java function names. Exception
/// throwing is identified by Throw or ThrowNew patterns.
///
/// # Invariants
/// - Returns true for Throw or ThrowNew patterns.
/// - Returns false for non-exception throwing patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for exception throwing.
///
/// # Returns
/// `true` if the function is identified as exception throwing, `false` otherwise.
pub fn is_exception_throwing(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("Throw") || function_name.contains("ThrowNew"))
}

/// Detects JNI exception handling patterns from a function name.
///
/// # Objective
/// Collect all JNI exception handling-related semantic patterns from a function name.
/// This provides a convenient way to get all exception handling patterns in one call.
///
/// # Arguments
/// * `function_name` - The function name to analyze for exception handling patterns.
///
/// # Returns
/// A Vec of `JavaSemanticPattern` containing detected exception handling patterns.
pub fn detect_exception_patterns(function_name: &str) -> Vec<JavaSemanticPattern> {
    let mut patterns = Vec::new();

    if is_exception_handling(function_name) {
        patterns.push(JavaSemanticPattern::JNIExceptionHandling);
    }

    patterns
}

/// Checks if a function uses JNI exception handling.
///
/// # Objective
/// Determine whether a function uses any JNI exception handling patterns. This is
/// used for feature flag detection in function analysis.
///
/// # Arguments
/// * `function_name` - The function name to check for exception handling usage.
///
/// # Returns
/// `true` if the function uses exception handling, `false` otherwise.
pub fn uses_exception_handling(function_name: &str) -> bool {
    is_exception_handling(function_name)
}

/// Helper function to check if a function name contains JNI call patterns.
fn is_jni_call(function_name: &str) -> bool {
    function_name.starts_with("Java_")
        || function_name.starts_with("JNI")
        || function_name.contains("(*env)->")
        || function_name.contains("JNIEnv")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exception_handling_detection() {
        // ExceptionOccurred
        assert!(
            is_exception_handling("(*env)->ExceptionOccurred"),
            "ExceptionOccurred must be detected as exception handling"
        );
        // ExceptionClear
        assert!(
            is_exception_handling("(*env)->ExceptionClear"),
            "ExceptionClear must be detected as exception handling"
        );
        // ExceptionCheck
        assert!(
            is_exception_handling("(*env)->ExceptionCheck"),
            "ExceptionCheck must be detected as exception handling"
        );
        // Throw
        assert!(
            is_exception_handling("(*env)->Throw"),
            "Throw must be detected as exception handling"
        );
        // ThrowNew
        assert!(
            is_exception_handling("(*env)->ThrowNew"),
            "ThrowNew must be detected as exception handling"
        );
        // Non-exception handling
        assert!(
            !is_exception_handling("(*env)->NewObject"),
            "Non-exception handling must not be detected"
        );
    }

    #[test]
    fn test_exception_occurrence_detection() {
        // ExceptionOccurred
        assert!(
            is_exception_occurrence("(*env)->ExceptionOccurred"),
            "ExceptionOccurred must be detected as exception occurrence"
        );
        // Non-exception occurrence
        assert!(
            !is_exception_occurrence("(*env)->ExceptionClear"),
            "Non-exception occurrence must not be detected"
        );
    }

    #[test]
    fn test_exception_clearing_detection() {
        // ExceptionClear
        assert!(
            is_exception_clearing("(*env)->ExceptionClear"),
            "ExceptionClear must be detected as exception clearing"
        );
        // Non-exception clearing
        assert!(
            !is_exception_clearing("(*env)->ExceptionOccurred"),
            "Non-exception clearing must not be detected"
        );
    }

    #[test]
    fn test_exception_checking_detection() {
        // ExceptionCheck
        assert!(
            is_exception_checking("(*env)->ExceptionCheck"),
            "ExceptionCheck must be detected as exception checking"
        );
        // Non-exception checking
        assert!(
            !is_exception_checking("(*env)->ExceptionOccurred"),
            "Non-exception checking must not be detected"
        );
    }

    #[test]
    fn test_exception_throwing_detection() {
        // Throw
        assert!(
            is_exception_throwing("(*env)->Throw"),
            "Throw must be detected as exception throwing"
        );
        // ThrowNew
        assert!(
            is_exception_throwing("(*env)->ThrowNew"),
            "ThrowNew must be detected as exception throwing"
        );
        // Non-exception throwing
        assert!(
            !is_exception_throwing("(*env)->ExceptionOccurred"),
            "Non-exception throwing must not be detected"
        );
    }

    #[test]
    fn test_detect_exception_patterns() {
        // ExceptionOccurred
        let patterns = detect_exception_patterns("(*env)->ExceptionOccurred");
        assert!(
            patterns.contains(&JavaSemanticPattern::JNIExceptionHandling),
            "JNIExceptionHandling must be detected"
        );

        // ExceptionClear
        let patterns = detect_exception_patterns("(*env)->ExceptionClear");
        assert!(
            patterns.contains(&JavaSemanticPattern::JNIExceptionHandling),
            "JNIExceptionHandling must be detected"
        );

        // Throw
        let patterns = detect_exception_patterns("(*env)->Throw");
        assert!(
            patterns.contains(&JavaSemanticPattern::JNIExceptionHandling),
            "JNIExceptionHandling must be detected"
        );
    }

    #[test]
    fn test_uses_exception_handling() {
        // ExceptionOccurred
        assert!(
            uses_exception_handling("(*env)->ExceptionOccurred"),
            "ExceptionOccurred must use exception handling"
        );
        // ExceptionClear
        assert!(
            uses_exception_handling("(*env)->ExceptionClear"),
            "ExceptionClear must use exception handling"
        );
        // Non-exception handling
        assert!(
            !uses_exception_handling("(*env)->NewObject"),
            "Non-exception handling must not use exception handling"
        );
    }
}
