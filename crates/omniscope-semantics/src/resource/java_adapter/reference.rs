//! JNI reference management pattern detection for Java.
//!
//! This module provides JNI reference management-specific semantic analysis, including:
//! - Local reference management
//! - Global reference management
//! - Weak global reference management
//! - Reference leak detection

use super::JavaSemanticPattern;

/// Checks if a function name indicates JNI local reference management.
///
/// # Objective
/// Detect JNI local reference management patterns in Java function names.
/// Local references are automatically freed when the native method returns,
/// but should be explicitly freed in long-running methods.
///
/// # Invariants
/// - Returns true for DeleteLocalRef patterns.
/// - Returns false for non-local reference management patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for local reference management.
///
/// # Returns
/// `true` if the function is identified as local reference management, `false` otherwise.
pub fn is_local_reference_management(function_name: &str) -> bool {
    is_jni_call(function_name) && function_name.contains("DeleteLocalRef")
}

/// Checks if a function name indicates JNI global reference management.
///
/// # Objective
/// Detect JNI global reference management patterns in Java function names.
/// Global references persist until explicitly deleted and are used to share
/// references across native method calls.
///
/// # Invariants
/// - Returns true for NewGlobalRef or DeleteGlobalRef patterns.
/// - Returns false for non-global reference management patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for global reference management.
///
/// # Returns
/// `true` if the function is identified as global reference management, `false` otherwise.
pub fn is_global_reference_management(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("NewGlobalRef") || function_name.contains("DeleteGlobalRef"))
}

/// Checks if a function name indicates JNI weak global reference management.
///
/// # Objective
/// Detect JNI weak global reference management patterns in Java function names.
/// Weak global references allow the garbage collector to collect the referenced
/// object if no strong references exist.
///
/// # Invariants
/// - Returns true for NewWeakGlobalRef or DeleteWeakGlobalRef patterns.
/// - Returns false for non-weak global reference management patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for weak global reference management.
///
/// # Returns
/// `true` if the function is identified as weak global reference management, `false` otherwise.
pub fn is_weak_global_reference_management(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("NewWeakGlobalRef")
            || function_name.contains("DeleteWeakGlobalRef"))
}

/// Checks if a function name indicates JNI reference creation.
///
/// # Objective
/// Detect JNI reference creation patterns in Java function names. Reference
/// creation includes local, global, and weak global references.
///
/// # Invariants
/// - Returns true for NewGlobalRef or NewWeakGlobalRef patterns.
/// - Returns false for non-reference creation patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for reference creation.
///
/// # Returns
/// `true` if the function is identified as reference creation, `false` otherwise.
pub fn is_reference_creation(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("NewGlobalRef") || function_name.contains("NewWeakGlobalRef"))
}

/// Checks if a function name indicates JNI reference cleanup.
///
/// # Objective
/// Detect JNI reference cleanup patterns in Java function names. Reference
/// cleanup includes deletion of local, global, and weak global references.
///
/// # Invariants
/// - Returns true for DeleteLocalRef, DeleteGlobalRef, or DeleteWeakGlobalRef patterns.
/// - Returns false for non-reference cleanup patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for reference cleanup.
///
/// # Returns
/// `true` if the function is identified as reference cleanup, `false` otherwise.
pub fn is_reference_cleanup(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("DeleteLocalRef")
            || function_name.contains("DeleteGlobalRef")
            || function_name.contains("DeleteWeakGlobalRef"))
}

/// Detects JNI reference management patterns from a function name.
///
/// # Objective
/// Collect all JNI reference management-related semantic patterns from a function name.
/// This provides a convenient way to get all reference management patterns in one call.
///
/// # Arguments
/// * `function_name` - The function name to analyze for reference management patterns.
///
/// # Returns
/// A Vec of `JavaSemanticPattern` containing detected reference management patterns.
pub fn detect_reference_patterns(function_name: &str) -> Vec<JavaSemanticPattern> {
    let mut patterns = Vec::new();

    if is_local_reference_management(function_name) {
        patterns.push(JavaSemanticPattern::JNILocalReference);
    }
    if is_global_reference_management(function_name) {
        patterns.push(JavaSemanticPattern::JNIGlobalReference);
    }
    if is_weak_global_reference_management(function_name) {
        patterns.push(JavaSemanticPattern::JNIWeakGlobalReference);
    }

    patterns
}

/// Checks if a function manages JNI references.
///
/// # Objective
/// Determine whether a function manages any JNI references. This is
/// used for feature flag detection in function analysis.
///
/// # Arguments
/// * `function_name` - The function name to check for JNI reference management.
///
/// # Returns
/// `true` if the function manages JNI references, `false` otherwise.
pub fn manages_jni_references(function_name: &str) -> bool {
    is_local_reference_management(function_name)
        || is_global_reference_management(function_name)
        || is_weak_global_reference_management(function_name)
}

/// Checks if a function has a JNI reference leak.
///
/// # Objective
/// Determine whether a function has a JNI reference leak by checking if it
/// creates references but doesn't clean them up. This is used for memory
/// leak detection.
///
/// # Arguments
/// * `function_name` - The function name to check for JNI reference leak.
///
/// # Returns
/// `true` if the function has a JNI reference leak, `false` otherwise.
pub fn has_reference_leak(function_name: &str) -> bool {
    is_reference_creation(function_name) && !is_reference_cleanup(function_name)
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
    fn test_local_reference_management_detection() {
        // DeleteLocalRef
        assert!(
            is_local_reference_management("(*env)->DeleteLocalRef"),
            "DeleteLocalRef must be detected as local reference management"
        );
        // Non-local reference management
        assert!(
            !is_local_reference_management("(*env)->NewObject"),
            "Non-local reference management must not be detected"
        );
    }

    #[test]
    fn test_global_reference_management_detection() {
        // NewGlobalRef
        assert!(
            is_global_reference_management("(*env)->NewGlobalRef"),
            "NewGlobalRef must be detected as global reference management"
        );
        // DeleteGlobalRef
        assert!(
            is_global_reference_management("(*env)->DeleteGlobalRef"),
            "DeleteGlobalRef must be detected as global reference management"
        );
        // Non-global reference management
        assert!(
            !is_global_reference_management("(*env)->NewObject"),
            "Non-global reference management must not be detected"
        );
    }

    #[test]
    fn test_weak_global_reference_management_detection() {
        // NewWeakGlobalRef
        assert!(
            is_weak_global_reference_management("(*env)->NewWeakGlobalRef"),
            "NewWeakGlobalRef must be detected as weak global reference management"
        );
        // DeleteWeakGlobalRef
        assert!(
            is_weak_global_reference_management("(*env)->DeleteWeakGlobalRef"),
            "DeleteWeakGlobalRef must be detected as weak global reference management"
        );
        // Non-weak global reference management
        assert!(
            !is_weak_global_reference_management("(*env)->NewObject"),
            "Non-weak global reference management must not be detected"
        );
    }

    #[test]
    fn test_reference_creation_detection() {
        // NewGlobalRef
        assert!(
            is_reference_creation("(*env)->NewGlobalRef"),
            "NewGlobalRef must be detected as reference creation"
        );
        // NewWeakGlobalRef
        assert!(
            is_reference_creation("(*env)->NewWeakGlobalRef"),
            "NewWeakGlobalRef must be detected as reference creation"
        );
        // Non-reference creation
        assert!(
            !is_reference_creation("(*env)->DeleteLocalRef"),
            "Non-reference creation must not be detected"
        );
    }

    #[test]
    fn test_reference_cleanup_detection() {
        // DeleteLocalRef
        assert!(
            is_reference_cleanup("(*env)->DeleteLocalRef"),
            "DeleteLocalRef must be detected as reference cleanup"
        );
        // DeleteGlobalRef
        assert!(
            is_reference_cleanup("(*env)->DeleteGlobalRef"),
            "DeleteGlobalRef must be detected as reference cleanup"
        );
        // DeleteWeakGlobalRef
        assert!(
            is_reference_cleanup("(*env)->DeleteWeakGlobalRef"),
            "DeleteWeakGlobalRef must be detected as reference cleanup"
        );
        // Non-reference cleanup
        assert!(
            !is_reference_cleanup("(*env)->NewObject"),
            "Non-reference cleanup must not be detected"
        );
    }

    #[test]
    fn test_detect_reference_patterns() {
        // Local reference management
        let patterns = detect_reference_patterns("(*env)->DeleteLocalRef");
        assert!(
            patterns.contains(&JavaSemanticPattern::JNILocalReference),
            "JNILocalReference must be detected"
        );

        // Global reference management
        let patterns = detect_reference_patterns("(*env)->NewGlobalRef");
        assert!(
            patterns.contains(&JavaSemanticPattern::JNIGlobalReference),
            "JNIGlobalReference must be detected"
        );

        // Weak global reference management
        let patterns = detect_reference_patterns("(*env)->NewWeakGlobalRef");
        assert!(
            patterns.contains(&JavaSemanticPattern::JNIWeakGlobalReference),
            "JNIWeakGlobalReference must be detected"
        );
    }

    #[test]
    fn test_manages_jni_references() {
        // DeleteLocalRef
        assert!(
            manages_jni_references("(*env)->DeleteLocalRef"),
            "DeleteLocalRef must manage JNI references"
        );
        // NewGlobalRef
        assert!(
            manages_jni_references("(*env)->NewGlobalRef"),
            "NewGlobalRef must manage JNI references"
        );
        // Non-reference management
        assert!(
            !manages_jni_references("(*env)->NewObject"),
            "Non-reference management must not manage JNI references"
        );
    }

    #[test]
    fn test_reference_leak_detection() {
        // Reference creation without cleanup
        assert!(
            has_reference_leak("(*env)->NewGlobalRef"),
            "Reference creation without cleanup must be detected as leak"
        );
        // Reference with cleanup
        assert!(
            !has_reference_leak("(*env)->DeleteLocalRef"),
            "Reference with cleanup must not be detected as leak"
        );
    }
}
