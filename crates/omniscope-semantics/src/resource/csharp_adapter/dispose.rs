//! IDisposable pattern detection for C#.
//!
//! This module provides IDisposable-specific semantic analysis, including:
//! - SafeHandle usage detection
//! - CriticalHandle usage detection
//! - IDisposable pattern detection

use super::CSharpSemanticPattern;

/// Checks if a function name indicates SafeHandle usage.
///
/// # Objective
/// Detect SafeHandle patterns in C# function names. SafeHandle provides
/// deterministic resource cleanup for native resources.
///
/// # Invariants
/// - Returns true for SafeHandle or CriticalHandle patterns.
/// - Returns false for non-SafeHandle patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for SafeHandle usage.
///
/// # Returns
/// `true` if the function is identified as using SafeHandle, `false` otherwise.
pub fn is_safe_handle_usage(function_name: &str) -> bool {
    function_name.contains("SafeHandle") || function_name.contains("CriticalHandle")
}

/// Checks if a function name indicates an IDisposable pattern.
///
/// # Objective
/// Detect IDisposable patterns in C# function names. IDisposable indicates
/// proper resource cleanup implementation.
///
/// # Invariants
/// - Returns true for IDisposable or .Dispose() patterns.
/// - Returns false for non-IDisposable patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for IDisposable patterns.
///
/// # Returns
/// `true` if the function is identified as using IDisposable, `false` otherwise.
pub fn is_idisposable_pattern(function_name: &str) -> bool {
    function_name.contains("IDisposable") || function_name.contains(".Dispose()")
}

/// Detects disposal-related patterns from a function name.
///
/// # Objective
/// Collect all disposal-related semantic patterns from a function name.
/// This provides a convenient way to get all disposal patterns in one call.
///
/// # Arguments
/// * `function_name` - The function name to analyze for disposal patterns.
///
/// # Returns
/// A Vec of `CSharpSemanticPattern` containing detected disposal patterns.
pub fn detect_dispose_patterns(function_name: &str) -> Vec<CSharpSemanticPattern> {
    let mut patterns = Vec::new();

    if is_safe_handle_usage(function_name) {
        patterns.push(CSharpSemanticPattern::SafeHandleUsage);
    }
    if is_idisposable_pattern(function_name) {
        patterns.push(CSharpSemanticPattern::IDisposablePattern);
    }

    patterns
}

/// Checks if a function implements proper resource cleanup.
///
/// # Objective
/// Determine whether a function implements proper resource cleanup through
/// SafeHandle or IDisposable patterns. This is used for safety assessment.
///
/// # Arguments
/// * `function_name` - The function name to check for proper resource cleanup.
///
/// # Returns
/// `true` if the function implements proper resource cleanup, `false` otherwise.
pub fn has_proper_resource_cleanup(function_name: &str) -> bool {
    is_safe_handle_usage(function_name) || is_idisposable_pattern(function_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_handle_usage_detection() {
        // SafeHandle
        assert!(
            is_safe_handle_usage("Microsoft.Win32.SafeHandles.SafeFileHandle"),
            "SafeHandle must be detected"
        );
        // CriticalHandle
        assert!(
            is_safe_handle_usage("Microsoft.Win32.SafeHandles.CriticalHandle"),
            "CriticalHandle must be detected"
        );
        // Non-SafeHandle
        assert!(
            !is_safe_handle_usage("MyNamespace.MyClass.MyMethod"),
            "Non-SafeHandle must not be detected"
        );
    }

    #[test]
    fn test_idisposable_pattern_detection() {
        // IDisposable
        assert!(
            is_idisposable_pattern("System.IDisposable.Dispose"),
            "IDisposable must be detected"
        );
        // .Dispose()
        assert!(
            is_idisposable_pattern("MyClass.Dispose()"),
            ".Dispose() must be detected"
        );
        // Non-IDisposable
        assert!(
            !is_idisposable_pattern("MyNamespace.MyClass.MyMethod"),
            "Non-IDisposable must not be detected"
        );
    }

    #[test]
    fn test_detect_dispose_patterns() {
        // SafeHandle
        let patterns = detect_dispose_patterns("Microsoft.Win32.SafeHandles.SafeFileHandle");
        assert!(
            patterns.contains(&CSharpSemanticPattern::SafeHandleUsage),
            "SafeHandle must be detected"
        );

        // IDisposable
        let patterns = detect_dispose_patterns("System.IDisposable.Dispose");
        assert!(
            patterns.contains(&CSharpSemanticPattern::IDisposablePattern),
            "IDisposable must be detected"
        );
    }

    #[test]
    fn test_proper_resource_cleanup() {
        // SafeHandle
        assert!(
            has_proper_resource_cleanup("Microsoft.Win32.SafeHandles.SafeFileHandle"),
            "SafeHandle must be detected as proper cleanup"
        );
        // IDisposable
        assert!(
            has_proper_resource_cleanup("System.IDisposable.Dispose"),
            "IDisposable must be detected as proper cleanup"
        );
        // Non-proper cleanup
        assert!(
            !has_proper_resource_cleanup("MyNamespace.MyClass.MyMethod"),
            "Non-proper cleanup must not be detected"
        );
    }
}
