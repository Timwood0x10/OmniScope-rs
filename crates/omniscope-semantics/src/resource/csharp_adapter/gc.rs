//! Garbage collection pattern detection for C#.
//!
//! This module provides GC-specific semantic analysis, including:
//! - GCHandle allocation and deallocation
//! - .NET GC operations
//! - Memory pinning detection

use super::CSharpSemanticPattern;

/// Checks if a function name indicates a GCHandle allocation.
///
/// # Objective
/// Detect GCHandle allocation patterns in C# function names. GCHandle
/// is used to pin managed objects for native code access.
///
/// # Invariants
/// - Returns true for GCHandle.Alloc patterns.
/// - Returns false for non-GCHandle allocation patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for GCHandle allocation.
///
/// # Returns
/// `true` if the function is identified as a GCHandle allocation, `false` otherwise.
pub fn is_gc_handle_allocation(function_name: &str) -> bool {
    function_name.contains("GCHandle.Alloc")
}

/// Checks if a function name indicates a GCHandle deallocation.
///
/// # Objective
/// Detect GCHandle deallocation patterns in C# function names. GCHandle
/// deallocation releases pinned managed objects.
///
/// # Invariants
/// - Returns true for GCHandle.Free patterns.
/// - Returns false for non-GCHandle deallocation patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for GCHandle deallocation.
///
/// # Returns
/// `true` if the function is identified as a GCHandle deallocation, `false` otherwise.
pub fn is_gc_handle_deallocation(function_name: &str) -> bool {
    function_name.contains("GCHandle.Free")
}

/// Checks if a function name indicates a .NET GC operation.
///
/// # Objective
/// Detect .NET GC operation patterns in C# function names. GC operations
/// interact with the garbage collector for memory management.
///
/// # Invariants
/// - Returns true for GC.Collect or GC.WaitForPendingFinalizers.
/// - Returns false for non-GC operation patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for GC operations.
///
/// # Returns
/// `true` if the function is identified as a GC operation, `false` otherwise.
pub fn is_gc_operation(function_name: &str) -> bool {
    function_name.contains("GC.Collect") || function_name.contains("GC.WaitForPendingFinalizers")
}

/// Detects GC-related patterns from a function name.
///
/// # Objective
/// Collect all GC-related semantic patterns from a function name.
/// This provides a convenient way to get all GC patterns in one call.
///
/// # Arguments
/// * `function_name` - The function name to analyze for GC patterns.
///
/// # Returns
/// A Vec of `CSharpSemanticPattern` containing detected GC patterns.
pub fn detect_gc_patterns(function_name: &str) -> Vec<CSharpSemanticPattern> {
    let mut patterns = Vec::new();

    if is_gc_handle_allocation(function_name) {
        patterns.push(CSharpSemanticPattern::GCHandleAllocation);
    }
    if is_gc_handle_deallocation(function_name) {
        patterns.push(CSharpSemanticPattern::GCHandleDeallocation);
    }
    if is_gc_operation(function_name) {
        patterns.push(CSharpSemanticPattern::GCOperation);
    }

    patterns
}

/// Checks if a function has a GCHandle leak.
///
/// # Objective
/// Determine whether a function has a GCHandle leak by checking if it
/// allocates GCHandle but doesn't deallocate it. This is used for
/// memory leak detection.
///
/// # Arguments
/// * `function_name` - The function name to check for GCHandle leak.
///
/// # Returns
/// `true` if the function has a GCHandle leak, `false` otherwise.
pub fn has_gc_handle_leak(function_name: &str) -> bool {
    is_gc_handle_allocation(function_name) && !is_gc_handle_deallocation(function_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gc_handle_allocation_detection() {
        // GCHandle.Alloc
        assert!(
            is_gc_handle_allocation("System.Runtime.InteropServices.GCHandle.Alloc"),
            "GCHandle.Alloc must be detected"
        );
        // Non-GCHandle allocation
        assert!(
            !is_gc_handle_allocation("GCHandle.Free"),
            "Non-GCHandle allocation must not be detected"
        );
    }

    #[test]
    fn test_gc_handle_deallocation_detection() {
        // GCHandle.Free
        assert!(
            is_gc_handle_deallocation("System.Runtime.InteropServices.GCHandle.Free"),
            "GCHandle.Free must be detected"
        );
        // Non-GCHandle deallocation
        assert!(
            !is_gc_handle_deallocation("GCHandle.Alloc"),
            "Non-GCHandle deallocation must not be detected"
        );
    }

    #[test]
    fn test_gc_operation_detection() {
        // GC.Collect
        assert!(is_gc_operation("GC.Collect"), "GC.Collect must be detected");
        // GC.WaitForPendingFinalizers
        assert!(
            is_gc_operation("GC.WaitForPendingFinalizers"),
            "GC.WaitForPendingFinalizers must be detected"
        );
        // Non-GC operation
        assert!(
            !is_gc_operation("MyNamespace.MyClass.MyMethod"),
            "Non-GC operation must not be detected"
        );
    }

    #[test]
    fn test_detect_gc_patterns() {
        // GCHandle allocation
        let patterns = detect_gc_patterns("System.Runtime.InteropServices.GCHandle.Alloc");
        assert!(
            patterns.contains(&CSharpSemanticPattern::GCHandleAllocation),
            "GCHandle allocation must be detected"
        );

        // GCHandle deallocation
        let patterns = detect_gc_patterns("System.Runtime.InteropServices.GCHandle.Free");
        assert!(
            patterns.contains(&CSharpSemanticPattern::GCHandleDeallocation),
            "GCHandle deallocation must be detected"
        );

        // GC operation
        let patterns = detect_gc_patterns("GC.Collect");
        assert!(
            patterns.contains(&CSharpSemanticPattern::GCOperation),
            "GC operation must be detected"
        );
    }

    #[test]
    fn test_gc_handle_leak_detection() {
        // GCHandle allocation without deallocation
        assert!(
            has_gc_handle_leak("System.Runtime.InteropServices.GCHandle.Alloc"),
            "GCHandle allocation without deallocation must be detected as leak"
        );
        // GCHandle with deallocation
        assert!(
            !has_gc_handle_leak("System.Runtime.InteropServices.GCHandle.Free"),
            "GCHandle with deallocation must not be detected as leak"
        );
    }
}
