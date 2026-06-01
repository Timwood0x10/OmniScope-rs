//! P/Invoke pattern detection for C#.
//!
//! This module provides P/Invoke-specific semantic analysis, including:
//! - P/Invoke call detection
//! - Marshal memory operations
//! - COM interop detection

use super::CSharpSemanticPattern;

/// Checks if a function name indicates a P/Invoke call.
///
/// # Objective
/// Detect P/Invoke patterns in C# function names. P/Invoke calls
/// bridge managed C# code and native C/C++ functions through
/// Platform Invocation Services.
///
/// # Invariants
/// - Returns true for P/Invoke or DllImport patterns.
/// - Returns false for non-P/Invoke patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for P/Invoke patterns.
///
/// # Returns
/// `true` if the function is identified as a P/Invoke call, `false` otherwise.
pub fn is_pinvoke_call(function_name: &str) -> bool {
    function_name.contains("P/Invoke") || function_name.contains("DllImport")
}

/// Checks if a function name indicates a Marshal memory allocation.
///
/// # Objective
/// Detect Marshal memory allocation patterns in C# function names.
/// Marshal allocations create memory on the native heap for interop
/// scenarios.
///
/// # Invariants
/// - Returns true for Marshal.AllocHGlobal or Marshal.AllocCoTaskMem.
/// - Returns false for non-Marshal allocation patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for Marshal allocation.
///
/// # Returns
/// `true` if the function is identified as a Marshal allocation, `false` otherwise.
pub fn is_marshal_allocation(function_name: &str) -> bool {
    function_name.contains("Marshal.AllocHGlobal")
        || function_name.contains("Marshal.AllocCoTaskMem")
}

/// Checks if a function name indicates a Marshal memory deallocation.
///
/// # Objective
/// Detect Marshal memory deallocation patterns in C# function names.
/// Marshal deallocations free memory from the native heap that was
/// allocated for interop scenarios.
///
/// # Invariants
/// - Returns true for Marshal.FreeHGlobal or Marshal.FreeCoTaskMem.
/// - Returns false for non-Marshal deallocation patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for Marshal deallocation.
///
/// # Returns
/// `true` if the function is identified as a Marshal deallocation, `false` otherwise.
pub fn is_marshal_deallocation(function_name: &str) -> bool {
    function_name.contains("Marshal.FreeHGlobal") || function_name.contains("Marshal.FreeCoTaskMem")
}

/// Checks if a function name indicates a COM interop operation.
///
/// # Objective
/// Detect COM interop patterns in C# function names. COM interop
/// handles interactions with COM objects through the .NET runtime.
///
/// # Invariants
/// - Returns true for Marshal.GetIUnknownForObject, Marshal.GetObjectForIUnknown, or ComVisible.
/// - Returns false for non-COM interop patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for COM interop patterns.
///
/// # Returns
/// `true` if the function is identified as a COM interop operation, `false` otherwise.
pub fn is_com_interop(function_name: &str) -> bool {
    function_name.contains("Marshal.GetIUnknownForObject")
        || function_name.contains("Marshal.GetObjectForIUnknown")
        || function_name.contains("ComVisible")
}

/// Detects P/Invoke-related patterns from a function name.
///
/// # Objective
/// Collect all P/Invoke-related semantic patterns from a function name.
/// This provides a convenient way to get all P/Invoke patterns in one call.
///
/// # Arguments
/// * `function_name` - The function name to analyze for P/Invoke patterns.
///
/// # Returns
/// A Vec of `CSharpSemanticPattern` containing detected P/Invoke patterns.
pub fn detect_pinvoke_patterns(function_name: &str) -> Vec<CSharpSemanticPattern> {
    let mut patterns = Vec::new();

    if is_pinvoke_call(function_name) {
        patterns.push(CSharpSemanticPattern::PInvokeCall);
    }
    if is_marshal_allocation(function_name) {
        patterns.push(CSharpSemanticPattern::MarshalAllocation);
    }
    if is_marshal_deallocation(function_name) {
        patterns.push(CSharpSemanticPattern::MarshalDeallocation);
    }
    if is_com_interop(function_name) {
        patterns.push(CSharpSemanticPattern::COMInterop);
    }

    patterns
}

/// Checks if a function is a P/Invoke wrapper.
///
/// # Objective
/// Determine whether a function serves as a wrapper for P/Invoke calls
/// that bridge managed C# code and native C/C++ functions.
///
/// # Arguments
/// * `function_name` - The function name to check for P/Invoke wrapper patterns.
///
/// # Returns
/// `true` if the function is identified as a P/Invoke wrapper, `false` otherwise.
pub fn is_pinvoke_wrapper(function_name: &str) -> bool {
    is_pinvoke_call(function_name) || function_name.contains("extern")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinvoke_call_detection() {
        // P/Invoke
        assert!(
            is_pinvoke_call("P/Invoke::kernel32.dll::CreateFile"),
            "P/Invoke must be detected"
        );
        // DllImport
        assert!(
            is_pinvoke_call("DllImport::user32.dll::MessageBox"),
            "DllImport must be detected"
        );
        // Non-P/Invoke
        assert!(
            !is_pinvoke_call("MyNamespace.MyClass.MyMethod"),
            "Non-P/Invoke must not be detected"
        );
    }

    #[test]
    fn test_marshal_allocation_detection() {
        // Marshal.AllocHGlobal
        assert!(
            is_marshal_allocation("Marshal.AllocHGlobal"),
            "Marshal.AllocHGlobal must be detected"
        );
        // Marshal.AllocCoTaskMem
        assert!(
            is_marshal_allocation("Marshal.AllocCoTaskMem"),
            "Marshal.AllocCoTaskMem must be detected"
        );
        // Non-Marshal allocation
        assert!(
            !is_marshal_allocation("Marshal.FreeHGlobal"),
            "Non-Marshal allocation must not be detected"
        );
    }

    #[test]
    fn test_marshal_deallocation_detection() {
        // Marshal.FreeHGlobal
        assert!(
            is_marshal_deallocation("Marshal.FreeHGlobal"),
            "Marshal.FreeHGlobal must be detected"
        );
        // Marshal.FreeCoTaskMem
        assert!(
            is_marshal_deallocation("Marshal.FreeCoTaskMem"),
            "Marshal.FreeCoTaskMem must be detected"
        );
        // Non-Marshal deallocation
        assert!(
            !is_marshal_deallocation("Marshal.AllocHGlobal"),
            "Non-Marshal deallocation must not be detected"
        );
    }

    #[test]
    fn test_com_interop_detection() {
        // Marshal.GetIUnknownForObject
        assert!(
            is_com_interop("Marshal.GetIUnknownForObject"),
            "Marshal.GetIUnknownForObject must be detected"
        );
        // Marshal.GetObjectForIUnknown
        assert!(
            is_com_interop("Marshal.GetObjectForIUnknown"),
            "Marshal.GetObjectForIUnknown must be detected"
        );
        // ComVisible
        assert!(is_com_interop("ComVisible"), "ComVisible must be detected");
        // Non-COM interop
        assert!(
            !is_com_interop("MyNamespace.MyClass.MyMethod"),
            "Non-COM interop must not be detected"
        );
    }

    #[test]
    fn test_detect_pinvoke_patterns() {
        // P/Invoke
        let patterns = detect_pinvoke_patterns("P/Invoke::kernel32.dll::CreateFile");
        assert!(
            patterns.contains(&CSharpSemanticPattern::PInvokeCall),
            "P/Invoke must be detected"
        );

        // Marshal allocation
        let patterns = detect_pinvoke_patterns("Marshal.AllocHGlobal");
        assert!(
            patterns.contains(&CSharpSemanticPattern::MarshalAllocation),
            "Marshal allocation must be detected"
        );

        // Marshal deallocation
        let patterns = detect_pinvoke_patterns("Marshal.FreeHGlobal");
        assert!(
            patterns.contains(&CSharpSemanticPattern::MarshalDeallocation),
            "Marshal deallocation must be detected"
        );
    }

    #[test]
    fn test_is_pinvoke_wrapper() {
        // P/Invoke
        assert!(
            is_pinvoke_wrapper("P/Invoke::kernel32.dll::CreateFile"),
            "P/Invoke must be detected as wrapper"
        );
        // extern
        assert!(
            is_pinvoke_wrapper("extern::MyFunction"),
            "extern must be detected as wrapper"
        );
        // Non-wrapper
        assert!(
            !is_pinvoke_wrapper("MyNamespace.MyClass.MyMethod"),
            "Non-wrapper must not be detected"
        );
    }
}
