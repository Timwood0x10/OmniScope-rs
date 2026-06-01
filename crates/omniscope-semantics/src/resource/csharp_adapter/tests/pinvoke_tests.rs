//! Tests for P/Invoke pattern detection in C# adapter.

use super::super::*;

/// Objective: Verify P/Invoke call detection
/// Invariants: P/Invoke and DllImport must be detected as PInvokeCall
#[test]
fn test_pinvoke_call_detection() {
    let adapter = CSharpAdapter::new();

    // P/Invoke
    let analysis = adapter.analyze_function("P/Invoke::kernel32.dll::CreateFile", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::PInvokeCall),
        "P/Invoke must be detected as PInvokeCall"
    );

    // DllImport
    let analysis = adapter.analyze_function("DllImport::user32.dll::MessageBox", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::PInvokeCall),
        "DllImport must be detected as PInvokeCall"
    );
}

/// Objective: Verify Marshal allocation detection
/// Invariants: Marshal.AllocHGlobal and Marshal.AllocCoTaskMem must be detected
#[test]
fn test_marshal_allocation_detection() {
    let adapter = CSharpAdapter::new();

    // Marshal.AllocHGlobal
    let analysis = adapter.analyze_function("Marshal.AllocHGlobal", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::MarshalAllocation),
        "Marshal.AllocHGlobal must be detected as MarshalAllocation"
    );

    // Marshal.AllocCoTaskMem
    let analysis = adapter.analyze_function("Marshal.AllocCoTaskMem", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::MarshalAllocation),
        "Marshal.AllocCoTaskMem must be detected as MarshalAllocation"
    );
}

/// Objective: Verify Marshal deallocation detection
/// Invariants: Marshal.FreeHGlobal and Marshal.FreeCoTaskMem must be detected
#[test]
fn test_marshal_deallocation_detection() {
    let adapter = CSharpAdapter::new();

    // Marshal.FreeHGlobal
    let analysis = adapter.analyze_function("Marshal.FreeHGlobal", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::MarshalDeallocation),
        "Marshal.FreeHGlobal must be detected as MarshalDeallocation"
    );

    // Marshal.FreeCoTaskMem
    let analysis = adapter.analyze_function("Marshal.FreeCoTaskMem", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::MarshalDeallocation),
        "Marshal.FreeCoTaskMem must be detected as MarshalDeallocation"
    );
}

/// Objective: Verify COM interop detection
/// Invariants: Marshal.GetIUnknownForObject and ComVisible must be detected
#[test]
fn test_com_interop_detection() {
    let adapter = CSharpAdapter::new();

    // Marshal.GetIUnknownForObject
    let analysis = adapter.analyze_function("Marshal.GetIUnknownForObject", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::COMInterop),
        "Marshal.GetIUnknownForObject must be detected as COMInterop"
    );

    // Marshal.GetObjectForIUnknown
    let analysis = adapter.analyze_function("Marshal.GetObjectForIUnknown", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::COMInterop),
        "Marshal.GetObjectForIUnknown must be detected as COMInterop"
    );

    // ComVisible
    let analysis = adapter.analyze_function("ComVisible", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::COMInterop),
        "ComVisible must be detected as COMInterop"
    );
}

/// Objective: Verify P/Invoke wrapper detection
/// Invariants: P/Invoke, DllImport, and extern must be detected as P/Invoke wrappers
#[test]
fn test_pinvoke_wrapper_detection() {
    let adapter = CSharpAdapter::new();

    // P/Invoke
    let analysis = adapter.analyze_function("P/Invoke::kernel32.dll::CreateFile", None);
    assert!(
        analysis.is_pinvoke_wrapper,
        "P/Invoke must be detected as P/Invoke wrapper"
    );

    // DllImport
    let analysis = adapter.analyze_function("DllImport::user32.dll::MessageBox", None);
    assert!(
        analysis.is_pinvoke_wrapper,
        "DllImport must be detected as P/Invoke wrapper"
    );

    // extern
    let analysis = adapter.analyze_function("extern::MyFunction", None);
    assert!(
        analysis.is_pinvoke_wrapper,
        "extern must be detected as P/Invoke wrapper"
    );

    // Non-wrapper
    let analysis = adapter.analyze_function("MyNamespace.MyClass.MyMethod", None);
    assert!(
        !analysis.is_pinvoke_wrapper,
        "Non-wrapper must not be detected as P/Invoke wrapper"
    );
}

/// Objective: Verify P/Invoke safety assessment
/// Invariants: P/Invoke without SafeHandle must be Unknown
#[test]
fn test_pinvoke_safety_assessment() {
    let adapter = CSharpAdapter::new();

    // P/Invoke without SafeHandle
    let analysis = adapter.analyze_function("P/Invoke::kernel32.dll::CreateFile", None);
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::Unknown,
        "P/Invoke without SafeHandle must be Unknown"
    );

    // P/Invoke with SafeHandle
    let analysis =
        adapter.analyze_function("P/Invoke::kernel32.dll::CreateFileWithSafeHandle", None);
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafePInvoke,
        "P/Invoke with SafeHandle must be SafePInvoke"
    );
}

/// Objective: Verify Marshal safety assessment
/// Invariants: Balanced Marshal alloc/dealloc must be SafeMarshal
#[test]
fn test_marshal_safety_assessment() {
    let adapter = CSharpAdapter::new();

    // Marshal allocation without deallocation
    let analysis = adapter.analyze_function("Marshal.AllocHGlobal", None);
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::ConcernPInvokeResource,
        "Marshal allocation without deallocation must be ConcernPInvokeResource"
    );

    // Marshal deallocation without allocation
    let analysis = adapter.analyze_function("Marshal.FreeHGlobal", None);
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::ConcernPInvokeResource,
        "Marshal deallocation without allocation must be ConcernPInvokeResource"
    );

    // Balanced Marshal allocation and deallocation
    let mut analysis = adapter.analyze_function("Marshal.AllocHGlobal", None);
    analysis
        .patterns
        .push(CSharpSemanticPattern::MarshalDeallocation);
    let ffi_safety = adapter.determine_ffi_safety("Marshal.AllocHGlobal", &analysis.patterns, None);
    assert_eq!(
        ffi_safety,
        CSharpFFISafety::SafeMarshal,
        "Balanced Marshal allocation and deallocation must be SafeMarshal"
    );
}
