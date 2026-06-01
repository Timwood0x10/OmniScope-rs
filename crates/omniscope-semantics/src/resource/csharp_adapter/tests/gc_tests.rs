//! Tests for GC pattern detection in C# adapter.

use super::super::*;

/// Objective: Verify GCHandle allocation detection
/// Invariants: GCHandle.Alloc must be detected as GCHandleAllocation
#[test]
fn test_gc_handle_allocation_detection() {
    let adapter = CSharpAdapter::new();

    // GCHandle.Alloc
    let analysis = adapter.analyze_function("System.Runtime.InteropServices.GCHandle.Alloc", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::GCHandleAllocation),
        "GCHandle.Alloc must be detected as GCHandleAllocation"
    );
}

/// Objective: Verify GCHandle deallocation detection
/// Invariants: GCHandle.Free must be detected as GCHandleDeallocation
#[test]
fn test_gc_handle_deallocation_detection() {
    let adapter = CSharpAdapter::new();

    // GCHandle.Free
    let analysis = adapter.analyze_function("System.Runtime.InteropServices.GCHandle.Free", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::GCHandleDeallocation),
        "GCHandle.Free must be detected as GCHandleDeallocation"
    );
}

/// Objective: Verify GC operation detection
/// Invariants: GC.Collect and GC.WaitForPendingFinalizers must be detected
#[test]
fn test_gc_operation_detection() {
    let adapter = CSharpAdapter::new();

    // GC.Collect
    let analysis = adapter.analyze_function("GC.Collect", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::GCOperation),
        "GC.Collect must be detected as GCOperation"
    );

    // GC.WaitForPendingFinalizers
    let analysis = adapter.analyze_function("GC.WaitForPendingFinalizers", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::GCOperation),
        "GC.WaitForPendingFinalizers must be detected as GCOperation"
    );
}

/// Objective: Verify GCHandle leak detection
/// Invariants: GCHandle allocation without deallocation must be ConcernGCHandleLeak
#[test]
fn test_gc_handle_leak_detection() {
    let adapter = CSharpAdapter::new();

    // GCHandle allocation without deallocation
    let analysis = adapter.analyze_function("System.Runtime.InteropServices.GCHandle.Alloc", None);
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::ConcernGCHandleLeak,
        "GCHandle allocation without deallocation must be ConcernGCHandleLeak"
    );

    // GCHandle with deallocation
    let mut analysis =
        adapter.analyze_function("System.Runtime.InteropServices.GCHandle.Alloc", None);
    analysis
        .patterns
        .push(CSharpSemanticPattern::GCHandleDeallocation);
    let ffi_safety = adapter.determine_ffi_safety(
        "System.Runtime.InteropServices.GCHandle.Alloc",
        &analysis.patterns,
        None,
    );
    assert_eq!(
        ffi_safety,
        CSharpFFISafety::Unknown,
        "GCHandle with deallocation must be Unknown"
    );
}

/// Objective: Verify SafeHandle detection
/// Invariants: SafeHandle must be detected as SafeHandleUsage
#[test]
fn test_safe_handle_detection() {
    let adapter = CSharpAdapter::new();

    // SafeHandle
    let analysis = adapter.analyze_function("Microsoft.Win32.SafeHandles.SafeFileHandle", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::SafeHandleUsage),
        "SafeHandle must be detected as SafeHandleUsage"
    );

    // CriticalHandle
    let analysis = adapter.analyze_function("Microsoft.Win32.SafeHandles.CriticalHandle", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::SafeHandleUsage),
        "CriticalHandle must be detected as SafeHandleUsage"
    );
}

/// Objective: Verify IDisposable detection
/// Invariants: IDisposable must be detected as IDisposablePattern
#[test]
fn test_idisposable_detection() {
    let adapter = CSharpAdapter::new();

    // IDisposable
    let analysis = adapter.analyze_function("System.IDisposable.Dispose", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::IDisposablePattern),
        "IDisposable must be detected as IDisposablePattern"
    );

    // .Dispose()
    let analysis = adapter.analyze_function("MyClass.Dispose()", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::IDisposablePattern),
        ".Dispose() must be detected as IDisposablePattern"
    );
}

/// Objective: Verify GC safety assessment
/// Invariants: SafeHandle must be SafePInvoke, IDisposable must be SafeManaged
#[test]
fn test_gc_safety_assessment() {
    let adapter = CSharpAdapter::new();

    // SafeHandle
    let analysis = adapter.analyze_function("Microsoft.Win32.SafeHandles.SafeFileHandle", None);
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafePInvoke,
        "SafeHandle must be SafePInvoke"
    );

    // IDisposable
    let analysis = adapter.analyze_function("System.IDisposable.Dispose", None);
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafeManaged,
        "IDisposable must be SafeManaged"
    );

    // GCHandle leak
    let analysis = adapter.analyze_function("System.Runtime.InteropServices.GCHandle.Alloc", None);
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::ConcernGCHandleLeak,
        "GCHandle leak must be ConcernGCHandleLeak"
    );
}
