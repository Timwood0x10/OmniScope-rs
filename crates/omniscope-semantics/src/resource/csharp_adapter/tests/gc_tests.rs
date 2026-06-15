//! Tests for GC pattern detection in C# adapter.

use super::super::*;
use crate::resource::semantic_tree::{FactConfidence, FactSource, SemanticKind};

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

/// Objective: Verify GC root tracking through SemanticFact conversion
/// Invariants: GCHandle patterns must produce CsharpPinvokeMarshal SemanticFacts
#[test]
fn test_gc_root_tracking_semantic_facts() {
    let adapter = CSharpAdapter::new();

    // GCHandle allocation produces a semantic fact
    let analysis = adapter.analyze_function("System.Runtime.InteropServices.GCHandle.Alloc", None);
    let facts = analysis.to_semantic_facts();
    let has_gchandle_fact = facts.iter().any(|f| {
        f.kind == SemanticKind::CsharpPinvokeMarshal
            && f.confidence == FactConfidence::Medium
            && f.source == FactSource::LanguageAdapter
    });
    assert!(
        has_gchandle_fact,
        "GCHandle allocation must produce CsharpPinvokeMarshal fact"
    );

    // GC operation produces RuntimeManagedResource facts
    let analysis = adapter.analyze_function("GC.Collect", None);
    let facts = analysis.to_semantic_facts();
    let has_gc_fact = facts.iter().any(|f| {
        f.kind == SemanticKind::RuntimeManagedResource
            && f.confidence == FactConfidence::High
            && f.source == FactSource::LanguageAdapter
    });
    assert!(
        has_gc_fact,
        "GC.Collect must produce RuntimeManagedResource fact"
    );

    // Unsafe function with GCHandle leak
    let analysis = adapter.analyze_function("System.Runtime.InteropServices.GCHandle.Alloc", None);
    let facts = analysis.to_semantic_facts();
    let has_concern_fact = facts.iter().any(|f| {
        f.kind == SemanticKind::Unknown
            && f.confidence == FactConfidence::Low
            && f.source == FactSource::LanguageAdapter
    });
    assert!(
        has_concern_fact,
        "GCHandle leak must produce low confidence concern fact"
    );
}

/// Objective: Verify GCHandle safety context with balanced alloc/dealloc in IR
/// Invariants: GCHandle.Alloc followed by GCHandle.Free must be properly assessed
#[test]
fn test_gc_handle_balanced_with_ir() {
    let adapter = CSharpAdapter::new();

    use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

    let body = FunctionBody {
        name: "test_gchandle_balanced".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%handle".to_string()),
                operands: vec!["i8*".to_string(), "%obj".to_string()],
                callee: Some("GCHandle.Alloc".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%handle = call i8* @GCHandle.Alloc(i8* %obj)".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec!["i8*".to_string(), "%handle".to_string()],
                callee: Some("GCHandle.Free".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @GCHandle.Free(i8* %handle)".to_string(),
                result_type: Some("void".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Ret,
                dest: None,
                operands: vec![],
                callee: None,
                atomic_op: None,
                icmp_pred: None,
                raw_text: "ret void".to_string(),
                result_type: Some("void".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
        ],
    };

    let analysis = adapter.analyze_function("test_gchandle_balanced", Some(&body));

    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::GCHandleAllocation),
        "GCHandle.Alloc must be detected from IR body"
    );
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::GCHandleDeallocation),
        "GCHandle.Free must be detected from IR body"
    );
    // With both alloc and dealloc, should not be GCHandleLeak
    assert_ne!(
        analysis.ffi_safety,
        CSharpFFISafety::ConcernGCHandleLeak,
        "Balanced GCHandle alloc/dealloc must not be ConcernGCHandleLeak"
    );
}

/// Objective: Verify GC pinned object detection
/// Invariants: P/Invoke with GCHandle pinning must be detected
#[test]
fn test_gc_pinned_object_detection() {
    let adapter = CSharpAdapter::new();

    // Simulate a function that pins managed memory via GCHandle
    let analysis = adapter.analyze_function("System.Runtime.InteropServices.GCHandle.Alloc", None);

    // Verify GCHandle allocation pattern is detected
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::GCHandleAllocation),
        "GCHandle.Alloc must be detected as GCHandleAllocation"
    );

    // Function that uses GCHandle for pinning but also shows GC interaction
    let analysis = adapter.analyze_function("GCHandle.Alloc_and_GC.Collect", None);
    let has_gchandle = analysis
        .patterns
        .contains(&CSharpSemanticPattern::GCHandleAllocation);
    let has_gc_op = analysis
        .patterns
        .contains(&CSharpSemanticPattern::GCOperation);
    assert!(
        has_gchandle || has_gc_op,
        "Function must detect at least one GC pattern"
    );
}
