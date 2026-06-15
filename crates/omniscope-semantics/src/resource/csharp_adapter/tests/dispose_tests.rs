//! Tests for Dispose pattern detection in C# adapter.

use super::super::*;
use crate::resource::semantic_tree::{FactConfidence, FactSource, SemanticKind};

/// Objective: Verify SafeHandle detection from adapter
/// Invariants: SafeHandle must be detected as SafeHandleUsage
#[test]
fn test_safe_handle_detection() {
    let adapter = CSharpAdapter::new();

    // SafeFileHandle
    let analysis = adapter.analyze_function("Microsoft.Win32.SafeHandles.SafeFileHandle", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::SafeHandleUsage),
        "SafeFileHandle must be detected as SafeHandleUsage"
    );

    // CriticalHandle
    let analysis = adapter.analyze_function("Microsoft.Win32.SafeHandles.CriticalHandle", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::SafeHandleUsage),
        "CriticalHandle must be detected as SafeHandleUsage"
    );

    // SafeHandle subclasses (SafeWaitHandle, SafeMemoryMappedViewHandle)
    let analysis = adapter.analyze_function("Microsoft.Win32.SafeHandles.SafeWaitHandle", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::SafeHandleUsage),
        "SafeWaitHandle must be detected as SafeHandleUsage"
    );
}

/// Objective: Verify IDisposable detection from adapter
/// Invariants: IDisposable and .Dispose() must be detected as IDisposablePattern
#[test]
fn test_idisposable_detection() {
    let adapter = CSharpAdapter::new();

    // IDisposable.Dispose
    let analysis = adapter.analyze_function("System.IDisposable.Dispose", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::IDisposablePattern),
        "IDisposable.Dispose must be detected as IDisposablePattern"
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

/// Objective: Verify Dispose pattern with IR body analysis
/// Invariants: Dispose calls in IR body must be detected as IDisposablePattern
#[test]
fn test_dispose_pattern_with_ir() {
    let adapter = CSharpAdapter::new();

    use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

    let body = FunctionBody {
        name: "test_dispose_function".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec!["i8*".to_string(), "%resource".to_string()],
                callee: Some("MyClass.Dispose()".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @MyClass.Dispose()(i8* %resource)".to_string(),
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

    let analysis = adapter.analyze_function("test_dispose_function", Some(&body));

    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::IDisposablePattern),
        "Dispose() call must be detected as IDisposablePattern from IR body"
    );
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafeManaged,
        "IDisposable pattern must be SafeManaged"
    );
}

/// Objective: Verify SafeHandle finalizer pattern detection
/// Invariants: SafeHandle with ~ destructor must be detected
#[test]
fn test_safe_handle_finalizer() {
    let adapter = CSharpAdapter::new();

    // SafeHandle with finalizer pattern in name
    let analysis =
        adapter.analyze_function("Microsoft.Win32.SafeHandles.SafeHandle.Finalize", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::SafeHandleUsage),
        "SafeHandle.Finalize must be detected as SafeHandleUsage"
    );

    // Verify safety assessment
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafePInvoke,
        "SafeHandle with finalizer must be SafePInvoke"
    );
}

/// Objective: Verify SemanticFact conversion for dispose patterns
/// Invariants: SafeHandle must produce CsharpSafeHandle facts
#[test]
fn test_dispose_semantic_facts() {
    let adapter = CSharpAdapter::new();

    // SafeHandle produces CsharpSafeHandle fact
    let analysis = adapter.analyze_function("Microsoft.Win32.SafeHandles.SafeFileHandle", None);
    let facts = analysis.to_semantic_facts();
    let has_safe_handle_fact = facts.iter().any(|f| {
        f.kind == SemanticKind::CsharpSafeHandle
            && f.confidence == FactConfidence::High
            && f.source == FactSource::LanguageAdapter
    });
    assert!(
        has_safe_handle_fact,
        "SafeHandle must produce CsharpSafeHandle fact with High confidence"
    );

    // IDisposable produces CsharpSafeHandle fact with Medium confidence
    let analysis = adapter.analyze_function("System.IDisposable.Dispose", None);
    let facts = analysis.to_semantic_facts();
    let has_idisposable_fact = facts.iter().any(|f| {
        f.kind == SemanticKind::CsharpSafeHandle
            && f.confidence == FactConfidence::Medium
            && f.source == FactSource::LanguageAdapter
    });
    assert!(
        has_idisposable_fact,
        "IDisposable must produce CsharpSafeHandle fact with Medium confidence"
    );
}

/// Objective: Verify dispose pattern safety assessment
/// Invariants: SafeHandle must be SafePInvoke, IDisposable must be SafeManaged
#[test]
fn test_dispose_safety_assessment() {
    let adapter = CSharpAdapter::new();

    // SafeHandle -> SafePInvoke
    let analysis = adapter.analyze_function("Microsoft.Win32.SafeHandles.SafeFileHandle", None);
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafePInvoke,
        "SafeHandle must be SafePInvoke"
    );

    // IDisposable -> SafeManaged
    let analysis = adapter.analyze_function("System.IDisposable.Dispose", None);
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafeManaged,
        "IDisposable must be SafeManaged"
    );

    // CriticalHandle -> SafePInvoke
    let analysis = adapter.analyze_function("Microsoft.Win32.SafeHandles.CriticalHandle", None);
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafePInvoke,
        "CriticalHandle must be SafePInvoke"
    );
}
