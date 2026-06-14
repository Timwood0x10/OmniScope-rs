//! Tests for Dispose pattern detection in C# adapter.

use super::super::*;
use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

/// Objective: Verify SafeHandle detection via adapter
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

/// Objective: Verify IDisposable detection via adapter
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

/// Objective: Verify SafeHandle detection with IR body
/// Invariants: IR body with SafeHandle calls must be detected
#[test]
fn test_safe_handle_with_ir_body() {
    let adapter = CSharpAdapter::new();

    let body = FunctionBody {
        name: "test_safe_handle".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%handle".to_string()),
                operands: vec!["i8*".to_string(), "%arg".to_string()],
                callee: Some("Microsoft.Win32.SafeHandles.SafeFileHandle".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%handle = call i8* @SafeFileHandle(i8* %arg)".to_string(),
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
                callee: Some("SafeHandle.ReleaseHandle".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @SafeHandle.ReleaseHandle(i8* %handle)".to_string(),
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

    let analysis = adapter.analyze_function("test_safe_handle", Some(&body));

    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::SafeHandleUsage),
        "SafeHandle must be detected from IR body"
    );
}

/// Objective: Verify GC safety assessment for SafeHandle/IDisposable
/// Invariants: SafeHandle must be SafePInvoke, IDisposable must be SafeManaged
#[test]
fn test_dispose_safety_assessment() {
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
}

/// Objective: Verify Dispose with IR body containing both SafeHandle and IDisposable
/// Invariants: Combined patterns must be correctly analyzed
#[test]
fn test_dispose_and_safe_handle_combined() {
    let adapter = CSharpAdapter::new();

    let body = FunctionBody {
        name: "test_combined_dispose".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%handle".to_string()),
                operands: vec!["i8*".to_string(), "%arg".to_string()],
                callee: Some("Microsoft.Win32.SafeHandles.SafeFileHandle".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%handle = call i8* @SafeFileHandle(i8* %arg)".to_string(),
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
                callee: Some("MyClass.Dispose()".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @MyClass.Dispose()".to_string(),
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

    let analysis = adapter.analyze_function("test_combined_dispose", Some(&body));

    // Should detect both SafeHandle and IDisposable from IR body
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::SafeHandleUsage),
        "SafeHandle must be detected from IR body"
    );
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::IDisposablePattern),
        "IDisposable must be detected from IR body"
    );

    // SafeHandle takes priority over IDisposable in safety assessment
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafePInvoke,
        "SafeHandle must be SafePInvoke"
    );
}
