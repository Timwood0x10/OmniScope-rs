//! Tests for exception handling pattern detection in C++ adapter.

use super::super::*;
use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

/// Objective: Verify exception handling detection
/// Invariants: __cxa_throw must be detected as ThrowExpression
#[test]
fn test_exception_handling_detection() {
    let adapter = CppAdapter::new();

    // throw
    let analysis = adapter.analyze_function("__cxa_throw", None);
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::ThrowExpression),
        "__cxa_throw must be detected as ThrowExpression"
    );
    assert!(
        analysis.uses_exceptions,
        "Function with throw must have uses_exceptions=true"
    );

    // catch
    let analysis = adapter.analyze_function("__cxa_begin_catch", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::CatchBlock),
        "__cxa_begin_catch must be detected as CatchBlock"
    );
}

/// Objective: Verify pure virtual function detection
/// Invariants: __cxa_pure_virtual must be detected as PureVirtual
#[test]
fn test_pure_virtual_detection() {
    let adapter = CppAdapter::new();

    let analysis = adapter.analyze_function("__cxa_pure_virtual", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::PureVirtual),
        "__cxa_pure_virtual must be detected as PureVirtual"
    );
}

/// Objective: Verify noexcept detection
/// Invariants: noexcept must be detected as Noexcept
#[test]
fn test_noexcept_detection() {
    let adapter = CppAdapter::new();

    // noexcept
    let analysis = adapter.analyze_function("noexcept_function", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::Noexcept),
        "noexcept must be detected as Noexcept"
    );

    // DnE pattern
    let analysis = adapter.analyze_function("_ZN5ClassDnE", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::Noexcept),
        "DnE pattern must be detected as Noexcept"
    );
}

/// Objective: Verify virtual call detection
/// Invariants: _vptr/vtable must be detected as VirtualCall
#[test]
fn test_virtual_call_detection() {
    let adapter = CppAdapter::new();

    // _vptr
    let analysis = adapter.analyze_function("_vptr_call", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::VirtualCall),
        "_vptr must be detected as VirtualCall"
    );

    // vtable
    let analysis = adapter.analyze_function("vtable_access", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::VirtualCall),
        "vtable must be detected as VirtualCall"
    );
}

/// Objective: Verify virtual destructor concern detection
/// Invariants: Virtual call without virtual destructor must be ConcernVirtualDestructor
#[test]
fn test_virtual_destructor_concern() {
    let adapter = CppAdapter::new();

    // Create a function body with virtual call but no virtual destructor
    let body = FunctionBody {
        name: "test_virtual_call".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%result".to_string()),
                operands: vec!["i8* %obj".to_string()],
                callee: Some("_vptr_method".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%result = call i8* @_vptr_method(i8* %obj)".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Ret,
                dest: None,
                operands: vec!["i8* %result".to_string()],
                callee: None,
                atomic_op: None,
                icmp_pred: None,
                raw_text: "ret i8* %result".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
        ],
    };

    let analysis = adapter.analyze_function("test_virtual_call", Some(&body));

    // Verify virtual call is detected
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::VirtualCall),
        "Virtual call must be detected from IR body"
    );

    // Verify concern assessment
    assert_eq!(
        analysis.ffi_safety,
        CppFFISafety::ConcernVirtualDestructor,
        "Virtual call without virtual destructor must be ConcernVirtualDestructor"
    );
}

/// Objective: Verify exception unsafe concern detection
/// Invariants: Throw without catch must be ConcernExceptionUnsafe
#[test]
fn test_exception_unsafe_concern() {
    let adapter = CppAdapter::new();

    // Create a function body with throw but no catch
    let body = FunctionBody {
        name: "test_throw_no_catch".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec!["i8* null".to_string()],
                callee: Some("__cxa_throw".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @__cxa_throw(i8* null)".to_string(),
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

    let analysis = adapter.analyze_function("test_throw_no_catch", Some(&body));

    // Verify throw is detected
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::ThrowExpression),
        "Throw must be detected from IR body"
    );

    // Verify concern assessment
    assert_eq!(
        analysis.ffi_safety,
        CppFFISafety::ConcernExceptionUnsafe,
        "Throw without catch must be ConcernExceptionUnsafe"
    );
}
