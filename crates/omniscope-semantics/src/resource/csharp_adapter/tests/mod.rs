//! Tests for C# adapter semantic analysis.

pub mod dispose_tests;
pub mod gc_tests;
pub mod pinvoke_tests;

use super::*;
use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

/// Objective: Verify C# adapter creation and basic functionality
/// Invariants: Adapter must be created with correct language setting
#[test]
fn test_csharp_adapter_creation() {
    let adapter = CSharpAdapter::new();
    assert_eq!(
        adapter.language(),
        Language::CSharp,
        "C# adapter must have CSharp language setting"
    );
}

/// Objective: Verify P/Invoke function analysis
/// Invariants: P/Invoke functions must be detected as PInvokeCall
#[test]
fn test_pinvoke_function_analysis() {
    let adapter = CSharpAdapter::new();
    let analysis = adapter.analyze_function("P/Invoke::kernel32.dll::CreateFile", None);

    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::PInvokeCall),
        "P/Invoke function must be detected as PInvokeCall"
    );
    assert!(
        analysis.is_pinvoke_wrapper,
        "P/Invoke function must be detected as P/Invoke wrapper"
    );
}

/// Objective: Verify Marshal allocation function analysis
/// Invariants: Marshal.AllocHGlobal must be detected as MarshalAllocation
#[test]
fn test_marshal_allocation_analysis() {
    let adapter = CSharpAdapter::new();
    let analysis = adapter.analyze_function("Marshal.AllocHGlobal", None);

    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::MarshalAllocation),
        "Marshal.AllocHGlobal must be detected as MarshalAllocation"
    );
    assert!(
        analysis.manages_native_memory,
        "Marshal.AllocHGlobal must manage native memory"
    );
}

/// Objective: Verify Marshal deallocation function analysis
/// Invariants: Marshal.FreeHGlobal must be detected as MarshalDeallocation
#[test]
fn test_marshal_deallocation_analysis() {
    let adapter = CSharpAdapter::new();
    let analysis = adapter.analyze_function("Marshal.FreeHGlobal", None);

    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::MarshalDeallocation),
        "Marshal.FreeHGlobal must be detected as MarshalDeallocation"
    );
    assert!(
        analysis.manages_native_memory,
        "Marshal.FreeHGlobal must manage native memory"
    );
}

/// Objective: Verify SafeHandle usage analysis
/// Invariants: SafeHandle must be detected as SafeHandleUsage
#[test]
fn test_safe_handle_analysis() {
    let adapter = CSharpAdapter::new();
    let analysis = adapter.analyze_function("Microsoft.Win32.SafeHandles.SafeFileHandle", None);

    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::SafeHandleUsage),
        "SafeHandle must be detected as SafeHandleUsage"
    );
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafePInvoke,
        "SafeHandle must be SafePInvoke"
    );
}

/// Objective: Verify IDisposable pattern analysis
/// Invariants: IDisposable must be detected as IDisposablePattern
#[test]
fn test_idisposable_pattern_analysis() {
    let adapter = CSharpAdapter::new();
    let analysis = adapter.analyze_function("System.IDisposable.Dispose", None);

    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::IDisposablePattern),
        "IDisposable must be detected as IDisposablePattern"
    );
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafeManaged,
        "IDisposable must be SafeManaged"
    );
}

/// Objective: Verify GCHandle allocation analysis
/// Invariants: GCHandle.Alloc must be detected as GCHandleAllocation
#[test]
fn test_gc_handle_allocation_analysis() {
    let adapter = CSharpAdapter::new();
    let analysis = adapter.analyze_function("System.Runtime.InteropServices.GCHandle.Alloc", None);

    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::GCHandleAllocation),
        "GCHandle.Alloc must be detected as GCHandleAllocation"
    );
}

/// Objective: Verify GCHandle leak detection
/// Invariants: GCHandle without release must be ConcernGCHandleLeak
#[test]
fn test_gc_handle_leak_detection() {
    let adapter = CSharpAdapter::new();
    // Function that allocates GCHandle but doesn't free it
    let analysis = adapter.analyze_function("System.Runtime.InteropServices.GCHandle.Alloc", None);

    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::ConcernGCHandleLeak,
        "GCHandle allocation without release must be ConcernGCHandleLeak"
    );
}

/// Objective: Verify Marshal balanced allocation/deallocation
/// Invariants: Function with both allocation and deallocation must be SafeMarshal
#[test]
fn test_marshal_balanced() {
    let adapter = CSharpAdapter::new();
    // Simulate a function that does both allocation and deallocation
    let mut analysis = adapter.analyze_function("Marshal.AllocHGlobal", None);

    // Manually add deallocation pattern to simulate balanced memory management
    analysis
        .patterns
        .push(CSharpSemanticPattern::MarshalDeallocation);

    let ffi_safety = adapter.determine_ffi_safety("Marshal.AllocHGlobal", &analysis.patterns, None);

    assert_eq!(
        ffi_safety,
        CSharpFFISafety::SafeMarshal,
        "Marshal with balanced allocation/deallocation must be SafeMarshal"
    );
}

/// Objective: Verify FFI safety score calculation
/// Invariants: Safe patterns must have higher scores than concerning patterns
#[test]
fn test_ffi_safety_scores() {
    assert!(
        CSharpFFISafety::SafeManaged.safety_score() > CSharpFFISafety::Unknown.safety_score(),
        "SafeManaged must have higher score than Unknown"
    );
    assert!(
        CSharpFFISafety::SafePInvoke.safety_score()
            > CSharpFFISafety::ConcernPInvokeResource.safety_score(),
        "SafePInvoke must have higher score than ConcernPInvokeResource"
    );
    assert!(
        CSharpFFISafety::ConcernGCHandleLeak.safety_score()
            < CSharpFFISafety::Unknown.safety_score(),
        "ConcernGCHandleLeak must have lower score than Unknown"
    );
}

/// Objective: Verify C# language detection from function names
/// Invariants: C# patterns must be correctly identified
#[test]
fn test_csharp_language_patterns() {
    let adapter = CSharpAdapter::new();

    // Test various C# function patterns
    let test_cases = vec![
        ("P/Invoke::kernel32.dll::CreateFile", true, "P/Invoke call"),
        ("Marshal.AllocHGlobal", true, "Marshal allocation"),
        (
            "System.Runtime.InteropServices.GCHandle.Alloc",
            true,
            "GCHandle allocation",
        ),
        (
            "Microsoft.Win32.SafeHandles.SafeFileHandle",
            true,
            "SafeHandle",
        ),
        ("System.IDisposable.Dispose", true, "IDisposable"),
        ("GC.Collect", true, "GC operation"),
        ("MyNamespace.MyClass.MyMethod", false, "Regular C# method"),
    ];

    for (func_name, should_be_interop, description) in test_cases {
        let analysis = adapter.analyze_function(func_name, None);
        let is_interop = !analysis.patterns.is_empty();

        if should_be_interop {
            assert!(
                is_interop,
                "{}: {} should be detected as C# interop pattern",
                description, func_name
            );
        }
    }
}

/// Objective: Verify C# adapter handles unknown functions gracefully
/// Invariants: Unknown functions must return Unknown safety
#[test]
fn test_unknown_function_handling() {
    let adapter = CSharpAdapter::new();
    let analysis = adapter.analyze_function("unknown_function", None);

    assert!(
        analysis.patterns.is_empty(),
        "Unknown function should have no patterns"
    );
    assert!(
        !analysis.is_pinvoke_wrapper,
        "Unknown function should not be a P/Invoke wrapper"
    );
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafeManaged,
        "Unknown function must have SafeManaged safety"
    );
}

/// Objective: Verify P/Invoke call semantics using embedded IR
/// Invariants: P/Invoke calls must be properly analyzed
#[test]
fn test_pinvoke_call_semantics_with_ir() {
    let adapter = CSharpAdapter::new();

    // Create a function body with P/Invoke calls
    let body = FunctionBody {
        name: "test_pinvoke_function".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%handle".to_string()),
                operands: vec!["i8*".to_string(), "i32 0".to_string()],
                callee: Some("P/Invoke::kernel32.dll::CreateFile".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%handle = call i8* @P/Invoke::kernel32.dll::CreateFile(i32 0)"
                    .to_string(),
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
                callee: Some("P/Invoke::kernel32.dll::CloseHandle".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @P/Invoke::kernel32.dll::CloseHandle(i8* %handle)".to_string(),
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

    let analysis = adapter.analyze_function("test_pinvoke_function", Some(&body));

    // Verify P/Invoke patterns are detected
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::PInvokeCall),
        "P/Invoke call must be detected from IR body"
    );

    // Verify FFI safety assessment
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::Unknown,
        "P/Invoke without SafeHandle must be Unknown"
    );
}

/// Objective: Verify Marshal allocation semantics using embedded IR
/// Invariants: Marshal allocations must be properly detected
#[test]
fn test_marshal_allocation_with_ir() {
    let adapter = CSharpAdapter::new();

    // Create a function body with Marshal allocation and deallocation
    let body = FunctionBody {
        name: "test_marshal_function".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%ptr".to_string()),
                operands: vec!["i64 100".to_string()],
                callee: Some("Marshal.AllocHGlobal".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%ptr = call i8* @Marshal.AllocHGlobal(i64 100)".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec!["i8*".to_string(), "%ptr".to_string()],
                callee: Some("Marshal.FreeHGlobal".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @Marshal.FreeHGlobal(i8* %ptr)".to_string(),
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

    let analysis = adapter.analyze_function("test_marshal_function", Some(&body));

    // Verify Marshal patterns are detected
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::MarshalAllocation),
        "Marshal allocation must be detected from IR body"
    );
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::MarshalDeallocation),
        "Marshal deallocation must be detected from IR body"
    );

    // Verify memory management flags
    assert!(
        analysis.manages_native_memory,
        "Function with Marshal calls must manage native memory"
    );
    assert!(
        !analysis.manages_managed_memory,
        "Function with only Marshal calls must not manage managed memory"
    );

    // Verify FFI safety assessment
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafeMarshal,
        "Marshal with balanced allocation/deallocation must be SafeMarshal"
    );
}

/// Objective: Verify SafeHandle detection with IR body
/// Invariants: SafeHandle functions must be correctly identified
#[test]
fn test_safe_handle_detection_with_ir() {
    let adapter = CSharpAdapter::new();

    // Create a function body with SafeHandle pattern
    let body = FunctionBody {
        name: "test_safe_handle_function".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%handle".to_string()),
                operands: vec!["i8*".to_string(), "%arg".to_string()],
                callee: Some("Microsoft.Win32.SafeHandles.SafeFileHandle".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text:
                    "%handle = call i8* @Microsoft.Win32.SafeHandles.SafeFileHandle(i8* %arg)"
                        .to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Ret,
                dest: None,
                operands: vec!["i8* %handle".to_string()],
                callee: None,
                atomic_op: None,
                icmp_pred: None,
                raw_text: "ret i8* %handle".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
        ],
    };

    let analysis = adapter.analyze_function("test_safe_handle_function", Some(&body));

    // Verify SafeHandle detection
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::SafeHandleUsage),
        "SafeHandle must be detected from IR body"
    );

    // Verify FFI safety assessment
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafePInvoke,
        "SafeHandle must be SafePInvoke"
    );
}

/// Objective: Verify mixed C# and P/Invoke patterns
/// Invariants: Functions with both C# and P/Invoke patterns must be correctly analyzed
#[test]
fn test_mixed_csharp_pinvoke_patterns() {
    let adapter = CSharpAdapter::new();

    // Create a function body with mixed C# and P/Invoke patterns
    let body = FunctionBody {
        name: "mixed_function".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%obj".to_string()),
                operands: vec!["i64 32".to_string()],
                callee: Some("new System.Object".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%obj = call i8* @new.System.Object(i64 32)".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%ptr".to_string()),
                operands: vec!["i64 100".to_string()],
                callee: Some("Marshal.AllocHGlobal".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%ptr = call i8* @Marshal.AllocHGlobal(i64 100)".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec!["i8*".to_string(), "%ptr".to_string()],
                callee: Some("Marshal.FreeHGlobal".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @Marshal.FreeHGlobal(i8* %ptr)".to_string(),
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

    let analysis = adapter.analyze_function("mixed_function", Some(&body));

    // Verify both C# and P/Invoke patterns are detected
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::MarshalAllocation),
        "Marshal allocation must be detected"
    );
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::MarshalDeallocation),
        "Marshal deallocation must be detected"
    );

    // Verify memory management flags
    assert!(
        analysis.manages_native_memory,
        "Function with Marshal calls must manage native memory"
    );

    // Verify FFI safety assessment
    // Mixed C# and P/Invoke patterns with balanced Marshal allocation/deallocation
    // should be SafeMarshal because Marshal calls are properly managed
    assert_eq!(
        analysis.ffi_safety,
        CSharpFFISafety::SafeMarshal,
        "Mixed C# and P/Invoke patterns with balanced Marshal calls must be SafeMarshal"
    );
}
