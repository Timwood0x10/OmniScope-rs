//! Tests for P/Invoke pattern detection in C# adapter.

use super::super::*;
use crate::resource::semantic_tree::{FactConfidence, FactSource, SemanticKind};

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

/// Objective: Verify Marshal class operations (PtrToStructure, StructureToPtr)
/// Invariants: Marshal.PtrToStructure and Marshal.StructureToPtr must be detected
#[test]
fn test_marshal_structure_operations() {
    let adapter = CSharpAdapter::new();

    // Marshal.PtrToStructure
    let analysis = adapter.analyze_function("Marshal.PtrToStructure", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::PInvokeCall),
        "Marshal.PtrToStructure must be detected as PInvokeCall"
    );

    // Marshal.StructureToPtr
    let analysis = adapter.analyze_function("Marshal.StructureToPtr", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::PInvokeCall),
        "Marshal.StructureToPtr must be detected as PInvokeCall"
    );

    // Marshal.SizeOf
    let analysis = adapter.analyze_function("Marshal.SizeOf", None);
    assert!(
        !analysis.patterns.is_empty(),
        "Marshal.SizeOf must produce at least one pattern"
    );
}

/// Objective: Verify Marshal string marshaling detection
/// Invariants: Marshal.StringToHGlobalAnsi and Marshal.PtrToStringAnsi must be detected
#[test]
fn test_marshal_string_marshaling() {
    let adapter = CSharpAdapter::new();

    // Marshal.StringToHGlobalAnsi (allocation)
    let analysis = adapter.analyze_function("Marshal.StringToHGlobalAnsi", None);
    let has_marshal_alloc = analysis
        .patterns
        .contains(&CSharpSemanticPattern::MarshalAllocation);
    let has_pinvoke = analysis
        .patterns
        .contains(&CSharpSemanticPattern::PInvokeCall);
    assert!(
        has_marshal_alloc || has_pinvoke,
        "Marshal.StringToHGlobalAnsi must be detected as allocation or P/Invoke"
    );

    // Marshal.PtrToStringAnsi (deallocation read)
    let analysis = adapter.analyze_function("Marshal.PtrToStringAnsi", None);
    assert!(
        !analysis.patterns.is_empty(),
        "Marshal.PtrToStringAnsi must produce at least one pattern"
    );

    // Marshal.StringToCoTaskMemAnsi (allocation)
    let analysis = adapter.analyze_function("Marshal.StringToCoTaskMemAnsi", None);
    let has_marshal_alloc = analysis
        .patterns
        .contains(&CSharpSemanticPattern::MarshalAllocation);
    let has_pinvoke = analysis
        .patterns
        .contains(&CSharpSemanticPattern::PInvokeCall);
    assert!(
        has_marshal_alloc || has_pinvoke,
        "Marshal.StringToCoTaskMemAnsi must be detected as allocation or P/Invoke"
    );
}

/// Objective: Verify COM interop with IR body analysis
/// Invariants: COM call patterns must be detected from IR body
#[test]
fn test_com_interop_with_ir() {
    let adapter = CSharpAdapter::new();

    use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

    let body = FunctionBody {
        name: "test_com_function".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%unk".to_string()),
                operands: vec!["i8*".to_string(), "%obj".to_string()],
                callee: Some("Marshal.GetIUnknownForObject".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%unk = call i8* @Marshal.GetIUnknownForObject(i8* %obj)".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec!["i8*".to_string(), "%unk".to_string()],
                callee: Some("Marshal.GetObjectForIUnknown".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @Marshal.GetObjectForIUnknown(i8* %unk)".to_string(),
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

    let analysis = adapter.analyze_function("test_com_function", Some(&body));

    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::COMInterop),
        "COM interop must be detected from IR body"
    );
}

/// Objective: Verify Marshal.GetComInterfaceForObject detection
/// Invariants: Marshal.GetComInterfaceForObject must be detected as COMInterop
#[test]
fn test_marshal_get_com_interface() {
    let adapter = CSharpAdapter::new();

    // Marshal.GetComInterfaceForObject
    let analysis = adapter.analyze_function("Marshal.GetComInterfaceForObject", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::COMInterop),
        "Marshal.GetComInterfaceForObject must be detected as COMInterop"
    );

    // Marshal.GetIDispatchForObject
    let analysis = adapter.analyze_function("Marshal.GetIDispatchForObject", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::COMInterop),
        "Marshal.GetIDispatchForObject must be detected as COMInterop"
    );

    // Marshal.ReleaseComObject
    let analysis = adapter.analyze_function("Marshal.ReleaseComObject", None);
    assert!(
        analysis
            .patterns
            .contains(&CSharpSemanticPattern::COMInterop),
        "Marshal.ReleaseComObject must be detected as COMInterop"
    );
}

/// Objective: Verify SemanticFact generation for P/Invoke patterns
/// Invariants: P/Invoke patterns must produce correct SemanticFacts
#[test]
fn test_pinvoke_semantic_facts() {
    let adapter = CSharpAdapter::new();

    // P/Invoke call produces CsharpPinvokeMarshal fact
    let analysis = adapter.analyze_function("P/Invoke::kernel32.dll::CreateFile", None);
    let facts = analysis.to_semantic_facts();
    let has_pinvoke_fact = facts.iter().any(|f| {
        f.kind == SemanticKind::CsharpPinvokeMarshal
            && f.confidence == FactConfidence::High
            && f.source == FactSource::LanguageAdapter
    });
    assert!(
        has_pinvoke_fact,
        "P/Invoke must produce CsharpPinvokeMarshal fact with High confidence"
    );

    // Marshal allocation produces HeapProvenance fact
    let analysis = adapter.analyze_function("Marshal.AllocHGlobal", None);
    let facts = analysis.to_semantic_facts();
    let has_alloc_fact = facts.iter().any(|f| {
        f.kind == SemanticKind::HeapProvenance
            && f.confidence == FactConfidence::High
            && f.source == FactSource::LanguageAdapter
    });
    assert!(
        has_alloc_fact,
        "Marshal.AllocHGlobal must produce HeapProvenance fact"
    );

    // Marshal deallocation produces RaiiDropRelease fact
    let analysis = adapter.analyze_function("Marshal.FreeHGlobal", None);
    let facts = analysis.to_semantic_facts();
    let has_dealloc_fact = facts.iter().any(|f| {
        f.kind == SemanticKind::RaiiDropRelease
            && f.confidence == FactConfidence::Medium
            && f.source == FactSource::LanguageAdapter
    });
    assert!(
        has_dealloc_fact,
        "Marshal.FreeHGlobal must produce RaiiDropRelease fact"
    );
}
