//! Tests for C++ adapter semantic analysis.

pub mod exception_tests;
pub mod raii_tests;
pub mod smart_pointer_tests;

use super::*;
use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

/// Objective: Verify C++ adapter creation and basic functionality
/// Invariants: Adapter must be created with correct language setting
#[test]
fn test_cpp_adapter_creation() {
    let adapter = CppAdapter::new();
    assert_eq!(
        adapter.language(),
        Language::Cpp,
        "C++ adapter must have Cpp language setting"
    );
}

/// Objective: Verify Itanium ABI mangled name detection
/// Invariants: Names starting with _Z must be detected as MangledName
#[test]
fn test_mangled_name_detection() {
    let adapter = CppAdapter::new();

    // Standard mangled name
    let analysis = adapter.analyze_function("_ZNSt6vectorIiSaIiEE9push_backERKi", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::MangledName),
        "Mangled name _ZNSt6vector... must be detected as MangledName"
    );

    // Double underscore prefix (some compilers)
    let analysis = adapter.analyze_function("__ZN5Class5methodEv", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::MangledName),
        "Double underscore mangled name must be detected as MangledName"
    );
}

/// Objective: Verify extern "C" detection
/// Invariants: c_/C_/ffi_ prefixed functions must be extern "C"
#[test]
fn test_extern_c_detection() {
    let adapter = CppAdapter::new();

    // c_ prefix
    let analysis = adapter.analyze_function("c_create_object", None);
    assert!(
        analysis.is_extern_c,
        "c_create_object must be detected as extern C"
    );

    // ffi_ prefix
    let analysis = adapter.analyze_function("ffi_call_function", None);
    assert!(
        analysis.is_extern_c,
        "ffi_call_function must be detected as extern C"
    );

    // Mangled name must not be extern "C"
    let analysis = adapter.analyze_function("_ZN5Class5methodEv", None);
    assert!(
        !analysis.is_extern_c,
        "Mangled name must not be detected as extern C"
    );
}

/// Objective: Verify FFI safety score calculation
/// Invariants: Safe patterns must have higher scores than concerning patterns
#[test]
fn test_ffi_safety_scores() {
    assert!(
        CppFFISafety::SafeRAII.safety_score() > CppFFISafety::Unknown.safety_score(),
        "SafeRAII must have higher score than Unknown"
    );
    assert!(
        CppFFISafety::SafeSmartPointer.safety_score()
            > CppFFISafety::ConcernRawAllocation.safety_score(),
        "SafeSmartPointer must have higher score than ConcernRawAllocation"
    );
    assert!(
        CppFFISafety::ConcernExceptionUnsafe.safety_score() < CppFFISafety::Unknown.safety_score(),
        "ConcernExceptionUnsafe must have lower score than Unknown"
    );
    assert!(CppFFISafety::SafeRAII.is_safe(), "SafeRAII must be safe");
    assert!(
        !CppFFISafety::ConcernRawAllocation.is_safe(),
        "ConcernRawAllocation must not be safe"
    );
}

/// Objective: Verify unknown function handling
/// Invariants: Unknown functions must return Unknown safety
#[test]
fn test_unknown_function_handling() {
    let adapter = CppAdapter::new();

    let analysis = adapter.analyze_function("some_random_function", None);
    assert!(
        analysis.patterns.is_empty(),
        "Unknown function should have no patterns"
    );
    assert!(!analysis.uses_raii, "Unknown function should not use RAII");
    assert!(
        !analysis.uses_smart_pointers,
        "Unknown function should not use smart pointers"
    );
    assert_eq!(
        analysis.ffi_safety,
        CppFFISafety::Unknown,
        "Unknown function must have Unknown safety"
    );
}

/// Objective: Verify RAII semantics using embedded IR
/// Invariants: RAII object must have constructor and destructor calls
#[test]
fn test_raii_semantics_with_ir() {
    let adapter = CppAdapter::new();

    // Create a function body with RAII pattern (constructor + destructor)
    let body = FunctionBody {
        name: "test_raii_function".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%obj".to_string()),
                operands: vec!["i8* null".to_string()],
                callee: Some("_ZN5ClassC1Ev".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%obj = call i8* @_ZN5ClassC1Ev(i8* null)".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec!["i8* %obj".to_string()],
                callee: Some("_ZN5ClassD1Ev".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @_ZN5ClassD1Ev(i8* %obj)".to_string(),
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

    let analysis = adapter.analyze_function("test_raii_function", Some(&body));

    // Verify RAII patterns are detected from IR
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::Constructor),
        "Constructor must be detected from IR body"
    );
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::Destructor),
        "Destructor must be detected from IR body"
    );

    // Verify RAII feature flag
    assert!(
        analysis.uses_raii,
        "Function with constructor+destructor must have uses_raii=true"
    );

    // Verify safety assessment
    assert_eq!(
        analysis.ffi_safety,
        CppFFISafety::SafeRAII,
        "RAII pattern must be assessed as SafeRAII"
    );
}

/// Objective: Verify smart pointer semantics using embedded IR
/// Invariants: Smart pointer must be detected from IR calls
#[test]
fn test_smart_pointer_semantics_with_ir() {
    let adapter = CppAdapter::new();

    // Create a function body with smart pointer usage
    let body = FunctionBody {
        name: "test_smart_ptr_function".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%ptr".to_string()),
                operands: vec![],
                callee: Some("_ZNSt10unique_ptrI5ClassSt14default_deleteIS0_EEC1Ev".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%ptr = call i8* @_ZNSt10unique_ptr...".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Ret,
                dest: None,
                operands: vec!["i8* %ptr".to_string()],
                callee: None,
                atomic_op: None,
                icmp_pred: None,
                raw_text: "ret i8* %ptr".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
        ],
    };

    let analysis = adapter.analyze_function("test_smart_ptr_function", Some(&body));

    // Verify smart pointer patterns are detected from IR
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::UniquePtrCreation),
        "unique_ptr must be detected from IR body"
    );

    // Verify smart pointer feature flag
    assert!(
        analysis.uses_smart_pointers,
        "Function with unique_ptr must have uses_smart_pointers=true"
    );

    // Verify safety assessment
    assert_eq!(
        analysis.ffi_safety,
        CppFFISafety::SafeSmartPointer,
        "Smart pointer usage must be assessed as SafeSmartPointer"
    );
}

/// Objective: Verify mixed ownership concern detection
/// Invariants: Smart pointer + raw allocation must be ConcernMixedOwnership
#[test]
fn test_mixed_ownership_concern() {
    let adapter = CppAdapter::new();

    // Create a function body with mixed ownership
    let body = FunctionBody {
        name: "test_mixed_ownership".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%smart".to_string()),
                operands: vec![],
                callee: Some("_ZNSt10shared_ptrI5ClassEC1Ev".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%smart = call i8* @_ZNSt10shared_ptr...".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%raw".to_string()),
                operands: vec!["i64 64".to_string()],
                callee: Some("_Znwm".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%raw = call i8* @_Znwm(i64 64)".to_string(),
                result_type: Some("i8*".to_string()),
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

    let analysis = adapter.analyze_function("test_mixed_ownership", Some(&body));

    // Verify mixed ownership is detected
    assert!(
        analysis.uses_smart_pointers,
        "Function with shared_ptr must have uses_smart_pointers=true"
    );

    // Verify concern assessment
    assert_eq!(
        analysis.ffi_safety,
        CppFFISafety::ConcernMixedOwnership,
        "Mixed ownership must be ConcernMixedOwnership"
    );
}

/// Objective: Verify reference count operations detection
/// Invariants: _M_add_ref/_M_release must be detected
#[test]
fn test_refcount_operations() {
    let adapter = CppAdapter::new();

    // Reference count increment
    let analysis = adapter.analyze_function(
        "_ZNSt14__shared_countILN9__gnu_cxx12_Lock_policyE2EE10_M_add_refEv",
        None,
    );
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::RefCountIncrement),
        "_M_add_ref must be detected as RefCountIncrement"
    );

    // Reference count decrement
    let analysis = adapter.analyze_function(
        "_ZNSt14__shared_countILN9__gnu_cxx12_Lock_policyE2EE10_M_releaseEv",
        None,
    );
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::RefCountDecrement),
        "_M_release must be detected as RefCountDecrement"
    );
}
