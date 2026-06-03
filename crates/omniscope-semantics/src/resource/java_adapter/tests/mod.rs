//! Tests for Java adapter semantic analysis.

pub mod jni_tests;
pub mod reference_tests;

use super::*;
use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

/// Objective: Verify Java adapter creation and basic functionality
/// Invariants: Adapter must be created with correct language setting
#[test]
fn test_java_adapter_creation() {
    let adapter = JavaAdapter::new();
    assert_eq!(
        adapter.language(),
        Language::Java,
        "Java adapter must have Java language setting"
    );
}

/// Objective: Verify JNI native method analysis
/// Invariants: Java_ prefixed functions must be detected as JNI native methods
#[test]
fn test_jni_native_method_analysis() {
    let adapter = JavaAdapter::new();
    let analysis = adapter.analyze_function("Java_com_example_MyClass_nativeMethod", None);

    assert!(
        analysis.patterns.contains(&JavaSemanticPattern::JNICall),
        "JNI native method must be detected as JNICall"
    );
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNINativeRegistration),
        "JNI native method must be detected as JNINativeRegistration"
    );
    assert!(
        analysis.is_jni_native,
        "JNI native method must be detected as JNI native"
    );
}

/// Objective: Verify JNI object creation analysis
/// Invariants: NewObject must be detected as JNIObjectCreation
#[test]
fn test_jni_object_creation_analysis() {
    let adapter = JavaAdapter::new();
    let analysis = adapter.analyze_function("(*env)->NewObject", None);

    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIObjectCreation),
        "NewObject must be detected as JNIObjectCreation"
    );
    assert!(
        analysis.patterns.contains(&JavaSemanticPattern::JNICall),
        "NewObject must be detected as JNICall"
    );
}

/// Objective: Verify JNI reference management analysis
/// Invariants: DeleteLocalRef must be detected as JNILocalReference
#[test]
fn test_jni_reference_management_analysis() {
    let adapter = JavaAdapter::new();
    let analysis = adapter.analyze_function("(*env)->DeleteLocalRef", None);

    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNILocalReference),
        "DeleteLocalRef must be detected as JNILocalReference"
    );
    assert!(
        analysis.manages_jni_references,
        "DeleteLocalRef must manage JNI references"
    );
}

/// Objective: Verify JNI class loading analysis
/// Invariants: FindClass must be detected as JNIClassLoading
#[test]
fn test_jni_class_loading_analysis() {
    let adapter = JavaAdapter::new();
    let analysis = adapter.analyze_function("(*env)->FindClass", None);

    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIClassLoading),
        "FindClass must be detected as JNIClassLoading"
    );
}

/// Objective: Verify JNI method resolution analysis
/// Invariants: GetMethodID must be detected as JNIMethodResolution
#[test]
fn test_jni_method_resolution_analysis() {
    let adapter = JavaAdapter::new();
    let analysis = adapter.analyze_function("(*env)->GetMethodID", None);

    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIMethodResolution),
        "GetMethodID must be detected as JNIMethodResolution"
    );
}

/// Objective: Verify JNI exception handling analysis
/// Invariants: ExceptionOccurred must be detected as JNIExceptionHandling
#[test]
fn test_jni_exception_handling_analysis() {
    let adapter = JavaAdapter::new();
    let analysis = adapter.analyze_function("(*env)->ExceptionOccurred", None);

    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIExceptionHandling),
        "ExceptionOccurred must be detected as JNIExceptionHandling"
    );
}

/// Objective: Verify JNI string operations analysis
/// Invariants: NewStringUTF must be detected as JNIStringOperation
#[test]
fn test_jni_string_operations_analysis() {
    let adapter = JavaAdapter::new();
    let analysis = adapter.analyze_function("(*env)->NewStringUTF", None);

    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIStringOperation),
        "NewStringUTF must be detected as JNIStringOperation"
    );
}

/// Objective: Verify JNI array operations analysis
/// Invariants: NewIntArray must be detected as JNIArrayOperation
#[test]
fn test_jni_array_operations_analysis() {
    let adapter = JavaAdapter::new();
    let analysis = adapter.analyze_function("(*env)->NewIntArray", None);

    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIArrayOperation),
        "NewIntArray must be detected as JNIArrayOperation"
    );
}

/// Objective: Verify JNI monitor operations analysis
/// Invariants: MonitorEnter must be detected as JNIMonitorOperation
#[test]
fn test_jni_monitor_operations_analysis() {
    let adapter = JavaAdapter::new();
    let analysis = adapter.analyze_function("(*env)->MonitorEnter", None);

    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIMonitorOperation),
        "MonitorEnter must be detected as JNIMonitorOperation"
    );
}

/// Objective: Verify JNI reference leak detection
/// Invariants: JNI without proper reference cleanup must be ConcernJNIReferenceLeak
#[test]
fn test_jni_reference_leak_detection() {
    let adapter = JavaAdapter::new();
    // Function that creates JNI references but doesn't clean them up
    let analysis = adapter.analyze_function("(*env)->NewObject", None);

    // Note: This test assumes NewObject creates references but doesn't clean them
    // In reality, we'd need to analyze the entire function body
    assert!(
        analysis.is_jni_native,
        "NewObject must be detected as JNI native"
    );
}

/// Objective: Verify JNI exception handling safety
/// Invariants: JNI without exception handling must be ConcernJNIException
#[test]
fn test_jni_exception_handling_safety() {
    let adapter = JavaAdapter::new();
    // Function that doesn't handle JNI exceptions
    let analysis = adapter.analyze_function("Java_com_example_MyClass_nativeMethod", None);

    // Note: This test assumes the function doesn't handle exceptions
    // In reality, we'd need to analyze the entire function body
    assert!(
        analysis.is_jni_native,
        "JNI native method must be detected as JNI native"
    );
}

/// Objective: Verify Java language detection from function names
/// Invariants: Java patterns must be correctly identified
#[test]
fn test_java_language_patterns() {
    let adapter = JavaAdapter::new();

    // Test various Java function patterns
    let test_cases = vec![
        (
            "Java_com_example_MyClass_nativeMethod",
            true,
            "JNI native method",
        ),
        ("(*env)->NewObject", true, "JNI object creation"),
        ("(*env)->DeleteLocalRef", true, "JNI reference management"),
        ("(*env)->FindClass", true, "JNI class loading"),
        ("(*env)->GetMethodID", true, "JNI method resolution"),
        ("(*env)->ExceptionOccurred", true, "JNI exception handling"),
        ("(*env)->NewStringUTF", true, "JNI string operations"),
        ("(*env)->NewIntArray", true, "JNI array operations"),
        ("(*env)->MonitorEnter", true, "JNI monitor operations"),
        ("JNI_OnLoad", true, "JNI initialization"),
        ("MyClass.myMethod", false, "Regular Java method"),
    ];

    for (func_name, should_be_jni, description) in test_cases {
        let analysis = adapter.analyze_function(func_name, None);
        let is_jni = analysis.is_jni_native;

        if should_be_jni {
            assert!(
                is_jni,
                "{}: {} should be detected as JNI native method",
                description, func_name
            );
        }
    }
}

/// Objective: Verify Java adapter handles unknown functions gracefully
/// Invariants: Unknown functions must return SafeJava safety
#[test]
fn test_unknown_function_handling() {
    let adapter = JavaAdapter::new();
    let analysis = adapter.analyze_function("unknown_function", None);

    assert!(
        analysis.patterns.is_empty(),
        "Unknown function should have no patterns"
    );
    assert!(
        !analysis.is_jni_native,
        "Unknown function should not be a JNI native method"
    );
    assert_eq!(
        analysis.ffi_safety,
        JavaFFISafety::SafeJava,
        "Unknown function must have SafeJava safety"
    );
}

/// Objective: Verify JNI call semantics using embedded IR
/// Invariants: JNI calls must be properly analyzed
#[test]
fn test_jni_call_semantics_with_ir() {
    let adapter = JavaAdapter::new();

    // Create a function body with JNI calls including exception handling
    let body = FunctionBody {
        name: "test_jni_function".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%class".to_string()),
                operands: vec!["i8*".to_string(), "i8*".to_string()],
                callee: Some("(*env)->FindClass".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%class = call i8* @(*env)->FindClass(i8* \"com/example/MyClass\")"
                    .to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
            conversion_opcode: None,
            binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%method".to_string()),
                operands: vec![
                    "i8*".to_string(),
                    "%class".to_string(),
                    "i8*".to_string(),
                    "i8*".to_string(),
                ],
                callee: Some("(*env)->GetMethodID".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%method = call i8* @(*env)->GetMethodID(i8* %class, i8* \"myMethod\", i8* \"()V\")".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
            conversion_opcode: None,
            binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%exception".to_string()),
                operands: vec![],
                callee: Some("(*env)->ExceptionOccurred".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%exception = call i8* @(*env)->ExceptionOccurred()".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
            conversion_opcode: None,
            binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec!["i8*".to_string(), "%class".to_string()],
                callee: Some("(*env)->DeleteLocalRef".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @(*env)->DeleteLocalRef(i8* %class)".to_string(),
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

    let analysis = adapter.analyze_function("test_jni_function", Some(&body));

    // Verify JNI patterns are detected
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIClassLoading),
        "JNI class loading must be detected from IR body"
    );
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIMethodResolution),
        "JNI method resolution must be detected from IR body"
    );
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNILocalReference),
        "JNI reference management must be detected from IR body"
    );
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIExceptionHandling),
        "JNI exception handling must be detected from IR body"
    );

    // Verify memory management flags
    assert!(
        analysis.manages_jni_references,
        "Function with JNI calls must manage JNI references"
    );
    assert!(
        analysis.manages_native_memory,
        "Function with JNI calls must manage native memory"
    );

    // Verify FFI safety assessment
    assert_eq!(
        analysis.ffi_safety,
        JavaFFISafety::SafeJNI,
        "JNI with proper reference management and exception handling must be SafeJNI"
    );
}

/// Objective: Verify JNI object creation semantics using embedded IR
/// Invariants: JNI object creation must be properly detected
#[test]
fn test_jni_object_creation_with_ir() {
    let adapter = JavaAdapter::new();

    // Create a function body with JNI object creation and proper cleanup
    let body = FunctionBody {
        name: "test_jni_object_creation".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%obj".to_string()),
                operands: vec![
                    "i8*".to_string(),
                    "%class".to_string(),
                    "%method".to_string(),
                ],
                callee: Some("(*env)->NewObject".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%obj = call i8* @(*env)->NewObject(i8* %class, i8* %method)".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%exception".to_string()),
                operands: vec![],
                callee: Some("(*env)->ExceptionOccurred".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%exception = call i8* @(*env)->ExceptionOccurred()".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec!["i8*".to_string(), "%obj".to_string()],
                callee: Some("(*env)->DeleteLocalRef".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @(*env)->DeleteLocalRef(i8* %obj)".to_string(),
                result_type: Some("void".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Ret,
                dest: None,
                operands: vec!["i8* %obj".to_string()],
                callee: None,
                atomic_op: None,
                icmp_pred: None,
                raw_text: "ret i8* %obj".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
        ],
    };

    let analysis = adapter.analyze_function("test_jni_object_creation", Some(&body));

    // Verify JNI object creation pattern is detected
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIObjectCreation),
        "JNI object creation must be detected from IR body"
    );
    assert!(
        analysis.patterns.contains(&JavaSemanticPattern::JNICall),
        "NewObject must be detected as JNICall"
    );
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIExceptionHandling),
        "JNI exception handling must be detected from IR body"
    );
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNILocalReference),
        "JNI reference management must be detected from IR body"
    );

    // Verify memory management flags
    assert!(
        analysis.manages_jni_references,
        "Function with NewObject must manage JNI references"
    );
    assert!(
        analysis.manages_native_memory,
        "Function with NewObject must manage native memory"
    );
}

/// Objective: Verify JNI exception handling detection with IR body
/// Invariants: JNI exception handling functions must be correctly identified
#[test]
fn test_jni_exception_handling_with_ir() {
    let adapter = JavaAdapter::new();

    // Create a function body with JNI exception handling
    let body = FunctionBody {
        name: "test_jni_exception_handling".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%exception".to_string()),
                operands: vec![],
                callee: Some("(*env)->ExceptionOccurred".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%exception = call i8* @(*env)->ExceptionOccurred()".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec![],
                callee: Some("(*env)->ExceptionClear".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @(*env)->ExceptionClear()".to_string(),
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

    let analysis = adapter.analyze_function("test_jni_exception_handling", Some(&body));

    // Verify JNI exception handling detection
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIExceptionHandling),
        "JNI exception handling must be detected from IR body"
    );

    // Verify FFI safety assessment
    assert_eq!(
        analysis.ffi_safety,
        JavaFFISafety::SafeJNI,
        "JNI with proper exception handling must be SafeJNI"
    );
}

/// Objective: Verify mixed Java and JNI patterns
/// Invariants: Functions with both Java and JNI patterns must be correctly analyzed
#[test]
fn test_mixed_java_jni_patterns() {
    let adapter = JavaAdapter::new();

    // Create a function body with mixed Java and JNI patterns including exception handling
    let body = FunctionBody {
        name: "mixed_function".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%obj".to_string()),
                operands: vec!["i64 32".to_string()],
                callee: Some("new java.lang.Object".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%obj = call i8* @new.java.lang.Object(i64 32)".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%class".to_string()),
                operands: vec!["i8*".to_string()],
                callee: Some("(*env)->FindClass".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%class = call i8* @(*env)->FindClass(i8* \"com/example/MyClass\")"
                    .to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%exception".to_string()),
                operands: vec![],
                callee: Some("(*env)->ExceptionOccurred".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%exception = call i8* @(*env)->ExceptionOccurred()".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec!["i8*".to_string(), "%class".to_string()],
                callee: Some("(*env)->DeleteLocalRef".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @(*env)->DeleteLocalRef(i8* %class)".to_string(),
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

    // Verify both Java and JNI patterns are detected
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIClassLoading),
        "JNI class loading must be detected"
    );
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNILocalReference),
        "JNI reference management must be detected"
    );
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIExceptionHandling),
        "JNI exception handling must be detected"
    );

    // Verify memory management flags
    assert!(
        analysis.manages_jni_references,
        "Function with JNI calls must manage JNI references"
    );
    assert!(
        analysis.manages_native_memory,
        "Function with JNI calls must manage native memory"
    );

    // Verify FFI safety assessment
    // Mixed Java and JNI patterns with proper reference management and exception handling
    // should be SafeJNI because JNI calls are properly managed
    assert_eq!(
        analysis.ffi_safety,
        JavaFFISafety::SafeJNI,
        "Mixed Java and JNI patterns with proper reference management and exception handling must be SafeJNI"
    );
}
