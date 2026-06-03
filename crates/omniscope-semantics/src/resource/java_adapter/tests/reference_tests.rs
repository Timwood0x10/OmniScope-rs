//! Tests for reference management pattern detection in Java adapter.

use super::super::*;
use omniscope_ir::parser::{FunctionBody, IRInstruction, IRInstructionKind};

/// Objective: Verify JNI local reference management detection
/// Invariants: DeleteLocalRef must be detected as JNILocalReference
#[test]
fn test_local_reference_management_detection() {
    let adapter = JavaAdapter::new();

    // DeleteLocalRef
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

/// Objective: Verify JNI global reference management detection
/// Invariants: NewGlobalRef must be detected as JNIGlobalReference
#[test]
fn test_global_reference_management_detection() {
    let adapter = JavaAdapter::new();

    // NewGlobalRef
    let analysis = adapter.analyze_function("(*env)->NewGlobalRef", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIGlobalReference),
        "NewGlobalRef must be detected as JNIGlobalReference"
    );
    assert!(
        analysis.manages_jni_references,
        "NewGlobalRef must manage JNI references"
    );

    // DeleteGlobalRef
    let analysis = adapter.analyze_function("(*env)->DeleteGlobalRef", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIGlobalReference),
        "DeleteGlobalRef must be detected as JNIGlobalReference"
    );
}

/// Objective: Verify JNI weak global reference management detection
/// Invariants: NewWeakGlobalRef must be detected as JNIWeakGlobalReference
#[test]
fn test_weak_global_reference_management_detection() {
    let adapter = JavaAdapter::new();

    // NewWeakGlobalRef
    let analysis = adapter.analyze_function("(*env)->NewWeakGlobalRef", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIWeakGlobalReference),
        "NewWeakGlobalRef must be detected as JNIWeakGlobalReference"
    );
    assert!(
        analysis.manages_jni_references,
        "NewWeakGlobalRef must manage JNI references"
    );

    // DeleteWeakGlobalRef
    let analysis = adapter.analyze_function("(*env)->DeleteWeakGlobalRef", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIWeakGlobalReference),
        "DeleteWeakGlobalRef must be detected as JNIWeakGlobalReference"
    );
}

/// Objective: Verify JNI reference leak detection
/// Invariants: JNI references without cleanup must be ConcernJNIException (due to missing exception handling)
#[test]
fn test_reference_leak_detection() {
    let adapter = JavaAdapter::new();

    // Reference creation without cleanup and without exception handling
    let analysis = adapter.analyze_function("(*env)->NewGlobalRef", None);
    assert_eq!(
        analysis.ffi_safety,
        JavaFFISafety::ConcernJNIException,
        "Reference creation without exception handling must be ConcernJNIException"
    );

    // Reference with cleanup and exception handling
    let mut analysis = adapter.analyze_function("(*env)->NewGlobalRef", None);
    analysis
        .patterns
        .push(JavaSemanticPattern::JNILocalReference);
    analysis
        .patterns
        .push(JavaSemanticPattern::JNIExceptionHandling);
    let ffi_safety = adapter.determine_ffi_safety("(*env)->NewGlobalRef", &analysis.patterns, None);
    assert_eq!(
        ffi_safety,
        JavaFFISafety::SafeJNI,
        "Reference with cleanup and exception handling must be SafeJNI"
    );
}

/// Objective: Verify JNI reference safety assessment
/// Invariants: JNI with proper reference management must be ConcernJNIException (due to missing exception handling)
#[test]
fn test_reference_safety_assessment() {
    let adapter = JavaAdapter::new();

    // JNI with proper reference management but without exception handling
    let analysis = adapter.analyze_function("(*env)->DeleteLocalRef", None);
    assert_eq!(
        analysis.ffi_safety,
        JavaFFISafety::ConcernJNIException,
        "JNI with reference management but without exception handling must be ConcernJNIException"
    );

    // JNI native method without exception handling
    let analysis = adapter.analyze_function("Java_com_example_MyClass_nativeMethod", None);
    assert_eq!(
        analysis.ffi_safety,
        JavaFFISafety::ConcernJNIException,
        "JNI native method without exception handling must be ConcernJNIException"
    );
}

/// Objective: Verify JNI reference management with IR body
/// Invariants: JNI reference management must be properly detected from IR
#[test]
fn test_reference_management_with_ir() {
    let adapter = JavaAdapter::new();

    // Create a function body with JNI reference management
    let body = FunctionBody {
        name: "test_reference_management".to_string(),
        instructions: vec![
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: Some("%ref".to_string()),
                operands: vec!["i8*".to_string(), "%obj".to_string()],
                callee: Some("(*env)->NewGlobalRef".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "%ref = call i8* @(*env)->NewGlobalRef(i8* %obj)".to_string(),
                result_type: Some("i8*".to_string()),
                element_type: None,
                function_signature: None,
                conversion_opcode: None,
                binary_opcode: None,
            },
            IRInstruction {
                kind: IRInstructionKind::Call,
                dest: None,
                operands: vec!["i8*".to_string(), "%ref".to_string()],
                callee: Some("(*env)->DeleteGlobalRef".to_string()),
                atomic_op: None,
                icmp_pred: None,
                raw_text: "call void @(*env)->DeleteGlobalRef(i8* %ref)".to_string(),
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

    let analysis = adapter.analyze_function("test_reference_management", Some(&body));

    // Verify reference management patterns are detected
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIGlobalReference),
        "Global reference management must be detected from IR body"
    );
    assert!(
        analysis.patterns.contains(&JavaSemanticPattern::JNICall),
        "JNI call must be detected from IR body"
    );

    // Verify memory management flags
    assert!(
        analysis.manages_jni_references,
        "Function with reference management must manage JNI references"
    );
    assert!(
        analysis.manages_native_memory,
        "Function with reference management must manage native memory"
    );

    // Verify FFI safety assessment
    assert_eq!(
        analysis.ffi_safety,
        JavaFFISafety::ConcernJNIException,
        "JNI with reference management but without exception handling must be ConcernJNIException"
    );
}
