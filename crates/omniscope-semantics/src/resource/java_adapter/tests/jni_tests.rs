//! Tests for JNI pattern detection in Java adapter.

use super::super::*;

/// Objective: Verify JNI native method detection
/// Invariants: Java_ prefixed functions must be detected as JNI native methods
#[test]
fn test_jni_native_method_detection() {
    let adapter = JavaAdapter::new();

    // Java_ prefixed function
    let analysis = adapter.analyze_function("Java_com_example_MyClass_nativeMethod", None);
    assert!(
        analysis.patterns.contains(&JavaSemanticPattern::JNICall),
        "Java_ prefixed function must be detected as JNICall"
    );
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNINativeRegistration),
        "Java_ prefixed function must be detected as JNINativeRegistration"
    );
    assert!(
        analysis.is_jni_native,
        "Java_ prefixed function must be detected as JNI native"
    );
}

/// Objective: Verify JNI object creation detection
/// Invariants: NewObject must be detected as JNIObjectCreation
#[test]
fn test_jni_object_creation_detection() {
    let adapter = JavaAdapter::new();

    // NewObject
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

    // NewString
    let analysis = adapter.analyze_function("(*env)->NewString", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIObjectCreation),
        "NewString must be detected as JNIObjectCreation"
    );

    // NewObjectArray
    let analysis = adapter.analyze_function("(*env)->NewObjectArray", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIObjectCreation),
        "NewObjectArray must be detected as JNIObjectCreation"
    );
}

/// Objective: Verify JNI class loading detection
/// Invariants: FindClass must be detected as JNIClassLoading
#[test]
fn test_jni_class_loading_detection() {
    let adapter = JavaAdapter::new();

    // FindClass
    let analysis = adapter.analyze_function("(*env)->FindClass", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIClassLoading),
        "FindClass must be detected as JNIClassLoading"
    );
}

/// Objective: Verify JNI method resolution detection
/// Invariants: GetMethodID must be detected as JNIMethodResolution
#[test]
fn test_jni_method_resolution_detection() {
    let adapter = JavaAdapter::new();

    // GetMethodID
    let analysis = adapter.analyze_function("(*env)->GetMethodID", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIMethodResolution),
        "GetMethodID must be detected as JNIMethodResolution"
    );

    // GetStaticMethodID
    let analysis = adapter.analyze_function("(*env)->GetStaticMethodID", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIMethodResolution),
        "GetStaticMethodID must be detected as JNIMethodResolution"
    );
}

/// Objective: Verify JNI field access detection
/// Invariants: GetFieldID must be detected as JNIFieldAccess
#[test]
fn test_jni_field_access_detection() {
    let adapter = JavaAdapter::new();

    // GetFieldID
    let analysis = adapter.analyze_function("(*env)->GetFieldID", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIFieldAccess),
        "GetFieldID must be detected as JNIFieldAccess"
    );

    // GetStaticFieldID
    let analysis = adapter.analyze_function("(*env)->GetStaticFieldID", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIFieldAccess),
        "GetStaticFieldID must be detected as JNIFieldAccess"
    );
}

/// Objective: Verify JNI string operation detection
/// Invariants: NewStringUTF must be detected as JNIStringOperation
#[test]
fn test_jni_string_operation_detection() {
    let adapter = JavaAdapter::new();

    // NewStringUTF
    let analysis = adapter.analyze_function("(*env)->NewStringUTF", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIStringOperation),
        "NewStringUTF must be detected as JNIStringOperation"
    );

    // GetStringUTFChars
    let analysis = adapter.analyze_function("(*env)->GetStringUTFChars", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIStringOperation),
        "GetStringUTFChars must be detected as JNIStringOperation"
    );
}

/// Objective: Verify JNI array operation detection
/// Invariants: NewIntArray must be detected as JNIArrayOperation
#[test]
fn test_jni_array_operation_detection() {
    let adapter = JavaAdapter::new();

    // NewIntArray
    let analysis = adapter.analyze_function("(*env)->NewIntArray", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIArrayOperation),
        "NewIntArray must be detected as JNIArrayOperation"
    );

    // GetArrayElements
    let analysis = adapter.analyze_function("(*env)->GetArrayElements", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIArrayOperation),
        "GetArrayElements must be detected as JNIArrayOperation"
    );
}

/// Objective: Verify JNI monitor operation detection
/// Invariants: MonitorEnter must be detected as JNIMonitorOperation
#[test]
fn test_jni_monitor_operation_detection() {
    let adapter = JavaAdapter::new();

    // MonitorEnter
    let analysis = adapter.analyze_function("(*env)->MonitorEnter", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIMonitorOperation),
        "MonitorEnter must be detected as JNIMonitorOperation"
    );

    // MonitorExit
    let analysis = adapter.analyze_function("(*env)->MonitorExit", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIMonitorOperation),
        "MonitorExit must be detected as JNIMonitorOperation"
    );
}

/// Objective: Verify JNI exception handling detection
/// Invariants: ExceptionOccurred must be detected as JNIExceptionHandling
#[test]
fn test_jni_exception_handling_detection() {
    let adapter = JavaAdapter::new();

    // ExceptionOccurred
    let analysis = adapter.analyze_function("(*env)->ExceptionOccurred", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIExceptionHandling),
        "ExceptionOccurred must be detected as JNIExceptionHandling"
    );

    // ExceptionClear
    let analysis = adapter.analyze_function("(*env)->ExceptionClear", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIExceptionHandling),
        "ExceptionClear must be detected as JNIExceptionHandling"
    );

    // ExceptionCheck
    let analysis = adapter.analyze_function("(*env)->ExceptionCheck", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIExceptionHandling),
        "ExceptionCheck must be detected as JNIExceptionHandling"
    );

    // Throw
    let analysis = adapter.analyze_function("(*env)->Throw", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIExceptionHandling),
        "Throw must be detected as JNIExceptionHandling"
    );

    // ThrowNew
    let analysis = adapter.analyze_function("(*env)->ThrowNew", None);
    assert!(
        analysis
            .patterns
            .contains(&JavaSemanticPattern::JNIExceptionHandling),
        "ThrowNew must be detected as JNIExceptionHandling"
    );
}

/// Objective: Verify JNI safety assessment
/// Invariants: JNI with proper exception handling must be SafeJNI
#[test]
fn test_jni_safety_assessment() {
    let adapter = JavaAdapter::new();

    // JNI without exception handling
    let analysis = adapter.analyze_function("Java_com_example_MyClass_nativeMethod", None);
    assert_eq!(
        analysis.ffi_safety,
        JavaFFISafety::ConcernJNIException,
        "JNI without exception handling must be ConcernJNIException"
    );

    // JNI with exception handling
    let analysis = adapter.analyze_function("(*env)->ExceptionOccurred", None);
    assert_eq!(
        analysis.ffi_safety,
        JavaFFISafety::SafeJNI,
        "JNI with exception handling must be SafeJNI"
    );

    // JNI native method without proper exception handling
    let analysis =
        adapter.analyze_function("Java_com_example_MyClass_nativeMethodWithException", None);
    assert_eq!(
        analysis.ffi_safety,
        JavaFFISafety::ConcernJNIException,
        "JNI native method without exception handling must be ConcernJNIException"
    );
}
