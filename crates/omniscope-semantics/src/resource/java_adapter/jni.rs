//! JNI call pattern detection for Java.
//!
//! This module provides JNI-specific semantic analysis, including:
//! - JNI native method detection
//! - JNI object creation detection
//! - JNI class loading detection
//! - JNI method resolution detection

use super::JavaSemanticPattern;

/// Checks if a function name indicates a JNI native method.
///
/// # Objective
/// Detect JNI native method patterns in Java function names. JNI native
/// methods are prefixed with "Java_" and bridge Java and native code.
///
/// # Invariants
/// - Returns true for Java_ prefixed functions.
/// - Returns false for non-JNI native method patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for JNI native method patterns.
///
/// # Returns
/// `true` if the function is identified as a JNI native method, `false` otherwise.
pub fn is_jni_native_method(function_name: &str) -> bool {
    function_name.starts_with("Java_")
}

/// Checks if a function name indicates a JNI call.
///
/// # Objective
/// Detect JNI call patterns in Java function names. JNI calls include
/// JNI native methods, JNI environment functions, and JNI prefixed functions.
///
/// # Invariants
/// - Returns true for Java_, JNI, (*env)->, or JNIEnv patterns.
/// - Returns false for non-JNI call patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for JNI call patterns.
///
/// # Returns
/// `true` if the function is identified as a JNI call, `false` otherwise.
pub fn is_jni_call(function_name: &str) -> bool {
    function_name.starts_with("Java_")
        || function_name.starts_with("JNI")
        || function_name.contains("(*env)->")
        || function_name.contains("JNIEnv")
}

/// Checks if a function name indicates JNI object creation.
///
/// # Objective
/// Detect JNI object creation patterns in Java function names. JNI object
/// creation includes NewObject, NewString, and NewObjectArray.
///
/// # Invariants
/// - Returns true for NewObject, NewString, or NewObjectArray patterns.
/// - Returns false for non-JNI object creation patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for JNI object creation.
///
/// # Returns
/// `true` if the function is identified as JNI object creation, `false` otherwise.
pub fn is_jni_object_creation(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("NewObject")
            || function_name.contains("NewString")
            || function_name.contains("NewObjectArray"))
}

/// Checks if a function name indicates JNI class loading.
///
/// # Objective
/// Detect JNI class loading patterns in Java function names. JNI class
/// loading is identified by FindClass patterns.
///
/// # Invariants
/// - Returns true for FindClass patterns.
/// - Returns false for non-JNI class loading patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for JNI class loading.
///
/// # Returns
/// `true` if the function is identified as JNI class loading, `false` otherwise.
pub fn is_jni_class_loading(function_name: &str) -> bool {
    is_jni_call(function_name) && function_name.contains("FindClass")
}

/// Checks if a function name indicates JNI method resolution.
///
/// # Objective
/// Detect JNI method resolution patterns in Java function names. JNI method
/// resolution is identified by GetMethodID or GetStaticMethodID patterns.
///
/// # Invariants
/// - Returns true for GetMethodID or GetStaticMethodID patterns.
/// - Returns false for non-JNI method resolution patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for JNI method resolution.
///
/// # Returns
/// `true` if the function is identified as JNI method resolution, `false` otherwise.
pub fn is_jni_method_resolution(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("GetMethodID") || function_name.contains("GetStaticMethodID"))
}

/// Checks if a function name indicates JNI field access.
///
/// # Objective
/// Detect JNI field access patterns in Java function names. JNI field access
/// is identified by GetFieldID, GetStaticFieldID, and related patterns.
///
/// # Invariants
/// - Returns true for GetFieldID, GetStaticFieldID, and related patterns.
/// - Returns false for non-JNI field access patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for JNI field access.
///
/// # Returns
/// `true` if the function is identified as JNI field access, `false` otherwise.
pub fn is_jni_field_access(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("GetFieldID")
            || function_name.contains("GetStaticFieldID")
            || function_name.contains("GetIntField")
            || function_name.contains("SetIntField")
            || function_name.contains("GetObjectField")
            || function_name.contains("SetObjectField"))
}

/// Checks if a function name indicates JNI string operations.
///
/// # Objective
/// Detect JNI string operation patterns in Java function names. JNI string
/// operations include NewStringUTF, GetStringUTFChars, etc.
///
/// # Invariants
/// - Returns true for NewStringUTF, GetStringUTFChars, etc.
/// - Returns false for non-JNI string operation patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for JNI string operations.
///
/// # Returns
/// `true` if the function is identified as JNI string operations, `false` otherwise.
pub fn is_jni_string_operation(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("NewStringUTF")
            || function_name.contains("GetStringUTFChars")
            || function_name.contains("ReleaseStringUTFChars")
            || function_name.contains("GetStringLength"))
}

/// Checks if a function name indicates JNI array operations.
///
/// # Objective
/// Detect JNI array operation patterns in Java function names. JNI array
/// operations include NewArray, GetArrayElements, etc.
///
/// # Invariants
/// - Returns true for NewArray, GetArrayElements, etc.
/// - Returns false for non-JNI array operation patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for JNI array operations.
///
/// # Returns
/// `true` if the function is identified as JNI array operations, `false` otherwise.
pub fn is_jni_array_operation(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("NewIntArray")
            || function_name.contains("NewBooleanArray")
            || function_name.contains("NewByteArray")
            || function_name.contains("NewCharArray")
            || function_name.contains("NewShortArray")
            || function_name.contains("NewLongArray")
            || function_name.contains("NewFloatArray")
            || function_name.contains("NewDoubleArray")
            || function_name.contains("GetArrayElements")
            || function_name.contains("ReleaseArrayElements")
            || function_name.contains("GetArrayLength"))
}

/// Checks if a function name indicates JNI monitor operations.
///
/// # Objective
/// Detect JNI monitor operation patterns in Java function names. JNI monitor
/// operations include MonitorEnter and MonitorExit.
///
/// # Invariants
/// - Returns true for MonitorEnter or MonitorExit patterns.
/// - Returns false for non-JNI monitor operation patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for JNI monitor operations.
///
/// # Returns
/// `true` if the function is identified as JNI monitor operations, `false` otherwise.
pub fn is_jni_monitor_operation(function_name: &str) -> bool {
    is_jni_call(function_name)
        && (function_name.contains("MonitorEnter") || function_name.contains("MonitorExit"))
}

/// Detects JNI-related patterns from a function name.
///
/// # Objective
/// Collect all JNI-related semantic patterns from a function name.
/// This provides a convenient way to get all JNI patterns in one call.
///
/// # Arguments
/// * `function_name` - The function name to analyze for JNI patterns.
///
/// # Returns
/// A Vec of `JavaSemanticPattern` containing detected JNI patterns.
pub fn detect_jni_patterns(function_name: &str) -> Vec<JavaSemanticPattern> {
    let mut patterns = Vec::new();

    if is_jni_native_method(function_name) {
        patterns.push(JavaSemanticPattern::JNICall);
        patterns.push(JavaSemanticPattern::JNINativeRegistration);
    }
    if is_jni_object_creation(function_name) {
        patterns.push(JavaSemanticPattern::JNIObjectCreation);
    }
    if is_jni_class_loading(function_name) {
        patterns.push(JavaSemanticPattern::JNIClassLoading);
    }
    if is_jni_method_resolution(function_name) {
        patterns.push(JavaSemanticPattern::JNIMethodResolution);
    }
    if is_jni_field_access(function_name) {
        patterns.push(JavaSemanticPattern::JNIFieldAccess);
    }
    if is_jni_string_operation(function_name) {
        patterns.push(JavaSemanticPattern::JNIStringOperation);
    }
    if is_jni_array_operation(function_name) {
        patterns.push(JavaSemanticPattern::JNIArrayOperation);
    }
    if is_jni_monitor_operation(function_name) {
        patterns.push(JavaSemanticPattern::JNIMonitorOperation);
    }

    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jni_native_method_detection() {
        // Java_ prefixed function
        assert!(
            is_jni_native_method("Java_com_example_MyClass_nativeMethod"),
            "Java_ prefixed function must be detected as JNI native method"
        );
        // Non-JNI native method
        assert!(
            !is_jni_native_method("MyClass.myMethod"),
            "Non-JNI native method must not be detected"
        );
    }

    #[test]
    fn test_jni_call_detection() {
        // Java_ prefixed function
        assert!(
            is_jni_call("Java_com_example_MyClass_nativeMethod"),
            "Java_ prefixed function must be detected as JNI call"
        );
        // JNI prefixed function
        assert!(
            is_jni_call("JNI_OnLoad"),
            "JNI prefixed function must be detected as JNI call"
        );
        // (*env)-> function
        assert!(
            is_jni_call("(*env)->FindClass"),
            "(*env)-> function must be detected as JNI call"
        );
        // JNIEnv function
        assert!(
            is_jni_call("JNIEnv"),
            "JNIEnv function must be detected as JNI call"
        );
        // Non-JNI call
        assert!(
            !is_jni_call("MyClass.myMethod"),
            "Non-JNI call must not be detected"
        );
    }

    #[test]
    fn test_jni_object_creation_detection() {
        // NewObject
        assert!(
            is_jni_object_creation("(*env)->NewObject"),
            "NewObject must be detected as JNI object creation"
        );
        // NewString
        assert!(
            is_jni_object_creation("(*env)->NewString"),
            "NewString must be detected as JNI object creation"
        );
        // NewObjectArray
        assert!(
            is_jni_object_creation("(*env)->NewObjectArray"),
            "NewObjectArray must be detected as JNI object creation"
        );
        // Non-JNI object creation
        assert!(
            !is_jni_object_creation("(*env)->FindClass"),
            "Non-JNI object creation must not be detected"
        );
    }

    #[test]
    fn test_jni_class_loading_detection() {
        // FindClass
        assert!(
            is_jni_class_loading("(*env)->FindClass"),
            "FindClass must be detected as JNI class loading"
        );
        // Non-JNI class loading
        assert!(
            !is_jni_class_loading("(*env)->NewObject"),
            "Non-JNI class loading must not be detected"
        );
    }

    #[test]
    fn test_jni_method_resolution_detection() {
        // GetMethodID
        assert!(
            is_jni_method_resolution("(*env)->GetMethodID"),
            "GetMethodID must be detected as JNI method resolution"
        );
        // GetStaticMethodID
        assert!(
            is_jni_method_resolution("(*env)->GetStaticMethodID"),
            "GetStaticMethodID must be detected as JNI method resolution"
        );
        // Non-JNI method resolution
        assert!(
            !is_jni_method_resolution("(*env)->NewObject"),
            "Non-JNI method resolution must not be detected"
        );
    }

    #[test]
    fn test_jni_field_access_detection() {
        // GetFieldID
        assert!(
            is_jni_field_access("(*env)->GetFieldID"),
            "GetFieldID must be detected as JNI field access"
        );
        // GetStaticFieldID
        assert!(
            is_jni_field_access("(*env)->GetStaticFieldID"),
            "GetStaticFieldID must be detected as JNI field access"
        );
        // Non-JNI field access
        assert!(
            !is_jni_field_access("(*env)->NewObject"),
            "Non-JNI field access must not be detected"
        );
    }

    #[test]
    fn test_jni_string_operation_detection() {
        // NewStringUTF
        assert!(
            is_jni_string_operation("(*env)->NewStringUTF"),
            "NewStringUTF must be detected as JNI string operation"
        );
        // GetStringUTFChars
        assert!(
            is_jni_string_operation("(*env)->GetStringUTFChars"),
            "GetStringUTFChars must be detected as JNI string operation"
        );
        // Non-JNI string operation
        assert!(
            !is_jni_string_operation("(*env)->NewObject"),
            "Non-JNI string operation must not be detected"
        );
    }

    #[test]
    fn test_jni_array_operation_detection() {
        // NewIntArray
        assert!(
            is_jni_array_operation("(*env)->NewIntArray"),
            "NewIntArray must be detected as JNI array operation"
        );
        // GetArrayElements
        assert!(
            is_jni_array_operation("(*env)->GetArrayElements"),
            "GetArrayElements must be detected as JNI array operation"
        );
        // Non-JNI array operation
        assert!(
            !is_jni_array_operation("(*env)->NewObject"),
            "Non-JNI array operation must not be detected"
        );
    }

    #[test]
    fn test_jni_monitor_operation_detection() {
        // MonitorEnter
        assert!(
            is_jni_monitor_operation("(*env)->MonitorEnter"),
            "MonitorEnter must be detected as JNI monitor operation"
        );
        // MonitorExit
        assert!(
            is_jni_monitor_operation("(*env)->MonitorExit"),
            "MonitorExit must be detected as JNI monitor operation"
        );
        // Non-JNI monitor operation
        assert!(
            !is_jni_monitor_operation("(*env)->NewObject"),
            "Non-JNI monitor operation must not be detected"
        );
    }

    #[test]
    fn test_detect_jni_patterns() {
        // JNI native method
        let patterns = detect_jni_patterns("Java_com_example_MyClass_nativeMethod");
        assert!(
            patterns.contains(&JavaSemanticPattern::JNICall),
            "JNICall must be detected"
        );
        assert!(
            patterns.contains(&JavaSemanticPattern::JNINativeRegistration),
            "JNINativeRegistration must be detected"
        );

        // JNI object creation
        let patterns = detect_jni_patterns("(*env)->NewObject");
        assert!(
            patterns.contains(&JavaSemanticPattern::JNIObjectCreation),
            "JNIObjectCreation must be detected"
        );

        // JNI class loading
        let patterns = detect_jni_patterns("(*env)->FindClass");
        assert!(
            patterns.contains(&JavaSemanticPattern::JNIClassLoading),
            "JNIClassLoading must be detected"
        );
    }
}
