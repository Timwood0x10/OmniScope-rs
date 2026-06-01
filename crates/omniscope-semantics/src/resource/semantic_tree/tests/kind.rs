//! Tests for SemanticKind classification and properties.

use super::super::*;

// ── Python semantic detection tests ──
/// Objective: Verify that Python reference counting patterns are correctly detected.
///
/// Invariants:
/// - Py_INCREF and Py_XINCREF should be detected as PythonRefcountInc
/// - Py_DECREF and Py_XDECREF should be detected as PythonRefcountDec
#[test]
fn test_semantic_kind_from_function_name_python_refcount() {
    // Test Python reference counting patterns
    assert_eq!(
        SemanticKind::from_function_name("Py_INCREF"),
        SemanticKind::PythonRefcountInc,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("Py_XINCREF"),
        SemanticKind::PythonRefcountInc,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("Py_DECREF"),
        SemanticKind::PythonRefcountDec,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("Py_XDECREF"),
        SemanticKind::PythonRefcountDec,
        "Expected values to be equal"
    );
}

/// Objective: Verify that Python borrowed and owned reference patterns are correctly detected.
///
/// Invariants:
/// - PyList_GetItem, PyTuple_GetItem, PyDict_GetItem should be detected as PythonBorrowedRef
/// - PyBytes_FromString, PyLong_FromLong, PyObject_Call should be detected as PythonOwnedRef
#[test]
fn test_semantic_kind_from_function_name_python_references() {
    // Test Python borrowed and owned references
    assert_eq!(
        SemanticKind::from_function_name("PyList_GetItem"),
        SemanticKind::PythonBorrowedRef,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("PyTuple_GetItem"),
        SemanticKind::PythonBorrowedRef,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("PyDict_GetItem"),
        SemanticKind::PythonBorrowedRef,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("PyBytes_FromString"),
        SemanticKind::PythonOwnedRef,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("PyLong_FromLong"),
        SemanticKind::PythonOwnedRef,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("PyObject_Call"),
        SemanticKind::PythonOwnedRef,
        "Expected values to be equal"
    );
}

/// Objective: Verify that Python GIL protection patterns are correctly detected.
///
/// Invariants:
/// - PyGILState_Ensure and PyGILState_Release should be detected as PythonGilProtected
#[test]
fn test_semantic_kind_from_function_name_python_gil() {
    // Test Python GIL protection patterns
    assert_eq!(
        SemanticKind::from_function_name("PyGILState_Ensure"),
        SemanticKind::PythonGilProtected,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("PyGILState_Release"),
        SemanticKind::PythonGilProtected,
        "Expected values to be equal"
    );
}

// ── Go semantic detection tests ──
/// Objective: Verify that Go defer and CGO patterns are correctly detected.
///
/// Invariants:
/// - defer C.free(ptr) should be detected as GoDeferCleanup
/// - runtime.SetFinalizer should be detected as GoFinalizer
/// - _Cgo_malloc and _cgo_free should be detected as GoCgoWrapper
/// - runtime.mallocgc and runtime.newobject should be detected as GoRuntimeAlloc
#[test]
fn test_semantic_kind_from_function_name_go_patterns() {
    // Test Go defer and CGO patterns
    assert_eq!(
        SemanticKind::from_function_name("defer C.free(ptr)"),
        SemanticKind::GoDeferCleanup,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("runtime.SetFinalizer"),
        SemanticKind::GoFinalizer,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("_Cgo_malloc"),
        SemanticKind::GoCgoWrapper,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("_cgo_free"),
        SemanticKind::GoCgoWrapper,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("runtime.mallocgc"),
        SemanticKind::GoRuntimeAlloc,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("runtime.newobject"),
        SemanticKind::GoRuntimeAlloc,
        "Expected values to be equal"
    );
}

// ── C++ semantic detection tests ──
/// Objective: Verify that C++ smart pointer patterns are correctly detected.
///
/// Invariants:
/// - std::unique_ptr and make_unique should be detected as CppUniquePtr
/// - std::shared_ptr and make_shared should be detected as CppSharedPtr
#[test]
fn test_semantic_kind_from_function_name_cpp_smart_pointers() {
    // Test C++ smart pointer patterns
    assert_eq!(
        SemanticKind::from_function_name("std::unique_ptr<int>"),
        SemanticKind::CppUniquePtr,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("make_unique<int>"),
        SemanticKind::CppUniquePtr,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("std::shared_ptr<int>"),
        SemanticKind::CppSharedPtr,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("make_shared<int>"),
        SemanticKind::CppSharedPtr,
        "Expected values to be equal"
    );
}

/// Objective: Verify that C++ destructor patterns are correctly detected.
///
/// Invariants:
/// - ~MyClass and MyClass::~MyClass should be detected as CppDestructor
#[test]
fn test_semantic_kind_from_function_name_cpp_destructor() {
    // Test C++ destructor patterns
    assert_eq!(
        SemanticKind::from_function_name("~MyClass"),
        SemanticKind::CppDestructor,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("MyClass::~MyClass"),
        SemanticKind::CppDestructor,
        "Expected values to be equal"
    );
}

/// Objective: Verify that C++ exception handling patterns are correctly detected.
///
/// Invariants:
/// - __cxa_throw, __cxa_begin_catch, __cxa_end_catch, __cxa_allocate_exception should be detected as CppExceptionPath
#[test]
fn test_semantic_kind_from_function_name_cpp_exception() {
    // Test C++ exception handling patterns
    assert_eq!(
        SemanticKind::from_function_name("__cxa_throw"),
        SemanticKind::CppExceptionPath,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("__cxa_begin_catch"),
        SemanticKind::CppExceptionPath,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("__cxa_end_catch"),
        SemanticKind::CppExceptionPath,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("__cxa_allocate_exception"),
        SemanticKind::CppExceptionPath,
        "Expected values to be equal"
    );
}

// ── C# semantic detection tests ──
/// Objective: Verify that C# SafeHandle and P/Invoke patterns are correctly detected.
///
/// Invariants:
/// - SafeHandle, ReleaseHandle, CriticalHandle should be detected as CsharpSafeHandle
/// - Finalize should be detected as CsharpFinalizer
/// - DllImport, Marshal.AllocHGlobal, Marshal.FreeHGlobal should be detected as CsharpPinvokeMarshal
#[test]
fn test_semantic_kind_from_function_name_csharp_patterns() {
    // Test C# SafeHandle and P/Invoke patterns
    assert_eq!(
        SemanticKind::from_function_name("SafeHandle"),
        SemanticKind::CsharpSafeHandle,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("ReleaseHandle"),
        SemanticKind::CsharpSafeHandle,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("CriticalHandle"),
        SemanticKind::CsharpSafeHandle,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("Finalize"),
        SemanticKind::CsharpFinalizer,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("DllImport"),
        SemanticKind::CsharpPinvokeMarshal,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("Marshal.AllocHGlobal"),
        SemanticKind::CsharpPinvokeMarshal,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("Marshal.FreeHGlobal"),
        SemanticKind::CsharpPinvokeMarshal,
        "Expected values to be equal"
    );
}

// ── Java JNI semantic detection tests ──
/// Objective: Verify that Java JNI reference patterns are correctly detected.
///
/// Invariants:
/// - NewLocalRef, DeleteLocalRef should be detected as JavaLocalRef
/// - NewGlobalRef, DeleteGlobalRef should be detected as JavaGlobalRef
/// - NewWeakGlobalRef, DeleteWeakGlobalRef should be detected as JavaWeakRef
#[test]
fn test_semantic_kind_from_function_name_java_jni() {
    // Test Java JNI reference patterns
    assert_eq!(
        SemanticKind::from_function_name("NewLocalRef"),
        SemanticKind::JavaLocalRef,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("DeleteLocalRef"),
        SemanticKind::JavaLocalRef,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("NewGlobalRef"),
        SemanticKind::JavaGlobalRef,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("DeleteGlobalRef"),
        SemanticKind::JavaGlobalRef,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("NewWeakGlobalRef"),
        SemanticKind::JavaWeakRef,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name("DeleteWeakGlobalRef"),
        SemanticKind::JavaWeakRef,
        "Expected values to be equal"
    );
}

// ── Safety score tests ──
/// Objective: Verify that semantic kinds have reasonable safety scores.
///
/// Invariants:
/// - RAII drop should have safety score >= 0.9
/// - C++ unique_ptr and shared_ptr should have safety score >= 0.8
/// - C# SafeHandle should have safety score >= 0.8
/// - Python borrowed ref should have safety score >= 0.7
/// - Python refcount inc should have safety score <= 0.4
/// - Java weak ref should have safety score <= 0.4
#[test]
fn test_semantic_kind_safety_scores() {
    // Test that safety scores are reasonable
    assert!(
        SemanticKind::RaiiDropRelease.safety_score() >= 0.9,
        "RAII drop should be very safe"
    );
    assert!(
        SemanticKind::CppUniquePtr.safety_score() >= 0.8,
        "C++ unique_ptr should be safe"
    );
    assert!(
        SemanticKind::CppSharedPtr.safety_score() >= 0.8,
        "C++ shared_ptr should be safe"
    );
    assert!(
        SemanticKind::CsharpSafeHandle.safety_score() >= 0.8,
        "C# SafeHandle should be safe"
    );
    assert!(
        SemanticKind::PythonBorrowedRef.safety_score() >= 0.7,
        "Python borrowed ref should be moderately safe"
    );
    assert!(
        SemanticKind::PythonRefcountInc.safety_score() <= 0.4,
        "Python refcount inc should be higher risk"
    );
    assert!(
        SemanticKind::JavaWeakRef.safety_score() <= 0.4,
        "Java weak ref should be higher risk"
    );
}

// ── Cleanup requirement tests ──
/// Objective: Verify that cleanup requirements are correctly detected.
///
/// Invariants:
/// - PythonRefcountInc, PythonOwnedRef, CppUniquePtr, CppSharedPtr, CsharpSafeHandle, JavaGlobalRef should require cleanup
/// - PythonBorrowedRef, JavaLocalRef should not require cleanup
#[test]
fn test_semantic_kind_requires_cleanup() {
    // Test cleanup requirement detection
    assert!(
        SemanticKind::PythonRefcountInc.requires_cleanup(),
        "Python refcount inc should require cleanup"
    );
    assert!(
        SemanticKind::PythonOwnedRef.requires_cleanup(),
        "Python owned ref should require cleanup"
    );
    assert!(
        SemanticKind::CppUniquePtr.requires_cleanup(),
        "C++ unique_ptr should require cleanup"
    );
    assert!(
        SemanticKind::CppSharedPtr.requires_cleanup(),
        "C++ shared_ptr should require cleanup"
    );
    assert!(
        SemanticKind::CsharpSafeHandle.requires_cleanup(),
        "C# SafeHandle should require cleanup"
    );
    assert!(
        SemanticKind::JavaGlobalRef.requires_cleanup(),
        "Java global ref should require cleanup"
    );
    assert!(
        !SemanticKind::PythonBorrowedRef.requires_cleanup(),
        "Python borrowed ref should not require cleanup"
    );
    assert!(
        !SemanticKind::JavaLocalRef.requires_cleanup(),
        "Java local ref should not require cleanup (auto-freed)"
    );
}

// ── Borrowed/temporary reference tests ──
/// Objective: Verify that borrowed/temporary references are correctly detected.
///
/// Invariants:
/// - PythonBorrowedRef, PythonGilProtected, JavaLocalRef, FromParameter should be temporary
/// - CppUniquePtr, JavaGlobalRef should not be temporary
#[test]
fn test_semantic_kind_is_borrowed_or_temporary() {
    // Test borrowed/temporary reference detection
    assert!(
        SemanticKind::PythonBorrowedRef.is_borrowed_or_temporary(),
        "Python borrowed ref should be temporary"
    );
    assert!(
        SemanticKind::PythonGilProtected.is_borrowed_or_temporary(),
        "Python GIL protected should be temporary"
    );
    assert!(
        SemanticKind::JavaLocalRef.is_borrowed_or_temporary(),
        "Java local ref should be temporary"
    );
    assert!(
        SemanticKind::FromParameter.is_borrowed_or_temporary(),
        "From parameter should be temporary"
    );
    assert!(
        !SemanticKind::CppUniquePtr.is_borrowed_or_temporary(),
        "C++ unique_ptr should not be temporary"
    );
    assert!(
        !SemanticKind::JavaGlobalRef.is_borrowed_or_temporary(),
        "Java global ref should not be temporary"
    );
}

// ── Suppression rule tests ──
/// Objective: Verify that write_to_immutable suppression rules are correctly applied.
///
/// Invariants:
/// - MutableParam, InteriorMutability, PythonGilProtected, CppUniquePtr, CppSharedPtr, CsharpSafeHandle should suppress write_to_immutable
#[test]
fn test_semantic_kind_suppresses_write_to_immutable() {
    // Test write_to_immutable suppression rules
    assert!(
        SemanticKind::MutableParam.suppresses_write_to_immutable(),
        "MutableParam should suppress write_to_immutable"
    );
    assert!(
        SemanticKind::InteriorMutability.suppresses_write_to_immutable(),
        "InteriorMutability should suppress write_to_immutable"
    );
    assert!(
        SemanticKind::PythonGilProtected.suppresses_write_to_immutable(),
        "Python GIL protected should suppress write_to_immutable"
    );
    assert!(
        SemanticKind::CppUniquePtr.suppresses_write_to_immutable(),
        "C++ unique_ptr should suppress write_to_immutable"
    );
    assert!(
        SemanticKind::CppSharedPtr.suppresses_write_to_immutable(),
        "C++ shared_ptr should suppress write_to_immutable"
    );
    assert!(
        SemanticKind::CsharpSafeHandle.suppresses_write_to_immutable(),
        "C# SafeHandle should suppress write_to_immutable"
    );
}

/// Objective: Verify that borrow_escape suppression rules are correctly applied.
///
/// Invariants:
/// - HeapProvenance, GlobalProvenance, FromParameter, PythonBorrowedRef, PythonGilProtected, GoDeferCleanup, CppUniquePtr, CppSharedPtr, JavaLocalRef should suppress borrow_escape
#[test]
fn test_semantic_kind_suppresses_borrow_escape() {
    // Test borrow_escape suppression rules
    assert!(
        SemanticKind::HeapProvenance.suppresses_borrow_escape(),
        "HeapProvenance should suppress borrow_escape"
    );
    assert!(
        SemanticKind::GlobalProvenance.suppresses_borrow_escape(),
        "GlobalProvenance should suppress borrow_escape"
    );
    assert!(
        SemanticKind::FromParameter.suppresses_borrow_escape(),
        "FromParameter should suppress borrow_escape"
    );
    assert!(
        SemanticKind::PythonBorrowedRef.suppresses_borrow_escape(),
        "Python borrowed ref should suppress borrow_escape"
    );
    assert!(
        SemanticKind::PythonGilProtected.suppresses_borrow_escape(),
        "Python GIL protected should suppress borrow_escape"
    );
    assert!(
        SemanticKind::GoDeferCleanup.suppresses_borrow_escape(),
        "Go defer cleanup should suppress borrow_escape"
    );
    assert!(
        SemanticKind::CppUniquePtr.suppresses_borrow_escape(),
        "C++ unique_ptr should suppress borrow_escape"
    );
    assert!(
        SemanticKind::CppSharedPtr.suppresses_borrow_escape(),
        "C++ shared_ptr should suppress borrow_escape"
    );
    assert!(
        SemanticKind::JavaLocalRef.suppresses_borrow_escape(),
        "Java local ref should suppress borrow_escape"
    );
}

/// Objective: Verify that use_after_free suppression rules are correctly applied.
///
/// Invariants:
/// - RaiiDropRelease, PythonRefcountInc, PythonOwnedRef, GoDeferCleanup, CppUniquePtr, CppSharedPtr, CsharpSafeHandle, JavaGlobalRef should suppress use_after_free
#[test]
fn test_semantic_kind_suppresses_use_after_free() {
    // Test use_after_free suppression rules
    assert!(
        SemanticKind::RaiiDropRelease.suppresses_use_after_free(),
        "RAII drop should suppress use_after_free"
    );
    assert!(
        SemanticKind::PythonRefcountInc.suppresses_use_after_free(),
        "Python refcount inc should suppress use_after_free"
    );
    assert!(
        SemanticKind::PythonOwnedRef.suppresses_use_after_free(),
        "Python owned ref should suppress use_after_free"
    );
    assert!(
        SemanticKind::GoDeferCleanup.suppresses_use_after_free(),
        "Go defer cleanup should suppress use_after_free"
    );
    assert!(
        SemanticKind::CppUniquePtr.suppresses_use_after_free(),
        "C++ unique_ptr should suppress use_after_free"
    );
    assert!(
        SemanticKind::CppSharedPtr.suppresses_use_after_free(),
        "C++ shared_ptr should suppress use_after_free"
    );
    assert!(
        SemanticKind::CsharpSafeHandle.suppresses_use_after_free(),
        "C# SafeHandle should suppress use_after_free"
    );
    assert!(
        SemanticKind::JavaGlobalRef.suppresses_use_after_free(),
        "Java global ref should suppress use_after_free"
    );
}

/// Objective: Verify that cross_language_free suppression rules are correctly applied.
///
/// Invariants:
/// - IntoRawTransfer, FileOperation, NetworkOperation, ProcessOperation, LibraryRelease, PythonRefcountDec, PythonOwnedRef, GoDeferCleanup, CppUniquePtr, CppSharedPtr, CsharpSafeHandle, JavaGlobalRef should suppress cross_language_free
#[test]
fn test_semantic_kind_suppresses_cross_language_free() {
    // Test cross_language_free suppression rules
    assert!(
        SemanticKind::IntoRawTransfer.suppresses_cross_language_free(),
        "IntoRawTransfer should suppress cross_language_free"
    );
    assert!(
        SemanticKind::FileOperation.suppresses_cross_language_free(),
        "FileOperation should suppress cross_language_free"
    );
    assert!(
        SemanticKind::NetworkOperation.suppresses_cross_language_free(),
        "NetworkOperation should suppress cross_language_free"
    );
    assert!(
        SemanticKind::ProcessOperation.suppresses_cross_language_free(),
        "ProcessOperation should suppress cross_language_free"
    );
    assert!(
        SemanticKind::LibraryRelease.suppresses_cross_language_free(),
        "LibraryRelease should suppress cross_language_free"
    );
    assert!(
        SemanticKind::PythonRefcountDec.suppresses_cross_language_free(),
        "Python refcount dec should suppress cross_language_free"
    );
    assert!(
        SemanticKind::PythonOwnedRef.suppresses_cross_language_free(),
        "Python owned ref should suppress cross_language_free"
    );
    assert!(
        SemanticKind::GoDeferCleanup.suppresses_cross_language_free(),
        "Go defer cleanup should suppress cross_language_free"
    );
    assert!(
        SemanticKind::CppUniquePtr.suppresses_cross_language_free(),
        "C++ unique_ptr should suppress cross_language_free"
    );
    assert!(
        SemanticKind::CppSharedPtr.suppresses_cross_language_free(),
        "C++ shared_ptr should suppress cross_language_free"
    );
    assert!(
        SemanticKind::CsharpSafeHandle.suppresses_cross_language_free(),
        "C# SafeHandle should suppress cross_language_free"
    );
    assert!(
        SemanticKind::JavaGlobalRef.suppresses_cross_language_free(),
        "Java global ref should suppress cross_language_free"
    );
}

// ── Unknown function detection test ──
/// Objective: Verify that unknown functions are correctly detected as Unknown.
///
/// Invariants:
/// - Random function names and empty strings should return Unknown
#[test]
fn test_semantic_kind_from_function_name_unknown() {
    // Test that unknown functions return Unknown
    assert_eq!(
        SemanticKind::from_function_name("some_random_function"),
        SemanticKind::Unknown,
        "Expected values to be equal"
    );
    assert_eq!(
        SemanticKind::from_function_name(""),
        SemanticKind::Unknown,
        "Expected values to be equal"
    );
}
