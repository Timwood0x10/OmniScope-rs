//! Tests for the semantic tree module.

use super::*;
use proptest::prelude::*;

/// Objective: Verify that getenv is correctly classified as EnvironmentConfig syscall.
///
/// Invariants:
/// - getenv function name should be classified as EnvironmentConfig
#[test]
fn test_syscall_classify_getenv() {
    assert_eq!(
        SyscallSemantic::classify("getenv"),
        SyscallSemantic::EnvironmentConfig
    );
}

/// Objective: Verify that strlen is correctly classified as DataQuery syscall.
///
/// Invariants:
/// - strlen function name should be classified as DataQuery
#[test]
fn test_syscall_classify_strlen() {
    assert_eq!(
        SyscallSemantic::classify("strlen"),
        SyscallSemantic::DataQuery
    );
}

/// Objective: Verify that malloc is correctly classified as MemoryManagement syscall.
///
/// Invariants:
/// - malloc function name should be classified as MemoryManagement
#[test]
fn test_syscall_classify_malloc() {
    assert_eq!(
        SyscallSemantic::classify("malloc"),
        SyscallSemantic::MemoryManagement
    );
}

/// Objective: Verify that free is correctly classified as MemoryManagement syscall.
///
/// Invariants:
/// - free function name should be classified as MemoryManagement
#[test]
fn test_syscall_classify_free() {
    assert_eq!(
        SyscallSemantic::classify("free"),
        SyscallSemantic::MemoryManagement
    );
}

/// Objective: Verify that highway functions are correctly classified as ComputeAccelerated syscall.
///
/// Invariants:
/// - highway_index_of_char function name should be classified as ComputeAccelerated
#[test]
fn test_syscall_classify_highway() {
    assert_eq!(
        SyscallSemantic::classify("highway_index_of_char"),
        SyscallSemantic::ComputeAccelerated
    );
}

/// Objective: Verify that Bun dispatch functions are correctly classified as InternalDispatch syscall.
///
/// Invariants:
/// - __bun_dispatch__OutputSink__Sys__quiet_writer_write_all function name should be classified as InternalDispatch
#[test]
fn test_syscall_classify_bun_dispatch() {
    assert_eq!(
        SyscallSemantic::classify("__bun_dispatch__OutputSink__Sys__quiet_writer_write_all"),
        SyscallSemantic::InternalDispatch
    );
}

/// Objective: Verify that Bun string functions are correctly classified as InternalDispatch syscall.
///
/// Invariants:
/// - BunString__fromBytes function name should be classified as InternalDispatch
#[test]
fn test_syscall_classify_bun_string() {
    assert_eq!(
        SyscallSemantic::classify("BunString__fromBytes"),
        SyscallSemantic::InternalDispatch
    );
}

/// Objective: Verify that WTF destroy functions are correctly classified as InternalDispatch syscall.
///
/// Invariants:
/// - Bun__WTFStringImpl__destroy function name should be classified as InternalDispatch
#[test]
fn test_syscall_classify_wtf_destroy() {
    assert_eq!(
        SyscallSemantic::classify("Bun__WTFStringImpl__destroy"),
        SyscallSemantic::InternalDispatch
    );
}

/// Objective: Verify that Rust mangled names for interior mutability types are correctly detected.
///
/// Invariants:
/// - Mangled name for std::sync::mutex::Mutex should be detected as InteriorMutability
#[test]
fn test_type_semantic_interior_mutability() {
    // Real mangled name from bun_core: std::sync::mutex::Mutex
    let name = "_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std3sys3pal4unix4sync5mutexNtB2_5Mutex4lock";
    assert_eq!(
        TypeSemantic::from_mangled_name(name),
        TypeSemantic::InteriorMutability
    );
}

/// Objective: Verify that Rust mangled names for Once types are correctly detected.
///
/// Invariants:
/// - Mangled name for OnceBox should be detected as Once
#[test]
fn test_type_semantic_once() {
    let name = "_RINvMNtNtNtCsg1bLsEOY8ZL_3std3sys4sync8once_boxINtB3_7OnceBox";
    assert_eq!(TypeSemantic::from_mangled_name(name), TypeSemantic::Once);
}

/// Objective: Verify that Rust mangled names for drop_in_place are correctly detected.
///
/// Invariants:
/// - Mangled name for drop_in_place should be detected as Drop
#[test]
fn test_type_semantic_drop() {
    let name = "_RINvNtCsgXhsEb1m4tm_4core3ptr13drop_in_place";
    assert_eq!(TypeSemantic::from_mangled_name(name), TypeSemantic::Drop);
}

/// Objective: Verify that non-Rust mangled names are correctly detected as Unknown.
///
/// Invariants:
/// - Non-Rust mangled names like "Bun__atexit" should be detected as Unknown
#[test]
fn test_type_semantic_non_rust() {
    assert_eq!(
        TypeSemantic::from_mangled_name("Bun__atexit"),
        TypeSemantic::Unknown
    );
}

/// Objective: Verify that data query functions have high safety scores.
///
/// Invariants:
/// - strlen call should have safety score > 0.8
#[test]
fn test_safety_score_data_query() {
    let node = SemanticNode::for_ffi_call(
        "some_rust_func",
        "strlen",
        PointerProvenance::Heap,
        TypeSemantic::Ordinary,
    );
    // Data query should have high safety score
    assert!(
        node.safety_score > 0.8,
        "strlen call should be safe: {}",
        node.safety_score
    );
}

/// Objective: Verify that memory management functions have lower safety scores.
///
/// Invariants:
/// - free call should have safety score < 0.6
#[test]
fn test_safety_score_memory_management() {
    let node = SemanticNode::for_ffi_call(
        "some_rust_func",
        "free",
        PointerProvenance::Heap,
        TypeSemantic::Ordinary,
    );
    // free() should have lower safety score than safe patterns
    assert!(
        node.safety_score < 0.6,
        "free call should be concerning: {}",
        node.safety_score
    );
}

/// Objective: Verify that internal dispatch functions have moderate-high safety scores.
///
/// Invariants:
/// - BunString__fromBytes call should have safety score > 0.6
#[test]
fn test_safety_score_internal_dispatch() {
    let node = SemanticNode::for_ffi_call(
        "some_rust_func",
        "BunString__fromBytes",
        PointerProvenance::Heap,
        TypeSemantic::Ordinary,
    );
    // Internal dispatch should have moderate-high safety score
    assert!(
        node.safety_score > 0.6,
        "internal dispatch should be moderate: {}",
        node.safety_score
    );
}

/// Objective: Verify that semantic tree is correctly built from FFI calls.
///
/// Invariants:
/// - Tree should contain 4 nodes for 4 FFI calls
/// - Safe pattern count should be 2 (getenv + strlen)
/// - Genuine concern count should be 0 (free score=0.54 >= 0.5)
#[test]
fn test_semantic_tree_build() {
    let ffi_calls = vec![
        ("rust_func".to_string(), "getenv".to_string(), true),
        ("rust_func".to_string(), "strlen".to_string(), true),
        ("rust_func".to_string(), "free".to_string(), true),
        (
            "rust_func".to_string(),
            "BunString__fromBytes".to_string(),
            true,
        ),
    ];

    let tree = build_semantic_tree(&ffi_calls);
    assert_eq!(tree.nodes().len(), 4);
    assert_eq!(tree.safe_pattern_count(), 2); // getenv + strlen
    assert_eq!(tree.genuine_concern_count(), 0); // free score=0.54 >= 0.5
}

/// Objective: Verify that memory ownership filtering correctly identifies memory management nodes.
///
/// Invariants:
/// - Memory ownership nodes should include malloc and free
/// - All memory ownership nodes should have MemoryManagement syscall semantic
#[test]
fn test_memory_ownership_filtering() {
    let ffi_calls = vec![
        ("rust_func".to_string(), "malloc".to_string(), true),
        ("rust_func".to_string(), "strlen".to_string(), true),
        ("rust_func".to_string(), "free".to_string(), true),
        ("rust_func".to_string(), "getenv".to_string(), true),
    ];

    let tree = build_semantic_tree(&ffi_calls);
    let mem_nodes = tree.memory_ownership_nodes();
    assert_eq!(mem_nodes.len(), 2); // malloc + free
    assert!(mem_nodes
        .iter()
        .all(|n| n.syscall_semantic == SyscallSemantic::MemoryManagement));
}

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
        SemanticKind::PythonRefcountInc
    );
    assert_eq!(
        SemanticKind::from_function_name("Py_XINCREF"),
        SemanticKind::PythonRefcountInc
    );
    assert_eq!(
        SemanticKind::from_function_name("Py_DECREF"),
        SemanticKind::PythonRefcountDec
    );
    assert_eq!(
        SemanticKind::from_function_name("Py_XDECREF"),
        SemanticKind::PythonRefcountDec
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
        SemanticKind::PythonBorrowedRef
    );
    assert_eq!(
        SemanticKind::from_function_name("PyTuple_GetItem"),
        SemanticKind::PythonBorrowedRef
    );
    assert_eq!(
        SemanticKind::from_function_name("PyDict_GetItem"),
        SemanticKind::PythonBorrowedRef
    );
    assert_eq!(
        SemanticKind::from_function_name("PyBytes_FromString"),
        SemanticKind::PythonOwnedRef
    );
    assert_eq!(
        SemanticKind::from_function_name("PyLong_FromLong"),
        SemanticKind::PythonOwnedRef
    );
    assert_eq!(
        SemanticKind::from_function_name("PyObject_Call"),
        SemanticKind::PythonOwnedRef
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
        SemanticKind::PythonGilProtected
    );
    assert_eq!(
        SemanticKind::from_function_name("PyGILState_Release"),
        SemanticKind::PythonGilProtected
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
        SemanticKind::GoDeferCleanup
    );
    assert_eq!(
        SemanticKind::from_function_name("runtime.SetFinalizer"),
        SemanticKind::GoFinalizer
    );
    assert_eq!(
        SemanticKind::from_function_name("_Cgo_malloc"),
        SemanticKind::GoCgoWrapper
    );
    assert_eq!(
        SemanticKind::from_function_name("_cgo_free"),
        SemanticKind::GoCgoWrapper
    );
    assert_eq!(
        SemanticKind::from_function_name("runtime.mallocgc"),
        SemanticKind::GoRuntimeAlloc
    );
    assert_eq!(
        SemanticKind::from_function_name("runtime.newobject"),
        SemanticKind::GoRuntimeAlloc
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
        SemanticKind::CppUniquePtr
    );
    assert_eq!(
        SemanticKind::from_function_name("make_unique<int>"),
        SemanticKind::CppUniquePtr
    );
    assert_eq!(
        SemanticKind::from_function_name("std::shared_ptr<int>"),
        SemanticKind::CppSharedPtr
    );
    assert_eq!(
        SemanticKind::from_function_name("make_shared<int>"),
        SemanticKind::CppSharedPtr
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
        SemanticKind::CppDestructor
    );
    assert_eq!(
        SemanticKind::from_function_name("MyClass::~MyClass"),
        SemanticKind::CppDestructor
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
        SemanticKind::CppExceptionPath
    );
    assert_eq!(
        SemanticKind::from_function_name("__cxa_begin_catch"),
        SemanticKind::CppExceptionPath
    );
    assert_eq!(
        SemanticKind::from_function_name("__cxa_end_catch"),
        SemanticKind::CppExceptionPath
    );
    assert_eq!(
        SemanticKind::from_function_name("__cxa_allocate_exception"),
        SemanticKind::CppExceptionPath
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
        SemanticKind::CsharpSafeHandle
    );
    assert_eq!(
        SemanticKind::from_function_name("ReleaseHandle"),
        SemanticKind::CsharpSafeHandle
    );
    assert_eq!(
        SemanticKind::from_function_name("CriticalHandle"),
        SemanticKind::CsharpSafeHandle
    );
    assert_eq!(
        SemanticKind::from_function_name("Finalize"),
        SemanticKind::CsharpFinalizer
    );
    assert_eq!(
        SemanticKind::from_function_name("DllImport"),
        SemanticKind::CsharpPinvokeMarshal
    );
    assert_eq!(
        SemanticKind::from_function_name("Marshal.AllocHGlobal"),
        SemanticKind::CsharpPinvokeMarshal
    );
    assert_eq!(
        SemanticKind::from_function_name("Marshal.FreeHGlobal"),
        SemanticKind::CsharpPinvokeMarshal
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
        SemanticKind::JavaLocalRef
    );
    assert_eq!(
        SemanticKind::from_function_name("DeleteLocalRef"),
        SemanticKind::JavaLocalRef
    );
    assert_eq!(
        SemanticKind::from_function_name("NewGlobalRef"),
        SemanticKind::JavaGlobalRef
    );
    assert_eq!(
        SemanticKind::from_function_name("DeleteGlobalRef"),
        SemanticKind::JavaGlobalRef
    );
    assert_eq!(
        SemanticKind::from_function_name("NewWeakGlobalRef"),
        SemanticKind::JavaWeakRef
    );
    assert_eq!(
        SemanticKind::from_function_name("DeleteWeakGlobalRef"),
        SemanticKind::JavaWeakRef
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
        SemanticKind::Unknown
    );
    assert_eq!(SemanticKind::from_function_name(""), SemanticKind::Unknown);
}

// ── Property-based tests using proptest ──

proptest! {
    /// Objective: 验证 from_function_name 对任意字符串输入不会 panic
    ///
    /// Invariants:
    /// - 对任意字符串输入，from_function_name 应返回 SemanticKind
    /// - 不应抛出异常或 panic
    #[test]
    fn prop_from_function_name_never_panics(
        func_name in "[a-zA-Z0-9_./:~]{0,200}"
    ) {
        // Property: from_function_name should never panic for any string
        let _result = SemanticKind::from_function_name(&func_name);
        // The property is that this doesn't panic
    }

    /// Objective: 验证安全分数始终在有效范围内
    ///
    /// Invariants:
    /// - 安全分数必须在 0.0 到 1.0 之间（包含边界值）
    /// - 确保所有 SemanticKind 的安全分数都在有效范围内
    #[test]
    fn prop_safety_score_range(
        func_name in "[a-zA-Z0-9_./:~]{0,200}"
    ) {
        // Property: safety score should always be between 0.0 and 1.0
        let kind = SemanticKind::from_function_name(&func_name);
        let score = kind.safety_score();
        prop_assert!(
            (0.0..=1.0).contains(&score),
            "Safety score {} for function '{}' is out of range [0.0, 1.0]",
            score,
            func_name
        );
    }

    /// Objective: 验证 requires_cleanup 方法与语义类型的一致性
    ///
    /// Invariants:
    /// - 需要清理的语义类型（如 PythonRefcountInc、CppUniquePtr 等）必须返回 true
    /// - 其他语义类型必须返回 false
    /// - 确保清理标志与语义类型定义一致
    #[test]
    fn prop_requires_cleanup_consistency(
        func_name in "[a-zA-Z0-9_./:~]{0,200}"
    ) {
        // Property: requires_cleanup should be consistent with the kind
        let kind = SemanticKind::from_function_name(&func_name);
        let requires_cleanup = kind.requires_cleanup();

        // Some known patterns that require cleanup
        let should_require_cleanup = matches!(
            kind,
            SemanticKind::PythonRefcountInc
                | SemanticKind::PythonOwnedRef
                | SemanticKind::GoRuntimeAlloc
                | SemanticKind::CppUniquePtr
                | SemanticKind::CppSharedPtr
                | SemanticKind::CsharpSafeHandle
                | SemanticKind::CsharpFinalizer
                | SemanticKind::CsharpPinvokeMarshal
                | SemanticKind::JavaGlobalRef
                | SemanticKind::JavaWeakRef
                | SemanticKind::HeapProvenance
                | SemanticKind::IntoRawTransfer
        );

        prop_assert_eq!(
            requires_cleanup,
            should_require_cleanup,
            "requires_cleanup mismatch for function '{}' with kind {:?}",
            func_name,
            kind
        );
    }

    /// Objective: 验证 is_borrowed_or_temporary 方法与语义类型的一致性
    ///
    /// Invariants:
    /// - 借用或临时语义类型（如 PythonBorrowedRef、FromParameter 等）必须返回 true
    /// - 其他语义类型必须返回 false
    /// - 确保借用标志与语义类型定义一致
    #[test]
    fn prop_is_borrowed_or_temporary_consistency(
        func_name in "[a-zA-Z0-9_./:~]{0,200}"
    ) {
        // Property: is_borrowed_or_temporary should be consistent with the kind
        let kind = SemanticKind::from_function_name(&func_name);
        let is_borrowed = kind.is_borrowed_or_temporary();

        // Some known patterns that are borrowed/temporary
        let should_be_borrowed = matches!(
            kind,
            SemanticKind::PythonBorrowedRef
                | SemanticKind::PythonGilProtected
                | SemanticKind::JavaLocalRef
                | SemanticKind::FromParameter
                | SemanticKind::ReadonlyParam
        );

        prop_assert_eq!(
            is_borrowed,
            should_be_borrowed,
            "is_borrowed_or_temporary mismatch for function '{}' with kind {:?}",
            func_name,
            kind
        );
    }

    /// Objective: 验证抑制规则与语义类型的一致性
    ///
    /// Invariants:
    /// - write_to_immutable 抑制规则必须与语义类型定义一致
    /// - borrow_escape 抑制规则必须与语义类型定义一致
    /// - use_after_free 抑制规则必须与语义类型定义一致
    /// - cross_language_free 抑制规则必须与语义类型定义一致
    #[test]
    fn prop_suppression_rules_consistency(
        func_name in "[a-zA-Z0-9_./:~]{0,200}"
    ) {
        // Property: suppression rules should be consistent with the kind
        let kind = SemanticKind::from_function_name(&func_name);

        // Test write_to_immutable suppression
        let suppresses_wti = kind.suppresses_write_to_immutable();
        let should_suppress_wti = matches!(
            kind,
            SemanticKind::MutableParam
                | SemanticKind::InteriorMutability
                | SemanticKind::PythonGilProtected
                | SemanticKind::CppUniquePtr
                | SemanticKind::CppSharedPtr
                | SemanticKind::CsharpSafeHandle
        );
        prop_assert_eq!(
            suppresses_wti,
            should_suppress_wti,
            "suppresses_write_to_immutable mismatch for function '{}' with kind {:?}",
            func_name,
            kind
        );

        // Test borrow_escape suppression
        let suppresses_be = kind.suppresses_borrow_escape();
        let should_suppress_be = matches!(
            kind,
            SemanticKind::HeapProvenance
                | SemanticKind::GlobalProvenance
                | SemanticKind::FromParameter
                | SemanticKind::PythonBorrowedRef
                | SemanticKind::PythonGilProtected
                | SemanticKind::GoDeferCleanup
                | SemanticKind::GoFinalizer
                | SemanticKind::GoRuntimeAlloc
                | SemanticKind::CppUniquePtr
                | SemanticKind::CppSharedPtr
                | SemanticKind::CppDestructor
                | SemanticKind::CsharpSafeHandle
                | SemanticKind::JavaLocalRef
        );
        prop_assert_eq!(
            suppresses_be,
            should_suppress_be,
            "suppresses_borrow_escape mismatch for function '{}' with kind {:?}",
            func_name,
            kind
        );

        // Test use_after_free suppression
        let suppresses_uaf = kind.suppresses_use_after_free();
        let should_suppress_uaf = matches!(
            kind,
            SemanticKind::RaiiDropRelease
                | SemanticKind::PythonRefcountInc
                | SemanticKind::PythonOwnedRef
                | SemanticKind::GoDeferCleanup
                | SemanticKind::GoFinalizer
                | SemanticKind::CppUniquePtr
                | SemanticKind::CppSharedPtr
                | SemanticKind::CppDestructor
                | SemanticKind::CsharpSafeHandle
                | SemanticKind::CsharpFinalizer
                | SemanticKind::JavaGlobalRef
        );
        prop_assert_eq!(
            suppresses_uaf,
            should_suppress_uaf,
            "suppresses_use_after_free mismatch for function '{}' with kind {:?}",
            func_name,
            kind
        );

        // Test cross_language_free suppression
        let suppresses_clf = kind.suppresses_cross_language_free();
        let should_suppress_clf = matches!(
            kind,
            SemanticKind::IntoRawTransfer
                | SemanticKind::FileOperation
                | SemanticKind::NetworkOperation
                | SemanticKind::ProcessOperation
                | SemanticKind::LibraryRelease
                | SemanticKind::PythonRefcountDec
                | SemanticKind::PythonOwnedRef
                | SemanticKind::GoDeferCleanup
                | SemanticKind::GoFinalizer
                | SemanticKind::GoRuntimeAlloc
                | SemanticKind::CppUniquePtr
                | SemanticKind::CppSharedPtr
                | SemanticKind::CppDestructor
                | SemanticKind::CsharpSafeHandle
                | SemanticKind::CsharpFinalizer
                | SemanticKind::CsharpPinvokeMarshal
                | SemanticKind::JavaGlobalRef
                | SemanticKind::JavaWeakRef
        );
        prop_assert_eq!(
            suppresses_clf,
            should_suppress_clf,
            "suppresses_cross_language_free mismatch for function '{}' with kind {:?}",
            func_name,
            kind
        );
    }

    /// Objective: 验证 Python 模式被正确检测
    ///
    /// Invariants:
    /// - Py_INCREF/Py_XINCREF 必须被识别为 PythonRefcountInc
    /// - Py_DECREF/Py_XDECREF 必须被识别为 PythonRefcountDec
    /// - PyList_GetItem 等必须被识别为 PythonBorrowedRef
    /// - PyBytes_FromString 等必须被识别为 PythonOwnedRef
    /// - PyGILState_Ensure/Release 必须被识别为 PythonGilProtected
    #[test]
    fn prop_python_patterns_detected(
        prefix in "(Py_INCREF|Py_XINCREF|Py_DECREF|Py_XDECREF|PyList_GetItem|PyTuple_GetItem|PyDict_GetItem|PyBytes_FromString|PyLong_FromLong|PyFloat_FromDouble|PyObject_Call|PyUnicode_FromString|PyBool_FromLong|PyGILState_Ensure|PyGILState_Release)",
        suffix in "[a-zA-Z0-9_]{0,20}"
    ) {
        // Property: Python patterns should be detected correctly
        let func_name = format!("{}{}", prefix, suffix);
        let kind = SemanticKind::from_function_name(&func_name);

        match prefix.as_str() {
            "Py_INCREF" | "Py_XINCREF" => prop_assert_eq!(kind, SemanticKind::PythonRefcountInc),
            "Py_DECREF" | "Py_XDECREF" => prop_assert_eq!(kind, SemanticKind::PythonRefcountDec),
            "PyList_GetItem" | "PyTuple_GetItem" | "PyDict_GetItem" => prop_assert_eq!(kind, SemanticKind::PythonBorrowedRef),
            "PyBytes_FromString" | "PyLong_FromLong" | "PyFloat_FromDouble" | "PyObject_Call" | "PyUnicode_FromString" | "PyBool_FromLong" => prop_assert_eq!(kind, SemanticKind::PythonOwnedRef),
            "PyGILState_Ensure" | "PyGILState_Release" => prop_assert_eq!(kind, SemanticKind::PythonGilProtected),
            _ => {} // Other prefixes don't match Python patterns
        }
    }

    /// Objective: 验证 Go 模式被正确检测
    ///
    /// Invariants:
    /// - defer C.free 必须被识别为 GoDeferCleanup
    /// - runtime.SetFinalizer 必须被识别为 GoFinalizer
    /// - _Cgo_/_cgo_ 必须被识别为 GoCgoWrapper
    /// - runtime.mallocgc 等必须被识别为 GoRuntimeAlloc
    #[test]
    fn prop_go_patterns_detected(
        prefix in "(defer C.free|runtime.SetFinalizer|_Cgo_|_cgo_|runtime.mallocgc|runtime.newobject|runtime.newarray)",
        suffix in "[a-zA-Z0-9_]{0,20}"
    ) {
        // Property: Go patterns should be detected correctly
        let func_name = format!("{}{}", prefix, suffix);
        let kind = SemanticKind::from_function_name(&func_name);

        match prefix.as_str() {
            "defer C.free" => prop_assert_eq!(kind, SemanticKind::GoDeferCleanup),
            "runtime.SetFinalizer" => prop_assert_eq!(kind, SemanticKind::GoFinalizer),
            "_Cgo_" | "_cgo_" => prop_assert_eq!(kind, SemanticKind::GoCgoWrapper),
            "runtime.mallocgc" | "runtime.newobject" | "runtime.newarray" => prop_assert_eq!(kind, SemanticKind::GoRuntimeAlloc),
            _ => {} // Other prefixes don't match Go patterns
        }
    }

    /// Objective: 验证 C++ 模式被正确检测
    ///
    /// Invariants:
    /// - unique_ptr/make_unique/std::unique_ptr 必须被识别为 CppUniquePtr
    /// - shared_ptr/make_shared/std::shared_ptr 必须被识别为 CppSharedPtr
    /// - ~ 必须被识别为 CppDestructor
    /// - __cxa_throw 等必须被识别为 CppExceptionPath
    #[test]
    fn prop_cpp_patterns_detected(
        prefix in "(unique_ptr|make_unique|std::unique_ptr|shared_ptr|make_shared|std::shared_ptr|~|__cxa_throw|__cxa_begin_catch|__cxa_end_catch|__cxa_allocate_exception)",
        suffix in "[a-zA-Z0-9_<>:]{0,20}"
    ) {
        // Property: C++ patterns should be detected correctly
        let func_name = format!("{}{}", prefix, suffix);
        let kind = SemanticKind::from_function_name(&func_name);

        match prefix.as_str() {
            "unique_ptr" | "make_unique" | "std::unique_ptr" => prop_assert_eq!(kind, SemanticKind::CppUniquePtr),
            "shared_ptr" | "make_shared" | "std::shared_ptr" => prop_assert_eq!(kind, SemanticKind::CppSharedPtr),
            "~" => prop_assert_eq!(kind, SemanticKind::CppDestructor),
            "__cxa_throw" | "__cxa_begin_catch" | "__cxa_end_catch" | "__cxa_allocate_exception" => prop_assert_eq!(kind, SemanticKind::CppExceptionPath),
            _ => {} // Other prefixes don't match C++ patterns
        }
    }

    /// Objective: 验证 C# 模式被正确检测
    ///
    /// Invariants:
    /// - SafeHandle/ReleaseHandle/CriticalHandle 必须被识别为 CsharpSafeHandle
    /// - Finalize 必须被识别为 CsharpFinalizer
    /// - DllImport/Marshal.AllocHGlobal/Marshal.FreeHGlobal 必须被识别为 CsharpPinvokeMarshal
    #[test]
    fn prop_csharp_patterns_detected(
        prefix in "(SafeHandle|ReleaseHandle|CriticalHandle|Finalize|DllImport|Marshal.AllocHGlobal|Marshal.FreeHGlobal)",
        suffix in "[a-zA-Z0-9_]{0,20}"
    ) {
        // Property: C# patterns should be detected correctly
        let func_name = format!("{}{}", prefix, suffix);
        let kind = SemanticKind::from_function_name(&func_name);

        match prefix.as_str() {
            "SafeHandle" | "ReleaseHandle" | "CriticalHandle" => prop_assert_eq!(kind, SemanticKind::CsharpSafeHandle),
            "Finalize" => prop_assert_eq!(kind, SemanticKind::CsharpFinalizer),
            "DllImport" | "Marshal.AllocHGlobal" | "Marshal.FreeHGlobal" => prop_assert_eq!(kind, SemanticKind::CsharpPinvokeMarshal),
            _ => {} // Other prefixes don't match C# patterns
        }
    }

    /// Objective: 验证 Java JNI 模式被正确检测
    ///
    /// Invariants:
    /// - NewLocalRef/DeleteLocalRef 必须被识别为 JavaLocalRef
    /// - NewGlobalRef/DeleteGlobalRef 必须被识别为 JavaGlobalRef
    /// - NewWeakGlobalRef/DeleteWeakGlobalRef 必须被识别为 JavaWeakRef
    #[test]
    fn prop_java_patterns_detected(
        prefix in "(NewLocalRef|DeleteLocalRef|NewGlobalRef|DeleteGlobalRef|NewWeakGlobalRef|DeleteWeakGlobalRef)",
        suffix in "[a-zA-Z0-9_]{0,20}"
    ) {
        // Property: Java JNI patterns should be detected correctly
        let func_name = format!("{}{}", prefix, suffix);
        let kind = SemanticKind::from_function_name(&func_name);

        match prefix.as_str() {
            "NewLocalRef" | "DeleteLocalRef" => prop_assert_eq!(kind, SemanticKind::JavaLocalRef),
            "NewGlobalRef" | "DeleteGlobalRef" => prop_assert_eq!(kind, SemanticKind::JavaGlobalRef),
            "NewWeakGlobalRef" | "DeleteWeakGlobalRef" => prop_assert_eq!(kind, SemanticKind::JavaWeakRef),
            _ => {} // Other prefixes don't match Java patterns
        }
    }

    /// Objective: 验证随机函数名返回 Unknown 语义类型
    ///
    /// Invariants:
    /// - 不匹配已知模式的随机函数名必须返回 SemanticKind::Unknown
    /// - 已知模式应被排除在检查之外
    /// - 确保未知函数不会被错误分类
    #[test]
    fn prop_random_function_names_unknown(
        func_name in "[a-zA-Z_][a-zA-Z0-9_]{0,30}"
    ) {
        // Property: random function names (not matching known patterns) should return Unknown
        let kind = SemanticKind::from_function_name(&func_name);

        // Check if this matches any known pattern
        let known_patterns = [
            "Py_INCREF", "Py_XINCREF", "Py_DECREF", "Py_XDECREF",
            "PyList_GetItem", "PyTuple_GetItem", "PyDict_GetItem", "PyList_GET_ITEM", "PyTuple_GET_ITEM",
            "PyBytes_FromString", "PyLong_FromLong", "PyFloat_FromDouble", "PyObject_Call", "PyUnicode_FromString", "PyBool_FromLong",
            "PyGILState_Ensure", "PyGILState_Release",
            "defer C.free", "runtime.SetFinalizer", "_Cgo_", "_cgo_", "runtime.mallocgc", "runtime.newobject", "runtime.newarray",
            "unique_ptr", "make_unique", "std::unique_ptr", "shared_ptr", "make_shared", "std::shared_ptr",
            "~", "__cxa_throw", "__cxa_begin_catch", "__cxa_end_catch", "__cxa_allocate_exception",
            "SafeHandle", "ReleaseHandle", "CriticalHandle", "Finalize", "DllImport", "Marshal.AllocHGlobal", "Marshal.FreeHGlobal",
            "NewLocalRef", "DeleteLocalRef", "NewGlobalRef", "DeleteGlobalRef", "NewWeakGlobalRef", "DeleteWeakGlobalRef",
        ];

        let is_known = known_patterns.iter().any(|pattern| func_name.contains(pattern));

        if !is_known {
            // Random function names should return Unknown
            prop_assert_eq!(
                kind,
                SemanticKind::Unknown,
                "Random function '{}' should return Unknown, got {:?}",
                func_name,
                kind
            );
        }
    }
}
