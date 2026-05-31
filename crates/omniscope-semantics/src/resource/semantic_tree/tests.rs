//! Tests for the semantic tree module.

use super::*;

#[test]
fn test_syscall_classify_getenv() {
    assert_eq!(
        SyscallSemantic::classify("getenv"),
        SyscallSemantic::EnvironmentConfig
    );
}

#[test]
fn test_syscall_classify_strlen() {
    assert_eq!(
        SyscallSemantic::classify("strlen"),
        SyscallSemantic::DataQuery
    );
}

#[test]
fn test_syscall_classify_malloc() {
    assert_eq!(
        SyscallSemantic::classify("malloc"),
        SyscallSemantic::MemoryManagement
    );
}

#[test]
fn test_syscall_classify_free() {
    assert_eq!(
        SyscallSemantic::classify("free"),
        SyscallSemantic::MemoryManagement
    );
}

#[test]
fn test_syscall_classify_highway() {
    assert_eq!(
        SyscallSemantic::classify("highway_index_of_char"),
        SyscallSemantic::ComputeAccelerated
    );
}

#[test]
fn test_syscall_classify_bun_dispatch() {
    assert_eq!(
        SyscallSemantic::classify("__bun_dispatch__OutputSink__Sys__quiet_writer_write_all"),
        SyscallSemantic::InternalDispatch
    );
}

#[test]
fn test_syscall_classify_bun_string() {
    assert_eq!(
        SyscallSemantic::classify("BunString__fromBytes"),
        SyscallSemantic::InternalDispatch
    );
}

#[test]
fn test_syscall_classify_wtf_destroy() {
    assert_eq!(
        SyscallSemantic::classify("Bun__WTFStringImpl__destroy"),
        SyscallSemantic::InternalDispatch
    );
}

#[test]
fn test_type_semantic_interior_mutability() {
    // Real mangled name from bun_core: std::sync::mutex::Mutex
    let name = "_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std3sys3pal4unix4sync5mutexNtB2_5Mutex4lock";
    assert_eq!(
        TypeSemantic::from_mangled_name(name),
        TypeSemantic::InteriorMutability
    );
}

#[test]
fn test_type_semantic_once() {
    let name = "_RINvMNtNtNtCsg1bLsEOY8ZL_3std3sys4sync8once_boxINtB3_7OnceBox";
    assert_eq!(TypeSemantic::from_mangled_name(name), TypeSemantic::Once);
}

#[test]
fn test_type_semantic_drop() {
    let name = "_RINvNtCsgXhsEb1m4tm_4core3ptr13drop_in_place";
    assert_eq!(TypeSemantic::from_mangled_name(name), TypeSemantic::Drop);
}

#[test]
fn test_type_semantic_non_rust() {
    assert_eq!(
        TypeSemantic::from_mangled_name("Bun__atexit"),
        TypeSemantic::Unknown
    );
}

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
#[test]
fn test_semantic_kind_from_function_name_unknown() {
    // Test that unknown functions return Unknown
    assert_eq!(
        SemanticKind::from_function_name("some_random_function"),
        SemanticKind::Unknown
    );
    assert_eq!(SemanticKind::from_function_name(""), SemanticKind::Unknown);
}
