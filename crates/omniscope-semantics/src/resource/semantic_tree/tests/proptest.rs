//! Property-based tests for semantic tree.

use super::super::*;
use proptest::prelude::*;

proptest! {
    /// Objective: Verify from_function_name never panics for arbitrary string inputs
    ///
    /// Invariants:
    /// - For arbitrary string inputs, from_function_name should return SemanticKind
    /// - Should not throw exceptions or panic
    #[test]
    fn prop_from_function_name_never_panics(
        func_name in "[a-zA-Z0-9_./:~]{0,200}"
    ) {
        // Property: from_function_name should never panic for any string
        let _result = SemanticKind::from_function_name(&func_name);
        // The property is that this doesn't panic
    }

    /// Objective: Verify safety score always stays within valid range
    ///
    /// Invariants:
    /// - Safety score must be between 0.0 and 1.0 (inclusive boundaries)
    /// - Ensure all SemanticKind safety scores are within valid range
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

    /// Objective: Verify requires_cleanup method consistency with semantic types
    ///
    /// Invariants:
    /// - Semantic types requiring cleanup (e.g., PythonRefcountInc, CppUniquePtr, etc.) must return true
    /// - Other semantic types must return false
    /// - Ensure cleanup flag is consistent with semantic type definitions
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

    /// Objective: Verify is_borrowed_or_temporary method consistency with semantic types
    ///
    /// Invariants:
    /// - Borrowed or temporary semantic types (e.g., PythonBorrowedRef, FromParameter, etc.) must return true
    /// - Other semantic types must return false
    /// - Ensure borrowed flag is consistent with semantic type definitions
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

    /// Objective: Verify suppression rules consistency with semantic types
    ///
    /// Invariants:
    /// - write_to_immutable suppression rule must be consistent with semantic type definitions
    /// - borrow_escape suppression rule must be consistent with semantic type definitions
    /// - use_after_free suppression rule must be consistent with semantic type definitions
    /// - cross_language_free suppression rule must be consistent with semantic type definitions
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

    /// Objective: Verify Python patterns are correctly detected
    ///
    /// Invariants:
    /// - Py_INCREF/Py_XINCREF must be recognized as PythonRefcountInc
    /// - Py_DECREF/Py_XDECREF must be recognized as PythonRefcountDec
    /// - PyList_GetItem, etc. must be recognized as PythonBorrowedRef
    /// - PyBytes_FromString, etc. must be recognized as PythonOwnedRef
    /// - PyGILState_Ensure/Release must be recognized as PythonGilProtected
    #[test]
    fn prop_python_patterns_detected(
        prefix in "(Py_INCREF|Py_XINCREF|Py_DECREF|Py_XDECREF|PyList_GetItem|PyTuple_GetItem|PyDict_GetItem|PyBytes_FromString|PyLong_FromLong|PyFloat_FromDouble|PyObject_Call|PyUnicode_FromString|PyBool_FromLong|PyGILState_Ensure|PyGILState_Release)",
        suffix in "[a-zA-Z0-9_]{0,20}"
    ) {
        // Property: Python patterns should be detected correctly
        let func_name = format!("{}{}", prefix, suffix);
        let kind = SemanticKind::from_function_name(&func_name);

        match prefix.as_str() {
            "Py_INCREF" | "Py_XINCREF" => prop_assert_eq!(kind, SemanticKind::PythonRefcountInc, "Python reference counting increment functions should be classified as PythonRefcountInc"),
            "Py_DECREF" | "Py_XDECREF" => prop_assert_eq!(kind, SemanticKind::PythonRefcountDec, "Python reference counting decrement functions should be classified as PythonRefcountDec"),
            "PyList_GetItem" | "PyTuple_GetItem" | "PyDict_GetItem" => prop_assert_eq!(kind, SemanticKind::PythonBorrowedRef, "Python container access functions should be classified as PythonBorrowedRef"),
            "PyBytes_FromString" | "PyLong_FromLong" | "PyFloat_FromDouble" | "PyObject_Call" | "PyUnicode_FromString" | "PyBool_FromLong" => prop_assert_eq!(kind, SemanticKind::PythonOwnedRef, "Python object creation functions should be classified as PythonOwnedRef"),
            "PyGILState_Ensure" | "PyGILState_Release" => prop_assert_eq!(kind, SemanticKind::PythonGilProtected, "Python GIL state functions should be classified as PythonGilProtected"),
            _ => {} // Other prefixes don't match Python patterns
        }
    }

    /// Objective: Verify Go patterns are correctly detected
    ///
    /// Invariants:
    /// - defer C.free must be recognized as GoDeferCleanup
    /// - runtime.SetFinalizer must be recognized as GoFinalizer
    /// - _Cgo_/_cgo_ must be recognized as GoCgoWrapper
    /// - runtime.mallocgc, etc. must be recognized as GoRuntimeAlloc
    #[test]
    fn prop_go_patterns_detected(
        prefix in "(defer C.free|runtime.SetFinalizer|_Cgo_|_cgo_|runtime.mallocgc|runtime.newobject|runtime.newarray)",
        suffix in "[a-zA-Z0-9_]{0,20}"
    ) {
        // Property: Go patterns should be detected correctly
        let func_name = format!("{}{}", prefix, suffix);
        let kind = SemanticKind::from_function_name(&func_name);

        match prefix.as_str() {
            "defer C.free" => prop_assert_eq!(kind, SemanticKind::GoDeferCleanup, "Go defer cleanup should be classified as GoDeferCleanup"),
            "runtime.SetFinalizer" => prop_assert_eq!(kind, SemanticKind::GoFinalizer, "Go finalizer should be classified as GoFinalizer"),
            "_Cgo_" | "_cgo_" => prop_assert_eq!(kind, SemanticKind::GoCgoWrapper, "CGO wrapper functions should be classified as GoCgoWrapper"),
            "runtime.mallocgc" | "runtime.newobject" | "runtime.newarray" => prop_assert_eq!(kind, SemanticKind::GoRuntimeAlloc, "Go runtime allocation functions should be classified as GoRuntimeAlloc"),
            _ => {} // Other prefixes don't match Go patterns
        }
    }

    /// Objective: Verify C++ patterns are correctly detected
    ///
    /// Invariants:
    /// - unique_ptr/make_unique/std::unique_ptr must be recognized as CppUniquePtr
    /// - shared_ptr/make_shared/std::shared_ptr must be recognized as CppSharedPtr
    /// - ~ must be recognized as CppDestructor
    /// - __cxa_throw, etc. must be recognized as CppExceptionPath
    #[test]
    fn prop_cpp_patterns_detected(
        prefix in "(unique_ptr|make_unique|std::unique_ptr|shared_ptr|make_shared|std::shared_ptr|~|__cxa_throw|__cxa_begin_catch|__cxa_end_catch|__cxa_allocate_exception)",
        suffix in "[a-zA-Z0-9_<>:]{0,20}"
    ) {
        // Property: C++ patterns should be detected correctly
        let func_name = format!("{}{}", prefix, suffix);
        let kind = SemanticKind::from_function_name(&func_name);

        match prefix.as_str() {
            "unique_ptr" | "make_unique" | "std::unique_ptr" => prop_assert_eq!(kind, SemanticKind::CppUniquePtr, "C++ unique pointer functions should be classified as CppUniquePtr"),
            "shared_ptr" | "make_shared" | "std::shared_ptr" => prop_assert_eq!(kind, SemanticKind::CppSharedPtr, "C++ shared pointer functions should be classified as CppSharedPtr"),
            "~" => prop_assert_eq!(kind, SemanticKind::CppDestructor, "C++ destructor functions should be classified as CppDestructor"),
            "__cxa_throw" | "__cxa_begin_catch" | "__cxa_end_catch" | "__cxa_allocate_exception" => prop_assert_eq!(kind, SemanticKind::CppExceptionPath, "C++ exception handling functions should be classified as CppExceptionPath"),
            _ => {} // Other prefixes don't match C++ patterns
        }
    }

    /// Objective: Verify C# patterns are correctly detected
    ///
    /// Invariants:
    /// - SafeHandle/ReleaseHandle/CriticalHandle must be recognized as CsharpSafeHandle
    /// - Finalize must be recognized as CsharpFinalizer
    /// - DllImport/Marshal.AllocHGlobal/Marshal.FreeHGlobal must be recognized as CsharpPinvokeMarshal
    #[test]
    fn prop_csharp_patterns_detected(
        prefix in "(SafeHandle|ReleaseHandle|CriticalHandle|Finalize|DllImport|Marshal.AllocHGlobal|Marshal.FreeHGlobal)",
        suffix in "[a-zA-Z0-9_]{0,20}"
    ) {
        // Property: C# patterns should be detected correctly
        let func_name = format!("{}{}", prefix, suffix);
        let kind = SemanticKind::from_function_name(&func_name);

        match prefix.as_str() {
            "SafeHandle" | "ReleaseHandle" | "CriticalHandle" => prop_assert_eq!(kind, SemanticKind::CsharpSafeHandle, "C# SafeHandle functions should be classified as CsharpSafeHandle"),
            "Finalize" => prop_assert_eq!(kind, SemanticKind::CsharpFinalizer, "C# Finalize function should be classified as CsharpFinalizer"),
            "DllImport" | "Marshal.AllocHGlobal" | "Marshal.FreeHGlobal" => prop_assert_eq!(kind, SemanticKind::CsharpPinvokeMarshal, "C# P/Invoke functions should be classified as CsharpPinvokeMarshal"),
            _ => {} // Other prefixes don't match C# patterns
        }
    }

    /// Objective: Verify Java JNI patterns are correctly detected
    ///
    /// Invariants:
    /// - NewLocalRef/DeleteLocalRef must be recognized as JavaLocalRef
    /// - NewGlobalRef/DeleteGlobalRef must be recognized as JavaGlobalRef
    /// - NewWeakGlobalRef/DeleteWeakGlobalRef must be recognized as JavaWeakRef
    #[test]
    fn prop_java_patterns_detected(
        prefix in "(NewLocalRef|DeleteLocalRef|NewGlobalRef|DeleteGlobalRef|NewWeakGlobalRef|DeleteWeakGlobalRef)",
        suffix in "[a-zA-Z0-9_]{0,20}"
    ) {
        // Property: Java JNI patterns should be detected correctly
        let func_name = format!("{}{}", prefix, suffix);
        let kind = SemanticKind::from_function_name(&func_name);

        match prefix.as_str() {
            "NewLocalRef" | "DeleteLocalRef" => prop_assert_eq!(kind, SemanticKind::JavaLocalRef, "Java local reference functions should be classified as JavaLocalRef"),
            "NewGlobalRef" | "DeleteGlobalRef" => prop_assert_eq!(kind, SemanticKind::JavaGlobalRef, "Java global reference functions should be classified as JavaGlobalRef"),
            "NewWeakGlobalRef" | "DeleteWeakGlobalRef" => prop_assert_eq!(kind, SemanticKind::JavaWeakRef, "Java weak reference functions should be classified as JavaWeakRef"),
            _ => {} // Other prefixes don't match Java patterns
        }
    }

    /// Objective: Verify random function names return Unknown semantic type
    ///
    /// Invariants:
    /// - Random function names not matching known patterns must return SemanticKind::Unknown
    /// - Known patterns should be excluded from the check
    /// - Ensure unknown functions are not misclassified
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
