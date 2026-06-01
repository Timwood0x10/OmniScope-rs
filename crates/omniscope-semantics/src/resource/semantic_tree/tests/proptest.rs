//! Property-based tests for semantic tree.

use super::super::*;
use proptest::prelude::*;

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
            "Py_INCREF" | "Py_XINCREF" => prop_assert_eq!(kind, SemanticKind::PythonRefcountInc, "Expected values to be equal"),
            "Py_DECREF" | "Py_XDECREF" => prop_assert_eq!(kind, SemanticKind::PythonRefcountDec, "Expected values to be equal"),
            "PyList_GetItem" | "PyTuple_GetItem" | "PyDict_GetItem" => prop_assert_eq!(kind, SemanticKind::PythonBorrowedRef, "Expected values to be equal"),
            "PyBytes_FromString" | "PyLong_FromLong" | "PyFloat_FromDouble" | "PyObject_Call" | "PyUnicode_FromString" | "PyBool_FromLong" => prop_assert_eq!(kind, SemanticKind::PythonOwnedRef, "Expected values to be equal"),
            "PyGILState_Ensure" | "PyGILState_Release" => prop_assert_eq!(kind, SemanticKind::PythonGilProtected, "Expected values to be equal"),
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
            "defer C.free" => prop_assert_eq!(kind, SemanticKind::GoDeferCleanup, "Expected values to be equal"),
            "runtime.SetFinalizer" => prop_assert_eq!(kind, SemanticKind::GoFinalizer, "Expected values to be equal"),
            "_Cgo_" | "_cgo_" => prop_assert_eq!(kind, SemanticKind::GoCgoWrapper, "Expected values to be equal"),
            "runtime.mallocgc" | "runtime.newobject" | "runtime.newarray" => prop_assert_eq!(kind, SemanticKind::GoRuntimeAlloc, "Expected values to be equal"),
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
            "unique_ptr" | "make_unique" | "std::unique_ptr" => prop_assert_eq!(kind, SemanticKind::CppUniquePtr, "Expected values to be equal"),
            "shared_ptr" | "make_shared" | "std::shared_ptr" => prop_assert_eq!(kind, SemanticKind::CppSharedPtr, "Expected values to be equal"),
            "~" => prop_assert_eq!(kind, SemanticKind::CppDestructor, "Expected values to be equal"),
            "__cxa_throw" | "__cxa_begin_catch" | "__cxa_end_catch" | "__cxa_allocate_exception" => prop_assert_eq!(kind, SemanticKind::CppExceptionPath, "Expected values to be equal"),
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
            "SafeHandle" | "ReleaseHandle" | "CriticalHandle" => prop_assert_eq!(kind, SemanticKind::CsharpSafeHandle, "Expected values to be equal"),
            "Finalize" => prop_assert_eq!(kind, SemanticKind::CsharpFinalizer, "Expected values to be equal"),
            "DllImport" | "Marshal.AllocHGlobal" | "Marshal.FreeHGlobal" => prop_assert_eq!(kind, SemanticKind::CsharpPinvokeMarshal, "Expected values to be equal"),
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
            "NewLocalRef" | "DeleteLocalRef" => prop_assert_eq!(kind, SemanticKind::JavaLocalRef, "Expected values to be equal"),
            "NewGlobalRef" | "DeleteGlobalRef" => prop_assert_eq!(kind, SemanticKind::JavaGlobalRef, "Expected values to be equal"),
            "NewWeakGlobalRef" | "DeleteWeakGlobalRef" => prop_assert_eq!(kind, SemanticKind::JavaWeakRef, "Expected values to be equal"),
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
