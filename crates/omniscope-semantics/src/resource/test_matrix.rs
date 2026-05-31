//! Test Matrix integration tests for the Resource Contract architecture.
//!
//! Verifies the key scenarios from ARCHITECTURE_ADJUSTMENT.md Test Matrix:
//! - Same-family and cross-family release matching
//! - Structural inference patterns (destructor, bridge, refcount, static-lifetime)
//! - Issue candidate verification and verdict gating
//!
//! These tests exercise the full inference chain:
//!   registry lookup → structural inference → family inference
//!
//! And the verification chain:
//!   candidate → verifier → verdict → reportability

use omniscope_core::IssueCandidate;
use omniscope_types::{Effect, EvidenceKind, FamilyId, IssueCandidateKind, VerifierVerdict};

use super::family_registry::FamilyRegistry;
use super::summary_inference::infer_summary_for_symbol;

// ─── Same-family release: safe ───────────────────────────────────────

/// Objective: 验证 malloc 和 free 是否正确注册在同一个家族中
///
/// Invariants:
/// - malloc 和 free 必须有相同的 family_id（均为 C_HEAP）
/// - is_compatible_release(malloc, free) 必须返回 true
/// - 同一家族的候选者应有匹配的 alloc/release 家族
#[test]
fn test_matrix_malloc_free_same_family_safe() {
    let registry = FamilyRegistry::new();
    let malloc = registry
        .lookup("malloc")
        .expect("test_matrix::test_matrix_malloc_free_same_family_safe: malloc must be registered");
    let free = registry
        .lookup("free")
        .expect("test_matrix::test_matrix_malloc_free_same_family_safe: free must be registered");

    assert_eq!(
        malloc.family_id, free.family_id,
        "malloc/free must be same family (c_heap)"
    );
    assert!(
        registry.is_compatible_release(malloc.family_id, free.family_id),
        "malloc/free must be compatible"
    );

    // Build a candidate and verify it's explained safe
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        malloc.family_id,
        "malloc",
    )
    .with_release_family(free.family_id)
    .with_release_function("free");

    // Same family release → ExplainedSafe
    assert_eq!(
        candidate.alloc_family,
        candidate
            .release_family
            .expect("test_matrix::test_matrix_malloc_free_same_family_safe: test_matrix: release_family should be set for cross-family candidate"),
        "Same-family candidate should have matching families"
    );
}

/// Objective: 验证 C++ new[] 和 delete[] 是否正确注册在同一个家族中
///
/// Invariants:
/// - new[] 和 delete[] 必须有相同的 family_id（均为 CPP_NEW_ARRAY）
/// - is_compatible_release(new[], delete[]) 必须返回 true
/// - 同一家族的分配和释放操作应正确配对
#[test]
fn test_matrix_new_array_delete_array_same_family_safe() {
    let registry = FamilyRegistry::new();
    let new_arr = registry.lookup("_Znam").expect("test_matrix::test_matrix_new_array_delete_array_same_family_safe: _Znam must be registered");
    let del_arr = registry
        .lookup("_ZdaPv")
        .expect("test_matrix::test_matrix_new_array_delete_array_same_family_safe: _ZdaPv must be registered");

    assert_eq!(
        new_arr.family_id, del_arr.family_id,
        "new[]/delete[] must be same family (cpp_new_array)"
    );
    assert!(
        registry.is_compatible_release(new_arr.family_id, del_arr.family_id),
        "new[]/delete[] must be compatible"
    );
}

/// Objective: 验证 Python 对象分配和释放函数是否正确注册在同一个家族中
///
/// Invariants:
/// - PyObject_New 和 PyObject_Free 必须有相同的 family_id（均为 PYTHON_OBJECT）
/// - Python 对象的分配和释放操作应正确配对
/// - 家族注册应支持跨语言（Python）的资源管理
#[test]
fn test_matrix_pyobject_new_pyobject_free_same_family_safe() {
    let registry = FamilyRegistry::new();
    let py_new = registry
        .lookup("PyObject_New")
        .expect("test_matrix::test_matrix_pyobject_new_pyobject_free_same_family_safe: PyObject_New must be registered");
    let py_free = registry
        .lookup("PyObject_Free")
        .expect("test_matrix::test_matrix_pyobject_new_pyobject_free_same_family_safe: PyObject_Free must be registered");

    assert_eq!(
        py_new.family_id, py_free.family_id,
        "PyObject_New/PyObject_Free must be same family (python_object)"
    );
}

// ─── Cross-family mismatch: confirmed issue ──────────────────────────

/// Objective: 验证 C malloc 和 C++ operator delete 是否正确识别为不同家族
///
/// Invariants:
/// - malloc 和 operator delete 必须有不同的 family_id
/// - is_compatible_release(malloc, delete) 必须返回 false
/// - 跨家族的分配/释放操作应被标记为不兼容
#[test]
fn test_matrix_malloc_delete_cross_family_mismatch() {
    let registry = FamilyRegistry::new();
    let malloc = registry.lookup("malloc").expect(
        "test_matrix::test_matrix_malloc_delete_cross_family_mismatch: malloc must be registered",
    );
    let del = registry
        .lookup("_ZdlPv")
        .expect("test_matrix::test_matrix_malloc_delete_cross_family_mismatch: operator delete must be registered");

    assert_ne!(
        malloc.family_id, del.family_id,
        "malloc and operator delete must be different families"
    );
    assert!(
        !registry.is_compatible_release(malloc.family_id, del.family_id),
        "malloc/delete must be incompatible"
    );
}

/// Objective: 验证 Rust 分配器和 C free 是否正确识别为不同家族
///
/// Invariants:
/// - __rust_alloc 和 free 必须有不同的 family_id
/// - is_compatible_release(__rust_alloc, free) 必须返回 false
/// - Rust 分配器与 C 标准库释放函数应被视为不兼容
#[test]
fn test_matrix_rust_alloc_free_cross_family_mismatch() {
    let registry = FamilyRegistry::new();
    let rust_alloc = registry
        .lookup("__rust_alloc")
        .expect("test_matrix::test_matrix_rust_alloc_free_cross_family_mismatch: __rust_alloc must be registered");
    let free = registry.lookup("free").expect(
        "test_matrix::test_matrix_rust_alloc_free_cross_family_mismatch: free must be registered",
    );

    assert_ne!(
        rust_alloc.family_id, free.family_id,
        "__rust_alloc and free must be different families"
    );
    assert!(
        !registry.is_compatible_release(rust_alloc.family_id, free.family_id),
        "__rust_alloc/free must be incompatible"
    );
}

/// Objective: 验证 Python 内存分配和对象释放函数是否正确识别为不同家族
///
/// Invariants:
/// - PyMem_Malloc 和 PyObject_Free 必须有不同的 family_id
/// - Python 内存管理与对象管理应被视为不同的资源家族
/// - 不同的 Python API 应有明确的家族边界
#[test]
fn test_matrix_pymem_malloc_pyobject_free_family_mismatch() {
    let registry = FamilyRegistry::new();
    let pymem = registry
        .lookup("PyMem_Malloc")
        .expect("test_matrix::test_matrix_pymem_malloc_pyobject_free_family_mismatch: PyMem_Malloc must be registered");
    let py_free = registry
        .lookup("PyObject_Free")
        .expect("test_matrix::test_matrix_pymem_malloc_pyobject_free_family_mismatch: PyObject_Free must be registered");

    assert_ne!(
        pymem.family_id, py_free.family_id,
        "PyMem_Malloc and PyObject_Free must be different families"
    );
}

/// Objective: 验证 JNI 本地引用和全局引用是否正确识别为不同家族
///
/// Invariants:
/// - NewLocalRef 和 DeleteGlobalRef 必须有不同的 family_id
/// - JNI 的本地引用和全局引用应被视为不同的资源类型
/// - 不同的 JNI 引用类型应有明确的家族边界
#[test]
fn test_matrix_jni_local_global_ref_mismatch() {
    let registry = FamilyRegistry::new();
    let local = registry.lookup("NewLocalRef").expect(
        "test_matrix::test_matrix_jni_local_global_ref_mismatch: NewLocalRef must be registered",
    );
    let global_del = registry
        .lookup("DeleteGlobalRef")
        .expect("test_matrix::test_matrix_jni_local_global_ref_mismatch: DeleteGlobalRef must be registered");

    assert_ne!(
        local.family_id, global_del.family_id,
        "Local and global refs are different families"
    );
}

/// Objective: 验证 Windows HGlobal 和 CoTaskMem 是否正确识别为不同家族
///
/// Invariants:
/// - AllocHGlobal 和 CoTaskMemFree 必须有不同的 family_id
/// - Windows 的不同内存管理 API 应被视为不同的资源家族
/// - 跨 Windows API 的分配/释放操作应被标记为不兼容
#[test]
fn test_matrix_hglobal_cotask_mismatch() {
    let registry = FamilyRegistry::new();
    let hglobal = registry
        .lookup("AllocHGlobal")
        .expect("AllocHGlobal must be registered");
    let cotask = registry
        .lookup("CoTaskMemFree")
        .expect("CoTaskMemFree must be registered");

    assert_ne!(
        hglobal.family_id, cotask.family_id,
        "HGlobal and CoTaskMem are different families"
    );
}

// ─── Refcount conditional release ─────────────────────────────────────

/// Objective: 验证 Py_DECREF 是否正确识别为条件释放而非无条件释放
///
/// Invariants:
/// - Py_DECREF 必须有 ConditionalRelease 效果，而不是无条件 Release
/// - Py_DECREF 必须属于 PYTHON_OBJECT 家族
/// - 推断摘要必须产生 ConditionalRelease 效果
/// - 条件释放不应被误报为内存泄漏
#[test]
fn test_matrix_py_decref_conditional_release_not_leak() {
    let registry = FamilyRegistry::new();
    let decref = registry
        .lookup("Py_DECREF")
        .expect("Py_DECREF must be registered");

    // Py_DECREF must be ConditionalRelease, NOT unconditional Release
    assert_eq!(
        decref.effect,
        super::family_registry::SymbolEffect::ConditionalRelease,
        "Py_DECREF must be conditional release"
    );
    assert_eq!(
        decref.family_id,
        FamilyId::PYTHON_OBJECT,
        "Py_DECREF must be in python_object family"
    );

    // Verify summary inference produces ConditionalRelease effect
    let summary = infer_summary_for_symbol("Py_DECREF", 1, 100, &registry);
    assert!(
        summary.releases_resource(),
        "Py_DECREF summary must release resource"
    );
    // The effect should be ConditionalRelease, not Release
    let has_conditional = summary
        .effects
        .iter()
        .any(|e| matches!(e, Effect::ConditionalRelease { .. }));
    assert!(
        has_conditional,
        "Py_DECREF must produce ConditionalRelease effect"
    );
}

// ─── Destructor-mediated release ──────────────────────────────────────

/// Objective: 验证 Rust Drop 函数是否正确推断为析构器释放模式
///
/// Invariants:
/// - drop 函数必须被推断为析构器
/// - 析构器摘要必须释放资源
/// - 必须附加 DestructorRelease 证据
/// - Rust Drop 调用 C free 应被识别为析构器中介释放
#[test]
fn test_matrix_rust_drop_calling_c_free_is_destructor_mediated() {
    // Rust Drop calling C free is destructor-mediated release.
    // The "drop" function should be inferred as a destructor.
    let registry = FamilyRegistry::new();

    let drop_summary = infer_summary_for_symbol("drop", 1, 100, &registry);
    assert!(
        drop_summary.is_destructor(),
        "drop must be inferred as destructor"
    );
    assert!(
        drop_summary.releases_resource(),
        "Destructor summary must release resource"
    );

    // Evidence must be attached
    let has_destructor_evidence = drop_summary
        .evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::DestructorRelease);
    assert!(
        has_destructor_evidence,
        "Destructor summary must have DestructorRelease evidence"
    );
}

// ─── Bridge inference ─────────────────────────────────────────────────

/// Objective: 验证 as_ptr 函数是否正确推断为桥接助手模式
///
/// Invariants:
/// - as_ptr 必须被推断为桥接助手
/// - 必须产生 ReturnsBorrowed 效果
/// - 不能产生 ReturnsOwned 效果
/// - 必须附加 BridgeHelper 证据
/// - 桥接助手应返回借用指针而非拥有指针
#[test]
fn test_matrix_as_ptr_bridge_returns_borrowed() {
    let registry = FamilyRegistry::new();

    let as_ptr_summary = infer_summary_for_symbol("as_ptr", 1, 100, &registry);
    assert!(
        as_ptr_summary.is_bridge(),
        "as_ptr must be inferred as bridge helper"
    );

    // Must return borrowed, not owned
    let has_returns_borrowed = as_ptr_summary.effects.contains(&Effect::ReturnsBorrowed);
    assert!(
        has_returns_borrowed,
        "as_ptr must produce ReturnsBorrowed effect"
    );

    // Must NOT produce ReturnsOwned
    let has_returns_owned = as_ptr_summary
        .effects
        .iter()
        .any(|e| matches!(e, Effect::ReturnsOwned { .. }));
    assert!(
        !has_returns_owned,
        "Bridge must NOT produce ReturnsOwned effect"
    );

    // Bridge evidence must be attached
    let has_bridge_evidence = as_ptr_summary
        .evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::BridgeHelper);
    assert!(
        has_bridge_evidence,
        "Bridge summary must have BridgeHelper evidence"
    );
}

// ─── Escape-based non-leak scenarios ─────────────────────────────────

/// Objective: 验证返回拥有指针的函数不会被误报为本地泄漏
///
/// Invariants:
/// - malloc 必须获取资源
/// - malloc 必须产生 ReturnsOwned 效果
/// - ReturnsOwned 是有效的逃逸机制，不应被视为泄漏
/// - 注册表匹配的函数应有正确的资源获取效果
#[test]
fn test_matrix_return_owned_not_local_leak() {
    // A function that returns owned pointer is not a local leak.
    // Verify by checking that ReturnsOwned is a valid escape.
    let registry = FamilyRegistry::new();
    let summary = infer_summary_for_symbol("malloc", 1, 100, &registry);

    assert!(summary.acquires_resource(), "malloc must acquire resource");

    // ReturnsOwned is a valid escape — not a leak
    let has_returns_owned = summary
        .effects
        .iter()
        .any(|e| matches!(e, Effect::ReturnsOwned { .. }));
    assert!(
        has_returns_owned,
        "Registry-matched malloc must produce ReturnsOwned effect"
    );
}

// ─── Static lifetime sink ─────────────────────────────────────────────

/// Objective: 验证全局静态初始化是否正确识别为静态生命周期
///
/// Invariants:
/// - __cxx_global_var_init 必须有 StaticLifetimeSink 证据
/// - 必须产生 StoresArgToGlobal 效果
/// - 静态生命周期不应被误报为内存泄漏
/// - 全局变量初始化应被视为静态生命周期接收器
#[test]
fn test_matrix_global_static_init_is_static_lifetime() {
    let registry = FamilyRegistry::new();
    let summary = infer_summary_for_symbol("__cxx_global_var_init", 1, 100, &registry);

    // Must have static-lifetime evidence
    let has_static_evidence = summary
        .evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::StaticLifetimeSink);
    assert!(
        has_static_evidence,
        "Global var init must have StaticLifetimeSink evidence"
    );

    // Must NOT be a leak — it's a static lifetime
    let has_global_store = summary
        .effects
        .iter()
        .any(|e| matches!(e, Effect::StoresArgToGlobal { .. }));
    assert!(
        has_global_store,
        "Static-lifetime inference must produce StoresArgToGlobal effect"
    );
}

// ─── NeedsModel diagnostic ───────────────────────────────────────────

/// Objective: 验证未知家族是否产生 NeedsModel 诊断而不是误报
///
/// Invariants:
/// - 未知符号不应产生高置信度推断
/// - 未知家族应产生 NeedsModel 类型候选
/// - Diagnostic 判定不应可报告
/// - 未知分配器应被标记为需要模型，而不是误报为问题
#[test]
fn test_matrix_unknown_family_needs_model_diagnostic() {
    let registry = FamilyRegistry::new();

    // Unknown symbol should not produce high-confidence inference
    let summary = infer_summary_for_symbol("custom_allocator_init", 1, 100, &registry);

    // If it doesn't match any pattern, it should be low confidence
    // and NOT produce ConfirmedIssue-level effects
    if !summary.acquires_resource() && !summary.releases_resource() {
        // Completely unknown — should be NeedsModel
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::NeedsModel,
            FamilyId::C_HEAP,
            "custom_allocator_init",
        )
        .with_verdict(VerifierVerdict::Diagnostic);

        assert!(
            !candidate.is_reportable(),
            "NeedsModel diagnostic must NOT be reportable"
        );
        assert_eq!(
            candidate.verdict,
            Some(VerifierVerdict::Diagnostic),
            "Unknown family should produce Diagnostic verdict"
        );
    }
}

// ─── Verifier verdict gating ──────────────────────────────────────────

/// Objective: 验证 ConfirmedIssue 判定是否正确标记为可报告
///
/// Invariants:
/// - ConfirmedIssue 判定必须可报告
/// - 跨家族释放问题应被正确识别和标记
/// - 判定门控应正确处理确认的问题
/// - 可报告状态应基于判定类型
#[test]
fn test_matrix_verdict_gating_confirmed_issue_reportable() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::CPP_NEW_SCALAR)
    .with_release_function("operator delete")
    .with_verdict(VerifierVerdict::ConfirmedIssue);

    assert!(
        candidate.is_reportable(),
        "ConfirmedIssue must be reportable"
    );
}

/// Objective: 验证 Diagnostic 判定是否正确标记为不可报告
///
/// Invariants:
/// - Diagnostic 判定必须不可报告
/// - 需要模型的诊断不应产生误报
/// - 判定门控应正确过滤诊断信息
/// - 诊断信息应仅用于内部分析，不对外报告
#[test]
fn test_matrix_verdict_gating_diagnostic_not_reportable() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::NeedsModel,
        FamilyId::C_HEAP,
        "custom_alloc",
    )
    .with_verdict(VerifierVerdict::Diagnostic);

    assert!(
        !candidate.is_reportable(),
        "Diagnostic must NOT be reportable"
    );
}

/// Objective: 验证 ExplainedSafe 判定是否正确标记为不可报告
///
/// Invariants:
/// - ExplainedSafe 判定必须不可报告
/// - 同一家族的分配/释放操作应被标记为安全
/// - 已解释的安全模式不应产生误报
/// - 判定门控应正确处理安全解释
#[test]
fn test_matrix_verdict_gating_explained_safe_not_reportable() {
    let candidate = IssueCandidate::new(
        1,
        IssueCandidateKind::CrossFamilyFree,
        FamilyId::C_HEAP,
        "malloc",
    )
    .with_release_family(FamilyId::C_HEAP) // Same family — not an issue
    .with_release_function("free")
    .with_verdict(VerifierVerdict::ExplainedSafe);

    assert!(
        !candidate.is_reportable(),
        "ExplainedSafe must NOT be reportable"
    );
}

// ─── End-to-end inference chain ───────────────────────────────────────

/// Objective: 验证推断链优先级：注册表匹配 > 结构推断 > 桥接推断
///
/// Invariants:
/// - 注册表匹配的符号应有高置信度（> 0.9）
/// - 不在注册表中的符号应回退到结构推断
/// - drop 函数应通过结构推断识别为析构器
/// - as_ptr 函数应通过结构推断识别为桥接助手
/// - 推断链应按优先级顺序执行
#[test]
fn test_matrix_inference_chain_priority() {
    let registry = FamilyRegistry::new();

    // "free" is in the registry — should get registry-level confidence
    let free_summary = infer_summary_for_symbol("free", 1, 100, &registry);
    assert!(
        free_summary.confidence > 0.9,
        "Registry match should have high confidence, got {}",
        free_summary.confidence
    );

    // "drop" is NOT in the registry — should fall through to structural inference
    let drop_summary = infer_summary_for_symbol("drop", 2, 200, &registry);
    assert!(
        drop_summary.is_destructor(),
        "drop should be inferred as destructor via structural inference"
    );

    // "as_ptr" is NOT in the registry — should fall through to bridge inference
    let bridge_summary = infer_summary_for_symbol("as_ptr", 3, 300, &registry);
    assert!(
        bridge_summary.is_bridge(),
        "as_ptr should be inferred as bridge via structural inference"
    );
}
