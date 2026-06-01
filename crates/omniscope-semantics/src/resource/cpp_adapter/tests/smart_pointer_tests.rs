//! Tests for smart pointer pattern detection in C++ adapter.

use super::super::*;

/// Objective: Verify smart pointer detection
/// Invariants: unique_ptr/shared_ptr/weak_ptr must be detected
#[test]
fn test_smart_pointer_detection() {
    let adapter = CppAdapter::new();

    // unique_ptr
    let analysis =
        adapter.analyze_function("_ZNSt10unique_ptrI5ClassSt14default_deleteIS0_EEC1Ev", None);
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::UniquePtrCreation),
        "unique_ptr must be detected as UniquePtrCreation"
    );
    assert!(
        analysis.uses_smart_pointers,
        "Function with unique_ptr must have uses_smart_pointers=true"
    );

    // shared_ptr
    let analysis = adapter.analyze_function("_ZNSt10shared_ptrI5ClassEC1Ev", None);
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::SharedPtrCreation),
        "shared_ptr must be detected as SharedPtrCreation"
    );

    // weak_ptr
    let analysis = adapter.analyze_function("_ZNSt10weak_ptrI5ClassEC1Ev", None);
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::WeakPtrCreation),
        "weak_ptr must be detected as WeakPtrCreation"
    );
}

/// Objective: Verify smart pointer safety assessment
/// Invariants: Smart pointer only must be SafeSmartPointer
#[test]
fn test_smart_pointer_safety() {
    let adapter = CppAdapter::new();

    let analysis =
        adapter.analyze_function("_ZNSt10unique_ptrI5ClassSt14default_deleteIS0_EEC1Ev", None);
    assert_eq!(
        analysis.ffi_safety,
        CppFFISafety::SafeSmartPointer,
        "Smart pointer usage must be SafeSmartPointer"
    );
}

/// Objective: Verify raw allocation concern detection
/// Invariants: Raw new without delete must be ConcernRawAllocation
#[test]
fn test_raw_allocation_concern() {
    let adapter = CppAdapter::new();

    // Raw new without delete
    let analysis = adapter.analyze_function("_Znwj", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::RawNew),
        "_Znwj must be detected as RawNew"
    );
    assert_eq!(
        analysis.ffi_safety,
        CppFFISafety::ConcernRawAllocation,
        "Raw new without delete must be ConcernRawAllocation"
    );
}

/// Objective: Verify move assignment detection
/// Invariants: aSEOS must be detected as MoveAssignment
#[test]
fn test_move_assignment_detection() {
    let adapter = CppAdapter::new();

    let analysis = adapter.analyze_function("_ZN5ClassaSEOS_", None);
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::MoveAssignment),
        "aSEOS must be detected as MoveAssignment"
    );
}

/// Objective: Verify STL container detection
/// Invariants: vector/map/set must be detected as StlContainer
#[test]
fn test_stl_container_detection() {
    let adapter = CppAdapter::new();

    // vector
    let analysis = adapter.analyze_function("_ZNSt6vectorIiSaIiEE9push_backERKi", None);
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::StlContainer),
        "vector must be detected as StlContainer"
    );

    // map
    let analysis = adapter.analyze_function("_ZNSt3mapIiiSt4lessIiESaISt4pairIKiiEEEixERS4_", None);
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::StlContainer),
        "map must be detected as StlContainer"
    );

    // unordered_map
    let analysis = adapter.analyze_function(
        "_ZNSt13unordered_mapIiiSt4hashIiESt8equal_toIiESaISt4pairIKiiEEEixERS6_",
        None,
    );
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::StlContainer),
        "unordered_map must be detected as StlContainer"
    );
}

/// Objective: Verify template instantiation detection
/// Invariants: Template patterns with I/E must be detected
#[test]
fn test_template_instantiation_detection() {
    let adapter = CppAdapter::new();

    // Template instantiation with I...E pattern
    let analysis = adapter.analyze_function("_ZNSt6vectorIiSaIiEE9push_backERKi", None);
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::TemplateInstantiation),
        "Template with I...E pattern must be detected as TemplateInstantiation"
    );
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::StlContainer),
        "vector must also be detected as StlContainer"
    );
}
