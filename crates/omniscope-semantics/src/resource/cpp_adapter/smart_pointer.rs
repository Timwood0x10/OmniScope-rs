//! Smart pointer pattern detection for C++.
//!
//! This module provides smart pointer-specific semantic analysis, including:
//! - unique_ptr, shared_ptr, weak_ptr detection
//! - Reference count operations
//! - Smart pointer safety assessment

use super::CppSemanticPattern;

/// Checks if a function name indicates a unique_ptr operation.
///
/// # Objective
/// Detect unique_ptr patterns in mangled C++ names. unique_ptr provides
/// exclusive ownership semantics and deterministic cleanup.
///
/// # Invariants
/// - Returns true for _ZNSt10unique_ptr patterns.
/// - Returns false for non-unique_ptr patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for unique_ptr patterns.
///
/// # Returns
/// `true` if the function is identified as a unique_ptr operation, `false` otherwise.
pub fn is_unique_ptr(function_name: &str) -> bool {
    function_name.contains("10unique_ptr")
}

/// Checks if a function name indicates a shared_ptr operation.
///
/// # Objective
/// Detect shared_ptr patterns in mangled C++ names. shared_ptr provides
/// shared ownership semantics with reference counting.
///
/// # Invariants
/// - Returns true for _ZNSt10shared_ptr patterns.
/// - Returns false for non-shared_ptr patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for shared_ptr patterns.
///
/// # Returns
/// `true` if the function is identified as a shared_ptr operation, `false` otherwise.
pub fn is_shared_ptr(function_name: &str) -> bool {
    function_name.contains("10shared_ptr")
}

/// Checks if a function name indicates a weak_ptr operation.
///
/// # Objective
/// Detect weak_ptr patterns in mangled C++ names. weak_ptr provides
/// non-owning observation of shared_ptr-managed objects.
///
/// # Invariants
/// - Returns true for _ZNSt10weak_ptr patterns.
/// - Returns false for non-weak_ptr patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for weak_ptr patterns.
///
/// # Returns
/// `true` if the function is identified as a weak_ptr operation, `false` otherwise.
pub fn is_weak_ptr(function_name: &str) -> bool {
    function_name.contains("10weak_ptr")
}

/// Checks if a function name indicates a reference count increment.
///
/// # Objective
/// Detect reference count increment patterns in mangled C++ names.
/// Reference counting is used by shared_ptr for shared ownership.
///
/// # Invariants
/// - Returns true for _M_add_ref or __add_ref patterns.
/// - Returns false for non-reference-count patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for reference count increment.
///
/// # Returns
/// `true` if the function is identified as a reference count increment, `false` otherwise.
pub fn is_refcount_increment(function_name: &str) -> bool {
    function_name.contains("_M_add_ref") || function_name.contains("__add_ref")
}

/// Checks if a function name indicates a reference count decrement.
///
/// # Objective
/// Detect reference count decrement patterns in mangled C++ names.
/// Reference counting is used by shared_ptr for shared ownership.
///
/// # Invariants
/// - Returns true for _M_release or __release patterns.
/// - Returns false for non-reference-count patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for reference count decrement.
///
/// # Returns
/// `true` if the function is identified as a reference count decrement, `false` otherwise.
pub fn is_refcount_decrement(function_name: &str) -> bool {
    function_name.contains("_M_release") || function_name.contains("__release")
}

/// Checks if a function name indicates a move assignment operator.
///
/// # Objective
/// Detect move assignment operator patterns in mangled C++ names.
/// Move assignment transfers ownership from the source object.
///
/// # Invariants
/// - Returns true for aSEOS or aSEO patterns.
/// - Returns false for non-move-assignment patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for move assignment patterns.
///
/// # Returns
/// `true` if the function is identified as a move assignment operator, `false` otherwise.
pub fn is_move_assignment(function_name: &str) -> bool {
    function_name.starts_with("_Z")
        && (function_name.contains("aSEOS") || function_name.contains("aSEO"))
}

/// Checks if a function name indicates a std::move call.
///
/// # Objective
/// Detect std::move patterns in function names. std::move is used to
/// cast an object to an rvalue reference for move semantics.
///
/// # Invariants
/// - Returns true for std::move or 4move patterns.
/// - Returns false for non-std::move patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for std::move patterns.
///
/// # Returns
/// `true` if the function is identified as a std::move call, `false` otherwise.
pub fn is_std_move(function_name: &str) -> bool {
    function_name.contains("std::move") || function_name.contains("4move")
}

/// Detects smart pointer patterns from a function name.
///
/// # Objective
/// Collect all smart pointer-related semantic patterns from a function name.
/// This provides a convenient way to get all smart pointer patterns in one call.
///
/// # Arguments
/// * `function_name` - The function name to analyze for smart pointer patterns.
///
/// # Returns
/// A Vec of `CppSemanticPattern` containing detected smart pointer patterns.
pub fn detect_smart_pointer_patterns(function_name: &str) -> Vec<CppSemanticPattern> {
    let mut patterns = Vec::new();

    if is_unique_ptr(function_name) {
        patterns.push(CppSemanticPattern::UniquePtrCreation);
    }
    if is_shared_ptr(function_name) {
        patterns.push(CppSemanticPattern::SharedPtrCreation);
    }
    if is_weak_ptr(function_name) {
        patterns.push(CppSemanticPattern::WeakPtrCreation);
    }
    if is_refcount_increment(function_name) {
        patterns.push(CppSemanticPattern::RefCountIncrement);
    }
    if is_refcount_decrement(function_name) {
        patterns.push(CppSemanticPattern::RefCountDecrement);
    }
    if is_move_assignment(function_name) {
        patterns.push(CppSemanticPattern::MoveAssignment);
    }
    if is_std_move(function_name) {
        patterns.push(CppSemanticPattern::StdMove);
    }

    patterns
}

/// Checks if a function uses smart pointers.
///
/// # Objective
/// Determine whether a function uses any smart pointer types. This is
/// used for feature flag detection in function analysis.
///
/// # Arguments
/// * `function_name` - The function name to check for smart pointer usage.
///
/// # Returns
/// `true` if the function uses smart pointers, `false` otherwise.
pub fn uses_smart_pointers(function_name: &str) -> bool {
    is_unique_ptr(function_name) || is_shared_ptr(function_name) || is_weak_ptr(function_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_ptr_detection() {
        // unique_ptr constructor
        assert!(
            is_unique_ptr("_ZNSt10unique_ptrI5ClassSt14default_deleteIS0_EEC1Ev"),
            "unique_ptr constructor must be detected"
        );
        // Non-unique_ptr
        assert!(
            !is_unique_ptr("_ZN5Class5methodEv"),
            "Non-unique_ptr must not be detected"
        );
    }

    #[test]
    fn test_shared_ptr_detection() {
        // shared_ptr constructor
        assert!(
            is_shared_ptr("_ZNSt10shared_ptrI5ClassEC1Ev"),
            "shared_ptr constructor must be detected"
        );
        // Non-shared_ptr
        assert!(
            !is_shared_ptr("_ZN5Class5methodEv"),
            "Non-shared_ptr must not be detected"
        );
    }

    #[test]
    fn test_weak_ptr_detection() {
        // weak_ptr constructor
        assert!(
            is_weak_ptr("_ZNSt10weak_ptrI5ClassEC1Ev"),
            "weak_ptr constructor must be detected"
        );
        // Non-weak_ptr
        assert!(
            !is_weak_ptr("_ZN5Class5methodEv"),
            "Non-weak_ptr must not be detected"
        );
    }

    #[test]
    fn test_refcount_operations() {
        // Reference count increment
        assert!(
            is_refcount_increment(
                "_ZNSt14__shared_countILN9__gnu_cxx12_Lock_policyE2EE10_M_add_refEv"
            ),
            "_M_add_ref must be detected as RefCountIncrement"
        );
        // Reference count decrement
        assert!(
            is_refcount_decrement(
                "_ZNSt14__shared_countILN9__gnu_cxx12_Lock_policyE2EE10_M_releaseEv"
            ),
            "_M_release must be detected as RefCountDecrement"
        );
    }

    #[test]
    fn test_move_assignment_detection() {
        // Move assignment operator
        assert!(
            is_move_assignment("_ZN5ClassaSEOS_"),
            "Move assignment operator must be detected"
        );
        // Non-move assignment
        assert!(
            !is_move_assignment("_ZN5ClassaSERKS_"),
            "Copy assignment must not be detected"
        );
    }

    #[test]
    fn test_std_move_detection() {
        // std::move
        assert!(is_std_move("std::move"), "std::move must be detected");
        // Mangled std::move
        assert!(is_std_move("4move"), "Mangled std::move must be detected");
        // Non-std::move
        assert!(!is_std_move("move"), "Non-std::move must not be detected");
    }

    #[test]
    fn test_detect_smart_pointer_patterns() {
        // unique_ptr
        let patterns =
            detect_smart_pointer_patterns("_ZNSt10unique_ptrI5ClassSt14default_deleteIS0_EEC1Ev");
        assert!(
            patterns.contains(&CppSemanticPattern::UniquePtrCreation),
            "unique_ptr must be detected"
        );

        // shared_ptr
        let patterns = detect_smart_pointer_patterns("_ZNSt10shared_ptrI5ClassEC1Ev");
        assert!(
            patterns.contains(&CppSemanticPattern::SharedPtrCreation),
            "shared_ptr must be detected"
        );

        // weak_ptr
        let patterns = detect_smart_pointer_patterns("_ZNSt10weak_ptrI5ClassEC1Ev");
        assert!(
            patterns.contains(&CppSemanticPattern::WeakPtrCreation),
            "weak_ptr must be detected"
        );
    }

    #[test]
    fn test_uses_smart_pointers() {
        // unique_ptr
        assert!(
            uses_smart_pointers("_ZNSt10unique_ptrI5ClassSt14default_deleteIS0_EEC1Ev"),
            "unique_ptr must be detected as smart pointer"
        );
        // shared_ptr
        assert!(
            uses_smart_pointers("_ZNSt10shared_ptrI5ClassEC1Ev"),
            "shared_ptr must be detected as smart pointer"
        );
        // weak_ptr
        assert!(
            uses_smart_pointers("_ZNSt10weak_ptrI5ClassEC1Ev"),
            "weak_ptr must be detected as smart pointer"
        );
        // Non-smart pointer
        assert!(
            !uses_smart_pointers("_ZN5Class5methodEv"),
            "Non-smart pointer must not be detected"
        );
    }
}
