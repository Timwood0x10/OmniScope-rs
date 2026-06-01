//! RAII (Resource Acquisition Is Initialization) pattern detection for C++.
//!
//! This module provides RAII-specific semantic analysis, including:
//! - Constructor and destructor detection
//! - RAII guard object detection (lock_guard, unique_lock, scoped_lock)
//! - Balanced resource management verification

use super::CppSemanticPattern;

/// Checks if a function name indicates a constructor.
///
/// # Objective
/// Detect constructor patterns in mangled C++ names using Itanium ABI
/// conventions. Constructors are identified by C1 (complete), C2 (base),
/// or CI (in-charge) suffixes.
///
/// # Invariants
/// - Returns true for C1E, C2E, or CI patterns in mangled names.
/// - Returns false for non-mangled names or destructor patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for constructor patterns.
///
/// # Returns
/// `true` if the function is identified as a constructor, `false` otherwise.
pub fn is_constructor(function_name: &str) -> bool {
    function_name.starts_with("_Z")
        && (function_name.contains("C1E")
            || function_name.contains("C2E")
            || function_name.contains("CI"))
}

/// Checks if a function name indicates a destructor.
///
/// # Objective
/// Detect destructor patterns in mangled C++ names using Itanium ABI
/// conventions. Destructors are identified by D0 (deleting), D1 (complete),
/// or D2 (base) suffixes.
///
/// # Invariants
/// - Returns true for D0E, D1E, or D2E patterns in mangled names.
/// - Returns false for non-mangled names or constructor patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for destructor patterns.
///
/// # Returns
/// `true` if the function is identified as a destructor, `false` otherwise.
pub fn is_destructor(function_name: &str) -> bool {
    function_name.starts_with("_Z")
        && (function_name.contains("D0E")
            || function_name.contains("D1E")
            || function_name.contains("D2E"))
}

/// Checks if a function name indicates a RAII guard object.
///
/// # Objective
/// Detect RAII guard objects that provide automatic resource management
/// through deterministic cleanup. Common RAII guards include mutex locks,
/// file handles, and other scoped resources.
///
/// # Invariants
/// - Returns true for lock_guard, unique_lock, scoped_lock, and RAII patterns.
/// - Returns false for non-RAII patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for RAII guard patterns.
///
/// # Returns
/// `true` if the function is identified as a RAII guard, `false` otherwise.
pub fn is_raii_guard(function_name: &str) -> bool {
    function_name.contains("lock_guard")
        || function_name.contains("unique_lock")
        || function_name.contains("scoped_lock")
        || function_name.contains("RAII")
}

/// Checks if a function name indicates a move constructor.
///
/// # Objective
/// Detect move constructor patterns in mangled C++ names. Move constructors
/// are identified by EOS (other source) or OE patterns in the parameter list.
///
/// # Invariants
/// - Returns true for move constructor patterns (EOS, OE).
/// - Must be called after confirming the function is a constructor.
///
/// # Arguments
/// * `function_name` - The function name to check for move constructor patterns.
///
/// # Returns
/// `true` if the function is identified as a move constructor, `false` otherwise.
pub fn is_move_constructor(function_name: &str) -> bool {
    is_constructor(function_name) && (function_name.contains("EOS") || function_name.contains("OE"))
}

/// Checks if a function name indicates a virtual destructor.
///
/// # Objective
/// Detect virtual destructor patterns in mangled C++ names. Virtual
/// destructors are common in polymorphic classes and are identified
/// by D0Ev or D1Ev patterns.
///
/// # Invariants
/// - Returns true for D0Ev or D1Ev patterns.
/// - Must be called after confirming the function is a destructor.
///
/// # Arguments
/// * `function_name` - The function name to check for virtual destructor patterns.
///
/// # Returns
/// `true` if the function is identified as a virtual destructor, `false` otherwise.
pub fn is_virtual_destructor(function_name: &str) -> bool {
    is_destructor(function_name)
        && (function_name.contains("D0Ev") || function_name.contains("D1Ev"))
}

/// Detects RAII patterns from a function name.
///
/// # Objective
/// Collect all RAII-related semantic patterns from a function name.
/// This provides a convenient way to get all RAII patterns in one call.
///
/// # Arguments
/// * `function_name` - The function name to analyze for RAII patterns.
///
/// # Returns
/// A Vec of `CppSemanticPattern` containing detected RAII patterns.
pub fn detect_raii_patterns(function_name: &str) -> Vec<CppSemanticPattern> {
    let mut patterns = Vec::new();

    if is_constructor(function_name) {
        patterns.push(CppSemanticPattern::Constructor);
        if is_move_constructor(function_name) {
            patterns.push(CppSemanticPattern::MoveConstructor);
        }
    }

    if is_destructor(function_name) {
        patterns.push(CppSemanticPattern::Destructor);
        if is_virtual_destructor(function_name) {
            patterns.push(CppSemanticPattern::VirtualDestructor);
        }
    }

    if is_raii_guard(function_name) {
        patterns.push(CppSemanticPattern::RaiiGuard);
    }

    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constructor_detection() {
        // Complete constructor (C1)
        assert!(
            is_constructor("_ZN5ClassC1Ev"),
            "C1 constructor must be detected"
        );
        // Base constructor (C2)
        assert!(
            is_constructor("_ZN5ClassC2Ei"),
            "C2 constructor must be detected"
        );
        // In-charge constructor (CI)
        assert!(
            is_constructor("_ZN5ClassCIvE"),
            "CI constructor must be detected"
        );
        // Non-constructor
        assert!(
            !is_constructor("_ZN5Class5methodEv"),
            "Non-constructor must not be detected"
        );
    }

    #[test]
    fn test_destructor_detection() {
        // Complete destructor (D1)
        assert!(
            is_destructor("_ZN5ClassD1Ev"),
            "D1 destructor must be detected"
        );
        // Deleting destructor (D0)
        assert!(
            is_destructor("_ZN5ClassD0Ev"),
            "D0 destructor must be detected"
        );
        // Base destructor (D2)
        assert!(
            is_destructor("_ZN5ClassD2Ev"),
            "D2 destructor must be detected"
        );
        // Non-destructor
        assert!(
            !is_destructor("_ZN5Class5methodEv"),
            "Non-destructor must not be detected"
        );
    }

    #[test]
    fn test_raii_guard_detection() {
        // lock_guard
        assert!(
            is_raii_guard("lock_guard_constructor"),
            "lock_guard must be detected"
        );
        // unique_lock
        assert!(
            is_raii_guard("unique_lock_acquire"),
            "unique_lock must be detected"
        );
        // scoped_lock
        assert!(
            is_raii_guard("scoped_lock_lock"),
            "scoped_lock must be detected"
        );
        // Non-RAII
        assert!(
            !is_raii_guard("normal_function"),
            "Non-RAII must not be detected"
        );
    }

    #[test]
    fn test_move_constructor_detection() {
        // Move constructor with EOS pattern
        assert!(
            is_move_constructor("_ZN5ClassCI5ClassEOS0_"),
            "Move constructor with EOS must be detected"
        );
        // Non-move constructor
        assert!(
            !is_move_constructor("_ZN5ClassC1Ev"),
            "Non-move constructor must not be detected"
        );
    }

    #[test]
    fn test_virtual_destructor_detection() {
        // Virtual destructor with D1Ev
        assert!(
            is_virtual_destructor("_ZN5ClassD1Ev"),
            "Virtual destructor with D1Ev must be detected"
        );
        // Virtual destructor with D0Ev
        assert!(
            is_virtual_destructor("_ZN5ClassD0Ev"),
            "Virtual destructor with D0Ev must be detected"
        );
        // Non-virtual destructor
        assert!(
            !is_virtual_destructor("_ZN5ClassD2Ev"),
            "Non-virtual destructor must not be detected"
        );
    }

    #[test]
    fn test_detect_raii_patterns() {
        // Constructor
        let patterns = detect_raii_patterns("_ZN5ClassC1Ev");
        assert!(
            patterns.contains(&CppSemanticPattern::Constructor),
            "Constructor must be detected"
        );

        // Destructor
        let patterns = detect_raii_patterns("_ZN5ClassD1Ev");
        assert!(
            patterns.contains(&CppSemanticPattern::Destructor),
            "Destructor must be detected"
        );
        assert!(
            patterns.contains(&CppSemanticPattern::VirtualDestructor),
            "VirtualDestructor must be detected"
        );

        // RAII guard
        let patterns = detect_raii_patterns("lock_guard_constructor");
        assert!(
            patterns.contains(&CppSemanticPattern::RaiiGuard),
            "RaiiGuard must be detected"
        );
    }
}
