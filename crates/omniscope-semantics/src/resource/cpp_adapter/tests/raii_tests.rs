//! Tests for RAII pattern detection in C++ adapter.

use super::super::*;

/// Objective: Verify constructor detection from mangled names
/// Invariants: C1/C2/CI patterns must be detected as Constructor
#[test]
fn test_constructor_detection() {
    let adapter = CppAdapter::new();

    // Complete constructor (C1)
    let analysis = adapter.analyze_function("_ZN5ClassC1Ev", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::Constructor),
        "C1 constructor must be detected as Constructor"
    );

    // Base constructor (C2)
    let analysis = adapter.analyze_function("_ZN5ClassC2Ei", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::Constructor),
        "C2 constructor must be detected as Constructor"
    );

    // In-charge constructor (CI)
    let analysis = adapter.analyze_function("_ZN5ClassCIvE", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::Constructor),
        "CI constructor must be detected as Constructor"
    );
}

/// Objective: Verify destructor detection from mangled names
/// Invariants: D0/D1/D2 patterns must be detected as Destructor
#[test]
fn test_destructor_detection() {
    let adapter = CppAdapter::new();

    // Complete destructor (D1)
    let analysis = adapter.analyze_function("_ZN5ClassD1Ev", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::Destructor),
        "D1 destructor must be detected as Destructor"
    );
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::VirtualDestructor),
        "D1Ev destructor must be detected as VirtualDestructor"
    );

    // Deleting destructor (D0)
    let analysis = adapter.analyze_function("_ZN5ClassD0Ev", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::Destructor),
        "D0 destructor must be detected as Destructor"
    );
}

/// Objective: Verify move constructor detection
/// Invariants: EOS patterns must be detected as MoveConstructor
#[test]
fn test_move_constructor_detection() {
    let adapter = CppAdapter::new();

    // Move constructor with EOS pattern
    let analysis = adapter.analyze_function("_ZN5ClassCI5ClassEOS0_", None);
    assert!(
        analysis
            .patterns
            .contains(&CppSemanticPattern::MoveConstructor),
        "Move constructor with EOS must be detected as MoveConstructor"
    );
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::Constructor),
        "Move constructor must also be detected as Constructor"
    );
}

/// Objective: Verify RAII guard detection
/// Invariants: lock_guard/unique_lock must be detected as RaiiGuard
#[test]
fn test_raii_guard_detection() {
    let adapter = CppAdapter::new();

    // lock_guard
    let analysis = adapter.analyze_function("lock_guard_constructor", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::RaiiGuard),
        "lock_guard must be detected as RaiiGuard"
    );
    assert!(
        analysis.uses_raii,
        "Function with lock_guard must have uses_raii=true"
    );

    // unique_lock
    let analysis = adapter.analyze_function("unique_lock_acquire", None);
    assert!(
        analysis.patterns.contains(&CppSemanticPattern::RaiiGuard),
        "unique_lock must be detected as RaiiGuard"
    );
}

/// Objective: Verify RAII safety assessment
/// Invariants: Constructor + Destructor must be SafeRAII
#[test]
fn test_raii_safety_assessment() {
    let adapter = CppAdapter::new();

    // RAII with balanced constructor/destructor
    let analysis = adapter.analyze_function("_ZN5ClassC1Ev", None);
    // Simulate destructor by adding it manually
    let mut patterns = analysis.patterns;
    patterns.push(CppSemanticPattern::Destructor);

    let ffi_safety = adapter.determine_ffi_safety("_ZN5ClassC1Ev", &patterns, None);
    assert_eq!(
        ffi_safety,
        CppFFISafety::SafeRAII,
        "RAII with balanced constructor/destructor must be SafeRAII"
    );
}
