//! Rust Drop tracker for RAII cleanup detection.
//!
//! Tracks Rust's RAII (Resource Acquisition Is Initialization) cleanup
//! operations to reduce false positives in resource leak analysis. When
//! Rust objects go out of scope, their `Drop` implementation is automatically
//! called, which may free resources. This tracker identifies these automatic
//! cleanup operations.
//!
//! ## Tracked Patterns
//!
//! - **Rust drop_in_place**: `_ZN4core3ptr*drop_in_place*`
//! - **Rust __rust_dealloc**: `__rust_dealloc`
//! - **C++ destructors**: `_ZN*D1Ev`, `_ZN*D0Ev`
//! - **Custom drop/cleanup/release**: `*drop*`, `*cleanup*`, `*release*`
//!
//! ## Integration
//!
//! This tracker is used by the `OwnershipSolverPass` to consider RAII
//! semantics when analyzing resource ownership transitions. Instances
//! marked as RAII cleanup are less likely to be false positives for
//! resource leak issues.

use std::collections::HashMap;

/// Information about a Drop/Raii cleanup operation.
///
/// Contains details about a specific Drop call instance, including
/// whether it's an RAII cleanup operation that should be considered
/// in ownership analysis.
#[derive(Debug, Clone)]
pub struct DropInfo {
    /// Unique identifier for the resource instance being dropped.
    pub instance_id: u64,
    /// Name of the Drop function being called.
    pub drop_function: String,
    /// Location/site where the Drop occurs (e.g., function name).
    pub drop_site: String,
    /// Whether this is an automatic RAII cleanup (vs explicit drop).
    pub is_raii_cleanup: bool,
}

/// Tracks Rust Drop operations for RAII cleanup detection.
///
/// Maintains a mapping from resource instance IDs to their Drop
/// information. This allows the ownership solver to query whether
/// a resource has been automatically cleaned up via RAII semantics.
pub struct RustDropTracker {
    /// Map from instance ID to Drop information.
    drop_instances: HashMap<u64, DropInfo>,
}

impl RustDropTracker {
    /// Creates a new Rust Drop tracker.
    ///
    /// Initializes an empty tracker with no recorded Drop operations.
    pub fn new() -> Self {
        Self {
            drop_instances: HashMap::new(),
        }
    }

    /// Tracks a Drop call for a resource instance.
    ///
    /// # Arguments
    ///
    /// * `instance_id` - Unique identifier for the resource instance
    /// * `callee` - Name of the called function (potential Drop function)
    /// * `caller` - Name of the function containing the call site
    ///
    /// # Behavior
    ///
    /// If the `callee` matches known Drop patterns, creates a `DropInfo`
    /// entry for the instance. The `is_raii_cleanup` flag is set based
    /// on whether the pattern indicates automatic RAII cleanup.
    pub fn track_drop_call(&mut self, instance_id: u64, callee: &str, caller: &str) {
        // Only track if this is a known Drop pattern
        if let Some(drop_info) = self.analyze_drop_pattern(instance_id, callee, caller) {
            self.drop_instances.insert(instance_id, drop_info);
        }
    }

    /// Checks if a resource instance has RAII cleanup.
    ///
    /// # Arguments
    ///
    /// * `instance_id` - Unique identifier for the resource instance
    ///
    /// # Returns
    ///
    /// `true` if the instance has been identified as having RAII cleanup,
    /// `false` otherwise.
    pub fn is_raii_cleanup(&self, instance_id: u64) -> bool {
        self.drop_instances
            .get(&instance_id)
            .is_some_and(|info| info.is_raii_cleanup)
    }

    /// Gets Drop information for a resource instance.
    ///
    /// # Arguments
    ///
    /// * `instance_id` - Unique identifier for the resource instance
    ///
    /// # Returns
    ///
    /// `Some(&DropInfo)` if Drop information exists for the instance,
    /// `None` otherwise.
    pub fn get_drop_info(&self, instance_id: u64) -> Option<&DropInfo> {
        self.drop_instances.get(&instance_id)
    }

    /// Analyzes a function call to determine if it's a Drop operation.
    ///
    /// # Arguments
    ///
    /// * `instance_id` - Unique identifier for the resource instance
    /// * `callee` - Name of the called function
    /// * `caller` - Name of the function containing the call site
    ///
    /// # Returns
    ///
    /// `Some(DropInfo)` if the call matches a Drop pattern, `None` otherwise.
    fn analyze_drop_pattern(
        &self,
        instance_id: u64,
        callee: &str,
        caller: &str,
    ) -> Option<DropInfo> {
        // Check for Rust drop_in_place pattern
        if self.is_rust_drop_in_place(callee) {
            return Some(DropInfo {
                instance_id,
                drop_function: callee.to_string(),
                drop_site: caller.to_string(),
                is_raii_cleanup: true,
            });
        }

        // Check for Rust __rust_dealloc pattern
        if self.is_rust_dealloc(callee) {
            return Some(DropInfo {
                instance_id,
                drop_function: callee.to_string(),
                drop_site: caller.to_string(),
                is_raii_cleanup: true,
            });
        }

        // Check for C++ destructor patterns
        if self.is_cpp_destructor(callee) {
            return Some(DropInfo {
                instance_id,
                drop_function: callee.to_string(),
                drop_site: caller.to_string(),
                is_raii_cleanup: true,
            });
        }

        // Check for custom drop/cleanup/release patterns
        if self.is_custom_drop(callee) {
            return Some(DropInfo {
                instance_id,
                drop_function: callee.to_string(),
                drop_site: caller.to_string(),
                is_raii_cleanup: false, // Custom drops may not be RAII
            });
        }

        None
    }

    /// Checks if a function name matches Rust's drop_in_place pattern.
    ///
    /// # Arguments
    ///
    /// * `callee` - Function name to check
    ///
    /// # Returns
    ///
    /// `true` if the function matches the drop_in_place pattern.
    fn is_rust_drop_in_place(&self, callee: &str) -> bool {
        // Rust mangled name: _ZN4core3ptr*drop_in_place*
        if callee.contains("drop_in_place") {
            return true;
        }

        // Rust v0 mangling: _RNv...13drop_in_place
        if callee.contains("13drop_in_place") {
            return true;
        }

        // Demangled: core::ptr::drop_in_place
        if callee.contains("::drop_in_place") {
            return true;
        }

        false
    }

    /// Checks if a function name matches Rust's __rust_dealloc pattern.
    ///
    /// # Arguments
    ///
    /// * `callee` - Function name to check
    ///
    /// # Returns
    ///
    /// `true` if the function matches the __rust_dealloc pattern.
    fn is_rust_dealloc(&self, callee: &str) -> bool {
        callee == "__rust_dealloc" || callee == "__rust_free"
    }

    /// Checks if a function name matches C++ destructor patterns.
    ///
    /// # Arguments
    ///
    /// * `callee` - Function name to check
    ///
    /// # Returns
    ///
    /// `true` if the function matches a C++ destructor pattern.
    fn is_cpp_destructor(&self, callee: &str) -> bool {
        // C++ destructors: _ZN*D1Ev, _ZN*D0Ev, _ZN*D2Ev
        if callee.starts_with("_ZN") {
            return callee.contains("D0Ev") || callee.contains("D1Ev") || callee.contains("D2Ev");
        }

        // Demangled C++ destructors: ~ClassName
        if callee.starts_with('~') {
            return true;
        }

        false
    }

    /// Checks if a function name matches custom drop/cleanup/release patterns.
    ///
    /// # Arguments
    ///
    /// * `callee` - Function name to check
    ///
    /// # Returns
    ///
    /// `true` if the function matches a custom drop pattern.
    fn is_custom_drop(&self, callee: &str) -> bool {
        // Common patterns for custom drop implementations
        let lower = callee.to_lowercase();
        lower.contains("drop") || lower.contains("cleanup") || lower.contains("release")
    }

    /// Returns the number of tracked Drop instances.
    ///
    /// # Returns
    ///
    /// The count of resource instances with tracked Drop operations.
    pub fn len(&self) -> usize {
        self.drop_instances.len()
    }

    /// Returns whether the tracker has any tracked Drop instances.
    ///
    /// # Returns
    ///
    /// `true` if no Drop instances are tracked, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.drop_instances.is_empty()
    }

    /// Clears all tracked Drop instances.
    ///
    /// Resets the tracker to an empty state.
    pub fn clear(&mut self) {
        self.drop_instances.clear();
    }
}

impl Default for RustDropTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify that RustDropTracker correctly identifies Rust drop_in_place patterns.
    /// Invariants: drop_in_place variants are recognized, non-drop patterns are rejected.
    #[test]
    fn test_rust_drop_in_place_detection() {
        let tracker = RustDropTracker::new();

        // Rust mangled name
        assert!(
            tracker.is_rust_drop_in_place("_ZN4core3ptr13drop_in_placeI3FooEEvPT_"),
            "Rust mangled drop_in_place must be recognized"
        );

        // Rust v0 mangling
        assert!(
            tracker.is_rust_drop_in_place("_RNvNtCsgXhsEb1m4tm_4core3ptr13drop_in_place"),
            "Rust v0 mangled drop_in_place must be recognized"
        );

        // Demangled name
        assert!(
            tracker.is_rust_drop_in_place("core::ptr::drop_in_place<Foo>"),
            "Demangled drop_in_place must be recognized"
        );

        // Negative: unrelated names
        assert!(
            !tracker.is_rust_drop_in_place("dropdown"),
            "Unrelated 'drop' substring must not match"
        );

        assert!(
            !tracker.is_rust_drop_in_place("malloc"),
            "malloc must not match drop_in_place"
        );
    }

    /// Objective: Verify that RustDropTracker correctly identifies __rust_dealloc patterns.
    /// Invariants: __rust_dealloc and __rust_free are recognized, other dealloc patterns are rejected.
    #[test]
    fn test_rust_dealloc_detection() {
        let tracker = RustDropTracker::new();

        assert!(
            tracker.is_rust_dealloc("__rust_dealloc"),
            "__rust_dealloc must be recognized"
        );

        assert!(
            tracker.is_rust_dealloc("__rust_free"),
            "__rust_free must be recognized"
        );

        // Negative: other dealloc patterns
        assert!(
            !tracker.is_rust_dealloc("custom_dealloc"),
            "custom_dealloc must not match __rust_dealloc"
        );

        assert!(
            !tracker.is_rust_dealloc("free"),
            "free must not match __rust_dealloc"
        );
    }

    /// Objective: Verify that RustDropTracker correctly identifies C++ destructor patterns.
    /// Invariants: Mangled and demangled destructors are recognized.
    #[test]
    fn test_cpp_destructor_detection() {
        let tracker = RustDropTracker::new();

        // Mangled destructors
        assert!(
            tracker.is_cpp_destructor("_ZN3FooD1Ev"),
            "Mangled destructor D1Ev must be recognized"
        );

        assert!(
            tracker.is_cpp_destructor("_ZN3FooD0Ev"),
            "Mangled destructor D0Ev must be recognized"
        );

        assert!(
            tracker.is_cpp_destructor("_ZN3FooD2Ev"),
            "Mangled destructor D2Ev must be recognized"
        );

        // Demangled destructor
        assert!(
            tracker.is_cpp_destructor("~Foo"),
            "Demangled destructor ~Foo must be recognized"
        );

        // Negative: non-destructor
        assert!(
            !tracker.is_cpp_destructor("_ZN3Foo3barEv"),
            "Non-destructor mangled name must not match"
        );
    }

    /// Objective: Verify that RustDropTracker correctly identifies custom drop patterns.
    /// Invariants: Custom drop/cleanup/release patterns are recognized.
    #[test]
    fn test_custom_drop_detection() {
        let tracker = RustDropTracker::new();

        assert!(
            tracker.is_custom_drop("my_drop"),
            "Custom 'drop' must be recognized"
        );

        assert!(
            tracker.is_custom_drop("cleanup_resources"),
            "Custom 'cleanup' must be recognized"
        );

        assert!(
            tracker.is_custom_drop("release_handle"),
            "Custom 'release' must be recognized"
        );

        // Negative: unrelated
        assert!(
            !tracker.is_custom_drop("malloc"),
            "malloc must not match custom drop"
        );
    }

    /// Objective: Verify that track_drop_call correctly records Drop operations.
    /// Invariants: Drop calls are recorded, non-Drop calls are ignored.
    #[test]
    fn test_track_drop_call() {
        let mut tracker = RustDropTracker::new();

        // Track a Rust drop_in_place call
        tracker.track_drop_call(1, "_ZN4core3ptr13drop_in_placeI3FooEEvPT_", "test_function");

        assert!(
            tracker.is_raii_cleanup(1),
            "Instance 1 must be marked as RAII cleanup"
        );

        let info = tracker.get_drop_info(1).unwrap();
        assert_eq!(info.instance_id, 1, "Instance ID must match");
        assert_eq!(
            info.drop_function, "_ZN4core3ptr13drop_in_placeI3FooEEvPT_",
            "Drop function must match"
        );
        assert_eq!(
            info.drop_site, "test_function",
            "Drop site must match caller"
        );
        assert!(info.is_raii_cleanup, "Must be RAII cleanup");

        // Track a __rust_dealloc call
        tracker.track_drop_call(2, "__rust_dealloc", "another_function");

        assert!(
            tracker.is_raii_cleanup(2),
            "Instance 2 must be marked as RAII cleanup"
        );

        // Track a custom drop (not RAII)
        tracker.track_drop_call(3, "my_custom_drop", "custom_function");

        assert!(
            !tracker.is_raii_cleanup(3),
            "Instance 3 must NOT be marked as RAII cleanup"
        );

        // Track a non-Drop call
        tracker.track_drop_call(4, "malloc", "allocator");

        assert!(
            !tracker.is_raii_cleanup(4),
            "Instance 4 must NOT be marked as RAII cleanup (malloc is not a drop)"
        );
        assert!(
            tracker.get_drop_info(4).is_none(),
            "Instance 4 must not have Drop info"
        );
    }

    /// Objective: Verify that RustDropTracker correctly handles multiple instances.
    /// Invariants: Each instance is tracked independently.
    #[test]
    fn test_multiple_instances() {
        let mut tracker = RustDropTracker::new();

        // Track multiple instances
        tracker.track_drop_call(10, "__rust_dealloc", "func_a");
        tracker.track_drop_call(20, "drop_in_place", "func_b");
        tracker.track_drop_call(30, "custom_cleanup", "func_c");

        assert_eq!(tracker.len(), 3, "Must track exactly 3 instances");
        assert!(!tracker.is_empty(), "Tracker must not be empty");

        // Verify each instance
        assert!(
            tracker.is_raii_cleanup(10),
            "Instance 10 must be RAII cleanup"
        );
        assert!(
            tracker.is_raii_cleanup(20),
            "Instance 20 must be RAII cleanup"
        );
        assert!(
            !tracker.is_raii_cleanup(30),
            "Instance 30 must NOT be RAII cleanup"
        );

        // Clear and verify
        tracker.clear();
        assert_eq!(tracker.len(), 0, "Must have 0 instances after clear");
        assert!(tracker.is_empty(), "Tracker must be empty after clear");
    }

    /// Objective: Verify that RustDropTracker correctly handles edge cases.
    /// Invariants: Empty strings, duplicate IDs, and invalid inputs are handled gracefully.
    #[test]
    fn test_edge_cases() {
        let mut tracker = RustDropTracker::new();

        // Empty strings
        tracker.track_drop_call(1, "", "");
        assert!(
            !tracker.is_raii_cleanup(1),
            "Empty strings must not match any pattern"
        );

        // Duplicate instance ID (second call should overwrite)
        tracker.track_drop_call(1, "__rust_dealloc", "new_function");
        assert!(
            tracker.is_raii_cleanup(1),
            "Duplicate ID must be overwritten with new info"
        );

        let info = tracker.get_drop_info(1).unwrap();
        assert_eq!(
            info.drop_function, "__rust_dealloc",
            "Must keep latest drop function"
        );
    }
}
