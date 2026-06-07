//! Shared noreturn callee recognition for resource analysis passes.
//!
//! These predicates model terminating control-flow endpoints such as
//! abort, panic, and OOM handlers.

/// Returns true when a callee terminates instead of returning normally.
pub(crate) fn is_noreturn_callee(name: &str) -> bool {
    matches!(
        name,
        "abort"
            | "_exit"
            | "_Exit"
            | "exit"
            | "quick_exit"
            | "__cxa_throw"
            | "__cxa_rethrow"
            | "core::panicking::panic"
            | "core::panicking::panic_fmt"
            | "std::rt::begin_panic"
            | "std::panicking::begin_panic"
            | "__rust_start_panic"
            | "out_of_memory"
            | "raise"
            | "__assert_fail"
            | "__assert_rtn"
            | "_assert"
    ) || name.starts_with("core::panicking")
        || name.starts_with("alloc::raw_vec")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify common abort and panic callees are terminating.
    /// Invariants: Noreturn callees match; normal allocator calls do not.
    #[test]
    fn test_noreturn_callee_recognition() {
        assert!(
            is_noreturn_callee("abort"),
            "abort should be recognized as noreturn"
        );
        assert!(
            is_noreturn_callee("__rust_start_panic"),
            "Rust panic entry should be recognized as noreturn"
        );
        assert!(
            !is_noreturn_callee("malloc"),
            "normal allocator calls must not be recognized as noreturn"
        );
    }
}
