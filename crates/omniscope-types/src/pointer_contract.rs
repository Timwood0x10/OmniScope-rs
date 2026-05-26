//! Pointer contract types for ownership and transfer semantics.
//!
//! `PointerContract` describes ownership, not type syntax. A raw pointer
//! from `as_ptr()` has `Borrowed` contract; a pointer from `into_raw()`
//! has `Transferred` contract. This distinction is what drives correct
//! alloc/free matching — not whether the pointer is `*const T` or `*mut T`.

use serde::{Deserialize, Serialize};

/// Ownership contract for a pointer or resource reference.
///
/// This enum captures the semantic ownership state, which is more
/// nuanced than Rust's `OwnershipKind` (Owned/Borrowed/Shared/Copy/Unknown).
/// It covers cross-language idioms like `Retained` (Python INCREF),
/// `ReturnedToCaller` (factory function), and `Escaped` (stored in global).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PointerContract {
    /// Full ownership — responsible for deallocation.
    Owned,
    /// Borrowed reference — NOT responsible for deallocation.
    Borrowed,
    /// Might be owned — evidence insufficient, conservative.
    MaybeOwned,
    /// Ownership transferred to the receiver (e.g. `into_raw`).
    Transferred,
    /// Reference count incremented (e.g. `Py_INCREF`, `CFRetain`).
    Retained,
    /// Reference count decremented (e.g. `Py_DECREF`, `CFRelease`).
    Released,
    /// Ownership returned to caller (factory/constructor return).
    ReturnedToCaller,
    /// Pointer stored inside an owner object's field.
    StoredInOwner,
    /// Pointer has escaped the current scope (leak candidate).
    Escaped,
    /// GC-managed, no manual deallocation needed.
    GcManaged,
    /// Static lifetime — no deallocation expected.
    StaticLifetime,
    /// Unknown ownership contract.
    Unknown,
}

impl PointerContract {
    /// Returns true if this contract implies responsibility for deallocation.
    pub fn requires_deallocation(&self) -> bool {
        matches!(
            self,
            PointerContract::Owned
                | PointerContract::MaybeOwned
                | PointerContract::Transferred
                | PointerContract::ReturnedToCaller
        )
    }

    /// Returns true if this contract is NOT responsible for deallocation.
    pub fn is_safe_no_free(&self) -> bool {
        matches!(
            self,
            PointerContract::Borrowed
                | PointerContract::GcManaged
                | PointerContract::StaticLifetime
                | PointerContract::StoredInOwner
        )
    }

    /// Returns true if this contract involves reference counting.
    pub fn is_refcount(&self) -> bool {
        matches!(self, PointerContract::Retained | PointerContract::Released)
    }

    /// Returns a human-readable label for diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            PointerContract::Owned => "owned",
            PointerContract::Borrowed => "borrowed",
            PointerContract::MaybeOwned => "maybe_owned",
            PointerContract::Transferred => "transferred",
            PointerContract::Retained => "retained",
            PointerContract::Released => "released",
            PointerContract::ReturnedToCaller => "returned_to_caller",
            PointerContract::StoredInOwner => "stored_in_owner",
            PointerContract::Escaped => "escaped",
            PointerContract::GcManaged => "gc_managed",
            PointerContract::StaticLifetime => "static_lifetime",
            PointerContract::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_requires_deallocation() {
        assert!(
            PointerContract::Owned.requires_deallocation(),
            "Owned must require deallocation"
        );
        assert!(
            PointerContract::Transferred.requires_deallocation(),
            "Transferred must require deallocation"
        );
        assert!(
            PointerContract::ReturnedToCaller.requires_deallocation(),
            "ReturnedToCaller must require deallocation"
        );
        assert!(
            !PointerContract::Borrowed.requires_deallocation(),
            "Borrowed must NOT require deallocation"
        );
        assert!(
            !PointerContract::GcManaged.requires_deallocation(),
            "GcManaged must NOT require deallocation"
        );
    }

    #[test]
    fn test_is_safe_no_free() {
        assert!(
            PointerContract::Borrowed.is_safe_no_free(),
            "Borrowed is safe (no free needed)"
        );
        assert!(
            PointerContract::GcManaged.is_safe_no_free(),
            "GcManaged is safe (GC handles it)"
        );
        assert!(
            PointerContract::StaticLifetime.is_safe_no_free(),
            "StaticLifetime is safe (never freed)"
        );
        assert!(
            PointerContract::StoredInOwner.is_safe_no_free(),
            "StoredInOwner is safe (owner handles it)"
        );
        assert!(
            !PointerContract::Owned.is_safe_no_free(),
            "Owned is NOT safe (must be freed)"
        );
    }

    #[test]
    fn test_refcount_operations() {
        assert!(
            PointerContract::Retained.is_refcount(),
            "Retained involves refcount"
        );
        assert!(
            PointerContract::Released.is_refcount(),
            "Released involves refcount"
        );
        assert!(
            !PointerContract::Owned.is_refcount(),
            "Owned does NOT involve refcount"
        );
    }
}
