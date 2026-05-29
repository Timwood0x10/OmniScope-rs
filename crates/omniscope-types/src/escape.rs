//! Escape kind classification for pointer and resource escape analysis.
//!
//! Before reporting a leak, classify HOW the pointer escaped the current
//! scope. Many escapes are intentional and safe (returning to caller,
//! storing in owner). Only truly unexplained escapes should produce
//! high-severity leak candidates.

use serde::{Deserialize, Serialize};

/// How a pointer or resource reference leaves the current scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscapeKind {
    /// Returned to caller — caller assumes ownership.
    ReturnToCaller,
    /// Written to an output parameter — caller assumes ownership.
    OutParam,
    /// Stored in a field of an owner object — owner is responsible.
    FieldStore,
    /// Stored in global/static storage — lives for process lifetime.
    GlobalStore,
    /// Passed to a callback — callback may assume ownership.
    Callback,
    /// Passed to another thread — thread may assume ownership.
    Thread,
    /// Stored in a container (Vec, HashMap, etc.) — container owns it.
    Container,
    /// Static lifetime — never deallocated, not a leak.
    StaticLifetime,
    /// Escaped via raw pointer (Box::into_raw, CString::into_raw).
    /// Ownership is tracked outside Rust's type system, not a leak per se.
    RawPointer,
    /// Unknown escape — cannot determine how it left scope.
    Unknown,
}

impl EscapeKind {
    /// Returns true if this escape kind is generally safe (not a leak).
    pub fn is_safe_escape(&self) -> bool {
        matches!(
            self,
            EscapeKind::ReturnToCaller
                | EscapeKind::OutParam
                | EscapeKind::FieldStore
                | EscapeKind::Container
                | EscapeKind::StaticLifetime
        )
    }

    /// Returns true if this escape kind needs further investigation.
    pub fn needs_investigation(&self) -> bool {
        matches!(
            self,
            EscapeKind::GlobalStore
                | EscapeKind::Callback
                | EscapeKind::Thread
                | EscapeKind::RawPointer
                | EscapeKind::Unknown
        )
    }

    /// Returns a human-readable label for diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            EscapeKind::ReturnToCaller => "return_to_caller",
            EscapeKind::OutParam => "out_param",
            EscapeKind::FieldStore => "field_store",
            EscapeKind::GlobalStore => "global_store",
            EscapeKind::Callback => "callback",
            EscapeKind::Thread => "thread",
            EscapeKind::Container => "container",
            EscapeKind::StaticLifetime => "static_lifetime",
            EscapeKind::RawPointer => "raw_pointer",
            EscapeKind::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_escapes() {
        assert!(
            EscapeKind::ReturnToCaller.is_safe_escape(),
            "ReturnToCaller is safe"
        );
        assert!(
            EscapeKind::FieldStore.is_safe_escape(),
            "FieldStore is safe"
        );
        assert!(EscapeKind::Container.is_safe_escape(), "Container is safe");
        assert!(
            EscapeKind::StaticLifetime.is_safe_escape(),
            "StaticLifetime is safe"
        );
        assert!(
            !EscapeKind::GlobalStore.is_safe_escape(),
            "GlobalStore needs investigation"
        );
    }

    #[test]
    fn test_needs_investigation() {
        assert!(
            EscapeKind::Unknown.needs_investigation(),
            "Unknown needs investigation"
        );
        assert!(
            EscapeKind::Callback.needs_investigation(),
            "Callback needs investigation"
        );
        assert!(
            !EscapeKind::ReturnToCaller.needs_investigation(),
            "ReturnToCaller is safe"
        );
    }
}
