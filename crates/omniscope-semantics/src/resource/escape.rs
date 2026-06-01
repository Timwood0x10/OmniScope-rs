//! Escape analysis for pointer scope tracking.
//!
//! Before reporting a leak, classify how the pointer left scope.
//! Many escapes are intentional (return-to-caller, field-store,
//! static-lifetime). Only truly unknown escapes produce leak candidates.

use omniscope_types::{EscapeKind, PointerContract};

/// Result of escape analysis for a pointer/resource.
#[derive(Debug, Clone)]
pub struct EscapeResult {
    /// How the pointer escaped.
    pub kind: EscapeKind,
    /// Pointer contract at the escape point.
    pub contract: PointerContract,
    /// Whether this escape is safe (not a leak).
    pub is_safe: bool,
    /// Human-readable explanation.
    pub reason: String,
}

impl EscapeResult {
    /// Creates an escape result.
    pub fn new(kind: EscapeKind, contract: PointerContract, reason: impl Into<String>) -> Self {
        Self {
            kind,
            contract,
            is_safe: kind.is_safe_escape() || contract.is_safe_no_free(),
            reason: reason.into(),
        }
    }
}

/// Classifies the escape kind from common patterns.
pub fn classify_escape(contract: PointerContract, context: EscapeContext) -> EscapeResult {
    match context {
        EscapeContext::ReturnToCaller => EscapeResult::new(
            EscapeKind::ReturnToCaller,
            contract,
            "pointer returned to caller — caller assumes ownership",
        ),
        EscapeContext::OutParam => EscapeResult::new(
            EscapeKind::OutParam,
            contract,
            "pointer written to output parameter — caller assumes ownership",
        ),
        EscapeContext::FieldStore => EscapeResult::new(
            EscapeKind::FieldStore,
            PointerContract::StoredInOwner,
            "pointer stored in owner field — owner is responsible",
        ),
        EscapeContext::GlobalStore => EscapeResult::new(
            EscapeKind::GlobalStore,
            contract,
            "pointer stored in global/static storage — needs investigation",
        ),
        EscapeContext::Callback => EscapeResult::new(
            EscapeKind::Callback,
            contract,
            "pointer passed to callback — callback may assume ownership",
        ),
        EscapeContext::StaticInit => EscapeResult::new(
            EscapeKind::StaticLifetime,
            PointerContract::StaticLifetime,
            "pointer initialized once in static storage — not a leak",
        ),
        EscapeContext::Unknown => EscapeResult::new(
            EscapeKind::Unknown,
            contract,
            "pointer escape mechanism unknown — leak candidate",
        ),
    }
}

/// Context describing how a pointer leaves scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EscapeContext {
    /// Returned from the function.
    ReturnToCaller,
    /// Written to an output parameter.
    OutParam,
    /// Stored in a field of an owner object.
    FieldStore,
    /// Stored in global/static storage.
    GlobalStore,
    /// Passed to a callback.
    Callback,
    /// Static initialization (process lifetime).
    StaticInit,
    /// Unknown escape mechanism.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_return_to_caller_is_safe() {
        let result = classify_escape(
            PointerContract::ReturnedToCaller,
            EscapeContext::ReturnToCaller,
        );
        assert!(result.is_safe, "ReturnToCaller escape is safe");
        assert_eq!(
            result.kind,
            EscapeKind::ReturnToCaller,
            "ReturnToCaller context must produce ReturnToCaller escape kind"
        );
    }

    #[test]
    fn test_field_store_is_safe() {
        let result = classify_escape(PointerContract::Owned, EscapeContext::FieldStore);
        assert!(result.is_safe, "FieldStore escape is safe");
    }

    #[test]
    fn test_global_store_needs_investigation() {
        let result = classify_escape(PointerContract::Owned, EscapeContext::GlobalStore);
        assert!(!result.is_safe, "GlobalStore escape needs investigation");
    }

    #[test]
    fn test_static_init_is_safe() {
        let result = classify_escape(PointerContract::Owned, EscapeContext::StaticInit);
        assert!(result.is_safe, "StaticInit is not a leak");
        assert_eq!(
            result.contract,
            PointerContract::StaticLifetime,
            "StaticInit must produce StaticLifetime contract"
        );
    }

    #[test]
    fn test_unknown_escape_is_candidate() {
        let result = classify_escape(PointerContract::Owned, EscapeContext::Unknown);
        assert!(!result.is_safe, "Unknown escape is a leak candidate");
    }
}
