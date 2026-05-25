//! Ownership types for memory safety analysis
//!
//! This module defines ownership-related types for tracking pointer ownership
//! and lifetime information.

use serde::{Deserialize, Serialize};

/// Ownership information for a value
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ownership {
    /// Kind of ownership
    pub kind: OwnershipKind,
    /// Whether the value is mutable
    pub mutable: bool,
    /// Lifetime identifier (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<LifetimeId>,
}

impl Ownership {
    /// Creates owned ownership
    pub fn owned() -> Self {
        Self {
            kind: OwnershipKind::Owned,
            mutable: true,
            lifetime: None,
        }
    }

    /// Creates borrowed ownership
    pub fn borrowed(mutable: bool) -> Self {
        Self {
            kind: OwnershipKind::Borrowed,
            mutable,
            lifetime: None,
        }
    }

    /// Creates shared ownership
    pub fn shared() -> Self {
        Self {
            kind: OwnershipKind::Shared,
            mutable: false,
            lifetime: None,
        }
    }

    /// Returns true if this is owned
    pub fn is_owned(&self) -> bool {
        matches!(self.kind, OwnershipKind::Owned)
    }

    /// Returns true if this is borrowed
    pub fn is_borrowed(&self) -> bool {
        matches!(self.kind, OwnershipKind::Borrowed)
    }
}

/// Kind of ownership
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum OwnershipKind {
    /// Full ownership (responsible for deallocation)
    Owned,
    /// Borrowed reference (not responsible for deallocation)
    Borrowed,
    /// Shared ownership (e.g., Arc)
    Shared,
    /// Copy semantics (no ownership)
    Copy,
    /// Unknown ownership
    #[default]
    Unknown,
}

/// Lifetime identifier
pub type LifetimeId = u32;

/// Lifetime information
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Lifetime {
    /// Lifetime identifier
    pub id: LifetimeId,
    /// Whether this is a static lifetime
    pub is_static: bool,
    /// Parent lifetime (for subtyping)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<LifetimeId>,
}

impl Lifetime {
    /// Creates a static lifetime
    pub fn static_lifetime() -> Self {
        Self {
            id: 0,
            is_static: true,
            parent: None,
        }
    }

    /// Creates a new lifetime with ID
    pub fn new(id: LifetimeId) -> Self {
        Self {
            id,
            is_static: false,
            parent: None,
        }
    }

    /// Sets parent lifetime
    pub fn with_parent(mut self, parent: LifetimeId) -> Self {
        self.parent = Some(parent);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ownership_creation() {
        let owned = Ownership::owned();
        assert!(owned.is_owned(), "Owned ownership should report as owned");
        assert!(
            !owned.is_borrowed(),
            "Owned ownership should not report as borrowed"
        );
        assert!(
            owned.mutable,
            "Owned ownership should be mutable by default"
        );

        let borrowed = Ownership::borrowed(true);
        assert!(
            borrowed.is_borrowed(),
            "Borrowed ownership should report as borrowed"
        );
        assert!(
            borrowed.mutable,
            "Mutable borrow should be marked as mutable"
        );

        let shared = Ownership::shared();
        assert!(!shared.mutable, "Shared ownership should be immutable");
    }

    #[test]
    fn test_lifetime() {
        let static_lt = Lifetime::static_lifetime();
        assert!(
            static_lt.is_static,
            "Static lifetime should be marked as static"
        );
        assert_eq!(static_lt.id, 0, "Static lifetime should have ID 0");

        let lt = Lifetime::new(1).with_parent(0);
        assert!(!lt.is_static, "Lifetime with parent should not be static");
        assert_eq!(lt.parent, Some(0), "Parent should be correctly set");
    }

    #[test]
    fn test_ownership_transfer() {
        // Test ownership transfer semantics
        let owned = Ownership::owned();
        assert_eq!(
            owned.kind,
            OwnershipKind::Owned,
            "Owned ownership should have Owned kind"
        );
        assert!(!owned.is_borrowed(), "Owned value should not be borrowed");

        let borrowed = Ownership::borrowed(true);
        assert_eq!(
            borrowed.kind,
            OwnershipKind::Borrowed,
            "Borrowed ownership should have Borrowed kind"
        );
        assert!(
            borrowed.is_borrowed(),
            "Borrowed value should report as borrowed"
        );

        // Test that owned and borrowed are distinct
        assert_ne!(
            owned.kind, borrowed.kind,
            "Owned and Borrowed should be different kinds"
        );

        // Test shared ownership
        let shared = Ownership::shared();
        assert_eq!(
            shared.kind,
            OwnershipKind::Shared,
            "Shared ownership should have Shared kind"
        );
        assert!(
            !shared.mutable,
            "Shared ownership should be immutable by default"
        );
    }
}
