//! Fact system for OmniScope
//!
//! Facts represent analysis findings that can be used by multiple passes.
//! This module provides a concurrent fact storage system with efficient indexing.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Unique identifier for facts
pub type FactId = u64;

/// Kind of fact
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FactKind {
    /// Memory allocation site
    AllocSite,
    /// Memory deallocation site
    DeallocSite,
    /// Taint source (e.g., user input)
    TaintSource,
    /// Taint sink (e.g., dangerous function)
    TaintSink,
    /// FFI boundary crossing
    FFIBoundary,
    /// Unsafe operation
    UnsafeOp,
    /// Pointer dereference
    PointerDeref,
    /// Function call
    FunctionCall,
    /// Lock acquisition
    LockAcquire,
    /// Lock release
    LockRelease,
    /// Thread spawn
    ThreadSpawn,
    /// Callback registration
    CallbackReg,
}

impl FactKind {
    /// Returns true if this is a memory-related fact
    pub fn is_memory(&self) -> bool {
        matches!(
            self,
            FactKind::AllocSite | FactKind::DeallocSite | FactKind::PointerDeref
        )
    }

    /// Returns true if this is a taint-related fact
    pub fn is_taint(&self) -> bool {
        matches!(self, FactKind::TaintSource | FactKind::TaintSink)
    }

    /// Returns true if this is a concurrency-related fact
    pub fn is_concurrency(&self) -> bool {
        matches!(
            self,
            FactKind::LockAcquire | FactKind::LockRelease | FactKind::ThreadSpawn
        )
    }
}

/// Source location for a fact
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FactLocation {
    /// File path
    pub file: PathBuf,
    /// Line number
    pub line: u32,
    /// Column number (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

impl FactLocation {
    /// Creates a new fact location
    pub fn new(file: PathBuf, line: u32) -> Self {
        Self {
            file,
            line,
            column: None,
        }
    }

    /// Adds column information
    pub fn with_column(mut self, column: u32) -> Self {
        self.column = Some(column);
        self
    }
}

/// A single fact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    /// Unique identifier
    pub id: FactId,
    /// Kind of fact
    pub kind: FactKind,
    /// Source location
    pub location: FactLocation,
    /// Additional metadata
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
    /// Confidence level (0.0 to 1.0)
    pub confidence: f32,
}

impl Fact {
    /// Creates a new fact
    pub fn new(id: FactId, kind: FactKind, location: FactLocation) -> Self {
        Self {
            id,
            kind,
            location,
            metadata: HashMap::new(),
            confidence: 1.0,
        }
    }

    /// Adds metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Sets confidence level
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Gets metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

/// Thread-safe fact store
#[derive(Debug)]
pub struct FactStore {
    /// All facts
    facts: DashMap<FactId, Fact>,
    /// Facts indexed by kind
    by_kind: DashMap<FactKind, Vec<FactId>>,
    /// Facts indexed by file
    by_file: DashMap<PathBuf, Vec<FactId>>,
    /// Next fact ID
    next_id: AtomicU64,
}

impl FactStore {
    /// Creates a new fact store
    pub fn new() -> Self {
        Self {
            facts: DashMap::new(),
            by_kind: DashMap::new(),
            by_file: DashMap::new(),
            next_id: AtomicU64::new(1),
        }
    }

    /// Adds a new fact
    pub fn add(&self, mut fact: Fact) -> FactId {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        fact.id = id;

        // Index by kind
        self.by_kind.entry(fact.kind).or_default().push(id);

        // Index by file
        self.by_file
            .entry(fact.location.file.clone())
            .or_default()
            .push(id);

        // Store fact
        self.facts.insert(id, fact);

        id
    }

    /// Gets a fact by ID
    pub fn get(&self, id: FactId) -> Option<Fact> {
        self.facts.get(&id).map(|r| r.clone())
    }

    /// Gets all facts of a kind
    pub fn by_kind(&self, kind: FactKind) -> Vec<Fact> {
        self.by_kind
            .get(&kind)
            .map(|ids| ids.iter().filter_map(|id| self.get(*id)).collect())
            .unwrap_or_default()
    }

    /// Gets all facts in a file
    pub fn by_file(&self, file: &PathBuf) -> Vec<Fact> {
        self.by_file
            .get(file)
            .map(|ids| ids.iter().filter_map(|id| self.get(*id)).collect())
            .unwrap_or_default()
    }

    /// Gets all facts
    pub fn all(&self) -> Vec<Fact> {
        self.facts.iter().map(|r| r.clone()).collect()
    }

    /// Returns the count of facts
    pub fn count(&self) -> usize {
        self.facts.len()
    }

    /// Returns the count of facts of a kind
    pub fn count_by_kind(&self, kind: FactKind) -> usize {
        self.by_kind(kind).len()
    }

    /// Clears all facts
    pub fn clear(&self) {
        self.facts.clear();
        self.by_kind.clear();
        self.by_file.clear();
    }

    /// Removes a fact by ID
    pub fn remove(&self, id: FactId) -> Option<Fact> {
        let fact = self.facts.remove(&id).map(|(_, f)| f)?;

        // Remove from kind index
        if let Some(mut ids) = self.by_kind.get_mut(&fact.kind) {
            ids.retain(|&fid| fid != id);
        }

        // Remove from file index
        if let Some(mut ids) = self.by_file.get_mut(&fact.location.file) {
            ids.retain(|&fid| fid != id);
        }

        Some(fact)
    }
}

impl Default for FactStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_fact_creation() {
        let fact = Fact::new(
            1,
            FactKind::AllocSite,
            FactLocation::new(PathBuf::from("test.rs"), 10),
        )
        .with_metadata("size", "1024")
        .with_confidence(0.95);

        assert_eq!(fact.id, 1, "Fact should have correct ID");
        assert_eq!(
            fact.kind,
            FactKind::AllocSite,
            "Fact should be AllocSite kind"
        );
        assert_eq!(fact.confidence, 0.95, "Fact should have correct confidence");
        assert_eq!(
            fact.get_metadata("size"),
            Some(&"1024".to_string()),
            "Fact should have correct metadata"
        );
    }

    #[test]
    fn test_fact_store() {
        let store = FactStore::new();

        let fact1 = Fact::new(
            0,
            FactKind::AllocSite,
            FactLocation::new(PathBuf::from("test.rs"), 10),
        );
        let fact2 = Fact::new(
            0,
            FactKind::DeallocSite,
            FactLocation::new(PathBuf::from("test.rs"), 20),
        );

        let id1 = store.add(fact1);
        let id2 = store.add(fact2);

        assert_ne!(
            id1, id2,
            "Fact store should assign different IDs to different facts"
        );
        assert_eq!(store.count(), 2, "Fact store should contain two facts");
        assert_eq!(
            store.count_by_kind(FactKind::AllocSite),
            1,
            "Fact store should have one AllocSite fact"
        );
        assert_eq!(
            store.count_by_kind(FactKind::DeallocSite),
            1,
            "Fact store should have one DeallocSite fact"
        );
    }

    #[test]
    fn test_fact_kind_checks() {
        assert!(
            FactKind::AllocSite.is_memory(),
            "AllocSite should be recognized as memory fact"
        );
        assert!(
            !FactKind::AllocSite.is_taint(),
            "AllocSite should NOT be recognized as taint fact"
        );
        assert!(
            FactKind::TaintSource.is_taint(),
            "TaintSource should be recognized as taint fact"
        );
        assert!(
            FactKind::LockAcquire.is_concurrency(),
            "LockAcquire should be recognized as concurrency fact"
        );
    }

    #[test]
    fn test_fact_removal() {
        let store = FactStore::new();

        let fact = Fact::new(
            0,
            FactKind::AllocSite,
            FactLocation::new(PathBuf::from("test.rs"), 10),
        );

        let id = store.add(fact);
        assert_eq!(
            store.count(),
            1,
            "Fact store should contain one fact after addition"
        );

        let removed = store.remove(id);
        assert!(
            removed.is_some(),
            "Fact removal should return the removed fact"
        );
        assert_eq!(store.count(), 0, "Fact store should be empty after removal");
    }
}
