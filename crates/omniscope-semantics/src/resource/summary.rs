//! Function summary for resource contract analysis.
//!
//! Every pass should read `ResourceSummary` instead of re-identifying
//! callee semantics from function names. Summaries are built from the
//! family registry and structural inference, then shared through the
//! pipeline context.

use omniscope_types::{Effect, Evidence, FunctionId, FunctionOrigin, LanguageHint, SymbolId};
use serde::{Deserialize, Serialize};

/// Resource-aware function summary.
///
/// Replaces the old `FunctionSummary` from `omniscope-dataflow` which
/// used generic `inputs/outputs/side_effects`. This version is built
/// around `Effect` and `Evidence`, which are the vocabulary of the
/// resource contract architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSummary {
    /// Function ID.
    pub function: FunctionId,
    /// Canonical symbol name ID.
    pub canonical_name: SymbolId,
    /// Human-readable function name (for diagnostics).
    pub name: String,
    /// Language hint (NOT the primary matching criterion).
    pub language_hint: LanguageHint,
    /// Where this function comes from.
    pub origin: FunctionOrigin,
    /// Effects this function has on resources.
    pub effects: Vec<Effect>,
    /// Overall confidence in this summary (0.0 - 1.0).
    pub confidence: f32,
    /// Evidence supporting this summary.
    pub evidence: Vec<Evidence>,
}

impl ResourceSummary {
    /// Creates a new summary with no effects.
    pub fn new(function: FunctionId, canonical_name: SymbolId, name: impl Into<String>) -> Self {
        Self {
            function,
            canonical_name,
            name: name.into(),
            language_hint: LanguageHint::Unknown,
            origin: FunctionOrigin::Unknown,
            effects: Vec::new(),
            confidence: 0.0,
            evidence: Vec::new(),
        }
    }

    /// Adds an effect to this summary.
    pub fn add_effect(&mut self, effect: Effect) {
        self.effects.push(effect);
    }

    /// Adds evidence to this summary.
    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.evidence.push(evidence);
    }

    /// Returns true if this function acquires any resource.
    pub fn acquires_resource(&self) -> bool {
        self.effects.iter().any(|e| e.is_acquire())
    }

    /// Returns true if this function releases any resource.
    pub fn releases_resource(&self) -> bool {
        self.effects.iter().any(|e| e.is_release())
    }

    /// Returns true if this function is a bridge helper (returns borrowed).
    pub fn is_bridge(&self) -> bool {
        self.effects.contains(&Effect::ReturnsBorrowed)
    }
}

/// Store for sharing function summaries across passes.
#[derive(Debug, Clone, Default)]
pub struct SummaryStore {
    summaries: std::collections::HashMap<FunctionId, ResourceSummary>,
}

impl SummaryStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or updates a summary.
    pub fn insert(&mut self, summary: ResourceSummary) {
        self.summaries.insert(summary.function, summary);
    }

    /// Looks up a summary by function ID.
    pub fn get(&self, function: FunctionId) -> Option<&ResourceSummary> {
        self.summaries.get(&function)
    }

    /// Returns the number of summaries.
    pub fn len(&self) -> usize {
        self.summaries.len()
    }

    /// Returns true if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.summaries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_summary_creation() {
        let summary = ResourceSummary::new(1, 100, "malloc");
        assert!(
            !summary.acquires_resource(),
            "Empty summary should not acquire"
        );
        assert!(
            !summary.releases_resource(),
            "Empty summary should not release"
        );
    }

    #[test]
    fn test_resource_summary_with_effects() {
        let mut summary = ResourceSummary::new(1, 100, "malloc");
        summary.add_effect(Effect::Acquire {
            family: omniscope_types::FamilyId::C_HEAP,
            result: 1,
        });
        assert!(
            summary.acquires_resource(),
            "Summary with Acquire should acquire"
        );
        assert!(
            !summary.releases_resource(),
            "Acquire-only summary should not release"
        );
    }

    #[test]
    fn test_bridge_summary() {
        let mut summary = ResourceSummary::new(2, 200, "as_ptr");
        summary.add_effect(Effect::ReturnsBorrowed);
        assert!(summary.is_bridge(), "as_ptr should be a bridge helper");
    }
}
