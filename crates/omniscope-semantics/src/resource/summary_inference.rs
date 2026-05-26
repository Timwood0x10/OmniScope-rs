//! Summary inference from family registry and structural patterns.
//!
//! Builds `ResourceSummary` entries from the `FamilyRegistry` for
//! known symbols, and from structural inference for unknown symbols.

use omniscope_types::{
    Effect, Evidence, EvidenceKind, FamilyId, FunctionId, FunctionOrigin, SymbolId,
};

use super::family_registry::{FamilyRegistry, SymbolEffect};
use super::summary::{ResourceSummary, SummaryStore};

/// Builds summaries for all symbols in the family registry.
///
/// This creates the initial summary store that passes can use
/// instead of re-identifying callee semantics.
pub fn build_builtin_summaries(registry: &FamilyRegistry) -> SummaryStore {
    let store = SummaryStore::new();
    // Note: In a full implementation, we would iterate over all
    // registered symbols and create a summary for each. For now,
    // summaries are built on-demand via `infer_summary_for_symbol`.
    let _ = registry;
    store
}

/// Infers a `ResourceSummary` for a symbol by looking up the registry
/// and, if not found, attempting pattern-based inference.
pub fn infer_summary_for_symbol(
    symbol: &str,
    function: FunctionId,
    canonical_name: SymbolId,
    registry: &FamilyRegistry,
) -> ResourceSummary {
    if let Some(entry) = registry.lookup(symbol) {
        return build_summary_from_entry(symbol, function, canonical_name, entry);
    }

    // Fall back to pattern-based inference
    let inferred = super::family_inference::infer_family(symbol, registry);
    let mut summary = ResourceSummary::new(function, canonical_name, symbol);
    summary.language_hint = inferred.language_hint;

    if let Some(effect_kind) = inferred.effect {
        let effect = match effect_kind {
            SymbolEffect::Acquire => Effect::ReturnsOwned {
                family: inferred.family_id.unwrap_or(FamilyId::C_HEAP),
            },
            SymbolEffect::Release => Effect::Release {
                family: inferred.family_id.unwrap_or(FamilyId::C_HEAP),
                arg: 0,
            },
            SymbolEffect::ConditionalRelease => Effect::ConditionalRelease {
                family: inferred.family_id.unwrap_or(FamilyId::C_HEAP),
                arg: 0,
            },
            SymbolEffect::Retain => Effect::Retain {
                family: inferred.family_id.unwrap_or(FamilyId::C_HEAP),
                arg: 0,
            },
        };
        summary.add_effect(effect);
        summary.confidence = inferred.confidence;
        summary.add_evidence(Evidence::new(EvidenceKind::SymbolPattern, inferred.reason));
    }

    summary
}

fn build_summary_from_entry(
    symbol: &str,
    function: FunctionId,
    canonical_name: SymbolId,
    entry: &super::family_registry::FamilyEntry,
) -> ResourceSummary {
    let mut summary = ResourceSummary::new(function, canonical_name, symbol);
    summary.language_hint = entry.language_hint;
    summary.origin = FunctionOrigin::Stdlib;

    let effect = match entry.effect {
        SymbolEffect::Acquire => Effect::ReturnsOwned {
            family: entry.family_id,
        },
        SymbolEffect::Release => Effect::Release {
            family: entry.family_id,
            arg: 0,
        },
        SymbolEffect::ConditionalRelease => Effect::ConditionalRelease {
            family: entry.family_id,
            arg: 0,
        },
        SymbolEffect::Retain => Effect::Retain {
            family: entry.family_id,
            arg: 0,
        },
    };

    summary.add_effect(effect);
    summary.confidence = 0.95;
    summary.add_evidence(Evidence::new(
        EvidenceKind::SymbolPattern,
        format!("symbol '{symbol}' registered in family registry"),
    ));

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_malloc_summary() {
        let registry = FamilyRegistry::new();
        let summary = infer_summary_for_symbol("malloc", 1, 100, &registry);
        assert!(
            summary.acquires_resource(),
            "malloc must be classified as acquire"
        );
        assert!(
            summary.confidence > 0.9,
            "Registry match should have high confidence"
        );
    }

    #[test]
    fn test_infer_free_summary() {
        let registry = FamilyRegistry::new();
        let summary = infer_summary_for_symbol("free", 2, 101, &registry);
        assert!(
            summary.releases_resource(),
            "free must be classified as release"
        );
    }

    #[test]
    fn test_infer_unknown_alloc_pattern() {
        let registry = FamilyRegistry::new();
        let summary = infer_summary_for_symbol("buffer_alloc", 3, 102, &registry);
        assert!(
            summary.acquires_resource(),
            "buffer_alloc pattern should be inferred as acquire"
        );
        assert!(
            summary.confidence < 0.9,
            "Pattern inference should have lower confidence than registry match"
        );
    }
}
