//! Summary inference from family registry and structural patterns.
//!
//! Builds `ResourceSummary` entries from the `FamilyRegistry` for
//! known symbols, and from structural inference for unknown symbols.
//!
//! Inference priority (first match wins):
//! 1. Family registry lookup (highest confidence)
//! 2. Structural inference — destructor/drop/dispose
//! 3. Structural inference — bridge/slice-to-pointer
//! 4. Structural inference — refcount conditional release
//! 5. Structural inference — static-lifetime sink
//! 6. Family inference from naming patterns (lowest confidence)

use omniscope_types::{
    Effect, Evidence, EvidenceKind, FamilyId, FunctionId, FunctionOrigin, SymbolId,
};

use super::family_registry::{FamilyRegistry, SymbolEffect};
use super::structural_inference::{
    infer_bridge_summary, infer_destructor_summary, infer_refcount_release_summary,
    infer_static_lifetime_summary,
};
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
/// and, if not found, attempting structural and pattern-based inference.
///
/// The inference chain applies in priority order: registry first,
/// then structural inference (destructor, bridge, refcount, static-lifetime),
/// then naming pattern fallback.
pub fn infer_summary_for_symbol(
    symbol: &str,
    function: FunctionId,
    canonical_name: SymbolId,
    registry: &FamilyRegistry,
) -> ResourceSummary {
    // Priority 1: Registry lookup (highest confidence)
    if let Some(entry) = registry.lookup(symbol) {
        return build_summary_from_entry(symbol, function, canonical_name, entry);
    }

    // Determine language hint from symbol naming conventions.
    let language_hint = super::family_inference::infer_language_hint(symbol);

    // Priority 2: Structural inference — destructor/drop/dispose
    let (destructor_summary, destructor_result) = infer_destructor_summary(
        symbol,
        function,
        canonical_name,
        language_hint,
        None, // release family unknown at this stage
    );
    if destructor_result.is_destructor {
        return destructor_summary;
    }

    // Priority 3: Structural inference — bridge/slice-to-pointer
    let (bridge_summary, bridge_result) =
        infer_bridge_summary(symbol, function, canonical_name, language_hint);
    if bridge_result.is_bridge {
        return bridge_summary;
    }

    // Priority 4: Structural inference — refcount conditional release
    let (refcount_summary, refcount_result) =
        infer_refcount_release_summary(symbol, function, canonical_name, language_hint);
    if refcount_result.is_refcount_release {
        return refcount_summary;
    }

    // Priority 5: Structural inference — static-lifetime sink
    let (static_summary, static_result) = infer_static_lifetime_summary(
        symbol,
        function,
        canonical_name,
        language_hint,
        FamilyId::C_HEAP, // default family for static init
    );
    if static_result.is_static_lifetime {
        return static_summary;
    }

    // Priority 6: Family inference from naming patterns (lowest confidence)
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
