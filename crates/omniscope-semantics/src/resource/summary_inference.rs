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
//! 6. Structural inference — into_raw/from_raw ownership transfer (R-6)
//! 7. Family inference from naming patterns (lowest confidence)

use omniscope_types::{
    Effect, Evidence, EvidenceKind, FamilyId, FunctionId, FunctionOrigin, LanguageHint, SymbolId,
};

use super::family_registry::{FamilyRegistry, SymbolEffect};
use super::structural_inference::{
    infer_bridge_summary, infer_destructor_summary, infer_into_raw_summary,
    infer_refcount_release_summary, infer_static_lifetime_summary,
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

    // Priority 5.5: Structural inference — into_raw/from_raw ownership transfer (R-6)
    // This handles mangled Rust names like _RNvXs_NtC...4alloc5boxed8Box3i328into_raw
    // that are NOT registered in FamilyRegistry (registry only has demangled names).
    let (into_raw_summary, into_raw_result) =
        infer_into_raw_summary(symbol, function, canonical_name, language_hint);
    if into_raw_result.is_into_raw {
        return into_raw_summary;
    }

    // Also check for from_raw pattern (ownership reclamation from raw pointer).
    // from_raw is the inverse of into_raw — it re-acquires ownership.
    if is_from_raw_pattern(symbol, language_hint) {
        let mut summary = ResourceSummary::new(function, canonical_name, symbol);
        summary.language_hint = language_hint;
        summary.origin = FunctionOrigin::UserCode;
        summary.confidence = 0.90;
        summary.add_effect(Effect::OwnershipReclaim {
            family: FamilyId::RUST_RAW_OWNERSHIP,
            result: 0,
        });
        summary.add_evidence(Evidence::new(
            EvidenceKind::OwnershipTransfer,
            format!(
                "function '{symbol}' inferred as from_raw — ownership reclaimed from raw pointer"
            ),
        ));
        return summary;
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
            SymbolEffect::Escape => Effect::OwnershipEscape {
                family: inferred.family_id.unwrap_or(FamilyId::RUST_RAW_OWNERSHIP),
                result: 0,
            },
            SymbolEffect::Reclaim => Effect::OwnershipReclaim {
                family: inferred.family_id.unwrap_or(FamilyId::RUST_RAW_OWNERSHIP),
                result: 0,
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
        SymbolEffect::Escape => Effect::OwnershipEscape {
            family: entry.family_id,
            result: 0,
        },
        SymbolEffect::Reclaim => Effect::OwnershipReclaim {
            family: entry.family_id,
            result: 0,
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

/// Checks whether a symbol name matches a from_raw ownership reclamation pattern.
///
/// Handles both demangled names (e.g. `Box::from_raw`) and Rust v0 mangled
/// names (e.g. `_RNvXs_NtC...4alloc5boxed8Box3i328from_raw`).
/// Only Rust has from_raw idioms — returns false for other languages.
fn is_from_raw_pattern(name: &str, language_hint: LanguageHint) -> bool {
    if language_hint != LanguageHint::Rust && language_hint != LanguageHint::Unknown {
        return false;
    }

    // Demangled: Box::from_raw, CString::from_raw, Vec::from_raw_parts
    if name.contains("from_raw") {
        return true;
    }

    // Rust v0 mangled names contain length-prefixed segments:
    // "8from_raw" (8 = strlen("from_raw"))
    // "14from_raw_parts" (14 = strlen("from_raw_parts"))
    if name.contains("8from_raw") || name.contains("14from_raw_parts") {
        return true;
    }

    false
}

/// Converts a `FunctionBehavior` (derived from IR instruction patterns)
/// into a `ResourceSummary`.
///
/// This is the key bridge from "IR pattern analysis" to "resource contract
/// pipeline". Instead of classifying by function name, we classify by the
/// instruction patterns within the function body.
///
/// Confidence levels:
/// - 0.92 for ConditionalRelease (strong IR evidence)
/// - 0.90 for OwnershipTransfer (direct alloc/free call)
/// - 0.85 for PointerProjection (pure GEP pattern)
/// - 0.80 for PureComputation (no ownership implication)
/// - 0.80 for Initialization (constructor pattern)
/// - 0.75 for InternalBridge (heuristic, project-prefix based)
/// - 0.88 for BorrowedReturn (readonly param evidence)
/// - 0.92 for RAiiDropRelease (compiler-inserted pattern)
/// - 0.88 for IntoRawTransfer (into_raw pattern)
/// - 0.85 for PosixNonMemoryOp (POSIX classification)
pub fn behavior_to_summary(
    behavior: &super::ir_pattern::FunctionBehavior,
    function: FunctionId,
    canonical_name: SymbolId,
) -> ResourceSummary {
    use super::ir_pattern::{BehaviorPattern, ReturnSource};

    let mut summary = ResourceSummary::new(function, canonical_name, &behavior.name);

    // If no patterns detected, return low-confidence unknown summary
    if behavior.patterns.is_empty() {
        summary.confidence = 0.1;
        summary.add_evidence(Evidence::new(
            EvidenceKind::Insufficient,
            format!("no IR behavior patterns detected for '{}'", behavior.name),
        ));
        return summary;
    }

    // Process each detected pattern into effects + evidence
    for pattern in &behavior.patterns {
        match pattern {
            BehaviorPattern::ConditionalRelease {
                atomic_op,
                threshold,
            } => {
                summary.add_effect(Effect::ConditionalRelease {
                    family: FamilyId::RUST_GLOBAL,
                    arg: 0,
                });
                summary.add_evidence(Evidence::new(
                    EvidenceKind::RefcountConditional,
                    format!(
                        "IR pattern: atomicrmw {} + icmp eq → conditional release (threshold={})",
                        atomic_op, threshold
                    ),
                ));
                summary.confidence = summary.confidence.max(0.92);
            }

            BehaviorPattern::OwnershipTransfer { is_acquire } => {
                if *is_acquire {
                    summary.add_effect(Effect::ReturnsOwned {
                        family: FamilyId::C_HEAP,
                    });
                    summary.add_evidence(Evidence::new(
                        EvidenceKind::OwnershipTransfer,
                        "IR pattern: call returns ptr from alloc → ownership acquired".to_string(),
                    ));
                } else {
                    summary.add_effect(Effect::Release {
                        family: FamilyId::C_HEAP,
                        arg: 0,
                    });
                    summary.add_evidence(Evidence::new(
                        EvidenceKind::OwnershipTransfer,
                        "IR pattern: ptr passed to dealloc → ownership released".to_string(),
                    ));
                }
                summary.confidence = summary.confidence.max(0.90);
            }

            BehaviorPattern::PureComputation => {
                summary.add_evidence(Evidence::new(
                    EvidenceKind::IrPattern,
                    "IR pattern: call results only in arithmetic/store → pure computation, no ownership".to_string(),
                ));
                summary.confidence = summary.confidence.max(0.80);
            }

            BehaviorPattern::PointerProjection => {
                summary.add_effect(Effect::ReturnsBorrowed);
                summary.add_evidence(Evidence::new(
                    EvidenceKind::IrPattern,
                    "IR pattern: GEP + bitcast + ret → pointer projection (borrowed return)"
                        .to_string(),
                ));
                summary.confidence = summary.confidence.max(0.85);
            }

            BehaviorPattern::Initialization => {
                summary.add_evidence(Evidence::new(
                    EvidenceKind::IrPattern,
                    "IR pattern: stores to struct fields + ret void → initialization, no ownership leak".to_string(),
                ));
                summary.confidence = summary.confidence.max(0.80);
            }

            BehaviorPattern::InternalBridge => {
                summary.add_evidence(Evidence::new(
                    EvidenceKind::CallGraphStructure,
                    "IR pattern: all calls to same-project functions → internal bridge".to_string(),
                ));
                summary.confidence = summary.confidence.max(0.75);
            }

            BehaviorPattern::BorrowedReturn {
                from_readonly_param,
            } => {
                summary.add_effect(Effect::ReturnsBorrowed);
                let evidence_desc = if *from_readonly_param {
                    "IR pattern: returns pointer from readonly param → borrowed return (&T → &T)"
                        .to_string()
                } else {
                    "IR pattern: returns pointer from field load → borrowed return".to_string()
                };
                summary.add_evidence(Evidence::new(EvidenceKind::IrPattern, evidence_desc));
                summary.confidence = summary.confidence.max(0.88);
            }

            BehaviorPattern::RAiiDropRelease { is_drop_in_place } => {
                summary.add_effect(Effect::Release {
                    family: FamilyId::RUST_GLOBAL,
                    arg: 0,
                });
                summary.add_effect(Effect::ConsumesArg {
                    arg: 0,
                    family: Some(FamilyId::RUST_GLOBAL),
                });
                let desc = if *is_drop_in_place {
                    "IR pattern: drop_in_place<T> → compiler-inserted RAII drop".to_string()
                } else {
                    "IR pattern: tail-position dealloc → RAII drop release".to_string()
                };
                summary.add_evidence(Evidence::new(EvidenceKind::RaiiDropRelease, desc));
                summary.confidence = summary.confidence.max(0.92);
            }

            BehaviorPattern::IntoRawTransfer => {
                summary.add_effect(Effect::ReturnsOwned {
                    family: FamilyId::RUST_GLOBAL,
                });
                summary.add_evidence(Evidence::new(
                    EvidenceKind::OwnershipTransfer,
                    "IR pattern: into_raw → intentional ownership transfer to caller".to_string(),
                ));
                summary.confidence = summary.confidence.max(0.88);
            }

            BehaviorPattern::PosixNonMemoryOp { category } => {
                let cat = match category {
                    super::ir_pattern::PosixOpCategory::File => "file",
                    super::ir_pattern::PosixOpCategory::Network => "network",
                    super::ir_pattern::PosixOpCategory::Process => "process",
                    super::ir_pattern::PosixOpCategory::Other => "other",
                };
                summary.add_evidence(Evidence::new(
                    EvidenceKind::PosixSyscallClass,
                    format!(
                        "IR pattern: POSIX {} operation → non-memory, no ownership effect",
                        cat
                    ),
                ));
                summary.confidence = summary.confidence.max(0.85);
            }

            BehaviorPattern::NullGuardedRelease { arg_index } => {
                summary.add_effect(Effect::ConditionalRelease {
                    family: FamilyId::C_HEAP,
                    arg: *arg_index,
                });
                summary.add_evidence(Evidence::new(
                    EvidenceKind::IrPattern,
                    format!(
                        "IR pattern: icmp eq ptr → null + br → release call → NULL-guarded release (arg {})",
                        arg_index
                    ),
                ));
                summary.confidence = summary.confidence.max(0.88);
            }

            BehaviorPattern::NullStoreAfterRelease { arg_index } => {
                summary.add_effect(Effect::Release {
                    family: FamilyId::C_HEAP,
                    arg: *arg_index,
                });
                summary.add_evidence(Evidence::new(
                    EvidenceKind::IrPattern,
                    format!(
                        "IR pattern: release call → store null → defensive null-after-release (arg {})",
                        arg_index
                    ),
                ));
                summary.confidence = summary.confidence.max(0.85);
            }

            BehaviorPattern::FallibleOutParamInit { out_arg_index } => {
                summary.add_effect(Effect::ReturnsOwned {
                    family: FamilyId::C_HEAP,
                });
                summary.add_evidence(Evidence::new(
                    EvidenceKind::IrPattern,
                    format!(
                        "IR pattern: store null → call → icmp → error null-store → fallible out-param init (arg {})",
                        out_arg_index
                    ),
                ));
                summary.confidence = summary.confidence.max(0.82);
            }

            BehaviorPattern::OutParamNullOnError { out_arg_index } => {
                summary.add_evidence(Evidence::new(
                    EvidenceKind::IrPattern,
                    format!(
                        "IR pattern: icmp → br → error block null-store → defensive out-param nulling (arg {})",
                        out_arg_index
                    ),
                ));
                summary.confidence = summary.confidence.max(0.80);
            }

            BehaviorPattern::OutParamOwnedOnSuccess { out_arg_index } => {
                summary.add_effect(Effect::ReturnsOwned {
                    family: FamilyId::C_HEAP,
                });
                summary.add_evidence(Evidence::new(
                    EvidenceKind::IrPattern,
                    format!(
                        "IR pattern: icmp → br → success block allocation → out-param owned on success (arg {})",
                        out_arg_index
                    ),
                ));
                summary.confidence = summary.confidence.max(0.85);
            }
        }
    }

    // Enrich with return source information
    match &behavior.return_source {
        ReturnSource::CallResult(callee) => {
            if summary.effects.is_empty() {
                summary.add_evidence(Evidence::new(
                    EvidenceKind::CallGraphStructure,
                    format!("returns result of call to '{}' — wrapper/delegate", callee),
                ));
            }
        }
        ReturnSource::GepResult => {
            if !behavior
                .patterns
                .contains(&BehaviorPattern::PointerProjection)
            {
                summary.add_evidence(Evidence::new(
                    EvidenceKind::IrPattern,
                    "return value derived from GEP — likely borrowed pointer".to_string(),
                ));
            }
        }
        ReturnSource::Void
        | ReturnSource::Constant
        | ReturnSource::Unknown
        | ReturnSource::LoadedValue
        | ReturnSource::Computed => {}
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BehaviorPattern;

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

    // ── behavior_to_summary tests (M4) ──

    #[test]
    fn test_behavior_to_summary_conditional_release() {
        let behavior = super::super::ir_pattern::FunctionBehavior {
            name: "mystery_drop".to_string(),
            alloca_count: 0,
            call_count: 1,
            atomic_rmw_count: 1,
            load_count: 0,
            store_count: 0,
            gep_count: 0,
            icmp_count: 1,
            branch_count: 1,
            patterns: vec![BehaviorPattern::ConditionalRelease {
                atomic_op: "sub".to_string(),
                threshold: "1".to_string(),
            }],
            return_source: super::super::ir_pattern::ReturnSource::Void,
        };

        let summary = behavior_to_summary(&behavior, 1, 1);
        assert!(
            summary.releases_resource(),
            "ConditionalRelease behavior should produce a release effect"
        );
        assert!(
            summary.confidence >= 0.92,
            "ConditionalRelease should have high confidence, got {}",
            summary.confidence
        );
        assert!(
            summary
                .evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::RefcountConditional),
            "Should have RefcountConditional evidence"
        );
    }

    #[test]
    fn test_behavior_to_summary_ownership_transfer_acquire() {
        let behavior = super::super::ir_pattern::FunctionBehavior {
            name: "custom_alloc".to_string(),
            alloca_count: 0,
            call_count: 1,
            atomic_rmw_count: 0,
            load_count: 0,
            store_count: 0,
            gep_count: 0,
            icmp_count: 0,
            branch_count: 0,
            patterns: vec![BehaviorPattern::OwnershipTransfer { is_acquire: true }],
            return_source: super::super::ir_pattern::ReturnSource::CallResult("malloc".to_string()),
        };

        let summary = behavior_to_summary(&behavior, 2, 2);
        assert!(
            summary.acquires_resource(),
            "OwnershipTransfer acquire should produce an acquire effect"
        );
        assert!(
            summary
                .evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::OwnershipTransfer),
            "Should have OwnershipTransfer evidence"
        );
    }

    #[test]
    fn test_behavior_to_summary_pointer_projection() {
        let behavior = super::super::ir_pattern::FunctionBehavior {
            name: "weird_accessor".to_string(),
            alloca_count: 0,
            call_count: 0,
            atomic_rmw_count: 0,
            load_count: 0,
            store_count: 0,
            gep_count: 1,
            icmp_count: 0,
            branch_count: 0,
            patterns: vec![BehaviorPattern::PointerProjection],
            return_source: super::super::ir_pattern::ReturnSource::GepResult,
        };

        let summary = behavior_to_summary(&behavior, 3, 3);
        assert!(
            summary.is_bridge(),
            "PointerProjection should produce ReturnsBorrowed (bridge)"
        );
    }

    #[test]
    fn test_behavior_to_summary_pure_computation_no_effects() {
        let behavior = super::super::ir_pattern::FunctionBehavior {
            name: "obscure_math".to_string(),
            alloca_count: 0,
            call_count: 0,
            atomic_rmw_count: 0,
            load_count: 0,
            store_count: 0,
            gep_count: 0,
            icmp_count: 0,
            branch_count: 0,
            patterns: vec![BehaviorPattern::PureComputation],
            return_source: super::super::ir_pattern::ReturnSource::Computed,
        };

        let summary = behavior_to_summary(&behavior, 4, 4);
        // PureComputation should have NO resource effects
        assert!(
            !summary.acquires_resource() && !summary.releases_resource(),
            "PureComputation should have no resource effects"
        );
        assert!(
            summary
                .evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::IrPattern),
            "Should have IrPattern evidence explaining why"
        );
    }

    #[test]
    fn test_behavior_to_summary_empty_patterns() {
        let behavior = super::super::ir_pattern::FunctionBehavior {
            name: "unknown_func".to_string(),
            alloca_count: 0,
            call_count: 0,
            atomic_rmw_count: 0,
            load_count: 0,
            store_count: 0,
            gep_count: 0,
            icmp_count: 0,
            branch_count: 0,
            patterns: vec![],
            return_source: super::super::ir_pattern::ReturnSource::Unknown,
        };

        let summary = behavior_to_summary(&behavior, 5, 5);
        assert!(
            summary.confidence < 0.2,
            "No patterns should result in low confidence, got {}",
            summary.confidence
        );
    }
}
