//! Summary builder pass for resource contract analysis.
//!
//! Builds `ResourceSummary` entries from the `FamilyRegistry`
//! for known symbols and stores them in the `SummaryStore` shared
//! through the pass context.
//!
//! # IR Behavior Integration
//!
//! This pass now also consumes `function_behaviors` from the
//! `IRBehaviorSummaryPass` (if available) to build summaries
//! for functions whose names are not in the family registry.

use omniscope_core::Result;
use omniscope_ir::IRInstructionKind;
use omniscope_semantics::{
    behavior_to_summary, extract_behavior, FamilyRegistry, FunctionBehavior, SummaryStore,
};
use omniscope_types::{Effect, FamilyId};

use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// Summary builder pass.
///
/// Creates the `SummaryStore` populated with built-in summaries
/// from the `FamilyRegistry` and IR behavior-based summaries,
/// and stores it in the pass context for downstream passes to consume.
pub struct SummaryBuilderPass;

impl SummaryBuilderPass {
    /// Creates a new summary builder pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for SummaryBuilderPass {
    fn name(&self) -> &'static str {
        "SummaryBuilder"
    }

    fn kind(&self) -> PassKind {
        PassKind::Foundation
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["RawFactCollector"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        let registry = FamilyRegistry::new();
        let mut store = SummaryStore::new();

        // Build summaries for all registered symbols.
        let symbol_count = registry.symbol_count();

        // Also build summaries from IR behaviors if available.
        // The IRBehaviorSummaryPass may have already stored
        // `function_behaviors` in the context.
        let behaviors: Option<Vec<FunctionBehavior>> = ctx.get("function_behaviors");
        let mut behavior_summary_count = 0;

        if let Some(behaviors) = &behaviors {
            for (idx, behavior) in behaviors.iter().enumerate() {
                if !behavior.patterns.is_empty() {
                    let summary = behavior_to_summary(behavior, idx as u64, idx as u64);
                    // Only insert if not already in registry
                    if registry.lookup(&behavior.name).is_none() {
                        store.insert(summary);
                        behavior_summary_count += 1;
                    }
                }
            }
        }

        //  Also try to extract behaviors directly from IRModule
        // if function_bodies exist but IRBehaviorSummaryPass hasn't run yet.
        if behaviors.is_none() {
            if let Some(module) = ctx.get_ir_module() {
                for (idx, (name, body)) in module.function_bodies.iter().enumerate() {
                    let behavior = extract_behavior(body);
                    if !behavior.patterns.is_empty() && registry.lookup(name).is_none() {
                        let summary = behavior_to_summary(&behavior, idx as u64, idx as u64);
                        store.insert(summary);
                        behavior_summary_count += 1;
                    }
                }
            }
        }

        // ── Ownership chain + standard library detection ──
        // Two goals in one pass:
        //   1. Detect factory functions (malloc + return) → ReturnsOwned
        //   2. Detect standard library functions (mangled-name pattern) → LibraryRelease
        if let Some(module) = ctx.get_ir_module() {
            // Build a set of known allocator call targets.
            let allocators: std::collections::HashSet<&str> = [
                "malloc",
                "calloc",
                "realloc",
                "_Znam",
                "_Znwm",
                "Marshal_AllocHGlobal",
                "CoTaskMemAlloc",
                "AllocHGlobal",
            ]
            .into_iter()
            .collect();

            // Collect existing summary names that have ReturnsOwned.
            let has_returns_owned: std::collections::HashSet<String> = store
                .iter()
                .filter(|(_, s)| {
                    s.effects
                        .iter()
                        .any(|e| matches!(e, Effect::ReturnsOwned { .. }))
                })
                .map(|(_, s)| s.name.clone())
                .collect();

            // ── Standard library / third-party function detection ──
            // When debug info is unavailable (no !DILocation in IR), we fall
            // back to mangled-name pattern matching.  The Itanium ABI uses
            // a special token `St` for the `std::` namespace — this is a
            // language-ABI guarantee, not a compiler-specific convention.
            //
            // Patterns:
            //   C++:  _ZNSt...  = std::*       (libc++ / libstdc++ / MSVC STL)
            //         _ZNKSt... = std::* const  (const methods)
            //   Rust: _ZN4core  = core::*
            //         _ZN3std   = std::*
            //         _ZN5alloc = alloc::*
            //   Go:   runtime.* (not mangled, plain prefix)
            let is_stdlib = |name: &str| -> bool {
                name.starts_with("_ZNSt")
                    || name.starts_with("_ZNKSt")
                    || name.starts_with("_ZN4core")
                    || name.starts_with("_ZN3std")
                    || name.starts_with("_ZN5alloc")
                    || name.starts_with("_ZN7runtime")
                    || name.starts_with("runtime.")
                    || name.starts_with("sync.")
            };

            for (idx, (name, body)) in module.function_bodies.iter().enumerate() {
                // Skip if already in registry (built-in symbol).
                if registry.lookup(name).is_some() {
                    continue;
                }
                // Skip if already has a summary with ReturnsOwned.
                if has_returns_owned.contains(name.as_str()) {
                    continue;
                }

                // ── Standard library / third-party marking ──
                // Functions from stdlib / third-party libraries should be
                // treated as opaque external code.  Their internal allocations
                // are managed by the library itself, not user code.
                if is_stdlib(name) {
                    let mut summary =
                        omniscope_semantics::ResourceSummary::new(idx as u64, idx as u64, name);
                    summary.origin = omniscope_types::FunctionOrigin::Stdlib;
                    summary.confidence = 0.85;
                    store.insert(summary);
                    behavior_summary_count += 1;
                    tracing::debug!(
                        "Stdlib detection: marked '{}' as library (mangled-name pattern)",
                        name
                    );
                    continue;
                }

                // ── Factory function detection ──
                // Functions that call an allocator AND return a pointer are
                // factory functions — ownership is transferred to the caller.
                let has_alloc_call = body.instructions.iter().any(|inst| {
                    if !matches!(inst.kind, IRInstructionKind::Call) {
                        return false;
                    }
                    inst.callee
                        .as_deref()
                        .is_some_and(|c| allocators.contains(c))
                });
                if !has_alloc_call {
                    continue;
                }

                // Check if the function returns a pointer (has `ret ptr`).
                let has_ptr_return = body.instructions.iter().any(|inst| {
                    matches!(inst.kind, IRInstructionKind::Ret)
                        && inst
                            .operands
                            .iter()
                            .any(|op| op.starts_with('%') || op.starts_with('@'))
                });
                if !has_ptr_return {
                    continue;
                }

                // This function is a factory: allocates + returns pointer.
                // Add ReturnsOwned effect so leak detection ignores it.
                let mut summary =
                    omniscope_semantics::ResourceSummary::new(idx as u64, idx as u64, name);
                summary.effects.push(Effect::ReturnsOwned {
                    family: FamilyId::C_HEAP,
                });
                summary.confidence = 0.8;
                store.insert(summary);
                behavior_summary_count += 1;
                tracing::debug!(
                    "Ownership chain: added ReturnsOwned for '{}' (factory pattern)",
                    name
                );
            }
        }

        ctx.store("family_registry", registry);
        ctx.store("summary_store", store);

        let mut result = PassResult::new(self.name())
            .with_nodes(symbol_count)
            .with_duration(start.elapsed().as_millis() as u64);

        result.add_stat("behavior_summary_count", behavior_summary_count);

        Ok(result)
    }
}

impl Default for SummaryBuilderPass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_semantics::infer_summary_for_symbol;

    #[test]
    fn test_summary_builder_creation() {
        let pass = SummaryBuilderPass::new();
        assert_eq!(
            pass.name(),
            "SummaryBuilder",
            "Pass name must be 'SummaryBuilder'"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Foundation,
            "SummaryBuilder must be a Foundation pass"
        );
        assert_eq!(
            pass.dependencies(),
            vec!["RawFactCollector"],
            "SummaryBuilder must depend on RawFactCollector"
        );
    }

    #[test]
    fn test_on_demand_summary_inference() {
        let registry = FamilyRegistry::new();

        // Known symbol — high confidence
        let malloc_summary = infer_summary_for_symbol("malloc", 1, 100, &registry);
        assert!(malloc_summary.acquires_resource(), "malloc must acquire");
        assert!(
            malloc_summary.confidence > 0.9,
            "malloc must have high confidence (>0.9)"
        );

        // Unknown symbol — pattern inference
        let custom_alloc = infer_summary_for_symbol("buffer_alloc", 2, 200, &registry);
        assert!(
            custom_alloc.acquires_resource(),
            "buffer_alloc pattern must infer acquire"
        );
        assert!(
            custom_alloc.confidence < 0.9,
            "Pattern inference should have lower confidence"
        );
    }
}
