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
use omniscope_ir::IRModule;
use omniscope_semantics::{
    behavior_to_summary, extract_behavior, FamilyRegistry, FunctionBehavior, SummaryStore,
};

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
            let ir_module: Option<IRModule> = ctx.get("ir_module");
            if let Some(module) = ir_module {
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
        assert_eq!(pass.name(), "SummaryBuilder", "Expected values to be equal");
        assert_eq!(
            pass.kind(),
            PassKind::Foundation,
            "Expected values to be equal"
        );
        assert_eq!(
            pass.dependencies(),
            vec!["RawFactCollector"],
            "Expected values to be equal"
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
            "Expected condition to be true"
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
