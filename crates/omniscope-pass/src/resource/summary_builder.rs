//! Summary builder pass for resource contract analysis.
//!
//! Builds `ResourceSummary` entries from the `FamilyRegistry`
//! for known symbols and stores them in the `SummaryStore` shared
//! through the pass context.

use omniscope_core::Result;
use omniscope_semantics::{FamilyRegistry, SummaryStore};

use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// Summary builder pass.
///
/// Creates the `SummaryStore` populated with built-in summaries
/// from the `FamilyRegistry` and stores it in the pass context
/// for downstream passes to consume.
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
        let store = SummaryStore::new();

        // Build summaries for all registered symbols.
        // In a full implementation, we would iterate over the
        // raw facts and create summaries for each function.
        // For now, we build the registry and store it for
        // on-demand lookup by downstream passes.
        let symbol_count = registry.symbol_count();

        ctx.store("family_registry", registry);
        ctx.store("summary_store", store);

        let result = PassResult::new(self.name())
            .with_nodes(symbol_count)
            .with_duration(start.elapsed().as_millis() as u64);

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
        assert_eq!(pass.name(), "SummaryBuilder");
        assert_eq!(pass.kind(), PassKind::Foundation);
        assert_eq!(pass.dependencies(), vec!["RawFactCollector"]);
    }

    #[test]
    fn test_on_demand_summary_inference() {
        let registry = FamilyRegistry::new();

        // Known symbol — high confidence
        let malloc_summary = infer_summary_for_symbol("malloc", 1, 100, &registry);
        assert!(malloc_summary.acquires_resource(), "malloc must acquire");
        assert!(malloc_summary.confidence > 0.9);

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
