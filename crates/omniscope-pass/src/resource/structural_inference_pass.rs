//! Structural inference pass for resource contract analysis.
//!
//! This pass runs after the summary builder and applies structural
//! inference patterns (destructor, bridge, refcount, static-lifetime)
//! to raw facts whose function names were not resolved by the family
//! registry. Inferred summaries are added to the `SummaryStore` so
//! downstream passes can consume them without re-running inference.

use omniscope_core::Result;
use omniscope_semantics::{infer_summary_for_symbol, FamilyRegistry, SummaryStore};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::raw_fact_collector::RawResourceFact;

/// Structural inference pass.
///
/// Applies destructor, bridge, refcount, and static-lifetime inference
/// to raw facts and augments the summary store with inferred entries.
pub struct StructuralInferencePass;

impl StructuralInferencePass {
    /// Creates a new structural inference pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for StructuralInferencePass {
    fn name(&self) -> &'static str {
        "StructuralInference"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["SummaryBuilder"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        let mut inferred_count: usize = 0;
        let mut destructor_count: usize = 0;
        let mut bridge_count: usize = 0;
        let mut refcount_count: usize = 0;
        let mut static_lifetime_count: usize = 0;

        // Retrieve shared data from earlier passes.
        let registry: Option<FamilyRegistry> = ctx.get("family_registry");
        let mut store: SummaryStore = ctx.get("summary_store").unwrap_or_default();

        let registry = registry.unwrap_or_default();

        // Retrieve raw facts collected by the RawFactCollector.
        let raw_facts: Option<Vec<RawResourceFact>> = ctx.get("raw_resource_facts");
        let raw_facts = raw_facts.unwrap_or_default();

        // For each raw fact with a known function name, infer a summary
        // using the full inference chain (registry → structural → pattern).
        for fact in &raw_facts {
            if fact.function_name.is_empty() {
                continue;
            }

            let summary = infer_summary_for_symbol(
                &fact.function_name,
                fact.function,
                0, // canonical_name placeholder
                &registry,
            );

            // Count inference types for statistics.
            let is_new = store.get(summary.function).is_none();
            if is_new {
                inferred_count += 1;
                if summary.is_destructor() {
                    destructor_count += 1;
                } else if summary.is_bridge() {
                    bridge_count += 1;
                } else if summary.releases_resource()
                    && summary
                        .evidence
                        .iter()
                        .any(|e| e.kind == omniscope_types::EvidenceKind::RefcountConditional)
                {
                    refcount_count += 1;
                } else if summary
                    .evidence
                    .iter()
                    .any(|e| e.kind == omniscope_types::EvidenceKind::StaticLifetimeSink)
                {
                    static_lifetime_count += 1;
                }
            }

            store.insert(summary);
        }

        // Store the augmented summary store back into the context.
        ctx.store("summary_store", store);
        ctx.store("structural_inference_done", true);

        let mut result = PassResult::new(self.name())
            .with_nodes(raw_facts.len())
            .with_duration(start.elapsed().as_millis() as u64);

        result.add_stat("inferred_summaries", inferred_count);
        result.add_stat("destructor_inferences", destructor_count);
        result.add_stat("bridge_inferences", bridge_count);
        result.add_stat("refcount_inferences", refcount_count);
        result.add_stat("static_lifetime_inferences", static_lifetime_count);

        Ok(result)
    }
}

impl Default for StructuralInferencePass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structural_inference_pass_creation() {
        let pass = StructuralInferencePass::new();
        assert_eq!(pass.name(), "StructuralInference");
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert_eq!(pass.dependencies(), vec!["SummaryBuilder"]);
    }

    #[test]
    fn test_structural_inference_pass_run_with_empty_facts() {
        let mut ctx = PassContext::new();
        // No raw facts — pass should still complete without errors.
        let pass = StructuralInferencePass::new();
        let result = pass.run(&mut ctx).unwrap();
        assert_eq!(
            result.stats.get("inferred_summaries"),
            Some(&0),
            "No facts means no inferred summaries"
        );
    }

    #[test]
    fn test_structural_inference_pass_infers_destructor() {
        let mut ctx = PassContext::new();

        // Set up prerequisite context data.
        ctx.store("family_registry", FamilyRegistry::new());
        ctx.store("summary_store", SummaryStore::new());

        // Simulate a raw fact for a destructor function.
        let raw_facts = vec![RawResourceFact {
            function: 1,
            function_name: "drop".to_string(),
            family: None,
            is_acquire: false,
            contract: omniscope_types::PointerContract::Owned,
            arg_index: Some(0),
        }];
        ctx.store("raw_resource_facts", raw_facts);

        let pass = StructuralInferencePass::new();
        let result = pass.run(&mut ctx).unwrap();

        assert_eq!(
            result.stats.get("destructor_inferences"),
            Some(&1),
            "drop should be inferred as destructor"
        );

        // Verify the summary store now contains the inferred summary.
        let store: SummaryStore = ctx.get("summary_store").unwrap();
        assert!(
            !store.is_empty(),
            "Summary store must contain inferred summaries after pass"
        );
    }

    #[test]
    fn test_structural_inference_pass_infers_bridge() {
        let mut ctx = PassContext::new();
        ctx.store("family_registry", FamilyRegistry::new());
        ctx.store("summary_store", SummaryStore::new());

        let raw_facts = vec![RawResourceFact {
            function: 2,
            function_name: "as_ptr".to_string(),
            family: None,
            is_acquire: false,
            contract: omniscope_types::PointerContract::Borrowed,
            arg_index: None,
        }];
        ctx.store("raw_resource_facts", raw_facts);

        let pass = StructuralInferencePass::new();
        let result = pass.run(&mut ctx).unwrap();

        assert_eq!(
            result.stats.get("bridge_inferences"),
            Some(&1),
            "as_ptr should be inferred as bridge"
        );
    }
}
