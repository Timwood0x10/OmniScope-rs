//! Structural inference pass for resource contract analysis.
//!
//! This pass runs after the summary builder and applies structural
//! inference patterns (destructor, bridge, refcount, static-lifetime)
//! to raw facts whose function names were not resolved by the family
//! registry. Inferred summaries are added to the `SummaryStore` so
//! downstream passes can consume them without re-running inference.
//!
//! # IR Behavior First
//!
//! This pass now prioritizes IR behavior-based summaries over
//! symbol-name-based inference. If a `function_behaviors` map is
//! available in the pass context (from `IRBehaviorSummaryPass`),
//! we first check whether the function has a behavior-derived summary.
//! Only when no behavior summary exists do we fall back to
//! `infer_summary_for_symbol`.

use omniscope_core::Result;
use omniscope_semantics::{
    behavior_to_summary, infer_summary_for_symbol, FamilyRegistry, FunctionBehavior, SummaryStore,
};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::raw_fact_collector::RawResourceFact;

/// Structural inference pass.
///
/// Applies destructor, bridge, refcount, and static-lifetime inference
/// to raw facts and augments the summary store with inferred entries.
///
/// Inference priority (enhancement):
/// 1. IR behavior summary (from `IRBehaviorSummaryPass`) — highest confidence
/// 2. Symbol-name inference (registry → structural → pattern) — fallback
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
        let mut behavior_override_count: usize = 0;

        // Retrieve shared data from earlier passes.
        let registry: Option<FamilyRegistry> = ctx.get("family_registry");
        let mut store: SummaryStore = ctx.get("summary_store").unwrap_or_default();

        let registry = registry.unwrap_or_default();

        // Retrieve IR behavior summaries (from IRBehaviorSummaryPass)
        let behaviors: Option<Vec<FunctionBehavior>> = ctx.get("function_behaviors");
        let behaviors = behaviors.unwrap_or_default();

        // Build a quick lookup: function_name → FunctionBehavior
        // so we can check if a behavior-derived summary exists before
        // falling back to symbol-name inference.
        let behavior_map: std::collections::HashMap<&str, &FunctionBehavior> =
            behaviors.iter().map(|b| (b.name.as_str(), b)).collect();

        // Retrieve raw facts collected by the RawFactCollector.
        let raw_facts: Option<Vec<RawResourceFact>> = ctx.get("raw_resource_facts");
        let raw_facts = raw_facts.unwrap_or_default();

        // For each raw fact, prefer IR behavior inference over symbol-name inference.
        for fact in &raw_facts {
            if fact.function_name.is_empty() {
                continue;
            }

            // 1: Check if we have an IR behavior for this function
            let summary = if let Some(behavior) = behavior_map.get(fact.function_name.as_str()) {
                // Use behavior-based inference — this can recognize unknown
                // function names with recognizable IR patterns
                behavior_override_count += 1;
                behavior_to_summary(behavior, fact.function, 0)
            } else {
                // 2: Fall back to symbol-name inference
                infer_summary_for_symbol(
                    &fact.function_name,
                    fact.function,
                    0, // canonical_name placeholder
                    &registry,
                )
            };

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

        // Also process functions that have IR behaviors but NO raw facts
        // (i.e., functions that weren't seen as alloc/dealloc sites but
        // have recognizable patterns like ConditionalRelease or PointerProjection).
        for behavior in &behaviors {
            // Skip if we already have a summary for this function
            // (either from raw facts or from IRBehaviorSummaryPass merge)
            let already_has_summary = store.iter().any(|(_, s)| s.name == behavior.name);
            if already_has_summary {
                continue;
            }

            if !behavior.patterns.is_empty() {
                let summary = behavior_to_summary(behavior, 0, 0);
                store.insert(summary);
                inferred_count += 1;
            }
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
        result.add_stat("behavior_override_count", behavior_override_count);

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
