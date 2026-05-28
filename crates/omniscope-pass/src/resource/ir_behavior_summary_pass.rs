//! IR behavior summary pass — extracts function behaviors from IR
//! instruction patterns and converts them into ResourceSummary entries.
//!
//! This is the M1 milestone: the key bridge from "IR pattern analysis"
//! to "resource contract pipeline". Before this pass, the pipeline
//! relied on symbol names and family registry for summary inference.
//! After this pass, functions with unknown names but recognizable IR
//! patterns (e.g., ConditionalRelease, PureComputation) also get
//! high-confidence summaries.
//!
//! # Pipeline Integration
//!
//! This pass runs after RawFactCollector (which provides IRModule)
//! and before SummaryBuilder. The `function_behaviors` it stores
//! in pass context are consumed by:
//! - SummaryBuilderPass (M2): to build summaries from behaviors
//! - StructuralInferencePass (M2): to prefer behavior-based inference

use omniscope_core::Result;
use omniscope_ir::IRModule;
use omniscope_semantics::{
    behavior_to_summary, extract_behavior, BehaviorPattern, FunctionBehavior, SummaryStore,
};

use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// IR behavior summary pass.
///
/// Iterates over all function bodies in the IR module, calls
/// `extract_behavior` on each, and converts detected patterns
/// into `ResourceSummary` entries stored in the `SummaryStore`.
pub struct IRBehaviorSummaryPass;

impl IRBehaviorSummaryPass {
    /// Creates a new IR behavior summary pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for IRBehaviorSummaryPass {
    fn name(&self) -> &'static str {
        "IRBehaviorSummary"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["RawFactCollector"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        // Get IR module from context (provided by RawFactCollector or Pipeline)
        let ir_module: Option<IRModule> = ctx.get("ir_module");
        let Some(module) = ir_module else {
            let mut result = PassResult::new(self.name())
                .with_issues(0)
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64);
            result.add_stat("behaviors_extracted", 0);
            result.add_stat("summaries_from_behavior", 0);
            return Ok(result);
        };

        let mut behaviors: Vec<FunctionBehavior> = Vec::new();
        let mut summary_store: SummaryStore = ctx.get("summary_store").unwrap_or_default();

        // Iterate over all function bodies and extract behaviors
        for (func_id, body) in module.function_bodies.values().enumerate() {
            let func_id = func_id as u64;
            let behavior = extract_behavior(body);
            behaviors.push(behavior.clone());

            // Convert behavior to summary and add to store
            if !behavior.patterns.is_empty() {
                let summary = behavior_to_summary(&behavior, func_id, func_id);
                summary_store.insert(summary);
            }
        }

        // Store behaviors for downstream passes (M2 integration)
        ctx.store("function_behaviors", behaviors.clone());
        ctx.store("ir_behavior_summary_store", summary_store.clone());

        // Merge into the main summary_store if it exists
        // (so downstream passes see both registry-based and behavior-based summaries)
        let mut existing_store: SummaryStore = ctx.get("summary_store").unwrap_or_default();
        for (_, summary) in summary_store.iter() {
            // Only insert if not already present (registry entries take precedence)
            if existing_store.get(summary.function).is_none() {
                existing_store.insert(summary.clone());
            }
        }
        ctx.store("summary_store", existing_store);

        // Count pattern statistics
        let mut conditional_release_count = 0;
        let mut ownership_transfer_count = 0;
        let mut pure_computation_count = 0;
        let mut pointer_projection_count = 0;
        let mut initialization_count = 0;
        let mut internal_bridge_count = 0;

        for behavior in &behaviors {
            for pattern in &behavior.patterns {
                match pattern {
                    BehaviorPattern::ConditionalRelease { .. } => conditional_release_count += 1,
                    BehaviorPattern::OwnershipTransfer { .. } => ownership_transfer_count += 1,
                    BehaviorPattern::PureComputation => pure_computation_count += 1,
                    BehaviorPattern::PointerProjection => pointer_projection_count += 1,
                    BehaviorPattern::Initialization => initialization_count += 1,
                    BehaviorPattern::InternalBridge => internal_bridge_count += 1,
                    _ => {} // Newer patterns counted separately if needed
                }
            }
        }

        let mut result = PassResult::new(self.name())
            .with_nodes(module.function_bodies.len())
            .with_duration(start.elapsed().as_millis() as u64);

        result.add_stat("behaviors_extracted", behaviors.len());
        result.add_stat("summaries_from_behavior", summary_store.len());
        result.add_stat("conditional_release", conditional_release_count);
        result.add_stat("ownership_transfer", ownership_transfer_count);
        result.add_stat("pure_computation", pure_computation_count);
        result.add_stat("pointer_projection", pointer_projection_count);
        result.add_stat("initialization", initialization_count);
        result.add_stat("internal_bridge", internal_bridge_count);

        Ok(result)
    }
}

impl Default for IRBehaviorSummaryPass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ir_behavior_summary_pass_creation() {
        let pass = IRBehaviorSummaryPass::new();
        assert_eq!(pass.name(), "IRBehaviorSummary");
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert_eq!(pass.dependencies(), vec!["RawFactCollector"]);
    }

    #[test]
    fn test_ir_behavior_summary_pass_no_ir_module() {
        let mut ctx = PassContext::new();
        let pass = IRBehaviorSummaryPass::new();
        let result = pass.run(&mut ctx).unwrap();
        assert_eq!(result.stats.get("behaviors_extracted"), Some(&0));
    }

    #[test]
    fn test_ir_behavior_summary_pass_with_conditional_release() {
        let mut ctx = PassContext::new();
        let ir = r#"
            define void @release_string(ptr %s) {
            entry:
                %22 = atomicrmw sub ptr %s, i32 2 monotonic
                %23 = icmp eq i32 %22, 2
                br i1 %23, label %destroy, label %exit
            destroy:
                tail call void @Bun__WTFStringImpl__destroy(ptr %s)
                ret void
            exit:
                ret void
            }
        "#;
        let module = IRModule::parse_from_text(ir);
        ctx.store("ir_module", module);

        let pass = IRBehaviorSummaryPass::new();
        let result = pass.run(&mut ctx).unwrap();

        assert_eq!(result.stats.get("conditional_release"), Some(&1));
        assert_eq!(result.stats.get("summaries_from_behavior"), Some(&1));

        // Verify that behaviors were stored in context
        let behaviors: Vec<FunctionBehavior> = ctx.get("function_behaviors").unwrap();
        assert_eq!(behaviors.len(), 1);
    }
}
