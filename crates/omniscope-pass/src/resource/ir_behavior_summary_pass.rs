//! IR behavior summary pass — extracts function behaviors from IR
//! instruction patterns and converts them into ResourceSummary entries
//! and SemanticFact records.
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
//! - IssueCandidateBuilderPass: to attach semantic facts as evidence
//!
//! # Semantic Fact Emission (Phase 3)
//!
//! Each detected BehaviorPattern is mapped to one or more SemanticFact
//! records with appropriate confidence and evidence strings. These facts
//! are stored in the pass context under "semantic_facts" for downstream
//! consumption by issue candidate builders.

use omniscope_core::Result;
use omniscope_ir::IRModule;
use omniscope_semantics::{
    behavior_to_summary, extract_behavior, BehaviorPattern, EscapeType, FactConfidence, FactSource,
    FunctionBehavior, PosixOpCategory, SemanticFact, SemanticKey, SemanticKind, SummaryStore,
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
        let mut semantic_facts: Vec<SemanticFact> = Vec::new();

        // Iterate over all function bodies in stable order.
        // HashMap iteration order is non-deterministic, so we sort by
        // function name first.
        let mut func_bodies: Vec<_> = module.function_bodies.iter().collect();
        func_bodies.sort_by(|a, b| a.0.cmp(b.0));

        for (_name, body) in func_bodies.iter() {
            let behavior = extract_behavior(body);
            behaviors.push(behavior.clone());

            // Convert behavior to summary and add to store
            if !behavior.patterns.is_empty() {
                // Derive a deterministic FunctionId from the function name
                // rather than using an enumeration index. The enumeration
                // index depends on HashMap iteration order and has no
                // relationship to function IDs used elsewhere in the pipeline
                // (e.g., contract_graph_builder's func_id_map). Using a
                // name-based hash ensures:
                //   1. Deterministic across runs (same name → same ID)
                //   2. Independent of HashMap iteration order
                //   3. Same ID produced regardless of which other functions
                //      are present in the module
                // Note: SummaryStore consumers use find_by_name(), not
                // get(FunctionId), so the exact value is only used as a
                // HashMap key — it just needs to be unique and deterministic.
                let func_id = name_to_stable_id(&behavior.name);
                let summary = behavior_to_summary(&behavior, func_id, func_id);
                summary_store.insert(summary);

                // Emit semantic facts from detected patterns (Phase 3)
                for pattern in &behavior.patterns {
                    let facts = pattern_to_facts(pattern, &behavior.name, func_id);
                    semantic_facts.extend(facts);
                }
            }
        }

        // Store behaviors for downstream passes (M2 integration)
        ctx.store("function_behaviors", behaviors.clone());
        ctx.store("ir_behavior_summary_store", summary_store.clone());
        // Store semantic facts for downstream issue candidate builders (Phase 3)
        ctx.store("semantic_facts", semantic_facts.clone());

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
        result.add_stat("semantic_facts_emitted", semantic_facts.len());
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

/// Derives a deterministic FunctionId from a function name.
///
/// Uses a simple FNV-1a-inspired hash to produce a stable u64 ID.
/// This ensures the same function name always maps to the same ID,
/// regardless of module composition or HashMap iteration order.
/// The ID only needs to be unique per name and deterministic —
/// it does not need to align with function IDs from other passes
/// because SummaryStore consumers use `find_by_name()` for lookup.
fn name_to_stable_id(name: &str) -> u64 {
    // FNV-1a offset basis and prime for 64-bit
    let mut hash: u64 = 14_695_981_039_346_656_037;
    for byte in name.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    // Avoid 0 as it's used as a sentinel ("no ID") elsewhere
    if hash == 0 {
        1
    } else {
        hash
    }
}

/// Maps a detected behavior pattern to semantic fact(s).
///
/// Each BehaviorPattern produces one or more SemanticFact records
/// with the appropriate SemanticKind, confidence, and evidence.
/// The key is constructed from the function name so downstream
/// consumers can look up facts by function symbol.
fn pattern_to_facts(
    pattern: &BehaviorPattern,
    func_name: &str,
    _func_id: u64,
) -> Vec<SemanticFact> {
    // Use Symbol key keyed by function name, NOT Resource(func_id).
    // func_id is derived from the function name hash (name_to_stable_id),
    // not from the contract graph's instance allocation IDs.
    let key = SemanticKey::Symbol(func_name.to_string());
    match pattern {
        BehaviorPattern::ConditionalRelease {
            atomic_op,
            threshold,
        } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::ReleaseOnAllExitPaths,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "ConditionalRelease: atomicrmw {} with threshold {} in {}",
                    atomic_op, threshold, func_name
                ),
            )]
        }
        BehaviorPattern::PureComputation => {
            vec![SemanticFact::new(
                key,
                SemanticKind::NonMemoryResource,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "PureComputation: {} has no ownership side effects",
                    func_name
                ),
            )]
        }
        BehaviorPattern::OwnershipTransfer { is_acquire } => {
            let kind = if *is_acquire {
                SemanticKind::HeapProvenance
            } else {
                SemanticKind::IntoRawTransfer
            };
            vec![SemanticFact::new(
                key,
                kind,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "OwnershipTransfer: {} (is_acquire={})",
                    func_name, is_acquire
                ),
            )]
        }
        BehaviorPattern::PointerProjection => {
            vec![SemanticFact::new(
                key,
                SemanticKind::FromParameter,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "PointerProjection: {} borrows pointer without ownership change",
                    func_name
                ),
            )]
        }
        BehaviorPattern::Initialization => {
            vec![SemanticFact::new(
                key,
                SemanticKind::NonMemoryResource,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "Initialization: {} writes to struct fields, no leak",
                    func_name
                ),
            )]
        }
        BehaviorPattern::InternalBridge => {
            vec![SemanticFact::new(
                key,
                SemanticKind::DeclaredCrossBoundary,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "InternalBridge: {} calls only same-project functions",
                    func_name
                ),
            )]
        }
        BehaviorPattern::BorrowedReturn {
            from_readonly_param,
        } => {
            let kind = if *from_readonly_param {
                SemanticKind::ReadonlyParam
            } else {
                SemanticKind::FromParameter
            };
            vec![SemanticFact::new(
                key,
                kind,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "BorrowedReturn: {} returns derived pointer (readonly={})",
                    func_name, from_readonly_param
                ),
            )]
        }
        BehaviorPattern::RAiiDropRelease { is_drop_in_place } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::RaiiDropRelease,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "RAiiDropRelease: {} (drop_in_place={})",
                    func_name, is_drop_in_place
                ),
            )]
        }
        BehaviorPattern::IntoRawTransfer => {
            vec![SemanticFact::new(
                key,
                SemanticKind::IntoRawTransfer,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "IntoRawTransfer: {} transfers ownership via into_raw",
                    func_name
                ),
            )]
        }
        BehaviorPattern::PosixNonMemoryOp { category } => {
            let kind = match category {
                PosixOpCategory::File => SemanticKind::FileOperation,
                PosixOpCategory::Network => SemanticKind::NetworkOperation,
                PosixOpCategory::Process => SemanticKind::ProcessOperation,
                PosixOpCategory::Other => SemanticKind::NonMemoryResource,
            };
            vec![SemanticFact::new(
                key,
                kind,
                FactConfidence::High,
                FactSource::IRPattern,
                format!("PosixNonMemoryOp: {} (category={:?})", func_name, category),
            )]
        }
        BehaviorPattern::NullGuardedRelease { arg_index } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::NullOnErrorPath,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "NullGuardedRelease: {} checks arg {} before release",
                    func_name, arg_index
                ),
            )]
        }
        BehaviorPattern::NullStoreAfterRelease { arg_index } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::AliasOfReleased,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "NullStoreAfterRelease: {} nulls slot after releasing arg {}",
                    func_name, arg_index
                ),
            )]
        }
        BehaviorPattern::FallibleOutParamInit { out_arg_index } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::FallibleOutParamInit,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "FallibleOutParamInit: {} initializes out-param arg {}",
                    func_name, out_arg_index
                ),
            )]
        }
        BehaviorPattern::OutParamNullOnError { out_arg_index } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::NullOnErrorPath,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "OutParamNullOnError: {} nulls out-param arg {} on error",
                    func_name, out_arg_index
                ),
            )]
        }
        BehaviorPattern::OutParamOwnedOnSuccess { out_arg_index } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::EscapedToOutParam,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "OutParamOwnedOnSuccess: {} gives ownership via out-param arg {}",
                    func_name, out_arg_index
                ),
            )]
        }
        BehaviorPattern::StoreToOwner { owner_field } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::StoredToOwner,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "StoreToOwner: {} stores resource to field '{}'",
                    func_name, owner_field
                ),
            )]
        }
        BehaviorPattern::StoreToRuntime { runtime_target } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::StoredToRuntime,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "StoreToRuntime: {} stores resource to runtime target '{}'",
                    func_name, runtime_target
                ),
            )]
        }
        BehaviorPattern::ResourceEscape { escape_type } => {
            let kind = match escape_type {
                EscapeType::ReturnValue => SemanticKind::EscapedToCaller,
                EscapeType::OutParameter => SemanticKind::EscapedToOutParam,
            };
            vec![SemanticFact::new(
                key,
                kind,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "ResourceEscape: {} escapes via {:?}",
                    func_name, escape_type
                ),
            )]
        }
        BehaviorPattern::ReleaseOnAllExitPaths { release_function } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::ReleaseOnAllExitPaths,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "ReleaseOnAllExitPaths: {} releases via {} on all paths",
                    func_name, release_function
                ),
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ir_behavior_summary_pass_creation() {
        let pass = IRBehaviorSummaryPass::new();
        assert_eq!(
            pass.name(),
            "IRBehaviorSummary",
            "Pass name should be IRBehaviorSummary"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Pass kind should be Analysis"
        );
        assert_eq!(
            pass.dependencies(),
            vec!["RawFactCollector"],
            "Dependencies should be RawFactCollector"
        );
    }

    #[test]
    fn test_ir_behavior_summary_pass_no_ir_module() {
        let mut ctx = PassContext::new();
        let pass = IRBehaviorSummaryPass::new();
        let result = pass.run(&mut ctx).unwrap();
        assert_eq!(
            result.stats.get("behaviors_extracted"),
            Some(&0),
            "No IR module should result in 0 behaviors extracted"
        );
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

        assert_eq!(
            result.stats.get("conditional_release"),
            Some(&1),
            "Conditional release should be detected"
        );
        assert_eq!(
            result.stats.get("summaries_from_behavior"),
            Some(&1),
            "Should generate 1 summary from behavior"
        );

        // Verify that behaviors were stored in context
        let behaviors: Vec<FunctionBehavior> = ctx.get("function_behaviors").unwrap();
        assert_eq!(behaviors.len(), 1, "Should have 1 behavior extracted");
    }
}
