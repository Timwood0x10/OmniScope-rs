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
    behavior_to_summary, extract_behavior, BehaviorPattern, FunctionBehavior, SemanticFact,
    SummaryStore, TypeConfusionDetector,
};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::pattern_to_facts::pattern_to_facts;

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

        // ── Type confusion detection (Phase 3: StructWidthMismatch) ──
        // Run TypeConfusionDetector on each function body to detect
        // cross-language struct width mismatches (e.g., void* casts that
        // truncate data). Convert results to SemanticFact records so the
        // IssueCandidateBuilder can generate BoundaryMisuse candidates.
        let type_confusion_detector = TypeConfusionDetector::new();
        for (_name, body) in func_bodies.iter() {
            let analysis = type_confusion_detector.analyze_function(body);
            if !analysis.patterns.is_empty() {
                let tc_facts = TypeConfusionDetector::patterns_to_semantic_facts(
                    &analysis.patterns,
                    &body.name,
                );
                semantic_facts.extend(tc_facts);
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
        let mut buffer_overflow_count = 0;

        for behavior in &behaviors {
            for pattern in &behavior.patterns {
                match pattern {
                    BehaviorPattern::ConditionalRelease { .. } => conditional_release_count += 1,
                    BehaviorPattern::OwnershipTransfer { .. } => ownership_transfer_count += 1,
                    BehaviorPattern::PureComputation => pure_computation_count += 1,
                    BehaviorPattern::PointerProjection => pointer_projection_count += 1,
                    BehaviorPattern::Initialization => initialization_count += 1,
                    BehaviorPattern::InternalBridge => internal_bridge_count += 1,
                    BehaviorPattern::BufferOverflow { .. } => buffer_overflow_count += 1,
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
        result.add_stat("buffer_overflow", buffer_overflow_count);

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
