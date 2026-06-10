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
        BehaviorPattern::StackToGlobalEscape {
            global_target,
            alloca_reg,
        } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::EscapedToCaller,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "StackToGlobalEscape: {} stores alloca-derived pointer {} to global {} — use-after-return",
                    func_name, alloca_reg, global_target
                ),
            )]
        }
        BehaviorPattern::ReturnAlias { aliased_param } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::FromParameter,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "ReturnAlias: {} returns alias of parameter {} without ownership transfer",
                    func_name, aliased_param
                ),
            )]
        }
        BehaviorPattern::FreeThenCallbackUse {
            freed_reg,
            use_callee,
        } => {
            let callee_name = use_callee.as_deref().unwrap_or("<indirect_call>");
            vec![SemanticFact::new(
                key,
                SemanticKind::AliasOfReleased,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "FreeThenCallbackUse: {} frees register {} then passes it to {} — use-after-free (CWE-416)",
                    func_name, freed_reg, callee_name
                ),
            )]
        }
    }
}

#[cfg(test)]
mod tests {
    // NOTE: Tests below mix unit tests (no external deps) with E2E diagnostic
    // tests that load .ll fixtures from ~/code/ffi-demo/output/. The E2E
    // tests (free_then_callback_use_real_ll, _e2e_candidate, etc.) should
    // eventually migrate to tests/integration_tests.rs for consistency.
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

    /// Objective: Verify that FreeThenCallbackUse is detected from the exact IR
    ///            produced by clang for uaf_through_ffi in c_ffi_traps.c (TRAP-C-9).
    /// Invariants: semantic_facts contains FreeThenCallbackUse evidence text.
    #[test]
    fn test_ir_behavior_summary_pass_free_then_callback_use() {
        let mut ctx = PassContext::new();
        // Exact IR from c_ffi_traps.ll — note the `tail` prefix on calls and
        // the cross-basic-block structure (free in block 3, use in block 6).
        let ir = r#"
            define void @uaf_through_ffi() local_unnamed_addr {
entry:
                %1 = tail call dereferenceable_or_null(32) ptr @malloc(i64 noundef 32)
                %2 = icmp eq ptr %1, null
                br i1 %2, label %8, label %3
3:
                tail call void @free(ptr noundef nonnull %1)
                %4 = load ptr, ptr @g_callback, align 8
                %5 = icmp eq ptr %4, null
                br i1 %5, label %8, label %6
6:
                %7 = load ptr, ptr @g_user_data, align 8
                tail call void %4(ptr noundef %7, ptr noundef nonnull %1, i64 noundef 32)
                br label %8
8:
                ret void
            }
        "#;
        let module = IRModule::parse_from_text(ir);
        ctx.store("ir_module", module.clone());

        let pass = IRBehaviorSummaryPass::new();
        let _result = pass.run(&mut ctx).unwrap();

        // Verify that semantic facts were emitted
        let facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap();

        // Debug: print detected patterns and facts on failure
        let behaviors: Vec<FunctionBehavior> = ctx.get("function_behaviors").unwrap();
        for b in &behaviors {
            if b.name == "uaf_through_ffi" {
                for p in &b.patterns {
                    eprintln!("[DEBUG] Pattern: {:?}", p);
                }
            }
        }
        for f in &facts {
            eprintln!("[DEBUG] Fact: {:?} | {}", f.kind, f.evidence);
        }

        let ftcu_fact = facts
            .iter()
            .find(|f| f.evidence.contains("FreeThenCallbackUse"));
        assert!(
            ftcu_fact.is_some(),
            "Should emit FreeThenCallbackUse semantic fact, got: {:?}",
            facts.iter().map(|f| &f.evidence).collect::<Vec<_>>()
        );

        // Verify function behaviors include the pattern
        let behaviors: Vec<FunctionBehavior> = ctx.get("function_behaviors").unwrap();
        let uaf_behavior = behaviors.iter().find(|b| b.name == "uaf_through_ffi");
        assert!(
            uaf_behavior.is_some(),
            "Should have behavior for uaf_through_ffi, got: {:?}",
            behaviors.iter().map(|b| &b.name).collect::<Vec<_>>()
        );
        let ftcu_pattern = uaf_behavior
            .unwrap()
            .patterns
            .iter()
            .find(|p| matches!(p, BehaviorPattern::FreeThenCallbackUse { .. }));
        assert!(
            ftcu_pattern.is_some(),
            "uaf_through_ffi should have FreeThenCallbackUse pattern, got: {:?}",
            uaf_behavior.unwrap().patterns
        );
    }

    /// Load the ACTUAL c_ffi_traps.ll from disk and verify FreeThenCallbackUse fires.
    /// This tests the real file (not hand-crafted IR) to catch any parsing differences.
    #[test]
    fn test_ir_behavior_summary_pass_free_then_callback_use_real_ll() {
        // Try multiple possible paths for ffi-demo output
        let paths = [
            "../../ffi-demo/output/c_ffi_traps.ll",
            "../../../ffi-demo/output/c_ffi_traps.ll",
            "/Users/scc/code/ffi-demo/output/c_ffi_traps.ll",
        ];
        let mut loaded = None;
        for p in &paths {
            if let Ok(m) = IRModule::load_from_file(std::path::Path::new(p)) {
                loaded = Some(m);
                break;
            }
        }
        let m = match loaded {
            Some(m) => m,
            None => {
                eprintln!("[SKIP] c_ffi_traps.ll not found in any search path");
                return;
            }
        };

        let mut ctx = PassContext::new();
        ctx.store("ir_module", m.clone());
        let pass = IRBehaviorSummaryPass::new();
        let _result = pass.run(&mut ctx).unwrap();

        let behaviors: Vec<FunctionBehavior> = ctx.get("function_behaviors").unwrap();
        let uaf_behavior = behaviors.iter().find(|b| b.name == "uaf_through_ffi");

        if let Some(b) = uaf_behavior {
            for p in &b.patterns {
                eprintln!("[REAL-LL] Pattern: {:?}", p);
            }
            let ftcu = b
                .patterns
                .iter()
                .find(|p| matches!(p, BehaviorPattern::FreeThenCallbackUse { .. }));
            assert!(
                ftcu.is_some(),
                "Real .ll file: uaf_through_ffi should have FreeThenCallbackUse, got: {:?}",
                b.patterns
            );
        } else {
            panic!(
                "Real .ll file: uaf_through_ffi not found in behaviors. Functions: {:?}",
                behaviors.iter().map(|b| &b.name).collect::<Vec<_>>()
            );
        }

        let facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap();
        for f in &facts {
            if let omniscope_semantics::SemanticKey::Symbol(name) = &f.key {
                if name.contains("uaf_through_ffi") {
                    eprintln!("[REAL-LL] Fact: {:?} | {}", f.kind, f.evidence);
                }
            }
        }
    }

    /// End-to-end test: run IRBehaviorSummaryPass + IssueCandidateBuilderPass on
    /// real c_ffi_traps.ll to verify FreeThenCallbackUse produces a candidate.
    #[test]
    fn test_free_then_callback_use_e2e_candidate() {
        let paths = [
            "../../ffi-demo/output/c_ffi_traps.ll",
            "../../../ffi-demo/output/c_ffi_traps.ll",
            "/Users/scc/code/ffi-demo/output/c_ffi_traps.ll",
        ];
        let mut loaded = None;
        for p in &paths {
            if let Ok(m) = IRModule::load_from_file(std::path::Path::new(p)) {
                loaded = Some(m);
                break;
            }
        }
        let m = match loaded {
            Some(m) => m,
            None => {
                eprintln!("[SKIP] c_ffi_traps.ll not found");
                return;
            }
        };

        // Run IRBehaviorSummaryPass
        let mut ctx = PassContext::new();
        ctx.store("ir_module", m.clone());
        let pass1 = IRBehaviorSummaryPass::new();
        let _ = pass1.run(&mut ctx).unwrap();

        // Check semantic facts
        let facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap_or_default();
        let ftcu_facts: Vec<_> = facts
            .iter()
            .filter(|f| f.evidence.contains("FreeThenCallbackUse"))
            .collect();
        eprintln!(
            "[E2E] FreeThenCallbackUse semantic facts: {}",
            ftcu_facts.len()
        );
        for f in &ftcu_facts {
            eprintln!("[E2E]   {:?}", f.evidence);
        }

        // Run IssueCandidateBuilderPass (need minimum context)
        use crate::resource::issue_candidate_builder::IssueCandidateBuilderPass;
        let pass2 = IssueCandidateBuilderPass::new();
        let result = pass2.run(&mut ctx);
        eprintln!(
            "[E2E] IssueCandidateBuilderPass result: {:?}",
            result.is_ok()
        );

        // Check candidates
        use omniscope_types::IssueCandidateKind;
        let candidates: Vec<omniscope_core::IssueCandidate> =
            ctx.get("issue_candidates").unwrap_or_default();
        let ftcu_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| {
                c.kind == IssueCandidateKind::UseAfterFree
                    && c.description
                        .as_deref()
                        .is_some_and(|d| d.contains("callback"))
            })
            .collect();
        eprintln!(
            "[E2E] FreeThenCallbackUse candidates: {}",
            ftcu_candidates.len()
        );
        for c in &ftcu_candidates {
            eprintln!(
                "[E2E]   kind={:?} func={} verdict={:?} ffi_evidence={:?}",
                c.kind, c.alloc_function, c.verdict, c.ffi_evidence
            );
        }

        assert!(
            !ftcu_facts.is_empty(),
            "Expected at least one FreeThenCallbackUse semantic fact"
        );
        assert!(
            !ftcu_candidates.is_empty(),
            "Expected at least one FreeThenCallbackUse candidate, total candidates: {}",
            candidates.len()
        );
    }

    /// Full-pipeline diagnostic: run all passes on c_ffi_traps.ll and trace
    /// the FreeThenCallbackUse candidate through builder → verifier → reconcile → emit.
    ///
    /// Objective: Identify where the UAF candidate is lost in the full pipeline.
    /// Invariants: After full pipeline, a UseAfterFree issue for uaf_through_ffi exists.
    #[test]
    fn test_free_then_callback_use_full_pipeline_trace() {
        use crate::resource::issue_candidate_builder::IssueCandidateBuilderPass;
        use crate::resource::issue_verifier::IssueVerifierPass;
        use omniscope_core::IssueKind;

        let paths = [
            "../../ffi-demo/output/c_ffi_traps.ll",
            "../../../ffi-demo/output/c_ffi_traps.ll",
            "/Users/scc/code/ffi-demo/output/c_ffi_traps.ll",
        ];
        let mut loaded = None;
        for p in &paths {
            if let Ok(m) = IRModule::load_from_file(std::path::Path::new(p)) {
                loaded = Some(m);
                break;
            }
        }
        let m = match loaded {
            Some(m) => m,
            None => {
                eprintln!("[SKIP] c_ffi_traps.ll not found");
                return;
            }
        };

        // Run IRBehaviorSummaryPass
        let mut ctx = PassContext::new();
        ctx.store("ir_module", m.clone());
        let pass1 = IRBehaviorSummaryPass::new();
        let _ = pass1.run(&mut ctx).unwrap();

        // Check semantic facts
        let facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap_or_default();
        let ftcu_facts: Vec<_> = facts
            .iter()
            .filter(|f| f.evidence.contains("FreeThenCallbackUse"))
            .collect();
        eprintln!(
            "[PIPELINE] FreeThenCallbackUse semantic facts: {}",
            ftcu_facts.len()
        );

        // Run IssueCandidateBuilderPass
        let pass2 = IssueCandidateBuilderPass::new();
        let _ = pass2.run(&mut ctx);

        let candidates: Vec<omniscope_core::IssueCandidate> =
            ctx.get("issue_candidates").unwrap_or_default();
        let uaf_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| {
                c.kind == omniscope_types::IssueCandidateKind::UseAfterFree
                    && c.alloc_function.contains("uaf_through_ffi")
            })
            .collect();
        eprintln!(
            "[PIPELINE] UseAfterFree candidates after builder: {}",
            uaf_candidates.len()
        );
        for c in &uaf_candidates {
            eprintln!(
                "[PIPELINE]   id={} kind={:?} func={} verdict={:?} ffi_evidence={:?} resource_id={:?}",
                c.id, c.kind, c.alloc_function, c.verdict, c.ffi_evidence, c.resource_id
            );
        }

        // Run IssueVerifierPass
        let pass3 = IssueVerifierPass::new();
        let result = pass3.run(&mut ctx);
        eprintln!("[PIPELINE] IssueVerifierPass result: {:?}", result.is_ok());
        if let Ok(ref r) = result {
            eprintln!("[PIPELINE]   PassResult stats: {:?}", r.stats);
            eprintln!("[PIPELINE]   PassResult issues: {}", r.issues.len());
            for i in &r.issues {
                eprintln!(
                    "[PIPELINE]     PR-ISSUE kind={:?} symbol={}",
                    i.kind,
                    i.symbol.as_str()
                );
            }
        }

        // Check verified candidates
        let verified: Vec<omniscope_core::IssueCandidate> =
            ctx.get("verified_candidates").unwrap_or_default();
        let uaf_verified: Vec<_> = verified
            .iter()
            .filter(|c| {
                c.kind == omniscope_types::IssueCandidateKind::UseAfterFree
                    && c.alloc_function.contains("uaf_through_ffi")
            })
            .collect();
        eprintln!(
            "[PIPELINE] UseAfterFree verified for uaf: {}",
            uaf_verified.len()
        );
        for c in &uaf_verified {
            eprintln!(
                "[PIPELINE]   id={} kind={:?} func={} verdict={:?} desc={:?}",
                c.id, c.kind, c.alloc_function, c.verdict, c.description
            );
        }

        // Check final issues
        let issues: Vec<omniscope_core::Issue> = ctx.get("issues").unwrap_or_default();
        let uaf_issues: Vec<_> = issues
            .iter()
            .filter(|i| {
                i.kind == IssueKind::UseAfterFree
                    && i.location
                        .as_ref()
                        .and_then(|l| l.function.as_deref())
                        .is_some_and(|f| f.contains("uaf_through_ffi"))
            })
            .collect();
        eprintln!(
            "[PIPELINE] UseAfterFree issues for uaf: {}",
            uaf_issues.len()
        );
        for i in &uaf_issues {
            eprintln!(
                "[PIPELINE]   kind={:?} symbol={} desc={}",
                i.kind,
                i.symbol.as_str(),
                i.description
            );
        }

        // Dump ALL issues for context
        eprintln!("[PIPELINE] Total issues: {}", issues.len());

        // Check suppressed issues too
        let suppressed: Vec<omniscope_core::Issue> =
            ctx.get("suppressed_issues").unwrap_or_default();
        eprintln!("[PIPELINE] Suppressed issues: {}", suppressed.len());
        for i in &suppressed {
            eprintln!(
                "[PIPELINE]   SUPPRESSED kind={:?} symbol={}",
                i.kind,
                i.symbol.as_str()
            );
        }

        // Extended diagnostics: dump ALL candidates and verified state
        eprintln!("[PIPELINE] === TOTAL CANDIDATES: {} ===", candidates.len());
        for (idx, c) in candidates.iter().enumerate() {
            eprintln!(
                "[PIPELINE]   [{}] kind={:?} func={} verdict={:?} reportable={} ffi={}",
                idx,
                c.kind,
                c.alloc_function,
                c.verdict,
                c.is_reportable(),
                c.has_ffi_evidence()
            );
        }
        eprintln!("[PIPELINE] === TOTAL VERIFIED: {} ===", verified.len());
        for (idx, c) in verified.iter().enumerate() {
            eprintln!(
                "[PIPELINE]   [{}] kind={:?} func={} verdict={:?} reportable={}",
                idx,
                c.kind,
                c.alloc_function,
                c.verdict,
                c.is_reportable()
            );
        }

        // Check reconcile actions by running reconcile manually
        use std::collections::HashSet;
        let reportable_set: HashSet<usize> = verified
            .iter()
            .enumerate()
            .filter(|(_idx, c)| c.is_reportable())
            .map(|(idx, _)| idx)
            .collect();
        eprintln!("[PIPELINE] reportable_set: {:?}", reportable_set);

        // We can't easily call reconcile_candidates from here since it's crate-private,
        // but we can check groupings
        eprintln!("[PIPELINE] === RESOURCE KEY GROUPING ===");
        use std::collections::HashMap;
        let mut key_groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, c) in verified.iter().enumerate() {
            let key = if let Some(rid) = c.resource_id {
                format!("Instance({})", rid)
            } else {
                format!(
                    "AllocSite(caller={}, fn={})",
                    c.alloc_caller.as_deref().unwrap_or(&c.alloc_function),
                    c.alloc_function
                )
            };
            key_groups.entry(key).or_default().push(idx);
        }
        for (key, indices) in &key_groups {
            eprintln!("[PIPELINE]   {}: {:?}", key, indices);
        }
        for i in &issues {
            eprintln!(
                "[PIPELINE]   kind={:?} symbol={} location_func={}",
                i.kind,
                i.symbol.as_str(),
                i.location
                    .as_ref()
                    .and_then(|l| l.function.as_deref())
                    .unwrap_or("<none>")
            );
        }

        // Assert: we expect at least one fact and one candidate
        assert!(
            !ftcu_facts.is_empty(),
            "Expected FreeThenCallbackUse semantic facts"
        );
        assert!(
            !uaf_candidates.is_empty(),
            "Expected UseAfterFree candidates from builder"
        );
    }

    /// Full Pipeline diagnostic: run the actual Pipeline on c_ffi_traps.ll
    /// and trace whether the UAF issue for uaf_through_ffi survives to final output.
    ///
    /// Objective: Identify where the UAF issue is lost in the FULL pipeline
    /// (which has 20 passes including SRT population).
    /// Invariants: Pipeline result contains a UseAfterFree issue for uaf_through_ffi.
    #[test]
    fn test_free_then_callback_use_full_pipeline_diagnostic() {
        use omniscope_core::IssueKind;
        use omniscope_pipeline::Pipeline;

        let paths = [
            "../../ffi-demo/output/c_ffi_traps.ll",
            "../../../ffi-demo/output/c_ffi_traps.ll",
            "/Users/scc/code/ffi-demo/output/c_ffi_traps.ll",
        ];
        let mut loaded = None;
        for p in &paths {
            if let Ok(m) = IRModule::load_from_file(std::path::Path::new(p)) {
                loaded = Some(m);
                break;
            }
        }
        let m = match loaded {
            Some(m) => m,
            None => {
                eprintln!("[SKIP] c_ffi_traps.ll not found");
                return;
            }
        };

        // Run the FULL pipeline (20 passes)
        let mut pipeline = Pipeline::new();
        pipeline.register_default_passes();
        pipeline.set_ir_module(m);
        let result = pipeline.run().unwrap();

        // Dump ALL issues from pipeline result
        eprintln!("[FULL-PIPELINE] Total issues: {}", result.issues().len());
        for i in result.issues() {
            eprintln!(
                "[FULL-PIPELINE]   ISSUE kind={:?} symbol='{}' location_func={} desc={}",
                i.kind,
                i.symbol.as_str(),
                i.location
                    .as_ref()
                    .and_then(|l| l.function.as_deref())
                    .unwrap_or("<none>"),
                i.description
            );
        }

        // Look specifically for UAF on uaf_through_ffi
        let uaf_issues: Vec<_> = result
            .issues()
            .iter()
            .filter(|i| {
                i.kind == IssueKind::UseAfterFree
                    && i.location
                        .as_ref()
                        .and_then(|l| l.function.as_deref())
                        .is_some_and(|f| f.contains("uaf_through_ffi"))
            })
            .collect();
        eprintln!(
            "[FULL-PIPELINE] UseAfterFree issues for uaf_through_ffi: {}",
            uaf_issues.len()
        );
        for i in &uaf_issues {
            eprintln!(
                "[FULL-PIPELINE]   UAF-ISSUE kind={:?} symbol='{}' desc={}",
                i.kind,
                i.symbol.as_str(),
                i.description
            );
        }

        // Also check all pass results for any UAF-related data
        eprintln!("[FULL-PIPELINE] Pass results: {}", result.pass_count());
        for pr in &result.pass_results {
            if !pr.issues.is_empty() {
                eprintln!(
                    "[FULL-PIPELINE]   PASS '{}' has {} issues",
                    pr.name,
                    pr.issues.len()
                );
                for i in &pr.issues {
                    if i.kind == IssueKind::UseAfterFree {
                        eprintln!(
                            "[FULL-PIPELINE]     PASS-UAF kind={:?} symbol='{}' loc={}",
                            i.kind,
                            i.symbol.as_str(),
                            i.location
                                .as_ref()
                                .and_then(|l| l.function.as_deref())
                                .unwrap_or("<none>")
                        );
                    }
                }
            }
        }

        // Check if there's an IssueVerifier pass result with stats
        if let Some(verifier_result) = result.get_pass_result("IssueVerifier") {
            eprintln!(
                "[FULL-PIPELINE] IssueVerifier stats: {:?}",
                verifier_result.stats
            );
            for (key, value) in &verifier_result.stats {
                eprintln!("[FULL-PIPELINE]   STAT {}={}", key, value);
            }
        }

        // Diagnostic: dump what we can about why UAF was suppressed
        // The stats show semantic_suppressed=5, meaning 5 candidates were suppressed
        // by EvidenceBundle semantic suppression. The UAF candidate is likely among them.
        eprintln!("[FULL-PIPELINE] === DIAGNOSTIC: UAF SUPPRESSION ROOT CAUSE ===");
        eprintln!("[FULL-PIPELINE] semantic_suppressed=5 means EvidenceBundle found suppressing SemanticKinds");
        eprintln!("[FULL-PIPELINE] For UAF candidate (alloc_function='uaf_through_ffi'), the bundle looks up");
        eprintln!("[FULL-PIPELINE] srt_resolutions['uaf_through_ffi'] which may contain suppressing kinds");
        eprintln!("[FULL-PIPELINE] Suppressing kinds: RuntimeManagedResource, StoredToOwner, StoredToRuntime,");
        eprintln!("[FULL-PIPELINE]   EscapedToCaller, EscapedToOutParam, RaiiDropRelease, CppDestructor, DestructorRelease");

        // Assert: the full pipeline should produce at least one UAF for uaf_through_ffi
        assert!(
            !uaf_issues.is_empty(),
            "Full pipeline should emit UseAfterFree for uaf_through_ffi, got {} total issues. Issues: {:?}",
            result.issues().len(),
            result.issues().iter().map(|i| format!("{:?}({})", i.kind, i.symbol.as_str())).collect::<Vec<_>>()
        );
    }
}
