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
//!
//! # SRT Resolution Population
//!
//! After building summaries, this pass extracts semantic resolutions
//! (R-0 MutableParam, R-8 FromParameter, R-1 HeapProvenance, etc.)
//! from the summary evidence and writes them into `srt_resolutions`
//! in the pass context. This is what makes the SRT gate in
//! `PassContext::emit_issue` actually work — without this step,
//! the gate has no data to query.

use std::collections::HashMap;

use omniscope_core::Result;
use omniscope_semantics::{
    behavior_to_summary, infer_summary_for_symbol, FamilyRegistry, FunctionBehavior, SemanticKind,
    SummaryStore,
};
use omniscope_types::EvidenceKind;

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
        ctx.store("summary_store", store.clone());
        ctx.store("structural_inference_done", true);

        // ── Build SRT resolutions from summary evidence ──
        // This populates `srt_resolutions` so that `PassContext::emit_issue`
        // can enforce the SRT gate. Without this, the gate is a no-op.
        let mut srt_resolutions: HashMap<String, Vec<SemanticKind>> = HashMap::new();

        for (_, summary) in store.iter() {
            let symbol = &summary.name;
            let mut kinds: Vec<SemanticKind> = Vec::new();

            for evidence in &summary.evidence {
                match evidence.kind {
                    // R-0: Parameter mutability → MutableParam suppresses WriteToImmutable
                    EvidenceKind::ParameterMutability => {
                        if evidence.description.contains("Mutable") {
                            kinds.push(SemanticKind::MutableParam);
                        } else if evidence.description.contains("Readonly") {
                            kinds.push(SemanticKind::ReadonlyParam);
                        }
                    }
                    // R-1: Heap/global provenance
                    EvidenceKind::SameFamilyRelease => {
                        kinds.push(SemanticKind::HeapProvenance);
                    }
                    // R-3: RAII drop release
                    EvidenceKind::RaiiDropRelease => {
                        kinds.push(SemanticKind::RaiiDropRelease);
                    }
                    // R-6: Ownership transfer — distinguish subtypes by description.
                    // Not all OwnershipTransfer is into_raw; box_leak and
                    // manually_drop are also ownership escape patterns.
                    EvidenceKind::OwnershipTransfer => {
                        if evidence.description.contains("into_raw") {
                            kinds.push(SemanticKind::IntoRawTransfer);
                        }
                        // box::leak and ManuallyDrop::new transfer ownership
                        // but do NOT use into_raw — they are leak-style escapes.
                        // Currently there is no separate SemanticKind for these,
                        // so we still map to IntoRawTransfer but log a debug
                        // note for future refinement.
                        else {
                            tracing::debug!(
                                "OwnershipTransfer without into_raw pattern: \
                                 '{}' — mapped to IntoRawTransfer (may need \
                                 dedicated SemanticKind in the future)",
                                evidence.description
                            );
                            kinds.push(SemanticKind::IntoRawTransfer);
                        }
                    }
                    // R-4: POSIX syscall classification
                    EvidenceKind::PosixSyscallClass => {
                        if evidence.description.contains("file")
                            || evidence.description.contains("File")
                        {
                            kinds.push(SemanticKind::FileOperation);
                        } else if evidence.description.contains("network")
                            || evidence.description.contains("Network")
                        {
                            kinds.push(SemanticKind::NetworkOperation);
                        } else if evidence.description.contains("process")
                            || evidence.description.contains("Process")
                        {
                            kinds.push(SemanticKind::ProcessOperation);
                        }
                    }
                    // R-7: Library allocator release
                    EvidenceKind::SymbolPattern if evidence.description.contains("library") => {
                        kinds.push(SemanticKind::LibraryRelease);
                    }
                    _ => {}
                }
            }

            // R-8: FromParameter — if the function takes pointer parameters and
            // doesn't allocate, the pointer comes from the caller, not a stack escape.
            //
            // CRITICAL: Only annotate when we have high confidence the function
            // is at an FFI boundary (cross-language call). Annotating all Rust
            // functions that don't alloc/dealloc would suppress valid BorrowEscape
            // issues for internal functions.
            //
            // Heuristic: Rust mangled names that bridge to C (contain FFI
            // indicators) or are explicitly `extern "C"` wrappers.
            if summary.language_hint == omniscope_types::LanguageHint::Rust
                && !summary.acquires_resource()
                && !summary.releases_resource()
                && !summary.name.contains("alloc")
                && !summary.name.contains("dealloc")
                && is_ffi_boundary_function(&summary.name)
            {
                kinds.push(SemanticKind::FromParameter);
            }

            if !kinds.is_empty() {
                srt_resolutions.insert(symbol.clone(), kinds);
            }
        }

        // Also populate SRT from IRModule call instructions — but only for
        // callers that are at an FFI boundary. Previously, every caller not
        // in the registry was annotated with FromParameter, which suppressed
        // valid BorrowEscape issues for internal (non-FFI) functions.
        //
        // Now we only annotate when the call is external (is_external flag)
        // or the callee is an FFI symbol — these are the true cross-language
        // boundaries where pointer parameters come from the C side.
        let ir_module: Option<omniscope_ir::IRModule> = ctx.get("ir_module");
        if let Some(ref module) = ir_module {
            let registry = FamilyRegistry::new();
            for call in &module.calls {
                // Only annotate callers at FFI boundaries:
                // 1. The callee is an external call (is_external flag)
                // 2. The callee is a known symbol in the registry (alloc/dealloc/FFI)
                // 3. The callee name has FFI indicators (C-style naming)
                let callee = call.callee.trim_start_matches('@');
                let caller = call.caller.trim_start_matches('@');
                let is_ffi_call = call.is_external
                    || registry.lookup(callee).is_some()
                    || is_ffi_boundary_function(caller);

                // Only annotate the CALLER with FromParameter when it's an
                // FFI boundary — the caller's pointers come from its own
                // caller (parameters), so passing them to FFI is not a
                // "stack escape".
                //
                // Do NOT annotate the CALLEE. External FFI functions may
                // return null or allocate — we don't know their pointer
                // provenance.
                if !caller.is_empty() && is_ffi_call && registry.lookup(caller).is_none() {
                    srt_resolutions
                        .entry(caller.to_string())
                        .or_insert_with(|| vec![SemanticKind::FromParameter]);
                }
            }
            // Put IRModule back for downstream passes.
            ctx.store("ir_module", module.clone());
        }

        let srt_entry_count = srt_resolutions.len();
        ctx.store("srt_resolutions", srt_resolutions);

        let mut result = PassResult::new(self.name())
            .with_nodes(raw_facts.len())
            .with_duration(start.elapsed().as_millis() as u64);

        result.add_stat("inferred_summaries", inferred_count);
        result.add_stat("destructor_inferences", destructor_count);
        result.add_stat("bridge_inferences", bridge_count);
        result.add_stat("refcount_inferences", refcount_count);
        result.add_stat("static_lifetime_inferences", static_lifetime_count);
        result.add_stat("behavior_override_count", behavior_override_count);
        result.add_stat("srt_resolution_entries", srt_entry_count);

        Ok(result)
    }
}

impl Default for StructuralInferencePass {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks whether a function name indicates an FFI boundary function.
///
/// FFI boundary functions are those that sit at the Rust↔C interface:
/// - Rust `extern "C"` wrappers (typically have `extern` or `ffi` in path)
/// - C callback targets called from Rust (e.g., `_ZN...callback...`)
/// - Functions with C-style naming that bridge to foreign code
///
/// Internal Rust functions (e.g., `Vec::push`, `HashMap::insert`) should
/// NOT be annotated with FromParameter — their pointer parameters are
/// internal to Rust's ownership system and don't indicate FFI escape.
fn is_ffi_boundary_function(name: &str) -> bool {
    // Rust mangled names with FFI indicators
    if name.starts_with("_R") {
        // extern "C" wrappers often contain these path segments
        if name.contains("ffi")
            || name.contains("extern")
            || name.contains("callback")
            || name.contains("c_api")
            || name.contains("sys")
        {
            return true;
        }
        // Rust std FFI wrappers: std::ffi, std::os, std::sys
        if name.contains("3ffi") || name.contains("2os") || name.contains("3sys") {
            return true;
        }
        return false;
    }

    // Demangled names with FFI indicators
    if name.contains("::ffi::")
        || name.contains("::extern::")
        || name.contains("::sys::")
        || name.contains("::c_api::")
        || name.contains("::callback::")
    {
        return true;
    }

    // C-style function names that are known FFI library functions.
    // Only match common C library prefixes to avoid annotating internal
    // Rust functions that happen to have underscores.
    // E.g. sqlite3_exec, uv_timer_start, curl_easy_setopt are FFI;
    // but process_data, handle_request, compute_result are NOT.
    if !name.contains("::") && !name.starts_with('_') && name.contains('_') {
        let ffi_prefixes = [
            "sqlite3_",
            "uv_",
            "curl_",
            "png_",
            "jpeg_",
            "zlib_",
            "ssl_",
            "openssl_",
            "crypto_",
            "gtk_",
            "gdk_",
            "SDL_",
            "lua_",
            "py_",
            "PyObject_",
            "PyModule_",
            "JNI_",
            "cf_",
            "CG",
            "NS",
            "CF",
        ];
        if ffi_prefixes.iter().any(|prefix| name.starts_with(prefix)) {
            return true;
        }
    }

    false
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
