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
        let registry = ctx
            .get_ref::<FamilyRegistry>("family_registry")
            .cloned()
            .unwrap_or_default();
        let mut store: SummaryStore = ctx
            .get_ref::<SummaryStore>("summary_store")
            .cloned()
            .unwrap_or_default();

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
        let mut srt_key_resolutions: HashMap<omniscope_semantics::SemanticKey, Vec<SemanticKind>> =
            HashMap::new();

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
                    // R-3+: Destructor release — map to language-specific SemanticKind
                    // based on DestructorKind in the evidence description.
                    // Description format: "function '...' inferred as <Kind> destructor ..."
                    EvidenceKind::DestructorRelease => {
                        if evidence.description.contains("CppDestructor") {
                            if !kinds.contains(&SemanticKind::CppDestructor) {
                                kinds.push(SemanticKind::CppDestructor);
                            }
                        } else if evidence.description.contains("CSharpDispose") {
                            if !kinds.contains(&SemanticKind::CsharpSafeHandle) {
                                kinds.push(SemanticKind::CsharpSafeHandle);
                            }
                        } else if evidence.description.contains("PythonFinalizer") {
                            if !kinds.contains(&SemanticKind::PythonRefcountDec) {
                                kinds.push(SemanticKind::PythonRefcountDec);
                            }
                        } else if evidence.description.contains("JavaFinalizer") {
                            if !kinds.contains(&SemanticKind::JavaLocalRef) {
                                kinds.push(SemanticKind::JavaLocalRef);
                            }
                        } else {
                            // RustDrop, CDestroy, GenericCleanup → RaiiDropRelease
                            if !kinds.contains(&SemanticKind::RaiiDropRelease) {
                                kinds.push(SemanticKind::RaiiDropRelease);
                            }
                        }
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
                    // R-3+: Refcount conditional release — indicates reference counting.
                    // If the description mentions Python, map to PythonRefcountDec;
                    // otherwise map to RuntimeManagedResource (GC/refcount managed).
                    EvidenceKind::RefcountConditional => {
                        if evidence.description.contains("Py")
                            || evidence.description.contains("python")
                            || evidence.description.contains("Python")
                        {
                            if !kinds.contains(&SemanticKind::PythonRefcountDec) {
                                kinds.push(SemanticKind::PythonRefcountDec);
                            }
                        } else if !kinds.contains(&SemanticKind::RuntimeManagedResource) {
                            kinds.push(SemanticKind::RuntimeManagedResource);
                        }
                    }
                    // R-3+: Null-guarded release — indicates safe release (free(NULL) is no-op).
                    // This is a strong signal that the release function is well-behaved.
                    EvidenceKind::NullGuardedRelease
                        if !kinds.contains(&SemanticKind::ReleaseOnAllExitPaths) =>
                    {
                        kinds.push(SemanticKind::ReleaseOnAllExitPaths);
                    }
                    // R-3+: OwnershipEscapeLeak — resource intentionally leaked via
                    // into_raw / ManuallyDrop / box_leak across FFI boundary.
                    EvidenceKind::OwnershipEscapeLeak
                        if !kinds.contains(&SemanticKind::IntoRawTransfer) =>
                    {
                        kinds.push(SemanticKind::IntoRawTransfer);
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

            // R-9+: Cross-language semantic inference via function name patterns.
            //
            // SemanticKind::from_function_name() uses API naming conventions to
            // detect Python (Py_INCREF, Py_DECREF, PyList_GetItem, etc.),
            // Go (defer+free, SetFinalizer, runtime.mallocgc, _Cgo_*),
            // C++ (unique_ptr, shared_ptr, ~Destructor, __cxa_throw),
            // C# (SafeHandle, Finalize, DllImport, Marshal.*),
            // and Java (NewLocalRef, DeleteGlobalRef, etc.) patterns.
            //
            // This bridges the SRT data flow gap: IssueGate queries these
            // SemanticKinds for Leak/BorrowEscape/UseAfterFree suppression,
            // but without this mapping they were never written to srt_resolutions,
            // making the suppression code dead code.
            let fn_name_kind = SemanticKind::from_function_name(symbol);
            if fn_name_kind != SemanticKind::Unknown && !kinds.contains(&fn_name_kind) {
                kinds.push(fn_name_kind);
            }

            // R-12: RuntimeInternal — Zig runtime functions (std.*, builtin.*,
            // compiler_rt.*, zig_allocator_*, zig.*, zig.heap.*, zig.mem.*)
            // These are compiler/runtime-internal and should suppress
            // WriteToImmutable and Leak issues.
            if is_runtime_internal(symbol) && !kinds.contains(&SemanticKind::RuntimeInternal) {
                kinds.push(SemanticKind::RuntimeInternal);
            }

            if !kinds.is_empty() {
                srt_resolutions.insert(symbol.clone(), kinds.clone());

                // Also populate SemanticKey-based resolutions
                let symbol_key = omniscope_semantics::SemanticKey::symbol(symbol);
                srt_key_resolutions.insert(symbol_key, kinds);
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
        if let Some(module) = ctx.get_ir_module() {
            let registry = FamilyRegistry::new();
            for call in &module.calls {
                let callee = call.callee.trim_start_matches('@');
                let caller = call.caller.trim_start_matches('@');
                let is_ffi_call = call.is_external
                    || registry.lookup(callee).is_some()
                    || is_ffi_boundary_function(caller);

                if !caller.is_empty() && is_ffi_call && registry.lookup(caller).is_none() {
                    srt_resolutions
                        .entry(caller.to_string())
                        .or_insert_with(|| vec![SemanticKind::FromParameter]);

                    // Also populate SemanticKey-based resolutions
                    let caller_key = omniscope_semantics::SemanticKey::symbol(caller);
                    srt_key_resolutions
                        .entry(caller_key)
                        .or_insert_with(|| vec![SemanticKind::FromParameter]);
                }
            }
        }

        // ── Write boundary semantics from --cross configuration ──
        // If --cross boundaries are configured, classify functions as
        // DeclaredCrossBoundary based on whether they are in the declared
        // boundary list.  When the boundary has an empty `functions` list
        // (CLI `--cross` without explicit function names), use language
        // detection to identify functions that actually cross the boundary.
        // Do NOT default to NonBoundaryInternal for other functions, as this
        // would incorrectly suppress valid cross-boundary issues when only
        // partial boundaries are declared or when CLI functions are empty.
        if let Some(config) = ctx.config() {
            let boundary_functions = config.ffi_boundary_functions();
            let boundary_set: std::collections::HashSet<&str> = boundary_functions
                .iter()
                .map(|(func, _, _)| *func)
                .collect();

            // Determine whether the config declares any boundary at all.
            // When `boundary_functions` is empty but `config.ffi_boundary`
            // is non-empty, the user specified `--cross FROM:TO` without
            // listing explicit function names — use language detection
            // to identify functions that actually cross the boundary.
            let use_language_detection = boundary_set.is_empty() && !config.ffi_boundary.is_empty();

            // Get all functions from IR module
            if let Some(module) = ctx.get_ir_module() {
                // Build a language detector for cross-boundary detection
                let detector = if use_language_detection {
                    Some(omniscope_semantics::LanguageDetector::new())
                } else {
                    None
                };

                // First, mark explicitly declared boundary functions
                for func_name in module.functions.keys() {
                    let func = func_name.trim_start_matches('@');

                    if boundary_set.contains(func) {
                        srt_resolutions
                            .entry(func.to_string())
                            .or_default()
                            .push(SemanticKind::DeclaredCrossBoundary);

                        let key = omniscope_semantics::SemanticKey::symbol(func);
                        srt_key_resolutions
                            .entry(key)
                            .or_default()
                            .push(SemanticKind::DeclaredCrossBoundary);
                    }
                }

                // Second, mark functions that have actual crossing call edges
                // (only when using language detection without explicit function list)
                if use_language_detection {
                    if let Some(ref det) = detector {
                        // Create a set to track already marked functions to avoid duplicates
                        let mut marked_functions: std::collections::HashSet<String> =
                            std::collections::HashSet::new();

                        for call in &module.calls {
                            let caller = call.caller.trim_start_matches('@');
                            let callee = call.callee.trim_start_matches('@');

                            let caller_lang = det.detect_from_function(caller);
                            let callee_lang = det.detect_from_function(callee);

                            // Check if this call edge crosses any declared boundary
                            for boundary in &config.ffi_boundary {
                                let crosses = (caller_lang == boundary.from
                                    && callee_lang == boundary.to)
                                    || (caller_lang == boundary.to && callee_lang == boundary.from);

                                // Also check explicit function list
                                let in_list = boundary
                                    .functions
                                    .iter()
                                    .any(|f| f == callee || f == caller);

                                // Also check pattern
                                let matches_pattern = boundary
                                    .pattern
                                    .as_ref()
                                    .map(|p| {
                                        omniscope_types::boundary::matches_pattern(callee, p)
                                            || omniscope_types::boundary::matches_pattern(caller, p)
                                    })
                                    .unwrap_or(false);

                                if crosses || in_list || matches_pattern {
                                    // Mark the callee as a boundary function
                                    if !marked_functions.contains(callee) {
                                        srt_resolutions
                                            .entry(callee.to_string())
                                            .or_default()
                                            .push(SemanticKind::DeclaredCrossBoundary);

                                        let key = omniscope_semantics::SemanticKey::symbol(callee);
                                        srt_key_resolutions
                                            .entry(key)
                                            .or_default()
                                            .push(SemanticKind::DeclaredCrossBoundary);

                                        marked_functions.insert(callee.to_string());
                                    }

                                    // Mark the caller as a boundary function
                                    if !caller.is_empty() && !marked_functions.contains(caller) {
                                        srt_resolutions
                                            .entry(caller.to_string())
                                            .or_default()
                                            .push(SemanticKind::DeclaredCrossBoundary);

                                        let key = omniscope_semantics::SemanticKey::symbol(caller);
                                        srt_key_resolutions
                                            .entry(key)
                                            .or_default()
                                            .push(SemanticKind::DeclaredCrossBoundary);

                                        marked_functions.insert(caller.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                // Do NOT mark functions not in boundary as NonBoundaryInternal
                // This allows the system to still detect cross-boundary issues
                // for functions that are not explicitly declared as boundaries
            }
        }

        let srt_entry_count = srt_resolutions.len();
        let srt_key_entry_count = srt_key_resolutions.len();
        ctx.store("srt_resolutions", srt_resolutions);
        ctx.store("srt_key_resolutions", srt_key_resolutions);

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
        result.add_stat("srt_key_resolution_entries", srt_key_entry_count);

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

/// Checks whether a function name indicates a runtime-internal function.
///
/// Runtime-internal functions are compiler/runtime-generated code that
/// should not be flagged as user bugs. This includes:
/// - Zig runtime: std.*, builtin.*, compiler_rt.*, zig_allocator_*, zig.*
/// - Rust runtime: __rust_*, core::panicking, alloc::raw_vec, etc.
/// - C runtime: __cxa_*, __llvm_*, compiler_builtins, etc.
///
/// These patterns mirror `is_zig_runtime_internal` in module_index.rs
/// and the NoiseReduction safe_patterns list, but are applied at the
/// SRT level so IssueGate can use RuntimeInternal for suppression.
pub fn is_runtime_internal(name: &str) -> bool {
    // ── Zig runtime internal ──
    if name.starts_with("std.") {
        return true;
    }
    if name.starts_with("builtin.") {
        return true;
    }
    if name.starts_with("compiler_rt.") || name == "compiler_rt" {
        return true;
    }
    if name.starts_with("zig_allocator_") || name.starts_with("zig.") {
        return true;
    }
    // Zig heap/memory management
    if name.starts_with("zig.heap.") || name.starts_with("zig.mem.") {
        return true;
    }
    // Zig runtime threading / I/O (mirrors NoiseReduction safe_patterns)
    if name.contains("Io.Threaded") {
        return true;
    }
    // Zig POSIX wrappers (mirrors NoiseReduction safe_patterns)
    if name.contains("posix.mmap") {
        return true;
    }
    if name.contains("Thread.PosixThreadImpl") {
        return true;
    }

    // ── POSIX/libc system functions (runtime-internal allocations) ──
    // mmap/munmap are OS-level memory mapping, managed by the runtime.
    // Reporting leaks for these is noise — the runtime handles cleanup.
    if name == "mmap" || name == "munmap" {
        return true;
    }
    // brk/sbrk are low-level heap management, not user-code allocations
    if name == "brk" || name == "sbrk" {
        return true;
    }
    // mprotect, madvise are memory management syscalls, not user allocs
    if name == "mprotect" || name == "madvise" {
        return true;
    }

    // ── Rust runtime internal ──
    // __rust_dealloc, __rust_alloc, __rust_realloc, __rust_alloc_zeroed
    if name.starts_with("__rust_") {
        return true;
    }
    // Core panicking / alloc internals (demangled and v0-mangled forms)
    if name.starts_with("core::panicking") || name.starts_with("alloc::raw_vec") {
        return true;
    }
    // Rust v0 mangled alloc/core internals: _ZN5alloc..., _ZN4core...
    if name.starts_with("_ZN5alloc") || name.starts_with("_ZN4core") {
        return true;
    }
    // Panic infrastructure (mirrors NoiseReduction safe_patterns)
    if name.contains("panic_fmt") || name.contains("begin_panic") {
        return true;
    }
    // Compiler-generated drop glue (mirrors NoiseReduction safe_patterns)
    if name.contains("drop_in_place") {
        return true;
    }

    // ── C/C++ runtime internal ──
    // __cxa_atexit, __cxa_throw, __cxa_begin_catch, etc.
    if name.starts_with("__cxa_") {
        return true;
    }
    // LLVM intrinsics (mirrors NoiseReduction safe_patterns)
    if name.starts_with("llvm.") || name.starts_with("__llvm_") {
        return true;
    }
    if name.starts_with("compiler_builtins") {
        return true;
    }
    // Stack canary (mirrors NoiseReduction safe_patterns)
    if name.starts_with("__stack_chk_") {
        return true;
    }
    // heap.c_allocator_impl — NoiseReduction safe pattern
    if name.contains("c_allocator_impl") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structural_inference_pass_creation() {
        let pass = StructuralInferencePass::new();
        assert_eq!(
            pass.name(),
            "StructuralInference",
            "Pass name must be 'StructuralInference'"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "StructuralInference must be an Analysis pass"
        );
        assert_eq!(
            pass.dependencies(),
            vec!["SummaryBuilder"],
            "StructuralInference must depend on SummaryBuilder"
        );
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
            caller_name: String::new(),
            family: None,
            boundary_evidence: None,
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
            caller_name: String::new(),
            family: None,
            boundary_evidence: None,
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
