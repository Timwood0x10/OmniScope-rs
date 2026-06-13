//! Shared instruction metadata cache for pass-level performance optimization.
//!
//! Multiple analysis passes independently iterate over the same `IRModule`
//! collections (`calls`, `function_bodies`, `declarations`) and recompute
//! the same derived properties (language detection, registry lookups,
//! string trimming). The [`ModuleIndex`] pre-computes these once and
//! stores them in the [`PassContext`] for downstream passes to consume.
//!
//! # Design Principles
//!
//! - **No precision loss**: All cached values are identical to what passes
//!   would compute themselves. This is a pure memoization layer.
//! - **Zero-clone access**: Passes obtain `&ModuleIndex` via
//!   `ctx.get_ref::<ModuleIndex>()`, avoiding O(n) clones.
//! - **Single allocation**: The index is built once during pipeline
//!   initialization and lives for the entire analysis run.
//
// TODO(refactor): module_index.rs exceeds 1000 lines (see aim/rules/rules.md #1).
// Should be split into submodules (call_meta, function_meta, language_detection,
// resource_pairs) when scope permits.

/// Minimum number of foreign-ABI extern declarations that demotes an
/// otherwise single-language module to mixed-language. Used to keep FFI
/// passes enabled on modules where the dominant defined language imports
/// many cross-ABI symbols (e.g. a Rust module declaring `malloc`, `free`,
/// `mmap` — these are FFI evidence even though no foreign function
/// definition exists in the IR).
///
/// Threshold of 3 chosen empirically: 1 or 2 externs may be incidental
/// (e.g. `__cxa_personality_v0` for unwinding), but 3+ strongly indicates
/// genuine FFI usage that downstream passes must analyze.
const MIN_FOREIGN_EXTERNS_FOR_MIXED: usize = 3;

use indexmap::IndexMap;
use omniscope_ir::IRModule;
use omniscope_semantics::{FamilyRegistry, LanguageDetector};
use omniscope_types::boundary::{BoundaryEvidence, FfiSliceInfo};
use omniscope_types::call_graph_types::{is_dangerous, is_libc, FunctionKind};
use omniscope_types::config::Language;

use crate::analysis::boundary_seeds::{classify_seed, FfiSlice, SeedContext};
use crate::analysis::ffi_boundary_detector::FFIBoundaryDetector;
use crate::resource::structural_inference_pass;

/// Pre-computed metadata for a single call instruction.
///
/// Caches language detection, registry lookup, and classification
/// results so that passes avoid redundant computation.
#[derive(Debug, Clone)]
pub struct CachedCallMeta {
    /// Index into the original `module.calls` vector.
    pub call_index: usize,
    /// Caller function name (trimmed, no leading `@`).
    pub caller_name: String,
    /// Callee function name (trimmed, no leading `@`).
    pub callee_name: String,
    /// Whether this is an external call.
    pub is_external: bool,
    /// Detected caller language.
    pub caller_lang: Language,
    /// Detected callee language.
    pub callee_lang: Language,
    /// Whether callee starts with `llvm.` (LLVM intrinsic).
    pub is_llvm_intrinsic: bool,
    /// Whether callee starts with `_Z` (C++ mangled name).
    pub is_cpp_mangled: bool,
    /// Whether this call is a known allocation function (malloc, calloc, etc.).
    pub is_alloc_call: bool,
    /// Whether this call is a known deallocation function (free, operator delete, etc.).
    pub is_dealloc_call: bool,
    /// Family registry lookup result: symbol effect (if found).
    pub symbol_effect: Option<omniscope_semantics::SymbolEffect>,
    /// Family registry lookup result: family ID (if found).
    pub family_id: Option<omniscope_types::FamilyId>,
    /// Whether this is a cross-language call (both langs known and different).
    pub is_cross_language: bool,
    /// Whether this is an FFI boundary (cross-language + not filtered).
    pub is_ffi_boundary: bool,
    /// Boundary evidence items collected for this call site.
    /// `None` = not yet computed; `Some([])` = computed but no evidence found.
    pub boundary_evidence: Option<Vec<BoundaryEvidence>>,
    /// FFI slice membership metadata for this call site.
    /// `None` = not yet computed; `Some(FfiSliceInfo)` = computed.
    pub ffi_slice_info: Option<FfiSliceInfo>,
}

/// Pre-computed metadata for a function definition or declaration.
#[derive(Debug, Clone)]
pub struct CachedFunctionMeta {
    /// Function name (trimmed, no leading `@`).
    pub name: String,
    /// Detected language.
    pub language: Language,
    /// Whether this is a declaration (extern).
    pub is_declaration: bool,
    /// Number of parameters.
    pub param_count: usize,
    /// Whether this function has any call instructions (as caller).
    pub has_calls: bool,
    /// Number of call instructions in this function (as caller).
    pub call_count: usize,
    /// Whether this function calls any allocation functions.
    pub calls_alloc: bool,
    /// Whether this function calls any deallocation functions.
    pub calls_dealloc: bool,
    /// Whether this function has any FFI boundary calls.
    pub has_ffi_calls: bool,
    /// Whether this function has any store instructions (in function body).
    pub has_stores: bool,
    /// Whether this function is runtime internal (compiler_rt, etc.).
    pub is_runtime_internal: bool,
}

/// Shared instruction metadata cache.
///
/// Built once from the `IRModule` and stored in `PassContext` for all
/// downstream passes to consume via `ctx.get_ref::<ModuleIndex>()`.
#[derive(Clone, Debug)]
pub struct ModuleIndex {
    /// Pre-computed metadata for each call instruction (same order as `module.calls`).
    pub call_metas: Vec<CachedCallMeta>,
    /// Pre-computed metadata for each function (keyed by trimmed name).
    /// Uses IndexMap for deterministic iteration order, ensuring pipeline
    /// output is stable across runs (fixes non-deterministic issue classification).
    pub function_metas: IndexMap<String, CachedFunctionMeta>,
    /// Callee name -> list of call indices that call this callee.
    pub callee_callers: IndexMap<String, Vec<usize>>,
    /// Caller name -> list of call indices in this function.
    pub caller_calls: IndexMap<String, Vec<usize>>,
    /// Function names that have FFI boundary calls (as caller).
    pub ffi_caller_functions: Vec<String>,
    /// Function names that call allocation functions.
    pub alloc_caller_functions: Vec<String>,
    /// Total number of instructions across all function bodies.
    pub total_instruction_count: usize,
    /// Total number of call instructions.
    pub total_call_count: usize,
    /// Pre-built FamilyRegistry (shared across passes to avoid repeated construction).
    pub family_registry: FamilyRegistry,
    /// Pre-built LanguageDetector (shared across passes to avoid repeated construction).
    pub language_detector: LanguageDetector,
    /// Cached SyscallSemantic classification for each unique callee name.
    /// Avoids repeated string matching in downstream passes.
    pub syscall_cache: std::collections::HashMap<String, omniscope_semantics::SyscallSemantic>,
    /// Cached FunctionKind classification for each unique function name.
    /// Avoids repeated classify_function() calls in call_graph and other passes.
    pub function_kind_cache: std::collections::HashMap<String, FunctionKind>,
    /// Whether the entire module uses a single known language.
    ///
    /// When true, there are no cross-language FFI boundaries, so
    /// FFI-specific passes can short-circuit and skip their work.
    /// This is determined by checking whether all detected languages
    /// (from both call_metas and function_metas) are the same.
    pub is_single_language: bool,
    /// Whether this module is an allocator crate (e.g., bun_alloc).
    ///
    /// Allocator crates wrap C allocation APIs (mi_malloc, mi_free,
    /// mmap, etc.) in safe Rust abstractions. Cross-language issues
    /// inside these crates are almost always false positives — the
    /// Rust code correctly manages ownership across the FFI boundary.
    ///
    /// Detected by checking whether a significant fraction of defined
    /// function names match known allocator patterns (bun_alloc crate
    /// hash, mimalloc API names, arena/zone types, etc.).
    pub is_allocator_crate: bool,
}

/// Check if a function signature involves pointer types (params or return).
///
/// Pointer types are identified by common IR patterns: `*`, `ptr`, `i8*`,
/// `*mut`, `*const`, etc. This is a heuristic — full type resolution
/// requires the data layout, but the string-level check is sufficient
/// for boundary seed classification.
fn has_pointer_in_signature(params: &[String], return_type: &str) -> bool {
    let is_ptr_type = |ty: &str| -> bool {
        let trimmed = ty.trim();
        trimmed.contains('*')
            || trimmed.contains("ptr")
            || trimmed.starts_with("i8*")
            || trimmed.starts_with("*mut")
            || trimmed.starts_with("*const")
            || trimmed.starts_with("opaque")
    };
    params.iter().any(|p| is_ptr_type(p)) || is_ptr_type(return_type)
}

/// Check if a function name is a language runtime intrinsic (cached version).
///
/// This is a copy of the function in call_graph.rs, used to avoid
/// importing it and creating a circular dependency.
fn is_runtime_intrinsic_cached(name: &str, language: Language) -> bool {
    match language {
        Language::Rust => {
            name.starts_with("__rust_")
                || name.starts_with("_ZN4core")
                || name.starts_with("_ZN5alloc")
        }
        Language::C => {
            name.starts_with("__libc_")
                || name.starts_with("__cxa_")
                || name.starts_with("_Unwind_")
                || name.starts_with("_tlv_")
        }
        Language::Cpp => {
            name.starts_with("__cxxabiv1")
                || name.starts_with("__cxa_")
                || name.starts_with("__gxx_")
        }
        _ => false,
    }
}

/// Check if a function name suggests it is part of the C++ runtime.
///
/// This covers C++ ABI/runtime infrastructure, not user-facing
/// allocation operators (operator new/delete). User-facing C++ allocation
/// functions (`_Znwm`, `_Znam`, `_Znwj`, `_Znaj`, `_ZdlPv`, `_ZdaPv`)
/// should NOT be classified as runtime-internal — doing so could suppress
/// legitimate leak/bug reports from the IssueGate.
fn is_cpp_runtime(name: &str) -> bool {
    // C++ ABI / runtime support (NOT operator new/delete)
    name.starts_with("__cxxabiv1") || name.starts_with("__cxa_") || name.starts_with("__gxx_")
}

/// Check if a function name suggests it is part of the C runtime.
///
/// C runtime infrastructure functions that are internal to the runtime,
/// not user-facing allocation APIs like malloc/free. User-facing alloc
/// functions (malloc, free, calloc, realloc, aligned_alloc) should NOT
/// be classified as runtime-internal — doing so would suppress genuine
/// leak/UAF bug reports from the IssueGate.
///
/// Low-level OS memory functions (mmap, munmap, brk, sbrk) are already
/// handled by `structural_inference_pass::is_runtime_internal`, so they
/// don't need to be duplicated here.
fn is_c_runtime(name: &str) -> bool {
    name.starts_with("__libc_")
        || name.starts_with("__cxa_")
        || name.starts_with("_Unwind_")
        || name.starts_with("_tlv_")
        || name.starts_with("__stack_chk_")
        || name.starts_with("__asan_")
        || name.starts_with("__tsan_")
        || name.starts_with("__msan_")
        || name.starts_with("__ubsan_")
}

/// Classify a function based on its name, declaration status, and language (cached version).
///
/// This is a copy of the function in call_graph.rs, used to pre-compute
/// function kinds during ModuleIndex construction.
fn classify_function_cached(name: &str, is_declaration: bool, language: Language) -> FunctionKind {
    // Known libc functions are trusted regardless of declaration status
    if is_libc(name) {
        return FunctionKind::LibC;
    }

    // Dangerous functions are always treated as potential FFI boundaries
    if is_dangerous(name) {
        return FunctionKind::ExternalUnknown;
    }

    // Language runtime intrinsics are external
    if is_runtime_intrinsic_cached(name, language) {
        return FunctionKind::ExternalUnknown;
    }

    // Functions with bodies are internal to the analyzed module
    if !is_declaration {
        return FunctionKind::Internal;
    }

    // Declarations without bodies: could be external FFI targets
    FunctionKind::ExternalUnknown
}

/// Count extern declarations whose names do NOT match the mangling scheme
/// of the dominant language. These are foreign-ABI symbols (typically C
/// libraries imported into a Rust/C++ module) and constitute FFI
/// evidence even when no foreign function is *defined* in the IR.
///
/// LLVM intrinsics (`llvm.*`) and runtime intrinsics that already belong
/// to the dominant language (e.g. `__rust_alloc` in a Rust module) are
/// excluded — they are not foreign FFI.
///
/// Unknown-language declarations are treated as foreign because plain C
/// symbols like `malloc`, `free`, `mmap` carry no mangling and therefore
/// produce `Language::Unknown` from the detector. This is the primary
/// case the demotion is designed to catch.
fn count_foreign_declared_externs(
    module: &IRModule,
    dominant_lang: Language,
    detector: &LanguageDetector,
) -> usize {
    // Bail out early if the dominant language is Unknown — there's no
    // meaningful "foreign" classification to make.
    if dominant_lang == Language::Unknown {
        return 0;
    }

    let mut count = 0usize;
    for name in module.declarations.keys() {
        let trimmed = name.trim_start_matches('@');

        // Skip LLVM compiler intrinsics — they are not FFI.
        if trimmed.starts_with("llvm.") {
            continue;
        }

        let detected = detector.detect_from_function(trimmed);

        // Detected as dominant language → not foreign.
        if detected == dominant_lang {
            continue;
        }

        // Runtime intrinsics of the dominant language (e.g. `__rust_alloc`
        // when dominant is Rust) are detected correctly above and skipped.
        // For safety also skip names that the runtime-intrinsic helper
        // attributes to the dominant language, since some patterns may
        // evolve out of band.
        if is_runtime_intrinsic_cached(trimmed, dominant_lang) {
            continue;
        }

        // Everything else (Unknown plain-C symbols, C++ mangled symbols,
        // explicit other-language symbols) counts as foreign-ABI evidence.
        count += 1;
    }
    count
}

/// Check if the module has C++ mangled symbols (_Z prefix).
/// Used to demote single-language modules to mixed when C++ operator
/// new/delete patterns are present in a C-compiled file.
fn has_cpp_mangled_symbols(module: &IRModule) -> bool {
    module
        .declarations
        .keys()
        .chain(module.functions.keys())
        .any(|name| name.starts_with("_Z"))
}

/// Allocator-related name patterns that indicate a function belongs to
/// an allocator crate (bun_alloc, mimalloc wrapper, etc.).
///
/// Used by `detect_allocator_crate` to classify modules that primarily
/// implement memory allocation abstractions over C FFI APIs.
fn is_allocator_name(name: &str) -> bool {
    // Bun's allocator crate (mangled with crate disambiguator hash)
    if name.contains("bun_alloc") || name.contains("9bun_alloc") {
        return true;
    }
    // Mimalloc API wrappers
    if name.contains("mi_heap")
        || name.contains("mi_malloc")
        || name.contains("mi_free")
        || name.contains("mi_realloc")
        || name.contains("mi_calloc")
        || name.contains("mi_recalloc")
    {
        return true;
    }
    // Arena / zone types used in allocators
    if name.contains("MimallocArena")
        || name.contains("ZAllocator")
        || name.contains("NullableAllocator")
        || name.contains("CAllocator")
    {
        return true;
    }
    // Allocator-internal module names
    if name.contains("heap_breakdown")
        || name.contains("bss_arena_bump")
        || name.contains("c_thunk")
    {
        return true;
    }
    false
}

/// Detects whether the IR module is an allocator crate.
///
/// An allocator crate is one where a significant portion of defined
/// functions are allocator-related (wrapping mi_*, malloc, mmap, etc.).
/// The threshold is 30%: if ≥30% of defined function names match
/// allocator patterns, the module is classified as an allocator crate.
///
/// Allocator crates need special treatment because their cross-language
/// FFI patterns (Rust calling C malloc/free/mi_malloc) are intentional
/// design choices, not bugs.
fn detect_allocator_crate(module: &IRModule) -> bool {
    let defined_count = module.functions.len();
    if defined_count == 0 {
        return false;
    }

    let mut allocator_match_count = 0usize;
    for name in module.functions.keys() {
        let trimmed = name.trim_start_matches('@');
        if is_allocator_name(trimmed) {
            allocator_match_count += 1;
        }
    }

    // Threshold: at least 30% of defined functions must be allocator-related,
    // OR at least 10 absolute matches (for small crates with few functions).
    let ratio = allocator_match_count as f64 / defined_count as f64;
    ratio >= 0.30 || allocator_match_count >= 10
}

impl ModuleIndex {
    /// Builds a `ModuleIndex` from an `IRModule`.
    ///
    /// This performs a single traversal of the module's calls, functions,
    /// and declarations, pre-computing all commonly needed metadata.
    pub fn build(module: &IRModule) -> Self {
        let detector = LanguageDetector::new();
        let registry = FamilyRegistry::new();

        let total_call_count = module.calls.len();
        let total_instruction_count: usize = module
            .function_bodies
            .values()
            .map(|body| body.instructions.len())
            .sum();

        // Pre-compute call metadata
        let mut call_metas: Vec<CachedCallMeta> = Vec::with_capacity(total_call_count);
        let mut callee_callers: IndexMap<String, Vec<usize>> = IndexMap::new();
        let mut caller_calls: IndexMap<String, Vec<usize>> = IndexMap::new();

        // Collect known languages during Phase 1 for early single-language detection
        let mut known_languages: std::collections::HashSet<Language> =
            std::collections::HashSet::new();

        for (idx, call) in module.calls.iter().enumerate() {
            let callee_name = call.callee.trim_start_matches('@').to_string();
            let caller_name = call.caller.trim_start_matches('@').to_string();

            let callee_lang = detector.detect_from_function(&callee_name);
            // Apply C-fallback for defined functions: if caller is a defined
            // function and its language is Unknown, default to C (common case
            // for .ll files from C source). This matches the original
            // FFIBoundaryPass behavior.
            let raw_caller_lang = detector.detect_from_function(&caller_name);
            let caller_lang = if raw_caller_lang == Language::Unknown
                && (module.functions.contains_key(call.caller.as_str())
                    || module.functions.contains_key(&call.caller))
            {
                Language::C
            } else {
                raw_caller_lang
            };

            let is_llvm_intrinsic = callee_name.starts_with("llvm.");
            let is_cpp_mangled = callee_name.starts_with("_Z");

            let lookup = registry.lookup(&callee_name);
            let symbol_effect = lookup.map(|e| e.effect);
            let family_id = lookup.map(|e| e.family_id);

            let is_alloc_call = matches!(
                symbol_effect,
                Some(
                    omniscope_semantics::SymbolEffect::Acquire
                        | omniscope_semantics::SymbolEffect::Retain
                        | omniscope_semantics::SymbolEffect::Reclaim
                )
            );
            let is_dealloc_call = matches!(
                symbol_effect,
                Some(
                    omniscope_semantics::SymbolEffect::Release
                        | omniscope_semantics::SymbolEffect::ConditionalRelease
                )
            );

            let is_cross_language = caller_lang != Language::Unknown
                && callee_lang != Language::Unknown
                && caller_lang != callee_lang;

            // FFI boundary determination:
            // 1. Both langs known and different (cross-language)
            // 2. C++ mangled name called from C
            // 3. Non-C language calling external unknown function (likely C)
            let is_ffi_boundary = (is_cross_language
                || (is_cpp_mangled && caller_lang == Language::C)
                || (caller_lang != Language::Unknown
                    && caller_lang != Language::C
                    && callee_lang == Language::Unknown
                    && call.is_external))
            // Filter out LLVM intrinsics
            && !is_llvm_intrinsic
            // Filter out language runtime intrinsics (__rust_*, _ZN4core*, etc.)
            // NOTE: We intentionally do NOT filter libc functions here because
            // libc functions (malloc, free, etc.) can be FFI boundaries in
            // cross-language ownership transfer scenarios (e.g., C malloc
            // released by C++ operator delete). libc FP suppression is handled
            // at the IssueGate level (Rule 3) instead.
            && !crate::analysis::ffi_boundary_detector::is_runtime_intrinsic(&callee_name, callee_lang)
            // Filter out compiler-generated drop/panic
            && !callee_name.contains("drop_in_place")
            && !callee_name.contains("panic");

            call_metas.push(CachedCallMeta {
                call_index: idx,
                caller_name: caller_name.clone(),
                callee_name: callee_name.clone(),
                is_external: call.is_external,
                caller_lang,
                callee_lang,
                is_llvm_intrinsic,
                is_cpp_mangled,
                is_alloc_call,
                is_dealloc_call,
                symbol_effect,
                family_id,
                is_cross_language,
                is_ffi_boundary,
                boundary_evidence: None,
                ffi_slice_info: None,
            });

            // Collect known languages for single-language detection
            if caller_lang != Language::Unknown {
                known_languages.insert(caller_lang);
            }
            if callee_lang != Language::Unknown {
                known_languages.insert(callee_lang);
            }

            callee_callers
                .entry(callee_name.clone())
                .or_default()
                .push(idx);
            caller_calls
                .entry(caller_name.clone())
                .or_default()
                .push(idx);
        }

        // ── Phase 2: Boundary seed classification and FFI slice expansion ──
        // Classify each call as a strong/weak/suppression seed using the
        // boundary_seeds module, then expand the FFI slice from strong seeds.
        // This populates the boundary_evidence and ffi_slice_info fields that
        // were left as None in Phase 1.
        //
        // If the module is single-language (only one known language detected
        // from call metadata), skip the entire Phase 2 — there are no FFI
        // boundaries to classify or expand. Function-level languages will be
        // added to known_languages later, but if call-level already shows
        // a single language, the final result will still be single-language
        // (adding more of the same language doesn't increase the count).
        let mut early_single_language = known_languages.len() <= 1;
        // Demote to mixed-language when the IR declares many foreign-ABI
        // externs — e.g. a Rust module that imports `malloc`, `free`, `mmap`.
        // The defined functions look pure-Rust but the declared externs are
        // FFI evidence that downstream passes must analyze.
        if early_single_language {
            if let Some(&dominant) = known_languages.iter().next() {
                let foreign_externs = count_foreign_declared_externs(module, dominant, &detector);
                if foreign_externs >= MIN_FOREIGN_EXTERNS_FOR_MIXED {
                    early_single_language = false;
                    tracing::info!(
                        target: "omniscope_pass::module_index",
                        "demoted single-language to mixed: {} foreign-ABI externs declared in {:?}-dominated module",
                        foreign_externs,
                        dominant
                    );
                }
                // Demote if module has C++ mangled symbols (_Z prefix)
                if early_single_language && has_cpp_mangled_symbols(module) {
                    early_single_language = false;
                    tracing::info!(
                        target: "omniscope_pass::module_index",
                        "demoted single-language to mixed: C++ mangled symbols found in {:?}-dominated module",
                        dominant
                    );
                }
            }
        }
        if early_single_language {
            // No FFI boundaries possible — skip seed classification and slice expansion.
            // Set boundary_evidence and ffi_slice_info to "computed, no boundary" for all calls.
            for meta in call_metas.iter_mut() {
                meta.boundary_evidence = Some(vec![]);
                meta.ffi_slice_info = Some(FfiSliceInfo::outside());
            }
            tracing::debug!(
                "ModuleIndex: single-language module — skipping Phase 2 boundary seed classification"
            );
        } else {
            let ffi_detector = FFIBoundaryDetector::with_detector(detector.clone());

            // Classify each call site
            let mut seed_results: IndexMap<usize, crate::analysis::boundary_seeds::SeedResult> =
                IndexMap::with_capacity(call_metas.len());

            for (idx, meta) in call_metas.iter().enumerate() {
                // Determine pointer signature from function metadata.
                // Look up the callee in declarations first, then functions.
                let (has_ptr_param, is_callback, is_runtime_bridge, is_exported_wrapper) = {
                    let callee = &meta.callee_name;
                    let caller = &meta.caller_name;

                    // Check pointer params/return from function metadata
                    let callee_func = module
                        .declarations
                        .get(callee)
                        .or_else(|| module.functions.get(callee));
                    let caller_func = module.functions.get(caller);

                    let ptr_in_callee = callee_func
                        .map(|f| has_pointer_in_signature(&f.params, &f.return_type))
                        .unwrap_or(false);
                    let ptr_in_caller = caller_func
                        .map(|f| has_pointer_in_signature(&f.params, &f.return_type))
                        .unwrap_or(false);
                    let has_ptr = ptr_in_callee || ptr_in_caller;

                    let is_cb =
                        crate::analysis::boundary_seeds::is_callback_registration_pattern(callee);
                    let is_bridge =
                        crate::analysis::boundary_seeds::is_runtime_bridge_function(callee);
                    let is_export = crate::analysis::boundary_seeds::looks_like_exported_wrapper(
                        caller,
                        meta.caller_lang,
                    );

                    (has_ptr, is_cb, is_bridge, is_export)
                };

                let is_dangerous_libc = is_dangerous(&meta.callee_name);

                let seed = classify_seed(&SeedContext {
                    caller: &meta.caller_name,
                    callee: &meta.callee_name,
                    caller_lang: meta.caller_lang,
                    callee_lang: meta.callee_lang,
                    is_external: meta.is_external,
                    is_llvm_intrinsic: meta.is_llvm_intrinsic,
                    is_cpp_mangled: meta.is_cpp_mangled,
                    is_cross_language: meta.is_cross_language,
                    has_pointer_param_or_return: has_ptr_param,
                    is_callback_registration: is_callback,
                    detector: &ffi_detector,
                    is_configured_boundary: false, // not available at index build time
                    is_runtime_bridge,
                    is_dangerous_libc,
                    is_exported_wrapper,
                    is_function_pointer_ffi: false, // requires deeper analysis
                    symbol_effect: meta.symbol_effect,
                });

                // Only store non-suppression seeds for expansion
                if seed.slice_info.is_in_slice() {
                    seed_results.insert(idx, seed);
                }
            }

            // Build resource pair closure: find acquire/release pairs
            // in the same function for the FFI slice expansion.
            let resource_pair_closure: Vec<(usize, usize)> =
                build_resource_pair_closure(&call_metas);

            // Expand FFI slice from strong seeds
            let ffi_slice = FfiSlice::expand_from_seeds(
                &seed_results,
                &caller_calls,
                &callee_callers,
                &call_metas,
                &resource_pair_closure,
            );

            // Write boundary evidence and FFI slice info back into call_metas
            for (idx, meta) in call_metas.iter_mut().enumerate() {
                // Boundary evidence from seed classification
                if let Some(seed) = seed_results.get(&idx) {
                    if !seed.evidence.is_empty() {
                        meta.boundary_evidence = Some(seed.evidence.clone());
                    } else {
                        // Computed but no evidence: empty vec distinguishes
                        // "computed and no boundary" from "not computed" (None)
                        meta.boundary_evidence = Some(vec![]);
                    }
                } else {
                    // Not a seed: computed but no boundary evidence
                    meta.boundary_evidence = Some(vec![]);
                }

                // FFI slice info
                if let Some(slice_info) = ffi_slice.call_info(idx) {
                    meta.ffi_slice_info = Some(slice_info.clone());
                } else {
                    // Call is outside the FFI slice
                    meta.ffi_slice_info = Some(FfiSliceInfo::outside());
                }
            }

            tracing::debug!(
                "ModuleIndex: boundary seeds classified {} calls, FFI slice contains {} functions / {} calls",
                seed_results.len(),
                ffi_slice.function_count(),
                ffi_slice.call_count(),
            );
        }

        // Pre-compute function metadata
        let mut function_metas: IndexMap<String, CachedFunctionMeta> = IndexMap::new();

        // Defined functions
        for (name, func) in &module.functions {
            let trimmed = name.trim_start_matches('@').to_string();
            // Apply C-fallback for defined functions
            let raw_language = detector.detect_from_function(&trimmed);
            let language = if raw_language == Language::Unknown {
                Language::C
            } else {
                raw_language
            };
            let calls = caller_calls.get(&trimmed);
            let call_count = calls.map(|c| c.len()).unwrap_or(0);
            let has_calls = call_count > 0;

            let calls_alloc = calls
                .map(|indices| indices.iter().any(|&idx| call_metas[idx].is_alloc_call))
                .unwrap_or(false);

            let calls_dealloc = calls
                .map(|indices| indices.iter().any(|&idx| call_metas[idx].is_dealloc_call))
                .unwrap_or(false);

            let has_ffi_calls = calls
                .map(|indices| indices.iter().any(|&idx| call_metas[idx].is_ffi_boundary))
                .unwrap_or(false);

            let has_stores = module
                .function_bodies
                .get(&trimmed)
                .map(|body| {
                    body.instructions
                        .iter()
                        .any(|i| i.kind == omniscope_ir::IRInstructionKind::Store)
                })
                .unwrap_or(false);

            // Check if this function is runtime internal
            let is_runtime_internal = structural_inference_pass::is_runtime_internal(&trimmed)
                || is_cpp_runtime(&trimmed)
                || is_c_runtime(&trimmed);

            function_metas.insert(
                trimmed.clone(),
                CachedFunctionMeta {
                    name: trimmed,
                    language,
                    is_declaration: false,
                    param_count: func.params.len(),
                    has_calls,
                    call_count,
                    calls_alloc,
                    calls_dealloc,
                    has_ffi_calls,
                    has_stores,
                    is_runtime_internal,
                },
            );
        }

        // Declarations
        for (name, func) in &module.declarations {
            let trimmed = name.trim_start_matches('@').to_string();
            let language = detector.detect_from_function(&trimmed);
            let calls = caller_calls.get(&trimmed);
            let call_count = calls.map(|c| c.len()).unwrap_or(0);

            // Check if this function is runtime internal
            let is_runtime_internal = structural_inference_pass::is_runtime_internal(&trimmed)
                || is_cpp_runtime(&trimmed)
                || is_c_runtime(&trimmed);

            function_metas.insert(
                trimmed.clone(),
                CachedFunctionMeta {
                    name: trimmed,
                    language,
                    is_declaration: true,
                    param_count: func.params.len(),
                    has_calls: call_count > 0,
                    call_count,
                    calls_alloc: false,
                    calls_dealloc: false,
                    has_ffi_calls: false,
                    has_stores: false,
                    is_runtime_internal,
                },
            );
        }

        // Collect functions with specific properties
        let ffi_caller_functions: Vec<String> = function_metas
            .values()
            .filter(|m| m.has_ffi_calls)
            .map(|m| m.name.clone())
            .collect();

        let alloc_caller_functions: Vec<String> = function_metas
            .values()
            .filter(|m| m.calls_alloc)
            .map(|m| m.name.clone())
            .collect();

        // Pre-compute SyscallSemantic classification for each unique callee name.
        // This avoids repeated string matching in downstream passes (semantic tree,
        // FFI boundary detection, etc.).
        let mut syscall_cache: std::collections::HashMap<
            String,
            omniscope_semantics::SyscallSemantic,
        > = std::collections::HashMap::new();
        for call_meta in &call_metas {
            syscall_cache
                .entry(call_meta.callee_name.clone())
                .or_insert_with(|| {
                    omniscope_semantics::SyscallSemantic::classify(&call_meta.callee_name)
                });
        }

        // Pre-compute FunctionKind classification for each unique function name.
        // This avoids repeated classify_function() calls in call_graph and other passes.
        let mut function_kind_cache: std::collections::HashMap<String, FunctionKind> =
            std::collections::HashMap::new();
        for (name, meta) in &function_metas {
            let kind = classify_function_cached(name, meta.is_declaration, meta.language);
            function_kind_cache.insert(name.clone(), kind);
        }

        // Finalize single-language detection by adding function-level languages.
        // known_languages was already populated from call metadata in Phase 1.
        for meta in function_metas.values() {
            if meta.language != Language::Unknown {
                known_languages.insert(meta.language);
            }
        }
        let mut is_single_language = known_languages.len() <= 1;
        // Same demotion as the early-detect site: a single-language defined
        // surface that imports many foreign-ABI externs is still effectively
        // mixed-language for FFI analysis purposes.
        if is_single_language {
            if let Some(&dominant) = known_languages.iter().next() {
                let foreign_externs = count_foreign_declared_externs(module, dominant, &detector);
                if foreign_externs >= MIN_FOREIGN_EXTERNS_FOR_MIXED {
                    is_single_language = false;
                    tracing::info!(
                        target: "omniscope_pass::module_index",
                        "demoted single-language to mixed: {} foreign-ABI externs declared in {:?}-dominated module",
                        foreign_externs,
                        dominant
                    );
                }
                // Demote if module has C++ mangled symbols (_Z prefix)
                if is_single_language && has_cpp_mangled_symbols(module) {
                    is_single_language = false;
                    tracing::info!(
                        target: "omniscope_pass::module_index",
                        "demoted single-language to mixed: C++ mangled symbols found in {:?}-dominated module",
                        dominant
                    );
                }
            }
        }

        if is_single_language {
            let lang_desc = known_languages
                .iter()
                .next()
                .map(|l| format!("{:?}", l))
                .unwrap_or_else(|| "Unknown".to_string());
            tracing::info!(
                "ModuleIndex: single-language module detected ({}) — FFI passes will be skipped",
                lang_desc
            );
        }

        Self {
            call_metas,
            function_metas,
            callee_callers,
            caller_calls,
            ffi_caller_functions,
            alloc_caller_functions,
            total_instruction_count,
            total_call_count,
            family_registry: registry,
            language_detector: detector,
            syscall_cache,
            function_kind_cache,
            is_single_language,
            is_allocator_crate: detect_allocator_crate(module),
        }
    }

    /// Returns all FFI boundary calls.
    pub fn ffi_boundary_calls(&self) -> impl Iterator<Item = &CachedCallMeta> {
        self.call_metas.iter().filter(|m| m.is_ffi_boundary)
    }

    /// Returns all allocation calls.
    pub fn alloc_calls(&self) -> impl Iterator<Item = &CachedCallMeta> {
        self.call_metas.iter().filter(|m| m.is_alloc_call)
    }

    /// Returns all deallocation calls.
    pub fn dealloc_calls(&self) -> impl Iterator<Item = &CachedCallMeta> {
        self.call_metas.iter().filter(|m| m.is_dealloc_call)
    }

    /// Returns calls made by a specific caller function.
    pub fn calls_by_caller(&self, caller: &str) -> &[usize] {
        self.caller_calls
            .get(caller)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns all callers of a specific callee function.
    pub fn callers_of(&self, callee: &str) -> &[usize] {
        self.callee_callers
            .get(callee)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns the function profile for a given function name.
    pub fn function_meta(&self, name: &str) -> Option<&CachedFunctionMeta> {
        self.function_metas.get(name.trim_start_matches('@'))
    }

    /// Returns all function profiles that have FFI calls.
    pub fn ffi_functions(&self) -> &[String] {
        &self.ffi_caller_functions
    }

    /// Returns all function profiles that call allocation functions.
    pub fn alloc_functions(&self) -> &[String] {
        &self.alloc_caller_functions
    }

    /// Returns the cached SyscallSemantic classification for a callee name.
    ///
    /// This avoids repeated string matching in downstream passes.
    /// Returns `SyscallSemantic::Unknown` if the callee is not in the cache.
    pub fn syscall_semantic(&self, callee: &str) -> omniscope_semantics::SyscallSemantic {
        self.syscall_cache
            .get(callee.trim_start_matches('@'))
            .copied()
            .unwrap_or(omniscope_semantics::SyscallSemantic::Unknown)
    }

    /// Returns the cached FunctionKind classification for a function name.
    ///
    /// This avoids repeated classify_function() calls in downstream passes.
    /// Returns `None` if the function is not in the cache.
    pub fn function_kind(&self, name: &str) -> Option<FunctionKind> {
        self.function_kind_cache
            .get(name.trim_start_matches('@'))
            .copied()
    }

    /// Returns whether a callee is a known allocation function (cached).
    pub fn is_alloc_function(&self, callee: &str) -> bool {
        matches!(
            self.syscall_semantic(callee),
            omniscope_semantics::SyscallSemantic::MemoryManagement
        )
    }

    /// Returns whether a callee involves memory ownership (cached).
    pub fn involves_memory_ownership(&self, callee: &str) -> bool {
        self.syscall_semantic(callee).involves_memory_ownership()
    }

    /// Returns whether a function is runtime internal (cached).
    ///
    /// This avoids repeated string matching in downstream passes.
    /// Returns `false` if the function is not in the cache.
    pub fn is_runtime_internal(&self, name: &str) -> bool {
        self.function_metas
            .get(name.trim_start_matches('@'))
            .map(|meta| meta.is_runtime_internal)
            .unwrap_or(false)
    }

    /// Returns whether this module is an allocator crate.
    ///
    /// Allocator crates (e.g., bun_alloc) wrap C allocation APIs in
    /// safe Rust abstractions. Cross-language FFI issues inside
    /// these crates are almost always false positives.
    pub fn is_allocator_crate(&self) -> bool {
        self.is_allocator_crate
    }
}

/// Build resource pair closure: find (acquire_call_idx, release_call_idx)
/// pairs that share the same caller function and family.
///
/// This is needed for FFI slice expansion — if an acquire call is in the
/// slice, its matching release should also be included (and vice versa).
fn build_resource_pair_closure(call_metas: &[CachedCallMeta]) -> Vec<(usize, usize)> {
    // Group calls by (caller_name, family_id)
    // Use IndexMap for deterministic iteration order.
    let mut acquire_by_key: IndexMap<(String, Option<omniscope_types::FamilyId>), Vec<usize>> =
        IndexMap::new();
    let mut release_by_key: IndexMap<(String, Option<omniscope_types::FamilyId>), Vec<usize>> =
        IndexMap::new();

    for (idx, meta) in call_metas.iter().enumerate() {
        let key = (meta.caller_name.clone(), meta.family_id);
        if meta.is_alloc_call {
            acquire_by_key.entry(key).or_default().push(idx);
        } else if meta.is_dealloc_call {
            release_by_key.entry(key).or_default().push(idx);
        }
    }

    let mut pairs = Vec::new();

    // Match acquires and releases in the same (caller, family) scope.
    // Use FIFO matching: first acquire pairs with first release.
    for (key, acquire_indices) in &acquire_by_key {
        if let Some(release_indices) = release_by_key.get(key) {
            let count = acquire_indices.len().min(release_indices.len());
            for i in 0..count {
                pairs.push((acquire_indices[i], release_indices[i]));
            }
        }
    }

    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_ir::{CallInstruction, Function, IRModule};

    fn create_test_module() -> IRModule {
        let mut module = IRModule::new();

        // Add a function definition
        module.functions.insert(
            "@test_func".to_string(),
            Function {
                name: "test_func".to_string(),
                is_declaration: false,
                params: vec!["i32".to_string()],
                return_type: "void".to_string(),
            },
        );

        // Add a declaration
        module.declarations.insert(
            "@malloc".to_string(),
            Function {
                name: "malloc".to_string(),
                is_declaration: true,
                params: vec!["i64".to_string()],
                return_type: "ptr".to_string(),
            },
        );

        // Add call instructions
        module.calls.push(CallInstruction {
            callee: "@malloc".to_string(),
            caller: "@test_func".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });
        module.calls.push(CallInstruction {
            callee: "@free".to_string(),
            caller: "@test_func".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });

        module
    }

    /// Objective: Verify that ModuleIndex::build correctly caches call metadata.
    /// Invariants: call_metas length matches module.calls length.
    #[test]
    fn test_module_index_build() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);

        assert_eq!(
            index.call_metas.len(),
            2,
            "ModuleIndex must cache metadata for all 2 call instructions"
        );
        assert_eq!(index.total_call_count, 2, "Total call count must be 2");
    }

    /// Objective: Verify that caller/callee indexing works correctly.
    /// Invariants: caller_calls maps caller to correct call indices.
    #[test]
    fn test_caller_callee_indexing() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);

        let test_func_calls = index.calls_by_caller("test_func");
        assert_eq!(
            test_func_calls.len(),
            2,
            "test_func must have 2 call instructions"
        );

        let malloc_callers = index.callers_of("malloc");
        assert_eq!(
            malloc_callers.len(),
            1,
            "malloc must be called from 1 call site"
        );
    }

    /// Objective: Verify that allocation/deallocation detection works.
    /// Invariants: malloc is detected as alloc, free as dealloc.
    #[test]
    fn test_alloc_dealloc_detection() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);

        let alloc_calls: Vec<_> = index.alloc_calls().collect();
        assert!(
            !alloc_calls.is_empty(),
            "Must detect at least 1 allocation call (malloc)"
        );

        let dealloc_calls: Vec<_> = index.dealloc_calls().collect();
        assert!(
            !dealloc_calls.is_empty(),
            "Must detect at least 1 deallocation call (free)"
        );
    }

    /// Objective: Verify that function metadata includes alloc/dealloc call tracking.
    /// Invariants: test_func profile shows calls_alloc=true, calls_dealloc=true.
    #[test]
    fn test_function_meta() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);

        let profile = index
            .function_meta("test_func")
            .expect("test_func must have a cached profile");

        assert_eq!(
            profile.language,
            Language::C,
            "test_func must be detected as C"
        );
        assert!(profile.calls_alloc, "test_func must call alloc functions");
        assert!(
            profile.calls_dealloc,
            "test_func must call dealloc functions"
        );
        assert_eq!(profile.call_count, 2, "test_func must have 2 calls");
    }

    /// Objective: Verify that LLVM intrinsic detection works.
    /// Invariants: llvm.* calls are marked as is_llvm_intrinsic.
    #[test]
    fn test_llvm_intrinsic_detection() {
        let mut module = IRModule::new();
        module.calls.push(CallInstruction {
            callee: "@llvm.lifetime.start".to_string(),
            caller: "@test".to_string(),
            is_external: false,
            location: None,
            args: Vec::new(),
            result: None,
        });

        let index = ModuleIndex::build(&module);
        assert!(
            index.call_metas[0].is_llvm_intrinsic,
            "llvm.lifetime.start must be detected as LLVM intrinsic"
        );
    }

    /// Objective: Verify that C++ mangled name detection works.
    /// Invariants: _Z prefixed names are detected as C++ mangled.
    #[test]
    fn test_cpp_mangled_detection() {
        let mut module = IRModule::new();
        module.calls.push(CallInstruction {
            callee: "@_ZdlPv".to_string(),
            caller: "@test".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });

        let index = ModuleIndex::build(&module);
        assert!(
            index.call_metas[0].is_cpp_mangled,
            "_ZdlPv must be detected as C++ mangled"
        );
    }

    /// Objective: Verify that module with no calls produces empty index.
    /// Invariants: Empty module produces zero-length call_metas without panic.
    #[test]
    fn test_empty_module_index() {
        let module = IRModule::new();
        let index = ModuleIndex::build(&module);

        assert!(
            index.call_metas.is_empty(),
            "Empty module must produce empty call_metas"
        );
        assert!(
            index.function_metas.is_empty(),
            "Empty module must produce empty function_metas"
        );
    }

    /// Objective: Verify that cross-language detection works correctly.
    /// Invariants: C function calling Rust function is detected as cross-language.
    #[test]
    fn test_cross_language_detection() {
        let mut module = IRModule::new();

        // Add a C-style function
        module.functions.insert(
            "@c_func".to_string(),
            Function {
                name: "c_func".to_string(),
                is_declaration: false,
                params: vec![],
                return_type: "void".to_string(),
            },
        );

        // Add a Rust-style function call (Rust mangled names start with _ZN)
        module.calls.push(CallInstruction {
            callee: "@_ZN3foo3bar17h1234567890abcdefE".to_string(),
            caller: "@c_func".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });

        let index = ModuleIndex::build(&module);

        // The caller is C, callee is detected as Rust
        // This should be detected as cross-language
        assert!(
            index.call_metas[0].is_cross_language || index.call_metas[0].is_ffi_boundary,
            "C calling Rust must be detected as cross-language or FFI boundary"
        );
    }

    /// Objective: Verify that ffi_functions() returns functions with FFI calls.
    /// Invariants: Functions calling cross-language functions appear in ffi_functions.
    #[test]
    fn test_ffi_functions_list() {
        let mut module = IRModule::new();

        module.functions.insert(
            "@caller".to_string(),
            Function {
                name: "caller".to_string(),
                is_declaration: false,
                params: vec![],
                return_type: "void".to_string(),
            },
        );

        module.calls.push(CallInstruction {
            callee: "@_ZN3foo3bar17h1234567890abcdefE".to_string(),
            caller: "@caller".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });

        let index = ModuleIndex::build(&module);
        let ffi_funcs = index.ffi_functions();

        assert!(
            !ffi_funcs.is_empty(),
            "Must detect at least 1 function with FFI calls"
        );
    }

    /// Helper: insert a Rust-mangled defined function with no calls.
    fn insert_rust_defined(module: &mut IRModule, mangled_name: &str) {
        let key = format!("@{}", mangled_name);
        module.functions.insert(
            key,
            Function {
                name: mangled_name.to_string(),
                is_declaration: false,
                params: vec![],
                return_type: "void".to_string(),
            },
        );
    }

    /// Helper: insert a declaration (extern) with the given plain name.
    fn insert_extern_decl(module: &mut IRModule, name: &str) {
        let key = format!("@{}", name);
        module.declarations.insert(
            key,
            Function {
                name: name.to_string(),
                is_declaration: true,
                params: vec!["i64".to_string()],
                return_type: "ptr".to_string(),
            },
        );
    }

    /// Objective: A Rust module that declares >=3 C externs (mi_malloc,
    /// mi_free, malloc, free) must be demoted from single-language to
    /// mixed so FFI passes stay enabled.
    /// Invariants: is_single_language == false.
    #[test]
    fn test_demotes_rust_module_with_c_externs() {
        let mut module = IRModule::new();
        // Defined: a Rust-mangled function (matches _ZN5alloc prefix).
        insert_rust_defined(
            &mut module,
            "_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$8allocate",
        );
        // Declared: plain C externs (no mangling → Language::Unknown).
        insert_extern_decl(&mut module, "mi_malloc");
        insert_extern_decl(&mut module, "mi_free");
        insert_extern_decl(&mut module, "malloc");
        insert_extern_decl(&mut module, "free");

        let index = ModuleIndex::build(&module);

        assert!(
            !index.is_single_language,
            "Rust module with 4 C externs must be demoted to mixed-language so FFI passes run"
        );
    }

    /// Objective: A pure Rust module with no foreign externs stays
    /// single-language so FFI passes can short-circuit.
    /// Invariants: is_single_language == true.
    #[test]
    fn test_keeps_single_language_when_no_externs() {
        let mut module = IRModule::new();
        insert_rust_defined(&mut module, "_ZN5alloc7raw_vec8allocate");
        insert_rust_defined(&mut module, "_ZN4core3str4len");

        let index = ModuleIndex::build(&module);

        assert!(
            index.is_single_language,
            "Pure-Rust module with no foreign externs must remain single-language"
        );
    }

    /// Objective: Below the demotion threshold (1-2 foreign externs),
    /// the module must stay single-language. Three is the demotion floor.
    /// Invariants: is_single_language == true with only 2 C externs.
    #[test]
    fn test_below_threshold() {
        let mut module = IRModule::new();
        insert_rust_defined(&mut module, "_ZN5alloc7raw_vec8allocate");
        // Only 2 foreign externs — under MIN_FOREIGN_EXTERNS_FOR_MIXED.
        insert_extern_decl(&mut module, "malloc");
        insert_extern_decl(&mut module, "free");

        let index = ModuleIndex::build(&module);

        assert!(
            index.is_single_language,
            "Rust module with only 2 C externs must remain single-language (below threshold of 3)"
        );
    }

    /// Objective: A module with many bun_alloc / mimalloc functions must
    /// be detected as an allocator crate.
    /// Invariants: is_allocator_crate() == true when ≥30% or ≥10 matches.
    #[test]
    fn test_detect_allocator_crate() {
        let mut module = IRModule::new();
        // Insert enough allocator-related functions to exceed threshold
        for i in 0..15 {
            insert_rust_defined(
                &mut module,
                &format!(
                    "_RNvCs92_9bun_alloc_7abe075f8accee73_5alloc_8allocator9ZAllocator{}alloc",
                    i
                ),
            );
        }
        // A few non-allocator functions (to keep ratio realistic)
        insert_rust_defined(&mut module, "_ZN4core3str4len");

        let index = ModuleIndex::build(&module);

        assert!(
            index.is_allocator_crate(),
            "Module with mostly bun_alloc functions must be detected as allocator crate"
        );
    }

    /// Objective: A normal Rust module without allocator patterns must NOT
    /// be detected as an allocator crate.
    /// Invariants: is_allocator_crate() == false.
    #[test]
    fn test_non_allocator_crate() {
        let mut module = IRModule::new();
        insert_rust_defined(&mut module, "_ZN5alloc7raw_vec8allocate");
        insert_rust_defined(&mut module, "_ZN4core3str4len");
        insert_rust_defined(&mut module, "_ZN3my_app4main");
        insert_rust_defined(&mut module, "_ZN3my_app3run");

        let index = ModuleIndex::build(&module);

        assert!(
            !index.is_allocator_crate(),
            "Normal application module must NOT be detected as allocator crate"
        );
    }
}
