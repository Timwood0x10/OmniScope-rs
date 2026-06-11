//! Helper functions for issue candidate builder.
//!
//! Contains general-purpose utility functions used across the candidate
//! builder, including pointer-type checks, FFI/export detection,
//! free-site construction for alias analysis, and boundary evidence
//! collection.

use omniscope_core::IssueCandidate;
use omniscope_semantics::SemanticFact;
use omniscope_types::{
    BoundaryDetectionMethod, CrossBoundaryEvidence, Evidence, EvidenceKind, FamilyId,
    IssueCandidateKind, Language,
};

use crate::resource::contract_graph_builder::{ContractEdge, ContractGraph};
use crate::resource::may_alias::FreeSite;

/// Converts a SemanticFact into an Evidence attachment for issue candidates.
///
/// The evidence kind is set to SemanticFactEvidence and the description
/// includes the fact's kind, source, confidence, and evidence text.
pub(crate) fn fact_to_evidence(fact: &SemanticFact) -> Evidence {
    let confidence = fact.confidence_score();
    Evidence::new(
        EvidenceKind::SemanticFactEvidence,
        format!(
            "[{:?}] {} (source={}, confidence={})",
            fact.kind, fact.evidence, fact.source, fact.confidence,
        ),
    )
    .with_confidence(confidence)
}

/// Check whether a contract edge has boundary evidence from the
/// boundary_seeds pipeline (not just BoundaryContext configuration).
///
/// Boundary evidence from `boundary_evidence: Some([..])` indicates
/// the seed classifier found a cross-language boundary at this edge.
/// `Some([])` means "computed but no boundary found".
/// `None` means "not computed" (should not happen after P1 wiring).
pub(crate) fn edge_has_boundary_evidence(edge: &ContractEdge) -> bool {
    edge.boundary_evidence
        .as_ref()
        .is_some_and(|ev| !ev.is_empty())
}

/// Collect boundary evidence from two edges (acquire + release) into
/// a single `CrossBoundaryEvidence` if any strong boundary signal exists.
///
/// Returns None if neither edge has boundary evidence.
pub(crate) fn collect_boundary_from_edges(
    acquire_edge: &ContractEdge,
    release_edge: &ContractEdge,
) -> Option<CrossBoundaryEvidence> {
    // Prefer evidence from the release edge (where the boundary violation
    // typically manifests), fall back to the acquire edge.
    let evidence = release_edge
        .boundary_evidence
        .as_ref()
        .filter(|ev| !ev.is_empty())
        .or_else(|| {
            acquire_edge
                .boundary_evidence
                .as_ref()
                .filter(|ev| !ev.is_empty())
        })?;

    // Find the strongest evidence item and convert to CrossBoundaryEvidence
    let best = evidence
        .iter()
        .find(|e| e.is_strong())
        .or(evidence.first())?;

    // Determine language pair from the evidence or edge metadata
    let from = best.caller_lang.unwrap_or(Language::Unknown);
    let to = best.callee_lang.unwrap_or(Language::Unknown);

    Some(CrossBoundaryEvidence {
        from,
        to,
        detection_method: BoundaryDetectionMethod::LanguagePairMatch,
    })
}

/// Checks if a function name is a known pointer-projection utility.
///
/// These functions (e.g., `as_ptr`, `as_mut_ptr`, `data`, `cast`) return
/// pointers that alias their input without ownership transfer. They are
/// never bugs — the caller explicitly requested the raw pointer.
pub(crate) fn is_known_pointer_projection(func_name: &str) -> bool {
    let name = func_name.trim_start_matches('@').to_lowercase();
    name.ends_with("as_ptr")
        || name.ends_with("as_mut_ptr")
        || name.ends_with(".data()")
        || name.ends_with(".cast()")
        || name.contains("::from_raw")
        || name.contains("::into_raw")
}

/// Checks if a function's return type is a pointer type.
///
/// ReturnAlias (BorrowEscape) is only meaningful when the function returns
/// a pointer — if it returns an integer (i32, i64, etc.), the aliasing
/// is a value copy (e.g., memcpy result count), not a dangling-pointer risk.
///
/// Looks up the function in both defined functions and external declarations
/// of the IR module. Returns `false` if the function is not found or the
/// return type cannot be determined (conservative: allow the candidate).
pub(crate) fn function_returns_pointer(
    func_name: &str,
    ir_module: Option<&omniscope_ir::IRModule>,
) -> bool {
    let ir_mod = match ir_module {
        Some(m) => m,
        None => return true, // Cannot determine — allow candidate conservatively
    };

    // Try defined functions first, then declarations
    let lookup_name = func_name.trim_start_matches('@');
    if let Some(func) = ir_mod.functions.get(lookup_name) {
        return is_pointer_type(&func.return_type);
    }
    if let Some(decl) = ir_mod.declarations.get(lookup_name) {
        return is_pointer_type(&decl.return_type);
    }

    // Function not found in module — allow candidate conservatively
    true
}

/// Checks if an LLVM type string represents a pointer type.
///
/// Pointer types in LLVM IR include:
/// - `ptr` (opaque pointer, LLVM 18+)
/// - `i8*`, `i32*`, etc. (typed pointers, legacy)
/// - `%struct.Foo*` (pointer to named struct)
/// - `[N x T]*` (pointer to array)
fn is_pointer_type(type_str: &str) -> bool {
    let t = type_str.trim();
    t == "ptr" || t.ends_with('*')
}

/// Checks if a function looks like an FFI export or public API boundary.
///
/// FFI exports typically have naming patterns like:
/// - Functions with well-known FFI/export markers in name or path
/// - C-style snake_case functions at language boundaries
///
/// Internal helpers from standard libraries (Rust std, etc.)
/// are excluded even if they match generic heuristics, because their
/// return-alias patterns are well-known idioms within that ecosystem.
///
/// # Limitations
/// This is a heuristic — it cannot detect FFI exports that:
/// - Use purely lowercase C names without FFI keywords (e.g., `gtk_widget_destroy`)
/// - Rely on `#[no_mangle]` attributes rather than naming conventions
/// - Are registered via runtime symbol tables
///
/// False positives are possible for internal CamelCase factory methods
/// containing Alloc/Create/etc. The exclusion list should be extended
/// as new FP patterns emerge.
pub(crate) fn looks_like_ffi_or_export(func_name: &str) -> bool {
    let name = func_name.trim_start_matches('@');

    // Exclude known library/namespace patterns that produce many FPs.
    // These ecosystems use return-alias patterns as normal idiom.
    if name.starts_with("Io.")
        || name.starts_with("std.")
        || name.starts_with("builtin.")
        || name.contains("::__anon_")
    {
        return false;
    }

    // FFI/export-specific markers (strong signal)
    if name.contains("export")
        || name.contains("extern")
        || name.contains("ffi_")
        || name.contains("_wrapper")
        || name.contains("_bindgen")
        || name.contains("marshal")
        || name.contains("interop")
        || name.contains("callback")
    {
        return true;
    }

    // CamelCase with known FFI-related terms
    let has_ffi_term = name.contains("Alloc")
        || name.contains("Free")
        || name.contains("Create")
        || name.contains("Destroy")
        || name.contains("Init")
        || name.contains("Open")
        || name.contains("Close");
    if has_ffi_term && name.chars().next().is_some_and(|c| c.is_uppercase()) {
        return true;
    }

    false
}

/// Helper: Build a cross-family free candidate.
///
/// Convenience function for constructing a `CrossFamilyFree` candidate
/// with the standard description format.
pub fn build_cross_family_candidate(
    id: u64,
    alloc_family: FamilyId,
    release_family: FamilyId,
    alloc_func: &str,
    release_func: &str,
) -> IssueCandidate {
    IssueCandidate::new(
        id,
        IssueCandidateKind::CrossFamilyFree,
        alloc_family,
        alloc_func,
    )
    .with_release_family(release_family)
    .with_release_function(release_func)
    .with_description(format!(
        "cross-family release: {} ({:?}) released by {} ({:?})",
        alloc_func, alloc_family, release_func, release_family
    ))
}

/// Build a `FreeSite` describing a release edge for the may-alias gate.
///
/// Walks the caller's function body, counts release calls to the edge's
/// callee, and returns the n-th such call's first SSA argument — where
/// n is determined by how many release edges to the same callee already
/// appeared in the caller. This best-effort mapping matches the order in
/// which the contract graph builder discovers release calls.
pub(crate) fn build_free_site_for_edge(
    graph: &ContractGraph,
    edge_idx: usize,
    ir_module: Option<&omniscope_ir::IRModule>,
) -> FreeSite {
    use omniscope_types::Effect;

    let edge = &graph.edges[edge_idx];
    let arg = ir_module.and_then(|m| {
        // How many earlier release edges (in graph order) target the same
        // (caller, callee) pair as this edge? That is the index of the
        // matching call instruction in the caller's body.
        let nth = graph.edges[..edge_idx]
            .iter()
            .filter(|e| {
                matches!(
                    e.effect,
                    Effect::Release { .. } | Effect::ConditionalRelease { .. }
                ) && e.caller_name == edge.caller_name
                    && e.function_name == edge.function_name
            })
            .count();
        let body = m.function_bodies.get(&edge.caller_name)?;
        let mut seen = 0usize;
        for inst in &body.instructions {
            if !matches!(inst.kind, omniscope_ir::IRInstructionKind::Call) {
                continue;
            }
            let Some(callee) = &inst.callee else { continue };
            if callee != &edge.function_name {
                continue;
            }
            if seen == nth {
                // Reuse the parsing helper from contract_graph_builder via raw text.
                return crate::resource::may_alias::first_call_arg_register(&inst.raw_text);
            }
            seen += 1;
        }
        None
    });
    FreeSite::new(&edge.caller_name, &edge.function_name, arg)
}

/// Checks if a function name is a pure deallocator — a function whose sole
/// purpose is to release a previously allocated resource (e.g., `free`,
/// `munmap`, `__rust_dealloc`). When such a function appears as the
/// `alloc_function` (Callee name) of a DoubleRelease candidate, it indicates
/// the candidate was generated from multiple `free(p)` calls merged into one
/// contract-graph instance, rather than a genuine user-code double-free.
pub(crate) fn is_pure_deallocator(function_name: &str) -> bool {
    matches!(
        function_name,
        "free" | "munmap" | "__rust_dealloc"
    ) || function_name.starts_with("_ZdlPv") // C++ operator delete
      || function_name.starts_with("_ZdaPv") // C++ operator delete[]
}

/// Checks if a release function is null-guarded.
///
/// Null-guarded release functions check if the pointer is NULL before
/// releasing it. For example, `free(NULL)` is safe in C, and many
/// libraries implement null-guarded release functions.
pub(crate) fn is_null_guarded_release(function_name: &str) -> bool {
    // Known null-guarded release functions. Only exact matches are used
    // to avoid false positives from pattern-based heuristics.
    const NULL_GUARDED_RELEASES: &[&str] = &[
        "free",            // C standard library free
        "cJSON_Delete",    // cJSON library
        "json_object_put", // json-c library
        "sqlite3_free",    // SQLite
        "g_free",          // GLib
        "g_slice_free",    // GLib
        "CFRelease",       // Core Foundation (though it crashes on NULL in practice)
        "Release",         // Common COM pattern
        "SafeRelease",     // Safe COM release pattern
        "SafeDelete",      // Safe delete pattern
        "SafeDeleteArray", // Safe delete array pattern
    ];

    NULL_GUARDED_RELEASES.contains(&function_name)
}

/// Checks if NULL is stored to a pointer after release in the contract graph.
///
/// This pattern prevents dangling pointer access by setting the pointer to NULL
/// after releasing the resource. For example:
/// ```c
/// free(ptr);
/// ptr = NULL;
/// ```
pub(crate) fn has_null_store_pattern(graph: &ContractGraph, instance_id: &u64) -> bool {
    use omniscope_types::Effect;
    // Look for edges that store NULL to this instance
    graph.edges.iter().any(|edge| {
        // Check if this edge stores to the same instance
        if edge.source == *instance_id {
            // Check if it's a NULL store effect
            matches!(edge.effect, Effect::StoresArgToGlobal { .. })
                || matches!(edge.effect, Effect::StoresArgToOwner { .. })
                || matches!(edge.effect, Effect::InitializesOutParam { .. })
        } else {
            false
        }
    })
}

/// Check if a function returns an acquired resource via `ret` instruction.
///
/// When a function calls malloc/mi_malloc/etc. (an Acquire edge) and then
/// returns that pointer to the caller, the resource is NOT leaked — it has
/// escaped to the caller. This is the "allocator factory" or "return-value-escape"
/// pattern common in FFI bridge layers like bun_alloc.
///
/// Returns `true` if the function body contains a `ret` instruction that
/// returns the acquired SSA register (or any register if the specific
/// register is not known).
///
/// # Arguments
/// * `func_name` - The function to check.
/// * `acquire_ssa_reg` - Optional SSA register (e.g., "%result") from the
///   acquire call. If provided, the ret instruction must return exactly this
///   register to count as return-value-escape.
/// * `ir_module` - The IR module containing function bodies.
///
/// # Fix 6
/// Previously this function returned `true` if ANY ret instruction existed,
/// which was unreliable — `ret void` or `ret i32 0` do NOT return the
/// acquired resource. Now we check whether the ret instruction actually
/// returns a register value (SSA operand starting with '%').
pub(crate) fn function_returns_acquired_resource(
    func_name: &str,
    acquire_ssa_reg: Option<&str>,
    ir_module: Option<&omniscope_ir::IRModule>,
) -> bool {
    let mod_ref = match ir_module {
        Some(m) => m,
        None => return false,
    };

    let body = match mod_ref.function_bodies.get(func_name) {
        Some(b) => b,
        None => return false,
    };

    // Find the first ret instruction.
    let ret_inst = match body
        .instructions
        .iter()
        .find(|inst| matches!(inst.kind, omniscope_ir::IRInstructionKind::Ret))
    {
        Some(inst) => inst,
        None => return false,
    };

    // If we know the specific acquire SSA register, check if ret returns it.
    if let Some(reg) = acquire_ssa_reg {
        return ret_inst.operands.iter().any(|op| op == reg);
    }

    // Otherwise, check if ret returns any register (starts with '%').
    // This excludes `ret void` and `ret i32 0` — returning a constant
    // or void does NOT escape the acquired resource.
    ret_inst.operands.iter().any(|op| op.starts_with('%'))
}

/// Check if a function name indicates it's an allocator factory function.
///
/// Allocator factory functions are thin wrappers whose job is to allocate
/// memory and return it to the caller. Their names contain alloc/malloc/
/// realloc/zalloc/dupe patterns. Leak reports for these are always FPs
/// because the allocation IS returned to the caller.
///
/// This is a stronger version of `is_allocator_thunk` from ffi_boundary_detector
/// — it requires the name to indicate memory allocation specifically.
pub(crate) fn is_allocator_factory_function(
    func_name: &str,
    ir_module: Option<&omniscope_ir::IRModule>,
) -> bool {
    use crate::analysis::ffi_boundary_detector::is_allocator_thunk;

    // Must be an allocator thunk first
    if !is_allocator_thunk(func_name, ir_module) {
        return false;
    }

    let name = func_name.trim_start_matches('@').to_lowercase();

    // Must have explicit allocator naming
    name.contains("malloc")
        || name.contains("zalloc")
        || name.contains("calloc")
        || name.contains("realloc")
        || (name.contains("alloc") && !name.contains("dealloc"))
        || name.contains("dupe")
        || name.contains("create")
}

/// Check if a leak candidate should be suppressed because of return-value-escape
/// or allocator factory pattern.
///
/// This implements two suppression rules:
/// 1. **Return-value-escape**: The function that acquired the resource also
///    has a `ret` instruction → the resource escapes to the caller.
/// 2. **Allocator factory**: The function name indicates it's an allocator
///    factory (e.g., mi_malloc_items, default_dupe, alloc_with_default_allocator).
///
/// Either condition is sufficient to suppress ConditionalLeak/DefiniteLeak.
pub(crate) fn should_suppress_leak_for_allocator_escape(
    alloc_caller: Option<&str>,
    alloc_func: &str,
    ir_module: Option<&omniscope_ir::IRModule>,
) -> bool {
    // Rule 1: Return-value-escape — check if the alloc_caller function has ret
    if let Some(caller) = alloc_caller {
        if function_returns_acquired_resource(caller, None, ir_module) {
            tracing::debug!(
                "[LEAK-SUPPRESS] alloc_caller '{}' has ret instruction — \
                 return-value-escape, suppressing leak",
                caller
            );
            return true;
        }
    }

    // Rule 2: Allocator factory — check function name patterns
    if is_allocator_factory_function(alloc_func, ir_module) {
        tracing::debug!(
            "[LEAK-SUPPRESS] alloc_func '{}' is allocator factory — suppressing leak",
            alloc_func
        );
        return true;
    }

    // Rule 3: Arena allocator — arena allocations are intentionally never freed individually
    if let Some(caller) = alloc_caller {
        use crate::analysis::ffi_boundary_detector::is_arena_allocator;
        if is_arena_allocator(caller) {
            tracing::debug!(
                "[LEAK-SUPPRESS] alloc_caller '{}' is arena allocator — suppressing leak",
                caller
            );
            return true;
        }
    }

    // Rule 4: Non-allocator API — the "acquire" is not actually acquiring memory
    use crate::analysis::ffi_boundary_detector::is_non_allocator_api;
    if is_non_allocator_api(alloc_func) {
        tracing::debug!(
            "[LEAK-SUPPRESS] alloc_func '{}' is non-allocator API — suppressing leak",
            alloc_func
        );
        return true;
    }

    false
}
