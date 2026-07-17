//! Helper functions for path-sensitive leak detection.
//!
//! Contains:
//! - Allocation/release counting functions
//! - Summary store checks
//! - Caller-owned resource detection
//! - Runtime-managed resource detection
//! - Call graph adjacency and reachability
//! - Data structures: LeakPath, PathAnalysisResult, FunctionTermination

use omniscope_ir::IRInstructionKind;
use omniscope_ir::IRModule;
use omniscope_semantics::{SemanticKind, SummaryStore};
use omniscope_types::{Effect, FamilyId};

use crate::resource::noreturn::is_noreturn_callee;
use crate::resource::raw_fact_collector::RawResourceFact;

/// Classification of a function's exit behavior.
///
/// Used by the OOM-termination FP suppression: allocations in functions
/// that only exit via abort/unreachable are not leaks — the program
/// terminates before any leak can occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FunctionTermination {
    /// Function has at least one normal `ret` exit (may also have abort paths).
    HasNormalReturn,
    /// Function exits *only* via abort/unreachable/noreturn calls — no `ret`.
    OnlyAborts,
    /// Cannot determine (no function body available).
    Unknown,
}

/// Represents a path through the CFG from an allocation to an exit.
///
/// Used internally for path slicing. In a full implementation,
/// this would carry actual CFG node IDs.
///
/// **Stub note**: The current `LeakDetectionPass::run()` uses a simpler
/// per-function release check instead of full path enumeration. This type
/// is retained as a placeholder for the planned path-sensitive upgrade.
#[derive(Debug, Clone)]
pub struct LeakPath {
    /// The allocation site (function ID).
    pub alloc_function: u64,
    /// The resource family of the allocation.
    pub alloc_family: FamilyId,
    /// Whether this path contains a same-family release.
    pub has_release: bool,
    /// Length of the path (number of CFG nodes).
    pub path_length: usize,
    /// Whether this path hit the budget limit.
    pub budget_exceeded: bool,
}

impl LeakPath {
    /// Creates a new leak path.
    pub fn new(alloc_function: u64, alloc_family: FamilyId) -> Self {
        Self {
            alloc_function,
            alloc_family,
            has_release: false,
            path_length: 0,
            budget_exceeded: false,
        }
    }

    /// Returns true if this path is a leak (no release).
    pub fn is_leak(&self) -> bool {
        !self.has_release
    }
}

/// Result of path-sensitive analysis for one allocation site.
///
/// **Stub note**: Retained as a placeholder for the planned path-sensitive
/// upgrade. The current implementation uses simpler per-function checks.
#[derive(Debug, Clone)]
pub struct PathAnalysisResult {
    /// Total paths explored.
    pub total_paths: usize,
    /// Number of paths that leak (no release).
    pub leaking_paths: usize,
    /// Number of paths that properly release.
    pub safe_paths: usize,
    /// Whether the path budget was exceeded.
    pub budget_exceeded: bool,
}

impl PathAnalysisResult {
    /// Creates a new result.
    pub fn new(total: usize, leaking: usize, safe: usize, budget_exceeded: bool) -> Self {
        Self {
            total_paths: total,
            leaking_paths: leaking,
            safe_paths: safe,
            budget_exceeded,
        }
    }

    /// Returns true if ALL paths leak (definite leak).
    pub fn is_definite_leak(&self) -> bool {
        self.total_paths > 0 && self.safe_paths == 0 && !self.budget_exceeded
    }

    /// Returns true if SOME paths leak (conditional leak).
    pub fn is_conditional_leak(&self) -> bool {
        self.leaking_paths > 0 && self.safe_paths > 0
    }

    /// Returns the leak confidence (0.0 - 1.0).
    ///
    /// All paths leaking → 0.9, some paths → proportional.
    pub fn leak_confidence(&self) -> f32 {
        if self.total_paths == 0 {
            return 0.0;
        }
        if self.is_definite_leak() {
            0.9
        } else {
            (self.leaking_paths as f32 / self.total_paths as f32) * 0.7
        }
    }
}

/// Counts allocations and releases of the same family for the given
/// allocation site, scoped to the allocation's function.
///
/// Returns (alloc_count, release_count). If release_count == 0 and
/// no summary release exists, the allocation is a definite leak.
/// If 0 < release_count < alloc_count, it is a conditional leak.
pub(super) fn count_alloc_release_in_facts(
    facts: &[RawResourceFact],
    alloc: &RawResourceFact,
) -> (u32, u32) {
    let alloc_family = alloc.family.unwrap_or(FamilyId::C_HEAP);

    let mut alloc_count = 0u32;
    let mut release_count = 0u32;

    for fact in facts {
        if fact.family != Some(alloc_family) {
            continue;
        }
        if fact.function != alloc.function && fact.function_name != alloc.function_name {
            continue;
        }
        if fact.is_acquire {
            alloc_count += 1;
        } else {
            release_count += 1;
        }
    }

    (alloc_count, release_count)
}

/// Checks if the summary store contains a function that releases
/// the same family as the allocation, scoped to the allocation's function.
///
/// Previously this searched ALL summaries globally, which caused false
/// suppression: any function with a same-family Release would suppress
/// the leak, even if the release was in a completely unrelated function.
///
/// Now we restrict the search to summaries whose `function` ID matches
/// the alloc's function ID (the function containing the alloc also releases).
///
/// NOTE: Cross-function release detection (e.g. a callee that frees memory
/// allocated by its caller) requires call graph data to connect the alloc
/// site to the release site. This function does not attempt that; matching
/// by callee name would be unsound because an alloc callee like "malloc"
/// would have Acquire effects, not Release effects.
pub(super) fn check_release_in_summaries(store: &SummaryStore, alloc: &RawResourceFact) -> bool {
    let alloc_family = alloc.family.unwrap_or(FamilyId::C_HEAP);

    for (_, summary) in store.iter() {
        // Only consider summaries in the same function as the allocation.
        if summary.function != alloc.function {
            continue;
        }

        for effect in &summary.effects {
            match effect {
                Effect::Release { family, .. } if *family == alloc_family => {
                    return true;
                }
                Effect::ConditionalRelease { family, .. } if *family == alloc_family => {
                    return true;
                }
                _ => {}
            }
        }
    }

    false
}

/// Checks if the alloc's caller function transfers ownership of the
/// allocated resource to its caller (via `ReturnsOwned`, `OutParamOwnedOnSuccess`,
/// or `OwnershipEscape` effect).
///
/// This is the FP#4 suppression: allocations in factory functions, `into_raw`
/// wrappers, and out-param initializers are *intentionally* not freed locally —
/// the caller takes ownership. Without this check, such allocations would be
/// flagged as leaks.
pub(super) fn caller_returns_owned_resource(store: &SummaryStore, alloc: &RawResourceFact) -> bool {
    let alloc_family = alloc.family.unwrap_or(FamilyId::C_HEAP);

    // Look up the caller function's summary by function ID first,
    // then fall back to name-based lookup.
    let summary_by_id = store.get(alloc.function);
    let summary_by_name = if summary_by_id.is_none() {
        store.find_by_name(&alloc.caller_name)
    } else {
        None
    };

    let check_effects = |summary: &omniscope_semantics::ResourceSummary| -> bool {
        summary.effects.iter().any(|effect| match effect {
            Effect::ReturnsOwned { family } if *family == alloc_family => true,
            Effect::OutParamOwnedOnSuccess { family, .. } if *family == alloc_family => true,
            Effect::OwnershipEscape { family, .. } if *family == alloc_family => true,
            _ => false,
        })
    };

    if let Some(summary) = summary_by_id {
        return check_effects(summary);
    }
    if let Some(summary) = summary_by_name {
        return check_effects(summary);
    }

    false
}

/// Checks if the allocation's caller function returns the allocated pointer
/// to its caller (the "malloc + return" pattern used by factory functions).
///
/// This is a direct IR-level check that looks at the function body for a `ret`
/// instruction that returns a pointer value derived from a `malloc`/`calloc` call.
/// It serves as a fallback when the summary store hasn't been populated yet.
///
/// Factory functions like `dupString()` allocate with `malloc()` and return the
/// pointer — the caller takes ownership. Without this check, such allocations
/// would be flagged as DefiniteLeak.
pub(super) fn allocation_returned_to_caller(
    module: &IRModule,
    alloc: &RawResourceFact,
) -> bool {
    // Get the function body for the caller.
    let body = match module.function_bodies.get(&alloc.caller_name) {
        Some(b) => b,
        None => return false,
    };

    // Check if the function returns a pointer (has a `ret` with a pointer operand).
    // This is a strong signal that the function is a factory/accessor, not a sink.
    let has_ptr_return = body.instructions.iter().any(|inst| {
        matches!(inst.kind, IRInstructionKind::Ret)
            && inst.operands.iter().any(|op| op.starts_with('%') || op.starts_with('@'))
    });
    if !has_ptr_return {
        return false;
    }

    // Check if the function has at least one allocator call (malloc, calloc, etc.)
    // that is a direct allocation (not a realloc). The allocator function name is
    // in `alloc.function_name`.
    let is_allocator = alloc.function_name == "malloc"
        || alloc.function_name == "calloc"
        || alloc.function_name == "realloc"
        || alloc.function_name == "_Znam"   // C++ operator new[]
        || alloc.function_name == "_Znwm";  // C++ operator new

    is_allocator && has_ptr_return
}

/// Checks if the alloc's function or caller is marked as runtime-managed
/// in the SRT (Semantic Resolution Tree) resolutions.
///
/// If a function is tagged with `RuntimeManagedResource`, `StoredToRuntime`,
/// or `StoredToOwner`, allocations within it are not local leaks — the
/// runtime/arena/owner is responsible for cleanup.
///
/// When SRT has no resolution for the function, falls back to a static
/// whitelist of well-known runtime/GC-managed allocators (e.g., C# COM
/// interop `CoTaskMemAlloc`, P/Invoke `Marshal.AllocHGlobal`).
pub(super) fn is_runtime_managed(
    srt_resolutions: &Option<std::collections::HashMap<String, Vec<SemanticKind>>>,
    alloc: &RawResourceFact,
) -> bool {
    let managed_kinds = [
        SemanticKind::RuntimeManagedResource,
        SemanticKind::StoredToRuntime,
        SemanticKind::StoredToOwner,
    ];

    // First, check SRT resolutions (most precise).
    if let Some(resolutions) = srt_resolutions {
        for name in [&alloc.function_name, &alloc.caller_name] {
            if let Some(kinds) = resolutions.get(name) {
                if kinds.iter().any(|k| managed_kinds.contains(k)) {
                    return true;
                }
            }
        }
    }

    // Fallback: check well-known runtime/GC-managed allocators by name.
    // This handles cases where SRT is empty or has no resolution for the
    // alloc function (e.g., C# CoTaskMemAlloc, Marshal.AllocHGlobal).
    is_well_known_runtime_allocator(&alloc.function_name)
}

/// Checks if a function name is a well-known runtime/GC-managed allocator.
///
/// These allocators are managed by their respective runtimes (CLR GC, Go
/// GC, JVM, etc.) and should not produce DefiniteLeak when the allocation
/// is not explicitly freed — the runtime will reclaim the memory.
fn is_well_known_runtime_allocator(name: &str) -> bool {
    // C# / .NET: COM interop — allocated by COM runtime, freed by CoTaskMemFree
    name == "CoTaskMemAlloc"
        // C# / .NET: P/Invoke Marshal — allocated by CLR, freed by FreeHGlobal
        || name == "Marshal.AllocHGlobal"
        || name == "Marshal_AllocHGlobal"
        || name == "AllocHGlobal"
        // Go runtime: GC-managed allocations
        || name == "runtime.mallocgc"
        || name == "runtime.newobject"
        || name == "runtime.newarray"
        // JNI: JVM-managed references
        || name == "NewLocalRef"
        || name == "NewGlobalRef"
        || name == "NewWeakGlobalRef"
        // Python: reference-counted allocations (managed by PyObject lifecycle)
        || name == "PyObject_New"
        || name == "PyObject_NewVar"
}

/// Classify a function's termination behavior by examining its IR body.
///
/// A function is `OnlyAborts` if it contains **no** `ret` instruction and
/// at least one noreturn indicator (`unreachable` instruction, or a call to
/// a known noreturn function like `abort`, `__cxa_throw`, `out_of_memory`,
/// `core::panicking::*`, etc.).
///
/// A function is `HasNormalReturn` if it has at least one `ret` instruction.
/// Even if the function also has abort paths (e.g. OOM handling), the
/// presence of a normal return means some paths *do* continue execution,
/// so allocations on those paths could potentially leak.
pub(super) fn classify_function_termination(
    module: &IRModule,
    caller_name: &str,
) -> FunctionTermination {
    let body = match module.function_bodies.get(caller_name) {
        Some(b) => b,
        None => return FunctionTermination::Unknown,
    };

    let has_ret = body
        .instructions
        .iter()
        .any(|i| i.kind == IRInstructionKind::Ret);

    if has_ret {
        return FunctionTermination::HasNormalReturn;
    }

    // No `ret` — check if there are noreturn exits.
    let has_noreturn = body.instructions.iter().any(|i| {
        match i.kind {
            IRInstructionKind::Other => {
                // The text parser maps `unreachable` to Other kind.
                i.raw_text.trim().starts_with("unreachable")
            }
            IRInstructionKind::Call => {
                // Check if the callee is a known noreturn function.
                i.callee.as_deref().is_some_and(is_noreturn_callee)
            }
            _ => false,
        }
    });

    if has_noreturn {
        FunctionTermination::OnlyAborts
    } else {
        // No ret and no noreturn — probably a declaration-only function
        // with no body. Treat as unknown.
        FunctionTermination::Unknown
    }
}

/// Check if a function contains an OOM-termination pattern.
///
/// An OOM-termination pattern is a sequence where a null-check on an
/// allocation result leads to a noreturn call (abort/panic/OOM handler).
/// This means the "leak" on the OOM path is not a real leak — the
/// program terminates before any leak matters.
///
/// Returns `true` if the function has at least one noreturn exit path
/// (abort/panic/unreachable), regardless of whether it also has normal
/// return paths. This is used to downgrade `DefiniteLeak` to
/// `ConditionalLeak` when the "unreleased" allocs might be on abort paths.
pub(super) fn function_has_noreturn_exit(module: &IRModule, caller_name: &str) -> bool {
    let body = match module.function_bodies.get(caller_name) {
        Some(b) => b,
        None => return false,
    };

    body.instructions.iter().any(|i| match i.kind {
        IRInstructionKind::Other => i.raw_text.trim().starts_with("unreachable"),
        IRInstructionKind::Call => i.callee.as_deref().is_some_and(is_noreturn_callee),
        _ => false,
    })
}

/// Build a caller → [callees] adjacency list from the call graph edges.
/// If no edges are available, returns an empty map (all releases are
/// conservatively considered reachable).
pub(super) fn build_call_adjacency(
    edges: Option<&[omniscope_types::call_graph_types::CallGraphEdge]>,
) -> std::collections::HashMap<String, Vec<String>> {
    let Some(edges) = edges else {
        return std::collections::HashMap::new();
    };
    let mut adj: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for edge in edges {
        adj.entry(edge.caller.clone())
            .or_default()
            .push(edge.callee.clone());
    }
    adj
}

/// Compute the set of function names reachable from `start` via the call
/// graph adjacency list. Uses BFS with a max depth to avoid infinite
/// recursion on cycles.
pub(super) fn reachable_functions(
    start: &str,
    adj: &std::collections::HashMap<String, Vec<String>>,
) -> std::collections::HashSet<String> {
    let mut reachable = std::collections::HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back((start.to_string(), 0u32));
    reachable.insert(start.to_string());

    const MAX_DEPTH: u32 = 16;

    while let Some((func, depth)) = queue.pop_front() {
        if depth >= MAX_DEPTH {
            continue;
        }
        if let Some(callees) = adj.get(&func) {
            for callee in callees {
                if reachable.insert(callee.clone()) {
                    queue.push_back((callee.clone(), depth + 1));
                }
            }
        }
    }

    reachable
}
