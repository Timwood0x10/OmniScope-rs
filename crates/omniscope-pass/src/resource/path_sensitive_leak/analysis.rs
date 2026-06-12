//! Path-sensitive analysis functions for leak detection.
//!
//! Contains:
//! - PathExitState, ResourcePathState types
//! - collect_exit_states — collects exit states from pointer state map
//! - classify_runtime_state — classifies runtime-managed resources
//! - is_safe_exit — checks if an exit state is safe
//! - path_state_label — human-readable label for exit states
//! - format_exit_state_summary — builds exit state summary string
//! - determine_leak_type — determines leak type from exit states
//! - compute_path_evidence — computes path evidence from instructions

use omniscope_semantics::{SemanticKind, SummaryStore};
use omniscope_types::{Evidence, PathEvidence};

use crate::resource::ownership_solver::PointerStateMap;
use crate::resource::raw_fact_collector::RawResourceFact;

use super::helpers::{caller_returns_owned_resource, is_runtime_managed, FunctionTermination};
use super::LeakType;

/// State of a resource at a function exit point.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(super) struct PathExitState {
    /// The state of the resource at exit.
    pub resource_state: ResourcePathState,
    /// Evidence supporting this state determination.
    pub evidence: Vec<Evidence>,
}

/// State of a resource at a function exit.
///
/// These exit categories drive the leak-type decision in Phase 4:
/// - `Owned` → potential leak (Definite or Conditional depending on mix)
/// - `Released`, `Null` → safe exit, no leak
/// - `EscapedToCaller`, `EscapedOutParam` → ownership transferred, safe
/// - `StoredToOwner`, `StoredToRuntime` → ownership transferred to container/runtime, safe
/// - `RuntimeManaged` → arena/zone/GC-managed, safe
/// - `StaticLifetime` → process-lifetime allocation, safe
/// - `AbortOrUnreachable` → program terminates, not a leak
/// - `Unknown` → fall back to counting logic
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(super) enum ResourcePathState {
    /// Resource is still owned (not freed).
    Owned,
    /// Resource has been released.
    Released,
    /// Resource escaped to caller (returned, stored to out-param).
    EscapedToCaller,
    /// Resource escaped via out-param.
    EscapedOutParam,
    /// Resource stored to an owner structure (struct field, container).
    StoredToOwner,
    /// Resource stored to runtime-managed structure (GC heap, global).
    StoredToRuntime,
    /// Resource is managed by a runtime (arena, zone, GC).
    RuntimeManaged,
    /// Resource has static/process lifetime.
    StaticLifetime,
    /// Path terminates via abort/unreachable — not a leak.
    AbortOrUnreachable,
    /// Resource is NULL (no allocation or freed).
    Null,
    /// Cannot determine state.
    Unknown,
}

/// Collects exit states for a specific allocation from pointer state map,
/// enriched with SRT, summary, and termination data.
///
/// The enrichment pass promotes basic PointerValueState→ResourcePathState
/// mappings to more precise exit categories:
/// - `Escaped` + `ReturnsOwned`/`OutParamOwnedOnSuccess` effect → `EscapedToCaller`/`EscapedOutParam`
/// - `Owned` + `RuntimeManagedResource`/`StoredToRuntime` semantic → `RuntimeManaged`/`StoredToRuntime`
/// - `Owned` + `StoredToOwner` semantic → `StoredToOwner`
/// - `Owned` + function only aborts → `AbortOrUnreachable`
/// - `Owned` + `StaticLifetime` semantic → `StaticLifetime`
pub(super) fn collect_exit_states(
    pointer_states: &PointerStateMap,
    alloc: &RawResourceFact,
    srt_resolutions: &Option<std::collections::HashMap<String, Vec<SemanticKind>>>,
    summary_store: &SummaryStore,
    func_termination: &std::collections::HashMap<String, FunctionTermination>,
) -> Vec<PathExitState> {
    let mut exit_states = Vec::new();

    // Track which resource instances have already been recorded as Released.
    //
    // Mutual-exclusivity deduplication: when the same instance appears as
    // Released on multiple execution paths (e.g. if/else branches that each
    // call free(p)), we record only one Released state because only one
    // path can execute at runtime.  Without this, code like:
    //
    //   if (cond) free(p); else free(p);
    //
    // produces two Released entries → downstream counters may interpret
    // that as a double-free even though the releases are mutually exclusive.
    let mut released_instances: std::collections::HashSet<u64> = std::collections::HashSet::new();

    // Look for pointer states related to this allocation's function.
    let function_prefix = format!("{}_", alloc.caller_name);

    for (slot, state) in pointer_states {
        if !slot.starts_with(&function_prefix) {
            continue;
        }

        // Skip duplicate Released states from mutually exclusive paths.
        if let crate::resource::ownership_solver::PointerValueState::Released { instance } = state {
            if !released_instances.insert(*instance) {
                // Instance already recorded as Released on a prior path —
                // this is a mutually-exclusive duplicate, not a real double-release.
                continue;
            }
        }

        let resource_state = match state {
            crate::resource::ownership_solver::PointerValueState::Unknown => {
                ResourcePathState::Unknown
            }
            crate::resource::ownership_solver::PointerValueState::Null => ResourcePathState::Null,
            crate::resource::ownership_solver::PointerValueState::Owned { .. } => {
                // Enrich: check if the function only aborts → AbortOrUnreachable
                if let Some(FunctionTermination::OnlyAborts) =
                    func_termination.get(&alloc.caller_name)
                {
                    ResourcePathState::AbortOrUnreachable
                }
                // Enrich: check SRT for runtime-managed/static-lifetime
                else if is_runtime_managed(srt_resolutions, alloc) {
                    // Distinguish: StoredToOwner vs RuntimeManaged vs StoredToRuntime vs StaticLifetime
                    classify_runtime_state(srt_resolutions, alloc)
                } else {
                    ResourcePathState::Owned
                }
            }
            crate::resource::ownership_solver::PointerValueState::Released { .. } => {
                ResourcePathState::Released
            }
            crate::resource::ownership_solver::PointerValueState::Escaped { .. } => {
                // Enrich: check if caller returns owned resource
                if caller_returns_owned_resource(summary_store, alloc) {
                    // Determine if escaped to caller or out-param based on slot name.
                    if slot.contains("out") || slot.contains("param") {
                        ResourcePathState::EscapedOutParam
                    } else {
                        ResourcePathState::EscapedToCaller
                    }
                } else if slot.contains("result") {
                    ResourcePathState::EscapedToCaller
                } else if slot.contains("out") || slot.contains("param") {
                    ResourcePathState::EscapedOutParam
                } else {
                    ResourcePathState::EscapedToCaller
                }
            }
        };

        exit_states.push(PathExitState {
            resource_state,
            evidence: Vec::new(),
        });
    }

    // Return empty vec when no pointer states match — the caller will
    // fall back to counting-based leak detection.
    exit_states
}

/// Classifies a runtime-managed resource into the precise exit category
/// based on SRT semantic kinds.
///
/// Priority: StoredToOwner > StoredToRuntime > RuntimeManaged > StaticLifetime
fn classify_runtime_state(
    srt_resolutions: &Option<std::collections::HashMap<String, Vec<SemanticKind>>>,
    alloc: &RawResourceFact,
) -> ResourcePathState {
    let Some(resolutions) = srt_resolutions else {
        return ResourcePathState::RuntimeManaged;
    };

    for name in [&alloc.function_name, &alloc.caller_name] {
        if let Some(kinds) = resolutions.get(name) {
            if kinds.contains(&SemanticKind::StoredToOwner) {
                return ResourcePathState::StoredToOwner;
            }
            if kinds.contains(&SemanticKind::StoredToRuntime) {
                return ResourcePathState::StoredToRuntime;
            }
            if kinds.contains(&SemanticKind::RuntimeManagedResource) {
                return ResourcePathState::RuntimeManaged;
            }
            if kinds.contains(&SemanticKind::GlobalProvenance) {
                return ResourcePathState::StaticLifetime;
            }
        }
    }

    // Default: if is_runtime_managed() returned true but no specific kind matched,
    // use RuntimeManaged as the generic safe category.
    ResourcePathState::RuntimeManaged
}

/// Returns `true` if the given resource state represents a safe exit
/// (not a leak) — the resource has been released, transferred, or
/// the path terminates without reaching a normal return.
pub(super) fn is_safe_exit(state: &ResourcePathState) -> bool {
    matches!(
        state,
        ResourcePathState::Released
            | ResourcePathState::EscapedToCaller
            | ResourcePathState::EscapedOutParam
            | ResourcePathState::StoredToOwner
            | ResourcePathState::StoredToRuntime
            | ResourcePathState::RuntimeManaged
            | ResourcePathState::StaticLifetime
            | ResourcePathState::AbortOrUnreachable
            | ResourcePathState::Null
    )
}

/// Returns a human-readable label for a `ResourcePathState` variant.
pub(super) fn path_state_label(state: &ResourcePathState) -> &'static str {
    match state {
        ResourcePathState::Owned => "Owned",
        ResourcePathState::Released => "Released",
        ResourcePathState::EscapedToCaller => "EscapedToCaller",
        ResourcePathState::EscapedOutParam => "EscapedOutParam",
        ResourcePathState::StoredToOwner => "StoredToOwner",
        ResourcePathState::StoredToRuntime => "StoredToRuntime",
        ResourcePathState::RuntimeManaged => "RuntimeManaged",
        ResourcePathState::StaticLifetime => "StaticLifetime",
        ResourcePathState::AbortOrUnreachable => "AbortOrUnreachable",
        ResourcePathState::Null => "Null",
        ResourcePathState::Unknown => "Unknown",
    }
}

/// Builds a concise summary of path exit states for evidence attachment.
///
/// Returns a string like "2 Owned, 1 Released, 1 EscapedToCaller" or
/// an empty string when no exit states are available.
pub(super) fn format_exit_state_summary(exit_states: &[PathExitState]) -> String {
    if exit_states.is_empty() {
        return String::new();
    }

    // Count each state type.
    let mut counts: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    for s in exit_states {
        *counts
            .entry(path_state_label(&s.resource_state))
            .or_insert(0) += 1;
    }

    // Sort by count descending for readability.
    let mut entries: Vec<(&str, usize)> = counts.into_iter().collect();
    entries.sort_by_key(|b| std::cmp::Reverse(b.1));

    entries
        .iter()
        .map(|(label, count)| format!("{count} {label}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Determines leak type from path-sensitive exit states.
///
/// Decision matrix (Phase 4):
/// - All exits safe   → Safe
/// - All exits Owned  → Definite
/// - Some Owned, some safe → Conditional
/// - Any Unknown      → fall through to counting logic (or NeedsModel)
pub(super) fn determine_leak_type(
    exit_states: &[PathExitState],
    alloc_count: u32,
    release_count: u32,
) -> LeakType {
    // If we have exit states, use path-sensitive analysis.
    if !exit_states.is_empty() {
        let all_owned = exit_states
            .iter()
            .all(|s| s.resource_state == ResourcePathState::Owned);
        let some_owned = exit_states
            .iter()
            .any(|s| s.resource_state == ResourcePathState::Owned);
        let all_safe = exit_states.iter().all(|s| is_safe_exit(&s.resource_state));
        let has_unknown = exit_states
            .iter()
            .any(|s| s.resource_state == ResourcePathState::Unknown);

        if all_safe {
            return LeakType::Safe;
        } else if all_owned {
            return LeakType::Definite;
        } else if some_owned {
            return LeakType::Conditional;
        } else if has_unknown {
            // Cannot determine conclusively — fall back to counting.
            // (Will continue to counting logic below.)
        } else {
            // Mix of safe states without any Owned — safe.
            return LeakType::Safe;
        }
    }

    // Fallback to simple counting when no exit states available.
    if alloc_count > 0 && release_count == 0 {
        LeakType::Definite
    } else if alloc_count > 0 && release_count > 0 && release_count < alloc_count {
        LeakType::Conditional
    } else if alloc_count > 0 && release_count >= alloc_count {
        LeakType::Safe
    } else {
        LeakType::NeedsModel
    }
}

/// Computes path evidence for a resource's lifecycle within a function body.
///
/// Scans the instruction sequence for release calls matching the given
/// callees and produces a `PathEvidence` summary indicating whether
/// the resource is released on all, some, or no paths.
pub fn compute_path_evidence(
    _instructions: &[omniscope_ir::IRInstruction],
    _release_callees: &[String],
    _alloc_reg: Option<String>,
    _branch_limit: usize,
) -> Option<PathEvidence> {
    // Disabled: the previous implementation was a naive instruction counter
    // that set `all_paths_release = release_count > 0`, which incorrectly
    // suppressed all double-release and UAF candidates. Real path-sensitive
    // analysis requires CFG traversal with branch-aware path enumeration.
    // Return None until that is implemented.
    None
}
