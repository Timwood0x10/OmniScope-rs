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
//! - PathConfidence — confidence level for path-sensitive analysis
//! - PathCombinationResult — aggregated result of combining path states
//! - combine_path_states — combines multiple path exit states into one result
//! - path_confidence_score — calculates confidence score from state distribution
//! - detect_release_path_pattern — detects the release pattern across paths

use omniscope_semantics::{SemanticKind, SummaryStore};
use omniscope_types::Evidence;

use crate::resource::ownership_solver::PointerStateMap;
use crate::resource::raw_fact_collector::RawResourceFact;

use super::helpers::{caller_returns_owned_resource, is_runtime_managed, FunctionTermination};
use super::LeakType;

/// State of a resource at a function exit point.
#[derive(Debug, Clone)]
pub(super) struct PathExitState {
    /// The state of the resource at exit.
    pub resource_state: ResourcePathState,
    /// Evidence supporting this state determination.
    pub _evidence: Vec<Evidence>,
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
    // Track total release events (including duplicates from mutually exclusive paths).
    let mut total_release_count: usize = 0;

    // Look for pointer states related to this allocation's function.
    let function_prefix = format!("{}_", alloc.caller_name);

    for (slot, state) in pointer_states {
        if !slot.starts_with(&function_prefix) {
            continue;
        }

        // Skip duplicate Released states from mutually exclusive paths.
        if let crate::resource::ownership_solver::PointerValueState::Released { instance } = state {
            total_release_count += 1;
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
            _evidence: Vec::new(),
        });
    }

    // Return empty vec when no pointer states match — the caller will
    // fall back to counting-based leak detection.

    // Analyze release path pattern when multiple releases were found.
    // This information can be used by the verifier to distinguish mutually
    // exclusive releases (if/else) from sequential releases (double-free).
    if released_instances.len() > 1 {
        let pattern = detect_release_path_pattern(total_release_count, released_instances.len());
        tracing::trace!(
            "release path pattern for '{}': {:?} ({} instances)",
            alloc.caller_name,
            pattern,
            released_instances.len()
        );
    }

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
/// an empty string when no exit states are available. When confidence
/// information is available, appends a confidence descriptor.
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

    let mut summary = entries
        .iter()
        .map(|(label, count)| format!("{count} {label}"))
        .collect::<Vec<_>>()
        .join(", ");

    // Append path confidence information when multiple paths exist.
    if exit_states.len() > 1 {
        let combined = combine_path_states(exit_states);
        summary.push_str(&format!(
            " [confidence={}, leak_ratio={:.2}]",
            combined.confidence.to_score(),
            combined.leak_ratio()
        ));
    }

    summary
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

/// Confidence level for path-sensitive analysis results.
///
/// Reflects how strongly the path analysis supports its conclusion:
/// - `High`: overwhelming majority of paths agree (e.g., all paths leak or all are safe).
/// - `Medium`: mixed results with a clear leaning.
/// - `Low`: approximately balanced or insufficient data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum PathConfidence {
    /// Weak confidence — paths are approximately balanced.
    Low,
    /// Moderate confidence — some paths disagree.
    Medium,
    /// Strong confidence in the analysis result.
    High,
}

impl PathConfidence {
    /// Returns `true` if this confidence level is at least `Medium`.
    #[cfg_attr(not(test), expect(dead_code, reason = "only used in tests"))]
    pub(super) fn is_at_least_medium(&self) -> bool {
        matches!(self, PathConfidence::High | PathConfidence::Medium)
    }

    /// Converts this confidence level to a numeric score in `[0.0, 1.0]`.
    pub(super) fn to_score(self) -> f32 {
        match self {
            PathConfidence::High => 0.9,
            PathConfidence::Medium => 0.6,
            PathConfidence::Low => 0.3,
        }
    }
}

/// Aggregated result of combining multiple path exit states for an allocation.
///
/// Provides a unified view of how many paths are safe vs. leaking, along
/// with a confidence score for the overall assessment.
#[derive(Debug, Clone)]
pub(super) struct PathCombinationResult {
    /// Total number of path exit states analyzed.
    pub total_paths: usize,
    /// Number of paths where the resource remains owned (potential leak).
    pub owned_paths: usize,
    /// Number of paths where the resource is safely released or transferred.
    pub safe_paths: usize,
    /// Number of paths with unknown or indeterminate state.
    pub unknown_paths: usize,
    /// Confidence level of the combined result.
    pub confidence: PathConfidence,
}

impl PathCombinationResult {
    /// Returns `true` when all paths are safe (no leak).
    #[cfg_attr(not(test), expect(dead_code, reason = "only used in tests"))]
    pub(super) fn is_all_safe(&self) -> bool {
        self.total_paths > 0 && self.owned_paths == 0 && self.unknown_paths == 0
    }

    /// Returns `true` when all paths leak (definite leak).
    #[cfg_attr(not(test), expect(dead_code, reason = "only used in tests"))]
    pub(super) fn is_all_leak(&self) -> bool {
        self.total_paths > 0 && self.safe_paths == 0 && self.unknown_paths == 0
    }

    /// Returns the ratio of owned (leaking) paths to total paths.
    pub(super) fn leak_ratio(&self) -> f32 {
        if self.total_paths == 0 {
            return 0.0;
        }
        self.owned_paths as f32 / self.total_paths as f32
    }
}

/// Combines multiple path exit states into a single aggregated result.
///
/// Counts owned vs. safe paths and assigns a confidence level based on
/// the distribution. This is useful for producing a summary verdict when
/// an allocation has multiple exit states from different execution paths.
///
/// # Examples
///
/// ```
/// # use omniscope_pass::resource::path_sensitive_leak::analysis::*;
/// let states = vec![
///     PathExitState { resource_state: ResourcePathState::Owned, _evidence: vec![] },
///     PathExitState { resource_state: ResourcePathState::Released, _evidence: vec![] },
/// ];
/// let result = combine_path_states(&states);
/// assert!(result.total_paths == 2);
/// assert!(result.owned_paths == 1);
/// assert!(result.safe_paths == 1);
/// ```
pub(super) fn combine_path_states(exit_states: &[PathExitState]) -> PathCombinationResult {
    let total_paths = exit_states.len();
    let mut owned_paths = 0usize;
    let mut safe_paths = 0usize;
    let mut unknown_paths = 0usize;

    for state in exit_states {
        if is_safe_exit(&state.resource_state) {
            safe_paths += 1;
        } else if state.resource_state == ResourcePathState::Owned {
            owned_paths += 1;
        } else {
            unknown_paths += 1;
        }
    }

    let confidence = path_confidence_score(total_paths, owned_paths, safe_paths);

    PathCombinationResult {
        total_paths,
        owned_paths,
        safe_paths,
        unknown_paths,
        confidence,
    }
}

/// Calculates the confidence score for a path-sensitive analysis result
/// based on the distribution of owned vs. safe paths.
///
/// Confidence is determined by the ratio of the majority outcome:
/// - >= 90% agreement → High
/// - >= 65% agreement → Medium
/// - Otherwise        → Low
fn path_confidence_score(total: usize, owned: usize, safe: usize) -> PathConfidence {
    if total == 0 {
        return PathConfidence::Low;
    }

    let majority_ratio = owned.max(safe) as f32 / total as f32;

    if majority_ratio >= 0.90 {
        PathConfidence::High
    } else if majority_ratio >= 0.65 {
        PathConfidence::Medium
    } else {
        PathConfidence::Low
    }
}

/// Describes the release pattern detected across multiple execution paths.
///
/// Used by the double-free verifier to distinguish between:
/// - Mutually exclusive releases (if/else branches each free once).
/// - Sequential releases (same path frees twice).
/// - Mixed patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReleasePathPattern {
    /// All release paths are mutually exclusive (branch-alternatives).
    /// Example: `if (cond) free(p); else free(p);`
    MutuallyExclusive,
    /// Releases appear on sequential (non-exclusive) paths.
    /// Example: `free(p); free(p);` in the same basic block.
    SequentialRelease,
    /// Mixed: some releases are mutually exclusive, some are sequential.
    #[expect(dead_code, reason = "available for future path analysis refinement")]
    MixedRelease,
    /// Cannot determine the release pattern.
    Indeterminate,
}

/// Detects the release path pattern from a set of exit states.
///
/// Examines the ratio of Released states to total states to determine
/// whether releases are likely mutually exclusive or sequential.
/// When more than half the exit states are Released for the same
/// instance, they are likely mutually exclusive branches (if/else).
/// When instances differ, releases are sequential.
///
/// # Examples
///
/// ```
/// # use omniscope_pass::resource::path_sensitive_leak::analysis::*;
/// // Two Released states for the same instance → mutually exclusive.
/// let pattern = detect_release_path_pattern(2, 1);
/// assert_eq!(pattern, ReleasePathPattern::MutuallyExclusive);
/// ```
pub(super) fn detect_release_path_pattern(
    total_released_instances: usize,
    unique_instances: usize,
) -> ReleasePathPattern {
    if total_released_instances == 0 {
        return ReleasePathPattern::Indeterminate;
    }

    if unique_instances == 0 {
        return ReleasePathPattern::Indeterminate;
    }

    // When there are more Released states than unique instances, the
    // same instance is released on multiple paths → mutually exclusive.
    if total_released_instances > unique_instances {
        ReleasePathPattern::MutuallyExclusive
    } else if total_released_instances == unique_instances {
        // Each release is for a distinct instance → sequential.
        ReleasePathPattern::SequentialRelease
    } else {
        // Should not normally happen, but be safe.
        ReleasePathPattern::Indeterminate
    }
}
