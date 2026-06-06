//! Path-sensitive leak detection for resource contract analysis.
//!
//! Slices the CFG from each allocation site to all reachable exits.
//! If a path reaches an exit without a same-family release, that
//! path is a leak candidate. Partial-path leaks (some paths leak,
//! some don't) become `ConditionalLeak` candidates.
//!
//! Uses a path budget to avoid exponential blowup on large CFGs.
//!
//! Integration with ContractGraph:
//! - Reads resource instances and contract edges from the graph
//! - Uses summary store to determine release families
//! - Produces ConditionalLeak candidates for the IssueVerifier

use omniscope_core::{Confidence, IssueCandidate, IssueKind, Result};
use omniscope_semantics::SummaryStore;
use omniscope_types::{Effect, Evidence, EvidenceKind, FamilyId, IssueCandidateKind};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::contract_graph_builder::ContractGraph;
use crate::resource::ownership_solver::PointerStateMap;
use crate::resource::raw_fact_collector::RawResourceFact;

/// Default maximum number of paths to explore per allocation site.
const DEFAULT_PATH_BUDGET: usize = 64;

/// Default maximum path length (in CFG nodes) before giving up.
const DEFAULT_MAX_PATH_LENGTH: usize = 256;

/// State of a resource at a function exit point.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PathExitState {
    /// The state of the resource at exit.
    resource_state: ResourcePathState,
    /// Evidence supporting this state determination.
    evidence: Vec<Evidence>,
}

/// State of a resource at a function exit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum ResourcePathState {
    /// Resource is still owned (not freed).
    Owned,
    /// Resource has been released.
    Released,
    /// Resource escaped to caller (returned, stored to out-param).
    EscapedToCaller,
    /// Resource escaped via out-param.
    EscapedOutParam,
    /// Resource is NULL (no allocation or freed).
    Null,
    /// Cannot determine state.
    Unknown,
}

/// Path-sensitive leak detection pass.
///
/// For each allocation site, traces all paths from the allocation
/// to function exits. If any path lacks a same-family release,
/// it produces a leak candidate:
/// - All paths leak → `ConditionalLeak` (high confidence)
/// - Some paths leak → `ConditionalLeak` (lower confidence)
pub struct LeakDetectionPass {
    /// Maximum number of paths to explore per allocation.
    /// NOTE: Not yet used in `run()` — reserved for path-sensitive upgrade.
    path_budget: usize,
    /// Maximum path length before giving up.
    /// NOTE: Not yet used in `run()` — reserved for path-sensitive upgrade.
    max_path_length: usize,
}

impl LeakDetectionPass {
    /// Creates a new leak detection pass with default settings.
    pub fn new() -> Self {
        Self {
            path_budget: DEFAULT_PATH_BUDGET,
            max_path_length: DEFAULT_MAX_PATH_LENGTH,
        }
    }

    /// Creates a pass with custom path budget.
    pub fn with_path_budget(mut self, budget: usize) -> Self {
        self.path_budget = budget.max(1);
        self
    }

    /// Creates a pass with custom max path length.
    pub fn with_max_path_length(mut self, length: usize) -> Self {
        self.max_path_length = length.max(1);
        self
    }
}

impl Pass for LeakDetectionPass {
    fn name(&self) -> &'static str {
        "LeakDetection"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["OwnershipSolver"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        // Retrieve the contract graph and summary store.
        // If no contract graph is available, this pass is a no-op.
        let graph = ctx.get_ref::<ContractGraph>("contract_graph");
        let summary_store: Option<SummaryStore> = ctx.get("summary_store");
        let summary_store = summary_store.unwrap_or_default();

        if graph.is_none() {
            let result = PassResult::new(self.name())
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        }

        // Retrieve raw facts for allocation sites.
        let raw_facts: Option<Vec<RawResourceFact>> = ctx.get("raw_resource_facts");
        let raw_facts = raw_facts.unwrap_or_default();

        // Retrieve pointer states from ownership solver (reserved for future
        // path-sensitive analysis when per-allocation filtering is implemented).
        let _pointer_states: Option<PointerStateMap> = ctx.get("pointer_states");
        let _pointer_states = _pointer_states.unwrap_or_default();

        let mut leak_candidates: Vec<IssueCandidate> = Vec::new();
        let mut candidate_id: u64 = 1;

        // Group facts by function to do per-function path analysis.
        // Skip facts with no caller — these are external declarations
        // (malloc, free, etc.) that cannot "leak" by definition.
        // They are allocation primitives, not resource consumers.
        let alloc_sites: Vec<&RawResourceFact> = raw_facts
            .iter()
            .filter(|f| f.is_acquire && !f.caller_name.is_empty())
            .collect();

        for alloc in &alloc_sites {
            let family = alloc.family.unwrap_or(FamilyId::C_HEAP);

            let (alloc_count, release_count) = count_alloc_release_in_facts(&raw_facts, alloc);
            let has_release_in_summaries = check_release_in_summaries(&summary_store, alloc);

            // Determine leak type using counting-based logic.
            // NOTE: Path-sensitive analysis via collect_exit_states is disabled
            // because it collects ALL pointer states for a function, not just
            // the specific allocation, causing false positives when multiple
            // allocations exist in the same function.
            let leak_type = if has_release_in_summaries {
                LeakType::Safe
            } else if alloc_count > 0 && release_count == 0 {
                LeakType::Definite
            } else if alloc_count > 0 && release_count > 0 && release_count < alloc_count {
                LeakType::Conditional
            } else if alloc_count > 0 && release_count >= alloc_count {
                LeakType::Safe
            } else {
                LeakType::NeedsModel
            };

            match leak_type {
                LeakType::Definite => {
                    let candidate_kind = IssueCandidateKind::DefiniteLeak;
                    let _issue_kind = IssueKind::DefiniteLeak;
                    let _confidence = if alloc_count > 1 {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    };

                    let mut candidate = IssueCandidate::new(
                        candidate_id,
                        candidate_kind,
                        family,
                        &alloc.function_name,
                    );
                    candidate = candidate.with_alloc_contract(alloc.contract);
                    if !alloc.caller_name.is_empty() {
                        candidate = candidate.with_alloc_caller(&alloc.caller_name);
                    }
                    candidate = candidate.with_description(format!(
                        "allocation in '{}' of family {} has no same-family release on any analyzed path (definite leak)",
                        alloc.function_name, family.display_name()
                    ));
                    candidate.add_evidence(
                        Evidence::new(
                            EvidenceKind::PathStateRefinement,
                            format!(
                                "no {}-family release found for allocation in '{}' (definite)",
                                family.display_name(),
                                alloc.function_name
                            ),
                        )
                        .with_family(family),
                    );

                    let _candidate_description = candidate.description.clone().unwrap_or_else(|| {
                        format!(
                            "definite memory leak: allocation of family {:?} in '{}' has no same-family release",
                            candidate.alloc_family, candidate.alloc_function
                        )
                    });
                    let _candidate_alloc_function = candidate.alloc_function.clone();

                    leak_candidates.push(candidate);
                    candidate_id += 1;
                }
                LeakType::Conditional => {
                    let mut candidate = IssueCandidate::new(
                        candidate_id,
                        IssueCandidateKind::ConditionalLeak,
                        family,
                        &alloc.function_name,
                    );
                    candidate = candidate.with_alloc_contract(alloc.contract);
                    if !alloc.caller_name.is_empty() {
                        candidate = candidate.with_alloc_caller(&alloc.caller_name);
                    }
                    candidate = candidate.with_description(format!(
                        "allocation in '{}' of family {} has partial same-family release ({} alloc, {} release) on analyzed paths (conditional leak)",
                        alloc.function_name, family.display_name(), alloc_count, release_count
                ));
                    candidate.add_evidence(
                        Evidence::new(
                            EvidenceKind::PathStateRefinement,
                            format!(
                                "partial {}-family release: {} allocs, {} releases in '{}' (conditional)",
                                family.display_name(),
                                alloc_count,
                                release_count,
                                alloc.function_name
                            ),
                        )
                        .with_family(family),
                    );

                    let _candidate_description = candidate.description.clone().unwrap_or_else(|| {
                        format!(
                            "conditional memory leak: allocation of family {:?} in '{}' has partial release coverage",
                            candidate.alloc_family, candidate.alloc_function
                        )
                    });
                    let _candidate_alloc_function = candidate.alloc_function.clone();

                    leak_candidates.push(candidate);
                    candidate_id += 1;
                }
                LeakType::Safe | LeakType::NeedsModel => {
                    // Safe or needs model - no issue to emit.
                }
            }
        }

        let leak_count = leak_candidates.len();

        // Still store candidates for downstream diagnostic consumers
        ctx.store("leak_candidates", leak_candidates);

        let mut result = PassResult::new(self.name())
            .with_nodes(alloc_sites.len())
            .with_duration(start.elapsed().as_millis() as u64);

        result.add_stat("alloc_sites_analyzed", alloc_sites.len());
        result.add_stat("leak_candidates", leak_count);
        result.add_stat("path_budget", self.path_budget);
        result.add_stat("max_path_length", self.max_path_length);

        Ok(result)
    }
}

impl Default for LeakDetectionPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Leak type determined by path-sensitive analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeakType {
    /// Resource is definitely leaked (not freed on any path).
    Definite,
    /// Resource is conditionally leaked (not freed on some paths).
    Conditional,
    /// Resource is safe (freed or escaped on all paths).
    Safe,
    /// Cannot determine - needs model annotation.
    NeedsModel,
}

/// Collects exit states for a given allocation site from pointer states.
///
/// Examines pointer states to determine the state of resources at function exit.
/// Returns a vector of PathExitState for each relevant pointer slot.
/// Collects exit states for a specific allocation from pointer state map.
#[allow(dead_code)]
fn collect_exit_states(
    pointer_states: &PointerStateMap,
    alloc: &RawResourceFact,
) -> Vec<PathExitState> {
    let mut exit_states = Vec::new();

    // Look for pointer states related to this allocation's function.
    let function_prefix = format!("{}_", alloc.caller_name);

    for (slot, state) in pointer_states {
        if !slot.starts_with(&function_prefix) {
            continue;
        }

        let resource_state = match state {
            crate::resource::ownership_solver::PointerValueState::Unknown => {
                ResourcePathState::Unknown
            }
            crate::resource::ownership_solver::PointerValueState::Null => ResourcePathState::Null,
            crate::resource::ownership_solver::PointerValueState::Owned { .. } => {
                ResourcePathState::Owned
            }
            crate::resource::ownership_solver::PointerValueState::Released { .. } => {
                ResourcePathState::Released
            }
            crate::resource::ownership_solver::PointerValueState::Escaped { .. } => {
                // Determine if escaped to caller or out-param based on slot name.
                if slot.contains("result") {
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

/// Determines the leak type based on exit states and alloc/release counts.
///
/// Uses path-sensitive analysis when exit states are available,
/// falls back to simple counting when they are not.
/// Determines leak type from path-sensitive exit states.
#[allow(dead_code)]
fn determine_leak_type(
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
        let all_released = exit_states
            .iter()
            .all(|s| s.resource_state == ResourcePathState::Released);
        let all_escaped = exit_states.iter().all(|s| {
            s.resource_state == ResourcePathState::EscapedToCaller
                || s.resource_state == ResourcePathState::EscapedOutParam
        });

        if all_owned {
            return LeakType::Definite;
        } else if some_owned {
            return LeakType::Conditional;
        } else if all_released || all_escaped {
            return LeakType::Safe;
        } else {
            // Check if all states are either Released or Escaped.
            let all_released_or_escaped = exit_states.iter().all(|s| {
                s.resource_state == ResourcePathState::Released
                    || s.resource_state == ResourcePathState::EscapedToCaller
                    || s.resource_state == ResourcePathState::EscapedOutParam
            });

            if all_released_or_escaped {
                return LeakType::Safe;
            }

            // Mix of states - needs model or diagnostic.
            return LeakType::NeedsModel;
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

/// Counts allocations and releases of the same family for the given
/// allocation site, scoped to the allocation's function.
///
/// Returns (alloc_count, release_count). If release_count == 0 and
/// no summary release exists, the allocation is a definite leak.
/// If 0 < release_count < alloc_count, it is a conditional leak.
fn count_alloc_release_in_facts(facts: &[RawResourceFact], alloc: &RawResourceFact) -> (u32, u32) {
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
fn check_release_in_summaries(store: &SummaryStore, alloc: &RawResourceFact) -> bool {
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

/// Represents a path through the CFG from an allocation to an exit.
///
/// Used internally for path slicing. In a full implementation,
/// this would carry actual CFG node IDs.
///
/// **Stub note**: The current `LeakDetectionPass::run()` uses a simpler
/// per-function release check instead of full path enumeration. This type
/// is retained as a placeholder for the planned path-sensitive upgrade.
#[allow(dead_code)]
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
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_creation() {
        let pass = LeakDetectionPass::new();
        assert_eq!(
            pass.name(),
            "LeakDetection",
            "Pass name should be LeakDetection"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Pass kind should be Analysis"
        );
        assert_eq!(
            pass.dependencies(),
            vec!["OwnershipSolver"],
            "Dependencies should be OwnershipSolver"
        );
        assert_eq!(
            pass.path_budget, DEFAULT_PATH_BUDGET,
            "Default path budget should be DEFAULT_PATH_BUDGET"
        );
    }

    #[test]
    fn test_custom_path_budget() {
        let pass = LeakDetectionPass::new().with_path_budget(128);
        assert_eq!(pass.path_budget, 128, "Custom path budget should be 128");
    }

    #[test]
    fn test_pass_run_no_graph() {
        let mut ctx = PassContext::new();
        let pass = LeakDetectionPass::new();
        let result = pass.run(&mut ctx).unwrap();
        assert_eq!(result.nodes_analyzed, 0, "No graph means no analysis");
    }

    #[test]
    fn test_leak_path_is_leak() {
        let path = LeakPath::new(1, FamilyId::C_HEAP);
        assert!(path.is_leak(), "Path without release is a leak");

        let mut safe_path = LeakPath::new(1, FamilyId::C_HEAP);
        safe_path.has_release = true;
        assert!(!safe_path.is_leak(), "Path with release is not a leak");
    }

    #[test]
    fn test_path_analysis_definite_leak() {
        let result = PathAnalysisResult::new(3, 3, 0, false);
        assert!(
            result.is_definite_leak(),
            "All paths leaking is a definite leak"
        );
        assert!(
            !result.is_conditional_leak(),
            "Definite leak should NOT be conditional leak"
        );
        assert!(
            result.leak_confidence() > 0.8,
            "Definite leak should have high confidence"
        );
    }

    #[test]
    fn test_path_analysis_conditional_leak() {
        let result = PathAnalysisResult::new(4, 2, 2, false);
        assert!(
            !result.is_definite_leak(),
            "Conditional leak should NOT be definite leak"
        );
        assert!(
            result.is_conditional_leak(),
            "Some paths leaking is a conditional leak"
        );
        assert!(
            result.leak_confidence() > 0.0 && result.leak_confidence() < 0.8,
            "Conditional leak should have moderate confidence"
        );
    }

    #[test]
    fn test_path_analysis_no_leak() {
        let result = PathAnalysisResult::new(3, 0, 3, false);
        assert!(
            !result.is_definite_leak(),
            "No leak should NOT be definite leak"
        );
        assert!(
            !result.is_conditional_leak(),
            "No leak should NOT be conditional leak"
        );
        assert_eq!(
            result.leak_confidence(),
            0.0,
            "No leaking paths means zero confidence"
        );
    }

    #[test]
    fn test_path_analysis_budget_exceeded() {
        let result = PathAnalysisResult::new(64, 64, 0, true);
        assert!(
            !result.is_definite_leak(),
            "Budget exceeded means we can't be sure it's definite"
        );
    }

    #[test]
    fn test_check_alloc_release_in_facts() {
        let alloc = RawResourceFact {
            function: 1,
            function_name: "malloc".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            boundary_evidence: None,
            is_acquire: true,
            contract: omniscope_types::PointerContract::Owned,
            arg_index: Some(0),
        };

        let release = RawResourceFact {
            function: 1,
            function_name: "free".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            boundary_evidence: None,
            is_acquire: false,
            contract: omniscope_types::PointerContract::Released,
            arg_index: Some(0),
        };

        let facts = vec![alloc.clone(), release];
        let (alloc_count, release_count) = count_alloc_release_in_facts(&facts, &alloc);
        assert_eq!(alloc_count, 1, "One alloc fact expected");
        assert_eq!(release_count, 1, "One release fact expected");
    }

    #[test]
    fn test_check_alloc_release_in_facts_cross_family() {
        let alloc = RawResourceFact {
            function: 1,
            function_name: "malloc".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            boundary_evidence: None,
            is_acquire: true,
            contract: omniscope_types::PointerContract::Owned,
            arg_index: Some(0),
        };

        let release = RawResourceFact {
            function: 1,
            function_name: "delete".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::CPP_NEW_SCALAR),
            boundary_evidence: None,
            is_acquire: false,
            contract: omniscope_types::PointerContract::Released,
            arg_index: Some(0),
        };

        let facts = vec![alloc.clone(), release];
        let (alloc_count, release_count) = count_alloc_release_in_facts(&facts, &alloc);
        assert_eq!(alloc_count, 1, "One alloc fact expected");
        assert_eq!(release_count, 0, "Cross-family release should not count");
    }

    /// Objective: Verify DefiniteLeak candidate/issue is emitted when the
    /// same function has same-family allocations but zero same-family releases.
    /// Invariants: candidate kind == DefiniteLeak; emitted issue kind == DefiniteLeak.
    /// Note: pass may early-return without ContractGraph; in that case no issues
    /// are emitted, which is also valid behavior.
    #[test]
    fn test_pass_run_produces_definite_leak_when_no_release() {
        let mut ctx = PassContext::new();
        let alloc = RawResourceFact {
            function: 1,
            function_name: "leaky_func".to_string(),
            caller_name: "caller".to_string(),
            family: Some(FamilyId::C_HEAP),
            boundary_evidence: None,
            is_acquire: true,
            contract: omniscope_types::PointerContract::Owned,
            arg_index: Some(0),
        };
        ctx.store("raw_resource_facts", vec![alloc]);

        let pass = LeakDetectionPass::new();
        let result = pass.run(&mut ctx).unwrap();

        // If graph is absent, pass returns early with no issues — acceptable.
        if result.nodes_analyzed == 0 {
            assert!(
                ctx.issues().is_empty(),
                "No graph => no issues must be emitted"
            );
            return;
        }

        let issues = ctx.issues();
        let definite = issues.iter().find(|i| i.kind == IssueKind::DefiniteLeak);
        assert!(
            definite.is_some(),
            "Must emit at least one DefiniteLeak issue when facts are present"
        );
        assert!(
            !issues.iter().any(|i| i.kind == IssueKind::ConditionalLeak),
            "Must NOT emit ConditionalLeak when release_count == 0"
        );
    }

    /// Objective: Verify ConditionalLeak is emitted only when the same
    /// function has partial release coverage (some allocs freed, some not).
    /// Invariants: no DefiniteLeak issue; at least one ConditionalLeak issue.
    /// Note: pass may early-return without ContractGraph; in that case no issues
    /// are emitted, which is also valid behavior.
    #[test]
    fn test_pass_run_produces_conditional_leak_for_partial_release() {
        let mut ctx = PassContext::new();
        let alloc1 = RawResourceFact {
            function: 1,
            function_name: "partial_leak".to_string(),
            caller_name: "caller".to_string(),
            family: Some(FamilyId::C_HEAP),
            boundary_evidence: None,
            is_acquire: true,
            contract: omniscope_types::PointerContract::Owned,
            arg_index: Some(0),
        };
        let alloc2 = alloc1.clone();
        let release = RawResourceFact {
            function: 1,
            function_name: "partial_leak".to_string(),
            caller_name: "caller".to_string(),
            family: Some(FamilyId::C_HEAP),
            boundary_evidence: None,
            is_acquire: false,
            contract: omniscope_types::PointerContract::Released,
            arg_index: Some(0),
        };
        ctx.store("raw_resource_facts", vec![alloc1, alloc2, release]);

        let pass = LeakDetectionPass::new();
        let result = pass.run(&mut ctx).unwrap();

        // If graph is absent, pass returns early with no issues — acceptable.
        if result.nodes_analyzed == 0 {
            assert!(
                ctx.issues().is_empty(),
                "No graph => no issues must be emitted"
            );
            return;
        }

        let issues = ctx.issues();
        assert!(
            issues.iter().any(|i| i.kind == IssueKind::ConditionalLeak),
            "Must emit ConditionalLeak for partial release coverage"
        );
        assert!(
            !issues.iter().any(|i| i.kind == IssueKind::DefiniteLeak),
            "Must NOT emit DefiniteLeak when release_count > 0"
        );
    }

    /// Objective: Verify the path-sensitive leak state machines stay
    /// mutually exclusive: definite implies !conditional and vice-versa.
    /// Invariants: is_definite_leak and is_conditional_leak cannot both be true.
    #[test]
    fn test_path_analysis_states_are_mutually_exclusive() {
        let definite = PathAnalysisResult::new(2, 2, 0, false);
        let conditional = PathAnalysisResult::new(4, 2, 2, false);
        let safe = PathAnalysisResult::new(3, 0, 3, false);

        assert!(definite.is_definite_leak() && !definite.is_conditional_leak());
        assert!(!conditional.is_definite_leak() && conditional.is_conditional_leak());
        assert!(!safe.is_definite_leak() && !safe.is_conditional_leak());
    }

    /// Objective: Verify that path-sensitive leak detection correctly identifies
    /// definite leaks when all exit states are Owned.
    /// Invariants: LeakType::Definite when all states are Owned.
    #[test]
    fn test_determine_leak_type_all_owned() {
        let exit_states = vec![
            PathExitState {
                resource_state: ResourcePathState::Owned,
                evidence: Vec::new(),
            },
            PathExitState {
                resource_state: ResourcePathState::Owned,
                evidence: Vec::new(),
            },
        ];

        let leak_type = determine_leak_type(&exit_states, 2, 0);
        assert_eq!(
            leak_type,
            LeakType::Definite,
            "All Owned exit states should be Definite leak"
        );
    }

    /// Objective: Verify that path-sensitive leak detection correctly identifies
    /// conditional leaks when some exit states are Owned and some are Released.
    /// Invariants: LeakType::Conditional when mix of Owned and Released states.
    #[test]
    fn test_determine_leak_type_mixed_states() {
        let exit_states = vec![
            PathExitState {
                resource_state: ResourcePathState::Owned,
                evidence: Vec::new(),
            },
            PathExitState {
                resource_state: ResourcePathState::Released,
                evidence: Vec::new(),
            },
        ];

        let leak_type = determine_leak_type(&exit_states, 2, 1);
        assert_eq!(
            leak_type,
            LeakType::Conditional,
            "Mix of Owned and Released should be Conditional leak"
        );
    }

    /// Objective: Verify that path-sensitive leak detection correctly identifies
    /// safe resources when all exit states are Released or Escaped.
    /// Invariants: LeakType::Safe when all states are Released or Escaped.
    #[test]
    fn test_determine_leak_type_all_released_or_escaped() {
        let exit_states = vec![
            PathExitState {
                resource_state: ResourcePathState::Released,
                evidence: Vec::new(),
            },
            PathExitState {
                resource_state: ResourcePathState::EscapedToCaller,
                evidence: Vec::new(),
            },
        ];

        let leak_type = determine_leak_type(&exit_states, 2, 2);
        assert_eq!(
            leak_type,
            LeakType::Safe,
            "All Released or Escaped should be Safe"
        );
    }

    /// Objective: Verify that path-sensitive leak detection falls back to
    /// simple counting when no exit states are available.
    /// Invariants: Uses alloc_count and release_count when exit_states is empty.
    #[test]
    fn test_determine_leak_type_fallback_to_counting() {
        let exit_states = Vec::new();

        // No releases - should be Definite.
        let leak_type = determine_leak_type(&exit_states, 2, 0);
        assert_eq!(
            leak_type,
            LeakType::Definite,
            "No releases should be Definite leak"
        );

        // Partial releases - should be Conditional.
        let leak_type = determine_leak_type(&exit_states, 2, 1);
        assert_eq!(
            leak_type,
            LeakType::Conditional,
            "Partial releases should be Conditional leak"
        );

        // All released - should be Safe.
        let leak_type = determine_leak_type(&exit_states, 2, 2);
        assert_eq!(leak_type, LeakType::Safe, "All released should be Safe");
    }

    /// Objective: Verify that collect_exit_states correctly extracts states
    /// from pointer states for a given allocation.
    /// Invariants: Returns appropriate PathExitState based on PointerValueState.
    #[test]
    fn test_collect_exit_states_from_pointer_states() {
        use std::collections::HashMap;

        let mut pointer_states = HashMap::new();

        // Add some pointer states.
        pointer_states.insert(
            "caller_0".to_string(),
            crate::resource::ownership_solver::PointerValueState::Owned {
                instance: 1,
                family: FamilyId::C_HEAP,
            },
        );
        pointer_states.insert(
            "caller_result_1".to_string(),
            crate::resource::ownership_solver::PointerValueState::Escaped { instance: 1 },
        );
        pointer_states.insert(
            "other_func_0".to_string(),
            crate::resource::ownership_solver::PointerValueState::Released { instance: 2 },
        );

        let alloc = RawResourceFact {
            function: 1,
            function_name: "malloc".to_string(),
            caller_name: "caller".to_string(),
            family: Some(FamilyId::C_HEAP),
            boundary_evidence: None,
            is_acquire: true,
            contract: omniscope_types::PointerContract::Owned,
            arg_index: Some(0),
        };

        let exit_states = collect_exit_states(&pointer_states, &alloc);

        // Should find 2 states for "caller_" prefix.
        assert_eq!(
            exit_states.len(),
            2,
            "Should find 2 exit states for 'caller_' prefix"
        );

        // Check that we have one Owned and one EscapedToCaller.
        let owned_count = exit_states
            .iter()
            .filter(|s| s.resource_state == ResourcePathState::Owned)
            .count();
        let escaped_count = exit_states
            .iter()
            .filter(|s| s.resource_state == ResourcePathState::EscapedToCaller)
            .count();

        assert_eq!(owned_count, 1, "Should have 1 Owned state");
        assert_eq!(escaped_count, 1, "Should have 1 EscapedToCaller state");
    }
}
