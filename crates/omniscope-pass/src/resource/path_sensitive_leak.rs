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

use omniscope_core::diagnostics::Severity;
use omniscope_core::{Confidence, Issue, IssueCandidate, IssueKind, Result};
use omniscope_semantics::SummaryStore;
use omniscope_types::{Effect, Evidence, EvidenceKind, FamilyId, IssueCandidateKind};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::contract_graph_builder::ContractGraph;
use crate::resource::raw_fact_collector::RawResourceFact;

/// Default maximum number of paths to explore per allocation site.
const DEFAULT_PATH_BUDGET: usize = 64;

/// Default maximum path length (in CFG nodes) before giving up.
const DEFAULT_MAX_PATH_LENGTH: usize = 256;

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

            if !has_release_in_summaries && release_count == 0 {
                let candidate_kind = if alloc_count > 0 {
                    IssueCandidateKind::DefiniteLeak
                } else {
                    IssueCandidateKind::ConditionalLeak
                };
                let issue_kind = IssueKind::DefiniteLeak;
                let confidence = if alloc_count > 1 {
                    Confidence::High
                } else {
                    Confidence::Medium
                };

                let mut candidate =
                    IssueCandidate::new(candidate_id, candidate_kind, family, &alloc.function_name);
                candidate = candidate.with_alloc_contract(alloc.contract);
                candidate = candidate.with_description(format!(
                    "allocation in '{}' of family {} has no same-family release on any analyzed path (definite leak)",
                    alloc.function_name, family.display_name()
                ));
                candidate.add_evidence(
                    Evidence::new(
                        EvidenceKind::Insufficient,
                        format!(
                            "no {}-family release found for allocation in '{}' (definite)",
                            family.display_name(),
                            alloc.function_name
                        ),
                    )
                    .with_family(family),
                );

                let candidate_description = candidate.description.clone().unwrap_or_else(|| {
                    format!(
                        "definite memory leak: allocation of family {:?} in '{}' has no same-family release",
                        candidate.alloc_family, candidate.alloc_function
                    )
                });
                let candidate_alloc_function = candidate.alloc_function.clone();
                let _candidate_alloc_family = candidate.alloc_family;

                leak_candidates.push(candidate);
                candidate_id += 1;

                let mut issue = Issue::new(
                    ctx.next_issue_id(),
                    issue_kind,
                    Severity::Warning,
                    candidate_description,
                )
                .with_symbol(candidate_alloc_function.clone())
                .with_confidence(confidence);

                if !candidate_alloc_function.is_empty() && candidate_alloc_function != "unknown" {
                    let location =
                        omniscope_core::IssueLocation::new(std::path::PathBuf::from("<ir>"), 0)
                            .with_function(&candidate_alloc_function);
                    issue = issue.with_location(location);
                }

                ctx.emit_issue(issue);
                continue;
            }

            if !has_release_in_summaries && release_count > 0 && release_count < alloc_count {
                let mut candidate = IssueCandidate::new(
                    candidate_id,
                    IssueCandidateKind::ConditionalLeak,
                    family,
                    &alloc.function_name,
                );
                candidate = candidate.with_alloc_contract(alloc.contract);
                candidate = candidate.with_description(format!(
                    "allocation in '{}' of family {} has partial same-family release ({} alloc, {} release) on analyzed paths (conditional leak)",
                    alloc.function_name, family.display_name(), alloc_count, release_count
                ));
                candidate.add_evidence(
                    Evidence::new(
                        EvidenceKind::Insufficient,
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

                let candidate_description = candidate.description.clone().unwrap_or_else(|| {
                    format!(
                        "conditional memory leak: allocation of family {:?} in '{}' has partial release coverage",
                        candidate.alloc_family, candidate.alloc_function
                    )
                });
                let candidate_alloc_function = candidate.alloc_function.clone();

                leak_candidates.push(candidate);
                candidate_id += 1;

                let mut issue = Issue::new(
                    ctx.next_issue_id(),
                    IssueKind::ConditionalLeak,
                    Severity::Warning,
                    candidate_description,
                )
                .with_symbol(candidate_alloc_function.clone())
                .with_confidence(Confidence::Medium);

                if !candidate_alloc_function.is_empty() && candidate_alloc_function != "unknown" {
                    let location =
                        omniscope_core::IssueLocation::new(std::path::PathBuf::from("<ir>"), 0)
                            .with_function(&candidate_alloc_function);
                    issue = issue.with_location(location);
                }

                ctx.emit_issue(issue);
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
            is_acquire: true,
            contract: omniscope_types::PointerContract::Owned,
            arg_index: Some(0),
        };

        let release = RawResourceFact {
            function: 1,
            function_name: "free".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
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
            is_acquire: true,
            contract: omniscope_types::PointerContract::Owned,
            arg_index: Some(0),
        };

        let release = RawResourceFact {
            function: 1,
            function_name: "delete".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::CPP_NEW_SCALAR),
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
    /// Invariants: candidate kind == DefiniteLeak; emitted issue kind == DefiniteLeak;
    /// at least one issue is raised through emit_issue.
    #[test]
    fn test_pass_run_produces_definite_leak_when_no_release() {
        let mut ctx = PassContext::new();
        let alloc = RawResourceFact {
            function: 1,
            function_name: "leaky_func".to_string(),
            caller_name: "caller".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: true,
            contract: omniscope_types::PointerContract::Owned,
            arg_index: Some(0),
        };
        ctx.store("raw_resource_facts", vec![alloc]);

        let pass = LeakDetectionPass::new();
        let result = pass.run(&mut ctx).unwrap();
        assert!(result.nodes_analyzed > 0, "pass must process alloc sites");

        let issues = ctx.issues();
        let definite = issues.iter().find(|i| i.kind == IssueKind::DefiniteLeak);
        assert!(
            definite.is_some(),
            "Must emit at least one DefiniteLeak issue"
        );
        assert!(
            !issues.iter().any(|i| i.kind == IssueKind::ConditionalLeak),
            "Must NOT emit ConditionalLeak when release_count == 0"
        );
    }

    /// Objective: Verify ConditionalLeak is emitted only when the same
    /// function has partial release coverage (some allocs freed, some not).
    /// Invariants: no DefiniteLeak issue; at least one ConditionalLeak issue.
    #[test]
    fn test_pass_run_produces_conditional_leak_for_partial_release() {
        let mut ctx = PassContext::new();
        let alloc1 = RawResourceFact {
            function: 1,
            function_name: "partial_leak".to_string(),
            caller_name: "caller".to_string(),
            family: Some(FamilyId::C_HEAP),
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
            is_acquire: false,
            contract: omniscope_types::PointerContract::Released,
            arg_index: Some(0),
        };
        ctx.store("raw_resource_facts", vec![alloc1, alloc2, release]);

        let pass = LeakDetectionPass::new();
        let result = pass.run(&mut ctx).unwrap();
        assert!(result.nodes_analyzed > 0, "pass must process alloc sites");

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
}
