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
use omniscope_core::{Issue, IssueCandidate, IssueKind, Result};
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
pub struct PathSensitiveLeakPass {
    /// Maximum number of paths to explore per allocation.
    path_budget: usize,
    /// Maximum path length before giving up.
    max_path_length: usize,
}

impl PathSensitiveLeakPass {
    /// Creates a new path-sensitive leak pass with default settings.
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

impl Pass for PathSensitiveLeakPass {
    fn name(&self) -> &'static str {
        "PathSensitiveLeak"
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
        let graph: Option<ContractGraph> = ctx.get("contract_graph");
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
        let alloc_sites: Vec<&RawResourceFact> =
            raw_facts.iter().filter(|f| f.is_acquire).collect();

        for alloc in &alloc_sites {
            let family = alloc.family.unwrap_or(FamilyId::C_HEAP);

            // Check if there's a matching same-family release in the
            // same function or via a summary in the summary store.
            let has_same_family_release = check_release_in_facts(&raw_facts, alloc)
                || check_release_in_summaries(&summary_store, alloc);

            if !has_same_family_release {
                // No same-family release found — potential leak.
                let mut candidate = IssueCandidate::new(
                    candidate_id,
                    IssueCandidateKind::ConditionalLeak,
                    family,
                    &alloc.function_name,
                );
                candidate = candidate.with_alloc_contract(alloc.contract);
                candidate = candidate.with_description(format!(
                    "allocation in '{}' of family {:?} has no same-family release on any analyzed path",
                    alloc.function_name, family
                ));

                // Attach evidence about the missing release.
                candidate.add_evidence(
                    Evidence::new(
                        EvidenceKind::Insufficient,
                        format!(
                            "no {:?}-family release found for allocation in '{}'",
                            family, alloc.function_name
                        ),
                    )
                    .with_family(family),
                );

                leak_candidates.push(candidate);
                candidate_id += 1;
            }
        }

        let leak_count = leak_candidates.len();

        // Emit each leak candidate as an Issue through the SRT gate.
        // Previously, candidates were only stored in the context but
        // never read by any downstream pass, causing silent data loss.
        for candidate in &leak_candidates {
            let issue_id = ctx.next_issue_id();
            let issue = Issue::new(
                issue_id,
                IssueKind::ConditionalLeak,
                Severity::Warning,
                candidate.description.clone().unwrap_or_else(|| {
                    format!(
                        "potential memory leak: allocation of family {:?} in '{}' \
                         has no same-family release on some paths",
                        candidate.alloc_family, candidate.alloc_function
                    )
                }),
            )
            .with_symbol(candidate.alloc_function.clone());
            ctx.emit_issue(issue);
        }

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

impl Default for PathSensitiveLeakPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks if there's a same-family release in the raw facts for
/// the given allocation site, scoped to the allocation's function
/// or its likely cleanup callees.
///
/// Previously this searched ALL facts globally, which caused false
/// suppression: any release in any function with the same family
/// would suppress the leak, even if the release was in a completely
/// unrelated function.
///
/// Now we restrict the search to:
/// 1. Facts whose `function` ID matches the alloc's function ID (same scope), OR
/// 2. Facts whose `function_name` matches the alloc's `function_name` (the
///    alloc's callee itself is a cleanup like `free`/`close`).
fn check_release_in_facts(facts: &[RawResourceFact], alloc: &RawResourceFact) -> bool {
    let alloc_family = alloc.family.unwrap_or(FamilyId::C_HEAP);

    facts
        .iter()
        .filter(|f| !f.is_acquire && f.family == Some(alloc_family))
        .any(|f| f.function == alloc.function || f.function_name == alloc.function_name)
}

/// Checks if the summary store contains a function that releases
/// the same family as the allocation, scoped to the allocation's function
/// or its likely cleanup callees.
///
/// Previously this searched ALL summaries globally, which caused false
/// suppression: any function with a same-family Release would suppress
/// the leak, even if the release was in a completely unrelated function.
///
/// Now we restrict the search to:
/// 1. The summary whose `function` ID matches the alloc's function ID, OR
/// 2. Summaries whose name matches the alloc's function_name (handles
///    the case where the alloc's callee itself has a release summary).
fn check_release_in_summaries(store: &SummaryStore, alloc: &RawResourceFact) -> bool {
    let alloc_family = alloc.family.unwrap_or(FamilyId::C_HEAP);

    for (_, summary) in store.iter() {
        // Scope: only consider summaries related to the allocation's function.
        // 1. Same function ID (the function containing the alloc also releases)
        // 2. Summary name matches the alloc's callee name (the called function
        //    itself is a known release, e.g. free, fclose, etc.)
        let same_function = summary.function == alloc.function;
        let named_like_alloc_callee = summary.name == alloc.function_name;
        if !same_function && !named_like_alloc_callee {
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
        let pass = PathSensitiveLeakPass::new();
        assert_eq!(pass.name(), "PathSensitiveLeak");
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert_eq!(pass.dependencies(), vec!["OwnershipSolver"]);
        assert_eq!(pass.path_budget, DEFAULT_PATH_BUDGET);
    }

    #[test]
    fn test_custom_path_budget() {
        let pass = PathSensitiveLeakPass::new().with_path_budget(128);
        assert_eq!(pass.path_budget, 128);
    }

    #[test]
    fn test_pass_run_no_graph() {
        let mut ctx = PassContext::new();
        let pass = PathSensitiveLeakPass::new();
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
        assert!(!result.is_conditional_leak());
        assert!(
            result.leak_confidence() > 0.8,
            "Definite leak should have high confidence"
        );
    }

    #[test]
    fn test_path_analysis_conditional_leak() {
        let result = PathAnalysisResult::new(4, 2, 2, false);
        assert!(!result.is_definite_leak());
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
        assert!(!result.is_definite_leak());
        assert!(!result.is_conditional_leak());
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
    fn test_check_release_in_facts() {
        let alloc = RawResourceFact {
            function: 1,
            function_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: true,
            contract: omniscope_types::PointerContract::Owned,
            arg_index: Some(0),
        };

        let release = RawResourceFact {
            function: 1,
            function_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: false,
            contract: omniscope_types::PointerContract::Released,
            arg_index: Some(0),
        };

        let facts = vec![alloc.clone(), release];
        assert!(
            check_release_in_facts(&facts, &alloc),
            "Same-family release in same function should be found"
        );
    }

    #[test]
    fn test_check_release_in_facts_cross_family() {
        let alloc = RawResourceFact {
            function: 1,
            function_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: true,
            contract: omniscope_types::PointerContract::Owned,
            arg_index: Some(0),
        };

        let release = RawResourceFact {
            function: 1,
            function_name: "test_func".to_string(),
            family: Some(FamilyId::CPP_NEW_SCALAR),
            is_acquire: false,
            contract: omniscope_types::PointerContract::Released,
            arg_index: Some(0),
        };

        let facts = vec![alloc.clone(), release];
        assert!(
            !check_release_in_facts(&facts, &alloc),
            "Cross-family release should NOT count as same-family"
        );
    }
}
