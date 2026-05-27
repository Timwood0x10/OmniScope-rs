//! Path-sensitive leak detection for resource contract analysis.
//!
//! Slices the CFG from each allocation site to all reachable exits.
//! If a path reaches an exit without a same-family release, that
//! path is a leak candidate. Partial-path leaks (some paths leak,
//! some don't) become `ConditionalLeak` candidates.
//!
//! Uses a path budget to avoid exponential blowup on large CFGs.

use omniscope_core::{IssueCandidate, Result};
use omniscope_types::{FamilyId, IssueCandidateKind};

use crate::pass::{Pass, PassContext, PassKind, PassResult};

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

        // Retrieve the contract graph and ownership states.
        // If no contract graph is available, this pass is a no-op.
        let has_graph: Option<bool> = ctx.get("contract_graph_built");
        if has_graph.is_none() {
            let result = PassResult::new(self.name())
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        }

        // In a full implementation, we would:
        // 1. Iterate over all resource instances in the contract graph
        // 2. For each Acquire node, trace all CFG paths to exits
        // 3. Check each path for a same-family Release
        // 4. Build ConditionalLeak candidates for paths missing release
        //
        // For now, we build the infrastructure and test the path
        // slicing logic with a simplified model.

        let mut leak_candidates: Vec<IssueCandidate> = Vec::new();
        let mut candidate_id: u64 = 1;

        // Check raw facts for allocations that might leak.
        let raw_facts: Option<Vec<crate::resource::raw_fact_collector::RawResourceFact>> =
            ctx.get("raw_resource_facts");
        let raw_facts = raw_facts.unwrap_or_default();

        // Group facts by function to do per-function path analysis.
        let mut alloc_sites: Vec<&crate::resource::raw_fact_collector::RawResourceFact> =
            Vec::new();
        for fact in &raw_facts {
            if fact.is_acquire {
                alloc_sites.push(fact);
            }
        }

        for alloc in &alloc_sites {
            // For each allocation, check if there's a matching release
            // in the same function.
            let has_release = raw_facts
                .iter()
                .any(|f| !f.is_acquire && f.function == alloc.function && f.family == alloc.family);

            if !has_release {
                // No same-family release found — potential leak.
                let family = alloc.family.unwrap_or(FamilyId::C_HEAP);
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

                leak_candidates.push(candidate);
                candidate_id += 1;
            }
        }

        let leak_count = leak_candidates.len();
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
}
