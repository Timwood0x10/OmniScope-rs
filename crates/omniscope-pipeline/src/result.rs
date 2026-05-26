//! Pipeline result aggregation
//!
//! This module provides result aggregation for the analysis pipeline.

use omniscope_core::Issue;
use omniscope_pass::PassResult;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Pipeline result aggregating all pass results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Individual pass results
    pub pass_results: Vec<PassResult>,
    /// Total number of issues found
    pub total_issues: usize,
    /// Total nodes analyzed
    pub total_nodes: usize,
    /// Total execution time
    pub duration: Duration,
    /// Pass statistics
    pub stats: PipelineStats,
    /// All concrete issues collected across passes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<Issue>,
}

impl PipelineResult {
    /// Creates a pipeline result from pass results
    pub fn from_pass_results(pass_results: Vec<PassResult>, duration: Duration) -> Self {
        let total_issues = pass_results.iter().map(|r| r.issues_found).sum();
        let total_nodes = pass_results.iter().map(|r| r.nodes_analyzed).sum();

        let stats = PipelineStats::from_pass_results(&pass_results);

        // Flatten all concrete issues from individual pass results
        let issues: Vec<Issue> = pass_results.iter().flat_map(|r| r.issues.clone()).collect();

        Self {
            pass_results,
            total_issues,
            total_nodes,
            duration,
            stats,
            issues,
        }
    }

    /// Creates a pipeline result with explicit issues (from context collection).
    pub fn with_issues(
        pass_results: Vec<PassResult>,
        duration: Duration,
        issues: Vec<Issue>,
    ) -> Self {
        let total_issues = issues.len();
        let total_nodes = pass_results.iter().map(|r| r.nodes_analyzed).sum();

        let stats = PipelineStats::from_pass_results(&pass_results);

        Self {
            pass_results,
            total_issues,
            total_nodes,
            duration,
            stats,
            issues,
        }
    }

    /// Returns the number of passes executed
    pub fn pass_count(&self) -> usize {
        self.pass_results.len()
    }

    /// Returns the number of issues found
    pub fn issue_count(&self) -> usize {
        self.total_issues
    }

    /// Returns true if any issues were found
    pub fn has_issues(&self) -> bool {
        self.total_issues > 0
    }

    /// Returns all collected issues.
    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }

    /// Returns high-severity issues (Warning or Error).
    pub fn high_issues(&self) -> Vec<&Issue> {
        self.issues
            .iter()
            .filter(|i| i.severity.is_error() || i.severity.is_warning())
            .collect()
    }

    /// Returns low-severity issues (Note or Help).
    pub fn low_issues(&self) -> Vec<&Issue> {
        self.issues
            .iter()
            .filter(|i| !i.severity.is_error() && !i.severity.is_warning())
            .collect()
    }

    /// Returns actionable issues (non-FP, confidence >= Medium).
    pub fn actionable_issues(&self) -> Vec<&Issue> {
        self.issues
            .iter()
            .filter(|i| i.confidence != omniscope_core::Confidence::Low)
            .collect()
    }

    /// Gets a pass result by name
    pub fn get_pass_result(&self, name: &str) -> Option<&PassResult> {
        self.pass_results.iter().find(|r| r.name == name)
    }

    /// Returns the execution time in milliseconds
    pub fn duration_ms(&self) -> u64 {
        self.duration.as_millis() as u64
    }

    /// Returns a summary string
    pub fn summary(&self) -> String {
        format!(
            "Pipeline completed: {} passes, {} issues found, {} nodes analyzed, {}ms",
            self.pass_count(),
            self.total_issues,
            self.total_nodes,
            self.duration_ms()
        )
    }
}

/// Pipeline statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStats {
    /// Number of foundation passes
    pub foundation_passes: usize,
    /// Number of analysis passes
    pub analysis_passes: usize,
    /// Number of transformation passes
    pub transformation_passes: usize,
    /// Average pass duration in milliseconds
    pub avg_duration_ms: f64,
    /// Maximum pass duration in milliseconds
    pub max_duration_ms: u64,
    /// Minimum pass duration in milliseconds
    pub min_duration_ms: u64,
    /// Total duration in milliseconds
    pub total_duration_ms: u64,
}

impl PipelineStats {
    /// Creates stats from pass results
    pub fn from_pass_results(pass_results: &[PassResult]) -> Self {
        let foundation_passes = pass_results
            .iter()
            .filter(|r| r.name == "CFG" || r.name == "DFG")
            .count();

        let analysis_passes = pass_results.len() - foundation_passes;

        let durations: Vec<u64> = pass_results.iter().map(|r| r.duration_ms).collect();

        let total_duration_ms: u64 = durations.iter().sum();
        let avg_duration_ms = if durations.is_empty() {
            0.0
        } else {
            total_duration_ms as f64 / durations.len() as f64
        };

        let max_duration_ms = durations.iter().copied().max().unwrap_or(0);
        let min_duration_ms = durations.iter().copied().min().unwrap_or(0);

        Self {
            foundation_passes,
            analysis_passes,
            transformation_passes: 0,
            avg_duration_ms,
            max_duration_ms,
            min_duration_ms,
            total_duration_ms,
        }
    }
}

impl Default for PipelineStats {
    fn default() -> Self {
        Self {
            foundation_passes: 0,
            analysis_passes: 0,
            transformation_passes: 0,
            avg_duration_ms: 0.0,
            max_duration_ms: 0,
            min_duration_ms: 0,
            total_duration_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_result_creation() {
        let pass_results = vec![
            PassResult::new("CFG").with_issues(0).with_nodes(100),
            PassResult::new("DFG").with_issues(2).with_nodes(150),
        ];

        let result = PipelineResult::from_pass_results(pass_results, Duration::from_millis(50));

        assert_eq!(result.pass_count(), 2);
        assert_eq!(result.issue_count(), 2);
        assert_eq!(result.total_nodes, 250);
        assert!(result.has_issues());
    }

    #[test]
    fn test_pipeline_result_summary() {
        let pass_results = vec![PassResult::new("CFG").with_issues(0).with_nodes(100)];

        let result = PipelineResult::from_pass_results(pass_results, Duration::from_millis(10));

        let summary = result.summary();
        assert!(summary.contains("1 passes"));
        assert!(summary.contains("0 issues"));
    }

    #[test]
    fn test_pipeline_stats() {
        let pass_results = vec![
            PassResult::new("CFG").with_duration(10),
            PassResult::new("DFG").with_duration(20),
            PassResult::new("FFIBoundary").with_duration(15),
        ];

        let stats = PipelineStats::from_pass_results(&pass_results);

        assert_eq!(stats.foundation_passes, 2);
        assert_eq!(stats.analysis_passes, 1);
        assert_eq!(stats.total_duration_ms, 45);
        assert_eq!(stats.max_duration_ms, 20);
        assert_eq!(stats.min_duration_ms, 10);
    }

    /// Objective: Verify Issue collection from PassResult into PipelineResult.
    /// Invariants: Issues from multiple passes must be correctly aggregated.
    #[test]
    fn test_pipeline_result_issue_collection() {
        use omniscope_core::{Issue, IssueKind, Severity};

        let mut pr1 = PassResult::new("FFIBoundary").with_nodes(5);
        pr1.add_issue(Issue::new(
            1,
            IssueKind::CrossLanguageFree,
            Severity::Warning,
            "cross-lang free",
        ));
        pr1.add_issue(Issue::new(
            2,
            IssueKind::FfiUnsafeCall,
            Severity::Note,
            "ffi unsafe",
        ));

        let mut pr2 = PassResult::new("DangerSurface").with_nodes(3);
        pr2.add_issue(Issue::new(
            3,
            IssueKind::NullDereference,
            Severity::Error,
            "null deref",
        ));

        let result = PipelineResult::from_pass_results(vec![pr1, pr2], Duration::from_millis(20));

        assert_eq!(
            result.total_issues, 3,
            "Must aggregate issues from all passes"
        );
        assert_eq!(result.issues.len(), 3, "issues vec must contain 3 entries");
        assert_eq!(result.issues[0].kind, IssueKind::CrossLanguageFree);
        assert_eq!(result.issues[2].kind, IssueKind::NullDereference);
    }

    /// Objective: Verify high/low/actionable issue filtering.
    /// Invariants: high_issues returns Warning+Error, low_issues returns Note+Help.
    #[test]
    fn test_pipeline_result_severity_filtering() {
        use omniscope_core::{Confidence, Issue, IssueKind, Severity};

        let mut pr = PassResult::new("test");
        pr.add_issue(
            Issue::new(1, IssueKind::CrossLanguageFree, Severity::Warning, "high")
                .with_confidence(Confidence::High),
        );
        pr.add_issue(
            Issue::new(2, IssueKind::MemoryLeak, Severity::Error, "critical")
                .with_confidence(Confidence::Medium),
        );
        pr.add_issue(
            Issue::new(3, IssueKind::FfiUnsafeCall, Severity::Note, "low")
                .with_confidence(Confidence::Low),
        );
        pr.add_issue(
            Issue::new(4, IssueKind::Unknown, Severity::Help, "help")
                .with_confidence(Confidence::Medium),
        );

        let result = PipelineResult::from_pass_results(vec![pr], Duration::from_millis(5));

        assert_eq!(
            result.high_issues().len(),
            2,
            "Must have 2 high-severity issues (Warning + Error)"
        );
        assert_eq!(
            result.low_issues().len(),
            2,
            "Must have 2 low-severity issues (Note + Help)"
        );
        assert_eq!(
            result.actionable_issues().len(),
            3,
            "Must have 3 actionable issues (not Low confidence)"
        );
    }

    /// Objective: Verify with_issues constructor from explicit issue list.
    /// Invariants: with_issues must override issues_found count with actual issue count.
    #[test]
    fn test_pipeline_result_with_issues() {
        use omniscope_core::{Issue, IssueKind, Severity};

        let issues = vec![
            Issue::new(1, IssueKind::InvalidFree, Severity::Warning, "invalid free"),
            Issue::new(2, IssueKind::MemoryLeak, Severity::Note, "leak"),
        ];
        let pr = PassResult::new("test").with_nodes(10);
        let result = PipelineResult::with_issues(vec![pr], Duration::from_millis(10), issues);

        assert_eq!(
            result.total_issues, 2,
            "total_issues must be len of issues vec"
        );
        assert_eq!(result.issues.len(), 2, "issues must be preserved");
        assert!(result.has_issues());
    }
}
