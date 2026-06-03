//! Pipeline result aggregation
//!
//! This module provides result aggregation for the analysis pipeline.

use omniscope_core::Issue;
use omniscope_pass::{PassResult, PassTiming};
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
    /// Per-pass timing information for performance reporting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pass_timings: Vec<PassTiming>,
}

impl PipelineResult {
    /// Creates a pipeline result from pass results
    pub fn from_pass_results(
        pass_results: Vec<PassResult>,
        duration: Duration,
        pass_timings: Vec<PassTiming>,
    ) -> Self {
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
            pass_timings,
        }
    }

    /// Creates a pipeline result with explicit issues (from context collection).
    ///
    /// Deduplicates issues by (kind, symbol, description) before counting.
    /// This prevents the same bug from being reported multiple times when
    /// multiple passes emit overlapping findings.
    pub fn with_issues(
        pass_results: Vec<PassResult>,
        duration: Duration,
        issues: Vec<Issue>,
        pass_timings: Vec<PassTiming>,
    ) -> Self {
        let total_nodes = pass_results.iter().map(|r| r.nodes_analyzed).sum();

        let stats = PipelineStats::from_pass_results(&pass_results);

        // Deduplicate: same (kind, symbol, description) → keep first occurrence.
        let mut seen = std::collections::HashSet::new();
        let deduped: Vec<Issue> = issues
            .into_iter()
            .filter(|issue| {
                let key = (issue.kind, issue.symbol.clone(), issue.description.clone());
                seen.insert(key)
            })
            .collect();

        let total_issues = deduped.len();

        Self {
            pass_results,
            total_issues,
            total_nodes,
            duration,
            stats,
            issues: deduped,
            pass_timings,
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

        let result = PipelineResult::from_pass_results(
            pass_results,
            Duration::from_millis(50),
            Vec::new(), // No pass timings in test
        );

        assert_eq!(
            result.pass_count(),
            2,
            "Pipeline result should contain two passes"
        );
        assert_eq!(
            result.issue_count(),
            2,
            "Pipeline result should contain two issues"
        );
        assert_eq!(
            result.total_nodes, 250,
            "Pipeline result should have 250 total nodes"
        );
        assert!(
            result.has_issues(),
            "Pipeline result should report that it has issues"
        );
    }

    #[test]
    fn test_pipeline_result_summary() {
        let pass_results = vec![PassResult::new("CFG").with_issues(0).with_nodes(100)];

        let result = PipelineResult::from_pass_results(
            pass_results,
            Duration::from_millis(10),
            Vec::new(), // No pass timings in test
        );

        let summary = result.summary();
        assert!(
            summary.contains("1 passes"),
            "Summary should indicate one pass was executed"
        );
        assert!(
            summary.contains("0 issues"),
            "Summary should indicate zero issues were found"
        );
    }

    #[test]
    fn test_pipeline_stats() {
        let pass_results = vec![
            PassResult::new("CFG").with_duration(10),
            PassResult::new("DFG").with_duration(20),
            PassResult::new("FFIBoundary").with_duration(15),
        ];

        let stats = PipelineStats::from_pass_results(&pass_results);

        assert_eq!(
            stats.foundation_passes, 2,
            "Pipeline stats should count two foundation passes"
        );
        assert_eq!(
            stats.analysis_passes, 1,
            "Pipeline stats should count one analysis pass"
        );
        assert_eq!(
            stats.total_duration_ms, 45,
            "Pipeline stats should have 45ms total duration"
        );
        assert_eq!(
            stats.max_duration_ms, 20,
            "Pipeline stats should have 20ms max duration"
        );
        assert_eq!(
            stats.min_duration_ms, 10,
            "Pipeline stats should have 10ms min duration"
        );
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

        let result = PipelineResult::from_pass_results(
            vec![pr1, pr2],
            Duration::from_millis(20),
            Vec::new(), // No pass timings in test
        );

        assert_eq!(
            result.total_issues, 3,
            "Must aggregate issues from all passes"
        );
        assert_eq!(result.issues.len(), 3, "issues vec must contain 3 entries");
        assert_eq!(
            result.issues[0].kind,
            IssueKind::CrossLanguageFree,
            "First issue should be CrossLanguageFree"
        );
        assert_eq!(
            result.issues[2].kind,
            IssueKind::NullDereference,
            "Third issue should be NullDereference"
        );
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

        let result = PipelineResult::from_pass_results(
            vec![pr],
            Duration::from_millis(5),
            Vec::new(), // No pass timings in test
        );

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
        let result = PipelineResult::with_issues(
            vec![pr],
            Duration::from_millis(10),
            issues,
            Vec::new(), // No pass timings in test
        );

        assert_eq!(
            result.total_issues, 2,
            "total_issues must be len of issues vec"
        );
        assert_eq!(result.issues.len(), 2, "issues must be preserved");
        assert!(
            result.has_issues(),
            "Result should report that it has issues"
        );
    }

    /// Objective: Verify that from_pass_results with an empty vec produces a zero-count result.
    /// Invariants: pass_count=0, issue_count=0, has_issues()=false.
    #[test]
    fn test_empty_pass_results() {
        let result = PipelineResult::from_pass_results(vec![], Duration::ZERO, Vec::new());
        assert_eq!(
            result.pass_count(),
            0,
            "pass_count must be 0 for empty input"
        );
        assert_eq!(
            result.issue_count(),
            0,
            "issue_count must be 0 for empty input"
        );
        assert!(
            !result.has_issues(),
            "has_issues must be false for empty input"
        );
    }

    /// Objective: Verify that get_pass_result finds a pass by name.
    /// Invariants: get_pass_result returns Some for an existing pass name.
    #[test]
    fn test_get_pass_result_found() {
        let pass_results = vec![
            PassResult::new("CFG").with_nodes(50),
            PassResult::new("DFG").with_nodes(75),
        ];
        let result =
            PipelineResult::from_pass_results(pass_results, Duration::from_millis(10), Vec::new());

        let cfg = result.get_pass_result("CFG");
        assert!(cfg.is_some(), "get_pass_result must find 'CFG'");
        assert_eq!(cfg.unwrap().name, "CFG", "found pass must have name 'CFG'");
    }

    /// Objective: Verify that get_pass_result returns None for a non-existent name.
    /// Invariants: get_pass_result("nonexistent") returns None.
    #[test]
    fn test_get_pass_result_miss() {
        let pass_results = vec![PassResult::new("CFG").with_nodes(50)];
        let result =
            PipelineResult::from_pass_results(pass_results, Duration::from_millis(10), Vec::new());

        assert!(
            result.get_pass_result("nonexistent").is_none(),
            "get_pass_result must return None for missing name"
        );
    }

    /// Objective: Verify that duration_ms accurately converts the Duration.
    /// Invariants: Duration::from_millis(42) yields duration_ms() == 42.
    #[test]
    fn test_duration_ms_accuracy() {
        let result =
            PipelineResult::from_pass_results(vec![], Duration::from_millis(42), Vec::new());
        assert_eq!(
            result.duration_ms(),
            42,
            "duration_ms must equal 42 for 42ms Duration"
        );
    }

    /// Objective: Verify pipeline stats for a single pass where avg, max, and min are all equal.
    /// Invariants: One pass with duration=100 produces avg=100.0, max=100, min=100.
    #[test]
    fn test_pipeline_stats_single_pass() {
        let pass_results = vec![PassResult::new("CFG").with_duration(100)];
        let stats = PipelineStats::from_pass_results(&pass_results);

        assert_eq!(
            stats.avg_duration_ms, 100.0,
            "avg must equal the single pass duration"
        );
        assert_eq!(
            stats.max_duration_ms, 100,
            "max must equal the single pass duration"
        );
        assert_eq!(
            stats.min_duration_ms, 100,
            "min must equal the single pass duration"
        );
    }

    /// Objective: Verify that PipelineStats::default() initializes all fields to zero.
    /// Invariants: All numeric fields are 0.
    #[test]
    fn test_pipeline_stats_default() {
        let stats = PipelineStats::default();

        assert_eq!(
            stats.foundation_passes, 0,
            "default foundation_passes must be 0"
        );
        assert_eq!(
            stats.analysis_passes, 0,
            "default analysis_passes must be 0"
        );
        assert_eq!(
            stats.transformation_passes, 0,
            "default transformation_passes must be 0"
        );
        assert_eq!(
            stats.avg_duration_ms, 0.0,
            "default avg_duration_ms must be 0.0"
        );
        assert_eq!(
            stats.max_duration_ms, 0,
            "default max_duration_ms must be 0"
        );
        assert_eq!(
            stats.min_duration_ms, 0,
            "default min_duration_ms must be 0"
        );
        assert_eq!(
            stats.total_duration_ms, 0,
            "default total_duration_ms must be 0"
        );
    }

    /// Objective: Verify that high_issues and low_issues are empty when no issues exist.
    /// Invariants: A result with no issues yields empty high_issues() and low_issues().
    #[test]
    fn test_high_low_issues_empty() {
        let pass_results = vec![PassResult::new("CFG").with_nodes(100)];
        let result =
            PipelineResult::from_pass_results(pass_results, Duration::from_millis(10), Vec::new());

        assert!(
            result.high_issues().is_empty(),
            "high_issues must be empty when no issues exist"
        );
        assert!(
            result.low_issues().is_empty(),
            "low_issues must be empty when no issues exist"
        );
    }
}
