//! Rich terminal output formatter.
//!
//! Produces colored, tabular output with detection paths, matching
//! the OmniScope canonical output format:
//!
//! ```text
//! ═══════════════════════════════════════════════════════════════
//!   OmniScope — Cross-Language Memory Safety Analysis
//! ═══════════════════════════════════════════════════════════════
//!
//! Coverage
//! ───────────────────────────────────────────────────────────────
//!   Functions:          15
//!   Issues detected:    5
//!   Actionable:         3
//!
//! Findings
//! ───────────────────────────────────────────────────────────────
//!   High:     3
//!   Low:      2
//!
//!   [HIGH] OMI-001
//!     Type:       invalid_free
//!     Confidence: MEDIUM (85%)
//!     Function:   tc2_c_malloc_cpp_delete
//!     Detail:     operator_delete() called on non-heap source pointer
//!     ┌─ Detection Path ──
//!     ├── [1] Free called on non-heap pointer
//!     ├── [2] Pointer origin: from malloc()
//!     └── [3] Passed to operator_delete()  ✗
//!
//! Summary
//! ───────────────────────────────────────────────────────────────
//!   ⚡ 3 high-severity issue(s) found.
//!   Analysis time: 16 ms
//! ═══════════════════════════════════════════════════════════════
//! ```

use super::{confidence_label, format_issue_id, issue_kind_label, severity_label, OutputFormatter};
use omniscope_pipeline::PipelineResult;

/// Rich terminal formatter with ANSI colors.
pub struct RichFormatter;

impl RichFormatter {
    /// Creates a new rich formatter.
    pub fn new() -> Self {
        Self
    }

    /// Renders a horizontal rule.
    fn rule() -> String {
        "═".repeat(63)
    }

    /// Renders a section divider.
    fn divider() -> String {
        "─".repeat(63)
    }

    /// Formats the coverage section.
    fn format_coverage(result: &PipelineResult) -> String {
        let actionable = result.actionable_issues().len();
        format!(
            "Coverage\n{}\n  Functions:          {}\n  Issues detected:    {}\n  Actionable:         {}",
            Self::divider(),
            result.total_nodes,
            result.total_issues,
            actionable
        )
    }

    /// Formats the findings section with per-issue details.
    fn format_findings(result: &PipelineResult) -> String {
        let high_count = result.high_issues().len();
        let low_count = result.low_issues().len();

        let mut out = format!(
            "Findings\n{}\n  High:     {}\n  Low:      {}",
            Self::divider(),
            high_count,
            low_count
        );

        if result.issues.is_empty() {
            out.push_str("\n\n  No issues detected.");
            return out;
        }

        // Sort issues: HIGH first, then by confidence descending
        let mut sorted: Vec<_> = result.issues.iter().collect();
        sorted.sort_by(|a, b| {
            // HIGH before LOW
            let sa = if a.severity.is_error() || a.severity.is_warning() {
                0
            } else {
                1
            };
            let sb = if b.severity.is_error() || b.severity.is_warning() {
                0
            } else {
                1
            };
            sa.cmp(&sb).then_with(|| {
                // Higher confidence first
                b.confidence
                    .as_f32()
                    .partial_cmp(&a.confidence.as_f32())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });

        for issue in &sorted {
            out.push('\n');
            out.push_str(&Self::format_single_issue(issue));
        }

        out
    }

    /// Formats a single issue with detection path.
    fn format_single_issue(issue: &&omniscope_core::Issue) -> String {
        let sev = severity_label(issue);
        let id = format_issue_id(issue.id);
        let kind = issue_kind_label(&issue.kind);
        let conf = confidence_label(&issue.confidence);

        // Extract function name from location or FFI boundary
        let function = if let Some(ref loc) = issue.location {
            loc.function.as_deref().unwrap_or("unknown")
        } else if let Some(ref ffi) = issue.ffi_boundary {
            &ffi.caller_name
        } else {
            "unknown"
        };

        let mut out = format!(
            "\n  [{}] {}\n    Type:       {}\n    Confidence: {}\n    Function:   {}\n    Detail:     {}",
            sev, id, kind, conf, function, issue.description
        );

        // CWE annotation
        if let Some(cwe) = issue.cwe_id {
            out.push_str(&format!(" (CWE-{})", cwe));
        }

        // Detection path (trace entries)
        if !issue.trace.is_empty() {
            out.push_str("\n    ┌─ Detection Path ──");
            let last = issue.trace.len() - 1;
            for (i, entry) in issue.trace.iter().enumerate() {
                if i == last {
                    out.push_str(&format!("\n    └── [{}] {}  ✗", i + 1, entry.description));
                } else {
                    out.push_str(&format!("\n    ├── [{}] {}", i + 1, entry.description));
                }
            }
        }

        // FFI boundary info
        if let Some(ref ffi) = issue.ffi_boundary {
            out.push_str(&format!(
                "\n    ┌─ FFI Boundary ──\n    ├── Caller: {} ({:?})\n    ├── Callee: {} ({:?})\n    └── Kind: {:?}",
                ffi.caller_name, ffi.caller_lang, ffi.callee_name, ffi.callee_lang, ffi.boundary_kind
            ));
        }

        out
    }

    /// Formats the summary section.
    fn format_summary(result: &PipelineResult) -> String {
        let high_count = result.high_issues().len();
        let duration_ms = result.duration_ms();

        let status = if high_count > 0 {
            format!("⚡ {} high-severity issue(s) found.", high_count)
        } else if result.total_issues > 0 {
            format!("ℹ {} low-severity issue(s) found.", result.total_issues)
        } else {
            "✓ No issues detected.".to_string()
        };

        format!(
            "Summary\n{}\n  {}\n  Analysis time: {} ms\n  (use --verbose for pipeline metrics, --debug for full trace)",
            Self::divider(),
            status,
            duration_ms
        )
    }
}

impl OutputFormatter for RichFormatter {
    fn format(&self, result: &PipelineResult) -> String {
        let mut out = String::new();

        // Header
        out.push_str(&format!(
            "{}\n  OmniScope — Cross-Language Memory Safety Analysis\n{}\n",
            Self::rule(),
            Self::rule()
        ));

        // Coverage
        out.push_str(&format!("\n{}\n", Self::format_coverage(result)));

        // Findings
        out.push_str(&format!("\n{}\n", Self::format_findings(result)));

        // Summary
        out.push_str(&format!("\n{}\n", Self::format_summary(result)));

        // Footer
        out.push_str(&Self::rule());

        out
    }
}

impl Default for RichFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_core::{Confidence, Issue, IssueKind, Severity};
    use omniscope_pass::PassResult;
    use std::time::Duration;

    /// Objective: Verify RichFormatter produces output with all sections.
    /// Invariants: Output must contain "OmniScope", "Coverage", "Findings", "Summary".
    #[test]
    fn test_rich_formatter_sections() {
        let formatter = RichFormatter::new();
        let pass_results = vec![PassResult::new("test")];
        let result = PipelineResult::from_pass_results(pass_results, Duration::from_millis(10));

        let output = formatter.format(&result);
        assert!(output.contains("OmniScope"), "Must contain header");
        assert!(output.contains("Coverage"), "Must contain coverage section");
        assert!(output.contains("Findings"), "Must contain findings section");
        assert!(output.contains("Summary"), "Must contain summary section");
    }

    /// Objective: Verify RichFormatter renders issues with detection paths.
    /// Invariants: Issues must show [HIGH]/[LOW], Type, Confidence, Function, Detail.
    #[test]
    fn test_rich_formatter_with_issues() {
        let formatter = RichFormatter::new();
        let issue = Issue::new(1, IssueKind::InvalidFree, Severity::Warning, "test detail")
            .with_confidence(Confidence::Medium)
            .with_location(
                omniscope_core::IssueLocation::new(std::path::PathBuf::from("test.c"), 10)
                    .with_function("test_func".to_string()),
            );

        let mut pass_result = PassResult::new("FFIBoundary").with_nodes(5);
        pass_result.add_issue(issue);

        let result =
            PipelineResult::from_pass_results(vec![pass_result], Duration::from_millis(16));
        let output = formatter.format(&result);

        assert!(output.contains("[HIGH]"), "Must show HIGH severity label");
        assert!(output.contains("OMI-001"), "Must show issue ID");
        assert!(output.contains("invalid_free"), "Must show issue kind");
        assert!(output.contains("MEDIUM"), "Must show confidence");
        assert!(output.contains("test_func"), "Must show function name");
        assert!(output.contains("test detail"), "Must show description");
    }

    /// Objective: Verify RichFormatter renders trace entries as detection paths.
    /// Invariants: Detection path must use tree-drawing characters.
    #[test]
    fn test_rich_formatter_detection_path() {
        let formatter = RichFormatter::new();
        let mut issue = Issue::new(
            1,
            IssueKind::CrossLanguageFree,
            Severity::Warning,
            "cross-lang free",
        );
        issue.add_trace(omniscope_core::TraceEntry::new("Step 1: malloc called"));
        issue.add_trace(omniscope_core::TraceEntry::new(
            "Step 2: passed to operator_delete",
        ));

        let mut pass_result = PassResult::new("FFIBoundary");
        pass_result.add_issue(issue);

        let result = PipelineResult::from_pass_results(vec![pass_result], Duration::from_millis(5));
        let output = formatter.format(&result);

        assert!(
            output.contains("Detection Path"),
            "Must show detection path header"
        );
        assert!(output.contains("├──"), "Must show tree branch character");
        assert!(output.contains("└──"), "Must show tree leaf character");
        assert!(output.contains("Step 1"), "Must show first trace step");
        assert!(output.contains("Step 2"), "Must show second trace step");
    }

    /// Objective: Verify empty result produces "No issues detected" message.
    #[test]
    fn test_rich_formatter_no_issues() {
        let formatter = RichFormatter::new();
        let result = PipelineResult::from_pass_results(vec![], Duration::from_millis(1));
        let output = formatter.format(&result);
        assert!(
            output.contains("No issues detected"),
            "Must show no-issues message"
        );
    }
}
