//! Rich terminal output formatter.
//!
//! Produces colored, tabular output with detection paths and
//! language→language arrows for resource contract issues.

use super::OutputFormatter;
use colored::*;
use omniscope_core::FindingView;
use omniscope_pipeline::PipelineResult;

/// Rich terminal formatter with ANSI colors.
pub struct RichFormatter {
    /// Whether to use ANSI colors.
    use_color: bool,
    /// Whether to include verbose fields (confidence_breakdown).
    verbose: bool,
    /// Whether to include debug fields (suppression_reason).
    debug: bool,
}

impl RichFormatter {
    /// Creates a new rich formatter with auto-detected color support.
    pub fn new() -> Self {
        use std::io::IsTerminal;
        Self {
            use_color: std::io::stdout().is_terminal(),
            verbose: false,
            debug: false,
        }
    }

    /// Creates a formatter with explicit verbose/debug flags.
    pub fn with_verbosity(verbose: bool, debug: bool) -> Self {
        use std::io::IsTerminal;
        Self {
            use_color: std::io::stdout().is_terminal(),
            verbose,
            debug,
        }
    }

    /// Creates a formatter with explicit color control (used in tests).
    #[cfg(test)]
    pub fn with_color(use_color: bool) -> Self {
        Self {
            use_color,
            verbose: false,
            debug: false,
        }
    }

    /// Applies color if enabled, otherwise returns plain string.
    fn maybe_color(&self, text: &str, color: &str) -> String {
        if self.use_color {
            match color {
                "red" => text.red().to_string(),
                "yellow" => text.yellow().to_string(),
                "blue" => text.blue().to_string(),
                "green" => text.green().to_string(),
                "cyan" => text.cyan().to_string(),
                "bold" => text.bold().to_string(),
                "white" => text.white().to_string(),
                _ => text.to_string(),
            }
        } else {
            text.to_string()
        }
    }

    /// Renders a horizontal rule.
    fn rule(&self) -> String {
        self.maybe_color(&"═".repeat(63), "cyan")
    }

    /// Renders a section divider.
    fn divider(&self) -> String {
        "─".repeat(63)
    }

    /// Formats the coverage section.
    fn format_coverage(&self, result: &PipelineResult) -> String {
        let actionable = result.actionable_issues().len();
        format!(
            "Coverage\n{}\n  Functions:          {}\n  Issues detected:    {}\n  Actionable:         {}",
            self.divider(),
            result.total_nodes,
            self.maybe_color(&result.total_issues.to_string(), if result.total_issues > 0 { "yellow" } else { "green" }),
            actionable
        )
    }

    /// Formats the findings section with per-issue details.
    fn format_findings(&self, result: &PipelineResult) -> String {
        let high_count = result.high_issues().len();
        let low_count = result.low_issues().len();

        let high_label = self.maybe_color(&high_count.to_string(), "red");
        let low_label = self.maybe_color(&low_count.to_string(), "yellow");

        let mut out = format!(
            "Findings\n{}\n  High:     {}\n  Low:      {}",
            self.divider(),
            high_label,
            low_label
        );

        if result.issues.is_empty() {
            let safe_msg = self.maybe_color("No issues detected.", "green");
            out.push_str(&format!("\n\n  {}", safe_msg));
            return out;
        }

        // Sort issues: HIGH first, then by confidence descending
        let mut sorted: Vec<_> = result.issues.iter().collect();
        sorted.sort_by(|a, b| {
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
                b.confidence
                    .as_f32()
                    .partial_cmp(&a.confidence.as_f32())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });

        for issue in &sorted {
            out.push('\n');
            out.push_str(&self.format_single_issue(issue));
        }

        out
    }

    /// Formats a single issue using the V2 FindingView model.
    ///
    /// V2 output includes a title, resource flow, why explanation,
    /// evidence list, and fix hint — all derived from the `FindingView`.
    fn format_single_issue(&self, issue: &&omniscope_core::Issue) -> String {
        let view = FindingView::from_issue(issue, self.verbose, self.debug);

        // Header line: [SEVERITY] OMI-NNN kind
        let badge = match view.severity.as_str() {
            "HIGH" => self.maybe_color(&format!("[{}]", view.severity), "red"),
            "LOW" => self.maybe_color(&format!("[{}]", view.severity), "yellow"),
            _ => self.maybe_color(&format!("[{}]", view.severity), "blue"),
        };
        let id = self.maybe_color(&view.id, "bold");
        let kind = self.maybe_color(&view.kind, "cyan");

        let mut out = format!("\n  {} {} {}", badge, id, kind);

        // Title — human-readable one-liner
        out.push_str(&format!(
            "\n    Title:     {}",
            self.maybe_color(&view.title, "bold")
        ));

        // Function (skip if empty)
        if let Some(ref function) = view.function {
            out.push_str(&format!("\n    Function:  {}", function));
        }

        // CWE
        if let Some(ref cwe) = view.cwe {
            out.push_str(&format!("\n    CWE:       {}", cwe));
        }

        // Confidence
        out.push_str(&format!("\n    Confidence: {}", view.confidence));

        // Resource flow
        if !view.resource_flow.is_empty() {
            out.push_str("\n    ┌─ Resource Flow ──");
            let last = view.resource_flow.len() - 1;
            for (i, step) in view.resource_flow.iter().enumerate() {
                let mut step_line = format!(
                    "{}. {:10} {}",
                    step.step,
                    format!("{}:", step.operation),
                    step.function
                );
                if let Some(ref family) = step.family {
                    step_line = format!("{}  family={}", step_line, family);
                }
                if i == last {
                    let cross = self.maybe_color("✗", "red");
                    out.push_str(&format!("\n    └── {}  {}", step_line, cross));
                } else {
                    out.push_str(&format!("\n    ├── {}", step_line));
                }
            }
        }

        // Why explanation
        out.push_str(&format!("\n    Why:\n      {}", view.why));

        // Evidence list
        if !view.evidence.is_empty() {
            out.push_str("\n    Evidence:");
            for ev in &view.evidence {
                let marker = self.maybe_color("+", "green");
                out.push_str(&format!("\n      {} {}", marker, ev));
            }
        }

        // Fix hint
        if let Some(ref fix) = view.fix_hint {
            out.push_str(&format!("\n    Fix:\n      {}", fix));
        }

        // Confidence breakdown (verbose mode)
        if let Some(ref breakdown) = view.confidence_breakdown {
            out.push_str(&format!("\n    Confidence Breakdown:\n      {}", breakdown));
        }

        // Suppression reason (debug mode)
        if let Some(ref reason) = view.suppression_reason {
            out.push_str(&format!("\n    Suppression: {}", reason));
        }

        out
    }

    /// Formats the summary section.
    fn format_summary(&self, result: &PipelineResult) -> String {
        let high_count = result.high_issues().len();
        let duration_ms = result.duration_ms();

        let status = if high_count > 0 {
            self.maybe_color(
                &format!("⚡ {} high-severity issue(s) found.", high_count),
                "red",
            )
        } else if result.total_issues > 0 {
            self.maybe_color(
                &format!("ℹ {} low-severity issue(s) found.", result.total_issues),
                "yellow",
            )
        } else {
            self.maybe_color("✓ No issues detected.", "green")
        };

        format!(
            "Summary\n{}\n  {}\n  Analysis time: {} ms\n  (use --verbose for pipeline metrics, --debug for full trace)",
            self.divider(),
            status,
            duration_ms
        )
    }
}

impl OutputFormatter for RichFormatter {
    fn format(&self, result: &PipelineResult) -> String {
        let mut out = String::new();

        // Header
        let title = self.maybe_color("OmniScope — Cross-Language Memory Safety Analysis", "bold");
        out.push_str(&format!("{}\n  {}\n{}\n", self.rule(), title, self.rule()));

        // Coverage
        out.push_str(&format!("\n{}\n", self.format_coverage(result)));

        // Findings
        out.push_str(&format!("\n{}\n", self.format_findings(result)));

        // Summary
        out.push_str(&format!("\n{}\n", self.format_summary(result)));

        // Footer
        out.push_str(&self.rule());

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
    use std::time::Duration;

    #[test]
    fn test_rich_formatter_sections() {
        let formatter = RichFormatter::with_color(false);
        let pass_results = vec![omniscope_pass::PassResult::new("test")];
        let result =
            PipelineResult::from_pass_results(pass_results, Duration::from_millis(10), Vec::new());

        let output = formatter.format(&result);
        assert!(output.contains("OmniScope"), "Must contain header");
        assert!(output.contains("Coverage"), "Must contain coverage section");
        assert!(output.contains("Findings"), "Must contain findings section");
        assert!(output.contains("Summary"), "Must contain summary section");
    }

    #[test]
    fn test_rich_formatter_with_issues() {
        let formatter = RichFormatter::with_color(false);
        let issue = Issue::new(1, IssueKind::InvalidFree, Severity::Warning, "test detail")
            .with_confidence(Confidence::Medium)
            .with_location(
                omniscope_core::IssueLocation::new(std::path::PathBuf::from("test.c"), 10)
                    .with_function("test_func".to_string()),
            );

        let mut pass_result = omniscope_pass::PassResult::new("FFIBoundary").with_nodes(5);
        pass_result.add_issue(issue);

        let result = PipelineResult::from_pass_results(
            vec![pass_result],
            Duration::from_millis(16),
            Vec::new(),
        );
        let output = formatter.format(&result);

        // V2 output checks: title, kind, function must appear.
        assert!(output.contains("HIGH"), "Must show HIGH severity label");
        assert!(output.contains("OMI-001"), "Must show issue ID");
        assert!(output.contains("invalid_free"), "Must show issue kind");
        assert!(output.contains("test_func"), "Must show function name");
        // V2 specific: title and why/evidence/fix sections.
        assert!(output.contains("Title:"), "V2 must show Title section");
        assert!(output.contains("Why:"), "V2 must show Why section");
        assert!(output.contains("Fix:"), "V2 must show Fix section");
    }

    #[test]
    fn test_rich_formatter_cross_family_issue() {
        // Verify V2 resource flow rendering for a cross-family issue.
        let formatter = RichFormatter::with_color(false);
        let issue = Issue::new(
            3,
            IssueKind::CrossFamilyFree,
            Severity::Error,
            "c_heap allocated by malloc released as sqlite3_free",
        );

        let mut pass_result = omniscope_pass::PassResult::new("ResourceContract").with_nodes(10);
        pass_result.add_issue(issue);

        let result = PipelineResult::from_pass_results(
            vec![pass_result],
            Duration::from_millis(5),
            Vec::new(),
        );
        let output = formatter.format(&result);

        assert!(
            output.contains("malloc buffer released by sqlite3_free"),
            "V2 title must describe cross-family free"
        );
        assert!(
            output.contains("Resource Flow"),
            "V2 must show resource flow section"
        );
        assert!(
            output.contains("alloc") && output.contains("release"),
            "V2 flow must show alloc and release steps"
        );
    }

    #[test]
    fn test_rich_formatter_no_issues() {
        let formatter = RichFormatter::with_color(false);
        let result =
            PipelineResult::from_pass_results(vec![], Duration::from_millis(1), Vec::new());
        let output = formatter.format(&result);
        assert!(
            output.contains("No issues detected"),
            "Must show no-issues message"
        );
    }

    #[test]
    fn test_rich_formatter_function_not_shown_when_empty() {
        // When no location is set, the Function line must not appear.
        let formatter = RichFormatter::with_color(false);
        let issue = Issue::new(
            1,
            IssueKind::MemoryLeak,
            Severity::Note,
            "allocation may leak",
        );

        let mut pass_result = omniscope_pass::PassResult::new("Leak").with_nodes(3);
        pass_result.add_issue(issue);

        let result = PipelineResult::from_pass_results(
            vec![pass_result],
            Duration::from_millis(1),
            Vec::new(),
        );
        let output = formatter.format(&result);

        assert!(
            !output.contains("Function:"),
            "Function line must not appear when no function is set"
        );
    }
}
