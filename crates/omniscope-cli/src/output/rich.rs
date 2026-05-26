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
