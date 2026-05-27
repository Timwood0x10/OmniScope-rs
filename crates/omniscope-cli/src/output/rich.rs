//! Rich terminal output formatter.
//!
//! Produces colored, tabular output with detection paths and
//! language→language arrows for resource contract issues.

use super::{confidence_label, format_issue_id, issue_kind_label, severity_label, OutputFormatter};
use colored::*;
use omniscope_pipeline::PipelineResult;
use omniscope_types::LanguageHint;

/// Rich terminal formatter with ANSI colors.
pub struct RichFormatter {
    /// Whether to use ANSI colors.
    use_color: bool,
}

impl RichFormatter {
    /// Creates a new rich formatter with auto-detected color support.
    pub fn new() -> Self {
        Self { use_color: true }
    }

    /// Creates a formatter with explicit color control.
    #[allow(dead_code)]
    pub fn with_color(use_color: bool) -> Self {
        Self { use_color }
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

    /// Formats a severity badge with color.
    fn severity_badge(&self, issue: &omniscope_core::Issue) -> String {
        let label = severity_label(issue);
        match label {
            "HIGH" => self.maybe_color(&format!("[{label}]"), "red"),
            "LOW" => self.maybe_color(&format!("[{label}]"), "yellow"),
            _ => self.maybe_color(&format!("[{label}]"), "blue"),
        }
    }

    /// Formats the language arrow for a resource contract issue.
    fn language_arrow_for_issue(&self, issue: &omniscope_core::Issue) -> Option<String> {
        use omniscope_core::IssueKind;
        if !issue.kind.is_resource_contract() {
            return None;
        }

        // Try to extract language info from FFI boundary or description
        if let Some(ref ffi) = issue.ffi_boundary {
            let caller = lang_label(ffi.caller_lang);
            let callee = lang_label(ffi.callee_lang);
            let is_mismatch = issue.kind == IssueKind::CrossFamilyFree;
            let arrow = if is_mismatch {
                self.maybe_color("──✕──>", "red")
            } else {
                self.maybe_color("──✓──>", "green")
            };
            Some(format!("{} {} {}", caller, arrow, callee))
        } else {
            // Infer from issue description patterns
            let desc = &issue.description;
            if desc.contains("cross-family") || desc.contains("cross_family") {
                Some(self.infer_arrow_from_description(desc))
            } else if issue.kind == IssueKind::ConditionalLeak {
                let lang = self.infer_lang_from_description(desc);
                Some(self.maybe_color(&format!("({})", language_label_str(lang)), "cyan"))
            } else {
                None
            }
        }
    }

    /// Infers language arrow from issue description text.
    fn infer_arrow_from_description(&self, desc: &str) -> String {
        // Common patterns in verifier descriptions:
        // "c_heap allocated ... released as cpp_new_scalar"
        let alloc_lang = if desc.contains("c_heap") || desc.contains("malloc") {
            LanguageHint::C
        } else if desc.contains("rust_global") || desc.contains("__rust") {
            LanguageHint::Rust
        } else if desc.contains("cpp_new") || desc.contains("operator") {
            LanguageHint::Cpp
        } else if desc.contains("python") {
            LanguageHint::Python
        } else {
            LanguageHint::Unknown
        };

        let release_lang = if desc.contains("cpp_new_scalar") || desc.contains("operator delete") {
            LanguageHint::Cpp
        } else if desc.contains("c_heap") && desc.contains("released as") {
            LanguageHint::C
        } else if desc.contains("rust_global") && desc.contains("released as") {
            LanguageHint::Rust
        } else if desc.contains("python") {
            LanguageHint::Python
        } else {
            LanguageHint::Unknown
        };

        let alloc_str = self.maybe_color(language_label_str(alloc_lang), "cyan");
        let arrow = self.maybe_color("──✕──>", "red");
        let release_str = self.maybe_color(language_label_str(release_lang), "cyan");
        format!("{} {} {}", alloc_str, arrow, release_str)
    }

    /// Infers a language from description text.
    fn infer_lang_from_description(&self, desc: &str) -> LanguageHint {
        if desc.contains("rust") || desc.contains("__rust") {
            LanguageHint::Rust
        } else if desc.contains("python") || desc.contains("Py") {
            LanguageHint::Python
        } else if desc.contains("cpp") || desc.contains("operator") {
            LanguageHint::Cpp
        } else {
            LanguageHint::C
        }
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

    /// Formats a single issue with detection path and language arrow.
    fn format_single_issue(&self, issue: &&omniscope_core::Issue) -> String {
        let badge = self.severity_badge(issue);
        let id = self.maybe_color(&format_issue_id(issue.id), "bold");
        let kind = self.maybe_color(issue_kind_label(&issue.kind), "cyan");
        let conf = confidence_label(&issue.confidence);

        // Extract function name from location or FFI boundary
        let function = if let Some(ref loc) = issue.location {
            loc.function.as_deref().unwrap_or("unknown")
        } else if let Some(ref ffi) = issue.ffi_boundary {
            &ffi.caller_name
        } else {
            "unknown"
        };

        let mut detail = issue.description.clone();

        // Append language arrow for resource contract issues
        if let Some(arrow) = self.language_arrow_for_issue(issue) {
            detail = format!("{} [{}]", detail, arrow);
        }

        let mut out = format!(
            "\n  {} {}\n    Type:       {}\n    Confidence: {}\n    Function:   {}\n    Detail:     {}",
            badge, id, kind, conf, function, detail
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
                    let cross = self.maybe_color("✗", "red");
                    out.push_str(&format!(
                        "\n    └── [{}] {}  {}",
                        i + 1,
                        entry.description,
                        cross
                    ));
                } else {
                    out.push_str(&format!("\n    ├── [{}] {}", i + 1, entry.description));
                }
            }
        }

        // FFI boundary info
        if let Some(ref ffi) = issue.ffi_boundary {
            let caller_lang = self.maybe_color(lang_label(ffi.caller_lang), "cyan");
            let callee_lang = self.maybe_color(lang_label(ffi.callee_lang), "cyan");
            out.push_str(&format!(
                "\n    ┌─ FFI Boundary ──\n    ├── Caller: {} ({})\n    ├── Callee: {} ({})\n    └── Kind: {:?}",
                ffi.caller_name, caller_lang, ffi.callee_name, callee_lang, ffi.boundary_kind
            ));
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

/// Converts a Language type to a short display label.
fn lang_label(lang: omniscope_types::Language) -> &'static str {
    use omniscope_types::Language;
    match lang {
        Language::C => "C",
        Language::Cpp => "C++",
        Language::Rust => "Rust",
        Language::Python => "Python",
        Language::Java => "Java",
        Language::Go => "Go",
        Language::Zig => "Zig",
        Language::Unknown => "?",
    }
}

/// Converts a LanguageHint to a short display label.
fn language_label_str(hint: LanguageHint) -> &'static str {
    match hint {
        LanguageHint::C => "C",
        LanguageHint::Cpp => "C++",
        LanguageHint::Rust => "Rust",
        LanguageHint::Python => "Python",
        LanguageHint::Java => "Java",
        LanguageHint::CSharp => "C#",
        LanguageHint::Go => "Go",
        LanguageHint::Zig => "Zig",
        LanguageHint::Unknown => "?",
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
        let result = PipelineResult::from_pass_results(pass_results, Duration::from_millis(10));

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

        let result =
            PipelineResult::from_pass_results(vec![pass_result], Duration::from_millis(16));
        let output = formatter.format(&result);

        assert!(output.contains("HIGH"), "Must show HIGH severity label");
        assert!(output.contains("OMI-001"), "Must show issue ID");
        assert!(output.contains("invalid_free"), "Must show issue kind");
        assert!(output.contains("MEDIUM"), "Must show confidence");
        assert!(output.contains("test_func"), "Must show function name");
    }

    #[test]
    fn test_rich_formatter_no_issues() {
        let formatter = RichFormatter::with_color(false);
        let result = PipelineResult::from_pass_results(vec![], Duration::from_millis(1));
        let output = formatter.format(&result);
        assert!(
            output.contains("No issues detected"),
            "Must show no-issues message"
        );
    }

    #[test]
    fn test_language_labels() {
        assert_eq!(lang_label(omniscope_types::Language::C), "C");
        assert_eq!(lang_label(omniscope_types::Language::Cpp), "C++");
        assert_eq!(lang_label(omniscope_types::Language::Rust), "Rust");
        assert_eq!(lang_label(omniscope_types::Language::Python), "Python");
        assert_eq!(lang_label(omniscope_types::Language::Unknown), "?");
    }
}
