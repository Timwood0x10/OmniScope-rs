//! JSON output formatter for CI/CD integration.
//!
//! Produces a structured JSON object containing all analysis results,
//! suitable for machine consumption in CI/CD pipelines. The output
//! includes both the original `PipelineResult` fields and a
//! `findings_v2` array with human-readable `FindingView` entries.
//!
//! ## Backward compatibility
//!
//! The `findings_v2` field is added alongside the existing fields.
//! Existing CI consumers that only read `issues`, `total_issues`,
//! and `pass_results` continue to work unchanged.

use super::OutputFormatter;
use omniscope_core::FindingView;
use omniscope_pipeline::PipelineResult;

/// JSON formatter producing serde-serialized output.
pub struct JsonFormatter {
    /// Whether to pretty-print the JSON output.
    pub pretty: bool,
    /// Whether to include the `findings_v2` array.
    pub include_v2: bool,
    /// Whether to include verbose fields (confidence_breakdown).
    pub verbose: bool,
    /// Whether to include debug fields (suppression_reason).
    pub debug: bool,
}

impl JsonFormatter {
    /// Creates a new JSON formatter with V2 findings and pretty-printing.
    pub fn new() -> Self {
        Self {
            pretty: true,
            include_v2: true,
            verbose: false,
            debug: false,
        }
    }

    /// Creates a compact JSON formatter (no pretty-printing).
    ///
    /// Use for CI pipelines where compact output is preferred.
    pub fn compact() -> Self {
        Self {
            pretty: false,
            include_v2: true,
            verbose: false,
            debug: false,
        }
    }

    /// Creates a formatter from the pretty flag.
    pub fn from_pretty(pretty: bool) -> Self {
        Self {
            pretty,
            include_v2: true,
            verbose: false,
            debug: false,
        }
    }

    /// Disables the `findings_v2` array in output.
    ///
    /// Use when only the original `PipelineResult` serialization
    /// is needed (e.g., strict backward-compatibility mode).
    #[allow(dead_code)]
    pub fn without_v2(mut self) -> Self {
        self.include_v2 = false;
        self
    }

    /// Enables verbose fields in `findings_v2` entries.
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Enables debug fields in `findings_v2` entries.
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Builds the `findings_v2` array from pipeline result issues.
    fn build_findings_v2(&self, result: &PipelineResult) -> Vec<FindingView> {
        result
            .issues()
            .iter()
            .map(|issue| FindingView::from_issue(issue, self.verbose, self.debug))
            .collect()
    }
}

impl OutputFormatter for JsonFormatter {
    fn format(&self, result: &PipelineResult) -> String {
        // First serialize the base PipelineResult to a JSON Value.
        let mut root: serde_json::Value = serde_json::to_value(result).unwrap_or_else(
            |e| serde_json::json!({ "error": format!("Failed to serialize result: {}", e) }),
        );

        // Append findings_v2 array when enabled and issues exist.
        if self.include_v2 && !result.issues().is_empty() {
            let findings = self.build_findings_v2(result);
            // Serialize findings_v2 entries to JSON values.
            let findings_json: Vec<serde_json::Value> = findings
                .iter()
                .map(|f| serde_json::to_value(f).unwrap_or(serde_json::Value::Null))
                .collect();
            // Insert into the root object.
            if let Some(obj) = root.as_object_mut() {
                obj.insert(
                    "findings_v2".to_string(),
                    serde_json::Value::Array(findings_json),
                );
            }
        }

        // Serialize the final composite object.
        if self.pretty {
            serde_json::to_string_pretty(&root)
                .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
        } else {
            serde_json::to_string(&root).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
        }
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_core::{Issue, IssueKind, Severity};
    use omniscope_pass::PassResult;
    use std::time::Duration;

    /// Helper: builds a PipelineResult with one issue.
    fn result_with_issue() -> PipelineResult {
        let mut pr = PassResult::new("test").with_nodes(10);
        pr.add_issue(Issue::new(
            1,
            IssueKind::CrossFamilyFree,
            Severity::Error,
            "c_heap allocated by malloc released as sqlite3_free",
        ));
        PipelineResult::from_pass_results(vec![pr], Duration::from_millis(5), Vec::new())
    }

    /// Objective: Verify JsonFormatter produces valid JSON output.
    /// Invariants: Output must parse as valid JSON with expected fields.
    #[test]
    fn test_json_formatter_valid_json() {
        let formatter = JsonFormatter::new();
        let pass_results = vec![PassResult::new("test").with_nodes(10)];
        let result =
            PipelineResult::from_pass_results(pass_results, Duration::from_millis(5), Vec::new());

        let output = formatter.format(&result);
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("JsonFormatter output must be valid JSON");
        assert!(
            parsed["total_issues"].is_number(),
            "Must contain total_issues"
        );
        assert!(
            parsed["pass_results"].is_array(),
            "Must contain pass_results array"
        );
    }

    /// Objective: Verify compact formatter produces non-pretty JSON.
    /// Invariants: Compact output must not contain newlines between fields.
    #[test]
    fn test_json_formatter_compact() {
        let formatter = JsonFormatter::compact();
        let pass_results = vec![PassResult::new("test")];
        let result =
            PipelineResult::from_pass_results(pass_results, Duration::from_millis(1), Vec::new());

        let output = formatter.format(&result);
        // Compact JSON should have fewer newlines than pretty.
        let pretty_output = JsonFormatter::new().format(&result);
        assert!(
            output.lines().count() < pretty_output.lines().count(),
            "Compact JSON must have fewer lines than pretty JSON"
        );
    }

    /// Objective: Verify findings_v2 is present when issues exist.
    /// Invariants: Output must contain findings_v2 array with FindingView entries.
    #[test]
    fn test_json_formatter_includes_findings_v2() {
        let formatter = JsonFormatter::new();
        let result = result_with_issue();

        let output = formatter.format(&result);
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("output must be valid JSON");

        let findings = &parsed["findings_v2"];
        assert!(findings.is_array(), "findings_v2 must be a JSON array");
        assert_eq!(
            findings.as_array().unwrap().len(),
            1,
            "findings_v2 must have one entry"
        );

        let entry = &findings[0];
        assert_eq!(entry["kind"], "cross_family_free");
        assert_eq!(entry["id"], "OMI-001");
        assert!(entry["title"].is_string(), "finding must have a title");
        assert!(entry["why"].is_string(), "finding must have a why field");
    }

    /// Objective: Verify findings_v2 contains title and resource_flow.
    /// Invariants: Each finding must have human-readable title and flow steps.
    #[test]
    fn test_json_findings_v2_has_title_and_flow() {
        let formatter = JsonFormatter::new();
        let result = result_with_issue();

        let output = formatter.format(&result);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let entry = &parsed["findings_v2"][0];
        let title = entry["title"].as_str().unwrap();
        assert!(
            title.contains("malloc"),
            "title must mention alloc function: got '{}'",
            title
        );

        let flow = &entry["resource_flow"];
        assert!(flow.is_array(), "resource_flow must be a JSON array");
    }

    /// Objective: Verify without_v2() suppresses findings_v2.
    /// Invariants: Output must not contain findings_v2 when disabled.
    #[test]
    fn test_json_formatter_without_v2() {
        let formatter = JsonFormatter::new().without_v2();
        let result = result_with_issue();

        let output = formatter.format(&result);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert!(
            parsed.get("findings_v2").is_none(),
            "findings_v2 must not be present when disabled"
        );
    }

    /// Objective: Verify findings_v2 is absent when no issues exist.
    /// Invariants: Empty result must not produce findings_v2 array.
    #[test]
    fn test_json_findings_v2_absent_when_no_issues() {
        let formatter = JsonFormatter::new();
        let result = PipelineResult::from_pass_results(
            vec![PassResult::new("test")],
            Duration::from_millis(1),
            Vec::new(),
        );

        let output = formatter.format(&result);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert!(
            parsed.get("findings_v2").is_none(),
            "findings_v2 must be absent when no issues exist"
        );
    }

    /// Objective: Verify verbose mode includes confidence_breakdown.
    /// Invariants: With verbose=true, each finding must have confidence_breakdown.
    #[test]
    fn test_json_verbose_confidence_breakdown() {
        let formatter = JsonFormatter::new().with_verbose(true);
        let result = result_with_issue();

        let output = formatter.format(&result);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let entry = &parsed["findings_v2"][0];
        assert!(
            entry["confidence_breakdown"].is_string(),
            "verbose mode must include confidence_breakdown"
        );
    }

    /// Objective: Verify backward compatibility — existing fields unchanged.
    /// Invariants: total_issues, issues, and pass_results must still be present.
    #[test]
    fn test_json_backward_compatible() {
        let formatter = JsonFormatter::new();
        let result = result_with_issue();

        let output = formatter.format(&result);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert!(
            parsed["total_issues"].is_number(),
            "total_issues must still be present"
        );
        assert!(parsed["issues"].is_array(), "issues must still be present");
        assert!(
            parsed["pass_results"].is_array(),
            "pass_results must still be present"
        );
    }
}
