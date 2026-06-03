//! JSON output formatter for CI/CD integration.
//!
//! Produces a structured JSON object containing all analysis results,
//! suitable for machine consumption in CI/CD pipelines.

use super::OutputFormatter;
use omniscope_pipeline::PipelineResult;

/// JSON formatter producing serde-serialized output.
pub struct JsonFormatter {
    /// Whether to pretty-print the JSON output.
    pub pretty: bool,
}

impl JsonFormatter {
    /// Creates a new JSON formatter.
    pub fn new() -> Self {
        Self { pretty: true }
    }

    /// Creates a compact JSON formatter (no pretty-printing).
    ///
    /// Use for CI pipelines where compact output is preferred.
    pub fn compact() -> Self {
        Self { pretty: false }
    }

    /// Creates a formatter from the pretty flag.
    pub fn from_pretty(pretty: bool) -> Self {
        Self { pretty }
    }
}

impl OutputFormatter for JsonFormatter {
    fn format(&self, result: &PipelineResult) -> String {
        if self.pretty {
            serde_json::to_string_pretty(result)
                .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize result: {}\"}}", e))
        } else {
            serde_json::to_string(result)
                .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize result: {}\"}}", e))
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
    use omniscope_pass::PassResult;
    use std::time::Duration;

    /// Objective: Verify JsonFormatter produces valid JSON output.
    /// Invariants: Output must parse as valid JSON with expected fields.
    #[test]
    fn test_json_formatter_valid_json() {
        let formatter = JsonFormatter::new();
        let pass_results = vec![PassResult::new("test").with_nodes(10)];
        let result = PipelineResult::from_pass_results(
            pass_results,
            Duration::from_millis(5),
            Vec::new(), // No pass timings in test
        );

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
        let result = PipelineResult::from_pass_results(
            pass_results,
            Duration::from_millis(1),
            Vec::new(), // No pass timings in test
        );

        let output = formatter.format(&result);
        // Compact JSON should have fewer newlines than pretty
        let pretty_output = JsonFormatter::new().format(&result);
        assert!(
            output.lines().count() < pretty_output.lines().count(),
            "Compact JSON must have fewer lines than pretty JSON"
        );
    }
}
