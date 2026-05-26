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
