//! SARIF (Static Analysis Results Interchange Format) output formatter.
//!
//! Produces SARIF v2.1.0 JSON compatible with GitHub Code Scanning,
//! Azure DevOps, and other SARIF consumers.
//!
//! Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use super::{issue_kind_label, OutputFormatter};
use omniscope_core::Issue;
use omniscope_pipeline::PipelineResult;
use serde_json::{json, Value};

/// SARIF v2.1.0 formatter for GitHub Code Scanning integration.
pub struct SarifFormatter;

/// Returns current UTC time as ISO 8601 string for SARIF invocation.
fn chrono_now() -> String {
    // Use std::time for simplicity — no chrono dependency needed
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}Z", secs)
}

impl SarifFormatter {
    /// Creates a new SARIF formatter.
    pub fn new() -> Self {
        Self
    }

    /// Builds a SARIF result object from an Issue.
    fn build_result(issue: &Issue) -> Value {
        let rule_id = format!("OMNI/{}", issue_kind_label(&issue.kind));

        // Message
        let message_text = if let Some(cwe) = issue.cwe_id {
            format!("{} (CWE-{})", issue.description, cwe)
        } else {
            issue.description.clone()
        };

        // Location
        let location = if let Some(ref loc) = issue.location {
            json!({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": loc.file.to_string_lossy()
                    },
                    "region": {
                        "startLine": loc.line,
                        "startColumn": loc.column.unwrap_or(1)
                    }
                }
            })
        } else {
            json!({
                "physicalLocation": {
                    "artifactLocation": { "uri": "unknown" },
                    "region": { "startLine": 1 }
                }
            })
        };

        // Code flows from trace entries
        let code_flows = if !issue.trace.is_empty() {
            let thread_flow = issue
                .trace
                .iter()
                .map(|entry| {
                    let loc = if let Some(ref tloc) = entry.location {
                        json!({
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": { "uri": tloc.file.to_string_lossy() },
                                    "region": { "startLine": tloc.line }
                                },
                                "message": { "text": entry.description }
                            }
                        })
                    } else {
                        json!({
                            "location": {
                                "message": { "text": entry.description }
                            }
                        })
                    };
                    loc
                })
                .collect::<Vec<_>>();

            json!([{
                "threadFlows": [{
                    "locations": thread_flow
                }]
            }])
        } else {
            json!([])
        };

        // Severity level mapping
        let level = if issue.severity.is_error() {
            "error"
        } else if issue.severity.is_warning() {
            "warning"
        } else {
            "note"
        };

        let mut result = json!({
            "ruleId": rule_id,
            "ruleIndex": 0,
            "level": level,
            "message": { "text": message_text },
            "locations": [location],
        });

        if !issue.trace.is_empty() {
            result["codeFlows"] = code_flows;
        }

        // FFI boundary as related location
        if let Some(ref ffi) = issue.ffi_boundary {
            result["relatedLocations"] = json!([{
                "message": {
                    "text": format!(
                        "FFI boundary: {} ({:?}) -> {} ({:?}) [{:?}]",
                        ffi.caller_name, ffi.caller_lang,
                        ffi.callee_name, ffi.callee_lang,
                        ffi.boundary_kind
                    )
                }
            }]);
        }

        result
    }

    /// Builds SARIF rule descriptors from all issue kinds.
    fn build_rules() -> Vec<Value> {
        use omniscope_core::IssueKind;
        let all_kinds = [
            IssueKind::CrossLanguageFree,
            IssueKind::OwnershipViolation,
            IssueKind::FfiTypeMismatch,
            IssueKind::AbiMismatch,
            IssueKind::UncheckedReturn,
            IssueKind::FfiUnsafeCall,
            IssueKind::CallbackEscape,
            IssueKind::DoubleFree,
            IssueKind::UseAfterFree,
            IssueKind::InvalidFree,
            IssueKind::MemoryLeak,
            IssueKind::BufferOverflow,
            IssueKind::NullDereference,
            IssueKind::IntegerOverflow,
            IssueKind::CrossFamilyFree,
            IssueKind::ConditionalLeak,
            IssueKind::BorrowEscape,
            IssueKind::CallbackEscapeIssue,
            IssueKind::NeedsModel,
            IssueKind::DataRace,
            IssueKind::LockOrderViolation,
            IssueKind::ThreadCrossing,
            IssueKind::Unknown,
        ];

        all_kinds
            .iter()
            .map(|kind| {
                let rule_id = format!("OMNI/{}", issue_kind_label(kind));
                let cwe = kind.cwe_id();
                let short_desc = format!("{:?} detected", kind);
                let full_desc = if let Some(cwe_id) = cwe {
                    format!("{} (CWE-{})", short_desc, cwe_id)
                } else {
                    short_desc.clone()
                };

                json!({
                    "id": rule_id,
                    "shortDescription": { "text": short_desc },
                    "fullDescription": { "text": full_desc },
                    "helpUri": format!(
                        "https://cwe.mitre.org/data/definitions/{}.html",
                        cwe.unwrap_or(0)
                    ),
                    "properties": {
                        "tags": if kind.is_ffi_boundary() {
                            json!(["ffi-boundary", "security"])
                        } else {
                            json!(["memory-safety", "security"])
                        }
                    }
                })
            })
            .collect()
    }
}

impl OutputFormatter for SarifFormatter {
    fn format(&self, result: &PipelineResult) -> String {
        let results: Vec<Value> = result.issues.iter().map(Self::build_result).collect();

        let sarif = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "OmniScope",
                        "version": env!("CARGO_PKG_VERSION"),
                        "semanticVersion": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/Timwood0x10/OmniScope-rs",
                        "rules": Self::build_rules(),
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": true,
                    "endTimeUtc": chrono_now(),
                }]
            }]
        });

        serde_json::to_string_pretty(&sarif)
            .unwrap_or_else(|e| format!("{{\"error\": \"SARIF serialization failed: {}\"}}", e))
    }
}

impl Default for SarifFormatter {
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

    /// Objective: Verify SarifFormatter produces valid SARIF v2.1.0 JSON.
    /// Invariants: Must contain $schema, version, runs with tool driver.
    #[test]
    fn test_sarif_structure() {
        let formatter = SarifFormatter::new();
        let pass_results = vec![PassResult::new("test")];
        let result = PipelineResult::from_pass_results(pass_results, Duration::from_millis(5));

        let output = formatter.format(&result);
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("SARIF output must be valid JSON");

        assert_eq!(parsed["version"], "2.1.0", "Must be SARIF v2.1.0");
        assert!(parsed["$schema"].is_string(), "Must contain $schema");
        assert!(parsed["runs"].is_array(), "Must contain runs array");
        assert_eq!(
            parsed["runs"][0]["tool"]["driver"]["name"], "OmniScope",
            "Tool name must be OmniScope"
        );
        assert!(
            parsed["runs"][0]["tool"]["driver"]["rules"].is_array(),
            "Must contain rule definitions"
        );
    }

    /// Objective: Verify SARIF result entries from issues.
    /// Invariants: Issues must produce results with ruleId, level, message, locations.
    #[test]
    fn test_sarif_with_issues() {
        let formatter = SarifFormatter::new();
        let issue = Issue::new(
            1,
            IssueKind::InvalidFree,
            Severity::Warning,
            "invalid free detected",
        )
        .with_confidence(Confidence::High)
        .with_location(omniscope_core::IssueLocation::new(
            std::path::PathBuf::from("test.c"),
            42,
        ));

        let mut pass_result = PassResult::new("FFIBoundary");
        pass_result.add_issue(issue);

        let result =
            PipelineResult::from_pass_results(vec![pass_result], Duration::from_millis(10));
        let output = formatter.format(&result);
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("SARIF with issues must be valid JSON");

        let results = &parsed["runs"][0]["results"];
        assert!(results.is_array(), "Must contain results array");
        assert_eq!(
            results.as_array().unwrap().len(),
            1,
            "Must have exactly 1 result"
        );
        assert_eq!(results[0]["level"], "warning", "Must have warning level");
        assert!(results[0]["ruleId"].is_string(), "Must have ruleId");
    }

    /// Objective: Verify SARIF code flows from trace entries.
    /// Invariants: Trace entries must produce codeFlows with threadFlows.
    #[test]
    fn test_sarif_code_flows() {
        let formatter = SarifFormatter::new();
        let mut issue = Issue::new(
            1,
            IssueKind::CrossLanguageFree,
            Severity::Error,
            "cross-lang free",
        );
        issue.add_trace(omniscope_core::TraceEntry::new("malloc called"));
        issue.add_trace(omniscope_core::TraceEntry::new("passed to operator_delete"));

        let mut pass_result = PassResult::new("FFIBoundary");
        pass_result.add_issue(issue);

        let result = PipelineResult::from_pass_results(vec![pass_result], Duration::from_millis(5));
        let output = formatter.format(&result);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let code_flows = &parsed["runs"][0]["results"][0]["codeFlows"];
        assert!(code_flows.is_array(), "Must contain codeFlows array");
        assert!(
            !code_flows.as_array().unwrap().is_empty(),
            "codeFlows must not be empty"
        );
    }
}
