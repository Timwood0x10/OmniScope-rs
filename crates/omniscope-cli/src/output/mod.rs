//! Output formatting for analysis results.
//!
//! Supports three output formats:
//! - **Rich Terminal** (default): colored, tabular, with detection paths
//! - **JSON**: machine-readable for CI/CD pipelines
//! - **SARIF**: GitHub Code Scanning integration

pub mod json;
pub mod rich;
pub mod sarif;

use omniscope_core::Issue;
use omniscope_pipeline::PipelineResult;

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Rich terminal output with colors and tables.
    Rich,
    /// JSON output for machine consumption.
    Json,
    /// SARIF output for GitHub Code Scanning.
    Sarif,
}

impl OutputFormat {
    /// Parse from string (case-insensitive).
    pub fn from_str_ignore_case(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "sarif" => OutputFormat::Sarif,
            _ => OutputFormat::Rich,
        }
    }
}

/// Trait for output formatters.
pub trait OutputFormatter {
    /// Format the pipeline result for display.
    fn format(&self, result: &PipelineResult) -> String;
}

/// Format a single issue ID as OMI-NNN.
pub fn format_issue_id(id: u64) -> String {
    format!("OMI-{:03}", id)
}

/// Classify issue severity as HIGH/LOW for display.
pub fn severity_label(issue: &Issue) -> &'static str {
    if issue.severity.is_error() || issue.severity.is_warning() {
        "HIGH"
    } else {
        "LOW"
    }
}

/// Convert IssueKind to a snake_case string for display.
pub fn issue_kind_label(kind: &omniscope_core::IssueKind) -> &'static str {
    use omniscope_core::IssueKind;
    match kind {
        IssueKind::CrossLanguageFree => "cross_language_free",
        IssueKind::OwnershipViolation => "ownership_violation",
        IssueKind::FfiTypeMismatch => "ffi_type_mismatch",
        IssueKind::AbiMismatch => "abi_mismatch",
        IssueKind::UncheckedReturn => "unchecked_return",
        IssueKind::FfiUnsafeCall => "ffi_unsafe_call",
        IssueKind::CallbackEscape => "callback_escape",
        IssueKind::LengthTruncation => "length_truncation",
        IssueKind::DoubleFree => "double_free",
        IssueKind::UseAfterFree => "use_after_free",
        IssueKind::InvalidFree => "invalid_free",
        IssueKind::MemoryLeak => "memory_leak",
        IssueKind::BufferOverflow => "buffer_overflow",
        IssueKind::NullDereference => "null_dereference",
        IssueKind::IntegerOverflow => "integer_overflow",
        IssueKind::CrossFamilyFree => "cross_family_free",
        IssueKind::ConditionalLeak => "conditional_leak",
        IssueKind::BorrowEscape => "borrow_escape",
        IssueKind::CallbackEscapeIssue => "callback_escape_issue",
        IssueKind::NeedsModel => "needs_model",
        IssueKind::DataRace => "data_race",
        IssueKind::LockOrderViolation => "lock_order_violation",
        IssueKind::ThreadCrossing => "thread_crossing",
        IssueKind::WriteToImmutable => "write_to_immutable",
        IssueKind::DoubleReclaim => "double_reclaim",
        IssueKind::OwnershipEscapeLeak => "ownership_escape_leak",
        IssueKind::Unknown => "unknown",
    }
}

/// Convert Confidence to display string with percentage.
pub fn confidence_label(confidence: &omniscope_core::Confidence) -> String {
    use omniscope_core::Confidence;
    match confidence {
        Confidence::High => "HIGH (100%)".to_string(),
        Confidence::Medium => "MEDIUM (85%)".to_string(),
        Confidence::Low => "HEURISTIC (50%)".to_string(),
    }
}
