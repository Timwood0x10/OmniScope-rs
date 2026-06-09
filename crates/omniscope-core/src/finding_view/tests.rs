use super::*;
use crate::diagnostics::Severity;
use crate::issue::{FFIBoundary, IssueLocation, TraceEntry};
use omniscope_types::config::Language;

/// Helper: builds a minimal issue for testing.
fn make_issue(kind: IssueKind, description: &str) -> Issue {
    Issue::new(3, kind, Severity::Error, description)
}

/// Helper: builds a cross-family issue with alloc/release description.
fn make_cross_family_issue() -> Issue {
    Issue::new(
        3,
        IssueKind::CrossFamilyFree,
        Severity::Error,
        "c_heap allocated by malloc released as sqlite3_free",
    )
    .with_location(
        IssueLocation::new(std::path::PathBuf::from("test.c"), 42)
            .with_function("library_family_mismatch"),
    )
    .with_ffi_boundary(FFIBoundary {
        caller_name: "library_family_mismatch".to_string(),
        callee_name: "sqlite3_free".to_string(),
        caller_lang: Language::C,
        callee_lang: Language::C,
        boundary_kind: crate::issue::BoundaryKind::Unknown,
    })
}

// ---- Title generation tests ----

#[test]
fn test_title_cross_family_with_alloc_and_release() {
    let issue = make_cross_family_issue();
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(
        view.title, "malloc buffer released by sqlite3_free",
        "title must combine alloc and release function names"
    );
}

#[test]
fn test_title_cross_family_alloc_only() {
    let issue = make_issue(
        IssueKind::CrossFamilyFree,
        "c_heap allocated by malloc released incorrectly",
    );
    let view = FindingView::from_issue(&issue, false, false);
    assert!(
        view.title.contains("malloc"),
        "title must include alloc function: got '{}'",
        view.title
    );
}

#[test]
fn test_title_cross_family_no_functions() {
    let issue = make_issue(IssueKind::CrossFamilyFree, "family mismatch detected");
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(
        view.title, "cross-family resource release",
        "title must use fallback when no function names are available"
    );
}

#[test]
fn test_title_double_free_conditional() {
    let issue = make_issue(
        IssueKind::DoubleFree,
        "conditional double free on error path",
    );
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(
        view.title, "conditional double free of same pointer",
        "title must detect conditional double-free"
    );
}

#[test]
fn test_title_double_free_plain() {
    let issue = make_issue(IssueKind::DoubleFree, "double free detected");
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(
        view.title, "double free of same pointer",
        "title for plain double-free"
    );
}

#[test]
fn test_title_conditional_leak_error_path() {
    let issue = make_issue(
        IssueKind::ConditionalLeak,
        "allocation may leak on error path",
    );
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(
        view.title, "allocation may leak on error path",
        "title must detect error-path leak"
    );
}

#[test]
fn test_title_definite_leak_with_alloc() {
    let issue = make_issue(
        IssueKind::DefiniteLeak,
        "c_heap allocated by malloc never freed",
    );
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(
        view.title, "malloc allocation never freed",
        "title must include alloc function for definite leak"
    );
}

#[test]
fn test_title_use_after_free_with_null_check() {
    let issue = make_issue(
        IssueKind::UseAfterFree,
        "pointer used before null check after free",
    );
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(
        view.title, "pointer used before null check after free",
        "title must detect null-check UAF pattern"
    );
}

#[test]
fn test_title_unchecked_return_with_ffi() {
    let issue =
        make_issue(IssueKind::UncheckedReturn, "unchecked return").with_ffi_boundary(FFIBoundary {
            caller_name: "caller".to_string(),
            callee_name: "malloc".to_string(),
            caller_lang: Language::C,
            callee_lang: Language::C,
            boundary_kind: crate::issue::BoundaryKind::Unknown,
        });
    let view = FindingView::from_issue(&issue, false, false);
    assert!(
        view.title.contains("malloc"),
        "title must include FFI callee name: got '{}'",
        view.title
    );
}

// ---- Resource flow tests ----

#[test]
fn test_resource_flow_from_description() {
    let issue = make_cross_family_issue();
    let view = FindingView::from_issue(&issue, false, false);
    // Description-based flow: alloc step + release step.
    assert!(
        !view.resource_flow.is_empty(),
        "resource flow must not be empty for cross-family issue"
    );
    let alloc_step = view.resource_flow.iter().find(|s| s.operation == "alloc");
    let release_step = view.resource_flow.iter().find(|s| s.operation == "release");
    assert!(alloc_step.is_some(), "flow must contain an alloc step");
    assert!(release_step.is_some(), "flow must contain a release step");
}

#[test]
fn test_resource_flow_from_trace() {
    let mut issue = make_cross_family_issue();
    // Add trace entries to override description-based flow.
    issue.add_trace(TraceEntry::new("malloc(len) alloc step family=C_HEAP"));
    issue.add_trace(TraceEntry::new(
        "sqlite3_free(buf) release step family=SQLITE_RESOURCE",
    ));
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(
        view.resource_flow.len(),
        2,
        "trace-based flow must have 2 steps"
    );
    assert_eq!(view.resource_flow[0].operation, "alloc");
    assert_eq!(view.resource_flow[1].operation, "release");
}

#[test]
fn test_resource_flow_family_extraction_from_trace() {
    let mut issue = make_issue(IssueKind::CrossFamilyFree, "family mismatch");
    issue.add_trace(TraceEntry::new("malloc(len) alloc family=C_HEAP"));
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(
        view.resource_flow[0].family,
        Some("C_HEAP".to_string()),
        "family must be extracted from trace description"
    );
}

// ---- Why/evidence/fix tests ----

#[test]
fn test_why_cross_family_with_functions() {
    let issue = make_cross_family_issue();
    let view = FindingView::from_issue(&issue, false, false);
    assert!(
        view.why.contains("sqlite3_free"),
        "why must mention release function"
    );
    assert!(
        view.why.contains("malloc"),
        "why must mention alloc function"
    );
}

#[test]
fn test_why_double_free() {
    let issue = make_issue(IssueKind::DoubleFree, "double free");
    let view = FindingView::from_issue(&issue, false, false);
    assert!(
        view.why.contains("freed twice"),
        "why for DoubleFree must mention double free"
    );
}

#[test]
fn test_evidence_from_ffi_boundary() {
    let issue = make_cross_family_issue();
    let view = FindingView::from_issue(&issue, false, false);
    assert!(
        view.evidence.iter().any(|e| e.contains("FFI boundary")),
        "evidence must include FFI boundary info"
    );
}

#[test]
fn test_evidence_from_description_patterns() {
    let issue = make_issue(
        IssueKind::CrossFamilyFree,
        "same resource instance, incompatible families, reachable release",
    );
    let view = FindingView::from_issue(&issue, false, false);
    assert!(
        view.evidence
            .iter()
            .any(|e| e.contains("same resource instance")),
        "evidence must detect same-resource pattern"
    );
    assert!(
        view.evidence
            .iter()
            .any(|e| e.contains("incompatible resource families")),
        "evidence must detect incompatible-families pattern"
    );
}

#[test]
fn test_fix_hint_cross_family() {
    let issue = make_cross_family_issue();
    let view = FindingView::from_issue(&issue, false, false);
    let hint = view.fix_hint.expect("cross-family must have fix hint");
    assert!(
        hint.contains("malloc") || hint.contains("sqlite3_free"),
        "fix hint must mention relevant functions: got '{}'",
        hint
    );
}

#[test]
fn test_fix_hint_double_free() {
    let issue = make_issue(IssueKind::DoubleFree, "double free");
    let view = FindingView::from_issue(&issue, false, false);
    assert!(view.fix_hint.is_some(), "DoubleFree must have fix hint");
}

#[test]
fn test_fix_hint_unknown_is_none() {
    let issue = make_issue(IssueKind::Unknown, "unknown issue");
    let view = FindingView::from_issue(&issue, false, false);
    assert!(
        view.fix_hint.is_none(),
        "Unknown issue must not have fix hint"
    );
}

// ---- Confidence and severity tests ----

#[test]
fn test_confidence_high() {
    let issue = make_issue(IssueKind::DoubleFree, "double free").with_confidence(Confidence::High);
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(view.confidence, "100%");
}

#[test]
fn test_confidence_medium() {
    let issue =
        make_issue(IssueKind::DoubleFree, "double free").with_confidence(Confidence::Medium);
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(view.confidence, "85%");
}

#[test]
fn test_confidence_low() {
    let issue = make_issue(IssueKind::DoubleFree, "double free").with_confidence(Confidence::Low);
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(view.confidence, "50%");
}

#[test]
fn test_severity_error_is_high() {
    let issue = make_issue(IssueKind::DoubleFree, "double free");
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(view.severity, "HIGH");
}

#[test]
fn test_severity_note_is_low() {
    let issue = Issue::new(1, IssueKind::NeedsModel, Severity::Note, "needs model");
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(view.severity, "LOW");
}

// ---- Verbose and debug mode tests ----

#[test]
fn test_verbose_mode_confidence_breakdown() {
    let issue = make_cross_family_issue();
    let view = FindingView::from_issue(&issue, true, false);
    assert!(
        view.confidence_breakdown.is_some(),
        "verbose mode must populate confidence_breakdown"
    );
    let bd = view.confidence_breakdown.unwrap();
    assert!(
        bd.contains("base="),
        "breakdown must contain base confidence"
    );
}

#[test]
fn test_non_verbose_no_confidence_breakdown() {
    let issue = make_cross_family_issue();
    let view = FindingView::from_issue(&issue, false, false);
    assert!(
        view.confidence_breakdown.is_none(),
        "non-verbose must not populate confidence_breakdown"
    );
}

// ---- ID formatting test ----

#[test]
fn test_id_formatting() {
    let issue = make_issue(IssueKind::DoubleFree, "double free");
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(view.id, "OMI-003", "ID must be formatted as OMI-NNN");
}

// ---- CWE test ----

#[test]
fn test_cwe_in_view() {
    let issue = make_issue(IssueKind::CrossFamilyFree, "test");
    // cwe_id is auto-populated from IssueKind::cwe_id() in Issue::new().
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(view.cwe, Some("CWE-762".to_string()));
}

// ---- Kind snake_case test ----

#[test]
fn test_kind_snake_case() {
    let issue = make_issue(IssueKind::CrossFamilyFree, "test");
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(view.kind, "cross_family_free");
}

// ---- Extract helper tests ----

#[test]
fn test_extract_alloc_release_standard() {
    let (alloc, release) =
        extract_alloc_release("c_heap allocated by malloc released as sqlite3_free");
    assert_eq!(alloc, Some("malloc".to_string()));
    assert_eq!(release, Some("sqlite3_free".to_string()));
}

#[test]
fn test_extract_alloc_release_alloc_from() {
    let (alloc, release) = extract_alloc_release("allocated from my_alloc released by my_free");
    assert_eq!(alloc, Some("my_alloc".to_string()));
    assert_eq!(release, Some("my_free".to_string()));
}

#[test]
fn test_extract_alloc_release_no_markers() {
    let (alloc, release) = extract_alloc_release("some description without markers");
    assert_eq!(alloc, None);
    assert_eq!(release, None);
}

#[test]
fn test_sanitize_display_function() {
    assert_eq!(sanitize_display_function("%call1"), "return value1");
    assert_eq!(sanitize_display_function("  'malloc'  "), "malloc");
    assert_eq!(sanitize_display_function("free"), "free");
}

// ---- Function field test ----

#[test]
fn test_function_from_location() {
    let issue = make_cross_family_issue();
    let view = FindingView::from_issue(&issue, false, false);
    assert_eq!(
        view.function,
        Some("library_family_mismatch".to_string()),
        "function must come from issue location"
    );
}

#[test]
fn test_function_none_when_empty() {
    let issue = make_issue(IssueKind::DoubleFree, "double free");
    let view = FindingView::from_issue(&issue, false, false);
    assert!(
        view.function.is_none(),
        "function must be None when no location is set"
    );
}
