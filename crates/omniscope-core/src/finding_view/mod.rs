//! Display-only presentation model for analysis findings.
//!
//! `FindingView` transforms the internal `Issue` representation into a
//! human-readable format that does not require knowledge of the pass
//! pipeline. It generates a title, resource flow, explanation, and
//! fix hints from the structured issue data.
//!
//! This module is display-only: it does not change `Issue` serialization
//! or affect the verifier pipeline. Existing JSON and SARIF outputs
//! remain backward-compatible.

use crate::issue::{Confidence, Issue, IssueKind};
use serde::Serialize;

/// A single step in the resource ownership flow.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceFlowStep {
    /// Step number (1-based).
    pub step: usize,
    /// Operation type: alloc, use, release, escape, exit.
    pub operation: &'static str,
    /// Function performing the operation.
    pub function: String,
    /// Resource family for this step (e.g., "C_HEAP", "CPP_NEW").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Enclosing caller function (if different from operation function).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
    /// Evidence source for this step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_source: Option<String>,
}

/// Display-only presentation of a single finding.
///
/// This type is constructed from an `Issue` and carries derived
/// human-readable fields (title, why, fix_hint, etc.) that are
/// computed at formatting time. It is not stored in the pipeline
/// result and does not affect backward compatibility.
#[derive(Debug, Clone, Serialize)]
pub struct FindingView {
    /// Issue ID formatted as OMI-NNN.
    pub id: String,
    /// Issue kind in snake_case.
    pub kind: String,
    /// Human-readable title (e.g., "malloc buffer released by sqlite3_free").
    pub title: String,
    /// Severity label (HIGH / LOW).
    pub severity: String,
    /// Confidence as a percentage string.
    pub confidence: String,
    /// CWE identifier (e.g., "CWE-762").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// Function where the issue was detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Resource ownership flow steps.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resource_flow: Vec<ResourceFlowStep>,
    /// Explanation of why this is an issue.
    pub why: String,
    /// Evidence supporting this finding.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Suggested fix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_hint: Option<String>,
    /// Suppression reason (only in debug/suppressed output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_reason: Option<String>,
    /// Confidence breakdown (only in verbose mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_breakdown: Option<String>,
}

impl FindingView {
    /// Builds a `FindingView` from an `Issue`.
    ///
    /// The `verbose` flag controls whether `confidence_breakdown` is
    /// populated. The `debug` flag controls whether `suppression_reason`
    /// is included for suppressed issues.
    pub fn from_issue(issue: &Issue, verbose: bool, debug: bool) -> Self {
        let id = format!("OMI-{:03}", issue.id);
        let kind = issue_kind_snake(&issue.kind).to_string();
        let title = generate_title(issue);
        let severity = if issue.severity.is_error() || issue.severity.is_warning() {
            "HIGH"
        } else {
            "LOW"
        }
        .to_string();
        let confidence = confidence_pct(&issue.confidence);
        let cwe = issue.cwe_id.map(|id| format!("CWE-{}", id));
        let function = issue
            .location
            .as_ref()
            .and_then(|loc| loc.function.clone())
            .or_else(|| {
                issue
                    .ffi_boundary
                    .as_ref()
                    .map(|ffi| ffi.caller_name.clone())
            })
            .filter(|f| !f.is_empty());
        let resource_flow = build_resource_flow(issue);
        let why = generate_why(issue);
        let evidence = collect_evidence(issue);
        let fix_hint = generate_fix_hint(issue);
        // Suppression reason: when debug mode is set, extract from
        // issue.description or trace if the issue was partially suppressed
        // (downgraded) by the verifier. Fully-suppressed (ExplainedSafe)
        // candidates don't reach this point — only downgraded issues
        // carry suppression markers in their description.
        let suppression_reason = if debug {
            extract_suppression_reason(issue)
        } else {
            None
        };
        let confidence_breakdown = if verbose {
            Some(format_confidence_breakdown(issue))
        } else {
            None
        };

        Self {
            id,
            kind,
            title,
            severity,
            confidence,
            cwe,
            function,
            resource_flow,
            why,
            evidence,
            fix_hint,
            suppression_reason,
            confidence_breakdown,
        }
    }
}

/// Maps an IssueKind to a snake_case string for display.
fn issue_kind_snake(kind: &IssueKind) -> &'static str {
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
        IssueKind::DefiniteLeak => "definite_leak",
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

/// Generates a human-readable title from an issue.
///
/// The title describes the core problem in one line, using function
/// names extracted from the issue description and FFI boundary.
fn generate_title(issue: &Issue) -> String {
    match issue.kind {
        IssueKind::CrossFamilyFree | IssueKind::CrossLanguageFree => title_cross_family(issue),
        IssueKind::DoubleFree => title_double_free(issue),
        IssueKind::UseAfterFree => title_use_after_free(issue),
        IssueKind::ConditionalLeak | IssueKind::MemoryLeak => title_conditional_leak(issue),
        IssueKind::DefiniteLeak => title_definite_leak(issue),
        IssueKind::InvalidFree => title_invalid_free(issue),
        IssueKind::BufferOverflow => "buffer overflow detected".to_string(),
        IssueKind::NullDereference => "null pointer dereference".to_string(),
        IssueKind::IntegerOverflow => "integer overflow detected".to_string(),
        IssueKind::BorrowEscape => "borrowed pointer escaped to owning context".to_string(),
        IssueKind::CallbackEscapeIssue => {
            "pointer escaped to callback assuming ownership".to_string()
        }
        IssueKind::OwnershipViolation => "ownership transfer violation".to_string(),
        IssueKind::FfiTypeMismatch => "FFI type mismatch at boundary".to_string(),
        IssueKind::AbiMismatch => "ABI calling convention mismatch".to_string(),
        IssueKind::UncheckedReturn => title_unchecked_return(issue),
        IssueKind::FfiUnsafeCall => "potentially dangerous FFI call".to_string(),
        IssueKind::CallbackEscape => "callback escape across language boundary".to_string(),
        IssueKind::LengthTruncation => "length truncation detected".to_string(),
        IssueKind::NeedsModel => "resource needs model annotation".to_string(),
        IssueKind::DataRace => "data race across FFI boundary".to_string(),
        IssueKind::LockOrderViolation => "lock ordering violation".to_string(),
        IssueKind::ThreadCrossing => "thread crossing with unsafe pointer".to_string(),
        IssueKind::WriteToImmutable => "write to immutable memory".to_string(),
        IssueKind::DoubleReclaim => "raw pointer reclaimed multiple times".to_string(),
        IssueKind::OwnershipEscapeLeak => {
            "ownership escaped via into_raw without from_raw".to_string()
        }
        IssueKind::Unknown => "unknown issue detected".to_string(),
    }
}

/// Extracts alloc/release function names from issue description.
///
/// The description typically follows patterns like:
/// "c_heap allocated by malloc ... released as cpp_new_scalar"
fn extract_alloc_release(desc: &str) -> (Option<String>, Option<String>) {
    let alloc_fn = extract_after_alloc_by(desc);
    let release_fn = extract_after_released_as(desc);
    (alloc_fn, release_fn)
}

/// Extracts the allocation function name after "allocated by" or "allocated from".
fn extract_after_alloc_by(desc: &str) -> Option<String> {
    let lower = desc.to_lowercase();
    let marker = if lower.contains("allocated by ") {
        "allocated by "
    } else if lower.contains("allocated from ") {
        "allocated from "
    } else {
        return None;
    };
    let start = lower.find(marker)? + marker.len();
    let rest = &desc[start..];
    // Take until whitespace or common separator.
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',')
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Extracts the release function name after "released as" or "released by".
fn extract_after_released_as(desc: &str) -> Option<String> {
    let lower = desc.to_lowercase();
    let marker = if lower.contains("released as ") {
        "released as "
    } else if lower.contains("released by ") {
        "released by "
    } else {
        return None;
    };
    let start = lower.find(marker)? + marker.len();
    let rest = &desc[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',')
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Title for cross-family/cross-language free issues.
fn title_cross_family(issue: &Issue) -> String {
    let (alloc_fn, release_fn) = extract_alloc_release(&issue.description);
    match (alloc_fn, release_fn) {
        (Some(alloc), Some(release)) => {
            format!("{} buffer released by {}", alloc, release)
        }
        (Some(alloc), None) => {
            if let Some(ref ffi) = issue.ffi_boundary {
                format!("{} buffer released by {}", alloc, ffi.callee_name)
            } else {
                format!("{} buffer released by mismatched deallocator", alloc)
            }
        }
        (None, Some(release)) => {
            format!("allocation released by mismatched {}", release)
        }
        (None, None) => "cross-family resource release".to_string(),
    }
}

/// Title for double-free issues.
fn title_double_free(issue: &Issue) -> String {
    if issue.description.contains("conditional") {
        "conditional double free of same pointer".to_string()
    } else {
        "double free of same pointer".to_string()
    }
}

/// Title for use-after-free issues.
fn title_use_after_free(issue: &Issue) -> String {
    let desc = &issue.description;
    if desc.contains("null check") || desc.contains("null-check") {
        "pointer used before null check after free".to_string()
    } else {
        "use after free".to_string()
    }
}

/// Title for conditional leak / memory leak issues.
fn title_conditional_leak(issue: &Issue) -> String {
    let desc = &issue.description;
    if desc.contains("error path") || desc.contains("error-path") {
        "allocation may leak on error path".to_string()
    } else if desc.contains("early return") {
        "allocation may leak on early return".to_string()
    } else {
        "allocation may leak".to_string()
    }
}

/// Title for definite leak issues.
fn title_definite_leak(issue: &Issue) -> String {
    let (alloc_fn, _) = extract_alloc_release(&issue.description);
    match alloc_fn {
        Some(alloc) => format!("{} allocation never freed", alloc),
        None => "allocation never freed".to_string(),
    }
}

/// Title for invalid free issues.
fn title_invalid_free(issue: &Issue) -> String {
    let desc = &issue.description;
    if desc.contains("borrowed") {
        "free of borrowed pointer".to_string()
    } else {
        "invalid free".to_string()
    }
}

/// Title for unchecked FFI return issues.
fn title_unchecked_return(issue: &Issue) -> String {
    let desc = &issue.description;
    if let Some(ref ffi) = issue.ffi_boundary {
        format!(
            "FFI pointer from {} used before null check",
            ffi.callee_name
        )
    } else if desc.contains("null") {
        "FFI pointer used before null check".to_string()
    } else {
        "unchecked FFI return value".to_string()
    }
}

/// Builds the resource flow steps from an issue.
///
/// The flow is derived from trace entries and FFI boundary metadata.
fn build_resource_flow(issue: &Issue) -> Vec<ResourceFlowStep> {
    let mut steps = Vec::new();
    let mut step_num = 1;

    // If the issue has trace entries, use them to build the flow.
    if !issue.trace.is_empty() {
        for entry in &issue.trace {
            let desc = &entry.description;
            let (operation, function) = classify_trace_entry(desc);
            steps.push(ResourceFlowStep {
                step: step_num,
                operation,
                function: sanitize_display_function(&function),
                family: extract_family_from_trace(desc),
                caller: None,
                evidence_source: entry
                    .location
                    .as_ref()
                    .map(|loc| format!("{}:{}", loc.file.display(), loc.line)),
            });
            step_num += 1;
        }
        return steps;
    }

    // Fallback: derive from description and FFI boundary.
    let (alloc_fn, release_fn) = extract_alloc_release(&issue.description);
    if let Some(alloc) = alloc_fn {
        steps.push(ResourceFlowStep {
            step: step_num,
            operation: "alloc",
            function: sanitize_display_function(&alloc),
            family: extract_family_from_description(&issue.description, true),
            caller: None,
            evidence_source: None,
        });
        step_num += 1;
    }
    if let Some(release) = release_fn {
        steps.push(ResourceFlowStep {
            step: step_num,
            operation: "release",
            function: sanitize_display_function(&release),
            family: extract_family_from_description(&issue.description, false),
            caller: None,
            evidence_source: None,
        });
    }

    steps
}

/// Classifies a trace entry description into an operation and function name.
fn classify_trace_entry(desc: &str) -> (&'static str, String) {
    let lower = desc.to_lowercase();
    if lower.contains("alloc")
        || lower.contains("malloc")
        || lower.contains("new")
        || lower.contains("create")
    {
        ("alloc", desc.to_string())
    } else if lower.contains("free")
        || lower.contains("delete")
        || lower.contains("release")
        || lower.contains("drop")
    {
        ("release", desc.to_string())
    } else if lower.contains("escape") || lower.contains("return") || lower.contains("out-param") {
        ("escape", desc.to_string())
    } else {
        // Covers "use", "access", "dereference", and any
        // unclassified operation — default to "use".
        ("use", desc.to_string())
    }
}

/// Sanitizes function names for display by removing IR-level noise.
fn sanitize_display_function(name: &str) -> String {
    // Strip LLVM IR variable prefixes.
    let result = name.replace("%call", "return value").replace('%', "");
    // Trim leading/trailing whitespace and quotes.
    let result = result.trim().trim_matches('\'').trim_matches('"');
    result.to_string()
}

/// Extracts resource family name from trace description.
fn extract_family_from_trace(desc: &str) -> Option<String> {
    // Look for "family=XXX" patterns in trace descriptions.
    if let Some(start) = desc.find("family=") {
        let rest = &desc[start + 7..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == ',' || c == ')')
            .unwrap_or(rest.len());
        Some(rest[..end].to_string())
    } else {
        None
    }
}

/// Extracts resource family from issue description.
fn extract_family_from_description(desc: &str, is_alloc: bool) -> Option<String> {
    let lower = desc.to_lowercase();
    if is_alloc {
        if lower.contains("c_heap") {
            return Some("C_HEAP".to_string());
        }
        if lower.contains("cpp_new") {
            return Some("CPP_NEW".to_string());
        }
        if lower.contains("rust_global") {
            return Some("RUST_GLOBAL".to_string());
        }
        if lower.contains("python") || lower.contains("pymem") {
            return Some("PYTHON_MEM".to_string());
        }
        if lower.contains("_cgo") {
            return Some("GO_GC".to_string());
        }
    } else {
        if lower.contains("cpp_new_scalar") || lower.contains("operator delete") {
            return Some("CPP_NEW_SCALAR".to_string());
        }
        if lower.contains("sqlite3") {
            return Some("SQLITE_RESOURCE".to_string());
        }
    }
    None
}

/// Generates the "why" explanation for an issue.
fn generate_why(issue: &Issue) -> String {
    match issue.kind {
        IssueKind::CrossFamilyFree | IssueKind::CrossLanguageFree => {
            why_cross_family(issue)
        }
        IssueKind::DoubleFree => {
            "The same pointer is freed twice, which corrupts the heap allocator metadata.".to_string()
        }
        IssueKind::UseAfterFree => {
            "A pointer is dereferenced after its allocation has been freed, leading to undefined behavior.".to_string()
        }
        IssueKind::ConditionalLeak | IssueKind::MemoryLeak => {
            why_leak(issue)
        }
        IssueKind::DefiniteLeak => {
            "An allocation is never freed on any analyzed execution path, resulting in a memory leak.".to_string()
        }
        IssueKind::InvalidFree => {
            "A pointer that was not returned by the matching allocation function is being freed.".to_string()
        }
        IssueKind::BufferOverflow => {
            "A write operation exceeds the allocated buffer bounds.".to_string()
        }
        IssueKind::NullDereference => {
            "A potentially null pointer is dereferenced without a prior null check.".to_string()
        }
        IssueKind::IntegerOverflow => {
            "An arithmetic operation may overflow, leading to incorrect allocation sizes.".to_string()
        }
        IssueKind::BorrowEscape => {
            "A borrowed reference escapes to a context that assumes ownership, potentially causing a double-free.".to_string()
        }
        IssueKind::CallbackEscapeIssue => {
            "A pointer is passed to a callback that may assume ownership, risking double-free or use-after-free.".to_string()
        }
        IssueKind::OwnershipViolation => {
            "Ownership semantics are violated across a boundary, potentially causing resource leaks or double-free.".to_string()
        }
        IssueKind::FfiTypeMismatch => {
            "The types used at the FFI boundary are incompatible, leading to undefined behavior.".to_string()
        }
        IssueKind::AbiMismatch => {
            "The calling conventions at the FFI boundary do not match, causing stack corruption or misaligned data.".to_string()
        }
        IssueKind::UncheckedReturn => {
            "An FFI call that may return an error or null pointer is used without checking the return value.".to_string()
        }
        IssueKind::FfiUnsafeCall => {
            "An FFI call with potentially dangerous semantics is performed without adequate safety checks.".to_string()
        }
        IssueKind::CallbackEscape => {
            "A callback escapes across a language boundary, potentially leading to use-after-free.".to_string()
        }
        IssueKind::LengthTruncation => {
            "A length value is truncated when crossing a type boundary, potentially leading to buffer overflows.".to_string()
        }
        IssueKind::NeedsModel => {
            "The resource management pattern is unclear and needs an explicit annotation to verify safety.".to_string()
        }
        IssueKind::DataRace => {
            "Concurrent access to shared data across an FFI boundary without synchronization.".to_string()
        }
        IssueKind::LockOrderViolation => {
            "Locks are acquired in inconsistent order across threads, risking deadlock.".to_string()
        }
        IssueKind::ThreadCrossing => {
            "An unsafe pointer is shared across thread boundaries without synchronization.".to_string()
        }
        IssueKind::WriteToImmutable => {
            "A write is attempted to memory that is marked as immutable.".to_string()
        }
        IssueKind::DoubleReclaim => {
            "The same raw pointer is reclaimed via from_raw multiple times, which is a double-free variant.".to_string()
        }
        IssueKind::OwnershipEscapeLeak => {
            "Ownership escapes via into_raw but is never reclaimed via from_raw, causing a leak.".to_string()
        }
        IssueKind::Unknown => {
            "An unknown issue was detected.".to_string()
        }
    }
}

/// Why explanation for cross-family/cross-language free issues.
fn why_cross_family(issue: &Issue) -> String {
    let (alloc_fn, release_fn) = extract_alloc_release(&issue.description);
    match (alloc_fn, release_fn) {
        (Some(alloc), Some(release)) => {
            format!(
                "{} expects memory from its own allocator, but this pointer came from {}.",
                release, alloc
            )
        }
        (Some(alloc), None) => {
            format!(
                "The release function expects differently-managed memory, but this pointer came from {}.",
                alloc
            )
        }
        _ => "The release function is incompatible with the allocation family.".to_string(),
    }
}

/// Why explanation for leak issues.
fn why_leak(issue: &Issue) -> String {
    let desc = &issue.description;
    if desc.contains("error path") || desc.contains("error-path") {
        "When an error occurs, the allocated resource is not freed before the function returns, causing a leak on that path.".to_string()
    } else if desc.contains("early return") {
        "An early return path skips the deallocation, leaving the resource unfreed.".to_string()
    } else {
        "The allocated resource is not freed before the function returns on some path, causing a potential leak.".to_string()
    }
}

/// Collects human-readable evidence strings from an issue.
fn collect_evidence(issue: &Issue) -> Vec<String> {
    let mut evidence = Vec::new();

    // Evidence from trace entries.
    for entry in &issue.trace {
        evidence.push(entry.description.clone());
    }

    // Evidence from FFI boundary.
    if let Some(ref ffi) = issue.ffi_boundary {
        evidence.push(format!(
            "FFI boundary: {} ({:?}) -> {} ({:?})",
            ffi.caller_name, ffi.caller_lang, ffi.callee_name, ffi.callee_lang
        ));
    }

    // Evidence from description patterns.
    let desc = &issue.description;
    if desc.contains("same resource") || desc.contains("same_resource") {
        evidence.push("same resource instance".to_string());
    }
    if desc.contains("incompatible families") || desc.contains("cross-family") {
        evidence.push("incompatible resource families".to_string());
    }
    if desc.contains("reachable") {
        evidence.push("release is reachable after allocation".to_string());
    }

    evidence
}

/// Generates a fix hint for the issue.
fn generate_fix_hint(issue: &Issue) -> Option<String> {
    match issue.kind {
        IssueKind::CrossFamilyFree | IssueKind::CrossLanguageFree => {
            fix_hint_cross_family(issue)
        }
        IssueKind::DoubleFree => {
            Some("Ensure the pointer is set to NULL after the first free, or track ownership explicitly.".to_string())
        }
        IssueKind::UseAfterFree => {
            Some("Avoid using the pointer after it has been freed. Move or copy the data before freeing if needed.".to_string())
        }
        IssueKind::ConditionalLeak | IssueKind::MemoryLeak | IssueKind::DefiniteLeak => {
            Some("Free the allocation on all exit paths, including error paths.".to_string())
        }
        IssueKind::InvalidFree => {
            Some("Use the matching deallocator for the allocation function.".to_string())
        }
        IssueKind::NullDereference => {
            Some("Add a null check before dereferencing the pointer.".to_string())
        }
        IssueKind::BufferOverflow => {
            Some("Validate buffer sizes before writing, and use bounds-checked APIs.".to_string())
        }
        IssueKind::IntegerOverflow => {
            Some("Use checked arithmetic or validate inputs before allocation size calculations.".to_string())
        }
        IssueKind::UncheckedReturn => {
            Some("Check the return value of the FFI call for errors or null pointers before using it.".to_string())
        }
        IssueKind::BorrowEscape | IssueKind::CallbackEscapeIssue | IssueKind::CallbackEscape => {
            Some("Clarify ownership at the boundary — pass a copy or use a reference-counted wrapper.".to_string())
        }
        IssueKind::OwnershipViolation => {
            Some("Ensure ownership is transferred explicitly using the correct ABI convention.".to_string())
        }
        IssueKind::FfiTypeMismatch => {
            Some("Verify the FFI type declarations match the actual types on both sides of the boundary.".to_string())
        }
        IssueKind::AbiMismatch => {
            Some("Use the correct calling convention annotation (extern \"C\", etc.) on both sides.".to_string())
        }
        IssueKind::LengthTruncation => {
            Some("Use a wider integer type or validate that the value fits before truncation.".to_string())
        }
        IssueKind::DoubleReclaim => {
            Some("Call from_raw only once per into_raw. Track raw pointer ownership explicitly.".to_string())
        }
        IssueKind::OwnershipEscapeLeak => {
            Some("Ensure every into_raw is paired with a from_raw to reclaim ownership.".to_string())
        }
        IssueKind::DataRace => {
            Some("Add synchronization (mutex or atomic) around shared data accessed across the FFI boundary.".to_string())
        }
        IssueKind::LockOrderViolation => {
            Some("Establish a consistent lock acquisition order across all threads.".to_string())
        }
        IssueKind::ThreadCrossing => {
            Some("Use thread-safe types or add synchronization when sharing data across threads.".to_string())
        }
        IssueKind::WriteToImmutable => {
            Some("Use a mutable reference or ensure the target is not declared immutable.".to_string())
        }
        IssueKind::NeedsModel => {
            Some("Add an explicit model annotation for this resource to enable verification.".to_string())
        }
        IssueKind::FfiUnsafeCall => {
            Some("Validate inputs and outputs around the FFI call, and wrap it in a safe abstraction.".to_string())
        }
        IssueKind::Unknown => None,
    }
}

/// Fix hint for cross-family/cross-language free issues.
fn fix_hint_cross_family(issue: &Issue) -> Option<String> {
    let (alloc_fn, release_fn) = extract_alloc_release(&issue.description);
    match (alloc_fn, release_fn) {
        (Some(alloc), Some(release)) => Some(format!(
            "Release {} memory with the matching deallocator, or allocate with {}.",
            alloc, release
        )),
        (Some(alloc), None) => Some(format!(
            "Release {} memory with its matching deallocator.",
            alloc
        )),
        (None, Some(release)) => Some(format!(
            "Allocate with the matching allocator for {}, or use the correct deallocator.",
            release
        )),
        (None, None) => Some(
            "Use matching allocation and deallocation functions from the same resource family."
                .to_string(),
        ),
    }
}

/// Extracts a suppression reason from the issue, if any.
///
/// The verifier may write a suppression reason into `issue.description`
/// when an issue was partially suppressed (downgraded but not eliminated).
/// Typical marker: "semantic suppression: ...".
/// Also checks `issue.trace` for downgrade markers.
fn extract_suppression_reason(issue: &Issue) -> Option<String> {
    // Check description for suppression markers.
    let lower = issue.description.to_lowercase();
    if lower.contains("semantic suppression") {
        // Extract the relevant portion from description.
        let marker = "semantic suppression";
        if let Some(start) = lower.find(marker) {
            let rest = &issue.description[start..];
            // Take until end of sentence or 200 chars.
            let end = rest
                .find(". ")
                .or_else(|| rest.find('\n'))
                .unwrap_or(rest.len().min(200));
            return Some(rest[..end].to_string());
        }
    }

    // Check trace entries for downgrade markers.
    for entry in &issue.trace {
        let tl = entry.description.to_lowercase();
        if tl.contains("suppression") || tl.contains("downgrad") {
            return Some(entry.description.clone());
        }
    }

    None
}

/// Converts confidence to a percentage string.
fn confidence_pct(confidence: &Confidence) -> String {
    match confidence {
        Confidence::High => "100%".to_string(),
        Confidence::Medium => "85%".to_string(),
        Confidence::Low => "50%".to_string(),
    }
}

/// Formats a confidence breakdown string for verbose mode.
fn format_confidence_breakdown(issue: &Issue) -> String {
    let base = match issue.confidence {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    };
    let mut parts = vec![format!("base={}", base)];
    if issue.kind.is_ffi_boundary() {
        parts.push("ffi_boundary=true".to_string());
    }
    if issue.ffi_boundary.is_some() {
        parts.push("cross_language=true".to_string());
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests;
