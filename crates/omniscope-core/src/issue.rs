//! Issue types and definitions for analysis results.
//!
//! Issues represent security problems or code quality issues detected
//! during analysis. Each issue carries a kind, severity, location,
//! and an optional trace (reasoning path) for SARIF code flows.
//!
//! ## Memory Ownership Model
//!
//! Issue uses explicit ownership tags to prevent memory leaks and
//! double-free. The `owned_description` flag indicates whether the
//! description string was heap-allocated and must be freed.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::diagnostics::Severity;

/// Unique identifier for issues.
pub type IssueId = u64;

/// Classification of the issue kind.
///
/// This drives the 90/10 priority split: FFI boundary issues are
/// the core focus (90% of effort), while local-only memory issues
/// are auxiliary (10%).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IssueKind {
    // === FFI Boundary Issues (90% core priority) ===
    /// Cross-language free mismatch (e.g., Rust frees C-allocated memory).
    CrossLanguageFree,
    /// Ownership transfer violation across FFI boundary.
    OwnershipViolation,
    /// Type mismatch at FFI boundary (ABI incompatibility).
    FfiTypeMismatch,
    /// ABI calling convention mismatch.
    AbiMismatch,
    /// Unchecked return value from FFI call.
    UncheckedReturn,
    /// FFI call with potentially dangerous semantics.
    FfiUnsafeCall,
    /// Callback escape across language boundary.
    CallbackEscape,

    // === Local-Only Memory Issues (10% auxiliary priority) ===
    /// Double free of the same allocation.
    DoubleFree,
    /// Use after free (dangling pointer dereference).
    UseAfterFree,
    /// Invalid free (freeing a pointer not from malloc).
    InvalidFree,
    /// Memory leak (allocation never freed).
    MemoryLeak,
    /// Buffer overflow (write past allocation bounds).
    BufferOverflow,
    /// Null pointer dereference.
    NullDereference,
    /// Integer overflow leading to memory corruption.
    IntegerOverflow,

    // === Resource Contract Issues (new architecture) ===
    /// Alloc and free from different resource families.
    CrossFamilyFree,
    /// Resource not freed on some execution paths.
    ConditionalLeak,
    /// Borrowed pointer escaped to a context requiring ownership.
    BorrowEscape,
    /// Pointer escaped to a callback that may assume ownership.
    CallbackEscapeIssue,
    /// Needs a model annotation — unknown family or cleanup.
    NeedsModel,
    /// Write to immutable memory location.
    WriteToImmutable,
    /// Same raw pointer reclaimed multiple times via from_raw (double reclaim).
    /// This is a use-after-free/double-free pattern for raw pointer ownership.
    DoubleReclaim,
    /// Ownership escaped via into_raw but never reclaimed via from_raw.
    OwnershipEscapeLeak,

    // === Concurrency Issues ===
    /// Data race across FFI boundary.
    DataRace,
    /// Lock ordering violation.
    LockOrderViolation,
    /// Thread crossing with unsafe pointer.
    ThreadCrossing,

    // === Unclassified ===
    /// Unknown issue kind (cannot determine specific category).
    Unknown,
}

impl IssueKind {
    /// Returns true if this is an FFI boundary issue (core priority).
    pub fn is_ffi_boundary(&self) -> bool {
        matches!(
            self,
            IssueKind::CrossLanguageFree
                | IssueKind::OwnershipViolation
                | IssueKind::FfiTypeMismatch
                | IssueKind::AbiMismatch
                | IssueKind::UncheckedReturn
                | IssueKind::FfiUnsafeCall
                | IssueKind::CallbackEscape
        )
    }

    /// Returns true if this is a local-only memory issue (auxiliary priority).
    pub fn is_local_memory(&self) -> bool {
        matches!(
            self,
            IssueKind::DoubleFree
                | IssueKind::UseAfterFree
                | IssueKind::InvalidFree
                | IssueKind::MemoryLeak
                | IssueKind::BufferOverflow
                | IssueKind::NullDereference
                | IssueKind::IntegerOverflow
        )
    }

    /// Returns true if this is a resource contract issue (new architecture).
    ///
    /// These issues are produced by the resource contract graph and
    /// verified by the issue verifier before reporting.
    pub fn is_resource_contract(&self) -> bool {
        matches!(
            self,
            IssueKind::CrossFamilyFree
                | IssueKind::ConditionalLeak
                | IssueKind::BorrowEscape
                | IssueKind::CallbackEscapeIssue
                | IssueKind::NeedsModel
                | IssueKind::WriteToImmutable
                | IssueKind::DoubleReclaim
                | IssueKind::OwnershipEscapeLeak
        )
    }

    /// Returns the CWE (Common Weakness Enumeration) ID if applicable.
    pub fn cwe_id(&self) -> Option<u32> {
        match self {
            // FFI boundary issues
            IssueKind::CrossLanguageFree => Some(762), // CWE-762: Mismatched Memory Management Routines
            IssueKind::OwnershipViolation => Some(763), // CWE-763: Release of Invalid Pointer or Reference
            IssueKind::FfiTypeMismatch => Some(843), // CWE-843: Access of Resource Using Incompatible Type
            IssueKind::AbiMismatch => Some(758), // CWE-758: Reliance on Undefined/Unspecified Behavior
            IssueKind::UncheckedReturn => Some(252), // CWE-252: Unchecked Return Value
            IssueKind::FfiUnsafeCall => Some(119), // CWE-119: Improper Restriction of Memory Buffer Operations
            IssueKind::CallbackEscape => Some(749), // CWE-749: Exposed Dangerous Method or Function
            // Local memory issues
            IssueKind::DoubleFree => Some(415), // CWE-415: Double Free
            IssueKind::UseAfterFree => Some(416), // CWE-416: Use After Free
            IssueKind::InvalidFree => Some(763), // CWE-763: Release of Invalid Pointer or Reference
            IssueKind::MemoryLeak => Some(401), // CWE-401: Missing Release of Memory
            IssueKind::BufferOverflow => Some(120), // CWE-120: Buffer Copy without Size Check
            IssueKind::NullDereference => Some(476), // CWE-476: NULL Pointer Dereference
            IssueKind::IntegerOverflow => Some(190), // CWE-190: Integer Overflow or Wraparound
            // Resource contract issues
            IssueKind::CrossFamilyFree => Some(762), // CWE-762: Mismatched Memory Management Routines
            IssueKind::ConditionalLeak => Some(772), // CWE-772: Missing Release of Resource after Effective Lifetime
            IssueKind::BorrowEscape => Some(822),    // CWE-822: Untrusted Pointer Dereference
            IssueKind::CallbackEscapeIssue => Some(749), // CWE-749: Exposed Dangerous Method or Function
            IssueKind::WriteToImmutable => Some(123),    // CWE-123: Write-what-where Condition
            IssueKind::DoubleReclaim => Some(415),       // CWE-415: Double Free
            IssueKind::OwnershipEscapeLeak => Some(772), // CWE-772: Missing Release after Effective Lifetime
            // Concurrency issues
            IssueKind::DataRace => Some(362), // CWE-362: Race Condition
            IssueKind::LockOrderViolation => Some(833), // CWE-833: Deadlock
            IssueKind::ThreadCrossing => Some(362), // CWE-362: Race Condition
            // No direct CWE mapping
            IssueKind::NeedsModel => None,
            IssueKind::Unknown => None,
        }
    }
}

/// Confidence level for an issue detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Confidence {
    /// Low confidence — may be a false positive.
    Low,
    /// Medium confidence — likely a real issue but not certain.
    Medium,
    /// High confidence — very likely a real issue.
    High,
}

impl Confidence {
    /// Returns a numeric value for comparison (0.0 - 1.0).
    pub fn as_f32(&self) -> f32 {
        match self {
            Confidence::Low => 0.33,
            Confidence::Medium => 0.66,
            Confidence::High => 1.0,
        }
    }
}

/// FFI boundary metadata for cross-language issues.
///
/// Carries information about the language transition at the
/// boundary, which is essential for producing actionable
/// diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FFIBoundary {
    /// Caller function name.
    pub caller_name: String,
    /// Callee function name.
    pub callee_name: String,
    /// Source language of the caller.
    pub caller_lang: omniscope_types::Language,
    /// Source language of the callee.
    pub callee_lang: omniscope_types::Language,
    /// Kind of boundary crossing.
    pub boundary_kind: BoundaryKind,
}

/// Kind of FFI boundary crossing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BoundaryKind {
    /// Rust → C/C++ FFI (extern "C" / extern "C++").
    RustToC,
    /// C/C++ → Rust FFI (#[no_mangle] export).
    CToRust,
    /// Zig → C FFI (@cImport).
    ZigToC,
    /// Go → C FFI (cgo).
    GoToC,
    /// Python → C FFI (C extension / ctypes).
    PythonToC,
    /// Java → C FFI (JNI).
    JavaToC,
    /// C# → C FFI (P/Invoke).
    CSharpToC,
    /// Unknown boundary kind.
    Unknown,
}

/// Trace entry for issue reasoning path.
///
/// Represents a single step in the reasoning path that led to
/// detecting an issue. Used for SARIF code flows and debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    /// Description of this trace step.
    pub description: String,
    /// Optional source location for this step.
    pub location: Option<IssueLocation>,
}

impl TraceEntry {
    /// Creates a trace entry with description only.
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            location: None,
        }
    }

    /// Creates a trace entry with both description and location.
    pub fn with_location(description: impl Into<String>, location: IssueLocation) -> Self {
        Self {
            description: description.into(),
            location: Some(location),
        }
    }
}

/// Source location for an issue.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IssueLocation {
    /// File path.
    pub file: PathBuf,
    /// Line number (1-based).
    pub line: u32,
    /// Column number (1-based, optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// Function name (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
}

impl IssueLocation {
    /// Creates a new issue location with file and line.
    pub fn new(file: PathBuf, line: u32) -> Self {
        Self {
            file,
            line,
            column: None,
            function: None,
        }
    }

    /// Adds column information.
    pub fn with_column(mut self, column: u32) -> Self {
        self.column = Some(column);
        self
    }

    /// Adds function name.
    pub fn with_function(mut self, function: impl Into<String>) -> Self {
        self.function = Some(function.into());
        self
    }
}

/// An issue represents a detected security problem.
///
/// Each issue has a kind, severity, location, and optional trace
/// entries that explain how the issue was detected. FFI boundary
/// issues additionally carry FFIBoundary metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    /// Unique issue identifier.
    pub id: IssueId,
    /// Issue kind classification.
    pub kind: IssueKind,
    /// Severity level.
    pub severity: Severity,
    /// Confidence level.
    pub confidence: Confidence,
    /// Human-readable description.
    pub description: String,
    /// Source location where the issue was detected.
    pub location: Option<IssueLocation>,
    /// FFI boundary metadata (if this is a cross-language issue).
    pub ffi_boundary: Option<FFIBoundary>,
    /// Trace entries explaining the reasoning path.
    pub trace: Vec<TraceEntry>,
    /// CWE identifier (if applicable).
    pub cwe_id: Option<u32>,
    /// Symbol name for SRT lookup (callee or function name).
    /// Used by the issue gate to query the Semantic Resolution Tree.
    pub symbol: String,
}

impl Issue {
    /// Creates a new issue with the given kind, severity, and description.
    pub fn new(
        id: IssueId,
        kind: IssueKind,
        severity: Severity,
        description: impl Into<String>,
    ) -> Self {
        let cwe_id = kind.cwe_id();
        Self {
            id,
            kind,
            severity,
            confidence: Confidence::Medium,
            description: description.into(),
            location: None,
            ffi_boundary: None,
            trace: Vec::new(),
            cwe_id,
            symbol: String::new(),
        }
    }

    /// Sets the location.
    pub fn with_location(mut self, location: IssueLocation) -> Self {
        self.location = Some(location);
        self
    }

    /// Sets the symbol name for SRT lookup.
    pub fn with_symbol(mut self, symbol: impl Into<String>) -> Self {
        self.symbol = symbol.into();
        self
    }

    /// Sets the confidence level.
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Sets the FFI boundary metadata.
    pub fn with_ffi_boundary(mut self, boundary: FFIBoundary) -> Self {
        self.ffi_boundary = Some(boundary);
        self
    }

    /// Adds a trace entry.
    pub fn add_trace(&mut self, entry: TraceEntry) {
        self.trace.push(entry);
    }

    /// Returns true if this is a high-priority FFI boundary issue.
    pub fn is_high_priority(&self) -> bool {
        self.kind.is_ffi_boundary() && self.confidence == Confidence::High
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_kind_classification() {
        assert!(
            IssueKind::CrossLanguageFree.is_ffi_boundary(),
            "CrossLanguageFree must be classified as FFI boundary"
        );
        assert!(
            IssueKind::DoubleFree.is_local_memory(),
            "DoubleFree must be classified as local memory"
        );
        assert!(
            !IssueKind::FfiUnsafeCall.is_local_memory(),
            "FfiUnsafeCall is FFI boundary, not local memory"
        );
    }

    #[test]
    fn test_cwe_id_mapping() {
        assert_eq!(
            IssueKind::UseAfterFree.cwe_id(),
            Some(416),
            "UseAfterFree must map to CWE-416"
        );
        assert_eq!(
            IssueKind::NullDereference.cwe_id(),
            Some(476),
            "NullDereference must map to CWE-476"
        );
        assert_eq!(
            IssueKind::AbiMismatch.cwe_id(),
            Some(758),
            "AbiMismatch must map to CWE-758"
        );
        assert_eq!(
            IssueKind::DoubleReclaim.cwe_id(),
            Some(415),
            "DoubleReclaim must map to CWE-415"
        );
        assert_eq!(
            IssueKind::OwnershipEscapeLeak.cwe_id(),
            Some(772),
            "OwnershipEscapeLeak must map to CWE-772"
        );
        assert_eq!(
            IssueKind::DataRace.cwe_id(),
            Some(362),
            "DataRace must map to CWE-362"
        );
        assert!(
            IssueKind::Unknown.cwe_id().is_none(),
            "Unknown has no CWE mapping"
        );
        assert!(
            IssueKind::NeedsModel.cwe_id().is_none(),
            "NeedsModel has no CWE mapping"
        );
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(
            Confidence::High.as_f32() > Confidence::Medium.as_f32(),
            "High confidence must exceed Medium"
        );
        assert!(
            Confidence::Medium.as_f32() > Confidence::Low.as_f32(),
            "Medium confidence must exceed Low"
        );
    }

    #[test]
    fn test_issue_construction_and_priority() {
        let issue = Issue::new(
            1,
            IssueKind::CrossLanguageFree,
            Severity::Error,
            "Rust frees C-allocated memory",
        )
        .with_confidence(Confidence::High);

        assert!(
            issue.is_high_priority(),
            "High-confidence FFI boundary issue must be high priority"
        );
        assert_eq!(
            issue.cwe_id,
            Some(762),
            "CWE ID must be auto-populated from issue kind"
        );
    }

    #[test]
    fn test_trace_entry_construction() {
        let entry = TraceEntry::with_location(
            "pointer allocated here",
            IssueLocation::new(PathBuf::from("main.rs"), 42),
        );
        assert!(
            entry.location.is_some(),
            "Trace entry with location must have location set"
        );
    }
}
