//! Issue Gate — unified SRT-based suppression for all issues.
//!
//! Every issue MUST pass through this gate before entering the
//! aggregator. The gate queries the Semantic Resolution Tree (SRT)
//! for each issue's value reference; if the SRT returns a suppression
//! tag (R-0~R-7), the issue is suppressed or downgraded.
//!
//! This is the single choke point that ensures no pass can emit an
//! issue without SRT consultation, preventing the "infrastructure
//! exists but isn't wired up" problem.
//!
//! # R-N Coverage
//!
//! | Issue Kind            | Suppression Signal         | R-N  |
//! |-----------------------|----------------------------|------|
//! | BorrowEscape          | HeapProvenance / GlobalProvenance | R-1 |
//! | BorrowEscape          | FromParameter (not stack)  | R-8  |
//! | WriteToImmutable      | MutableParam               | R-0  |
//! | WriteToImmutable      | InteriorMutability         | R-2  |
//! | UseAfterFree          | RaiiDropRelease            | R-3  |
//! | CrossLanguageFree     | IntoRawTransfer            | R-6  |
//! | CrossLanguageFree     | File/Network/ProcessOp     | R-4  |
//! | CrossLanguageFree     | LibraryRelease             | R-7  |
//! | DoubleFree            | RaiiDropRelease            | R-3  |

use omniscope_core::Issue;
use omniscope_semantics::SemanticKind;

/// Verdict returned by the issue gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateVerdict {
    /// Issue passes the gate — report it.
    Allow,
    /// Issue suppressed because the value has heap provenance (R-1).
    SuppressHeapOrigin,
    /// Issue suppressed because the value has global provenance (R-1).
    SuppressGlobalOrigin,
    /// Issue suppressed because the value comes from a mutable param (R-0).
    SuppressMutableParam,
    /// Issue suppressed because the value has interior mutability (R-2).
    SuppressInteriorMut,
    /// Issue suppressed because the release is RAII drop (R-3).
    SuppressRaii,
    /// Issue suppressed because ownership was transferred via into_raw (R-6).
    SuppressOwnershipTransfer,
    /// Issue suppressed because the callee is a non-memory syscall (R-4).
    SuppressNonMemorySyscall,
    /// Issue suppressed because the callee is a library allocator release (R-7).
    SuppressLibraryRelease,
    /// Issue suppressed because the pointer comes from a function parameter (R-8).
    SuppressFromParameter,
}

impl GateVerdict {
    /// Returns true if this verdict allows the issue to be reported.
    pub fn is_allowed(&self) -> bool {
        matches!(self, GateVerdict::Allow)
    }

    /// Returns a human-readable reason for the suppression.
    pub fn reason(&self) -> &'static str {
        match self {
            GateVerdict::Allow => "no suppression signal found",
            GateVerdict::SuppressHeapOrigin => "R-1: value has heap provenance, not a stack escape",
            GateVerdict::SuppressGlobalOrigin => "R-1: value has global/static provenance",
            GateVerdict::SuppressMutableParam => "R-0: dest comes from &mut T (mutable param)",
            GateVerdict::SuppressInteriorMut => "R-2: type has interior mutability (UnsafeCell)",
            GateVerdict::SuppressRaii => "R-3: compiler-inserted RAII drop/dealloc",
            GateVerdict::SuppressOwnershipTransfer => "R-6: ownership transferred via into_raw",
            GateVerdict::SuppressNonMemorySyscall => {
                "R-4: callee is a non-memory syscall (file/net/proc)"
            }
            GateVerdict::SuppressLibraryRelease => {
                "R-7: callee is a library allocator release (mi_free/inflateEnd/etc)"
            }
            GateVerdict::SuppressFromParameter => {
                "R-8: pointer from function parameter, not stack escape"
            }
        }
    }
}

/// Checks an issue against the SRT and returns a gate verdict.
///
/// The `query_kind` closure is used to look up whether a value
/// referenced by the issue has a particular semantic kind in the SRT.
/// This decouples the gate from the SRT's concrete data structure.
///
/// # Arguments
///
/// * `issue` — The issue to check.
/// * `has_kind` — A closure that takes a value reference key and a
///   `SemanticKind`, returning `true` if the SRT has a resolution
///   of that kind for the value.
pub fn check_issue<F>(issue: &Issue, has_kind: F) -> GateVerdict
where
    F: Fn(&str, SemanticKind) -> bool,
{
    // Use the issue's symbol (callee or function name) as the SRT key.
    let key = &issue.symbol;

    match issue.kind {
        // ── BorrowEscape: R-1 heap/global provenance + R-8 from_parameter ──
        omniscope_core::IssueKind::BorrowEscape => {
            if has_kind(key, SemanticKind::HeapProvenance) {
                return GateVerdict::SuppressHeapOrigin;
            }
            if has_kind(key, SemanticKind::GlobalProvenance) {
                return GateVerdict::SuppressGlobalOrigin;
            }
            if has_kind(key, SemanticKind::FromParameter) {
                return GateVerdict::SuppressFromParameter;
            }
        }

        // ── UseAfterFree: R-3 RAII drop ──
        omniscope_core::IssueKind::UseAfterFree if has_kind(key, SemanticKind::RaiiDropRelease) => {
            return GateVerdict::SuppressRaii;
        }

        // ── WriteToImmutable: R-0 MutableParam + R-2 InteriorMutability ──
        omniscope_core::IssueKind::WriteToImmutable => {
            if has_kind(key, SemanticKind::MutableParam) {
                return GateVerdict::SuppressMutableParam;
            }
            if has_kind(key, SemanticKind::InteriorMutability) {
                return GateVerdict::SuppressInteriorMut;
            }
        }

        // ── CrossLanguageFree: R-4 + R-6 + R-7 ──
        omniscope_core::IssueKind::CrossLanguageFree => {
            if has_kind(key, SemanticKind::IntoRawTransfer) {
                return GateVerdict::SuppressOwnershipTransfer;
            }
            if has_kind(key, SemanticKind::FileOperation) {
                return GateVerdict::SuppressNonMemorySyscall;
            }
            if has_kind(key, SemanticKind::NetworkOperation) {
                return GateVerdict::SuppressNonMemorySyscall;
            }
            if has_kind(key, SemanticKind::ProcessOperation) {
                return GateVerdict::SuppressNonMemorySyscall;
            }
            if has_kind(key, SemanticKind::LibraryRelease) {
                return GateVerdict::SuppressLibraryRelease;
            }
        }

        // ── DoubleFree: R-3 RAII drop ──
        omniscope_core::IssueKind::DoubleFree if has_kind(key, SemanticKind::RaiiDropRelease) => {
            return GateVerdict::SuppressRaii;
        }

        // ── CrossFamilyFree: same logic as CrossLanguageFree ──
        omniscope_core::IssueKind::CrossFamilyFree => {
            if has_kind(key, SemanticKind::IntoRawTransfer) {
                return GateVerdict::SuppressOwnershipTransfer;
            }
            if has_kind(key, SemanticKind::FileOperation)
                || has_kind(key, SemanticKind::NetworkOperation)
                || has_kind(key, SemanticKind::ProcessOperation)
            {
                return GateVerdict::SuppressNonMemorySyscall;
            }
            if has_kind(key, SemanticKind::LibraryRelease) {
                return GateVerdict::SuppressLibraryRelease;
            }
        }

        // ── FfiUnsafeCall: suppress for non-memory syscalls and safe patterns ──
        omniscope_core::IssueKind::FfiUnsafeCall
            if has_kind(key, SemanticKind::FileOperation)
                || has_kind(key, SemanticKind::NetworkOperation)
                || has_kind(key, SemanticKind::ProcessOperation) =>
        {
            return GateVerdict::SuppressNonMemorySyscall;
        }

        // Other issue kinds have no SRT-based suppression yet.
        _ => {}
    }

    GateVerdict::Allow
}

/// Checks an issue against multiple semantic kinds.
///
/// Convenience wrapper around `check_issue` that builds the `has_kind`
/// closure from a pre-computed map of symbol → set of SemanticKinds.
pub fn check_issue_with_kinds(
    issue: &Issue,
    resolutions: &std::collections::HashMap<String, Vec<SemanticKind>>,
) -> GateVerdict {
    check_issue(issue, |key, kind| {
        resolutions
            .get(key)
            .is_some_and(|kinds| kinds.contains(&kind))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_core::diagnostics::Severity;
    use omniscope_core::{Issue, IssueKind};
    use std::collections::HashMap;

    fn make_issue(kind: IssueKind, symbol: &str) -> Issue {
        Issue::new(
            1,
            kind,
            Severity::Warning,
            format!("test issue for {symbol}"),
        )
        .with_symbol(symbol.to_string())
    }

    #[test]
    fn test_gate_allows_unknown_issue() {
        let issue = make_issue(IssueKind::NullDereference, "foo");
        let verdict = check_issue(&issue, |_, _| false);
        assert_eq!(
            verdict,
            GateVerdict::Allow,
            "Unknown issue should be allowed through the gate"
        );
    }

    #[test]
    fn test_gate_suppresses_borrow_escape_heap() {
        let issue = make_issue(IssueKind::BorrowEscape, "box_ptr");
        let verdict = check_issue(&issue, |key, kind| {
            key == "box_ptr" && kind == SemanticKind::HeapProvenance
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressHeapOrigin,
            "Borrow escape with heap provenance should be suppressed"
        );
    }

    #[test]
    fn test_gate_suppresses_borrow_escape_global() {
        let issue = make_issue(IssueKind::BorrowEscape, "static_val");
        let verdict = check_issue(&issue, |key, kind| {
            key == "static_val" && kind == SemanticKind::GlobalProvenance
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressGlobalOrigin,
            "Borrow escape with global provenance should be suppressed"
        );
    }

    #[test]
    fn test_gate_suppresses_uaf_raii() {
        let issue = make_issue(IssueKind::UseAfterFree, "drop_in_place");
        let verdict = check_issue(&issue, |key, kind| {
            key == "drop_in_place" && kind == SemanticKind::RaiiDropRelease
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressRaii,
            "Use-after-free with RAII drop should be suppressed"
        );
    }

    #[test]
    fn test_gate_suppresses_cross_lang_into_raw() {
        let issue = make_issue(IssueKind::CrossLanguageFree, "into_raw_ptr");
        let verdict = check_issue(&issue, |key, kind| {
            key == "into_raw_ptr" && kind == SemanticKind::IntoRawTransfer
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressOwnershipTransfer,
            "Cross-language free with into_raw transfer should be suppressed"
        );
    }

    #[test]
    fn test_gate_suppresses_cross_lang_file_op() {
        let issue = make_issue(IssueKind::CrossLanguageFree, "close");
        let verdict = check_issue(&issue, |key, kind| {
            key == "close" && kind == SemanticKind::FileOperation
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressNonMemorySyscall,
            "Cross-language free with file operation should be suppressed"
        );
    }

    #[test]
    fn test_gate_suppresses_cross_lang_library_release() {
        let issue = make_issue(IssueKind::CrossLanguageFree, "mi_free");
        let verdict = check_issue(&issue, |key, kind| {
            key == "mi_free" && kind == SemanticKind::LibraryRelease
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressLibraryRelease,
            "Cross-language free with library release should be suppressed"
        );
    }

    #[test]
    fn test_gate_with_kinds_map() {
        let mut resolutions = HashMap::new();
        resolutions.insert(
            "box_ptr".to_string(),
            vec![SemanticKind::HeapProvenance, SemanticKind::MutableParam],
        );

        let issue = make_issue(IssueKind::BorrowEscape, "box_ptr");
        let verdict = check_issue_with_kinds(&issue, &resolutions);
        assert_eq!(
            verdict,
            GateVerdict::SuppressHeapOrigin,
            "Borrow escape with heap provenance should be suppressed via kinds map"
        );
    }

    #[test]
    fn test_gate_allows_when_no_matching_kind() {
        let mut resolutions = HashMap::new();
        resolutions.insert("some_func".to_string(), vec![SemanticKind::ReadonlyParam]);

        let issue = make_issue(IssueKind::BorrowEscape, "some_func");
        let verdict = check_issue_with_kinds(&issue, &resolutions);
        assert_eq!(
            verdict,
            GateVerdict::Allow,
            "Issue should be allowed when no matching kind is found"
        );
    }

    #[test]
    fn test_gate_suppresses_double_free_raii() {
        let issue = make_issue(IssueKind::DoubleFree, "drop_in_place");
        let verdict = check_issue(&issue, |key, kind| {
            key == "drop_in_place" && kind == SemanticKind::RaiiDropRelease
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressRaii,
            "Double-free with RAII drop should be suppressed"
        );
    }

    #[test]
    fn test_verdict_reason_not_empty() {
        for verdict in [
            GateVerdict::Allow,
            GateVerdict::SuppressHeapOrigin,
            GateVerdict::SuppressGlobalOrigin,
            GateVerdict::SuppressMutableParam,
            GateVerdict::SuppressInteriorMut,
            GateVerdict::SuppressRaii,
            GateVerdict::SuppressOwnershipTransfer,
            GateVerdict::SuppressNonMemorySyscall,
            GateVerdict::SuppressLibraryRelease,
            GateVerdict::SuppressFromParameter,
        ] {
            assert!(
                !verdict.reason().is_empty(),
                "reason should not be empty for {verdict:?}"
            );
        }
    }
}
