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
//! | UncheckedReturn       | HeapProvenance (allocator) | R-9  |
//! | FfiUnsafeCall         | File/Network/ProcessOp     | R-4  |
//! | FfiUnsafeCall         | LibraryRelease             | R-7  |
//! | FfiUnsafeCall         | IntoRawTransfer            | R-6  |
//! | FfiUnsafeCall         | RaiiDropRelease            | R-3  |
//! | FfiUnsafeCall         | HeapProvenance/GlobalProvenance | R-1 |
//! | FfiUnsafeCall         | FromParameter              | R-8  |
//! | FfiUnsafeCall         | CppDestructor/UniquePtr/SharedPtr | C++ RAII |
//! | FfiUnsafeCall         | GoDeferCleanup/GoFinalizer | Go cleanup |
//! | FfiUnsafeCall         | PythonRefcount*/BorrowedRef/OwnedRef/GilProtected | Python |
//! | FfiUnsafeCall         | CsharpSafeHandle/CsharpFinalizer | C# SafeHandle |
//! | FfiUnsafeCall         | JavaLocalRef/GlobalRef/WeakRef | Java JNI |
//! | ConditionalLeak       | RaiiDropRelease/CppDestructor/GoDeferCleanup/etc. | R-3+ |
//! | DefiniteLeak          | RaiiDropRelease/CppDestructor/GoDeferCleanup/etc. | R-3+ |
//! | OwnershipEscapeLeak   | RaiiDropRelease/IntoRawTransfer/RuntimeInternal | R-3/R-6/RuntimeInternal |

use omniscope_core::Issue;
use omniscope_semantics::{SemanticKey, SemanticKind};

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
    /// Issue suppressed because the callee is a known allocator (R-9).
    /// Suppresses UncheckedReturn for malloc/calloc/aligned_alloc etc.
    SuppressAllocatorReturn,
    /// Suppressed because the symbol is a runtime/compiler internal (e.g.,
    /// __rust_alloc, _ZN5alloc*, __cxa_*), not a user-code FFI violation.
    SuppressRuntimeInternal,
    /// Suppressed because the function is a thin wrapper that delegates to
    /// a single callee. Double-free signals from the callee's internal
    /// memory management are false positives when attributed to the wrapper.
    SuppressWrapperDelegation,
    /// Issue suppressed because the pointer is null-checked before dereference.
    /// Pattern: `icmp eq ptr %x, null` → `br` → dereference only in non-null arm.
    SuppressNullChecked,
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
            GateVerdict::SuppressAllocatorReturn => {
                "R-9: callee is a system/library allocator, unchecked return is expected noise"
            }
            GateVerdict::SuppressRuntimeInternal => {
                "runtime/compiler internal symbol, not a user-code FFI violation"
            }
            GateVerdict::SuppressWrapperDelegation => {
                "thin wrapper delegates to single callee; double-free from callee's internal memory management is FP"
            }
            GateVerdict::SuppressNullChecked => {
                "pointer verified non-null by conditional branch before dereference"
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
        // ── BorrowEscape: R-1 heap/global provenance + R-7 library + R-8 from_parameter ──
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
            // R-7: C library internal pointer-passing patterns
            if has_kind(key, SemanticKind::LibraryRelease) {
                return GateVerdict::SuppressLibraryRelease;
            }
        }

        // ── UseAfterFree: R-3 RAII drop + R-7 library release ──
        omniscope_core::IssueKind::UseAfterFree => {
            if has_kind(key, SemanticKind::RaiiDropRelease) {
                return GateVerdict::SuppressRaii;
            }
            if has_kind(key, SemanticKind::LibraryRelease) {
                return GateVerdict::SuppressLibraryRelease;
            }
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

        // ── CrossLanguageFree: R-4 + R-6 + R-7 + runtime ──
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
            // Runtime internal wrappers (e.g., heap.c_allocator_impl)
            // are legitimate bridges between language-specific and C allocators — not FFI violations.
            if has_kind(key, SemanticKind::RuntimeInternal) {
                return GateVerdict::SuppressRuntimeInternal;
            }
        }

        // ── OwnershipViolation: same suppression signals as CrossLanguageFree ──
        // Runtime wrappers (heap.c_allocator_impl.alloc/free) are legitimate
        // ownership bridges, not violations.
        omniscope_core::IssueKind::OwnershipViolation => {
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
            if has_kind(key, SemanticKind::RuntimeInternal) {
                return GateVerdict::SuppressRuntimeInternal;
            }
            // Python reference counting / copy-constructor patterns.
            // Functions like PyUnicode_FromString copy their input — the
            // caller retains ownership of the original buffer.  Python's
            // refcount system manages the returned object, not the input.
            if has_kind(key, SemanticKind::PythonRefcountInc)
                || has_kind(key, SemanticKind::PythonRefcountDec)
                || has_kind(key, SemanticKind::PythonBorrowedRef)
                || has_kind(key, SemanticKind::PythonOwnedRef)
                || has_kind(key, SemanticKind::PythonGilProtected)
            {
                return GateVerdict::SuppressRaii;
            }
        }

        // ── DoubleFree: R-3 RAII drop + R-7 library release ──
        omniscope_core::IssueKind::DoubleFree => {
            if has_kind(key, SemanticKind::RaiiDropRelease) {
                return GateVerdict::SuppressRaii;
            }
            if has_kind(key, SemanticKind::LibraryRelease) {
                return GateVerdict::SuppressLibraryRelease;
            }
        }

        // ── InvalidFree: R-7 library release (library-internal cleanup) ──
        omniscope_core::IssueKind::InvalidFree => {
            if has_kind(key, SemanticKind::LibraryRelease) {
                return GateVerdict::SuppressLibraryRelease;
            }
        }

        // ── UncheckedReturn: R-9 allocator provenance + NullChecked ──
        // System/library allocators (malloc, calloc, aligned_alloc, etc.) are
        // expected to be used without explicit null checks in many codebases.
        // Suppressing when HeapProvenance is detected covers these cases.
        // Also suppress when the pointer is null-checked before use.
        omniscope_core::IssueKind::UncheckedReturn => {
            if has_kind(key, SemanticKind::HeapProvenance) {
                return GateVerdict::SuppressAllocatorReturn;
            }
            if has_kind(key, SemanticKind::GoRuntimeAlloc) {
                return GateVerdict::SuppressAllocatorReturn;
            }
            if has_kind(key, SemanticKind::NullChecked) {
                return GateVerdict::SuppressNullChecked;
            }
            if let Some(func) = issue.location.as_ref().and_then(|l| l.function.as_ref()) {
                if func.as_str() != key.as_str() && has_kind(func, SemanticKind::NullChecked) {
                    return GateVerdict::SuppressNullChecked;
                }
            }
        }

        // ── CrossFamilyFree: detect wrong allocator/deallocator pairing ──
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
            // NOTE: Do NOT suppress LibraryRelease for CrossFamilyFree.
            // CrossFamilyFree specifically detects when a library release function
            // is used with the WRONG allocator (e.g., malloc + sqlite3_free).
            // Suppressing LibraryRelease would defeat the purpose of this check.
        }

        // ── FfiUnsafeCall: suppress for non-memory syscalls and safe patterns ──
        omniscope_core::IssueKind::FfiUnsafeCall => {
            // R-4: POSIX non-memory syscalls
            if has_kind(key, SemanticKind::FileOperation)
                || has_kind(key, SemanticKind::NetworkOperation)
                || has_kind(key, SemanticKind::ProcessOperation)
            {
                return GateVerdict::SuppressNonMemorySyscall;
            }
            // R-7: Library allocator releases (zlib/openssl/sqlite/mimalloc)
            if has_kind(key, SemanticKind::LibraryRelease) {
                return GateVerdict::SuppressLibraryRelease;
            }
            // R-6: Ownership transfer via into_raw
            if has_kind(key, SemanticKind::IntoRawTransfer) {
                return GateVerdict::SuppressOwnershipTransfer;
            }
            // R-3: RAII drop/dealloc patterns
            if has_kind(key, SemanticKind::RaiiDropRelease) {
                return GateVerdict::SuppressRaii;
            }
            // R-1: Heap/global provenance (not a stack escape)
            if has_kind(key, SemanticKind::HeapProvenance)
                || has_kind(key, SemanticKind::GlobalProvenance)
            {
                return GateVerdict::SuppressHeapOrigin;
            }
            // R-8: From function parameter (not stack escape)
            if has_kind(key, SemanticKind::FromParameter) {
                return GateVerdict::SuppressFromParameter;
            }
            // C++ RAII patterns (destructor, smart pointers)
            if has_kind(key, SemanticKind::CppDestructor)
                || has_kind(key, SemanticKind::CppUniquePtr)
                || has_kind(key, SemanticKind::CppSharedPtr)
            {
                return GateVerdict::SuppressRaii;
            }
            // Go cleanup patterns (defer, finalizer)
            if has_kind(key, SemanticKind::GoDeferCleanup)
                || has_kind(key, SemanticKind::GoFinalizer)
            {
                return GateVerdict::SuppressRaii;
            }
            // Python reference counting patterns
            if has_kind(key, SemanticKind::PythonRefcountInc)
                || has_kind(key, SemanticKind::PythonRefcountDec)
                || has_kind(key, SemanticKind::PythonBorrowedRef)
                || has_kind(key, SemanticKind::PythonOwnedRef)
                || has_kind(key, SemanticKind::PythonGilProtected)
            {
                return GateVerdict::SuppressRaii;
            }
            // C# SafeHandle and finalizer patterns
            if has_kind(key, SemanticKind::CsharpSafeHandle)
                || has_kind(key, SemanticKind::CsharpFinalizer)
            {
                return GateVerdict::SuppressRaii;
            }
            // Java JNI reference patterns
            if has_kind(key, SemanticKind::JavaLocalRef)
                || has_kind(key, SemanticKind::JavaGlobalRef)
                || has_kind(key, SemanticKind::JavaWeakRef)
            {
                return GateVerdict::SuppressRaii;
            }
            // RuntimeInternal: compiler/runtime bridges (e.g., __rust_alloc,
            // _ZN5alloc*, _ZN4core*, __cxa_*) — legitimate runtime calls, not FFI violations
            if has_kind(key, SemanticKind::RuntimeInternal) {
                return GateVerdict::SuppressRuntimeInternal;
            }
        }

        // ── ConditionalLeak / DefiniteLeak: suppress when SRT signals indicate
        // the resource is managed by a cleanup mechanism (RAII, defer, GC, etc.)
        // R-3: RAII drop/dealloc — compiler-inserted, resource will be freed
        // C++ RAII: destructor/smart-ptr ensures cleanup
        // Go: defer/finalizer ensures cleanup
        // Python: refcount ensures cleanup
        // C#: SafeHandle/finalizer ensures cleanup
        // Java: JNI reference management ensures cleanup
        // R-1: Heap/global provenance — runtime-managed, not a local leak
        // RuntimeInternal: runtime wrapper (e.g., heap.c_allocator_impl) — bridge, not leak
        omniscope_core::IssueKind::ConditionalLeak | omniscope_core::IssueKind::DefiniteLeak => {
            // R-3: RAII drop — compiler will free, not a leak
            if has_kind(key, SemanticKind::RaiiDropRelease) {
                return GateVerdict::SuppressRaii;
            }
            // C++ RAII: destructor/smart-ptr ensures cleanup
            if has_kind(key, SemanticKind::CppDestructor)
                || has_kind(key, SemanticKind::CppUniquePtr)
                || has_kind(key, SemanticKind::CppSharedPtr)
            {
                return GateVerdict::SuppressRaii;
            }
            // Go: defer/finalizer ensures cleanup
            if has_kind(key, SemanticKind::GoDeferCleanup)
                || has_kind(key, SemanticKind::GoFinalizer)
            {
                return GateVerdict::SuppressRaii;
            }
            // Python: refcount ensures cleanup
            if has_kind(key, SemanticKind::PythonRefcountInc)
                || has_kind(key, SemanticKind::PythonRefcountDec)
                || has_kind(key, SemanticKind::PythonBorrowedRef)
                || has_kind(key, SemanticKind::PythonOwnedRef)
                || has_kind(key, SemanticKind::PythonGilProtected)
            {
                return GateVerdict::SuppressRaii;
            }
            // C#: SafeHandle/finalizer ensures cleanup
            if has_kind(key, SemanticKind::CsharpSafeHandle)
                || has_kind(key, SemanticKind::CsharpFinalizer)
            {
                return GateVerdict::SuppressRaii;
            }
            // Java: JNI reference management ensures cleanup
            if has_kind(key, SemanticKind::JavaLocalRef)
                || has_kind(key, SemanticKind::JavaGlobalRef)
                || has_kind(key, SemanticKind::JavaWeakRef)
            {
                return GateVerdict::SuppressRaii;
            }
            // R-1: Heap/global provenance — runtime-managed resource
            if has_kind(key, SemanticKind::HeapProvenance)
                || has_kind(key, SemanticKind::GlobalProvenance)
            {
                return GateVerdict::SuppressHeapOrigin;
            }
            // RuntimeInternal: runtime wrapper bridges (e.g., heap.c_allocator_impl)
            if has_kind(key, SemanticKind::RuntimeInternal) {
                return GateVerdict::SuppressRuntimeInternal;
            }
        }

        // ── OwnershipEscapeLeak: suppress for RAII/cleanup patterns ──
        omniscope_core::IssueKind::OwnershipEscapeLeak => {
            // R-3: RAII drop
            if has_kind(key, SemanticKind::RaiiDropRelease) {
                return GateVerdict::SuppressRaii;
            }
            // C++ RAII
            if has_kind(key, SemanticKind::CppDestructor)
                || has_kind(key, SemanticKind::CppUniquePtr)
                || has_kind(key, SemanticKind::CppSharedPtr)
            {
                return GateVerdict::SuppressRaii;
            }
            // Go cleanup
            if has_kind(key, SemanticKind::GoDeferCleanup)
                || has_kind(key, SemanticKind::GoFinalizer)
            {
                return GateVerdict::SuppressRaii;
            }
            // R-6: Ownership transfer via into_raw — by design, not a leak
            if has_kind(key, SemanticKind::IntoRawTransfer) {
                return GateVerdict::SuppressOwnershipTransfer;
            }
            // RuntimeInternal: runtime wrapper
            if has_kind(key, SemanticKind::RuntimeInternal) {
                return GateVerdict::SuppressRuntimeInternal;
            }
        }

        // ── NullDereference: suppress when pointer is null-checked before use ──
        // Pattern: `icmp eq ptr %x, null` → `br` → dereference only in non-null arm.
        // The FfiReturnCheckPass detects this at the candidate level, but the gate
        // provides a second defense layer via SRT-based NullChecked facts.
        // Check by both the symbol (callee) and the enclosing function name.
        omniscope_core::IssueKind::NullDereference => {
            if has_kind(key, SemanticKind::NullChecked) {
                return GateVerdict::SuppressNullChecked;
            }
            if let Some(func) = issue.location.as_ref().and_then(|l| l.function.as_ref()) {
                if func.as_str() != key.as_str() && has_kind(func, SemanticKind::NullChecked) {
                    return GateVerdict::SuppressNullChecked;
                }
            }
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

/// Checks an issue against multiple semantic kinds using SemanticKey.
///
/// This function supports multi-key queries by converting string keys to
/// SemanticKey and checking against the resolutions map. It maintains
/// backward compatibility with existing string-based queries while
/// supporting new key types (Resource, Path, Owner, Value).
///
/// # Arguments
///
/// * `issue` — The issue to check.
/// * `resolutions` — A map from SemanticKey to set of SemanticKinds.
pub fn check_issue_with_keys(
    issue: &Issue,
    resolutions: &std::collections::HashMap<SemanticKey, Vec<SemanticKind>>,
) -> GateVerdict {
    // Try multiple key types for the issue

    // First try direct symbol lookup
    let has_kind = |key: &SemanticKey, kind: SemanticKind| -> bool {
        if let Some(kinds) = resolutions.get(key) {
            kinds.contains(&kind)
        } else {
            // For backward compatibility, also try string-based lookup
            // This allows gradual migration from string keys to SemanticKey
            false
        }
    };

    // Use the symbol key for the main check
    check_issue(issue, |key, kind| {
        let semantic_key = SemanticKey::from_string(key);
        has_kind(&semantic_key, kind)
    })
}

/// Checks an issue against multiple semantic kinds with hybrid key support.
///
/// This function supports both string-based keys (for backward compatibility)
/// and SemanticKey-based keys (for new multi-key queries). It checks both
/// maps and returns the first suppression found.
///
/// # Arguments
///
/// * `issue` — The issue to check.
/// * `string_resolutions` — Legacy string-based resolutions map.
/// * `key_resolutions` — New SemanticKey-based resolutions map.
pub fn check_issue_with_hybrid_keys(
    issue: &Issue,
    string_resolutions: &std::collections::HashMap<String, Vec<SemanticKind>>,
    key_resolutions: &std::collections::HashMap<SemanticKey, Vec<SemanticKind>>,
) -> GateVerdict {
    // First try string-based lookup (backward compatibility)
    let string_verdict = check_issue_with_kinds(issue, string_resolutions);
    if !string_verdict.is_allowed() {
        return string_verdict;
    }

    // Then try SemanticKey-based lookup
    check_issue_with_keys(issue, key_resolutions)
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
            GateVerdict::SuppressAllocatorReturn,
            GateVerdict::SuppressRuntimeInternal,
            GateVerdict::SuppressWrapperDelegation,
            GateVerdict::SuppressNullChecked,
        ] {
            assert!(
                !verdict.reason().is_empty(),
                "reason should not be empty for {verdict:?}"
            );
        }
    }

    /// Objective: Verify UncheckedReturn with heap provenance (allocator) is suppressed.
    /// Invariants: malloc/calloc return values flagged as UncheckedReturn must be suppressed.
    #[test]
    fn test_gate_suppresses_unchecked_return_allocator() {
        let issue = make_issue(IssueKind::UncheckedReturn, "malloc");
        let verdict = check_issue(&issue, |key, kind| {
            key == "malloc" && kind == SemanticKind::HeapProvenance
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressAllocatorReturn,
            "UncheckedReturn for system allocator (malloc) must be suppressed"
        );
    }

    /// Objective: Verify UncheckedReturn without heap provenance passes the gate.
    /// Invariants: Non-allocator FFI calls still produce UncheckedReturn.
    #[test]
    fn test_gate_allows_unchecked_return_non_allocator() {
        let issue = make_issue(IssueKind::UncheckedReturn, "fopen");
        let verdict = check_issue(&issue, |_, _| false);
        assert_eq!(
            verdict,
            GateVerdict::Allow,
            "UncheckedReturn for non-allocator FFI (fopen) must pass the gate"
        );
    }

    // ── Leak suppression tests ──────────────────────────────────────

    /// Objective: Verify ConditionalLeak with RAII drop is suppressed.
    /// Invariants: RAII-managed resources are not leaks.
    #[test]
    fn test_gate_suppresses_conditional_leak_raii() {
        let issue = make_issue(IssueKind::ConditionalLeak, "drop_in_place");
        let verdict = check_issue(&issue, |key, kind| {
            key == "drop_in_place" && kind == SemanticKind::RaiiDropRelease
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressRaii,
            "ConditionalLeak with RAII drop should be suppressed"
        );
    }

    /// Objective: Verify ConditionalLeak with C++ destructor is suppressed.
    /// Invariants: C++ RAII ensures cleanup, not a leak.
    #[test]
    fn test_gate_suppresses_conditional_leak_cpp_destructor() {
        let issue = make_issue(IssueKind::ConditionalLeak, "~String");
        let verdict = check_issue(&issue, |key, kind| {
            key == "~String" && kind == SemanticKind::CppDestructor
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressRaii,
            "ConditionalLeak with C++ destructor should be suppressed"
        );
    }

    /// Objective: Verify DefiniteLeak with Go defer is suppressed.
    /// Invariants: Go defer ensures cleanup, not a leak.
    #[test]
    fn test_gate_suppresses_definite_leak_go_defer() {
        let issue = make_issue(IssueKind::DefiniteLeak, "defer_close");
        let verdict = check_issue(&issue, |key, kind| {
            key == "defer_close" && kind == SemanticKind::GoDeferCleanup
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressRaii,
            "DefiniteLeak with Go defer cleanup should be suppressed"
        );
    }

    /// Objective: Verify ConditionalLeak with RuntimeInternal is suppressed.
    /// Invariants: Runtime internal wrappers (e.g., heap.c_allocator_impl) are bridges, not leaks.
    #[test]
    fn test_gate_suppresses_conditional_leak_runtime_internal() {
        let issue = make_issue(IssueKind::ConditionalLeak, "c_allocator_impl");
        let verdict = check_issue(&issue, |key, kind| {
            key == "c_allocator_impl" && kind == SemanticKind::RuntimeInternal
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressRuntimeInternal,
            "ConditionalLeak with RuntimeInternal should be suppressed"
        );
    }

    /// Objective: Verify ConditionalLeak with HeapProvenance is suppressed.
    /// Invariants: Heap-provenance resources are runtime-managed, not local leaks.
    #[test]
    fn test_gate_suppresses_conditional_leak_heap_provenance() {
        let issue = make_issue(IssueKind::ConditionalLeak, "alloc");
        let verdict = check_issue(&issue, |key, kind| {
            key == "alloc" && kind == SemanticKind::HeapProvenance
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressHeapOrigin,
            "ConditionalLeak with heap provenance should be suppressed"
        );
    }

    /// Objective: Verify OwnershipEscapeLeak with RAII drop is suppressed.
    /// Invariants: RAII-managed ownership escape is not a real leak.
    #[test]
    fn test_gate_suppresses_ownership_escape_leak_raii() {
        let issue = make_issue(IssueKind::OwnershipEscapeLeak, "drop_in_place");
        let verdict = check_issue(&issue, |key, kind| {
            key == "drop_in_place" && kind == SemanticKind::RaiiDropRelease
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressRaii,
            "OwnershipEscapeLeak with RAII drop should be suppressed"
        );
    }

    /// Objective: Verify OwnershipEscapeLeak with IntoRawTransfer is suppressed.
    /// Invariants: into_raw transfers are by-design ownership escapes.
    #[test]
    fn test_gate_suppresses_ownership_escape_leak_into_raw() {
        let issue = make_issue(IssueKind::OwnershipEscapeLeak, "into_raw");
        let verdict = check_issue(&issue, |key, kind| {
            key == "into_raw" && kind == SemanticKind::IntoRawTransfer
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressOwnershipTransfer,
            "OwnershipEscapeLeak with into_raw transfer should be suppressed"
        );
    }

    /// Objective: Verify ConditionalLeak without matching kind passes the gate.
    /// Invariants: Leaks without cleanup signals should still be reported.
    #[test]
    fn test_gate_allows_conditional_leak_no_suppression() {
        let issue = make_issue(IssueKind::ConditionalLeak, "raw_malloc");
        let verdict = check_issue(&issue, |_, _| false);
        assert_eq!(
            verdict,
            GateVerdict::Allow,
            "ConditionalLeak without suppression signal must pass the gate"
        );
    }

    // ── RuntimeInternal verdict tests ────────────────────────────────

    /// Objective: Verify CrossLanguageFree with RuntimeInternal returns
    /// SuppressRuntimeInternal (NOT SuppressRaii).
    /// Invariants: RuntimeInternal is distinct from RAII — it covers
    /// compiler/runtime glue with no user boundary path.
    #[test]
    fn test_gate_suppresses_cross_language_free_runtime_internal() {
        let issue = make_issue(IssueKind::CrossLanguageFree, "c_allocator_impl");
        let verdict = check_issue(&issue, |key, kind| {
            key == "c_allocator_impl" && kind == SemanticKind::RuntimeInternal
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressRuntimeInternal,
            "CrossLanguageFree with RuntimeInternal must return SuppressRuntimeInternal, not SuppressRaii"
        );
    }

    /// Objective: Verify OwnershipViolation with RuntimeInternal returns
    /// SuppressRuntimeInternal.
    /// Invariants: Runtime glue is not an ownership violation.
    #[test]
    fn test_gate_suppresses_ownership_violation_runtime_internal() {
        let issue = make_issue(IssueKind::OwnershipViolation, "heap_alloc_impl");
        let verdict = check_issue(&issue, |key, kind| {
            key == "heap_alloc_impl" && kind == SemanticKind::RuntimeInternal
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressRuntimeInternal,
            "OwnershipViolation with RuntimeInternal must return SuppressRuntimeInternal"
        );
    }

    /// Objective: Verify OwnershipViolation with PythonOwnedRef is suppressed.
    /// Invariants: Python copy constructors (PyUnicode_FromString etc.) copy
    /// their input — the caller retains ownership of the original buffer.
    /// Suppressing this avoids FPs where the analyzer thinks the C string
    /// ownership was transferred to Python.
    #[test]
    fn test_gate_suppresses_ownership_violation_python_owned_ref() {
        let issue = make_issue(IssueKind::OwnershipViolation, "PyUnicode_FromString");
        let verdict = check_issue(&issue, |key, kind| {
            key == "PyUnicode_FromString" && kind == SemanticKind::PythonOwnedRef
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressRaii,
            "OwnershipViolation with PythonOwnedRef (copy constructor) must be suppressed"
        );
    }

    /// Objective: Verify OwnershipEscapeLeak with RuntimeInternal returns
    /// SuppressRuntimeInternal.
    /// Invariants: Runtime bridges are not user-level ownership escapes.
    #[test]
    fn test_gate_suppresses_ownership_escape_leak_runtime_internal() {
        let issue = make_issue(IssueKind::OwnershipEscapeLeak, "runtime_bridge");
        let verdict = check_issue(&issue, |key, kind| {
            key == "runtime_bridge" && kind == SemanticKind::RuntimeInternal
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressRuntimeInternal,
            "OwnershipEscapeLeak with RuntimeInternal must return SuppressRuntimeInternal"
        );
    }

    /// Objective: Verify SuppressRuntimeInternal reason is informative.
    /// Invariants: The reason must clearly distinguish from SuppressRaii.
    #[test]
    fn test_runtime_internal_verdict_reason() {
        let reason = GateVerdict::SuppressRuntimeInternal.reason();
        assert!(
            !reason.is_empty(),
            "SuppressRuntimeInternal reason must not be empty"
        );
        assert!(
            reason.contains("runtime") || reason.contains("internal"),
            "SuppressRuntimeInternal reason must mention runtime/internal, got: {reason}"
        );
    }

    // ── NullChecked suppression tests (CWE-476 FP reduction) ──────────

    /// Objective: Verify NullDereference with NullChecked SRT entry is suppressed.
    /// Invariants: When the enclosing function has null-check patterns (icmp+br),
    /// the gate must suppress NullDereference to avoid false positives.
    #[test]
    fn test_gate_suppresses_null_dereference_null_checked() {
        let issue = make_issue(IssueKind::NullDereference, "strlen");
        let verdict = check_issue(&issue, |key, kind| {
            key == "strlen" && kind == SemanticKind::NullChecked
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressNullChecked,
            "NullDereference with NullChecked SRT entry must be suppressed"
        );
    }

    /// Objective: Verify NullDereference without NullChecked passes the gate.
    /// Invariants: When no null-check pattern exists, the issue must be reported.
    #[test]
    fn test_gate_allows_null_dereference_no_null_check() {
        let issue = make_issue(IssueKind::NullDereference, "strlen");
        let verdict = check_issue(&issue, |_, _| false);
        assert_eq!(
            verdict,
            GateVerdict::Allow,
            "NullDereference without NullChecked must pass the gate"
        );
    }

    /// Objective: Verify UncheckedReturn with NullChecked SRT entry is suppressed.
    /// Invariants: FFI returns that are null-checked before Load/Store/GEP
    /// must be suppressed.
    #[test]
    fn test_gate_suppresses_unchecked_return_null_checked() {
        let issue = make_issue(IssueKind::UncheckedReturn, "ffi_get");
        let verdict = check_issue(&issue, |key, kind| {
            key == "ffi_get" && kind == SemanticKind::NullChecked
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressNullChecked,
            "UncheckedReturn with NullChecked SRT entry must be suppressed"
        );
    }

    /// Objective: Verify NullDereference is suppressed when NullChecked is on
    /// the enclosing function (location.function), not just the symbol.
    /// Invariants: The gate checks both issue.symbol and issue.location.function.
    #[test]
    fn test_gate_suppresses_null_dereference_by_location_function() {
        use omniscope_core::IssueLocation;
        let mut issue = make_issue(IssueKind::NullDereference, "duckdb_prepare_error");
        issue.location = Some(
            IssueLocation::new(std::path::PathBuf::from("<ir>"), 0)
                .with_function("result_from_duckdb_prepare"),
        );
        let verdict = check_issue(&issue, |key, kind| {
            // NullChecked is on the enclosing function, not the callee
            key == "result_from_duckdb_prepare" && kind == SemanticKind::NullChecked
        });
        assert_eq!(
            verdict,
            GateVerdict::SuppressNullChecked,
            "NullDereference must be suppressed when enclosing function has NullChecked"
        );
    }

    /// Objective: Verify SuppressNullChecked reason is informative.
    /// Invariants: The reason must mention null-check or conditional branch.
    #[test]
    fn test_null_checked_verdict_reason() {
        let reason = GateVerdict::SuppressNullChecked.reason();
        assert!(
            !reason.is_empty(),
            "SuppressNullChecked reason must not be empty"
        );
        assert!(
            reason.contains("null") || reason.contains("conditional"),
            "SuppressNullChecked reason must mention null/conditional, got: {reason}"
        );
    }
}
