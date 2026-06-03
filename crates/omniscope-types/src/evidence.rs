//! Evidence types for issue verification and diagnostic context.
//!
//! Every inferred summary and verified issue must carry evidence.
//! Evidence explains *why* a conclusion was reached, enabling
//! auditable output and human review of false positives.

use serde::{Deserialize, Serialize};

use crate::effect::Effect;
use crate::escape::EscapeKind;
use crate::pointer_contract::PointerContract;
use crate::resource_family::FamilyId;

/// Kind of evidence supporting a conclusion.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Same-family release evidence (alloc and free from same family).
    SameFamilyRelease,
    /// Cross-family mismatch evidence.
    CrossFamilyMismatch,
    /// Destructor/drop-mediated release.
    DestructorRelease,
    /// Slice-to-pointer bridge (borrowed return helper).
    BridgeHelper,
    /// Reference count conditional release.
    RefcountConditional,
    /// Static lifetime sink.
    StaticLifetimeSink,
    /// Return-to-caller ownership transfer.
    ReturnToCaller,
    /// Out-param initialization.
    OutParamInit,
    /// Field-store into owner.
    FieldStoreToOwner,
    /// Global/static store.
    GlobalStore,
    /// Callback escape.
    CallbackEscape,
    /// Symbol name pattern match.
    SymbolPattern,
    /// Debug info / source language hint.
    DebugInfo,
    /// Call graph structural evidence.
    CallGraphStructure,
    /// IR pattern (e.g. getelementptr-only body).
    IrPattern,
    /// Manual model annotation.
    ModelAnnotation,
    /// Parameter mutability inference (readonly=&T, mutable=&mut T).
    /// Evidence: bun_fp R-0 — LLVM readonly/noalias parameter attributes.
    ParameterMutability,
    /// Ownership transfer via into_raw (Box/CString/Vec::into_raw).
    /// Evidence: bun_fp R-6 — intentional ownership transfer to caller.
    OwnershipTransfer,
    /// POSIX syscall semantic classification (file/net/proc/mem).
    /// Evidence: bun_fp R-4 — non-memory POSIX ops don't participate in UAF.
    PosixSyscallClass,
    /// RAII drop release (compiler-inserted cleanup, not user bug).
    /// Evidence: bun_fp R-3 — drop_in_place / tail dealloc.
    RaiiDropRelease,
    /// Raw pointer ownership reclaimed via from_raw (Box::from_raw, CString::from_raw).
    /// Indicates the resource re-entered Rust's ownership from a raw pointer.
    RawOwnershipReclaim,
    /// Ownership escaped via into_raw without matching from_raw reclaim.
    /// Evidence: ownership_transfer_escape — resource leaked across FFI boundary.
    OwnershipEscapeLeak,
    /// Double/multiple release on the same resource instance.
    /// Evidence: instance released more than once — structural double-free.
    MultipleRelease,
    /// Use-after-free: a released resource was subsequently used
    /// (e.g. passed to an FFI function or borrowed).
    /// Distinct from BorrowEscape — this requires the resource to
    /// have been freed before the use.
    UseAfterFree,
    /// Invalid free of a borrowed pointer: a borrowed pointer (not owned)
    /// was passed to a release function. This is a contract violation
    /// because borrowed pointers should not be freed by the borrower.
    /// Evidence: borrowed pointer instance with release edge.
    InvalidBorrowedFree,
    /// Cross-language free: resource allocated in one language family
    /// but freed in another language family (e.g., Rust alloc + C free).
    /// This is a subset of CrossFamilyMismatch for language boundaries.
    CrossLanguageFree,
    /// Release function has NULL guard (release(NULL) is safe).
    /// Common in C libraries: free(NULL), cJSON_Delete(NULL).
    NullGuardedRelease,
    /// NULL is stored to pointer after release.
    /// Pattern: `free(p); p = NULL;` - prevents dangling pointer.
    NullStoreAfterRelease,
    /// Out-param receives owned resource on success.
    /// Pattern: `if (success) *out = new_resource;`
    OutParamOwnedOnSuccess,
    /// Out-param is set to NULL on error path.
    /// Pattern: `if (error) *out = NULL;`
    OutParamNullOnError,
    /// Path state refined by analysis.
    /// Indicates conditional branches were analyzed to determine
    /// resource ownership state on specific paths.
    PathStateRefinement,
    /// Unknown or insufficient evidence.
    Insufficient,
}

/// An evidence item supporting a conclusion about a resource or issue.
///
/// Evidence objects are produced by inference passes and consumed
/// by the verifier. They should be attached to summaries and
/// issue candidates, and included in diagnostic/debug output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// What kind of evidence this is.
    pub kind: EvidenceKind,
    /// Human-readable description of the evidence.
    pub description: String,
    /// Resource family involved (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<FamilyId>,
    /// Pointer contract involved (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<PointerContract>,
    /// Escape kind involved (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escape: Option<EscapeKind>,
    /// Effect that produced this evidence (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<Effect>,
    /// Confidence level for this evidence (0.0 - 1.0).
    pub confidence: f32,
}

impl Evidence {
    /// Creates evidence with a kind and description.
    pub fn new(kind: EvidenceKind, description: impl Into<String>) -> Self {
        Self {
            kind,
            description: description.into(),
            family: None,
            contract: None,
            escape: None,
            effect: None,
            confidence: 0.5,
        }
    }

    /// Sets the confidence level.
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    /// Attaches a resource family.
    pub fn with_family(mut self, family: FamilyId) -> Self {
        self.family = Some(family);
        self
    }

    /// Attaches a pointer contract.
    pub fn with_contract(mut self, contract: PointerContract) -> Self {
        self.contract = Some(contract);
        self
    }

    /// Attaches an escape kind.
    pub fn with_escape(mut self, escape: EscapeKind) -> Self {
        self.escape = Some(escape);
        self
    }

    /// Returns true if this evidence is high-confidence (>= 0.8).
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }
}

/// Issue candidate kinds, produced by the candidate builder
/// before verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IssueCandidateKind {
    /// Alloc and free from different resource families.
    CrossFamilyFree,
    /// Pointer used after it was released.
    UseAfterRelease,
    /// Same resource released twice.
    DoubleRelease,
    /// Resource not freed on some execution paths.
    ConditionalLeak,
    /// Resource not freed on any analyzed path (definite leak).
    DefiniteLeak,
    /// Borrowed pointer escaped to a context requiring ownership.
    BorrowEscape,
    /// Pointer escaped to a callback that may assume ownership.
    CallbackEscape,
    /// Needs a model annotation — unknown family or cleanup.
    NeedsModel,
    /// Same raw pointer reclaimed multiple times via from_raw (double reclaim).
    /// This is a use-after-free/double-free pattern for raw pointer ownership.
    DoubleReclaim,
    /// Ownership escaped via into_raw but never reclaimed via from_raw.
    /// The raw pointer was leaked across the FFI boundary.
    OwnershipEscapeLeak,
    /// Use-after-free: a released resource was subsequently used
    /// (e.g. passed to an FFI function after being freed).
    /// Distinct from BorrowEscape (borrowed reference escaping scope)
    /// and UseAfterRelease (released allocation used again) — this
    /// specifically covers the FFI boundary case where a freed
    /// pointer is passed across the language boundary.
    UseAfterFree,
    /// Invalid free of a borrowed pointer: a borrowed pointer (not owned)
    /// was passed to a release function. This is a contract violation
    /// because borrowed pointers should not be freed by the borrower.
    /// This is different from BorrowEscape (which is about escaping scope)
    /// — this is about actually freeing a borrowed pointer.
    InvalidBorrowedFree,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_builder_pattern() {
        let evidence = Evidence::new(
            EvidenceKind::SameFamilyRelease,
            "malloc/free from c_heap family",
        )
        .with_confidence(0.95)
        .with_family(FamilyId::C_HEAP);

        assert_eq!(
            evidence.kind,
            EvidenceKind::SameFamilyRelease,
            "Evidence kind must be SameFamilyRelease"
        );
        assert_eq!(
            evidence.family,
            Some(FamilyId::C_HEAP),
            "Evidence family must be C_HEAP"
        );
        assert!(
            evidence.is_high_confidence(),
            "0.95 >= 0.8 should be high confidence"
        );
    }

    #[test]
    fn test_low_confidence_evidence() {
        let evidence = Evidence::new(EvidenceKind::SymbolPattern, "name matches prefix pattern")
            .with_confidence(0.3);

        assert!(
            !evidence.is_high_confidence(),
            "0.3 < 0.8 should NOT be high confidence"
        );
    }

    #[test]
    fn test_issue_candidate_kinds() {
        // Verify all candidate kinds from the architecture doc are present.
        let kinds = [
            IssueCandidateKind::CrossFamilyFree,
            IssueCandidateKind::UseAfterRelease,
            IssueCandidateKind::DoubleRelease,
            IssueCandidateKind::ConditionalLeak,
            IssueCandidateKind::DefiniteLeak,
            IssueCandidateKind::BorrowEscape,
            IssueCandidateKind::CallbackEscape,
            IssueCandidateKind::NeedsModel,
            IssueCandidateKind::DoubleReclaim,
            IssueCandidateKind::OwnershipEscapeLeak,
            IssueCandidateKind::UseAfterFree,
            IssueCandidateKind::InvalidBorrowedFree,
        ];
        assert_eq!(
            kinds.len(),
            12,
            "Must have 12 candidate kinds as specified in architecture doc"
        );
    }
}
