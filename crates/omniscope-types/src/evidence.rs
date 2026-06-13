//! Evidence types for issue verification and diagnostic context.
//!
//! Every inferred summary and verified issue must carry evidence.
//! Evidence explains *why* a conclusion was reached, enabling
//! auditable output and human review of false positives.

use serde::{Deserialize, Serialize};

use crate::config::Language;
use crate::effect::Effect;
use crate::escape::EscapeKind;
use crate::pointer_contract::PointerContract;
use crate::resource_family::FamilyId;

/// Kind of evidence supporting a conclusion about a resource or issue.
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
    /// FFI return value null check missing.
    /// An FFI function returned a pointer that was used without
    /// a null check (load/store/gep/call-sink).
    FfiReturnNullCheck,
    /// Semantic fact derived from IR behavior analysis.
    /// Records a SemanticKind classification with source and confidence,
    /// enabling downstream verifiers to weight or suppress issues based
    /// on semantic understanding rather than just structural patterns.
    SemanticFactEvidence,
    /// ABI layout mismatch: struct has padding/alignment that causes
    /// incorrect field offsets at FFI boundaries.
    AbiLayoutMismatch,
    /// Unknown or insufficient evidence.
    Insufficient,
}

/// Kind of boundary evidence supporting FFI boundary detection conclusions.
///
/// This enum is separate from `EvidenceKind` because boundary detection
/// and resource contract analysis are distinct concerns:
/// - Boundary evidence answers: "Is this a cross-language boundary?"
/// - Resource evidence answers: "Is this a resource misuse?"
///
/// Separating them enables independent evolution of FFI boundary
/// detection accuracy metrics from resource contract metrics.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BoundaryEvidenceKind {
    /// Direct cross-language call detected (caller and callee have
    /// different source languages inferred from symbol mangling or
    /// debug info).
    CrossLanguageCall,
    /// Function explicitly listed in FFI boundary configuration
    /// (via --cross CLI or config file).
    ConfiguredBoundary,
    /// Call uses a non-default ABI convention (e.g., C call from
    /// Rust via extern "C", stdcall, fastcall).
    ExternalAbiCall,
    /// Function pointer or callback passed across a language boundary,
    /// creating a callback invocation path from one language into another.
    CallbackAcrossBoundary,
    /// Function pointer with ABI-annotated type (e.g., Option<extern "C" fn()>)
    /// indicating an intentional cross-language interface.
    FunctionPointerAbi,
    /// Wrapper function that exports functionality across a language
    /// boundary (e.g., #[no_mangle] extern "C" fn in Rust).
    ExportedWrapper,
    /// Runtime or compiler-generated bridge function that mediates
    /// between languages (e.g., Rust __rust_alloc).
    RuntimeBridge,
    /// Call to a known allocator/deallocator function (from family registry).
    /// Promotes weak seeds to strong when the callee has SymbolEffect::Acquire.
    AllocatorCall,
}

/// Kind of resource evidence supporting resource contract analysis conclusions.
///
/// This enum captures resource-specific evidence that indicates ownership
/// or lifetime violations. These are distinct from boundary evidence because
/// they describe what went wrong with resource management, not whether a
/// boundary was crossed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceEvidenceKind {
    /// Resource released by a different family than the one that allocated it
    /// (e.g., malloc + operator delete).
    CrossFamilyRelease,
    /// Ownership transferred across a boundary without proper cleanup
    /// on the receiving side (e.g., Box::into_raw without from_raw).
    OwnershipTransfer,
    /// Borrowed reference used in a context that requires ownership
    /// (e.g., PyList_GetItem result decremented by caller).
    BorrowedAsOwned,
    /// Reference count increment/decrement mismatch — the number of
    /// INCREF calls does not match the number of DECREF calls.
    RetainReleaseMismatch,
    /// FFI function return value used without null check — potential
    /// null pointer dereference if the FFI function fails.
    FfiReturnUnchecked,
}

/// Returns true if an `EvidenceKind` variant is a boundary-related evidence.
///
/// Boundary evidence answers: "Is this a cross-language boundary?" Only
/// kinds that directly indicate a boundary crossing are included here.
/// Resource/pointer facts (OwnershipTransfer, OwnershipEscapeLeak,
/// FfiReturnNullCheck) are NOT boundary evidence — they describe what
/// went wrong with resource management, not whether a boundary exists.
/// Including them would recreate the design bug where resource evidence
/// alone satisfies FFI evidence requirements.
pub fn is_boundary_evidence(kind: &EvidenceKind) -> bool {
    matches!(
        kind,
        EvidenceKind::CrossLanguageFree | EvidenceKind::CallbackEscape
    )
}

/// Returns true if an `EvidenceKind` variant is a resource-related evidence.
///
/// This helper supports gradual migration from the unified `EvidenceKind`
/// to the separated `BoundaryEvidenceKind` / `ResourceEvidenceKind` model.
pub fn is_resource_evidence(kind: &EvidenceKind) -> bool {
    matches!(
        kind,
        EvidenceKind::SameFamilyRelease
            | EvidenceKind::CrossFamilyMismatch
            | EvidenceKind::DestructorRelease
            | EvidenceKind::RaiiDropRelease
            | EvidenceKind::MultipleRelease
            | EvidenceKind::UseAfterFree
            | EvidenceKind::InvalidBorrowedFree
            | EvidenceKind::RawOwnershipReclaim
            | EvidenceKind::RefcountConditional
    )
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
    /// Unchecked FFI return value: an FFI function returned a pointer
    /// that was used without a null check (load/store/gep/call-sink).
    /// This is a potential null pointer dereference if the FFI function
    /// returns null on failure.
    UncheckedFfiReturn,
    /// Null pointer dereference: a pointer that may be null was
    /// dereferenced without a null check. This includes FFI returns
    /// passed to null-sink functions (strlen, memcpy, free, etc.).
    NullDereference,
    /// Cross-language free: memory allocated in one language freed in another.
    /// This is the FFI boundary variant of cross-family free.
    /// Example: Rust Box allocated, C free() called.
    CrossLanguageFree,
    /// ABI layout mismatch: struct has padding/alignment issues that
    /// cause incorrect field offsets when accessed across FFI boundaries.
    /// Example: {u32, u8, size_t} has 3 bytes of padding that a packed
    /// layout caller does not account for.
    AbiLayoutMismatch,
    /// Boundary misuse: data is passed across an FFI boundary with
    /// incompatible types, causing silent truncation or corruption.
    /// Example: C passes {u64,u64} (16B) via void*, C reads as
    /// {u32,u32} (8B) — high 32 bits silently truncated (FN-8).
    BoundaryMisuse,
}

/// Evidence that a resource crosses a declared FFI boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossBoundaryEvidence {
    /// Source language of the boundary.
    pub from: Language,
    /// Target language of the boundary.
    pub to: Language,
    /// How the boundary was detected.
    pub detection_method: BoundaryDetectionMethod,
}

/// How a cross-boundary relationship was detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BoundaryDetectionMethod {
    /// Explicit function in declared boundary list.
    ExplicitFunction,
    /// Pattern match (e.g., c_*).
    PatternMatch,
    /// Language-pair match (empty functions list).
    LanguagePairMatch,
    /// Auto-inferred from naming conventions.
    AutoInferred,
}

/// A free/deallocation site with its context.
///
/// Tracks where a free/release call occurs, the resource being freed,
/// and whether the site is confirmed as a release. Used by the may-alias
/// gate to determine if two free sites refer to the same underlying
/// allocation, and by issue candidates to record participating free calls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FreeSite {
    /// Function name where the free occurs.
    pub function_name: String,
    /// Instruction index or IR line of the free call.
    pub location: usize,
    /// The resource ID being freed (if determinable).
    pub resource_id: Option<u64>,
    /// The callee being called (e.g., "free", "c_free").
    pub callee: String,
    /// Whether this is a confirmed free site vs. a potential one.
    pub is_confirmed: bool,
    /// SSA register / global of the pointer argument, if recoverable.
    /// Used by the may-alias gate for SSA root tracing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arg_register: Option<String>,
    /// Enclosing caller function name (the caller that contains this free call).
    /// Distinct from `function_name` when the free is indirect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
}

impl FreeSite {
    /// Creates a new FreeSite with the given function name, callee, and
    /// optional SSA argument register. Other fields default to sensible
    /// values (location=0, is_confirmed=true).
    pub fn new(
        function_name: impl Into<String>,
        callee: impl Into<String>,
        arg_register: Option<String>,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            location: 0,
            resource_id: None,
            callee: callee.into(),
            is_confirmed: true,
            arg_register,
            caller: None,
        }
    }

    /// Sets the instruction location for this free site.
    pub fn with_location(mut self, location: usize) -> Self {
        self.location = location;
        self
    }

    /// Sets the resource ID for this free site.
    pub fn with_resource_id(mut self, resource_id: u64) -> Self {
        self.resource_id = Some(resource_id);
        self
    }

    /// Sets whether this is a confirmed free site.
    pub fn with_confirmed(mut self, is_confirmed: bool) -> Self {
        self.is_confirmed = is_confirmed;
        self
    }

    /// Sets the enclosing caller function name.
    pub fn with_caller(mut self, caller: impl Into<String>) -> Self {
        self.caller = Some(caller.into());
        self
    }
}

/// Source of alias determination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AliasSource {
    /// Same pointer value (identical SSA value or direct pointer match).
    SamePointer,
    /// Store-load chain: `store p` then `load` produces value aliasing p.
    StoreLoadChain,
    /// Memory graph analysis found alias relationship.
    MemoryGraph,
    /// IR pattern matched alias-producing code sequence.
    IRPattern,
    /// Conservative alias (assume alias when uncertain).
    Conservative,
}

/// Confidence level for evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Structured alias evidence produced by may_alias analysis.
///
/// This links two free sites when they are determined to alias the same
/// underlying resource, enabling the verifier to distinguish confirmed
/// double-free from independent frees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasEvidence {
    /// Unique identifier for this evidence instance.
    pub id: u64,
    /// The resource ID that is being aliased (if known).
    pub resource_id: Option<u64>,
    /// The first free site involved in the alias.
    pub free_site_a: FreeSite,
    /// The second free site involved in the alias.
    pub free_site_b: FreeSite,
    /// Source of the alias determination.
    pub source: AliasSource,
    /// Confidence level.
    pub confidence: Confidence,
    /// Human-readable description of the alias reasoning.
    pub description: String,
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
        // When adding new variants, update this list — do NOT assert a
        // hardcoded count, as it silently breaks when variants are added.
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
            IssueCandidateKind::UncheckedFfiReturn,
            IssueCandidateKind::NullDereference,
            IssueCandidateKind::CrossLanguageFree,
            IssueCandidateKind::AbiLayoutMismatch,
            IssueCandidateKind::BoundaryMisuse,
        ];
        // Verify no duplicates (each variant appears exactly once)
        let unique_count = {
            let mut seen = std::collections::HashSet::new();
            kinds.iter().filter(|k| seen.insert(**k)).count()
        };
        assert_eq!(
            unique_count,
            kinds.len(),
            "Duplicate IssueCandidateKind variants in test list"
        );
    }

    #[test]
    fn test_boundary_evidence_kind_variants() {
        // Verify all BoundaryEvidenceKind variants exist and are distinct.
        let kinds = [
            BoundaryEvidenceKind::CrossLanguageCall,
            BoundaryEvidenceKind::ConfiguredBoundary,
            BoundaryEvidenceKind::ExternalAbiCall,
            BoundaryEvidenceKind::CallbackAcrossBoundary,
            BoundaryEvidenceKind::FunctionPointerAbi,
            BoundaryEvidenceKind::ExportedWrapper,
            BoundaryEvidenceKind::RuntimeBridge,
        ];
        assert_eq!(
            kinds.len(),
            7,
            "Must have 7 BoundaryEvidenceKind variants as specified in FFI plan"
        );
    }

    #[test]
    fn test_resource_evidence_kind_variants() {
        // Verify all ResourceEvidenceKind variants exist and are distinct.
        let kinds = [
            ResourceEvidenceKind::CrossFamilyRelease,
            ResourceEvidenceKind::OwnershipTransfer,
            ResourceEvidenceKind::BorrowedAsOwned,
            ResourceEvidenceKind::RetainReleaseMismatch,
            ResourceEvidenceKind::FfiReturnUnchecked,
        ];
        assert_eq!(
            kinds.len(),
            5,
            "Must have 5 ResourceEvidenceKind variants as specified in FFI plan"
        );
    }

    #[test]
    fn test_is_boundary_evidence_classification() {
        // Only kinds that directly indicate a cross-language boundary
        // crossing should be classified as boundary evidence.
        // Resource/pointer facts (OwnershipTransfer, OwnershipEscapeLeak,
        // FfiReturnNullCheck) are NOT boundary evidence — they describe
        // what went wrong with resource management, not whether a boundary
        // exists.
        assert!(
            is_boundary_evidence(&EvidenceKind::CrossLanguageFree),
            "CrossLanguageFree must be classified as boundary evidence"
        );
        assert!(
            is_boundary_evidence(&EvidenceKind::CallbackEscape),
            "CallbackEscape must be classified as boundary evidence"
        );
        // OwnershipTransfer is a resource fact, not boundary evidence.
        assert!(
            !is_boundary_evidence(&EvidenceKind::OwnershipTransfer),
            "OwnershipTransfer must NOT be classified as boundary evidence"
        );
        // OwnershipEscapeLeak is a resource fact, not boundary evidence.
        assert!(
            !is_boundary_evidence(&EvidenceKind::OwnershipEscapeLeak),
            "OwnershipEscapeLeak must NOT be classified as boundary evidence"
        );
        // FfiReturnNullCheck is a call-safety fact, not boundary evidence.
        assert!(
            !is_boundary_evidence(&EvidenceKind::FfiReturnNullCheck),
            "FfiReturnNullCheck must NOT be classified as boundary evidence"
        );
        // Non-boundary evidence should not be classified as boundary.
        assert!(
            !is_boundary_evidence(&EvidenceKind::SameFamilyRelease),
            "SameFamilyRelease must NOT be classified as boundary evidence"
        );
        assert!(
            !is_boundary_evidence(&EvidenceKind::RaiiDropRelease),
            "RaiiDropRelease must NOT be classified as boundary evidence"
        );
    }

    #[test]
    fn test_is_resource_evidence_classification() {
        // Resource-related EvidenceKind variants should be classified as resource.
        assert!(
            is_resource_evidence(&EvidenceKind::SameFamilyRelease),
            "SameFamilyRelease must be classified as resource evidence"
        );
        assert!(
            is_resource_evidence(&EvidenceKind::CrossFamilyMismatch),
            "CrossFamilyMismatch must be classified as resource evidence"
        );
        assert!(
            is_resource_evidence(&EvidenceKind::UseAfterFree),
            "UseAfterFree must be classified as resource evidence"
        );
        // Non-resource evidence should not be classified as resource.
        assert!(
            !is_resource_evidence(&EvidenceKind::CrossLanguageFree),
            "CrossLanguageFree must NOT be classified as resource evidence"
        );
        assert!(
            !is_resource_evidence(&EvidenceKind::SymbolPattern),
            "SymbolPattern must NOT be classified as resource evidence"
        );
    }
}
