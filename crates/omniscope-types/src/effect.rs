//! Function effect types for resource contract analysis.
//!
//! Effects are the shared vocabulary consumed by memory, lifetime, FFI,
//! and dataflow analysis. Every pass should read `FunctionSummary` effects
//! instead of re-identifying callee semantics from function names.

use serde::{Deserialize, Serialize};

use crate::resource_family::FamilyId;

/// Index of a function argument (0-based).
pub type ArgIndex = u32;

/// A function effect describes what a function does to a resource.
///
/// Effects are the atomic units of function summaries. Instead of
/// classifying functions by name patterns, we classify them by the
/// effects they produce. This enables correct behavior for wrappers,
/// inline functions, and unknown call targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Effect {
    /// Acquires a resource from the given family (e.g. malloc, PyObject_New).
    Acquire {
        family: FamilyId,
        /// Value ID that receives the acquired resource.
        result: u64,
    },
    /// Unconditionally releases a resource (e.g. free, operator delete).
    Release {
        family: FamilyId,
        /// Argument index that holds the resource to release.
        arg: ArgIndex,
    },
    /// Conditionally releases a resource (e.g. Py_DECREF, Arc::drop).
    ///
    /// The release only happens when the refcount reaches zero.
    /// Do NOT model this as unconditional `Release`.
    ConditionalRelease { family: FamilyId, arg: ArgIndex },
    /// Retains a reference (e.g. Py_INCREF, CFRetain, AddRef).
    Retain { family: FamilyId, arg: ArgIndex },
    /// Returns an owned resource to the caller (e.g. factory functions).
    ReturnsOwned { family: FamilyId },
    /// Returns a borrowed reference (e.g. as_ptr, getelementptr bridges).
    ReturnsBorrowed,
    /// Consumes an argument without releasing it (e.g. move, transfer).
    ConsumesArg {
        arg: ArgIndex,
        /// Family if known, None if unknown.
        family: Option<FamilyId>,
    },
    /// Stores an argument into an owner object's field.
    StoresArgToOwner {
        arg: ArgIndex,
        /// The argument that owns the destination.
        owner: ArgIndex,
    },
    /// Stores an argument to global/static storage.
    StoresArgToGlobal { arg: ArgIndex },
    /// Initializes an output parameter with a resource.
    InitializesOutParam { arg: ArgIndex, family: FamilyId },
    /// Argument escapes to a callback function.
    EscapesToCallback { arg: ArgIndex },
    /// Ownership escapes via into_raw (Box::into_raw, CString::into_raw).
    /// The resource is still allocated but ownership is now tracked by
    /// a raw pointer outside Rust's type system. This is NOT a release —
    /// the resource must eventually be reclaimed via from_raw.
    OwnershipEscape {
        family: FamilyId,
        /// Value ID of the raw pointer that receives ownership.
        result: u64,
    },
    /// Ownership reclaimed from a raw pointer via from_raw
    /// (Box::from_raw, CString::from_raw). This is an Acquire from the
    /// raw pointer perspective — the resource re-enters Rust's ownership.
    OwnershipReclaim {
        family: FamilyId,
        /// Value ID that receives the reclaimed resource.
        result: u64,
    },
    /// Cross-language free: resource allocated in one language family
    /// but freed in another language family (e.g., Rust alloc + C free).
    /// This is a stronger signal than ConditionalRelease for language
    /// boundary violations.
    CrossLanguageFree {
        /// The family that allocated the resource.
        alloc_family: FamilyId,
        /// The family that is releasing the resource.
        release_family: FamilyId,
        /// Argument index that holds the resource to release.
        arg: ArgIndex,
    },
    /// Release function has NULL guard - release(NULL) is safe no-op.
    /// Common pattern in C libraries (e.g., free(NULL), cJSON_Delete(NULL)).
    NullGuardedRelease {
        /// Resource family that this release belongs to.
        family: FamilyId,
        /// Argument index that holds the resource to release.
        arg: ArgIndex,
    },
    /// Out-param receives owned resource on success path.
    /// Pattern: `if (success) *out = new_resource;`
    OutParamOwnedOnSuccess {
        /// Resource family being transferred.
        family: FamilyId,
        /// Argument index of the out-parameter.
        arg: ArgIndex,
    },
    /// Out-param is set to NULL on error path.
    /// Pattern: `if (error) *out = NULL;`
    OutParamNullOnError {
        /// Argument index of the out-parameter.
        arg: ArgIndex,
    },
    /// NULL store after release - slot becomes NULL after dealloc.
    /// Pattern: `free(p); p = NULL;`
    NullStoreAfterRelease {
        /// Argument index of the pointer being nulled.
        arg: ArgIndex,
    },
}

impl Effect {
    /// Returns the resource family involved in this effect, if any.
    pub fn family(&self) -> Option<FamilyId> {
        match self {
            Effect::Acquire { family, .. } => Some(*family),
            Effect::Release { family, .. } => Some(*family),
            Effect::ConditionalRelease { family, .. } => Some(*family),
            Effect::Retain { family, .. } => Some(*family),
            Effect::ReturnsOwned { family } => Some(*family),
            Effect::ConsumesArg { family, .. } => *family,
            Effect::InitializesOutParam { family, .. } => Some(*family),
            Effect::OwnershipEscape { family, .. } => Some(*family),
            Effect::OwnershipReclaim { family, .. } => Some(*family),
            Effect::CrossLanguageFree { release_family, .. } => Some(*release_family),
            Effect::NullGuardedRelease { family, .. } => Some(*family),
            Effect::OutParamOwnedOnSuccess { family, .. } => Some(*family),
            Effect::ReturnsBorrowed
            | Effect::StoresArgToOwner { .. }
            | Effect::StoresArgToGlobal { .. }
            | Effect::EscapesToCallback { .. }
            | Effect::OutParamNullOnError { .. }
            | Effect::NullStoreAfterRelease { .. } => None,
        }
    }

    /// Returns true if this effect acquires a resource.
    pub fn is_acquire(&self) -> bool {
        matches!(
            self,
            Effect::Acquire { .. } | Effect::ReturnsOwned { .. } | Effect::OwnershipReclaim { .. }
        )
    }

    /// Returns true if this effect releases a resource (conditional or unconditional).
    pub fn is_release(&self) -> bool {
        matches!(
            self,
            Effect::Release { .. }
                | Effect::ConditionalRelease { .. }
                | Effect::CrossLanguageFree { .. }
                | Effect::NullGuardedRelease { .. }
        )
    }

    /// Returns true if this effect is a retain (refcount increment).
    pub fn is_retain(&self) -> bool {
        matches!(self, Effect::Retain { .. })
    }

    /// Returns true if this effect represents ownership escape (into_raw).
    pub fn is_ownership_escape(&self) -> bool {
        matches!(self, Effect::OwnershipEscape { .. })
    }

    /// Returns a human-readable label for diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Effect::Acquire { .. } => "acquire",
            Effect::Release { .. } => "release",
            Effect::ConditionalRelease { .. } => "conditional_release",
            Effect::Retain { .. } => "retain",
            Effect::ReturnsOwned { .. } => "returns_owned",
            Effect::ReturnsBorrowed => "returns_borrowed",
            Effect::ConsumesArg { .. } => "consumes_arg",
            Effect::StoresArgToOwner { .. } => "stores_arg_to_owner",
            Effect::StoresArgToGlobal { .. } => "stores_arg_to_global",
            Effect::InitializesOutParam { .. } => "initializes_out_param",
            Effect::EscapesToCallback { .. } => "escapes_to_callback",
            Effect::OwnershipEscape { .. } => "ownership_escape",
            Effect::OwnershipReclaim { .. } => "ownership_reclaim",
            Effect::CrossLanguageFree { .. } => "cross_language_free",
            Effect::NullGuardedRelease { .. } => "null_guarded_release",
            Effect::OutParamOwnedOnSuccess { .. } => "out_param_owned_on_success",
            Effect::OutParamNullOnError { .. } => "out_param_null_on_error",
            Effect::NullStoreAfterRelease { .. } => "null_store_after_release",
        }
    }
}

/// Language hint for a function, derived from debug info and symbol patterns.
///
/// Language is NOT the primary criterion for alloc/free matching.
/// It serves as context for demangling, ABI hints, and report formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LanguageHint {
    /// C language.
    C,
    /// C++ language.
    Cpp,
    /// Rust language.
    Rust,
    /// Python C API.
    Python,
    /// Java/JNI.
    Java,
    /// C# / .NET.
    CSharp,
    /// Go language.
    Go,
    /// Zig language.
    Zig,
    /// Unknown or ambiguous language.
    Unknown,
}

/// Origin of a function (where it comes from).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FunctionOrigin {
    /// User/application code.
    UserCode,
    /// Standard library (libc, libstdc++, etc.).
    Stdlib,
    /// Runtime library (compiler-rt, etc.).
    Runtime,
    /// Third-party library.
    ThirdParty,
    /// Auto-generated (bindgen, cxx, protobuf).
    Generated,
    /// Unknown origin.
    Unknown,
}

/// Verifier verdict for an issue candidate.
///
/// Only `ConfirmedIssue` and high-confidence `ProbableIssue` should
/// appear in default JSON/SARIF output. Diagnostics require explicit
/// debug flags. `ExplainedSafe` means the candidate was investigated
/// and found to be benign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerifierVerdict {
    /// Confirmed real issue with high confidence.
    ConfirmedIssue,
    /// Probable issue — needs human review but likely real.
    ProbableIssue,
    /// Diagnostic — not a bug, but useful for debugging analysis.
    Diagnostic,
    /// Candidate was investigated and explained as safe.
    ExplainedSafe,
}

impl VerifierVerdict {
    /// Returns true if this verdict should appear in default output.
    pub fn is_reportable(&self) -> bool {
        matches!(
            self,
            VerifierVerdict::ConfirmedIssue | VerifierVerdict::ProbableIssue
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effect_classification() {
        let acquire = Effect::Acquire {
            family: FamilyId::C_HEAP,
            result: 1,
        };
        assert!(
            acquire.is_acquire(),
            "Acquire must be classified as acquire"
        );
        assert!(
            !acquire.is_release(),
            "Acquire must NOT be classified as release"
        );

        let release = Effect::Release {
            family: FamilyId::C_HEAP,
            arg: 0,
        };
        assert!(
            release.is_release(),
            "Release must be classified as release"
        );
        assert!(
            !release.is_acquire(),
            "Release must NOT be classified as acquire"
        );

        let cond_release = Effect::ConditionalRelease {
            family: FamilyId::PYTHON_OBJECT,
            arg: 0,
        };
        assert!(
            cond_release.is_release(),
            "ConditionalRelease must be classified as release"
        );
    }

    #[test]
    fn test_effect_family_extraction() {
        let effect = Effect::Acquire {
            family: FamilyId::RUST_GLOBAL,
            result: 1,
        };
        assert_eq!(
            effect.family(),
            Some(FamilyId::RUST_GLOBAL),
            "Acquire effect must return its family"
        );

        let borrowed = Effect::ReturnsBorrowed;
        assert_eq!(
            borrowed.family(),
            None,
            "ReturnsBorrowed must have no family"
        );
    }

    #[test]
    fn test_verifier_verdict_reportable() {
        assert!(
            VerifierVerdict::ConfirmedIssue.is_reportable(),
            "ConfirmedIssue is reportable"
        );
        assert!(
            VerifierVerdict::ProbableIssue.is_reportable(),
            "ProbableIssue is reportable"
        );
        assert!(
            !VerifierVerdict::Diagnostic.is_reportable(),
            "Diagnostic is NOT reportable by default"
        );
        assert!(
            !VerifierVerdict::ExplainedSafe.is_reportable(),
            "ExplainedSafe is NOT reportable"
        );
    }
}
