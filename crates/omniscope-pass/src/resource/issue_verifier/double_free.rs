//! Double release / double free verification logic.

use omniscope_core::IssueCandidate;
use omniscope_types::{EvidenceKind, VerifierVerdict};

use super::super::evidence_bundle::EvidenceBundle;
use super::helpers::has_evidence;

/// Verifies a double release candidate using the evidence bundle.
///
/// This is the bundle-based replacement for `verify_double_release`.
/// It requires:
/// - Same resource instance (resource_id or MultipleRelease evidence)
/// - No alias rejection (may_alias != NotAlias)
/// - No null-safe pattern with path evidence
pub(crate) fn verify_double_release_with_bundle(bundle: &EvidenceBundle) -> VerifierVerdict {
    let has_null_guard = bundle
        .evidence_kinds
        .contains(&EvidenceKind::NullGuardedRelease);
    let has_null_store = bundle
        .evidence_kinds
        .contains(&EvidenceKind::NullStoreAfterRelease);
    let has_path_refinement = bundle
        .evidence_kinds
        .contains(&EvidenceKind::PathStateRefinement);

    // All three: fully analyzed null-guarded pattern → safe.
    if has_null_guard && has_null_store && has_path_refinement {
        return VerifierVerdict::ExplainedSafe;
    }

    // Null-guarded release in different callers: if the alloc and release
    // happen in different enclosing functions, the releases are from
    // separate call sites — not a same-pointer double-free.
    if has_null_guard {
        if let (Some(ref alloc_caller), Some(ref release_caller)) =
            (bundle.alloc_caller.as_ref(), bundle.release_caller.as_ref())
        {
            if alloc_caller != release_caller {
                return VerifierVerdict::ExplainedSafe;
            }
        }
    }

    // ── Same resource instance gate ──
    let has_same_instance = bundle.has_same_resource_evidence
        || bundle
            .evidence_kinds
            .contains(&EvidenceKind::MultipleRelease);

    // ── May-alias gate ──
    if bundle.has_alias_rejection {
        tracing::debug!(
            candidate_id = bundle.candidate_id,
            "DoubleFree alias gate rejected: site_a={:?} site_b={:?} reason=NotAlias",
            bundle.alloc_caller,
            bundle.release_caller
        );
        return VerifierVerdict::ProbableIssue;
    }

    // If we lack same-instance evidence AND lack alias rejection,
    // we cannot confirm this is a same-pointer double-free.
    if !has_same_instance {
        tracing::debug!(
            candidate_id = bundle.candidate_id,
            "DoubleFree same-instance gate: no same_resource or MultipleRelease evidence, downgrading to ProbableIssue"
        );
        return VerifierVerdict::ProbableIssue;
    }

    // Null-guard alone does NOT make double-free safe.
    // `free(NULL)` is safe, but `free(ptr); free(ptr)` with non-null
    // ptr is undefined behavior (CWE-415). Without path analysis
    // proving the pointer is null at the second release, this is
    // still a confirmed issue.

    // Default: double-free is a confirmed issue when we have
    // same-instance evidence and no alias rejection.
    VerifierVerdict::ConfirmedIssue
}

/// Verifies a double release candidate.
///
/// Checks if the double release is safe based on evidence:
/// - Null-guarded release functions (release(NULL) is safe)
/// - NULL stored after release (prevents dangling pointer)
/// - Path state refinement (control flow analysis)
/// - Multiple free calls in different callers (not same-instance double-free)
pub(crate) fn verify_double_release(candidate: &IssueCandidate) -> VerifierVerdict {
    let has_null_guard = has_evidence(candidate, EvidenceKind::NullGuardedRelease);
    let has_null_store = has_evidence(candidate, EvidenceKind::NullStoreAfterRelease);
    let has_path_refinement = has_evidence(candidate, EvidenceKind::PathStateRefinement);

    // All three: fully analyzed null-guarded pattern → safe.
    if has_null_guard && has_null_store && has_path_refinement {
        return VerifierVerdict::ExplainedSafe;
    }

    // Null-guarded release in different callers.
    if has_null_guard {
        if let (Some(ref alloc_caller), Some(ref release_caller)) = (
            candidate.alloc_caller.as_ref(),
            candidate.release_caller.as_ref(),
        ) {
            if alloc_caller != release_caller {
                return VerifierVerdict::ExplainedSafe;
            }
        }
    }

    // ── May-alias gate ──
    if has_may_alias_rejection(candidate) {
        tracing::debug!(
            target: "omniscope_pass::issue_verifier",
            "DoubleFree alias gate rejected: site_a={:?} site_b={:?} reason=NotAlias",
            candidate.alloc_caller,
            candidate.release_caller
        );
        return VerifierVerdict::ProbableIssue;
    }

    // Null-guard alone does NOT make double-free safe.
    // Default: double-free is a confirmed issue
    VerifierVerdict::ConfirmedIssue
}

/// Returns true when the candidate carries an `Insufficient` evidence
/// describing a may-alias gate rejection (description prefixed with
/// `may_alias=NotAlias`). This is the contract between the candidate
/// builder and `verify_double_release`.
pub(crate) fn has_may_alias_rejection(candidate: &IssueCandidate) -> bool {
    candidate.evidence.iter().any(|e| {
        e.kind == EvidenceKind::Insufficient && e.description.starts_with("may_alias=NotAlias")
    })
}
