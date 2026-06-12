//! Double release / double free verification logic.

use omniscope_core::IssueCandidate;
use omniscope_types::{EvidenceKind, VerifierVerdict};

use super::super::evidence_bundle::EvidenceBundle;
use super::helpers::{has_evidence, is_runtime_deallocator_function};

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

    // ── Mutual-exclusivity (same-function deallocator) gate ──
    // When alloc_function is a pure runtime deallocator (free, munmap,
    // __rust_dealloc, _ZdlPv, _ZdaPv) AND both releases originate from
    // the same caller function, the double-release candidate almost always
    // comes from if/else branches where each path frees the resource once.
    //
    // This is NOT a same-pointer double-free — it is a control-flow merge
    // artefact where the contract graph cannot distinguish mutually
    // exclusive basic blocks. Examples:
    //   - merkle_free_node(node, is_leaf): leaf_free vs internal_free
    //   - fft_bridge_cleanup(result, has_error): error_free vs normal_free
    //
    // This gate runs BEFORE the same-instance and alias checks because
    // candidates lacking strong same-instance evidence (no resource_id,
    // no MultipleRelease) would be downgraded to ProbableIssue before
    // reaching a later mutual-exclusivity check. The pattern itself —
    // pure deallocation function + same caller — is strong enough to
    // suppress regardless of instance-tracking strength.
    //
    // Legitimate same-function double-frees (sequential free(ptr); free(ptr))
    // are rare and typically carry additional evidence that bypasses this
    // gate: post-release use (UAF check below via has_use_after), or
    // strong alias proof from cross-call-site analysis.
    let has_use_after = bundle.evidence_kinds.contains(&EvidenceKind::UseAfterFree);
    let is_deallocator = is_runtime_deallocator_function(&bundle.alloc_function);
    let same_caller = match (&bundle.alloc_caller, &bundle.release_caller) {
        (Some(alloc), Some(release)) => alloc == release,
        _ => false,
    };
    if is_deallocator && same_caller && !has_use_after {
        // When the candidate lacks strong same-instance evidence (resource_id
        // or MultipleRelease), the double-release almost always comes from
        // if/else branches where each path frees once — a control-flow merge
        // artefact. Suppress these as ExplainedSafe.
        //
        // When same-instance evidence IS present, the candidate may be a
        // genuine sequential double-free (e.g., free(ptr); free(ptr) in one
        // BB). Let downstream gates (alias, UAF) classify it correctly.
        let has_strong_instance = bundle.has_same_resource_evidence
            || bundle
                .evidence_kinds
                .contains(&EvidenceKind::MultipleRelease);
        if !has_strong_instance {
            tracing::debug!(
                candidate_id = bundle.candidate_id,
                alloc_fn = %bundle.alloc_function,
                caller = ?bundle.alloc_caller,
                "DoubleFree mutual-exclusivity gate: pure deallocator with \
                 same-caller releases and no strong instance evidence — \
                 likely if/else path merge artefact, downgrading to ExplainedSafe"
            );
            return VerifierVerdict::ExplainedSafe;
        }
    }

    // ── Path evidence: mutual exclusion ──
    // When path evidence shows all paths release the resource exactly once
    // (all_paths_release=true, release_path_count>=2, no duplicate releases),
    // this is a mutual exclusion pattern (if/else branches), not a real
    // double-free. The releases happen on different paths.
    if let Some(ref pe) = bundle.path_evidence {
        if pe.all_paths_release && pe.release_path_count >= 2 && !pe.duplicate_release_paths {
            tracing::debug!(
                candidate_id = bundle.candidate_id,
                release_path_count = pe.release_path_count,
                "DoubleFree path evidence: mutually exclusive release paths — explained safe"
            );
            return VerifierVerdict::ExplainedSafe;
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

    // ── Use-after-release gate ──
    // If the candidate carries both MultipleRelease AND UseAfterFree
    // evidence, the actual bug is likely use-after-free (UAF) rather than
    // pure double-release. The free+use pattern gets misclassified as
    // double-free when the post-release dereference triggers a second
    // release on an aliased path. Downgrade to Diagnostic so the
    // reconciliation layer can reclassify via UseAfterRelease.
    // Note: has_use_after is already computed by the mutual-exclusivity gate above.
    if has_same_instance && has_use_after {
        tracing::debug!(
            candidate_id = bundle.candidate_id,
            "DoubleFree UAF gate: candidate has both MultipleRelease and \
             UseAfterFree evidence — appears to be use-after-free rather \
             than pure double-release"
        );
        return VerifierVerdict::Diagnostic;
    }

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
