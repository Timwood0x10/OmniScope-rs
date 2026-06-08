//! Leak verification logic (definite leak, conditional leak, borrow escape).

use omniscope_core::IssueCandidate;
use omniscope_types::{EvidenceKind, VerifierVerdict};

use super::super::evidence_bundle::EvidenceBundle;
use super::helpers::has_evidence;

/// Bundle-based verification for definite leak candidates.
///
/// Uses the evidence bundle's fused view to make a confidence-aware decision:
/// - If `has_leak_suppression_high_confidence` returns true → `ExplainedSafe`
/// - If `has_leak_suppression_medium_confidence` but not high → `ProbableIssue`
/// - If the bundle has `OwnershipEscapeLeak` evidence → `ConfirmedIssue`
/// - Otherwise → `ConfirmedIssue` (all exit paths leak).
pub(crate) fn verify_definite_leak_with_bundle(bundle: &EvidenceBundle) -> VerifierVerdict {
    // OwnershipEscapeLeak: into_raw without from_raw — the raw pointer
    // was explicitly leaked across the FFI boundary.
    if bundle
        .evidence_kinds
        .contains(&EvidenceKind::OwnershipEscapeLeak)
    {
        return VerifierVerdict::ConfirmedIssue;
    }

    // High-confidence leak suppression: semantic or evidence facts explain
    // why the resource is not freed locally.
    if bundle.has_leak_suppression_high_confidence() {
        return VerifierVerdict::ExplainedSafe;
    }

    // Medium-confidence suppression: downgrade to probable.
    if bundle.has_leak_suppression_medium_confidence() {
        return VerifierVerdict::ProbableIssue;
    }

    // Definite leak: all exit paths own the resource at exit, and no
    // semantic or evidence fact explains the lack of local release.
    VerifierVerdict::ConfirmedIssue
}

/// Bundle-based verification for conditional leak candidates.
///
/// Uses the evidence bundle's fused view to make a confidence-aware decision:
/// - If `has_leak_suppression_high_confidence` returns true → `ExplainedSafe`
/// - If `has_leak_suppression_medium_confidence` but not high → `ExplainedSafe`
/// - If `OwnershipEscapeLeak` evidence → `ProbableIssue`
/// - If `PathStateRefinement` evidence → `ProbableIssue`
/// - Otherwise → `ProbableIssue`
pub(crate) fn verify_conditional_leak_with_bundle(bundle: &EvidenceBundle) -> VerifierVerdict {
    // OwnershipEscapeLeak: into_raw without from_raw.
    if bundle
        .evidence_kinds
        .contains(&EvidenceKind::OwnershipEscapeLeak)
    {
        return VerifierVerdict::ProbableIssue;
    }

    // High-confidence leak suppression: fully explain the conditional leak.
    if bundle.has_leak_suppression_high_confidence() {
        return VerifierVerdict::ExplainedSafe;
    }

    // Medium-confidence suppression: for conditional leaks, downgrade to ProbableIssue.
    if bundle.has_leak_suppression_medium_confidence() {
        return VerifierVerdict::ProbableIssue;
    }

    // Fallback: check the legacy leak suppression method.
    if bundle.has_leak_suppression() {
        return VerifierVerdict::ExplainedSafe;
    }

    // Path-state refinement means we analyzed the control flow.
    if bundle
        .evidence_kinds
        .contains(&EvidenceKind::PathStateRefinement)
    {
        return VerifierVerdict::ProbableIssue;
    }

    // No suppression, no path refinement — probable leak.
    VerifierVerdict::ProbableIssue
}

pub(crate) fn verify_definite_leak(candidate: &IssueCandidate) -> VerifierVerdict {
    // OwnershipEscapeLeak: into_raw without from_raw
    if has_evidence(candidate, EvidenceKind::OwnershipEscapeLeak) {
        return VerifierVerdict::ConfirmedIssue;
    }

    // Resource returned via out-param on success — caller owns it.
    if has_evidence(candidate, EvidenceKind::OutParamOwnedOnSuccess) {
        return VerifierVerdict::ExplainedSafe;
    }

    // Resource returned to caller — not a local leak.
    if has_evidence(candidate, EvidenceKind::ReturnToCaller) {
        return VerifierVerdict::ExplainedSafe;
    }

    // Definite leak: all paths leak. No valid escape can explain it.
    VerifierVerdict::ConfirmedIssue
}

/// Verifies a conditional leak candidate.
pub(crate) fn verify_conditional_leak(candidate: &IssueCandidate) -> VerifierVerdict {
    // OwnershipEscapeLeak
    if has_evidence(candidate, EvidenceKind::OwnershipEscapeLeak) {
        return VerifierVerdict::ProbableIssue;
    }

    // Check for valid escape that explains the "leak".
    if has_evidence(candidate, EvidenceKind::ReturnToCaller) {
        return VerifierVerdict::ExplainedSafe;
    }

    if has_evidence(candidate, EvidenceKind::OutParamInit) {
        return VerifierVerdict::ExplainedSafe;
    }

    // Resource returned via out-param on success — caller owns it.
    if has_evidence(candidate, EvidenceKind::OutParamOwnedOnSuccess) {
        return VerifierVerdict::ExplainedSafe;
    }

    // Out-param set to NULL on error — no dangling pointer on error path.
    if has_evidence(candidate, EvidenceKind::OutParamNullOnError) {
        return VerifierVerdict::ExplainedSafe;
    }

    if has_evidence(candidate, EvidenceKind::FieldStoreToOwner) {
        return VerifierVerdict::ExplainedSafe;
    }

    if has_evidence(candidate, EvidenceKind::StaticLifetimeSink) {
        return VerifierVerdict::ExplainedSafe;
    }

    if has_evidence(candidate, EvidenceKind::RefcountConditional) {
        return VerifierVerdict::ProbableIssue;
    }

    // Check if we have path state refinement
    if has_evidence(candidate, EvidenceKind::PathStateRefinement) {
        return VerifierVerdict::ProbableIssue;
    }

    // No valid escape found — probable leak.
    VerifierVerdict::ProbableIssue
}

/// Verifies a borrow escape candidate.
pub(crate) fn verify_borrow_escape(candidate: &IssueCandidate) -> VerifierVerdict {
    // Check if the "escape" is actually a bridge helper.
    if has_evidence(candidate, EvidenceKind::BridgeHelper) {
        return VerifierVerdict::ExplainedSafe;
    }

    // Check if the escaped pointer has heap provenance (R-1).
    if has_evidence(candidate, EvidenceKind::IrPattern) {
        let has_heap = candidate.evidence.iter().any(|e| {
            e.kind == EvidenceKind::IrPattern
                && (e.description.contains("heap") || e.description.contains("global"))
        });
        if has_heap {
            return VerifierVerdict::ExplainedSafe;
        }
    }

    // Check if ownership was transferred via into_raw (R-6).
    if has_evidence(candidate, EvidenceKind::OwnershipTransfer) {
        return VerifierVerdict::ExplainedSafe;
    }

    // Stack/borrowed userdata escaped to callback — real issue.
    VerifierVerdict::ProbableIssue
}
