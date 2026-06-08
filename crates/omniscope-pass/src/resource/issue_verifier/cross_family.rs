//! Cross-family free verification logic.

use omniscope_core::IssueCandidate;
use omniscope_semantics::{FamilyRegistry, LanguageDetector};
use omniscope_types::{EvidenceKind, OmniScopeConfig, VerifierVerdict};

use super::super::evidence_bundle::EvidenceBundle;
use super::helpers::{has_escape_evidence, has_evidence};

/// Verifies a cross-family free candidate using the evidence bundle.
///
/// This is the bundle-based replacement for `verify_cross_family_free`.
/// It makes the decision from a joined view of:
/// - allocation family and release family compatibility
/// - release reachability
/// - semantic suppression facts
/// - cross-language boundary evidence
///
/// Cross-language evidence is attached as a secondary fact rather than
/// replacing the primary `CrossFamilyFree` issue kind.
pub(crate) fn verify_cross_family_with_bundle(
    bundle: &EvidenceBundle,
    registry: &FamilyRegistry,
) -> VerifierVerdict {
    // Phase 2 gate: release family must be present
    let Some(release_family) = bundle.release_family else {
        // Release family unknown — probable issue but not confirmed.
        return VerifierVerdict::ProbableIssue;
    };

    // Check compatible release via the registry.
    if registry.is_compatible_release(bundle.alloc_family, release_family) {
        // Same or compatible family — this was a false alarm.
        return VerifierVerdict::ExplainedSafe;
    }

    // A confirmed TP needs a reachable release or same-resource flow signal.
    // A bare family mismatch without release-flow evidence is suspicious but
    // not strong enough for ConfirmedIssue.
    if !bundle.has_reachable_release && !bundle.has_same_resource_evidence {
        return VerifierVerdict::ProbableIssue;
    }

    // Check for destructor-mediated release — this is a valid
    // release path. E.g., Rust Drop calling C free.
    if bundle
        .evidence_kinds
        .contains(&EvidenceKind::DestructorRelease)
    {
        return VerifierVerdict::ExplainedSafe;
    }

    // Check for valid escape — if the resource was returned to caller
    // or stored in an owner, the release may be in a different context.
    if bundle.evidence_kinds.iter().any(|k| {
        matches!(
            k,
            EvidenceKind::ReturnToCaller
                | EvidenceKind::OutParamInit
                | EvidenceKind::FieldStoreToOwner
        )
    }) {
        // Escaped via valid path — the release may happen elsewhere.
        // Cross-family is still a probable issue but not confirmed.
        return VerifierVerdict::ProbableIssue;
    }

    // ── Semantic suppression gate (confidence-aware) ──
    // High-confidence semantic suppression partially explains the family mismatch
    // (e.g., IntoRawTransfer, LibraryRelease with high confidence), but for
    // cross-family free we only downgrade to probable — the family mismatch
    // itself is still a signal that should not be fully silenced.
    if bundle.has_semantic_suppression_high_confidence() {
        tracing::debug!(
            candidate_id = bundle.candidate_id,
            "Cross-family free downgraded to probable by high-confidence semantic evidence: {:?}",
            bundle.semantic_kinds
        );
        return VerifierVerdict::ProbableIssue;
    }

    // Medium-confidence semantic suppression: downgrade from confirmed
    // to probable (not safe enough to fully suppress a cross-family free).
    if bundle.has_semantic_suppression_medium_confidence() {
        tracing::debug!(
            candidate_id = bundle.candidate_id,
            "Cross-family free downgraded by medium-confidence semantic evidence: {:?}",
            bundle.semantic_kinds
        );
        return VerifierVerdict::ProbableIssue;
    }

    // Fallback: check legacy has_semantic_suppression which considers
    // semantic kinds from srt_resolutions (without confidence data).
    // These are treated as medium confidence — downgrade to probable.
    if bundle.has_semantic_suppression() {
        tracing::debug!(
            candidate_id = bundle.candidate_id,
            "Cross-family free downgraded by legacy semantic evidence (no confidence): {:?}",
            bundle.semantic_kinds
        );
        return VerifierVerdict::ProbableIssue;
    }

    // ── Confirmed TP ──
    // Families are incompatible, release is reachable, and no semantic
    // or escape evidence explains the mismatch.
    VerifierVerdict::ConfirmedIssue
}

pub(crate) fn should_report_as_cross_family(
    candidate: &IssueCandidate,
    registry: &FamilyRegistry,
) -> bool {
    candidate.release_family.is_some_and(|release_family| {
        !registry.is_compatible_release(candidate.alloc_family, release_family)
    })
}

/// Verifies a cross-family free candidate.
///
/// Uses BoundaryContext for FFI boundary verification when available,
/// falling back to config for other checks.
pub(crate) fn verify_cross_family_free(
    candidate: &IssueCandidate,
    registry: &FamilyRegistry,
    config: Option<&OmniScopeConfig>,
    boundary_ctx: Option<&omniscope_types::boundary::BoundaryContext>,
) -> VerifierVerdict {
    let Some(release_family) = candidate.release_family else {
        // Release family unknown — probable issue but not confirmed.
        return VerifierVerdict::ProbableIssue;
    };

    // Check if this is a configured FFI boundary.
    let release_func = candidate.release_function.as_deref().unwrap_or("");

    // Use BoundaryContext for boundary checking if available
    if let Some(boundary_ctx) = boundary_ctx {
        if let Some((from, to)) = boundary_ctx.is_declared_boundary(release_func) {
            tracing::debug!(
                "Cross-family free in FFI boundary function '{}' ({:?} -> {:?})",
                release_func,
                from,
                to
            );
            return VerifierVerdict::ConfirmedIssue;
        }

        let detector = LanguageDetector::new();
        let caller_lang =
            detector.detect_from_function(candidate.release_caller.as_deref().unwrap_or(""));
        let release_lang = detector.detect_from_function(release_func);

        if boundary_ctx.matches_call(caller_lang, release_lang) {
            tracing::debug!(
                "Cross-family free in FFI boundary function '{}' via language detection ({:?} -> {:?})",
                release_func,
                caller_lang,
                release_lang
            );
            return VerifierVerdict::ConfirmedIssue;
        }
    } else if let Some(config) = config {
        if let Some((from, to)) = config.is_ffi_boundary(release_func) {
            tracing::debug!(
                "Cross-family free in FFI boundary function '{}' ({:?} -> {:?})",
                release_func,
                from,
                to
            );
            return VerifierVerdict::ConfirmedIssue;
        }

        let detector = LanguageDetector::new();
        let caller_lang =
            detector.detect_from_function(candidate.release_caller.as_deref().unwrap_or(""));
        let release_lang = detector.detect_from_function(release_func);

        if let Some((from, to)) =
            config.is_ffi_boundary_with_lang(release_func, caller_lang, release_lang)
        {
            tracing::debug!(
                "Cross-family free in FFI boundary function '{}' via language detection ({:?} -> {:?})",
                release_func,
                from,
                to
            );
            return VerifierVerdict::ConfirmedIssue;
        }
    }

    // Check compatible release via the registry.
    if registry.is_compatible_release(candidate.alloc_family, release_family) {
        return VerifierVerdict::ExplainedSafe;
    }

    // Check for destructor-mediated release
    if has_evidence(candidate, EvidenceKind::DestructorRelease) {
        return VerifierVerdict::ExplainedSafe;
    }

    // Check for valid escape
    if has_escape_evidence(candidate, EvidenceKind::ReturnToCaller)
        || has_escape_evidence(candidate, EvidenceKind::OutParamInit)
        || has_escape_evidence(candidate, EvidenceKind::FieldStoreToOwner)
    {
        return VerifierVerdict::ProbableIssue;
    }

    // Genuinely different families with no valid escape — confirmed.
    VerifierVerdict::ConfirmedIssue
}
