//! Risk scoring for verified issue candidates.
//!
//! Centralized risk scoring module — all risk calculations live here,
//! not scattered across passes. Scores are used to prioritize issues
//! in reports and to decide which issues appear in default output
//! vs. debug/diagnostic output.
//!
//! Scoring inputs:
//! - Issue candidate kind (cross-family free is worse than needs-model)
//! - Verifier verdict (confirmed > probable > diagnostic)
//! - FFI boundary proximity (cross-boundary issues score higher)
//! - Family certainty (known families score higher than unknown)
//! - Evidence count (more evidence → higher confidence in the score)

use omniscope_types::{FamilyId, IssueCandidateKind, VerifierVerdict};

/// Risk score for an issue candidate (0.0 - 1.0).
///
/// Higher scores indicate more severe or more certain issues.
/// The score is NOT a probability — it is a priority ranking.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct RiskScore(f32);

impl RiskScore {
    /// Minimum risk score.
    pub const MIN: RiskScore = RiskScore(0.0);
    /// Maximum risk score.
    pub const MAX: RiskScore = RiskScore(1.0);

    /// Creates a new risk score, clamped to [0.0, 1.0].
    pub fn new(value: f32) -> Self {
        RiskScore(value.clamp(0.0, 1.0))
    }

    /// Returns the raw score value.
    pub fn value(&self) -> f32 {
        self.0
    }

    /// Returns true if this score indicates a reportable issue
    /// (score >= 0.5, which corresponds to ProbableIssue or above).
    pub fn is_reportable(&self) -> bool {
        self.0 >= 0.5
    }

    /// Returns true if this score indicates a high-priority issue
    /// (score >= 0.8, which corresponds to ConfirmedIssue with
    /// cross-boundary proximity).
    pub fn is_high_priority(&self) -> bool {
        self.0 >= 0.8
    }

    /// Returns a human-readable label for the score range.
    pub fn label(&self) -> &'static str {
        if self.0 >= 0.8 {
            "critical"
        } else if self.0 >= 0.6 {
            "high"
        } else if self.0 >= 0.4 {
            "medium"
        } else if self.0 >= 0.2 {
            "low"
        } else {
            "informational"
        }
    }
}

/// Context for computing a risk score.
pub struct RiskContext {
    /// The candidate kind.
    pub kind: IssueCandidateKind,
    /// The verifier verdict.
    pub verdict: VerifierVerdict,
    /// Whether the issue crosses an FFI boundary.
    pub crosses_ffi_boundary: bool,
    /// The allocation family (None = unknown).
    pub alloc_family: Option<FamilyId>,
    /// The release family (None = unknown).
    pub release_family: Option<FamilyId>,
    /// Number of evidence items supporting this candidate.
    pub evidence_count: usize,
}

/// Computes a risk score from the given context.
///
/// The scoring formula is:
/// ```text
/// base = kind_score * verdict_weight
/// boundary_bonus = 0.15 if crosses FFI boundary
/// family_penalty = -0.1 if either family is unknown
/// evidence_bonus = min(0.1, evidence_count * 0.02)
/// score = clamp(base + boundary_bonus + family_penalty + evidence_bonus)
/// ```
pub fn compute_risk_score(ctx: &RiskContext) -> RiskScore {
    // ExplainedSafe is always zero — no bonuses apply.
    if ctx.verdict == VerifierVerdict::ExplainedSafe {
        return RiskScore::MIN;
    }

    let kind_score = kind_base_score(ctx.kind);
    let verdict_weight = verdict_weight(ctx.verdict);

    let base = kind_score * verdict_weight;

    let boundary_bonus = if ctx.crosses_ffi_boundary { 0.15 } else { 0.0 };

    let family_penalty = if ctx.alloc_family.is_none() || ctx.release_family.is_none() {
        -0.1
    } else {
        0.0
    };

    let evidence_bonus = (ctx.evidence_count as f32 * 0.02).min(0.1);

    RiskScore::new(base + boundary_bonus + family_penalty + evidence_bonus)
}

/// Returns the base score for an issue candidate kind.
///
/// More severe issue kinds get higher base scores.
fn kind_base_score(kind: IssueCandidateKind) -> f32 {
    match kind {
        IssueCandidateKind::CrossFamilyFree => 0.9,
        IssueCandidateKind::UseAfterRelease => 0.95,
        IssueCandidateKind::DoubleRelease => 0.95,
        IssueCandidateKind::ConditionalLeak => 0.6,
        IssueCandidateKind::DefiniteLeak => 0.85,
        IssueCandidateKind::BorrowEscape => 0.5,
        IssueCandidateKind::CallbackEscape => 0.3,
        IssueCandidateKind::NeedsModel => 0.1,
        IssueCandidateKind::DoubleReclaim => 0.9,
        IssueCandidateKind::OwnershipEscapeLeak => 0.7,
        IssueCandidateKind::UseAfterFree => 0.95,
    }
}

/// Returns the verdict weight multiplier.
///
/// Confirmed issues keep full weight; diagnostics are heavily discounted.
fn verdict_weight(verdict: VerifierVerdict) -> f32 {
    match verdict {
        VerifierVerdict::ConfirmedIssue => 1.0,
        VerifierVerdict::ProbableIssue => 0.7,
        VerifierVerdict::Diagnostic => 0.2,
        VerifierVerdict::ExplainedSafe => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify risk score clamping.
    /// Invariants: Score must always be in [0.0, 1.0].
    #[test]
    fn test_risk_score_clamping() {
        assert_eq!(
            RiskScore::new(-0.5).value(),
            0.0,
            "Negative scores clamp to 0"
        );
        assert_eq!(
            RiskScore::new(1.5).value(),
            1.0,
            "Scores above 1 clamp to 1"
        );
        assert_eq!(
            RiskScore::new(0.5).value(),
            0.5,
            "Valid scores pass through"
        );
    }

    /// Objective: Verify risk score ordering.
    /// Invariants: Confirmed cross-family free > Probable conditional leak.
    #[test]
    fn test_confirmed_cross_family_scores_higher() {
        let confirmed = compute_risk_score(&RiskContext {
            kind: IssueCandidateKind::CrossFamilyFree,
            verdict: VerifierVerdict::ConfirmedIssue,
            crosses_ffi_boundary: true,
            alloc_family: Some(FamilyId::C_HEAP),
            release_family: Some(FamilyId::CPP_NEW_SCALAR),
            evidence_count: 3,
        });

        let probable = compute_risk_score(&RiskContext {
            kind: IssueCandidateKind::ConditionalLeak,
            verdict: VerifierVerdict::ProbableIssue,
            crosses_ffi_boundary: false,
            alloc_family: Some(FamilyId::C_HEAP),
            release_family: None,
            evidence_count: 1,
        });

        assert!(
            confirmed > probable,
            "Confirmed cross-family free (score={:.2}) must score higher than probable conditional leak (score={:.2})",
            confirmed.value(), probable.value()
        );
    }

    /// Objective: Verify FFI boundary bonus.
    /// Invariants: Same kind/verdict scores higher with FFI boundary.
    #[test]
    fn test_ffi_boundary_bonus() {
        let with_boundary = compute_risk_score(&RiskContext {
            kind: IssueCandidateKind::CrossFamilyFree,
            verdict: VerifierVerdict::ConfirmedIssue,
            crosses_ffi_boundary: true,
            alloc_family: Some(FamilyId::C_HEAP),
            release_family: Some(FamilyId::CPP_NEW_SCALAR),
            evidence_count: 0,
        });

        let without_boundary = compute_risk_score(&RiskContext {
            kind: IssueCandidateKind::CrossFamilyFree,
            verdict: VerifierVerdict::ConfirmedIssue,
            crosses_ffi_boundary: false,
            alloc_family: Some(FamilyId::C_HEAP),
            release_family: Some(FamilyId::CPP_NEW_SCALAR),
            evidence_count: 0,
        });

        assert!(
            with_boundary > without_boundary,
            "FFI boundary must increase risk score"
        );
    }

    /// Objective: Verify NeedsModel gets low score.
    /// Invariants: NeedsModel + Diagnostic should not be reportable.
    #[test]
    fn test_needs_model_low_score() {
        let score = compute_risk_score(&RiskContext {
            kind: IssueCandidateKind::NeedsModel,
            verdict: VerifierVerdict::Diagnostic,
            crosses_ffi_boundary: false,
            alloc_family: None,
            release_family: None,
            evidence_count: 0,
        });

        assert!(
            !score.is_reportable(),
            "NeedsModel diagnostic should not be reportable (score={:.2})",
            score.value()
        );
    }

    /// Objective: Verify ExplainedSafe always scores zero.
    /// Invariants: Regardless of kind, ExplainedSafe = 0.
    #[test]
    fn test_explained_safe_zero_score() {
        let score = compute_risk_score(&RiskContext {
            kind: IssueCandidateKind::CrossFamilyFree,
            verdict: VerifierVerdict::ExplainedSafe,
            crosses_ffi_boundary: true,
            alloc_family: Some(FamilyId::C_HEAP),
            release_family: Some(FamilyId::C_HEAP),
            evidence_count: 5,
        });

        assert_eq!(score.value(), 0.0, "ExplainedSafe must always score zero");
    }

    /// Objective: Verify risk score labels.
    /// Invariants: Labels must match the expected ranges.
    #[test]
    fn test_risk_score_labels() {
        assert_eq!(
            RiskScore::new(0.9).label(),
            "critical",
            "Score 0.9 should be labeled 'critical'"
        );
        assert_eq!(
            RiskScore::new(0.7).label(),
            "high",
            "Score 0.7 should be labeled 'high'"
        );
        assert_eq!(
            RiskScore::new(0.5).label(),
            "medium",
            "Score 0.5 should be labeled 'medium'"
        );
        assert_eq!(
            RiskScore::new(0.3).label(),
            "low",
            "Score 0.3 should be labeled 'low'"
        );
        assert_eq!(
            RiskScore::new(0.1).label(),
            "informational",
            "Score 0.1 should be labeled 'informational'"
        );
    }

    /// Objective: Verify evidence bonus is capped.
    /// Invariants: Adding more than 5 evidence items should not
    /// increase the bonus beyond 0.1.
    #[test]
    fn test_evidence_bonus_capped() {
        let few_evidence = compute_risk_score(&RiskContext {
            kind: IssueCandidateKind::ConditionalLeak,
            verdict: VerifierVerdict::ProbableIssue,
            crosses_ffi_boundary: false,
            alloc_family: Some(FamilyId::C_HEAP),
            release_family: None,
            evidence_count: 2,
        });

        let much_evidence = compute_risk_score(&RiskContext {
            kind: IssueCandidateKind::ConditionalLeak,
            verdict: VerifierVerdict::ProbableIssue,
            crosses_ffi_boundary: false,
            alloc_family: Some(FamilyId::C_HEAP),
            release_family: None,
            evidence_count: 100,
        });

        let diff = much_evidence.value() - few_evidence.value();
        assert!(
            diff <= 0.1,
            "Evidence bonus must be capped at 0.1, got diff={diff:.3}"
        );
    }
}
