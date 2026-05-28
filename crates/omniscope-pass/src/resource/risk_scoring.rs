//! Risk scoring for resource contract issue candidates.
//!
//! Centralized risk scoring in one module, not scattered across passes.
//! Scores are computed from candidate properties and evidence, and
//! used to rank and prioritize reportable issues.
//!
//! Risk is a combination of:
//! - **Severity**: How bad the issue would be if real.
//! - **Confidence**: How likely the issue is real.
//! - **Reachability**: Whether the issue path is reachable.
//!
//! The final risk score (0.0 - 1.0) is used for SARIF ranking
//! and for filtering low-risk diagnostics.

use omniscope_core::IssueCandidate;
use omniscope_types::{IssueCandidateKind, VerifierVerdict};

/// Risk score for an issue candidate (0.0 - 1.0).
///
/// Higher scores indicate more severe or more confident issues.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct RiskScore(pub f32);

impl RiskScore {
    /// Minimum risk score (no risk).
    pub const MIN: RiskScore = RiskScore(0.0);
    /// Maximum risk score (critical risk).
    pub const MAX: RiskScore = RiskScore(1.0);

    /// Creates a new risk score, clamped to [0.0, 1.0].
    pub fn new(score: f32) -> Self {
        RiskScore(score.clamp(0.0, 1.0))
    }

    /// Returns the raw score value.
    pub fn value(&self) -> f32 {
        self.0
    }

    /// Returns true if this risk score is high (>= 0.7).
    pub fn is_high(&self) -> bool {
        self.0 >= 0.7
    }

    /// Returns true if this risk score is medium (0.4 - 0.7).
    pub fn is_medium(&self) -> bool {
        self.0 >= 0.4 && self.0 < 0.7
    }

    /// Returns true if this risk score is low (< 0.4).
    pub fn is_low(&self) -> bool {
        self.0 < 0.4
    }
}

/// Computes the risk score for a verified issue candidate.
///
/// The score is based on:
/// 1. Base severity from the candidate kind
/// 2. Verdict confidence multiplier
/// 3. Evidence quality bonus/penalty
pub fn compute_risk_score(candidate: &IssueCandidate) -> RiskScore {
    let base = base_severity(candidate.kind);
    let verdict_mult = verdict_multiplier(candidate.verdict);
    let evidence_mult = evidence_multiplier(candidate);

    RiskScore::new(base * verdict_mult * evidence_mult)
}

/// Returns the base severity for each candidate kind.
///
/// Per ARCHITECTURE_ADJUSTMENT.md, FFI boundary issues are 90%
/// priority, local-only memory issues are 10%.
fn base_severity(kind: IssueCandidateKind) -> f32 {
    match kind {
        // High severity: cross-family issues are the core focus
        IssueCandidateKind::CrossFamilyFree => 0.9,
        IssueCandidateKind::UseAfterRelease => 0.85,
        IssueCandidateKind::DoubleRelease => 0.8,
        // Medium severity: conditional issues
        IssueCandidateKind::ConditionalLeak => 0.6,
        IssueCandidateKind::BorrowEscape => 0.55,
        // Low severity: informational
        IssueCandidateKind::CallbackEscape => 0.3,
        IssueCandidateKind::NeedsModel => 0.1,
        // High severity: double reclaim is as severe as double release
        IssueCandidateKind::DoubleReclaim => 0.85,
        IssueCandidateKind::OwnershipEscapeLeak => 0.65,
    }
}

/// Returns the confidence multiplier based on the verifier verdict.
fn verdict_multiplier(verdict: Option<VerifierVerdict>) -> f32 {
    match verdict {
        Some(VerifierVerdict::ConfirmedIssue) => 1.0,
        Some(VerifierVerdict::ProbableIssue) => 0.7,
        Some(VerifierVerdict::Diagnostic) => 0.3,
        Some(VerifierVerdict::ExplainedSafe) => 0.0,
        None => 0.5, // Unverified — moderate confidence
    }
}

/// Returns the evidence quality multiplier.
///
/// More evidence items → higher confidence. But low-confidence
/// evidence reduces the multiplier.
fn evidence_multiplier(candidate: &IssueCandidate) -> f32 {
    if candidate.evidence.is_empty() {
        return 1.0; // No evidence — rely on verdict confidence
    }

    // Average confidence across evidence items
    let avg_confidence: f32 = candidate.evidence.iter().map(|e| e.confidence).sum::<f32>()
        / candidate.evidence.len() as f32;

    // Scale: 0.7 (low-quality evidence) to 1.0 (high-quality evidence)
    0.7 + (avg_confidence * 0.3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_types::{Evidence, EvidenceKind, FamilyId};

    #[test]
    fn test_risk_score_clamping() {
        assert_eq!(RiskScore::new(-0.5).value(), 0.0);
        assert_eq!(RiskScore::new(1.5).value(), 1.0);
        assert_eq!(RiskScore::new(0.5).value(), 0.5);
    }

    #[test]
    fn test_risk_score_levels() {
        assert!(RiskScore::new(0.8).is_high());
        assert!(RiskScore::new(0.5).is_medium());
        assert!(RiskScore::new(0.2).is_low());
        assert!(!RiskScore::new(0.2).is_high());
    }

    #[test]
    fn test_cross_family_high_risk() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_release_family(FamilyId::CPP_NEW_SCALAR)
        .with_release_function("operator delete")
        .with_verdict(VerifierVerdict::ConfirmedIssue);

        let score = compute_risk_score(&candidate);
        assert!(
            score.is_high(),
            "Confirmed cross-family free should have high risk, got {}",
            score.value()
        );
    }

    #[test]
    fn test_needs_model_low_risk() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::NeedsModel,
            FamilyId::C_HEAP,
            "custom_alloc",
        )
        .with_verdict(VerifierVerdict::Diagnostic);

        let score = compute_risk_score(&candidate);
        assert!(
            score.is_low(),
            "NeedsModel diagnostic should have low risk, got {}",
            score.value()
        );
    }

    #[test]
    fn test_explained_safe_zero_risk() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_release_family(FamilyId::C_HEAP)
        .with_release_function("free")
        .with_verdict(VerifierVerdict::ExplainedSafe);

        let score = compute_risk_score(&candidate);
        assert_eq!(score.value(), 0.0, "ExplainedSafe should have zero risk");
    }

    #[test]
    fn test_evidence_quality_improves_score() {
        let mut with_high_evidence = IssueCandidate::new(
            1,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_verdict(VerifierVerdict::ProbableIssue);
        with_high_evidence.add_evidence(
            Evidence::new(
                EvidenceKind::CrossFamilyMismatch,
                "family mismatch detected",
            )
            .with_confidence(0.9),
        );

        let mut with_low_evidence = IssueCandidate::new(
            2,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_verdict(VerifierVerdict::ProbableIssue);
        with_low_evidence.add_evidence(
            Evidence::new(EvidenceKind::SymbolPattern, "name pattern match").with_confidence(0.3),
        );

        let score_high = compute_risk_score(&with_high_evidence);
        let score_low = compute_risk_score(&with_low_evidence);

        // High-quality evidence should score higher than low-quality evidence
        assert!(
            score_high.value() > score_low.value(),
            "High-quality evidence should score higher than low-quality: {} vs {}",
            score_high.value(),
            score_low.value()
        );
    }
}
