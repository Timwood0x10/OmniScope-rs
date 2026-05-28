//! Confidence scorer for issue prioritization.
//!
//! Computes a 4-dimensional confidence score for each issue, then
//! classifies it into one of 4 tiers:
//!
//! | Tier           | Threshold     | Display              | User Action        |
//! |----------------|---------------|----------------------|--------------------|
//! | Critical       | score ≥ 0.85  | Terminal top / error | Must fix           |
//! | High           | 0.70 ≤ s < 85| Warning              | Strongly recommend |
//! | Medium         | 0.50 ≤ s < 70| --verbose / note     | Optional review    |
//! | Informational  | score < 0.50  | SARIF only           | Reference only     |
//!
//! # Score Dimensions
//!
//! 1. **Provenance clarity** — DI available (+0.2), use-def only (+0.1), none (-0.1)
//! 2. **Corpus frequency** — high frequency in clean corpus → likely idiom → penalty
//! 3. **Dataflow proximity** — shorter source→sink path → more suspicious (+bonus)
//! 4. **Multi-detector consensus** — ≥2 detectors flag same value → +0.15

use crate::resource::semantic_tree::SemanticTree;

// ──────────────────────────────────────────────────────────────────────────
// Confidence Tier
// ──────────────────────────────────────────────────────────────────────────

/// Confidence tier for issue prioritization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConfidenceTier {
    /// Informational — score < 0.50. SARIF only, no terminal output.
    Informational,
    /// Medium — 0.50 ≤ score < 0.70. Shown with --verbose.
    Medium,
    /// High — 0.70 ≤ score < 0.85. Shown as warning.
    High,
    /// Critical — score ≥ 0.85. Shown as error, must fix.
    Critical,
}

impl ConfidenceTier {
    /// Classifies a raw score into a tier.
    pub fn from_score(score: f32) -> Self {
        if score >= 0.85 {
            ConfidenceTier::Critical
        } else if score >= 0.70 {
            ConfidenceTier::High
        } else if score >= 0.50 {
            ConfidenceTier::Medium
        } else {
            ConfidenceTier::Informational
        }
    }

    /// Returns a human-readable label for this tier.
    pub fn label(&self) -> &'static str {
        match self {
            ConfidenceTier::Critical => "CRITICAL",
            ConfidenceTier::High => "HIGH",
            ConfidenceTier::Medium => "MEDIUM",
            ConfidenceTier::Informational => "INFO",
        }
    }

    /// Returns the numeric threshold for this tier.
    pub fn threshold(&self) -> f32 {
        match self {
            ConfidenceTier::Critical => 0.85,
            ConfidenceTier::High => 0.70,
            ConfidenceTier::Medium => 0.50,
            ConfidenceTier::Informational => 0.00,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Score Breakdown — detailed score components for debugging/explanation
// ──────────────────────────────────────────────────────────────────────────

/// Breakdown of the confidence score by dimension.
#[derive(Debug, Clone, Default)]
pub struct ScoreBreakdown {
    /// Base severity score (0.5 default).
    pub base: f32,
    /// Provenance clarity bonus: DI (+0.2), use-def (+0.1), none (-0.1).
    pub provenance_clarity: f32,
    /// Corpus frequency penalty: high freq in clean corpus → negative.
    pub corpus_frequency: f32,
    /// Dataflow proximity bonus: shorter path → higher.
    pub dataflow_proximity: f32,
    /// Multi-detector consensus bonus: ≥2 detectors → +0.15.
    pub multi_detector_consensus: f32,
}

impl ScoreBreakdown {
    /// Computes the total score by summing all dimensions.
    pub fn total(&self) -> f32 {
        let sum = self.base
            + self.provenance_clarity
            + self.corpus_frequency
            + self.dataflow_proximity
            + self.multi_detector_consensus;
        sum.clamp(0.0, 1.0)
    }

    /// Returns a formatted breakdown string for diagnostics.
    pub fn format(&self) -> String {
        format!(
            "base={:.2} + provenance={:+.2} - corpus_freq={:+.2} + proximity={:+.2} + consensus={:+.2} = {:.2}",
            self.base,
            self.provenance_clarity,
            self.corpus_frequency,
            self.dataflow_proximity,
            self.multi_detector_consensus,
            self.total(),
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Scoring Input — context needed to compute the score
// ──────────────────────────────────────────────────────────────────────────

/// Context for scoring an issue.
pub struct ScoringContext<'a> {
    /// The semantic tree for provenance and resolution queries.
    pub srt: &'a SemanticTree,
    /// Whether DI metadata was available for the value.
    pub has_di_metadata: bool,
    /// Whether use-def chain analysis was used (fallback from DI).
    pub has_usedef_analysis: bool,
    /// Number of times this (callee, kind) pattern appears in the clean corpus.
    /// Higher count → more likely to be an idiom → lower confidence.
    pub corpus_frequency: u32,
    /// Number of dataflow steps from source to sink (taint-like issues).
    /// Shorter path → more suspicious.
    pub dataflow_distance: u32,
    /// Number of distinct detectors that flagged this value.
    pub detector_count: u32,
}

impl<'a> ScoringContext<'a> {
    /// Creates a minimal scoring context with just the SRT.
    pub fn new(srt: &'a SemanticTree) -> Self {
        Self {
            srt,
            has_di_metadata: false,
            has_usedef_analysis: false,
            corpus_frequency: 0,
            dataflow_distance: 0,
            detector_count: 1,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Score computation
// ──────────────────────────────────────────────────────────────────────────

/// Base severity for each issue kind (0.0–1.0).
fn base_severity_for_kind(kind: &str) -> f32 {
    match kind {
        "use_after_free" => 0.65,
        "double_free" => 0.60,
        "cross_language_free" | "cross_family_free" => 0.55,
        "buffer_overflow" => 0.70,
        "borrow_escape" => 0.50,
        "memory_leak" | "conditional_leak" => 0.45,
        "command_injection" => 0.60,
        _ => 0.50,
    }
}

/// Computes provenance clarity bonus.
///
/// DI metadata available → highest confidence (+0.2).
/// Use-def chain only → moderate (+0.1).
/// Neither → uncertain (-0.1).
fn provenance_clarity_bonus(has_di: bool, has_usedef: bool) -> f32 {
    if has_di {
        0.20
    } else if has_usedef {
        0.10
    } else {
        -0.10
    }
}

/// Computes corpus frequency penalty.
///
/// The more often this pattern appears in the clean corpus,
/// the more likely it's a benign idiom, not a bug.
fn corpus_frequency_penalty(freq: u32) -> f32 {
    if freq == 0 {
        return 0.0;
    }
    // Logarithmic decay: higher frequency → stronger penalty.
    // freq=1 → -0.03, freq=2 → -0.05, freq=10 → -0.10, freq=100 → -0.17
    let penalty = 0.03 * (freq as f32 + 1.0).ln();
    -penalty.min(0.30) // cap at -0.30
}

/// Computes dataflow proximity bonus.
///
/// Shorter source→sink path → more suspicious → higher bonus.
/// distance=1 → +0.15, distance=5 → +0.05, distance≥10 → 0
fn dataflow_proximity_bonus(distance: u32) -> f32 {
    if distance == 0 {
        return 0.0; // no taint path → no bonus
    }
    let bonus = 0.15 / (distance as f32).max(1.0);
    bonus.min(0.15)
}

/// Computes multi-detector consensus bonus.
///
/// ≥2 detectors flagging the same value increases confidence.
fn multi_detector_consensus_bonus(detector_count: u32) -> f32 {
    if detector_count >= 2 {
        0.15
    } else {
        0.0
    }
}

/// Scores an issue and returns both the score and the breakdown.
///
/// # Arguments
///
/// * `issue_kind` — The kind of issue (e.g., "use_after_free").
/// * `ctx` — Scoring context with SRT, metadata, and frequency info.
///
/// # Returns
///
/// A `ScoreBreakdown` with the total score and per-dimension values.
pub fn score_issue(issue_kind: &str, ctx: &ScoringContext) -> ScoreBreakdown {
    let base = base_severity_for_kind(issue_kind);
    let prov = provenance_clarity_bonus(ctx.has_di_metadata, ctx.has_usedef_analysis);
    let freq = corpus_frequency_penalty(ctx.corpus_frequency);
    let prox = dataflow_proximity_bonus(ctx.dataflow_distance);
    let cons = multi_detector_consensus_bonus(ctx.detector_count);

    ScoreBreakdown {
        base,
        provenance_clarity: prov,
        corpus_frequency: freq,
        dataflow_proximity: prox,
        multi_detector_consensus: cons,
    }
}

/// Convenience: score and classify in one call.
pub fn classify_issue(issue_kind: &str, ctx: &ScoringContext) -> (ConfidenceTier, ScoreBreakdown) {
    let breakdown = score_issue(issue_kind, ctx);
    let tier = ConfidenceTier::from_score(breakdown.total());
    (tier, breakdown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::semantic_tree::SemanticTree;

    fn empty_srt() -> SemanticTree {
        SemanticTree::new()
    }

    #[test]
    fn test_tier_classification() {
        assert_eq!(ConfidenceTier::from_score(0.90), ConfidenceTier::Critical);
        assert_eq!(ConfidenceTier::from_score(0.85), ConfidenceTier::Critical);
        assert_eq!(ConfidenceTier::from_score(0.75), ConfidenceTier::High);
        assert_eq!(ConfidenceTier::from_score(0.70), ConfidenceTier::High);
        assert_eq!(ConfidenceTier::from_score(0.60), ConfidenceTier::Medium);
        assert_eq!(ConfidenceTier::from_score(0.50), ConfidenceTier::Medium);
        assert_eq!(
            ConfidenceTier::from_score(0.30),
            ConfidenceTier::Informational
        );
    }

    #[test]
    fn test_base_severity() {
        assert!(base_severity_for_kind("use_after_free") > 0.6);
        assert!(base_severity_for_kind("borrow_escape") > 0.4);
        assert!(base_severity_for_kind("unknown_kind") > 0.0);
    }

    #[test]
    fn test_provenance_clarity_bonus() {
        assert_eq!(provenance_clarity_bonus(true, false), 0.20);
        assert_eq!(provenance_clarity_bonus(false, true), 0.10);
        assert_eq!(provenance_clarity_bonus(false, false), -0.10);
    }

    #[test]
    fn test_corpus_frequency_penalty() {
        assert_eq!(corpus_frequency_penalty(0), 0.0);
        assert!(corpus_frequency_penalty(1) < 0.0);
        assert!(corpus_frequency_penalty(100) < corpus_frequency_penalty(1));
        assert!(corpus_frequency_penalty(10000) >= -0.30); // capped
    }

    #[test]
    fn test_dataflow_proximity() {
        assert_eq!(dataflow_proximity_bonus(0), 0.0); // no taint path
        assert!(dataflow_proximity_bonus(1) > 0.1);
        assert!(dataflow_proximity_bonus(5) < dataflow_proximity_bonus(1));
        assert_eq!(dataflow_proximity_bonus(100), 0.0015); // near zero
    }

    #[test]
    fn test_multi_detector_consensus() {
        assert_eq!(multi_detector_consensus_bonus(1), 0.0);
        assert_eq!(multi_detector_consensus_bonus(2), 0.15);
        assert_eq!(multi_detector_consensus_bonus(5), 0.15);
    }

    #[test]
    fn test_score_breakdown_clamp() {
        let srt = empty_srt();
        let ctx = ScoringContext::new(&srt);
        let bd = score_issue("use_after_free", &ctx);
        assert!(bd.total() >= 0.0 && bd.total() <= 1.0);
    }

    #[test]
    fn test_score_with_high_corpus_freq() {
        let srt = empty_srt();
        let ctx = ScoringContext {
            srt: &srt,
            has_di_metadata: false,
            has_usedef_analysis: false,
            corpus_frequency: 1000,
            dataflow_distance: 0,
            detector_count: 1,
        };
        let bd = score_issue("borrow_escape", &ctx);
        // High corpus frequency + no DI + no use-def → very low score
        assert!(bd.total() < 0.5, "expected low score, got {}", bd.total());
        assert_eq!(
            ConfidenceTier::from_score(bd.total()),
            ConfidenceTier::Informational
        );
    }

    #[test]
    fn test_score_with_strong_signals() {
        let srt = empty_srt();
        let ctx = ScoringContext {
            srt: &srt,
            has_di_metadata: true,
            has_usedef_analysis: true,
            corpus_frequency: 0,
            dataflow_distance: 1,
            detector_count: 3,
        };
        let bd = score_issue("use_after_free", &ctx);
        // Strong signals → high score
        assert!(
            bd.total() >= 0.85,
            "expected critical score, got {}",
            bd.total()
        );
        assert_eq!(
            ConfidenceTier::from_score(bd.total()),
            ConfidenceTier::Critical
        );
    }

    #[test]
    fn test_classify_issue() {
        let srt = empty_srt();
        let ctx = ScoringContext::new(&srt);
        let (tier, bd) = classify_issue("use_after_free", &ctx);
        assert_eq!(tier, ConfidenceTier::from_score(bd.total()));
    }

    #[test]
    fn test_breakdown_format() {
        let srt = empty_srt();
        let ctx = ScoringContext::new(&srt);
        let bd = score_issue("use_after_free", &ctx);
        let formatted = bd.format();
        assert!(formatted.contains("base="));
        assert!(formatted.contains("provenance="));
        assert!(formatted.contains("corpus_freq="));
    }
}
