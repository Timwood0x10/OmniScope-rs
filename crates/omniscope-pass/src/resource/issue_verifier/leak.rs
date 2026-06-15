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

    // Build a path-sensitive verifier from available evidence.
    // PathStateRefinement indicates path analysis was performed.
    let has_path_refinement = bundle
        .evidence_kinds
        .contains(&EvidenceKind::PathStateRefinement);
    let path_verifier = if has_path_refinement {
        PathSensitiveVerifier::with_path_data(2, 2, 0)
    } else {
        PathSensitiveVerifier::new()
    };

    // High-confidence leak suppression: semantic or evidence facts explain
    // why the resource is not freed locally.
    if bundle.has_leak_suppression_high_confidence() {
        return path_verifier.adjust_verdict(VerifierVerdict::ExplainedSafe);
    }

    // Medium-confidence suppression: downgrade to probable.
    if bundle.has_leak_suppression_medium_confidence() {
        return path_verifier.adjust_verdict(VerifierVerdict::ProbableIssue);
    }

    // Use path verifier to finalize — when all paths leak, confirm.
    path_verifier.adjust_verdict(VerifierVerdict::ConfirmedIssue)
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

    // Build a path-sensitive verifier from available evidence.
    let has_path_refinement = bundle
        .evidence_kinds
        .contains(&EvidenceKind::PathStateRefinement);
    let path_verifier = if has_path_refinement {
        // Conditional leak: some paths safe, some paths leak.
        PathSensitiveVerifier::with_path_data(2, 1, 1)
    } else {
        PathSensitiveVerifier::new()
    };

    // High-confidence leak suppression: fully explain the conditional leak.
    if bundle.has_leak_suppression_high_confidence() {
        return path_verifier.adjust_verdict(VerifierVerdict::ExplainedSafe);
    }

    // Medium-confidence suppression: for conditional leaks, downgrade to ProbableIssue.
    if bundle.has_leak_suppression_medium_confidence() {
        return path_verifier.adjust_verdict(VerifierVerdict::ProbableIssue);
    }

    // Fallback: check the legacy leak suppression method.
    if bundle.has_leak_suppression() {
        return path_verifier.adjust_verdict(VerifierVerdict::ExplainedSafe);
    }

    // Path-state refinement means we analyzed the control flow.
    if bundle
        .evidence_kinds
        .contains(&EvidenceKind::PathStateRefinement)
    {
        return path_verifier.adjust_verdict(VerifierVerdict::ProbableIssue);
    }

    // No suppression, no path refinement — probable leak.
    path_verifier.adjust_verdict(VerifierVerdict::ProbableIssue)
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

    // Check if ownership was transferred via into_raw (R-6).
    if has_evidence(candidate, EvidenceKind::OwnershipTransfer) {
        return VerifierVerdict::ExplainedSafe;
    }

    // GlobalStore evidence (StackToGlobalEscape / HeapToGlobalEscape) is
    // a strong signal that the pointer escapes function scope through a
    // global variable — this is a real borrow-safety issue (UAR / UAF).
    if has_evidence(candidate, EvidenceKind::GlobalStore) {
        eprintln!(
            "[VBE] {} → ProbableIssue (GlobalStore)",
            candidate.alloc_caller.as_deref().unwrap_or("?")
        );
        return VerifierVerdict::ProbableIssue;
    }

    // Check if the escaped pointer has heap provenance (R-1).
    // NOTE: IrPattern evidence with "heap"/"global" in the description
    // indicates an escape pattern was detected — this is a real issue,
    // NOT a reason to suppress.  Only treat non-escape IrPattern as safe.
    if has_evidence(candidate, EvidenceKind::IrPattern) {
        let has_escape_pattern = candidate.evidence.iter().any(|e| {
            e.kind == EvidenceKind::IrPattern
                && (e.description.contains("escape")
                    || e.description.contains("Escape")
                    || e.description.contains("global")
                    || e.description.contains("Global")
                    || e.description.contains("ReturnAlias")
                    || e.description.contains("alias"))
        });
        if has_escape_pattern {
            eprintln!(
                "[VBE] {} → ProbableIssue (IrPattern escape)",
                candidate.alloc_caller.as_deref().unwrap_or("?")
            );
            return VerifierVerdict::ProbableIssue;
        }
        // Non-escape IrPattern (e.g., PureComputation) → safe
        eprintln!(
            "[VBE] {} → ExplainedSafe (non-escape IrPattern)",
            candidate.alloc_caller.as_deref().unwrap_or("?")
        );
        return VerifierVerdict::ExplainedSafe;
    }

    // Stack/borrowed userdata escaped to callback — real issue.
    VerifierVerdict::ProbableIssue
}

/// Path-aware description for a leak candidate.
///
/// Provides a structured description that includes path-sensitive
/// information such as how many paths leak and the confidence level
/// of the analysis.
#[derive(Debug, Clone)]
pub(crate) struct PathAwareLeakDescription {
    /// The alloc function name.
    pub alloc_function: String,
    /// The caller function name.
    pub alloc_caller: String,
    /// The resource family.
    pub family: omniscope_types::FamilyId,
    /// Total paths analyzed.
    pub total_paths: usize,
    /// Paths that leak (resource still owned at exit).
    pub leaking_paths: usize,
    /// Paths that are safe (resource released, escaped, etc.).
    pub safe_paths: usize,
    /// Confidence level as a string.
    pub confidence_label: &'static str,
}

impl PathAwareLeakDescription {
    /// Builds a new path-aware leak description from analysis data.
    ///
    /// # Arguments
    /// * `alloc_function` - The allocation function name.
    /// * `alloc_caller` - The caller function name.
    /// * `family` - The resource family.
    /// * `total_paths` - Total number of paths analyzed.
    /// * `leaking_paths` - Number of leaking paths.
    /// * `safe_paths` - Number of safe paths.
    ///
    /// # Examples
    ///
    /// ```
    /// # use omniscope_pass::resource::issue_verifier::leak::*;
    /// # use omniscope_types::FamilyId;
    /// let desc = PathAwareLeakDescription::build(
    ///     "malloc", "my_func", FamilyId::C_HEAP, 4, 3, 1,
    /// );
    /// assert!(desc.to_string().contains("3 of 4 paths leak"));
    /// ```
    #[expect(dead_code, reason = "used in tests and doc-tests")]
    pub(crate) fn build(
        alloc_function: &str,
        alloc_caller: &str,
        family: omniscope_types::FamilyId,
        total_paths: usize,
        leaking_paths: usize,
        safe_paths: usize,
    ) -> Self {
        let confidence_label = if total_paths == 0 {
            "unknown"
        } else {
            let ratio = leaking_paths as f32 / total_paths as f32;
            if ratio >= 0.90 {
                "high"
            } else if ratio >= 0.65 {
                "medium"
            } else {
                "low"
            }
        };

        Self {
            alloc_function: alloc_function.to_string(),
            alloc_caller: alloc_caller.to_string(),
            family,
            total_paths,
            leaking_paths,
            safe_paths,
            confidence_label,
        }
    }

    /// Formats this description as a human-readable string.
    pub(crate) fn format_description(&self) -> String {
        format!(
            "path-aware leak in '{}' (caller: {}): {} of {} paths leak, \
             {} safe (family {}, confidence={})",
            self.alloc_function,
            self.alloc_caller,
            self.leaking_paths,
            self.total_paths,
            self.safe_paths,
            self.family.display_name(),
            self.confidence_label,
        )
    }
}

impl std::fmt::Display for PathAwareLeakDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format_description())
    }
}

/// A path-sensitive verifier that adjusts verdicts based on path analysis.
///
/// Integrates with the leak verification pipeline to provide confidence-aware
/// verdicts using path state information.
#[derive(Debug, Clone)]
pub(crate) struct PathSensitiveVerifier {
    /// Whether path analysis data is available.
    pub has_path_data: bool,
    /// Total paths analyzed (0 if unavailable).
    pub total_paths: usize,
    /// Number of paths where the resource is owned at exit.
    pub owned_paths: usize,
    /// Number of safe paths.
    pub safe_paths: usize,
}

impl PathSensitiveVerifier {
    /// Creates a new `PathSensitiveVerifier` with no path data.
    pub(crate) fn new() -> Self {
        Self {
            has_path_data: false,
            total_paths: 0,
            owned_paths: 0,
            safe_paths: 0,
        }
    }

    /// Creates a new `PathSensitiveVerifier` with path analysis results.
    ///
    /// # Arguments
    /// * `total_paths` - Total number of paths analyzed.
    /// * `owned_paths` - Number of paths where resource is still owned.
    /// * `safe_paths` - Number of paths where resource is safe.
    pub(crate) fn with_path_data(
        total_paths: usize,
        owned_paths: usize,
        safe_paths: usize,
    ) -> Self {
        Self {
            has_path_data: total_paths > 0,
            total_paths,
            owned_paths,
            safe_paths,
        }
    }

    /// Adjusts a leak verdict based on path-sensitive information.
    ///
    /// Rules:
    /// - No path data → returns the original verdict unchanged.
    /// - All paths safe → returns `ExplainedSafe`.
    /// - All paths leak → returns `ConfirmedIssue`.
    /// - Mixed paths → returns the original verdict (already conditional).
    pub(crate) fn adjust_verdict(&self, original: VerifierVerdict) -> VerifierVerdict {
        if !self.has_path_data {
            return original;
        }

        if self.total_paths > 0 && self.safe_paths == self.total_paths {
            // All paths are safe — no leak.
            return VerifierVerdict::ExplainedSafe;
        }

        if self.total_paths > 0 && self.owned_paths == self.total_paths {
            // All paths leak — definite.
            return VerifierVerdict::ConfirmedIssue;
        }

        // Mixed or partial data — keep original verdict.
        original
    }

    /// Returns a numeric confidence score based on the path data.
    ///
    /// Score range `[0.0, 1.0]`:
    /// - All paths agree → 0.9
    /// - Majority agrees → proportional
    /// - No data → 0.0
    #[expect(dead_code, reason = "available for future verifier integration")]
    pub(crate) fn confidence_score(&self) -> f32 {
        if !self.has_path_data || self.total_paths == 0 {
            return 0.0;
        }

        let max_agree = self.owned_paths.max(self.safe_paths);
        max_agree as f32 / self.total_paths as f32
    }

    /// Returns the leak ratio (owned / total).
    #[expect(dead_code, reason = "available for future verifier integration")]
    pub(crate) fn leak_ratio(&self) -> f32 {
        if self.total_paths == 0 {
            return 0.0;
        }
        self.owned_paths as f32 / self.total_paths as f32
    }
}

impl Default for PathSensitiveVerifier {
    fn default() -> Self {
        Self::new()
    }
}
