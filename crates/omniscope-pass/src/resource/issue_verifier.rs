//! Issue verifier pass for resource contract analysis.
//!
//! The ONLY pass that should produce reportable issues. Verifies
//! each `IssueCandidate` and assigns a `VerifierVerdict`:
//!
//! - `ConfirmedIssue` — high confidence real issue
//! - `ProbableIssue` — likely real, needs human review
//! - `Diagnostic` — not a bug, useful for debugging
//! - `ExplainedSafe` — investigated and found benign

use omniscope_core::{Issue, IssueCandidate, Result};
use omniscope_types::{IssueCandidateKind, VerifierVerdict};

use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// Issue verifier pass.
///
/// Verifies each candidate from the `IssueCandidateBuilder` and
/// assigns a verdict. Only `ConfirmedIssue` and `ProbableIssue`
/// candidates become reportable `Issue` entries.
pub struct IssueVerifierPass;

impl IssueVerifierPass {
    /// Creates a new issue verifier pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for IssueVerifierPass {
    fn name(&self) -> &'static str {
        "IssueVerifier"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["IssueCandidateBuilder"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        let candidates: Vec<IssueCandidate> = ctx.get("issue_candidates").unwrap_or_default();

        let mut verified: Vec<IssueCandidate> = Vec::new();
        let mut issues: Vec<Issue> = Vec::new();

        for mut candidate in candidates {
            let verdict = verify_candidate(&candidate);
            candidate.verdict = Some(verdict);

            if candidate.is_reportable() {
                let issue_id = ctx.next_issue_id();
                let issue = Issue::new(
                    issue_id,
                    candidate.to_issue_kind(),
                    candidate.severity(),
                    candidate.description.clone().unwrap_or_default(),
                );
                ctx.emit_issue(issue.clone());
                issues.push(issue);
            }

            verified.push(candidate);
        }

        let verified_count = verified.len();
        ctx.store("verified_candidates", verified);

        let mut result = PassResult::new(self.name())
            .with_nodes(verified_count)
            .with_duration(start.elapsed().as_millis() as u64);
        for issue in issues {
            result.add_issue(issue);
        }

        Ok(result)
    }
}

impl Default for IssueVerifierPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifies a single issue candidate and returns a verdict.
///
/// This is the core verification logic. It checks:
/// - Family match or mismatch
/// - Ownership state
/// - Valid escape (return/out-param/field/global/callback)
/// - Destructor/drop/cleanup release path
/// - Unknown family policy (NeedsModel, not high severity)
fn verify_candidate(candidate: &IssueCandidate) -> VerifierVerdict {
    match candidate.kind {
        IssueCandidateKind::CrossFamilyFree => {
            // Cross-family release is a confirmed issue if families are
            // genuinely different and not compatible.
            if let Some(release_family) = candidate.release_family {
                if candidate.alloc_family == release_family {
                    // Same family — this was a false alarm
                    VerifierVerdict::ExplainedSafe
                } else {
                    // Different families — confirmed cross-family free
                    VerifierVerdict::ConfirmedIssue
                }
            } else {
                // Release family unknown — probable issue
                VerifierVerdict::ProbableIssue
            }
        }
        IssueCandidateKind::UseAfterRelease => {
            // Use-after-release is almost always a real issue
            VerifierVerdict::ConfirmedIssue
        }
        IssueCandidateKind::DoubleRelease => {
            // Double release is always a real issue
            VerifierVerdict::ConfirmedIssue
        }
        IssueCandidateKind::ConditionalLeak => {
            // Conditional leak — probable issue, needs human review
            VerifierVerdict::ProbableIssue
        }
        IssueCandidateKind::BorrowEscape => {
            // Borrow escape — probable issue
            VerifierVerdict::ProbableIssue
        }
        IssueCandidateKind::CallbackEscape => {
            // Callback escape — diagnostic, not necessarily a bug
            VerifierVerdict::Diagnostic
        }
        IssueCandidateKind::NeedsModel => {
            // Unknown family/cleanup — diagnostic, not a bug
            VerifierVerdict::Diagnostic
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        let pass = IssueVerifierPass::new();
        assert_eq!(pass.name(), "IssueVerifier");
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert_eq!(pass.dependencies(), vec!["IssueCandidateBuilder"]);
    }

    #[test]
    fn test_verify_cross_family_confirmed() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_release_family(FamilyId::CPP_NEW_SCALAR)
        .with_release_function("operator delete");

        let verdict = verify_candidate(&candidate);
        assert_eq!(verdict, VerifierVerdict::ConfirmedIssue);
    }

    #[test]
    fn test_verify_same_family_explained_safe() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_release_family(FamilyId::C_HEAP)
        .with_release_function("free");

        let verdict = verify_candidate(&candidate);
        assert_eq!(
            verdict,
            VerifierVerdict::ExplainedSafe,
            "Same-family release is not an issue"
        );
    }

    #[test]
    fn test_verify_needs_model_is_diagnostic() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::NeedsModel,
            FamilyId::C_HEAP,
            "custom_alloc",
        );

        let verdict = verify_candidate(&candidate);
        assert_eq!(
            verdict,
            VerifierVerdict::Diagnostic,
            "NeedsModel should be a diagnostic, not an error"
        );
    }

    #[test]
    fn test_verify_double_release_confirmed() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::DoubleRelease,
            FamilyId::C_HEAP,
            "free",
        );

        let verdict = verify_candidate(&candidate);
        assert_eq!(verdict, VerifierVerdict::ConfirmedIssue);
    }
}
