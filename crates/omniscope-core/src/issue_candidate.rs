//! Issue candidate types for the resource contract architecture.
//!
//! Issues are NOT produced directly from pattern matching. Instead:
//!
//! ```text
//! raw pattern -> IssueCandidate -> IssueVerifier -> report or diagnostic
//! ```
//!
//! Only the verifier should produce reportable issues. Candidates are
//! intermediate artifacts that carry evidence but have not yet been
//! verified.

use omniscope_types::{Evidence, FamilyId, IssueCandidateKind, PointerContract, VerifierVerdict};
use serde::{Deserialize, Serialize};

use crate::diagnostics::Severity;
use crate::issue::{IssueKind, IssueLocation};

/// An issue candidate produced by the candidate builder.
///
/// Candidates carry the raw evidence and context for a potential issue.
/// They must be verified by the `IssueVerifier` before becoming reportable
/// issues. The verifier assigns a `VerifierVerdict` and may downgrade
/// or explain candidates as safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueCandidate {
    /// Candidate ID (distinct from issue ID — assigned at verification).
    pub id: CandidateId,
    /// What kind of candidate this is.
    pub kind: IssueCandidateKind,
    /// Resource family of the allocation.
    pub alloc_family: FamilyId,
    /// Resource family of the release (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_family: Option<FamilyId>,
    /// Pointer contract at the allocation point.
    pub alloc_contract: PointerContract,
    /// Pointer contract at the release point (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_contract: Option<PointerContract>,
    /// Function where the allocation occurs.
    pub alloc_function: String,
    /// Function where the release occurs (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_function: Option<String>,
    /// Verifier verdict (assigned by the verifier).
    pub verdict: Option<VerifierVerdict>,
    /// Evidence supporting this candidate.
    pub evidence: Vec<Evidence>,
    /// Source location of the allocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alloc_location: Option<IssueLocation>,
    /// Source location of the release.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_location: Option<IssueLocation>,
    /// Human-readable description (populated by verifier).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Unique identifier for issue candidates.
pub type CandidateId = u64;

impl IssueCandidate {
    /// Creates a new issue candidate with the given kind and families.
    pub fn new(
        id: CandidateId,
        kind: IssueCandidateKind,
        alloc_family: FamilyId,
        alloc_function: impl Into<String>,
    ) -> Self {
        Self {
            id,
            kind,
            alloc_family,
            release_family: None,
            alloc_contract: PointerContract::Unknown,
            release_contract: None,
            alloc_function: alloc_function.into(),
            release_function: None,
            verdict: None,
            evidence: Vec::new(),
            alloc_location: None,
            release_location: None,
            description: None,
        }
    }

    /// Adds evidence to this candidate.
    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.evidence.push(evidence);
    }

    /// Sets the release family.
    pub fn with_release_family(mut self, family: FamilyId) -> Self {
        self.release_family = Some(family);
        self
    }

    /// Sets the alloc contract.
    pub fn with_alloc_contract(mut self, contract: PointerContract) -> Self {
        self.alloc_contract = contract;
        self
    }

    /// Sets the release contract.
    pub fn with_release_contract(mut self, contract: PointerContract) -> Self {
        self.release_contract = Some(contract);
        self
    }

    /// Sets the release function.
    pub fn with_release_function(mut self, function: impl Into<String>) -> Self {
        self.release_function = Some(function.into());
        self
    }

    /// Sets the verifier verdict.
    pub fn with_verdict(mut self, verdict: VerifierVerdict) -> Self {
        self.verdict = Some(verdict);
        self
    }

    /// Sets the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Returns true if this candidate has been verified.
    pub fn is_verified(&self) -> bool {
        self.verdict.is_some()
    }

    /// Returns true if this candidate should be reported (verified as
    /// ConfirmedIssue or ProbableIssue).
    pub fn is_reportable(&self) -> bool {
        self.verdict.is_some_and(|v| v.is_reportable())
    }

    /// Converts a verified candidate to the corresponding `IssueKind`
    /// for reporting.
    pub fn to_issue_kind(&self) -> IssueKind {
        match self.kind {
            IssueCandidateKind::CrossFamilyFree => IssueKind::CrossFamilyFree,
            IssueCandidateKind::UseAfterRelease => IssueKind::UseAfterFree,
            IssueCandidateKind::DoubleRelease => IssueKind::DoubleFree,
            IssueCandidateKind::ConditionalLeak => IssueKind::ConditionalLeak,
            IssueCandidateKind::BorrowEscape => IssueKind::BorrowEscape,
            IssueCandidateKind::CallbackEscape => IssueKind::CallbackEscapeIssue,
            IssueCandidateKind::NeedsModel => IssueKind::NeedsModel,
            IssueCandidateKind::DoubleReclaim => IssueKind::DoubleReclaim,
            IssueCandidateKind::OwnershipEscapeLeak => IssueKind::OwnershipEscapeLeak,
            IssueCandidateKind::UseAfterFree => IssueKind::UseAfterFree,
        }
    }

    /// Returns the severity based on the candidate kind and verdict.
    pub fn severity(&self) -> Severity {
        match self.verdict {
            Some(VerifierVerdict::ConfirmedIssue) => Severity::Error,
            Some(VerifierVerdict::ProbableIssue) => Severity::Warning,
            Some(VerifierVerdict::Diagnostic) => Severity::Note,
            Some(VerifierVerdict::ExplainedSafe) => Severity::Note,
            None => Severity::Warning, // Unverified default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_creation() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        );
        assert!(
            !candidate.is_verified(),
            "New candidate should not be verified"
        );
        assert!(
            !candidate.is_reportable(),
            "Unverified candidate should not be reportable"
        );
    }

    #[test]
    fn test_candidate_verified_reportable() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_release_family(FamilyId::CPP_NEW_SCALAR)
        .with_release_function("operator delete")
        .with_verdict(VerifierVerdict::ConfirmedIssue);

        assert!(candidate.is_verified());
        assert!(candidate.is_reportable());
        assert_eq!(candidate.to_issue_kind(), IssueKind::CrossFamilyFree);
        assert_eq!(candidate.severity(), Severity::Error);
    }

    #[test]
    fn test_candidate_explained_safe_not_reportable() {
        let candidate = IssueCandidate::new(
            2,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::PYTHON_OBJECT,
            "PyObject_New",
        )
        .with_verdict(VerifierVerdict::ExplainedSafe);

        assert!(candidate.is_verified());
        assert!(
            !candidate.is_reportable(),
            "ExplainedSafe should NOT be reportable"
        );
        assert_eq!(candidate.severity(), Severity::Note);
    }

    #[test]
    fn test_candidate_to_issue_kind_mapping() {
        assert_eq!(
            IssueCandidate::new(
                1,
                IssueCandidateKind::CrossFamilyFree,
                FamilyId::C_HEAP,
                "f"
            )
            .to_issue_kind(),
            IssueKind::CrossFamilyFree
        );
        assert_eq!(
            IssueCandidate::new(
                2,
                IssueCandidateKind::UseAfterRelease,
                FamilyId::C_HEAP,
                "f"
            )
            .to_issue_kind(),
            IssueKind::UseAfterFree
        );
        assert_eq!(
            IssueCandidate::new(3, IssueCandidateKind::DoubleRelease, FamilyId::C_HEAP, "f")
                .to_issue_kind(),
            IssueKind::DoubleFree
        );
        assert_eq!(
            IssueCandidate::new(
                4,
                IssueCandidateKind::ConditionalLeak,
                FamilyId::C_HEAP,
                "f"
            )
            .to_issue_kind(),
            IssueKind::ConditionalLeak
        );
        assert_eq!(
            IssueCandidate::new(5, IssueCandidateKind::BorrowEscape, FamilyId::C_HEAP, "f")
                .to_issue_kind(),
            IssueKind::BorrowEscape
        );
        assert_eq!(
            IssueCandidate::new(6, IssueCandidateKind::CallbackEscape, FamilyId::C_HEAP, "f")
                .to_issue_kind(),
            IssueKind::CallbackEscapeIssue
        );
        assert_eq!(
            IssueCandidate::new(7, IssueCandidateKind::NeedsModel, FamilyId::C_HEAP, "f")
                .to_issue_kind(),
            IssueKind::NeedsModel
        );
        assert_eq!(
            IssueCandidate::new(8, IssueCandidateKind::UseAfterFree, FamilyId::C_HEAP, "f")
                .to_issue_kind(),
            IssueKind::UseAfterFree
        );
    }
}
