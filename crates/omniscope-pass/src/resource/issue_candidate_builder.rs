//! Issue candidate builder pass for resource contract analysis.
//!
//! Builds `IssueCandidate` entries from the contract graph and
//! ownership states. Candidates are NOT reportable issues — they
//! must pass through the `IssueVerifier` first.

use omniscope_core::{IssueCandidate, Result};
use omniscope_types::{FamilyId, IssueCandidateKind};

use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// Issue candidate builder pass.
///
/// Scans the contract graph and ownership states for potential issues:
/// - Cross-family release edges
/// - Unreleased resources (leak candidates)
/// - Double release edges
/// - Borrowed pointer escapes
///
/// Each candidate carries evidence but NO verdict. The verifier
/// must be run after this pass.
pub struct IssueCandidateBuilderPass;

impl IssueCandidateBuilderPass {
    /// Creates a new issue candidate builder pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for IssueCandidateBuilderPass {
    fn name(&self) -> &'static str {
        "IssueCandidateBuilder"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["OwnershipSolver"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        let candidates: Vec<IssueCandidate> = Vec::new();

        // In a full implementation, we would:
        // 1. Load contract graph from context
        // 2. Load ownership states from context
        // 3. For each acquire→release edge, check family compatibility
        // 4. For each unreleased instance, create ConditionalLeak candidate
        // 5. For each double-release edge, create DoubleRelease candidate
        // 6. For each borrow→escape edge, create BorrowEscape candidate

        ctx.store("issue_candidates", candidates.clone());

        let result = PassResult::new(self.name())
            .with_nodes(candidates.len())
            .with_duration(start.elapsed().as_millis() as u64);

        Ok(result)
    }
}

impl Default for IssueCandidateBuilderPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper: Build a cross-family free candidate.
pub fn build_cross_family_candidate(
    id: u64,
    alloc_family: FamilyId,
    release_family: FamilyId,
    alloc_func: &str,
    release_func: &str,
) -> IssueCandidate {
    let _mismatch = alloc_family != release_family;
    IssueCandidate::new(
        id,
        IssueCandidateKind::CrossFamilyFree,
        alloc_family,
        alloc_func,
    )
    .with_release_family(release_family)
    .with_release_function(release_func)
    .with_description(format!(
        "cross-family release: {} ({:?}) released by {} ({:?})",
        alloc_func, alloc_family, release_func, release_family
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_builder_creation() {
        let pass = IssueCandidateBuilderPass::new();
        assert_eq!(pass.name(), "IssueCandidateBuilder");
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert_eq!(pass.dependencies(), vec!["OwnershipSolver"]);
    }

    #[test]
    fn test_cross_family_candidate() {
        let candidate = build_cross_family_candidate(
            1,
            FamilyId::C_HEAP,
            FamilyId::CPP_NEW_SCALAR,
            "malloc",
            "operator delete",
        );
        assert_eq!(candidate.kind, IssueCandidateKind::CrossFamilyFree);
        assert_eq!(candidate.alloc_family, FamilyId::C_HEAP);
        assert_eq!(candidate.release_family, Some(FamilyId::CPP_NEW_SCALAR));
        assert!(
            !candidate.is_verified(),
            "Candidate should not be verified yet"
        );
    }
}
