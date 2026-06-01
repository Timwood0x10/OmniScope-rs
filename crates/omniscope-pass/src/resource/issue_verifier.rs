//! Issue verifier pass for resource contract analysis.
//!
//! The ONLY pass that should produce reportable issues. Verifies
//! each `IssueCandidate` and assigns a `VerifierVerdict`:
//!
//! - `ConfirmedIssue` — high confidence real issue
//! - `ProbableIssue` — likely real, needs human review
//! - `Diagnostic` — not a bug, useful for debugging
//! - `ExplainedSafe` — investigated and found benign
//!
//! Verification checks (per ARCHITECTURE_ADJUSTMENT.md):
//! - Family match or mismatch (using registry compatible-release)
//! - Ownership state at release point
//! - Valid escape (return/out-param/field/global/callback)
//! - Destructor/drop/cleanup release path
//! - Runtime/compiler origin (lower severity for runtime-originated)
//! - Unknown-family and unknown-cleanup policy
//! - **Issue Gate (SRT-based)** — before emitting, every issue is
//!   checked against the Semantic Resolution Tree. If the SRT has
//!   a suppression tag (R-0~R-7), the issue is suppressed.

use omniscope_core::{Issue, IssueCandidate, Result};
use omniscope_semantics::FamilyRegistry;
use omniscope_types::{EvidenceKind, IssueCandidateKind, VerifierVerdict};

use crate::analysis::NoiseReduction;
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

        let candidates: Vec<IssueCandidate> = ctx
            .get_ref::<Vec<IssueCandidate>>("issue_candidates")
            .cloned()
            .unwrap_or_default();
        let registry = ctx
            .get_ref::<FamilyRegistry>("family_registry")
            .cloned()
            .unwrap_or_default();

        // Layer 1: NoiseReduction — fast string-based FP pre-filter.
        let noise = NoiseReduction::new();

        let mut verified: Vec<IssueCandidate> = Vec::new();
        let mut issues: Vec<Issue> = Vec::new();
        let mut noise_suppressed: usize = 0;

        for mut candidate in candidates {
            let verdict = verify_candidate(&candidate, &registry);
            candidate.verdict = Some(verdict);

            // Attach a human-readable description based on the verdict.
            if candidate.description.is_none() {
                candidate.description = Some(build_verdict_description(&candidate, verdict));
            }

            // Layer 1: Fast string-based FP suppression — skip known
            // safe patterns (compiler intrinsics, allocator internals, etc.)
            // before even reaching the SRT gate.
            let func_name = candidate
                .release_function
                .as_deref()
                .unwrap_or(&candidate.alloc_function);
            if noise.should_suppress(func_name) {
                noise_suppressed += 1;
                candidate.verdict = Some(VerifierVerdict::ExplainedSafe);
                verified.push(candidate);
                continue;
            }

            if candidate.is_reportable() {
                let issue_id = ctx.next_issue_id();
                let mut issue = Issue::new(
                    issue_id,
                    candidate.to_issue_kind(),
                    candidate.severity(),
                    candidate.description.clone().unwrap_or_default(),
                );

                // Set symbol for SRT lookup from the candidate's function names.
                let symbol = candidate
                    .release_function
                    .as_deref()
                    .unwrap_or(&candidate.alloc_function);
                issue = issue.with_symbol(symbol);

                // Set the issue location with the function name from the candidate.
                // Use alloc_function as the primary location (where the resource
                // was acquired), which is the most relevant for diagnostics.
                if !candidate.alloc_function.is_empty() && candidate.alloc_function != "unknown" {
                    let location =
                        omniscope_core::IssueLocation::new(std::path::PathBuf::from("<ir>"), 0)
                            .with_function(&candidate.alloc_function);
                    issue = issue.with_location(location);
                }

                // emit_issue is the SRT gate choke point — only add to
                // PassResult.issues if the gate allows it.
                let outcome = ctx.emit_issue(issue.clone());
                if outcome.is_allowed() {
                    issues.push(issue);
                }
            }

            verified.push(candidate);
        }

        let verified_count = verified.len();
        let gate_suppressed = ctx.suppressed_issue_count();
        ctx.store("verified_candidates", verified);

        let mut result = PassResult::new(self.name())
            .with_nodes(verified_count)
            .with_duration(start.elapsed().as_millis() as u64);
        for issue in issues {
            result.add_issue(issue);
        }
        result.add_stat("gate_suppressed", gate_suppressed);
        result.add_stat("noise_suppressed", noise_suppressed);

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
/// - Family match or mismatch (using registry compatible-release)
/// - Ownership state and pointer contract
/// - Valid escape (return/out-param/field/global/callback)
/// - Destructor/drop/cleanup release path
/// - Runtime/compiler origin
/// - Unknown family policy (NeedsModel → Diagnostic, not high severity)
fn verify_candidate(candidate: &IssueCandidate, registry: &FamilyRegistry) -> VerifierVerdict {
    match candidate.kind {
        IssueCandidateKind::CrossFamilyFree => verify_cross_family_free(candidate, registry),
        IssueCandidateKind::UseAfterRelease => {
            // Use-after-release is almost always a real issue,
            // unless there is clear evidence of re-acquisition.
            if has_escape_evidence(candidate, EvidenceKind::ReturnToCaller) {
                // Returned to caller — caller may re-acquire. Probable.
                VerifierVerdict::ProbableIssue
            } else {
                VerifierVerdict::ConfirmedIssue
            }
        }
        IssueCandidateKind::DoubleRelease => {
            // Double release is always a real issue.
            VerifierVerdict::ConfirmedIssue
        }
        IssueCandidateKind::ConditionalLeak => verify_conditional_leak(candidate),
        IssueCandidateKind::BorrowEscape => verify_borrow_escape(candidate),
        IssueCandidateKind::CallbackEscape => {
            // Callback escape — diagnostic, not necessarily a bug.
            // The callback may or may not assume ownership.
            VerifierVerdict::Diagnostic
        }
        IssueCandidateKind::NeedsModel => {
            // Unknown family/cleanup — diagnostic, not a bug.
            VerifierVerdict::Diagnostic
        }
        IssueCandidateKind::DoubleReclaim => {
            // Double reclaim (from_raw called twice on same pointer)
            // is always a real issue — same as double free.
            VerifierVerdict::ConfirmedIssue
        }
        IssueCandidateKind::OwnershipEscapeLeak => {
            // into_raw without from_raw — ownership leaked across FFI boundary.
            // Always at least probable since the pointer may be reclaimed
            // in a different compilation unit we don't see.
            VerifierVerdict::ProbableIssue
        }
        IssueCandidateKind::UseAfterFree => {
            // Use-after-free through FFI boundary is almost always confirmed.
            // The resource was freed and then used — this is undefined behavior.
            VerifierVerdict::ConfirmedIssue
        }
    }
}

/// Verifies a cross-family free candidate.
fn verify_cross_family_free(
    candidate: &IssueCandidate,
    registry: &FamilyRegistry,
) -> VerifierVerdict {
    let Some(release_family) = candidate.release_family else {
        // Release family unknown — probable issue but not confirmed.
        return VerifierVerdict::ProbableIssue;
    };

    // Check compatible release via the registry.
    if registry.is_compatible_release(candidate.alloc_family, release_family) {
        // Same or compatible family — this was a false alarm.
        return VerifierVerdict::ExplainedSafe;
    }

    // Check for destructor-mediated release — this is a valid
    // release path. E.g., Rust Drop calling C free.
    if has_evidence(candidate, EvidenceKind::DestructorRelease) {
        return VerifierVerdict::ExplainedSafe;
    }

    // Check for valid escape — if the resource was returned to caller
    // or stored in an owner, the release may be in a different context.
    if has_escape_evidence(candidate, EvidenceKind::ReturnToCaller)
        || has_escape_evidence(candidate, EvidenceKind::OutParamInit)
        || has_escape_evidence(candidate, EvidenceKind::FieldStoreToOwner)
    {
        // Escaped via valid path — the release may happen elsewhere.
        // Cross-family is still a probable issue but not confirmed.
        return VerifierVerdict::ProbableIssue;
    }

    // Genuinely different families with no valid escape — confirmed.
    VerifierVerdict::ConfirmedIssue
}

/// Verifies a conditional leak candidate.
fn verify_conditional_leak(candidate: &IssueCandidate) -> VerifierVerdict {
    // OwnershipEscapeLeak: into_raw without from_raw — the raw pointer
    // was explicitly leaked across the FFI boundary. This is a stronger
    // signal than a generic conditional leak; the pointer may never be
    // reclaimed. Skip the usual escape-based suppression checks.
    if has_evidence(candidate, EvidenceKind::OwnershipEscapeLeak) {
        return VerifierVerdict::ProbableIssue;
    }

    // Check for valid escape that explains the "leak".
    if has_evidence(candidate, EvidenceKind::ReturnToCaller) {
        // Returned to caller — not a local leak.
        return VerifierVerdict::ExplainedSafe;
    }

    if has_evidence(candidate, EvidenceKind::OutParamInit) {
        // Stored via out-param — not a leak.
        return VerifierVerdict::ExplainedSafe;
    }

    if has_evidence(candidate, EvidenceKind::FieldStoreToOwner) {
        // Stored in owner field — not an immediate leak.
        return VerifierVerdict::ExplainedSafe;
    }

    if has_evidence(candidate, EvidenceKind::StaticLifetimeSink) {
        // Static lifetime — not a leak (process lives forever).
        return VerifierVerdict::ExplainedSafe;
    }

    if has_evidence(candidate, EvidenceKind::RefcountConditional) {
        // Refcount conditional release — the leak is conditional
        // on refcount not reaching zero.
        return VerifierVerdict::ProbableIssue;
    }

    // No valid escape found — probable leak.
    VerifierVerdict::ProbableIssue
}

/// Verifies a borrow escape candidate.
fn verify_borrow_escape(candidate: &IssueCandidate) -> VerifierVerdict {
    // Check if the "escape" is actually a bridge helper.
    if has_evidence(candidate, EvidenceKind::BridgeHelper) {
        // Bridge helper returns borrowed pointer — not an escape.
        return VerifierVerdict::ExplainedSafe;
    }

    // Check if the escaped pointer has heap provenance (R-1).
    // Heap pointers passed to callbacks are safe — the heap allocation
    // outlives the callback registration.
    if has_evidence(candidate, EvidenceKind::IrPattern) {
        // IR pattern evidence may indicate heap/global provenance.
        // Check if the evidence mentions heap or global provenance.
        let has_heap = candidate.evidence.iter().any(|e| {
            e.kind == EvidenceKind::IrPattern
                && (e.description.contains("heap") || e.description.contains("global"))
        });
        if has_heap {
            return VerifierVerdict::ExplainedSafe;
        }
    }

    // Check if ownership was transferred via into_raw (R-6).
    // If the pointer was intentionally moved to the C side via into_raw,
    // the C callback using it is by-design.
    if has_evidence(candidate, EvidenceKind::OwnershipTransfer) {
        return VerifierVerdict::ExplainedSafe;
    }

    // Stack/borrowed userdata escaped to callback — real issue.
    // The stack frame may be gone by the time the callback fires.
    VerifierVerdict::ProbableIssue
}

/// Checks if the candidate has evidence of a specific kind.
fn has_evidence(candidate: &IssueCandidate, kind: EvidenceKind) -> bool {
    candidate.evidence.iter().any(|e| e.kind == kind)
}

/// Checks if the candidate has an escape-related evidence of a specific kind.
fn has_escape_evidence(candidate: &IssueCandidate, kind: EvidenceKind) -> bool {
    candidate
        .evidence
        .iter()
        .any(|e| e.kind == kind && e.escape.is_some())
}

/// Builds a human-readable description for a verified candidate.
fn build_verdict_description(candidate: &IssueCandidate, verdict: VerifierVerdict) -> String {
    let kind_label = match candidate.kind {
        IssueCandidateKind::CrossFamilyFree => "cross-family free",
        IssueCandidateKind::UseAfterRelease => "use after release",
        IssueCandidateKind::DoubleRelease => "double release",
        IssueCandidateKind::ConditionalLeak => "conditional leak",
        IssueCandidateKind::BorrowEscape => "borrow escape",
        IssueCandidateKind::CallbackEscape => "callback escape",
        IssueCandidateKind::NeedsModel => "needs model",
        IssueCandidateKind::DoubleReclaim => "double reclaim",
        IssueCandidateKind::OwnershipEscapeLeak => "ownership escape leak",
        IssueCandidateKind::UseAfterFree => "use-after-free",
    };

    let verdict_label = match verdict {
        VerifierVerdict::ConfirmedIssue => "confirmed",
        VerifierVerdict::ProbableIssue => "probable",
        VerifierVerdict::Diagnostic => "diagnostic",
        VerifierVerdict::ExplainedSafe => "explained safe",
    };

    match candidate.kind {
        IssueCandidateKind::CrossFamilyFree => {
            let alloc_label = format!("{:?}", candidate.alloc_family);
            let release_label = candidate
                .release_family
                .map_or("unknown".to_string(), |f| format!("{f:?}"));
            format!(
                "{kind_label}: {alloc_label} allocated in '{}' released as {release_label} in '{}' [{verdict_label}]",
                candidate.alloc_function,
                candidate.release_function.as_deref().unwrap_or("unknown")
            )
        }
        IssueCandidateKind::ConditionalLeak => {
            format!(
                "{kind_label}: resource from '{}' ({:?}) may not be freed on all paths [{verdict_label}]",
                candidate.alloc_function, candidate.alloc_family
            )
        }
        IssueCandidateKind::NeedsModel => {
            format!(
                "{kind_label}: unknown resource family in '{}' [{verdict_label}]",
                candidate.alloc_function
            )
        }
        _ => {
            format!(
                "{kind_label} in '{}' [{verdict_label}]",
                candidate.alloc_function
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_types::{Evidence, FamilyId};

    #[test]
    fn test_verifier_creation() {
        let pass = IssueVerifierPass::new();
        assert_eq!(
            pass.name(),
            "IssueVerifier",
            "Pass name should be IssueVerifier"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Pass kind should be Analysis"
        );
        assert_eq!(
            pass.dependencies(),
            vec!["IssueCandidateBuilder"],
            "Dependencies should be IssueCandidateBuilder"
        );
    }

    #[test]
    fn test_verify_cross_family_confirmed() {
        let registry = FamilyRegistry::new();
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_release_family(FamilyId::CPP_NEW_SCALAR)
        .with_release_function("operator delete");

        let verdict = verify_candidate(&candidate, &registry);
        assert_eq!(
            verdict,
            VerifierVerdict::ConfirmedIssue,
            "Cross-family free should be confirmed issue"
        );
    }

    #[test]
    fn test_verify_same_family_explained_safe() {
        let registry = FamilyRegistry::new();
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_release_family(FamilyId::C_HEAP)
        .with_release_function("free");

        let verdict = verify_candidate(&candidate, &registry);
        assert_eq!(
            verdict,
            VerifierVerdict::ExplainedSafe,
            "Same-family release is not an issue"
        );
    }

    #[test]
    fn test_verify_needs_model_is_diagnostic() {
        let registry = FamilyRegistry::new();
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::NeedsModel,
            FamilyId::C_HEAP,
            "custom_alloc",
        );

        let verdict = verify_candidate(&candidate, &registry);
        assert_eq!(
            verdict,
            VerifierVerdict::Diagnostic,
            "NeedsModel should be a diagnostic, not an error"
        );
    }

    #[test]
    fn test_verify_double_release_confirmed() {
        let registry = FamilyRegistry::new();
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::DoubleRelease,
            FamilyId::C_HEAP,
            "free",
        );

        let verdict = verify_candidate(&candidate, &registry);
        assert_eq!(
            verdict,
            VerifierVerdict::ConfirmedIssue,
            "Double release should be confirmed issue"
        );
    }

    #[test]
    fn test_verify_destructor_release_explained_safe() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::RUST_GLOBAL,
            "__rust_alloc",
        )
        .with_release_family(FamilyId::C_HEAP)
        .with_release_function("drop");

        // Attach destructor release evidence
        candidate.add_evidence(
            Evidence::new(EvidenceKind::DestructorRelease, "Rust Drop calling C free")
                .with_confidence(0.9),
        );

        let verdict = verify_candidate(&candidate, &registry);
        assert_eq!(
            verdict,
            VerifierVerdict::ExplainedSafe,
            "Destructor-mediated release should be explained safe"
        );
    }

    #[test]
    fn test_verify_conditional_leak_with_return_escape() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::C_HEAP,
            "malloc",
        );

        // Attach return-to-caller evidence
        candidate.add_evidence(
            Evidence::new(EvidenceKind::ReturnToCaller, "pointer returned to caller")
                .with_confidence(0.95),
        );

        let verdict = verify_candidate(&candidate, &registry);
        assert_eq!(
            verdict,
            VerifierVerdict::ExplainedSafe,
            "Return-to-caller escape should explain the leak"
        );
    }

    #[test]
    fn test_verify_conditional_leak_with_static_lifetime() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::C_HEAP,
            "__cxx_global_var_init",
        );

        candidate.add_evidence(
            Evidence::new(
                EvidenceKind::StaticLifetimeSink,
                "global variable initialization",
            )
            .with_confidence(0.95),
        );

        let verdict = verify_candidate(&candidate, &registry);
        assert_eq!(
            verdict,
            VerifierVerdict::ExplainedSafe,
            "Static-lifetime sink should explain the leak"
        );
    }

    #[test]
    fn test_verify_borrow_escape_with_bridge_evidence() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::BorrowEscape,
            FamilyId::C_HEAP,
            "as_ptr",
        );

        candidate.add_evidence(
            Evidence::new(
                EvidenceKind::BridgeHelper,
                "as_ptr returns borrowed pointer",
            )
            .with_confidence(0.95),
        );

        let verdict = verify_candidate(&candidate, &registry);
        assert_eq!(
            verdict,
            VerifierVerdict::ExplainedSafe,
            "Bridge helper should explain the borrow escape"
        );
    }

    #[test]
    fn test_verify_callback_escape_diagnostic() {
        let registry = FamilyRegistry::new();
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CallbackEscape,
            FamilyId::C_HEAP,
            "register_callback",
        );

        let verdict = verify_candidate(&candidate, &registry);
        assert_eq!(
            verdict,
            VerifierVerdict::Diagnostic,
            "Callback escape should be diagnostic"
        );
    }

    #[test]
    fn test_verify_cross_family_unknown_release_family() {
        let registry = FamilyRegistry::new();
        // No release family specified — probable issue
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        );

        let verdict = verify_candidate(&candidate, &registry);
        assert_eq!(
            verdict,
            VerifierVerdict::ProbableIssue,
            "Unknown release family should be probable issue"
        );
    }

    #[test]
    fn test_verdict_description_cross_family() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_release_family(FamilyId::CPP_NEW_SCALAR)
        .with_release_function("operator delete");

        let desc = build_verdict_description(&candidate, VerifierVerdict::ConfirmedIssue);
        assert!(
            desc.contains("cross-family free"),
            "Description must mention cross-family free"
        );
        assert!(
            desc.contains("confirmed"),
            "Description must mention verdict"
        );
    }

    #[test]
    fn test_verdict_description_needs_model() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::NeedsModel,
            FamilyId::C_HEAP,
            "custom_alloc",
        );

        let desc = build_verdict_description(&candidate, VerifierVerdict::Diagnostic);
        assert!(
            desc.contains("needs model"),
            "Description must mention needs model"
        );
        assert!(
            desc.contains("diagnostic"),
            "Description must mention verdict"
        );
    }
}
