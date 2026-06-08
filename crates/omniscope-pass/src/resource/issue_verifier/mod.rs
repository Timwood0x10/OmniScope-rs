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

mod cross_family;
mod double_free;
mod helpers;
mod leak;

#[cfg(test)]
mod tests;

use omniscope_core::{Issue, IssueCandidate, Result};
#[allow(unused_imports)]
use omniscope_semantics::resource::memory_graph::{
    family_to_resource_class, MemoryGraph, ResourceClass, ResourceState,
};
use omniscope_semantics::{FamilyRegistry, SemanticKind};
use omniscope_types::{EvidenceKind, IssueCandidateKind, OmniScopeConfig, VerifierVerdict};

use super::evidence_bundle::EvidenceBundle;
use super::structural_inference_pass::is_runtime_internal;
use crate::analysis::NoiseReduction;
use crate::pass::{Pass, PassContext, PassKind, PassResult};

// Re-export from submodules
pub(crate) use cross_family::{
    should_report_as_cross_family, verify_cross_family_free, verify_cross_family_with_bundle,
};
pub(crate) use double_free::{verify_double_release, verify_double_release_with_bundle};
pub(crate) use helpers::{
    build_verdict_description, deduplicate_leak_candidates, has_escape_evidence,
    is_declaration_only_candidate, is_ffi_specific_issue, is_leak_candidate, is_memory_resource,
    is_runtime_allocator_function, is_runtime_deallocator_function,
    is_same_language_allocator_wrapper_noise,
};
pub(crate) use leak::{
    verify_borrow_escape, verify_conditional_leak, verify_conditional_leak_with_bundle,
    verify_definite_leak, verify_definite_leak_with_bundle,
};

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
        vec!["IssueCandidateBuilder", "FfiReturnCheck", "LeakDetection"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        // Collect candidates from multiple sources:
        // 1. IssueCandidateBuilder (resource contract analysis)
        // 2. FfiReturnCheckPass (FFI null check analysis)
        // 3. LeakDetectionPass (path-sensitive leak analysis)
        let mut candidates: Vec<IssueCandidate> = Vec::new();

        // Source 1: IssueCandidateBuilder
        if let Some(issue_candidates) = ctx.get_ref::<Vec<IssueCandidate>>("issue_candidates") {
            candidates.extend(issue_candidates.iter().cloned());
        }

        // Source 2: FfiReturnCheckPass
        if let Some(ffi_candidates) = ctx.get_ref::<Vec<IssueCandidate>>("ffi_return_candidates") {
            candidates.extend(ffi_candidates.iter().cloned());
        }

        // Source 3: LeakDetectionPass
        if let Some(leak_candidates) = ctx.get_ref::<Vec<IssueCandidate>>("leak_candidates") {
            candidates.extend(leak_candidates.iter().cloned());
        }

        // ── Deduplicate leak candidates ──
        deduplicate_leak_candidates(&mut candidates);

        let registry = ctx
            .get_ref::<FamilyRegistry>("family_registry")
            .cloned()
            .unwrap_or_default();

        // Get configuration from context
        let config = ctx.config().cloned();

        // Get boundary context from context
        #[allow(unused_variables)]
        let boundary_ctx = ctx
            .get_ref::<omniscope_types::boundary::BoundaryContext>("boundary_context")
            .cloned();

        // Get MemoryGraph for resource state verification
        let memory_graph = ctx.get_ref::<MemoryGraph>("memory_graph").cloned();

        // Get SRT resolutions for semantic-based verification
        let srt_resolutions = ctx
            .get_ref::<std::collections::HashMap<String, Vec<SemanticKind>>>("srt_resolutions")
            .cloned();

        // Get SRT facts for confidence-aware semantic verification
        let srt_facts = ctx
            .get_ref::<std::collections::HashMap<String, Vec<omniscope_semantics::SemanticFact>>>(
                "srt_facts",
            )
            .cloned();

        // Layer 1: NoiseReduction — fast string-based FP pre-filter.
        let noise = NoiseReduction::new();

        // ── Collect user-defined function names from IR ──
        let user_defined_functions: std::collections::HashSet<String> = ctx
            .get_ir_module()
            .map(|m| m.function_bodies.keys().cloned().collect())
            .unwrap_or_else(|| {
                ctx.get_ref::<omniscope_ir::IRModule>("ir_module")
                    .map(|m| m.function_bodies.keys().cloned().collect())
                    .unwrap_or_default()
            });
        let declared_functions: std::collections::HashSet<String> = ctx
            .get_ir_module()
            .map(|m| m.declarations.keys().cloned().collect())
            .unwrap_or_else(|| {
                ctx.get_ref::<omniscope_ir::IRModule>("ir_module")
                    .map(|m| m.declarations.keys().cloned().collect())
                    .unwrap_or_default()
            });
        let module_index = ctx
            .get_ref::<crate::module_index::ModuleIndex>("module_index")
            .cloned();

        // ── Single-language shortcut ──
        let is_single_language = ctx
            .get_ref::<crate::module_index::ModuleIndex>("module_index")
            .map(|idx| idx.is_single_language)
            .unwrap_or(false);

        let mut verified: Vec<IssueCandidate> = Vec::new();
        let mut issues: Vec<Issue> = Vec::new();
        let mut noise_suppressed: usize = 0;
        let mut ffi_gate_suppressed: usize = 0;
        let mut single_lang_suppressed: usize = 0;
        let mut semantic_suppressed: usize = 0;

        for mut candidate in candidates {
            let evidence_bundle = EvidenceBundle::from_candidate(
                &candidate,
                memory_graph.as_ref(),
                srt_resolutions.as_ref(),
                srt_facts.as_ref(),
            );
            let has_semantic_suppression = evidence_bundle.has_semantic_suppression();
            tracing::trace!(
                candidate_id = evidence_bundle.candidate_id,
                resource_id = ?evidence_bundle.resource_id,
                has_boundary_evidence = evidence_bundle.has_boundary_evidence,
                has_same_resource_evidence = evidence_bundle.has_same_resource_evidence,
                has_reachable_release = evidence_bundle.has_reachable_release,
                has_alias_rejection = evidence_bundle.has_alias_rejection,
                has_semantic_suppression,
                "built resource evidence bundle"
            );

            if is_declaration_only_candidate(
                &candidate,
                &user_defined_functions,
                &declared_functions,
            ) {
                semantic_suppressed += 1;
                candidate.verdict = Some(VerifierVerdict::ExplainedSafe);
                candidate.description.get_or_insert_with(|| {
                    "issue candidate refers only to extern declaration(s), not an executable code path".to_string()
                });
                verified.push(candidate);
                continue;
            }

            if let Some(ref index) = module_index {
                if is_same_language_allocator_wrapper_noise(&candidate, index) {
                    semantic_suppressed += 1;
                    candidate.verdict = Some(VerifierVerdict::ExplainedSafe);
                    candidate.description.get_or_insert_with(|| {
                        "allocator wrapper stays within one language/runtime family; no cross-language ownership violation".to_string()
                    });
                    verified.push(candidate);
                    continue;
                }
            }

            // ── Single-language filter ──
            if is_single_language && is_ffi_specific_issue(&candidate) {
                single_lang_suppressed += 1;
                candidate.verdict = Some(VerifierVerdict::ExplainedSafe);
                verified.push(candidate);
                continue;
            }

            // ── FFI Gate: suppress runtime-internal leaks without FFI evidence ──
            let alloc_fn = candidate.alloc_function.clone();
            let caller_is_runtime = candidate
                .alloc_caller
                .as_deref()
                .is_none_or(is_runtime_internal);
            if !candidate.has_ffi_evidence()
                && is_leak_candidate(&candidate)
                && is_runtime_internal(&alloc_fn)
                && caller_is_runtime
            {
                tracing::debug!(
                    "FFI Gate: suppressing runtime-internal leak {} ({:?}) from {}",
                    candidate.id,
                    candidate.kind,
                    alloc_fn
                );
                ffi_gate_suppressed += 1;
                candidate.verdict = Some(VerifierVerdict::Diagnostic);
                verified.push(candidate);
                continue;
            }

            // Check MemoryGraph state first for leak candidates
            let verdict = if let Some(resource_id) = candidate.resource_id {
                if let Some(ref graph) = memory_graph {
                    if let Some(node) = graph.get_node(resource_id) {
                        match node.state {
                            ResourceState::StoredToOwner
                            | ResourceState::StoredToRuntime
                            | ResourceState::EscapedToCaller
                            | ResourceState::EscapedToOutParam
                            | ResourceState::RuntimeManaged => {
                                if is_leak_candidate(&candidate) {
                                    tracing::debug!(
                                        "Resource {} in {:?} state: ExplainedSafe (leak candidate)",
                                        resource_id,
                                        node.state
                                    );
                                    VerifierVerdict::ExplainedSafe
                                } else {
                                    verify_candidate_inner(
                                        &candidate,
                                        &registry,
                                        config.as_ref(),
                                        boundary_ctx.as_ref(),
                                        Some(&evidence_bundle),
                                    )
                                }
                            }
                            _ => {
                                let symbol = candidate
                                    .release_function
                                    .as_deref()
                                    .unwrap_or(&candidate.alloc_function);
                                if let Some(ref resolutions) = srt_resolutions {
                                    if let Some(kinds) = resolutions.get(symbol) {
                                        if kinds.contains(&SemanticKind::StoredToOwner)
                                            || kinds.contains(&SemanticKind::StoredToRuntime)
                                            || kinds.contains(&SemanticKind::RuntimeManagedResource)
                                            || kinds.contains(&SemanticKind::EscapedToCaller)
                                            || kinds.contains(&SemanticKind::EscapedToOutParam)
                                        {
                                            if is_leak_candidate(&candidate) {
                                                tracing::debug!(
                                                    "SRT has suppression for '{}': ExplainedSafe (leak candidate)",
                                                    symbol
                                                );
                                                VerifierVerdict::ExplainedSafe
                                            } else {
                                                verify_candidate_inner(
                                                    &candidate,
                                                    &registry,
                                                    config.as_ref(),
                                                    boundary_ctx.as_ref(),
                                                    Some(&evidence_bundle),
                                                )
                                            }
                                        } else {
                                            verify_candidate_inner(
                                                &candidate,
                                                &registry,
                                                config.as_ref(),
                                                boundary_ctx.as_ref(),
                                                Some(&evidence_bundle),
                                            )
                                        }
                                    } else {
                                        verify_candidate_inner(
                                            &candidate,
                                            &registry,
                                            config.as_ref(),
                                            boundary_ctx.as_ref(),
                                            Some(&evidence_bundle),
                                        )
                                    }
                                } else {
                                    verify_candidate_inner(
                                        &candidate,
                                        &registry,
                                        config.as_ref(),
                                        boundary_ctx.as_ref(),
                                        Some(&evidence_bundle),
                                    )
                                }
                            }
                        }
                    } else {
                        verify_candidate_inner(
                            &candidate,
                            &registry,
                            config.as_ref(),
                            boundary_ctx.as_ref(),
                            Some(&evidence_bundle),
                        )
                    }
                } else {
                    verify_candidate_inner(
                        &candidate,
                        &registry,
                        config.as_ref(),
                        boundary_ctx.as_ref(),
                        Some(&evidence_bundle),
                    )
                }
            } else {
                verify_candidate_inner(
                    &candidate,
                    &registry,
                    config.as_ref(),
                    boundary_ctx.as_ref(),
                    Some(&evidence_bundle),
                )
            };
            candidate.verdict = Some(verdict);

            // Attach a human-readable description based on the verdict.
            if candidate.description.is_none() {
                candidate.description = Some(build_verdict_description(&candidate, verdict));
            }

            // Layer 1: Fast string-based FP suppression
            let func_name = match candidate.kind {
                IssueCandidateKind::NullDereference | IssueCandidateKind::UncheckedFfiReturn => {
                    candidate
                        .alloc_caller
                        .as_deref()
                        .unwrap_or(&candidate.alloc_function)
                }
                _ => candidate
                    .release_function
                    .as_deref()
                    .unwrap_or(&candidate.alloc_function),
            };
            if noise.should_suppress(func_name) {
                noise_suppressed += 1;
                candidate.verdict = Some(VerifierVerdict::ExplainedSafe);
                verified.push(candidate);
                continue;
            }

            // Layer 1b: Runtime-caller FP suppression
            if matches!(
                candidate.kind,
                IssueCandidateKind::DoubleRelease
                    | IssueCandidateKind::UseAfterRelease
                    | IssueCandidateKind::UseAfterFree
            ) {
                // 1b-1: Check caller context
                let caller = candidate
                    .release_caller
                    .as_deref()
                    .or(candidate.alloc_caller.as_deref());
                if let Some(caller_name) = caller {
                    if noise.should_suppress_runtime_caller(caller_name) {
                        noise_suppressed += 1;
                        candidate.verdict = Some(VerifierVerdict::ExplainedSafe);
                        verified.push(candidate);
                        continue;
                    }
                }
                // 1b-2: Check if alloc_function is a C runtime function
                if !candidate.has_ffi_evidence()
                    && is_runtime_allocator_function(&candidate.alloc_function)
                {
                    noise_suppressed += 1;
                    candidate.verdict = Some(VerifierVerdict::ExplainedSafe);
                    verified.push(candidate);
                    continue;
                }
                // 1b-3: If alloc_function is a pure deallocator
                if !candidate.has_ffi_evidence()
                    && is_runtime_deallocator_function(&candidate.alloc_function)
                {
                    let caller = candidate
                        .release_caller
                        .as_deref()
                        .or(candidate.alloc_caller.as_deref());
                    let caller_is_runtime = caller
                        .map(|c| {
                            if user_defined_functions.contains(c) {
                                return false;
                            }
                            noise.should_suppress_runtime_caller(c)
                                || is_runtime_deallocator_function(c)
                        })
                        .unwrap_or(false);
                    if caller_is_runtime {
                        noise_suppressed += 1;
                        candidate.verdict = Some(VerifierVerdict::ExplainedSafe);
                        verified.push(candidate);
                        continue;
                    }
                }
            }

            if candidate.is_reportable() {
                if candidate.kind == IssueCandidateKind::CrossLanguageFree
                    && should_report_as_cross_family(&candidate, &registry)
                {
                    candidate.kind = IssueCandidateKind::CrossFamilyFree;
                    candidate.add_evidence(
                        omniscope_types::Evidence::new(
                            EvidenceKind::CrossLanguageFree,
                            "cross-language boundary is secondary evidence for family mismatch",
                        )
                        .with_confidence(0.9),
                    );
                    candidate.description = Some(build_verdict_description(
                        &candidate,
                        candidate.verdict.unwrap_or(VerifierVerdict::ProbableIssue),
                    ));
                }
                let issue_id = ctx.next_issue_id();
                let mut issue = Issue::new(
                    issue_id,
                    candidate.to_issue_kind(),
                    candidate.severity(),
                    candidate.description.clone().unwrap_or_default(),
                );

                let symbol = candidate
                    .release_function
                    .as_deref()
                    .unwrap_or(&candidate.alloc_function);
                issue = issue.with_symbol(symbol);

                let location_func = match candidate.kind {
                    IssueCandidateKind::NullDereference
                    | IssueCandidateKind::UncheckedFfiReturn => candidate
                        .alloc_caller
                        .as_deref()
                        .unwrap_or(&candidate.alloc_function),
                    _ => &candidate.alloc_function,
                };
                if !location_func.is_empty() && location_func != "unknown" {
                    let location =
                        omniscope_core::IssueLocation::new(std::path::PathBuf::from("<ir>"), 0)
                            .with_function(location_func);
                    issue = issue.with_location(location);
                }

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
        result.add_stat("ffi_gate_suppressed", ffi_gate_suppressed);
        result.add_stat("single_lang_suppressed", single_lang_suppressed);
        result.add_stat("semantic_suppressed", semantic_suppressed);

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
/// - Unknown family policy
#[allow(dead_code)] // used by integration and unit tests, not called from lib code
pub(crate) fn verify_candidate(
    candidate: &IssueCandidate,
    registry: &FamilyRegistry,
    config: Option<&OmniScopeConfig>,
    boundary_ctx: Option<&omniscope_types::boundary::BoundaryContext>,
) -> VerifierVerdict {
    verify_candidate_inner(candidate, registry, config, boundary_ctx, None)
}

/// Inner implementation that accepts an optional evidence bundle.
fn verify_candidate_inner(
    candidate: &IssueCandidate,
    registry: &FamilyRegistry,
    config: Option<&OmniScopeConfig>,
    boundary_ctx: Option<&omniscope_types::boundary::BoundaryContext>,
    bundle: Option<&EvidenceBundle>,
) -> VerifierVerdict {
    // First, check if this is a non-memory resource (e.g., file descriptors).
    if !is_memory_resource(candidate.alloc_family) {
        match candidate.kind {
            IssueCandidateKind::DefiniteLeak | IssueCandidateKind::ConditionalLeak => {
                return VerifierVerdict::ExplainedSafe;
            }
            _ => {}
        }
    }
    match candidate.kind {
        IssueCandidateKind::CrossFamilyFree => {
            if let Some(b) = bundle {
                verify_cross_family_with_bundle(b, registry)
            } else {
                verify_cross_family_free(candidate, registry, config, boundary_ctx)
            }
        }
        IssueCandidateKind::UseAfterRelease => {
            if has_escape_evidence(candidate, EvidenceKind::ReturnToCaller) {
                VerifierVerdict::ProbableIssue
            } else {
                VerifierVerdict::ConfirmedIssue
            }
        }
        IssueCandidateKind::DoubleRelease => {
            if let Some(b) = bundle {
                verify_double_release_with_bundle(b)
            } else {
                verify_double_release(candidate)
            }
        }
        IssueCandidateKind::ConditionalLeak => {
            if let Some(b) = bundle {
                verify_conditional_leak_with_bundle(b)
            } else {
                verify_conditional_leak(candidate)
            }
        }
        IssueCandidateKind::DefiniteLeak => {
            if let Some(b) = bundle {
                verify_definite_leak_with_bundle(b)
            } else {
                verify_definite_leak(candidate)
            }
        }
        IssueCandidateKind::BorrowEscape => verify_borrow_escape(candidate),
        IssueCandidateKind::CallbackEscape => VerifierVerdict::Diagnostic,
        IssueCandidateKind::NeedsModel => VerifierVerdict::Diagnostic,
        IssueCandidateKind::DoubleReclaim => VerifierVerdict::ConfirmedIssue,
        IssueCandidateKind::OwnershipEscapeLeak => VerifierVerdict::ProbableIssue,
        IssueCandidateKind::UseAfterFree => VerifierVerdict::ConfirmedIssue,
        IssueCandidateKind::InvalidBorrowedFree => VerifierVerdict::ConfirmedIssue,
        IssueCandidateKind::UncheckedFfiReturn => VerifierVerdict::ProbableIssue,
        IssueCandidateKind::NullDereference => VerifierVerdict::ConfirmedIssue,
        IssueCandidateKind::CrossLanguageFree => {
            if let Some(b) = bundle {
                verify_cross_family_with_bundle(b, registry)
            } else {
                verify_cross_family_free(candidate, registry, config, boundary_ctx)
            }
        }
    }
}
