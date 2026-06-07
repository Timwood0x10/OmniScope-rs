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
#[allow(unused_imports)]
use omniscope_semantics::resource::memory_graph::{
    family_to_resource_class, MemoryGraph, ResourceClass, ResourceState,
};
use omniscope_semantics::{FamilyRegistry, LanguageDetector, SemanticKind};
use omniscope_types::{
    EvidenceKind, FamilyId, IssueCandidateKind, OmniScopeConfig, VerifierVerdict,
};

use super::structural_inference_pass::is_runtime_internal;
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
        // When IssueCandidateBuilder and LeakDetectionPass both detect the same
        // allocation as leaking, we may get duplicate candidates. Deduplication
        // uses two strategies:
        // 1. resource_id overlap: candidates sharing the same resource_id are
        //    duplicates (same allocation instance). Keep the strongest.
        // 2. alloc_caller overlap: LeakDetectionPass uses runtime function names
        //    (malloc, _Znam) as alloc_function but sets alloc_caller to the user
        //    function. When a runtime candidate's alloc_caller matches a user
        //    candidate's alloc_function (same alloc_family), they refer to the
        //    same allocation. Keep the more precise one (user function name).
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
        // Clone to avoid borrow conflict with mutable ctx operations
        let memory_graph = ctx.get_ref::<MemoryGraph>("memory_graph").cloned();

        // Get SRT resolutions for semantic-based verification
        // Clone to avoid borrow conflict with mutable ctx operations
        let srt_resolutions = ctx
            .get_ref::<std::collections::HashMap<String, Vec<SemanticKind>>>("srt_resolutions")
            .cloned();

        // Layer 1: NoiseReduction — fast string-based FP pre-filter.
        let noise = NoiseReduction::new();

        // ── Single-language shortcut ──
        // If the module has only one language, skip FFI-specific issue types
        // (CrossLanguageFree, UncheckedFfiReturn, NullDereference, etc.)
        // and only keep generic bug types (DoubleRelease, UseAfterFree, etc.)
        let is_single_language = ctx
            .get_ref::<crate::module_index::ModuleIndex>("module_index")
            .map(|idx| idx.is_single_language)
            .unwrap_or(false);

        let mut verified: Vec<IssueCandidate> = Vec::new();
        let mut issues: Vec<Issue> = Vec::new();
        let mut noise_suppressed: usize = 0;
        let mut ffi_gate_suppressed: usize = 0;
        let mut single_lang_suppressed: usize = 0;

        for mut candidate in candidates {
            // ── Single-language filter ──
            // For single-language modules, skip FFI-specific issue types.
            // Only keep generic bug types that don't require cross-language
            // interaction: DoubleRelease, UseAfterFree, UseAfterRelease.
            // Leak types are also kept as they represent real resource bugs.
            if is_single_language && is_ffi_specific_issue(&candidate) {
                single_lang_suppressed += 1;
                candidate.verdict = Some(VerifierVerdict::ExplainedSafe);
                verified.push(candidate);
                continue;
            }

            // ── FFI Gate: suppress runtime-internal leaks without FFI evidence ──
            // Only downgrade leak candidates where BOTH:
            //   1. No FFI evidence attached (not from FFI boundary detection)
            //   2. The alloc function is a known runtime internal
            // This preserves user-code leaks (real bugs) while suppressing
            // allocator/runtime noise. DoubleFree, UseAfterFree etc. always pass.
            let alloc_fn = candidate.alloc_function.clone();
            if !candidate.has_ffi_evidence()
                && is_leak_candidate(&candidate)
                && is_runtime_internal(&alloc_fn)
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
                        // Check if resource is in a managed state
                        // Only suppress leak-type candidates when resource is managed
                        // CrossFamilyFree, UseAfterFree etc. should still be verified
                        match node.state {
                            ResourceState::StoredToOwner
                            | ResourceState::StoredToRuntime
                            | ResourceState::EscapedToCaller
                            | ResourceState::EscapedToOutParam
                            | ResourceState::RuntimeManaged => {
                                // Resource is managed, not a local leak
                                // Only suppress leak-type candidates
                                if is_leak_candidate(&candidate) {
                                    tracing::debug!(
                                        "Resource {} in {:?} state: ExplainedSafe (leak candidate)",
                                        resource_id,
                                        node.state
                                    );
                                    VerifierVerdict::ExplainedSafe
                                } else {
                                    // For non-leak candidates (CrossFamilyFree, UseAfterFree, etc.),
                                    // continue with standard verification
                                    verify_candidate(
                                        &candidate,
                                        &registry,
                                        config.as_ref(),
                                        boundary_ctx.as_ref(),
                                    )
                                }
                            }
                            _ => {
                                // Check SRT resolutions for semantic-based suppression
                                // Only suppress leak-type candidates when SRT has suppression
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
                                            // Only suppress leak-type candidates
                                            if is_leak_candidate(&candidate) {
                                                tracing::debug!(
                                                    "SRT has suppression for '{}': ExplainedSafe (leak candidate)",
                                                    symbol
                                                );
                                                VerifierVerdict::ExplainedSafe
                                            } else {
                                                // For non-leak candidates, continue with standard verification
                                                verify_candidate(
                                                    &candidate,
                                                    &registry,
                                                    config.as_ref(),
                                                    boundary_ctx.as_ref(),
                                                )
                                            }
                                        } else {
                                            verify_candidate(
                                                &candidate,
                                                &registry,
                                                config.as_ref(),
                                                boundary_ctx.as_ref(),
                                            )
                                        }
                                    } else {
                                        verify_candidate(
                                            &candidate,
                                            &registry,
                                            config.as_ref(),
                                            boundary_ctx.as_ref(),
                                        )
                                    }
                                } else {
                                    verify_candidate(
                                        &candidate,
                                        &registry,
                                        config.as_ref(),
                                        boundary_ctx.as_ref(),
                                    )
                                }
                            }
                        }
                    } else {
                        // No node in MemoryGraph, use standard verification
                        verify_candidate(
                            &candidate,
                            &registry,
                            config.as_ref(),
                            boundary_ctx.as_ref(),
                        )
                    }
                } else {
                    // No MemoryGraph available, use standard verification
                    verify_candidate(
                        &candidate,
                        &registry,
                        config.as_ref(),
                        boundary_ctx.as_ref(),
                    )
                }
            } else {
                // No resource_id, use standard verification
                verify_candidate(
                    &candidate,
                    &registry,
                    config.as_ref(),
                    boundary_ctx.as_ref(),
                )
            };
            candidate.verdict = Some(verdict);

            // Attach a human-readable description based on the verdict.
            if candidate.description.is_none() {
                candidate.description = Some(build_verdict_description(&candidate, verdict));
            }

            // Layer 1: Fast string-based FP suppression — skip known
            // safe patterns (compiler intrinsics, allocator internals, etc.)
            // before even reaching the SRT gate.
            // For FfiReturn candidates, check alloc_caller (the enclosing function)
            // instead of alloc_function (the FFI callee).
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

            // Layer 1b: Runtime-caller FP suppression — for generic C functions
            // (free, malloc, etc.) that produce double_free / use_after_free,
            // the function name alone is too generic. Check if the *caller*
            // is a known runtime internal (e.g., Zig mem.Allocator.reallocAdvanced).
            // Only applies to double_free / use_after_free kinds — leak issues
            // from user code must always be reported.
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
                // (free, malloc, munmap, etc.) without FFI evidence.
                // When alloc_function IS a deallocator (free/munmap/_ZdlPv/_ZdaPv),
                // it means the "allocation" was actually a release call — this is
                // a genuine double-free from user code, so only suppress if the
                // caller is also a runtime internal (not user code).
                // When alloc_function is an allocator (malloc/new/etc.), the
                // double-free was detected inside the allocator itself — always FP.
                if !candidate.has_ffi_evidence()
                    && is_runtime_allocator_function(&candidate.alloc_function)
                {
                    noise_suppressed += 1;
                    candidate.verdict = Some(VerifierVerdict::ExplainedSafe);
                    verified.push(candidate);
                    continue;
                }
                // 1b-3: If alloc_function is a pure deallocator (free, munmap, etc.)
                // and the caller is also a runtime internal, suppress as FP.
                // If the caller is user code, it's a genuine double-free.
                // If caller is unknown (None), default to NOT suppressing —
                // it's better to report a potential bug than to hide it.
                if !candidate.has_ffi_evidence()
                    && is_runtime_deallocator_function(&candidate.alloc_function)
                {
                    let caller = candidate
                        .release_caller
                        .as_deref()
                        .or(candidate.alloc_caller.as_deref());
                    let caller_is_runtime = caller
                        .map(|c| {
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
                // For FFI return candidates, use alloc_caller (the enclosing function
                // where the unchecked return occurs). For other candidates, use
                // alloc_function (where the resource was acquired).
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
        result.add_stat("ffi_gate_suppressed", ffi_gate_suppressed);
        result.add_stat("single_lang_suppressed", single_lang_suppressed);

        Ok(result)
    }
}

impl Default for IssueVerifierPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Determines if a resource family represents memory resources.
///
/// HeapMemory and RuntimeManaged families are considered memory-like
/// resources because they require explicit release and can leak.
/// FileDescriptor, Socket, ProcessHandle are OS handle resources that
/// should not be reported as memory leaks.
///
/// # Arguments
/// * `family_id` - The resource family identifier to check.
///
/// # Returns
/// `true` if the family represents memory-like resources, `false` otherwise.
fn is_memory_resource(family_id: FamilyId) -> bool {
    // Map family IDs to their resource classes.
    // HeapMemory and RuntimeManaged are memory-like resources.
    // FileDescriptor, Socket, ProcessHandle are OS handles, not memory.
    matches!(
        family_to_resource_class(family_id),
        ResourceClass::HeapMemory | ResourceClass::RuntimeManaged
    )
}

/// Deduplicate leak candidates that share the same resource_id.
///
/// When IssueCandidateBuilder and LeakDetectionPass both detect the same
/// allocation as leaking, we may get duplicate candidates with the same
/// resource_id. This keeps only the strongest leak type per resource_id:
///   DefiniteLeak > ConditionalLeak > OwnershipEscapeLeak
///
/// Non-leak candidates and candidates without resource_id are never removed.
fn deduplicate_leak_candidates(candidates: &mut Vec<IssueCandidate>) {
    fn leak_priority(kind: &IssueCandidateKind) -> u8 {
        match kind {
            IssueCandidateKind::DefiniteLeak => 3,
            IssueCandidateKind::ConditionalLeak => 2,
            IssueCandidateKind::OwnershipEscapeLeak => 1,
            _ => 0,
        }
    }

    /// Returns true if this candidate's alloc_function is a runtime/allocator
    /// function (malloc, _Znam, etc.) — detected by alloc_caller != alloc_function.
    fn is_runtime_alloc_candidate(candidate: &IssueCandidate) -> bool {
        candidate.alloc_caller.is_some()
            && candidate.alloc_caller.as_deref() != Some(&candidate.alloc_function)
    }

    let mut to_remove: std::collections::HashSet<usize> = std::collections::HashSet::new();

    // ── Strategy 1: resource_id overlap ──
    let mut best_per_rid: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (i, candidate) in candidates.iter().enumerate() {
        if !is_leak_candidate(candidate) {
            continue;
        }
        let Some(rid) = candidate.resource_id else {
            continue;
        };
        let priority = leak_priority(&candidate.kind);
        let entry = best_per_rid.entry(rid).or_insert(i);
        let existing_priority = leak_priority(&candidates[*entry].kind);
        if priority > existing_priority {
            *entry = i;
        }
    }
    for (i, candidate) in candidates.iter().enumerate() {
        if !is_leak_candidate(candidate) {
            continue;
        }
        let Some(rid) = candidate.resource_id else {
            continue;
        };
        if let Some(&best_idx) = best_per_rid.get(&rid) {
            if best_idx != i {
                to_remove.insert(i);
            }
        }
    }

    // ── Strategy 2: alloc_caller overlap ──
    // LeakDetectionPass candidates have alloc_function = runtime function (malloc)
    // and alloc_caller = user function. IssueCandidateBuilder candidates have
    // alloc_function = user function. When a runtime candidate's alloc_caller
    // matches a user candidate's alloc_function (same alloc_family), they refer
    // to the same allocation. Remove the runtime candidate if the user candidate
    // is at least as strong (equal or higher priority).
    let mut user_leak_by_func: std::collections::HashMap<(String, FamilyId), usize> =
        std::collections::HashMap::new();
    for (i, candidate) in candidates.iter().enumerate() {
        if !is_leak_candidate(candidate) || to_remove.contains(&i) {
            continue;
        }
        if is_runtime_alloc_candidate(candidate) {
            continue; // skip runtime candidates for this map
        }
        let key = (candidate.alloc_function.clone(), candidate.alloc_family);
        let priority = leak_priority(&candidate.kind);
        let entry = user_leak_by_func.entry(key).or_insert(i);
        let existing_priority = leak_priority(&candidates[*entry].kind);
        if priority > existing_priority {
            *entry = i;
        }
    }

    // Check runtime candidates against the user map.
    for (i, candidate) in candidates.iter().enumerate() {
        if !is_leak_candidate(candidate) || to_remove.contains(&i) {
            continue;
        }
        if !is_runtime_alloc_candidate(candidate) {
            continue;
        }
        let Some(ref caller) = candidate.alloc_caller else {
            continue;
        };
        let key = (caller.clone(), candidate.alloc_family);
        if let Some(&user_idx) = user_leak_by_func.get(&key) {
            let runtime_priority = leak_priority(&candidate.kind);
            let user_priority = leak_priority(&candidates[user_idx].kind);
            // Remove the runtime candidate if the user candidate is at least as
            // strong. The user candidate has a more precise alloc_function name
            // and is better for issue reporting.
            if runtime_priority <= user_priority {
                tracing::debug!(
                    "Dedup (caller overlap): removing runtime #{} ({:?} in '{}', caller='{}') — keeping user #{} ({:?} in '{}')",
                    i, candidate.kind, candidate.alloc_function, caller,
                    user_idx, candidates[user_idx].kind, candidates[user_idx].alloc_function
                );
                to_remove.insert(i);
            }
        }
    }

    if to_remove.is_empty() {
        return;
    }

    tracing::debug!("Deduplicating {} leak candidates", to_remove.len());

    // Remove in reverse order to preserve indices.
    let mut indices: Vec<usize> = to_remove.into_iter().collect();
    indices.sort();
    for idx in indices.iter().rev() {
        candidates.remove(*idx);
    }
}

/// Checks if a function name is a known C/C runtime allocator.
///
/// These functions (malloc, calloc, new, etc.) are C/C++ standard library
/// allocators. When they appear as the `alloc_function` in a DoubleRelease /
/// UseAfterFree candidate without FFI evidence, it means the double-free was
/// detected *inside* the runtime allocator/deallocator itself — typically a
/// false positive from runtime bookkeeping rather than a user bug.
///
/// Note: Pure deallocators (free, _ZdlPv, _ZdaPv) are NOT listed here
/// because if `alloc_function` is a deallocator (e.g., free→free), it's
/// a genuine double-free bug that should be reported.
/// Checks if a function name is a known C/C++ runtime allocator.
///
/// These functions (malloc, calloc, new, etc.) are C/C++ standard library
/// allocators. When they appear as the `alloc_function` in a DoubleRelease /
/// UseAfterFree candidate without FFI evidence, it means the double-free was
/// detected *inside* the runtime allocator itself — typically a false positive
/// from runtime bookkeeping rather than a user bug.
fn is_runtime_allocator_function(name: &str) -> bool {
    matches!(
        name,
        "malloc" | "calloc" | "realloc" | "mmap"
    ) || name.starts_with("_Znam")   // C++ operator new[]
      || name.starts_with("_Znwm") // C++ operator new
}

/// Checks if a function name is a known C/C++ runtime deallocator.
///
/// Pure deallocators (free, munmap, _ZdlPv, _ZdaPv) when appearing as
/// `alloc_function` indicate a double-release (e.g., free→free).
/// This is only a genuine bug when called from user code; if the caller
/// is also runtime-internal, it's typically a false positive.
fn is_runtime_deallocator_function(name: &str) -> bool {
    matches!(
        name,
        "free" | "munmap" | "__rust_dealloc"
    ) || name.starts_with("_ZdlPv")  // C++ operator delete
      || name.starts_with("_ZdaPv") // C++ operator delete[]
}

/// Checks if a candidate is a leak type issue.
///
/// Leak type issues are those that represent memory leaks or resource leaks.
/// This includes DefiniteLeak, ConditionalLeak, and OwnershipEscapeLeak.
///
/// # Arguments
/// * `candidate` - The issue candidate to check.
///
/// # Returns
/// `true` if the candidate is a leak type issue, `false` otherwise.
fn is_leak_candidate(candidate: &IssueCandidate) -> bool {
    matches!(
        candidate.kind,
        IssueCandidateKind::DefiniteLeak
            | IssueCandidateKind::ConditionalLeak
            | IssueCandidateKind::OwnershipEscapeLeak
    )
}

/// Checks if a candidate is an FFI-specific issue type.
///
/// These issue types only make sense in the context of cross-language
/// FFI interaction. In single-language modules, they are suppressed:
/// - `CrossLanguageFree` — only occurs across language boundaries
/// - `UncheckedFfiReturn` — only occurs at FFI call sites
/// - `NullDereference` — only occurs from unchecked FFI returns
/// - `CallbackEscape` — only occurs across FFI callback boundaries
/// - `BorrowEscape` — only meaningful across FFI boundaries
/// - `CrossFamilyFree` — typically a cross-language family mismatch
///
/// Generic bug types that apply to any language are NOT FFI-specific:
/// - `DoubleRelease`, `UseAfterFree`, `UseAfterRelease` — real bugs in any context
/// - `DefiniteLeak`, `ConditionalLeak` — real resource leaks in any context
fn is_ffi_specific_issue(candidate: &IssueCandidate) -> bool {
    matches!(
        candidate.kind,
        IssueCandidateKind::CrossLanguageFree
            | IssueCandidateKind::UncheckedFfiReturn
            | IssueCandidateKind::NullDereference
            | IssueCandidateKind::CallbackEscape
            | IssueCandidateKind::BorrowEscape
    )
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
///
/// # Arguments
/// * `candidate` - The issue candidate to verify.
/// * `registry` - Family registry for compatible-release checks.
/// * `config` - Optional configuration for other checks.
/// * `boundary_ctx` - Optional boundary context for FFI boundary verification.
fn verify_candidate(
    candidate: &IssueCandidate,
    registry: &FamilyRegistry,
    config: Option<&OmniScopeConfig>,
    boundary_ctx: Option<&omniscope_types::boundary::BoundaryContext>,
) -> VerifierVerdict {
    // First, check if this is a non-memory resource (e.g., file descriptors).
    // Non-memory resources should not be reported as memory leaks.
    if !is_memory_resource(candidate.alloc_family) {
        // For non-memory resources, only allow cross-family-free and use-after-release
        // issues. Leak issues (DefiniteLeak, ConditionalLeak) should be suppressed.
        match candidate.kind {
            IssueCandidateKind::DefiniteLeak | IssueCandidateKind::ConditionalLeak => {
                return VerifierVerdict::ExplainedSafe;
            }
            _ => {} // Other issue types may still be relevant
        }
    }
    match candidate.kind {
        IssueCandidateKind::CrossFamilyFree => {
            verify_cross_family_free(candidate, registry, config, boundary_ctx)
        }
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
        IssueCandidateKind::DoubleRelease => verify_double_release(candidate),
        IssueCandidateKind::ConditionalLeak => verify_conditional_leak(candidate),
        IssueCandidateKind::DefiniteLeak => verify_definite_leak(candidate),
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
        IssueCandidateKind::InvalidBorrowedFree => {
            // Invalid free of a borrowed pointer is always a real issue.
            // Borrowed pointers should not be freed by the borrower.
            VerifierVerdict::ConfirmedIssue
        }
        IssueCandidateKind::UncheckedFfiReturn => {
            // Unchecked FFI return value — potential null dereference.
            // This is a real issue if the FFI function can return null.
            VerifierVerdict::ProbableIssue
        }
        IssueCandidateKind::NullDereference => {
            // Null pointer dereference — always a real issue.
            VerifierVerdict::ConfirmedIssue
        }
        IssueCandidateKind::CrossLanguageFree => {
            // Cross-language free is similar to cross-family free
            // but across language boundaries. Usually a real issue.
            verify_cross_family_free(candidate, registry, config, boundary_ctx)
        }
    }
}

/// Verifies a cross-family free candidate.
///
/// Uses BoundaryContext for FFI boundary verification when available,
/// falling back to config for other checks.
fn verify_cross_family_free(
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
    // If the function is in a known FFI boundary, it's likely a real issue
    // because cross-family free across language boundaries is dangerous.
    let release_func = candidate.release_function.as_deref().unwrap_or("");

    // Use BoundaryContext for boundary checking if available
    if let Some(boundary_ctx) = boundary_ctx {
        // Check exact function name and pattern matches
        if let Some((from, to)) = boundary_ctx.is_declared_boundary(release_func) {
            // This is a known FFI boundary function. The cross-family free
            // across language boundaries is almost always a real issue.
            tracing::debug!(
                "Cross-family free in FFI boundary function '{}' ({:?} -> {:?})",
                release_func,
                from,
                to
            );
            return VerifierVerdict::ConfirmedIssue;
        }

        // Check language pair matching when functions list is empty.
        // Use release_caller for caller language detection — this is where
        // the release call happens, which is the correct semantic for
        // cross-language detection (release_caller in language X calls
        // release_function in language Y).
        let detector = LanguageDetector::new();
        let caller_lang =
            detector.detect_from_function(candidate.release_caller.as_deref().unwrap_or(""));
        let release_lang = detector.detect_from_function(release_func);

        if boundary_ctx.matches_call(caller_lang, release_lang) {
            // This is a known FFI boundary function via language detection.
            tracing::debug!(
                "Cross-family free in FFI boundary function '{}' via language detection ({:?} -> {:?})",
                release_func,
                caller_lang,
                release_lang
            );
            return VerifierVerdict::ConfirmedIssue;
        }
    } else if let Some(config) = config {
        // Fallback to config if BoundaryContext is not available
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

/// Verifies a double release candidate.
///
/// Checks if the double release is safe based on evidence:
/// - Null-guarded release functions (release(NULL) is safe)
/// - NULL stored after release (prevents dangling pointer)
/// - Path state refinement (control flow analysis)
/// - Multiple free calls in different callers (not same-instance double-free)
fn verify_double_release(candidate: &IssueCandidate) -> VerifierVerdict {
    let has_null_guard = has_evidence(candidate, EvidenceKind::NullGuardedRelease);
    let has_null_store = has_evidence(candidate, EvidenceKind::NullStoreAfterRelease);
    let has_path_refinement = has_evidence(candidate, EvidenceKind::PathStateRefinement);

    // All three: fully analyzed null-guarded pattern → safe.
    // This means we know: (1) the release function guards against null,
    // (2) the pointer was set to NULL after the first release, and
    // (3) path analysis confirmed the second release only fires when
    // the pointer is NULL. All conditions met → safe.
    if has_null_guard && has_null_store && has_path_refinement {
        return VerifierVerdict::ExplainedSafe;
    }

    // Null-guarded release in different callers: if the alloc and release
    // happen in different enclosing functions, the releases are from
    // separate call sites (e.g., error paths in different callers) —
    // not a same-pointer double-free.
    if has_null_guard {
        if let (Some(ref alloc_caller), Some(ref release_caller)) = (
            candidate.alloc_caller.as_ref(),
            candidate.release_caller.as_ref(),
        ) {
            if alloc_caller != release_caller {
                return VerifierVerdict::ExplainedSafe;
            }
        }
    }

    // Null-guard alone does NOT make double-free safe.
    // `free(NULL)` is safe, but `free(ptr); free(ptr)` with non-null
    // ptr is undefined behavior (CWE-415). Without path analysis
    // proving the pointer is null at the second release, this is
    // still a confirmed issue.
    //
    // Note: we intentionally skip the old "null_guard only → Diagnostic"
    // path because it incorrectly suppressed real double-frees where
    // the release function happens to be null-guarded (e.g., `free`).

    // Default: double-free is a confirmed issue
    VerifierVerdict::ConfirmedIssue
}

/// Verifies a definite leak candidate (all analyzed paths leak).
fn verify_definite_leak(candidate: &IssueCandidate) -> VerifierVerdict {
    // OwnershipEscapeLeak: into_raw without from_raw — the raw pointer
    // was explicitly leaked across the FFI boundary.
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

    // Resource returned via out-param on success — caller owns it.
    if has_evidence(candidate, EvidenceKind::OutParamOwnedOnSuccess) {
        return VerifierVerdict::ExplainedSafe;
    }

    // Out-param set to NULL on error — no dangling pointer on error path.
    if has_evidence(candidate, EvidenceKind::OutParamNullOnError) {
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

    // Check if we have path state refinement
    if has_evidence(candidate, EvidenceKind::PathStateRefinement) {
        // We've analyzed the control flow, but still a conditional leak
        // This is more confident than without path analysis
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
        IssueCandidateKind::CrossLanguageFree => "cross-language free",
        IssueCandidateKind::UseAfterRelease => "use after release",
        IssueCandidateKind::DoubleRelease => "double release",
        IssueCandidateKind::ConditionalLeak => "conditional leak",
        IssueCandidateKind::DefiniteLeak => "definite leak",
        IssueCandidateKind::BorrowEscape => "borrow escape",
        IssueCandidateKind::CallbackEscape => "callback escape",
        IssueCandidateKind::NeedsModel => "needs model",
        IssueCandidateKind::DoubleReclaim => "double reclaim",
        IssueCandidateKind::OwnershipEscapeLeak => "ownership escape leak",
        IssueCandidateKind::UseAfterFree => "use-after-free",
        IssueCandidateKind::InvalidBorrowedFree => "invalid borrowed free",
        IssueCandidateKind::UncheckedFfiReturn => "unchecked FFI return",
        IssueCandidateKind::NullDereference => "null dereference",
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
        IssueCandidateKind::DefiniteLeak => {
            format!(
                "{kind_label}: resource from '{}' ({:?}) has no release on any analyzed path [{verdict_label}]",
                candidate.alloc_function, candidate.alloc_family
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
        IssueCandidateKind::InvalidBorrowedFree => {
            format!(
                "{kind_label}: borrowed pointer in '{}' passed to release function [{verdict_label}]",
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
            vec!["IssueCandidateBuilder", "FfiReturnCheck", "LeakDetection"],
            "Dependencies should be IssueCandidateBuilder, FfiReturnCheck, and LeakDetection"
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

        let verdict = verify_candidate(&candidate, &registry, None, None);
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

        let verdict = verify_candidate(&candidate, &registry, None, None);
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

        let verdict = verify_candidate(&candidate, &registry, None, None);
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

        let verdict = verify_candidate(&candidate, &registry, None, None);
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

        let verdict = verify_candidate(&candidate, &registry, None, None);
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

        let verdict = verify_candidate(&candidate, &registry, None, None);
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

        let verdict = verify_candidate(&candidate, &registry, None, None);
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

        let verdict = verify_candidate(&candidate, &registry, None, None);
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

        let verdict = verify_candidate(&candidate, &registry, None, None);
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

        let verdict = verify_candidate(&candidate, &registry, None, None);
        assert_eq!(
            verdict,
            VerifierVerdict::ProbableIssue,
            "Unknown release family should be probable issue"
        );
    }

    #[test]
    fn test_verify_definite_leak_without_escape_is_confirmed() {
        let registry = FamilyRegistry::new();
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::C_HEAP,
            "malloc",
        );

        let verdict = verify_candidate(&candidate, &registry, None, None);
        assert_eq!(
            verdict,
            VerifierVerdict::ConfirmedIssue,
            "Definite leak without valid escape must be confirmed issue"
        );
    }

    #[test]
    fn test_verify_definite_leak_with_ownership_escape_is_confirmed() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::C_HEAP,
            "into_raw_wrapper",
        );
        candidate.add_evidence(
            Evidence::new(
                EvidenceKind::OwnershipEscapeLeak,
                "Box::into_raw without matching from_raw",
            )
            .with_confidence(0.95),
        );

        let verdict = verify_candidate(&candidate, &registry, None, None);
        assert_eq!(
            verdict,
            VerifierVerdict::ConfirmedIssue,
            "Definite leak with OwnershipEscapeLeak evidence must still be confirmed"
        );
    }

    #[test]
    fn test_verdict_description_definite_leak() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::C_HEAP,
            "malloc",
        );

        let desc = build_verdict_description(&candidate, VerifierVerdict::ConfirmedIssue);
        assert!(
            desc.contains("definite leak"),
            "Description must mention definite leak"
        );
        assert!(
            desc.contains("no release on any analyzed path"),
            "Description must mention no release on any analyzed path"
        );
    }

    #[test]
    fn test_verdict_description_conditional_leak() {
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::C_HEAP,
            "malloc",
        );

        let desc = build_verdict_description(&candidate, VerifierVerdict::ProbableIssue);
        assert!(
            desc.contains("conditional leak"),
            "Description must mention conditional leak"
        );
        assert!(
            desc.contains("may not be freed on all paths"),
            "Description must mention partial release coverage"
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

    /// Objective: Verify that null-guard alone does NOT suppress double-free.
    /// Invariants: Double-free is confirmed even when release function is
    /// null-guarded, because `free(ptr); free(ptr)` with non-null ptr is UB.
    /// Only when path analysis proves the pointer is null at the second release
    /// (via NullStoreAfterRelease + PathStateRefinement) can we suppress.
    #[test]
    fn test_verify_double_release_with_null_guard_evidence() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::DoubleRelease,
            FamilyId::C_HEAP,
            "free",
        );

        // Add null-guarded release evidence only (no path analysis)
        candidate.add_evidence(
            Evidence::new(EvidenceKind::NullGuardedRelease, "free(NULL) is safe in C")
                .with_confidence(0.9),
        );

        let verdict = verify_candidate(&candidate, &registry, None, None);
        assert_eq!(
            verdict,
            VerifierVerdict::ConfirmedIssue,
            "Null-guarded release without path analysis should still be confirmed issue — \
             double-free on non-null pointer is UB regardless of null-guard"
        );
    }

    #[test]
    fn test_verify_double_release_with_all_evidence() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::DoubleRelease,
            FamilyId::C_HEAP,
            "free",
        );

        // Add all required evidence for safe pattern
        candidate.add_evidence(
            Evidence::new(EvidenceKind::NullGuardedRelease, "free(NULL) is safe in C")
                .with_confidence(0.9),
        );
        candidate.add_evidence(
            Evidence::new(
                EvidenceKind::NullStoreAfterRelease,
                "NULL stored after release",
            )
            .with_confidence(0.8),
        );
        candidate.add_evidence(
            Evidence::new(EvidenceKind::PathStateRefinement, "control flow analyzed")
                .with_confidence(0.85),
        );

        let verdict = verify_candidate(&candidate, &registry, None, None);
        assert_eq!(
            verdict,
            VerifierVerdict::ExplainedSafe,
            "Double release with null guard, null store, and path refinement should be explained safe"
        );
    }

    #[test]
    fn test_verify_double_release_without_evidence() {
        let registry = FamilyRegistry::new();
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::DoubleRelease,
            FamilyId::C_HEAP,
            "free",
        );

        let verdict = verify_candidate(&candidate, &registry, None, None);
        assert_eq!(
            verdict,
            VerifierVerdict::ConfirmedIssue,
            "Double release without evidence should be confirmed issue"
        );
    }

    #[test]
    fn test_verify_definite_leak_with_out_param_evidence() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::C_HEAP,
            "malloc",
        );

        // Add out-param evidence
        candidate.add_evidence(
            Evidence::new(
                EvidenceKind::OutParamOwnedOnSuccess,
                "resource returned via out-param on success",
            )
            .with_confidence(0.9),
        );

        let verdict = verify_candidate(&candidate, &registry, None, None);
        assert_eq!(
            verdict,
            VerifierVerdict::ExplainedSafe,
            "Definite leak with out-param escape should be explained safe"
        );
    }

    #[test]
    fn test_verify_definite_leak_with_return_evidence() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::DefiniteLeak,
            FamilyId::C_HEAP,
            "malloc",
        );

        // Add return-to-caller evidence
        candidate.add_evidence(
            Evidence::new(EvidenceKind::ReturnToCaller, "resource returned to caller")
                .with_confidence(0.95),
        );

        let verdict = verify_candidate(&candidate, &registry, None, None);
        assert_eq!(
            verdict,
            VerifierVerdict::ExplainedSafe,
            "Definite leak with return escape should be explained safe"
        );
    }

    #[test]
    fn test_verify_conditional_leak_with_out_param_on_success() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::C_HEAP,
            "malloc",
        );

        // Add out-param on success evidence
        candidate.add_evidence(
            Evidence::new(
                EvidenceKind::OutParamOwnedOnSuccess,
                "resource returned via out-param on success",
            )
            .with_confidence(0.9),
        );

        let verdict = verify_candidate(&candidate, &registry, None, None);
        assert_eq!(
            verdict,
            VerifierVerdict::ExplainedSafe,
            "Conditional leak with out-param on success should be explained safe"
        );
    }

    #[test]
    fn test_verify_conditional_leak_with_out_param_null_on_error() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::C_HEAP,
            "malloc",
        );

        // Add out-param null on error evidence
        candidate.add_evidence(
            Evidence::new(
                EvidenceKind::OutParamNullOnError,
                "out-param set to NULL on error path",
            )
            .with_confidence(0.9),
        );

        let verdict = verify_candidate(&candidate, &registry, None, None);
        assert_eq!(
            verdict,
            VerifierVerdict::ExplainedSafe,
            "Conditional leak with out-param null on error should be explained safe"
        );
    }

    #[test]
    fn test_verify_conditional_leak_with_path_refinement() {
        let registry = FamilyRegistry::new();
        let mut candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::C_HEAP,
            "malloc",
        );

        // Add path state refinement evidence
        candidate.add_evidence(
            Evidence::new(EvidenceKind::PathStateRefinement, "control flow analyzed")
                .with_confidence(0.85),
        );

        let verdict = verify_candidate(&candidate, &registry, None, None);
        assert_eq!(
            verdict,
            VerifierVerdict::ProbableIssue,
            "Conditional leak with path refinement should be probable issue"
        );
    }
}
