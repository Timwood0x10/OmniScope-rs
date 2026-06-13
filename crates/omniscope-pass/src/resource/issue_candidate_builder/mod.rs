//! Issue candidate builder pass for resource contract analysis.
//!
//! Builds `IssueCandidate` entries from the contract graph and
//! ownership states. Candidates are NOT reportable issues — they
//! must pass through the `IssueVerifier` first.
//!
//! # Candidate Generation Strategy
//!
//! 1. **CrossFamilyFree** — For each acquire→release pair where the
//!    alloc family and release family are not compatible (checked
//!    via `FamilyRegistry::is_compatible_release`).
//! 2. **DoubleRelease** — For each resource instance that has more
//!    than one release edge targeting it.
//! 3. **ConditionalLeak** — For each resource instance in the
//!    `Acquired`/`Retained`/`Unknown` ownership state (never released
//!    or escaped).
//! 4. **BorrowEscape** — For each instance with a `Borrowed` contract
//!    that has an escape edge (excluding bridge helpers).
//! 5. **UseAfterFree** — For each instance in `Released` state that
//!    has a subsequent use edge (e.g. EscapesToCallback). Distinct
//!    from BorrowEscape: the resource was explicitly freed before use.

mod grouping;
mod helpers;
mod pattern_candidates;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_dual_evidence;

use omniscope_core::issue_candidate::FfiEvidence;
use omniscope_core::{IssueCandidate, Result};
use omniscope_semantics::resource::allocator_shim::AllocatorShimDetector;
use omniscope_semantics::{
    FamilyRegistry, LanguageDetector, OwnershipState, ResourceInstance, SemanticFact,
};
use omniscope_types::{
    BoundaryContext, BoundaryDetectionMethod, CrossBoundaryEvidence, Effect, Evidence,
    EvidenceKind, FamilyId, IssueCandidateKind, PointerContract,
};

use crate::analysis::ffi_boundary_detector::is_allocator_thunk;
use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::contract_graph_builder::ContractGraph;
use crate::resource::may_alias::{may_alias, MayAliasResult};
use grouping::InstanceEdgeGroups;
// Import helper functions from helpers module
use helpers::{
    build_free_site_for_edge, collect_boundary_from_edges, edge_has_boundary_evidence,
    fact_to_evidence, has_null_store_pattern, is_null_guarded_release, is_pure_deallocator,
    should_suppress_leak_for_allocator_escape,
};
// Re-export public API
pub use helpers::build_cross_family_candidate;
pub use helpers::is_thin_wrapper_function;

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

        let mut candidates: Vec<IssueCandidate> = Vec::new();
        let mut next_id: u64 = 1;

        // Load the contract graph and ownership states from context.
        // Use get_ref to avoid cloning large collections.
        let graph = ctx.get_ref::<ContractGraph>("contract_graph");
        let ownership_states = ctx.get_ref::<Vec<ResourceInstance>>("ownership_states");
        let ir_module = ctx.get_ir_module();
        let registry = ctx
            .get_ref::<FamilyRegistry>("family_registry")
            .cloned()
            .unwrap_or_default();

        // Load boundary context for FFI boundary detection.
        let boundary_ctx = ctx.get_ref::<BoundaryContext>("boundary_context").cloned();
        let detector = LanguageDetector::new();

        // Load semantic facts from IR behavior summary pass (Phase 3).
        // Build a function-name → facts index for O(1) lookup per candidate.
        // Facts are keyed by SemanticKey::Symbol(func_name), not Resource IDs,
        // because the fact emitter operates on function behavior, not resource
        // instances. Matching by alloc_function or alloc_caller name connects
        // the fact to candidates that involve the same function.
        let semantic_facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap_or_default();
        let fact_index: std::collections::HashMap<String, Vec<&SemanticFact>> = {
            let mut idx: std::collections::HashMap<String, Vec<&SemanticFact>> =
                std::collections::HashMap::new();
            for fact in &semantic_facts {
                if let Some(func_name) = fact.key.as_symbol() {
                    idx.entry(func_name.to_string()).or_default().push(fact);
                }
            }
            idx
        };

        if let Some(graph) = graph {
            // Build index-based edge groups (zero-clone).
            let groups = InstanceEdgeGroups::new(graph);

            // Pre-build an ownership state index for O(1) lookup by instance ID.
            // This replaces the repeated O(n) `.iter().find()` calls.
            let state_index: std::collections::HashMap<u64, usize> = ownership_states
                .map(|states| states.iter().enumerate().map(|(i, s)| (s.id, i)).collect())
                .unwrap_or_default();

            // ── Single-pass candidate detection over each instance group ──
            for instance_id in groups.instance_ids() {
                let edge_indices = groups.edges_of(*instance_id);

                // Classify edges in one pass, collecting indices by effect kind.
                let mut acquire_indices: Vec<usize> = Vec::new();
                let mut release_indices: Vec<usize> = Vec::new();
                let mut escape_callback_indices: Vec<usize> = Vec::new();
                let mut ownership_escape_indices: Vec<usize> = Vec::new();
                let mut ownership_reclaim_indices: Vec<usize> = Vec::new();
                let mut returns_borrowed_indices: Vec<usize> = Vec::new();
                let mut other_use_indices: Vec<usize> = Vec::new();

                for &idx in edge_indices {
                    match graph.edges[idx].effect {
                        Effect::Acquire { .. } => acquire_indices.push(idx),
                        Effect::Release { .. } | Effect::ConditionalRelease { .. } => {
                            release_indices.push(idx)
                        }
                        Effect::CrossLanguageFree { .. } => {
                            // CrossLanguageFree is a release with cross-language mismatch
                            release_indices.push(idx);
                        }
                        Effect::EscapesToCallback { .. } => escape_callback_indices.push(idx),
                        Effect::OwnershipEscape { .. } => ownership_escape_indices.push(idx),
                        Effect::OwnershipReclaim { .. } => ownership_reclaim_indices.push(idx),
                        Effect::ReturnsBorrowed => returns_borrowed_indices.push(idx),
                        _ => other_use_indices.push(idx),
                    }
                }

                // ── CrossFamilyFree ──
                for &ai in &acquire_indices {
                    let alloc_family = graph.edges[ai].family.unwrap_or(FamilyId::C_HEAP);
                    let alloc_func = graph.edges[ai].function_name.as_str();

                    for &ri in &release_indices {
                        let release_family = graph.edges[ri].family.unwrap_or(FamilyId::C_HEAP);
                        let release_func = graph.edges[ri].function_name.as_str();

                        // Check if this is a CrossLanguageFree edge
                        let is_cross_language =
                            matches!(graph.edges[ri].effect, Effect::CrossLanguageFree { .. });

                        if registry.is_compatible_release(alloc_family, release_family) {
                            continue;
                        }

                        let id = next_id;
                        next_id += 1;

                        if is_cross_language {
                            // Cross-language free: stronger signal
                            let mut candidate = IssueCandidate::new(
                                id,
                                IssueCandidateKind::CrossFamilyFree,
                                alloc_family,
                                alloc_func,
                            )
                            .with_release_family(release_family)
                            .with_release_function(release_func)
                            .with_resource_id(*instance_id)
                            .with_alloc_caller(&graph.edges[ai].caller_name)
                            .with_release_caller(&graph.edges[ri].caller_name)
                            .with_description(format!(
                                "cross-language free: {} ({:?}) released by {} ({:?})",
                                alloc_func, alloc_family, release_func, release_family
                            ));
                            candidate.add_evidence(
                                Evidence::new(
                                    EvidenceKind::CrossLanguageFree,
                                    format!(
                                        "resource allocated in {:?} family freed in {:?} family",
                                        alloc_family, release_family
                                    ),
                                )
                                .with_confidence(0.9),
                            );

                            // Check boundary context for cross-boundary evidence
                            let boundary_evidence = if let Some(ref ctx) = boundary_ctx {
                                // Check explicit function match
                                if let Some((from, to)) = ctx.is_declared_boundary(release_func) {
                                    Some(CrossBoundaryEvidence {
                                        from,
                                        to,
                                        detection_method: BoundaryDetectionMethod::ExplicitFunction,
                                    })
                                }
                                // Check pattern match
                                else if let Some(edge) = ctx.declared_edges().iter().find(|e| {
                                    if let Some(ref pattern) = e.pattern {
                                        omniscope_types::matches_pattern(release_func, pattern)
                                    } else {
                                        false
                                    }
                                }) {
                                    Some(CrossBoundaryEvidence {
                                        from: edge.from,
                                        to: edge.to,
                                        detection_method: BoundaryDetectionMethod::PatternMatch,
                                    })
                                }
                                // Check language pair match.
                                // Use release_caller for caller language — this is where the
                                // release call happens, which is the correct semantic for
                                // cross-language detection (release_caller in language X calls
                                // release_function in language Y).
                                else {
                                    let caller_lang =
                                        detector.detect_from_function(&graph.edges[ri].caller_name);
                                    let callee_lang = detector.detect_from_function(release_func);
                                    if ctx.matches_call(caller_lang, callee_lang) {
                                        Some(CrossBoundaryEvidence {
                                            from: caller_lang,
                                            to: callee_lang,
                                            detection_method:
                                                BoundaryDetectionMethod::LanguagePairMatch,
                                        })
                                    } else {
                                        None
                                    }
                                }
                            } else {
                                None
                            };

                            if let Some(ref boundary) = boundary_evidence {
                                candidate = candidate.with_boundary(boundary.clone());
                            }

                            // Dual-evidence gating (§7.5.3): FFI evidence is set
                            // only when boundary evidence exists. Without boundary
                            // evidence, this is a resource mismatch, not FFI.
                            //
                            // Boundary evidence sources (in priority order):
                            // 1. BoundaryContext (user-configured boundaries)
                            // 2. ContractEdge.boundary_evidence (from boundary_seeds)
                            let has_boundary = boundary_evidence.is_some()
                                || edge_has_boundary_evidence(&graph.edges[ai])
                                || edge_has_boundary_evidence(&graph.edges[ri]);

                            if has_boundary {
                                let caller_lang =
                                    detector.detect_from_function(&graph.edges[ri].caller_name);
                                let callee_lang = detector.detect_from_function(release_func);
                                candidate =
                                    candidate.with_ffi_evidence(FfiEvidence::CrossLanguageCall {
                                        caller_lang: format!("{:?}", caller_lang),
                                        callee_lang: format!("{:?}", callee_lang),
                                    });

                                // Also set boundary from edge evidence if BoundaryContext
                                // did not provide one
                                if candidate.boundary.is_none() {
                                    if let Some(be) = collect_boundary_from_edges(
                                        &graph.edges[ai],
                                        &graph.edges[ri],
                                    ) {
                                        candidate = candidate.with_boundary(be);
                                    }
                                }
                            }

                            // ── FFI Bridge Layer suppression ──
                            // When the release_caller is an allocator thunk (e.g.,
                            // free_sensitive_cstr, vtable_free, mi_free_bytes), the
                            // cross-language free IS the intended behavior — this
                            // function's job is to bridge allocation between
                            // language boundaries. Suppress as FP.
                            let release_caller_name = graph.edges[ri].caller_name.as_str();
                            let alloc_caller_name = graph.edges[ai].caller_name.as_str();
                            if is_allocator_thunk(release_caller_name, ir_module)
                                || is_allocator_thunk(alloc_caller_name, ir_module)
                            {
                                tracing::debug!(
                                    "[FP-SUPPRESS] CrossLanguageFree suppressed: \
                                     alloc_caller={} release_caller={} is allocator thunk",
                                    alloc_caller_name,
                                    release_caller_name
                                );
                                continue;
                            }

                            candidates.push(candidate);
                        } else {
                            // Regular cross-family free
                            let mut candidate = IssueCandidate::new(
                                id,
                                IssueCandidateKind::CrossFamilyFree,
                                alloc_family,
                                alloc_func,
                            )
                            .with_release_family(release_family)
                            .with_release_function(release_func)
                            .with_resource_id(*instance_id)
                            .with_alloc_caller(&graph.edges[ai].caller_name)
                            .with_release_caller(&graph.edges[ri].caller_name)
                            .with_description(format!(
                                "cross-family release: {} ({:?}) released by {} ({:?})",
                                alloc_func, alloc_family, release_func, release_family
                            ));

                            // Check boundary context for cross-boundary evidence
                            let boundary_evidence = if let Some(ref ctx) = boundary_ctx {
                                // Check explicit function match
                                if let Some((from, to)) = ctx.is_declared_boundary(release_func) {
                                    Some(CrossBoundaryEvidence {
                                        from,
                                        to,
                                        detection_method: BoundaryDetectionMethod::ExplicitFunction,
                                    })
                                }
                                // Check pattern match
                                else if let Some(edge) = ctx.declared_edges().iter().find(|e| {
                                    if let Some(ref pattern) = e.pattern {
                                        omniscope_types::matches_pattern(release_func, pattern)
                                    } else {
                                        false
                                    }
                                }) {
                                    Some(CrossBoundaryEvidence {
                                        from: edge.from,
                                        to: edge.to,
                                        detection_method: BoundaryDetectionMethod::PatternMatch,
                                    })
                                }
                                // Check language pair match.
                                // Use release_caller for caller language — this is where the
                                // release call happens, which is the correct semantic for
                                // cross-language detection (release_caller in language X calls
                                // release_function in language Y).
                                else {
                                    let caller_lang =
                                        detector.detect_from_function(&graph.edges[ri].caller_name);
                                    let callee_lang = detector.detect_from_function(release_func);
                                    if ctx.matches_call(caller_lang, callee_lang) {
                                        Some(CrossBoundaryEvidence {
                                            from: caller_lang,
                                            to: callee_lang,
                                            detection_method:
                                                BoundaryDetectionMethod::LanguagePairMatch,
                                        })
                                    } else {
                                        None
                                    }
                                }
                            } else {
                                None
                            };

                            if let Some(ref boundary) = boundary_evidence {
                                candidate = candidate.with_boundary(boundary.clone());
                            }

                            // Dual-evidence gating (§7.5.3): FFI evidence requires
                            // both boundary evidence AND resource evidence.
                            // Cross-family is resource evidence; we need boundary.
                            let has_boundary = boundary_evidence.is_some()
                                || edge_has_boundary_evidence(&graph.edges[ai])
                                || edge_has_boundary_evidence(&graph.edges[ri]);

                            if has_boundary {
                                candidate =
                                    candidate.with_ffi_evidence(FfiEvidence::CrossFamilyRelease {
                                        alloc_family: format!("{:?}", alloc_family),
                                        release_family: format!("{:?}", release_family),
                                    });

                                // Also set boundary from edge evidence if BoundaryContext
                                // did not provide one
                                if candidate.boundary.is_none() {
                                    if let Some(be) = collect_boundary_from_edges(
                                        &graph.edges[ai],
                                        &graph.edges[ri],
                                    ) {
                                        candidate = candidate.with_boundary(be);
                                    }
                                }
                            }

                            // ── FFI Bridge Layer suppression (regular cross-family) ──
                            let reg_release_caller = graph.edges[ri].caller_name.as_str();
                            let reg_alloc_caller = graph.edges[ai].caller_name.as_str();
                            if is_allocator_thunk(reg_release_caller, ir_module)
                                || is_allocator_thunk(reg_alloc_caller, ir_module)
                            {
                                tracing::debug!(
                                    "[FP-SUPPRESS] CrossFamilyFree suppressed: \
                                     alloc_caller={} release_caller={} is allocator thunk",
                                    reg_alloc_caller,
                                    reg_release_caller
                                );
                                continue;
                            }

                            candidates.push(candidate);
                        }
                    }
                }

                // ── DoubleRelease: multiple release edges ──
                // Create N-1 candidates (one per release beyond the first),
                // each with MultipleRelease evidence. PathStateRefinement
                // must come from MemoryGraph proof in the verifier, not from
                // "all releases are null-guarded" heuristic.
                if release_indices.len() > 1 {
                    let all_null_guarded = release_indices
                        .iter()
                        .all(|&ri| is_null_guarded_release(&graph.edges[ri].function_name));

                    // ── Caller-consistency filter for DoubleRelease candidates ──
                    //
                    // When the alloc_function is a pure deallocator (free, munmap,
                    // __rust_dealloc, etc.), multiple release edges in the same
                    // instance often result from the contract graph merging
                    // unrelated `free(p)` calls from different functions into one
                    // instance. This produces false-positive DoubleFree reports
                    // like "double release in 'free'".
                    //
                    // A genuine double-free from user code (e.g., `free(p); free(p)`
                    // in the same function) has all release edges sharing the same
                    // caller_name. Contract-graph-merged FP edges have different
                    // caller_names. So when alloc_function is a deallocator, we
                    // only create DoubleRelease candidates for edges whose
                    // caller_name matches the first release edge's caller_name.
                    let first_caller = &graph.edges[release_indices[0]].caller_name;
                    let alloc_is_deallocator =
                        is_pure_deallocator(&graph.edges[release_indices[0]].function_name);

                    for &ri in release_indices.iter().skip(1) {
                        // Skip candidate if alloc is a deallocator and callers differ
                        if alloc_is_deallocator && graph.edges[ri].caller_name != *first_caller {
                            tracing::debug!(
                                "[DR-FILTER] instance={} skipped: dealloc caller {} != first caller {}",
                                instance_id, graph.edges[ri].caller_name, first_caller
                            );
                            continue;
                        }

                        tracing::debug!(
                            "[DR-CREATE] instance={} alloc_fn={} caller={} first_caller={}",
                            instance_id,
                            graph.edges[ri].function_name,
                            graph.edges[ri].caller_name,
                            first_caller
                        );

                        // ── May-alias gate ──
                        // Build a FreeSite for both the first and the i-th release
                        // edge and run the alias check. The result is recorded on
                        // the candidate; the verifier consults it before upgrading
                        // the verdict to ConfirmedIssue.
                        let site_a = build_free_site_for_edge(graph, release_indices[0], ir_module);
                        let site_b = build_free_site_for_edge(graph, ri, ir_module);
                        let (alias_result, alias_evidence) = may_alias(&site_a, &site_b, ir_module);

                        let family = graph.edges[ri].family.unwrap_or(FamilyId::C_HEAP);
                        let id = next_id;
                        next_id += 1;

                        let mut candidate = IssueCandidate::new(
                            id,
                            IssueCandidateKind::DoubleRelease,
                            family,
                            &graph.edges[ri].function_name,
                        )
                        .with_resource_id(*instance_id)
                        .with_alloc_caller(&graph.edges[release_indices[0]].caller_name)
                        .with_release_caller(&graph.edges[ri].caller_name)
                        .with_free_site(site_a.clone())
                        .with_free_site(site_b.clone());

                        // Add MultipleRelease evidence
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::MultipleRelease,
                                format!(
                                    "instance {} released {} times",
                                    instance_id,
                                    release_indices.len()
                                ),
                            )
                            .with_confidence(0.9),
                        );

                        // Record the alias-gate verdict. The description prefix
                        // `may_alias=` is the contract with `verify_double_release`
                        // — that function downgrades the verdict when it sees
                        // `may_alias=NotAlias` here.
                        if !matches!(alias_result, MayAliasResult::MayAlias) {
                            tracing::debug!(
                                target: "omniscope_pass::issue_verifier",
                                "DoubleFree alias gate rejected at candidate-build: site_a={:?} site_b={:?} reason=NoSharedSsaRoot",
                                site_a,
                                site_b
                            );
                            candidate.add_evidence(
                                Evidence::new(
                                    EvidenceKind::Insufficient,
                                    format!(
                                        "may_alias=NotAlias: site_a=({:?}, {}, {:?}) site_b=({:?}, {}, {:?})",
                                        site_a.caller,
                                        site_a.callee,
                                        site_a.arg_register,
                                        site_b.caller,
                                        site_b.callee,
                                        site_b.arg_register,
                                    ),
                                )
                                .with_confidence(0.9),
                            );
                        }

                        // Add NullGuardedRelease evidence if applicable
                        if all_null_guarded {
                            candidate.add_evidence(
                                Evidence::new(
                                    EvidenceKind::NullGuardedRelease,
                                    format!(
                                        "instance {} has {} null-guarded releases",
                                        instance_id,
                                        release_indices.len()
                                    ),
                                )
                                .with_confidence(0.9),
                            );
                        }

                        // Check if NULL is stored after release
                        if has_null_store_pattern(graph, instance_id) {
                            candidate.add_evidence(
                                Evidence::new(
                                    EvidenceKind::NullStoreAfterRelease,
                                    "NULL stored after release - prevents dangling pointer"
                                        .to_string(),
                                )
                                .with_confidence(0.8),
                            );
                        }

                        // Attach AliasEvidence if the may_alias gate found an alias
                        if let Some(ev) = alias_evidence {
                            candidate = candidate.with_alias_evidence(ev);
                        }

                        candidates.push(candidate);
                    }
                }

                // ── BorrowEscape: borrowed pointer with escape edge ──
                if !escape_callback_indices.is_empty() {
                    if let Some(&sidx) = state_index.get(instance_id) {
                        if let Some(states) = ownership_states {
                            let inst = &states[sidx];
                            if inst.contract == PointerContract::Borrowed {
                                let id = next_id;
                                next_id += 1;

                                let func_name = if inst.function_name.is_empty() {
                                    "unknown"
                                } else {
                                    &inst.function_name
                                };
                                let mut candidate = IssueCandidate::new(
                                    id,
                                    IssueCandidateKind::BorrowEscape,
                                    inst.family,
                                    func_name,
                                )
                                .with_resource_id(*instance_id);
                                candidate.add_evidence(
                                    Evidence::new(
                                        EvidenceKind::CallbackEscape,
                                        format!(
                                            "borrowed pointer (instance {}) escaped to callback",
                                            instance_id
                                        ),
                                    )
                                    .with_confidence(0.7),
                                );

                                // Dual-evidence gating (§7.5.3): CallbackEscape
                                // is only FFI evidence when boundary evidence exists.
                                let escape_edge = &graph.edges[escape_callback_indices[0]];
                                let has_boundary = edge_has_boundary_evidence(escape_edge);
                                if has_boundary {
                                    candidate =
                                        candidate.with_ffi_evidence(FfiEvidence::CallbackEscape);
                                    if let Some(be) =
                                        collect_boundary_from_edges(escape_edge, escape_edge)
                                    {
                                        candidate = candidate.with_boundary(be);
                                    }
                                }

                                candidates.push(candidate);
                            }
                        }
                    }
                }

                // ── InvalidBorrowedFree: borrowed pointer with release edge ──
                // This detects when a borrowed pointer (not owned) is passed to
                // a release function. This is a contract violation because
                // borrowed pointers should not be freed by the borrower.
                if !release_indices.is_empty() {
                    if let Some(&sidx) = state_index.get(instance_id) {
                        if let Some(states) = ownership_states {
                            let inst = &states[sidx];
                            if inst.contract == PointerContract::Borrowed {
                                let id = next_id;
                                next_id += 1;

                                let func_name = if inst.function_name.is_empty() {
                                    "unknown"
                                } else {
                                    &inst.function_name
                                };
                                let mut candidate = IssueCandidate::new(
                                    id,
                                    IssueCandidateKind::InvalidBorrowedFree,
                                    inst.family,
                                    func_name,
                                )
                                .with_resource_id(*instance_id);
                                candidate.add_evidence(
                                    Evidence::new(
                                        EvidenceKind::InvalidBorrowedFree,
                                        format!(
                                            "borrowed pointer (instance {}) passed to release function",
                                            instance_id
                                        ),
                                    )
                                    .with_confidence(0.8),
                                );

                                candidates.push(candidate);
                            }
                        }
                    }
                }

                // ── UseAfterFree: released resource then used ──
                if !release_indices.is_empty() {
                    let last_release_idx = *release_indices
                        .last()
                        .expect("issue_candidate_builder: release_indices should not be empty");

                    // Check for use edges after the last release.
                    // Covers: EscapesToCallback, ReturnsBorrowed, ConsumesArg,
                    // StoresArgToOwner, StoresArgToGlobal — any edge that passes
                    // the released pointer to another function or storage location
                    // constitutes a use-after-free (CWE-416).
                    let post_release_uses: Vec<usize> = edge_indices
                        .iter()
                        .filter(|&&idx| {
                            idx > last_release_idx
                                && matches!(
                                    graph.edges[idx].effect,
                                    Effect::EscapesToCallback { .. }
                                        | Effect::ReturnsBorrowed
                                        | Effect::ConsumesArg { .. }
                                        | Effect::StoresArgToOwner { .. }
                                        | Effect::StoresArgToGlobal { .. }
                                )
                        })
                        .copied()
                        .collect();

                    if !post_release_uses.is_empty() {
                        if let Some(&sidx) = state_index.get(instance_id) {
                            if let Some(states) = ownership_states {
                                let inst = &states[sidx];
                                if inst.state == OwnershipState::Released
                                    && inst.contract != PointerContract::Borrowed
                                {
                                    let id = next_id;
                                    next_id += 1;

                                    let func_name = if inst.function_name.is_empty() {
                                        "unknown"
                                    } else {
                                        &inst.function_name
                                    };
                                    let mut candidate = IssueCandidate::new(
                                        id,
                                        IssueCandidateKind::UseAfterFree,
                                        inst.family,
                                        func_name,
                                    )
                                    .with_resource_id(*instance_id);

                                    let use_desc = post_release_uses
                                        .iter()
                                        .map(|&idx| graph.edges[idx].function_name.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    candidate.add_evidence(
                                        Evidence::new(
                                            EvidenceKind::UseAfterFree,
                                            format!(
                                                "instance {} released then used in '{}' — \
                                                 use-after-free (CWE-416)",
                                                instance_id, use_desc
                                            ),
                                        )
                                        .with_confidence(0.85),
                                    );

                                    candidates.push(candidate);
                                }
                            }
                        }
                    }
                }

                // ── DoubleReclaim: same raw pointer reclaimed multiple times ──
                if ownership_reclaim_indices.len() > 1 {
                    for &ri in ownership_reclaim_indices.iter().skip(1) {
                        let family = graph.edges[ri]
                            .family
                            .unwrap_or(FamilyId::RUST_RAW_OWNERSHIP);
                        let id = next_id;
                        next_id += 1;

                        let mut candidate = IssueCandidate::new(
                            id,
                            IssueCandidateKind::DoubleReclaim,
                            family,
                            &graph.edges[ri].function_name,
                        )
                        .with_resource_id(*instance_id);
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::RawOwnershipReclaim,
                                format!(
                                    "instance {} reclaimed {} times via from_raw — \
                                     double reclaim is undefined behavior",
                                    instance_id,
                                    ownership_reclaim_indices.len()
                                ),
                            )
                            .with_confidence(0.9),
                        );

                        candidates.push(candidate);
                    }
                }

                // ── OwnershipEscapeLeak: into_raw without matching from_raw ──
                if !ownership_escape_indices.is_empty() && ownership_reclaim_indices.is_empty() {
                    let &escape_idx = ownership_escape_indices.first().expect(
                        "issue_candidate_builder: ownership_escape_indices should not be empty",
                    );
                    let family = graph.edges[escape_idx]
                        .family
                        .unwrap_or(FamilyId::RUST_RAW_OWNERSHIP);
                    let escape_func = graph.edges[escape_idx].function_name.as_str();

                    let id = next_id;
                    next_id += 1;

                    let mut candidate = IssueCandidate::new(
                        id,
                        IssueCandidateKind::OwnershipEscapeLeak,
                        family,
                        escape_func,
                    )
                    .with_resource_id(*instance_id);
                    candidate.add_evidence(
                        Evidence::new(
                            EvidenceKind::OwnershipEscapeLeak,
                            format!(
                                "instance {} escaped via into_raw ('{}') but never reclaimed via from_raw — potential leak",
                                instance_id, escape_func
                            ),
                        )
                        .with_confidence(0.7),
                    );

                    // Dual-evidence gating (§7.5.3): OwnershipTransfer FFI
                    // evidence requires boundary evidence. into_raw within the
                    // same language is not an FFI signal unless boundary seeds
                    // found a boundary at this edge.
                    let escape_edge = &graph.edges[escape_idx];
                    let escape_caller = escape_edge.caller_name.as_str();
                    let escape_lang = detector.detect_from_function(escape_func);
                    let caller_lang = detector.detect_from_function(escape_caller);
                    let cross_lang = escape_lang != caller_lang;
                    let has_boundary = cross_lang || edge_has_boundary_evidence(escape_edge);
                    if has_boundary {
                        candidate = candidate.with_ffi_evidence(FfiEvidence::OwnershipTransfer);
                        if candidate.boundary.is_none() {
                            if let Some(be) = collect_boundary_from_edges(escape_edge, escape_edge)
                            {
                                candidate = candidate.with_boundary(be);
                            }
                        }
                    }

                    candidates.push(candidate);
                }

                // ── Cross-family reclaim: C family pointer reclaimed by Rust ──
                let non_rust_acquires: Vec<usize> = acquire_indices
                    .iter()
                    .filter(|&&idx| {
                        graph.edges[idx].family.is_some_and(|f| {
                            f != FamilyId::RUST_RAW_OWNERSHIP && f != FamilyId::RUST_GLOBAL
                        })
                    })
                    .copied()
                    .collect();

                for &ai in &non_rust_acquires {
                    for &ri in &ownership_reclaim_indices {
                        let alloc_family = graph.edges[ai].family.unwrap_or(FamilyId::C_HEAP);
                        let reclaim_family = graph.edges[ri]
                            .family
                            .unwrap_or(FamilyId::RUST_RAW_OWNERSHIP);

                        if !registry.is_compatible_release(alloc_family, reclaim_family) {
                            let id = next_id;
                            next_id += 1;

                            let mut candidate = IssueCandidate::new(
                                id,
                                IssueCandidateKind::CrossFamilyFree,
                                alloc_family,
                                &graph.edges[ai].function_name,
                            )
                            .with_release_family(reclaim_family)
                            .with_release_function(&graph.edges[ri].function_name)
                            .with_resource_id(*instance_id)
                            .with_description(format!(
                                "cross-family reclaim: {} ({:?}) reclaimed by {} ({:?})",
                                graph.edges[ai].function_name,
                                alloc_family,
                                graph.edges[ri].function_name,
                                reclaim_family
                            ));

                            // Dual-evidence gating (§7.5.3): CrossFamilyRelease
                            // FFI evidence requires boundary evidence. A
                            // cross-family reclaim at a non-boundary site
                            // is a family mismatch, not an FFI bug.
                            let has_boundary = edge_has_boundary_evidence(&graph.edges[ai])
                                || edge_has_boundary_evidence(&graph.edges[ri]);
                            if has_boundary {
                                candidate =
                                    candidate.with_ffi_evidence(FfiEvidence::CrossFamilyRelease {
                                        alloc_family: format!("{:?}", alloc_family),
                                        release_family: format!("{:?}", reclaim_family),
                                    });
                                if candidate.boundary.is_none() {
                                    if let Some(be) = collect_boundary_from_edges(
                                        &graph.edges[ai],
                                        &graph.edges[ri],
                                    ) {
                                        candidate = candidate.with_boundary(be);
                                    }
                                }
                            }

                            candidates.push(candidate);
                        }
                    }
                }

                // ── NeedsModel: Reclaim without matching Acquire or Escape ──
                if acquire_indices.is_empty()
                    && ownership_escape_indices.is_empty()
                    && !ownership_reclaim_indices.is_empty()
                {
                    for &ri in &ownership_reclaim_indices {
                        let family = graph.edges[ri]
                            .family
                            .unwrap_or(FamilyId::RUST_RAW_OWNERSHIP);
                        let id = next_id;
                        next_id += 1;

                        let mut candidate = IssueCandidate::new(
                            id,
                            IssueCandidateKind::NeedsModel,
                            family,
                            &graph.edges[ri].function_name,
                        )
                        .with_resource_id(*instance_id);
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::RawOwnershipReclaim,
                                format!(
                                    "instance {} reclaimed via '{}' with unknown provenance — \
                                     needs model for raw pointer source",
                                    instance_id, graph.edges[ri].function_name
                                ),
                            )
                            .with_confidence(0.5),
                        );

                        candidates.push(candidate);
                    }
                }
            }
        }

        // ── ConditionalLeak: from ownership states ──
        if let Some(states) = ownership_states {
            for instance in states.iter() {
                if instance.is_leak_candidate() {
                    let id = next_id;
                    next_id += 1;

                    let func_name = if instance.function_name.is_empty() {
                        "unknown"
                    } else {
                        &instance.function_name
                    };
                    let mut candidate = IssueCandidate::new(
                        id,
                        IssueCandidateKind::ConditionalLeak,
                        instance.family,
                        func_name,
                    )
                    .with_alloc_contract(instance.contract)
                    .with_resource_id(instance.id);

                    candidate.add_evidence(
                        Evidence::new(
                            EvidenceKind::Insufficient,
                            format!(
                                "resource instance {} in {:?} state — never released or escaped",
                                instance.id, instance.state
                            ),
                        )
                        .with_confidence(0.6),
                    );

                    // ── Allocator escape / arena / non-allocator API suppression ──
                    // Suppress ConditionalLeak when:
                    // 1. The alloc_caller returns the resource (return-value-escape)
                    // 2. The function is an allocator factory (malloc/realloc wrapper)
                    // 3. The function is an arena/bump allocator (intentional no-free)
                    // 4. The "acquire" is a non-allocator API (malloc_set_zone_name, etc.)
                    if should_suppress_leak_for_allocator_escape(
                        None, // ownership_state instances don't have alloc_caller
                        func_name, ir_module,
                    ) {
                        tracing::debug!(
                            "[LEAK-SUPPRESS] ConditionalLeak suppressed for '{}' — \
                             allocator escape / arena / non-allocator API",
                            func_name
                        );
                        continue;
                    }

                    candidates.push(candidate);
                }
            }
        }

        // ── Pattern-based candidates from IR behavior facts (Phase 3) ──
        // Delegated to pattern_candidates module: StackToGlobalEscape,
        // HeapToGlobalEscape, ReturnAlias, AbiLayoutPadding, TypeConfusion,
        // FreeThenCallbackUse, BufferOverflow.
        let pattern_cands =
            pattern_candidates::generate_pattern_candidates(&semantic_facts, next_id, ir_module);
        candidates.extend(pattern_cands);

        // Filter out custom allocator shims to reduce false positives
        // Note: We only filter custom allocator shims (mimalloc, jemalloc, etc.),
        // not system or Rust allocators, as those are legitimate for analysis.
        let allocator_detector = AllocatorShimDetector::new();

        // Attach semantic facts as evidence to matching candidates (Phase 3).
        //
        // Two lookup strategies:
        // 1. Caller-keyed facts (alloc_caller / release_caller): These match
        //    IRBehaviorSummary facts whose key is the *enclosing function*
        //    where a behavior was detected (e.g., "main").
        // 2. Callee-keyed facts (alloc_function / release_function): These
        //    match LanguageAdapter facts whose key is the *API function name*
        //    (e.g., "Py_DECREF", "JNI_NewGlobalRef"). Without this, adapter
        //    facts become "orphan facts" — generated but never attached to
        //    any candidate.
        let mut facts_attached: usize = 0;
        for candidate in &mut candidates {
            // Collect lookup keys as owned Strings to avoid borrow conflict
            // with the mutable borrow from add_evidence below.
            // Priority: caller context first, then callee/API names.
            let lookup_keys: Vec<String> = vec![
                candidate.alloc_caller.clone().unwrap_or_default(),
                candidate.release_caller.clone().unwrap_or_default(),
                candidate.alloc_function.clone(),
                candidate.release_function.clone().unwrap_or_default(),
            ];
            for key in &lookup_keys {
                if key.is_empty() {
                    continue;
                }
                if let Some(facts) = fact_index.get(key) {
                    for fact in facts {
                        candidate.add_evidence(fact_to_evidence(fact));
                        facts_attached += 1;
                    }
                }
            }
        }

        // ── Precision metrics (§7.5.7) ──
        // Count candidates by FFI evidence status and kind before filtering.
        // These metrics enable downstream precision analysis without
        // re-running the pipeline.
        let ffi_evidence_count = candidates.iter().filter(|c| c.has_ffi_evidence()).count();
        let boundary_evidence_count = candidates.iter().filter(|c| c.boundary.is_some()).count();
        let needs_model_count = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::NeedsModel)
            .count();
        let local_bug_count = candidates
            .iter()
            .filter(|c| {
                matches!(
                    c.kind,
                    IssueCandidateKind::DoubleRelease
                        | IssueCandidateKind::UseAfterFree
                        | IssueCandidateKind::ConditionalLeak
                        | IssueCandidateKind::DoubleReclaim
                        | IssueCandidateKind::InvalidBorrowedFree
                )
            })
            .count();
        // Cross-family candidates without FFI evidence: suppressed by
        // dual-evidence gating. These would have been FFI reports under
        // the old system but are now downgraded to resource-only issues.
        let boundary_suppressed = candidates
            .iter()
            .filter(|c| {
                matches!(
                    c.kind,
                    IssueCandidateKind::CrossFamilyFree
                        | IssueCandidateKind::CrossLanguageFree
                        | IssueCandidateKind::OwnershipEscapeLeak
                        | IssueCandidateKind::BorrowEscape
                ) && !c.has_ffi_evidence()
            })
            .count();

        // ── Freed-pointer-as-argument UAF detection ──
        // Scan IR for patterns where a freed pointer is passed as an argument
        // to a subsequent function call. Tracks poisoned locations (globals/allocas
        // that hold freed pointers) and propagates through load/store chains.
        if let Some(ir_module) = ctx.get_ir_module() {
            use crate::resource::may_alias::{build_def_map, build_store_map, trace_root_set};
            use omniscope_semantics::resource::ir_pattern::is_release_callee;

            for body in ir_module.function_bodies.values() {
                let defs = build_def_map(body);
                let stores = build_store_map(body);
                // Registers that trace back to a freed pointer
                let mut poisoned_regs: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                // Locations (globals/allocas) that hold a freed pointer
                let mut poisoned_locs: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                // Map from freed root to the release callee name
                let mut freed_by_root: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();

                for inst in &body.instructions {
                    if let omniscope_ir::IRInstructionKind::Call = &inst.kind {
                        // Phase 1: Check if this call frees a pointer
                        if let Some(callee) = &inst.callee {
                            let callee_trimmed = callee.trim_start_matches('@');
                            if is_release_callee(callee_trimmed) {
                                if let Some(freed_reg) = inst.operands.first() {
                                    let roots = trace_root_set(
                                        freed_reg,
                                        &defs,
                                        &stores,
                                        &mut std::collections::HashSet::new(),
                                    );
                                    for root in &roots {
                                        poisoned_regs.insert(root.clone());
                                        freed_by_root
                                            .insert(root.clone(), callee_trimmed.to_string());
                                    }
                                    // Check store_map: if the freed pointer was stored to
                                    // any location, poison that location too
                                    if let Some(locs) = stores.get(freed_reg) {
                                        for loc in locs {
                                            poisoned_locs.insert(loc.clone());
                                        }
                                    }
                                }
                            }
                        }

                        // Phase 2: Check if any argument is a poisoned register
                        if !poisoned_regs.is_empty() {
                            for (i, operand) in inst.operands.iter().enumerate().skip(1) {
                                let arg_roots = trace_root_set(
                                    operand,
                                    &defs,
                                    &stores,
                                    &mut std::collections::HashSet::new(),
                                );
                                let intersects =
                                    arg_roots.iter().any(|r| poisoned_regs.contains(r));
                                if intersects {
                                    let callee_name = inst.callee.as_deref().unwrap_or("unknown");
                                    let freed_by = arg_roots
                                        .iter()
                                        .find_map(|r| freed_by_root.get(r))
                                        .map(|s| s.as_str())
                                        .unwrap_or("free");
                                    let family = registry
                                        .lookup(freed_by)
                                        .map(|e| e.family_id)
                                        .unwrap_or(FamilyId::C_HEAP);

                                    let id = next_id;
                                    next_id += 1;
                                    let mut candidate = IssueCandidate::new(
                                        id,
                                        IssueCandidateKind::UseAfterFree,
                                        family,
                                        callee_name,
                                    );
                                    candidate = candidate.with_description(format!(
                                        "freed pointer (by {}) passed as arg {} to {} — use-after-free",
                                        freed_by, i, callee_name
                                    ));
                                    candidate.add_evidence(
                                        Evidence::new(
                                            EvidenceKind::UseAfterFree,
                                            format!(
                                                "pointer freed by {} is used as argument {} in call to {}",
                                                freed_by, i, callee_name
                                            ),
                                        )
                                        .with_family(family),
                                    );
                                    candidates.push(candidate);
                                }
                            }
                        }
                    } else if let omniscope_ir::IRInstructionKind::Store = &inst.kind {
                        // Track store→load propagation: if storing to a location,
                        // check if the stored value is poisoned
                        if let (Some(dest), Some(src)) =
                            (inst.operands.first(), inst.operands.get(1))
                        {
                            let src_roots = trace_root_set(
                                src,
                                &defs,
                                &stores,
                                &mut std::collections::HashSet::new(),
                            );
                            let src_poisoned = src_roots.iter().any(|r| poisoned_regs.contains(r));
                            if src_poisoned {
                                poisoned_locs.insert(dest.clone());
                            } else {
                                // Overwriting a poisoned location with a clean value un-poisons it
                                poisoned_locs.remove(dest);
                            }
                        }
                    } else if let omniscope_ir::IRInstructionKind::Load = &inst.kind {
                        // If loading from a poisoned location, poison the result register
                        if let (Some(dest), Some(src_loc)) =
                            (inst.dest.as_ref(), inst.operands.first())
                        {
                            if poisoned_locs.contains(src_loc) {
                                poisoned_regs.insert(dest.clone());
                            }
                        }
                    }
                }
            }
        }

        let filtered_candidates: Vec<IssueCandidate> = candidates
            .into_iter()
            .filter(|candidate| {
                // Check if the candidate's function is a custom allocator shim
                let func_name = &candidate.alloc_function;
                let release_func = candidate.release_function.as_deref().unwrap_or("");

                // Keep candidates where neither the allocation nor release function
                // is a custom allocator shim
                !allocator_detector.is_custom_allocator_shim(func_name)
                    && !allocator_detector.is_custom_allocator_shim(release_func)
            })
            .collect();

        let candidate_count = filtered_candidates.len();
        ctx.store("issue_candidates", filtered_candidates);

        let mut result = PassResult::new(self.name())
            .with_nodes(candidate_count)
            .with_duration(start.elapsed().as_millis() as u64);
        result.add_stat("semantic_facts_attached", facts_attached);
        result.add_stat("ffi_evidence_count", ffi_evidence_count);
        result.add_stat("boundary_evidence_count", boundary_evidence_count);
        result.add_stat("needs_model_count", needs_model_count);
        result.add_stat("local_bug_count", local_bug_count);
        result.add_stat("boundary_suppressed", boundary_suppressed);

        Ok(result)
    }
}

impl Default for IssueCandidateBuilderPass {
    fn default() -> Self {
        Self::new()
    }
}
