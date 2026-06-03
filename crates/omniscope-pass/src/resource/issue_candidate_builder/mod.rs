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
#[cfg(test)]
mod tests;

use omniscope_core::{IssueCandidate, Result};
use omniscope_semantics::resource::allocator_shim::AllocatorShimDetector;
use omniscope_semantics::{FamilyRegistry, OwnershipState, ResourceInstance};
use omniscope_types::{
    Effect, Evidence, EvidenceKind, FamilyId, IssueCandidateKind, PointerContract,
};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::contract_graph_builder::ContractGraph;
use grouping::InstanceEdgeGroups;

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
        let registry = ctx
            .get_ref::<FamilyRegistry>("family_registry")
            .cloned()
            .unwrap_or_default();

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
                            candidates.push(candidate);
                        } else {
                            // Regular cross-family free
                            let candidate = IssueCandidate::new(
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
                            ));
                            candidates.push(candidate);
                        }
                    }
                }

                // ── DoubleRelease: multiple release edges ──
                // Check pointer state at each release point
                if release_indices.len() > 1 {
                    // Check if releases are null-guarded
                    let null_guarded_releases: Vec<usize> = release_indices
                        .iter()
                        .filter(|&&ri| is_null_guarded_release(&graph.edges[ri].function_name))
                        .copied()
                        .collect();

                    // If all releases are null-guarded, this is safe
                    if null_guarded_releases.len() == release_indices.len() {
                        // All releases are null-guarded - safe pattern
                        let id = next_id;
                        next_id += 1;

                        let mut candidate = IssueCandidate::new(
                            id,
                            IssueCandidateKind::DoubleRelease,
                            graph.edges[release_indices[0]]
                                .family
                                .unwrap_or(FamilyId::C_HEAP),
                            &graph.edges[release_indices[0]].function_name,
                        );
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
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::PathStateRefinement,
                                "all releases are null-guarded - safe pattern".to_string(),
                            )
                            .with_confidence(0.85),
                        );
                        candidates.push(candidate);
                    } else {
                        // Some releases are not null-guarded - potential double release
                        for &ri in release_indices.iter().skip(1) {
                            let family = graph.edges[ri].family.unwrap_or(FamilyId::C_HEAP);
                            let id = next_id;
                            next_id += 1;

                            let mut candidate = IssueCandidate::new(
                                id,
                                IssueCandidateKind::DoubleRelease,
                                family,
                                &graph.edges[ri].function_name,
                            );
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

                            candidates.push(candidate);
                        }
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
                                );
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
                                );
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
                    let post_release_uses: Vec<usize> = edge_indices
                        .iter()
                        .filter(|&&idx| {
                            idx > last_release_idx
                                && (matches!(
                                    graph.edges[idx].effect,
                                    Effect::EscapesToCallback { .. }
                                ) || matches!(graph.edges[idx].effect, Effect::ReturnsBorrowed))
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
                                    );

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
                        );
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
                    );
                    candidate.add_evidence(
                        Evidence::new(
                            EvidenceKind::OwnershipEscapeLeak,
                            format!(
                                "instance {} escaped via into_raw ('{}') but never \
                                 reclaimed via from_raw — potential leak",
                                instance_id, escape_func
                            ),
                        )
                        .with_confidence(0.7),
                    );

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

                            let candidate = IssueCandidate::new(
                                id,
                                IssueCandidateKind::CrossFamilyFree,
                                alloc_family,
                                &graph.edges[ai].function_name,
                            )
                            .with_release_family(reclaim_family)
                            .with_release_function(&graph.edges[ri].function_name)
                            .with_description(format!(
                                "cross-family reclaim: {} ({:?}) reclaimed by {} ({:?})",
                                graph.edges[ai].function_name,
                                alloc_family,
                                graph.edges[ri].function_name,
                                reclaim_family
                            ));

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
                        );
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
                    .with_alloc_contract(instance.contract);

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

                    candidates.push(candidate);
                }
            }
        }

        // Filter out custom allocator shims to reduce false positives
        // Note: We only filter custom allocator shims (mimalloc, jemalloc, etc.),
        // not system or Rust allocators, as those are legitimate for analysis.
        let allocator_detector = AllocatorShimDetector::new();
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

        let result = PassResult::new(self.name())
            .with_nodes(candidate_count)
            .with_duration(start.elapsed().as_millis() as u64);

        Ok(result)
    }
}

/// Helper: Build a cross-family free candidate.
///
/// Convenience function for constructing a `CrossFamilyFree` candidate
/// with the standard description format.
pub fn build_cross_family_candidate(
    id: u64,
    alloc_family: FamilyId,
    release_family: FamilyId,
    alloc_func: &str,
    release_func: &str,
) -> IssueCandidate {
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

/// Checks if a release function is null-guarded.
///
/// Null-guarded release functions check if the pointer is NULL before
/// releasing it. For example, `free(NULL)` is safe in C, and many
/// libraries implement null-guarded release functions.
fn is_null_guarded_release(function_name: &str) -> bool {
    // Known null-guarded release functions. Only exact matches are used
    // to avoid false positives from pattern-based heuristics.
    const NULL_GUARDED_RELEASES: &[&str] = &[
        "free",            // C standard library free
        "cJSON_Delete",    // cJSON library
        "json_object_put", // json-c library
        "sqlite3_free",    // SQLite
        "g_free",          // GLib
        "g_slice_free",    // GLib
        "CFRelease",       // Core Foundation (though it crashes on NULL in practice)
        "Release",         // Common COM pattern
        "SafeRelease",     // Safe COM release pattern
        "SafeDelete",      // Safe delete pattern
        "SafeDeleteArray", // Safe delete array pattern
    ];

    NULL_GUARDED_RELEASES.contains(&function_name)
}

/// Checks if NULL is stored to a pointer after release in the contract graph.
///
/// This pattern prevents dangling pointer access by setting the pointer to NULL
/// after releasing the resource. For example:
/// ```c
/// free(ptr);
/// ptr = NULL;
/// ```
fn has_null_store_pattern(graph: &ContractGraph, instance_id: &u64) -> bool {
    // Look for edges that store NULL to this instance
    graph.edges.iter().any(|edge| {
        // Check if this edge stores to the same instance
        if edge.source == *instance_id {
            // Check if it's a NULL store effect
            matches!(edge.effect, Effect::StoresArgToGlobal { .. })
                || matches!(edge.effect, Effect::StoresArgToOwner { .. })
                || matches!(edge.effect, Effect::InitializesOutParam { .. })
        } else {
            false
        }
    })
}

impl Default for IssueCandidateBuilderPass {
    fn default() -> Self {
        Self::new()
    }
}
