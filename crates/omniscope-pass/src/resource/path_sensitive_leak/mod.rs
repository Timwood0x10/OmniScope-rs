//! Path-sensitive leak detection for resource contract analysis.
//!
//! Slices the CFG from each allocation site to all reachable exits.
//! If a path reaches an exit without a same-family release, that
//! path is a leak candidate. Partial-path leaks (some paths leak,
//! some don't) become `ConditionalLeak` candidates.
//!
//! Uses a path budget to avoid exponential blowup on large CFGs.
//!
//! Integration with ContractGraph:
//! - Reads resource instances and contract edges from the graph
//! - Uses summary store to determine release families
//! - Produces ConditionalLeak candidates for the IssueVerifier

pub mod analysis;
pub mod helpers;

#[cfg(test)]
mod tests;

use omniscope_core::{Confidence, IssueCandidate, IssueKind, Result};
use omniscope_semantics::SummaryStore;
use omniscope_types::{
    Effect, Evidence, EvidenceKind, FamilyId, IssueCandidateKind, VerifierVerdict,
};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::contract_graph_builder::ContractGraph;
use crate::resource::ownership_solver::PointerStateMap;
use crate::resource::raw_fact_collector::RawResourceFact;

use analysis::{collect_exit_states, determine_leak_type, format_exit_state_summary};
use helpers::{
    build_call_adjacency, caller_returns_owned_resource, check_release_in_summaries,
    classify_function_termination, count_alloc_release_in_facts, function_has_noreturn_exit,
    is_runtime_managed, reachable_functions, FunctionTermination,
};

// Re-export public types from helpers.
pub use helpers::{LeakPath, PathAnalysisResult};

/// Default maximum number of paths to explore per allocation site.
const DEFAULT_PATH_BUDGET: usize = 64;

/// Default maximum path length (in CFG nodes) before giving up.
const DEFAULT_MAX_PATH_LENGTH: usize = 256;

/// Leak type determined by path-sensitive analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LeakType {
    /// Resource is definitely leaked (not freed on any path).
    Definite,
    /// Resource is conditionally leaked (not freed on some paths).
    Conditional,
    /// Resource is safe (freed or escaped on all paths).
    Safe,
    /// Cannot determine - needs model annotation.
    NeedsModel,
}

/// Path-sensitive leak detection pass.
///
/// For each allocation site, traces all paths from the allocation
/// to function exits. If any path lacks a same-family release,
/// it produces a leak candidate:
/// - All paths leak → `ConditionalLeak` (high confidence)
/// - Some paths leak → `ConditionalLeak` (lower confidence)
pub struct LeakDetectionPass {
    /// Maximum number of paths to explore per allocation.
    /// NOTE: Not yet used in `run()` — reserved for path-sensitive upgrade.
    pub path_budget: usize,
    /// Maximum path length before giving up.
    /// NOTE: Not yet used in `run()` — reserved for path-sensitive upgrade.
    pub max_path_length: usize,
}

impl LeakDetectionPass {
    /// Creates a new leak detection pass with default settings.
    pub fn new() -> Self {
        Self {
            path_budget: DEFAULT_PATH_BUDGET,
            max_path_length: DEFAULT_MAX_PATH_LENGTH,
        }
    }

    /// Creates a pass with custom path budget.
    pub fn with_path_budget(mut self, budget: usize) -> Self {
        self.path_budget = budget.max(1);
        self
    }

    /// Creates a pass with custom max path length.
    pub fn with_max_path_length(mut self, length: usize) -> Self {
        self.max_path_length = length.max(1);
        self
    }
}

impl Pass for LeakDetectionPass {
    fn name(&self) -> &'static str {
        "LeakDetection"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["OwnershipSolver"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        // Retrieve the contract graph and summary store.
        // If no contract graph is available, this pass is a no-op.
        let graph = ctx.get_ref::<ContractGraph>("contract_graph");
        let summary_store: Option<SummaryStore> = ctx.get("summary_store");
        let summary_store = summary_store.unwrap_or_default();

        // Retrieve SRT resolutions for runtime-managed resource suppression.
        let srt_resolutions: Option<
            std::collections::HashMap<String, Vec<omniscope_semantics::SemanticKind>>,
        > = ctx.get("srt_resolutions");

        let Some(graph) = graph else {
            let result = PassResult::new(self.name())
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        };

        // Retrieve raw facts for allocation sites.
        let raw_facts: Option<Vec<RawResourceFact>> = ctx.get("raw_resource_facts");
        let raw_facts = raw_facts.unwrap_or_default();

        // Precompute per-family release sites from the contract graph.
        let release_sites_by_family: std::collections::HashMap<FamilyId, Vec<String>> = {
            let mut families: std::collections::HashSet<FamilyId> =
                std::collections::HashSet::new();
            for f in &raw_facts {
                if f.is_acquire {
                    families.insert(f.family.unwrap_or(FamilyId::C_HEAP));
                }
            }
            let mut map: std::collections::HashMap<FamilyId, Vec<String>> =
                std::collections::HashMap::with_capacity(families.len());
            for fam in families {
                if graph.has_release_for_family(fam) {
                    let sites: Vec<String> = graph
                        .release_call_sites_for_family(fam)
                        .map(|s| s.to_string())
                        .collect();
                    map.insert(fam, sites);
                }
            }
            map
        };

        // Extract ReturnsOwned caller set from the graph for ownership transfer.
        let returns_owned_callers: std::collections::HashSet<String> = graph
            .edges
            .iter()
            .filter_map(|e| {
                if matches!(e.effect, Effect::ReturnsOwned { .. }) {
                    Some(e.caller_name.clone())
                } else {
                    None
                }
            })
            .collect();

        // Drop the borrow on `ctx` (held by `graph`).
        let _ = graph;

        // ── Call-path reachability analysis ──
        let call_graph_edges: Option<Vec<omniscope_types::call_graph_types::CallGraphEdge>> =
            ctx.get("call_graph_edges");
        let call_adj: std::collections::HashMap<String, Vec<String>> =
            build_call_adjacency(call_graph_edges.as_deref());

        // Retrieve pointer states from ownership solver.
        let pointer_states: Option<PointerStateMap> = ctx.get("pointer_states");
        let pointer_states = pointer_states.unwrap_or_default();

        let mut leak_candidates: Vec<IssueCandidate> = Vec::new();
        let mut candidate_id: u64 = 1;

        // Group facts by function to do per-function path analysis.
        let alloc_sites: Vec<&RawResourceFact> = raw_facts
            .iter()
            .filter(|f| f.is_acquire && !f.caller_name.is_empty())
            .collect();

        // ── OOM-termination analysis ──
        let ir_module = ctx.get_ir_module();
        let mut func_termination: std::collections::HashMap<String, FunctionTermination> =
            std::collections::HashMap::new();
        let mut func_has_noreturn: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        if let Some(module) = ir_module {
            for alloc in &alloc_sites {
                if !func_termination.contains_key(&alloc.caller_name) {
                    let term = classify_function_termination(module, &alloc.caller_name);
                    func_termination.insert(alloc.caller_name.clone(), term);
                    if function_has_noreturn_exit(module, &alloc.caller_name) {
                        func_has_noreturn.insert(alloc.caller_name.clone());
                    }
                }
            }
        }

        for alloc in &alloc_sites {
            let family = alloc.family.unwrap_or(FamilyId::C_HEAP);

            let (alloc_count, release_count) = count_alloc_release_in_facts(&raw_facts, alloc);
            let has_release_in_summaries = check_release_in_summaries(&summary_store, alloc);

            // ── Call-path reachability filter ──
            let has_call_graph = !call_adj.is_empty();
            let reachable = if has_call_graph {
                reachable_functions(&alloc.caller_name, &call_adj)
            } else {
                let mut r = std::collections::HashSet::new();
                r.insert(alloc.caller_name.clone());
                r
            };

            // Determine leak type using path-sensitive analysis with counting fallback.
            let exit_states = collect_exit_states(
                &pointer_states,
                alloc,
                &srt_resolutions,
                &summary_store,
                &func_termination,
            );

            // Counting-based baseline (always computed for cross-validation).
            let counting_leak_type = if has_release_in_summaries
                && alloc_count > 0
                && (release_count as usize) >= alloc_count as usize
            {
                LeakType::Safe
            } else if has_release_in_summaries
                && alloc_count > 0
                && (release_count as usize) < alloc_count as usize
            {
                LeakType::Conditional
            } else if !has_release_in_summaries && alloc_count > 0 && release_count == 0 {
                LeakType::Definite
            } else if alloc_count > 0
                && release_count > 0
                && (release_count as usize) < alloc_count as usize
            {
                LeakType::Conditional
            } else if alloc_count > 0 && (release_count as usize) >= alloc_count as usize {
                LeakType::Safe
            } else {
                LeakType::NeedsModel
            };

            // Path-sensitive result.
            let path_leak_type = determine_leak_type(&exit_states, alloc_count, release_count);

            // Cross-validate.
            let mut leak_type = match (counting_leak_type, path_leak_type) {
                (LeakType::Safe, LeakType::Safe) => LeakType::Safe,
                (LeakType::Definite, LeakType::Definite) => LeakType::Definite,
                (LeakType::Conditional, LeakType::Conditional) => LeakType::Conditional,

                (LeakType::Safe, LeakType::Definite | LeakType::Conditional) => {
                    tracing::debug!(
                        target: "omniscope_pass::path_sensitive_leak::run",
                        "path-sensitive override suppressed for family {:?} in '{}': counting=Safe, path={:?}",
                        family, alloc.caller_name, path_leak_type
                    );
                    LeakType::Safe
                }

                (LeakType::Definite | LeakType::Conditional, LeakType::Safe) => counting_leak_type,

                (LeakType::Definite, LeakType::Conditional) => LeakType::Conditional,
                (LeakType::Conditional, LeakType::Definite) => LeakType::Conditional,

                (LeakType::NeedsModel, _) => path_leak_type,
                (_, LeakType::NeedsModel) => counting_leak_type,
            };

            // Summary-store override.
            if leak_type != LeakType::Safe && has_release_in_summaries {
                if alloc_count > 0
                    && release_count > 0
                    && (release_count as usize) < alloc_count as usize
                {
                    tracing::debug!(
                        target: "omniscope_pass::path_sensitive_leak::run",
                        "partial-release downgrade for family {:?} in '{}': alloc_count={}, release_count={}, summary has release → Conditional",
                        family, alloc.caller_name, alloc_count, release_count
                    );
                    leak_type = LeakType::Conditional;
                } else {
                    leak_type = LeakType::Safe;
                }
            }

            // ── OOM-termination downgrade ──
            if leak_type == LeakType::Definite || leak_type == LeakType::Conditional {
                let termination = func_termination.get(&alloc.caller_name);
                match termination {
                    Some(FunctionTermination::OnlyAborts) => {
                        tracing::info!(
                            target: "omniscope_pass::path_sensitive_leak::run",
                            "suppressed leak on family {:?} in '{}': function exits only via abort/unreachable (OOM path)",
                            family,
                            alloc.caller_name
                        );
                        leak_type = LeakType::Safe;
                    }
                    Some(FunctionTermination::HasNormalReturn)
                        if leak_type == LeakType::Definite
                            && func_has_noreturn.contains(&alloc.caller_name) =>
                    {
                        tracing::info!(
                            target: "omniscope_pass::path_sensitive_leak::run",
                            "downgraded DefiniteLeak to Conditional on family {:?} in '{}': function has OOM/abort exit paths",
                            family,
                            alloc.caller_name
                        );
                        leak_type = LeakType::Conditional;
                    }
                    _ => {}
                }
            }

            // ── Caller-owned effect downgrade ──
            if (leak_type == LeakType::Definite || leak_type == LeakType::Conditional)
                && (caller_returns_owned_resource(&summary_store, alloc)
                    || returns_owned_callers.contains(&alloc.caller_name))
            {
                tracing::info!(
                    target: "omniscope_pass::path_sensitive_leak::run",
                    "suppressed leak on family {:?} in '{}': caller function transfers ownership to caller (ReturnsOwned/OutParamOwned/OwnershipEscape)",
                    family,
                    alloc.caller_name
                );
                leak_type = LeakType::Safe;
            }

            // ── Runtime-managed resource downgrade ──
            if (leak_type == LeakType::Definite || leak_type == LeakType::Conditional)
                && is_runtime_managed(&srt_resolutions, alloc)
            {
                tracing::info!(
                    target: "omniscope_pass::path_sensitive_leak::run",
                    "suppressed leak on family {:?} in '{}': resource is runtime-managed (arena/zone/GC) or stored to owner",
                    family,
                    alloc.caller_name
                );
                leak_type = LeakType::Safe;
            }

            match leak_type {
                LeakType::Definite => {
                    let reachable_release_sites: Vec<String> = release_sites_by_family
                        .get(&family)
                        .map(|sites| {
                            sites
                                .iter()
                                .filter(|s| reachable.contains(s.as_str()))
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default();

                    let (candidate_kind, downgrade_with_sites): (
                        IssueCandidateKind,
                        Option<Vec<String>>,
                    ) = if !reachable_release_sites.is_empty() {
                        tracing::info!(
                            target: "omniscope_pass::path_sensitive_leak::run",
                            "downgraded leak on family {:?}: {} reachable release sites (of {} total)",
                            family,
                            reachable_release_sites.len(),
                            release_sites_by_family.get(&family).map(|s| s.len()).unwrap_or(0)
                        );
                        (
                            IssueCandidateKind::ConditionalLeak,
                            Some(reachable_release_sites),
                        )
                    } else {
                        (IssueCandidateKind::DefiniteLeak, None)
                    };
                    let _issue_kind = IssueKind::DefiniteLeak;
                    let _confidence = if alloc_count > 1 {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    };

                    let mut candidate = IssueCandidate::new(
                        candidate_id,
                        candidate_kind,
                        family,
                        &alloc.function_name,
                    );
                    candidate = candidate.with_alloc_contract(alloc.contract);
                    if !alloc.caller_name.is_empty() {
                        candidate = candidate.with_alloc_caller(&alloc.caller_name);
                    }
                    if let Some(sites) = downgrade_with_sites {
                        candidate = candidate.with_description(format!(
                            "allocation in '{}' of family {} initially flagged as definite leak; downgraded: family has {} release sites at functions [{}]",
                            alloc.function_name,
                            family.display_name(),
                            sites.len(),
                            sites.join(", ")
                        ));
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::PathStateRefinement,
                                format!(
                                    "downgraded DefiniteLeak → ConditionalLeak on family {}: {} paired release site(s) at [{}]",
                                    family.display_name(),
                                    sites.len(),
                                    sites.join(", ")
                                ),
                            )
                            .with_family(family),
                        );
                    } else {
                        candidate = candidate.with_description(format!(
                            "allocation in '{}' of family {} has no same-family release on any analyzed path (definite leak)",
                            alloc.function_name, family.display_name()
                        ));
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::PathStateRefinement,
                                format!(
                                    "no {}-family release found for allocation in '{}' (definite)",
                                    family.display_name(),
                                    alloc.function_name
                                ),
                            )
                            .with_family(family),
                        );
                    }

                    let exit_summary = format_exit_state_summary(&exit_states);
                    if !exit_summary.is_empty() {
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::PathStateRefinement,
                                format!("exit states: {exit_summary}"),
                            )
                            .with_family(family),
                        );
                    }

                    let _candidate_description = candidate.description.clone().unwrap_or_else(|| {
                        format!(
                            "definite memory leak: allocation of family {:?} in '{}' has no same-family release",
                            candidate.alloc_family, candidate.alloc_function
                        )
                    });
                    let _candidate_alloc_function = candidate.alloc_function.clone();

                    leak_candidates.push(candidate);
                    candidate_id += 1;
                }
                LeakType::Conditional => {
                    let reachable_sites: Vec<String> = release_sites_by_family
                        .get(&family)
                        .map(|sites| {
                            sites
                                .iter()
                                .filter(|s| reachable.contains(s.as_str()))
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default();

                    if !reachable_sites.is_empty() {
                        let family_alloc_count = raw_facts
                            .iter()
                            .filter(|f| f.is_acquire && f.family == Some(family))
                            .count();
                        if reachable_sites.len() >= family_alloc_count {
                            tracing::info!(
                                target: "omniscope_pass::path_sensitive_leak::run",
                                "downgraded ConditionalLeak to Diagnostic on family {:?}: {} reachable release sites (>= {} acquires)",
                                family,
                                reachable_sites.len(),
                                family_alloc_count
                            );
                            let mut candidate = IssueCandidate::new(
                                candidate_id,
                                IssueCandidateKind::ConditionalLeak,
                                family,
                                &alloc.function_name,
                            );
                            candidate_id += 1;
                            candidate = candidate.with_alloc_contract(alloc.contract);
                            if !alloc.caller_name.is_empty() {
                                candidate = candidate.with_alloc_caller(&alloc.caller_name);
                            }
                            candidate.verdict = Some(VerifierVerdict::Diagnostic);
                            candidate = candidate.with_description(format!(
                                "allocation in '{}' of family {} paired with {} reachable release site(s) at [{}] (downgraded: not a confirmed leak)",
                                alloc.function_name,
                                family.display_name(),
                                reachable_sites.len(),
                                reachable_sites.join(", ")
                            ));
                            candidate.add_evidence(
                                Evidence::new(
                                    EvidenceKind::PathStateRefinement,
                                    format!(
                                        "paired-release downgrade: {} reachable release site(s) for family {} at [{}]",
                                        reachable_sites.len(),
                                        family.display_name(),
                                        reachable_sites.join(", ")
                                    ),
                                )
                                .with_family(family),
                            );
                            leak_candidates.push(candidate);
                            continue;
                        } else {
                            tracing::info!(
                                target: "omniscope_pass::path_sensitive_leak::run",
                                "downgraded leak on family {:?}: {} reachable release sites (some acquires unpaired)",
                                family,
                                reachable_sites.len()
                            );
                        }
                    }

                    let mut candidate = IssueCandidate::new(
                        candidate_id,
                        IssueCandidateKind::ConditionalLeak,
                        family,
                        &alloc.function_name,
                    );
                    candidate = candidate.with_alloc_contract(alloc.contract);
                    if !alloc.caller_name.is_empty() {
                        candidate = candidate.with_alloc_caller(&alloc.caller_name);
                    }
                    let partial_note = if !reachable_sites.is_empty() {
                        format!(
                            "; partial graph pairing: {} reachable release site(s) at [{}]",
                            reachable_sites.len(),
                            reachable_sites.join(", ")
                        )
                    } else {
                        String::new()
                    };
                    candidate = candidate.with_description(format!(
                        "allocation in '{}' of family {} has partial same-family release ({} alloc, {} release) on analyzed paths (conditional leak){}",
                        alloc.function_name, family.display_name(), alloc_count, release_count, partial_note
                ));
                    candidate.add_evidence(
                        Evidence::new(
                            EvidenceKind::PathStateRefinement,
                            format!(
                                "partial {}-family release: {} allocs, {} releases in '{}' (conditional){}",
                                family.display_name(),
                                alloc_count,
                                release_count,
                                alloc.function_name,
                                partial_note
                            ),
                        )
                        .with_family(family),
                    );

                    let exit_summary = format_exit_state_summary(&exit_states);
                    if !exit_summary.is_empty() {
                        candidate.add_evidence(
                            Evidence::new(
                                EvidenceKind::PathStateRefinement,
                                format!("exit states: {exit_summary}"),
                            )
                            .with_family(family),
                        );
                    }

                    let _candidate_description = candidate.description.clone().unwrap_or_else(|| {
                        format!(
                            "conditional memory leak: allocation of family {:?} in '{}' has partial release coverage",
                            candidate.alloc_family, candidate.alloc_function
                        )
                    });
                    let _candidate_alloc_function = candidate.alloc_function.clone();

                    leak_candidates.push(candidate);
                    candidate_id += 1;
                }
                LeakType::Safe | LeakType::NeedsModel => {
                    // Safe or needs model - no issue to emit.
                }
            }
        }

        let leak_count = leak_candidates.len();

        ctx.store("leak_candidates", leak_candidates);

        let mut result = PassResult::new(self.name())
            .with_nodes(alloc_sites.len())
            .with_duration(start.elapsed().as_millis() as u64);

        result.add_stat("alloc_sites_analyzed", alloc_sites.len());
        result.add_stat("leak_candidates", leak_count);
        result.add_stat("path_budget", self.path_budget);
        result.add_stat("max_path_length", self.max_path_length);

        Ok(result)
    }
}

impl Default for LeakDetectionPass {
    fn default() -> Self {
        Self::new()
    }
}
