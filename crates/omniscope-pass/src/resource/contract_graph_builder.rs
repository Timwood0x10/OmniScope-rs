//! Contract graph builder pass for resource contract analysis.
//!
//! Builds the resource contract graph from raw facts and summaries.
//! The graph captures edges between resource instances: acquire→release,
//! acquire→escape, acquire→transfer, etc.
//!
//! ## Memory pool integration
//!
//! Temporary string keys (`func_id_map`) are allocated from the arena-based
//! `MemoryPool` in `PassContext` to reduce per-key heap overhead. The pool
//! is reset at the start of each pass run so that the arena is reused.

use omniscope_core::Result;
use omniscope_types::{Effect, FamilyId, FunctionId, Language, OmniScopeConfig};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::raw_fact_collector::RawResourceFact;
use omniscope_semantics::ffi_contract::{ContractType, FFIContractDB};
use omniscope_semantics::resource::memory_graph::MemoryGraph;
use omniscope_semantics::resource::summary::SummaryStore;
use omniscope_semantics::LanguageDetector;
use omniscope_types::boundary::BoundaryEvidence;

/// FIFO queue entry: (instance_id, optional_alloc_family).
type AcquireEntry = (u64, Option<FamilyId>);

/// An edge in the resource contract graph.
#[derive(Debug, Clone)]
pub struct ContractEdge {
    /// Source resource instance ID.
    pub source: u64,
    /// Target resource instance ID (or 0 if terminal).
    pub target: u64,
    /// The effect that creates this edge.
    pub effect: Effect,
    /// Function where this edge occurs.
    pub function: FunctionId,
    /// Callee function name (for diagnostics).
    pub function_name: String,
    /// Caller function name — the enclosing function that contains this call.
    /// Used for issue location reporting.
    pub caller_name: String,
    /// The resource family (if known).
    pub family: Option<FamilyId>,
    /// Boundary evidence attached to this edge (if near an FFI boundary).
    /// Enables downstream verifiers to assess whether the edge crosses
    /// a language boundary, affecting issue severity and FP filtering.
    pub boundary_evidence: Option<Vec<BoundaryEvidence>>,
}

/// FFI boundary definition.
#[derive(Debug, Clone)]
pub struct FFIBoundary {
    /// Source language.
    pub from: Language,
    /// Target language.
    pub to: Language,
}

/// The resource contract graph.
#[derive(Debug, Clone, Default)]
pub struct ContractGraph {
    /// All contract edges.
    pub edges: Vec<ContractEdge>,
    /// Resource instance ID counter.
    next_instance_id: u64,
    /// FFI boundary definitions from configuration.
    pub ffi_boundaries: std::collections::HashMap<String, FFIBoundary>,
}

impl ContractGraph {
    /// Creates a new empty graph.
    pub fn new() -> Self {
        Self {
            edges: Vec::new(),
            next_instance_id: 1,
            ffi_boundaries: std::collections::HashMap::new(),
        }
    }

    /// Allocates a new resource instance ID.
    pub fn alloc_instance(&mut self) -> u64 {
        let id = self.next_instance_id;
        self.next_instance_id += 1;
        id
    }

    /// Adds an edge to the graph.
    pub fn add_edge(&mut self, edge: ContractEdge) {
        self.edges.push(edge);
    }

    /// Returns the number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Mark a function as an FFI boundary.
    pub fn mark_ffi_boundary(&mut self, function: &str, from: Language, to: Language) {
        self.ffi_boundaries
            .insert(function.to_string(), FFIBoundary { from, to });
    }

    /// Check if a function is an FFI boundary.
    pub fn is_ffi_boundary(&self, function: &str) -> Option<(Language, Language)> {
        self.ffi_boundaries.get(function).map(|b| (b.from, b.to))
    }
}

/// Contract graph builder pass.
///
/// Builds the resource contract graph from raw facts and function
/// summaries. Each acquire fact creates a resource instance and
/// each release fact creates a release edge to that instance.
pub struct ContractGraphBuilderPass {
    /// Optional configuration for FFI boundaries and resource families.
    config: Option<OmniScopeConfig>,
}

impl ContractGraphBuilderPass {
    /// Creates a new contract graph builder pass.
    pub fn new() -> Self {
        Self { config: None }
    }

    /// Creates a new contract graph builder pass with configuration.
    pub fn with_config(config: OmniScopeConfig) -> Self {
        Self {
            config: Some(config),
        }
    }

    /// Apply configuration to the contract graph.
    ///
    /// This method applies FFI boundary and resource family configuration
    /// to the graph. It should be called after the graph is built from IR.
    ///
    /// When `boundary.functions` is empty, it means "match all functions
    /// between these languages". In this case, we use language detection
    /// to identify functions that cross the boundary.
    fn apply_config(
        &self,
        config: &OmniScopeConfig,
        graph: &mut ContractGraph,
        raw_facts: &[RawResourceFact],
    ) {
        // Create language detector for wildcard boundaries
        let detector = LanguageDetector::new();

        // Apply FFI boundaries
        for boundary in &config.ffi_boundary {
            // 如果有显式函数列表，标记这些函数为 FFI 边界
            if !boundary.functions.is_empty() {
                for func in &boundary.functions {
                    // Mark functions as FFI boundaries
                    graph.mark_ffi_boundary(func, boundary.from, boundary.to);

                    tracing::debug!(
                        function = %func,
                        from = %boundary.from,
                        to = %boundary.to,
                        "Applied FFI boundary from config"
                    );
                }
            } else {
                // 空函数列表表示匹配该语言对的所有函数
                // 使用语言检测器来识别跨越边界的函数
                tracing::info!(
                    from = %boundary.from,
                    to = %boundary.to,
                    "Processing wildcard FFI boundary for language pair"
                );

                // 遍历所有原始事实，检测语言并标记边界
                for fact in raw_facts {
                    let caller_lang = detector.detect_from_function(&fact.caller_name);
                    let callee_lang = detector.detect_from_function(&fact.function_name);

                    // 如果调用者和被调用者的语言与边界匹配，标记为 FFI 边界
                    if caller_lang == boundary.from && callee_lang == boundary.to {
                        graph.mark_ffi_boundary(&fact.function_name, boundary.from, boundary.to);

                        tracing::debug!(
                            function = %fact.function_name,
                            caller = %fact.caller_name,
                            from = %boundary.from,
                            to = %boundary.to,
                            "Marked function as FFI boundary via language detection"
                        );
                    }
                }
            }
        }

        // Apply resource families
        for family in &config.resource_family {
            tracing::debug!(
                "Custom resource family: {} ({:?})",
                family.name,
                family.kind
            );
            // Register acquire and release functions for custom families
            // This will be used by the FamilyRegistry for symbol lookup
        }
    }

    /// Build contract graph with configuration.
    pub fn build_with_config(
        &mut self,
        _module: &omniscope_ir::IRModule,
        config: &OmniScopeConfig,
    ) -> ContractGraph {
        let mut graph = ContractGraph::new();

        // 1. 应用配置中的 FFI 边界
        // 注意：这里没有原始事实，所以使用空切片
        self.apply_config(config, &mut graph, &[]);

        // 2. 正常构建图
        // Note: This is a simplified version. In practice, we would need to
        // integrate with the existing run() method logic.
        // For now, we just apply the configuration.

        graph
    }
}

impl Pass for ContractGraphBuilderPass {
    fn name(&self) -> &'static str {
        "ContractGraphBuilder"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["StructuralInference"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        // Reset the arena pool so previous pass data is reclaimed.
        ctx.reset_pool();

        let mut graph = ContractGraph::new();
        let mut memory_graph = MemoryGraph::new();

        // Retrieve raw facts from the context
        let raw_facts: Option<Vec<RawResourceFact>> = ctx.get("raw_resource_facts");
        let raw_facts = raw_facts.unwrap_or_default();

        // Retrieve summary store for IR-derived summaries
        let summary_store: SummaryStore = ctx.get("summary_store").unwrap_or_default();

        // Pre-allocate graph edges to reduce reallocations.
        graph.edges.reserve(raw_facts.len());
        memory_graph.nodes.reserve(raw_facts.len());
        memory_graph.edges.reserve(raw_facts.len());

        // Build contract edges from raw facts
        // Group facts by (function_id, family) for acquire→release pairing.
        // Using function_name as key is unreliable: different callees may
        // be aliases or the same callee may appear in different families.
        // Using (func_id, family) ensures acquire and release pair only
        // when they share both the enclosing function and the family.
        // FIFO queue per (func_id, family) so multiple allocations of the same
        // family are matched to releases in allocation order instead of
        // collapsing to a single instance.
        // Use VecDeque for O(1) pop_front instead of Vec::remove(0) which is O(n).
        let mut acquire_instances: std::collections::HashMap<
            (u64, FamilyId),
            std::collections::VecDeque<AcquireEntry>,
        > = std::collections::HashMap::with_capacity(raw_facts.len().max(16));

        for fact in &raw_facts {
            let family = fact.family.unwrap_or(FamilyId::C_HEAP);
            let key = (fact.function, family);

            if fact.is_acquire {
                // Create a new resource instance for this acquire
                let instance_id = graph.alloc_instance();
                graph.add_edge(ContractEdge {
                    source: 0, // 0 = "source" (allocation origin)
                    target: instance_id,
                    effect: Effect::Acquire {
                        family,
                        result: instance_id,
                    },
                    function: fact.function,
                    function_name: fact.function_name.clone(),
                    caller_name: fact.caller_name.clone(),
                    family: Some(family),
                    boundary_evidence: fact.boundary_evidence.clone(),
                });
                // Track this instance by (func_id, family) for matching with releases
                acquire_instances
                    .entry(key)
                    .or_default()
                    .push_back((instance_id, Some(family)));
            } else {
                // Release — pop the oldest matching acquire instance (FIFO)
                // First try same-family matching (exact key)
                let (source_id, alloc_family) = if let Some(instances) =
                    acquire_instances.get_mut(&key)
                {
                    if let Some((sid, af)) = instances.pop_front() {
                        (sid, af)
                    } else {
                        (0, None)
                    }
                } else {
                    // No same-family acquire found — try controlled cross-family matching.
                    //
                    // Cross-family matching is a fallback for real patterns like:
                    //   malloc → operator delete   (C ↔ C++ scalar)
                    //   new[]   → free              (C++ array ↔ C)
                    //   Zig allocator → raw free    (Zig ↔ C)
                    //
                    // BUT it must NOT blindly pair every different-family acquire,
                    // which would create FP in functions managing multiple resources
                    // of different families (e.g., open fd + malloc in same function).
                    //
                    // Controlled conditions (all must be true):
                    //  1. Same function scope          — guaranteed by the loop structure
                    //  2. Release after acquire        — guaranteed by fact ordering
                    //  3. Both families are known      — neither is UNKNOWN
                    //  4. Families are incompatible    — not in each other's compatible_releases
                    //  5. Same-family match unavailable— we are in this branch
                    //  6. Single unmatched acquire, or nearest unmatched acquire is
                    //     the only one in a different family (to avoid multi-resource FP)
                    let mut found = (0, None);
                    // Collect candidates: acquires in the same function with different family
                    let mut candidates: Vec<(
                        &mut std::collections::VecDeque<AcquireEntry>,
                        FamilyId,
                    )> = Vec::new();
                    for ((other_func, other_family), instances) in acquire_instances.iter_mut() {
                        if *other_func == fact.function
                            && *other_family != family
                            && !instances.is_empty()
                        {
                            candidates.push((instances, *other_family));
                        }
                    }

                    // Apply controlled conditions
                    if !candidates.is_empty() {
                        // Condition 3: release family must be known (not UNKNOWN)
                        if family != FamilyId::UNKNOWN {
                            // Filter candidates by condition 3 & 4:
                            // - candidate acquire family must be known
                            // - families must be incompatible
                            let mut viable: Vec<_> = candidates
                                .into_iter()
                                .filter(|(_, other_family)| {
                                    // Condition 3: acquire family is known
                                    if *other_family == FamilyId::UNKNOWN {
                                        return false;
                                    }
                                    // Condition 4: families are incompatible
                                    // (not same, and not in compatible_releases)
                                    !omniscope_types::are_families_compatible(*other_family, family)
                                })
                                .collect();

                            // Condition 6: single unmatched acquire, or only one viable
                            if viable.len() == 1 {
                                // Only one viable candidate — safe to match
                                if let Some((sid, af)) = viable[0].0.pop_front() {
                                    found = (sid, af);
                                }
                            } else if viable.len() > 1 {
                                // Multiple viable candidates — only match if exactly one
                                // unmatched acquire exists total in this function scope,
                                // to avoid FP in multi-resource functions.
                                let total_unmatched: usize =
                                    viable.iter().map(|(q, _)| q.len()).sum();
                                if total_unmatched == 1 {
                                    // Exactly one unmatched acquire across all viable
                                    // candidates — match it
                                    for (instances, _) in viable {
                                        if let Some((sid, af)) = instances.pop_front() {
                                            found = (sid, af);
                                            break;
                                        }
                                    }
                                }
                                // else: multiple unmatched acquires — too ambiguous,
                                // create orphan release instead of risking FP
                            }
                        }
                    }
                    found
                };

                // If no matching acquire, create a standalone instance.
                // Do NOT push into acquire_instances — this is an orphan release
                // and must not corrupt the FIFO queue for subsequent releases.
                let source_id = if source_id == 0 {
                    graph.alloc_instance()
                } else {
                    source_id
                };

                // Check for cross-family release
                let is_cross_family = alloc_family.is_some() && alloc_family != Some(family);

                // Check for cross-language release (different language families)
                let is_cross_language = is_cross_language_mismatch(alloc_family, Some(family));

                let effect = if is_cross_family {
                    if is_cross_language {
                        // Cross-language release: different language families
                        // This is a stronger signal than just cross-family
                        Effect::CrossLanguageFree {
                            alloc_family: alloc_family.unwrap_or(FamilyId::C_HEAP),
                            release_family: family,
                            arg: fact.arg_index.unwrap_or(0),
                        }
                    } else {
                        // Cross-family release: release family differs from alloc family.
                        // Model as ConditionalRelease to signal potential CrossFamilyFree risk —
                        // the release may not follow the allocation family's protocol.
                        Effect::ConditionalRelease {
                            family, // the actual release family
                            arg: fact.arg_index.unwrap_or(0),
                        }
                    }
                } else {
                    Effect::Release {
                        family,
                        arg: fact.arg_index.unwrap_or(0),
                    }
                };

                graph.add_edge(ContractEdge {
                    source: source_id,
                    target: 0, // 0 = "sink" (deallocation)
                    effect,
                    function: fact.function,
                    function_name: fact.function_name.clone(),
                    caller_name: fact.caller_name.clone(),
                    family: Some(family),
                    boundary_evidence: fact.boundary_evidence.clone(),
                });
            }
        }

        // Also scan IRModule for per-function alloc→release patterns
        let ir_module: Option<omniscope_ir::IRModule> = ctx.get("ir_module");
        if let Some(ref module) = ir_module {
            let registry = omniscope_semantics::FamilyRegistry::new();
            let ffi_db = FFIContractDB::new();

            // Group calls by caller function
            let mut calls_by_caller: std::collections::HashMap<&str, Vec<&str>> =
                std::collections::HashMap::new();
            for call in &module.calls {
                let callee = call.callee.trim_start_matches('@');
                let caller = call.caller.trim_start_matches('@');
                calls_by_caller.entry(caller).or_default().push(callee);
            }

            // For each function, find acquire→release patterns.
            // Track a per-caller function ID so edges are scoped correctly.
            // Keys are `&str` borrowed from the IR module (via calls_by_caller),
            // avoiding per-key String heap allocation entirely.
            let mut next_func_id: u64 = 1;
            let mut func_id_map: std::collections::HashMap<&str, u64> =
                std::collections::HashMap::with_capacity(calls_by_caller.len().max(16));

            for (caller_name, callees) in &calls_by_caller {
                let func_id = *func_id_map.entry(caller_name).or_insert_with(|| {
                    let id = next_func_id;
                    next_func_id += 1;
                    id
                });

                // VecDeque for FIFO consumption — releases match acquires in order.
                // Pre-allocate with callee count as upper bound to reduce
                // reallocations in the inner loop.
                let cap = callees.len();
                let mut func_acquires: std::collections::VecDeque<(u64, FamilyId, &str)> =
                    std::collections::VecDeque::with_capacity(cap);
                let mut func_releases: Vec<(FamilyId, &str, bool)> = Vec::with_capacity(cap);
                let mut func_escapes: Vec<(u64, FamilyId, &str)> = Vec::with_capacity(cap);
                let mut func_reclaims: Vec<(u64, FamilyId, &str)> = Vec::with_capacity(cap);

                for &callee in callees {
                    // Try IR-derived summary first
                    if let Some(summary) = summary_store.find_by_name(callee) {
                        let context = CallContext {
                            function_id: func_id,
                            callee_name: callee.to_string(),
                            caller_name: caller_name.to_string(),
                            instance_id: None,
                            family: None,
                        };
                        for effect in &summary.effects {
                            let edge = effect_to_contract_edge(effect, &context, &mut graph);
                            graph.add_edge(edge);
                        }
                        continue;
                    }

                    if let Some(entry) = registry.lookup(callee) {
                        match entry.effect {
                            omniscope_semantics::SymbolEffect::Acquire => {
                                let id = graph.alloc_instance();
                                func_acquires.push_back((id, entry.family_id, callee));
                            }
                            omniscope_semantics::SymbolEffect::Reclaim => {
                                let id = graph.alloc_instance();
                                func_reclaims.push((id, entry.family_id, callee));
                            }
                            omniscope_semantics::SymbolEffect::Release => {
                                func_releases.push((entry.family_id, callee, false));
                            }
                            omniscope_semantics::SymbolEffect::ConditionalRelease => {
                                func_releases.push((entry.family_id, callee, true));
                            }
                            omniscope_semantics::SymbolEffect::Escape => {
                                // into_raw: ownership escapes to raw pointer
                                // Create an escape edge for the instance
                                let id = graph.alloc_instance();
                                func_escapes.push((id, entry.family_id, callee));
                            }
                            _ => {}
                        }
                    } else if let Some(contract) = ffi_db.lookup(callee) {
                        // Use FFI contract database for functions not in FamilyRegistry
                        match contract.contract_type {
                            ContractType::Allocator => {
                                let id = graph.alloc_instance();
                                if let Some(family) = contract.family_id {
                                    func_acquires.push_back((id, family, callee));
                                }
                            }
                            ContractType::Deallocator => {
                                if let Some(family) = contract.family_id {
                                    func_releases.push((family, callee, false));
                                }
                            }
                            ContractType::Retainer => {
                                // Retainers don't create edges in the contract graph
                            }
                            ContractType::Releaser => {
                                if let Some(family) = contract.family_id {
                                    func_releases.push((family, callee, true));
                                }
                            }
                            ContractType::Borrower => {
                                // Borrowers don't create edges in the contract graph
                            }
                            ContractType::Transfer => {
                                // Transfers are handled as escapes
                                if let Some(family) = contract.family_id {
                                    let id = graph.alloc_instance();
                                    func_escapes.push((id, family, callee));
                                }
                            }
                        }
                    }
                }

                // Create edges for each acquire
                for (instance_id, family, callee_name) in &func_acquires {
                    graph.add_edge(ContractEdge {
                        source: 0,
                        target: *instance_id,
                        effect: Effect::Acquire {
                            family: *family,
                            result: *instance_id,
                        },
                        function: func_id,
                        function_name: callee_name.to_string(),
                        caller_name: caller_name.to_string(),
                        family: Some(*family),
                        boundary_evidence: None,
                    });
                }

                // Create edges for each release, consuming matched acquires (FIFO)
                for (family, callee_name, is_conditional) in &func_releases {
                    // Find and consume a matching acquire (same family preferred)
                    let source_id = if let Some(pos) =
                        func_acquires.iter().position(|(_, f, _)| *f == *family)
                    {
                        let (id, _, _) = func_acquires
                            .remove(pos)
                            .expect("contract_graph_builder: position should be valid after find");
                        id
                    } else {
                        // No same-family acquire — try controlled cross-family matching.
                        // Apply the same conditions as the raw_facts path:
                        //  1. Both families must be known (not UNKNOWN)
                        //  2. Families must be incompatible (not in compatible_releases)
                        //  3. Only match if exactly one unmatched acquire exists,
                        //     or only one viable cross-family candidate
                        if *family != FamilyId::UNKNOWN {
                            let viable_indices: Vec<usize> = func_acquires
                                .iter()
                                .enumerate()
                                .filter(|(_, (_, acq_family, _))| {
                                    *acq_family != FamilyId::UNKNOWN
                                        && *acq_family != *family
                                        && !omniscope_types::are_families_compatible(
                                            *acq_family,
                                            *family,
                                        )
                                })
                                .map(|(i, _)| i)
                                .collect();

                            if viable_indices.len() == 1 {
                                // Exactly one viable cross-family candidate — safe to match
                                func_acquires
                                    .remove(viable_indices[0])
                                    .map(|(id, _, _)| id)
                                    .unwrap_or(0)
                            } else {
                                // Multiple or no viable candidates — create orphan release
                                // to avoid FP in multi-resource functions
                                0
                            }
                        } else {
                            0
                        }
                    };

                    let effect = if *is_conditional {
                        Effect::ConditionalRelease {
                            family: *family,
                            arg: 0,
                        }
                    } else {
                        Effect::Release {
                            family: *family,
                            arg: 0,
                        }
                    };

                    graph.add_edge(ContractEdge {
                        source: source_id,
                        target: 0,
                        effect,
                        function: func_id,
                        function_name: callee_name.to_string(),
                        caller_name: caller_name.to_string(),
                        family: Some(*family),
                        boundary_evidence: None,
                    });
                }

                // Create edges for each escape (into_raw), consuming matched acquires.
                // The edge source must be an existing acquire instance so the
                // ownership solver can look it up in instance_map.  The freshly-
                // allocated escape instance is kept for reclaim matching.
                for (escape_id, family, callee_name) in &func_escapes {
                    let source_id = if let Some(pos) =
                        func_acquires.iter().position(|(_, f, _)| *f == *family)
                    {
                        let (id, _, _) = func_acquires
                            .remove(pos)
                            .expect("contract_graph_builder: position should be valid after find");
                        id
                    } else {
                        *escape_id
                    };

                    graph.add_edge(ContractEdge {
                        source: source_id,
                        target: 0,
                        effect: Effect::OwnershipEscape {
                            family: *family,
                            result: *escape_id,
                        },
                        function: func_id,
                        function_name: callee_name.to_string(),
                        caller_name: caller_name.to_string(),
                        family: Some(*family),
                        boundary_evidence: None,
                    });
                }

                // Create edges for each reclaim (from_raw).
                // Try to match reclaims to existing escape or acquire instances
                // of the same family. This enables DoubleReclaim detection when
                // multiple from_raw calls target the same escaped instance.
                let mut escape_claimed: std::collections::HashSet<u64> =
                    std::collections::HashSet::with_capacity(func_escapes.len().max(4));
                let mut reclaim_fallback_id: Option<u64> = None;
                for (instance_id, family, callee_name) in &func_reclaims {
                    // Priority 1: match an escape instance of the same family
                    let target_id = func_escapes
                        .iter()
                        .find(|(eid, efam, _)| *efam == *family && !escape_claimed.contains(eid))
                        .map(|(eid, _, _)| *eid)
                        .or_else(|| {
                            // Priority 2: match any unclaimed escape (cross-family reclaim)
                            func_escapes
                                .iter()
                                .find(|(eid, _, _)| !escape_claimed.contains(eid))
                                .map(|(eid, _, _)| *eid)
                        })
                        .or_else(|| {
                            // Priority 3: match an unclaimed acquire of the same family
                            func_acquires
                                .iter()
                                .find(|(id, f, _)| *f == *family && !escape_claimed.contains(id))
                                .map(|(id, _, _)| *id)
                        })
                        .or_else(|| {
                            // Priority 4: match any acquire instance (cross-family reclaim)
                            // This enables CrossFamilyFree detection for malloc→Box::from_raw
                            func_acquires
                                .iter()
                                .find(|(id, _, _)| !escape_claimed.contains(id))
                                .map(|(id, _, _)| *id)
                        })
                        .or_else(|| {
                            // Priority 4: reuse the same instance for multiple reclaims
                            // without matching escape/acquire (enables DoubleReclaim)
                            if let Some(fallback) = reclaim_fallback_id {
                                Some(fallback)
                            } else {
                                reclaim_fallback_id = Some(*instance_id);
                                Some(*instance_id)
                            }
                        })
                        .unwrap_or(*instance_id);

                    if target_id != *instance_id {
                        escape_claimed.insert(target_id);
                    }

                    graph.add_edge(ContractEdge {
                        source: target_id,
                        // target uses the fresh reclaim instance ID so the edge
                        // is not a self-loop; the solver uses source to find and
                        // transition the escaped instance.
                        target: *instance_id,
                        effect: Effect::OwnershipReclaim {
                            family: *family,
                            result: *instance_id,
                        },
                        function: func_id,
                        function_name: callee_name.to_string(),
                        caller_name: caller_name.to_string(),
                        family: Some(*family),
                        boundary_evidence: None,
                    });
                }

                // ── Callback/userdata escape detection ──
                // When a function calls an FFI API that registers a callback,
                // any stack/borrowed userdata pointer passed to that API
                // escapes to the C side, potentially outliving the stack frame.
                // This generates EscapesToCallback edges for each userdata source.
                //
                // Suppression: if the function has into_raw (func_escapes) or
                // heap-family acquires, the userdata is likely heap-allocated
                // and safely managed — do NOT generate EscapesToCallback.
                let has_heap_source = !func_escapes.is_empty()
                    || func_acquires.iter().any(|(_, f, _)| {
                        *f == FamilyId::C_HEAP
                            || *f == FamilyId::RUST_GLOBAL
                            || *f == FamilyId::RUST_RAW_OWNERSHIP
                            || *f == FamilyId::CPP_NEW_SCALAR
                            || *f == FamilyId::CPP_NEW_ARRAY
                    });

                for &callee in callees {
                    if is_callback_registration_api(callee) && !has_heap_source {
                        // Find a non-heap acquire instance in this function.
                        let userdata_instance = func_acquires
                            .iter()
                            .find(|(_, family, _)| {
                                // Only stack-like or borrowed origins: NOT heap families
                                *family != FamilyId::C_HEAP
                                    && *family != FamilyId::RUST_GLOBAL
                                    && *family != FamilyId::RUST_RAW_OWNERSHIP
                                    && *family != FamilyId::CPP_NEW_SCALAR
                                    && *family != FamilyId::CPP_NEW_ARRAY
                            })
                            .map(|(id, _, _)| *id);

                        // If no non-heap acquire found, create a new instance
                        // representing the stack userdata. The OwnershipSolver
                        // will mark it as Borrowed since it has no Acquire edge.
                        let instance_id =
                            userdata_instance.unwrap_or_else(|| graph.alloc_instance());

                        graph.add_edge(ContractEdge {
                            source: instance_id,
                            target: 0,
                            effect: Effect::EscapesToCallback { arg: 0 },
                            function: func_id,
                            function_name: callee.to_string(),
                            caller_name: caller_name.to_string(),
                            family: None,
                            boundary_evidence: None,
                        });
                    }
                }
            }

            // ── Cross-function pointer lifetime propagation ──
            // When a callee function releases a pointer parameter (orphan release),
            // propagate the lifetime back to the caller's acquire. This handles
            // patterns like: caller mallocs → passes ptr to callee → callee frees.
            //
            // Algorithm:
            // 1. Build a call graph: caller → set of callees
            // 2. For each callee that has orphan releases (no matching acquire),
            //    find the caller that allocated the pointer
            // 3. Create cross-function edges connecting the acquire in the caller
            //    to the release in the callee
            propagate_ptr_lifetime_across_functions(
                &mut graph,
                module,
                &registry,
                &ffi_db,
                &calls_by_caller,
                &func_id_map,
            );

            // ── Post-free call use detection ──
            // When a function contains a malloc→free→call pattern (direct or
            // indirect), the freed pointer (or a GEP-derived alias) passed to
            // a subsequent call is a use-after-free. This handles FFI UAF
            // patterns like:
            //   malloc → free → call @ffi_process_buffer(freed_ptr, ...)
            //   malloc → free → call void %callback(freed_ptr, ...)
            detect_post_free_call_use(&mut graph, module, &func_id_map);

            // Keep the IRModule in context
            ctx.store("ir_module", module.clone());
        }

        // Populate MemoryGraph from ContractGraph
        // Create nodes for each resource instance and edges for acquire/release
        for edge in &graph.edges {
            match &edge.effect {
                Effect::Acquire { family, result } => {
                    // Create a node for the acquired resource
                    let resource_class =
                        omniscope_semantics::resource::memory_graph::family_to_resource_class(
                            *family,
                        );
                    let node = omniscope_semantics::resource::memory_graph::MemoryNode {
                        id: *result,
                        resource_class,
                        state: omniscope_semantics::resource::memory_graph::ResourceState::Owned,
                        function_name: edge.caller_name.clone(),
                        family_id: Some(*family),
                    };
                    memory_graph.add_node(node);
                }
                Effect::Release { family: _, arg: _ } => {
                    // Create an edge for the release
                    let memory_edge = omniscope_semantics::resource::memory_graph::MemoryEdge {
                        source: edge.source,
                        target: 0, // 0 = "sink" (deallocation)
                        kind: omniscope_semantics::resource::memory_graph::MemoryEdgeKind::Release,
                        function_name: edge.function_name.clone(),
                    };
                    memory_graph.add_edge(memory_edge);

                    // Update the source node state to Released
                    memory_graph.set_state(
                        edge.source,
                        omniscope_semantics::resource::memory_graph::ResourceState::Released,
                    );
                }
                Effect::ConditionalRelease { family: _, arg: _ } => {
                    // Create an edge for conditional release
                    let memory_edge = omniscope_semantics::resource::memory_graph::MemoryEdge {
                        source: edge.source,
                        target: 0, // 0 = "sink" (deallocation)
                        kind: omniscope_semantics::resource::memory_graph::MemoryEdgeKind::Release,
                        function_name: edge.function_name.clone(),
                    };
                    memory_graph.add_edge(memory_edge);
                }
                Effect::OwnershipEscape {
                    family: _,
                    result: _,
                } => {
                    // Create an edge for ownership escape
                    let memory_edge = omniscope_semantics::resource::memory_graph::MemoryEdge {
                        source: edge.source,
                        target: 0, // 0 = "sink" (escape)
                        kind: omniscope_semantics::resource::memory_graph::MemoryEdgeKind::ReturnToCaller,
                        function_name: edge.function_name.clone(),
                    };
                    memory_graph.add_edge(memory_edge);

                    // Update the source node state to EscapedToCaller
                    memory_graph.set_state(
                        edge.source,
                        omniscope_semantics::resource::memory_graph::ResourceState::EscapedToCaller,
                    );
                }
                Effect::OwnershipReclaim {
                    family: _,
                    result: _,
                } => {
                    // Create an edge for ownership reclaim (from_raw)
                    let memory_edge = omniscope_semantics::resource::memory_graph::MemoryEdge {
                        source: edge.source,
                        target: edge.target,
                        kind: omniscope_semantics::resource::memory_graph::MemoryEdgeKind::Use,
                        function_name: edge.function_name.clone(),
                    };
                    memory_graph.add_edge(memory_edge);
                }
                Effect::EscapesToCallback { arg: _ } => {
                    // Create an edge for callback escape
                    let memory_edge = omniscope_semantics::resource::memory_graph::MemoryEdge {
                        source: edge.source,
                        target: 0, // 0 = "sink" (callback)
                        kind: omniscope_semantics::resource::memory_graph::MemoryEdgeKind::Use,
                        function_name: edge.function_name.clone(),
                    };
                    memory_graph.add_edge(memory_edge);
                }
                _ => {
                    // For other effects, create a generic use edge
                    if edge.source != 0 {
                        let memory_edge = omniscope_semantics::resource::memory_graph::MemoryEdge {
                            source: edge.source,
                            target: edge.target,
                            kind: omniscope_semantics::resource::memory_graph::MemoryEdgeKind::Use,
                            function_name: edge.function_name.clone(),
                        };
                        memory_graph.add_edge(memory_edge);
                    }
                }
            }
        }

        // Apply configuration if available
        // First try self.config, then try from context
        let config = self.config.as_ref().or_else(|| ctx.config());
        if let Some(config) = config {
            // 获取原始事实用于语言检测
            let raw_facts: Option<Vec<RawResourceFact>> = ctx.get("raw_resource_facts");
            let raw_facts = raw_facts.unwrap_or_default();
            self.apply_config(config, &mut graph, &raw_facts);
        }

        let edge_count = graph.edge_count();
        ctx.store("contract_graph", graph);
        ctx.store("memory_graph", memory_graph);

        let result = PassResult::new(self.name())
            .with_nodes(edge_count)
            .with_duration(start.elapsed().as_millis() as u64);

        Ok(result)
    }
}

impl Default for ContractGraphBuilderPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Propagates pointer lifetime across function boundaries.
///
/// When a callee function releases a pointer parameter (orphan release),
/// this function propagates the lifetime back to the caller's acquire.
/// This handles patterns like: caller mallocs → passes ptr to callee → callee frees.
///
/// # Arguments
/// * `graph` - The contract graph to add edges to
/// * `module` - The IR module containing function definitions
/// * `registry` - The family registry for symbol lookup
/// * `ffi_db` - The FFI contract database
/// * `calls_by_caller` - Map of caller function name to list of callees
/// * `func_id_map` - Map of function name to function ID
fn propagate_ptr_lifetime_across_functions(
    graph: &mut ContractGraph,
    module: &omniscope_ir::IRModule,
    registry: &omniscope_semantics::FamilyRegistry,
    ffi_db: &FFIContractDB,
    calls_by_caller: &std::collections::HashMap<&str, Vec<&str>>,
    func_id_map: &std::collections::HashMap<&str, u64>,
) {
    // Build a reverse call graph: callee → set of callers
    let mut callers_of: std::collections::HashMap<&str, std::collections::HashSet<&str>> =
        std::collections::HashMap::new();
    for (&caller, callees) in calls_by_caller {
        for &callee in callees {
            callers_of.entry(callee).or_default().insert(caller);
        }
    }

    // For each function definition, check if it has releases that are not
    // matched to acquires (orphan releases). If so, propagate the lifetime
    // to the caller's acquire.
    for func_name in module.functions.keys() {
        let func_name = func_name.trim_start_matches('@');

        // Get the callees of this function
        let callees = match calls_by_caller.get(func_name) {
            Some(c) => c,
            None => continue,
        };

        // Collect releases and acquires in this function
        let mut func_releases: Vec<(FamilyId, &str)> = Vec::new();
        let mut func_acquires: Vec<(FamilyId, &str)> = Vec::new();

        for &callee in callees {
            if let Some(entry) = registry.lookup(callee) {
                match entry.effect {
                    omniscope_semantics::SymbolEffect::Release
                    | omniscope_semantics::SymbolEffect::ConditionalRelease => {
                        func_releases.push((entry.family_id, callee));
                    }
                    omniscope_semantics::SymbolEffect::Acquire
                    | omniscope_semantics::SymbolEffect::Retain
                    | omniscope_semantics::SymbolEffect::Reclaim => {
                        func_acquires.push((entry.family_id, callee));
                    }
                    _ => {}
                }
            } else if let Some(contract) = ffi_db.lookup(callee) {
                match contract.contract_type {
                    ContractType::Deallocator | ContractType::Releaser => {
                        if let Some(family) = contract.family_id {
                            func_releases.push((family, callee));
                        }
                    }
                    ContractType::Allocator => {
                        if let Some(family) = contract.family_id {
                            func_acquires.push((family, callee));
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check if there are orphan releases (releases without matching acquires)
        // If the function has more releases than acquires, some releases are orphaned
        let orphan_releases = func_releases.len() > func_acquires.len();
        if !orphan_releases {
            continue;
        }

        // Get the callers of this function
        let callers = match callers_of.get(func_name) {
            Some(c) => c,
            None => continue,
        };

        // For each caller, check if it has matching acquires for the orphan releases
        for &caller_name in callers {
            let caller_func_id = match func_id_map.get(caller_name) {
                Some(&id) => id,
                None => continue,
            };

            // Get the callees of the caller
            let caller_callees = match calls_by_caller.get(caller_name) {
                Some(c) => c,
                None => continue,
            };

            // Collect acquires in the caller
            let mut caller_acquires: Vec<(FamilyId, &str)> = Vec::new();
            for &callee in caller_callees {
                if callee == func_name {
                    continue; // Skip the callee we're processing
                }
                if let Some(entry) = registry.lookup(callee) {
                    if matches!(
                        entry.effect,
                        omniscope_semantics::SymbolEffect::Acquire
                            | omniscope_semantics::SymbolEffect::Retain
                            | omniscope_semantics::SymbolEffect::Reclaim
                    ) {
                        caller_acquires.push((entry.family_id, callee));
                    }
                } else if let Some(contract) = ffi_db.lookup(callee) {
                    if contract.contract_type == ContractType::Allocator {
                        if let Some(family) = contract.family_id {
                            caller_acquires.push((family, callee));
                        }
                    }
                }
            }

            // Match orphan releases in callee to acquires in caller
            for &(release_family, release_callee) in &func_releases {
                // Find a matching acquire in the caller (same family preferred)
                let matching_acquire = caller_acquires
                    .iter()
                    .find(|(f, _)| *f == release_family)
                    .or_else(|| caller_acquires.first());

                if let Some((acquire_family, acquire_callee)) = matching_acquire {
                    // Create a cross-function edge:
                    // Acquire in caller → Release in callee
                    let instance_id = graph.alloc_instance();

                    // Add acquire edge in caller
                    graph.add_edge(ContractEdge {
                        source: 0,
                        target: instance_id,
                        effect: Effect::Acquire {
                            family: *acquire_family,
                            result: instance_id,
                        },
                        function: caller_func_id,
                        function_name: acquire_callee.to_string(),
                        caller_name: caller_name.to_string(),
                        family: Some(*acquire_family),
                        boundary_evidence: None,
                    });

                    // Add release edge in callee (pointing to the same instance)
                    let is_cross_family = *acquire_family != release_family;
                    let effect = if is_cross_family {
                        Effect::ConditionalRelease {
                            family: release_family,
                            arg: 0,
                        }
                    } else {
                        Effect::Release {
                            family: release_family,
                            arg: 0,
                        }
                    };

                    graph.add_edge(ContractEdge {
                        source: instance_id,
                        target: 0,
                        effect,
                        function: *func_id_map.get(func_name).unwrap_or(&0),
                        function_name: release_callee.to_string(),
                        caller_name: func_name.to_string(),
                        family: Some(release_family),
                        boundary_evidence: None,
                    });

                    // Remove the matched acquire from caller_acquires to avoid double-matching
                    if let Some(pos) = caller_acquires
                        .iter()
                        .position(|(f, c)| *f == *acquire_family && *c == *acquire_callee)
                    {
                        caller_acquires.remove(pos);
                    }
                }
            }
        }
    }
}

/// Checks whether a callee name matches a callback registration API pattern.
///
/// These are FFI functions that register a callback function pointer with
/// an associated userdata/context pointer. The userdata pointer escapes
/// to the C side and may be used after the Rust stack frame is gone.
///
/// Only matches high-confidence patterns — registering, setting, or
/// connecting a callback/handler/listener.
fn is_callback_registration_api(callee: &str) -> bool {
    let lower = callee.to_lowercase();

    // Pattern: *_register_callback, *_set_callback, *_on_event, etc.
    // These are the most common FFI callback registration APIs.
    if lower.contains("register_callback")
        || lower.contains("set_callback")
        || lower.contains("add_callback")
        || lower.contains("on_event")
        || lower.contains("set_handler")
        || lower.contains("add_handler")
        || lower.contains("set_listener")
        || lower.contains("connect_callback")
    {
        return true;
    }

    // Common C library patterns: uv_*_start (libuv), sqlite3_*, etc.
    if lower.starts_with("uv_") && lower.ends_with("_start") {
        return true;
    }

    false
}

/// Checks if the alloc family and release family are from different language families.
///
/// This function identifies cross-language free patterns where memory allocated
/// in one language (e.g., Rust) is freed in another language (e.g., C).
/// This is a stronger signal than just cross-family mismatch.
///
/// Returns true if the families are from different language families.
pub fn is_cross_language_mismatch(
    alloc_family: Option<FamilyId>,
    release_family: Option<FamilyId>,
) -> bool {
    let Some(alloc_fam) = alloc_family else {
        return false;
    };
    let Some(release_fam) = release_family else {
        return false;
    };

    // Define language family groups
    let rust_families = [FamilyId::RUST_GLOBAL, FamilyId::RUST_RAW_OWNERSHIP];
    let c_families = [
        FamilyId::C_HEAP,
        FamilyId::CPP_NEW_SCALAR,
        FamilyId::CPP_NEW_ARRAY,
        FamilyId::ZLIB_STREAM,
        FamilyId::OPENSSL_RESOURCE,
        FamilyId::SQLITE_RESOURCE,
        FamilyId::MIMALLOC,
    ];
    let python_families = [
        FamilyId::PYTHON_OBJECT,
        FamilyId::PYTHON_MEM,
        FamilyId::PYTHON_MEM_RAW,
    ];
    let java_families = [FamilyId::JAVA_LOCAL_REF, FamilyId::JAVA_GLOBAL_REF];
    let csharp_families = [
        FamilyId::CSHARP_HGLOBAL,
        FamilyId::CSHARP_COTASK,
        FamilyId::CSHARP_COM,
    ];
    let go_families = [FamilyId::GO_GC, FamilyId::GO_CGO];
    let zig_families = [FamilyId::ZIG_ALLOCATOR];

    // Check if alloc and release families are in different language groups
    let alloc_is_rust = rust_families.contains(&alloc_fam);
    let alloc_is_c = c_families.contains(&alloc_fam);
    let alloc_is_python = python_families.contains(&alloc_fam);
    let alloc_is_java = java_families.contains(&alloc_fam);
    let alloc_is_csharp = csharp_families.contains(&alloc_fam);
    let alloc_is_go = go_families.contains(&alloc_fam);
    let alloc_is_zig = zig_families.contains(&alloc_fam);

    let release_is_rust = rust_families.contains(&release_fam);
    let release_is_c = c_families.contains(&release_fam);
    let release_is_python = python_families.contains(&release_fam);
    let release_is_java = java_families.contains(&release_fam);
    let release_is_csharp = csharp_families.contains(&release_fam);
    let release_is_go = go_families.contains(&release_fam);
    let release_is_zig = zig_families.contains(&release_fam);

    // Cross-language if both are in different language groups
    (alloc_is_rust
        && (release_is_c
            || release_is_python
            || release_is_java
            || release_is_csharp
            || release_is_go
            || release_is_zig))
        || (alloc_is_c
            && (release_is_rust
                || release_is_python
                || release_is_java
                || release_is_csharp
                || release_is_go
                || release_is_zig))
        || (alloc_is_python
            && (release_is_rust
                || release_is_c
                || release_is_java
                || release_is_csharp
                || release_is_go
                || release_is_zig))
        || (alloc_is_java
            && (release_is_rust
                || release_is_c
                || release_is_python
                || release_is_csharp
                || release_is_go
                || release_is_zig))
        || (alloc_is_csharp
            && (release_is_rust
                || release_is_c
                || release_is_python
                || release_is_java
                || release_is_go
                || release_is_zig))
        || (alloc_is_go
            && (release_is_rust
                || release_is_c
                || release_is_python
                || release_is_java
                || release_is_csharp
                || release_is_zig))
        || (alloc_is_zig
            && (release_is_rust
                || release_is_c
                || release_is_python
                || release_is_java
                || release_is_csharp
                || release_is_go))
}

/// Converts an Effect to a ContractEdge for a given call context.
///
/// This is used to create edges from IR-derived summaries. The effect
/// is converted to an edge with the appropriate source and target IDs.
fn effect_to_contract_edge(
    effect: &Effect,
    context: &CallContext,
    graph: &mut ContractGraph,
) -> ContractEdge {
    match effect {
        Effect::Acquire { family, .. } => {
            let instance_id = graph.alloc_instance();
            ContractEdge {
                source: 0,
                target: instance_id,
                effect: Effect::Acquire {
                    family: *family,
                    result: instance_id,
                },
                function: context.function_id,
                function_name: context.callee_name.clone(),
                caller_name: context.caller_name.clone(),
                family: Some(*family),
                boundary_evidence: None,
            }
        }
        Effect::Release { family, arg } => ContractEdge {
            source: context.instance_id.unwrap_or(0),
            target: 0,
            effect: Effect::Release {
                family: *family,
                arg: *arg,
            },
            function: context.function_id,
            function_name: context.callee_name.clone(),
            caller_name: context.caller_name.clone(),
            family: Some(*family),
            boundary_evidence: None,
        },
        Effect::ConditionalRelease { family, arg } => ContractEdge {
            source: context.instance_id.unwrap_or(0),
            target: 0,
            effect: Effect::ConditionalRelease {
                family: *family,
                arg: *arg,
            },
            function: context.function_id,
            function_name: context.callee_name.clone(),
            caller_name: context.caller_name.clone(),
            family: Some(*family),
            boundary_evidence: None,
        },
        Effect::NullGuardedRelease { family, arg } => ContractEdge {
            source: context.instance_id.unwrap_or(0),
            target: 0,
            effect: Effect::NullGuardedRelease {
                family: *family,
                arg: *arg,
            },
            function: context.function_id,
            function_name: context.callee_name.clone(),
            caller_name: context.caller_name.clone(),
            family: Some(*family),
            boundary_evidence: None,
        },
        Effect::OutParamOwnedOnSuccess { family, arg } => {
            let instance_id = graph.alloc_instance();
            ContractEdge {
                source: 0,
                target: instance_id,
                effect: Effect::OutParamOwnedOnSuccess {
                    family: *family,
                    arg: *arg,
                },
                function: context.function_id,
                function_name: context.callee_name.clone(),
                caller_name: context.caller_name.clone(),
                family: Some(*family),
                boundary_evidence: None,
            }
        }
        Effect::OutParamNullOnError { arg } => ContractEdge {
            source: context.instance_id.unwrap_or(0),
            target: 0,
            effect: Effect::OutParamNullOnError { arg: *arg },
            function: context.function_id,
            function_name: context.callee_name.clone(),
            caller_name: context.caller_name.clone(),
            family: context.family,
            boundary_evidence: None,
        },
        Effect::OwnershipEscape { family, result: _ } => {
            let instance_id = graph.alloc_instance();
            ContractEdge {
                source: context.instance_id.unwrap_or(0),
                target: 0,
                effect: Effect::OwnershipEscape {
                    family: *family,
                    result: instance_id,
                },
                function: context.function_id,
                function_name: context.callee_name.clone(),
                caller_name: context.caller_name.clone(),
                family: Some(*family),
                boundary_evidence: None,
            }
        }
        Effect::OwnershipReclaim { family, result: _ } => {
            let instance_id = graph.alloc_instance();
            ContractEdge {
                source: context.instance_id.unwrap_or(instance_id),
                target: instance_id,
                effect: Effect::OwnershipReclaim {
                    family: *family,
                    result: instance_id,
                },
                function: context.function_id,
                function_name: context.callee_name.clone(),
                caller_name: context.caller_name.clone(),
                family: Some(*family),
                boundary_evidence: None,
            }
        }
        Effect::ReturnsBorrowed => {
            // ReturnsBorrowed doesn't create a graph edge
            ContractEdge {
                source: 0,
                target: 0,
                effect: Effect::ReturnsBorrowed,
                function: context.function_id,
                function_name: context.callee_name.clone(),
                caller_name: context.caller_name.clone(),
                family: None,
                boundary_evidence: None,
            }
        }
        Effect::ReturnsOwned { family } => {
            let instance_id = graph.alloc_instance();
            ContractEdge {
                source: 0,
                target: instance_id,
                effect: Effect::ReturnsOwned { family: *family },
                function: context.function_id,
                function_name: context.callee_name.clone(),
                caller_name: context.caller_name.clone(),
                family: Some(*family),
                boundary_evidence: None,
            }
        }
        Effect::ConsumesArg { arg, family } => ContractEdge {
            source: context.instance_id.unwrap_or(0),
            target: 0,
            effect: Effect::ConsumesArg {
                arg: *arg,
                family: *family,
            },
            function: context.function_id,
            function_name: context.callee_name.clone(),
            caller_name: context.caller_name.clone(),
            family: context.family,
            boundary_evidence: None,
        },
        Effect::CrossLanguageFree {
            alloc_family,
            release_family,
            arg,
        } => ContractEdge {
            source: context.instance_id.unwrap_or(0),
            target: 0,
            effect: Effect::CrossLanguageFree {
                alloc_family: *alloc_family,
                release_family: *release_family,
                arg: *arg,
            },
            function: context.function_id,
            function_name: context.callee_name.clone(),
            caller_name: context.caller_name.clone(),
            family: Some(*release_family),
            boundary_evidence: None,
        },
        Effect::EscapesToCallback { arg } => ContractEdge {
            source: context.instance_id.unwrap_or(0),
            target: 0,
            effect: Effect::EscapesToCallback { arg: *arg },
            function: context.function_id,
            function_name: context.callee_name.clone(),
            caller_name: context.caller_name.clone(),
            family: None,
            boundary_evidence: None,
        },
        // Handle other effect variants
        _ => {
            // For effects that don't create edges (e.g., Retain, StoresArgToOwner, etc.)
            // or effects that need special handling, we create a dummy edge
            ContractEdge {
                source: 0,
                target: 0,
                effect: effect.clone(),
                function: context.function_id,
                function_name: context.callee_name.clone(),
                caller_name: context.caller_name.clone(),
                family: context.family,
                boundary_evidence: None,
            }
        }
    }
}

/// Context for a function call used when converting effects to contract edges.
struct CallContext {
    /// The function ID of the caller.
    function_id: FunctionId,
    /// The name of the callee function.
    callee_name: String,
    /// The name of the caller function.
    caller_name: String,
    /// The instance ID if known (for releases).
    instance_id: Option<u64>,
    /// The family if known.
    family: Option<FamilyId>,
}

/// Detect indirect calls that use freed pointers (FFI callback UAF pattern).
///
/// Scans function bodies for the pattern: malloc → free → indirect_call(freed_ptr).
/// When found, generates ConsumesArg edges so the issue candidate builder
/// can detect use-after-free via its post_release_uses check.
///
/// This handles FFI callback UAF patterns like:
/// ```llvm
/// %1 = call ptr @malloc(i64 32)
/// call void @free(ptr %1)
/// %4 = load ptr, ptr @g_callback
/// call void %4(ptr %7, ptr %1, i64 32)  ; UAF: %1 used after free
/// ```
/// Detects post-free call use patterns in function bodies.
///
/// Scans function_bodies for patterns where:
/// 1. A pointer is allocated (malloc/calloc/realloc)
/// 2. The pointer is freed
/// 3. The freed pointer (or a GEP-derived alias) is passed to a subsequent
///    call (direct or indirect)
///
/// Unlike the previous `detect_indirect_call_post_free_use`, this function:
/// - Checks both direct and indirect calls
/// - Tracks GEP-derived aliases (GEP dest inherits the source's freed status)
/// - Does NOT create new Acquire/Release edges (avoids duplicate edges that
///   cause false-positive ConditionalLeak)
/// - Only adds ConsumesArg edges pointing to existing instances found in
///   graph.edges (from the main loop's malloc/free processing)
///
/// The ConsumesArg edge after a Release edge on the same instance triggers
/// UseAfterFree detection in issue_candidate_builder.
fn detect_post_free_call_use(
    graph: &mut ContractGraph,
    module: &omniscope_ir::IRModule,
    func_id_map: &std::collections::HashMap<&str, u64>,
) {
    use omniscope_ir::IRInstructionKind;

    // Phase 1: Build an index of existing instances that have both Acquire
    // and Release edges in the same function.
    //
    // We collect all data from graph.edges FIRST (immutable borrow), then
    // add new edges AFTER (mutable borrow), to satisfy the borrow checker.
    //
    // Key indices built:
    //   - instance_has_acquire / instance_has_release: filter for instances
    //     that are both acquired and released (candidates for UAF)
    //   - release_func_by_instance: instance_id → release function name (e.g.,
    //     "free", "_ZdlPv") used to identify free calls in Phase 2
    let mut instance_has_acquire: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut instance_has_release: std::collections::HashSet<u64> = std::collections::HashSet::new();
    // Track which release function each instance was freed by,
    // so Phase 2 can match free-call instructions to instances.
    let mut release_func_by_instance: std::collections::HashMap<u64, String> =
        std::collections::HashMap::new();

    for edge in &graph.edges {
        match &edge.effect {
            Effect::Acquire { result, .. } => {
                instance_has_acquire.insert(*result);
            }
            #[allow(clippy::collapsible_match)]
            Effect::Release { .. } | Effect::ConditionalRelease { .. } => {
                if edge.source != 0 {
                    instance_has_release.insert(edge.source);
                    release_func_by_instance.insert(edge.source, edge.function_name.clone());
                }
            }
            _ => {}
        }
    }

    // Find instances that have both Acquire and Release
    let released_instances: std::collections::HashSet<u64> = instance_has_acquire
        .intersection(&instance_has_release)
        .copied()
        .collect();

    // Map caller_name → instance_ids that are released.
    // Build from graph.edges in edge order (not from release_callers HashMap)
    // so the Vec ordering matches the sequential order of release calls
    // in the instruction stream — free_call_index depends on this.
    let mut released_instances_by_caller: std::collections::HashMap<String, Vec<u64>> =
        std::collections::HashMap::new();
    for edge in &graph.edges {
        match &edge.effect {
            Effect::Release { .. } | Effect::ConditionalRelease { .. }
                if edge.source != 0
                    && released_instances.contains(&edge.source) =>
            {
                released_instances_by_caller
                    .entry(edge.caller_name.clone())
                    .or_default()
                    .push(edge.source);
            }
            Effect::CrossLanguageFree { .. }
                // CrossLanguageFree is also a release — include it
                if edge.source != 0
                    && released_instances.contains(&edge.source) =>
            {
                released_instances_by_caller
                    .entry(edge.caller_name.clone())
                    .or_default()
                    .push(edge.source);
            }
            _ => {}
        }
    }

    // Phase 2: Scan function_bodies for post-free call patterns
    // Collect new edges to add (deferred to avoid borrow conflicts)
    let mut new_edges: Vec<ContractEdge> = Vec::new();

    for (func_name, body) in &module.function_bodies {
        let func_id = match func_id_map.get(func_name.as_str()) {
            Some(&id) => id,
            None => continue,
        };

        // Get the released instance IDs for this function from the main loop
        let released_ids = match released_instances_by_caller.get(func_name.as_str()) {
            Some(ids) => ids.clone(),
            None => continue, // No released instances in this function
        };

        // Only check functions that have released instances AND either:
        // 1. Are near an FFI boundary (call or are called by FFI functions), OR
        // 2. Have indirect calls (function pointer calls) after free — these
        //    are characteristic of FFI callback UAF patterns
        let has_indirect_call = body
            .instructions
            .iter()
            .any(|inst| matches!(inst.kind, IRInstructionKind::IndirectCall));

        let is_ffi_adjacent = module.calls.iter().any(|c| {
            let caller = c.caller.trim_start_matches('@');
            let callee = c.callee.trim_start_matches('@');
            // This function either calls FFI or is called by FFI
            (caller == func_name || callee == func_name) && graph.is_ffi_boundary(callee).is_some()
        }) || module.functions.iter().any(|(name, _)| {
            name.trim_start_matches('@') == func_name && graph.is_ffi_boundary(func_name).is_some()
        });

        // Check for a simple same-function UAF pattern: free followed by a
        // direct call that passes the freed pointer. This is always a bug
        // regardless of FFI adjacency, so we skip the FFI/indirect-call
        // gate when this pattern is present.
        let has_simple_post_free_use = body.instructions.windows(2).any(|pair| {
            // First instruction is a free/delete call
            matches!(pair[0].kind, IRInstructionKind::Call)
                && pair[0].callee.as_deref().is_some_and(|c| {
                    c == "free" || c == "_ZdlPv" || c == "_ZdaPv"
                        || c == "HeapFree" || c == "VirtualFree"
                })
                // Second instruction is a call that might use the freed pointer
                && matches!(pair[1].kind, IRInstructionKind::Call | IRInstructionKind::IndirectCall)
        });

        if !is_ffi_adjacent && !has_indirect_call && !has_simple_post_free_use {
            continue;
        }

        // Track register → is_freed status and register → instance_id mapping.
        // A register is "freed" if it holds a pointer to a released allocation.
        // GEP destinations inherit the freed status of their source pointer.
        // The reg→instance_id map enables ConsumesArg edges to point to the
        // correct instance, not just released_ids.first().
        let mut freed_regs: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut freed_reg_to_instance: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();

        // Track how many free/release calls we've seen for this function,
        // so we can map each free call to the corresponding released instance.
        // released_ids is built from graph.edges in edge order, which
        // matches the order free calls appear in the instruction stream.
        let mut free_call_index: usize = 0;

        for inst in &body.instructions {
            match inst.kind {
                IRInstructionKind::Call => {
                    if let Some(callee) = &inst.callee {
                        // Track free/dealloc: mark the operand register as freed
                        if callee == "free" || callee == "_ZdaPv" || callee == "_ZdlPv" {
                            // Direct calls have empty operands (see instruction_parser.rs:408),
                            // so we must parse arguments from raw_text.
                            let call_args = extract_call_arg_registers(&inst.raw_text);
                            // Map this free call to the corresponding released instance
                            // using sequential ordering (free_call_index matches the order
                            // instances appear in released_ids from graph.edges).
                            let instance_id = if free_call_index < released_ids.len() {
                                let id = released_ids[free_call_index];
                                free_call_index += 1;
                                Some(id)
                            } else {
                                None
                            };
                            for reg in &call_args {
                                freed_regs.insert(reg.clone());
                                if let Some(id) = instance_id {
                                    freed_reg_to_instance.insert(reg.clone(), id);
                                }
                            }
                            // Don't check for post-free use in the free call itself
                            continue;
                        }
                    }
                    // Check direct calls for post-free use:
                    // If any operand register is in freed_regs, it's a UAF
                    // Direct calls have empty operands, so parse from raw_text
                    if !freed_regs.is_empty() {
                        let call_args = extract_call_arg_registers(&inst.raw_text);
                        for reg in &call_args {
                            if freed_regs.contains(reg) {
                                // Found a post-free use via direct call.
                                // Look up the correct instance_id from the freed
                                // register → instance mapping, not released_ids.first().
                                let instance_id = freed_reg_to_instance
                                    .get(reg)
                                    .copied()
                                    .or_else(|| released_ids.first().copied())
                                    .unwrap_or(0);
                                if instance_id != 0 {
                                    let callee_name = inst.callee.as_deref().unwrap_or("unknown");
                                    new_edges.push(ContractEdge {
                                        source: instance_id,
                                        target: 0,
                                        effect: Effect::ConsumesArg {
                                            arg: 0,
                                            family: Some(FamilyId::C_HEAP),
                                        },
                                        function: func_id,
                                        function_name: callee_name.to_string(),
                                        caller_name: func_name.clone(),
                                        family: Some(FamilyId::C_HEAP),
                                        boundary_evidence: None,
                                    });
                                }
                                break; // Only add one ConsumesArg per call
                            }
                        }
                    }
                }
                IRInstructionKind::IndirectCall if !freed_regs.is_empty() => {
                    // Check indirect calls for post-free use
                    let callee_reg = inst.callee.as_deref().unwrap_or("");
                    // Indirect calls have operands, but they may include type
                    // annotations (e.g., "%4(ptr"). Also check raw_text.
                    let call_args = extract_call_arg_registers(&inst.raw_text);
                    // Combine raw_text args and operands for thorough matching
                    let mut all_args: Vec<String> = call_args;
                    for op in &inst.operands {
                        if !all_args.contains(op) {
                            all_args.push(op.clone());
                        }
                    }
                    for op in &all_args {
                        let op_clean = op.split('(').next().unwrap_or(op.as_str());
                        if op_clean.starts_with('%')
                            && op_clean != callee_reg
                            && freed_regs.contains(op_clean)
                        {
                            // Look up the correct instance_id from the freed
                            // register → instance mapping.
                            let instance_id = freed_reg_to_instance
                                .get(op_clean)
                                .copied()
                                .or_else(|| released_ids.first().copied())
                                .unwrap_or(0);
                            if instance_id != 0 {
                                new_edges.push(ContractEdge {
                                    source: instance_id,
                                    target: 0,
                                    effect: Effect::ConsumesArg {
                                        arg: 0,
                                        family: Some(FamilyId::C_HEAP),
                                    },
                                    function: func_id,
                                    function_name: format!("indirect_call_via_{}", callee_reg),
                                    caller_name: func_name.clone(),
                                    family: Some(FamilyId::C_HEAP),
                                    boundary_evidence: None,
                                });
                            }
                            break;
                        }
                    }
                }
                IRInstructionKind::GetElementPtr => {
                    // GEP dest inherits freed status from source pointer
                    if let Some(dest) = &inst.dest {
                        for op in &inst.operands {
                            if op.starts_with('%') && freed_regs.contains(op) {
                                freed_regs.insert(dest.clone());
                                // Inherit the instance_id mapping from the source
                                if let Some(&instance_id) = freed_reg_to_instance.get(op) {
                                    freed_reg_to_instance.insert(dest.clone(), instance_id);
                                }
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Phase 3: Add the collected edges
    for edge in new_edges {
        graph.add_edge(edge);
    }
}

/// Extracts register names (%-prefixed) from the argument list of a call instruction.
///
/// For direct calls like `call void @free(ptr %buf)`, the text parser sets
/// `operands` to an empty Vec (see `instruction_parser.rs:408`). This helper
/// parses the raw_text to recover the argument registers.
///
/// Handles LLVM IR formats like:
/// - `call void @free(ptr %buf)`
/// - `call i32 @ffi_process_buffer(ptr %rebased, i64 %size)`
/// - `tail call void @free(ptr nonnull %1)`
fn extract_call_arg_registers(raw_text: &str) -> Vec<String> {
    let mut regs = Vec::new();

    // Find the argument list: everything between the first '(' and its matching ')'
    // after the callee name.
    let text = raw_text.trim();

    // Strategy: find the last matching ')' for the call arguments.
    // The argument list starts after the callee name.
    // For `call void @free(ptr %buf)`, the args are `ptr %buf`
    // For `call i32 @func(ptr %1, i64 %2)`, the args are `ptr %1, i64 %2`

    // Find the opening paren of the argument list.
    // It's after the callee (which could be @name or %reg).
    // We look for the last ')' in the line and then find its matching '('.
    let close_paren = match text.rfind(')') {
        Some(pos) => pos,
        None => return regs,
    };

    // Walk backwards to find the matching '('
    let mut depth = 1i32;
    let mut open_paren = 0;
    for (i, ch) in text[..close_paren].char_indices().rev() {
        if ch == ')' {
            depth += 1;
        } else if ch == '(' {
            depth -= 1;
            if depth == 0 {
                open_paren = i;
                break;
            }
        }
    }

    if depth != 0 {
        return regs;
    }

    // Extract the argument text between parentheses
    let args_text = &text[open_paren + 1..close_paren];

    // Split by comma and extract register names
    for arg in args_text.split(',') {
        let arg = arg.trim();
        // Each argument may have type annotations like "ptr %1" or "i64 %size"
        // or "ptr nonnull %buf". We want just the register name.
        for token in arg.split_whitespace() {
            if token.starts_with('%') {
                regs.push(token.to_string());
                break; // One register per argument
            }
        }
    }

    regs
}

#[cfg(test)]
#[path = "contract_graph_builder_tests.rs"]
mod tests;
