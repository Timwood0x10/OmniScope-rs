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
use omniscope_types::{Effect, FamilyId, FunctionId};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::raw_fact_collector::RawResourceFact;
use omniscope_semantics::ffi_contract::{ContractType, FFIContractDB};
use omniscope_semantics::resource::summary::SummaryStore;

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
}

/// The resource contract graph.
#[derive(Debug, Clone, Default)]
pub struct ContractGraph {
    /// All contract edges.
    pub edges: Vec<ContractEdge>,
    /// Resource instance ID counter.
    next_instance_id: u64,
}

impl ContractGraph {
    /// Creates a new empty graph.
    pub fn new() -> Self {
        Self {
            edges: Vec::new(),
            next_instance_id: 1,
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
}

/// Contract graph builder pass.
///
/// Builds the resource contract graph from raw facts and function
/// summaries. Each acquire fact creates a resource instance and
/// each release fact creates a release edge to that instance.
pub struct ContractGraphBuilderPass;

impl ContractGraphBuilderPass {
    /// Creates a new contract graph builder pass.
    pub fn new() -> Self {
        Self
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

        // Retrieve raw facts from the context
        let raw_facts: Option<Vec<RawResourceFact>> = ctx.get("raw_resource_facts");
        let raw_facts = raw_facts.unwrap_or_default();

        // Retrieve summary store for IR-derived summaries
        let summary_store: SummaryStore = ctx.get("summary_store").unwrap_or_default();

        // Pre-allocate graph edges to reduce reallocations.
        graph.edges.reserve(raw_facts.len());

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
                });
                // Track this instance by (func_id, family) for matching with releases
                acquire_instances
                    .entry(key)
                    .or_default()
                    .push_back((instance_id, Some(family)));
            } else {
                // Release — pop the oldest matching acquire instance (FIFO)
                let (source_id, alloc_family) =
                    if let Some(instances) = acquire_instances.get_mut(&key) {
                        if let Some((sid, af)) = instances.pop_front() {
                            (sid, af)
                        } else {
                            (0, None)
                        }
                    } else {
                        (0, None)
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
                    });
                }

                // Create edges for each release, consuming matched acquires (FIFO)
                for (family, callee_name, is_conditional) in &func_releases {
                    // Find and consume a matching acquire (same family preferred, else any)
                    let source_id = if let Some(pos) =
                        func_acquires.iter().position(|(_, f, _)| *f == *family)
                    {
                        let (id, _, _) = func_acquires
                            .remove(pos)
                            .expect("contract_graph_builder: position should be valid after find");
                        id
                    } else if let Some((id, _, _)) = func_acquires.pop_front() {
                        // Cross-family fallback: consume oldest unmatched acquire
                        id
                    } else {
                        0
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

            // Keep the IRModule in context
            ctx.store("ir_module", module.clone());
        }

        let edge_count = graph.edge_count();
        ctx.store("contract_graph", graph);

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
        },
        Effect::EscapesToCallback { arg } => ContractEdge {
            source: context.instance_id.unwrap_or(0),
            target: 0,
            effect: Effect::EscapesToCallback { arg: *arg },
            function: context.function_id,
            function_name: context.callee_name.clone(),
            caller_name: context.caller_name.clone(),
            family: None,
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

#[cfg(test)]
#[path = "contract_graph_builder_tests.rs"]
mod tests;
