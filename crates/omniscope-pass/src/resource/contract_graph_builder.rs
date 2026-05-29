//! Contract graph builder pass for resource contract analysis.
//!
//! Builds the resource contract graph from raw facts and summaries.
//! The graph captures edges between resource instances: acquire→release,
//! acquire→escape, acquire→transfer, etc.

use omniscope_core::Result;
use omniscope_types::{Effect, FamilyId, FunctionId};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::raw_fact_collector::RawResourceFact;

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

        let mut graph = ContractGraph::new();

        // Retrieve raw facts from the context
        let raw_facts: Option<Vec<RawResourceFact>> = ctx.get("raw_resource_facts");
        let raw_facts = raw_facts.unwrap_or_default();

        // Build contract edges from raw facts
        // Group facts by (function_id, family) for acquire→release pairing.
        // Using function_name as key is unreliable: different callees may
        // be aliases or the same callee may appear in different families.
        // Using (func_id, family) ensures acquire and release pair only
        // when they share both the enclosing function and the family.
        // FIFO queue per (func_id, family) so multiple allocations of the same
        // family are matched to releases in allocation order instead of
        // collapsing to a single instance.
        let mut acquire_instances: std::collections::HashMap<
            (u64, FamilyId),
            Vec<(u64, Option<FamilyId>)>,
        > = std::collections::HashMap::new();

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
                    .push((instance_id, Some(family)));
            } else {
                // Release — pop the oldest matching acquire instance (FIFO)
                let (source_id, alloc_family) =
                    if let Some(instances) = acquire_instances.get_mut(&key) {
                        if let Some((sid, af)) = instances.first().copied() {
                            instances.remove(0); // consume FIFO
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

                let effect = if is_cross_family {
                    // Cross-family release: release family differs from alloc family.
                    // Model as ConditionalRelease to signal potential CrossFamilyFree risk —
                    // the release may not follow the allocation family's protocol.
                    Effect::ConditionalRelease {
                        family, // the actual release family
                        arg: fact.arg_index.unwrap_or(0),
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
            let mut next_func_id: u64 = 1;
            let mut func_id_map: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();

            for (caller_name, callees) in &calls_by_caller {
                let func_id = *func_id_map
                    .entry(caller_name.to_string())
                    .or_insert_with(|| {
                        let id = next_func_id;
                        next_func_id += 1;
                        id
                    });

                // VecDeque for FIFO consumption — releases match acquires in order
                let mut func_acquires: std::collections::VecDeque<(u64, FamilyId, &str)> =
                    std::collections::VecDeque::new();
                let mut func_releases: Vec<(FamilyId, &str, bool)> = Vec::new();
                let mut func_escapes: Vec<(u64, FamilyId, &str)> = Vec::new();
                let mut func_reclaims: Vec<(u64, FamilyId, &str)> = Vec::new();

                for &callee in callees {
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
                        let (id, _, _) = func_acquires.remove(pos).unwrap();
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
                        let (id, _, _) = func_acquires.remove(pos).unwrap();
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
                    std::collections::HashSet::new();
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

#[cfg(test)]
#[path = "contract_graph_builder_tests.rs"]
mod tests;
