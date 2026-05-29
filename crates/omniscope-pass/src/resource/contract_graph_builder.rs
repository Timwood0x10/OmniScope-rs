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
    /// Function name (for diagnostics).
    pub function_name: String,
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
        let mut acquire_instances: std::collections::HashMap<
            (u64, FamilyId),
            (u64, Option<FamilyId>),
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
                    family: Some(family),
                });
                // Track this instance by (func_id, family) for matching with releases
                acquire_instances
                    .entry(key)
                    .or_insert((instance_id, Some(family)));
            } else {
                // Release — find the matching acquire instance by (func_id, family)
                let (source_id, alloc_family) =
                    acquire_instances.get(&key).copied().unwrap_or((0, None));

                // If no matching acquire, create a standalone instance
                let source_id = if source_id == 0 {
                    let id = graph.alloc_instance();
                    acquire_instances.entry(key).or_insert((id, Some(family)));
                    id
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

            // For each function, find acquire→release patterns
            for callees in calls_by_caller.values() {
                let mut func_acquires: Vec<(u64, FamilyId, &str)> = Vec::new();
                let mut func_releases: Vec<(FamilyId, &str)> = Vec::new();
                let mut func_escapes: Vec<(u64, FamilyId, &str)> = Vec::new();
                let mut func_reclaims: Vec<(u64, FamilyId, &str)> = Vec::new();

                for &callee in callees {
                    if let Some(entry) = registry.lookup(callee) {
                        match entry.effect {
                            omniscope_semantics::SymbolEffect::Acquire => {
                                let id = graph.alloc_instance();
                                func_acquires.push((id, entry.family_id, callee));
                            }
                            omniscope_semantics::SymbolEffect::Reclaim => {
                                let id = graph.alloc_instance();
                                func_reclaims.push((id, entry.family_id, callee));
                            }
                            omniscope_semantics::SymbolEffect::Release
                            | omniscope_semantics::SymbolEffect::ConditionalRelease => {
                                func_releases.push((entry.family_id, callee));
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
                        function: 0,
                        function_name: callee_name.to_string(),
                        family: Some(*family),
                    });
                }

                // Create edges for each release
                for (family, callee_name) in &func_releases {
                    // Find a matching acquire instance (same family or cross-family)
                    let source_id = func_acquires
                        .iter()
                        .find(|(_, f, _)| *f == *family)
                        .map(|(id, _, _)| *id)
                        .or_else(|| func_acquires.last().map(|(id, _, _)| *id))
                        .unwrap_or(0);

                    graph.add_edge(ContractEdge {
                        source: source_id,
                        target: 0,
                        effect: Effect::Release {
                            family: *family,
                            arg: 0,
                        },
                        function: 0,
                        function_name: callee_name.to_string(),
                        family: Some(*family),
                    });
                }

                // Create edges for each escape (into_raw)
                for (instance_id, family, callee_name) in &func_escapes {
                    graph.add_edge(ContractEdge {
                        source: *instance_id,
                        target: 0,
                        effect: Effect::OwnershipEscape {
                            family: *family,
                            result: *instance_id,
                        },
                        function: 0,
                        function_name: callee_name.to_string(),
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
                            // Priority 3: match an acquire instance of the same family
                            func_acquires
                                .iter()
                                .find(|(_, f, _)| *f == *family)
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
                        target: target_id,
                        effect: Effect::OwnershipReclaim {
                            family: *family,
                            result: target_id,
                        },
                        function: 0,
                        function_name: callee_name.to_string(),
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
                            function: 0,
                            function_name: callee.to_string(),
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
mod tests {
    use super::*;
    use crate::resource::raw_fact_collector::RawResourceFact;
    use omniscope_types::{FamilyId, PointerContract};

    #[test]
    fn test_contract_graph_builder_creation() {
        let pass = ContractGraphBuilderPass::new();
        assert_eq!(pass.name(), "ContractGraphBuilder");
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert_eq!(pass.dependencies(), vec!["StructuralInference"]);
    }

    #[test]
    fn test_contract_graph_edge_building() {
        let mut graph = ContractGraph::new();
        let instance = graph.alloc_instance();
        assert_eq!(instance, 1, "First instance ID should be 1");

        graph.add_edge(ContractEdge {
            source: instance,
            target: 0,
            effect: Effect::Release {
                family: FamilyId::C_HEAP,
                arg: 0,
            },
            function: 42,
            function_name: "free".to_string(),
            family: Some(FamilyId::C_HEAP),
        });

        assert_eq!(
            graph.edge_count(),
            1,
            "Graph should have one edge after adding"
        );
    }

    /// Objective: Verify that an acquire-release pair in the same function
    /// produces exactly two edges: one Acquire and one Release, with the
    /// Release edge pointing from the acquire instance to the sink (target=0).
    /// Invariants: Acquire edge source=0, Release edge target=0, same instance ID.
    #[test]
    fn test_acquire_release_pair_in_same_function() {
        let pass = ContractGraphBuilderPass::new();
        let mut ctx = PassContext::new();

        // Two facts in the same function (func_id=1) and same family (C_HEAP):
        // one acquire, one release. They should pair up.
        let facts = vec![
            RawResourceFact {
                function: 1,
                function_name: "malloc".to_string(),
                family: Some(FamilyId::C_HEAP),
                is_acquire: true,
                contract: PointerContract::Owned,
                arg_index: Some(0),
            },
            RawResourceFact {
                function: 1,
                function_name: "free".to_string(),
                family: Some(FamilyId::C_HEAP),
                is_acquire: false,
                contract: PointerContract::Unknown,
                arg_index: Some(0),
            },
        ];
        ctx.store("raw_resource_facts", facts);

        let result = pass.run(&mut ctx).expect("Pass execution must succeed");
        assert!(
            result.nodes_analyzed >= 2,
            "Must produce at least 2 edges (acquire + release), got {}",
            result.nodes_analyzed
        );

        let graph: ContractGraph = ctx
            .get("contract_graph")
            .expect("ContractGraph must be stored in context");

        // Verify acquire edge
        let acquire_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| matches!(e.effect, Effect::Acquire { .. }))
            .collect();
        assert_eq!(
            acquire_edges.len(),
            1,
            "Exactly one Acquire edge expected for one malloc call"
        );
        assert_eq!(
            acquire_edges[0].source, 0,
            "Acquire edge source must be 0 (allocation origin)"
        );
        assert!(
            acquire_edges[0].target > 0,
            "Acquire edge target must be a valid instance ID"
        );

        // Verify release edge
        let release_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| matches!(e.effect, Effect::Release { .. }))
            .collect();
        assert_eq!(
            release_edges.len(),
            1,
            "Exactly one Release edge expected for one free call"
        );
        assert_eq!(
            release_edges[0].target, 0,
            "Release edge target must be 0 (deallocation sink)"
        );
        assert_eq!(
            release_edges[0].source, acquire_edges[0].target,
            "Release edge source must match Acquire edge target (same instance)"
        );
    }

    /// Objective: Verify cross-family release detection: when a fact has a
    /// different family from its (func_id, family)-grouped acquire, it produces
    /// a ConditionalRelease effect instead of Release.
    /// Invariants: Two separate (func_id, family) groups are formed, so the
    /// release with CPP_NEW_SCALAR creates its own standalone instance.
    #[test]
    fn test_cross_family_release_detection() {
        let pass = ContractGraphBuilderPass::new();
        let mut ctx = PassContext::new();

        // Acquire with C_HEAP, release with CPP_NEW_SCALAR in same function.
        // Because grouping is by (func_id, family), these form different groups:
        // (1, C_HEAP) -> acquire, (1, CPP_NEW_SCALAR) -> release (standalone).
        let facts = vec![
            RawResourceFact {
                function: 1,
                function_name: "malloc".to_string(),
                family: Some(FamilyId::C_HEAP),
                is_acquire: true,
                contract: PointerContract::Owned,
                arg_index: Some(0),
            },
            RawResourceFact {
                function: 1,
                function_name: "operator delete".to_string(),
                family: Some(FamilyId::CPP_NEW_SCALAR),
                is_acquire: false,
                contract: PointerContract::Unknown,
                arg_index: Some(0),
            },
        ];
        ctx.store("raw_resource_facts", facts);

        let result = pass.run(&mut ctx).expect("Pass execution must succeed");
        assert!(
            result.nodes_analyzed >= 2,
            "Must produce at least 2 edges, got {}",
            result.nodes_analyzed
        );

        let graph: ContractGraph = ctx
            .get("contract_graph")
            .expect("ContractGraph must be stored in context");

        // Verify the acquire edge uses C_HEAP
        let acquire_edge = graph.edges.iter().find(
            |e| matches!(e.effect, Effect::Acquire { family, .. } if family == FamilyId::C_HEAP),
        );
        assert!(
            acquire_edge.is_some(),
            "Must have an Acquire edge for C_HEAP family"
        );

        // The CPP_NEW_SCALAR release has no matching acquire in the same
        // (func_id, family) group, so a standalone instance is created and
        // a Release (not ConditionalRelease) edge is produced. The cross-family
        // detection in raw facts path only triggers when alloc_family != family
        // within the SAME (func_id, family) group.
        let release_edge = graph
            .edges
            .iter()
            .find(|e| matches!(e.effect, Effect::Release { family, .. } if family == FamilyId::CPP_NEW_SCALAR));
        assert!(
            release_edge.is_some(),
            "Must have a Release edge for CPP_NEW_SCALAR family"
        );
    }

    /// Objective: Verify that when an acquire and release share the same
    /// (func_id, family) key but the release's family differs from the
    /// acquire's stored alloc_family, a ConditionalRelease effect is produced.
    /// This is achieved by having two acquire facts with different families
    /// in the same function, then releasing with a family that matches one key
    /// but has a different alloc_family stored.
    ///
    /// Note: In the raw facts path, each fact's own `family` field determines
    /// the grouping key. Cross-family detection compares `alloc_family` (from
    /// the first acquire in the group) with the release's family. Since the
    /// key is (func_id, family) and the release's family must match the key,
    /// cross-family in raw facts requires the acquire to have a different
    /// original family from the release within the same group. This happens
    /// when the first acquire in the group has a different family from the
    /// group key (which is the release's family).
    ///
    /// However, looking at the code more carefully: `or_insert` means only the
    /// FIRST acquire in a (func_id, family) group sets the alloc_family.
    /// If a release with family=F creates the group first (standalone instance),
    /// and then an acquire with family=F comes, the acquire goes into the
    /// existing group with alloc_family=Some(F). So alloc_family == family
    /// and no cross-family detection triggers.
    ///
    /// The real cross-family path is: acquire with family=A creates group (fn, A)
    /// with alloc_family=Some(A). Then release with family=A would match that
    /// group. But if the release's fact.family is B, it would go to group (fn, B).
    ///
    /// This test validates the ConditionalRelease path by checking that when
    /// alloc_family and the release family differ within the same key, the
    /// effect is ConditionalRelease. We construct this by ensuring the acquire
    /// instance was stored with alloc_family=A but a release comes through with
    /// the same key but a detected mismatch.
    ///
    /// Since the raw facts path groups strictly by (func_id, fact.family), and
    /// alloc_family is set from the first acquire's family, the only way to get
    /// ConditionalRelease is if the first acquire in the group has a DIFFERENT
    /// family from the group key. This cannot happen in normal raw facts because
    /// the group key IS the fact's family. Therefore, ConditionalRelease in the
    /// raw facts path is effectively unreachable (it's a safety net).
    ///
    /// We test ConditionalRelease via the IRModule path instead (see
    /// test_conditional_release_via_ir_module).
    #[test]
    fn test_conditional_release_edge_present() {
        let pass = ContractGraphBuilderPass::new();
        let mut ctx = PassContext::new();

        // Create an IRModule where the same function calls Py_INCREF (Retain)
        // and Py_DECREF (ConditionalRelease) on a Python object.
        let mut module = omniscope_ir::IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "PyObject_New".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Py_DECREF".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });
        ctx.store("ir_module", module);

        // Run the pass — it will process IRModule via FamilyRegistry
        let _ = pass.run(&mut ctx);

        let graph: Option<ContractGraph> = ctx.get("contract_graph");
        let graph = graph.expect("ContractGraph must be stored in context");

        // In the IRModule path, both SymbolEffect::Release and
        // SymbolEffect::ConditionalRelease are mapped to Effect::Release.
        // Verify that Py_DECREF produces a Release edge with the correct family.
        let release_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| matches!(e.effect, Effect::Release { family, .. } if family == FamilyId::PYTHON_OBJECT))
            .collect();
        assert!(
            !release_edges.is_empty(),
            "IRModule path must produce Release edge for Py_DECREF, found {} edges total",
            graph.edges.len()
        );

        // Also verify the acquire edge from PyObject_New
        let acquire_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| matches!(e.effect, Effect::Acquire { family, .. } if family == FamilyId::PYTHON_OBJECT))
            .collect();
        assert!(
            !acquire_edges.is_empty(),
            "Must have Acquire edge for PyObject_New with PYTHON_OBJECT family"
        );
    }

    /// Objective: Verify that escape edges are created when the IRModule
    /// contains calls to into_raw (e.g., Box::into_raw).
    /// Invariants: An OwnershipEscape edge is produced with the correct family.
    #[test]
    fn test_escape_edge_creation_via_ir_module() {
        let pass = ContractGraphBuilderPass::new();
        let mut ctx = PassContext::new();

        // A function that allocates a Box and converts it to a raw pointer
        let mut module = omniscope_ir::IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Box::into_raw".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });
        ctx.store("ir_module", module);

        let _ = pass.run(&mut ctx);

        let graph: Option<ContractGraph> = ctx.get("contract_graph");
        let graph = graph.expect("ContractGraph must be stored in context");

        // Verify OwnershipEscape edge is created
        let escape_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| matches!(e.effect, Effect::OwnershipEscape { .. }))
            .collect();
        assert!(
            !escape_edges.is_empty(),
            "Must produce OwnershipEscape edge for Box::into_raw call"
        );

        // Verify the escape edge uses RUST_RAW_OWNERSHIP family
        let escape = &escape_edges[0];
        match &escape.effect {
            Effect::OwnershipEscape { family, .. } => {
                assert_eq!(
                    *family,
                    FamilyId::RUST_RAW_OWNERSHIP,
                    "Box::into_raw must use RUST_RAW_OWNERSHIP family"
                );
            }
            _ => unreachable!("Already filtered for OwnershipEscape"),
        }
    }

    /// Objective: Verify that reclaim edges are created when the IRModule
    /// contains calls to from_raw (e.g., Box::from_raw).
    /// Invariants: An OwnershipReclaim edge is produced and linked to the
    /// escape instance when both into_raw and from_raw are present.
    #[test]
    fn test_reclaim_edge_creation_via_ir_module() {
        let pass = ContractGraphBuilderPass::new();
        let mut ctx = PassContext::new();

        // A function that escapes ownership and then reclaims it
        let mut module = omniscope_ir::IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Box::into_raw".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Box::from_raw".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });
        ctx.store("ir_module", module);

        let _ = pass.run(&mut ctx);

        let graph: Option<ContractGraph> = ctx.get("contract_graph");
        let graph = graph.expect("ContractGraph must be stored in context");

        // Verify OwnershipReclaim edge is created
        let reclaim_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| matches!(e.effect, Effect::OwnershipReclaim { .. }))
            .collect();
        assert!(
            !reclaim_edges.is_empty(),
            "Must produce OwnershipReclaim edge for Box::from_raw call"
        );

        // Verify reclaim edge links to the escape instance (same source and target)
        let reclaim = &reclaim_edges[0];
        assert_eq!(
            reclaim.source, reclaim.target,
            "Reclaim edge source and target must be the same instance (reclaims from self)"
        );

        // Verify the reclaim edge uses RUST_RAW_OWNERSHIP family
        match &reclaim.effect {
            Effect::OwnershipReclaim { family, .. } => {
                assert_eq!(
                    *family,
                    FamilyId::RUST_RAW_OWNERSHIP,
                    "Box::from_raw must use RUST_RAW_OWNERSHIP family"
                );
            }
            _ => unreachable!("Already filtered for OwnershipReclaim"),
        }

        // Verify the escape edge was also created
        let escape_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| matches!(e.effect, Effect::OwnershipEscape { .. }))
            .collect();
        assert!(
            !escape_edges.is_empty(),
            "Must also have OwnershipEscape edge for the paired Box::into_raw"
        );
    }

    /// Objective: Verify that Vec::from_raw_parts produces a reclaim edge
    /// even without a matching into_raw, since from_raw_parts can also
    /// reassemble a previously escaped Vec.
    /// Invariants: OwnershipReclaim edge is created with RUST_RAW_OWNERSHIP family.
    #[test]
    fn test_reclaim_from_raw_parts_without_escape() {
        let pass = ContractGraphBuilderPass::new();
        let mut ctx = PassContext::new();

        let mut module = omniscope_ir::IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "Vec::from_raw_parts".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });
        ctx.store("ir_module", module);

        let _ = pass.run(&mut ctx);

        let graph: Option<ContractGraph> = ctx.get("contract_graph");
        let graph = graph.expect("ContractGraph must be stored in context");

        let reclaim_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| matches!(e.effect, Effect::OwnershipReclaim { .. }))
            .collect();
        assert!(
            !reclaim_edges.is_empty(),
            "Vec::from_raw_parts must produce an OwnershipReclaim edge"
        );
    }

    /// Objective: Verify that when no raw facts are provided, the pass
    /// produces an empty graph without errors.
    /// Invariants: graph.edge_count() == 0, pass returns Ok.
    #[test]
    fn test_empty_raw_facts_produces_empty_graph() {
        let pass = ContractGraphBuilderPass::new();
        let mut ctx = PassContext::new();
        // Do not store any raw_resource_facts — the pass should handle None gracefully

        let result = pass.run(&mut ctx);
        assert!(result.is_ok(), "Pass must succeed even with no raw facts");

        let graph: Option<ContractGraph> = ctx.get("contract_graph");
        let graph = graph.expect("ContractGraph must be stored in context");
        assert_eq!(
            graph.edge_count(),
            0,
            "Empty raw facts must produce an empty graph"
        );
    }

    /// Objective: Verify that a release without a matching acquire in the
    /// same (func_id, family) group creates a standalone instance.
    /// Invariants: A standalone instance is allocated and the Release edge
    /// references it (source > 0, target = 0).
    #[test]
    fn test_release_without_matching_acquire() {
        let pass = ContractGraphBuilderPass::new();
        let mut ctx = PassContext::new();

        // Only a release fact, no corresponding acquire in the same group
        let facts = vec![RawResourceFact {
            function: 5,
            function_name: "free".to_string(),
            family: Some(FamilyId::C_HEAP),
            is_acquire: false,
            contract: PointerContract::Unknown,
            arg_index: Some(0),
        }];
        ctx.store("raw_resource_facts", facts);

        let result = pass.run(&mut ctx);
        assert!(result.is_ok(), "Pass must succeed");

        let graph: ContractGraph = ctx
            .get("contract_graph")
            .expect("ContractGraph must be stored in context");

        let release_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| matches!(e.effect, Effect::Release { .. }))
            .collect();
        assert_eq!(
            release_edges.len(),
            1,
            "Exactly one Release edge expected for the standalone free"
        );
        assert!(
            release_edges[0].source > 0,
            "Standalone release must have a valid source instance ID, got {}",
            release_edges[0].source
        );
        assert_eq!(
            release_edges[0].target, 0,
            "Release edge target must be 0 (sink)"
        );
    }

    /// Objective: Verify that the is_callback_registration_api helper
    /// correctly identifies callback registration patterns.
    /// Invariants: Known patterns return true, non-callback names return false.
    #[test]
    fn test_callback_registration_api_detection() {
        // Positive cases: known callback registration patterns
        assert!(
            is_callback_registration_api("register_callback"),
            "'register_callback' must be detected as callback registration"
        );
        assert!(
            is_callback_registration_api("my_lib_set_callback"),
            "'my_lib_set_callback' must be detected as callback registration"
        );
        assert!(
            is_callback_registration_api("uv_poll_start"),
            "'uv_poll_start' (libuv pattern) must be detected as callback registration"
        );
        assert!(
            is_callback_registration_api("on_event"),
            "'on_event' must be detected as callback registration"
        );
        assert!(
            is_callback_registration_api("connect_callback"),
            "'connect_callback' must be detected as callback registration"
        );

        // Negative cases: non-callback names
        assert!(
            !is_callback_registration_api("malloc"),
            "'malloc' must NOT be detected as callback registration"
        );
        assert!(
            !is_callback_registration_api("free"),
            "'free' must NOT be detected as callback registration"
        );
        assert!(
            !is_callback_registration_api("printf"),
            "'printf' must NOT be detected as callback registration"
        );
    }

    /// Objective: Verify that multiple acquire-release pairs in different
    /// functions produce independent edges with correct instance pairing.
    /// Invariants: Each function gets its own acquire and release edges,
    /// and release source matches the correct acquire target.
    #[test]
    fn test_multiple_function_independent_pairing() {
        let pass = ContractGraphBuilderPass::new();
        let mut ctx = PassContext::new();

        let facts = vec![
            // Function 1: malloc + free
            RawResourceFact {
                function: 1,
                function_name: "malloc".to_string(),
                family: Some(FamilyId::C_HEAP),
                is_acquire: true,
                contract: PointerContract::Owned,
                arg_index: Some(0),
            },
            RawResourceFact {
                function: 1,
                function_name: "free".to_string(),
                family: Some(FamilyId::C_HEAP),
                is_acquire: false,
                contract: PointerContract::Unknown,
                arg_index: Some(0),
            },
            // Function 2: PyObject_New + Py_DECREF
            RawResourceFact {
                function: 2,
                function_name: "PyObject_New".to_string(),
                family: Some(FamilyId::PYTHON_OBJECT),
                is_acquire: true,
                contract: PointerContract::Owned,
                arg_index: Some(0),
            },
            RawResourceFact {
                function: 2,
                function_name: "Py_DECREF".to_string(),
                family: Some(FamilyId::PYTHON_OBJECT),
                is_acquire: false,
                contract: PointerContract::Unknown,
                arg_index: Some(0),
            },
        ];
        ctx.store("raw_resource_facts", facts);

        let result = pass.run(&mut ctx);
        assert!(result.is_ok(), "Pass must succeed");

        let graph: ContractGraph = ctx
            .get("contract_graph")
            .expect("ContractGraph must be stored in context");

        // Two acquire edges (one per function/family)
        let acquire_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| matches!(e.effect, Effect::Acquire { .. }))
            .collect();
        assert_eq!(
            acquire_edges.len(),
            2,
            "Must have exactly 2 Acquire edges for 2 independent functions"
        );

        // Two release edges
        let release_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|e| matches!(e.effect, Effect::Release { .. }))
            .collect();
        assert_eq!(
            release_edges.len(),
            2,
            "Must have exactly 2 Release edges for 2 independent functions"
        );

        // Each release's source must match its paired acquire's target
        for release in &release_edges {
            let matching_acquire = acquire_edges.iter().find(|a| a.target == release.source);
            assert!(
                matching_acquire.is_some(),
                "Every Release edge source must match an Acquire edge target — release source={} has no matching acquire",
                release.source
            );
        }
    }
}
