//! Ownership solver pass for resource contract analysis.
//!
//! Runs ownership state propagation across the contract graph.
//! Each resource instance transitions through the ownership state
//! machine based on the effects applied to it.
//!
//! # Output
//!
//! Stores `ownership_states: Vec<ResourceInstance>` in the pass context,
//! which downstream passes (especially `IssueCandidateBuilder`) consume
//! to detect leak candidates, double-release, and borrow-escape issues.

use omniscope_core::Result;
use omniscope_semantics::{OwnershipEvent, OwnershipState, ResourceInstance};
use omniscope_types::{Effect, EscapeKind, FamilyId, PointerContract};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::contract_graph_builder::ContractGraph;

/// Ownership solver pass.
///
/// Propagates ownership states across the contract graph.
/// For each resource instance in the contract graph:
/// 1. Create a `ResourceInstance` for each acquire edge.
/// 2. Apply ownership state transitions for each effect edge.
/// 3. Collect instances and store them in the pass context.
pub struct OwnershipSolverPass;

impl OwnershipSolverPass {
    /// Creates a new ownership solver pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for OwnershipSolverPass {
    fn name(&self) -> &'static str {
        "OwnershipSolver"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["ContractGraphBuilder"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        let mut instances: Vec<ResourceInstance> = Vec::new();

        // Load the contract graph from context.
        let graph: Option<ContractGraph> = ctx.get("contract_graph");

        if let Some(ref graph) = graph {
            // Index instances by their ID for fast lookup during transitions.
            let mut instance_map: std::collections::HashMap<u64, usize> =
                std::collections::HashMap::new();

            // First pass: create ResourceInstance for each acquire edge.
            for edge in &graph.edges {
                if let Effect::Acquire { family, result } = edge.effect {
                    if let std::collections::hash_map::Entry::Vacant(e) = instance_map.entry(result)
                    {
                        let mut instance =
                            ResourceInstance::new(result, family, PointerContract::Owned);
                        instance.function_name = edge.caller_name.clone();
                        e.insert(instances.len());
                        instances.push(instance);
                    } else {
                        tracing::warn!(
                            instance_id = result,
                            "duplicate instance_id in acquire edge — first instance kept"
                        );
                    }
                }
            }

            // Second pass: apply transitions for release/escape/transfer edges.
            for edge in &graph.edges {
                match edge.effect {
                    Effect::Acquire { .. } => {
                        // Already handled above.
                    }
                    Effect::Release { arg, .. } | Effect::ConditionalRelease { arg, .. } => {
                        // The source field holds the instance ID for release edges.
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            let instance = &mut instances[idx];
                            // If the instance is already released, the transition will
                            // return DoubleRelease error — we record it but don't fail.
                            match instance.transition(OwnershipEvent::Release {
                                function: edge.function,
                            }) {
                                Ok(()) => {}
                                Err(omniscope_semantics::OwnershipError::DoubleRelease {
                                    ..
                                }) => {
                                    tracing::debug!(
                                        "DoubleRelease detected for instance {} in function {}",
                                        edge.source,
                                        edge.function_name
                                    );
                                    // Keep the instance in Released state — the candidate
                                    // builder will generate a DoubleRelease candidate from
                                    // the contract graph edge count.
                                }
                                Err(omniscope_semantics::OwnershipError::ReleaseBorrowed {
                                    ..
                                }) => {
                                    tracing::debug!(
                                        "ReleaseBorrowed detected for instance {} in function {}",
                                        edge.source,
                                        edge.function_name
                                    );
                                }
                                Err(omniscope_semantics::OwnershipError::InvalidTransition {
                                    from_state,
                                    event,
                                    ..
                                }) => {
                                    tracing::debug!(
                                        "Invalid Release transition for instance {} from {:?} \
                                         in function {} (event: {})",
                                        edge.source,
                                        from_state,
                                        edge.function_name,
                                        event
                                    );
                                }
                            }
                        }
                        let _ = arg; // suppress unused warning
                    }
                    Effect::Retain { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            if let Err(e) = instances[idx].transition(OwnershipEvent::Retain) {
                                tracing::debug!(
                                    "Retain transition error for instance {}: {:?} in function {}",
                                    edge.source,
                                    e,
                                    edge.function_name
                                );
                            }
                        }
                    }
                    Effect::ReturnsOwned { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            if let Err(e) = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::ReturnToCaller,
                            }) {
                                tracing::debug!(
                                    "Escape(ReturnToCaller) transition error for instance {}: \
                                     {:?} in function {}",
                                    edge.source,
                                    e,
                                    edge.function_name
                                );
                            }
                        }
                    }
                    Effect::ReturnsBorrowed => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            if let Err(e) = instances[idx].transition(OwnershipEvent::Borrow) {
                                tracing::debug!(
                                    "Borrow transition error for instance {}: {:?} in function {}",
                                    edge.source,
                                    e,
                                    edge.function_name
                                );
                            }
                        }
                    }
                    Effect::ConsumesArg { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            if let Err(e) = instances[idx].transition(OwnershipEvent::Transfer) {
                                tracing::debug!(
                                    "Transfer transition error for instance {}: {:?} in function {}",
                                    edge.source,
                                    e,
                                    edge.function_name
                                );
                            }
                        }
                    }
                    Effect::StoresArgToOwner { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            if let Err(e) = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::FieldStore,
                            }) {
                                tracing::debug!(
                                    "Escape(FieldStore) transition error for instance {}: \
                                     {:?} in function {}",
                                    edge.source,
                                    e,
                                    edge.function_name
                                );
                            }
                        }
                    }
                    Effect::StoresArgToGlobal { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            if let Err(e) = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::GlobalStore,
                            }) {
                                tracing::debug!(
                                    "Escape(GlobalStore) transition error for instance {}: \
                                     {:?} in function {}",
                                    edge.source,
                                    e,
                                    edge.function_name
                                );
                            }
                        }
                    }
                    Effect::InitializesOutParam { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            if let Err(e) = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::OutParam,
                            }) {
                                tracing::debug!(
                                    "Escape(OutParam) transition error for instance {}: \
                                     {:?} in function {}",
                                    edge.source,
                                    e,
                                    edge.function_name
                                );
                            }
                        }
                    }
                    Effect::EscapesToCallback { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            if let Err(e) = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::Callback,
                            }) {
                                tracing::debug!(
                                    "Escape(Callback) transition error for instance {}: \
                                     {:?} in function {}",
                                    edge.source,
                                    e,
                                    edge.function_name
                                );
                            }
                        } else {
                            // Stack/borrowed userdata: no prior Acquire, so create a
                            // Borrowed instance directly. This models the case where
                            // a stack-allocated pointer escapes to a C callback.
                            // Note: ResourceInstance::new() always starts in Acquired,
                            // so we must explicitly transition to Borrowed.
                            let mut instance = ResourceInstance::new(
                                edge.source,
                                edge.family.unwrap_or(FamilyId::C_HEAP),
                                PointerContract::Borrowed,
                            );
                            instance.state = OwnershipState::Borrowed;
                            instance.function_name = edge.caller_name.clone();
                            if let std::collections::hash_map::Entry::Vacant(entry) =
                                instance_map.entry(edge.source)
                            {
                                entry.insert(instances.len());
                                instances.push(instance);
                            } else {
                                tracing::warn!(
                                    instance_id = edge.source,
                                    "duplicate instance_id in callback escape edge — first instance kept, duplicate dropped"
                                );
                            }
                        }
                    }
                    Effect::OwnershipEscape { .. } => {
                        // into_raw: ownership escapes to raw pointer.
                        // The instance is still allocated but ownership is now
                        // tracked outside Rust's type system.
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            if let Err(e) = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::RawPointer,
                            }) {
                                tracing::debug!(
                                    "Escape(RawPointer) transition error for instance {}: \
                                     {:?} in function {}",
                                    edge.source,
                                    e,
                                    edge.function_name
                                );
                            }
                        }
                    }
                    Effect::OwnershipReclaim { family, result } => {
                        // from_raw: ownership reclaimed from raw pointer.
                        // Transition the escaped instance out of Escaped state so that
                        // subsequent reclaim edges targeting the same escape do not
                        // produce a false DoubleReclaim, and the reclaimed instance
                        // does not start orphaned (false ConditionalLeak).
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            match instances[idx].transition(OwnershipEvent::Release {
                                function: edge.function,
                            }) {
                                Ok(()) => {}
                                Err(omniscope_semantics::OwnershipError::DoubleRelease {
                                    ..
                                }) => {
                                    tracing::debug!(
                                        "DoubleRelease detected for escaped instance {} \
                                         during reclaim in function {}",
                                        edge.source,
                                        edge.function_name
                                    );
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        "Release transition error for escaped instance {} \
                                         during reclaim in function {}: {:?}",
                                        edge.source,
                                        edge.function_name,
                                        e
                                    );
                                }
                            }
                        }
                        // Create a new ResourceInstance for the reclaimed resource.
                        let mut instance =
                            ResourceInstance::new(result, family, PointerContract::Owned);
                        instance.function_name = edge.caller_name.clone();
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            instance_map.entry(result)
                        {
                            entry.insert(instances.len());
                            instances.push(instance);
                        } else {
                            tracing::warn!(
                                instance_id = result,
                                "duplicate instance_id in reclaim edge — first instance kept"
                            );
                        }
                    }
                }
            }
        }

        let instance_count = instances.len();
        ctx.store("ownership_states", instances);

        let result = PassResult::new(self.name())
            .with_nodes(instance_count)
            .with_duration(start.elapsed().as_millis() as u64);

        Ok(result)
    }
}

impl Default for OwnershipSolverPass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pass::PassContext;
    use crate::resource::contract_graph_builder::ContractEdge;
    use omniscope_types::FamilyId;

    #[test]
    fn test_ownership_solver_creation() {
        let pass = OwnershipSolverPass::new();
        assert_eq!(pass.name(), "OwnershipSolver");
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert_eq!(pass.dependencies(), vec!["ContractGraphBuilder"]);
    }

    #[test]
    fn test_ownership_state_machine_integration() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        assert!(instance.is_leak_candidate());

        // Simulate: malloc → escape (return to caller) → free
        instance
            .transition(OwnershipEvent::Escape {
                kind: EscapeKind::ReturnToCaller,
            })
            .unwrap();
        assert!(
            !instance.is_leak_candidate(),
            "Escaped via return is not a leak"
        );
    }

    #[test]
    fn test_solver_with_contract_graph() {
        // Objective: Verify that the solver correctly creates instances
        // from the contract graph and applies state transitions.
        // Invariants: acquire→release = Released state, acquire only = leak candidate.
        let mut ctx = PassContext::new();

        // Build a contract graph with one malloc→free pair.
        let mut graph = ContractGraph::new();
        let instance_id = graph.alloc_instance();

        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family: FamilyId::C_HEAP,
                result: instance_id,
            },
            function: 0,
            function_name: "malloc".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
        });

        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::Release {
                family: FamilyId::C_HEAP,
                arg: 0,
            },
            function: 1,
            function_name: "free".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
        });

        ctx.store("contract_graph", graph);

        // Run the solver
        let pass = OwnershipSolverPass::new();
        let result = pass.run(&mut ctx).unwrap();

        assert_eq!(
            result.nodes_analyzed, 1,
            "Solver must create exactly 1 instance"
        );

        // Check the ownership state
        let states: Option<Vec<ResourceInstance>> = ctx.get("ownership_states");
        assert!(
            states.is_some(),
            "ownership_states must be stored in context"
        );

        let states = states.unwrap();
        assert_eq!(states.len(), 1, "Must have 1 resource instance");

        let inst = &states[0];
        assert_eq!(
            inst.state,
            OwnershipState::Released,
            "malloc→free must result in Released state"
        );
        assert!(
            !inst.is_leak_candidate(),
            "Released instance must NOT be a leak candidate"
        );
    }

    #[test]
    fn test_solver_leak_candidate_acquired_only() {
        // Objective: Verify that an acquire-only graph produces a leak candidate.
        // Invariants: Acquired state without release = leak candidate.
        let mut ctx = PassContext::new();

        let mut graph = ContractGraph::new();
        let instance_id = graph.alloc_instance();

        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family: FamilyId::C_HEAP,
                result: instance_id,
            },
            function: 0,
            function_name: "malloc".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
        });

        ctx.store("contract_graph", graph);

        let pass = OwnershipSolverPass::new();
        pass.run(&mut ctx).unwrap();

        let states: Option<Vec<ResourceInstance>> = ctx.get("ownership_states");
        let states = states.unwrap();
        assert_eq!(states.len(), 1);

        assert!(
            states[0].is_leak_candidate(),
            "Acquired-only instance must be a leak candidate"
        );
    }

    #[test]
    fn test_solver_double_release_error() {
        // Objective: Verify that double release does not crash the solver.
        // Invariants: After two releases, the instance stays in Released state
        // (the double-release is recorded but doesn't fail the pass).
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Release { function: 42 })
            .unwrap();
        let result = instance.transition(OwnershipEvent::Release { function: 43 });
        assert!(result.is_err(), "Double release must be an error");
    }

    #[test]
    fn test_solver_reclaim_transitions_escaped_instance_to_released() {
        // Objective: Verify that an escape+reclaim cycle transitions the
        // escaped instance to Released state. Without the fix, the escaped
        // instance stays in Escaped(RawPointer) forever, which can cause
        // false DoubleReclaim and false ConditionalLeak.
        let mut ctx = PassContext::new();

        let mut graph = ContractGraph::new();
        let instance_id = graph.alloc_instance();
        let reclaimed_id = graph.alloc_instance();

        // Acquire: create the original resource instance.
        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family: FamilyId::C_HEAP,
                result: instance_id,
            },
            function: 0,
            function_name: "malloc".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
        });

        // Escape: ownership escapes to a raw pointer (into_raw).
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::OwnershipEscape {
                family: FamilyId::C_HEAP,
                result: instance_id,
            },
            function: 1,
            function_name: "into_raw".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
        });

        // Reclaim: ownership reclaimed from the raw pointer (from_raw).
        // edge.source is the escaped instance ID; result is the new instance.
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: reclaimed_id,
            effect: Effect::OwnershipReclaim {
                family: FamilyId::C_HEAP,
                result: reclaimed_id,
            },
            function: 2,
            function_name: "from_raw".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
        });

        ctx.store("contract_graph", graph);

        let pass = OwnershipSolverPass::new();
        let result = pass.run(&mut ctx).unwrap();

        assert_eq!(
            result.nodes_analyzed, 2,
            "Solver must create exactly 2 instances (original + reclaimed)"
        );

        let states: Option<Vec<ResourceInstance>> = ctx.get("ownership_states");
        let states = states.expect("ownership_states must be stored in context");
        assert_eq!(states.len(), 2, "Must have 2 resource instances");

        // Find the original (escaped) instance and the reclaimed instance.
        let original = states
            .iter()
            .find(|i| i.id == instance_id)
            .expect("Original instance must exist");
        let reclaimed = states
            .iter()
            .find(|i| i.id == reclaimed_id)
            .expect("Reclaimed instance must exist");

        assert_eq!(
            original.state,
            OwnershipState::Released,
            "Escaped instance must be transitioned to Released after reclaim"
        );
        assert_eq!(
            reclaimed.state,
            OwnershipState::Acquired,
            "Reclaimed instance must start in Acquired state"
        );
    }
}
