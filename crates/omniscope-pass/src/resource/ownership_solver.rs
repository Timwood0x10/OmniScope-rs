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
use omniscope_types::{Effect, EscapeKind, PointerContract};

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
                    let instance = ResourceInstance::new(result, family, PointerContract::Owned);
                    instance_map.insert(result, instances.len());
                    instances.push(instance);
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
                            }
                        }
                        let _ = arg; // suppress unused warning
                    }
                    Effect::Retain { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            let _ = instances[idx].transition(OwnershipEvent::Retain);
                        }
                    }
                    Effect::ReturnsOwned { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            let _ = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::ReturnToCaller,
                            });
                        }
                    }
                    Effect::ReturnsBorrowed => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            instances[idx].state = OwnershipState::Borrowed;
                        }
                    }
                    Effect::ConsumesArg { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            let _ = instances[idx].transition(OwnershipEvent::Transfer);
                        }
                    }
                    Effect::StoresArgToOwner { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            let _ = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::FieldStore,
                            });
                        }
                    }
                    Effect::StoresArgToGlobal { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            let _ = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::GlobalStore,
                            });
                        }
                    }
                    Effect::InitializesOutParam { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            let _ = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::OutParam,
                            });
                        }
                    }
                    Effect::EscapesToCallback { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            let _ = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::Callback,
                            });
                        }
                    }
                    Effect::OwnershipEscape { .. } => {
                        // into_raw: ownership escapes to raw pointer.
                        // The instance is still allocated but ownership is now
                        // tracked outside Rust's type system.
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            let _ = instances[idx].transition(OwnershipEvent::Escape {
                                kind: EscapeKind::ReturnToCaller,
                            });
                        }
                    }
                    Effect::OwnershipReclaim { family, result } => {
                        // from_raw: ownership reclaimed from raw pointer.
                        // Create a new ResourceInstance for the reclaimed resource.
                        let instance =
                            ResourceInstance::new(result, family, PointerContract::Owned);
                        instance_map.insert(result, instances.len());
                        instances.push(instance);
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
}
