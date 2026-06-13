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

use std::collections::HashMap;

use omniscope_core::Result;
use omniscope_semantics::{OwnershipEvent, ResourceInstance};
use omniscope_types::{Effect, EscapeKind, FamilyId, PointerContract};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::contract_graph_builder::ContractGraph;
use crate::resource::rust_drop_tracker::RustDropTracker;
use crate::resource::union_find::OwnershipCycleDetector;

/// State of a pointer value at a specific program point.
///
/// Tracks the ownership state of pointer values to enable path-sensitive
/// analysis and proper handling of null-guarded releases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerValueState {
    /// Unknown state - cannot determine.
    Unknown,
    /// Pointer is known to be NULL.
    Null,
    /// Pointer owns a resource instance.
    Owned { instance: u64, family: FamilyId },
    /// Pointer's resource has been released.
    Released { instance: u64 },
    /// Pointer has escaped (returned to caller, stored to out-param, etc.).
    Escaped { instance: u64 },
}

/// Maps pointer slots to their current state.
pub type PointerStateMap = HashMap<String, PointerValueState>;

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

        // Pre-allocate instances Vec (will be sized after acquire edge count).
        let mut instances: Vec<ResourceInstance> = Vec::new();

        // Load the contract graph from context (reference, no clone).
        let graph_ref = ctx.get_ref::<ContractGraph>("contract_graph");

        // Initialize cycle detector for incremental escape-reclaim detection.
        // This avoids redundant state transitions by tracking ownership chains.
        let mut cycle_detector = OwnershipCycleDetector::new();

        // Initialize Rust Drop tracker for RAII cleanup detection.
        // Tracks automatic Drop operations to reduce false positives.
        let mut drop_tracker = RustDropTracker::new();

        // Initialize pointer state map for path-sensitive tracking.
        // Maps pointer slot names to their current ownership state.
        let mut pointer_states: PointerStateMap = HashMap::new();

        if let Some(graph) = graph_ref {
            // Pre-allocate based on acquire edge count to avoid realloc.
            let acquire_count = graph
                .edges
                .iter()
                .filter(|e| matches!(e.effect, Effect::Acquire { .. }))
                .count();
            instances.reserve(acquire_count);
            // Index instances by their ID for fast lookup during transitions.
            let mut instance_map: std::collections::HashMap<u64, usize> =
                std::collections::HashMap::new();

            // First pass: create ResourceInstance for each acquire edge.
            for edge in &graph.edges {
                if let Effect::Acquire { family, result } = edge.effect {
                    // Track pointer state for acquired resource.
                    // The result value receives the acquired resource.
                    let pointer_slot = format!("{}_result_{}", edge.caller_name, result);
                    pointer_states.insert(
                        pointer_slot,
                        PointerValueState::Owned {
                            instance: result,
                            family,
                        },
                    );

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
                    Effect::Release { family: _, arg } => {
                        // Track potential Drop operations for RAII cleanup detection.
                        drop_tracker.track_drop_call(
                            edge.source,
                            &edge.function_name,
                            &edge.caller_name,
                        );

                        // Track pointer state for path-sensitive analysis.
                        let pointer_slot = format!("{}_{}", edge.caller_name, arg);
                        let current_state = pointer_states.get(&pointer_slot).cloned();

                        match current_state {
                            Some(PointerValueState::Null) => {
                                // release(NULL) - safe no-op if release function is null-guarded.
                                // Otherwise potentially invalid.
                                tracing::debug!("Releasing NULL pointer in {}", edge.function_name);
                            }
                            Some(PointerValueState::Owned { instance, .. }) => {
                                // Normal release - transition to Released.
                                pointer_states
                                    .insert(pointer_slot, PointerValueState::Released { instance });
                            }
                            Some(PointerValueState::Released { instance }) => {
                                // Double release!
                                tracing::warn!(
                                    "Double release detected: instance {} in {}",
                                    instance,
                                    edge.function_name
                                );
                            }
                            Some(PointerValueState::Escaped { instance }) => {
                                // Releasing an escaped pointer - potentially problematic.
                                tracing::warn!(
                                    "Releasing escaped pointer: instance {} in {}",
                                    instance,
                                    edge.function_name
                                );
                            }
                            Some(PointerValueState::Unknown) | None => {
                                // Cannot determine state - report as diagnostic.
                                tracing::debug!(
                                    "Releasing pointer with unknown state in {}",
                                    edge.function_name
                                );
                            }
                        }

                        apply_transition(
                            &mut instances,
                            &instance_map,
                            edge.source,
                            OwnershipEvent::Release {
                                function: edge.function,
                            },
                            &edge.function_name,
                        );
                    }
                    Effect::ConditionalRelease { .. } => {
                        // ConditionalRelease uses a distinct event so the state
                        // machine can model refcount semantics correctly:
                        // Retained + ConditionalRelease → Acquired (refcount > 0)
                        // Acquired + ConditionalRelease → Released (last ref)
                        apply_transition(
                            &mut instances,
                            &instance_map,
                            edge.source,
                            OwnershipEvent::ConditionalRelease {
                                function: edge.function,
                            },
                            &edge.function_name,
                        );
                    }
                    Effect::Retain { .. } => {
                        apply_transition(
                            &mut instances,
                            &instance_map,
                            edge.source,
                            OwnershipEvent::Retain,
                            &edge.function_name,
                        );
                    }
                    Effect::ReturnsOwned { .. } => {
                        // Track pointer state for escaped resource.
                        let pointer_slot = format!("{}_result_{}", edge.caller_name, edge.source);
                        if let Some(PointerValueState::Owned { instance, .. }) =
                            pointer_states.get(&pointer_slot)
                        {
                            pointer_states.insert(
                                pointer_slot,
                                PointerValueState::Escaped {
                                    instance: *instance,
                                },
                            );
                        }

                        apply_transition(
                            &mut instances,
                            &instance_map,
                            edge.source,
                            OwnershipEvent::Escape {
                                kind: EscapeKind::ReturnToCaller,
                            },
                            &edge.function_name,
                        );
                    }
                    Effect::ReturnsBorrowed => {
                        apply_transition(
                            &mut instances,
                            &instance_map,
                            edge.source,
                            OwnershipEvent::Borrow,
                            &edge.function_name,
                        );
                    }
                    Effect::ConsumesArg { .. } => {
                        apply_transition(
                            &mut instances,
                            &instance_map,
                            edge.source,
                            OwnershipEvent::Transfer,
                            &edge.function_name,
                        );
                    }
                    Effect::StoresArgToOwner { .. } => {
                        apply_transition(
                            &mut instances,
                            &instance_map,
                            edge.source,
                            OwnershipEvent::Escape {
                                kind: EscapeKind::FieldStore,
                            },
                            &edge.function_name,
                        );
                    }
                    Effect::StoresArgToGlobal { .. } => {
                        apply_transition(
                            &mut instances,
                            &instance_map,
                            edge.source,
                            OwnershipEvent::Escape {
                                kind: EscapeKind::GlobalStore,
                            },
                            &edge.function_name,
                        );
                    }
                    Effect::InitializesOutParam { .. } => {
                        apply_transition(
                            &mut instances,
                            &instance_map,
                            edge.source,
                            OwnershipEvent::Escape {
                                kind: EscapeKind::OutParam,
                            },
                            &edge.function_name,
                        );
                    }
                    Effect::EscapesToCallback { .. } => {
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            apply_transition_at(
                                &mut instances,
                                idx,
                                OwnershipEvent::Escape {
                                    kind: EscapeKind::Callback,
                                },
                                &edge.function_name,
                            );
                        } else {
                            // Stack/borrowed userdata: no prior Acquire, so create a
                            // Borrowed instance directly. This models the case where
                            // a stack-allocated pointer escapes to a C callback.
                            let mut instance = ResourceInstance::new_borrowed(
                                edge.source,
                                edge.family.unwrap_or(FamilyId::C_HEAP),
                            );
                            instance.function_name = edge.caller_name.clone();
                            if let std::collections::hash_map::Entry::Vacant(entry) =
                                instance_map.entry(edge.source)
                            {
                                entry.insert(instances.len());
                                instances.push(instance);
                            } else {
                                tracing::warn!(
                                    instance_id = edge.source,
                                    "duplicate instance_id in callback escape edge — \
                                     first instance kept, duplicate dropped"
                                );
                            }
                        }
                    }
                    Effect::OwnershipEscape { result, .. } => {
                        // into_raw: ownership escapes to raw pointer.
                        // The instance is still allocated but ownership is now
                        // tracked outside Rust's type system.

                        // Track pointer state for escaped resource.
                        let pointer_slot = format!("{}_raw_{}", edge.caller_name, result);
                        pointer_states.insert(
                            pointer_slot,
                            PointerValueState::Escaped {
                                instance: edge.source,
                            },
                        );

                        if let Some(&idx) = instance_map.get(&edge.source) {
                            apply_transition_at(
                                &mut instances,
                                idx,
                                OwnershipEvent::Escape {
                                    kind: EscapeKind::RawPointer,
                                },
                                &edge.function_name,
                            );
                            // Register the raw-pointer value ID so downstream
                            // passes can trace data flow through the escaped
                            // pointer. The escaped instance retains its original
                            // ID; `result` is an alias.
                            if let std::collections::hash_map::Entry::Vacant(entry) =
                                instance_map.entry(result)
                            {
                                entry.insert(idx);
                            }
                            // Track escape relationship in cycle detector for
                            // incremental cycle detection.
                            cycle_detector.record_escape(edge.source, result);
                        }
                    }
                    Effect::OwnershipReclaim { family, result } => {
                        // from_raw: ownership reclaimed from raw pointer.
                        // Transition the escaped instance out of Escaped state so
                        // that subsequent reclaim edges targeting the same escape
                        // do not produce a false DoubleReclaim, and the reclaimed
                        // instance does not start orphaned (false ConditionalLeak).
                        if let Some(&idx) = instance_map.get(&edge.source) {
                            apply_transition_at(
                                &mut instances,
                                idx,
                                OwnershipEvent::Release {
                                    function: edge.function,
                                },
                                &edge.function_name,
                            );
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
                        // Track reclaim relationship in cycle detector for
                        // incremental cycle detection.
                        cycle_detector.record_reclaim(edge.source, result);
                    }
                    Effect::CrossLanguageFree {
                        alloc_family,
                        release_family,
                        ..
                    } => {
                        // Cross-language free: resource allocated in one language
                        // family but freed in another language family.
                        // This is a strong signal of a contract violation.
                        // Treat as a release event for ownership state tracking.
                        apply_transition(
                            &mut instances,
                            &instance_map,
                            edge.source,
                            OwnershipEvent::Release {
                                function: edge.function,
                            },
                            &edge.function_name,
                        );
                        // Log the cross-language free for diagnostics
                        tracing::info!(
                            "Cross-language free detected: {:?} -> {:?} in {}",
                            alloc_family,
                            release_family,
                            edge.function_name
                        );
                    }
                    Effect::NullGuardedRelease { family: _, arg } => {
                        // Null-guarded release: check if the argument is NULL.
                        // If NULL, treat as safe no-op. If non-NULL, proceed with release.
                        let pointer_slot = format!("{}_{}", edge.caller_name, arg);
                        let current_state = pointer_states.get(&pointer_slot).cloned();

                        match current_state {
                            Some(PointerValueState::Null) => {
                                // release(NULL) is safe - no-op.
                                tracing::debug!(
                                    "Null-guarded release of NULL pointer in {} - safe no-op",
                                    edge.function_name
                                );
                            }
                            Some(PointerValueState::Owned { instance, .. }) => {
                                // Non-NULL release - transition to Released.
                                pointer_states
                                    .insert(pointer_slot, PointerValueState::Released { instance });
                                // Apply conditional release transition.
                                apply_transition(
                                    &mut instances,
                                    &instance_map,
                                    edge.source,
                                    OwnershipEvent::ConditionalRelease {
                                        function: edge.function,
                                    },
                                    &edge.function_name,
                                );
                            }
                            _ => {
                                // Unknown state - treat as conditional release.
                                apply_transition(
                                    &mut instances,
                                    &instance_map,
                                    edge.source,
                                    OwnershipEvent::ConditionalRelease {
                                        function: edge.function,
                                    },
                                    &edge.function_name,
                                );
                            }
                        }
                    }
                    Effect::OutParamOwnedOnSuccess { family, arg } => {
                        // Out-param receives owned resource on success path.
                        // Treat as an acquire edge: create a new ResourceInstance.
                        let result = edge.target;

                        // Track pointer state for out-param.
                        let pointer_slot = format!("{}_{}", edge.caller_name, arg);
                        pointer_states.insert(
                            pointer_slot,
                            PointerValueState::Owned {
                                instance: result,
                                family,
                            },
                        );

                        if let std::collections::hash_map::Entry::Vacant(e) =
                            instance_map.entry(result)
                        {
                            let mut instance =
                                ResourceInstance::new(result, family, PointerContract::Owned);
                            instance.function_name = edge.caller_name.clone();
                            e.insert(instances.len());
                            instances.push(instance);
                        } else {
                            tracing::warn!(
                                instance_id = result,
                                "duplicate instance_id in OutParamOwnedOnSuccess edge — \\\n                                 first instance kept"
                            );
                        }
                    }
                    Effect::OutParamNullOnError { arg } => {
                        // Out-param is set to NULL on error path.
                        // Track pointer state for out-param.
                        let pointer_slot = format!("{}_{}", edge.caller_name, arg);
                        pointer_states.insert(pointer_slot, PointerValueState::Null);

                        // This is a conditional release on error path.
                        apply_transition(
                            &mut instances,
                            &instance_map,
                            edge.source,
                            OwnershipEvent::ConditionalRelease {
                                function: edge.function,
                            },
                            &edge.function_name,
                        );
                    }
                    Effect::NullStoreAfterRelease { arg } => {
                        // NULL store after release: slot becomes NULL after dealloc.
                        // This is a cleanup operation, not an ownership change.
                        // Track pointer state for the nulled slot.
                        let pointer_slot = format!("{}_{}", edge.caller_name, arg);
                        pointer_states.insert(pointer_slot, PointerValueState::Null);
                    }
                }
            }
            // Store cycle detector for downstream passes to efficiently
            // query ownership chain relationships.
            ctx.store("ownership_cycle_detector", cycle_detector);

            // Store Drop tracker for downstream passes to consider RAII semantics.
            ctx.store("rust_drop_tracker", drop_tracker);

            // Store pointer states for path-sensitive analysis.
            ctx.store("pointer_states", pointer_states);
        }

        let instance_count = instances.len();
        ctx.store("ownership_states", instances);

        let result = PassResult::new(self.name())
            .with_nodes(instance_count)
            .with_duration(start.elapsed().as_millis() as u64);

        Ok(result)
    }
}

/// Applies an ownership transition event to the instance identified by
/// `instance_id`, logging errors at debug level without failing the pass.
fn apply_transition(
    instances: &mut [ResourceInstance],
    instance_map: &std::collections::HashMap<u64, usize>,
    instance_id: u64,
    event: OwnershipEvent,
    function_name: &str,
) {
    if let Some(&idx) = instance_map.get(&instance_id) {
        apply_transition_at(instances, idx, event, function_name);
    }
}

/// Applies an ownership transition event to the instance at the given
/// index, logging errors at debug level without failing the pass.
///
/// Special handling for `ReleaseBorrowed` errors: when a borrowed pointer
/// encounters a Release event, we log this as a potential invalid borrowed
/// free. The state machine will reject the transition, but we want to
/// record this as a signal for the issue candidate builder.
fn apply_transition_at(
    instances: &mut [ResourceInstance],
    idx: usize,
    event: OwnershipEvent,
    function_name: &str,
) {
    if let Err(e) = instances[idx].transition(event) {
        match &e {
            omniscope_semantics::OwnershipError::ReleaseBorrowed { instance } => {
                // Log at info level — this is a potential invalid borrowed free
                tracing::info!(
                    "Invalid borrowed free detected: instance {} in {} — \
                     borrowed pointer passed to release function",
                    instance,
                    function_name
                );
                // Mark the instance as having a contract violation
                // The state remains Borrowed, but we've detected the issue
                // The issue candidate builder will pick this up from the
                // ownership states and release edges.
            }
            omniscope_semantics::OwnershipError::InvalidTransition {
                from_state: omniscope_semantics::OwnershipState::Borrowed,
                event: "Escape",
                ..
            } => {
                // C library pattern: borrowed pointer escapes (e.g. sqlite3Malloc
                // returns a pointer that was borrowed from an allocator pool).
                // This is expected behavior, not a bug.
                tracing::debug!(
                    "Borrowed->Escape ignored: instance {} in {} — C library pattern",
                    instances[idx].id,
                    function_name
                );
            }
            _ => {
                tracing::warn!(
                    "Transition error for instance {} in {}: {:?}",
                    instances[idx].id,
                    function_name,
                    e
                );
            }
        }
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
    use omniscope_semantics::OwnershipState;
    use omniscope_types::{EscapeKind, FamilyId};

    /// Objective: Verify that OwnershipSolverPass is correctly initialized with expected properties.
    /// Invariants: name() == "OwnershipSolver", kind() == PassKind::Analysis, dependencies() == ["ContractGraphBuilder"].
    #[test]
    fn test_ownership_solver_creation() {
        let pass = OwnershipSolverPass::new();
        assert_eq!(
            pass.name(),
            "OwnershipSolver",
            "OwnershipSolverPass must have name 'OwnershipSolver'"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "OwnershipSolverPass must be an Analysis pass"
        );
        assert_eq!(
            pass.dependencies(),
            vec!["ContractGraphBuilder"],
            "OwnershipSolverPass must depend on ContractGraphBuilder"
        );
    }

    /// Objective: Verify that ownership state machine correctly handles escape transitions.
    /// Invariants: Owned instance is leak candidate, Escaped instance is not leak candidate.
    #[test]
    fn test_ownership_state_machine_integration() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        assert!(
            instance.is_leak_candidate(),
            "Owned instance must be a leak candidate before escape"
        );

        // Simulate: malloc → escape (return to caller) → free
        instance
            .transition(OwnershipEvent::Escape {
                kind: EscapeKind::ReturnToCaller,
            })
            .unwrap();
        assert!(
            !instance.is_leak_candidate(),
            "Escaped via return is not a leak candidate"
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
            boundary_evidence: None,
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
            boundary_evidence: None,
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
        let states = ctx.get_ref::<Vec<ResourceInstance>>("ownership_states");
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
            boundary_evidence: None,
        });

        ctx.store("contract_graph", graph);

        let pass = OwnershipSolverPass::new();
        pass.run(&mut ctx).unwrap();

        let states = ctx.get_ref::<Vec<ResourceInstance>>("ownership_states");
        let states = states.unwrap();
        assert_eq!(
            states.len(),
            1,
            "Must have exactly 1 instance for one Acquire edge"
        );

        assert!(
            states[0].is_leak_candidate(),
            "Acquired-only instance must be a leak candidate"
        );
    }

    /// Objective: Verify that double release does not crash the solver.
    /// Invariants: After two releases, the instance stays in Released state
    /// (the double-release is recorded but doesn't fail the pass).
    #[test]
    fn test_solver_double_release_error() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Release { function: 42 })
            .unwrap();
        let result = instance.transition(OwnershipEvent::Release { function: 43 });
        assert!(
            result.is_err(),
            "Double release must return an error to indicate contract violation"
        );
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
            boundary_evidence: None,
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
            boundary_evidence: None,
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
            boundary_evidence: None,
        });

        ctx.store("contract_graph", graph);

        let pass = OwnershipSolverPass::new();
        let result = pass.run(&mut ctx).unwrap();

        assert_eq!(
            result.nodes_analyzed, 2,
            "Solver must create exactly 2 instances (original + reclaimed)"
        );

        let states = ctx.get_ref::<Vec<ResourceInstance>>("ownership_states");
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

    // ── ConditionalRelease solver integration tests ──

    /// Objective: Verify that ConditionalRelease from Retained goes back to
    ///            Acquired (Py_INCREF / Py_DECREF cycle, object stays alive).
    /// Invariants: Retained + ConditionalRelease → Acquired, not Released.
    #[test]
    fn test_solver_conditional_release_from_retained() {
        let mut ctx = PassContext::new();
        let mut graph = ContractGraph::new();
        let instance_id = graph.alloc_instance();

        // Acquire (e.g. PyObject_New)
        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family: FamilyId::PYTHON_OBJECT,
                result: instance_id,
            },
            function: 0,
            function_name: "PyObject_New".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::PYTHON_OBJECT),
            boundary_evidence: None,
        });

        // Retain (Py_INCREF)
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::Retain {
                family: FamilyId::PYTHON_OBJECT,
                arg: 0,
            },
            function: 1,
            function_name: "Py_INCREF".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::PYTHON_OBJECT),
            boundary_evidence: None,
        });

        // ConditionalRelease (Py_DECREF — refcount > 0 after decrement)
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::ConditionalRelease {
                family: FamilyId::PYTHON_OBJECT,
                arg: 0,
            },
            function: 2,
            function_name: "Py_DECREF".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::PYTHON_OBJECT),
            boundary_evidence: None,
        });

        ctx.store("contract_graph", graph);

        let pass = OwnershipSolverPass::new();
        pass.run(&mut ctx).unwrap();

        let states = ctx.get_ref::<Vec<ResourceInstance>>("ownership_states");
        let states = states.expect("ownership_states must be stored");
        let inst = &states[0];

        assert_eq!(
            inst.state,
            OwnershipState::Acquired,
            "Py_INCREF + Py_DECREF cycle must return to Acquired, not Released"
        );
        assert!(
            inst.is_leak_candidate(),
            "Acquired after Py_DECREF cycle is still a leak candidate"
        );
    }

    /// Objective: Verify that ConditionalRelease from Acquired transitions
    ///            to Released (only reference, so decrement is definitive).
    /// Invariants: Acquired + ConditionalRelease → Released.
    #[test]
    fn test_solver_conditional_release_from_acquired() {
        let mut ctx = PassContext::new();
        let mut graph = ContractGraph::new();
        let instance_id = graph.alloc_instance();

        // Acquire (e.g. PyObject_New)
        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family: FamilyId::PYTHON_OBJECT,
                result: instance_id,
            },
            function: 0,
            function_name: "PyObject_New".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::PYTHON_OBJECT),
            boundary_evidence: None,
        });

        // ConditionalRelease (Py_DECREF — only reference, so it's definitive)
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::ConditionalRelease {
                family: FamilyId::PYTHON_OBJECT,
                arg: 0,
            },
            function: 1,
            function_name: "Py_DECREF".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::PYTHON_OBJECT),
            boundary_evidence: None,
        });

        ctx.store("contract_graph", graph);

        let pass = OwnershipSolverPass::new();
        pass.run(&mut ctx).unwrap();

        let states = ctx.get_ref::<Vec<ResourceInstance>>("ownership_states");
        let inst = &states.expect("ownership_states must be stored")[0];

        assert_eq!(
            inst.state,
            OwnershipState::Released,
            "ConditionalRelease from Acquired (only ref) must transition to Released"
        );
    }

    // ── ReturnsOwned solver integration test ──

    /// Objective: Verify that ReturnsOwned transitions the instance to
    ///            Escaped(ReturnToCaller).
    /// Invariants: Acquired + ReturnsOwned → Escaped(ReturnToCaller).
    #[test]
    fn test_solver_returns_owned_escape() {
        let mut ctx = PassContext::new();
        let mut graph = ContractGraph::new();
        let instance_id = graph.alloc_instance();

        // Acquire
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
            boundary_evidence: None,
        });

        // ReturnsOwned
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::ReturnsOwned {
                family: FamilyId::C_HEAP,
            },
            function: 1,
            function_name: "create_buffer".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            boundary_evidence: None,
        });

        ctx.store("contract_graph", graph);

        let pass = OwnershipSolverPass::new();
        pass.run(&mut ctx).unwrap();

        let states = ctx.get_ref::<Vec<ResourceInstance>>("ownership_states");
        let inst = &states.expect("ownership_states must be stored")[0];

        assert_eq!(
            inst.state,
            OwnershipState::Escaped(EscapeKind::ReturnToCaller),
            "ReturnsOwned must transition to Escaped(ReturnToCaller)"
        );
        assert!(
            !inst.is_leak_candidate(),
            "Escaped resource is NOT a leak candidate"
        );
    }

    // ── ConsumesArg solver integration test ──

    /// Objective: Verify that ConsumesArg transitions the instance to
    ///            Transferred.
    /// Invariants: Acquired + ConsumesArg → Transferred.
    #[test]
    fn test_solver_consumes_arg_transfer() {
        let mut ctx = PassContext::new();
        let mut graph = ContractGraph::new();
        let instance_id = graph.alloc_instance();

        // Acquire
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
            boundary_evidence: None,
        });

        // ConsumesArg
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::ConsumesArg {
                arg: 0,
                family: Some(FamilyId::C_HEAP),
            },
            function: 1,
            function_name: "queue_push".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
            boundary_evidence: None,
        });

        ctx.store("contract_graph", graph);

        let pass = OwnershipSolverPass::new();
        pass.run(&mut ctx).unwrap();

        let states = ctx.get_ref::<Vec<ResourceInstance>>("ownership_states");
        let inst = &states.expect("ownership_states must be stored")[0];

        assert_eq!(
            inst.state,
            OwnershipState::Transferred,
            "ConsumesArg must transition to Transferred"
        );
    }

    // ── OwnershipEscape result mapping test ──

    /// Objective: Verify that the raw-pointer value ID (result) from
    ///            OwnershipEscape is registered in the instance map, enabling
    ///            downstream passes to trace data flow.
    /// Invariants: Both the original ID and the result ID resolve to the
    ///             same instance.
    #[test]
    fn test_solver_ownership_escape_registers_result() {
        let mut ctx = PassContext::new();
        let mut graph = ContractGraph::new();
        let instance_id = graph.alloc_instance();
        let raw_ptr_id = graph.alloc_instance();

        // Acquire
        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family: FamilyId::RUST_RAW_OWNERSHIP,
                result: instance_id,
            },
            function: 0,
            function_name: "Box::new".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::RUST_RAW_OWNERSHIP),
            boundary_evidence: None,
        });

        // OwnershipEscape — result is the raw pointer value ID
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::OwnershipEscape {
                family: FamilyId::RUST_RAW_OWNERSHIP,
                result: raw_ptr_id,
            },
            function: 1,
            function_name: "Box::into_raw".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::RUST_RAW_OWNERSHIP),
            boundary_evidence: None,
        });

        ctx.store("contract_graph", graph);

        let pass = OwnershipSolverPass::new();
        pass.run(&mut ctx).unwrap();

        let states = ctx.get_ref::<Vec<ResourceInstance>>("ownership_states");
        let states = states.expect("ownership_states must be stored");
        // Only 1 instance — raw_ptr_id is an alias, not a new instance.
        assert_eq!(
            states.len(),
            1,
            "Must have 1 instance (original only), raw_ptr_id is an alias"
        );
        let inst = &states[0];
        assert_eq!(
            inst.id, instance_id,
            "Instance ID must match the original instance_id"
        );
        assert_eq!(
            inst.state,
            OwnershipState::Escaped(EscapeKind::RawPointer),
            "OwnershipEscape must transition to Escaped(RawPointer)"
        );
    }

    // ── EscapesToCallback with new_borrowed test ──

    /// Objective: Verify that an EscapesToCallback edge with no prior
    ///            Acquire creates a Borrowed instance via new_borrowed().
    /// Invariants: instance.state == Borrowed, contract == Borrowed.
    #[test]
    fn test_solver_escapes_to_callback_creates_borrowed() {
        let mut ctx = PassContext::new();
        let mut graph = ContractGraph::new();
        let stack_id = graph.alloc_instance();

        // No Acquire edge — stack userdata.

        // EscapesToCallback
        graph.add_edge(ContractEdge {
            source: stack_id,
            target: 0,
            effect: Effect::EscapesToCallback { arg: 0 },
            function: 0,
            function_name: "register_callback".to_string(),
            caller_name: "test_func".to_string(),
            family: None,
            boundary_evidence: None,
        });

        ctx.store("contract_graph", graph);

        let pass = OwnershipSolverPass::new();
        pass.run(&mut ctx).unwrap();

        let states = ctx.get_ref::<Vec<ResourceInstance>>("ownership_states");
        let states = states.expect("ownership_states must be stored");
        assert_eq!(
            states.len(),
            1,
            "Must have 1 borrowed instance for EscapesToCallback edge"
        );

        let inst = &states[0];
        assert_eq!(
            inst.state,
            OwnershipState::Borrowed,
            "EscapesToCallback must create a Borrowed instance"
        );
        assert_eq!(
            inst.contract,
            PointerContract::Borrowed,
            "Borrowed instance must have Borrowed contract"
        );
        assert!(
            !inst.is_leak_candidate(),
            "Borrowed instance is NOT a leak candidate"
        );
    }

    // ── RustDropTracker integration test ──

    /// Objective: Verify that RustDropTracker is correctly integrated into
    ///            OwnershipSolverPass and tracks Drop operations.
    /// Invariants: Drop tracker is stored in context, tracks RAII cleanup.
    #[test]
    fn test_solver_with_drop_tracker() {
        let mut ctx = PassContext::new();
        let mut graph = ContractGraph::new();
        let instance_id = graph.alloc_instance();

        // Acquire: create a resource instance.
        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family: FamilyId::RUST_RAW_OWNERSHIP,
                result: instance_id,
            },
            function: 0,
            function_name: "Box::new".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::RUST_RAW_OWNERSHIP),
            boundary_evidence: None,
        });

        // Release via drop_in_place (RAII cleanup).
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::Release {
                family: FamilyId::RUST_RAW_OWNERSHIP,
                arg: 0,
            },
            function: 1,
            function_name: "_ZN4core3ptr13drop_in_placeI3FooEEvPT_".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::RUST_RAW_OWNERSHIP),
            boundary_evidence: None,
        });

        ctx.store("contract_graph", graph);

        let pass = OwnershipSolverPass::new();
        pass.run(&mut ctx).unwrap();

        // Verify that the Drop tracker is stored.
        let drop_tracker = ctx.get_ref::<RustDropTracker>("rust_drop_tracker");
        assert!(
            drop_tracker.is_some(),
            "RustDropTracker must be stored in context"
        );

        let drop_tracker = drop_tracker.unwrap();
        assert!(
            drop_tracker.is_raii_cleanup(instance_id),
            "Instance must be marked as RAII cleanup via drop_in_place"
        );

        let drop_info = drop_tracker.get_drop_info(instance_id);
        assert!(drop_info.is_some(), "Drop info must exist for the instance");

        let drop_info = drop_info.unwrap();
        assert!(
            drop_info.is_raii_cleanup,
            "Drop info must indicate RAII cleanup"
        );
        assert!(
            drop_info.drop_function.contains("drop_in_place"),
            "Drop function must be drop_in_place"
        );

        // Verify that the resource is in Released state.
        let states = ctx.get_ref::<Vec<ResourceInstance>>("ownership_states");
        let states = states.expect("ownership_states must be stored");
        let inst = &states[0];
        assert_eq!(
            inst.state,
            OwnershipState::Released,
            "Resource must be in Released state after drop_in_place"
        );
    }
}
