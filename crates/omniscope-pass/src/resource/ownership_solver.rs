//! Ownership solver pass for resource contract analysis.
//!
//! Runs ownership state propagation across the contract graph.
//! Each resource instance transitions through the ownership state
//! machine based on the effects applied to it.

use omniscope_core::Result;

use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// Ownership solver pass.
///
/// Propagates ownership states across the contract graph.
/// In a full implementation, this would:
/// 1. Load the contract graph
/// 2. Create ResourceInstances for each acquire
/// 3. Apply transitions for each release/escape/transfer
/// 4. Store the resulting ownership states
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

    fn run(&self, _ctx: &mut PassContext) -> Result<PassResult> {
        // In a full implementation, we would:
        // 1. Load contract_graph from context
        // 2. Create ResourceInstance for each acquire edge
        // 3. Apply ownership state transitions for each effect edge
        // 4. Collect instances in Acquired/Retained/Unknown state as leak candidates
        // 5. Store ownership states in context

        let result = PassResult::new(self.name()).with_nodes(0).with_duration(0);

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
    use omniscope_semantics::{OwnershipEvent, ResourceInstance};
    use omniscope_types::{EscapeKind, FamilyId, PointerContract};

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
}
