//! Contract graph builder pass for resource contract analysis.
//!
//! Builds the resource contract graph from raw facts and summaries.
//! The graph captures edges between resource instances: acquire→release,
//! acquire→escape, acquire→transfer, etc.

use omniscope_core::Result;
use omniscope_types::{Effect, FunctionId};

use crate::pass::{Pass, PassContext, PassKind, PassResult};

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
/// summaries. In a full implementation, this would iterate over
/// all function calls and create edges based on effects.
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
        vec!["SummaryBuilder"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        let graph = ContractGraph::new();

        // In a full implementation, we would:
        // 1. Iterate over all functions in the IR
        // 2. Look up summaries for each callee
        // 3. Create resource instances for Acquire effects
        // 4. Create contract edges for Release/Escape/Transfer effects
        // 5. Link edges to CrossLangEdge / FFI boundary evidence

        ctx.store("contract_graph", graph.clone());

        let result = PassResult::new(self.name())
            .with_nodes(graph.edge_count())
            .with_duration(start.elapsed().as_millis() as u64);

        Ok(result)
    }
}

impl Default for ContractGraphBuilderPass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_graph_builder_creation() {
        let pass = ContractGraphBuilderPass::new();
        assert_eq!(pass.name(), "ContractGraphBuilder");
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert_eq!(pass.dependencies(), vec!["SummaryBuilder"]);
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
        });

        assert_eq!(
            graph.edge_count(),
            1,
            "Graph should have one edge after adding"
        );
    }
}
