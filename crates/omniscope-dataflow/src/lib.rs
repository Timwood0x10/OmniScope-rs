//! OmniScope Dataflow - Dataflow analysis engine
//!
//! This crate provides dataflow analysis infrastructure for OmniScope,
//! including:
//!
//! - Dataflow graph construction
//! - Forward and backward analysis
//! - Path-sensitive analysis support

pub mod analysis;
pub mod graph;

// Re-exports
pub use analysis::{AnalysisDomain, BackwardAnalysis, ForwardAnalysis};
pub use graph::{DataEdge, DataFlowGraph, DataNode, EdgeType, MemoryLocation, ValueType};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dataflow_module_exports() {
        let _graph = DataFlowGraph::new();
    }
}
