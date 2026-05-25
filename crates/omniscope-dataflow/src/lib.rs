//! OmniScope Dataflow - Dataflow analysis engine

pub mod graph;

pub use graph::DataFlowGraph;

#[cfg(test)]
mod tests {
    #[test]
    fn test_dataflow_module() {
        assert!(true);
    }
}
