//! Dataflow analysis framework
//!
//! This module provides the framework for performing forward and backward
//! dataflow analysis.

use crate::graph::{DataFlowGraph, DataNode};
use omniscope_types::NodeId;
use std::collections::HashMap;

/// Analysis domain trait
pub trait AnalysisDomain: Clone {
    /// The type of dataflow values
    type Value: Clone;

    /// Returns the initial value for the analysis
    fn initial(&self) -> Self::Value;

    /// Returns the bottom (least) element
    fn bottom(&self) -> Self::Value;

    /// Returns the top (greatest) element
    fn top(&self) -> Self::Value;

    /// Computes the join (least upper bound) of two values
    fn join(&self, a: &Self::Value, b: &Self::Value) -> Self::Value;

    /// Computes the meet (greatest lower bound) of two values
    fn meet(&self, a: &Self::Value, b: &Self::Value) -> Self::Value;

    /// Transfer function for a node
    fn transfer(&self, node: &DataNode, input: &Self::Value) -> Self::Value;
}

/// Forward dataflow analysis
pub struct ForwardAnalysis<D: AnalysisDomain> {
    /// Analysis domain
    domain: D,
    /// Input values for each node
    inputs: HashMap<NodeId, D::Value>,
    /// Output values for each node
    outputs: HashMap<NodeId, D::Value>,
}

impl<D: AnalysisDomain> ForwardAnalysis<D> {
    /// Creates a new forward analysis
    pub fn new(domain: D) -> Self {
        Self {
            domain,
            inputs: HashMap::new(),
            outputs: HashMap::new(),
        }
    }

    /// Runs the forward analysis
    pub fn run(&mut self, graph: &DataFlowGraph) {
        // Initialize all nodes with bottom
        for node in graph.all_nodes() {
            self.inputs.insert(node.id, self.domain.bottom());
            self.outputs.insert(node.id, self.domain.bottom());
        }

        // Set entry node to initial value
        if let Some(entry) = graph.entry() {
            self.inputs.insert(entry, self.domain.initial());
        }

        // Iterate until fixpoint
        let mut changed = true;
        while changed {
            changed = false;

            for node in graph.all_nodes() {
                // Compute input as join of all predecessor outputs
                let preds = graph.predecessors(node.id);
                let input = if preds.is_empty() {
                    self.domain.bottom()
                } else {
                    preds
                        .iter()
                        .map(|&pred| {
                            self.outputs
                                .get(&pred)
                                .cloned()
                                .unwrap_or_else(|| self.domain.bottom())
                        })
                        .fold(self.domain.bottom(), |acc, val| {
                            self.domain.join(&acc, &val)
                        })
                };

                // Update input if changed
                if let Some(old_input) = self.inputs.get(&node.id) {
                    let new_input = self.domain.join(old_input, &input);
                    if self.inputs.insert(node.id, new_input.clone()).is_some() {
                        changed = true;
                    }
                }

                // Compute output using transfer function
                let output = self.domain.transfer(&node, &input);

                // Update output if changed
                if let Some(old_output) = self.outputs.get(&node.id) {
                    let new_output = self.domain.join(old_output, &output);
                    if self.outputs.insert(node.id, new_output).is_some() {
                        changed = true;
                    }
                }
            }
        }
    }

    /// Gets the input value for a node
    pub fn get_input(&self, node_id: NodeId) -> Option<&D::Value> {
        self.inputs.get(&node_id)
    }

    /// Gets the output value for a node
    pub fn get_output(&self, node_id: NodeId) -> Option<&D::Value> {
        self.outputs.get(&node_id)
    }
}

/// Backward dataflow analysis
pub struct BackwardAnalysis<D: AnalysisDomain> {
    /// Analysis domain
    domain: D,
    /// Input values for each node
    inputs: HashMap<NodeId, D::Value>,
    /// Output values for each node
    outputs: HashMap<NodeId, D::Value>,
}

impl<D: AnalysisDomain> BackwardAnalysis<D> {
    /// Creates a new backward analysis
    pub fn new(domain: D) -> Self {
        Self {
            domain,
            inputs: HashMap::new(),
            outputs: HashMap::new(),
        }
    }

    /// Runs the backward analysis
    pub fn run(&mut self, graph: &DataFlowGraph) {
        // Initialize all nodes with top
        for node in graph.all_nodes() {
            self.inputs.insert(node.id, self.domain.top());
            self.outputs.insert(node.id, self.domain.top());
        }

        // Set exit node to initial value
        if let Some(exit) = graph.exit() {
            self.outputs.insert(exit, self.domain.initial());
        }

        // Iterate until fixpoint
        let mut changed = true;
        while changed {
            changed = false;

            for node in graph.all_nodes() {
                // Compute output as meet of all successor inputs
                let succs = graph.successors(node.id);
                let output = if succs.is_empty() {
                    self.domain.top()
                } else {
                    succs
                        .iter()
                        .map(|&succ| {
                            self.inputs
                                .get(&succ)
                                .cloned()
                                .unwrap_or_else(|| self.domain.top())
                        })
                        .fold(self.domain.top(), |acc, val| self.domain.meet(&acc, &val))
                };

                // Update output if changed
                if let Some(old_output) = self.outputs.get(&node.id) {
                    let new_output = self.domain.meet(old_output, &output);
                    if self.outputs.insert(node.id, new_output.clone()).is_some() {
                        changed = true;
                    }
                }

                // Compute input using transfer function
                let input = self.domain.transfer(&node, &output);

                // Update input if changed
                if let Some(old_input) = self.inputs.get(&node.id) {
                    let new_input = self.domain.meet(old_input, &input);
                    if self.inputs.insert(node.id, new_input).is_some() {
                        changed = true;
                    }
                }
            }
        }
    }

    /// Gets the input value for a node
    pub fn get_input(&self, node_id: NodeId) -> Option<&D::Value> {
        self.inputs.get(&node_id)
    }

    /// Gets the output value for a node
    pub fn get_output(&self, node_id: NodeId) -> Option<&D::Value> {
        self.outputs.get(&node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple constant propagation domain
    #[derive(Clone)]
    struct ConstantProp;

    impl AnalysisDomain for ConstantProp {
        type Value = Option<i64>;

        fn initial(&self) -> Self::Value {
            None // Unknown
        }

        fn bottom(&self) -> Self::Value {
            None // Unknown
        }

        fn top(&self) -> Self::Value {
            None // Unknown
        }

        fn join(&self, a: &Self::Value, b: &Self::Value) -> Self::Value {
            match (a, b) {
                (Some(v1), Some(v2)) if v1 == v2 => Some(*v1),
                _ => None,
            }
        }

        fn meet(&self, a: &Self::Value, b: &Self::Value) -> Self::Value {
            match (a, b) {
                (Some(v1), Some(v2)) if v1 == v2 => Some(*v1),
                (Some(v), None) | (None, Some(v)) => Some(*v),
                _ => None,
            }
        }

        fn transfer(&self, _node: &DataNode, input: &Self::Value) -> Self::Value {
            *input
        }
    }

    #[test]
    fn test_forward_analysis() {
        let graph = DataFlowGraph::new();
        let domain = ConstantProp;
        let mut analysis = ForwardAnalysis::new(domain);

        // Empty graph should complete without panic
        analysis.run(&graph);
    }

    #[test]
    fn test_backward_analysis() {
        let graph = DataFlowGraph::new();
        let domain = ConstantProp;
        let mut analysis = BackwardAnalysis::new(domain);

        // Empty graph should complete without panic
        analysis.run(&graph);
    }
}
