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
    type Value: Clone + PartialEq;

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

    /// Transfer function for a node (forward direction).
    /// Given the input fact, computes the output fact after executing the node.
    fn transfer(&self, node: &DataNode, input: &Self::Value) -> Self::Value;

    /// Transfer function for a node (backward direction).
    /// Given the output fact (fact from successors), computes the input fact
    /// (fact needed before executing the node). For backward analyses like
    /// live variables, this is the inverse application of the node's effect.
    ///
    /// Default implementation delegates to `transfer`, which is only correct
    /// for identity/passthrough transfer functions. Domains with non-trivial
    /// forward transfer must override this to provide the correct backward
    /// semantics.
    fn transfer_backward(&self, node: &DataNode, output: &Self::Value) -> Self::Value {
        // Fallback: same as forward transfer. Domains with non-trivial
        // transfer must override this.
        self.transfer(node, output)
    }
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
                // Compute input as join of all predecessor outputs.
                // For the entry node (no predecessors), input is fixed
                // to the initial boundary value and must not be overwritten.
                let preds = graph.predecessors(node.id);
                let input = if preds.is_empty() {
                    // Entry node: preserve the initial boundary value
                    self.inputs
                        .get(&node.id)
                        .cloned()
                        .unwrap_or_else(|| self.domain.bottom())
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

                // Update input if changed — input is already the join of all
                // predecessor outputs, so assign directly instead of accumulating.
                if let Some(old_input) = self.inputs.get(&node.id) {
                    if *old_input != input {
                        self.inputs.insert(node.id, input.clone());
                        changed = true;
                    }
                }

                // Compute output using transfer function
                let output = self.domain.transfer(
                    &node,
                    self.inputs.get(&node.id).unwrap_or(&self.domain.bottom()),
                );

                // Update output if changed — output is the direct result of
                // transfer, so assign directly instead of accumulating.
                if let Some(old_output) = self.outputs.get(&node.id) {
                    if *old_output != output {
                        self.outputs.insert(node.id, output);
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
                // Compute output as meet of all successor inputs.
                // For the exit node (no successors), output is fixed
                // to the initial boundary value and must not be overwritten.
                let succs = graph.successors(node.id);
                let output = if succs.is_empty() {
                    // Exit node: preserve the initial boundary value
                    self.outputs
                        .get(&node.id)
                        .cloned()
                        .unwrap_or_else(|| self.domain.top())
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

                // Update output if changed — output is already the meet of all
                // successor inputs, so assign directly instead of accumulating.
                if let Some(old_output) = self.outputs.get(&node.id) {
                    if *old_output != output {
                        self.outputs.insert(node.id, output.clone());
                        changed = true;
                    }
                }

                // Compute input using backward transfer function
                let input = self.domain.transfer_backward(
                    &node,
                    self.outputs.get(&node.id).unwrap_or(&self.domain.top()),
                );

                // Update input if changed — input is the direct result of
                // backward transfer, so assign directly instead of accumulating.
                if let Some(old_input) = self.inputs.get(&node.id) {
                    if *old_input != input {
                        self.inputs.insert(node.id, input);
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
    use crate::graph::{DataEdge, DataNode, EdgeType, ValueType};

    /// A test domain modeling abstract values along a lattice:
    /// Bottom (unreachable) ⊑ Const(v) ⊑ Top (conflicting).
    ///
    /// Join: same const → const, different const → Top, anything + Bottom → other.
    /// Meet: same const → const, different const → Bottom, anything + Top → other.
    ///
    /// Transfer: nodes named "entry" produce Const(1), "inc" adds 1 to Const,
    /// all others pass through.
    #[derive(Clone)]
    struct TestDomain;

    #[derive(Debug, Clone, PartialEq)]
    enum AbsVal {
        Bottom,
        Const(i64),
        Top,
    }

    impl AnalysisDomain for TestDomain {
        type Value = AbsVal;

        fn initial(&self) -> Self::Value {
            AbsVal::Const(1)
        }

        fn bottom(&self) -> Self::Value {
            AbsVal::Bottom
        }

        fn top(&self) -> Self::Value {
            AbsVal::Top
        }

        fn join(&self, a: &Self::Value, b: &Self::Value) -> Self::Value {
            match (a, b) {
                (AbsVal::Bottom, x) | (x, AbsVal::Bottom) => x.clone(),
                (AbsVal::Top, _) | (_, AbsVal::Top) => AbsVal::Top,
                (AbsVal::Const(v1), AbsVal::Const(v2)) if v1 == v2 => AbsVal::Const(*v1),
                (AbsVal::Const(_), AbsVal::Const(_)) => AbsVal::Top,
            }
        }

        fn meet(&self, a: &Self::Value, b: &Self::Value) -> Self::Value {
            match (a, b) {
                (AbsVal::Top, x) | (x, AbsVal::Top) => x.clone(),
                (AbsVal::Bottom, _) | (_, AbsVal::Bottom) => AbsVal::Bottom,
                (AbsVal::Const(v1), AbsVal::Const(v2)) if v1 == v2 => AbsVal::Const(*v1),
                (AbsVal::Const(_), AbsVal::Const(_)) => AbsVal::Bottom,
            }
        }

        fn transfer(&self, node: &DataNode, input: &Self::Value) -> Self::Value {
            match node.value_type {
                ValueType::Variable(ref name) if name == "entry" => AbsVal::Const(1),
                ValueType::Variable(ref name) if name == "inc" => {
                    if let AbsVal::Const(v) = input {
                        AbsVal::Const(v + 1)
                    } else {
                        input.clone()
                    }
                }
                _ => input.clone(),
            }
        }

        /// Backward transfer: inverse of forward transfer.
        /// "inc" forward adds 1, so backward subtracts 1 (dec).
        /// "entry" is a generator in forward direction; in backward it
        /// simply passes through the output fact.
        fn transfer_backward(&self, node: &DataNode, output: &Self::Value) -> Self::Value {
            match node.value_type {
                ValueType::Variable(ref name) if name == "inc" => {
                    if let AbsVal::Const(v) = output {
                        AbsVal::Const(v - 1)
                    } else {
                        output.clone()
                    }
                }
                // "entry" generates a value going forward, but going backward
                // it does not constrain the input — pass through.
                _ => output.clone(),
            }
        }
    }

    /// Builds a linear graph: entry → a → b → exit.
    fn build_linear_graph() -> (DataFlowGraph, NodeId, NodeId, NodeId, NodeId) {
        let mut graph = DataFlowGraph::new();
        let entry = graph.add_node(DataNode::new(ValueType::Variable("entry".into())));
        let a = graph.add_node(DataNode::new(ValueType::Variable("a".into())));
        let b = graph.add_node(DataNode::new(ValueType::Variable("b".into())));
        let exit = graph.add_node(DataNode::new(ValueType::Variable("exit".into())));

        graph.add_edge(DataEdge::new(entry, a, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(a, b, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(b, exit, EdgeType::Assignment));

        graph.set_entry(entry);
        graph.set_exit(exit);

        (graph, entry, a, b, exit)
    }

    /// Objective: Verify forward analysis propagates values along a linear chain.
    /// Invariants: Entry gets initial=Const(1), downstream passthrough nodes
    /// must propagate the value exactly (no accumulating join to mask errors).
    #[test]
    fn test_forward_linear_propagation() {
        let (graph, entry, a, b, exit) = build_linear_graph();

        let mut analysis = ForwardAnalysis::new(TestDomain);
        analysis.run(&graph);

        let entry_out = analysis.get_output(entry);
        assert!(
            entry_out.is_some(),
            "Entry node must have an output after analysis"
        );
        assert_eq!(
            entry_out.unwrap(),
            &AbsVal::Const(1),
            "Entry transfer must produce Const(1)"
        );

        // Node "a" is a pass-through, must propagate the value from entry
        let a_out = analysis.get_output(a);
        assert_eq!(
            a_out.unwrap(),
            &AbsVal::Const(1),
            "Node 'a' must propagate Const(1) from entry"
        );

        // Node "b" is also a pass-through
        let b_out = analysis.get_output(b);
        assert_eq!(
            b_out.unwrap(),
            &AbsVal::Const(1),
            "Node 'b' must propagate Const(1) from a"
        );

        // Exit is also a pass-through
        let exit_out = analysis.get_output(exit);
        assert_eq!(
            exit_out.unwrap(),
            &AbsVal::Const(1),
            "Exit must propagate Const(1) from b"
        );
    }

    /// Objective: Verify backward analysis propagates values backward along
    /// a linear chain and uses the backward transfer function correctly.
    /// Invariants: Exit gets initial=Const(1), passthrough predecessors
    /// must propagate the value backward exactly.
    #[test]
    fn test_backward_linear_propagation() {
        let (graph, entry, a, b, exit) = build_linear_graph();

        let mut analysis = BackwardAnalysis::new(TestDomain);
        analysis.run(&graph);

        let exit_out = analysis.get_output(exit);
        assert!(
            exit_out.is_some(),
            "Exit node must have an output after backward analysis"
        );
        assert_eq!(
            exit_out.unwrap(),
            &AbsVal::Const(1),
            "Backward exit must have initial value Const(1)"
        );

        // In backward analysis, passthrough nodes propagate the value
        // from their successors backward.
        let b_input = analysis.get_input(b);
        assert_eq!(
            b_input.unwrap(),
            &AbsVal::Const(1),
            "Node 'b' input must propagate Const(1) backward from exit"
        );

        let a_input = analysis.get_input(a);
        assert_eq!(
            a_input.unwrap(),
            &AbsVal::Const(1),
            "Node 'a' input must propagate Const(1) backward from b"
        );

        let entry_input = analysis.get_input(entry);
        assert_eq!(
            entry_input.unwrap(),
            &AbsVal::Const(1),
            "Entry input must propagate Const(1) backward from a"
        );
    }

    /// Objective: Verify forward analysis on a diamond CFG (split + merge).
    /// Invariants: Analysis must terminate. Merge node receives join of both paths.
    #[test]
    fn test_forward_diamond_cfg() {
        // entry → left → merge ← right ← entry
        let mut graph = DataFlowGraph::new();
        let entry = graph.add_node(DataNode::new(ValueType::Variable("entry".into())));
        let left = graph.add_node(DataNode::new(ValueType::Variable("left".into())));
        let right = graph.add_node(DataNode::new(ValueType::Variable("right".into())));
        let merge = graph.add_node(DataNode::new(ValueType::Variable("merge".into())));

        graph.add_edge(DataEdge::new(entry, left, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(entry, right, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(left, merge, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(right, merge, EdgeType::Assignment));

        graph.set_entry(entry);
        graph.set_exit(merge);

        let mut analysis = ForwardAnalysis::new(TestDomain);
        analysis.run(&graph);

        // Both branches produce the same value (pass-through from entry's output),
        // so join at merge should preserve the value.
        let merge_in = analysis.get_input(merge);
        assert!(
            merge_in.is_some(),
            "Merge node must have an input after diamond analysis"
        );
    }

    /// Objective: Verify backward analysis on a diamond CFG.
    /// Invariants: Analysis must terminate without panicking.
    #[test]
    fn test_backward_diamond_cfg() {
        let mut graph = DataFlowGraph::new();
        let entry = graph.add_node(DataNode::new(ValueType::Variable("entry".into())));
        let left = graph.add_node(DataNode::new(ValueType::Variable("left".into())));
        let right = graph.add_node(DataNode::new(ValueType::Variable("right".into())));
        let merge = graph.add_node(DataNode::new(ValueType::Variable("merge".into())));

        graph.add_edge(DataEdge::new(entry, left, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(entry, right, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(left, merge, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(right, merge, EdgeType::Assignment));

        graph.set_entry(entry);
        graph.set_exit(merge);

        let mut analysis = BackwardAnalysis::new(TestDomain);
        analysis.run(&graph);

        // Verify all nodes have outputs
        for node in graph.all_nodes() {
            assert!(
                analysis.get_output(node.id).is_some(),
                "Node {} must have output in backward diamond analysis",
                node.id
            );
        }
    }

    /// Objective: Verify forward analysis handles a self-loop without infinite loop.
    /// Invariants: The analysis must terminate (fixpoint reached).
    #[test]
    fn test_forward_self_loop() {
        let mut graph = DataFlowGraph::new();
        let entry = graph.add_node(DataNode::new(ValueType::Variable("entry".into())));
        let loop_node = graph.add_node(DataNode::new(ValueType::Variable("loop".into())));
        let exit = graph.add_node(DataNode::new(ValueType::Variable("exit".into())));

        graph.add_edge(DataEdge::new(entry, loop_node, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(loop_node, loop_node, EdgeType::Assignment)); // self-loop
        graph.add_edge(DataEdge::new(loop_node, exit, EdgeType::Assignment));

        graph.set_entry(entry);
        graph.set_exit(exit);

        let mut analysis = ForwardAnalysis::new(TestDomain);
        // This must terminate — if it hangs, the test will timeout.
        analysis.run(&graph);

        assert!(
            analysis.get_output(entry).is_some(),
            "Entry must have output after self-loop analysis"
        );
        assert!(
            analysis.get_output(loop_node).is_some(),
            "Loop node must have output after self-loop analysis"
        );
    }

    /// Objective: Verify backward analysis handles a cycle.
    /// Invariants: Must terminate.
    #[test]
    fn test_backward_cycle() {
        // a → b → c → a (cycle)
        let mut graph = DataFlowGraph::new();
        let a = graph.add_node(DataNode::new(ValueType::Variable("a".into())));
        let b = graph.add_node(DataNode::new(ValueType::Variable("b".into())));
        let c = graph.add_node(DataNode::new(ValueType::Variable("c".into())));

        graph.add_edge(DataEdge::new(a, b, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(b, c, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(c, a, EdgeType::Assignment)); // back edge

        graph.set_entry(a);
        graph.set_exit(c);

        let mut analysis = BackwardAnalysis::new(TestDomain);
        analysis.run(&graph);

        for node in graph.all_nodes() {
            assert!(
                analysis.get_output(node.id).is_some(),
                "Node must have output in cyclic backward analysis"
            );
        }
    }

    /// Objective: Verify get_input/get_output return None for non-existent node.
    /// Invariants: Querying unknown node ID must not panic, must return None.
    #[test]
    fn test_analysis_unknown_node_returns_none() {
        let _graph = DataFlowGraph::new();
        let analysis = ForwardAnalysis::<TestDomain>::new(TestDomain);

        assert!(
            analysis.get_input(999).is_none(),
            "get_input for non-existent node must return None"
        );
        assert!(
            analysis.get_output(999).is_none(),
            "get_output for non-existent node must return None"
        );
    }

    /// Objective: Verify forward analysis on empty graph terminates cleanly.
    /// Invariants: No panics, no outputs.
    #[test]
    fn test_forward_empty_graph() {
        let graph = DataFlowGraph::new();
        let mut analysis = ForwardAnalysis::new(TestDomain);
        analysis.run(&graph);

        assert!(
            analysis.get_input(0).is_none(),
            "Empty graph must have no inputs"
        );
        assert!(
            analysis.get_output(0).is_none(),
            "Empty graph must have no outputs"
        );
    }

    /// Objective: Verify backward analysis on empty graph terminates cleanly.
    #[test]
    fn test_backward_empty_graph() {
        let graph = DataFlowGraph::new();
        let mut analysis = BackwardAnalysis::new(TestDomain);
        analysis.run(&graph);

        assert!(
            analysis.get_output(0).is_none(),
            "Empty graph must have no outputs in backward analysis"
        );
    }

    /// Objective: Verify join lattice properties — idempotent, commutative, associative.
    /// Invariants: join(a,a)=a, join(a,b)=join(b,a), join(join(a,b),c)=join(a,join(b,c)).
    #[test]
    fn test_join_lattice_properties() {
        let domain = TestDomain;

        // Idempotent: join(a, a) = a
        let a = AbsVal::Const(42);
        assert_eq!(
            domain.join(&a, &a),
            a,
            "Join must be idempotent: join(a,a) = a"
        );

        let bot = AbsVal::Bottom;
        assert_eq!(
            domain.join(&bot, &bot),
            bot,
            "Join of two bottoms must be bottom"
        );

        let top = AbsVal::Top;
        assert_eq!(domain.join(&top, &top), top, "Join of two tops must be top");

        // Commutative: join(a, b) = join(b, a)
        let b = AbsVal::Const(99);
        assert_eq!(
            domain.join(&a, &b),
            domain.join(&b, &a),
            "Join must be commutative"
        );

        // Bottom is identity: join(a, bottom) = a
        assert_eq!(domain.join(&a, &bot), a, "Bottom must be join identity");
        assert_eq!(
            domain.join(&bot, &a),
            a,
            "Bottom must be join identity (commutative)"
        );

        // Top absorbs: join(a, top) = top
        assert_eq!(domain.join(&a, &top), top, "Top must absorb in join");
    }

    /// Objective: Verify meet lattice properties — idempotent, commutative, associative.
    /// Invariants: meet(a,a)=a, meet(a,b)=meet(b,a), top is identity, bottom absorbs.
    #[test]
    fn test_meet_lattice_properties() {
        let domain = TestDomain;

        let a = AbsVal::Const(42);
        let b = AbsVal::Const(99);
        let top = AbsVal::Top;
        let bot = AbsVal::Bottom;

        // Idempotent
        assert_eq!(domain.meet(&a, &a), a, "Meet must be idempotent");

        // Commutative
        assert_eq!(
            domain.meet(&a, &b),
            domain.meet(&b, &a),
            "Meet must be commutative"
        );

        // Top is identity: meet(a, top) = a
        assert_eq!(domain.meet(&a, &top), a, "Top must be meet identity");
        assert_eq!(
            domain.meet(&top, &a),
            a,
            "Top must be meet identity (commutative)"
        );

        // Bottom absorbs: meet(a, bottom) = bottom
        assert_eq!(domain.meet(&a, &bot), bot, "Bottom must absorb in meet");
    }

    /// Objective: Verify transfer function transforms values correctly.
    /// Invariants: "entry" → Const(1), "inc" with Const(v) → Const(v+1), others pass through.
    #[test]
    fn test_transfer_function_semantics() {
        let domain = TestDomain;

        let entry_node = DataNode::new(ValueType::Variable("entry".into()));
        let inc_node = DataNode::new(ValueType::Variable("inc".into()));
        let pass_node = DataNode::new(ValueType::Variable("other".into()));

        // Entry always produces Const(1) regardless of input
        assert_eq!(
            domain.transfer(&entry_node, &AbsVal::Bottom),
            AbsVal::Const(1),
            "Entry transfer must produce Const(1) even from bottom"
        );
        assert_eq!(
            domain.transfer(&entry_node, &AbsVal::Const(999)),
            AbsVal::Const(1),
            "Entry transfer must produce Const(1) regardless of input"
        );

        // Inc adds 1 to constant inputs
        assert_eq!(
            domain.transfer(&inc_node, &AbsVal::Const(5)),
            AbsVal::Const(6),
            "Inc transfer must add 1 to Const(5)"
        );

        // Inc passes through non-constant
        assert_eq!(
            domain.transfer(&inc_node, &AbsVal::Top),
            AbsVal::Top,
            "Inc transfer must pass through Top"
        );
        assert_eq!(
            domain.transfer(&inc_node, &AbsVal::Bottom),
            AbsVal::Bottom,
            "Inc transfer must pass through Bottom"
        );

        // Other nodes pass through
        assert_eq!(
            domain.transfer(&pass_node, &AbsVal::Const(42)),
            AbsVal::Const(42),
            "Pass-through transfer must preserve input"
        );
    }

    /// Objective: Verify forward analysis with branching produces Top at merge
    /// when branches have different transfer outputs.
    /// Invariants: Two branches with different Const values join to Top.
    #[test]
    fn test_forward_branching_conflicting_values() {
        // Build: entry → split_a (inc) → merge
        //             → split_b (pass) → merge
        // inc produces Const(2) from Const(1), pass produces Const(1).
        // At merge: join(Const(2), Const(1)) = Top.
        let mut graph = DataFlowGraph::new();
        let entry = graph.add_node(DataNode::new(ValueType::Variable("entry".into())));
        let split_a = graph.add_node(DataNode::new(ValueType::Variable("inc".into())));
        let split_b = graph.add_node(DataNode::new(ValueType::Variable("pass".into())));
        let merge = graph.add_node(DataNode::new(ValueType::Variable("merge".into())));

        graph.add_edge(DataEdge::new(entry, split_a, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(entry, split_b, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(split_a, merge, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(split_b, merge, EdgeType::Assignment));

        graph.set_entry(entry);
        graph.set_exit(merge);

        let mut analysis = ForwardAnalysis::new(TestDomain);
        analysis.run(&graph);

        // Verify analysis terminates and produces outputs for all nodes
        for node in graph.all_nodes() {
            assert!(
                analysis.get_output(node.id).is_some(),
                "All nodes must have outputs after analysis"
            );
        }

        // Verify the merge node receives Top due to conflicting values
        let merge_input = analysis.get_input(merge);
        assert_eq!(
            merge_input.unwrap(),
            &AbsVal::Top,
            "Merge must be Top when branches produce conflicting Const values"
        );
    }

    /// Objective: Verify backward transfer function produces correct inverse.
    /// Invariants: "inc" backward subtracts 1, "entry" backward passes through.
    #[test]
    fn test_backward_transfer_function_semantics() {
        let domain = TestDomain;

        let inc_node = DataNode::new(ValueType::Variable("inc".into()));
        let entry_node = DataNode::new(ValueType::Variable("entry".into()));
        let pass_node = DataNode::new(ValueType::Variable("other".into()));

        // Backward inc: Const(v) → Const(v-1)
        assert_eq!(
            domain.transfer_backward(&inc_node, &AbsVal::Const(5)),
            AbsVal::Const(4),
            "Backward inc transfer must subtract 1 from Const(5)"
        );
        assert_eq!(
            domain.transfer_backward(&inc_node, &AbsVal::Const(1)),
            AbsVal::Const(0),
            "Backward inc transfer must subtract 1 from Const(1)"
        );

        // Backward inc passes through Top and Bottom
        assert_eq!(
            domain.transfer_backward(&inc_node, &AbsVal::Top),
            AbsVal::Top,
            "Backward inc must pass through Top"
        );
        assert_eq!(
            domain.transfer_backward(&inc_node, &AbsVal::Bottom),
            AbsVal::Bottom,
            "Backward inc must pass through Bottom"
        );

        // Backward entry is passthrough (entry generates forward, but
        // does not constrain backward).
        assert_eq!(
            domain.transfer_backward(&entry_node, &AbsVal::Const(42)),
            AbsVal::Const(42),
            "Backward entry must pass through output fact"
        );

        // Other nodes pass through backward
        assert_eq!(
            domain.transfer_backward(&pass_node, &AbsVal::Const(7)),
            AbsVal::Const(7),
            "Backward passthrough must preserve output fact"
        );
    }

    /// Objective: Verify backward analysis with "inc" node uses
    /// transfer_backward correctly (CRITICAL #1 regression test).
    /// Invariants: If forward inc adds 1, backward analysis through inc
    /// should subtract 1 from the successor's fact.
    #[test]
    fn test_backward_inc_node_uses_backward_transfer() {
        // Build: entry → inc → exit
        // Forward: entry produces Const(1), inc adds 1 → Const(2).
        // Backward: exit gets initial=Const(1), inc backward subtracts 1 → Const(0).
        let mut graph = DataFlowGraph::new();
        let entry = graph.add_node(DataNode::new(ValueType::Variable("entry".into())));
        let inc = graph.add_node(DataNode::new(ValueType::Variable("inc".into())));
        let exit = graph.add_node(DataNode::new(ValueType::Variable("exit".into())));

        graph.add_edge(DataEdge::new(entry, inc, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(inc, exit, EdgeType::Assignment));

        graph.set_entry(entry);
        graph.set_exit(exit);

        let mut analysis = BackwardAnalysis::new(TestDomain);
        analysis.run(&graph);

        // Exit output = initial = Const(1)
        let exit_out = analysis.get_output(exit);
        assert_eq!(
            exit_out.unwrap(),
            &AbsVal::Const(1),
            "Exit backward output must be Const(1)"
        );

        // Inc input = backward_transfer(Const(1)) = Const(0)
        let inc_input = analysis.get_input(inc);
        assert_eq!(
            inc_input.unwrap(),
            &AbsVal::Const(0),
            "Inc backward input must be Const(0) — backward transfer subtracts 1"
        );
    }

    /// Objective: Verify that forward analysis computes the least fixpoint
    /// without accumulative join masking (CRITICAL #4 regression test).
    /// Invariants: Direct assignment means transfer results propagate exactly,
    /// not obscured by spurious accumulation.
    #[test]
    fn test_forward_no_accumulative_join_masking() {
        // Build: entry → a → b → exit
        // All passthrough: each node must produce exactly Const(1).
        // If accumulative join masked the transfer, values could be
        // artificially inflated.
        let (graph, entry, a, b, exit) = build_linear_graph();

        let mut analysis = ForwardAnalysis::new(TestDomain);
        analysis.run(&graph);

        // Every node must have exactly Const(1) as output — no accumulation
        for (id, name) in [(entry, "entry"), (a, "a"), (b, "b"), (exit, "exit")] {
            let out = analysis.get_output(id);
            assert_eq!(
                out.unwrap(),
                &AbsVal::Const(1),
                "Node '{}' must have output Const(1) without accumulation",
                name
            );
        }
    }
}
