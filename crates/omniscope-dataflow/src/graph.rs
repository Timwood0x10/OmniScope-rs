//! Data flow graph for analysis
//!
//! This module provides the core dataflow graph structure for tracking
//! data dependencies and performing dataflow analysis.

use dashmap::DashMap;
use omniscope_types::{EdgeId, NodeId, ValueId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Data flow graph for analysis
pub struct DataFlowGraph {
    /// All nodes in the graph
    nodes: DashMap<NodeId, DataNode>,
    /// All edges in the graph
    edges: DashMap<EdgeId, DataEdge>,
    /// Entry node ID
    entry_node: Option<NodeId>,
    /// Exit node ID
    exit_node: Option<NodeId>,
    /// Next node ID
    next_node_id: NodeId,
    /// Next edge ID
    next_edge_id: EdgeId,
}

impl DataFlowGraph {
    /// Creates a new dataflow graph
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
            edges: DashMap::new(),
            entry_node: None,
            exit_node: None,
            next_node_id: 0,
            next_edge_id: 0,
        }
    }

    /// Adds a node to the graph
    pub fn add_node(&mut self, node: DataNode) -> NodeId {
        let id = self.next_node_id;
        self.next_node_id += 1;

        let mut node = node;
        node.id = id;

        self.nodes.insert(id, node);
        id
    }

    /// Adds an edge to the graph
    pub fn add_edge(&mut self, edge: DataEdge) -> EdgeId {
        let id = self.next_edge_id;
        self.next_edge_id += 1;

        let mut edge = edge;
        edge.id = id;

        // Update node connectivity
        if let Some(mut from_node) = self.nodes.get_mut(&edge.from) {
            from_node.outgoing_edges.push(id);
        }
        if let Some(mut to_node) = self.nodes.get_mut(&edge.to) {
            to_node.incoming_edges.push(id);
        }

        self.edges.insert(id, edge);
        id
    }

    /// Gets a node by ID
    pub fn get_node(&self, id: NodeId) -> Option<DataNode> {
        self.nodes.get(&id).map(|n| n.clone())
    }

    /// Gets an edge by ID
    pub fn get_edge(&self, id: EdgeId) -> Option<DataEdge> {
        self.edges.get(&id).map(|e| e.clone())
    }

    /// Sets the entry node
    pub fn set_entry(&mut self, node_id: NodeId) {
        self.entry_node = Some(node_id);
    }

    /// Sets the exit node
    pub fn set_exit(&mut self, node_id: NodeId) {
        self.exit_node = Some(node_id);
    }

    /// Returns the entry node
    pub fn entry(&self) -> Option<NodeId> {
        self.entry_node
    }

    /// Returns the exit node
    pub fn exit(&self) -> Option<NodeId> {
        self.exit_node
    }

    /// Returns the number of nodes
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of edges
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Returns all nodes
    pub fn all_nodes(&self) -> Vec<DataNode> {
        self.nodes.iter().map(|n| n.clone()).collect()
    }

    /// Returns all edges
    pub fn all_edges(&self) -> Vec<DataEdge> {
        self.edges.iter().map(|e| e.clone()).collect()
    }

    /// Returns predecessors of a node
    pub fn predecessors(&self, node_id: NodeId) -> Vec<NodeId> {
        self.edges
            .iter()
            .filter(|e| e.to == node_id)
            .map(|e| e.from)
            .collect()
    }

    /// Returns successors of a node
    pub fn successors(&self, node_id: NodeId) -> Vec<NodeId> {
        self.edges
            .iter()
            .filter(|e| e.from == node_id)
            .map(|e| e.to)
            .collect()
    }

    /// Clears the graph
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.edges.clear();
        self.entry_node = None;
        self.exit_node = None;
        self.next_node_id = 0;
        self.next_edge_id = 0;
    }
}

impl Default for DataFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Data node in the graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataNode {
    /// Node ID
    pub id: NodeId,
    /// Value type
    pub value_type: ValueType,
    /// Incoming edges
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incoming_edges: Vec<EdgeId>,
    /// Outgoing edges
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outgoing_edges: Vec<EdgeId>,
    /// Metadata
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl DataNode {
    /// Creates a new data node
    pub fn new(value_type: ValueType) -> Self {
        Self {
            id: 0,
            value_type,
            incoming_edges: Vec::new(),
            outgoing_edges: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Adds metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Value type for data nodes
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueType {
    /// Variable with name
    Variable(String),
    /// Temporary value with ID
    Temporary(ValueId),
    /// Constant value
    Constant(String),
    /// Memory location
    Memory(MemoryLocation),
    /// Function parameter
    Parameter(u32),
    /// Return value
    ReturnValue,
}

/// Memory location
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryLocation {
    /// Base address (variable name or ID)
    pub base: String,
    /// Offset (for array/struct access)
    pub offset: Option<i64>,
    /// Size in bytes
    pub size: Option<u64>,
}

impl MemoryLocation {
    /// Creates a new memory location
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            offset: None,
            size: None,
        }
    }

    /// Adds offset
    pub fn with_offset(mut self, offset: i64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Adds size
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }
}

/// Data edge in the graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEdge {
    /// Edge ID
    pub id: EdgeId,
    /// Source node
    pub from: NodeId,
    /// Target node
    pub to: NodeId,
    /// Edge type
    pub edge_type: EdgeType,
}

impl DataEdge {
    /// Creates a new data edge
    pub fn new(from: NodeId, to: NodeId, edge_type: EdgeType) -> Self {
        Self {
            id: 0,
            from,
            to,
            edge_type,
        }
    }
}

/// Edge type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeType {
    /// Assignment
    Assignment,
    /// Parameter passing (parameter index)
    Parameter(u32),
    /// Return value
    Return,
    /// Field access (field name)
    FieldAccess(String),
    /// Array index
    ArrayIndex,
    /// Pointer dereference
    Deref,
    /// Address-of operation
    AddressOf,
    /// Call edge
    Call,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_creation() {
        let graph = DataFlowGraph::new();
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_add_nodes() {
        let mut graph = DataFlowGraph::new();

        let node1 = DataNode::new(ValueType::Variable("x".to_string()));
        let node2 = DataNode::new(ValueType::Variable("y".to_string()));

        let id1 = graph.add_node(node1);
        let id2 = graph.add_node(node2);

        assert_ne!(id1, id2);
        assert_eq!(graph.node_count(), 2);
    }

    #[test]
    fn test_add_edges() {
        let mut graph = DataFlowGraph::new();

        let node1 = DataNode::new(ValueType::Variable("x".to_string()));
        let node2 = DataNode::new(ValueType::Variable("y".to_string()));

        let id1 = graph.add_node(node1);
        let id2 = graph.add_node(node2);

        let edge = DataEdge::new(id1, id2, EdgeType::Assignment);
        let _edge_id = graph.add_edge(edge);

        assert_eq!(graph.edge_count(), 1);

        let successors = graph.successors(id1);
        assert_eq!(successors.len(), 1);
        assert_eq!(successors[0], id2);
    }

    #[test]
    fn test_memory_location() {
        let loc = MemoryLocation::new("arr").with_offset(8).with_size(4);

        assert_eq!(loc.base, "arr");
        assert_eq!(loc.offset, Some(8));
        assert_eq!(loc.size, Some(4));
    }

    /// Objective: Verify that a self-loop edge makes a node both its own successor and predecessor.
    /// Invariants: successors(n) and predecessors(n) both contain n when edge n->n exists.
    #[test]
    fn test_self_loop() {
        let mut graph = DataFlowGraph::new();
        let node = DataNode::new(ValueType::Variable("x".to_string()));
        let id = graph.add_node(node);
        graph.add_edge(DataEdge::new(id, id, EdgeType::Assignment));

        let succs = graph.successors(id);
        assert!(
            succs.contains(&id),
            "self-loop node must be its own successor"
        );

        let preds = graph.predecessors(id);
        assert!(
            preds.contains(&id),
            "self-loop node must be its own predecessor"
        );
    }

    /// Objective: Verify that a cyclic graph a->b->c->a has correct predecessor/successor relationships.
    /// Invariants: Each node's successors and predecessors reflect the cycle structure.
    #[test]
    fn test_cycle_detection() {
        let mut graph = DataFlowGraph::new();
        let a = graph.add_node(DataNode::new(ValueType::Variable("a".to_string())));
        let b = graph.add_node(DataNode::new(ValueType::Variable("b".to_string())));
        let c = graph.add_node(DataNode::new(ValueType::Variable("c".to_string())));

        graph.add_edge(DataEdge::new(a, b, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(b, c, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(c, a, EdgeType::Assignment));

        assert_eq!(graph.successors(a), vec![b], "a's successor must be b");
        assert_eq!(graph.successors(b), vec![c], "b's successor must be c");
        assert_eq!(graph.successors(c), vec![a], "c's successor must be a");

        assert_eq!(graph.predecessors(a), vec![c], "a's predecessor must be c");
        assert_eq!(graph.predecessors(b), vec![a], "b's predecessor must be a");
        assert_eq!(graph.predecessors(c), vec![b], "c's predecessor must be b");
    }

    /// Objective: Verify that clear() resets all graph state to empty defaults.
    /// Invariants: After clear(), node_count=0, edge_count=0, entry=None, exit=None.
    #[test]
    fn test_clear_resets_state() {
        let mut graph = DataFlowGraph::new();
        let n1 = graph.add_node(DataNode::new(ValueType::Variable("a".to_string())));
        let n2 = graph.add_node(DataNode::new(ValueType::Variable("b".to_string())));
        graph.add_edge(DataEdge::new(n1, n2, EdgeType::Assignment));
        graph.set_entry(n1);
        graph.set_exit(n2);

        graph.clear();

        assert_eq!(graph.node_count(), 0, "node_count must be 0 after clear");
        assert_eq!(graph.edge_count(), 0, "edge_count must be 0 after clear");
        assert_eq!(graph.entry(), None, "entry must be None after clear");
        assert_eq!(graph.exit(), None, "exit must be None after clear");
    }

    /// Objective: Verify that get_node returns None for a non-existent node ID.
    /// Invariants: Looking up an ID that was never assigned yields None.
    #[test]
    fn test_get_node_returns_none_for_missing() {
        let graph = DataFlowGraph::new();
        assert!(
            graph.get_node(999).is_none(),
            "get_node for missing ID must return None"
        );
    }

    /// Objective: Verify that get_edge returns None for a non-existent edge ID.
    /// Invariants: Looking up an ID that was never assigned yields None.
    #[test]
    fn test_get_edge_returns_none_for_missing() {
        let graph = DataFlowGraph::new();
        assert!(
            graph.get_edge(999).is_none(),
            "get_edge for missing ID must return None"
        );
    }

    /// Objective: Verify that set_entry and set_exit correctly configure entry/exit nodes.
    /// Invariants: entry() and exit() return the IDs passed to set_entry/set_exit.
    #[test]
    fn test_set_entry_exit() {
        let mut graph = DataFlowGraph::new();
        let n1 = graph.add_node(DataNode::new(ValueType::Variable("a".to_string())));
        let n2 = graph.add_node(DataNode::new(ValueType::Variable("b".to_string())));

        graph.set_entry(n1);
        graph.set_exit(n2);

        assert_eq!(
            graph.entry(),
            Some(n1),
            "entry must return the ID set by set_entry"
        );
        assert_eq!(
            graph.exit(),
            Some(n2),
            "exit must return the ID set by set_exit"
        );
    }

    /// Objective: Verify that a newly created graph has no entry or exit node.
    /// Invariants: entry() and exit() both return None on a fresh graph.
    #[test]
    fn test_entry_exit_default_none() {
        let graph = DataFlowGraph::new();
        assert_eq!(graph.entry(), None, "new graph must have no entry node");
        assert_eq!(graph.exit(), None, "new graph must have no exit node");
    }

    /// Objective: Verify that edges of different EdgeType variants are stored correctly.
    /// Invariants: Each edge retains its EdgeType variant after insertion.
    #[test]
    fn test_multiple_edge_types() {
        let mut graph = DataFlowGraph::new();
        let n0 = graph.add_node(DataNode::new(ValueType::Variable("a".to_string())));
        let n1 = graph.add_node(DataNode::new(ValueType::Variable("b".to_string())));
        let n2 = graph.add_node(DataNode::new(ValueType::Variable("c".to_string())));
        let n3 = graph.add_node(DataNode::new(ValueType::Variable("d".to_string())));
        let n4 = graph.add_node(DataNode::new(ValueType::Variable("e".to_string())));

        let e0 = graph.add_edge(DataEdge::new(n0, n1, EdgeType::Assignment));
        let e1 = graph.add_edge(DataEdge::new(n1, n2, EdgeType::Parameter(0)));
        let e2 = graph.add_edge(DataEdge::new(n2, n3, EdgeType::Return));
        let e3 = graph.add_edge(DataEdge::new(
            n3,
            n4,
            EdgeType::FieldAccess("field".to_string()),
        ));
        let e4 = graph.add_edge(DataEdge::new(n0, n4, EdgeType::ArrayIndex));

        assert_eq!(
            graph.get_edge(e0).unwrap().edge_type,
            EdgeType::Assignment,
            "edge 0 must be Assignment"
        );
        assert_eq!(
            graph.get_edge(e1).unwrap().edge_type,
            EdgeType::Parameter(0),
            "edge 1 must be Parameter(0)"
        );
        assert_eq!(
            graph.get_edge(e2).unwrap().edge_type,
            EdgeType::Return,
            "edge 2 must be Return"
        );
        assert_eq!(
            graph.get_edge(e3).unwrap().edge_type,
            EdgeType::FieldAccess("field".to_string()),
            "edge 3 must be FieldAccess"
        );
        assert_eq!(
            graph.get_edge(e4).unwrap().edge_type,
            EdgeType::ArrayIndex,
            "edge 4 must be ArrayIndex"
        );
    }

    /// Objective: Verify that a node with no incoming edges has empty predecessors.
    /// Invariants: predecessors() for a root node returns an empty vec.
    #[test]
    fn test_predecessors_empty_for_root() {
        let mut graph = DataFlowGraph::new();
        let root = graph.add_node(DataNode::new(ValueType::Variable("root".to_string())));
        let child = graph.add_node(DataNode::new(ValueType::Variable("child".to_string())));
        graph.add_edge(DataEdge::new(root, child, EdgeType::Assignment));

        assert!(
            graph.predecessors(root).is_empty(),
            "root node must have no predecessors"
        );
    }

    /// Objective: Verify that a node with no outgoing edges has empty successors.
    /// Invariants: successors() for a leaf node returns an empty vec.
    #[test]
    fn test_successors_empty_for_leaf() {
        let mut graph = DataFlowGraph::new();
        let parent = graph.add_node(DataNode::new(ValueType::Variable("parent".to_string())));
        let leaf = graph.add_node(DataNode::new(ValueType::Variable("leaf".to_string())));
        graph.add_edge(DataEdge::new(parent, leaf, EdgeType::Assignment));

        assert!(
            graph.successors(leaf).is_empty(),
            "leaf node must have no successors"
        );
    }

    /// Objective: Verify that DataNode::with_metadata stores key-value pairs correctly.
    /// Invariants: Metadata inserted via with_metadata is retrievable from the HashMap.
    #[test]
    fn test_node_with_metadata() {
        let node =
            DataNode::new(ValueType::Variable("x".to_string())).with_metadata("key1", "value1");

        assert_eq!(
            node.metadata.get("key1"),
            Some(&"value1".to_string()),
            "metadata must contain key1=value1"
        );
        assert_eq!(
            node.metadata.len(),
            1,
            "metadata must have exactly one entry"
        );
    }

    /// Objective: Verify that MemoryLocation::new sets base but defaults offset and size to None.
    /// Invariants: offset and size are both None unless explicitly set.
    #[test]
    fn test_memory_location_defaults() {
        let loc = MemoryLocation::new("base_ptr");
        assert_eq!(loc.base, "base_ptr", "base must match the provided string");
        assert_eq!(loc.offset, None, "offset must default to None");
        assert_eq!(loc.size, None, "size must default to None");
    }
}
