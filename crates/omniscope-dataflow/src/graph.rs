//! Data flow graph for analysis
//!
//! This module provides the core dataflow graph structure for tracking
//! data dependencies and performing dataflow analysis.

use dashmap::DashMap;
use omniscope_types::{EdgeId, NodeId, ValueId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
        let edge_id = graph.add_edge(edge);
        
        assert_eq!(graph.edge_count(), 1);
        
        let successors = graph.successors(id1);
        assert_eq!(successors.len(), 1);
        assert_eq!(successors[0], id2);
    }

    #[test]
    fn test_memory_location() {
        let loc = MemoryLocation::new("arr")
            .with_offset(8)
            .with_size(4);
        
        assert_eq!(loc.base, "arr");
        assert_eq!(loc.offset, Some(8));
        assert_eq!(loc.size, Some(4));
    }
}
