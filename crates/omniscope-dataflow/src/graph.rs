//! Data flow graph for analysis
//!
//! This module provides the core dataflow graph structure for tracking
//! data dependencies and performing dataflow analysis.

use omniscope_types::{EdgeId, NodeId, ValueId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Data flow graph for analysis
///
/// Uses CSR (Compressed Sparse Row) format after `freeze()` for cache-friendly
/// successor/predecessor queries. Before freezing, uses HashMap-based adjacency
/// lists for incremental construction.
pub struct DataFlowGraph {
    /// All nodes in the graph
    nodes: HashMap<NodeId, DataNode>,
    /// All edges in the graph
    edges: HashMap<EdgeId, DataEdge>,
    /// Entry node ID
    entry_node: Option<NodeId>,
    /// Exit node ID
    exit_node: Option<NodeId>,
    /// Next node ID
    next_node_id: NodeId,
    /// Next edge ID
    next_edge_id: EdgeId,
    /// Forward adjacency: node -> successor node IDs (O(1) lookup for successors)
    forward_adj: HashMap<NodeId, Vec<NodeId>>,
    /// Reverse adjacency: node -> predecessor node IDs (O(1) lookup for predecessors)
    reverse_adj: HashMap<NodeId, Vec<NodeId>>,

    // ── Frozen CSR fields (populated by `freeze()`) ──────────────────
    //
    // CSR format stores adjacency in two contiguous arrays:
    //   offsets[i]..offsets[i+1] indexes into `forward_targets` for node i's successors
    //   offsets[i]..offsets[i+1] indexes into `reverse_targets` for node i's predecessors
    //
    // This eliminates per-node HashMap/Vec allocations and improves cache locality.
    /// CSR offsets for forward adjacency (len = max_node_id + 2)
    frozen_forward_offsets: Vec<usize>,
    /// Contiguous successor node IDs for forward adjacency
    frozen_forward_targets: Vec<NodeId>,
    /// CSR offsets for reverse adjacency (len = max_node_id + 2)
    frozen_reverse_offsets: Vec<usize>,
    /// Contiguous predecessor node IDs for reverse adjacency
    frozen_reverse_targets: Vec<NodeId>,
}

impl DataFlowGraph {
    /// Creates a new dataflow graph
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            entry_node: None,
            exit_node: None,
            next_node_id: 0,
            next_edge_id: 0,
            forward_adj: HashMap::new(),
            reverse_adj: HashMap::new(),
            frozen_forward_offsets: Vec::new(),
            frozen_forward_targets: Vec::new(),
            frozen_reverse_offsets: Vec::new(),
            frozen_reverse_targets: Vec::new(),
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

    /// Adds an edge to the graph.
    ///
    /// Both endpoints must already exist as nodes; missing endpoints trigger
    /// a debug-level warning and the edge is skipped for those nodes' edge
    /// lists, but still stored in `self.edges` and adjacency maps for
    /// diagnostic purposes.
    ///
    /// **Note:** Adding edges invalidates any frozen CSR state (from a prior
    /// `freeze()` call). The graph must be re-frozen before CSR-accelerated
    /// queries are available again.
    pub fn add_edge(&mut self, edge: DataEdge) -> EdgeId {
        let id = self.next_edge_id;
        self.next_edge_id += 1;

        let from = edge.from;
        let to = edge.to;

        // Validate endpoints exist
        debug_assert!(
            self.nodes.contains_key(&from),
            "add_edge: source node {} does not exist — edges should connect existing nodes",
            from
        );
        debug_assert!(
            self.nodes.contains_key(&to),
            "add_edge: target node {} does not exist — edges should connect existing nodes",
            to
        );

        let mut edge = edge;
        edge.id = id;

        // Invalidate frozen CSR — adjacency has changed
        self.invalidate_csr();

        // Update node connectivity
        if let Some(from_node) = self.nodes.get_mut(&from) {
            from_node.outgoing_edges.push(id);
        } else {
            tracing::debug!(
                "add_edge: source node {} missing, skipping outgoing edge update",
                from
            );
        }
        if let Some(to_node) = self.nodes.get_mut(&to) {
            to_node.incoming_edges.push(id);
        } else {
            tracing::debug!(
                "add_edge: target node {} missing, skipping incoming edge update",
                to
            );
        }

        // Update adjacency lists for O(1) predecessor/successor lookup
        self.forward_adj.entry(from).or_default().push(to);
        self.reverse_adj.entry(to).or_default().push(from);

        self.edges.insert(id, edge);
        id
    }

    /// Gets a node by ID
    pub fn get_node(&self, id: NodeId) -> Option<DataNode> {
        self.nodes.get(&id).cloned()
    }

    /// Gets an edge by ID
    pub fn get_edge(&self, id: EdgeId) -> Option<DataEdge> {
        self.edges.get(&id).cloned()
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
        self.nodes.values().cloned().collect()
    }

    /// Returns all edges
    pub fn all_edges(&self) -> Vec<DataEdge> {
        self.edges.values().cloned().collect()
    }

    /// Returns predecessors of a node.
    ///
    /// When the graph is frozen (CSR), returns a zero-copy slice into the
    /// contiguous predecessor array — O(1) with no allocation.
    /// When unfrozen, clones from the HashMap adjacency list.
    pub fn predecessors(&self, node_id: NodeId) -> &[NodeId] {
        if !self.frozen_reverse_offsets.is_empty() {
            let idx = node_id as usize;
            if idx + 1 < self.frozen_reverse_offsets.len() {
                let start = self.frozen_reverse_offsets[idx];
                let end = self.frozen_reverse_offsets[idx + 1];
                return &self.frozen_reverse_targets[start..end];
            }
            return &[];
        }
        self.reverse_adj
            .get(&node_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns successors of a node.
    ///
    /// When the graph is frozen (CSR), returns a zero-copy slice into the
    /// contiguous successor array — O(1) with no allocation.
    /// When unfrozen, clones from the HashMap adjacency list.
    pub fn successors(&self, node_id: NodeId) -> &[NodeId] {
        if !self.frozen_forward_offsets.is_empty() {
            let idx = node_id as usize;
            if idx + 1 < self.frozen_forward_offsets.len() {
                let start = self.frozen_forward_offsets[idx];
                let end = self.frozen_forward_offsets[idx + 1];
                return &self.frozen_forward_targets[start..end];
            }
            return &[];
        }
        self.forward_adj
            .get(&node_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Freezes the graph into CSR (Compressed Sparse Row) format.
    ///
    /// Converts the HashMap-based adjacency lists into contiguous arrays
    /// for cache-friendly traversal. After freezing:
    /// - `successors()` and `predecessors()` return zero-copy slices.
    /// - The HashMap adjacency lists are cleared to reclaim memory.
    /// - Adding new edges via `add_edge()` will auto-invalidate CSR and
    ///   require re-freezing.
    ///
    /// This is a one-time O(V + E) conversion. Call after all edges are added.
    pub fn freeze(&mut self) {
        let max_id = self.next_node_id as usize;

        // Build forward CSR
        let mut fwd_counts = vec![0usize; max_id + 1];
        for (&src, neighbors) in &self.forward_adj {
            fwd_counts[src as usize] = neighbors.len();
        }

        let mut fwd_offsets = vec![0usize; max_id + 2];
        for i in 0..=max_id {
            fwd_offsets[i + 1] = fwd_offsets[i] + fwd_counts[i];
        }

        let total_fwd = fwd_offsets[max_id + 1];
        let mut fwd_targets = vec![0u64; total_fwd];
        let mut fwd_pos = fwd_offsets.clone();

        for (&src, neighbors) in &self.forward_adj {
            let idx = src as usize;
            for &dst in neighbors {
                let pos = fwd_pos[idx];
                fwd_targets[pos] = dst;
                fwd_pos[idx] += 1;
            }
        }

        // Build reverse CSR
        let mut rev_counts = vec![0usize; max_id + 1];
        for (&dst, neighbors) in &self.reverse_adj {
            rev_counts[dst as usize] = neighbors.len();
        }

        let mut rev_offsets = vec![0usize; max_id + 2];
        for i in 0..=max_id {
            rev_offsets[i + 1] = rev_offsets[i] + rev_counts[i];
        }

        let total_rev = rev_offsets[max_id + 1];
        let mut rev_targets = vec![0u64; total_rev];
        let mut rev_pos = rev_offsets.clone();

        for (&dst, neighbors) in &self.reverse_adj {
            let idx = dst as usize;
            for &src in neighbors {
                let pos = rev_pos[idx];
                rev_targets[pos] = src;
                rev_pos[idx] += 1;
            }
        }

        // Store CSR and free HashMap adjacency lists
        self.frozen_forward_offsets = fwd_offsets;
        self.frozen_forward_targets = fwd_targets;
        self.frozen_reverse_offsets = rev_offsets;
        self.frozen_reverse_targets = rev_targets;
        self.forward_adj.clear();
        self.reverse_adj.clear();
    }

    /// Returns whether the graph is frozen in CSR format.
    pub fn is_frozen(&self) -> bool {
        !self.frozen_forward_offsets.is_empty()
    }

    /// Invalidates frozen CSR data (called internally when edges are added).
    fn invalidate_csr(&mut self) {
        if self.frozen_forward_offsets.is_empty() {
            return;
        }
        // Rebuild HashMap adjacency from frozen CSR before clearing
        let max_id = self.next_node_id as usize;
        for node_idx in 0..max_id {
            let start = self.frozen_forward_offsets[node_idx];
            let end = self.frozen_forward_offsets[node_idx + 1];
            if start < end {
                let neighbors: Vec<NodeId> = self.frozen_forward_targets[start..end].to_vec();
                self.forward_adj.insert(node_idx as NodeId, neighbors);
            }

            let r_start = self.frozen_reverse_offsets[node_idx];
            let r_end = self.frozen_reverse_offsets[node_idx + 1];
            if r_start < r_end {
                let neighbors: Vec<NodeId> = self.frozen_reverse_targets[r_start..r_end].to_vec();
                self.reverse_adj.insert(node_idx as NodeId, neighbors);
            }
        }
        self.frozen_forward_offsets.clear();
        self.frozen_forward_targets.clear();
        self.frozen_reverse_offsets.clear();
        self.frozen_reverse_targets.clear();
    }

    /// Clears the graph
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.edges.clear();
        self.forward_adj.clear();
        self.reverse_adj.clear();
        self.frozen_forward_offsets.clear();
        self.frozen_forward_targets.clear();
        self.frozen_reverse_offsets.clear();
        self.frozen_reverse_targets.clear();
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
        assert_eq!(graph.node_count(), 0, "New graph should have zero nodes");
        assert_eq!(graph.edge_count(), 0, "New graph should have zero edges");
    }

    #[test]
    fn test_add_nodes() {
        let mut graph = DataFlowGraph::new();

        let node1 = DataNode::new(ValueType::Variable("x".to_string()));
        let node2 = DataNode::new(ValueType::Variable("y".to_string()));

        let id1 = graph.add_node(node1);
        let id2 = graph.add_node(node2);

        assert_ne!(
            id1, id2,
            "Graph should assign different IDs to different nodes"
        );
        assert_eq!(graph.node_count(), 2, "Graph should contain two nodes");
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

        assert_eq!(graph.edge_count(), 1, "Graph should contain one edge");

        let successors = graph.successors(id1);
        assert_eq!(successors.len(), 1, "Node should have one successor");
        assert_eq!(successors[0], id2, "Successor should be the target node");
    }

    #[test]
    fn test_memory_location() {
        let loc = MemoryLocation::new("arr").with_offset(8).with_size(4);

        assert_eq!(loc.base, "arr", "Memory location should have correct base");
        assert_eq!(
            loc.offset,
            Some(8),
            "Memory location should have correct offset"
        );
        assert_eq!(
            loc.size,
            Some(4),
            "Memory location should have correct size"
        );
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

    // ── CSR (Compressed Sparse Row) freeze tests ─────────────────────

    /// Objective: Verify that a newly created graph is not frozen.
    /// Invariants: is_frozen() == false for a fresh graph.
    #[test]
    fn test_not_frozen_by_default() {
        let graph = DataFlowGraph::new();
        assert!(!graph.is_frozen(), "New graph must not be frozen");
    }

    /// Objective: Verify freeze() transitions graph to frozen state.
    /// Invariants: After freeze(), is_frozen() == true.
    #[test]
    fn test_freeze_transitions_to_frozen() {
        let mut graph = DataFlowGraph::new();
        let n0 = graph.add_node(DataNode::new(ValueType::Variable("a".to_string())));
        let n1 = graph.add_node(DataNode::new(ValueType::Variable("b".to_string())));
        graph.add_edge(DataEdge::new(n0, n1, EdgeType::Assignment));

        graph.freeze();

        assert!(
            graph.is_frozen(),
            "Graph must be frozen after calling freeze()"
        );
    }

    /// Objective: Verify that freeze on empty graph does not panic.
    /// Invariants: freeze() on an empty graph is a no-op, graph remains unfrozen.
    #[test]
    fn test_freeze_empty_graph_noop() {
        let mut graph = DataFlowGraph::new();
        graph.freeze();
        // Empty graph has no nodes, CSR is vacuously empty
        assert!(
            graph.is_frozen(),
            "freeze() on empty graph should still mark as frozen (vacuously)"
        );
    }

    /// Objective: Verify that CSR successors match HashMap successors after freeze.
    /// Invariants: successors() returns identical node IDs before and after freeze.
    #[test]
    fn test_csr_successors_match_hashmap() {
        let mut graph = DataFlowGraph::new();
        let n0 = graph.add_node(DataNode::new(ValueType::Variable("a".to_string())));
        let n1 = graph.add_node(DataNode::new(ValueType::Variable("b".to_string())));
        let n2 = graph.add_node(DataNode::new(ValueType::Variable("c".to_string())));
        let n3 = graph.add_node(DataNode::new(ValueType::Variable("d".to_string())));

        graph.add_edge(DataEdge::new(n0, n1, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(n0, n2, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(n1, n3, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(n2, n3, EdgeType::Assignment));

        // Snapshot pre-freeze successors
        let pre_succ_n0 = graph.successors(n0).to_vec();
        let pre_succ_n1 = graph.successors(n1).to_vec();
        let pre_succ_n2 = graph.successors(n2).to_vec();

        let pre_pred_n3 = graph.predecessors(n3).to_vec();

        graph.freeze();

        // Verify CSR successors match pre-freeze values
        assert_eq!(
            graph.successors(n0),
            pre_succ_n0.as_slice(),
            "CSR successors for n0 must match pre-freeze"
        );
        assert_eq!(
            graph.successors(n1),
            pre_succ_n1.as_slice(),
            "CSR successors for n1 must match pre-freeze"
        );
        assert_eq!(
            graph.successors(n2),
            pre_succ_n2.as_slice(),
            "CSR successors for n2 must match pre-freeze"
        );
        assert!(
            graph.successors(n3).is_empty(),
            "n3 must have no successors"
        );

        // Verify CSR predecessors match pre-freeze values
        assert!(
            graph.predecessors(n0).is_empty(),
            "n0 must have no predecessors"
        );
        assert_eq!(
            graph.predecessors(n3),
            pre_pred_n3.as_slice(),
            "CSR predecessors for n3 must match pre-freeze"
        );
    }

    /// Objective: Verify that CSR handles self-loops correctly.
    /// Invariants: A self-loop node must appear in its own successors list after freeze.
    #[test]
    fn test_csr_self_loop() {
        let mut graph = DataFlowGraph::new();
        let n = graph.add_node(DataNode::new(ValueType::Variable("loop".to_string())));
        graph.add_edge(DataEdge::new(n, n, EdgeType::Assignment));

        graph.freeze();

        let succs = graph.successors(n);
        assert_eq!(
            succs.len(),
            1,
            "Self-loop node must have exactly 1 successor"
        );
        assert_eq!(succs[0], n, "Self-loop successor must be the node itself");

        let preds = graph.predecessors(n);
        assert_eq!(
            preds.len(),
            1,
            "Self-loop node must have exactly 1 predecessor"
        );
        assert_eq!(preds[0], n, "Self-loop predecessor must be the node itself");
    }

    /// Objective: Verify that add_edge after freeze invalidates CSR and
    /// requires re-freezing for CSR queries.
    /// Invariants: After add_edge, is_frozen()==false; after re-freeze,
    /// successors reflect the new edge.
    #[test]
    fn test_add_edge_invalidates_csr() {
        let mut graph = DataFlowGraph::new();
        let n0 = graph.add_node(DataNode::new(ValueType::Variable("a".to_string())));
        let n1 = graph.add_node(DataNode::new(ValueType::Variable("b".to_string())));
        let n2 = graph.add_node(DataNode::new(ValueType::Variable("c".to_string())));

        graph.add_edge(DataEdge::new(n0, n1, EdgeType::Assignment));
        graph.freeze();

        assert!(graph.is_frozen(), "Must be frozen after freeze()");

        // Add a new edge — should invalidate CSR
        graph.add_edge(DataEdge::new(n0, n2, EdgeType::Assignment));
        assert!(
            !graph.is_frozen(),
            "CSR must be invalidated after add_edge()"
        );

        // Re-freeze and verify new edge is included
        graph.freeze();
        assert!(graph.is_frozen(), "Must be frozen after re-freeze()");

        let succs = graph.successors(n0);
        assert!(succs.contains(&n1), "n0 successors must still contain n1");
        assert!(succs.contains(&n2), "n0 successors must now include n2");
    }

    /// Objective: Verify that clear() resets frozen CSR state.
    /// Invariants: After clear(), is_frozen()==false, node_count()==0.
    #[test]
    fn test_clear_resets_frozen_state() {
        let mut graph = DataFlowGraph::new();
        let n0 = graph.add_node(DataNode::new(ValueType::Variable("a".to_string())));
        let n1 = graph.add_node(DataNode::new(ValueType::Variable("b".to_string())));
        graph.add_edge(DataEdge::new(n0, n1, EdgeType::Assignment));
        graph.freeze();

        assert!(graph.is_frozen(), "Must be frozen before clear()");

        graph.clear();

        assert!(!graph.is_frozen(), "Must not be frozen after clear()");
        assert_eq!(graph.node_count(), 0, "Must have 0 nodes after clear()");
    }

    /// Objective: Verify CSR on a larger diamond DAG with multiple edges.
    /// Invariants: All successor/predecessor relationships are preserved
    /// through the freeze conversion for a non-trivial graph.
    #[test]
    fn test_csr_diamond_dag() {
        // Build: entry → left, entry → right, left → merge, right → merge
        let mut graph = DataFlowGraph::new();
        let entry = graph.add_node(DataNode::new(ValueType::Variable("entry".into())));
        let left = graph.add_node(DataNode::new(ValueType::Variable("left".into())));
        let right = graph.add_node(DataNode::new(ValueType::Variable("right".into())));
        let merge = graph.add_node(DataNode::new(ValueType::Variable("merge".into())));

        graph.add_edge(DataEdge::new(entry, left, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(entry, right, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(left, merge, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(right, merge, EdgeType::Assignment));

        graph.freeze();

        // Entry has 2 successors
        let entry_succs = graph.successors(entry);
        assert_eq!(entry_succs.len(), 2, "Entry must have 2 successors");
        assert!(entry_succs.contains(&left), "Entry must reach left");
        assert!(entry_succs.contains(&right), "Entry must reach right");

        // Merge has 2 predecessors
        let merge_preds = graph.predecessors(merge);
        assert_eq!(merge_preds.len(), 2, "Merge must have 2 predecessors");
        assert!(
            merge_preds.contains(&left),
            "Merge must be reached from left"
        );
        assert!(
            merge_preds.contains(&right),
            "Merge must be reached from right"
        );

        // Entry has no predecessors
        assert!(
            graph.predecessors(entry).is_empty(),
            "Entry must have no predecessors"
        );

        // Merge has no successors
        assert!(
            graph.successors(merge).is_empty(),
            "Merge must have no successors"
        );
    }

    /// Objective: Verify that CSR produces zero-copy slices (same pointer identity).
    /// Invariants: Two calls to successors() with the same node return
    /// the same underlying memory slice (not just equal content).
    #[test]
    fn test_csr_returns_same_slice() {
        let mut graph = DataFlowGraph::new();
        let n0 = graph.add_node(DataNode::new(ValueType::Variable("a".into())));
        let n1 = graph.add_node(DataNode::new(ValueType::Variable("b".into())));
        graph.add_edge(DataEdge::new(n0, n1, EdgeType::Assignment));
        graph.freeze();

        let slice1 = graph.successors(n0);
        let slice2 = graph.successors(n0);

        assert_eq!(
            slice1.as_ptr(),
            slice2.as_ptr(),
            "CSR must return the same slice pointer for repeated queries (zero-copy)"
        );
    }

    /// Objective: Verify that freeze preserves data through a cycle.
    /// Invariants: In a cycle a→b→c→a, each node's successor and predecessor
    /// lists are identical before and after freeze.
    #[test]
    fn test_csr_preserves_cycle() {
        let mut graph = DataFlowGraph::new();
        let a = graph.add_node(DataNode::new(ValueType::Variable("a".into())));
        let b = graph.add_node(DataNode::new(ValueType::Variable("b".into())));
        let c = graph.add_node(DataNode::new(ValueType::Variable("c".into())));

        graph.add_edge(DataEdge::new(a, b, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(b, c, EdgeType::Assignment));
        graph.add_edge(DataEdge::new(c, a, EdgeType::Assignment));

        let pre_a_succ = graph.successors(a).to_vec();
        let pre_b_succ = graph.successors(b).to_vec();
        let pre_c_succ = graph.successors(c).to_vec();
        let pre_a_pred = graph.predecessors(a).to_vec();
        let pre_b_pred = graph.predecessors(b).to_vec();
        let pre_c_pred = graph.predecessors(c).to_vec();

        graph.freeze();

        assert_eq!(graph.successors(a), pre_a_succ.as_slice(), "a successors");
        assert_eq!(graph.successors(b), pre_b_succ.as_slice(), "b successors");
        assert_eq!(graph.successors(c), pre_c_succ.as_slice(), "c successors");
        assert_eq!(
            graph.predecessors(a),
            pre_a_pred.as_slice(),
            "a predecessors"
        );
        assert_eq!(
            graph.predecessors(b),
            pre_b_pred.as_slice(),
            "b predecessors"
        );
        assert_eq!(
            graph.predecessors(c),
            pre_c_pred.as_slice(),
            "c predecessors"
        );
    }

    /// Objective: Verify that querying successors for a non-existent node
    /// after freeze returns an empty slice (no panic).
    /// Invariants: CSR query for out-of-range node returns &[], no panic.
    #[test]
    fn test_csr_out_of_range_node_returns_empty() {
        let mut graph = DataFlowGraph::new();
        let n0 = graph.add_node(DataNode::new(ValueType::Variable("a".into())));
        let n1 = graph.add_node(DataNode::new(ValueType::Variable("b".into())));
        graph.add_edge(DataEdge::new(n0, n1, EdgeType::Assignment));
        graph.freeze();

        // Node ID 999 was never added
        assert!(
            graph.successors(999).is_empty(),
            "CSR query for non-existent node must return empty slice"
        );
        assert!(
            graph.predecessors(999).is_empty(),
            "CSR predecessor query for non-existent node must return empty slice"
        );
    }
}
