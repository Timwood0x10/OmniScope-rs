//! Memory graph for resource lifecycle tracking.
//!
//! This module provides a unified graph representation for tracking resource
//! lifecycle across function boundaries. It captures:
//!
//! - Resource class (heap, mmap, fd, socket, etc.)
//! - Resource state (acquired, released, escaped, stored)
//! - Memory edges (acquire, release, store, escape, alias, use)
//!
//! The MemoryGraph is built during contract graph construction and provides
//! a queryable interface for downstream analysis passes.

use omniscope_types::FamilyId;

/// Resource class categorization.
///
/// Groups resources by their underlying storage mechanism and management model.
/// This is a higher-level abstraction than `FamilyId` — multiple families can
/// map to the same resource class (e.g., C_HEAP, CPP_NEW_SCALAR, RUST_GLOBAL
/// all map to HeapMemory).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceClass {
    /// Heap-allocated memory (malloc, new, Box, etc.)
    HeapMemory,
    /// Memory-mapped regions (mmap, VirtualAlloc, etc.)
    MmapRegion,
    /// File descriptors (open, creat, socket, etc.)
    FileDescriptor,
    /// Network sockets (socket, accept, connect, etc.)
    Socket,
    /// Process handles (fork, CreateProcess, etc.)
    ProcessHandle,
    /// Thread handles (pthread_create, CreateThread, etc.)
    ThreadHandle,
    /// Runtime-managed resources (GC, refcount, etc.)
    RuntimeManaged,
    /// Unknown or unclassified resource.
    Unknown,
}

/// Resource state in the memory graph.
///
/// Tracks the lifecycle state of a resource instance. Transitions follow
/// a deterministic state machine: Unknown → Owned → Released/Escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceState {
    /// Initial or unknown state.
    Unknown,
    /// Null pointer or invalid resource.
    Null,
    /// Resource is owned (acquired, not yet released).
    Owned,
    /// Resource has been released.
    Released,
    /// Resource escapes to caller (return value).
    EscapedToCaller,
    /// Resource escapes via output parameter.
    EscapedToOutParam,
    /// Resource stored to an owner object (field assignment).
    StoredToOwner,
    /// Resource stored to runtime (GC, refcount).
    StoredToRuntime,
    /// Resource managed by runtime (GC-managed, refcounted).
    RuntimeManaged,
}

/// Memory edge kind.
///
/// Describes the relationship between two resource instances or the
/// effect of an operation on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryEdgeKind {
    /// Resource acquisition (malloc, new, Box::new, etc.)
    Acquire,
    /// Resource release (free, delete, close, etc.)
    Release,
    /// Resource stored to an owner object (field assignment).
    StoreToOwner,
    /// Resource stored to runtime (GC root, refcount increment).
    StoreToRuntime,
    /// Resource returned to caller (return statement).
    ReturnToCaller,
    /// Output parameter initialization.
    InitOutParam,
    /// Null on error path (conditional allocation failure).
    NullOnErrorPath,
    /// Alias relationship (two pointers to same resource).
    Alias,
    /// Use relationship (non-owning access).
    Use,
}

/// Memory node representing a resource instance.
///
/// Each node corresponds to a unique resource instance identified by its ID.
/// The node tracks the resource's class, current state, and associated metadata.
#[derive(Debug, Clone)]
pub struct MemoryNode {
    /// Unique identifier for this resource instance.
    pub id: u64,
    /// Resource class (heap, fd, socket, etc.)
    pub resource_class: ResourceClass,
    /// Current lifecycle state.
    pub state: ResourceState,
    /// Function where this resource was created.
    pub function_name: String,
    /// Resource family (if known).
    pub family_id: Option<FamilyId>,
}

/// Memory edge representing resource flow.
///
/// Edges capture the relationships between resource instances: acquire→release,
/// acquire→escape, store→owner, etc.
#[derive(Debug, Clone)]
pub struct MemoryEdge {
    /// Source resource instance ID.
    pub source: u64,
    /// Target resource instance ID.
    pub target: u64,
    /// Edge kind.
    pub kind: MemoryEdgeKind,
    /// Function where this edge occurs.
    pub function_name: String,
}

/// Memory graph for resource tracking.
///
/// Provides a unified representation of resource lifecycle across function
/// boundaries. Nodes represent resource instances, edges represent lifecycle
/// transitions and relationships.
#[derive(Debug, Clone)]
pub struct MemoryGraph {
    /// All resource nodes.
    pub nodes: Vec<MemoryNode>,
    /// All memory edges.
    pub edges: Vec<MemoryEdge>,
    /// Index for fast node lookup by ID.
    node_index: std::collections::HashMap<u64, usize>,
    /// Index for fast lookup by value/alias.
    value_index: std::collections::HashMap<u64, u64>,
}

impl MemoryGraph {
    /// Creates a new empty memory graph.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            node_index: std::collections::HashMap::new(),
            value_index: std::collections::HashMap::new(),
        }
    }

    /// Adds a node to the graph.
    ///
    /// # Arguments
    /// * `node` - The memory node to add.
    ///
    /// # Returns
    /// The node ID.
    pub fn add_node(&mut self, node: MemoryNode) -> u64 {
        let id = node.id;
        let index = self.nodes.len();
        self.nodes.push(node);
        self.node_index.insert(id, index);
        id
    }

    /// Adds an edge to the graph.
    ///
    /// # Arguments
    /// * `edge` - The memory edge to add.
    pub fn add_edge(&mut self, edge: MemoryEdge) {
        self.edges.push(edge);
    }

    /// Gets a node by ID.
    ///
    /// # Arguments
    /// * `id` - The resource instance ID.
    ///
    /// # Returns
    /// A reference to the node if found.
    pub fn get_node(&self, id: u64) -> Option<&MemoryNode> {
        self.node_index.get(&id).map(|&idx| &self.nodes[idx])
    }

    /// Gets a mutable reference to a node by ID.
    ///
    /// # Arguments
    /// * `id` - The resource instance ID.
    ///
    /// # Returns
    /// A mutable reference to the node if found.
    pub fn get_node_mut(&mut self, id: u64) -> Option<&mut MemoryNode> {
        self.node_index.get(&id).map(|&idx| &mut self.nodes[idx])
    }

    /// Gets the state of a resource.
    ///
    /// # Arguments
    /// * `id` - The resource instance ID.
    ///
    /// # Returns
    /// The resource state if found.
    pub fn get_state(&self, id: u64) -> Option<ResourceState> {
        self.get_node(id).map(|node| node.state)
    }

    /// Sets the state of a resource.
    ///
    /// # Arguments
    /// * `id` - The resource instance ID.
    /// * `state` - The new state.
    pub fn set_state(&mut self, id: u64, state: ResourceState) {
        if let Some(node) = self.get_node_mut(id) {
            node.state = state;
        }
    }

    /// Finds a resource by value/alias.
    ///
    /// # Arguments
    /// * `value` - The value/alias to search for.
    ///
    /// # Returns
    /// The resource ID if found.
    pub fn find_by_value(&self, value: u64) -> Option<u64> {
        self.value_index.get(&value).copied()
    }

    /// Registers a value/alias mapping.
    ///
    /// # Arguments
    /// * `value` - The value/alias.
    /// * `resource_id` - The resource ID.
    pub fn register_value(&mut self, value: u64, resource_id: u64) {
        self.value_index.insert(value, resource_id);
    }

    /// Gets the number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Gets the number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Returns an iterator over all edges of a specific kind.
    pub fn edges_of_kind(&self, kind: MemoryEdgeKind) -> impl Iterator<Item = &MemoryEdge> {
        self.edges.iter().filter(move |e| e.kind == kind)
    }

    /// Returns all edges from a specific source.
    pub fn edges_from(&self, source: u64) -> impl Iterator<Item = &MemoryEdge> {
        self.edges.iter().filter(move |e| e.source == source)
    }

    /// Returns all edges to a specific target.
    pub fn edges_to(&self, target: u64) -> impl Iterator<Item = &MemoryEdge> {
        self.edges.iter().filter(move |e| e.target == target)
    }
}

impl Default for MemoryGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps a FamilyId to a ResourceClass.
///
/// # Arguments
/// * `family_id` - The resource family ID.
///
/// # Returns
/// The corresponding resource class.
pub fn family_to_resource_class(family_id: FamilyId) -> ResourceClass {
    match family_id {
        // Heap memory families
        FamilyId::C_HEAP
        | FamilyId::CPP_NEW_SCALAR
        | FamilyId::CPP_NEW_ARRAY
        | FamilyId::RUST_GLOBAL
        | FamilyId::RUST_RAW_OWNERSHIP
        | FamilyId::PYTHON_MEM
        | FamilyId::PYTHON_MEM_RAW
        | FamilyId::MIMALLOC
        | FamilyId::GO_CGO => ResourceClass::HeapMemory,

        // Garbage-collected or refcounted families
        FamilyId::GO_GC | FamilyId::PYTHON_OBJECT => ResourceClass::RuntimeManaged,

        // Handle-based families
        // Note: JAVA_LOCAL_REF and JAVA_GLOBAL_REF are JVM-managed references,
        // NOT OS handles. They require explicit release (DeleteLocalRef/DeleteGlobalRef)
        // and can leak. Classify as RuntimeManaged so is_memory_resource() returns true.
        FamilyId::JAVA_LOCAL_REF | FamilyId::JAVA_GLOBAL_REF => ResourceClass::RuntimeManaged,

        // File descriptor family
        FamilyId::FILE_DESCRIPTOR => ResourceClass::FileDescriptor,

        // Library-managed families (default to heap)
        FamilyId::ZLIB_STREAM
        | FamilyId::OPENSSL_RESOURCE
        | FamilyId::SQLITE_RESOURCE
        | FamilyId::CSHARP_HGLOBAL
        | FamilyId::CSHARP_COTASK
        | FamilyId::CSHARP_COM => ResourceClass::HeapMemory,

        // Unknown family
        _ => ResourceClass::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test node.
    fn create_test_node(
        id: u64,
        resource_class: ResourceClass,
        state: ResourceState,
    ) -> MemoryNode {
        MemoryNode {
            id,
            resource_class,
            state,
            function_name: "test_function".to_string(),
            family_id: Some(FamilyId::C_HEAP),
        }
    }

    /// Helper to create a test edge.
    fn create_test_edge(source: u64, target: u64, kind: MemoryEdgeKind) -> MemoryEdge {
        MemoryEdge {
            source,
            target,
            kind,
            function_name: "test_function".to_string(),
        }
    }

    /// Objective: Verify acquire→release flow tracking.
    /// Invariants: Acquired resource must transition to Released state.
    #[test]
    fn test_acquire_release_flow() {
        let mut graph = MemoryGraph::new();

        // Create a resource and mark as acquired
        let node = create_test_node(1, ResourceClass::HeapMemory, ResourceState::Owned);
        graph.add_node(node);

        // Add acquire edge
        graph.add_edge(create_test_edge(0, 1, MemoryEdgeKind::Acquire));

        // Verify initial state
        assert_eq!(
            graph.get_state(1),
            Some(ResourceState::Owned),
            "Resource should be in Owned state after acquire"
        );

        // Add release edge and update state
        graph.add_edge(create_test_edge(1, 0, MemoryEdgeKind::Release));
        graph.set_state(1, ResourceState::Released);

        // Verify final state
        assert_eq!(
            graph.get_state(1),
            Some(ResourceState::Released),
            "Resource should be in Released state after release"
        );

        // Verify edge counts
        assert_eq!(
            graph.edge_count(),
            2,
            "Should have 2 edges (acquire + release)"
        );
        assert_eq!(graph.node_count(), 1, "Should have 1 node");
    }

    /// Objective: Verify escape-to-caller tracking.
    /// Invariants: Escaped resource must be marked as EscapedToCaller.
    #[test]
    fn test_escape_to_caller() {
        let mut graph = MemoryGraph::new();

        // Create a resource
        let node = create_test_node(1, ResourceClass::HeapMemory, ResourceState::Owned);
        graph.add_node(node);

        // Add acquire edge
        graph.add_edge(create_test_edge(0, 1, MemoryEdgeKind::Acquire));

        // Add escape edge (return to caller)
        graph.add_edge(create_test_edge(1, 0, MemoryEdgeKind::ReturnToCaller));
        graph.set_state(1, ResourceState::EscapedToCaller);

        // Verify state
        assert_eq!(
            graph.get_state(1),
            Some(ResourceState::EscapedToCaller),
            "Resource should be in EscapedToCaller state"
        );

        // Verify edge kind
        let escape_edges: Vec<_> = graph
            .edges_of_kind(MemoryEdgeKind::ReturnToCaller)
            .collect();
        assert_eq!(escape_edges.len(), 1, "Should have 1 return-to-caller edge");
    }

    /// Objective: Verify store-to-owner tracking.
    /// Invariants: Stored resource must be marked as StoredToOwner.
    #[test]
    fn test_store_to_owner() {
        let mut graph = MemoryGraph::new();

        // Create a resource and an owner
        let resource = create_test_node(1, ResourceClass::HeapMemory, ResourceState::Owned);
        let owner = create_test_node(2, ResourceClass::HeapMemory, ResourceState::Owned);
        graph.add_node(resource);
        graph.add_node(owner);

        // Add acquire edge
        graph.add_edge(create_test_edge(0, 1, MemoryEdgeKind::Acquire));

        // Add store-to-owner edge
        graph.add_edge(create_test_edge(1, 2, MemoryEdgeKind::StoreToOwner));
        graph.set_state(1, ResourceState::StoredToOwner);

        // Verify state
        assert_eq!(
            graph.get_state(1),
            Some(ResourceState::StoredToOwner),
            "Resource should be in StoredToOwner state"
        );

        // Verify edge
        let store_edges: Vec<_> = graph.edges_of_kind(MemoryEdgeKind::StoreToOwner).collect();
        assert_eq!(store_edges.len(), 1, "Should have 1 store-to-owner edge");
    }

    /// Objective: Verify alias tracking.
    /// Invariants: Two nodes can be linked via Alias edge.
    #[test]
    fn test_alias_tracking() {
        let mut graph = MemoryGraph::new();

        // Create two resources
        let node1 = create_test_node(1, ResourceClass::HeapMemory, ResourceState::Owned);
        let node2 = create_test_node(2, ResourceClass::HeapMemory, ResourceState::Owned);
        graph.add_node(node1);
        graph.add_node(node2);

        // Add alias edge
        graph.add_edge(create_test_edge(1, 2, MemoryEdgeKind::Alias));

        // Verify alias edges
        let alias_edges: Vec<_> = graph.edges_of_kind(MemoryEdgeKind::Alias).collect();
        assert_eq!(alias_edges.len(), 1, "Should have 1 alias edge");

        // Verify edges from source
        let edges_from_1: Vec<_> = graph.edges_from(1).collect();
        assert_eq!(edges_from_1.len(), 1, "Should have 1 edge from node 1");

        // Verify edges to target
        let edges_to_2: Vec<_> = graph.edges_to(2).collect();
        assert_eq!(edges_to_2.len(), 1, "Should have 1 edge to node 2");
    }

    /// Objective: Verify state transitions.
    /// Invariants: State must transition correctly through lifecycle.
    #[test]
    fn test_state_transitions() {
        let mut graph = MemoryGraph::new();

        // Create a resource
        let node = create_test_node(1, ResourceClass::HeapMemory, ResourceState::Unknown);
        graph.add_node(node);

        // Test state transitions
        assert_eq!(
            graph.get_state(1),
            Some(ResourceState::Unknown),
            "Initial state should be Unknown"
        );

        // Transition: Unknown → Owned
        graph.set_state(1, ResourceState::Owned);
        assert_eq!(
            graph.get_state(1),
            Some(ResourceState::Owned),
            "Should transition to Owned"
        );

        // Transition: Owned → EscapedToCaller
        graph.set_state(1, ResourceState::EscapedToCaller);
        assert_eq!(
            graph.get_state(1),
            Some(ResourceState::EscapedToCaller),
            "Should transition to EscapedToCaller"
        );

        // Transition: EscapedToCaller → Released
        graph.set_state(1, ResourceState::Released);
        assert_eq!(
            graph.get_state(1),
            Some(ResourceState::Released),
            "Should transition to Released"
        );
    }

    /// Objective: Verify value/alias lookup.
    /// Invariants: find_by_value must return correct resource ID.
    #[test]
    fn test_value_lookup() {
        let mut graph = MemoryGraph::new();

        // Create a resource
        let node = create_test_node(1, ResourceClass::HeapMemory, ResourceState::Owned);
        graph.add_node(node);

        // Register value mapping
        graph.register_value(0x1000, 1);

        // Lookup by value
        assert_eq!(
            graph.find_by_value(0x1000),
            Some(1),
            "Should find resource by value"
        );

        // Lookup non-existent value
        assert_eq!(
            graph.find_by_value(0x2000),
            None,
            "Should return None for non-existent value"
        );
    }

    /// Objective: Verify family_to_resource_class mapping.
    /// Invariants: All heap families must map to HeapMemory.
    #[test]
    fn test_family_to_resource_class_mapping() {
        // Heap families
        assert_eq!(
            family_to_resource_class(FamilyId::C_HEAP),
            ResourceClass::HeapMemory,
            "C_HEAP should map to HeapMemory"
        );
        assert_eq!(
            family_to_resource_class(FamilyId::CPP_NEW_SCALAR),
            ResourceClass::HeapMemory,
            "CPP_NEW_SCALAR should map to HeapMemory"
        );
        assert_eq!(
            family_to_resource_class(FamilyId::RUST_GLOBAL),
            ResourceClass::HeapMemory,
            "RUST_GLOBAL should map to HeapMemory"
        );

        // Runtime-managed families
        assert_eq!(
            family_to_resource_class(FamilyId::GO_GC),
            ResourceClass::RuntimeManaged,
            "GO_GC should map to RuntimeManaged"
        );
        assert_eq!(
            family_to_resource_class(FamilyId::PYTHON_OBJECT),
            ResourceClass::RuntimeManaged,
            "PYTHON_OBJECT should map to RuntimeManaged"
        );

        // JNI references are runtime-managed (JVM refs, not OS handles)
        assert_eq!(
            family_to_resource_class(FamilyId::JAVA_LOCAL_REF),
            ResourceClass::RuntimeManaged,
            "JAVA_LOCAL_REF should map to RuntimeManaged"
        );

        // File descriptor family
        assert_eq!(
            family_to_resource_class(FamilyId::FILE_DESCRIPTOR),
            ResourceClass::FileDescriptor,
            "FILE_DESCRIPTOR should map to FileDescriptor"
        );

        // Unknown family
        assert_eq!(
            family_to_resource_class(FamilyId(999)),
            ResourceClass::Unknown,
            "Unknown family should map to Unknown"
        );
    }
}
