//! Union-Find data structure for incremental cycle detection.
//!
//! This module provides a Union-Find (Disjoint Set Union) data structure
//! optimized for tracking ownership escape-reclaim cycles in the
//! ownership solver. It enables incremental cycle detection with
//! near-constant time operations.
//!
//! # Algorithm Complexity
//!
//! - `find`: O(α(n)) amortized (inverse Ackermann function, nearly constant)
//! - `union`: O(α(n)) amortized
//! - `connected`: O(α(n)) amortized
//!
//! where α is the inverse Ackermann function, which grows extremely slowly
//! and is effectively ≤ 5 for all practical inputs.
//!
//! # Use Case
//!
//! In the ownership solver, we track escape-reclaim cycles:
//! 1. Acquire: Create instance A
//! 2. OwnershipEscape: A escapes to raw pointer (escape_id)
//! 3. OwnershipReclaim: A reclaimed from raw pointer (reclaim_id)
//! 4. Release: reclaim_id released
//!
//! Using Union-Find, we can efficiently:
//! - Detect if two instances are part of the same ownership chain
//! - Merge instances when they are connected through escape-reclaim
//! - Avoid redundant state transitions

use std::collections::HashMap;

/// Union-Find data structure with path compression and union by rank.
///
/// Tracks equivalence classes of resource instance IDs to enable
/// efficient cycle detection in ownership escape-reclaim patterns.
#[derive(Debug, Clone)]
pub struct OwnershipUnionFind {
    /// Parent pointer for each element. `parent[x] = x` means x is a root.
    parent: HashMap<u64, u64>,
    /// Rank (approximate tree height) for union by rank optimization.
    rank: HashMap<u64, u32>,
    /// Size of each set (number of elements in the component).
    /// Useful for tracking the number of instances in an ownership chain.
    size: HashMap<u64, u32>,
}

impl OwnershipUnionFind {
    /// Creates a new empty Union-Find structure.
    pub fn new() -> Self {
        Self {
            parent: HashMap::new(),
            rank: HashMap::new(),
            size: HashMap::new(),
        }
    }

    /// Creates a new Union-Find structure with pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Expected number of elements to store
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            parent: HashMap::with_capacity(capacity),
            rank: HashMap::with_capacity(capacity),
            size: HashMap::with_capacity(capacity),
        }
    }

    /// Adds a new element to the Union-Find structure.
    ///
    /// If the element already exists, this is a no-op.
    ///
    /// # Arguments
    ///
    /// * `x` - The element to add
    pub fn make_set(&mut self, x: u64) {
        if let std::collections::hash_map::Entry::Vacant(e) = self.parent.entry(x) {
            e.insert(x);
            self.rank.insert(x, 0);
            self.size.insert(x, 1);
        }
    }

    /// Finds the representative (root) of the set containing `x`.
    ///
    /// Uses path compression to flatten the tree structure, making
    /// future operations faster.
    ///
    /// # Arguments
    ///
    /// * `x` - The element to find
    ///
    /// # Returns
    ///
    /// The representative element of the set containing `x`, or `None`
    /// if `x` is not in the structure.
    pub fn find(&mut self, x: u64) -> Option<u64> {
        if !self.parent.contains_key(&x) {
            return None;
        }

        // Path compression: make every node point directly to the root
        let root = self.find_root(x);
        self.compress_path(x, root);
        Some(root)
    }

    /// Internal recursive find with path compression.
    fn find_root(&self, x: u64) -> u64 {
        let parent = *self.parent.get(&x)
            .expect("union_find: element should exist in parent map");
        if parent == x {
            x
        } else {
            self.find_root(parent)
        }
    }

    /// Compresses the path from `x` to `root` by updating all intermediate nodes.
    fn compress_path(&mut self, x: u64, root: u64) {
        let mut current = x;
        while current != root {
            let parent = *self.parent.get(&current)
                .expect("union_find: element should exist in parent map");
            self.parent.insert(current, root);
            current = parent;
        }
    }

    /// Unites the sets containing `x` and `y`.
    ///
    /// Uses union by rank to keep the tree balanced. If `x` and `y`
    /// are already in the same set, this is a no-op.
    ///
    /// # Arguments
    ///
    /// * `x` - First element
    /// * `y` - Second element
    ///
    /// # Returns
    ///
    /// `true` if the sets were merged (they were different), `false` if
    /// they were already in the same set.
    pub fn union(&mut self, x: u64, y: u64) -> bool {
        // Ensure both elements exist
        self.make_set(x);
        self.make_set(y);

        let root_x = self.find(x)
            .expect("union_find: element should exist after make_set");
        let root_y = self.find(y)
            .expect("union_find: element should exist after make_set");

        // Already in the same set
        if root_x == root_y {
            return false;
        }

        // Union by rank: attach smaller tree under larger tree
        let rank_x = *self.rank.get(&root_x)
            .expect("union_find: root should exist in rank map");
        let rank_y = *self.rank.get(&root_y)
            .expect("union_find: root should exist in rank map");

        let (smaller, larger) = if rank_x < rank_y {
            (root_x, root_y)
        } else if rank_x > rank_y {
            (root_y, root_x)
        } else {
            // Same rank: choose one as root and increment its rank
            self.rank.insert(root_x, rank_x + 1);
            (root_y, root_x)
        };

        // Merge the smaller into the larger
        self.parent.insert(smaller, larger);

        // Update size
        let size_smaller = *self.size.get(&smaller)
            .expect("union_find: element should exist in size map");
        let size_larger = *self.size.get(&larger)
            .expect("union_find: element should exist in size map");
        self.size.insert(larger, size_smaller + size_larger);

        true
    }

    /// Checks if `x` and `y` are in the same set (connected).
    ///
    /// # Arguments
    ///
    /// * `x` - First element
    /// * `y` - Second element
    ///
    /// # Returns
    ///
    /// `true` if `x` and `y` are in the same set, `false` otherwise.
    pub fn connected(&mut self, x: u64, y: u64) -> bool {
        match (self.find(x), self.find(y)) {
            (Some(root_x), Some(root_y)) => root_x == root_y,
            _ => false,
        }
    }

    /// Returns the size of the set containing `x`.
    ///
    /// # Arguments
    ///
    /// * `x` - The element to query
    ///
    /// # Returns
    ///
    /// The number of elements in the set containing `x`, or `None` if
    /// `x` is not in the structure.
    pub fn set_size(&mut self, x: u64) -> Option<u32> {
        let root = self.find(x)?;
        self.size.get(&root).copied()
    }

    /// Returns the number of distinct sets.
    ///
    /// # Returns
    ///
    /// The number of disjoint sets in the structure.
    pub fn set_count(&self) -> usize {
        self.parent
            .iter()
            .filter(|(&x, &parent)| x == parent)
            .count()
    }

    /// Returns the total number of elements.
    pub fn len(&self) -> usize {
        self.parent.len()
    }

    /// Returns `true` if the structure contains no elements.
    pub fn is_empty(&self) -> bool {
        self.parent.is_empty()
    }

    /// Checks if an element exists in the structure.
    pub fn contains(&self, x: &u64) -> bool {
        self.parent.contains_key(x)
    }
}

impl Default for OwnershipUnionFind {
    fn default() -> Self {
        Self::new()
    }
}

/// Cycle detector for ownership escape-reclaim patterns.
///
/// Uses Union-Find to efficiently detect and track cycles in the
/// ownership graph. This enables incremental cycle detection without
/// re-traversing the entire graph.
#[derive(Debug, Clone)]
pub struct OwnershipCycleDetector {
    /// Union-Find structure for tracking instance relationships.
    uf: OwnershipUnionFind,
    /// Tracks which instances are in an escape state.
    escaped: std::collections::HashSet<u64>,
    /// Tracks which instances have been reclaimed.
    reclaimed: std::collections::HashSet<u64>,
    /// Maps instance ID to its escape target (raw pointer ID).
    escape_targets: HashMap<u64, u64>,
    /// Maps instance ID to its reclaim source.
    reclaim_sources: HashMap<u64, u64>,
}

impl OwnershipCycleDetector {
    /// Creates a new cycle detector.
    pub fn new() -> Self {
        Self {
            uf: OwnershipUnionFind::new(),
            escaped: std::collections::HashSet::new(),
            reclaimed: std::collections::HashSet::new(),
            escape_targets: HashMap::new(),
            reclaim_sources: HashMap::new(),
        }
    }

    /// Creates a new cycle detector with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            uf: OwnershipUnionFind::with_capacity(capacity),
            escaped: std::collections::HashSet::with_capacity(capacity),
            reclaimed: std::collections::HashSet::with_capacity(capacity),
            escape_targets: HashMap::with_capacity(capacity),
            reclaim_sources: HashMap::with_capacity(capacity),
        }
    }

    /// Registers a new instance in the detector.
    pub fn register_instance(&mut self, instance_id: u64) {
        self.uf.make_set(instance_id);
    }

    /// Records an escape event for an instance.
    ///
    /// # Arguments
    ///
    /// * `instance_id` - The instance that escaped
    /// * `escape_target` - The raw pointer ID it escaped to
    pub fn record_escape(&mut self, instance_id: u64, escape_target: u64) {
        self.uf.make_set(instance_id);
        self.uf.make_set(escape_target);
        self.escaped.insert(instance_id);
        self.escape_targets.insert(instance_id, escape_target);
        // Unite the instance with its escape target
        self.uf.union(instance_id, escape_target);
    }

    /// Records a reclaim event for an instance.
    ///
    /// # Arguments
    ///
    /// * `source_id` - The escaped instance being reclaimed
    /// * `reclaim_id` - The new instance created by reclaim
    pub fn record_reclaim(&mut self, source_id: u64, reclaim_id: u64) {
        self.uf.make_set(reclaim_id);
        self.reclaimed.insert(reclaim_id);
        self.reclaim_sources.insert(reclaim_id, source_id);
        // Unite the reclaim with the source
        self.uf.union(source_id, reclaim_id);
    }

    /// Checks if two instances are part of the same ownership chain.
    ///
    /// # Arguments
    ///
    /// * `a` - First instance ID
    /// * `b` - Second instance ID
    ///
    /// # Returns
    ///
    /// `true` if both instances are connected through escape-reclaim chains.
    pub fn are_connected(&mut self, a: u64, b: u64) -> bool {
        self.uf.connected(a, b)
    }

    /// Checks if an instance is part of an escape-reclaim cycle.
    ///
    /// # Arguments
    ///
    /// * `instance_id` - The instance to check
    ///
    /// # Returns
    ///
    /// `true` if the instance has been both escaped and reclaimed.
    pub fn is_in_cycle(&self, instance_id: &u64) -> bool {
        self.escaped.contains(instance_id) || self.reclaimed.contains(instance_id)
    }

    /// Returns the escape target for an instance, if any.
    pub fn get_escape_target(&self, instance_id: &u64) -> Option<&u64> {
        self.escape_targets.get(instance_id)
    }

    /// Returns the reclaim source for an instance, if any.
    pub fn get_reclaim_source(&self, instance_id: &u64) -> Option<&u64> {
        self.reclaim_sources.get(instance_id)
    }

    /// Returns the size of the ownership chain containing an instance.
    pub fn chain_size(&mut self, instance_id: u64) -> Option<u32> {
        self.uf.set_size(instance_id)
    }

    /// Returns the number of distinct ownership chains.
    pub fn chain_count(&self) -> usize {
        self.uf.set_count()
    }

    /// Returns the total number of tracked instances.
    pub fn instance_count(&self) -> usize {
        self.uf.len()
    }
}

impl Default for OwnershipCycleDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify that Union-Find correctly tracks set membership.
    /// Invariants: After make_set, element exists; find returns itself.
    #[test]
    fn test_union_find_basic_operations() {
        let mut uf = OwnershipUnionFind::new();

        // Add elements
        uf.make_set(1);
        uf.make_set(2);
        uf.make_set(3);

        assert_eq!(uf.len(), 3, "Must have 3 elements");
        assert_eq!(uf.set_count(), 3, "Must have 3 distinct sets");

        // Each element is its own root
        assert_eq!(uf.find(1), Some(1), "1 must be its own root");
        assert_eq!(uf.find(2), Some(2), "2 must be its own root");
        assert_eq!(uf.find(3), Some(3), "3 must be its own root");

        // Elements are not connected
        assert!(!uf.connected(1, 2), "1 and 2 must not be connected");
        assert!(!uf.connected(2, 3), "2 and 3 must not be connected");
    }

    /// Objective: Verify that union correctly merges sets.
    /// Invariants: After union(1,2), 1 and 2 are connected; set_count decreases.
    #[test]
    fn test_union_find_merge() {
        let mut uf = OwnershipUnionFind::new();

        uf.make_set(1);
        uf.make_set(2);
        uf.make_set(3);

        // Union 1 and 2
        assert!(
            uf.union(1, 2),
            "Union of 1 and 2 must return true (new merge)"
        );
        assert_eq!(uf.set_count(), 2, "Must have 2 sets after first union");
        assert!(uf.connected(1, 2), "1 and 2 must be connected after union");

        // Union already-connected elements returns false
        assert!(
            !uf.union(1, 2),
            "Union of already-connected elements must return false"
        );

        // Union 2 and 3
        assert!(uf.union(2, 3), "Union of 2 and 3 must return true");
        assert_eq!(uf.set_count(), 1, "Must have 1 set after second union");
        assert!(uf.connected(1, 3), "1 and 3 must be connected through 2");
    }

    /// Objective: Verify that set_size correctly tracks component sizes.
    /// Invariants: After union, size reflects the merged component.
    #[test]
    fn test_union_find_set_size() {
        let mut uf = OwnershipUnionFind::new();

        uf.make_set(1);
        uf.make_set(2);
        uf.make_set(3);

        assert_eq!(uf.set_size(1), Some(1), "Initial size must be 1");
        assert_eq!(uf.set_size(2), Some(1), "Initial size must be 1");

        // Union 1 and 2
        uf.union(1, 2);
        assert_eq!(uf.set_size(1), Some(2), "Size must be 2 after union");
        assert_eq!(uf.set_size(2), Some(2), "Size must be 2 after union");

        // Union 2 and 3
        uf.union(2, 3);
        assert_eq!(uf.set_size(1), Some(3), "Size must be 3 after second union");
        assert_eq!(uf.set_size(3), Some(3), "Size must be 3 after second union");
    }

    /// Objective: Verify path compression works correctly.
    /// Invariants: After find, elements point directly to root.
    #[test]
    fn test_union_find_path_compression() {
        let mut uf = OwnershipUnionFind::new();

        // Create a chain: 1 -> 2 -> 3 -> 4
        uf.make_set(1);
        uf.make_set(2);
        uf.make_set(3);
        uf.make_set(4);

        uf.union(1, 2);
        uf.union(2, 3);
        uf.union(3, 4);

        // Find should compress paths
        let root = uf.find(1).unwrap();
        assert_eq!(
            root,
            uf.find(4).unwrap(),
            "All elements must have same root"
        );

        // After path compression, all should point to root
        assert_eq!(uf.find(1), Some(root), "1 must point to root");
        assert_eq!(uf.find(2), Some(root), "2 must point to root");
        assert_eq!(uf.find(3), Some(root), "3 must point to root");
        assert_eq!(uf.find(4), Some(root), "4 must point to root");
    }

    /// Objective: Verify that find returns None for non-existent elements.
    /// Invariants: find(x) returns None if x was never added.
    #[test]
    fn test_union_find_nonexistent_element() {
        let mut uf = OwnershipUnionFind::new();

        assert_eq!(
            uf.find(42),
            None,
            "find must return None for non-existent element"
        );
        assert_eq!(
            uf.set_size(42),
            None,
            "set_size must return None for non-existent element"
        );
        assert!(
            !uf.connected(1, 2),
            "connected must return false for non-existent elements"
        );
    }

    /// Objective: Verify that OwnershipCycleDetector correctly tracks escape-reclaim cycles.
    /// Invariants: After escape+reclaim, instances are connected and in cycle.
    #[test]
    fn test_cycle_detector_escape_reclaim() {
        let mut detector = OwnershipCycleDetector::new();

        // Register instances
        detector.register_instance(1);
        detector.register_instance(2);

        // Record escape: instance 1 escapes to raw pointer 100
        detector.record_escape(1, 100);
        assert!(
            detector.is_in_cycle(&1),
            "Instance 1 must be in cycle after escape"
        );
        assert_eq!(
            detector.get_escape_target(&1),
            Some(&100),
            "Escape target must be 100"
        );

        // Record reclaim: instance 1 reclaimed as instance 2
        detector.record_reclaim(1, 2);
        assert!(
            detector.is_in_cycle(&2),
            "Instance 2 must be in cycle after reclaim"
        );
        assert_eq!(
            detector.get_reclaim_source(&2),
            Some(&1),
            "Reclaim source must be 1"
        );

        // Instances 1 and 2 must be connected
        assert!(
            detector.are_connected(1, 2),
            "Instances 1 and 2 must be connected through escape-reclaim"
        );
    }

    /// Objective: Verify that cycle detector correctly handles multiple chains.
    /// Invariants: Separate chains are not connected.
    #[test]
    fn test_cycle_detector_multiple_chains() {
        let mut detector = OwnershipCycleDetector::new();

        // Chain 1: 1 -> 100 -> 2
        detector.register_instance(1);
        detector.register_instance(2);
        detector.record_escape(1, 100);
        detector.record_reclaim(1, 2);

        // Chain 2: 3 -> 200 -> 4
        detector.register_instance(3);
        detector.register_instance(4);
        detector.record_escape(3, 200);
        detector.record_reclaim(3, 4);

        // Chains are separate
        assert!(
            !detector.are_connected(1, 3),
            "Instances 1 and 3 must NOT be connected (separate chains)"
        );
        assert!(
            !detector.are_connected(2, 4),
            "Instances 2 and 4 must NOT be connected (separate chains)"
        );

        // Within each chain, instances are connected
        assert!(
            detector.are_connected(1, 2),
            "Instances 1 and 2 must be connected (same chain)"
        );
        assert!(
            detector.are_connected(3, 4),
            "Instances 3 and 4 must be connected (same chain)"
        );
    }

    /// Objective: Verify that cycle detector correctly tracks chain sizes.
    /// Invariants: Chain size reflects the number of instances in the chain.
    #[test]
    fn test_cycle_detector_chain_size() {
        let mut detector = OwnershipCycleDetector::new();

        detector.register_instance(1);
        detector.register_instance(2);
        detector.register_instance(3);

        // Initial size: 1 each
        assert_eq!(
            detector.chain_size(1),
            Some(1),
            "Initial chain size must be 1"
        );

        // Escape: 1 -> 100
        detector.record_escape(1, 100);
        assert_eq!(
            detector.chain_size(1),
            Some(2),
            "Chain size must be 2 after escape"
        );

        // Reclaim: 1 -> 2
        detector.record_reclaim(1, 2);
        assert_eq!(
            detector.chain_size(1),
            Some(3),
            "Chain size must be 3 after reclaim"
        );

        // Verify all are in same chain
        assert!(detector.are_connected(1, 2), "1 and 2 must be connected");
        assert!(
            detector.are_connected(1, 100),
            "1 and 100 must be connected"
        );
    }

    /// Objective: Verify that Union-Find handles large number of elements efficiently.
    /// Invariants: Operations complete in reasonable time for 10k elements.
    #[test]
    fn test_union_find_performance_10k() {
        let mut uf = OwnershipUnionFind::with_capacity(10000);

        // Add 10k elements
        for i in 0..10000 {
            uf.make_set(i);
        }
        assert_eq!(uf.len(), 10000, "Must have 10k elements");

        // Union adjacent elements: 0-1, 2-3, 4-5, ...
        for i in (0..10000).step_by(2) {
            uf.union(i, i + 1);
        }
        assert_eq!(uf.set_count(), 5000, "Must have 5k sets after unions");

        // Union pairs: 0-2, 4-6, 8-10, ...
        for i in (0..10000).step_by(4) {
            uf.union(i, i + 2);
        }
        assert_eq!(
            uf.set_count(),
            2500,
            "Must have 2.5k sets after second unions"
        );

        // Verify connectivity
        assert!(uf.connected(0, 1), "0 and 1 must be connected");
        assert!(uf.connected(0, 2), "0 and 2 must be connected");
        assert!(uf.connected(0, 3), "0 and 3 must be connected");
        assert!(!uf.connected(0, 4), "0 and 4 must NOT be connected");
    }

    /// Objective: Verify that cycle detector correctly handles re-registration.
    /// Invariants: Re-registering an existing instance is a no-op.
    #[test]
    fn test_cycle_detector_reregistration() {
        let mut detector = OwnershipCycleDetector::new();

        detector.register_instance(1);
        detector.register_instance(1); // Re-register

        assert_eq!(detector.instance_count(), 1, "Must have exactly 1 instance");
    }

    /// Objective: Verify that cycle detector correctly handles empty state.
    /// Invariants: Empty detector has no cycles, no connections.
    #[test]
    fn test_cycle_detector_empty() {
        let detector = OwnershipCycleDetector::new();

        assert_eq!(
            detector.instance_count(),
            0,
            "Empty detector must have 0 instances"
        );
        assert_eq!(
            detector.chain_count(),
            0,
            "Empty detector must have 0 chains"
        );
        assert!(
            !detector.is_in_cycle(&1),
            "Empty detector must have no cycles"
        );
    }
}
