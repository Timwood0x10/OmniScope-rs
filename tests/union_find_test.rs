//! Standalone test for Union-Find and OwnershipCycleDetector.
//!
//! This test file verifies the correctness of the Union-Find data structure
//! and the OwnershipCycleDetector for incremental cycle detection.

use omniscope_pass::resource::union_find::{OwnershipCycleDetector, OwnershipUnionFind};

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

/// Objective: Verify that path compression works correctly.
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

/// Objective: Verify that cycle detector correctly handles escape-reclaim with
///            multiple instances in the same chain.
/// Invariants: All instances in a chain are connected.
#[test]
fn test_cycle_detector_complex_chain() {
    let mut detector = OwnershipCycleDetector::new();

    // Create a complex chain: 1 -> 100 -> 2 -> 200 -> 3 -> 300 -> 4
    detector.register_instance(1);
    detector.register_instance(2);
    detector.register_instance(3);
    detector.register_instance(4);

    // First escape-reclaim cycle: 1 -> 100 -> 2
    detector.record_escape(1, 100);
    detector.record_reclaim(1, 2);

    // Second escape-reclaim cycle: 2 -> 200 -> 3
    detector.record_escape(2, 200);
    detector.record_reclaim(2, 3);

    // Third escape-reclaim cycle: 3 -> 300 -> 4
    detector.record_escape(3, 300);
    detector.record_reclaim(3, 4);

    // All instances must be connected
    assert!(detector.are_connected(1, 2), "1 and 2 must be connected");
    assert!(detector.are_connected(1, 3), "1 and 3 must be connected");
    assert!(detector.are_connected(1, 4), "1 and 4 must be connected");
    assert!(detector.are_connected(2, 3), "2 and 3 must be connected");
    assert!(detector.are_connected(2, 4), "2 and 4 must be connected");
    assert!(detector.are_connected(3, 4), "3 and 4 must be connected");

    // Chain size must be 7 (4 instances + 3 escape targets)
    assert_eq!(detector.chain_size(1), Some(7), "Chain size must be 7");
}
