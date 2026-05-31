//! Tests for SemanticTree building and querying.

use super::super::*;

/// Objective: Verify that semantic tree is correctly built from FFI calls.
///
/// Invariants:
/// - Tree should contain 4 nodes for 4 FFI calls
/// - Safe pattern count should be 2 (getenv + strlen)
/// - Genuine concern count should be 0 (free score=0.54 >= 0.5)
#[test]
fn test_semantic_tree_build() {
    let ffi_calls = vec![
        ("rust_func".to_string(), "getenv".to_string(), true),
        ("rust_func".to_string(), "strlen".to_string(), true),
        ("rust_func".to_string(), "free".to_string(), true),
        (
            "rust_func".to_string(),
            "BunString__fromBytes".to_string(),
            true,
        ),
    ];

    let tree = build_semantic_tree(&ffi_calls);
    assert_eq!(tree.nodes().len(), 4);
    assert_eq!(tree.safe_pattern_count(), 2); // getenv + strlen
    assert_eq!(tree.genuine_concern_count(), 0); // free score=0.54 >= 0.5
}

/// Objective: Verify that memory ownership filtering correctly identifies memory management nodes.
///
/// Invariants:
/// - Memory ownership nodes should include malloc and free
/// - All memory ownership nodes should have MemoryManagement syscall semantic
#[test]
fn test_memory_ownership_filtering() {
    let ffi_calls = vec![
        ("rust_func".to_string(), "malloc".to_string(), true),
        ("rust_func".to_string(), "strlen".to_string(), true),
        ("rust_func".to_string(), "free".to_string(), true),
        ("rust_func".to_string(), "getenv".to_string(), true),
    ];

    let tree = build_semantic_tree(&ffi_calls);
    let mem_nodes = tree.memory_ownership_nodes();
    assert_eq!(mem_nodes.len(), 2); // malloc + free
    assert!(mem_nodes
        .iter()
        .all(|n| n.syscall_semantic == SyscallSemantic::MemoryManagement));
}
