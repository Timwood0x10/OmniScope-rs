//! Tests for SemanticNode functionality.

use super::super::*;

/// Objective: Verify that data query functions have high safety scores.
///
/// Invariants:
/// - strlen call should have safety score > 0.8
#[test]
fn test_safety_score_data_query() {
    let node = SemanticNode::for_ffi_call(
        "some_rust_func",
        "strlen",
        PointerProvenance::Heap,
        TypeSemantic::Ordinary,
    );
    // Data query should have high safety score
    assert!(
        node.safety_score > 0.8,
        "strlen call should be safe: {}",
        node.safety_score
    );
}

/// Objective: Verify that memory management functions have lower safety scores.
///
/// Invariants:
/// - free call should have safety score < 0.6
#[test]
fn test_safety_score_memory_management() {
    let node = SemanticNode::for_ffi_call(
        "some_rust_func",
        "free",
        PointerProvenance::Heap,
        TypeSemantic::Ordinary,
    );
    // free() should have lower safety score than safe patterns
    assert!(
        node.safety_score < 0.6,
        "free call should be concerning: {}",
        node.safety_score
    );
}

/// Objective: Verify that internal dispatch functions have moderate-high safety scores.
///
/// Invariants:
/// - BunString__fromBytes call should have safety score > 0.6
#[test]
fn test_safety_score_internal_dispatch() {
    let node = SemanticNode::for_ffi_call(
        "some_rust_func",
        "BunString__fromBytes",
        PointerProvenance::Heap,
        TypeSemantic::Ordinary,
    );
    // Internal dispatch should have moderate-high safety score
    assert!(
        node.safety_score > 0.6,
        "internal dispatch should be moderate: {}",
        node.safety_score
    );
}
