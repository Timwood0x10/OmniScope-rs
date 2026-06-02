//! Semantic Tree — the complete semantic annotation for a module
//!
//! This module provides the `SemanticTree` struct for storing
//! semantic annotations for an entire IR module.

use std::collections::HashMap;

use super::kind::{SemanticKind, SemanticResolution};
use super::node::SemanticNode;
use super::provenance::PointerProvenance;
use super::syscall::SyscallSemantic;
use super::type_semantic::TypeSemantic;

/// The semantic tree for an entire IR module.
///
/// Built by walking the IR and annotating each FFI boundary with
/// provenance, type, syscall semantics, and R-0~R-6 resolutions.
/// Used by downstream passes to make informed decisions about issue
/// severity and FP suppression.
#[derive(Debug, Clone)]
pub struct SemanticTree {
    /// Semantic annotations for each FFI call.
    nodes: Vec<SemanticNode>,
    /// Index from callee symbol to node indices.
    callee_index: HashMap<String, Vec<usize>>,
    /// Resolution index: symbol -> semantic resolutions (R-0~R-6).
    resolution_index: HashMap<String, Vec<SemanticResolution>>,
}

impl SemanticTree {
    /// Creates a new empty semantic tree.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            callee_index: HashMap::new(),
            resolution_index: HashMap::new(),
        }
    }

    /// Adds a semantic node to the tree.
    pub fn add_node(&mut self, node: SemanticNode) {
        let idx = self.nodes.len();
        // Extract callee from symbol format "caller -> callee"
        if let Some(callee) = node.symbol.split(" -> ").nth(1) {
            self.callee_index
                .entry(callee.to_string())
                .or_default()
                .push(idx);
        }
        self.nodes.push(node);
    }

    /// Adds a semantic resolution for a symbol.
    ///
    /// Multiple resolutions can exist for the same symbol (e.g., a value
    /// can be both HeapProvenance and MutableParam).
    pub fn add_resolution(&mut self, symbol: &str, resolution: SemanticResolution) {
        self.resolution_index
            .entry(symbol.to_string())
            .or_default()
            .push(resolution);
    }

    /// Queries whether a symbol has a specific semantic kind.
    ///
    /// Returns the highest-confidence resolution matching the kind,
    /// or None if no such resolution exists.
    pub fn has_kind(&self, symbol: &str, kind: SemanticKind) -> Option<&SemanticResolution> {
        self.resolution_index.get(symbol).and_then(|resolutions| {
            resolutions
                .iter()
                .filter(|r| r.kind == kind)
                .max_by(|a, b| {
                    a.confidence
                        .partial_cmp(&b.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        })
    }

    /// Returns all resolutions for a symbol.
    pub fn all_resolutions(&self, symbol: &str) -> &[SemanticResolution] {
        self.resolution_index
            .get(symbol)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns true if any resolution for the symbol would suppress
    /// write_to_immutable issues.
    pub fn suppresses_write_to_immutable(&self, symbol: &str) -> bool {
        self.resolution_index
            .get(symbol)
            .map(|rs| rs.iter().any(|r| r.kind.suppresses_write_to_immutable()))
            .unwrap_or(false)
    }

    /// Returns true if any resolution for the symbol would suppress
    /// borrow_escape issues.
    pub fn suppresses_borrow_escape(&self, symbol: &str) -> bool {
        self.resolution_index
            .get(symbol)
            .map(|rs| rs.iter().any(|r| r.kind.suppresses_borrow_escape()))
            .unwrap_or(false)
    }

    /// Returns true if any resolution for the symbol would suppress
    /// use_after_free issues.
    pub fn suppresses_use_after_free(&self, symbol: &str) -> bool {
        self.resolution_index
            .get(symbol)
            .map(|rs| rs.iter().any(|r| r.kind.suppresses_use_after_free()))
            .unwrap_or(false)
    }

    /// Returns true if any resolution for the symbol would suppress
    /// cross_language_free issues.
    pub fn suppresses_cross_language_free(&self, symbol: &str) -> bool {
        self.resolution_index
            .get(symbol)
            .map(|rs| rs.iter().any(|r| r.kind.suppresses_cross_language_free()))
            .unwrap_or(false)
    }

    /// Returns all semantic nodes.
    pub fn nodes(&self) -> &[SemanticNode] {
        &self.nodes
    }

    /// Returns semantic nodes for a specific callee.
    pub fn nodes_for_callee(&self, callee: &str) -> Vec<&SemanticNode> {
        self.callee_index
            .get(callee)
            .map(|indices| indices.iter().map(|&i| &self.nodes[i]).collect())
            .unwrap_or_default()
    }

    /// Returns the number of nodes that indicate a genuine safety concern
    /// (safety_score < 0.5).
    pub fn genuine_concern_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.safety_score < 0.5).count()
    }

    /// Returns the number of nodes that are safe FFI patterns
    /// (safety_score >= 0.8).
    pub fn safe_pattern_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.safety_score >= 0.8).count()
    }

    /// Returns nodes that involve memory ownership operations
    /// (potential CrossFamilyFree candidates).
    pub fn memory_ownership_nodes(&self) -> Vec<&SemanticNode> {
        self.nodes
            .iter()
            .filter(|n| n.syscall_semantic.involves_memory_ownership())
            .collect()
    }
}

impl Default for SemanticTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a semantic tree from an IR module's FFI boundaries.
///
/// For each FFI call in the module, this function:
/// 1. Classifies the callee's syscall semantic
/// 2. Infers the type semantic from mangled names
/// 3. Determines pointer provenance from IR patterns
/// 4. Computes a combined safety score
pub fn build_semantic_tree(
    ffi_calls: &[(String, String, bool)], // (caller, callee, is_external)
) -> SemanticTree {
    build_semantic_tree_with_cache(ffi_calls, &std::collections::HashMap::new())
}

/// Builds a semantic tree from an IR module's FFI boundaries with a syscall cache.
///
/// This is the cached version that uses pre-computed `SyscallSemantic` classifications
/// from `ModuleIndex` to avoid repeated string matching.
///
/// For each FFI call in the module, this function:
/// 1. Looks up the callee's syscall semantic from the cache (or classifies it)
/// 2. Infers the type semantic from mangled names
/// 3. Determines pointer provenance from IR patterns
/// 4. Computes a combined safety score
pub fn build_semantic_tree_with_cache(
    ffi_calls: &[(String, String, bool)], // (caller, callee, is_external)
    syscall_cache: &std::collections::HashMap<String, SyscallSemantic>,
) -> SemanticTree {
    let mut tree = SemanticTree::new();

    for (caller, callee, _is_external) in ffi_calls {
        // Extract type semantic from caller name (if Rust)
        let type_semantic = TypeSemantic::from_mangled_name(caller);

        // Use cached syscall semantic if available
        let syscall_semantic = syscall_cache
            .get(callee)
            .copied()
            .unwrap_or_else(|| SyscallSemantic::classify(callee));

        // Determine pointer provenance using cached syscall semantic
        let provenance = infer_provenance_from_syscall(caller, syscall_semantic);

        let node = SemanticNode::for_ffi_call_with_syscall(
            caller,
            callee,
            provenance,
            type_semantic,
            syscall_semantic,
        );
        tree.add_node(node);
    }

    tree
}

/// Infers pointer provenance from the call context.
///
/// Heuristics based on Rustonomicon FFI patterns:
/// - Calling libc::getenv/strlen → passes pointers to global/heap data → safe
/// - Calling Box::into_raw → heap provenance
/// - Calling BunString__fromBytes → passes slice ptr → heap provenance
/// - Calling malloc/__rust_alloc → returns heap provenance
pub fn infer_provenance_from_context(caller: &str, callee: &str) -> PointerProvenance {
    let syscall = SyscallSemantic::classify(callee);
    infer_provenance_from_syscall(caller, syscall)
}

/// Infers pointer provenance from the call context with a pre-computed syscall semantic.
///
/// This is the cached version that avoids repeated `SyscallSemantic::classify()`
/// calls when the classification is already available.
pub fn infer_provenance_from_syscall(caller: &str, syscall: SyscallSemantic) -> PointerProvenance {
    match syscall {
        // These return heap pointers
        SyscallSemantic::MemoryManagement => PointerProvenance::Heap,
        // These read from global/process data
        SyscallSemantic::DataQuery | SyscallSemantic::EnvironmentConfig => {
            PointerProvenance::Global
        }
        // These operate on caller-owned buffers (heap)
        SyscallSemantic::StringManipulation | SyscallSemantic::ComputeAccelerated => {
            PointerProvenance::Heap
        }
        // Internal dispatch — by-design FFI, usually heap provenance
        SyscallSemantic::InternalDispatch => PointerProvenance::Heap,
        // File/network ops — FD is an integer, not a pointer
        SyscallSemantic::FileOperation
        | SyscallSemantic::IOOperation
        | SyscallSemantic::NetworkOperation => PointerProvenance::Global,
        // Thread sync — operates on sync primitives (heap or global)
        SyscallSemantic::ThreadSync => PointerProvenance::Heap,
        // Process ops — no pointer passing typically
        SyscallSemantic::ProcessOperation | SyscallSemantic::TimeOperation => {
            PointerProvenance::Unknown
        }
        // Unknown — could be anything
        SyscallSemantic::Unknown => {
            // If the caller is Rust and callee is unknown external, check
            // if the caller involves heap types
            if caller.starts_with("_R") {
                let type_sem = TypeSemantic::from_mangled_name(caller);
                match type_sem {
                    TypeSemantic::Box | TypeSemantic::Vec => PointerProvenance::Heap,
                    TypeSemantic::Drop => PointerProvenance::Heap,
                    _ => PointerProvenance::Unknown,
                }
            } else {
                PointerProvenance::Unknown
            }
        }
    }
}
