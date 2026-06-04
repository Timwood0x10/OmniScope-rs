//! Semantic tree for Rustonomicon-aware analysis.
//!
//! This module reconstructs high-level Rust semantics from LLVM IR,
//! based on concepts from The Rustonomicon (The Dark Arts of Unsafe Rust).
//!
//! # Architecture
//!
//! ```text
//! LLVM IR ──→ ProvenanceTracker ──→ PointerProvenance
//!         ──→ TypeSemanticExtractor ──→ TypeSemantic
//!         ──→ SyscallClassifier ──→ SyscallSemantic
//!         ──→ SemanticNode ──→ SemanticTree
//! ```
//!
//! # Key Insight
//!
//! The root problem is that LLVM IR flattens Rust's ownership model:
//! - `Box::new()` heap pointer vs `alloca` stack pointer → both become `ptr`
//! - `UnsafeCell<T>` interior mutability vs immutable struct → both become `store`
//! - `unlink()` (file op) vs `free()` (memory release) → both become FFI calls
//!
//! The semantic tree reconstructs these distinctions from:
//! 1. **Mangled name patterns** (Rust v0 mangling encodes type paths)
//! 2. **IR instruction patterns** (alloca, call @malloc, load from global)
//! 3. **Syscall classification** (semantic model, not whitelist)
//!
//! This is NOT a whitelist — it's a semantic understanding layer.

// ── Submodules ──
pub mod kind;
pub mod node;
pub mod provenance;
pub mod syscall;
pub mod tree;
pub mod type_semantic;

// ── Re-exports for backward compatibility ──
pub use kind::{SemanticKey, SemanticKind, SemanticResolution};
pub use node::SemanticNode;
pub use provenance::PointerProvenance;
pub use syscall::SyscallSemantic;
pub use tree::{
    build_semantic_tree, build_semantic_tree_with_cache, infer_provenance_from_context,
    infer_provenance_from_syscall, SemanticTree,
};
pub use type_semantic::TypeSemantic;

// ── Tests ──
#[cfg(test)]
mod tests;
