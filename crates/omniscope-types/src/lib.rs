//! OmniScope Types - Type definitions for static analysis
//!
//! This crate provides all type definitions used throughout the OmniScope analyzer,
//! including:
//!
//! - ABI types for FFI analysis
//! - Ownership types for memory safety
//! - Call graph types
//! - Configuration types
//! - Resource family types (replacing language-based allocator matching)
//! - Pointer contract types (describing ownership semantics)
//! - Effect types (function effects for resource contract analysis)
//! - Escape kinds (how pointers leave scope)
//! - Evidence types (supporting issue verification)
//! - Verifier verdicts (gating issue output)

pub mod abi;
pub mod call_graph_types;
pub mod config;
pub mod effect;
pub mod escape;
pub mod evidence;
pub mod pointer_contract;
pub mod resource_family;

// Re-exports
pub use abi::{AbiType, CallingConvention};
pub use call_graph_types::{
    is_dangerous, is_libc, is_sink, is_source, CallGraphEdge, CallGraphNode, CrossLangEdge,
    FunctionKind,
};
pub use config::{AnalysisConfig, Language, OutputFormat};

// Re-exports — Resource contract types
pub use effect::{ArgIndex, Effect, FunctionOrigin, LanguageHint, VerifierVerdict};
pub use escape::EscapeKind;
pub use evidence::{Evidence, EvidenceKind, IssueCandidateKind};
pub use pointer_contract::PointerContract;
pub use resource_family::{
    FamilyId, FamilyKind, LifetimeDomain, ResourceFamily, BUILTIN_FAMILIES, FAMILY_CPP_NEW_ARRAY,
    FAMILY_CPP_NEW_SCALAR, FAMILY_CSHARP_COTASK, FAMILY_CSHARP_HGLOBAL, FAMILY_C_HEAP,
    FAMILY_GO_GC, FAMILY_JAVA_GLOBAL_REF, FAMILY_JAVA_LOCAL_REF, FAMILY_PYTHON_MEM,
    FAMILY_PYTHON_MEM_RAW, FAMILY_PYTHON_OBJECT, FAMILY_RUST_GLOBAL, FAMILY_RUST_RAW_OWNERSHIP,
    FAMILY_ZIG_ALLOCATOR,
};

/// Unique identifier for nodes in analysis graphs
pub type NodeId = u64;

/// Unique identifier for edges in analysis graphs
pub type EdgeId = u64;

/// Unique identifier for values
pub type ValueId = u64;

/// Unique identifier for functions
pub type FunctionId = u64;

/// Unique identifier for symbols (canonical names)
pub type SymbolId = u64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_ids() {
        let node: NodeId = 1;
        let edge: EdgeId = 2;
        let value: ValueId = 3;
        let func: FunctionId = 4;

        assert_ne!(node, edge);
        assert_ne!(value, func);
    }
}
