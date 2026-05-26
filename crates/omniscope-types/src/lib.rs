//! OmniScope Types - Type definitions for static analysis
//!
//! This crate provides all type definitions used throughout the OmniScope analyzer,
//! including:
//!
//! - ABI types for FFI analysis
//! - Ownership types for memory safety
//! - Call graph types
//! - Configuration types

pub mod abi;
pub mod call_graph_types;
pub mod config;
pub mod ownership;
pub mod zone_types;

// Re-exports
pub use abi::{AbiType, CallingConvention};
pub use call_graph_types::{
    is_dangerous, is_libc, is_sink, is_source, CallGraphEdge, CallGraphNode, CrossLangEdge,
    FunctionKind,
};
pub use config::{AnalysisConfig, Language, OutputFormat};
pub use ownership::{Ownership, OwnershipKind};
pub use zone_types::{classify_by_patterns, EscapeTrigger, ZoneClass, ZoneKind, ZoneStats};

/// Unique identifier for nodes in analysis graphs
pub type NodeId = u64;

/// Unique identifier for edges in analysis graphs
pub type EdgeId = u64;

/// Unique identifier for values
pub type ValueId = u64;

/// Unique identifier for functions
pub type FunctionId = u64;

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
