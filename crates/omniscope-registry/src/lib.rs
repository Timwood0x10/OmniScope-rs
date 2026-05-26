//! OmniScope Registry - Function semantic registries for FFI analysis.
//!
//! Provides a multi-layer knowledge base for FFI boundary function semantics,
//! covering C stdlib, Rust ownership, Go cgo, C++, Zig, JNI, and Python C API.

pub mod semantic_registry;

pub use semantic_registry::{
    FunctionSemantics, MatchType, RiskKind, RiskSeverity, SemanticRegistry,
};
