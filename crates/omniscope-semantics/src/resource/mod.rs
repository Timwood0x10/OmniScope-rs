//! Resource contract modules for semantic analysis.
//!
//! This module tree implements the Resource Contract architecture:
//!
//! - `family_registry`: Registry for looking up families by symbol name.
//! - `family_inference`: Inferring families from symbol patterns.
//! - `summary`: Function summary representation.
//! - `summary_inference`: Inferring summaries from IR and patterns.
//! - `ownership_state`: Ownership state machine for tracking resources.
//! - `escape`: Escape analysis for pointer scope tracking.
//! - `structural_inference`: Phase 4 structural inference patterns
//!   (destructor, bridge, refcount, static-lifetime).
//! - `allocator_shim`: Detector for filtering false positives from custom allocators.
//! - `cross_function_lifetime`: Cross-function lifetime tracking for resource lifecycle analysis.

pub mod allocator_shim;
pub mod confidence_scorer;
pub mod cpp_adapter;
pub mod cross_function_lifetime;
pub mod csharp_adapter;
pub mod escape;
pub mod family_inference;
pub mod family_registry;
pub mod ffi_contract;
pub mod go_adapter;
pub mod ir_pattern;
pub mod java_adapter;
pub mod ownership_state;
pub mod python_adapter;
pub mod rust_stdlib_whitelist;
pub mod semantic_engine;
pub mod semantic_tree;
pub mod structural_inference;
pub mod summary;
pub mod summary_inference;

#[cfg(test)]
mod test_matrix;
