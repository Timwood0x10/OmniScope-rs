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

pub mod escape;
pub mod family_inference;
pub mod family_registry;
pub mod ownership_state;
pub mod structural_inference;
pub mod summary;
pub mod summary_inference;
