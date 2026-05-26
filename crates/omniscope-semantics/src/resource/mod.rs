//! Resource contract modules for semantic analysis.
//!
//! This module tree implements the Resource Contract architecture:
//!
//! - `family`: Resource family types and built-in definitions.
//! - `family_registry`: Registry for looking up families by symbol name.
//! - `family_inference`: Inferring families from symbol patterns.
//! - `contract`: Pointer contract classification.
//! - `effect`: Function effect types.
//! - `summary`: Function summary representation.
//! - `summary_inference`: Inferring summaries from IR and patterns.
//! - `ownership_state`: Ownership state machine for tracking resources.
//! - `escape`: Escape analysis for pointer scope tracking.
//! - `evidence`: Evidence collection for verification.

pub mod escape;
pub mod family_inference;
pub mod family_registry;
pub mod ownership_state;
pub mod summary;
pub mod summary_inference;
