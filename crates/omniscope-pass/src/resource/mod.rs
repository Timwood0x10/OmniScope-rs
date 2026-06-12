//! Resource contract analysis passes.
//!
//! Implements the resource contract architecture:
//!
//! - `raw_fact_collector` — Collects raw resource facts from IR.
//! - `abi_layout` — Detects struct padding/alignment issues at FFI boundaries.
//! - `summary_builder` — Builds function summaries from the family registry.
//! - `structural_inference_pass` — Infers destructor, bridge, refcount,
//!   and static-lifetime summaries from structural patterns.
//! - `contract_graph_builder` — Builds the resource contract graph.
//! - `ownership_solver` — Runs ownership state propagation.
//! - `issue_candidate_builder` — Builds issue candidates from graph edges.
//! - `issue_verifier` — Verifies candidates and assigns verdicts.
//! - `risk_scoring` — Centralized risk scoring for issue candidates.
//! - `path_sensitive_leak` — Path-sensitive leak detection (Phase 6).
//! - `rust_drop_tracker` — Tracks Rust Drop operations for RAII cleanup detection.

pub mod abi_layout_pass;
pub mod contract_graph_builder;
pub mod cross_function_lifetime_pass;
pub(crate) mod evidence_bundle;
pub mod ffi_return_check;
pub mod incremental_cache;
pub mod ir_behavior_summary_pass;
#[cfg(test)]
mod ir_behavior_summary_pass_tests;
pub mod issue_candidate_builder;
pub mod issue_gate;
pub mod issue_verifier;
pub mod language_adapter_fact_pass;
pub mod may_alias;
pub mod noreturn;
pub mod ownership_solver;
pub mod path_sensitive_leak;
pub(crate) mod pattern_to_facts;
pub mod raw_fact_collector;
pub(crate) mod reconcile;
pub mod risk_scoring;
pub mod rust_drop_tracker;
pub mod structural_inference_pass;
pub mod summary_builder;
pub mod union_find;
