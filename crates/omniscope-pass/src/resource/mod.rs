//! Resource contract analysis passes.
//!
//! Implements the resource contract architecture:
//!
//! - `raw_fact_collector` — Collects raw resource facts from IR.
//! - `summary_builder` — Builds function summaries from the family registry.
//! - `structural_inference_pass` — Infers destructor, bridge, refcount,
//!   and static-lifetime summaries from structural patterns.
//! - `contract_graph_builder` — Builds the resource contract graph.
//! - `ownership_solver` — Runs ownership state propagation.
//! - `issue_candidate_builder` — Builds issue candidates from graph edges.
//! - `issue_verifier` — Verifies candidates and assigns verdicts.
//! - `risk_scoring` — Centralized risk scoring for issue candidates.
//! - `path_sensitive_leak` — Path-sensitive leak detection (Phase 6).

pub mod contract_graph_builder;
pub mod ir_behavior_summary_pass;
pub mod issue_candidate_builder;
pub mod issue_gate;
pub mod issue_verifier;
pub mod ownership_solver;
pub mod path_sensitive_leak;
pub mod raw_fact_collector;
pub mod risk_scoring;
pub mod structural_inference_pass;
pub mod summary_builder;
