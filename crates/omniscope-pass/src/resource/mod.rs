//! Resource contract analysis passes.
//!
//! Implements the resource contract architecture:
//!
//! - `raw_fact_collector` — Collects raw resource facts from IR.
//! - `summary_builder` — Builds function summaries from the family registry.
//! - `contract_graph_builder` — Builds the resource contract graph.
//! - `ownership_solver` — Runs ownership state propagation.
//! - `issue_candidate_builder` — Builds issue candidates from graph edges.
//! - `issue_verifier` — Verifies candidates and assigns verdicts.

pub mod contract_graph_builder;
pub mod issue_candidate_builder;
pub mod issue_verifier;
pub mod ownership_solver;
pub mod raw_fact_collector;
pub mod summary_builder;
