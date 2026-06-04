//! OmniScope Pass - Analysis pass infrastructure.
//!
//! This crate provides analysis pass infrastructure for OmniScope,
//! including:
//!
//! - Pass trait and context
//! - Analysis passes (FFI boundary, surface classifier, danger surface)
//! - Noise reduction and FP precision guard
//! - Resource contract passes (new architecture)
//! - Pass manager for orchestration
//! - Shared instruction metadata cache (ModuleIndex) for performance

pub mod analysis;
pub mod manager;
pub mod module_index;
pub mod pass;
pub mod resource;

// Re-exports — Analysis passes
pub use analysis::{
    infer_boundaries, BorrowEscapePass, CallGraphPass, DangerSurfacePass, FFIBoundaryPass,
    HeapProvenancePass, InteriorMutabilityPass, NoiseReduction, PrecisionMetrics, RaiiDropPass,
    SurfaceClassifierPass, WriteToImmutablePass,
};

// Re-exports — Resource contract passes
pub use resource::contract_graph_builder::{ContractEdge, ContractGraph, ContractGraphBuilderPass};
pub use resource::ffi_return_check::FfiReturnCheckPass;
pub use resource::ir_behavior_summary_pass::IRBehaviorSummaryPass;
pub use resource::issue_candidate_builder::IssueCandidateBuilderPass;
pub use resource::issue_gate::{check_issue, check_issue_with_kinds, GateVerdict};
pub use resource::issue_verifier::IssueVerifierPass;
pub use resource::ownership_solver::OwnershipSolverPass;
pub use resource::path_sensitive_leak::{LeakDetectionPass, LeakPath, PathAnalysisResult};
pub use resource::raw_fact_collector::RawFactCollectorPass;
pub use resource::risk_scoring::{compute_risk_score, RiskScore};
pub use resource::structural_inference_pass::StructuralInferencePass;
pub use resource::summary_builder::SummaryBuilderPass;

// Re-exports — Infrastructure
pub use manager::PassManager;
pub use module_index::ModuleIndex;
pub use pass::{Pass, PassContext, PassKind, PassResult, PassTiming};
