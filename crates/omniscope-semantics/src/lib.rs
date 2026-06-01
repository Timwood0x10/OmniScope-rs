//! OmniScope Semantics - Semantic analysis engine.
//!
//! This crate provides semantic analysis for OmniScope, including:
//!
//! - Language detection from LLVM IR (with weighted voting)
//! - Zone classification for optimization (safe/escape/boundary)
//! - Surface classification for function provenance
//! - Resource contract analysis (family, contract, effect, summary, evidence)

pub mod language_detector;
pub mod resource;
pub mod surface_classifier;

// Re-exports
pub use language_detector::LanguageDetector;
pub use surface_classifier::{Confidence, FunctionSurface, SurfaceClassifier, SurfaceHint};

// Re-exports — Resource contract modules
pub use resource::confidence_scorer::{
    classify_issue, score_issue, ConfidenceTier, ScoreBreakdown, ScoringContext,
};
pub use resource::escape::{classify_escape, EscapeContext, EscapeResult};
pub use resource::family_inference::infer_family;
pub use resource::family_registry::{
    FamilyEntry, FamilyRegistry, ResourceFamilyOwned, SymbolEffect,
};
pub use resource::ffi_contract;
pub use resource::go_adapter::{GoAdapter, GoFFISafety, GoFunctionAnalysis, GoSemanticPattern};
pub use resource::ir_pattern::{extract_behavior, BehaviorPattern, FunctionBehavior, ReturnSource};
pub use resource::ownership_state::{
    OwnershipError, OwnershipEvent, OwnershipState, ResourceInstance,
};
pub use resource::python_adapter::{PythonAdapter, PythonPattern, PythonSemantic};
pub use resource::semantic_engine::{
    assess_ffi_safety, FFISafetyAssessment, FFIVerdict, IREvidence,
};
pub use resource::semantic_tree::{
    build_semantic_tree, infer_provenance_from_context, PointerProvenance, SemanticKind,
    SemanticNode, SemanticResolution, SemanticTree, SyscallSemantic, TypeSemantic,
};
pub use resource::structural_inference::{
    infer_bridge_summary, infer_destructor_summary, infer_refcount_release_summary,
    infer_static_lifetime_summary, BridgeInferenceResult, BridgeKind, DestructorInferenceResult,
    DestructorKind, RefcountInferenceResult, RefcountKind, StaticLifetimeInferenceResult,
    StaticLifetimeKind,
};
pub use resource::summary::{ResourceSummary, SummaryStore};
pub use resource::summary_inference::{behavior_to_summary, infer_summary_for_symbol};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantics_module_exports() {
        let _detector = LanguageDetector::new();
        let _surface = SurfaceClassifier::new();
        let _registry = FamilyRegistry::new();
    }
}
