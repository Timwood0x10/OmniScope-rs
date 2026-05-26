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
pub mod zone_classifier;

// Re-exports — Legacy modules
pub use language_detector::LanguageDetector;
pub use surface_classifier::{Confidence, FunctionSurface, SurfaceClassifier, SurfaceHint};
pub use zone_classifier::{ZoneClassifier, ZoneKind, ZoneStats};

// Re-exports — Resource contract modules
pub use resource::escape::{classify_escape, EscapeContext, EscapeResult};
pub use resource::family_inference::infer_family;
pub use resource::family_registry::{
    FamilyEntry, FamilyRegistry, ResourceFamilyOwned, SymbolEffect,
};
pub use resource::ownership_state::{
    OwnershipError, OwnershipEvent, OwnershipState, ResourceInstance,
};
pub use resource::summary::{ResourceSummary, SummaryStore};
pub use resource::summary_inference::infer_summary_for_symbol;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantics_module_exports() {
        let _detector = LanguageDetector::new();
        let _classifier = ZoneClassifier::new();
        let _surface = SurfaceClassifier::new();
        let _registry = FamilyRegistry::new();
    }
}
