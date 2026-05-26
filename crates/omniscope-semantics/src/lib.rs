//! OmniScope Semantics - Semantic analysis engine.
//!
//! This crate provides semantic analysis for OmniScope, including:
//!
//! - Language detection from LLVM IR (with weighted voting)
//! - Zone classification for optimization (safe/escape/boundary)
//! - Surface classification for function provenance

pub mod language_detector;
pub mod surface_classifier;
pub mod zone_classifier;

// Re-exports
pub use language_detector::LanguageDetector;
pub use surface_classifier::{Confidence, FunctionSurface, SurfaceClassifier, SurfaceHint};
pub use zone_classifier::{ZoneClassifier, ZoneKind, ZoneStats};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantics_module_exports() {
        let _detector = LanguageDetector::new();
        let _classifier = ZoneClassifier::new();
        let _surface = SurfaceClassifier::new();
    }
}
