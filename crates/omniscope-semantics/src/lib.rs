//! OmniScope Semantics - Semantic analysis engine
//!
//! This crate provides semantic analysis for OmniScope, including:
//!
//! - Language detection from LLVM IR
//! - Zone classification for optimization
//! - Noise reduction filters

pub mod language_detector;
pub mod zone_classifier;

// Re-exports
pub use language_detector::LanguageDetector;
pub use zone_classifier::{ZoneClassifier, ZoneKind, ZoneStats};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantics_module_exports() {
        let _detector = LanguageDetector::new();
        let _classifier = ZoneClassifier::new();
    }
}
