//! OmniScope Semantics - Semantic analysis engine

pub mod language_detector;

pub use language_detector::LanguageDetector;

#[cfg(test)]
mod tests {
    #[test]
    fn test_semantics_module() {
        assert!(true);
    }
}
