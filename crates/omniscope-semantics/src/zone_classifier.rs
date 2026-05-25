//! Zone classifier for analysis optimization
//!
//! This module classifies code into safe/risky zones to skip unnecessary analysis.

use omniscope_types::Language;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Zone classification for optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ZoneKind {
    /// Safe zone - can skip analysis
    Safe,
    /// Risky zone - needs analysis
    Risky,
    /// Unknown zone - conservative analysis
    Unknown,
}

impl Default for ZoneKind {
    fn default() -> Self {
        ZoneKind::Unknown
    }
}

/// Zone classifier for optimizing analysis
pub struct ZoneClassifier {
    /// Safe function patterns
    safe_patterns: Vec<String>,
    /// Risky function patterns
    risky_patterns: Vec<String>,
    /// Cache of classified functions
    cache: HashSet<String>,
}

impl ZoneClassifier {
    /// Creates a new zone classifier
    pub fn new() -> Self {
        Self {
            safe_patterns: Self::build_safe_patterns(),
            risky_patterns: Self::build_risky_patterns(),
            cache: HashSet::new(),
        }
    }

    /// Classifies a function into a zone
    pub fn classify(&self, function_name: &str, language: Language) -> ZoneKind {
        // Check risky patterns first
        for pattern in &self.risky_patterns {
            if function_name.contains(pattern) {
                return ZoneKind::Risky;
            }
        }

        // Check language-specific risky patterns
        if self.is_risky_for_language(function_name, language) {
            return ZoneKind::Risky;
        }

        // Check safe patterns
        for pattern in &self.safe_patterns {
            if function_name.contains(pattern) {
                return ZoneKind::Safe;
            }
        }

        // Default to unknown for conservative analysis
        ZoneKind::Unknown
    }

    /// Checks if function is risky for a specific language
    fn is_risky_for_language(&self, function_name: &str, language: Language) -> bool {
        match language {
            Language::Rust => {
                // Rust unsafe functions
                function_name.contains("unsafe")
                    || function_name.contains("transmute")
                    || function_name.contains("from_raw")
                    || function_name.contains("as_ptr")
            }
            Language::C | Language::Cpp => {
                // C/C++ memory functions
                function_name.contains("malloc")
                    || function_name.contains("free")
                    || function_name.contains("realloc")
                    || function_name.contains("memcpy")
                    || function_name.contains("strcpy")
            }
            Language::Zig => {
                // Zig unsafe operations
                function_name.contains("unsafe") || function_name.contains("ptrCast")
            }
            _ => false,
        }
    }

    /// Builds safe function patterns
    fn build_safe_patterns() -> Vec<String> {
        vec![
            // Standard library safe functions
            "strlen".to_string(),
            "strcmp".to_string(),
            "strncmp".to_string(),
            // Math functions
            "sin".to_string(),
            "cos".to_string(),
            "sqrt".to_string(),
            "abs".to_string(),
            // String operations
            "isalpha".to_string(),
            "isdigit".to_string(),
            "isspace".to_string(),
        ]
    }

    /// Builds risky function patterns
    fn build_risky_patterns() -> Vec<String> {
        vec![
            // Memory allocation
            "malloc".to_string(),
            "calloc".to_string(),
            "realloc".to_string(),
            "free".to_string(),
            // Memory operations
            "memcpy".to_string(),
            "memmove".to_string(),
            "memset".to_string(),
            // String operations (unsafe)
            "strcpy".to_string(),
            "strcat".to_string(),
            "sprintf".to_string(),
            // FFI
            "dlopen".to_string(),
            "dlsym".to_string(),
            // Unsafe operations
            "unsafe".to_string(),
            "transmute".to_string(),
        ]
    }

    /// Returns statistics about classification
    pub fn stats(&self) -> ZoneStats {
        ZoneStats {
            cached: self.cache.len(),
        }
    }

    /// Clears the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

impl Default for ZoneClassifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Zone classification statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneStats {
    /// Number of cached classifications
    pub cached: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_classifier_creation() {
        let classifier = ZoneClassifier::new();
        assert!(true);
    }

    #[test]
    fn test_classify_safe_functions() {
        let classifier = ZoneClassifier::new();

        let zone = classifier.classify("strlen", Language::C);
        assert_eq!(zone, ZoneKind::Safe);

        let zone = classifier.classify("abs", Language::C);
        assert_eq!(zone, ZoneKind::Safe);
    }

    #[test]
    fn test_classify_risky_functions() {
        let classifier = ZoneClassifier::new();

        let zone = classifier.classify("malloc", Language::C);
        assert_eq!(zone, ZoneKind::Risky);

        let zone = classifier.classify("free", Language::C);
        assert_eq!(zone, ZoneKind::Risky);

        let zone = classifier.classify("strcpy", Language::C);
        assert_eq!(zone, ZoneKind::Risky);
    }

    #[test]
    fn test_classify_rust_unsafe() {
        let classifier = ZoneClassifier::new();

        let zone = classifier.classify("std::mem::transmute", Language::Rust);
        assert_eq!(zone, ZoneKind::Risky);

        let zone = classifier.classify("from_raw_parts", Language::Rust);
        assert_eq!(zone, ZoneKind::Risky);
    }

    #[test]
    fn test_classify_unknown() {
        let classifier = ZoneClassifier::new();

        let zone = classifier.classify("custom_function", Language::C);
        assert_eq!(zone, ZoneKind::Unknown);
    }
}
