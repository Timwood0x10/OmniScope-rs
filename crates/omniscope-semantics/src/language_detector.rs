//! Language detection from LLVM IR
//!
//! This module detects the source language from LLVM IR characteristics.

use omniscope_types::Language;
use std::collections::HashMap;

/// Language detector for identifying source language
pub struct LanguageDetector {
    /// Language patterns to match
    patterns: Vec<LanguagePattern>,
}

impl LanguageDetector {
    /// Creates a new language detector
    pub fn new() -> Self {
        Self {
            patterns: Self::build_patterns(),
        }
    }

    /// Detects the source language from function name patterns
    pub fn detect_from_function(&self, function_name: &str) -> Language {
        for pattern in &self.patterns {
            if pattern.matches(function_name) {
                return pattern.language;
            }
        }
        Language::Unknown
    }

    /// Detects language from module name
    pub fn detect_from_module(&self, module_name: &str) -> Language {
        // Check for language-specific extensions
        if module_name.ends_with(".rs") || module_name.contains("rust") {
            return Language::Rust;
        }
        if module_name.ends_with(".zig") || module_name.contains("zig") {
            return Language::Zig;
        }
        if module_name.ends_with(".go") || module_name.contains("go") {
            return Language::Go;
        }
        if module_name.ends_with(".py") || module_name.contains("python") {
            return Language::Python;
        }
        if module_name.ends_with(".java") || module_name.contains("java") {
            return Language::Java;
        }
        if module_name.ends_with(".cpp") || module_name.ends_with(".cc") {
            return Language::Cpp;
        }
        if module_name.ends_with(".c") {
            return Language::C;
        }
        Language::Unknown
    }

    /// Detects language from multiple function names
    pub fn detect_from_functions(&self, functions: &[&str]) -> Language {
        let mut scores: HashMap<Language, usize> = HashMap::new();

        for func in functions {
            let lang = self.detect_from_function(func);
            *scores.entry(lang).or_insert(0) += 1;
        }

        scores
            .into_iter()
            .filter(|(lang, _)| *lang != Language::Unknown)
            .max_by_key(|(_, count)| *count)
            .map(|(lang, _)| lang)
            .unwrap_or(Language::Unknown)
    }

    /// Builds language patterns
    fn build_patterns() -> Vec<LanguagePattern> {
        vec![
            // Rust patterns
            LanguagePattern::new(Language::Rust, "_ZN").prefix(), // Rust mangling
            LanguagePattern::new(Language::Rust, "_ZN4core").prefix(),
            LanguagePattern::new(Language::Rust, "_ZN5alloc").prefix(),
            LanguagePattern::new(Language::Rust, "std::").contains(),
            // C++ patterns
            LanguagePattern::new(Language::Cpp, "_Z").prefix(), // C++ mangling
            LanguagePattern::new(Language::Cpp, "std::").contains(),
            LanguagePattern::new(Language::Cpp, "::").contains(),
            // Go patterns
            LanguagePattern::new(Language::Go, "main.").prefix(),
            LanguagePattern::new(Language::Go, "runtime.").prefix(),
            LanguagePattern::new(Language::Go, ".").contains(),
            // Zig patterns
            LanguagePattern::new(Language::Zig, "zig.").prefix(),
            // Python patterns
            LanguagePattern::new(Language::Python, "Py").prefix(),
            LanguagePattern::new(Language::Python, "PyObject").contains(),
            // Java patterns
            LanguagePattern::new(Language::Java, "Java_").prefix(),
            LanguagePattern::new(Language::Java, "JNI").contains(),
        ]
    }
}

impl Default for LanguageDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Language pattern for matching
struct LanguagePattern {
    language: Language,
    pattern: String,
    match_type: MatchType,
}

impl LanguagePattern {
    fn new(language: Language, pattern: impl Into<String>) -> Self {
        Self {
            language,
            pattern: pattern.into(),
            match_type: MatchType::Contains,
        }
    }

    fn prefix(mut self) -> Self {
        self.match_type = MatchType::Prefix;
        self
    }

    fn contains(mut self) -> Self {
        self.match_type = MatchType::Contains;
        self
    }

    fn matches(&self, text: &str) -> bool {
        match self.match_type {
            MatchType::Prefix => text.starts_with(&self.pattern),
            MatchType::Contains => text.contains(&self.pattern),
        }
    }
}

/// Match type for patterns
enum MatchType {
    Prefix,
    Contains,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_detector_creation() {
        let detector = LanguageDetector::new();
        assert!(true);
    }

    #[test]
    fn test_detect_rust() {
        let detector = LanguageDetector::new();

        let lang = detector.detect_from_function("_ZN4core3str4len");
        assert_eq!(lang, Language::Rust);

        let lang = detector.detect_from_module("lib.rs");
        assert_eq!(lang, Language::Rust);
    }

    #[test]
    fn test_detect_cpp() {
        let detector = LanguageDetector::new();

        let lang = detector.detect_from_function("_Z3fooi");
        assert_eq!(lang, Language::Cpp);

        let lang = detector.detect_from_module("main.cpp");
        assert_eq!(lang, Language::Cpp);
    }

    #[test]
    fn test_detect_c() {
        let detector = LanguageDetector::new();

        let lang = detector.detect_from_module("main.c");
        assert_eq!(lang, Language::C);
    }

    #[test]
    fn test_detect_from_functions() {
        let detector = LanguageDetector::new();

        let functions = vec!["_ZN4core3str4len", "_ZN5alloc5alloc", "unknown_func"];

        let lang = detector.detect_from_functions(&functions);
        assert_eq!(lang, Language::Rust);
    }
}
