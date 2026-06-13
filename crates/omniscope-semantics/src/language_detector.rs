//! Language detection from LLVM IR
//!
//! This module detects the source language from LLVM IR characteristics.

use omniscope_types::Language;
use std::collections::HashMap;

/// Language detector for identifying source language
#[derive(Clone, Debug)]
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
        // Strip LLVM IR quotes that may surround names with special characters
        let function_name = function_name.trim_matches('"');

        // Pre-check: Rust Itanium (_ZN) mangling has distinctive features
        // that distinguish it from C++ Itanium mangling. Rust _ZN names
        // use special dollar-sign encodings ($LT$, $u20$, $RF$, etc.)
        // and have a hash suffix pattern (17h<hex>E). Check these before
        // the generic _ZN->Cpp pattern to avoid false language classification.
        if function_name.starts_with("_ZN") && is_rust_zn_mangling(function_name) {
            return Language::Rust;
        }

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
        if module_name.ends_with(".go") || module_name.contains("go") {
            return Language::Go;
        }
        if module_name.ends_with(".py") || module_name.contains("python") {
            return Language::Python;
        }
        if module_name.ends_with(".java") || module_name.contains("java") {
            return Language::Java;
        }
        if module_name.ends_with(".cs") || module_name.contains("csharp") {
            return Language::CSharp;
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
            // Rust patterns — Rust v0 mangling (_R prefix, used by modern Rust)
            LanguagePattern::new(Language::Rust, "_R").prefix(),
            // Rust allocator runtime (__rust_alloc, __rust_dealloc, etc.)
            LanguagePattern::new(Language::Rust, "__rust_").prefix(),
            // Rust Itanium mangling (older Rust, less common now)
            LanguagePattern::new(Language::Rust, "_ZN4core").prefix(),
            LanguagePattern::new(Language::Rust, "_ZN5alloc").prefix(),
            LanguagePattern::new(Language::Rust, "_ZN3std").prefix(),
            LanguagePattern::new(Language::Rust, "_ZN7cstring").prefix(),
            LanguagePattern::new(Language::Rust, "_ZN12alloc").prefix(),
            // C++ patterns (more general _ZN after Rust-specific patterns)
            LanguagePattern::new(Language::Cpp, "_ZN").prefix(), // C++ Itanium mangling
            LanguagePattern::new(Language::Cpp, "_ZS").prefix(), // C++ mangling (local)
            LanguagePattern::new(Language::Cpp, "_Z").prefix(),  // C++ mangling (short)
            LanguagePattern::new(Language::Cpp, "std::").contains(),
            LanguagePattern::new(Language::Cpp, "::").contains(),
            // Go patterns (more specific than just main.)
            LanguagePattern::new(Language::Go, "_Cfunc_").prefix(),
            LanguagePattern::new(Language::Go, "_cgo_").prefix(),
            LanguagePattern::new(Language::Go, "runtime.").prefix(),
            // Python patterns
            LanguagePattern::new(Language::Python, "Py").prefix(),
            LanguagePattern::new(Language::Python, "PyObject").contains(),
            // Java patterns
            LanguagePattern::new(Language::Java, "Java_").prefix(),
            LanguagePattern::new(Language::Java, "JNI").contains(),
            // C# patterns (P/Invoke)
            LanguagePattern::new(Language::CSharp, "System.Runtime.InteropServices").contains(),
            LanguagePattern::new(Language::CSharp, "DllImport").contains(),
            LanguagePattern::new(Language::CSharp, "P/Invoke").contains(),
            LanguagePattern::new(Language::CSharp, "Marshal_").prefix(),
            LanguagePattern::new(Language::CSharp, "Marshal.").prefix(),
            // Custom allocator wrapper patterns (red_team corpus)
            LanguagePattern::new(Language::Rust, "rust_box_new").contains(),
            LanguagePattern::new(Language::Cpp, "cpp_new_object").contains(),
            LanguagePattern::new(Language::Cpp, "cpp_delete_object").contains(),
            LanguagePattern::new(Language::Go, "go_alloc").contains(),
            LanguagePattern::new(Language::Go, "go_free").contains(),
            LanguagePattern::new(Language::Java, "jni_alloc").contains(),
        ]
    }
}

impl Default for LanguageDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Language pattern for matching
#[derive(Clone, Debug)]
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

/// Check if a _ZN-prefixed mangled name is Rust (not C++).
///
/// Rust Itanium mangling (_ZN) has distinctive features that C++ does not:
/// - Dollar-sign encodings: $LT$ (angle bracket), $u20$ (space),
///   $RF$ (ampersand), $BP$ (star), $u5b$ (open bracket), $u5d$ (close bracket)
/// - Hash suffix: 17h followed by hex digits and E (e.g., 17h45b67272fd153021E)
///
/// C++ Itanium mangling uses St for std::, N for nested names, and
/// never uses dollar-sign encodings or hash suffixes.
pub fn is_rust_zn_mangling(name: &str) -> bool {
    // Strip LLVM IR quotes that may surround names with special characters
    let name = name.trim_matches('"');
    // Rust-specific dollar-sign encodings (never appear in C++ mangling)
    if name.contains("$LT$")
        || name.contains("$GT$")
        || name.contains("$u20$")
        || name.contains("$RF$")
        || name.contains("$BP$")
        || name.contains("$u5b$")
        || name.contains("$u5d$")
    {
        return true;
    }

    // Rust hash suffix pattern: 17h<hex>E at the end.
    // The hash is typically 16 hex digits (64-bit) followed by E.
    if let Some(rest) = name.strip_prefix("_ZN") {
        if let Some(pos) = rest.find("17h") {
            let after_hash_start = &rest[pos + 3..];
            let hex_len = after_hash_start
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .count();
            if hex_len >= 16 {
                let after_hex = &after_hash_start[hex_len..];
                if after_hex.starts_with('E') {
                    return true;
                }
            }
        }
    }

    // Known Rust stdlib prefixes (Itanium mangling)
    if name.starts_with("_ZN4core")
        || name.starts_with("_ZN5alloc")
        || name.starts_with("_ZN3std")
        || name.starts_with("_ZN7cstring")
        || name.starts_with("_ZN12alloc")
    {
        return true;
    }

    // Rust v0 mangling: _R prefix is exclusively Rust
    if name.starts_with("_R") {
        return true;
    }

    false
}

/// Match type for patterns
#[derive(Clone, Debug)]
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
        assert!(
            !detector.patterns.is_empty(),
            "Language detector should have patterns"
        );
    }

    #[test]
    fn test_detect_rust() {
        let detector = LanguageDetector::new();

        let lang = detector.detect_from_function("_ZN4core3str4len");
        assert_eq!(
            lang,
            Language::Rust,
            "Rust mangled name should be detected as Rust"
        );

        let lang = detector.detect_from_module("lib.rs");
        assert_eq!(lang, Language::Rust, "Rust file should be detected as Rust");
    }

    #[test]
    fn test_detect_cpp() {
        let detector = LanguageDetector::new();

        let lang = detector.detect_from_function("_Z3fooi");
        assert_eq!(
            lang,
            Language::Cpp,
            "C++ mangled name should be detected as C++"
        );

        let lang = detector.detect_from_module("main.cpp");
        assert_eq!(lang, Language::Cpp, "C++ file should be detected as C++");
    }

    #[test]
    fn test_detect_c() {
        let detector = LanguageDetector::new();

        let lang = detector.detect_from_module("main.c");
        assert_eq!(lang, Language::C, "C file should be detected as C");
    }

    #[test]
    fn test_detect_csharp() {
        let detector = LanguageDetector::new();

        let lang = detector.detect_from_module("Program.cs");
        assert_eq!(lang, Language::CSharp, "C# file should be detected as C#");

        let lang = detector.detect_from_module("csharp_module");
        assert_eq!(lang, Language::CSharp, "C# module should be detected as C#");
    }

    #[test]
    fn test_detect_java() {
        let detector = LanguageDetector::new();

        let lang = detector.detect_from_module("Main.java");
        assert_eq!(lang, Language::Java, "Java file should be detected as Java");

        let lang = detector.detect_from_module("java_module");
        assert_eq!(
            lang,
            Language::Java,
            "Java module should be detected as Java"
        );
    }

    #[test]
    fn test_detect_from_functions() {
        let detector = LanguageDetector::new();

        let functions = vec!["_ZN4core3str4len", "_ZN5alloc5alloc", "unknown_func"];

        let lang = detector.detect_from_functions(&functions);
        assert_eq!(
            lang,
            Language::Rust,
            "Rust functions should be detected as Rust"
        );
    }
}
