//! Surface Classifier — Language-Agnostic Function Surface Classification.
//!
//! Replaces the name-based whitelist approach with a provenance-based
//! classification system. Shared across all passes via PassContext.
//!
//! ## Layers
//!
//!   L1 — Linkage Heuristic (function linkage + visibility)
//!   L2 — Debug Origin / Source Path Provenance
//!   L3 — CallGraph Reachability (invoked by pass)
//!
//! ## Design Principle
//!
//! Do NOT rely on crate name whitelists. Do NOT scan function bodies to
//! decide "whether it is worth analyzing." Preserve FFI producer, boundary,
//! and unknown scenarios. Let all heavy passes share the same surface
//! classification result.

use omniscope_types::Language;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Canonical function surface classification.
///
/// Shared across all analysis passes. Determines whether a function
/// should be analyzed, skipped, or treated as a boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum FunctionSurface {
    /// User-written code — always analyze.
    UserCode,
    /// Third-party dependency — analyze but lower priority.
    Dependency,
    /// FFI / cross-language boundary — always preserve.
    Boundary,
    /// Standard library — skip by default.
    #[default]
    StandardLibrary,
    /// Compiler-generated glue (drop glue, shims, panic) — skip.
    CompilerGenerated,
    /// Language runtime internals — skip.
    Runtime,
    /// Cannot determine — keep for analysis (safe default).
    Unknown,
}

impl FunctionSurface {
    /// Returns a human-readable string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            FunctionSurface::UserCode => "USER_CODE",
            FunctionSurface::Dependency => "DEPENDENCY",
            FunctionSurface::Boundary => "BOUNDARY",
            FunctionSurface::StandardLibrary => "STDLIB",
            FunctionSurface::CompilerGenerated => "COMPILER_GEN",
            FunctionSurface::Runtime => "RUNTIME",
            FunctionSurface::Unknown => "UNKNOWN",
        }
    }

    /// Should functions of this surface be analyzed by default?
    ///
    /// User code, dependencies, boundaries, and unknowns must be
    /// analyzed. Standard library, compiler-generated, and runtime
    /// internals can be safely skipped.
    pub fn should_analyze(&self) -> bool {
        matches!(
            self,
            FunctionSurface::UserCode
                | FunctionSurface::Dependency
                | FunctionSurface::Boundary
                | FunctionSurface::Unknown
        )
    }
}

/// Confidence level for a classification hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Confidence {
    /// Low confidence — the hint may be wrong.
    Low,
    /// Medium confidence — likely correct but not certain.
    Medium,
    /// High confidence — very likely correct.
    High,
}

/// Intermediate result from a single classification layer.
///
/// Each layer produces hints; the final decision merges all layers
/// by picking the hint with the highest confidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceHint {
    /// The proposed surface classification.
    pub surface: FunctionSurface,
    /// How confident this layer is about the classification.
    pub confidence: Confidence,
    /// Human-readable reason for this hint.
    pub reason: String,
}

/// Surface classifier performing multi-layer function classification.
///
/// This is the main entry point for surface classification. It applies
/// L1 (linkage) and L2 (debug origin) heuristics and merges the results.
/// L3 (callgraph reachability) is applied separately by the
/// SurfaceClassifierPass.
pub struct SurfaceClassifier {
    /// Cache of known stdlib/runtime prefixes per language.
    stdlib_prefixes: HashMap<Language, Vec<&'static str>>,
    /// Cache of known compiler-generated prefixes per language.
    compiler_prefixes: HashMap<Language, Vec<&'static str>>,
    /// Cache of known runtime prefixes per language.
    runtime_prefixes: HashMap<Language, Vec<&'static str>>,
}

impl SurfaceClassifier {
    /// Creates a new surface classifier with built-in pattern knowledge.
    pub fn new() -> Self {
        Self {
            stdlib_prefixes: Self::build_stdlib_prefixes(),
            compiler_prefixes: Self::build_compiler_prefixes(),
            runtime_prefixes: Self::build_runtime_prefixes(),
        }
    }

    /// Classifies a function using L1 + L2 heuristics.
    ///
    /// L1 checks the function name against known stdlib/compiler/runtime
    /// prefixes. L2 checks the source path (if available) for provenance
    /// signals. The result with highest confidence wins.
    pub fn classify(
        &self,
        func_name: &str,
        language: Language,
        source_path: Option<&str>,
    ) -> FunctionSurface {
        let hints = self.collect_hints(func_name, language, source_path);
        self.merge_hints(&hints)
    }

    /// Collects classification hints from all layers.
    pub fn collect_hints(
        &self,
        func_name: &str,
        language: Language,
        source_path: Option<&str>,
    ) -> Vec<SurfaceHint> {
        let mut hints = Vec::new();

        // L1: Linkage / name-based heuristic
        if let Some(hint) = self.classify_linkage(func_name, language) {
            hints.push(hint);
        }

        // L2: Debug origin / source path provenance
        if let Some(path) = source_path {
            if let Some(hint) = self.classify_source_path(path) {
                hints.push(hint);
            }
        }

        // If no hints produced, default to Unknown
        if hints.is_empty() {
            hints.push(SurfaceHint {
                surface: FunctionSurface::Unknown,
                confidence: Confidence::Low,
                reason: "no classification signals found".to_string(),
            });
        }

        hints
    }

    /// L1: Classify based on function name linkage patterns.
    fn classify_linkage(&self, func_name: &str, language: Language) -> Option<SurfaceHint> {
        // Check runtime prefixes first (highest skip priority)
        if let Some(prefixes) = self.runtime_prefixes.get(&language) {
            for prefix in prefixes {
                if func_name.starts_with(prefix) {
                    return Some(SurfaceHint {
                        surface: FunctionSurface::Runtime,
                        confidence: Confidence::High,
                        reason: format!("name matches runtime prefix '{}'", prefix),
                    });
                }
            }
        }

        // Check compiler-generated prefixes
        if let Some(prefixes) = self.compiler_prefixes.get(&language) {
            for prefix in prefixes {
                if func_name.starts_with(prefix) {
                    return Some(SurfaceHint {
                        surface: FunctionSurface::CompilerGenerated,
                        confidence: Confidence::High,
                        reason: format!("name matches compiler-generated prefix '{}'", prefix),
                    });
                }
            }
        }

        // Check stdlib prefixes
        if let Some(prefixes) = self.stdlib_prefixes.get(&language) {
            for prefix in prefixes {
                if func_name.starts_with(prefix) {
                    return Some(SurfaceHint {
                        surface: FunctionSurface::StandardLibrary,
                        confidence: Confidence::Medium,
                        reason: format!("name matches stdlib prefix '{}'", prefix),
                    });
                }
            }
        }

        // Language-specific FFI boundary detection
        if self.is_ffi_boundary_name(func_name, language) {
            return Some(SurfaceHint {
                surface: FunctionSurface::Boundary,
                confidence: Confidence::High,
                reason: "name indicates FFI boundary crossing".to_string(),
            });
        }

        None
    }

    /// L2: Classify based on source file path provenance.
    fn classify_source_path(&self, path: &str) -> Option<SurfaceHint> {
        // Standard library paths (Rust core/std/alloc, C system headers)
        let stdlib_paths = [
            "/usr/include/",
            "/usr/lib/",
            "/usr/local/include/",
            "rustc/",
            "rustlib/",
            ".rustup/",
            "std/src/",
            "core/src/",
            "alloc/src/",
        ];

        for stdlib_path in &stdlib_paths {
            if path.contains(stdlib_path) {
                return Some(SurfaceHint {
                    surface: FunctionSurface::StandardLibrary,
                    confidence: Confidence::High,
                    reason: format!("source path indicates stdlib: '{}'", stdlib_path),
                });
            }
        }

        // Dependency paths (third-party crates from package registries)
        let dep_paths = [
            ".cargo/registry/",
            ".cargo/git/",
            "vendor/",
            "node_modules/",
            "third_party/",
        ];

        for dep_path in &dep_paths {
            if path.contains(dep_path) {
                return Some(SurfaceHint {
                    surface: FunctionSurface::Dependency,
                    confidence: Confidence::High,
                    reason: format!("source path indicates dependency: '{}'", dep_path),
                });
            }
        }

        // Dependency paths
        let dep_paths = [".cargo/registry/src/", "vendor/", "third_party/"];
        for dep_path in &dep_paths {
            if path.contains(dep_path) {
                return Some(SurfaceHint {
                    surface: FunctionSurface::Dependency,
                    confidence: Confidence::Medium,
                    reason: format!("source path indicates dependency: '{}'", dep_path),
                });
            }
        }

        None
    }

    /// Checks if a function name indicates an FFI boundary.
    fn is_ffi_boundary_name(&self, func_name: &str, language: Language) -> bool {
        match language {
            Language::Rust => {
                func_name.contains("extern")
                    || func_name.contains("ffi")
                    || func_name.contains("c_api")
                    || func_name.contains("_with_c")
            }
            Language::Go => func_name.starts_with("C.") || func_name.contains("cgo"),
            _ => false,
        }
    }

    /// Merges multiple hints by picking the highest-confidence one.
    ///
    /// In case of equal confidence, Boundary > Unknown > others
    /// (conservative: preserve FFI boundaries and unknowns).
    fn merge_hints(&self, hints: &[SurfaceHint]) -> FunctionSurface {
        hints
            .iter()
            .max_by(|a, b| {
                let cmp = self
                    .confidence_order(a.confidence)
                    .cmp(&self.confidence_order(b.confidence));
                if cmp != std::cmp::Ordering::Equal {
                    return cmp;
                }
                // Equal confidence: prefer Boundary, then Unknown
                self.surface_priority(a.surface)
                    .cmp(&self.surface_priority(b.surface))
            })
            .map(|h| h.surface)
            .unwrap_or(FunctionSurface::Unknown)
    }

    fn confidence_order(&self, c: Confidence) -> u8 {
        match c {
            Confidence::Low => 0,
            Confidence::Medium => 1,
            Confidence::High => 2,
        }
    }

    fn surface_priority(&self, s: FunctionSurface) -> u8 {
        match s {
            FunctionSurface::Boundary => 6,
            FunctionSurface::Unknown => 5,
            FunctionSurface::UserCode => 4,
            FunctionSurface::Dependency => 3,
            FunctionSurface::StandardLibrary => 2,
            FunctionSurface::CompilerGenerated => 1,
            FunctionSurface::Runtime => 0,
        }
    }

    fn build_stdlib_prefixes() -> HashMap<Language, Vec<&'static str>> {
        let mut map = HashMap::new();
        map.insert(
            Language::Rust,
            vec!["core::", "alloc::", "std::", "std_unicode::"],
        );
        map.insert(
            Language::Go,
            vec!["runtime.", "fmt.", "strings.", "strconv."],
        );
        map.insert(Language::Cpp, vec!["std::"]);
        map
    }

    fn build_compiler_prefixes() -> HashMap<Language, Vec<&'static str>> {
        let mut map = HashMap::new();
        map.insert(
            Language::Rust,
            vec![
                "_ZN4core",
                "drop_in_place",
                "__rust_dealloc",
                "__rust_alloc",
                "__rust_realloc",
                "panic_fmt",
                "begin_panic",
                "alloc::alloc::",
            ],
        );
        map.insert(Language::Cpp, vec!["_ZNSt", "_GLOBAL_", "__cxxabiv1"]);
        map
    }

    fn build_runtime_prefixes() -> HashMap<Language, Vec<&'static str>> {
        let mut map = HashMap::new();
        map.insert(
            Language::Rust,
            vec!["__rust_", "_ZN3std9panicking", "probe", "__rg_"],
        );
        map.insert(Language::C, vec!["__libc_", "__cxa_", "_Unwind_", "_tlv_"]);
        map
    }
}

impl Default for SurfaceClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_surface_analysis_decision() {
        assert!(
            FunctionSurface::UserCode.should_analyze(),
            "User code must be analyzed"
        );
        assert!(
            FunctionSurface::Boundary.should_analyze(),
            "Boundary must always be analyzed"
        );
        assert!(
            FunctionSurface::Unknown.should_analyze(),
            "Unknown must be analyzed (conservative)"
        );
        assert!(
            !FunctionSurface::StandardLibrary.should_analyze(),
            "Stdlib can be skipped"
        );
        assert!(
            !FunctionSurface::CompilerGenerated.should_analyze(),
            "Compiler glue can be skipped"
        );
        assert!(
            !FunctionSurface::Runtime.should_analyze(),
            "Runtime internals can be skipped"
        );
    }

    #[test]
    fn test_rust_stdlib_classification() {
        let classifier = SurfaceClassifier::new();
        let surface = classifier.classify("std::vec::Vec::push", Language::Rust, None);
        assert_eq!(
            surface,
            FunctionSurface::StandardLibrary,
            "std:: prefix must classify as StandardLibrary"
        );
    }

    #[test]
    fn test_rust_runtime_classification() {
        let classifier = SurfaceClassifier::new();
        let surface = classifier.classify("__rust_dealloc", Language::Rust, None);
        assert_eq!(
            surface,
            FunctionSurface::Runtime,
            "__rust_ prefix must classify as Runtime"
        );
    }

    #[test]
    fn test_ffi_boundary_detection() {
        let classifier = SurfaceClassifier::new();
        let surface = classifier.classify("my_c_api_handler", Language::Rust, None);
        assert_eq!(
            surface,
            FunctionSurface::Boundary,
            "c_api in name must classify as FFI Boundary"
        );
    }

    #[test]
    fn test_source_path_provenance() {
        let classifier = SurfaceClassifier::new();
        let surface = classifier.classify(
            "my_func",
            Language::Rust,
            Some("/home/user/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0/src/lib.rs"),
        );
        assert_eq!(
            surface,
            FunctionSurface::Dependency,
            ".cargo/registry path must classify as Dependency"
        );
    }

    #[test]
    fn test_unknown_function_defaults_to_analyze() {
        let classifier = SurfaceClassifier::new();
        let surface = classifier.classify("my_custom_function", Language::C, None);
        assert!(
            surface.should_analyze(),
            "Unknown functions must default to being analyzed (conservative)"
        );
    }
}
