//! Family inference from symbol patterns and debug info.
//!
//! When a symbol is not directly registered in the `FamilyRegistry`,
//! we can infer its likely family from naming conventions, debug info,
//! and call graph structure. This is the "fuzzy lookup" layer.

use omniscope_types::{FamilyId, LanguageHint};

use super::family_registry::{FamilyRegistry, SymbolEffect};

/// Result of family inference for an unknown symbol.
#[derive(Debug, Clone)]
pub struct InferredFamily {
    /// The inferred family ID (or None if no inference possible).
    pub family_id: Option<FamilyId>,
    /// The inferred effect (or None if unclear).
    pub effect: Option<SymbolEffect>,
    /// Language hint from naming patterns.
    pub language_hint: LanguageHint,
    /// Confidence of the inference (0.0 - 1.0).
    pub confidence: f32,
    /// Reason for the inference.
    pub reason: String,
}

/// Infers a family entry for a symbol not found in the registry.
///
/// Uses naming conventions (prefix, suffix) and language patterns
/// to guess the likely family and effect. Returns `None` if no
/// reasonable inference can be made.
pub fn infer_family(symbol: &str, registry: &FamilyRegistry) -> InferredFamily {
    // Check for common alloc/create/init patterns
    if let Some(entry) = try_alloc_pattern(symbol, registry) {
        return entry;
    }

    // Check for common free/destroy/delete patterns
    if let Some(entry) = try_release_pattern(symbol, registry) {
        return entry;
    }

    // Check for into_raw/from_raw ownership transfer patterns (R-6)
    if let Some(entry) = try_raw_ownership_pattern(symbol) {
        return entry;
    }

    InferredFamily {
        family_id: None,
        effect: None,
        language_hint: infer_language_hint(symbol),
        confidence: 0.0,
        reason: format!("no pattern match for symbol: {symbol}"),
    }
}

/// Try to infer an acquire (alloc) pattern from the symbol name.
fn try_alloc_pattern(symbol: &str, _registry: &FamilyRegistry) -> Option<InferredFamily> {
    let lower = symbol.to_lowercase();

    // foo_alloc / foo_create / foo_new / foo_init patterns
    if lower.ends_with("_alloc") || lower.ends_with("_create") || lower.ends_with("_new") {
        return Some(InferredFamily {
            family_id: None, // Will need model mining to determine exact family
            effect: Some(SymbolEffect::Acquire),
            language_hint: infer_language_hint(symbol),
            confidence: 0.4,
            reason: format!("symbol ends with alloc/create/new pattern: {symbol}"),
        });
    }

    None
}

/// Try to infer a release (free) pattern from the symbol name.
fn try_release_pattern(symbol: &str, _registry: &FamilyRegistry) -> Option<InferredFamily> {
    let lower = symbol.to_lowercase();

    // foo_free / foo_destroy / foo_delete / foo_deinit / foo_close patterns
    if lower.ends_with("_free")
        || lower.ends_with("_destroy")
        || lower.ends_with("_delete")
        || lower.ends_with("_deinit")
        || lower.ends_with("_close")
        || lower.ends_with("_release")
    {
        return Some(InferredFamily {
            family_id: None,
            effect: Some(SymbolEffect::Release),
            language_hint: infer_language_hint(symbol),
            confidence: 0.4,
            reason: format!("symbol ends with free/destroy/delete/deinit pattern: {symbol}"),
        });
    }

    None
}

/// Try to infer an into_raw/from_raw ownership transfer pattern (R-6).
///
/// Handles both demangled names (e.g. `Box::into_raw`) and Rust v0
/// mangled names (e.g. `_RNvXs_...8into_raw`). These are Rust-specific
/// idioms for crossing the safe/unsafe boundary via raw pointer conversion.
fn try_raw_ownership_pattern(symbol: &str) -> Option<InferredFamily> {
    let language_hint = infer_language_hint(symbol);
    if language_hint != LanguageHint::Rust && language_hint != LanguageHint::Unknown {
        return None;
    }

    // into_raw: ownership escapes to raw pointer
    // Demangled: "into_raw" substring, Mangled: "8into_raw" segment
    if symbol.contains("into_raw") || symbol.contains("8into_raw") {
        return Some(InferredFamily {
            family_id: Some(FamilyId::RUST_RAW_OWNERSHIP),
            effect: Some(SymbolEffect::Escape),
            language_hint,
            confidence: 0.85,
            reason: format!("symbol matches into_raw ownership escape pattern: {symbol}"),
        });
    }

    // from_raw: ownership reclaimed from raw pointer
    // Demangled: "from_raw" substring, Mangled: "8from_raw" / "14from_raw_parts"
    if symbol.contains("from_raw")
        || symbol.contains("8from_raw")
        || symbol.contains("14from_raw_parts")
    {
        return Some(InferredFamily {
            family_id: Some(FamilyId::RUST_RAW_OWNERSHIP),
            effect: Some(SymbolEffect::Reclaim),
            language_hint,
            confidence: 0.85,
            reason: format!("symbol matches from_raw ownership reclaim pattern: {symbol}"),
        });
    }

    None
}

/// Infer a language hint from symbol naming conventions.
///
/// This is used by summary inference to determine the language context
/// before attempting structural inference patterns.
pub fn infer_language_hint(symbol: &str) -> LanguageHint {
    if symbol.starts_with("_Z") {
        LanguageHint::Cpp
    } else if symbol.starts_with("__cxx") || symbol.starts_with("_GLOBAL__") {
        // C++ global constructors / guards: __cxx_global_var_init, _GLOBAL__I_*
        LanguageHint::Cpp
    } else if symbol.starts_with("__rust_") {
        LanguageHint::Rust
    } else if symbol.starts_with("Py") || symbol.starts_with("Py_") {
        LanguageHint::Python
    } else if symbol.contains("::") {
        LanguageHint::Cpp
    } else {
        LanguageHint::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_pattern_inference() {
        let registry = FamilyRegistry::new();
        let result = infer_family("foo_alloc", &registry);
        assert_eq!(
            result.effect,
            Some(SymbolEffect::Acquire),
            "foo_alloc should be inferred as Acquire effect"
        );
        assert!(
            result.confidence > 0.0,
            "Pattern match should have positive confidence"
        );
    }

    #[test]
    fn test_free_pattern_inference() {
        let registry = FamilyRegistry::new();
        let result = infer_family("bar_destroy", &registry);
        assert_eq!(
            result.effect,
            Some(SymbolEffect::Release),
            "bar_destroy should be inferred as Release effect"
        );
    }

    #[test]
    fn test_unknown_symbol_no_inference() {
        let registry = FamilyRegistry::new();
        let result = infer_family("my_func", &registry);
        assert_eq!(
            result.family_id, None,
            "Unknown symbol should have no family ID"
        );
        assert_eq!(result.effect, None, "Unknown symbol should have no effect");
    }

    #[test]
    fn test_language_hint_cpp_mangling() {
        assert_eq!(
            infer_language_hint("_ZN3foo3barEv"),
            LanguageHint::Cpp,
            "C++ mangled name should be detected as Cpp"
        );
        assert_eq!(
            infer_language_hint("__rust_alloc"),
            LanguageHint::Rust,
            "Rust runtime function should be detected as Rust"
        );
        assert_eq!(
            infer_language_hint("PyObject_New"),
            LanguageHint::Python,
            "Python C API function should be detected as Python"
        );
    }

    /// Objective: Verify that into_raw pattern is inferred as Escape effect.
    /// Invariants: Symbol containing "into_raw" → SymbolEffect::Escape.
    #[test]
    fn test_into_raw_pattern_inference() {
        let registry = FamilyRegistry::new();
        let result = infer_family("_RNvXs_NtC4alloc5boxed8Box8into_raw", &registry);
        assert_eq!(
            result.effect,
            Some(SymbolEffect::Escape),
            "Mangled into_raw must be inferred as Escape"
        );
        assert_eq!(
            result.family_id,
            Some(FamilyId::RUST_RAW_OWNERSHIP),
            "into_raw must be RUST_RAW_OWNERSHIP family"
        );
    }

    /// Objective: Verify that from_raw pattern is inferred as Reclaim effect.
    /// Invariants: Symbol containing "from_raw" → SymbolEffect::Reclaim.
    #[test]
    fn test_from_raw_pattern_inference() {
        let registry = FamilyRegistry::new();
        // Use a mangled name that is NOT in the registry
        let result = infer_family("_RNvXs_NtC4alloc5boxed8Box8from_raw", &registry);
        assert_eq!(
            result.effect,
            Some(SymbolEffect::Reclaim),
            "Mangled from_raw must be inferred as Reclaim"
        );
        assert_eq!(
            result.family_id,
            Some(FamilyId::RUST_RAW_OWNERSHIP),
            "from_raw must be RUST_RAW_OWNERSHIP family"
        );
    }
}
