//! Family inference from symbol patterns and debug info.
//!
//! When a symbol is not directly registered in the `FamilyRegistry`,
//! we can infer its likely family from naming conventions, debug info,
//! and call graph structure. This is the "fuzzy lookup" layer.

use omniscope_types::{FamilyId, LanguageHint};
use phf::phf_map;

use super::family_registry::{FamilyRegistry, SymbolEffect};

/// Exact allocator function name to language mapping.
///
/// This set provides precise language classification for known allocator
/// functions, used by `infer_language_hint` to improve accuracy for
/// common allocation/deallocation patterns.
///
/// # Design Principle
///
/// Use exact matching (not prefix/substring) for allocators where the
/// full function name uniquely identifies the language. This avoids
/// false positives from prefix-based heuristics.
///
/// # Examples
///
/// ```rust
/// use omniscope_semantics::resource::family_inference::EXACT_ALLOC_SET;
/// use omniscope_types::LanguageHint;
///
/// assert_eq!(EXACT_ALLOC_SET.get("malloc"), Some(&LanguageHint::C));
/// assert_eq!(EXACT_ALLOC_SET.get("__rust_alloc"), Some(&LanguageHint::Rust));
/// assert_eq!(EXACT_ALLOC_SET.get("mi_malloc"), Some(&LanguageHint::C));
/// ```
pub static EXACT_ALLOC_SET: phf::Map<&'static str, LanguageHint> = phf_map! {
    // ── C standard library allocators ──────────────────────────────
    "malloc" => LanguageHint::C,
    "calloc" => LanguageHint::C,
    "realloc" => LanguageHint::C,
    "free" => LanguageHint::C,
    "aligned_alloc" => LanguageHint::C,
    "posix_memalign" => LanguageHint::C,
    "valloc" => LanguageHint::C,
    "pvalloc" => LanguageHint::C,
    "memalign" => LanguageHint::C,
    "reallocarray" => LanguageHint::C,
    // Windows allocators
    "HeapAlloc" => LanguageHint::C,
    "HeapFree" => LanguageHint::C,
    "HeapReAlloc" => LanguageHint::C,
    "LocalAlloc" => LanguageHint::C,
    "LocalFree" => LanguageHint::C,
    "LocalReAlloc" => LanguageHint::C,
    "GlobalAlloc" => LanguageHint::C,
    "GlobalFree" => LanguageHint::C,
    "GlobalReAlloc" => LanguageHint::C,
    "VirtualAlloc" => LanguageHint::C,
    "VirtualFree" => LanguageHint::C,

    // ── Rust global allocator intrinsics ───────────────────────────
    "__rust_alloc" => LanguageHint::Rust,
    "__rust_dealloc" => LanguageHint::Rust,
    "__rust_realloc" => LanguageHint::Rust,
    "__rust_alloc_zeroed" => LanguageHint::Rust,
    // Rust allocator wrappers
    "alloc::alloc::alloc" => LanguageHint::Rust,
    "alloc::alloc::dealloc" => LanguageHint::Rust,
    "alloc::alloc::realloc" => LanguageHint::Rust,
    "alloc::alloc::alloc_zeroed" => LanguageHint::Rust,
    "std::alloc::alloc" => LanguageHint::Rust,
    "std::alloc::dealloc" => LanguageHint::Rust,
    "std::alloc::realloc" => LanguageHint::Rust,
    "std::alloc::alloc_zeroed" => LanguageHint::Rust,
    // Rust allocator variants (evidence: bun_alloc.ll)
    "__rdl_dealloc" => LanguageHint::Rust,
    "__rg_dealloc" => LanguageHint::Rust,

    // ── C++ new/delete ─────────────────────────────────────────────
    "_Znwm" => LanguageHint::Cpp,
    "_Znwj" => LanguageHint::Cpp,
    "_Znam" => LanguageHint::Cpp,
    "_Znaj" => LanguageHint::Cpp,
    "_ZdlPv" => LanguageHint::Cpp,
    "_ZdaPv" => LanguageHint::Cpp,
    "operator new" => LanguageHint::Cpp,
    "operator delete" => LanguageHint::Cpp,
    "operator new[]" => LanguageHint::Cpp,
    "operator delete[]" => LanguageHint::Cpp,

    // ── Python C API ───────────────────────────────────────────────
    "PyObject_New" => LanguageHint::Python,
    "PyObject_NewVar" => LanguageHint::Python,
    "PyObject_Del" => LanguageHint::Python,
    "PyObject_Free" => LanguageHint::Python,
    "PyMem_Malloc" => LanguageHint::Python,
    "PyMem_Calloc" => LanguageHint::Python,
    "PyMem_Realloc" => LanguageHint::Python,
    "PyMem_Free" => LanguageHint::Python,
    "PyMem_RawMalloc" => LanguageHint::Python,
    "PyMem_RawCalloc" => LanguageHint::Python,
    "PyMem_RawRealloc" => LanguageHint::Python,
    "PyMem_RawFree" => LanguageHint::Python,
    "PyBytes_FromStringAndSize" => LanguageHint::Python,
    "PyBytes_FromString" => LanguageHint::Python,
    "PyUnicode_FromString" => LanguageHint::Python,
    "PyUnicode_FromStringAndSize" => LanguageHint::Python,
    "PyList_New" => LanguageHint::Python,
    "PyTuple_New" => LanguageHint::Python,
    "PyDict_New" => LanguageHint::Python,
    "PySet_New" => LanguageHint::Python,

    // ── Java/JNI ───────────────────────────────────────────────────
    "NewLocalRef" => LanguageHint::Java,
    "DeleteLocalRef" => LanguageHint::Java,
    "NewGlobalRef" => LanguageHint::Java,
    "DeleteGlobalRef" => LanguageHint::Java,
    "GetStringUTFChars" => LanguageHint::Java,
    "ReleaseStringUTFChars" => LanguageHint::Java,
    "GetPrimitiveArrayCritical" => LanguageHint::Java,
    "ReleasePrimitiveArrayCritical" => LanguageHint::Java,
    "GetByteArrayElements" => LanguageHint::Java,
    "ReleaseByteArrayElements" => LanguageHint::Java,
    "NewStringUTF" => LanguageHint::Java,
    "NewByteArray" => LanguageHint::Java,

    // ── C#/.NET ────────────────────────────────────────────────────
    "AllocHGlobal" => LanguageHint::CSharp,
    "FreeHGlobal" => LanguageHint::CSharp,
    "CoTaskMemAlloc" => LanguageHint::CSharp,
    "CoTaskMemFree" => LanguageHint::CSharp,

    // ── Go runtime ─────────────────────────────────────────────────
    "runtime.mallocgc" => LanguageHint::Go,
    "runtime.alloc" => LanguageHint::Go,
    "_cgo_allocate" => LanguageHint::Go,
    "_cgo_free" => LanguageHint::Go,
    "_Cfunc_GoMalloc" => LanguageHint::Go,
    "_Cfunc_GoFree" => LanguageHint::Go,

    // ── mimalloc (C-based custom allocator) ────────────────────────
    "mi_malloc" => LanguageHint::C,
    "mi_free" => LanguageHint::C,
    "mi_calloc" => LanguageHint::C,
    "mi_realloc" => LanguageHint::C,
    "mi_zalloc" => LanguageHint::C,
    "mi_malloc_aligned" => LanguageHint::C,
    "mi_free_aligned" => LanguageHint::C,
    "mi_realloc_aligned" => LanguageHint::C,

    // ── jemalloc (C-based custom allocator) ────────────────────────
    "je_malloc" => LanguageHint::C,
    "je_free" => LanguageHint::C,
    "je_calloc" => LanguageHint::C,
    "je_realloc" => LanguageHint::C,
    "je_mallocx" => LanguageHint::C,
    "je_dallocx" => LanguageHint::C,
    "je_rallocx" => LanguageHint::C,
    "je_xallocx" => LanguageHint::C,
    "je_sallocx" => LanguageHint::C,

    // ── tcmalloc (C-based custom allocator) ────────────────────────
    "tc_malloc" => LanguageHint::C,
    "tc_free" => LanguageHint::C,
    "tc_calloc" => LanguageHint::C,
    "tc_realloc" => LanguageHint::C,
    "tc_malloc_skip_new_handler" => LanguageHint::C,
    "tc_malloc_nothrow" => LanguageHint::C,
    "tc_new" => LanguageHint::C,
    "tc_delete" => LanguageHint::C,
    "tc_newarray" => LanguageHint::C,
    "tc_deletearray" => LanguageHint::C,

    // ── dlmalloc ───────────────────────────────────────────────────
    "dlmalloc" => LanguageHint::C,
    "dlfree" => LanguageHint::C,
    "dlcalloc" => LanguageHint::C,
    "dlrealloc" => LanguageHint::C,
    "dlmemalign" => LanguageHint::C,

    // ── nedmalloc ──────────────────────────────────────────────────
    "nedmalloc" => LanguageHint::C,
    "nedfree" => LanguageHint::C,
    "nedcalloc" => LanguageHint::C,
    "nedrealloc" => LanguageHint::C,
    "nedmemalign" => LanguageHint::C,

    // ── rpmalloc ───────────────────────────────────────────────────
    "rpmalloc" => LanguageHint::C,
    "rpfree" => LanguageHint::C,
    "rpcalloc" => LanguageHint::C,
    "rprealloc" => LanguageHint::C,
    "rpmemalign" => LanguageHint::C,

    // ── snmalloc ───────────────────────────────────────────────────
    "sn_malloc" => LanguageHint::C,
    "sn_free" => LanguageHint::C,
    "sn_calloc" => LanguageHint::C,
    "sn_realloc" => LanguageHint::C,
};

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
///
/// # Classification Strategy
///
/// 1. **Exact match** (EXACT_ALLOC_SET): O(1) lookup for known allocator
///    functions with known language mapping.
/// 2. **Prefix heuristics**: For C++ mangling (`_Z*`), Rust runtime (`__rust_*`),
///    Python C API (`Py*`), and other language-specific prefixes.
/// 3. **Contains heuristics**: For C++ namespaces (`::`) and other patterns.
///
/// # Examples
///
/// ```rust
/// use omniscope_semantics::resource::family_inference::infer_language_hint;
/// use omniscope_types::LanguageHint;
///
/// // Exact match
/// assert_eq!(infer_language_hint("malloc"), LanguageHint::C);
/// assert_eq!(infer_language_hint("__rust_alloc"), LanguageHint::Rust);
///
/// // Prefix heuristics
/// assert_eq!(infer_language_hint("_Znwm"), LanguageHint::Cpp);
/// assert_eq!(infer_language_hint("PyObject_New"), LanguageHint::Python);
///
/// // Unknown
/// assert_eq!(infer_language_hint("my_custom_function"), LanguageHint::Unknown);
/// ```
pub fn infer_language_hint(symbol: &str) -> LanguageHint {
    // 1. Exact match for known allocators (O(1) lookup)
    if let Some(lang) = EXACT_ALLOC_SET.get(symbol) {
        return *lang;
    }

    // 2. Prefix heuristics for language-specific patterns
    if symbol.starts_with("_Z") {
        LanguageHint::Cpp
    } else if symbol.starts_with("__cxx") || symbol.starts_with("_GLOBAL__") {
        // C++ global constructors / guards: __cxx_global_var_init, _GLOBAL__I_*
        LanguageHint::Cpp
    } else if symbol.starts_with("__rust_") {
        LanguageHint::Rust
    } else if symbol.starts_with("Py") || symbol.starts_with("Py_") {
        LanguageHint::Python
    } else if symbol.starts_with("runtime.") {
        LanguageHint::Go
    } else if symbol.starts_with("Java_") {
        LanguageHint::Java
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

    /// Objective: Verify EXACT_ALLOC_SET provides correct language classification.
    /// Invariants: Known allocator functions map to their expected languages.
    #[test]
    fn test_exact_alloc_set_language_classification() {
        // C standard library allocators
        assert_eq!(
            EXACT_ALLOC_SET.get("malloc"),
            Some(&LanguageHint::C),
            "malloc must be classified as C"
        );
        assert_eq!(
            EXACT_ALLOC_SET.get("free"),
            Some(&LanguageHint::C),
            "free must be classified as C"
        );
        assert_eq!(
            EXACT_ALLOC_SET.get("calloc"),
            Some(&LanguageHint::C),
            "calloc must be classified as C"
        );
        assert_eq!(
            EXACT_ALLOC_SET.get("realloc"),
            Some(&LanguageHint::C),
            "realloc must be classified as C"
        );

        // Rust allocators
        assert_eq!(
            EXACT_ALLOC_SET.get("__rust_alloc"),
            Some(&LanguageHint::Rust),
            "__rust_alloc must be classified as Rust"
        );
        assert_eq!(
            EXACT_ALLOC_SET.get("__rust_dealloc"),
            Some(&LanguageHint::Rust),
            "__rust_dealloc must be classified as Rust"
        );

        // C++ allocators
        assert_eq!(
            EXACT_ALLOC_SET.get("_Znwm"),
            Some(&LanguageHint::Cpp),
            "_Znwm must be classified as C++"
        );
        assert_eq!(
            EXACT_ALLOC_SET.get("operator new"),
            Some(&LanguageHint::Cpp),
            "operator new must be classified as C++"
        );

        // Python allocators
        assert_eq!(
            EXACT_ALLOC_SET.get("PyObject_New"),
            Some(&LanguageHint::Python),
            "PyObject_New must be classified as Python"
        );
        assert_eq!(
            EXACT_ALLOC_SET.get("PyMem_Malloc"),
            Some(&LanguageHint::Python),
            "PyMem_Malloc must be classified as Python"
        );

        // Go allocators
        assert_eq!(
            EXACT_ALLOC_SET.get("runtime.mallocgc"),
            Some(&LanguageHint::Go),
            "runtime.mallocgc must be classified as Go"
        );
        assert_eq!(
            EXACT_ALLOC_SET.get("_cgo_allocate"),
            Some(&LanguageHint::Go),
            "_cgo_allocate must be classified as Go"
        );

        // Custom allocators (mimalloc, jemalloc, tcmalloc) should be C
        assert_eq!(
            EXACT_ALLOC_SET.get("mi_malloc"),
            Some(&LanguageHint::C),
            "mi_malloc must be classified as C"
        );
        assert_eq!(
            EXACT_ALLOC_SET.get("je_malloc"),
            Some(&LanguageHint::C),
            "je_malloc must be classified as C"
        );
        assert_eq!(
            EXACT_ALLOC_SET.get("tc_malloc"),
            Some(&LanguageHint::C),
            "tc_malloc must be classified as C"
        );
    }

    /// Objective: Verify EXACT_ALLOC_SET doesn't contain non-allocator functions.
    /// Invariants: Non-allocator functions should not be in the set.
    #[test]
    fn test_exact_alloc_set_excludes_non_allocators() {
        assert!(
            EXACT_ALLOC_SET.get("my_custom_function").is_none(),
            "Non-allocator functions should not be in EXACT_ALLOC_SET"
        );
        assert!(
            EXACT_ALLOC_SET.get("strlen").is_none(),
            "String functions should not be in EXACT_ALLOC_SET"
        );
        assert!(
            EXACT_ALLOC_SET.get("printf").is_none(),
            "I/O functions should not be in EXACT_ALLOC_SET"
        );
    }

    /// Objective: Verify infer_language_hint uses EXACT_ALLOC_SET correctly.
    /// Invariants: infer_language_hint should match EXACT_ALLOC_SET for known allocators.
    #[test]
    fn test_infer_language_hint_uses_exact_alloc_set() {
        // Test that infer_language_hint uses EXACT_ALLOC_SET
        assert_eq!(
            infer_language_hint("malloc"),
            LanguageHint::C,
            "infer_language_hint must classify malloc as C"
        );
        assert_eq!(
            infer_language_hint("__rust_alloc"),
            LanguageHint::Rust,
            "infer_language_hint must classify __rust_alloc as Rust"
        );
        assert_eq!(
            infer_language_hint("_Znwm"),
            LanguageHint::Cpp,
            "infer_language_hint must classify _Znwm as C++"
        );
        assert_eq!(
            infer_language_hint("PyObject_New"),
            LanguageHint::Python,
            "infer_language_hint must classify PyObject_New as Python"
        );
        assert_eq!(
            infer_language_hint("runtime.mallocgc"),
            LanguageHint::Go,
            "infer_language_hint must classify runtime.mallocgc as Go"
        );
    }

    /// Objective: Verify infer_language_hint falls back to prefix heuristics.
    /// Invariants: For unknown allocators, prefix heuristics should be used.
    #[test]
    fn test_infer_language_hint_prefix_heuristics() {
        // Test prefix heuristics for unknown allocators
        assert_eq!(
            infer_language_hint("_Z3fooi"),
            LanguageHint::Cpp,
            "C++ mangled names must be classified as C++"
        );
        assert_eq!(
            infer_language_hint("__rust_custom_alloc"),
            LanguageHint::Rust,
            "Rust runtime functions must be classified as Rust"
        );
        assert_eq!(
            infer_language_hint("PyObject_GetAttr"),
            LanguageHint::Python,
            "Python C API functions must be classified as Python"
        );
        assert_eq!(
            infer_language_hint("runtime.newobject"),
            LanguageHint::Go,
            "Go runtime functions must be classified as Go"
        );
        assert_eq!(
            infer_language_hint("Java_com_example_MyClass"),
            LanguageHint::Java,
            "Java JNI functions must be classified as Java"
        );
    }

    /// Objective: Verify infer_language_hint returns Unknown for unrecognized functions.
    /// Invariants: Functions without clear language indicators should be Unknown.
    #[test]
    fn test_infer_language_hint_unknown() {
        assert_eq!(
            infer_language_hint("my_custom_function"),
            LanguageHint::Unknown,
            "Unknown functions must be classified as Unknown"
        );
        assert_eq!(
            infer_language_hint("process_data"),
            LanguageHint::Unknown,
            "Generic functions must be classified as Unknown"
        );
    }
}
