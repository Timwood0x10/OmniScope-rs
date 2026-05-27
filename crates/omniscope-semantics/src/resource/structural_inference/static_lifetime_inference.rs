//! Static-lifetime sink inference for structural analysis.
//!
//! When a resource is initialized once and stored in global/static storage,
//! model it as:
//!
//! ```text
//! EscapeKind::StaticLifetime
//! LifetimeDomain::ProcessStatic
//! ```
//!
//! This is NOT automatic suppression. If allocation happens in a loop
//! or repeated path, keep a leak candidate. Only truly one-time static
//! initialization should be classified as a static-lifetime sink.

use omniscope_types::{
    Effect, EscapeKind, Evidence, EvidenceKind, FamilyId, FunctionId, FunctionOrigin, LanguageHint,
    LifetimeDomain, PointerContract, SymbolId,
};

use crate::resource::summary::ResourceSummary;

/// Result of static-lifetime inference for a function.
#[derive(Debug, Clone)]
pub struct StaticLifetimeInferenceResult {
    /// Whether this function was inferred as a static-lifetime sink.
    pub is_static_lifetime: bool,
    /// The kind of static storage inferred.
    pub kind: StaticLifetimeKind,
    /// The resource family being stored.
    pub family: FamilyId,
    /// Whether this is a loop-safe initialization (single-execution).
    pub is_single_init: bool,
    /// Confidence of the inference (0.0 - 1.0).
    pub confidence: f32,
    /// Reason for the inference.
    pub reason: String,
}

/// Kind of static storage inferred from context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StaticLifetimeKind {
    /// C/C++ static local variable initialization.
    StaticLocal,
    /// C/C++ global variable initialization.
    GlobalVariable,
    /// Rust lazy_static / OnceLock / Once.
    RustLazyStatic,
    /// Rust static / const item.
    RustStaticItem,
    /// Java class initializer (static block).
    JavaClassInit,
    /// Python module-level initialization.
    PythonModuleInit,
    /// Generic once-only initialization.
    GenericOnceInit,
}

/// Infers whether a function performs static-lifetime initialization
/// and builds its summary.
///
/// Static initialization is not a leak — the resource lives for the
/// entire process lifetime. However, if allocation happens in a loop
/// or repeated path, this inference should NOT apply.
///
/// The inference uses naming patterns, language hints, and context
/// to determine if the allocation is a one-time static init.
pub fn infer_static_lifetime_summary(
    name: &str,
    function: FunctionId,
    canonical_name: SymbolId,
    language_hint: LanguageHint,
    alloc_family: FamilyId,
) -> (ResourceSummary, StaticLifetimeInferenceResult) {
    let mut summary = ResourceSummary::new(function, canonical_name, name);
    summary.language_hint = language_hint;

    let Some((kind, confidence, is_single_init)) =
        classify_static_lifetime_name(name, language_hint)
    else {
        let result = StaticLifetimeInferenceResult {
            is_static_lifetime: false,
            kind: StaticLifetimeKind::GenericOnceInit,
            family: alloc_family,
            is_single_init: false,
            confidence: 0.0,
            reason: format!("no static-lifetime pattern match for: {name}"),
        };
        return (summary, result);
    };

    summary.origin = FunctionOrigin::UserCode;
    summary.confidence = confidence;

    // StoresArgToGlobal: the function stores a resource to static storage.
    summary.add_effect(Effect::StoresArgToGlobal { arg: 0 });

    // Attach static-lifetime evidence
    summary.add_evidence(
        Evidence::new(
            EvidenceKind::StaticLifetimeSink,
            format!(
                "function '{name}' inferred as {:?} static-lifetime sink for {:?}",
                kind, alloc_family
            ),
        )
        .with_confidence(confidence)
        .with_family(alloc_family)
        .with_escape(EscapeKind::StaticLifetime),
    );

    let result = StaticLifetimeInferenceResult {
        is_static_lifetime: true,
        kind,
        family: alloc_family,
        is_single_init,
        confidence,
        reason: format!(
            "function '{name}' matches {:?} static-lifetime initialization pattern",
            kind
        ),
    };

    (summary, result)
}

/// Classifies a function name as a static-lifetime kind.
fn classify_static_lifetime_name(
    name: &str,
    language_hint: LanguageHint,
) -> Option<(StaticLifetimeKind, f32, bool)> {
    // Language-specific patterns
    match language_hint {
        LanguageHint::Rust => {
            // lazy_static! / OnceLock / Once
            if name.contains("lazy_static")
                || name.contains("OnceLock")
                || name.contains("once_lock")
                || name.contains("Once::call_once")
                || name.contains("call_once")
            {
                return Some((StaticLifetimeKind::RustLazyStatic, 0.85, true));
            }
            // static items
            if name.starts_with("<static>")
                || name.contains("::init::")
                || name.contains("__static_init")
            {
                return Some((StaticLifetimeKind::RustStaticItem, 0.8, true));
            }
        }
        LanguageHint::Cpp => {
            // C++ static local variables — guard patterns
            if name.contains("__cxa_guard_acquire") || name.contains("__cxa_guard_release") {
                return Some((StaticLifetimeKind::StaticLocal, 0.9, true));
            }
            // Global constructors (_GLOBAL__I_, __cxx_global_var_init)
            if name.starts_with("_GLOBAL__I_")
                || name == "__cxx_global_var_init"
                || name.starts_with("__cxx_global_var_init")
            {
                return Some((StaticLifetimeKind::GlobalVariable, 0.95, true));
            }
        }
        LanguageHint::Java if name == "<clinit>" || name.ends_with(".<clinit>") => {
            // <clinit> — class initialization method
            return Some((StaticLifetimeKind::JavaClassInit, 0.85, true));
        }
        LanguageHint::Python if name.starts_with("PyInit_") => {
            // Module init functions (PyInit_*)
            return Some((StaticLifetimeKind::PythonModuleInit, 0.8, true));
        }
        _ => {}
    }

    // Generic patterns
    let lower = name.to_lowercase();

    // init / initialize / setup — only if clearly one-time
    if lower.ends_with("_init_once") || lower.ends_with("_once_init") {
        return Some((StaticLifetimeKind::GenericOnceInit, 0.7, true));
    }

    // global_init / static_init
    if lower.contains("global_init")
        || lower.contains("static_init")
        || lower.contains("_global_ctor")
    {
        return Some((StaticLifetimeKind::GlobalVariable, 0.75, true));
    }

    // register / install — might be one-time, but lower confidence
    if lower.ends_with("_register") || lower.ends_with("_install") {
        return Some((StaticLifetimeKind::GenericOnceInit, 0.4, false));
    }

    None
}

/// Returns the appropriate `LifetimeDomain` for a static-lifetime result.
pub fn lifetime_domain_for(kind: StaticLifetimeKind) -> LifetimeDomain {
    match kind {
        StaticLifetimeKind::StaticLocal
        | StaticLifetimeKind::GlobalVariable
        | StaticLifetimeKind::RustLazyStatic
        | StaticLifetimeKind::RustStaticItem
        | StaticLifetimeKind::JavaClassInit
        | StaticLifetimeKind::PythonModuleInit
        | StaticLifetimeKind::GenericOnceInit => LifetimeDomain::ProcessStatic,
    }
}

/// Returns the appropriate `PointerContract` for a static-lifetime result.
pub fn pointer_contract_for(_kind: StaticLifetimeKind) -> PointerContract {
    PointerContract::StaticLifetime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cxx_global_var_init() {
        let (_summary, result) = infer_static_lifetime_summary(
            "__cxx_global_var_init",
            1,
            100,
            LanguageHint::Cpp,
            FamilyId::C_HEAP,
        );
        assert!(
            result.is_static_lifetime,
            "__cxx_global_var_init must be inferred as static-lifetime"
        );
        assert_eq!(result.kind, StaticLifetimeKind::GlobalVariable);
        assert!(result.is_single_init, "Global var init is single execution");
        assert!(result.confidence > 0.9);
    }

    #[test]
    fn test_rust_lazy_static() {
        let (summary, result) = infer_static_lifetime_summary(
            "lazy_static_init",
            2,
            200,
            LanguageHint::Rust,
            FamilyId::RUST_GLOBAL,
        );
        assert!(
            result.is_static_lifetime,
            "lazy_static must be inferred as static-lifetime"
        );
        assert_eq!(result.kind, StaticLifetimeKind::RustLazyStatic);
        assert!(
            !summary.evidence.is_empty(),
            "Static-lifetime summary must have evidence"
        );
    }

    #[test]
    fn test_cxx_guard_acquire() {
        let (_, result) = infer_static_lifetime_summary(
            "__cxa_guard_acquire",
            3,
            300,
            LanguageHint::Cpp,
            FamilyId::C_HEAP,
        );
        assert!(
            result.is_static_lifetime,
            "C++ guard must be inferred as static-lifetime"
        );
        assert_eq!(result.kind, StaticLifetimeKind::StaticLocal);
    }

    #[test]
    fn test_java_clinit() {
        let (_, result) =
            infer_static_lifetime_summary("<clinit>", 4, 400, LanguageHint::Java, FamilyId::C_HEAP);
        assert!(
            result.is_static_lifetime,
            "Java <clinit> must be inferred as static-lifetime"
        );
        assert_eq!(result.kind, StaticLifetimeKind::JavaClassInit);
    }

    #[test]
    fn test_python_module_init() {
        let (_, result) = infer_static_lifetime_summary(
            "PyInit_mymodule",
            5,
            500,
            LanguageHint::Python,
            FamilyId::PYTHON_MEM,
        );
        assert!(
            result.is_static_lifetime,
            "PyInit_* must be inferred as static-lifetime"
        );
        assert_eq!(result.kind, StaticLifetimeKind::PythonModuleInit);
    }

    #[test]
    fn test_generic_once_init() {
        let (_, result) = infer_static_lifetime_summary(
            "config_init_once",
            6,
            600,
            LanguageHint::Unknown,
            FamilyId::C_HEAP,
        );
        assert!(
            result.is_static_lifetime,
            "once_init must be inferred as static-lifetime"
        );
        assert_eq!(result.kind, StaticLifetimeKind::GenericOnceInit);
        assert!(result.is_single_init);
    }

    #[test]
    fn test_register_is_lower_confidence() {
        let (_, result) = infer_static_lifetime_summary(
            "plugin_register",
            7,
            700,
            LanguageHint::Unknown,
            FamilyId::C_HEAP,
        );
        assert!(
            result.is_static_lifetime,
            "register must be inferred as potential static-lifetime"
        );
        assert!(
            !result.is_single_init,
            "register is NOT guaranteed single init"
        );
        assert!(
            result.confidence < 0.6,
            "register pattern should have low confidence"
        );
    }

    #[test]
    fn test_non_static_not_inferred() {
        let (_, result) = infer_static_lifetime_summary(
            "process_request",
            8,
            800,
            LanguageHint::Unknown,
            FamilyId::C_HEAP,
        );
        assert!(
            !result.is_static_lifetime,
            "process_request must NOT be inferred as static-lifetime"
        );
    }

    #[test]
    fn test_static_lifetime_evidence_has_escape() {
        let (summary, _) = infer_static_lifetime_summary(
            "__cxx_global_var_init",
            1,
            100,
            LanguageHint::Cpp,
            FamilyId::C_HEAP,
        );
        assert_eq!(
            summary.evidence[0].kind,
            EvidenceKind::StaticLifetimeSink,
            "Evidence must be StaticLifetimeSink"
        );
        assert_eq!(
            summary.evidence[0].escape,
            Some(EscapeKind::StaticLifetime),
            "Evidence must have StaticLifetime escape"
        );
    }

    #[test]
    fn test_lifetime_domain_process_static() {
        assert_eq!(
            lifetime_domain_for(StaticLifetimeKind::GlobalVariable),
            LifetimeDomain::ProcessStatic
        );
        assert_eq!(
            lifetime_domain_for(StaticLifetimeKind::RustLazyStatic),
            LifetimeDomain::ProcessStatic
        );
    }

    #[test]
    fn test_pointer_contract_static_lifetime() {
        assert_eq!(
            pointer_contract_for(StaticLifetimeKind::GlobalVariable),
            PointerContract::StaticLifetime
        );
    }
}
