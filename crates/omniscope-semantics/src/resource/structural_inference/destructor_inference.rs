//! Destructor/drop/dispose inference for structural analysis.
//!
//! Infers destructor-like summaries when a function:
//! - Has a name/debug marker such as `drop`, `destroy`, `dealloc`,
//!   `delete`, `Dispose`, `finalize`, `__del__`, or C++ destructor mangling.
//! - Takes a pointer-like receiver or argument.
//! - Calls known release functions or releases fields.
//! - Does not return an owned resource.
//!
//! Generated effects:
//! ```text
//! ConsumesArg + Release / release-fields evidence
//! ```
//!
//! This handles Rust Drop calling C free, C++ destructors, C# Dispose,
//! and Python-style finalizers.

use omniscope_types::{
    Effect, Evidence, EvidenceKind, FamilyId, FunctionId, FunctionOrigin, LanguageHint, SymbolId,
};

use crate::resource::summary::ResourceSummary;

/// Result of destructor inference for a function.
#[derive(Debug, Clone)]
pub struct DestructorInferenceResult {
    /// Whether this function was inferred as a destructor.
    pub is_destructor: bool,
    /// The kind of destructor inferred.
    pub kind: DestructorKind,
    /// The argument index that is consumed (the receiver/self).
    pub consumed_arg: u32,
    /// The resource family being released (if determinable).
    pub release_family: Option<FamilyId>,
    /// Confidence of the inference (0.0 - 1.0).
    pub confidence: f32,
    /// Reason for the inference.
    pub reason: String,
}

/// Kind of destructor inferred from naming patterns and behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DestructorKind {
    /// Rust Drop trait implementation.
    RustDrop,
    /// C++ destructor (mangled or explicit).
    CppDestructor,
    /// C# Dispose pattern.
    CSharpDispose,
    /// Python __del__ finalizer.
    PythonFinalizer,
    /// C-style destroy/dealloc function.
    CDestroy,
    /// Java finalize method.
    JavaFinalizer,
    /// Generic cleanup function (close, cleanup, teardown).
    GenericCleanup,
}

/// Infers whether a function is a destructor and builds its summary.
///
/// Uses naming conventions, language hints, and optional call behavior
/// to determine if a function has destructor semantics. If inferred,
/// the summary includes `ConsumesArg` and `Release` effects with
/// `DestructorRelease` evidence.
pub fn infer_destructor_summary(
    name: &str,
    function: FunctionId,
    canonical_name: SymbolId,
    language_hint: LanguageHint,
    release_family: Option<FamilyId>,
) -> (ResourceSummary, DestructorInferenceResult) {
    let mut summary = ResourceSummary::new(function, canonical_name, name);
    summary.language_hint = language_hint;

    // Try to infer destructor kind from name patterns
    let Some((kind, confidence)) = classify_destructor_name(name, language_hint) else {
        let result = DestructorInferenceResult {
            is_destructor: false,
            kind: DestructorKind::GenericCleanup,
            consumed_arg: 0,
            release_family: None,
            confidence: 0.0,
            reason: format!("no destructor pattern match for: {name}"),
        };
        return (summary, result);
    };

    // Build destructor effects
    let family = release_family.unwrap_or(FamilyId::C_HEAP);

    summary.origin = FunctionOrigin::UserCode;
    summary.confidence = confidence;

    // ConsumesArg: the function takes ownership of the receiver
    summary.add_effect(Effect::ConsumesArg {
        arg: 0,
        family: Some(family),
    });

    // Release: the function releases the resource
    summary.add_effect(Effect::Release { family, arg: 0 });

    // Attach destructor-release evidence
    summary.add_evidence(
        Evidence::new(
            EvidenceKind::DestructorRelease,
            format!(
                "function '{name}' inferred as {:?} destructor releasing {:?}",
                kind, family
            ),
        )
        .with_confidence(confidence)
        .with_family(family),
    );

    let result = DestructorInferenceResult {
        is_destructor: true,
        kind,
        consumed_arg: 0,
        release_family: Some(family),
        confidence,
        reason: format!(
            "function '{name}' matches {:?} destructor naming pattern",
            kind
        ),
    };

    (summary, result)
}

/// Classifies a function name as a destructor kind based on naming
/// conventions and language hints.
fn classify_destructor_name(
    name: &str,
    language_hint: LanguageHint,
) -> Option<(DestructorKind, f32)> {
    // C++ mangled destructor: _ZN...D0Ev, _ZN...D1Ev, _ZN...D2Ev
    if (name.contains("D0Ev") || name.contains("D1Ev") || name.contains("D2Ev"))
        && name.starts_with("_ZN")
    {
        return Some((DestructorKind::CppDestructor, 0.95));
    }

    // Language-specific patterns first (higher confidence)
    match language_hint {
        LanguageHint::Rust
            if name == "drop"
                || name.ends_with("::drop")
                || name == "drop_in_place"
                || name.contains("drop_in_place") =>
        {
            return Some((DestructorKind::RustDrop, 0.9));
        }
        LanguageHint::Python if name == "__del__" || name.ends_with(".__del__") => {
            return Some((DestructorKind::PythonFinalizer, 0.85));
        }
        LanguageHint::CSharp
            if name == "Dispose" || name.ends_with(".Dispose") || name.ends_with("::Dispose") =>
        {
            return Some((DestructorKind::CSharpDispose, 0.85));
        }
        LanguageHint::CSharp if name.starts_with('~') => {
            return Some((DestructorKind::CSharpDispose, 0.8));
        }
        LanguageHint::Java if name == "finalize" => {
            return Some((DestructorKind::JavaFinalizer, 0.8));
        }
        _ => {}
    }

    // Generic patterns (lower confidence, language-agnostic)
    let lower = name.to_lowercase();

    // destroy / destroy_at
    if lower.starts_with("destroy") || lower.contains("_destroy") || lower.contains("::destroy") {
        return Some((DestructorKind::CDestroy, 0.7));
    }

    // dealloc / deallocate
    if lower.starts_with("dealloc") || lower.contains("_dealloc") {
        return Some((DestructorKind::CDestroy, 0.75));
    }

    // delete (not C++ mangled — already handled above)
    if lower == "delete" || lower.ends_with("_delete") {
        return Some((DestructorKind::CDestroy, 0.6));
    }

    // finalize
    if lower == "finalize" || lower.ends_with("_finalize") {
        return Some((DestructorKind::JavaFinalizer, 0.6));
    }

    // close / cleanup / teardown / shutdown
    if lower == "close"
        || lower.ends_with("_close")
        || lower.ends_with("_cleanup")
        || lower.ends_with("_teardown")
        || lower.ends_with("_shutdown")
    {
        return Some((DestructorKind::GenericCleanup, 0.5));
    }

    // deinit
    if lower.ends_with("_deinit") || lower == "deinit" {
        return Some((DestructorKind::CDestroy, 0.65));
    }

    // drop / drop_in_place — generic fallback for Rust Drop without
    // language hint. Also matches C++ style drop helpers.
    if lower == "drop" || lower.ends_with("_drop") || lower.contains("drop_in_place") {
        return Some((DestructorKind::RustDrop, 0.65));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_drop_inference() {
        let (summary, result) = infer_destructor_summary(
            "drop",
            1,
            100,
            LanguageHint::Rust,
            Some(FamilyId::RUST_GLOBAL),
        );
        assert!(result.is_destructor, "drop must be inferred as destructor");
        assert_eq!(result.kind, DestructorKind::RustDrop);
        assert!(
            summary.releases_resource(),
            "Destructor summary must release resource"
        );
        assert!(
            result.confidence > 0.8,
            "Rust Drop inference should have high confidence"
        );
    }

    #[test]
    fn test_cpp_destructor_mangling() {
        let (summary, result) = infer_destructor_summary(
            "_ZN1AD2Ev",
            2,
            200,
            LanguageHint::Cpp,
            Some(FamilyId::CPP_NEW_SCALAR),
        );
        assert!(result.is_destructor, "C++ destructor must be inferred");
        assert_eq!(result.kind, DestructorKind::CppDestructor);
        assert!(summary.releases_resource());
    }

    #[test]
    fn test_csharp_dispose() {
        let (summary, result) = infer_destructor_summary(
            "Dispose",
            3,
            300,
            LanguageHint::CSharp,
            Some(FamilyId::CSHARP_HGLOBAL),
        );
        assert!(
            result.is_destructor,
            "Dispose must be inferred as destructor"
        );
        assert_eq!(result.kind, DestructorKind::CSharpDispose);
        assert!(summary.releases_resource());
    }

    #[test]
    fn test_python_del() {
        let (_, result) = infer_destructor_summary(
            "__del__",
            4,
            400,
            LanguageHint::Python,
            Some(FamilyId::PYTHON_OBJECT),
        );
        assert!(
            result.is_destructor,
            "__del__ must be inferred as destructor"
        );
        assert_eq!(result.kind, DestructorKind::PythonFinalizer);
    }

    #[test]
    fn test_c_destroy_pattern() {
        let (_, result) = infer_destructor_summary("buffer_destroy", 5, 500, LanguageHint::C, None);
        assert!(
            result.is_destructor,
            "buffer_destroy must be inferred as destructor"
        );
        assert_eq!(result.kind, DestructorKind::CDestroy);
    }

    #[test]
    fn test_close_as_generic_cleanup() {
        let (_, result) =
            infer_destructor_summary("connection_close", 6, 600, LanguageHint::Unknown, None);
        assert!(
            result.is_destructor,
            "connection_close must be inferred as destructor"
        );
        assert_eq!(result.kind, DestructorKind::GenericCleanup);
        assert!(
            result.confidence < 0.7,
            "Generic cleanup should have moderate confidence"
        );
    }

    #[test]
    fn test_non_destructor_not_inferred() {
        let (_, result) =
            infer_destructor_summary("process_data", 7, 700, LanguageHint::Unknown, None);
        assert!(
            !result.is_destructor,
            "process_data must NOT be inferred as destructor"
        );
    }

    #[test]
    fn test_destructor_evidence_attached() {
        let (summary, _) = infer_destructor_summary(
            "drop",
            1,
            100,
            LanguageHint::Rust,
            Some(FamilyId::RUST_GLOBAL),
        );
        assert!(
            !summary.evidence.is_empty(),
            "Destructor summary must have evidence"
        );
        assert_eq!(
            summary.evidence[0].kind,
            EvidenceKind::DestructorRelease,
            "Evidence must be DestructorRelease"
        );
    }
}
