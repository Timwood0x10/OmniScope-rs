//! Reference-count conditional-release inference for structural analysis.
//!
//! Infers conditional release when a function has refcount decrement
//! semantics. These functions only release when the reference count
//! drops to zero. DO NOT model them as unconditional `Release`.
//!
//! Recognized refcount release patterns:
//! - Py_DECREF, Py_XDECREF (Python)
//! - Arc::drop (Rust)
//! - CFRelease (Core Foundation)
//! - IUnknown::Release (COM)
//! - objc_release (Objective-C)
//!
//! Generated effect:
//! ```text
//! ConditionalRelease + refcount-conditional evidence
//! ```

use omniscope_types::{
    Effect, Evidence, EvidenceKind, FamilyId, FunctionId, FunctionOrigin, LanguageHint, SymbolId,
};

use crate::resource::summary::ResourceSummary;

/// Result of refcount inference for a function.
#[derive(Debug, Clone)]
pub struct RefcountInferenceResult {
    /// Whether this function was inferred as a refcount release.
    pub is_refcount_release: bool,
    /// The kind of refcount mechanism inferred.
    pub kind: RefcountKind,
    /// The resource family involved.
    pub family: FamilyId,
    /// The argument index being conditionally released.
    pub arg: u32,
    /// Confidence of the inference (0.0 - 1.0).
    pub confidence: f32,
    /// Reason for the inference.
    pub reason: String,
}

/// Kind of reference-counting mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefcountKind {
    /// Python INCREF/DECREF — PyObject refcount.
    PythonRefcount,
    /// Rust Arc<T> / Rc<T> — atomic/non-atomic refcount.
    RustArc,
    /// Core Foundation CFRelease / CFRetain.
    CoreFoundation,
    /// COM IUnknown::AddRef / IUnknown::Release.
    ComRefCount,
    /// Objective-C objc_retain / objc_release.
    ObjcArc,
    /// Generic refcount — unknown mechanism.
    Generic,
}

/// Infers whether a function has refcount conditional-release semantics
/// and builds its summary.
///
/// Refcount decrement functions are modeled as `ConditionalRelease`,
/// NOT as unconditional `Release`. This distinction is critical:
/// `Py_DECREF` only frees the object when its refcount reaches zero,
/// so it must not trigger a double-free report when the object has
/// other references.
pub fn infer_refcount_release_summary(
    name: &str,
    function: FunctionId,
    canonical_name: SymbolId,
    language_hint: LanguageHint,
) -> (ResourceSummary, RefcountInferenceResult) {
    let mut summary = ResourceSummary::new(function, canonical_name, name);
    summary.language_hint = language_hint;

    let Some((kind, family, confidence)) = classify_refcount_name(name, language_hint) else {
        let result = RefcountInferenceResult {
            is_refcount_release: false,
            kind: RefcountKind::Generic,
            family: FamilyId::C_HEAP,
            arg: 0,
            confidence: 0.0,
            reason: format!("no refcount pattern match for: {name}"),
        };
        return (summary, result);
    };

    summary.origin = FunctionOrigin::Stdlib;
    summary.confidence = confidence;

    // ConditionalRelease: the function conditionally releases when
    // refcount drops to zero.
    summary.add_effect(Effect::ConditionalRelease { family, arg: 0 });

    // Attach refcount-conditional evidence
    summary.add_evidence(
        Evidence::new(
            EvidenceKind::RefcountConditional,
            format!(
                "function '{name}' inferred as {:?} conditional release for {:?}",
                kind, family
            ),
        )
        .with_confidence(confidence)
        .with_family(family),
    );

    let result = RefcountInferenceResult {
        is_refcount_release: true,
        kind,
        family,
        arg: 0,
        confidence,
        reason: format!(
            "function '{name}' matches {:?} refcount conditional release pattern",
            kind
        ),
    };

    (summary, result)
}

/// Classifies a function name as a refcount release kind.
fn classify_refcount_name(
    name: &str,
    language_hint: LanguageHint,
) -> Option<(RefcountKind, FamilyId, f32)> {
    // Language-specific patterns (highest confidence)
    match language_hint {
        LanguageHint::Python => {
            // Py_DECREF / Py_XDECREF are already in the registry,
            // but this handles wrapper/decorator variants.
            if name == "Py_DECREF" || name == "Py_XDECREF" {
                return Some((RefcountKind::PythonRefcount, FamilyId::PYTHON_OBJECT, 0.95));
            }
            // Py_CLEAR — safe decref that also sets the pointer to NULL
            if name == "Py_CLEAR" {
                return Some((RefcountKind::PythonRefcount, FamilyId::PYTHON_OBJECT, 0.9));
            }
            // Py_XDECREF variant with different naming
            if name.contains("DECREF") || name.contains("XDECREF") {
                return Some((RefcountKind::PythonRefcount, FamilyId::PYTHON_OBJECT, 0.85));
            }
        }
        LanguageHint::Rust
            if name.contains("Arc::drop") || name.contains("drop_in_place") || name == "drop" =>
        {
            // Rust Arc uses the global allocator for the inner value
            // when refcount hits zero, but the Arc itself is managed
            // by Rust's allocator.
            return Some((RefcountKind::RustArc, FamilyId::RUST_GLOBAL, 0.85));
        }
        LanguageHint::CSharp if name == "Release" || name.ends_with("::Release") => {
            // COM IUnknown::Release
            return Some((RefcountKind::ComRefCount, FamilyId::CSHARP_COTASK, 0.8));
        }
        _ => {}
    }

    // Generic patterns (lower confidence)
    let lower = name.to_lowercase();

    // Core Foundation CFRelease / objc_release
    if lower.starts_with("cfrelease") || lower == "cfrelease" {
        return Some((RefcountKind::CoreFoundation, FamilyId::C_HEAP, 0.85));
    }

    if lower.contains("objc_release") || lower == "objc_release" {
        return Some((RefcountKind::ObjcArc, FamilyId::C_HEAP, 0.8));
    }

    // Generic release / decref patterns
    // Exclude non-refcount release operations: semaphore_release, lock_release,
    // thread_release, sem_release, etc. These are synchronization primitives,
    // not reference counting operations.
    if lower.ends_with("_release") && !lower.contains("unconditional") {
        let non_refcount_release = [
            "semaphore",
            "lock",
            "mutex",
            "thread",
            "sem_",
            "spinlock",
            "rwlock",
            "condvar",
            "fence",
        ];
        let is_sync_release = non_refcount_release
            .iter()
            .any(|prefix| lower.contains(prefix));
        if !is_sync_release {
            return Some((RefcountKind::Generic, FamilyId::C_HEAP, 0.5));
        }
    }

    if lower.ends_with("_decref") || lower.contains("_decref") {
        return Some((RefcountKind::Generic, FamilyId::C_HEAP, 0.6));
    }

    // refcount_down / rc_dec
    if lower.ends_with("_refcount_dec") || lower.ends_with("_rc_dec") {
        return Some((RefcountKind::Generic, FamilyId::C_HEAP, 0.55));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_py_decref_conditional_release() {
        let (summary, result) =
            infer_refcount_release_summary("Py_DECREF", 1, 100, LanguageHint::Python);
        assert!(
            result.is_refcount_release,
            "Py_DECREF must be inferred as refcount release"
        );
        assert_eq!(result.kind, RefcountKind::PythonRefcount);
        assert_eq!(result.family, FamilyId::PYTHON_OBJECT);
        assert!(
            summary.releases_resource(),
            "Py_DECREF summary must release resource"
        );
        assert!(
            result.confidence > 0.9,
            "Registry-symbol match should have high confidence"
        );
    }

    #[test]
    fn test_py_xdecref_conditional_release() {
        let (summary, result) =
            infer_refcount_release_summary("Py_XDECREF", 2, 200, LanguageHint::Python);
        assert!(result.is_refcount_release);
        assert_eq!(result.kind, RefcountKind::PythonRefcount);
        assert!(summary.releases_resource());
    }

    #[test]
    fn test_py_clear_conditional_release() {
        let (_, result) = infer_refcount_release_summary("Py_CLEAR", 3, 300, LanguageHint::Python);
        assert!(
            result.is_refcount_release,
            "Py_CLEAR must be inferred as refcount release"
        );
    }

    #[test]
    fn test_arc_drop_conditional_release() {
        let (summary, result) =
            infer_refcount_release_summary("Arc::drop", 4, 400, LanguageHint::Rust);
        assert!(
            result.is_refcount_release,
            "Arc::drop must be inferred as refcount release"
        );
        assert_eq!(result.kind, RefcountKind::RustArc);
        assert!(summary.releases_resource());
    }

    #[test]
    fn test_cfrelease_conditional_release() {
        let (_, result) = infer_refcount_release_summary("CFRelease", 5, 500, LanguageHint::C);
        assert!(
            result.is_refcount_release,
            "CFRelease must be inferred as refcount release"
        );
        assert_eq!(result.kind, RefcountKind::CoreFoundation);
    }

    #[test]
    fn test_com_release() {
        let (_, result) = infer_refcount_release_summary("Release", 6, 600, LanguageHint::CSharp);
        assert!(
            result.is_refcount_release,
            "COM Release must be inferred as refcount release"
        );
        assert_eq!(result.kind, RefcountKind::ComRefCount);
    }

    #[test]
    fn test_objc_release() {
        let (_, result) =
            infer_refcount_release_summary("objc_release", 7, 700, LanguageHint::Unknown);
        assert!(
            result.is_refcount_release,
            "objc_release must be inferred as refcount release"
        );
        assert_eq!(result.kind, RefcountKind::ObjcArc);
    }

    #[test]
    fn test_generic_decref_pattern() {
        let (_, result) =
            infer_refcount_release_summary("ref_decref", 8, 800, LanguageHint::Unknown);
        assert!(
            result.is_refcount_release,
            "ref_decref must be inferred as refcount release"
        );
        assert_eq!(result.kind, RefcountKind::Generic);
        assert!(
            result.confidence < 0.7,
            "Generic pattern should have moderate confidence"
        );
    }

    #[test]
    fn test_non_refcount_not_inferred() {
        let (_, result) = infer_refcount_release_summary("free", 9, 900, LanguageHint::C);
        assert!(
            !result.is_refcount_release,
            "free must NOT be inferred as refcount release — it is unconditional"
        );
    }

    #[test]
    fn test_refcount_evidence_attached() {
        let (summary, _) =
            infer_refcount_release_summary("Py_DECREF", 1, 100, LanguageHint::Python);
        assert!(
            !summary.evidence.is_empty(),
            "Refcount summary must have evidence"
        );
        assert_eq!(
            summary.evidence[0].kind,
            EvidenceKind::RefcountConditional,
            "Evidence must be RefcountConditional"
        );
    }
}
