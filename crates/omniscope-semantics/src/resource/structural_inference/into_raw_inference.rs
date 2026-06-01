//! Ownership transfer via into_raw inference for structural analysis (R-6).
//!
//! Infers that `Box::into_raw`, `CString::into_raw`, and `Vec::into_raw`
//! return a raw pointer with ownership transferred to the caller.
//! Subsequent C `free()` on this pointer is by-design, NOT a cross_language_free.
//!
//! # Key Insight (R-6)
//!
//! Rust's `into_raw()` methods consume self and return a raw pointer.
//! The caller is now responsible for the memory. In FFI patterns, the
//! C side typically calls `free()` — this is intentional ownership
//! transfer, not a cross-family mismatch.
//!
//! Evidence: `rust_ffi_bugs.ll` — `Box::into_raw` + C `free()` pattern.
//! Evidence: `bun_*.bc` — multiple into_raw + free patterns.

use omniscope_types::{
    Effect, Evidence, EvidenceKind, FamilyId, FunctionId, FunctionOrigin, LanguageHint, SymbolId,
};

use crate::resource::summary::ResourceSummary;

/// Result of into_raw ownership transfer inference.
#[derive(Debug, Clone)]
pub struct IntoRawInferenceResult {
    /// Whether this function was inferred as into_raw transfer.
    pub is_into_raw: bool,
    /// The kind of into_raw function inferred.
    pub kind: IntoRawKind,
    /// The resource family that the pointer belongs to.
    pub family: FamilyId,
    /// The argument index consumed (self parameter).
    pub consumed_arg: u32,
    /// Confidence of the inference (0.0 - 1.0).
    pub confidence: f32,
    /// Reason for the inference.
    pub reason: String,
}

/// Kind of into_raw function inferred from naming patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntoRawKind {
    /// Box::into_raw — heap pointer, C free() is legal.
    BoxIntoRaw,
    /// CString::into_raw — heap pointer to C string, C free() is legal.
    CStringIntoRaw,
    /// Vec::into_raw — heap pointer to buffer, C free() is legal.
    VecIntoRaw,
    /// ManuallyDrop::into_raw — explicit ownership extraction.
    ManuallyDropIntoRaw,
    /// Generic into_raw pattern.
    GenericIntoRaw,
}

/// Infers whether a function is an into_raw transfer and builds its summary.
///
/// into_raw functions transfer ownership to the caller. The returned
/// pointer is NOT a borrowed reference — it's an owned pointer that
/// the caller must eventually free. This is the key distinction from
/// bridge_inference's ReturnsBorrowed.
pub fn infer_into_raw_summary(
    name: &str,
    function: FunctionId,
    canonical_name: SymbolId,
    language_hint: LanguageHint,
) -> (ResourceSummary, IntoRawInferenceResult) {
    let mut summary = ResourceSummary::new(function, canonical_name, name);
    summary.language_hint = language_hint;

    let Some((kind, family, confidence)) = classify_into_raw_name(name, language_hint) else {
        let result = IntoRawInferenceResult {
            is_into_raw: false,
            kind: IntoRawKind::GenericIntoRaw,
            family: FamilyId::C_HEAP,
            consumed_arg: 0,
            confidence: 0.0,
            reason: format!("no into_raw pattern match for: {name}"),
        };
        return (summary, result);
    };

    summary.origin = FunctionOrigin::UserCode;
    summary.confidence = confidence;

    // The function escapes ownership to a raw pointer (into_raw transfer).
    // This is NOT a normal ReturnsOwned — the pointer leaves Rust's type system.
    summary.add_effect(Effect::OwnershipEscape {
        family: FamilyId::RUST_RAW_OWNERSHIP,
        result: 0,
    });

    // The function consumes its self argument
    summary.add_effect(Effect::ConsumesArg {
        arg: 0,
        family: Some(family),
    });

    // Attach ownership-transfer evidence
    summary.add_evidence(
        Evidence::new(
            EvidenceKind::OwnershipTransfer,
            format!(
                "function '{name}' inferred as {:?} — ownership transferred to caller, \
                 C free() is legal",
                kind
            ),
        )
        .with_confidence(confidence),
    );

    let result = IntoRawInferenceResult {
        is_into_raw: true,
        kind,
        family,
        consumed_arg: 0,
        confidence,
        reason: format!(
            "function '{name}' matches {:?} into_raw naming pattern",
            kind
        ),
    };

    (summary, result)
}

/// Classifies a function name as into_raw kind based on naming conventions.
fn classify_into_raw_name(
    name: &str,
    language_hint: LanguageHint,
) -> Option<(IntoRawKind, FamilyId, f32)> {
    // Only Rust has into_raw patterns (C/C++/Go don't have this idiom)
    if language_hint != LanguageHint::Rust && language_hint != LanguageHint::Unknown {
        return None;
    }

    // Rust v0 mangled names contain length-prefixed segments:
    // _RNvXs...NtC...4alloc5boxed8Box<T>8into_raw
    // The "8into_raw" segment is the key identifier (8 = strlen("into_raw"))
    if name.contains("8into_raw") || name.contains("into_raw") {
        // Distinguish Box vs CString vs Vec vs ManuallyDrop
        if name.contains("3box") || name.contains("4Box") || name.contains("boxed") {
            return Some((IntoRawKind::BoxIntoRaw, FamilyId::RUST_GLOBAL, 0.95));
        }
        if name.contains("6CString") || name.contains("6string") || name.contains("7cstring") {
            return Some((IntoRawKind::CStringIntoRaw, FamilyId::RUST_GLOBAL, 0.95));
        }
        if name.contains("3Vec") || name.contains("3vec") {
            return Some((IntoRawKind::VecIntoRaw, FamilyId::RUST_GLOBAL, 0.95));
        }
        if name.contains("12ManuallyDrop") || name.contains("13manually_drop") {
            return Some((
                IntoRawKind::ManuallyDropIntoRaw,
                FamilyId::RUST_GLOBAL,
                0.90,
            ));
        }
        // Generic into_raw — lower confidence
        return Some((IntoRawKind::GenericIntoRaw, FamilyId::RUST_GLOBAL, 0.80));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_box_into_raw() {
        let (summary, result) = infer_into_raw_summary(
            "_RNvXs_NtC...4alloc5boxed8Box3i328into_raw",
            1,
            100,
            LanguageHint::Rust,
        );
        assert!(result.is_into_raw, "Box::into_raw must be inferred");
        assert_eq!(
            result.kind,
            IntoRawKind::BoxIntoRaw,
            "Expected values to be equal"
        );
        assert!(
            summary.is_ownership_transfer(),
            "Summary must be classified as ownership transfer"
        );
    }

    #[test]
    fn test_cstring_into_raw() {
        let (_, result) = infer_into_raw_summary(
            "_RNvXs_3std3ffi6CString8into_raw",
            2,
            200,
            LanguageHint::Rust,
        );
        assert!(result.is_into_raw, "CString::into_raw must be inferred");
        assert_eq!(
            result.kind,
            IntoRawKind::CStringIntoRaw,
            "Expected values to be equal"
        );
    }

    #[test]
    fn test_vec_into_raw() {
        let (_, result) =
            infer_into_raw_summary("_RNvXs_5alloc3vec3Vec8into_raw", 3, 300, LanguageHint::Rust);
        assert!(result.is_into_raw, "Vec::into_raw must be inferred");
        assert_eq!(
            result.kind,
            IntoRawKind::VecIntoRaw,
            "Expected values to be equal"
        );
    }

    #[test]
    fn test_non_into_raw_not_inferred() {
        let (_, result) = infer_into_raw_summary("as_ptr", 4, 400, LanguageHint::Rust);
        assert!(
            !result.is_into_raw,
            "as_ptr must NOT be inferred as into_raw"
        );
    }

    #[test]
    fn test_c_function_no_into_raw() {
        let (_, result) = infer_into_raw_summary("malloc", 5, 500, LanguageHint::C);
        assert!(
            !result.is_into_raw,
            "C functions must not be inferred as into_raw"
        );
    }
}
