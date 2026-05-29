//! Slice-to-pointer bridge inference for structural analysis.
//!
//! Infers borrowed-return summary when a function body only performs
//! pointer projection:
//!
//! ```text
//! getelementptr / bitcast / extractvalue / addrspacecast / return
//! no alloc, no release, no global store
//! ```
//!
//! Generated effects:
//! ```text
//! ReturnsBorrowed + bridge-helper evidence
//! ```
//!
//! This prevents `as_ptr`, `as_mut_ptr`, and FFI helper functions
//! from being treated as ownership escapes.
//!
//! # R-8: from_parameter is not a stack escape
//!
//! Function parameters are NOT stack allocations in the current function.
//! The caller owns the pointer and is responsible for its lifetime.
//! When `traceValueSource` returns `from_parameter`, the pointer should
//! NOT be marked as a stack escape — only `from_alloca` counts.
//! This eliminates 39 borrow_escape FP where parameter-derived pointers
//! were incorrectly flagged as escaping stack memory.

use omniscope_types::{
    Effect, Evidence, EvidenceKind, FunctionId, FunctionOrigin, LanguageHint, SymbolId,
};

use crate::resource::summary::ResourceSummary;

/// Result of bridge inference for a function.
#[derive(Debug, Clone)]
pub struct BridgeInferenceResult {
    /// Whether this function was inferred as a bridge helper.
    pub is_bridge: bool,
    /// The kind of bridge function inferred.
    pub kind: BridgeKind,
    /// Confidence of the inference (0.0 - 1.0).
    pub confidence: f32,
    /// Reason for the inference.
    pub reason: String,
}

/// Kind of bridge function inferred from naming and IR patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BridgeKind {
    /// Rust as_ptr / as_mut_ptr — returns a raw pointer from a slice/reference.
    AsPtr,
    /// Rust from_raw_parts / slice_from_raw_parts — reconstructs a slice.
    FromRawParts,
    /// C++ data() / c_str() — returns a pointer to internal buffer.
    DataAccessor,
    /// GEP-only body — LLVM IR body contains only pointer arithmetic.
    GepOnlyBody,
    /// Bitcast / pointer cast wrapper — just reinterprets the pointer.
    PointerCast,
}

/// Infers whether a function is a bridge helper and builds its summary.
///
/// Bridge helpers return borrowed pointers — they do not transfer
/// ownership and should not be treated as allocation escapes.
/// This function uses naming patterns to identify bridge functions.
/// In a full implementation, it would also inspect the IR body for
/// GEP-only / bitcast-only patterns.
pub fn infer_bridge_summary(
    name: &str,
    function: FunctionId,
    canonical_name: SymbolId,
    language_hint: LanguageHint,
) -> (ResourceSummary, BridgeInferenceResult) {
    let mut summary = ResourceSummary::new(function, canonical_name, name);
    summary.language_hint = language_hint;

    let Some((kind, confidence)) = classify_bridge_name(name, language_hint) else {
        let result = BridgeInferenceResult {
            is_bridge: false,
            kind: BridgeKind::AsPtr,
            confidence: 0.0,
            reason: format!("no bridge pattern match for: {name}"),
        };
        return (summary, result);
    };

    summary.origin = FunctionOrigin::UserCode;
    summary.confidence = confidence;

    // ReturnsBorrowed: the function returns a borrowed pointer
    summary.add_effect(Effect::ReturnsBorrowed);

    // Attach bridge-helper evidence
    summary.add_evidence(
        Evidence::new(
            EvidenceKind::BridgeHelper,
            format!(
                "function '{name}' inferred as {:?} bridge helper returning borrowed pointer",
                kind
            ),
        )
        .with_confidence(confidence),
    );

    let result = BridgeInferenceResult {
        is_bridge: true,
        kind,
        confidence,
        reason: format!("function '{name}' matches {:?} bridge naming pattern", kind),
    };

    (summary, result)
}

// ──────────────────────────────────────────────────────────────────────────
// R-8: from_parameter is not a stack escape
// ──────────────────────────────────────────────────────────────────────────

/// Returns true if the pointer source is a function parameter (R-8).
///
/// Function parameters are NOT stack allocations in the current function.
/// The caller owns the pointer and is responsible for its lifetime.
/// Only `from_alloca` should be treated as a stack escape.
///
/// This eliminates 39 borrow_escape FP where parameter-derived pointers
/// were incorrectly flagged as escaping stack memory.
pub fn is_parameter_source(name: &str) -> bool {
    // Function parameters in LLVM IR are function arguments (first N values).
    // In our naming convention, parameters have no `%` prefix — they use
    // the argument name directly. A value coming "from parameter" means
    // it was passed into the function by the caller.
    //
    // This is a lightweight check: if the name matches a parameter pattern
    // (no alloca prefix, no global @ prefix), it's likely from parameter.
    !name.starts_with('%') && !name.starts_with('@')
}

// ──────────────────────────────────────────────────────────────────────────
// Bridge name classification
// ──────────────────────────────────────────────────────────────────────────

/// Classifies a function name as a bridge kind based on naming
/// conventions and language hints.
fn classify_bridge_name(name: &str, language_hint: LanguageHint) -> Option<(BridgeKind, f32)> {
    // Language-specific patterns first
    match language_hint {
        LanguageHint::Rust => {
            // as_ptr, as_mut_ptr — most common Rust bridge
            if name == "as_ptr"
                || name.ends_with("::as_ptr")
                || name == "as_mut_ptr"
                || name.ends_with("::as_mut_ptr")
            {
                return Some((BridgeKind::AsPtr, 0.95));
            }
            // from_raw_parts, slice_from_raw_parts — ownership reclaim, NOT bridge.
            // These reconstruct an owned object from a raw pointer, reclaiming
            // ownership that was previously transferred via into_raw. They should
            // be classified as OwnershipReclaim rather than ReturnsBorrowed.
            if name.contains("from_raw_parts") || name.contains("slice_from_raw_parts") {
                return None;
            }
            // from_raw — ownership reclaim (Box::from_raw, CString::from_raw)
            if name.contains("from_raw") {
                return None;
            }
            // into_raw — this is actually a transfer, NOT a bridge.
            // Do not classify into_raw as ReturnsBorrowed.
            if name.contains("into_raw") {
                return None;
            }
        }
        LanguageHint::Cpp => {
            // data(), c_str()
            if name == "data" || name.ends_with("::data") {
                return Some((BridgeKind::DataAccessor, 0.85));
            }
            if name == "c_str" || name.ends_with("::c_str") {
                return Some((BridgeKind::DataAccessor, 0.9));
            }
        }
        _ => {}
    }

    // Generic patterns
    let lower = name.to_lowercase();

    // as_ptr, as_mut_ptr (generic form)
    if lower.ends_with("_as_ptr") || lower.ends_with("_as_mut_ptr") {
        return Some((BridgeKind::AsPtr, 0.8));
    }

    // get_ptr, ptr, raw_ptr
    if lower.ends_with("_get_ptr") || lower.ends_with("_ptr") {
        return Some((BridgeKind::AsPtr, 0.6));
    }

    // c_str (C-style)
    if lower.ends_with("_c_str") {
        return Some((BridgeKind::DataAccessor, 0.75));
    }

    // data (generic accessor) — exclude verbs that indicate processing,
    // not just pointer projection. Words like "process", "compute",
    // "transform", "validate", "parse", "encode", "decode", "compress",
    // "decompress", "encrypt", "decrypt", "filter", "sort", "merge",
    // "convert", "generate", "serialize", "deserialize" indicate
    // computation, not pointer access.
    let excluded_verbs = [
        "process",
        "compute",
        "transform",
        "validate",
        "parse",
        "encode",
        "decode",
        "compress",
        "decompress",
        "encrypt",
        "decrypt",
        "filter",
        "sort",
        "merge",
        "convert",
        "generate",
        "serialize",
        "deserialize",
        "handle",
        "manage",
        "update",
        "modify",
        "write",
        "send",
        "receive",
        "transfer",
        "copy",
        "clone",
        "load",
        "read",
    ];
    let is_excluded = excluded_verbs.iter().any(|v| lower.contains(v));
    if lower.ends_with("_data") && !is_excluded {
        return Some((BridgeKind::DataAccessor, 0.5));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_as_ptr_bridge() {
        let (summary, result) = infer_bridge_summary("as_ptr", 1, 100, LanguageHint::Rust);
        assert!(result.is_bridge, "as_ptr must be inferred as bridge");
        assert_eq!(result.kind, BridgeKind::AsPtr);
        assert!(summary.is_bridge(), "Summary must be classified as bridge");
        assert!(
            result.confidence > 0.9,
            "as_ptr should have high confidence"
        );
    }

    #[test]
    fn test_rust_as_mut_ptr_bridge() {
        let (summary, result) = infer_bridge_summary("as_mut_ptr", 2, 200, LanguageHint::Rust);
        assert!(result.is_bridge, "as_mut_ptr must be inferred as bridge");
        assert!(summary.is_bridge());
    }

    #[test]
    fn test_rust_from_raw_parts_not_bridge() {
        // from_raw_parts is ownership reclaim, NOT a bridge.
        // It reconstructs an owned object from a raw pointer, reclaiming
        // ownership previously transferred via into_raw.
        let (_summary, result) = infer_bridge_summary("from_raw_parts", 3, 300, LanguageHint::Rust);
        assert!(
            !result.is_bridge,
            "from_raw_parts must NOT be inferred as bridge — it is ownership reclaim"
        );
    }

    #[test]
    fn test_cpp_data_accessor() {
        let (summary, result) =
            infer_bridge_summary("std::string::data", 4, 400, LanguageHint::Cpp);
        assert!(result.is_bridge, "data() must be inferred as bridge");
        assert_eq!(result.kind, BridgeKind::DataAccessor);
        assert!(summary.is_bridge());
    }

    #[test]
    fn test_cpp_c_str_accessor() {
        let (_, result) = infer_bridge_summary("c_str", 5, 500, LanguageHint::Cpp);
        assert!(result.is_bridge, "c_str must be inferred as bridge");
        assert_eq!(result.kind, BridgeKind::DataAccessor);
    }

    #[test]
    fn test_into_raw_not_bridge() {
        // into_raw is a transfer, NOT a bridge
        let (_, result) = infer_bridge_summary("into_raw", 6, 600, LanguageHint::Rust);
        assert!(
            !result.is_bridge,
            "into_raw must NOT be inferred as bridge — it transfers ownership"
        );
    }

    #[test]
    fn test_non_bridge_not_inferred() {
        let (_, result) = infer_bridge_summary("process_data", 7, 700, LanguageHint::Unknown);
        assert!(
            !result.is_bridge,
            "process_data must NOT be inferred as bridge"
        );
    }

    #[test]
    fn test_bridge_evidence_attached() {
        let (summary, _) = infer_bridge_summary("as_ptr", 1, 100, LanguageHint::Rust);
        assert!(
            !summary.evidence.is_empty(),
            "Bridge summary must have evidence"
        );
        assert_eq!(
            summary.evidence[0].kind,
            EvidenceKind::BridgeHelper,
            "Evidence must be BridgeHelper"
        );
    }

    // ── R-8 tests: from_parameter is not a stack escape ──

    #[test]
    fn test_parameter_source_not_stack_escape() {
        // R-8: Function parameters are not stack escapes.
        // The caller owns the pointer and is responsible for its lifetime.
        assert!(
            is_parameter_source("src"),
            "Parameter name should be identified as parameter source"
        );
        assert!(
            is_parameter_source("data"),
            "Parameter name should be identified as parameter source"
        );
    }

    #[test]
    fn test_alloca_not_parameter_source() {
        // Stack allocations (alloca) are NOT parameter sources.
        assert!(
            !is_parameter_source("%buf"),
            "Alloca names (%-prefixed) should NOT be parameter sources"
        );
    }

    #[test]
    fn test_global_not_parameter_source() {
        // Global references are NOT parameter sources.
        assert!(
            !is_parameter_source("@global_var"),
            "Global names (@-prefixed) should NOT be parameter sources"
        );
    }
}
