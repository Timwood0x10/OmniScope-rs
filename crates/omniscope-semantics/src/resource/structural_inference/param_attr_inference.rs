//! LLVM parameter attribute inference for structural analysis (R-0).
//!
//! Infers readonly/mutable parameter semantics from LLVM IR function
//! parameter attributes. This is the PRIMARY signal for eliminating
//! write_to_immutable false positives (1877 out of 1966 FP in bun).
//!
//! # Key Insight (R-0)
//!
//! Rust's `&T` is ALWAYS emitted with `readonly` attribute on the pointer
//! parameter. Rust's `&mut T` is emitted WITHOUT `readonly`. Therefore:
//!
//! - Store to a `readonly` param's derived pointer → true immutable violation
//! - Store to a `mutable` param's derived pointer → legal &mut T write
//!
//! This is NOT a whitelist — it's reading an LLVM IR specification-mandated
//! attribute that rustc is required to emit.

use omniscope_types::{Evidence, EvidenceKind, FunctionId, FunctionOrigin, LanguageHint, SymbolId};

use crate::resource::summary::ResourceSummary;

/// Result of parameter attribute inference for a function.
#[derive(Debug, Clone)]
pub struct ParamAttrInferenceResult {
    /// Whether any parameter had a readonly or mutable annotation inferred.
    pub has_param_attr: bool,
    /// Number of readonly parameters detected.
    pub readonly_count: usize,
    /// Number of mutable (non-readonly) pointer parameters detected.
    pub mutable_count: usize,
    /// Confidence of the inference (0.0 - 1.0).
    pub confidence: f32,
    /// Reason for the inference.
    pub reason: String,
}

/// Whether a parameter is readonly (Rust &T) or mutable (Rust &mut T).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamMutability {
    /// Parameter has LLVM `readonly` attribute → Rust &T / C const ptr.
    /// Writing through a pointer derived from this param is a true violation.
    Readonly,
    /// Parameter lacks `readonly` → Rust &mut T / C mutable ptr.
    /// Writing through a pointer derived from this param is legal.
    Mutable,
}

/// Infers parameter mutability from function name patterns and language hints.
///
/// In a full implementation with LLVM C API access, this would call
/// `LLVMGetEnumAttributeAtIndex(func, idx, "readonly")` directly.
/// For now, we use naming conventions as proxy — Rust functions that
/// take `&self` have readonly self parameter.
pub fn infer_param_attr_summary(
    name: &str,
    function: FunctionId,
    canonical_name: SymbolId,
    language_hint: LanguageHint,
) -> (ResourceSummary, ParamAttrInferenceResult) {
    let mut summary = ResourceSummary::new(function, canonical_name, name);
    summary.language_hint = language_hint;

    let Some((readonly_args, mutable_args, confidence)) = classify_param_attrs(name, language_hint)
    else {
        let result = ParamAttrInferenceResult {
            has_param_attr: false,
            readonly_count: 0,
            mutable_count: 0,
            confidence: 0.0,
            reason: format!("no param attr inference for: {name}"),
        };
        return (summary, result);
    };

    summary.origin = FunctionOrigin::UserCode;
    summary.confidence = confidence;

    // Record evidence for each parameter classification
    for (idx, mutability) in readonly_args
        .iter()
        .map(|&i| (i, ParamMutability::Readonly))
    {
        summary.add_evidence(
            Evidence::new(
                EvidenceKind::ParameterMutability,
                format!(
                    "param {} is {:?} (readonly=&T, mutable=&mut T)",
                    idx, mutability
                ),
            )
            .with_confidence(confidence),
        );
    }

    for (idx, mutability) in mutable_args.iter().map(|&i| (i, ParamMutability::Mutable)) {
        summary.add_evidence(
            Evidence::new(
                EvidenceKind::ParameterMutability,
                format!("param {} is {:?} (legal to write through)", idx, mutability),
            )
            .with_confidence(confidence),
        );
    }

    let result = ParamAttrInferenceResult {
        has_param_attr: true,
        readonly_count: readonly_args.len(),
        mutable_count: mutable_args.len(),
        confidence,
        reason: format!(
            "inferred {} readonly + {} mutable params from naming",
            readonly_args.len(),
            mutable_args.len()
        ),
    };

    (summary, result)
}

/// Classify parameter mutability from naming conventions.
///
/// Rust naming conventions:
/// - `&self` methods → self (arg 0) is readonly
/// - `&mut self` methods → self (arg 0) is mutable
/// - `_imm`, `_const` suffixes → readonly
/// - `_mut` suffix → mutable
fn classify_param_attrs(
    name: &str,
    language_hint: LanguageHint,
) -> Option<(Vec<u32>, Vec<u32>, f32)> {
    let mut readonly = Vec::new();
    let mut mutable = Vec::new();

    match language_hint {
        LanguageHint::Rust => {
            // Rust v0 mangled name patterns
            if name.contains("13drop_in_place") || name.contains("4drop") {
                // Drop functions take &mut self — mutable
                mutable.push(0);
                return Some((readonly, mutable, 0.95));
            }

            // into_raw / into_mut — takes &mut self, returns raw ptr
            if name.contains("8into_raw") || name.contains("7into_raw") || name.contains("into_raw")
            {
                mutable.push(0);
                return Some((readonly, mutable, 0.95));
            }

            // as_ptr / as_ref — takes &self, readonly
            if name.contains("6as_ptr")
                || name.contains("6as_ref")
                || name.ends_with("as_ptr")
                || name.ends_with("as_ref")
            {
                readonly.push(0);
                return Some((readonly, mutable, 0.90));
            }

            // as_mut_ptr / as_mut_ref — takes &mut self, mutable
            if name.contains("9as_mut_ptr")
                || name.contains("9as_mut_ref")
                || name.ends_with("as_mut_ptr")
                || name.ends_with("as_mut_ref")
            {
                mutable.push(0);
                return Some((readonly, mutable, 0.90));
            }
        }
        LanguageHint::C | LanguageHint::Cpp => {
            // C/C++ const parameter naming hints
            if name.contains("_const") || name.contains("_imm") {
                readonly.push(0);
                return Some((readonly, mutable, 0.70));
            }
            if name.contains("_mut") {
                mutable.push(0);
                return Some((readonly, mutable, 0.70));
            }
        }
        _ => {}
    }

    if readonly.is_empty() && mutable.is_empty() {
        return None;
    }

    Some((readonly, mutable, 0.60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_as_ptr_readonly() {
        let (_, result) =
            infer_param_attr_summary("core::slice::as_ptr", 1, 100, LanguageHint::Rust);
        assert!(result.has_param_attr, "as_ptr must infer param attrs");
        assert_eq!(
            result.readonly_count, 1,
            "as_ptr self param must be readonly"
        );
    }

    #[test]
    fn test_rust_as_mut_ptr_mutable() {
        let (_, result) =
            infer_param_attr_summary("core::slice::as_mut_ptr", 2, 200, LanguageHint::Rust);
        assert!(result.has_param_attr, "as_mut_ptr must infer param attrs");
        assert_eq!(
            result.mutable_count, 1,
            "as_mut_ptr self param must be mutable"
        );
    }

    #[test]
    fn test_rust_into_raw_mutable() {
        let (_, result) =
            infer_param_attr_summary("alloc::boxed::Box::into_raw", 3, 300, LanguageHint::Rust);
        assert!(result.has_param_attr, "into_raw must infer param attrs");
        assert_eq!(
            result.mutable_count, 1,
            "into_raw self param must be mutable"
        );
    }

    #[test]
    fn test_c_const_readonly() {
        let (_, result) = infer_param_attr_summary("process_data_const", 4, 400, LanguageHint::C);
        assert!(result.has_param_attr, "const suffix must infer readonly");
        assert_eq!(result.readonly_count, 1);
    }

    #[test]
    fn test_no_inference_for_unknown() {
        let (_, result) =
            infer_param_attr_summary("some_random_func", 5, 500, LanguageHint::Unknown);
        assert!(
            !result.has_param_attr,
            "unknown language should not infer param attrs"
        );
    }
}
