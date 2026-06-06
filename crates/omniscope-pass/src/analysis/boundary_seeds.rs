//! Boundary seed classification and FFI slice expansion.
//!
//! This module implements the seed-based FFI boundary detection strategy:
//!
//! 1. **Seed Classification**: Each call site is classified as a Strong,
//!    Weak, or Suppression seed based on structural evidence.
//! 2. **FFI Slice Expansion**: From strong seeds, the slice is expanded
//!    backward (callers) and forward (callees) by 2 hops, including
//!    resource-pair closure and callback closure.
//! 3. **Metadata Attachment**: Functions/calls in the slice receive
//!    `FfiSliceInfo` with depth and relevance metadata.
//!
//! # Seed Rules
//!
//! **Strong seeds** (definite cross-language boundary):
//! - Known cross-language edge (both languages detected and different)
//! - User-configured boundary function
//! - Non-C language calling external unknown declaration
//! - C calling C++ Itanium symbol (excluding Rust `_ZN` mangling)
//! - Exported wrapper with pointer param/return
//! - Function pointer passed to/returned from external call
//! - Callback registration pattern
//!
//! **Weak seeds** (possible boundary, indirect evidence):
//! - Known FFI contract symbol from same language
//! - Dangerous libc/resource inside a wrapper
//! - Runtime bridge symbol connected to user boundary flow
//!
//! **Suppression seeds** (explicitly excluded):
//! - LLVM intrinsics
//! - Compiler/runtime glue with no user boundary path
//! - Pure libc helper with no ownership transfer
//! - Internal same-language call with no external/callback/exported ABI evidence

use omniscope_types::boundary::{
    BoundaryConfidence, BoundaryEvidence, FfiSliceInfo, SeedClassification,
};
use omniscope_types::config::Language;
use omniscope_types::evidence::BoundaryEvidenceKind;
use tracing::{debug, trace};

use super::ffi_boundary_detector::{is_runtime_intrinsic, FFIBoundaryDetector};

/// Maximum expansion depth from a strong seed (2 hops).
const MAX_EXPANSION_DEPTH: u32 = 2;

/// Result of classifying a single call site as a boundary seed.
#[derive(Debug, Clone)]
pub struct SeedResult {
    /// The seed classification (Strong, Weak, or Suppression).
    pub classification: SeedClassification,
    /// Evidence items supporting this classification.
    pub evidence: Vec<BoundaryEvidence>,
    /// FFI slice info for this call (seed gets depth=0, strong relevance).
    pub slice_info: FfiSliceInfo,
}

/// Classify a call site as a boundary seed.
///
/// This function examines a call's metadata and applies the seed rules
/// to determine whether the call is a Strong seed, Weak seed, or
/// Suppression seed.
///
/// # Arguments
/// * `caller` - Caller function name (trimmed, no `@` prefix).
/// * `callee` - Callee function name (trimmed, no `@` prefix).
/// * `caller_lang` - Detected caller language.
/// * `callee_lang` - Detected callee language.
/// * `is_external` - Whether the callee is an external declaration.
/// * `is_llvm_intrinsic` - Whether the callee is an LLVM intrinsic.
/// * `is_cpp_mangled` - Whether the callee has a C++ Itanium mangling (`_Z`).
/// * `is_cross_language` - Whether the call is cross-language.
/// * `has_pointer_param_or_return` - Whether the call involves pointer types.
/// * `is_callback_registration` - Whether the callee name matches a callback
///   registration pattern.
/// * `detector` - The FFI boundary detector for language queries.
/// * `is_configured_boundary` - Whether this call is in user-configured boundary.
/// * `is_runtime_bridge` - Whether the callee is a runtime bridge function.
/// * `is_dangerous_libc` - Whether the callee is a dangerous libc function.
/// * `is_exported_wrapper` - Whether the caller is an exported wrapper function.
/// * `is_function_pointer_ffi` - Whether a function pointer is passed to/returned
///   from an external call.
pub fn classify_seed(
    caller: &str,
    callee: &str,
    caller_lang: Language,
    callee_lang: Language,
    is_external: bool,
    is_llvm_intrinsic: bool,
    is_cpp_mangled: bool,
    is_cross_language: bool,
    has_pointer_param_or_return: bool,
    is_callback_registration: bool,
    _detector: &FFIBoundaryDetector,
    is_configured_boundary: bool,
    is_runtime_bridge: bool,
    is_dangerous_libc: bool,
    is_exported_wrapper: bool,
    is_function_pointer_ffi: bool,
) -> SeedResult {
    // ── Derive cross-language from caller/callee languages ──
    // If the caller/callee have different languages, treat as cross-language
    // even if the caller didn't set the flag (defensive).
    let effective_cross_language = is_cross_language
        || (caller_lang != callee_lang
            && caller_lang != Language::Unknown
            && callee_lang != Language::Unknown);

    // ── Suppression seeds: always checked first ──

    // LLVM intrinsics are never FFI boundaries
    if is_llvm_intrinsic {
        trace!(callee, "Suppressing LLVM intrinsic");
        return SeedResult {
            classification: SeedClassification::Suppression,
            evidence: vec![BoundaryEvidence::new(
                BoundaryEvidenceKind::RuntimeBridge,
                format!("LLVM intrinsic: {callee}"),
            )
            .with_confidence(BoundaryConfidence::None)],
            slice_info: FfiSliceInfo::outside(),
        };
    }

    // Compiler/runtime glue with no user boundary path
    if is_runtime_intrinsic(callee, callee_lang) && !is_configured_boundary {
        trace!(callee, "Suppressing runtime intrinsic");
        return SeedResult {
            classification: SeedClassification::Suppression,
            evidence: vec![BoundaryEvidence::new(
                BoundaryEvidenceKind::RuntimeBridge,
                format!("Runtime intrinsic with no user boundary path: {callee}"),
            )
            .with_confidence(BoundaryConfidence::None)],
            slice_info: FfiSliceInfo::outside(),
        };
    }

    // Pure libc helper with no ownership transfer
    if omniscope_types::call_graph_types::is_libc(callee)
        && !is_dangerous_libc
        && !has_pointer_param_or_return
    {
        trace!(callee, "Suppressing pure libc helper");
        return SeedResult {
            classification: SeedClassification::Suppression,
            evidence: vec![BoundaryEvidence::new(
                BoundaryEvidenceKind::RuntimeBridge,
                format!("Pure libc helper with no ownership transfer: {callee}"),
            )
            .with_confidence(BoundaryConfidence::None)],
            slice_info: FfiSliceInfo::outside(),
        };
    }

    // Internal same-language call with no external/callback/exported ABI evidence
    if !effective_cross_language
        && !is_external
        && !is_callback_registration
        && !is_exported_wrapper
        && !is_function_pointer_ffi
        && !is_configured_boundary
    {
        trace!(caller, callee, "Suppressing internal same-language call");
        return SeedResult {
            classification: SeedClassification::Suppression,
            evidence: vec![BoundaryEvidence::new(
                BoundaryEvidenceKind::RuntimeBridge,
                format!(
                    "Internal same-language call with no boundary evidence: {caller} -> {callee}"
                ),
            )
            .with_confidence(BoundaryConfidence::None)],
            slice_info: FfiSliceInfo::outside(),
        };
    }

    // ── Strong seeds ──

    let mut strong_evidence: Vec<BoundaryEvidence> = Vec::new();

    // 1. Known cross-language edge
    if effective_cross_language {
        strong_evidence.push(
            BoundaryEvidence::new(
                BoundaryEvidenceKind::CrossLanguageCall,
                format!(
                    "Cross-language call: {:?} -> {:?} ({caller} -> {callee})",
                    caller_lang, callee_lang
                ),
            )
            .with_caller_lang(caller_lang)
            .with_callee_lang(callee_lang)
            .with_confidence(BoundaryConfidence::Strong),
        );
    }

    // 2. User-configured boundary function
    if is_configured_boundary {
        strong_evidence.push(
            BoundaryEvidence::new(
                BoundaryEvidenceKind::ConfiguredBoundary,
                format!("User-configured boundary: {caller} -> {callee}"),
            )
            .with_caller_lang(caller_lang)
            .with_callee_lang(callee_lang)
            .with_confidence(BoundaryConfidence::Strong),
        );
    }

    // 3. Non-C language calling external unknown declaration
    if caller_lang != Language::Unknown
        && caller_lang != Language::C
        && callee_lang == Language::Unknown
        && is_external
    {
        strong_evidence.push(
            BoundaryEvidence::new(
                BoundaryEvidenceKind::ExternalAbiCall,
                format!(
                    "Non-C ({:?}) calling external unknown declaration: {callee}",
                    caller_lang
                ),
            )
            .with_caller_lang(caller_lang)
            .with_callee_lang(Language::C)
            .with_confidence(BoundaryConfidence::Strong),
        );
    }

    // 4. C calling C++ Itanium symbol (excluding Rust _ZN mangling)
    let is_cpp_ffi = is_cpp_mangled
        && caller_lang == Language::C
        && !omniscope_semantics::is_rust_zn_mangling(callee);
    if is_cpp_ffi {
        strong_evidence.push(
            BoundaryEvidence::new(
                BoundaryEvidenceKind::CrossLanguageCall,
                format!("C calling C++ Itanium symbol: {callee}"),
            )
            .with_caller_lang(caller_lang)
            .with_callee_lang(Language::Cpp)
            .with_confidence(BoundaryConfidence::Strong),
        );
    }

    // 5. Exported wrapper with pointer param/return
    if is_exported_wrapper && has_pointer_param_or_return {
        strong_evidence.push(
            BoundaryEvidence::new(
                BoundaryEvidenceKind::ExportedWrapper,
                format!("Exported wrapper with pointer param/return: {caller}"),
            )
            .with_caller_lang(caller_lang)
            .with_confidence(BoundaryConfidence::Strong),
        );
    }

    // 6. Function pointer passed to/returned from external call
    if is_function_pointer_ffi {
        strong_evidence.push(
            BoundaryEvidence::new(
                BoundaryEvidenceKind::FunctionPointerAbi,
                format!("Function pointer passed to/returned from external call: {callee}"),
            )
            .with_confidence(BoundaryConfidence::Strong),
        );
    }

    // 7. Callback registration pattern
    if is_callback_registration {
        strong_evidence.push(
            BoundaryEvidence::new(
                BoundaryEvidenceKind::CallbackAcrossBoundary,
                format!("Callback registration pattern: {callee}"),
            )
            .with_confidence(BoundaryConfidence::Strong),
        );
    }

    // If we have strong evidence, classify as strong seed
    if !strong_evidence.is_empty() {
        let reason = format!("Strong seed: {} -> {}", caller, callee);
        debug!(caller, callee, "Classified as strong seed");
        return SeedResult {
            classification: SeedClassification::Strong,
            evidence: strong_evidence,
            slice_info: FfiSliceInfo::seed(&reason),
        };
    }

    // ── Weak seeds ──

    let mut weak_evidence: Vec<BoundaryEvidence> = Vec::new();

    // 1. Known FFI contract symbol from same language
    //    (e.g., Rust Box::into_raw called from Rust code that is
    //    itself an FFI wrapper — the contract symbol indicates FFI
    //    intent even though the language pair isn't cross-language)
    if !effective_cross_language && is_external && has_pointer_param_or_return {
        weak_evidence.push(
            BoundaryEvidence::new(
                BoundaryEvidenceKind::ExternalAbiCall,
                format!("Same-language FFI contract symbol with pointer: {caller} -> {callee}"),
            )
            .with_caller_lang(caller_lang)
            .with_callee_lang(callee_lang)
            .with_confidence(BoundaryConfidence::Weak),
        );
    }

    // 2. Dangerous libc/resource inside a wrapper
    if is_dangerous_libc && is_exported_wrapper {
        weak_evidence.push(
            BoundaryEvidence::new(
                BoundaryEvidenceKind::ExportedWrapper,
                format!("Dangerous libc inside wrapper: {callee}"),
            )
            .with_confidence(BoundaryConfidence::Weak),
        );
    }

    // 3. Runtime bridge symbol connected to user boundary flow
    if is_runtime_bridge && is_configured_boundary {
        weak_evidence.push(
            BoundaryEvidence::new(
                BoundaryEvidenceKind::RuntimeBridge,
                format!("Runtime bridge connected to user boundary: {callee}"),
            )
            .with_confidence(BoundaryConfidence::Weak),
        );
    }

    if !weak_evidence.is_empty() {
        let reason = format!("Weak seed: {} -> {}", caller, callee);
        debug!(caller, callee, "Classified as weak seed");
        return SeedResult {
            classification: SeedClassification::Weak,
            evidence: weak_evidence,
            slice_info: FfiSliceInfo::expanded(0, BoundaryConfidence::Weak, &reason),
        };
    }

    // Default: suppression (no evidence of boundary)
    trace!(caller, callee, "Defaulting to suppression (no evidence)");
    SeedResult {
        classification: SeedClassification::Suppression,
        evidence: vec![],
        slice_info: FfiSliceInfo::outside(),
    }
}

/// Check if a function name matches a callback registration pattern.
///
/// Common patterns:
/// - `register_callback*`, `set_callback*`, `*_set_callback`
/// - `on_event*`, `*_handler`, `*_notify`
/// - `atexit`, `on_exit`
pub fn is_callback_registration_pattern(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("register_callback")
        || lower.contains("set_callback")
        || lower.contains("_set_callback")
        || lower.starts_with("on_event")
        || lower.ends_with("_handler")
        || lower.ends_with("_notify")
        || lower == "atexit"
        || lower == "on_exit"
        || lower.contains("register_notify")
        || lower.contains("set_notifier")
}

/// Check if a function name is a known runtime bridge function.
///
/// Runtime bridges are compiler/language runtime functions that mediate
/// between languages. Examples: `__rust_alloc`, `c_allocator_impl`,
/// `__cxa_allocate_exception`.
pub fn is_runtime_bridge_function(name: &str) -> bool {
    name.starts_with("__rust_alloc")
        || name.starts_with("__rust_dealloc")
        || name.starts_with("__rust_realloc")
        || name == "c_allocator_impl"
        || name.starts_with("__cxa_allocate")
        || name.starts_with("__cxa_begin")
        || name.starts_with("objc_")
        || name.starts_with("swift_")
}

/// Check if a callee name looks like an exported wrapper function.
///
/// Exported wrappers are functions that export functionality across
/// a language boundary, typically with `extern "C"` or `#[no_mangle]`
/// annotations. In LLVM IR, these appear as defined functions that
/// are also declared externally (or have external linkage).
pub fn looks_like_exported_wrapper(name: &str, caller_lang: Language) -> bool {
    // Rust no_mangle wrappers typically have simple C-like names
    // (no mangling prefix) when called from C
    match caller_lang {
        Language::Rust => {
            // Rust exported wrappers often don't have _R or _ZN prefix
            // but they're defined in the same module
            !name.starts_with("_R") && !name.starts_with("_ZN")
        }
        Language::Cpp => {
            // C++ exported wrappers often use `extern "C"` so they
            // don't have _Z mangling
            !name.starts_with("_Z")
        }
        _ => false,
    }
}

/// Represents the FFI slice — the set of functions and calls near
/// an FFI boundary, expanded from strong/weak seeds.
#[derive(Debug, Clone, Default)]
pub struct FfiSlice {
    /// Map from function name to its FFI slice metadata.
    pub function_slice_info: std::collections::HashMap<String, FfiSliceInfo>,
    /// Map from call index to its FFI slice metadata.
    pub call_slice_info: std::collections::HashMap<usize, FfiSliceInfo>,
}

impl FfiSlice {
    /// Creates a new empty FFI slice.
    pub fn new() -> Self {
        Self::default()
    }

    /// Expands the FFI slice from seed classifications.
    ///
    /// For each strong seed, expands backward (callers) and forward (callees)
    /// by up to `MAX_EXPANSION_DEPTH` hops. Also includes resource-pair
    /// closure (acquire/release pairs) and callback closure
    /// (register/unregister/callback/userdata).
    ///
    /// # Arguments
    /// * `seed_results` - Map from call index to seed classification result.
    /// * `caller_calls` - Map from caller name to call indices (for forward expansion).
    /// * `callee_callers` - Map from callee name to call indices (for backward expansion).
    /// * `call_metas` - Pre-computed call metadata for looking up call details.
    /// * `resource_pair_closure` - Optional pairs of (acquire_call_idx, release_call_idx)
    ///   for resource-pair closure.
    pub fn expand_from_seeds(
        seed_results: &std::collections::HashMap<usize, SeedResult>,
        caller_calls: &std::collections::HashMap<String, Vec<usize>>,
        callee_callers: &std::collections::HashMap<String, Vec<usize>>,
        call_metas: &[crate::module_index::CachedCallMeta],
        resource_pair_closure: &[(usize, usize)],
    ) -> Self {
        let mut slice = Self::new();

        // Step 1: Register seed call sites and their functions.
        // Only insert in-slice seeds (Strong/Weak) into call_slice_info.
        // Suppression seeds use FfiSliceInfo::outside() (is_in_slice() = false),
        // so inserting them would make call_info(idx).is_some() return true
        // even though the call is not in the slice — downstream logic that
        // tests is_some() cannot distinguish "outside" from "not computed".
        for (&call_idx, seed) in seed_results {
            if !seed.slice_info.is_in_slice() {
                continue;
            }

            // Add the seed call itself
            slice
                .call_slice_info
                .insert(call_idx, seed.slice_info.clone());

            // Add the seed function
            let caller = &call_metas[call_idx].caller_name;
            slice
                .function_slice_info
                .insert(caller.clone(), seed.slice_info.clone());

            let callee = &call_metas[call_idx].callee_name;
            // If the callee is a defined function, add it too
            if !slice.function_slice_info.contains_key(callee) {
                slice.function_slice_info.insert(
                    callee.clone(),
                    FfiSliceInfo::expanded(
                        1,
                        seed.slice_info.ffi_relevance,
                        format!(
                            "Callee of seed: {}",
                            seed.slice_info.ffi_reason.as_deref().unwrap_or("unknown")
                        ),
                    ),
                );
            }
        }

        // Step 2: Expand from strong seeds (2 hops forward and backward)
        let strong_seeds: Vec<usize> = seed_results
            .iter()
            .filter(|(_, s)| s.classification == SeedClassification::Strong)
            .map(|(&idx, _)| idx)
            .collect();

        for seed_idx in strong_seeds {
            let seed_caller = call_metas[seed_idx].caller_name.clone();
            let seed_callee = call_metas[seed_idx].callee_name.clone();

            // Forward expansion: from seed callee, follow its calls
            let mut visited_fwd: std::collections::HashSet<(String, u32)> =
                std::collections::HashSet::new();
            expand_forward(
                &seed_callee,
                1,
                caller_calls,
                call_metas,
                &mut slice,
                &mut visited_fwd,
            );

            // Backward expansion: from seed caller, find who calls it
            let mut visited_bwd: std::collections::HashSet<(String, u32)> =
                std::collections::HashSet::new();
            expand_backward(
                &seed_caller,
                1,
                callee_callers,
                call_metas,
                &mut slice,
                &mut visited_bwd,
            );
        }

        // Step 3: Resource-pair closure
        // If an acquire call is in the slice, include its release pair and vice versa
        for &(acquire_idx, release_idx) in resource_pair_closure {
            let acquire_in_slice = slice.call_slice_info.contains_key(&acquire_idx);
            let release_in_slice = slice.call_slice_info.contains_key(&release_idx);
            if acquire_in_slice && !release_in_slice {
                let reason = "Resource pair closure: release of in-slice acquire";
                let release_meta = &call_metas[release_idx];
                slice.call_slice_info.insert(
                    release_idx,
                    FfiSliceInfo::expanded(MAX_EXPANSION_DEPTH, BoundaryConfidence::Weak, reason),
                );
                slice.function_slice_info.insert(
                    release_meta.caller_name.clone(),
                    FfiSliceInfo::expanded(MAX_EXPANSION_DEPTH, BoundaryConfidence::Weak, reason),
                );
            } else if release_in_slice && !acquire_in_slice {
                let reason = "Resource pair closure: acquire of in-slice release";
                let acquire_meta = &call_metas[acquire_idx];
                slice.call_slice_info.insert(
                    acquire_idx,
                    FfiSliceInfo::expanded(MAX_EXPANSION_DEPTH, BoundaryConfidence::Weak, reason),
                );
                slice.function_slice_info.insert(
                    acquire_meta.caller_name.clone(),
                    FfiSliceInfo::expanded(MAX_EXPANSION_DEPTH, BoundaryConfidence::Weak, reason),
                );
            }
        }

        slice
    }

    /// Returns true if a function is in the FFI slice.
    pub fn is_function_in_slice(&self, function: &str) -> bool {
        self.function_slice_info
            .get(function)
            .map(|info| info.is_in_slice())
            .unwrap_or(false)
    }

    /// Returns the FfiSliceInfo for a function, if it's in the slice.
    pub fn function_info(&self, function: &str) -> Option<&FfiSliceInfo> {
        self.function_slice_info.get(function)
    }

    /// Returns the FfiSliceInfo for a call index, if it's in the slice.
    pub fn call_info(&self, call_idx: usize) -> Option<&FfiSliceInfo> {
        self.call_slice_info.get(&call_idx)
    }

    /// Returns the number of functions in the slice.
    pub fn function_count(&self) -> usize {
        self.function_slice_info
            .values()
            .filter(|info| info.is_in_slice())
            .count()
    }

    /// Returns the number of calls in the slice.
    pub fn call_count(&self) -> usize {
        self.call_slice_info
            .values()
            .filter(|info| info.is_in_slice())
            .count()
    }
}

/// Expand forward from a function: add all its callees to the slice.
/// Uses a visited set keyed by (function, depth) to avoid re-traversing
/// the same node at the same depth in cyclic call graphs.
fn expand_forward(
    function: &str,
    current_depth: u32,
    caller_calls: &std::collections::HashMap<String, Vec<usize>>,
    call_metas: &[crate::module_index::CachedCallMeta],
    slice: &mut FfiSlice,
    visited: &mut std::collections::HashSet<(String, u32)>,
) {
    if current_depth > MAX_EXPANSION_DEPTH {
        return;
    }

    // Skip if we've already expanded this function at this depth
    let visit_key = (function.to_string(), current_depth);
    if !visited.insert(visit_key) {
        return;
    }

    let relevance = if current_depth == 1 {
        BoundaryConfidence::Strong
    } else {
        BoundaryConfidence::Weak
    };

    if let Some(call_indices) = caller_calls.get(function) {
        for &call_idx in call_indices {
            let callee = &call_metas[call_idx].callee_name;
            let reason = format!("Forward expansion depth {current_depth} from {function}");

            // Add the call to the slice
            slice
                .call_slice_info
                .entry(call_idx)
                .or_insert_with(|| FfiSliceInfo::expanded(current_depth, relevance, &reason));

            // Add the callee function to the slice
            slice
                .function_slice_info
                .entry(callee.clone())
                .or_insert_with(|| FfiSliceInfo::expanded(current_depth, relevance, &reason));

            // Recurse into callee's callees
            expand_forward(
                callee,
                current_depth + 1,
                caller_calls,
                call_metas,
                slice,
                visited,
            );
        }
    }
}

/// Expand backward from a function: add all its callers to the slice.
/// Uses a visited set keyed by (function, depth) to avoid re-traversing
/// the same node at the same depth in cyclic call graphs.
fn expand_backward(
    function: &str,
    current_depth: u32,
    callee_callers: &std::collections::HashMap<String, Vec<usize>>,
    call_metas: &[crate::module_index::CachedCallMeta],
    slice: &mut FfiSlice,
    visited: &mut std::collections::HashSet<(String, u32)>,
) {
    if current_depth > MAX_EXPANSION_DEPTH {
        return;
    }

    // Skip if we've already expanded this function at this depth
    let visit_key = (function.to_string(), current_depth);
    if !visited.insert(visit_key) {
        return;
    }

    let relevance = if current_depth == 1 {
        BoundaryConfidence::Strong
    } else {
        BoundaryConfidence::Weak
    };

    if let Some(call_indices) = callee_callers.get(function) {
        for &call_idx in call_indices {
            let caller = &call_metas[call_idx].caller_name;
            let reason = format!("Backward expansion depth {current_depth} to {function}");

            // Add the call to the slice
            slice
                .call_slice_info
                .entry(call_idx)
                .or_insert_with(|| FfiSliceInfo::expanded(current_depth, relevance, &reason));

            // Add the caller function to the slice
            slice
                .function_slice_info
                .entry(caller.clone())
                .or_insert_with(|| FfiSliceInfo::expanded(current_depth, relevance, &reason));

            // Recurse into caller's callers
            expand_backward(
                caller,
                current_depth + 1,
                callee_callers,
                call_metas,
                slice,
                visited,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify strong seed classification for cross-language call.
    /// Invariants: Cross-language call with both languages known → Strong seed.
    #[test]
    fn test_strong_seed_cross_language() {
        let detector = FFIBoundaryDetector::new();
        let result = classify_seed(
            "rust_main",
            "c_handler",
            Language::Rust,
            Language::C,
            true,
            false,
            false,
            true,
            false,
            false,
            &detector,
            false,
            false,
            false,
            false,
            false,
        );
        assert_eq!(
            result.classification,
            SeedClassification::Strong,
            "Cross-language call must be strong seed"
        );
        assert!(
            result.slice_info.is_in_slice(),
            "Strong seed must be in slice"
        );
        assert_eq!(
            result.slice_info.ffi_slice_depth,
            Some(0),
            "Seed must have depth 0"
        );
        assert!(
            result.evidence.iter().any(|e| e.is_strong()),
            "Must have strong evidence"
        );
    }

    /// Objective: Verify strong seed for C calling C++ mangled name.
    /// Invariants: C calling _Z symbol (non-Rust) → Strong seed.
    #[test]
    fn test_strong_seed_cpp_ffi() {
        let detector = FFIBoundaryDetector::new();
        let result = classify_seed(
            "c_main",
            "_Z3fooi",
            Language::C,
            Language::Cpp,
            false,
            false,
            true,
            false,
            false,
            false,
            &detector,
            false,
            false,
            false,
            false,
            false,
        );
        assert_eq!(
            result.classification,
            SeedClassification::Strong,
            "C calling C++ mangled must be strong seed"
        );
    }

    /// Objective: Verify suppression for LLVM intrinsic.
    /// Invariants: LLVM intrinsic → Suppression.
    #[test]
    fn test_suppression_llvm_intrinsic() {
        let detector = FFIBoundaryDetector::new();
        let result = classify_seed(
            "c_main",
            "llvm.memcpy",
            Language::C,
            Language::Unknown,
            false,
            true,
            false,
            false,
            false,
            false,
            &detector,
            false,
            false,
            false,
            false,
            false,
        );
        assert_eq!(
            result.classification,
            SeedClassification::Suppression,
            "LLVM intrinsic must be suppressed"
        );
        assert!(
            !result.slice_info.is_in_slice(),
            "Suppressed call must not be in slice"
        );
    }

    /// Objective: Verify suppression for internal same-language call.
    /// Invariants: Same language, non-external, no callback → Suppression.
    #[test]
    fn test_suppression_internal_same_language() {
        let detector = FFIBoundaryDetector::new();
        let result = classify_seed(
            "c_helper",
            "c_utility",
            Language::C,
            Language::C,
            false,
            false,
            false,
            false,
            false,
            false,
            &detector,
            false,
            false,
            false,
            false,
            false,
        );
        assert_eq!(
            result.classification,
            SeedClassification::Suppression,
            "Internal same-language call must be suppressed"
        );
    }

    /// Objective: Verify weak seed for same-language FFI with pointer.
    /// Invariants: Same language, external, pointer param → Weak seed.
    #[test]
    fn test_weak_seed_same_language_ffi() {
        let detector = FFIBoundaryDetector::new();
        let result = classify_seed(
            "rust_wrapper",
            "rust_into_raw",
            Language::Rust,
            Language::Rust,
            true,
            false,
            false,
            false,
            true,
            false,
            &detector,
            false,
            false,
            false,
            false,
            false,
        );
        assert_eq!(
            result.classification,
            SeedClassification::Weak,
            "Same-language FFI with pointer must be weak seed"
        );
    }

    /// Objective: Verify callback registration pattern detection.
    /// Invariants: register_callback, atexit, _handler → true.
    #[test]
    fn test_callback_registration_patterns() {
        assert!(
            is_callback_registration_pattern("register_callback"),
            "register_callback must match callback pattern"
        );
        assert!(
            is_callback_registration_pattern("set_callback_handler"),
            "set_callback_handler must match callback pattern"
        );
        assert!(
            is_callback_registration_pattern("atexit"),
            "atexit must match callback pattern"
        );
        assert!(
            !is_callback_registration_pattern("malloc"),
            "malloc must NOT match callback pattern"
        );
    }

    /// Objective: Verify runtime bridge function detection.
    /// Invariants: __rust_alloc, c_allocator_impl → true; user_fn → false.
    #[test]
    fn test_runtime_bridge_functions() {
        assert!(
            is_runtime_bridge_function("__rust_alloc"),
            "__rust_alloc must be runtime bridge"
        );
        assert!(
            is_runtime_bridge_function("c_allocator_impl"),
            "c_allocator_impl must be runtime bridge"
        );
        assert!(
            !is_runtime_bridge_function("my_function"),
            "User function must not be runtime bridge"
        );
    }

    /// Objective: Verify FfiSlice expansion from seeds.
    /// Invariants: Strong seed expands 2 hops forward and backward.
    #[test]
    fn test_ffi_slice_expansion() {
        use crate::module_index::CachedCallMeta;

        // Build a simple call graph: A -> B -> C -> D
        // B -> C is a strong seed (cross-language)
        // Expansion should include A (backward), B, C, D (forward)
        let call_metas = vec![
            CachedCallMeta {
                call_index: 0,
                caller_name: "A".to_string(),
                callee_name: "B".to_string(),
                is_external: false,
                caller_lang: Language::C,
                callee_lang: Language::C,
                is_llvm_intrinsic: false,
                is_cpp_mangled: false,
                is_alloc_call: false,
                is_dealloc_call: false,
                symbol_effect: None,
                family_id: None,
                is_cross_language: false,
                is_ffi_boundary: false,
                boundary_evidence: None,
                ffi_slice_info: None,
            },
            CachedCallMeta {
                call_index: 1,
                caller_name: "B".to_string(),
                callee_name: "C_rust".to_string(),
                is_external: true,
                caller_lang: Language::C,
                callee_lang: Language::Rust,
                is_llvm_intrinsic: false,
                is_cpp_mangled: false,
                is_alloc_call: false,
                is_dealloc_call: false,
                symbol_effect: None,
                family_id: None,
                is_cross_language: true,
                is_ffi_boundary: true,
                boundary_evidence: None,
                ffi_slice_info: None,
            },
            CachedCallMeta {
                call_index: 2,
                caller_name: "C_rust".to_string(),
                callee_name: "D".to_string(),
                is_external: false,
                caller_lang: Language::Rust,
                callee_lang: Language::Rust,
                is_llvm_intrinsic: false,
                is_cpp_mangled: false,
                is_alloc_call: false,
                is_dealloc_call: false,
                symbol_effect: None,
                family_id: None,
                is_cross_language: false,
                is_ffi_boundary: false,
                boundary_evidence: None,
                ffi_slice_info: None,
            },
        ];

        let mut caller_calls = std::collections::HashMap::new();
        caller_calls.insert("A".to_string(), vec![0]);
        caller_calls.insert("B".to_string(), vec![1]);
        caller_calls.insert("C_rust".to_string(), vec![2]);

        let mut callee_callers = std::collections::HashMap::new();
        callee_callers.insert("B".to_string(), vec![0]);
        callee_callers.insert("C_rust".to_string(), vec![1]);
        callee_callers.insert("D".to_string(), vec![2]);

        // Seed: call 1 (B -> C_rust) is strong
        let mut seed_results = std::collections::HashMap::new();
        seed_results.insert(
            1,
            SeedResult {
                classification: SeedClassification::Strong,
                evidence: vec![],
                slice_info: FfiSliceInfo::seed("B -> C_rust"),
            },
        );

        let slice = FfiSlice::expand_from_seeds(
            &seed_results,
            &caller_calls,
            &callee_callers,
            &call_metas,
            &[],
        );

        // B and C_rust must be in slice (seed + immediate)
        assert!(
            slice.is_function_in_slice("B"),
            "B (seed caller) must be in slice"
        );
        assert!(
            slice.is_function_in_slice("C_rust"),
            "C_rust (seed callee) must be in slice"
        );
        // A must be in slice (backward expansion from B, depth 1)
        assert!(
            slice.is_function_in_slice("A"),
            "A (backward 1-hop from B) must be in slice"
        );
        // D must be in slice (forward expansion from C_rust, depth 1)
        assert!(
            slice.is_function_in_slice("D"),
            "D (forward 1-hop from C_rust) must be in slice"
        );
    }
}
