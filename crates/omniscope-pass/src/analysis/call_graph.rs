//! Call Graph Analysis Pass.
//!
//! Builds a call graph from parsed LLVM IR, recording function relationships
//! and classifying functions by kind (internal, libc, external_unknown).
//! Detects cross-language edges using LanguageDetector.
//!
//! This pass is stateless — it analyzes the IR directly and produces
//! CallGraphNode / CallGraphEdge / CrossLangEdge data structures
//! stored in PassContext for downstream passes.

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::Result;
use omniscope_semantics::LanguageDetector;
use omniscope_types::call_graph_types::{
    is_dangerous, is_libc, CallGraphEdge, CallGraphNode, CrossLangEdge, FunctionKind,
};
use omniscope_types::config::Language;
use tracing::{debug, info};

/// Call graph analysis pass.
///
/// Builds a call graph from the IR module's functions and call
/// instructions. Each function is classified as Internal, LibC,
/// or ExternalUnknown. Cross-language edges are detected by
/// comparing the detected language of caller and callee.
pub struct CallGraphPass;

impl CallGraphPass {
    /// Creates a new call graph pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for CallGraphPass {
    fn name(&self) -> &'static str {
        "CallGraph"
    }

    fn kind(&self) -> PassKind {
        PassKind::Foundation
    }

    fn dependencies(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        // Retrieve the IR module from context
        let Some(module) = ctx.get_ir_module() else {
            debug!("CallGraphPass: no IR module in context, producing empty results");
            return Ok(PassResult::new(self.name())
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64));
        };

        let mut nodes: Vec<CallGraphNode> = Vec::new();
        let mut edges: Vec<CallGraphEdge> = Vec::new();
        let mut cross_lang_edges: Vec<CrossLangEdge> = Vec::new();

        // Try to use ModuleIndex for cached language detection
        let module_index: Option<crate::module_index::ModuleIndex> = ctx.get("module_index");

        if let Some(ref index) = module_index {
            // Fast path: use pre-computed metadata from ModuleIndex
            // Phase 1: Build function nodes from cached function metadata
            for (name, meta) in &index.function_metas {
                let kind = classify_function(name, meta.is_declaration, meta.language);
                nodes.push(CallGraphNode {
                    name: name.clone(),
                    kind,
                    param_count: meta.param_count,
                    is_declaration: meta.is_declaration,
                    language: Some(meta.language),
                });
            }

            // Phase 2: Build edges from cached call metadata
            for call_meta in &index.call_metas {
                let is_cross_lang = call_meta.is_cross_language;

                edges.push(CallGraphEdge {
                    caller: call_meta.caller_name.clone(),
                    callee: call_meta.callee_name.clone(),
                    is_cross_lang,
                    caller_lang: Some(call_meta.caller_lang),
                    callee_lang: Some(call_meta.callee_lang),
                });

                // Phase 3: Detect FFI boundaries from cross-language edges
                if is_cross_lang {
                    let is_ffi = is_ffi_boundary(
                        &call_meta.caller_name,
                        &call_meta.callee_name,
                        call_meta.caller_lang,
                        call_meta.callee_lang,
                    );
                    cross_lang_edges.push(CrossLangEdge {
                        caller_name: call_meta.caller_name.clone(),
                        callee_name: call_meta.callee_name.clone(),
                        is_ffi_boundary: is_ffi,
                        caller_lang: call_meta.caller_lang,
                        callee_lang: call_meta.callee_lang,
                        calling_convention: None,
                    });
                    debug!(
                        "CrossLangEdge: {} ({:?}) -> {} ({:?}), ffi={}",
                        call_meta.caller_name,
                        call_meta.caller_lang,
                        call_meta.callee_name,
                        call_meta.callee_lang,
                        is_ffi
                    );
                }
            }
        } else {
            // Fallback path: recompute metadata (legacy behavior).
            // Uses a language cache to avoid redundant `detect_from_function`
            // calls for the same function name across nodes and edges.
            let detector = LanguageDetector::new();
            let mut lang_cache: std::collections::HashMap<String, Language> =
                std::collections::HashMap::with_capacity(
                    module.functions.len() + module.declarations.len() + module.calls.len() * 2,
                );

            // Helper: detect and cache language for a function name.
            let detect_cached = |cache: &mut std::collections::HashMap<String, Language>,
                                 detector: &LanguageDetector,
                                 name: &str|
             -> Language {
                if let Some(&lang) = cache.get(name) {
                    return lang;
                }
                let lang = detector.detect_from_function(name);
                cache.insert(name.to_string(), lang);
                lang
            };

            // Phase 1: Build function nodes from definitions and declarations
            // in a single merged iteration chain.
            let def_iter = module
                .functions
                .iter()
                .map(|(name, func)| (name, func, false));
            let decl_iter = module
                .declarations
                .iter()
                .map(|(name, func)| (name, func, true));

            for (name, func, is_declaration) in def_iter.chain(decl_iter) {
                let language = detect_cached(&mut lang_cache, &detector, name);
                let kind = classify_function(name, is_declaration, language);
                nodes.push(CallGraphNode {
                    name: name.clone(),
                    kind,
                    param_count: func.params.len(),
                    is_declaration: func.is_declaration,
                    language: Some(language),
                });
            }

            // Phase 2+3: Build edges and detect FFI boundaries in one pass.
            for call in &module.calls {
                let caller_lang = detect_cached(&mut lang_cache, &detector, &call.caller);
                let callee_lang = detect_cached(&mut lang_cache, &detector, &call.callee);
                let is_cross_lang = caller_lang != Language::Unknown
                    && callee_lang != Language::Unknown
                    && caller_lang != callee_lang;

                edges.push(CallGraphEdge {
                    caller: call.caller.clone(),
                    callee: call.callee.clone(),
                    is_cross_lang,
                    caller_lang: Some(caller_lang),
                    callee_lang: Some(callee_lang),
                });

                // Detect FFI boundaries from cross-language edges inline
                if is_cross_lang {
                    let is_ffi =
                        is_ffi_boundary(&call.caller, &call.callee, caller_lang, callee_lang);
                    cross_lang_edges.push(CrossLangEdge {
                        caller_name: call.caller.clone(),
                        callee_name: call.callee.clone(),
                        is_ffi_boundary: is_ffi,
                        caller_lang,
                        callee_lang,
                        calling_convention: None,
                    });
                    debug!(
                        "CrossLangEdge: {} ({:?}) -> {} ({:?}), ffi={}",
                        call.caller, caller_lang, call.callee, callee_lang, is_ffi
                    );
                }
            }
        }

        let node_count = nodes.len();
        let edge_count = edges.len();
        let cross_lang_count = cross_lang_edges.len();
        let ffi_count = cross_lang_edges
            .iter()
            .filter(|e| e.is_ffi_boundary)
            .count();

        // Store results in PassContext for downstream passes
        ctx.store("call_graph_nodes", nodes);
        ctx.store("call_graph_edges", edges);
        ctx.store("cross_lang_edges", cross_lang_edges);

        info!(
            "CallGraphPass: {} nodes, {} edges, {} cross-lang, {} FFI boundaries",
            node_count, edge_count, cross_lang_count, ffi_count
        );

        let mut result = PassResult::new(self.name())
            .with_nodes(node_count)
            .with_duration(start.elapsed().as_millis() as u64);
        result.add_stat("edges", edge_count);
        result.add_stat("cross_lang", cross_lang_count);
        result.add_stat("ffi_boundaries", ffi_count);
        Ok(result)
    }
}

impl Default for CallGraphPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify a function based on its name, declaration status, and language.
///
/// Classification priority:
/// 1. Known libc function → LibC
/// 2. Known dangerous function → ExternalUnknown (treated as FFI boundary)
/// 3. Has a body (not declaration) → Internal
/// 4. No body (declaration) → ExternalUnknown
fn classify_function(name: &str, is_declaration: bool, language: Language) -> FunctionKind {
    // Known libc functions are trusted regardless of declaration status
    if is_libc(name) {
        return FunctionKind::LibC;
    }

    // Dangerous functions are always treated as potential FFI boundaries
    if is_dangerous(name) {
        return FunctionKind::ExternalUnknown;
    }

    // Language runtime intrinsics (e.g., __rust_*, _Unwind_*) are external
    if is_runtime_intrinsic(name, language) {
        return FunctionKind::ExternalUnknown;
    }

    // Functions with bodies are internal to the analyzed module
    if !is_declaration {
        return FunctionKind::Internal;
    }

    // Declarations without bodies: could be external FFI targets
    FunctionKind::ExternalUnknown
}

/// Check if a function name is a language runtime intrinsic.
///
/// Runtime intrinsics should not be treated as user FFI boundaries.
///
/// Note: For C++, we only filter actual compiler/runtime support functions
/// (`__cxxabiv1::*`, `__cxa_*`), NOT all `_Z`-prefixed mangled names.
/// User C++ functions like `_ZdlPv` (operator delete) are legitimate FFI
/// boundaries when called from C code.
fn is_runtime_intrinsic(name: &str, language: Language) -> bool {
    match language {
        Language::Rust => {
            name.starts_with("__rust_")
                || name.starts_with("_ZN4core")
                || name.starts_with("_ZN5alloc")
        }
        Language::C => {
            name.starts_with("__libc_")
                || name.starts_with("__cxa_")
                || name.starts_with("_Unwind_")
                || name.starts_with("_tlv_")
        }
        Language::Cpp => {
            // Only filter actual compiler runtime support, not all _Z mangled names
            name.starts_with("__cxxabiv1")
                || name.starts_with("__cxa_")
                || name.starts_with("__gxx_")
        }
        _ => false,
    }
}

/// Determine if a cross-language edge is a genuine FFI boundary.
///
/// Not every cross-language call is an FFI boundary. For example,
/// Rust calling its own core:: functions is internal, not FFI.
/// A genuine FFI boundary is where user code crosses into a
/// different language's memory management domain.
fn is_ffi_boundary(
    _caller: &str,
    callee: &str,
    caller_lang: Language,
    callee_lang: Language,
) -> bool {
    // If either language is Unknown, we cannot confirm it's FFI
    if caller_lang == Language::Unknown || callee_lang == Language::Unknown {
        return false;
    }

    // Same language → not FFI
    if caller_lang == callee_lang {
        return false;
    }

    // libc functions called from any language are NOT FFI boundaries
    // (they are the expected C ABI interface, not cross-language issues)
    if is_libc(callee) {
        return false;
    }

    // Runtime intrinsics are not FFI boundaries
    if is_runtime_intrinsic(callee, callee_lang) {
        return false;
    }

    // Skip compiler-generated drop glue and panicking
    if callee.contains("drop_in_place") || callee.contains("panic") {
        return false;
    }

    // Everything else crossing a language boundary is an FFI boundary
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify function classification for libc and dangerous functions.
    /// Invariants: malloc=LibC, system=ExternalUnknown, user_fn=Internal.
    #[test]
    fn test_function_classification() {
        assert_eq!(
            classify_function("malloc", false, Language::C),
            FunctionKind::LibC,
            "malloc must be classified as LibC"
        );
        assert_eq!(
            classify_function("system", false, Language::C),
            FunctionKind::ExternalUnknown,
            "system is dangerous → ExternalUnknown"
        );
        assert_eq!(
            classify_function("my_func", false, Language::Rust),
            FunctionKind::Internal,
            "user function with body must be Internal"
        );
        assert_eq!(
            classify_function("ext_func", true, Language::C),
            FunctionKind::ExternalUnknown,
            "declaration without body must be ExternalUnknown"
        );
    }

    /// Objective: Verify Rust runtime intrinsics are not treated as FFI.
    /// Invariants: __rust_dealloc, _ZN4core → ExternalUnknown but NOT FFI boundary.
    #[test]
    fn test_rust_runtime_intrinsics() {
        assert!(
            is_runtime_intrinsic("__rust_dealloc", Language::Rust),
            "__rust_ prefix must be recognized as runtime intrinsic"
        );
        assert!(
            is_runtime_intrinsic("_ZN4core3ptr7drop_in_place", Language::Rust),
            "_ZN4core prefix must be recognized as runtime intrinsic"
        );
        assert!(
            !is_runtime_intrinsic("my_c_func", Language::C),
            "user functions must not be classified as runtime intrinsics"
        );
    }

    /// Objective: Verify FFI boundary detection logic.
    /// Invariants: Same language → not FFI; libc → not FFI; cross-lang user → FFI.
    #[test]
    fn test_ffi_boundary_detection() {
        // Same language → not FFI
        assert!(
            !is_ffi_boundary("rust_fn", "rust_fn2", Language::Rust, Language::Rust),
            "same language must not be FFI boundary"
        );

        // libc → not FFI (even if cross-language)
        assert!(
            !is_ffi_boundary("rust_main", "malloc", Language::Rust, Language::C),
            "libc functions must not be flagged as FFI boundary"
        );

        // Runtime intrinsics → not FFI
        assert!(
            !is_ffi_boundary("rust_fn", "__rust_dealloc", Language::Rust, Language::Rust),
            "runtime intrinsics must not be flagged as FFI boundary"
        );

        // Unknown language → cannot confirm FFI
        assert!(
            !is_ffi_boundary("unknown_fn", "c_func", Language::Unknown, Language::C),
            "Unknown language cannot confirm FFI boundary"
        );
    }

    /// Objective: Verify that genuine cross-language calls are detected.
    /// Invariants: Rust→C user function is FFI boundary.
    #[test]
    fn test_genuine_cross_lang_ffi() {
        assert!(
            is_ffi_boundary("rust_main", "c_handler", Language::Rust, Language::C),
            "Rust calling C user function must be FFI boundary"
        );
        assert!(
            is_ffi_boundary("zig_main", "c_process", Language::Zig, Language::C),
            "Zig calling C function must be FFI boundary"
        );
    }

    /// Objective: Verify CallGraphPass creation and Pass trait compliance.
    /// Invariants: name="CallGraph", kind=Foundation, no dependencies.
    #[test]
    fn test_call_graph_pass_trait() {
        let pass = CallGraphPass::new();
        assert_eq!(pass.name(), "CallGraph", "pass name must be CallGraph");
        assert_eq!(pass.kind(), PassKind::Foundation, "must be Foundation kind");
        assert!(
            pass.dependencies().is_empty(),
            "CallGraph has no dependencies"
        );
    }
}
