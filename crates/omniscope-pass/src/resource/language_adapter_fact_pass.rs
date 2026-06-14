//! Language adapter semantic fact extraction pass.
//!
//! This pass runs language-specific adapters (C++, Python, Java/JNI,
//! Go, C#) on each function in the module index, collects the
//! resulting `SemanticFact` records, and merges them into the
//! pass context's `semantic_facts` store for downstream consumption
//! by `IssueCandidateBuilderPass`.
//!
//! # Language Detection Strategy
//!
//! Language is determined in priority order:
//! 1. `ModuleIndex.call_metas` — `caller_lang`/`callee_lang`/`is_ffi_boundary`
//!    from the boundary seed detector (most reliable).
//! 2. `ModuleIndex.function_metas` — `language` field from function-level
//!    detection.
//! 3. Name heuristics (`looks_like_cpp`, etc.) — fallback only, used
//!    when ModuleIndex has no language hint for a given function.
//!
//! # Pipeline Position
//!
//! Runs after `ModuleIndex` (which provides function names and
//! language hints) and before or alongside `IRBehaviorSummaryPass`.
//! Both passes write to the `semantic_facts` key; the merge is
//! append-only so order does not matter.

use omniscope_core::Result;
use omniscope_semantics::{
    CSharpAdapter, CppAdapter, GoAdapter, JavaAdapter, PythonAdapter, SemanticFact, WasAdapter,
};
use omniscope_types::config::Language;

use crate::module_index::ModuleIndex;
use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// Language adapter semantic fact extraction pass.
///
/// For each function in the module index, this pass:
/// 1. Detects the language from ModuleIndex metadata (priority) or
///    name heuristics (fallback).
/// 2. Calls the appropriate language adapter's `analyze_function`.
/// 3. Converts the adapter's result into `SemanticFact` records
///    via each adapter's `to_semantic_facts()` method.
/// 4. Merges the facts into the pass context's `semantic_facts` store.
pub struct LanguageAdapterFactPass;

impl LanguageAdapterFactPass {
    /// Creates a new language adapter fact pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for LanguageAdapterFactPass {
    fn name(&self) -> &'static str {
        "LanguageAdapterFact"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["ModuleIndex"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        // Use get_ref to avoid cloning the entire ModuleIndex (§7.5 perf).
        let index = ctx.get_ref::<ModuleIndex>("module_index");
        let Some(index) = index else {
            let result = PassResult::new(self.name())
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        };

        // Build language map from ModuleIndex metadata (priority source).
        // Maps function_name → Language, preferring FFI boundary call info
        // over function-level detection.
        let mut lang_map: std::collections::HashMap<String, Language> =
            std::collections::HashMap::new();

        // Priority 1: call_metas with known caller/callee languages
        for meta in &index.call_metas {
            if meta.caller_lang != Language::Unknown {
                lang_map
                    .entry(meta.caller_name.clone())
                    .or_insert(meta.caller_lang);
            }
            if meta.callee_lang != Language::Unknown {
                lang_map
                    .entry(meta.callee_name.clone())
                    .or_insert(meta.callee_lang);
            }
        }

        // Priority 2: function_metas with detected language
        for (name, fmeta) in &index.function_metas {
            if fmeta.language != Language::Unknown {
                lang_map.entry(name.clone()).or_insert(fmeta.language);
            }
        }

        // Collect unique function names from call metas and function metas
        let mut func_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        for meta in &index.call_metas {
            func_names.insert(meta.caller_name.clone());
            func_names.insert(meta.callee_name.clone());
        }
        for name in index.function_metas.keys() {
            func_names.insert(name.clone());
        }

        // Short-circuit: if the module is single-language, there are no
        // cross-language FFI boundaries, so most language adapters are not needed.
        // However, WASM/JS modules may still have FFI patterns detectable via
        // name/body heuristics, so we still run the WASM adapter even in
        // single-language mode.
        if index.is_single_language {
            let ir_module = ctx.get_ir_module();
            let wasm_adapter = WasAdapter::new();
            let mut wasm_count: usize = 0;
            let mut adapter_facts: Vec<SemanticFact> = Vec::new();

            for func_name in &func_names {
                if looks_like_wasm(func_name) {
                    let body = ir_module.and_then(|m| m.function_bodies.get(func_name));
                    let analysis = wasm_adapter.analyze_function(func_name, body);
                    let facts = analysis.to_semantic_facts();
                    wasm_count += facts.len();
                    adapter_facts.extend(facts);
                }
            }

            // Store WASM facts into context for downstream consumption
            let mut existing_facts: Vec<SemanticFact> =
                ctx.get("semantic_facts").unwrap_or_default();
            existing_facts.extend(adapter_facts);
            ctx.store("semantic_facts", existing_facts);

            let mut result = PassResult::new(self.name())
                .with_nodes(func_names.len())
                .with_duration(start.elapsed().as_millis() as u64);
            result.add_stat("adapter_facts_emitted", wasm_count);
            result.add_stat("wasm_facts", wasm_count);
            return Ok(result);
        }

        // Initialize language adapters
        let cpp_adapter = CppAdapter::new();
        let python_adapter = PythonAdapter::new();
        let java_adapter = JavaAdapter::new();
        let go_adapter = GoAdapter::new();
        let csharp_adapter = CSharpAdapter::new();
        let wasm_adapter = WasAdapter::new();

        let mut adapter_facts: Vec<SemanticFact> = Vec::new();
        let mut cpp_count: usize = 0;
        let mut python_count: usize = 0;
        let mut java_count: usize = 0;
        let mut go_count: usize = 0;
        let mut csharp_count: usize = 0;
        let mut wasm_count: usize = 0;
        let ir_module = ctx.get_ir_module();

        for func_name in &func_names {
            // Determine language: ModuleIndex first, heuristic fallback
            let lang = lang_map
                .get(func_name)
                .copied()
                .unwrap_or(Language::Unknown);

            // Only run adapters when we have a confident language assignment
            // or when the heuristic matches. This avoids false positives
            // from overly broad heuristic rules on non-FFI functions.
            let run_cpp =
                lang == Language::Cpp || (lang == Language::Unknown && looks_like_cpp(func_name));
            let run_python = lang == Language::Python
                || (lang == Language::Unknown && looks_like_python(func_name))
                // Rust functions calling Python C API (e.g., pyo3 bindings)
                // should also be analyzed for refcount patterns.
                || (lang == Language::Rust && ir_module.is_some_and(|m| calls_python_c_api(func_name, m)));
            let run_java =
                lang == Language::Java || (lang == Language::Unknown && looks_like_jni(func_name));
            let run_go =
                lang == Language::Go || (lang == Language::Unknown && looks_like_go(func_name));
            let run_csharp = lang == Language::CSharp
                || (lang == Language::Unknown && looks_like_csharp(func_name));
            let run_wasm = lang == Language::Unknown && looks_like_wasm(func_name);

            if run_cpp {
                let analysis = cpp_adapter.analyze_function(func_name, None);
                let facts = analysis.to_semantic_facts();
                cpp_count += facts.len();
                adapter_facts.extend(facts);
            }

            if run_python {
                let body = ir_module.and_then(|m| {
                    m.function_bodies
                        .get(func_name)
                        .or_else(|| m.function_bodies.get(&format!("\"{func_name}\"")))
                });
                let analysis = python_adapter.analyze_function_with_ir(func_name, body);
                let facts = analysis.to_semantic_facts();
                python_count += facts.len();
                adapter_facts.extend(facts);
            }

            if run_java {
                let analysis = java_adapter.analyze_function(func_name, None);
                let facts = analysis.to_semantic_facts();
                java_count += facts.len();
                adapter_facts.extend(facts);
            }

            if run_go {
                let analysis = go_adapter.analyze_function(func_name, None);
                let facts = analysis.to_semantic_facts();
                go_count += facts.len();
                adapter_facts.extend(facts);
            }

            if run_csharp {
                let analysis = csharp_adapter.analyze_function(func_name, None);
                let facts = analysis.to_semantic_facts();
                csharp_count += facts.len();
                adapter_facts.extend(facts);
            }

            if run_wasm {
                let body = ctx
                    .get_ir_module()
                    .and_then(|m| m.function_bodies.get(func_name));
                let analysis = wasm_adapter.analyze_function(func_name, body);
                let facts = analysis.to_semantic_facts();
                wasm_count += facts.len();
                adapter_facts.extend(facts);
            }
        }

        let adapter_fact_count = adapter_facts.len();

        // Merge into existing semantic_facts from IRBehaviorSummaryPass.
        // Avoid cloning adapter_facts — move directly into the merged vec.
        let mut existing_facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap_or_default();
        existing_facts.extend(adapter_facts);
        ctx.store("semantic_facts", existing_facts);

        let mut result = PassResult::new(self.name())
            .with_nodes(func_names.len())
            .with_duration(start.elapsed().as_millis() as u64);

        result.add_stat("adapter_facts_emitted", adapter_fact_count);
        result.add_stat("cpp_facts", cpp_count);
        result.add_stat("python_facts", python_count);
        result.add_stat("java_facts", java_count);
        result.add_stat("go_facts", go_count);
        result.add_stat("csharp_facts", csharp_count);
        result.add_stat("wasm_facts", wasm_count);

        Ok(result)
    }
}

impl Default for LanguageAdapterFactPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a function name looks like C++ (mangled Itanium/MSVC names).
///
/// **Fallback only** — ModuleIndex language detection takes priority.
fn looks_like_cpp(name: &str) -> bool {
    name.starts_with("_Z")
        || name.starts_with("__Z")
        || name.starts_with("?") // MSVC mangling
        || name.contains("::")
        || name.contains("std::")
        || name.contains("operator")
}

/// Check if a function name looks like Python C API.
///
/// **Fallback only** — ModuleIndex language detection takes priority.
fn looks_like_python(name: &str) -> bool {
    name.starts_with("Py")
        || name.starts_with("_Py")
        || name.contains("PyObject")
        || name.contains("PyList")
        || name.contains("PyDict")
        || name.contains("PyTuple")
        || name.contains("PyErr")
        || name.contains("PyGIL")
        || name.contains("PyMem")
}

/// Check if a function's IR body calls Python C API functions.
///
/// Used to run the Python adapter on Rust functions that interact with
/// Python's refcount system (e.g., pyo3 bindings). Generic: works for
/// any function that calls Py* functions, not just pyo3.
fn calls_python_c_api(func_name: &str, ir_module: &omniscope_ir::IRModule) -> bool {
    let name = func_name.trim_start_matches('@');
    // function_bodies keys may have quotes around names with special chars
    let body = ir_module
        .function_bodies
        .get(name)
        .or_else(|| ir_module.function_bodies.get(&format!("\"{name}\"")));
    body.map(|b| {
        b.call_instructions().iter().any(|inst| {
            inst.callee.as_deref().is_some_and(|c| {
                let c = c.trim_start_matches('@');
                c.starts_with("Py") || c.starts_with("_Py")
            })
        })
    })
    .unwrap_or(false)
}

/// Check if a function name looks like Java/JNI.
///
/// **Fallback only** — ModuleIndex language detection takes priority.
fn looks_like_jni(name: &str) -> bool {
    name.starts_with("Java_")
        || name.starts_with("JNI_")
        || name.contains("JNIEnv")
        || name.contains("NewGlobalRef")
        || name.contains("DeleteGlobalRef")
        || name.contains("NewLocalRef")
        || name.contains("DeleteLocalRef")
        || name.contains("GetStringUTFChars")
        || name.contains("ReleaseStringUTFChars")
}

/// Check if a function name looks like Go/CGO.
///
/// **Fallback only** — ModuleIndex language detection takes priority.
/// Note: `main.` prefix is deliberately excluded because it matches
/// too many ordinary Go functions; use ModuleIndex language detection
/// for those instead.
fn looks_like_go(name: &str) -> bool {
    name.starts_with("runtime.")
        || name.starts_with("_cgo_")
        || name.starts_with("_Cfunc_")
        || name.contains("crossboundary2")
}

/// Check if a function name looks like C#/P/Invoke.
///
/// **Fallback only** — ModuleIndex language detection takes priority.
/// Note: broad patterns like `Dispose`, `System_`, `Microsoft_` are
/// deliberately excluded to avoid false positives on non-FFI .NET code;
/// use ModuleIndex language detection for those instead.
fn looks_like_csharp(name: &str) -> bool {
    name.contains("Marshal") || name.contains("SafeHandle") || name.contains("GCHandle")
}

/// Check if a function name looks like WASM/JS FFI.
///
/// **Fallback only** — WASM is a compilation target and has no dedicated
/// Language variant; we rely entirely on name heuristics.
fn looks_like_wasm(name: &str) -> bool {
    name.starts_with("emscripten_")
        || name.starts_with("emnapi_")
        || name.starts_with("wasm_")
        || name.starts_with("__wasm_call_ctors")
        || name.starts_with("__import_")
        || name.starts_with("__export_")
        || name.starts_with("__asyncify")
        || name.contains("EM_JS_")
        || name.contains("EM_ASM_")
        || name.contains("memory.grow")
        || name.contains("__memory_grow")
}
