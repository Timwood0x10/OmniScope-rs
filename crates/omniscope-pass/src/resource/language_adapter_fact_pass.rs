//! Language adapter semantic fact extraction pass.
//!
//! This pass runs language-specific adapters (C++, Python, Java/JNI,
//! Go, C#) on each function in the module index, collects the
//! resulting `SemanticFact` records, and merges them into the
//! pass context's `semantic_facts` store for downstream consumption
//! by `IssueCandidateBuilderPass`.
//!
//! # Pipeline Position
//!
//! Runs after `ModuleIndex` (which provides function names and
//! language hints) and before or alongside `IRBehaviorSummaryPass`.
//! Both passes write to the `semantic_facts` key; the merge is
//! append-only so order does not matter.

use omniscope_core::Result;
use omniscope_semantics::{
    CSharpAdapter, CppAdapter, GoAdapter, JavaAdapter, PythonAdapter, SemanticFact,
};

use crate::module_index::ModuleIndex;
use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// Language adapter semantic fact extraction pass.
///
/// For each function in the module index, this pass:
/// 1. Detects the language from the function name.
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

        // Get function names from ModuleIndex
        let module_index: Option<ModuleIndex> = ctx.get("module_index");
        let Some(index) = module_index else {
            let result = PassResult::new(self.name())
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        };

        // Initialize language adapters
        let cpp_adapter = CppAdapter::new();
        let python_adapter = PythonAdapter::new();
        let java_adapter = JavaAdapter::new();
        let go_adapter = GoAdapter::new();
        let csharp_adapter = CSharpAdapter::new();

        let mut adapter_facts: Vec<SemanticFact> = Vec::new();
        let mut cpp_count: usize = 0;
        let mut python_count: usize = 0;
        let mut java_count: usize = 0;
        let mut go_count: usize = 0;
        let mut csharp_count: usize = 0;

        // Collect all function names from call metas and function metas
        let mut func_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        for meta in &index.call_metas {
            func_names.insert(meta.callee_name.clone());
            func_names.insert(meta.caller_name.clone());
        }
        for name in index.function_metas.keys() {
            func_names.insert(name.clone());
        }

        for func_name in &func_names {
            // C++ adapter: detect C++ mangled names and patterns
            if looks_like_cpp(func_name) {
                let analysis = cpp_adapter.analyze_function(func_name, None);
                let facts = analysis.to_semantic_facts();
                cpp_count += facts.len();
                adapter_facts.extend(facts);
            }

            // Python adapter: detect Python C API function names
            if looks_like_python(func_name) {
                if let Some(semantic) = python_adapter.analyze_function(func_name) {
                    adapter_facts.push(semantic.to_semantic_fact());
                    python_count += 1;
                }
            }

            // Java/JNI adapter: detect JNI function names
            if looks_like_jni(func_name) {
                let analysis = java_adapter.analyze_function(func_name, None);
                let facts = analysis.to_semantic_facts();
                java_count += facts.len();
                adapter_facts.extend(facts);
            }

            // Go adapter: detect Go/CGO function names
            if looks_like_go(func_name) {
                let analysis = go_adapter.analyze_function(func_name, None);
                let facts = analysis.to_semantic_facts();
                go_count += facts.len();
                adapter_facts.extend(facts);
            }

            // C# adapter: detect C#/P/Invoke function names
            if looks_like_csharp(func_name) {
                let analysis = csharp_adapter.analyze_function(func_name, None);
                let facts = analysis.to_semantic_facts();
                csharp_count += facts.len();
                adapter_facts.extend(facts);
            }
        }

        // Merge into existing semantic_facts from IRBehaviorSummaryPass
        let mut existing_facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap_or_default();
        existing_facts.extend(adapter_facts.clone());
        ctx.store("semantic_facts", existing_facts);

        let mut result = PassResult::new(self.name())
            .with_nodes(func_names.len())
            .with_duration(start.elapsed().as_millis() as u64);

        result.add_stat("adapter_facts_emitted", adapter_facts.len());
        result.add_stat("cpp_facts", cpp_count);
        result.add_stat("python_facts", python_count);
        result.add_stat("java_facts", java_count);
        result.add_stat("go_facts", go_count);
        result.add_stat("csharp_facts", csharp_count);

        Ok(result)
    }
}

impl Default for LanguageAdapterFactPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a function name looks like C++ (mangled Itanium/MSVC names).
fn looks_like_cpp(name: &str) -> bool {
    name.starts_with("_Z")
        || name.starts_with("__Z")
        || name.starts_with("?") // MSVC mangling
        || name.contains("::")
        || name.contains("std::")
        || name.contains("operator")
}

/// Check if a function name looks like Python C API.
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

/// Check if a function name looks like Java/JNI.
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
fn looks_like_go(name: &str) -> bool {
    name.starts_with("runtime.")
        || name.starts_with("_cgo_")
        || name.starts_with("_Cfunc_")
        || name.starts_with("main.")
        || name.contains("crossboundary2")
}

/// Check if a function name looks like C#/P/Invoke.
fn looks_like_csharp(name: &str) -> bool {
    name.starts_with("System_")
        || name.starts_with("Microsoft_")
        || name.contains("Marshal")
        || name.contains("SafeHandle")
        || name.contains("GCHandle")
        || name.contains("IDisposable")
        || name.contains("Dispose")
}
