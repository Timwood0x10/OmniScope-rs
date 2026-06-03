//! Shared instruction metadata cache for pass-level performance optimization.
//!
//! Multiple analysis passes independently iterate over the same `IRModule`
//! collections (`calls`, `function_bodies`, `declarations`) and recompute
//! the same derived properties (language detection, registry lookups,
//! string trimming). The [`ModuleIndex`] pre-computes these once and
//! stores them in the [`PassContext`] for downstream passes to consume.
//!
//! # Design Principles
//!
//! - **No precision loss**: All cached values are identical to what passes
//!   would compute themselves. This is a pure memoization layer.
//! - **Zero-clone access**: Passes obtain `&ModuleIndex` via
//!   `ctx.get_ref::<ModuleIndex>()`, avoiding O(n) clones.
//! - **Single allocation**: The index is built once during pipeline
//!   initialization and lives for the entire analysis run.

use omniscope_ir::IRModule;
use omniscope_semantics::{FamilyRegistry, LanguageDetector};
use omniscope_types::call_graph_types::{is_dangerous, is_libc, FunctionKind};
use omniscope_types::config::Language;
use std::collections::HashMap;

/// Pre-computed metadata for a single call instruction.
///
/// Caches language detection, registry lookup, and classification
/// results so that passes avoid redundant computation.
#[derive(Debug, Clone)]
pub struct CachedCallMeta {
    /// Index into the original `module.calls` vector.
    pub call_index: usize,
    /// Caller function name (trimmed, no leading `@`).
    pub caller_name: String,
    /// Callee function name (trimmed, no leading `@`).
    pub callee_name: String,
    /// Whether this is an external call.
    pub is_external: bool,
    /// Detected caller language.
    pub caller_lang: Language,
    /// Detected callee language.
    pub callee_lang: Language,
    /// Whether callee starts with `llvm.` (LLVM intrinsic).
    pub is_llvm_intrinsic: bool,
    /// Whether callee starts with `_Z` (C++ mangled name).
    pub is_cpp_mangled: bool,
    /// Whether this call is a known allocation function (malloc, calloc, etc.).
    pub is_alloc_call: bool,
    /// Whether this call is a known deallocation function (free, operator delete, etc.).
    pub is_dealloc_call: bool,
    /// Family registry lookup result: symbol effect (if found).
    pub symbol_effect: Option<omniscope_semantics::SymbolEffect>,
    /// Family registry lookup result: family ID (if found).
    pub family_id: Option<omniscope_types::FamilyId>,
    /// Whether this is a cross-language call (both langs known and different).
    pub is_cross_language: bool,
    /// Whether this is an FFI boundary (cross-language + not filtered).
    pub is_ffi_boundary: bool,
}

/// Pre-computed metadata for a function definition or declaration.
#[derive(Debug, Clone)]
pub struct CachedFunctionMeta {
    /// Function name (trimmed, no leading `@`).
    pub name: String,
    /// Detected language.
    pub language: Language,
    /// Whether this is a declaration (extern).
    pub is_declaration: bool,
    /// Number of parameters.
    pub param_count: usize,
    /// Whether this function has any call instructions (as caller).
    pub has_calls: bool,
    /// Number of call instructions in this function (as caller).
    pub call_count: usize,
    /// Whether this function calls any allocation functions.
    pub calls_alloc: bool,
    /// Whether this function calls any deallocation functions.
    pub calls_dealloc: bool,
    /// Whether this function has any FFI boundary calls.
    pub has_ffi_calls: bool,
    /// Whether this function has any store instructions (in function body).
    pub has_stores: bool,
    /// Whether this function is runtime internal (Zig stdlib, compiler_rt, etc.).
    pub is_runtime_internal: bool,
}

/// Shared instruction metadata cache.
///
/// Built once from the `IRModule` and stored in `PassContext` for all
/// downstream passes to consume via `ctx.get_ref::<ModuleIndex>()`.
#[derive(Clone, Debug)]
pub struct ModuleIndex {
    /// Pre-computed metadata for each call instruction (same order as `module.calls`).
    pub call_metas: Vec<CachedCallMeta>,
    /// Pre-computed metadata for each function (keyed by trimmed name).
    pub function_metas: HashMap<String, CachedFunctionMeta>,
    /// Callee name -> list of call indices that call this callee.
    pub callee_callers: HashMap<String, Vec<usize>>,
    /// Caller name -> list of call indices in this function.
    pub caller_calls: HashMap<String, Vec<usize>>,
    /// Function names that have FFI boundary calls (as caller).
    pub ffi_caller_functions: Vec<String>,
    /// Function names that call allocation functions.
    pub alloc_caller_functions: Vec<String>,
    /// Total number of instructions across all function bodies.
    pub total_instruction_count: usize,
    /// Total number of call instructions.
    pub total_call_count: usize,
    /// Pre-built FamilyRegistry (shared across passes to avoid repeated construction).
    pub family_registry: FamilyRegistry,
    /// Pre-built LanguageDetector (shared across passes to avoid repeated construction).
    pub language_detector: LanguageDetector,
    /// Cached SyscallSemantic classification for each unique callee name.
    /// Avoids repeated string matching in downstream passes.
    pub syscall_cache: HashMap<String, omniscope_semantics::SyscallSemantic>,
    /// Cached FunctionKind classification for each unique function name.
    /// Avoids repeated classify_function() calls in call_graph and other passes.
    pub function_kind_cache: HashMap<String, FunctionKind>,
}

/// Check if a function name is a language runtime intrinsic (cached version).
///
/// This is a copy of the function in call_graph.rs, used to avoid
/// importing it and creating a circular dependency.
fn is_runtime_intrinsic_cached(name: &str, language: Language) -> bool {
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
            name.starts_with("__cxxabiv1")
                || name.starts_with("__cxa_")
                || name.starts_with("__gxx_")
        }
        _ => false,
    }
}

/// Classify a function based on its name, declaration status, and language (cached version).
///
/// This is a copy of the function in call_graph.rs, used to pre-compute
/// function kinds during ModuleIndex construction.
fn classify_function_cached(name: &str, is_declaration: bool, language: Language) -> FunctionKind {
    // Known libc functions are trusted regardless of declaration status
    if is_libc(name) {
        return FunctionKind::LibC;
    }

    // Dangerous functions are always treated as potential FFI boundaries
    if is_dangerous(name) {
        return FunctionKind::ExternalUnknown;
    }

    // Language runtime intrinsics are external
    if is_runtime_intrinsic_cached(name, language) {
        return FunctionKind::ExternalUnknown;
    }

    // Functions with bodies are internal to the analyzed module
    if !is_declaration {
        return FunctionKind::Internal;
    }

    // Declarations without bodies: could be external FFI targets
    FunctionKind::ExternalUnknown
}

/// Check if a function is Zig runtime internal.
///
/// This includes Zig standard library, compiler runtime, allocator glue,
/// and other runtime initialization paths that should be suppressed in
/// WriteToImmutable analysis to reduce false positives.
fn is_zig_runtime_internal(name: &str, language: Language) -> bool {
    // Only apply to Zig functions
    if language != Language::Zig {
        return false;
    }

    // Zig standard library functions (std.*)
    if name.starts_with("std.") {
        return true;
    }

    // Zig builtin functions (use precise prefix to avoid matching user code)
    if name.starts_with("builtin.") {
        return true;
    }

    // Zig compiler runtime (use precise prefix to avoid matching user code)
    if name.starts_with("compiler_rt.") || name == "compiler_rt" {
        return true;
    }

    // Zig allocator vtable and runtime glue
    if name.starts_with("zig_allocator_") {
        return true;
    }

    // Zig runtime initialization and glue
    if name.starts_with("zig.") {
        return true;
    }

    // Zig heap management functions
    if name.starts_with("zig.heap.") {
        return true;
    }

    // Zig memory management functions
    if name.starts_with("zig.mem.") {
        return true;
    }

    false
}

impl ModuleIndex {
    /// Builds a `ModuleIndex` from an `IRModule`.
    ///
    /// This performs a single traversal of the module's calls, functions,
    /// and declarations, pre-computing all commonly needed metadata.
    pub fn build(module: &IRModule) -> Self {
        let detector = LanguageDetector::new();
        let registry = FamilyRegistry::new();

        let total_call_count = module.calls.len();
        let total_instruction_count: usize = module
            .function_bodies
            .values()
            .map(|body| body.instructions.len())
            .sum();

        // Pre-compute call metadata
        let mut call_metas: Vec<CachedCallMeta> = Vec::with_capacity(total_call_count);
        let mut callee_callers: HashMap<String, Vec<usize>> = HashMap::new();
        let mut caller_calls: HashMap<String, Vec<usize>> = HashMap::new();

        for (idx, call) in module.calls.iter().enumerate() {
            let callee_name = call.callee.trim_start_matches('@').to_string();
            let caller_name = call.caller.trim_start_matches('@').to_string();

            let callee_lang = detector.detect_from_function(&callee_name);
            // Apply C-fallback for defined functions: if caller is a defined
            // function and its language is Unknown, default to C (common case
            // for .ll files from C source). This matches the original
            // FFIBoundaryPass behavior.
            let raw_caller_lang = detector.detect_from_function(&caller_name);
            let caller_lang = if raw_caller_lang == Language::Unknown
                && (module.functions.contains_key(call.caller.as_str())
                    || module.functions.contains_key(&call.caller))
            {
                Language::C
            } else {
                raw_caller_lang
            };

            let is_llvm_intrinsic = callee_name.starts_with("llvm.");
            let is_cpp_mangled = callee_name.starts_with("_Z");

            let lookup = registry.lookup(&callee_name);
            let symbol_effect = lookup.map(|e| e.effect);
            let family_id = lookup.map(|e| e.family_id);

            let is_alloc_call = matches!(
                symbol_effect,
                Some(
                    omniscope_semantics::SymbolEffect::Acquire
                        | omniscope_semantics::SymbolEffect::Retain
                        | omniscope_semantics::SymbolEffect::Reclaim
                )
            );
            let is_dealloc_call = matches!(
                symbol_effect,
                Some(
                    omniscope_semantics::SymbolEffect::Release
                        | omniscope_semantics::SymbolEffect::ConditionalRelease
                )
            );

            let is_cross_language = caller_lang != Language::Unknown
                && callee_lang != Language::Unknown
                && caller_lang != callee_lang;

            // FFI boundary determination:
            // 1. Both langs known and different (cross-language)
            // 2. C++ mangled name called from C
            // 3. Non-C language calling external unknown function (likely C)
            let is_ffi_boundary = (is_cross_language
                || (is_cpp_mangled && caller_lang == Language::C)
                || (caller_lang != Language::Unknown
                    && caller_lang != Language::C
                    && callee_lang == Language::Unknown
                    && call.is_external))
            // Filter out LLVM intrinsics
            && !is_llvm_intrinsic;

            call_metas.push(CachedCallMeta {
                call_index: idx,
                caller_name: caller_name.clone(),
                callee_name: callee_name.clone(),
                is_external: call.is_external,
                caller_lang,
                callee_lang,
                is_llvm_intrinsic,
                is_cpp_mangled,
                is_alloc_call,
                is_dealloc_call,
                symbol_effect,
                family_id,
                is_cross_language,
                is_ffi_boundary,
            });

            callee_callers
                .entry(callee_name.clone())
                .or_default()
                .push(idx);
            caller_calls
                .entry(caller_name.clone())
                .or_default()
                .push(idx);
        }

        // Pre-compute function metadata
        let mut function_metas: HashMap<String, CachedFunctionMeta> = HashMap::new();

        // Defined functions
        for (name, func) in &module.functions {
            let trimmed = name.trim_start_matches('@').to_string();
            // Apply C-fallback for defined functions
            let raw_language = detector.detect_from_function(&trimmed);
            let language = if raw_language == Language::Unknown {
                Language::C
            } else {
                raw_language
            };
            let calls = caller_calls.get(&trimmed);
            let call_count = calls.map(|c| c.len()).unwrap_or(0);
            let has_calls = call_count > 0;

            let calls_alloc = calls
                .map(|indices| indices.iter().any(|&idx| call_metas[idx].is_alloc_call))
                .unwrap_or(false);

            let calls_dealloc = calls
                .map(|indices| indices.iter().any(|&idx| call_metas[idx].is_dealloc_call))
                .unwrap_or(false);

            let has_ffi_calls = calls
                .map(|indices| indices.iter().any(|&idx| call_metas[idx].is_ffi_boundary))
                .unwrap_or(false);

            let has_stores = module
                .function_bodies
                .get(&trimmed)
                .map(|body| {
                    body.instructions
                        .iter()
                        .any(|i| i.kind == omniscope_ir::IRInstructionKind::Store)
                })
                .unwrap_or(false);

            // Check if this function is Zig runtime internal
            let is_runtime_internal = is_zig_runtime_internal(&trimmed, language);

            function_metas.insert(
                trimmed.clone(),
                CachedFunctionMeta {
                    name: trimmed,
                    language,
                    is_declaration: false,
                    param_count: func.params.len(),
                    has_calls,
                    call_count,
                    calls_alloc,
                    calls_dealloc,
                    has_ffi_calls,
                    has_stores,
                    is_runtime_internal,
                },
            );
        }

        // Declarations
        for (name, func) in &module.declarations {
            let trimmed = name.trim_start_matches('@').to_string();
            let language = detector.detect_from_function(&trimmed);
            let calls = caller_calls.get(&trimmed);
            let call_count = calls.map(|c| c.len()).unwrap_or(0);

            // Check if this function is Zig runtime internal
            let is_runtime_internal = is_zig_runtime_internal(&trimmed, language);

            function_metas.insert(
                trimmed.clone(),
                CachedFunctionMeta {
                    name: trimmed,
                    language,
                    is_declaration: true,
                    param_count: func.params.len(),
                    has_calls: call_count > 0,
                    call_count,
                    calls_alloc: false,
                    calls_dealloc: false,
                    has_ffi_calls: false,
                    has_stores: false,
                    is_runtime_internal,
                },
            );
        }

        // Collect functions with specific properties
        let ffi_caller_functions: Vec<String> = function_metas
            .values()
            .filter(|m| m.has_ffi_calls)
            .map(|m| m.name.clone())
            .collect();

        let alloc_caller_functions: Vec<String> = function_metas
            .values()
            .filter(|m| m.calls_alloc)
            .map(|m| m.name.clone())
            .collect();

        // Pre-compute SyscallSemantic classification for each unique callee name.
        // This avoids repeated string matching in downstream passes (semantic tree,
        // FFI boundary detection, etc.).
        let mut syscall_cache: HashMap<String, omniscope_semantics::SyscallSemantic> =
            HashMap::new();
        for call_meta in &call_metas {
            syscall_cache
                .entry(call_meta.callee_name.clone())
                .or_insert_with(|| {
                    omniscope_semantics::SyscallSemantic::classify(&call_meta.callee_name)
                });
        }

        // Pre-compute FunctionKind classification for each unique function name.
        // This avoids repeated classify_function() calls in call_graph and other passes.
        let mut function_kind_cache: HashMap<String, FunctionKind> = HashMap::new();
        for (name, meta) in &function_metas {
            let kind = classify_function_cached(name, meta.is_declaration, meta.language);
            function_kind_cache.insert(name.clone(), kind);
        }

        Self {
            call_metas,
            function_metas,
            callee_callers,
            caller_calls,
            ffi_caller_functions,
            alloc_caller_functions,
            total_instruction_count,
            total_call_count,
            family_registry: registry,
            language_detector: detector,
            syscall_cache,
            function_kind_cache,
        }
    }

    /// Returns all FFI boundary calls.
    pub fn ffi_boundary_calls(&self) -> impl Iterator<Item = &CachedCallMeta> {
        self.call_metas.iter().filter(|m| m.is_ffi_boundary)
    }

    /// Returns all allocation calls.
    pub fn alloc_calls(&self) -> impl Iterator<Item = &CachedCallMeta> {
        self.call_metas.iter().filter(|m| m.is_alloc_call)
    }

    /// Returns all deallocation calls.
    pub fn dealloc_calls(&self) -> impl Iterator<Item = &CachedCallMeta> {
        self.call_metas.iter().filter(|m| m.is_dealloc_call)
    }

    /// Returns calls made by a specific caller function.
    pub fn calls_by_caller(&self, caller: &str) -> &[usize] {
        self.caller_calls
            .get(caller)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns all callers of a specific callee function.
    pub fn callers_of(&self, callee: &str) -> &[usize] {
        self.callee_callers
            .get(callee)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns the function profile for a given function name.
    pub fn function_meta(&self, name: &str) -> Option<&CachedFunctionMeta> {
        self.function_metas.get(name.trim_start_matches('@'))
    }

    /// Returns all function profiles that have FFI calls.
    pub fn ffi_functions(&self) -> &[String] {
        &self.ffi_caller_functions
    }

    /// Returns all function profiles that call allocation functions.
    pub fn alloc_functions(&self) -> &[String] {
        &self.alloc_caller_functions
    }

    /// Returns the cached SyscallSemantic classification for a callee name.
    ///
    /// This avoids repeated string matching in downstream passes.
    /// Returns `SyscallSemantic::Unknown` if the callee is not in the cache.
    pub fn syscall_semantic(&self, callee: &str) -> omniscope_semantics::SyscallSemantic {
        self.syscall_cache
            .get(callee.trim_start_matches('@'))
            .copied()
            .unwrap_or(omniscope_semantics::SyscallSemantic::Unknown)
    }

    /// Returns the cached FunctionKind classification for a function name.
    ///
    /// This avoids repeated classify_function() calls in downstream passes.
    /// Returns `None` if the function is not in the cache.
    pub fn function_kind(&self, name: &str) -> Option<FunctionKind> {
        self.function_kind_cache
            .get(name.trim_start_matches('@'))
            .copied()
    }

    /// Returns whether a callee is a known allocation function (cached).
    pub fn is_alloc_function(&self, callee: &str) -> bool {
        matches!(
            self.syscall_semantic(callee),
            omniscope_semantics::SyscallSemantic::MemoryManagement
        )
    }

    /// Returns whether a callee involves memory ownership (cached).
    pub fn involves_memory_ownership(&self, callee: &str) -> bool {
        self.syscall_semantic(callee).involves_memory_ownership()
    }

    /// Returns whether a function is runtime internal (cached).
    ///
    /// This avoids repeated string matching in downstream passes.
    /// Returns `false` if the function is not in the cache.
    pub fn is_runtime_internal(&self, name: &str) -> bool {
        self.function_metas
            .get(name.trim_start_matches('@'))
            .map(|meta| meta.is_runtime_internal)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_ir::{CallInstruction, Function, IRModule};

    fn create_test_module() -> IRModule {
        let mut module = IRModule::new();

        // Add a function definition
        module.functions.insert(
            "@test_func".to_string(),
            Function {
                name: "test_func".to_string(),
                is_declaration: false,
                params: vec!["i32".to_string()],
                return_type: "void".to_string(),
            },
        );

        // Add a declaration
        module.declarations.insert(
            "@malloc".to_string(),
            Function {
                name: "malloc".to_string(),
                is_declaration: true,
                params: vec!["i64".to_string()],
                return_type: "ptr".to_string(),
            },
        );

        // Add call instructions
        module.calls.push(CallInstruction {
            callee: "@malloc".to_string(),
            caller: "@test_func".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });
        module.calls.push(CallInstruction {
            callee: "@free".to_string(),
            caller: "@test_func".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });

        module
    }

    /// Objective: Verify that ModuleIndex::build correctly caches call metadata.
    /// Invariants: call_metas length matches module.calls length.
    #[test]
    fn test_module_index_build() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);

        assert_eq!(
            index.call_metas.len(),
            2,
            "ModuleIndex must cache metadata for all 2 call instructions"
        );
        assert_eq!(index.total_call_count, 2, "Total call count must be 2");
    }

    /// Objective: Verify that caller/callee indexing works correctly.
    /// Invariants: caller_calls maps caller to correct call indices.
    #[test]
    fn test_caller_callee_indexing() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);

        let test_func_calls = index.calls_by_caller("test_func");
        assert_eq!(
            test_func_calls.len(),
            2,
            "test_func must have 2 call instructions"
        );

        let malloc_callers = index.callers_of("malloc");
        assert_eq!(
            malloc_callers.len(),
            1,
            "malloc must be called from 1 call site"
        );
    }

    /// Objective: Verify that allocation/deallocation detection works.
    /// Invariants: malloc is detected as alloc, free as dealloc.
    #[test]
    fn test_alloc_dealloc_detection() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);

        let alloc_calls: Vec<_> = index.alloc_calls().collect();
        assert!(
            !alloc_calls.is_empty(),
            "Must detect at least 1 allocation call (malloc)"
        );

        let dealloc_calls: Vec<_> = index.dealloc_calls().collect();
        assert!(
            !dealloc_calls.is_empty(),
            "Must detect at least 1 deallocation call (free)"
        );
    }

    /// Objective: Verify that function metadata includes alloc/dealloc call tracking.
    /// Invariants: test_func profile shows calls_alloc=true, calls_dealloc=true.
    #[test]
    fn test_function_meta() {
        let module = create_test_module();
        let index = ModuleIndex::build(&module);

        let profile = index
            .function_meta("test_func")
            .expect("test_func must have a cached profile");

        assert_eq!(
            profile.language,
            Language::C,
            "test_func must be detected as C"
        );
        assert!(profile.calls_alloc, "test_func must call alloc functions");
        assert!(
            profile.calls_dealloc,
            "test_func must call dealloc functions"
        );
        assert_eq!(profile.call_count, 2, "test_func must have 2 calls");
    }

    /// Objective: Verify that LLVM intrinsic detection works.
    /// Invariants: llvm.* calls are marked as is_llvm_intrinsic.
    #[test]
    fn test_llvm_intrinsic_detection() {
        let mut module = IRModule::new();
        module.calls.push(CallInstruction {
            callee: "@llvm.lifetime.start".to_string(),
            caller: "@test".to_string(),
            is_external: false,
            location: None,
            args: Vec::new(),
            result: None,
        });

        let index = ModuleIndex::build(&module);
        assert!(
            index.call_metas[0].is_llvm_intrinsic,
            "llvm.lifetime.start must be detected as LLVM intrinsic"
        );
    }

    /// Objective: Verify that C++ mangled name detection works.
    /// Invariants: _Z prefixed names are detected as C++ mangled.
    #[test]
    fn test_cpp_mangled_detection() {
        let mut module = IRModule::new();
        module.calls.push(CallInstruction {
            callee: "@_ZdlPv".to_string(),
            caller: "@test".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });

        let index = ModuleIndex::build(&module);
        assert!(
            index.call_metas[0].is_cpp_mangled,
            "_ZdlPv must be detected as C++ mangled"
        );
    }

    /// Objective: Verify that module with no calls produces empty index.
    /// Invariants: Empty module produces zero-length call_metas without panic.
    #[test]
    fn test_empty_module_index() {
        let module = IRModule::new();
        let index = ModuleIndex::build(&module);

        assert!(
            index.call_metas.is_empty(),
            "Empty module must produce empty call_metas"
        );
        assert!(
            index.function_metas.is_empty(),
            "Empty module must produce empty function_metas"
        );
    }

    /// Objective: Verify that cross-language detection works correctly.
    /// Invariants: C function calling Rust function is detected as cross-language.
    #[test]
    fn test_cross_language_detection() {
        let mut module = IRModule::new();

        // Add a C-style function
        module.functions.insert(
            "@c_func".to_string(),
            Function {
                name: "c_func".to_string(),
                is_declaration: false,
                params: vec![],
                return_type: "void".to_string(),
            },
        );

        // Add a Rust-style function call (Rust mangled names start with _ZN)
        module.calls.push(CallInstruction {
            callee: "@_ZN3foo3bar17h1234567890abcdefE".to_string(),
            caller: "@c_func".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });

        let index = ModuleIndex::build(&module);

        // The caller is C, callee is detected as Rust
        // This should be detected as cross-language
        assert!(
            index.call_metas[0].is_cross_language || index.call_metas[0].is_ffi_boundary,
            "C calling Rust must be detected as cross-language or FFI boundary"
        );
    }

    /// Objective: Verify that ffi_functions() returns functions with FFI calls.
    /// Invariants: Functions calling cross-language functions appear in ffi_functions.
    #[test]
    fn test_ffi_functions_list() {
        let mut module = IRModule::new();

        module.functions.insert(
            "@caller".to_string(),
            Function {
                name: "caller".to_string(),
                is_declaration: false,
                params: vec![],
                return_type: "void".to_string(),
            },
        );

        module.calls.push(CallInstruction {
            callee: "@_ZN3foo3bar17h1234567890abcdefE".to_string(),
            caller: "@caller".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });

        let index = ModuleIndex::build(&module);
        let ffi_funcs = index.ffi_functions();

        assert!(
            !ffi_funcs.is_empty(),
            "Must detect at least 1 function with FFI calls"
        );
    }

    /// Objective: Verify that is_zig_runtime_internal correctly identifies Zig runtime functions.
    /// Invariants: Zig stdlib, builtin, compiler_rt, and allocator functions are detected.
    #[test]
    fn test_is_zig_runtime_internal() {
        // Zig standard library functions
        assert!(
            is_zig_runtime_internal("std.mem.Allocator", Language::Zig),
            "std.mem.Allocator must be Zig runtime internal"
        );
        assert!(
            is_zig_runtime_internal("std.heap.page_allocator", Language::Zig),
            "std.heap.page_allocator must be Zig runtime internal"
        );
        assert!(
            is_zig_runtime_internal("std.math.log2", Language::Zig),
            "std.math.log2 must be Zig runtime internal"
        );

        // Zig builtin functions
        assert!(
            is_zig_runtime_internal("builtin.mul", Language::Zig),
            "builtin.mul must be Zig runtime internal"
        );
        assert!(
            is_zig_runtime_internal("zig.builtin.add", Language::Zig),
            "zig.builtin.add must be Zig runtime internal"
        );

        // Zig compiler runtime
        assert!(
            is_zig_runtime_internal("compiler_rt.add", Language::Zig),
            "compiler_rt.add must be Zig runtime internal"
        );

        // Zig allocator vtable
        assert!(
            is_zig_runtime_internal("zig_allocator_allocImpl", Language::Zig),
            "zig_allocator_allocImpl must be Zig runtime internal"
        );
        assert!(
            is_zig_runtime_internal("zig_allocator_freeImpl", Language::Zig),
            "zig_allocator_freeImpl must be Zig runtime internal"
        );

        // Zig runtime functions
        assert!(
            is_zig_runtime_internal("zig.heap.page_allocator", Language::Zig),
            "zig.heap.page_allocator must be Zig runtime internal"
        );
        assert!(
            is_zig_runtime_internal("zig.mem.Allocator", Language::Zig),
            "zig.mem.Allocator must be Zig runtime internal"
        );

        // Non-Zig functions should not be detected
        assert!(
            !is_zig_runtime_internal("std::vector", Language::Cpp),
            "C++ std::vector must not be Zig runtime internal"
        );
        assert!(
            !is_zig_runtime_internal("_ZN4core3str4len", Language::Rust),
            "Rust function must not be Zig runtime internal"
        );
        assert!(
            !is_zig_runtime_internal("malloc", Language::C),
            "C malloc must not be Zig runtime internal"
        );

        // User Zig functions should not be detected
        assert!(
            !is_zig_runtime_internal("my_function", Language::Zig),
            "User Zig function must not be Zig runtime internal"
        );
        assert!(
            !is_zig_runtime_internal("main", Language::Zig),
            "main function must not be Zig runtime internal"
        );
    }

    /// Objective: Verify that ModuleIndex caches is_runtime_internal correctly.
    /// Invariants: Zig runtime functions have is_runtime_internal=true in cached metadata.
    #[test]
    fn test_module_index_runtime_internal_cache() {
        let mut module = IRModule::new();

        // Add a Zig runtime function with explicit Zig prefix
        module.functions.insert(
            "@zig.mem.Allocator".to_string(),
            Function {
                name: "zig.mem.Allocator".to_string(),
                is_declaration: false,
                params: vec![],
                return_type: "void".to_string(),
            },
        );

        // Add a Zig allocator function
        module.functions.insert(
            "@zig_allocator_allocImpl".to_string(),
            Function {
                name: "zig_allocator_allocImpl".to_string(),
                is_declaration: false,
                params: vec![],
                return_type: "void".to_string(),
            },
        );

        // Add a user function
        module.functions.insert(
            "@my_function".to_string(),
            Function {
                name: "my_function".to_string(),
                is_declaration: false,
                params: vec![],
                return_type: "void".to_string(),
            },
        );

        let index = ModuleIndex::build(&module);

        // Check that runtime internal is cached correctly
        assert!(
            index.is_runtime_internal("zig.mem.Allocator"),
            "zig.mem.Allocator must be cached as runtime internal"
        );
        assert!(
            index.is_runtime_internal("zig_allocator_allocImpl"),
            "zig_allocator_allocImpl must be cached as runtime internal"
        );
        assert!(
            !index.is_runtime_internal("my_function"),
            "my_function must not be cached as runtime internal"
        );

        // Check function_meta returns correct is_runtime_internal
        let zig_runtime_meta = index
            .function_meta("zig.mem.Allocator")
            .expect("zig.mem.Allocator must have cached profile");
        assert!(
            zig_runtime_meta.is_runtime_internal,
            "zig.mem.Allocator profile must have is_runtime_internal=true"
        );

        let zig_allocator_meta = index
            .function_meta("zig_allocator_allocImpl")
            .expect("zig_allocator_allocImpl must have cached profile");
        assert!(
            zig_allocator_meta.is_runtime_internal,
            "zig_allocator_allocImpl profile must have is_runtime_internal=true"
        );

        let user_func_meta = index
            .function_meta("my_function")
            .expect("my_function must have cached profile");
        assert!(
            !user_func_meta.is_runtime_internal,
            "my_function profile must have is_runtime_internal=false"
        );
    }
}
