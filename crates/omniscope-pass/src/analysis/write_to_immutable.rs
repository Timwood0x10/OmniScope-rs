//! Write-to-immutable detection pass.
//!
//! This pass detects attempts to write to immutable memory locations,
//! which is a common source of undefined behavior in FFI code.
//!
//! The pass uses semantic tree analysis to suppress false positives:
//! - If the target has MutableParam semantic → not an error (R-0)
//! - If the target has InteriorMutability semantic → not an error (R-2)
//! - If the target is from a function parameter → not a stack escape (R-8)
//! - If the store targets local SSA value → not an error (R-10)
//! - If caller is C/C++ language → not an error (R-13, no immutability semantics)
//! - If caller is Rust arena/allocator internal → not an error (R-14)
//! - If caller is RawVec/buffer write pattern → not an error (R-15)

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::{Issue, IssueKind, Result, Severity};
use omniscope_semantics::{SemanticKind, SemanticResolution, SemanticTree};

/// Write-to-immutable detection pass.
///
/// Analyzes IR instructions to detect stores to immutable memory.
/// Uses semantic tree to suppress false positives based on R-0~R-8 patterns.
pub struct WriteToImmutablePass;

impl WriteToImmutablePass {
    /// Creates a new write-to-immutable detection pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for WriteToImmutablePass {
    fn name(&self) -> &'static str {
        "WriteToImmutable"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["RawFactCollector"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        // Get IR module for analysis
        let Some(module) = ctx.get_ir_module() else {
            return Ok(PassResult::new(self.name())
                .with_issues(0)
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64));
        };

        let mut issues = Vec::new();
        let mut nodes_analyzed = 0;

        // Build semantic tree for R-0~R-8 pattern suppression
        let mut semantic_tree = SemanticTree::new();

        // Collect store instructions with runtime internal flag (avoid borrow conflicts)
        // Use ModuleIndex for function pre-filtering (reference, no clone)
        let mut store_instructions = Vec::new();
        let mut runtime_internal_funcs = std::collections::HashSet::new();
        {
            let module_index: Option<&crate::module_index::ModuleIndex> =
                ctx.get_ref("module_index");

            for (func_name, body) in &module.function_bodies {
                // Use ModuleIndex to skip functions without store instructions
                // Also collect runtime internal function names
                if let Some(index) = module_index {
                    let trimmed_name = func_name.trim_start_matches('@');
                    if let Some(meta) = index.function_meta(trimmed_name) {
                        if meta.is_runtime_internal {
                            runtime_internal_funcs.insert(trimmed_name.to_string());
                        }
                        if !meta.has_stores {
                            continue;
                        }
                    }
                }

                for inst in body.instructions_of_kind(omniscope_ir::IRInstructionKind::Store) {
                    store_instructions.push((func_name.clone(), inst.clone()));
                }
            }
        } // Release immutable borrow on ctx here

        // Now process store instructions without borrow conflicts
        for (func_name, inst) in store_instructions {
            nodes_analyzed += 1;

            // Build a target symbol from the function name and store operands.
            // Use structured fields instead of raw_text to avoid ensure_raw() overhead.
            let operands_summary = inst.operands.join(" ");
            let target_symbol = format!("{}->store:{}", func_name, operands_summary);

            // Analyze the store target for semantic context.
            // Pass operands_summary instead of raw_text for structured field access.
            self.analyze_store_target(
                ctx,
                &mut semantic_tree,
                &target_symbol,
                &func_name,
                &operands_summary,
                &runtime_internal_funcs,
                &mut issues,
            );
        }

        // Store semantic tree for downstream passes
        ctx.store("write_to_immutable_tree", semantic_tree);

        let issues_found = issues.len();
        let mut result = PassResult::new(self.name())
            .with_issues(issues_found)
            .with_nodes(nodes_analyzed)
            .with_duration(start.elapsed().as_millis() as u64);

        for issue in issues {
            result.add_issue(issue);
        }

        Ok(result)
    }
}

impl WriteToImmutablePass {
    /// Analyzes a store instruction target for write-to-immutable violations.
    #[allow(clippy::too_many_arguments)]
    fn analyze_store_target(
        &self,
        ctx: &mut PassContext,
        semantic_tree: &mut SemanticTree,
        symbol: &str,
        caller: &str,
        callee: &str,
        runtime_internal_funcs: &std::collections::HashSet<String>,
        issues: &mut Vec<Issue>,
    ) {
        // Add semantic resolutions based on IR patterns

        // R-12: Check for runtime internal functions (suppresses false positives)
        // Runtime internal functions (compiler_rt, allocator glue, etc.)
        // should not be reported as WriteToImmutable violations.
        let trimmed_caller = caller.trim_start_matches('@');
        if runtime_internal_funcs.contains(trimmed_caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::RuntimeInternal,
                confidence: 0.95,
                evidence: "Function is runtime internal (stdlib/compiler_rt/allocator)".to_string(),
                pattern_id: "R-12",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - runtime internal function
        }

        // R-12b: C++ runtime/internal function patterns that commonly produce WTI FPs.
        // These include:
        //   - C++ exception handling (__cxa_*, __gxx_*)
        //   - C++ guard variables for thread-safe static initialization (__cxa_guard_*)
        //   - C++ RTTI functions (_ZTI*, _ZTS*, _ZTV*)
        //   - C++ file-scope static functions (_ZZ*)
        //   - C++ operator overloads (operator new, operator delete)
        if self.is_cpp_runtime_internal(caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::RuntimeInternal,
                confidence: 0.94,
                evidence: "C++ runtime/internal function (exception/guard/RTTI/operator)"
                    .to_string(),
                pattern_id: "R-12b",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - C++ runtime internal
        }

        // R-0: Check for mutable parameters (suppresses false positives)
        if self.is_mutable_parameter(caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::MutableParam,
                confidence: 0.95,
                evidence: "Function parameter lacks readonly attribute".to_string(),
                pattern_id: "R-0",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - parameter is mutable
        }

        // R-2: Check for interior mutability types (suppresses false positives)
        if self.has_interior_mutability(caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::InteriorMutability,
                confidence: 0.90,
                evidence: "Type contains UnsafeCell for interior mutability".to_string(),
                pattern_id: "R-2",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - interior mutability is safe
        }

        // R-8: Check for function parameters (suppresses false positives)
        if self.is_function_parameter(symbol) {
            let resolution = SemanticResolution {
                kind: SemanticKind::FromParameter,
                confidence: 0.95,
                evidence: "Target is a function parameter, not stack escape".to_string(),
                pattern_id: "R-8",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - parameter is caller-owned
        }

        // R-10: Check for stores to local SSA values (alloca'd stack
        // variables, function parameters, or heap pointers). In LLVM IR,
        // local SSA values (prefixed with `%`) are derived from alloca
        // instructions, function parameters, or heap allocations — none
        // of which are immutable. Truly immutable stores target global
        // constants (`@` prefixed with `constant` keyword).
        if self.is_store_to_local_ssa(callee) {
            let resolution = SemanticResolution {
                kind: SemanticKind::HeapProvenance,
                confidence: 0.90,
                evidence: "Store destination is a local SSA value (stack/param/heap)".to_string(),
                pattern_id: "R-10",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - local SSA values are mutable
        }

        // R-13: C/C++ callers have no immutability semantics.
        // In C, all struct fields are mutable by default — there is no
        // `const` qualifier at the IR level for struct field stores.
        // C++ has const-correctness but LLVM IR often loses it.
        // This suppresses the vast majority of FPs from C/C++ codebases.
        if self.is_c_or_cpp_caller(caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::RuntimeInternal,
                confidence: 0.92,
                evidence: "C/C++ caller: no immutability semantics at IR level".to_string(),
                pattern_id: "R-13",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - C has no immutable concept
        }

        // R-14: Rust arena/allocator internal functions.
        // Bun's allocator crate (bun_alloc), mimalloc arena wrappers,
        // ZAllocator, NullableAllocator, CAllocator, heap_breakdown,
        // bss_arena_bump, c_thunks — all use &self to write into
        // internal buffers via UnsafeCell interior mutability.
        // These are correct Rust FFI patterns, not bugs.
        if self.is_rust_allocator_internal(caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::InteriorMutability,
                confidence: 0.93,
                evidence:
                    "Rust allocator/arena internal function (UnsafeCell-based interior mutability)"
                        .to_string(),
                pattern_id: "R-14",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - allocator internals
        }

        // R-15: RawVec / buffer write patterns from Rust alloc crate.
        // RawVec::grow_one, RawVecInner::finish_grow, and similar
        // functions write to internally-managed buffers. These are
        // core alloc crate operations that are always safe.
        if self.is_raw_vec_or_buffer_write(caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::InteriorMutability,
                confidence: 0.91,
                evidence: "RawVec/buffer write (alloc crate internal)".to_string(),
                pattern_id: "R-15",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - alloc crate internal
        }

        // If none of the suppression patterns match, emit the issue
        let issue_id = ctx.next_issue_id();
        let location = omniscope_core::IssueLocation::new(std::path::PathBuf::from("<ffi>"), 0)
            .with_function(caller);
        let issue = Issue::new(
            issue_id,
            IssueKind::WriteToImmutable,
            Severity::Warning,
            format!(
                "Potential write to immutable memory: {} -> {} [symbol={}]",
                caller, callee, symbol
            ),
        )
        .with_symbol(symbol)
        .with_location(location);

        let outcome = ctx.emit_issue(issue.clone());
        if outcome.is_allowed() {
            issues.push(issue);
        }
    }

    /// Checks if a function parameter is mutable (has &mut indicator).
    fn is_mutable_parameter(&self, caller: &str) -> bool {
        // R-0: Rust mangled names with explicit mut reference pattern indicate mutable params.
        // Interior mutability (R-2) is a separate concept and is checked independently.
        caller.starts_with("_R") && caller.contains("mut")
    }

    /// Checks if a type has interior mutability (contains UnsafeCell).
    fn has_interior_mutability(&self, caller: &str) -> bool {
        // Check for interior mutability patterns in mangled names.
        // Use specific prefixes to avoid false matches (e.g. "Cell" matching "Cancel",
        // "sync" matching "async").
        caller.contains("UnsafeCell")
            || caller.contains("RefCell")
            || caller.contains("_Cell")
            || caller.contains("4Cell")
            || caller.contains("Mutex")
            || caller.contains("RwLock")
            || caller.contains("_sync")
            || caller.contains("4sync")
            || caller.contains("_atomic")
            || caller.contains("7atomic")
    }

    /// Checks if a symbol represents a function parameter.
    fn is_function_parameter(&self, symbol: &str) -> bool {
        // Heuristic: symbols containing function parameter patterns
        symbol.contains("param") || symbol.contains("arg") || symbol.contains("parameter")
    }

    /// Checks if a store instruction targets a local SSA value.
    ///
    /// In LLVM IR, store instructions have the form:
    /// ```text
    /// store <type> <value>, ptr <dest>, <attributes>
    /// ```
    ///
    /// If `<dest>` is a local SSA value (prefixed with `%`), the store
    /// targets stack memory (alloca), a function parameter, or a heap
    /// pointer — all of which are mutable. Truly immutable stores target
    /// global constants (`@` prefixed with `constant`).
    ///
    /// Uses structured operands field instead of raw text parsing to
    /// enable --no-raw mode support.
    fn is_store_to_local_ssa(&self, operands_summary: &str) -> bool {
        // Parse "store ..., ptr %N, ..." pattern from operands summary
        // The operands summary is space-separated operands from the instruction
        // Find "ptr " followed by the destination operand
        if let Some(ptr_pos) = operands_summary.find(" ptr ") {
            let after_ptr = &operands_summary[ptr_pos + 5..];
            // The destination operand follows "ptr "
            // It starts with "%" for local SSA values or "@" for globals
            let trimmed = after_ptr.trim_start();
            trimmed.starts_with('%')
        } else {
            // If we can't parse the store format, don't suppress
            false
        }
    }

    /// R-13: Checks if caller is a C or C++ function.
    ///
    /// C has no immutable memory concept — all struct field writes are
    /// valid by default. C++ has const-correctness but LLVM IR typically
    /// does not preserve it for struct field stores. This suppresses
    /// the majority of FPs from C/C++ codebases analyzed as FFI targets.
    fn is_c_or_cpp_caller(&self, caller: &str) -> bool {
        let trimmed = caller.trim_start_matches('@');
        // C functions: plain names (no Rust _R/_ZN prefix, no C++ _Z prefix),
        // or explicitly C-mangled names.
        // C++ functions: _Z prefixed (Itanium mangling).
        // Also catch common C library/pattern naming conventions.
        let is_plain_c =
            !trimmed.starts_with('_') || trimmed.starts_with("__") || trimmed.starts_with("_$"); // some LLVM-internal C symbols

        // C++ Itanium ABI mangling prefixes:
        //   _Z   - regular C++ function
        //   _ZZ  - C++ file-scope static function
        //   _ZTV - vtable
        //   _ZTI - typeinfo
        //   _ZTS - typeinfo name
        let is_cpp_mangled = trimmed.starts_with("_Z");

        // C++ standard library / runtime patterns in demangled or decorated names:
        //   std::      - C++ standard library namespace (demangled)
        //   __gnu_     - GCC/libstdc++ internal
        //   __cxx      - C++ ABI / libc++ internal
        //   operator   - C++ operator overload (e.g. "operator new", "operator delete")
        //   __cxa_     - Itanium C++ ABI exception handling
        //   __gxx_     - GCC C++ exception support
        let is_cpp_runtime = trimmed.contains("std::")
            || trimmed.contains("__gnu_")
            || trimmed.contains("__cxx")
            || trimmed.contains("operator")
            || trimmed.contains("__cxa_")
            || trimmed.contains("__gxx_");

        // Any name starting with '_' is assumed C++ unless it's Rust
        let is_cpp_by_convention = trimmed.starts_with('_');

        // Exclude Rust-mangled names (_R, _ZN)
        // Note: We check for "std::" (C++) BEFORE checking "std." —
        // a function name starting with "std." could be ambiguous, but
        // containing "std::" is treated as C++.
        let is_rust_only = trimmed.starts_with("_R") || trimmed.starts_with("_ZN");

        let is_cpp = is_cpp_mangled || is_cpp_runtime || is_cpp_by_convention;

        (is_plain_c || is_cpp) && !is_rust_only
    }

    /// R-12b: Checks if caller is a C++ runtime/internal function that
    /// commonly produces WriteToImmutable false positives.
    ///
    /// These patterns are not caught by the broader R-13 `is_c_or_cpp_caller`
    /// check because they often appear in partially-demangled form or use
    /// non-standard decoration. Examples:
    ///   - `__cxa_guard_acquire` / `__cxa_guard_release` (static init guards)
    ///   - `_ZTI*` / `_ZTS*` / `_ZTV*` (RTTI type info, vtable)
    ///   - `_ZZ*` (file-scope static functions inside functions)
    ///   - `operator new` / `operator delete` (C++ memory management)
    ///   - `__cxa_throw` / `__cxa_begin_catch` (exception handling)
    ///   - `__gnu_cxx::` / `std::` namespace functions
    fn is_cpp_runtime_internal(&self, caller: &str) -> bool {
        let trimmed = caller.trim_start_matches('@');

        // Itanium C++ ABI: vtable, typeinfo, typeinfo name, file-scope static
        let is_cpp_abi_special = trimmed.starts_with("_ZTI")
            || trimmed.starts_with("_ZTS")
            || trimmed.starts_with("_ZTV")
            || trimmed.starts_with("_ZZ");

        // C++ exception handling and guard functions
        let is_cpp_exception_guard = trimmed.contains("__cxa_") || trimmed.contains("__gxx_");

        // C++ operator overloads (demangled form in IR comments or metadata)
        let is_cpp_operator = trimmed.contains("operator new")
            || trimmed.contains("operator delete")
            || trimmed.contains("operator=")
            || trimmed.contains("operator+")
            || trimmed.contains("operator-");

        // C++ standard library internal (demangled forms)
        let is_cpp_stdlib_demangled = trimmed.contains("std::")
            || trimmed.contains("__gnu_cxx::")
            || trimmed.contains("__cxxabiv1::");

        // C++ static initialization guard variables (__tls_*, _GLOBAL__*)
        let is_cpp_static_init = trimmed.contains("_GLOBAL__")
            || trimmed.contains("__tls_")
            || trimmed.starts_with("_GLOBAL_")
            || trimmed.starts_with("__T");

        is_cpp_abi_special
            || is_cpp_exception_guard
            || is_cpp_operator
            || is_cpp_stdlib_demangled
            || is_cpp_static_init
    }

    /// R-14: Checks if caller is a Rust arena/allocator internal function.
    ///
    /// Bun's allocator crate (`bun_alloc` / `9bun_alloc`), mimalloc arena
    /// wrappers, ZAllocator, NullableAllocator, CAllocator, heap_breakdown,
    /// bss_arena_bump, c_thunks — all use `&self` to write into internal
    /// buffers via UnsafeCell interior mutability. These are correct Rust
    /// FFI patterns, not WriteToImmutable violations.
    fn is_rust_allocator_internal(&self, caller: &str) -> bool {
        // Bun's allocator crate (mangled name contains crate hash)
        caller.contains("9bun_alloc")
            || caller.contains("bun_alloc")
            // Mimalloc arena wrappers used in Bun
            || caller.contains("MimallocArena")
            || caller.contains("mimalloc_arena")
            || caller.contains("MiMallocArena")
            // ZAllocator (Bun's generic allocator wrapper)
            || caller.contains("ZAllocator")
            || caller.contains("zallocator")
            || caller.contains("5alloc") // alloc crate path segments
            // NullableAllocator
            || caller.contains("NullableAllocator")
            || caller.contains("nullable_allocator")
            // CAllocator
            || caller.contains("CAllocator")
            || caller.contains("c_allocator")
            // heap_breakdown module (Bun's zone/heap management)
            || caller.contains("heap_breakdown")
            || caller.contains("heap_break")
            // bss_arena_bump (Bun's BSS arena bump allocator)
            || caller.contains("bss_arena_bump")
            || caller.contains("BssArenaBump")
            // c_thunks module (mi_free_bytes, mi_free_opaque, mi_malloc_items)
            || caller.contains("c_thunks")
            || caller.contains("c_thunk")
            // Zone-based allocation (Bun's JS heap zones)
            || caller.contains("Zone")
            || caller.contains("4zone")
            // SliceCursor / Write trait impls writing to buffers
            || caller.contains("SliceCursor")
            || caller.contains("slice_cursor")
            || caller.contains("WritePtr")
            || caller.contains("write_ptr")
            // macOS malloc_zone APIs called from Rust
            || caller.contains("malloc_zone")
            || caller.contains("malloc_set_zone")
            || caller.contains("malloc_create_zone")
            || caller.contains("malloc_default_zone")
            || caller.contains("malloc_zone_memalign")
            // mimalloc API functions implemented/wrapped in Rust
            || caller.contains("mi_heap_new")
            || caller.contains("mi_heap_destroy")
            || caller.contains("mi_heap_visit")
            || caller.contains("mi_is_in_heap")
            || caller.contains("mi_malloc")
            || caller.contains("mi_free")
            || caller.contains("mi_realloc")
            // Generic allocator vtable methods
            || caller.contains("alloc_impl")
            || caller.contains("dealloc_impl")
            || caller.contains("grow_impl")
            || caller.contains("shrink_impl")
    }

    /// R-15: Checks if caller is a RawVec/buffer write pattern from alloc crate.
    ///
    /// RawVec::grow_one, RawVecInner::finish_grow, and similar functions
    /// write to internally-managed buffers that are always mutable.
    /// These are core alloc crate operations — never true WTI violations.
    fn is_raw_vec_or_buffer_write(&self, caller: &str) -> bool {
        caller.contains("RawVec")
            || caller.contains("raw_vec")
            || caller.contains("7raw_vec")
            || caller.contains("RawVecInner")
            || caller.contains("finish_grow")
            || caller.contains("grow_one")
            || caller.contains("allocate_one")
            || caller.contains("8allocate") // alloc::raw_vec::allocate etc.
            || caller.contains("6resize") // Vec::reserve/grow internals
    }
}

impl Default for WriteToImmutablePass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_to_immutable_pass_creation() {
        let pass = WriteToImmutablePass::new();
        assert_eq!(
            pass.name(),
            "WriteToImmutable",
            "Pass name should be WriteToImmutable"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Pass kind should be Analysis"
        );
    }

    #[test]
    fn test_is_mutable_parameter() {
        let pass = WriteToImmutablePass::new();
        // A Rust mangled name with "mut" and _R prefix is a mutable parameter
        assert!(
            pass.is_mutable_parameter("_RNvMNtCsg1bLsEOY8ZL_3foo3mut"),
            "Rust mangled name with mut must be mutable parameter"
        );
        // Cell type has interior mutability but is NOT a mutable parameter
        assert!(
            !pass.is_mutable_parameter("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell4Cell"),
            "Cell type is not a mutable parameter"
        );
        assert!(
            !pass.is_mutable_parameter("_RNvNtCsgXhsEb1m4tm_4core9panicking5panic_readonly"),
            "Readonly parameter must not be mutable"
        );
    }

    #[test]
    fn test_has_interior_mutability() {
        let pass = WriteToImmutablePass::new();
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell10UnsafeCell"),
            "UnsafeCell must have interior mutability"
        );
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell4Cell"),
            "std::cell::Cell must have interior mutability"
        );
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4sync5mutex"),
            "std::sync::Mutex must have interior mutability"
        );
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4sync7atomic"),
            "std::sync::atomic must have interior mutability"
        );
        assert!(
            !pass.has_interior_mutability("_RNvNtCsgXhsEb1m4tm_4core9panicking5panic"),
            "panicking must not have interior mutability"
        );
    }

    #[test]
    fn test_is_function_parameter() {
        let pass = WriteToImmutablePass::new();
        assert!(
            pass.is_function_parameter("func->param"),
            "func->param should be recognized as function parameter"
        );
        assert!(
            pass.is_function_parameter("func->arg"),
            "func->arg should be recognized as function parameter"
        );
        assert!(
            !pass.is_function_parameter("func->local"),
            "func->local should NOT be recognized as function parameter"
        );
    }

    /// Objective: Verify stores to local SSA values are suppressed.
    /// Invariants: Stores to `%` prefixed destinations (alloca, params, heap) must be suppressed.
    #[test]
    fn test_is_store_to_local_ssa() {
        let pass = WriteToImmutablePass::new();
        // Stores to local SSA values (alloca, function params, heap pointers)
        assert!(
            pass.is_store_to_local_ssa("store i8 -128, ptr %12, align 1, !tbaa !5"),
            "Store to alloca-derived %12 must be local SSA"
        );
        assert!(
            pass.is_store_to_local_ssa("store i8 %41, ptr %2, align 1, !tbaa !5"),
            "Store to function param %2 must be local SSA"
        );
        assert!(
            pass.is_store_to_local_ssa("store <8 x i8> %29, ptr %18, align 1, !tbaa !5"),
            "Store to GEP-derived %18 must be local SSA"
        );
        assert!(
            pass.is_store_to_local_ssa("store i32 %116, ptr %1, align 4, !tbaa !10"),
            "Store to param %1 must be local SSA"
        );
        // Stores to global constants are NOT local SSA
        assert!(
            !pass.is_store_to_local_ssa("store i32 42, ptr @global_const, align 4"),
            "Store to global @global_const must NOT be local SSA"
        );
    }

    /// Objective: Verify C/C++ callers are suppressed (R-13).
    /// Invariants: Plain C names and C++ mangled names match; Rust does not.
    #[test]
    fn test_is_c_or_cpp_caller() {
        let pass = WriteToImmutablePass::new();
        // Plain C functions — no underscore prefix (or __ / _$)
        assert!(
            pass.is_c_or_cpp_caller("malloc_zone_memalign"),
            "Plain C function must be C/C++ caller"
        );
        assert!(
            pass.is_c_or_cpp_caller("__stack_chk_fail"),
            "C runtime function with __ prefix must be C/C++ caller"
        );
        // C++ mangled names
        assert!(
            pass.is_c_or_cpp_caller("_ZdlPv"),
            "C++ _Z mangled name must be C/C++ caller"
        );
        // Rust-mangled names must NOT match
        assert!(
            !pass.is_c_or_cpp_caller("_RNvMNtCsg1bLsEOY8ZL_3foo3bar"),
            "Rust _R mangled must NOT be C/C++ caller"
        );
        assert!(
            !pass.is_c_or_cpp_caller("_ZN5alloc7raw_vec8allocate"),
            "Rust _ZN mangled must NOT be C/C++ caller"
        );
    }

    /// Objective: Verify Rust allocator internal functions are suppressed (R-14).
    /// Invariants: bun_alloc, MimallocArena, ZAllocator, etc. all match.
    #[test]
    fn test_is_rust_allocator_internal() {
        let pass = WriteToImmutablePass::new();
        // Bun's allocator crate
        assert!(
            pass.is_rust_allocator_internal("_RNvC9bun_alloc5heap_11Zone::allocate"),
            "bun_alloc Zone function must be allocator internal"
        );
        assert!(
            pass.is_rust_allocator_internal(
                "_RNvCs92_9bun_alloc_7abe075f8accee73_5alloc_8allocator9ZAllocator3alloc"
            ),
            "9bun_alloc crate hash must be allocator internal"
        );
        // Mimalloc arena wrappers
        assert!(
            pass.is_rust_allocator_internal("MimallocArena::allocate"),
            "MimallocArena must be allocator internal"
        );
        // ZAllocator
        assert!(
            pass.is_rust_allocator_internal("ZAllocator::alloc"),
            "ZAllocator must be allocator internal"
        );
        // NullableAllocator / CAllocator
        assert!(
            pass.is_rust_allocator_internal("NullableAllocator::alloc"),
            "NullableAllocator must be allocator internal"
        );
        assert!(
            pass.is_rust_allocator_internal("CAllocator::malloc"),
            "CAllocator must be allocator internal"
        );
        // heap_breakdown
        assert!(
            pass.is_rust_allocator_internal("heap_breakdown::record_alloc"),
            "heap_breakdown must be allocator internal"
        );
        // bss_arena_bump
        assert!(
            pass.is_rust_allocator_internal("bss_arena_bump::alloc"),
            "bss_arena_bump must be allocator internal"
        );
        // c_thunks
        assert!(
            pass.is_rust_allocator_internal("c_thunks::mi_free_bytes"),
            "c_thunks must be allocator internal"
        );
        // Zone-based allocation
        assert!(
            pass.is_rust_allocator_internal("Zone::malloc"),
            "Zone must be allocator internal"
        );
        // SliceCursor / WritePtr
        assert!(
            pass.is_rust_allocator_internal("SliceCursor::write_bytes"),
            "SliceCursor must be allocator internal"
        );
        // macOS malloc_zone APIs
        assert!(
            pass.is_rust_allocator_internal("malloc_set_zone_name"),
            "malloc_set_zone_name must be allocator internal"
        );
        // mimalloc API wrapped in Rust
        assert!(
            pass.is_rust_allocator_internal("mi_heap_new"),
            "mi_heap_new must be allocator internal"
        );
        // Non-allocator Rust function must NOT match
        assert!(
            !pass.is_rust_allocator_internal("_RNvNtCsgXhsEb1m4tm_4core9panicking5panic"),
            "Core panic must NOT be allocator internal"
        );
    }

    /// Objective: Verify RawVec/buffer write patterns are suppressed (R-15).
    /// Invariants: RawVec, raw_vec, finish_grow, grow_one all match.
    #[test]
    fn test_is_raw_vec_or_buffer_write() {
        let pass = WriteToImmutablePass::new();
        assert!(
            pass.is_raw_vec_or_buffer_write("_ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$8grow_one"),
            "RawVec::grow_one must be buffer write pattern"
        );
        assert!(
            pass.is_raw_vec_or_buffer_write("_ZN5alloc7raw_vec12RawVecInner10finish_grow"),
            "RawVecInner::finish_grow must be buffer write pattern"
        );
        assert!(
            pass.is_raw_vec_or_buffer_write("raw_vec::allocate_one"),
            "raw_vec allocate must be buffer write pattern"
        );
        // Non-RawVec function must NOT match
        assert!(
            !pass.is_raw_vec_or_buffer_write("_RNvNtCsgXhsEb1m4tm_4core9panicking5panic"),
            "Core panic must NOT be RawVec pattern"
        );
    }
}
