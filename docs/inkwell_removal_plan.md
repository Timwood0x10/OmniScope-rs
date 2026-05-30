# Phase 4: inkwell Removal Plan

## Overview

Remove the `inkwell` dependency and all dead code that depends on it.
The real IR pipeline uses `IRModule::load_from_file` and `IRModule::parse_from_text` (in `parser.rs`), which parse LLVM IR text directly and never touch inkwell.
The inkwell-dependent modules (`loader.rs`, `safe_wrappers.rs`, `view.rs`, `debug_info.rs`) are unused stubs or wrappers that no downstream crate calls.

---

## 1. Files to Delete

| File | Reason |
|------|--------|
| `crates/omniscope-ir/src/loader.rs` | `IRLoader` is a TODO stub. `load_from_file` never actually loads a module -- it just validates the file extension and stores the path. The real loading path is `IRModule::load_from_file` in `parser.rs`. |
| `crates/omniscope-ir/src/safe_wrappers.rs` | `SafeFunction`, `SafeBasicBlock`, `SafeInstruction` wrap `inkwell` types. No code outside this file references them. |
| `crates/omniscope-ir/src/view.rs` | `FunctionView`, `BasicBlockView`, `InstructionView`, `ModuleView` depend on `safe_wrappers` and `inkwell::module::Module`. No code outside this file references them. |
| `crates/omniscope-ir/src/debug_info.rs` | `DebugInfoExtractor::extract_location` always returns `None`. `TypeInfo` is defined here but never used outside this file. Both methods that take `inkwell::values::InstructionValue` are dead code. |
| `crates/omniscope-ir/src/platform.rs` | `Platform`, `Architecture`, `PlatformInfo`, `PlatformFilterRegistry` are never used by any downstream crate. All references are self-contained within this file (tests, doc examples). |

---

## 2. Changes to `crates/omniscope-ir/src/lib.rs`

Remove the following module declarations (lines 24-31 currently):

```rust
// REMOVE these lines:
pub mod debug_info;
pub mod loader;
pub mod platform;
pub mod safe_wrappers;
pub mod view;
```

Remove the following re-exports (lines 34-42 currently):

```rust
// REMOVE these lines:
pub use debug_info::{DebugInfoExtractor, TypeInfo};
pub use loader::IRLoader;
pub use platform::{Architecture, Platform, PlatformFilterRegistry, PlatformInfo};
pub use safe_wrappers::{SafeBasicBlock, SafeFunction, SafeInstruction};
pub use view::{BasicBlockView, FunctionView, InstructionView, ModuleView};
```

Remove the doc example that references `IRLoader` (lines 17-21):

```rust
// REMOVE:
//! ```rust,no_run
//! use omniscope_ir::IRLoader;
//! use std::path::Path;
//!
//! let mut loader = IRLoader::new();
//! // loader.load_from_file(Path::new("test.ll")).unwrap();
//! ```
```

Remove the test that creates `IRLoader` and `DebugInfoExtractor` (lines 49-52):

```rust
// REMOVE:
        let _loader = IRLoader::new();
        let _debug_info = DebugInfoExtractor::new();
```

Update the module-level doc comment to remove mentions of:
- "IR loading from .ll and .bc files" (this is handled by `parser.rs`, not the deleted `loader.rs`)
- "Safe wrappers for LLVM types"
- "Debug information extraction"
- "IR view abstractions"
- "Platform-specific filtering"

**Keep** these modules and re-exports:

```rust
pub mod instruction_parser;
pub mod llvm_ir_adapter;   // new llvm-ir adapter (no inkwell dependency)
pub mod location;
pub mod parser;

pub use location::{LocationManager, SourceLocation};
pub use parser::{
    CallInstruction, Function, FunctionBody, IRInstruction, IRInstructionKind, IRModule,
};
```

After removal, the `lib.rs` test `test_ir_module_exports` should still compile -- `LocationManager::new()` remains valid.

---

## 3. Cargo.toml Dependency Changes

### Workspace root `Cargo.toml`

Remove line 53:

```toml
# REMOVE:
inkwell = { version = "0.9.0", features = ["llvm12-0"] }
```

### `crates/omniscope-ir/Cargo.toml`

Remove line 17:

```toml
# REMOVE:
inkwell = { workspace = true }
```

Keep `tempfile` in `[dependencies]` -- it is used at runtime by `llvm_ir_adapter.rs` (the new llvm-ir adapter, which writes IR content to a temp file for parsing). Also keep it in `[dev-dependencies]` for test usage.

---

## 4. Tests Affected

### Tests that will be DELETED with their files:

| File | Tests |
|------|-------|
| `crates/omniscope-ir/src/loader.rs` | `test_loader_creation`, `test_load_nonexistent_file`, `test_invalid_extension`, `test_valid_extension` |
| `crates/omniscope-ir/src/debug_info.rs` | `test_debug_info_extractor_creation`, `test_type_info_creation` |
| `crates/omniscope-ir/src/platform.rs` | `test_platform_detection_macos`, `test_platform_detection_linux`, `test_platform_detection_windows_one`, `test_platform_detection_windows`, `test_platform_detection_aarch64`, `test_platform_detection_linux_gnu`, `test_macos_zone_allocator_safe`, `test_linux_glibc_safe`, `test_windows_heap_safe`, `test_cross_platform_safe`, `test_dangerous_ffi_not_safe` |

### Tests that need MIGRATION:

| File | Issue | Fix |
|------|-------|-----|
| `crates/omniscope-ir/src/lib.rs` (`test_ir_module_exports`) | References `IRLoader::new()` and `DebugInfoExtractor::new()` | Remove those two lines; keep `LocationManager::new()` |
| `tests/corpus_regression.rs` | Imports and uses `IRLoader` (line 15, 77-78). The loader is used only as a file existence check -- the module is never passed to the pipeline. | Replace `IRLoader::new()` + `loader.load_from_file(path)` with `IRModule::load_from_file(path)`. The loaded module is not used further (the pipeline reads from its own config), so the loaded `IRModule` can be discarded. Change import from `use omniscope_ir::IRLoader` to `use omniscope_ir::IRModule`. |

### Tests that are UNAFFECTED:

All other test files (`integration_tests.rs`, `ffi_analysis_tests.rs`, `corpus_tests.rs`, `corpus_detection_audit.rs`, and all tests under `crates/omniscope-pass/` and `crates/omniscope-semantics/`) use only `IRModule`, `CallInstruction`, `FunctionBody`, `IRInstruction`, `IRInstructionKind` -- all from `parser.rs`. They are not affected.

---

## 5. Search Results: inkwell in Test Code

No test code outside the five files being deleted references `inkwell` types directly. The only test files that reference types from the deleted modules are:

- `crates/omniscope-ir/src/lib.rs` test -- references `IRLoader` and `DebugInfoExtractor` (must be updated)
- `tests/corpus_regression.rs` -- references `IRLoader` (must be migrated)

---

## 6. New `IRModule` API (Post-Removal)

The public API of `omniscope-ir` after removal:

```rust
// Modules
pub mod instruction_parser;
pub mod llvm_ir_adapter;
pub mod location;
pub mod parser;

// Re-exports from location.rs
pub use location::{LocationManager, SourceLocation};

// Re-exports from parser.rs
pub use parser::{
    CallInstruction,
    Function,
    FunctionBody,
    IRInstruction,
    IRInstructionKind,
    IRModule,
};
```

`IRModule` provides the full loading API (no inkwell needed):

```rust
impl IRModule {
    pub fn new() -> Self;
    pub fn load_from_file(path: &Path) -> Result<IRModule>;
    pub fn parse_from_text(ir_text: &str) -> IRModule;
    // ... other methods
}
```

This is the API that the entire pipeline (`omniscope-pipeline`, `omniscope-pass`, `omniscope-semantics`, `omniscope-cli`) already uses.

---

## 7. Execution Order

1. Delete the five source files: `loader.rs`, `safe_wrappers.rs`, `view.rs`, `debug_info.rs`, `platform.rs`
2. Update `lib.rs`: remove module declarations, re-exports, doc example, and test references
3. Update `Cargo.toml` files: remove `inkwell` dependency from workspace root and `omniscope-ir`
4. Keep `tempfile` in `[dependencies]` -- `llvm_ir_adapter.rs` uses it at runtime
5. Migrate `tests/corpus_regression.rs`: replace `IRLoader` with `IRModule::load_from_file`
6. Run `cargo check --workspace` to verify no compilation errors
7. Run `cargo test --workspace` to verify no test regressions

---

## 8. Risk Assessment

- **Zero risk to runtime behavior**: All deleted modules are dead code. No downstream crate calls any type or function from them.
- **No API surface change for consumers**: The public API that matters (`IRModule`, `Function`, `IRInstruction`, etc.) is untouched.
- **Test coverage**: The 13 tests deleted are testing dead code paths. The real IR parsing and pipeline behavior is covered by `integration_tests.rs`, `corpus_tests.rs`, and pass-level tests.
- **Build time improvement**: Removing `inkwell` (which pulls in LLVM C bindings) should significantly reduce compile times for `omniscope-ir`.
