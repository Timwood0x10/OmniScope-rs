# inkwell Removal Status

> Status: completed. This document records the current code state after the old `inkwell`-based IR wrappers were removed.

---

## Current State

The workspace no longer depends on `inkwell`. The old `omniscope-ir` modules that wrapped `inkwell` types have been removed from the source tree and from public exports.

Verified against the current code:

- `Cargo.toml` and `crates/omniscope-ir/Cargo.toml` contain no `inkwell` dependency.
- `crates/omniscope-ir/src/lib.rs` exports only the active IR parser/model/loading API.
- Removed modules are not present under `crates/omniscope-ir/src/`: `loader.rs`, `safe_wrappers.rs`, `view.rs`, `debug_info.rs`, and `platform.rs`.
- Tests and downstream crates use `IRModule`, `load_ir`, `LoadStrategy`, or model conversion APIs instead of `IRLoader`/`Safe*` wrappers.

---

## Active IR Loading API

The primary entry point is `load_ir(path, strategy)` from `crates/omniscope-ir/src/loader_v2.rs`:

```rust
pub use loader_v2::{load_ir, LoadStrategy};
```

`LoadStrategy::Auto` probes backends in this order:

1. `llvm-sys` backend, only when compiled with `--features llvm-backend`.
2. C++ SafetyExportPass backend, when both `opt` and `SafetyExportPass` are discoverable.
3. Text parser backend, using `.ll` directly or `llvm-dis` for `.bc` input.

The text parser API remains available directly through `IRModule`:

```rust
IRModule::load_from_file(path)?;
IRModule::parse_from_text(ir_text);
```

---

## Public `omniscope-ir` Surface

Current active modules:

```rust
pub mod instruction_parser;
pub mod ir_model;
#[cfg(feature = "llvm-backend")]
pub mod llvm_sys_adapter;
pub mod loader_v2;
pub mod location;
pub mod parser;
```

Current important exports:

```rust
pub use ir_model::{
    load_from_json, parse_from_json, IRBasicBlock, IRDeclaration, IRFunction,
    IRGepDetails, IRGepIndex, IRGlobalVariable, IRInstructionModel, IRModuleModel,
};
pub use loader_v2::{load_ir, LoadStrategy};
pub use location::{LocationManager, SourceLocation};
pub use parser::{
    CallInstruction, Function, FunctionBody, IRInstruction, IRInstructionKind, IRModule,
};
```

---

## Notes For Future Work

- Keep documentation aligned with `loader_v2.rs`; older references to `IRLoader`, `safe_wrappers`, `view`, or `debug_info` are obsolete.
- `tempfile` is still used by the IR crate tests and should not be removed blindly.
- If `llvm-sys` becomes the default backend later, update this document and `docs/architecture.md` together.
