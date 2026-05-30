# Code Review Round 3 -- 2026/05/30

Reviewer: Claude (automated)
Scope: 3 parallel fix areas + rules.md compliance + architecture check

---

## 1. C++ Pass JSON Output

**Status: PASS (with one minor note)**

### Required fields

The C++ pass (`pass/SafetyExportPass.cpp`) emits all six required top-level fields:

| Field                  | Present | Source (line)           |
|------------------------|---------|-------------------------|
| `target_triple`        | Yes     | L226                    |
| `data_layout`          | Yes     | L227                    |
| `functions`            | Yes     | L240                    |
| `declarations`         | Yes     | L241                    |
| `named_struct_types`   | Yes     | L242                    |
| `global_variables`     | Yes     | L243                    |

### Clean JSON (no module dump pollution)

The pass writes JSON to `llvm::outs()` (L250) and the module itself is never printed.
`PreservedAnalyses::all()` is returned (L253), so `opt` does not re-emit the module.
No stray output to stdout from helper functions -- all serialization goes through
`llvm::raw_string_ostream` into a local `std::string`.

### named_struct_types populated

`serializeNamedStructs` (L187-201) iterates `M.getIdentifiedStructTypes()`, strips the
leading `%` from struct names, and emits field type arrays.  Correct.

### Minor note: redundant `is_declaration` field

`serializeFunction` (L151) emits `"is_declaration": false` in every function object.
This field is not present in the Rust `IRFunction` struct, so serde silently ignores it.
The field is redundant because the separation into `functions[]` vs `declarations[]`
already encodes this information.  Harmless but could be removed to reduce JSON size.

### Tests

`cargo test --workspace` passes: **669 tests, 0 failures**.

---

## 2. Inkwell Dead Code Removal

**Status: PASS**

### Files deleted

| File                       | Deleted from disk | Deleted from git |
|----------------------------|-------------------|------------------|
| `loader.rs`                | Yes               | Yes (staged `D`) |
| `safe_wrappers.rs`         | Yes               | Yes (staged `D`) |
| `view.rs`                  | Yes               | Yes (staged `D`) |
| `debug_info.rs`            | Yes               | Yes (staged `D`) |

### Removed from lib.rs

`lib.rs` (L19-26) declares only these modules:
- `instruction_parser`
- `ir_model`
- `llvm_sys_adapter` (feature-gated)
- `loader_v2`
- `location`
- `parser`
- `platform`

No `mod loader;`, `mod safe_wrappers;`, `mod view;`, or `mod debug_info;` remain.

### inkwell removed from Cargo.toml

`grep -r "inkwell"` across all `Cargo.toml` and `*.rs` files returns zero matches.
The `omniscope-ir/Cargo.toml` dependencies list shows:
`omniscope-core`, `omniscope-types`, `anyhow`, `llvm-sys` (optional), `serde`,
`serde_json`, `tempfile`, `thiserror`, `tracing`.  No inkwell.

### No dangling references

No Rust source file references `inkwell`, `loader::`, `safe_wrappers::`, `view::`, or
`debug_info::` types outside of doc comments and test code.

---

## 3. Loader v2 Integration

**Status: PASS (with one issue in the CLI)**

### find_pass_plugin() finds .dylib

`loader_v2.rs` L286-292 defines `LIB_NAMES` on macOS:
```
libSafetyExportPass.dylib    (first)
SafetyExportPass.dylib
libSafetyExportPass.so
SafetyExportPass.so
```

Correct -- `.dylib` is prioritized on macOS.

### load_via_cpp_pass() runs opt WITHOUT -S

`loader_v2.rs` L188-196:
```rust
let output = std::process::Command::new(&opt)
    .arg("-load-pass-plugin")
    .arg(&plugin)
    .arg("-passes=safety-export")
    .arg(path)
    .arg("-o")
    .arg("/dev/null")
    .output()
```

No `-S` flag.  This is correct: with `-S`, `opt` would write textual IR to stdout,
corrupting the JSON output.  Without `-S`, only the pass's `llvm::outs()` JSON
appears on stdout.

### JSON round-trip works

The integration test `test_json_deserialize_cpp_pass_output` (plan_a_c_integration.rs L377-481)
verifies the full pipeline: JSON string -> `IRModuleModel::from_json_str` ->
field-by-field validation.  The `test_json_model_roundtrip` test (L222-342)
verifies serialize -> deserialize preserves all fields.

### ISSUE: CLI does not use loader_v2

`crates/omniscope-cli/src/main.rs` L137 and L230 both use:
```rust
let module = omniscope_ir::IRModule::load_from_file(&cmd.input)?;
```

This calls the legacy text parser directly, bypassing the smart loading pipeline
(`loader_v2::load_ir`).  The C++ pass and llvm-sys backends are never invoked
from the CLI.  This should be:
```rust
let module = omniscope_ir::loader_v2::load_ir(&cmd.input, omniscope_ir::LoadStrategy::Auto)?;
```

Or a new `--strategy` CLI flag should be added.

---

## 4. rules.md Compliance

**Status: FAIL (1 violation)**

### make fmt

`cargo fmt --all -- --check` passes.  No formatting issues.

### make check (clippy)

`cargo clippy --workspace --all-targets -- -D warnings` passes with zero warnings.

### cargo test --workspace

669 tests pass, 0 failures.

### File lengths under 1000 lines

| File                        | Lines |
|-----------------------------|-------|
| `instruction_parser.rs`     | 909   |
| `parser.rs`                 | 913   |
| `llvm_sys_adapter.rs`       | 733   |
| `ir_model_tests.rs`         | 574   |
| `loader_v2.rs`              | 534   |
| `ir_model.rs`               | 456   |
| `rich.rs`                   | 423   |
| `SafetyExportPass.cpp`      | 278   |

All under 1000.  PASS.

### VIOLATION: #[allow(dead_code)]

`crates/omniscope-cli/src/output/rich.rs` L24:
```rust
#[allow(dead_code)]
pub fn with_color(use_color: bool) -> Self {
```

This method is defined but never called outside of tests.  Either:
- Remove the `#[allow(dead_code)]` and call it from the `--no-color` CLI path, or
- Remove the method entirely if it is genuinely unused.

### No using namespace llvm

`grep -r "using namespace" pass/` returns zero matches.  PASS.

### All assertions have messages

All test assertions in `plan_a_c_integration.rs`, `llvm_sys_test.rs`, `loader_v2.rs`,
and `ir_model_tests.rs` include descriptive failure messages.  PASS.

---

## 5. Overall Architecture

**Status: PASS (with integration gap)**

### Fallback chain

`loader_v2.rs` `load_auto()` (L96-132):
1. Try `llvm-sys` (feature-gated)
2. Try C++ pass (`opt` + SafetyExportPass plugin)
3. Fall back to text parser

Priority order is correct.  Each fallback is guarded by a capability check
(`can_use_llvm_sys()`, `can_use_cpp_pass()`).

### Default build (no features) works

`cargo test --workspace` without `--features llvm-backend` passes all 669 tests.
The `llvm_sys_adapter` module is compiled out via `#[cfg(feature = "llvm-backend")]`.
The `LlvmSys` strategy returns a clear error when the feature is disabled.

### --features llvm-backend adds llvm-sys path

`Cargo.toml`: `llvm-backend = ["llvm-sys"]` (optional dependency).
`lib.rs` L21: `#[cfg(feature = "llvm-backend")] pub mod llvm_sys_adapter;`
`loader_v2.rs` L142-145: `can_use_llvm_sys()` returns `true` only when feature is enabled.

Correct.

### Integration gap

The CLI (`main.rs`) does not use `loader_v2`, so the architecture is complete at the
library level but not wired end-to-end.  See Issue in Section 3.

---

## Summary of Issues

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 1 | **High** | `main.rs:137,230` | CLI uses `load_from_file()` instead of `loader_v2::load_ir()`, bypassing C++ pass and llvm-sys backends |
| 2 | **Medium** | `rich.rs:24` | `#[allow(dead_code)]` on `with_color()` violates rules.md |
| 3 | **Low** | `SafetyExportPass.cpp:151` | Redundant `is_declaration` field in function JSON (harmless) |
| 4 | **Low** | `build.sh:31` | Hardcodes `.dylib` extension -- won't work on Linux without modification |

## What Works Well

- The inkwell removal is clean: all four files deleted, no dangling references, no inkwell in Cargo.toml.
- The C++ pass is well-structured with correct JSON output and proper separation of declarations.
- The loader_v2 fallback chain is correct and properly feature-gated.
- All three backends (text parser, C++ pass JSON model, llvm-sys) produce consistent `IRModule` output, verified by cross-validation tests.
- Test coverage is thorough: 669 tests covering JSON round-trip, opcode classification, CFG edges, cross-backend consistency, and error handling.
