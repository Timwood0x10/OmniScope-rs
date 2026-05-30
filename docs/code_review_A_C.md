# Code Review: Plan A (C++ LLVM Pass) and Plan C (llvm-sys adapter)

**Date**: 2026-05-29
**Reviewer**: Code Review Agent
**Scope**: `pass/SafetyExportPass.cpp`, `crates/omniscope-ir/src/ir_model.rs`, `crates/omniscope-ir/src/llvm_sys_adapter.rs`, `crates/omniscope-ir/src/loader_v2.rs`

---

## 1. Summary of Findings

| File | Lines | Verdict | Notes |
|------|-------|---------|-------|
| `pass/SafetyExportPass.cpp` | 281 | PASS (with minor issues) | `using namespace llvm;` style violation; no functional bugs found |
| `crates/omniscope-ir/src/ir_model.rs` | 1288 | FAIL | Exceeds 1000-line limit; field name mismatch with C++ (`type` vs `ty`); test failure |
| `crates/omniscope-ir/src/llvm_sys_adapter.rs` | 75 | PASS (stub) | Clean stub with correct API surface |
| `crates/omniscope-ir/src/loader_v2.rs` | 512 | FAIL (2 bugs) | Plugin name mismatch (`.so` vs `.dylib`); only searches for `SafetyExportPass.so` on macOS |

---

## 2. Bugs Found (Prioritized)

### BUG-1 (Critical): Global variable field name mismatch -- deserialization will fail

**File**: `crates/omniscope-ir/src/ir_model.rs:196` vs `pass/SafetyExportPass.cpp:211`

The C++ pass outputs global variable type as `"type"`:
```cpp
G["type"] = typeToString(GV.getValueType());  // SafetyExportPass.cpp:211
```

But the Rust struct expects `"ty"`:
```rust
pub struct IRGlobalVariable {
    pub ty: String,    // expects JSON key "ty"
    ...
}
```

Since `ty` is a required field (not `Option`, no `serde(default)`), **deserialization will fail** whenever the C++ pass outputs a module with global variables. The existing test `test_global_variables_parsed` uses `"ty"` in its test JSON, masking this issue.

**Fix**: Either rename the Rust field to `type` (requires `#[serde(rename = "type")]`) or change the C++ output to `"ty"`. The Rust-side fix is preferred:
```rust
#[serde(rename = "type")]
pub ty: String,
```

### BUG-2 (Critical): Plugin search ignores macOS `.dylib` extension

**File**: `crates/omniscope-ir/src/loader_v2.rs:284-293`

`find_pass_plugin()` only searches for `SafetyExportPass.so`:
```rust
let candidates = [
    root.join("pass").join("build").join("SafetyExportPass.so"),
    // ...
];
```

But `pass/build.sh` produces `libSafetyExportPass.dylib` on macOS (line 31):
```
echo "Build complete. Plugin: $SCRIPT_DIR/build/libSafetyExportPass.dylib"
```

The C++ pass backend will **never** be discovered on macOS. Both `.dylib` and `.so` variants (with and without `lib` prefix) should be searched.

**Fix**: Add platform-aware candidates:
```rust
let candidates = [
    root.join("pass").join("build").join("libSafetyExportPass.dylib"),
    root.join("pass").join("build").join("libSafetyExportPass.so"),
    root.join("pass").join("build").join("SafetyExportPass.so"),
    root.join("pass").join("build").join("SafetyExportPass.dylib"),
    // ... lib/ and Release/ variants
];
```

### BUG-3 (Medium): Data layout pointer size parsing picks wrong address space

**File**: `crates/omniscope-ir/src/parser.rs:329-340`

`parse_datalayout_info()` grabs the first `p`-prefixed segment. For data layouts with address-space-specific pointers (e.g., `p270:32:32-p271:32:32-p272:64:64`), it reports `pointer_size = 32` from address space 270 instead of the generic pointer (address space 0) which defaults to 64 on this target.

This causes the test `test_to_ir_module_basic` to fail:
```
assertion `left == right` failed: Pointer size should be derived from data layout
  left: Some(32)
 right: Some(64)
```

**Fix**: Only match `p:` (generic, no address space) or `p0:` (explicit address space 0):
```rust
if part.starts_with('p') {
    let parts: Vec<&str> = part.split(':').collect();
    // Generic pointer: "p:64:64" (parts[0] == "p") or "p0:64:64" (parts[0] == "p0")
    let is_generic = parts[0] == "p" || parts[0] == "p0";
    if is_generic && parts.len() >= 2 {
        if let Ok(size) = parts[1].parse::<u32>() {
            self.data_layout.pointer_size = Some(size);
            break;
        }
    }
}
```

### BUG-4 (Low): `ir_model.rs` exceeds 1000-line limit

**File**: `crates/omniscope-ir/src/ir_model.rs` -- 1288 lines

Per rules.md: "The code length of a single file should not exceed 1000 lines (including comments and test cases)."

The test section alone is ~790 lines.

**Fix**: Extract tests into a separate file `ir_model_tests.rs` or split the model types and conversion logic into separate modules.

---

## 3. Style Violations

### STYLE-1: `using namespace llvm;` in C++ code

**File**: `pass/SafetyExportPass.cpp:20`

The rules say "No `using namespace std;`". While the rule specifically mentions `std`, the principle applies to all namespace imports. Using `using namespace llvm;` in a header-included file pollutes the namespace.

**Fix**: Remove `using namespace llvm;` and prefix all LLVM types with `llvm::`, or scope it inside the anonymous namespace only.

### STYLE-2: C++ function lengths

All C++ functions are within the 50-line limit. PASS.

### STYLE-3: File length for `ir_model.rs`

1288 lines exceeds the 1000-line limit. See BUG-4.

---

## 4. Cross-Implementation Consistency Issues

### CONSISTENCY-1: `IRInstructionModel.id` -- C++ emits, Rust ignores

The C++ pass emits an `"id"` field per instruction (sequential per basic block). The Rust `IRInstructionModel` has no `id` field, so this data is silently dropped. This is acceptable for now but should be documented as intentional data loss.

### CONSISTENCY-2: `IRFunction.linkage` -- C++ does not emit, Rust expects `Option`

The C++ pass does not output `"linkage"` for function definitions. The Rust model has `pub linkage: Option<String>` which defaults to `None`. This is fine -- serde handles the missing field gracefully.

### CONSISTENCY-3: C++ `invoke` instruction handling

The C++ pass handles `InvokeInst` separately from `CallInst` (lines 92-99), producing the same JSON fields (`callee`, `is_indirect`). However, when the Rust side converts this to `IRInstruction`, the opcode `"invoke"` will fall through to `IRInstructionKind::Other` in `classify_opcode()` (line 419). This means invoke-based calls will not be recognized as calls in the legacy IRModule, potentially missing exception-handling call edges.

**Fix**: Add `"invoke"` to the `classify_opcode()` mapping, either as `Call` or a new `Invoke` variant.

### CONSISTENCY-4: `to_ir_module()` does not propagate global variables or named structs

The `to_ir_module()` conversion (lines 206-346) populates functions, declarations, calls, function bodies, and calling conventions. However, it does **not** store `named_struct_types` or `global_variables` anywhere in the legacy `IRModule`. These are available on the `IRModuleModel` but are lost during conversion.

Since `IRModule` has no fields for struct types or globals, this is a limitation of the legacy format. This should be documented.

### CONSISTENCY-5: Plan C (`llvm_sys_adapter`) always returns `false` / errors

The stub implementation is clean and correct. `is_available()` returns `false` and `parse_with_llvm_sys()` returns an error. This is the correct behavior during development -- `load_auto()` will gracefully skip to the next backend.

---

## 5. Positive Findings

- **JSON schema alignment (after fix)**: Once BUG-1 is fixed, the C++ pass JSON output correctly maps to the Rust `IRModuleModel` serde structs. The `IRFunction`, `IRBasicBlock`, `IRInstructionModel`, and `IRDeclaration` structs all use `#[serde(default)]` appropriately for optional fields.
- **Opcode classification**: `classify_opcode()` in `ir_model.rs` covers all major LLVM instruction categories and correctly falls through to `Other` for unknown opcodes.
- **Test quality**: Tests in `ir_model.rs` cover round-trip serialization, conversion with calls, atomicrmw patterns, indirect calls, CFG successors, multiple calling conventions, and default traits. All assertions have descriptive messages.
- **Loader fallback logic**: `load_auto()` in `loader_v2.rs` correctly probes llvm-sys -> C++ pass -> text parser with proper error propagation and logging at each stage.
- **Tool discovery**: `find_opt()` and `llvm_config_bindir()` have comprehensive search paths covering env vars, llvm-config, PATH, and Homebrew.
- **No `unwrap()` in library code**: All `unwrap()` calls are confined to `#[cfg(test)]` blocks.
- **No `#[allow(dead_code)]`**: Clean.
- **Proper error handling**: `anyhow::Result` used throughout with `.context()` for error chaining.
- **C++ code quality**: No raw `new`/`delete`, functions under 50 lines, proper use of LLVM JSON API, `PreservedAnalyses::all()` correctly returned.

---

## 6. Recommended Fixes (Priority Order)

1. **BUG-1 (Critical)**: Add `#[serde(rename = "type")]` to `IRGlobalVariable.ty` in `ir_model.rs:196`
2. **BUG-2 (Critical)**: Add `.dylib` and `lib`-prefixed variants to `find_pass_plugin()` candidates in `loader_v2.rs:284`
3. **BUG-3 (Medium)**: Fix `parse_datalayout_info()` to only match generic pointer (address space 0) in `parser.rs:329`
4. **BUG-4 (Low)**: Split `ir_model.rs` tests into a separate file to meet the 1000-line limit
5. **CONSISTENCY-3 (Low)**: Add `"invoke"` to `classify_opcode()` in `ir_model.rs:400`
6. **STYLE-1 (Low)**: Scope `using namespace llvm;` inside the anonymous namespace in `SafetyExportPass.cpp`
