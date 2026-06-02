# rust_sqlite.ll Performance Analysis and Optimization Plan

> Case: `./build/omniscope analyze ~/code/zigcode/OmniScope/corpus/real_world/other/rust_sqlite.ll`

---

## 1. Summary

The observed 26s runtime is not caused by the Rust analysis pipeline itself.

The main bottleneck is the default `auto` IR loading strategy choosing the C++ SafetyExportPass backend and running LLVM `opt` on a 13 MB / 344k-line LLVM IR file.

Measured locally on the same input:

| Command | Wall Time | Pipeline Time | Loader Used |
|---------|-----------|---------------|-------------|
| `./build/omniscope analyze rust_sqlite.ll` | ~26.15s | ~318ms | C++ pass via `opt` |
| `./build/omniscope analyze --strategy text-parser rust_sqlite.ll` | ~0.36s | ~276ms | built-in text parser |

The CLI output field `Analysis time` currently reports only `Pipeline::run()` duration. It does **not** include IR loading time. Therefore the user sees:

```text
Analysis time: 645 ms
./build/omniscope analyze ... 26.576 total
```

This mismatch means roughly 25+ seconds are spent before the pipeline starts.

---

## 2. Evidence

### Input Size

```text
rust_sqlite.ll: 13 MB
line count:     344,112
```

### Default `auto` Strategy

With `--verbose`, the default path shows:

```text
Parsing LLVM IR ... (strategy: auto)
llvm-sys not available
Found opt via Homebrew path: /opt/homebrew/opt/llvm@22/bin/opt
Found plugin: pass/build/SafetyExportPass.dylib
Attempting C++ pass backend
Running C++ pass via opt ... rust_sqlite.ll
Loaded via C++ pass
Pipeline completed ... 318ms
Analysis completed in 26.148s
```

So the time split is approximately:

```text
Total wall time:      ~26.15s
C++ pass / opt load:  ~25.83s
Pipeline:             ~0.32s
Formatting/output:    negligible
```

### Forced Text Parser

With `--strategy text-parser`, the same input shows:

```text
IR loaded: 1582 functions, 110 declarations, 15626 calls
Pipeline completed ... 276ms
Analysis completed in 355ms
real 0.36s
```

The reported findings are equivalent for this case:

- `sqlite3_finalize` double free
- `sqlite3_free` double free
- `sqlite3MemInit` conditional leak
- unknown SQLite resource conditional leak
- `malloc_set_zone_name` definite leak

---

## 3. Root Cause

### 3.1 `auto` Prefers C++ Pass Before Text Parser

Current `LoadStrategy::Auto` order in `crates/omniscope-ir/src/loader_v2.rs` is:

```text
llvm-sys → C++ SafetyExportPass → text-parser
```

When `llvm-sys` is not enabled but `opt` and `SafetyExportPass` are discoverable, `auto` runs:

```text
opt -load-pass-plugin SafetyExportPass.dylib -passes=safety-export rust_sqlite.ll -o /dev/null
```

This is expensive on large text IR.

### 3.2 CLI Timing Hides Loading Cost

`crates/omniscope-pipeline/src/pipeline.rs` measures only pass execution:

```text
Pipeline::run()
  start timer
  pass_manager.run_all_with_ir(...)
  stop timer
```

`crates/omniscope-cli/src/output/rich.rs` displays that pipeline duration as `Analysis time`.

This makes the UI misleading for slow loads: the real end-to-end cost is much higher than the displayed analysis time.

### 3.3 Current Pipeline Is Not the Main Bottleneck

For this input, `--verbose` shows the most expensive passes are still sub-100ms scale:

| Pass | Time |
|------|------|
| `ContractGraphBuilder` | ~78-95ms |
| `IRBehaviorSummary` | ~50-58ms |
| `FFIBoundary` | ~40-42ms |
| `RaiiDrop` | ~36-42ms |
| `FfiReturnCheck` | ~34-40ms |

The pass pipeline is already fast relative to `opt`.

---

## 4. Immediate Workaround

For large `.ll` files where the text parser provides equivalent precision, run:

```bash
./build/omniscope analyze --strategy text-parser ~/code/zigcode/OmniScope/corpus/real_world/other/rust_sqlite.ll
```

This reduces the observed runtime from ~26s to ~0.36s in this case.

This workaround should not reduce precision for this specific `rust_sqlite.ll` case based on observed output equivalence. For other inputs, use the C++ pass only when enriched type/debug metadata is required.

---

## 5. No-Precision-Loss Optimization Plan

The goal is to avoid unnecessary C++ pass work without losing precision.

## Task 1: Report End-to-End Timing Separately

Priority: P0

Files:

- `crates/omniscope-cli/src/main.rs`
- `crates/omniscope-cli/src/output/rich.rs`
- `crates/omniscope-pipeline/src/result.rs`

Change:

- Track these timings independently:
  - `load_ms`
  - `pipeline_ms`
  - `format_ms`
  - `total_ms`
- Keep `PipelineResult::duration` as pipeline time.
- Add CLI-side timing fields or a separate timing summary.

Target output:

```text
Timing
────────────────────────────────────────
  IR loading:      25,830 ms  (cpp-pass)
  Pipeline:           318 ms
  Formatting:           2 ms
  Total:           26,148 ms
```

Why no precision loss:

- Pure instrumentation only.
- Does not alter detection logic.

Validation:

```bash
RUSTC_WRAPPER= cargo check --workspace
./build/omniscope analyze --verbose rust_sqlite.ll
```

---

## Task 2: Make Loader Strategy Visible in Normal Output

Priority: P0

Files:

- `crates/omniscope-ir/src/loader_v2.rs`
- `crates/omniscope-cli/src/main.rs`
- `crates/omniscope-cli/src/output/rich.rs`

Change:

- Return load metadata together with `IRModule`:

```rust
pub struct LoadedIr {
    pub module: IRModule,
    pub strategy_used: LoadStrategy,
    pub load_ms: u64,
    pub functions: usize,
    pub declarations: usize,
    pub calls: usize,
}
```

- Keep current `load_ir()` API for compatibility.
- Add `load_ir_with_metadata()` for CLI.

Why no precision loss:

- Only exposes which backend was used.
- Does not change backend selection yet.

Benefit:

- Users can immediately see when `auto` selected the expensive C++ pass.

---

## Task 3: Add `auto-fast` Strategy

Priority: P1

Files:

- `crates/omniscope-ir/src/loader_v2.rs`
- `crates/omniscope-cli/src/main.rs`
- `docs/usage_guide.md`

Change:

Add a strategy that prefers the text parser for `.ll` inputs and uses heavier backends only when needed:

```text
auto-fast for .ll:
  text-parser → cpp-pass fallback only if parser fails or required metadata missing

auto-fast for .bc:
  llvm-sys → cpp-pass → text-parser via llvm-dis
```

Keep current `auto` behavior unchanged to avoid surprising users.

Why no precision loss:

- This is opt-in.
- Existing `auto` remains the precision-first path.
- `auto-fast` can fallback to C++ pass if text parsing fails.

Validation:

```bash
./build/omniscope analyze --strategy auto-fast rust_sqlite.ll
./build/omniscope analyze --strategy auto rust_sqlite.ll
```

Expected:

- Same findings on `rust_sqlite.ll`.
- `auto-fast` wall time close to `text-parser`.

---

## Task 4: Add Large `.ll` Heuristic With Safe Fallback

Priority: P1

Files:

- `crates/omniscope-ir/src/loader_v2.rs`

Change:

For `LoadStrategy::Auto`, optionally add a conservative heuristic:

```text
If input is .ll and file_size > N MB:
  try text-parser first
  if parse succeeds and required coverage is acceptable, use it
  otherwise fallback to C++ pass
```

Coverage checks:

- parsed function count > 0
- parsed call count > 0 for non-empty IR
- no parser failure or malformed-function sentinel explosion
- optional: compare declaration/function counts when cheap metadata exists

Why no precision loss:

- Fallback preserves C++ pass when text parsing is insufficient.
- Heuristic should be gated by config/env var first:

```bash
OMNISCOPE_AUTO_FAST_LL=1
```

Recommended threshold:

```text
N = 5 MB initially
```

Reason:

- `rust_sqlite.ll` is 13 MB and benefits strongly.

---

## Task 5: Cache C++ Pass JSON Output

Priority: P1

Files:

- `crates/omniscope-ir/src/loader_v2.rs`
- optional new file: `crates/omniscope-ir/src/load_cache.rs`

Change:

Cache `SafetyExportPass` JSON output by input file fingerprint:

```text
cache key = path + file size + mtime + optional content hash
cache value = serialized IRModuleModel JSON
```

Suggested cache path:

```text
target/omniscope-cache/<hash>.ir.json
```

Load order for C++ pass:

```text
if cache hit:
  deserialize JSON directly
else:
  run opt + SafetyExportPass
  write JSON cache
```

Why no precision loss:

- Cached JSON is exactly the C++ pass output for the same file fingerprint.
- Invalidation is deterministic.

Expected benefit:

- First run remains ~26s.
- Repeated runs avoid `opt` and should be near sub-second.

Validation:

```bash
time ./build/omniscope analyze rust_sqlite.ll
time ./build/omniscope analyze rust_sqlite.ll
```

Expected:

- Second run much faster.
- Findings identical.

---

## Task 6: Avoid Redundant Tool Discovery

Priority: P2

Files:

- `crates/omniscope-ir/src/loader_v2.rs`

Current issue:

- `can_use_cpp_pass()` calls `find_opt()` and `find_pass_plugin()`.
- `load_via_cpp_pass()` calls them again.

Change:

- Resolve backend availability once:

```rust
struct CppPassBackend {
    opt: PathBuf,
    plugin: PathBuf,
}
```

- Pass resolved paths into `load_via_cpp_pass_with_backend()`.

Why no precision loss:

- Only removes duplicate filesystem/process checks.

Expected benefit:

- Small but free improvement.
- Helps CLI responsiveness.

---

## Task 7: Reduce Cloning in Pass Context

Priority: P2

Files:

- `crates/omniscope-pass/src/pass.rs`
- `crates/omniscope-pass/src/analysis/write_to_immutable.rs`
- `crates/omniscope-pass/src/resource/raw_fact_collector.rs`
- `crates/omniscope-pass/src/analysis/borrow_escape.rs`
- `crates/omniscope-pass/src/analysis/heap_provenance.rs`

Current issue:

- Several passes still use `ctx.get("ir_module")` or `ctx.get("module_index")`, which clones large structures.

Change:

- Prefer:

```rust
ctx.get_ref::<IRModule>("ir_module")
ctx.get_ref::<ModuleIndex>("module_index")
```

Why no precision loss:

- Read-only access to identical data.
- No detector logic change.

Expected benefit:

- Smaller memory pressure.
- Better scalability for large IR.

Note:

- This will not fix the 26s case by itself, because the dominant cost is `opt`.
- It is still useful for large inputs and future path-sensitive analysis.

---

## 6. Recommended Implementation Order

| Order | Task | Reason |
|-------|------|--------|
| 1 | Task 1: timing breakdown | Makes performance truthful and debuggable |
| 2 | Task 2: expose loader strategy | Users can see when C++ pass is selected |
| 3 | Task 3: `auto-fast` | Immediate safe speed path without changing `auto` |
| 4 | Task 5: C++ pass cache | Preserves precision and accelerates repeated runs |
| 5 | Task 6: tool discovery cleanup | Small easy win |
| 6 | Task 7: reduce cloning | Improves scalability |
| 7 | Task 4: large `.ll` heuristic | Consider after enough regression data |

---

## 7. Precision-Safety Policy

Performance changes must not reduce detection precision. Use this policy:

1. Do not remove the C++ pass backend.
2. Do not change existing `auto` behavior until `auto-fast` has enough regression coverage.
3. Any text-parser-first optimization must either be opt-in or have a C++ pass fallback.
4. Cache entries must be invalidated by file fingerprint.
5. Compare findings between strategies on representative fixtures:

```bash
./build/omniscope analyze --strategy auto rust_sqlite.ll --format json > auto.json
./build/omniscope analyze --strategy text-parser rust_sqlite.ll --format json > text.json
```

Then compare issue kind/function pairs, ignoring unstable issue IDs.

---

## 8. Practical Recommendation For Current Use

For this specific `rust_sqlite.ll` file, use:

```bash
./build/omniscope analyze --strategy text-parser ~/code/zigcode/OmniScope/corpus/real_world/other/rust_sqlite.ll
```

Reason:

- Same observed findings.
- Runtime drops from ~26s to ~0.36s.
- The C++ pass does not appear to add useful precision for this case.

If enriched type/debug metadata becomes necessary for another input, use default `auto` or explicit:

```bash
./build/omniscope analyze --strategy cpp-pass <input.ll>
```

---

## 9. Validation Commands

Build/check:

```bash
RUSTC_WRAPPER= cargo check --workspace
```

Baseline performance:

```bash
/usr/bin/time -p ./build/omniscope analyze --verbose rust_sqlite.ll
/usr/bin/time -p ./build/omniscope analyze --strategy text-parser --verbose rust_sqlite.ll
```

Accuracy regression:

```bash
RUSTC_WRAPPER= cargo test accuracy_regression -- --nocapture
```

Strategy equivalence check:

```bash
./build/omniscope analyze --strategy auto --format json rust_sqlite.ll > /tmp/auto.json
./build/omniscope analyze --strategy text-parser --format json rust_sqlite.ll > /tmp/text.json
```

Compare issue kind/function pairs rather than raw issue IDs.
