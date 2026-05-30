# OmniScope-rs Performance Analysis Report

Date: 2026-05-30
Benchmark source: `benches/bench.log`
Hardware: Apple Silicon (arm64-apple-darwin)

---

## 1. Current Performance Baseline

### IR Parsing (ir_parsing.rs)

| Fixture | Size | Time | Throughput |
|---------|------|------|-----------|
| rust_hash | 2KB | 9.8µs | 211 MiB/s |
| c_hash_bridge | 7KB | 20.6µs | 331 MiB/s |
| python_ffi | 7KB | 20.8µs | 323 MiB/s |
| go_ffi | 8KB | 28.9µs | 275 MiB/s |
| zig_ffi | 14KB | 50.0µs | 266 MiB/s |
| c_ffi_bugs | 17KB | 59.1µs | 292 MiB/s |
| cpp_hash | 23KB | 166µs | 136 MiB/s |
| rust_ffi_bugs | 30KB | 102µs | 288 MiB/s |

**Observation**: Parsing throughput 136-331 MiB/s. cpp_hash is slower (136 MiB/s) because it has more complex type structures and struct definitions. Parsing is NOT a bottleneck.

### Pipeline End-to-End (pipeline.rs)

| Fixture | Size | Functions | Calls | Time |
|---------|------|-----------|-------|------|
| c_hash_bridge | 7KB | 10 | 11 | 240µs |
| zig_ffi | 14KB | 25 | 20 | 362µs |
| c_ffi_bugs | 17KB | 20 | 24 | 452µs |
| cpp_hash | 23KB | 11 | 30 | 921µs |
| rust_ffi_bugs | 30KB | 43 | 84 | 4.44ms |
| rust_merkle | 44KB | 26 | 75 | 2.54ms |

**Observation**: Pipeline time correlates strongly with **call count**, not file size or function count. rust_ffi_bugs has 84 calls and takes 4.4ms; rust_merkle has 75 calls and takes 2.5ms. The per-call analysis overhead is the dominant factor.

### Synthetic Scaling (pipeline_synthetic)

| Functions | Time | Per-function |
|-----------|------|-------------|
| 5 | 458µs | 91.6µs |
| 10 | 937µs | 93.7µs |
| 50 | 8.69ms | 173.8µs |
| 100 | 26.5ms | 265.0µs |

**Observation**: Per-function cost grows from 92µs to 265µs as function count increases (2.9x). This suggests some O(n) or O(n log n) overhead in inter-function analysis (call graph traversal, global state lookups).

### Resource Analysis (resource_analysis.rs)

| Component | 100 | 1,000 | 10,000 |
|-----------|-----|-------|--------|
| Ownership Solver (balanced) | 42µs | 390µs | 4.39ms |
| Ownership Solver (leak) | 25µs | 261µs | 2.51ms |
| Ownership Solver (multi-family) | 41µs | 415µs | 4.47ms |
| Ownership Solver (escape reclaim) | 97µs | 885µs | **10.7ms** |
| Contract Graph Construction | 13.5µs | 150µs | 1.41ms |

**Observation**: Ownership Solver escape reclaim is the hottest path -- 10.7ms at 10k cycles, 2.4x slower than balanced mode. The escape detection involves cycle enumeration which has super-linear cost.

---

## 2. Performance Regressions (bugfix_regression.rs)

Multiple benchmarks show significant regressions compared to previous baseline:

| Benchmark | Regression | Root Cause |
|-----------|-----------|------------|
| bug6_write_to_immutable (100 stores) | **+71%** (182µs) | Store scanning logic added new checks |
| bug8_leak_detection (100 facts) | **+105%** (53µs) | Leak detection path analysis expanded |
| bug8_leak_detection (1000 facts) | **+34%** (975µs) | Same, scales with fact count |
| bug10_ffi_return_check (17KB) | **+95%** (88µs) | FFI return value null-check pass added |
| cpp_accuracy (5 bugs) | **+85%** (554µs) | New passes enrich analysis |
| rust_accuracy (5 bugs) | **+80%** (371µs) | Same |
| cpp_scaling (23KB) | **+116%** (839µs) | Cumulative pass overhead |
| rust_scaling (30KB) | **+100%** (4.46ms) | Same |
| rust_scaling (merkle 44KB) | **+91%** (2.60ms) | Same |

**Verdict**: The regressions are the **cost of improved accuracy**. The accuracy report shows 100% F1 for both C++ and Rust hidden bug detection (5/5 TP, 0 FN, 0 FP). This is a correct trade-off.

---

## 3. Bottleneck Analysis

### Bottleneck #1: Ownership Solver Escape Detection (10.7ms @ 10k)

**Location**: `crates/omniscope-pass/src/resource/ownership_solver.rs`

**Why it's slow**: Escape reclaim detection enumerates ownership cycles. At 10k cycles, the solver performs ~10.7ms of work, which is 2.4x the balanced mode (4.4ms). The cycle detection likely involves graph traversal with repeated state lookups.

**Optimization opportunities**:
- Use `HashMap` instead of `BTreeMap` for `instance_map` lookups (amortized O(1) vs O(log n))
- Cache cycle membership instead of re-traversing
- Consider incremental cycle detection (union-find) instead of full enumeration
- Potential: **30-50% reduction** (estimate 5-7ms at 10k)

### Bottleneck #2: Per-Call Analysis Overhead

**Location**: `crates/omniscope-pass/src/resource/contract_graph_builder.rs` and downstream passes

**Why it's slow**: Each call instruction triggers:
1. FamilyRegistry lookup (now `LazyLock` singleton — **FIXED**)
2. `PassContext::get()` clones entire collections (O(n) per access) — **PARTIALLY FIXED** via `get_ref()`, but some call sites still use `get()`
3. Semantic engine re-evaluation per call site

**Optimization opportunities**:
- Migrate remaining `ctx.get()` calls to `get_ref()` (some call sites remain)
- Batch call analysis instead of per-call processing
- Potential: **10-20% additional reduction** in pipeline E2E

### Bottleneck #3: DashMap Overhead in DataFlowGraph ✅ FIXED

**Location**: `crates/omniscope-dataflow/src/graph.rs`

**Why it was slow**: `DashMap` uses sharded RwLock per bucket. Every `add_node`/`add_edge`/`get` acquires a lock. All methods take `&mut self`, so no concurrent access is possible.

**Fix**: Replaced `DashMap` with `HashMap`. Removed `dashmap` dependency. Simplified accessor methods.

**Result**: 5-15% reduction in dataflow-heavy passes (estimated).

### Bottleneck #4: Synthetic Scaling Non-linearity

**Location**: Inter-function analysis in pipeline

**Why it's slow**: Per-function cost grows from 92µs (5 funcs) to 265µs (100 funcs) -- 2.9x growth. This suggests some global state is being re-computed or re-looked-up per function.

**Optimization opportunities**:
- Profile to identify the specific O(n) lookup
- Pre-compute global summaries once, reuse per function
- Potential: Flatten per-function cost to ~100µs constant

---

## 4. Optimization Roadmap

### Tier 1: Trivial (no behavior change)

| Fix | Effort | Expected Gain | Status |
|-----|--------|--------------|--------|
| DashMap -> HashMap (graph.rs) | 10 min | 5-15% dataflow | ✅ DONE |
| `ir_module.take()` -> `.clone()` | 5 min | correctness fix | OPEN |

### Tier 2: Easy (small behavior change)

| Fix | Effort | Expected Gain | Status |
|-----|--------|--------------|--------|
| `PassContext::get_ref()` API | 1 hr | 20-40% pipeline | ✅ DONE |
| FamilyRegistry singleton reuse | 30 min | 5-10% | ✅ DONE (LazyLock) |
| `contains("_free")` word-boundary fix | 30 min | correctness | ✅ DONE |
| Iteration bound on fixpoint loop | 15 min | safety guard | OPEN |

### Tier 3: Medium (architectural)

| Fix | Effort | Expected Gain | Status |
|-----|--------|--------------|--------|
| Ownership solver: HashMap for instance_map | 2 hrs | 10-20% escape | OPEN |
| Incremental cycle detection (union-find) | 1 day | 30-50% escape | OPEN |
| Batch call analysis | 2 days | 20-40% pipeline | OPEN |

### Tier 4: Hard (new infrastructure)

| Fix | Effort | Expected Gain | Status |
|-----|--------|--------------|--------|
| Path-sensitive leak detection | 1-2 weeks | accuracy++ | STUB (annotated) |
| llvm-sys global variables | — | data completeness | ✅ DONE |
| llvm-sys operands population | 3 days | data completeness | OPEN |

---

## 5. Target Performance

Based on current data and optimization potential:

| Scenario | Baseline (pre-fix) | After Tier 1+2 | Remaining Target | Method |
|----------|--------------------|----------------|-----------------|--------|
| Pipeline E2E (30KB/84 calls) | 4.4ms | ~3.0-3.5ms | **2-2.5ms** | Tier 3 |
| Pipeline E2E (100 funcs) | 26.5ms | ~18-20ms | **12-15ms** | Tier 3 |
| Ownership Solver (10k escape) | 10.7ms | 10.7ms | **5-7ms** | Tier 3 |
| IR Parsing | 101µs | 101µs | 101µs | no change needed |

**Completed optimizations**:
- ✅ DashMap → HashMap (graph.rs): removed lock overhead
- ✅ FamilyRegistry LazyLock singleton: eliminated per-call allocation
- ✅ `PassContext::get_ref()`: zero-copy for hot paths
- ✅ `contains("_free")` word-boundary: correctness fix, no perf impact

**Remaining for next round**:
- Migrate remaining `ctx.get()` → `get_ref()` call sites
- Ownership solver: `HashMap` for `instance_map`
- Incremental cycle detection (union-find)
- llvm-sys operands population (data completeness)

For a real-world project with ~1000 functions and ~500 calls, current estimate: **~35-40ms** (after Tier 1+2). Target after Tier 3: **~20-25ms**. This is well within interactive CLI response time requirements.
