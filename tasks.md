# OmniScope-rs Development Tasks

## Coding Rules (MUST follow)

All rules come from `./aim/rules/rules.md`. Key points:

1. **Single file <= 1000 lines** (500-1000 ideal). Files exceeding this must be split into modules.
2. **`make check` must return 0 errors** before committing.
3. **Run `make fmt`** after every modification.
4. **All `assert!` / `assert_eq!` must include specific error messages** — no bare assertions.
5. **All comments in English**, code-to-comment ratio 7:3.
6. **Do NOT use `#[allow(dead_code)]`** — fix the root cause instead.
7. **Do NOT use `git && rm`** commands.
8. **Test module by module** — complete one before moving to the next.
9. **No coverage tests** (wastes time and resources).
10. **Prefer `&str` / `&[T]` over `&String` / `&Vec<T>`** in function signatures.
11. **Avoid `unwrap()` in library code** unless provably safe (with comment explaining why).
12. **Use `?` operator** for error propagation.
13. **Each test must have Objective + Invariants documentation.**
14. **Test priority: detect hidden bugs, not superficial assertions.**

---

## Reference: Zig OmniScope Architecture

Source: `/Users/scc/code/zigcode/omniscope/src/` (the mature Zig implementation)

Key modules to port/adapt:

| Zig Module | Rust Target Crate | Status |
|---|---|---|
| `semantics/surface_classifier/` | `omniscope-semantics` | **Done** (L1+L2+L3) |
| `semantics/language_detector` | `omniscope-semantics` | Basic done, needs weighted voting |
| `semantics/zone_classifier` | `omniscope-semantics` | Basic done, needs escape triggers |
| `registry/semantic_registry` | `omniscope-registry` | **Done** (L1-L6+JNI/Python/POSIX) |
| `pass/analysis/call_graph` | `omniscope-pass` | **Done** |
| `pass/analysis/ffi/ffi_boundary` | `omniscope-pass` | **Done** (rewritten with SemanticRegistry) |
| `pass/analysis/ffi/ffi_detector` | `omniscope-pass` | **Done** (merged into FFIBoundaryPass) |
| `pass/analysis/taint/taint_propagation` | `omniscope-pass` | **TODO** (stub only) |
| `pass/analysis/pointer_ownership` | `omniscope-pass` | **TODO** (stub only) |
| `pass/analysis/danger_surface` | `omniscope-pass` | **Done** |
| `pass/analysis/surface_classifier_pass` | `omniscope-pass` | **Done** |
| `pass/analysis/noise/noise_reduction` | `omniscope-pass` | **Done** |
| `pass/filter/fp_precision_guard` | `omniscope-pass` | **Done** (merged into noise_reduction) |
| `pass/foundation/cfg` | `omniscope-pass` | Stub done, needs real impl |
| `pass/foundation/dfg` | `omniscope-pass` | Stub done, needs real impl |
| `diag/issue` | `omniscope-core` | **Done** |
| `fact/query` (QueryEngine) | `omniscope-core` | **TODO** |
| `dataflow/` (guard, path_condition) | `omniscope-dataflow` | **TODO** (advanced) |
| `output/` (CLI, SARIF, LSP) | `omniscope-cli` | Basic CLI done, SARIF/LSP **TODO** |

---

## Completed Tasks

### Phase A: Type System Foundation
- [x] `omniscope-types`: Added `call_graph_types.rs` — `FunctionKind`, `CallGraphNode`, `CallGraphEdge`, `CrossLangEdge`, libc/dangerous/source/sink function lists
- [x] `omniscope-types`: Added `zone_types.rs` — `ZoneKind`, `EscapeTrigger`, `ZoneClass`, `ZoneStats`, language-specific safe/escape patterns
- [x] `omniscope-core`: Added `issue.rs` — `IssueKind` (FFI boundary 90% + local memory 10%), `Confidence`, `FFIBoundary`, `BoundaryKind`, `TraceEntry`, `Issue`, CWE ID mapping
- [x] `omniscope-core`: Added `omniscope-types` dependency for Language type
- [x] `omniscope-semantics`: Added `surface_classifier.rs` — `FunctionSurface`, `SurfaceHint`, `Confidence`, multi-layer classification (L1 linkage + L2 source path)
- [x] `omniscope-registry`: Rewrote `semantic_registry.rs` — 6-layer + JNI/Python/POSIX registry with `RiskKind`, `RiskSeverity`, `MatchType`, `FunctionSemantics`
- [x] `omniscope-registry`: Added `serde` dependency to Cargo.toml
- [x] Full `cargo check` passes with 0 errors

### Phase B: Core Analysis Passes
- [x] **T1: CallGraphPass** — builds call graph from IR, classifies functions (Internal/LibC/ExternalUnknown), detects CrossLangEdge, FFI boundary detection with runtime-intrinsic filtering
- [x] **T2: SurfaceClassifierPass** — applies L1+L2+L3 classification, stores per-function surface in PassContext, upgrades Unknown→Boundary at FFI boundaries
- [x] **T3: FFIBoundaryPass** — rewritten with SemanticRegistry integration, checks each FFI boundary against risk database, produces Issue with FFIBoundary metadata, BoundaryKind classification
- [x] **T5: DangerSurfacePass** — graph-driven FFI boundary analyzer, traces from danger surfaces outward, checks high-risk callees via SemanticRegistry
- [x] **T6: NoiseReduction** — suppresses false positives from known safe patterns (drop_in_place, __rust_*, llvm.*, __cxa_*, etc.)
- [x] **T7: FPPrecisionGuard** — `PrecisionMetrics` with precision/recall/F1/FP rate, gate check with 88% precision threshold and 12% max FP rate
- [x] `make check` + `make fmt` both pass with 0 errors

### Phase C: Output System & Logging
- [x] **PassResult/PipelineResult** — added `issues: Vec<Issue>` field for concrete issue collection
- [x] **PassContext** — added `emit_issue()`, `next_issue_id()`, `issues()` methods for issue collection across passes
- [x] **FFIBoundaryPass** — now emits Issue objects into PassContext + PassResult (was only counting before)
- [x] **Pipeline** — `run()` now uses `run_all_with_issues()` to collect issues from context
- [x] **Output formatter module** — `omniscope-cli/src/output/` with `OutputFormat` trait
- [x] **RichFormatter** — canonical terminal output with Coverage/Findings/Summary sections, detection paths, FFI boundary info, severity sorting
- [x] **JsonFormatter** — serde-serialized JSON with pretty/compact modes
- [x] **SarifFormatter** — SARIF v2.1.0 with code flows, rule descriptors, CWE links, GitHub Code Scanning compatible
- [x] **CLI rewrite** — `analyze` command now uses formatters, `--format rich|json|sarif`, `--verbose`/`--debug` for log level control
- [x] **Tracing logs** — added `info!`/`debug!` to all passes (CallGraph, FFIBoundary, DangerSurface, SurfaceClassifier, CFG, DFG, MemorySafety, PointerOwnership, BufferOverflow, NoiseReduction, IR parser)
- [x] **Bug fix: `is_high_risk()`** — operator precedence bug: `matches && High || Critical` → `matches && (High || Critical)`
- [x] **Bug fix: `classify_source_path()`** — `.cargo/registry/` now classifies as `Dependency` (not `StandardLibrary`)
- [x] `make check` + `make fmt` + all tests pass with 0 errors

---

## Remaining Tasks (Priority Order)

### P1: Advanced Analysis (important, second wave)

- [ ] **T4: TaintPropagationPass rewrite** (`omniscope-pass/src/analysis/taint.rs`)
  - Track pointer flow from taint sources to sinks
  - Use SOURCE_FUNCTIONS / SINK_PATTERNS from call_graph_types
  - Confidence decay propagation
  - Depends on: CallGraphPass, DFG

### P2: Precision & Infrastructure (polish)

- [ ] **T8: Foundation passes real implementation** (`omniscope-pass/src/foundation/`)
  - CFG: build from IR basic blocks
  - DFG: build data flow edges from CFG
  - Both currently stubs, need real IR processing

- [ ] **T9: QueryEngine for FactStore** (`omniscope-core/src/fact.rs`)
  - Inverted index for O(1) single-dimension lookups
  - Index by kind, subject, object, context
  - Lazy index building

- [ ] **T10: Language detection enhancement** (`omniscope-semantics/src/language_detector.rs`)
  - 3-round weighted voting (sampling + personality + globals)
  - LanguageProfile with confidence score
  - Module-level detection (detect once, cache)

- [ ] **T11: PointerOwnershipPass rewrite** (`omniscope-pass/src/analysis/mod.rs`)
  - Track pointer ownership across FFI boundaries
  - Detect cross-language free mismatch
  - Depends on: FFIBoundaryPass, TaintPropagation

### P3: Output & CLI (nice-to-have)

- [x] **T12: SARIF output** — structured output for GitHub integration
- [x] **T14: Enhanced CLI** — integrate output formatters (rich/JSON/SARIF) + tracing logs
- [ ] **T13: LSP mode** — language server protocol for IDE integration

---

## Architecture Notes

### Key Design Principles (from Zig reference)

1. **Do NOT rely on crate name whitelists** — use provenance-based SurfaceClassifier instead
2. **Do NOT scan function bodies to decide "worth analyzing"** — use SurfaceClassifier
3. **Preserve FFI producer, boundary, and unknown scenarios** — never silently drop
4. **All heavy passes share the same surface classification result** via PassContext
5. **90/10 priority**: FFI boundary issues are core (90%), local memory is auxiliary (10%)
6. **Escape patterns override safe patterns** — conservative by default

### Dependency Graph

```
IR Parser → CallGraphPass → SurfaceClassifierPass → FFIBoundaryPass → DangerSurfacePass
                   ↓                                      ↓
              TaintPropagationPass                 PointerOwnershipPass
                   ↓                                      ↓
              NoiseReduction  ←  FPPrecisionGuard
```

### Module Size Tracking

| File | Lines | Status |
|---|---|---|
| `omniscope-types/src/call_graph_types.rs` | ~175 | OK |
| `omniscope-types/src/zone_types.rs` | ~210 | OK |
| `omniscope-core/src/issue.rs` | ~280 | OK |
| `omniscope-semantics/src/surface_classifier.rs` | ~230 | OK |
| `omniscope-registry/src/semantic_registry.rs` | ~310 | OK |
| `omniscope-pass/src/analysis/call_graph.rs` | ~250 | OK |
| `omniscope-pass/src/analysis/surface_classifier_pass.rs` | ~150 | OK |
| `omniscope-pass/src/analysis/mod.rs` | ~270 | OK |
| `omniscope-pass/src/analysis/danger_surface.rs` | ~110 | OK |
| `omniscope-pass/src/analysis/noise_reduction.rs` | ~180 | OK |
| `omniscope-cli/src/output/mod.rs` | ~85 | OK |
| `omniscope-cli/src/output/rich.rs` | ~180 | OK |
| `omniscope-cli/src/output/json.rs` | ~60 | OK |
| `omniscope-cli/src/output/sarif.rs` | ~150 | OK |
| `omniscope-cli/src/main.rs` | ~230 | OK |