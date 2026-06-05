# FFI Accuracy Development Plan

> Goal: improve true positives, reduce false negatives and false positives for cross-language FFI bug detection. This plan covers all supported FFI surfaces, not only Rust unsafe/FFI.

## 1. Scope

OmniScope should behave as an FFI-focused detector. A reportable high-confidence issue should usually be tied to a language boundary, ABI boundary, ownership transfer, callback escape, or resource-family mismatch across that boundary.

In scope:

- Rust `unsafe`, `extern "C"`, `Box::into_raw`, `CString::into_raw`, `from_raw`, `__rust_alloc`, `__rust_dealloc`
- C/C++ ABI crossings, C++ mangled symbols, `new/delete`, `new[]/delete[]`, RAII boundary leaks
- Zig allocator and C ABI interaction
- Go CGO pointer escape and C heap use
- Python C API, CFFI, borrowed/stolen/owned reference handling
- JNI local/global reference handling
- C# P/Invoke and SafeHandle/Dispose resource handling
- POSIX/library resources crossing FFI, such as file descriptors, `FILE*`, OpenSSL, SQLite, zlib, libuv

Out of scope for the FFI accuracy metric:

- Pure single-language internal resource issues with no FFI evidence
- Runtime/compiler glue noise unless it directly participates in a user-visible FFI bug
- Generic unchecked return warnings that are not tied to dangerous FFI/resource semantics

## 2. Current Baseline

The current `tests/accuracy_regression.rs` baseline records approximately:

| Metric | Baseline |
|---|---:|
| TP | 13 |
| FP | 22 |
| FN | 11 |
| Precision | 37.1% |
| Recall | 54.2% |
| F1 | 44.1% |

Short-term target:

| Metric | Target |
|---|---:|
| TP | >= 18 |
| FP | <= 15 |
| FN | <= 6 |
| Precision | >= 55% |
| Recall | >= 70% |

These targets should be measured on FFI-relevant fixtures only. General resource-analysis regressions should be tracked separately.

## 3. Core Strategy

Do not build a separate detector from scratch. Reuse the current resource pipeline:

```text
RawFactCollector
    -> ContractGraphBuilder
    -> OwnershipSolver
    -> IssueCandidateBuilder
    -> IssueVerifier
    -> Output
```

The next work should improve the evidence that flows through this pipeline:

- whether a call/resource edge is FFI-relevant
- which languages are on each side of the boundary
- whether the pointer/resource crosses ownership domains
- whether the pointer is owned, borrowed, retained, stolen, escaped, or reclaimed
- whether the evidence is runtime/internal noise or user FFI code

## 4. Use codegraph as an Auxiliary Tool

`codegraph` should be used as an auxiliary index, not as the final issue oracle.

Recommended responsibilities:

- Find FFI seed functions: external calls, exported wrappers, callbacks, function pointer calls, ABI boundary functions.
- Build a small FFI slice around each seed, default 2 hops.
- Identify caller/callee paths that connect allocation, boundary transfer, release, and use.
- Help explain why an issue is FFI-relevant.
- Help suppress issues outside the FFI slice in FFI-focused mode.

Suggested FFI slice model:

```text
seed:
  external declaration
  exported symbol
  cross-language call
  callback registration
  function pointer crossing ABI
  known family acquire/release symbol

expansion:
  backward callers: 2 hops
  forward callees: 2 hops
  resource pair closure: alloc/free and retain/release pairs
  callback closure: registered callback and userdata flow
```

## 5. P0 Work Items

### P0.1 Build an FFI-Focused Accuracy Harness

Files:

- `tests/accuracy_regression.rs`
- `tests/corpus_detection_audit.rs`
- optional: `tests/fixtures/ffi_accuracy_expectations.json`

Add metadata to expectations:

```text
file
function substring
accepted issue kinds
boundary kind
language pair
resource family
requires FFI evidence
is known TP / known FN / expected noise
```

Separate metrics:

- FFI Precision/Recall/F1
- General resource Precision/Recall/F1
- Runtime-noise FP count
- Known-FN recovery count

Success criteria:

- A single command prints TP/FP/FN and per-fixture diagnostics.
- Moving an item from known FN to TP is visible in the report.
- New FP functions are listed explicitly.

### P0.2 Add FFI Relevance Metadata

Files:

- `crates/omniscope-pass/src/module_index.rs`
- `crates/omniscope-pass/src/analysis/ffi_boundary_detector.rs`
- `crates/omniscope-pass/src/resource/raw_fact_collector.rs`
- `crates/omniscope-pass/src/resource/contract_graph_builder.rs`

Extend cached metadata and raw facts with:

```text
caller_language
callee_language
is_ffi_boundary
is_ffi_relevant
ffi_slice_depth
boundary_kind
is_runtime_internal
confidence
```

The first implementation can use conservative heuristics:

- known cross-language call
- non-C language calling external unknown declaration, likely C ABI
- exported function with pointer parameter/return
- callback registration or function pointer argument
- known acquire/release symbol from FFI contract database
- codegraph slice membership, when available

Success criteria:

- Existing passes can query FFI relevance without repeating string matching.
- FFI relevance is explainable in test output.

### P0.3 Add an FFI Gate Before High-Confidence Reporting

Files:

- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs`
- `crates/omniscope-pass/src/resource/issue_verifier.rs`
- optional: `crates/omniscope-pass/src/resource/issue_gate.rs`

High-confidence issue candidates should require at least one strong FFI signal:

- confirmed cross-language call
- resource family mismatch across boundary
- pointer escapes through callback/userdata
- owned/borrowed/stolen/retained contract violation across boundary
- codegraph proves the issue is inside an FFI slice

Candidates without FFI evidence should be downgraded or suppressed in FFI-focused mode.

Success criteria:

- FP decreases without hiding current confirmed FFI TPs.
- Suppressed issues are auditable with a reason.

## 6. P0 Detection Improvements

### P0.4 Cross-Family and Cross-Language Free

Target FN examples:

- `malloc` -> C++ `operator delete`
- `new/new[]` -> `free`
- Rust `__rust_alloc` -> C `free`
- C `malloc` -> Rust reclaim/dealloc path
- Zig allocator allocation -> raw C free
- Python object/memory allocation -> wrong family release

Required improvements:

- Track allocation family and release family on the same resource instance.
- Preserve caller/release caller names for language-boundary evidence.
- Avoid defaulting unknown family to `C_HEAP` when evidence is weak.

Success criteria:

- `cross_family_free` known misses become TP.
- Same-family internal releases are not reported as cross-family bugs.

### P0.5 Use-After-Free Through FFI

Target FN examples:

- free then pass pointer to external call
- free then pass alias to indirect call
- explicit release followed by callback/userdata use

Required improvements:

- Add lightweight alias propagation for `bitcast`, `getelementptr`, simple `load/store`, call return, and function argument forwarding.
- Treat external calls and indirect calls as uses when the pointer crosses an FFI boundary.
- Use codegraph to connect release and later FFI use in the same slice.

Success criteria:

- `uaf_through_ffi` and `indirect_uaf` become TP.
- Pure internal post-free patterns do not dominate FFI metrics unless configured.

### P0.6 Callback/Userdata Escape

Target FN examples:

- stack/local pointer passed as callback userdata
- Rust/Go/Zig owned pointer stored by C then freed/dropped by owner
- callback registered without matching unregister/revoke

Heuristics:

- callee name contains `register`, `set_callback`, `add_callback`, `subscribe`, `handler`
- arguments include function pointer plus pointer-like userdata
- userdata provenance is stack/local/borrowed/owned-by-managed-runtime
- missing matching unregister or release ordering is unsafe

Success criteria:

- `leaked_callback_userdata` and similar callback escape cases become TP.
- Read-only callback invocations without retained userdata stay clean.

## 7. P1 Work Items

### P1.1 Language-Specific Contract Refinement

Improve built-in FFI contract databases:

- Python: owned/borrowed/stolen references, `Py_INCREF`, `Py_DECREF`, `PyList_GetItem`, `PyTuple_SetItem`
- JNI: local/global/weak global refs, `NewGlobalRef`, `DeleteGlobalRef`, local ref lifetime
- Go: CGO pointer escape, C heap ownership
- C#: P/Invoke ownership, SafeHandle, Dispose/finalizer patterns
- C++: RAII suppressions, smart pointer boundaries, `new[]` vs `delete[]`
- Rust: `into_raw/from_raw`, allocator API, drop glue/runtime suppression

Success criteria:

- FFI contract DB gives stronger evidence than name-only matching.
- Borrowed/stolen/owned contract violations are classified consistently.

### P1.2 Runtime Noise Suppression

Runtime/internal noise should not dominate FFI metrics.

Suppress or downgrade:

- Rust core/alloc/drop glue/panic/runtime internals
- Zig stdlib/compiler_rt/allocator internals
- Go runtime and GC internals
- Python interpreter internals unless user extension code crosses the API incorrectly
- C++ ABI exception/runtime support

Success criteria:

- FP list is mostly user-facing FFI code, not runtime glue.
- Suppression reasons are visible in audit reports.

### P1.3 Better Path Sensitivity

Improve conditional leak and release ordering:

- distinguish definite leak from conditional leak
- model early returns around FFI allocation
- model paired cleanup on all exits
- avoid reporting leaks when RAII/defer/drop cleanup is proven

Success criteria:

- Leak TP increases without reintroducing large FP counts.
- Safe RAII/defer/drop cleanup fixtures stay clean.

## 8. Verification Commands

Run after each meaningful detector change:

```bash
cargo test accuracy_regression -- --nocapture
cargo test --test corpus_detection_audit -- --nocapture
cargo test ffi_analysis_tests
```

When changing shared resource logic, also run:

```bash
cargo test resource
cargo test regression
```

Record the result after each step:

```text
TP delta:
FP delta:
FN delta:
Precision delta:
Recall delta:
New TPs:
New FPs:
Suppressed issues:
Remaining top FNs:
```

## 9. Recommended Development Order

1. Add FFI-focused metric separation to the accuracy harness.
2. Add FFI relevance metadata to `ModuleIndex` and raw facts.
3. Add FFI gate before high-confidence candidate verification.
4. Recover cross-family/cross-language free known misses.
5. Recover UAF-through-FFI and indirect-call known misses.
6. Add callback/userdata escape detection.
7. Refine language-specific contracts and runtime suppression.

This order keeps the work measurable. First make the metric trustworthy, then lower FP with FFI evidence, then recover known FN classes one by one.
