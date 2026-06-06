# FFI Boundary and IR Semantics Accuracy Plan

> Goal: improve TP, reduce FN and FP for FFI/unsafe-related detection by strengthening two foundations: FFI boundary detection and precise IR semantic recognition. The plan uses existing OmniScope infrastructure first and uses `codegraph` as an auxiliary source/code graph tool, not as a replacement for IR analysis.

## 1. Core Thesis

The current detector should not be pushed by adding larger symbol whitelists. Accuracy should improve by making two signals more precise:

1. Boundary signal: is this call/resource flow actually crossing an ABI, language, runtime, callback, or ownership boundary?
2. Semantic signal: what does the IR prove about allocation, release, ownership transfer, pointer provenance, aliasing, cleanup, path conditions, and runtime management?

High-confidence issues should be emitted only when these signals support the same story:

```text
boundary evidence
  + resource / pointer semantic evidence
  + graph path connecting acquire -> transfer/use/release
  + no strong safe semantic resolution
  => report
```

This keeps the design graph-driven and semantics-driven instead of whitelist-driven.

## 2. Existing Infrastructure to Reuse

Use these components as the foundation:

| Layer | Existing component | Role |
|---|---|---|
| Source/code graph | `codegraph` | Source-level symbol context, callers/callees, impact analysis, test targeting |
| IR cache | `ModuleIndex` | Per-call/per-function cached language, family, external, runtime, call metadata |
| Boundary detection | `FFIBoundaryDetector`, `CallGraphPass`, `FFIBoundaryPass` | Cross-language and configured boundary recognition |
| Resource facts | `RawFactCollector`, `SummaryBuilder`, `StructuralInferencePass` | Acquire/release/escape/reclaim facts and inferred summaries |
| Resource graph | `ContractGraphBuilder`, `OwnershipSolver`, `MemoryGraph` | Resource instance graph and ownership state |
| IR behavior | `IRBehaviorSummaryPass`, `FunctionBehavior` | Behavior-derived summaries for symbols not covered by registry |
| Semantic resolution | `SemanticTree`, `SemanticKind`, `srt_resolutions`, `issue_gate` | FP suppression and semantic explanation |
| Candidate verification | `IssueCandidateBuilder`, `IssueVerifier`, `IssueGate` | Candidate creation, downgrade, suppression, final issue emission |
| Contracts | `FFIContractDB`, `FamilyRegistry`, language adapters | Library and language-specific ownership contracts |
| Metrics | `accuracy_regression`, `corpus_detection_audit` | TP/FP/FN tracking and regression protection |

## 2.5 Multi-Language IR Loading Performance Contract

All language frontends and runtime adapters must cooperate so IR loading is not the dominant cost. The immediate pressure point is C++ LLVM IR loading, but the rule is broader: C/C++, Rust, Java/JNI, Zig, Python/C API, Go/cgo, and future language adapters must share one Rust-owned orchestration path instead of each adapter reloading or reparsing whole IR independently.

The unacceptable failure mode is:

```text
total analysis time: 10s
IR load/extract: 9.5s
semantic analysis: 0.5s
```

That means no backend should be used as a repeated whole-module loader for every analysis pass, every test case, or every retry path. C++ should be an expensive producer of reusable LLVM facts; Rust should own orchestration, caching, slicing, fallback, and repeated semantic analysis. Language adapters should consume normalized IR facts and emit typed semantic facts, not trigger another extraction path.

Required contract:

- Rust calls a heavyweight backend at most once per unchanged input, strategy, slice mode, extractor version, schema version, and relevant config.
- C++ emits a compact structured representation for Rust to reuse; prefer MessagePack for direct extractor output and JSON only as compatibility fallback.
- Java/JNI, Zig, Python, Go/cgo, Rust, and C/C++ semantics are derived from `IRModule`, `ModuleIndex`, `FunctionBehavior`, `SemanticFact`, and contract DB data. They do not own separate IR loaders.
- Rust keeps heavyweight backend output in `IrCache` with strategy-specific keys (`direct-cpp`, `direct-cpp-ffi`, slice mode, config version).
- FFI-focused analysis uses `DirectCppFfi` or an equivalent FFI slice first, not whole-module extraction.
- `.ll` files use the Rust text parser fast path for tests and small/medium development workflows unless richer C++ facts are explicitly required.
- Empty FFI slices are a soft result, not a reason to rerun full C++ extraction blindly.
- Backend discovery (`opt`, pass plugin, direct extractor path) is cached with `OnceLock` and must not scan the filesystem per analysis.
- Any pass that needs IR facts consumes `IRModule`, `ModuleIndex`, summaries, or cached model data; it must not spawn C++ directly.

Language adapter contract:

| Adapter | Input it may consume | Output it must emit | Must not do |
|---|---|---|---|
| C/C++ | LLVM call/function/type facts, mangling, allocation symbols, EH cleanup blocks | allocation family, release family, RAII cleanup, exception cleanup, ABI boundary facts | Spawn `opt`/extractor from resource or boundary passes |
| Rust | LLVM symbols, alloc/dealloc calls, drop glue, panic paths, raw ownership calls | `IntoRawTransfer`, `ReclaimRaw`, `RuntimeManagedResource`, drop cleanup facts | Treat Rust runtime internals as user FFI boundaries without wrapper evidence |
| Java/JNI | JNI symbol calls, native method exports, local/global ref calls, env pointer usage | local/global/weak reference ownership, frame lifetime, global-ref release requirements | Model JNI refs as ordinary C heap pointers |
| Zig | allocator vtable calls, `c_allocator`, defer-like cleanup shape, Zig runtime symbols | allocator-instance facts, defer cleanup, runtime suppression, C allocator bridge facts | Equate every allocator free with raw `free` |
| Python | Python C API calls, refcount calls, borrowed/stolen APIs, GIL calls | owned/borrowed/stolen ref facts, refcount balance, GIL state facts | Treat `PyObject*` as ordinary `malloc` memory |
| Go/cgo | cgo bridge symbols, Go runtime allocation, C heap calls, pointer escape patterns | Go-GC pointer escape, C-owned memory lifecycle, runtime-managed allocation facts | Report Go runtime allocations as C heap leaks |

Implementation notes for the current codebase:

- `load_ir(..., LoadStrategy::AutoFast)` should remain the default developer/test path for `.ll` inputs.
- `DirectCppFfi` should keep `--slice=ffi --slice-hops=2 --no-raw --format=msgpack` as the fast C++ path.
- `IrCache::check_cache_with_params` / `save_to_cache_bytes_with_params` should be the normal path for direct C++ output.
- Add the extractor binary version, plugin mtime, or schema version into the `extra` cache key before changing extractor output semantics.
- Keep `LoadedIr.load_ms`, `backend_ms`, `deserialize_ms`, and `cache_hit` meaningful enough to diagnose regressions; returning `None` forever for backend/deserialization timings is not sufficient for performance work.
- Add language adapter timing counters separately from IR load timing. Slow Java/Python/Zig/Go semantic adaptation should not be hidden inside "load" time.

Performance acceptance:

```text
warm unchanged input:
  C++ backend invocation count = 0
  cache_hit = true
  load time should be dominated by cache read + deserialize

FFI-focused input:
  DirectCppFfi output size << whole-module output size when non-FFI code dominates
  Rust semantic passes operate only on the sliced/cached module unless full context is requested

inline test IR:
  no C++ backend process is spawned
  tests exercise parser + Rust semantic passes directly

multi-language semantic pass:
  each adapter consumes shared indexed IR facts
  no adapter reparses the whole module
  per-language adaptation time is measured independently
```

Regression tests should include a fake or counted backend seam where possible. At minimum, tests must protect that inline IR fixtures call `IRModule::parse_from_text` and not `IRModule::load_from_file`, because unit/integration tests with large embedded IR should not pay C++ process startup or whole-module load cost.

## 3. How to Use codegraph

`codegraph` is useful for source-level intelligence and development workflow. It should not decide LLVM IR semantics.

Current available commands:

```bash
codegraph status .
codegraph context "<task>"
codegraph query <symbol>
codegraph callers <symbol>
codegraph callees <symbol>
codegraph impact <symbol>
codegraph affected <files...>
codegraph sync .
```

Recommended uses:

- Build implementation context before touching a pass:
  ```bash
  codegraph context "improve FFI boundary detection in ModuleIndex CallGraph FFIBoundaryDetector"
  ```
- Inspect pass impact:
  ```bash
  codegraph impact FFIBoundaryDetector
  codegraph impact ContractGraphBuilder
  codegraph impact SemanticKind
  ```
- Find call sites and dependencies:
  ```bash
  codegraph callers is_ffi_boundary
  codegraph callers emit_issue
  codegraph callees IssueVerifierPass::run
  ```
- Select tests after changes:
  ```bash
  codegraph affected crates/omniscope-pass/src/analysis/ffi_boundary_detector.rs
  ```

Planned optional integration:

- Add a small developer script that runs `codegraph context` for known tasks and writes context to `target/codegraph_context/*.md`.
- Use `codegraph affected` in local CI guidance to recommend focused tests.
- Do not make runtime analysis depend on `codegraph`; the analyzer should remain deterministic from IR input and config.

## 4. Boundary Detection Plan

### 4.1 Replace Boolean Boundary with Boundary Confidence

Current metadata has mostly boolean fields such as `is_cross_language` and `is_ffi_boundary`. Replace the internal model with a small confidence object while preserving old booleans for compatibility:

```text
BoundaryEvidence {
  kind: LanguagePair | ExternalAbi | ConfiguredBoundary | ExportedWrapper |
        CallbackRegistration | FunctionPointerAbi | RuntimeBridge | Unknown,
  caller_lang,
  callee_lang,
  confidence,
  reason,
}
```

Where to store it:

- `CachedCallMeta` in `ModuleIndex`
- `CallGraphEdge` / `CrossLangEdge`
- `RawResourceFact`
- `ContractEdge`
- `IssueCandidate`

Do not treat every resource mismatch as FFI boundary evidence. Resource mismatch is a resource signal; it becomes FFI-relevant only when connected to a boundary or ABI flow.

### 4.2 Boundary Seed Rules

Use graph and IR properties first:

Strong boundary seeds:

- Known cross-language edge where both languages are known and different.
- User-configured boundary from `--cross`.
- Non-C language calling an external unknown declaration, resolved as likely C ABI.
- C calling C++ Itanium symbol, excluding Rust `_ZN` mangling.
- Exported wrapper with pointer parameter or pointer return.
- Function pointer passed to or returned from external call.
- Callback registration pattern with function pointer plus userdata.

Weak boundary seeds:

- Known FFI contract symbol called from same language.
- Dangerous libc/resource function inside a wrapper.
- Runtime bridge symbol, only when connected to user-facing boundary flow.

Suppression seeds:

- LLVM intrinsics.
- Compiler/runtime glue with no user boundary path.
- Pure libc helper with no ownership transfer.
- Internal same-language call with no external declaration, callback, or exported ABI evidence.

### 4.2.1 Multi-Language Boundary Matrix

Boundary evidence should be language-aware, but the internal model should stay generic. Each adapter maps language-specific IR shapes into the same `BoundaryEvidence` kinds.

| Source/target | Strong boundary evidence | Resource semantics to attach | Common FP suppression |
|---|---|---|---|
| Rust -> C | `extern "C"` style external call, unmangled C symbol, pointer args/returns | raw pointer borrow/own transfer, `Box`/`CString`/`Vec` raw ownership | pure compute calls, libc helpers with no ownership transfer |
| C -> Rust | exported Rust ABI wrapper, Rust v0/legacy mangled callee behind C wrapper | Rust allocator/deallocator, drop glue, panic boundary | Rust runtime/panic glue with no user wrapper |
| C -> C++ | C wrapper calling Itanium/MSVC C++ symbols, C allocation passed to C++ | C heap vs C++ new/delete family, RAII cleanup | pure C++ compute helper called from C bridge |
| C++ -> C | `extern "C"` call, libc/resource calls, callback registration | C heap ownership, callback userdata, errno/out-param patterns | STL/runtime allocation internals not crossing wrapper boundary |
| Java/JNI -> native | `JNIEXPORT` native methods, `JNIEnv*`, `Java_pkg_Class_method` names | local/global/weak refs, array/string pinning, exception state | local refs auto-released by native frame |
| native -> Java/JNI | `Call<Type>Method`, `NewObject`, `NewGlobalRef`, callback through JVM | ref lifetime, pending exception path, global ref cleanup | `FindClass`/local lookup when frame lifetime is sufficient |
| Zig -> C | `c_allocator`, extern declarations, C ABI wrapper names | allocator instance, C heap bridge, `defer` cleanup | Zig runtime/compiler_rt symbols |
| C -> Zig | exported Zig ABI functions, Zig namespace-mangled symbols behind C wrapper | Zig allocator ownership, slice/pointer length pair | Zig panic/runtime helpers without user boundary |
| Python -> C | Python extension module entrypoints, C API calls, capsule/cffi/ctypes patterns | owned/borrowed/stolen refs, buffer views, GIL state | borrowed refs used read-only, non-owning views |
| C -> Python runtime | `PyObject_Call*`, refcount APIs, module callbacks | refcount transfer, callback escape, exception state | interpreter-managed singleton/borrowed objects |
| Go -> C | cgo bridge wrappers, `_cgo_*`, C symbols from Go wrappers | Go pointer escape to C, C heap ownership, finalizer/defer cleanup | Go runtime allocation and stack maps |
| C -> Go | exported cgo functions, callbacks into Go, handle indirection | Go handle lifetime, pinned pointer rules, C-owned pointer release | runtime trampoline internals |

The boundary detector should produce one or more `BoundaryEvidence` records for these cases, then the candidate gate decides whether resource evidence makes it reportable.

### 4.3 Boundary Slice

Build an FFI slice around boundary seeds in `ModuleIndex` or a new lightweight `FfiSlice` stored in `PassContext`.

Default expansion:

```text
backward callers: 2 hops
forward callees: 2 hops
resource pair closure: acquire/release pairs
callback closure: register/unregister/callback/userdata edges
ownership closure: into_raw/from_raw, retain/release, inc/dec
```

Each function/call can then carry:

```text
ffi_slice_depth: 0 for seed, 1..N for expanded context
ffi_relevance: Strong | Weak | None
ffi_reason: short explainable reason
```

This directly helps:

- Reduce FP: suppress or downgrade candidates outside FFI slice in FFI-focused mode.
- Reduce FN: include helper functions that do allocation/release around FFI wrappers.
- Explain reports: show why the issue is FFI-relevant.

### 4.4 Boundary-Aware Candidate Gate

Do not use a single `has_ffi_evidence()` boolean unless evidence is separated.

Use two classes:

```text
Boundary evidence:
  CrossLanguageCall
  ConfiguredBoundary
  ExternalAbiCall
  CallbackAcrossBoundary
  FunctionPointerAbi
  ExportedWrapper

Resource evidence:
  CrossFamilyRelease
  OwnershipTransfer
  BorrowedAsOwned
  RetainReleaseMismatch
  FfiReturnUnchecked
```

High-confidence reporting should usually require:

```text
boundary evidence OR ffi_slice_depth <= 2
AND resource/pointer evidence
AND no strong safe SemanticKind
```

Exceptions:

- Definite memory bugs such as double-free or UAF can still be reported outside FFI mode, but should not count as FFI TP unless boundary evidence exists.

## 5. IR Semantic Recognition Plan

### 5.1 Create a Unified Semantic Fact Layer

Today semantic information is split across `RawResourceFact`, `FunctionBehavior`, `SemanticKind`, `SummaryStore`, `ContractEdge`, and `MemoryGraph`.

Keep those structures, but add a normalized semantic fact layer:

```text
SemanticFact {
  key: Symbol | Value | Resource | Path | Owner | CallSite,
  kind: SemanticKind,
  confidence,
  source: IRPattern | ContractDB | BehaviorSummary | BoundaryDetector | MemoryGraph,
  evidence: short reason
}
```

This can initially be implemented by extending `srt_key_resolutions` and `SemanticTree`, without a large rewrite.

### 5.2 Prioritize IR Behavior Over Symbol Names

The current `StructuralInferencePass` already prefers `IRBehaviorSummaryPass` over symbol-name inference. Expand this direction:

IR behavior summaries should identify:

- allocation-like return
- release-like argument consumption
- conditional release
- ownership escape/reclaim
- returns borrowed pointer
- stores pointer to global/owner/runtime
- callback registration
- function pointer call
- out-param initialization
- null/error path
- cleanup on all exits

Symbol names should remain a fallback, not the primary proof.

### 5.3 Add Value/Resource-Level Semantics

Most FP/FN comes from losing pointer identity. Add value/resource keys to semantic resolution:

```text
SemanticKey::Value("%ptr")
SemanticKey::Resource(resource_id)
SemanticKey::Path(function, path_id)
SemanticKey::Owner(owner_symbol)
```

Track these facts:

- `HeapProvenance`
- `GlobalProvenance`
- `FromParameter`
- `IntoRawTransfer`
- `RuntimeManagedResource`
- `StoredToOwner`
- `StoredToRuntime`
- `EscapedToCaller`
- `EscapedToOutParam`
- `ReleaseOnAllExitPaths`
- `AliasOfReleased`
- `NonMemoryResource`
- `NullOnErrorPath`

This avoids broad function-level suppression. A function may contain one safe runtime-managed pointer and one real bug; suppression should apply to the right value/resource, not the whole function.

### 5.4 Lightweight Alias Semantics

Avoid full points-to analysis initially. Add a narrow alias model over common LLVM IR operations:

```text
same resource identity:
  bitcast
  getelementptr with same base pointer
  ptrtoint/inttoptr round-trip when local and direct
  load/store through local alloca slot
  phi/select with same-family inputs
  function argument forwarding within FFI slice
```

Outputs:

- `AliasOfReleased`
- canonical resource ID for acquire/release/use edges
- post-release FFI use evidence

This helps:

- `double_free_aliasing`
- `uaf_through_ffi`
- `indirect_uaf`
- cross-family free where release uses an alias.

### 5.5 Path Semantics Without Full Symbolic Execution

Add small path facts before attempting full path-sensitive analysis:

- release happens on all exits
- release only on success path
- out-param null on error
- early return before cleanup
- cleanup block post-dominates allocation
- `defer`/RAII/drop cleanup guarantees release

These should map to:

- `ReleaseOnAllExitPaths`
- `FallibleOutParamInit`
- `NullOnErrorPath`
- language-specific cleanup kinds

This reduces leak FP and improves partial-failure FN.

## 6. ContractGraph and ResourceGraph Improvements

### 6.1 Cross-Family Matching

In `ContractGraphBuilder`, keep same-family FIFO matching first, then add a controlled cross-family fallback:

```text
same function
release occurs after acquire
both families known
families incompatible
same-family match unavailable
single unmatched acquire OR nearest unmatched acquire within small distance
```

This should recover:

- `malloc -> operator delete`
- `new[] -> free`
- Zig allocator allocation -> raw free
- C allocation reclaimed through Rust raw ownership path

Do not blindly pair all `alloc_family != release_family`. That would create FP in functions managing multiple independent resources.

### 6.2 FFI Use Edges

To detect UAF through FFI, the graph must represent calls that use a pointer after release.

Use existing effects where possible:

- `ConsumesArg`
- `StoresArgToGlobal`
- `StoresArgToOwner`
- `EscapesToCallback`

Add those edges for external/indirect/callback calls when an argument aliases a tracked resource and the call is in the FFI slice.

Then `IssueCandidateBuilder` can treat post-release use edges as UAF evidence.

### 6.3 Callback/Userdata Edges

Represent callback registration as graph edges:

```text
resource/userdata -> EscapesToCallback(register_call)
callback function -> FunctionPointerAbi
register -> optional unregister/revoke pair
```

Detect:

- stack/local userdata escapes to C
- managed-runtime pointer stored by native side
- unregister missing
- owner frees/drops while native side may retain pointer

This should be P1/P2 because lifetime modeling is harder than same-function cross-family matching.

## 7. Language-Specific Semantic Adapters

Keep language adapters, but make them emit semantic contracts and semantic facts instead of only naming patterns.

Adapter output should be normalized:

```text
LanguageAdapterResult {
  language,
  boundary_facts: Vec<BoundaryEvidence>,
  semantic_facts: Vec<SemanticFact>,
  resource_facts: Vec<RawResourceFact>,
  suppressions: Vec<SemanticResolution>,
  confidence,
}
```

Each adapter is responsible for translating language-specific IR shapes into generic ownership and boundary facts. It is not responsible for final issue emission.

### Rust

Focus:

- `Box::into_raw` / `Box::from_raw`
- `CString::into_raw` / `CString::from_raw`
- `Vec::from_raw_parts`
- `__rust_alloc` / `__rust_dealloc`
- drop glue and panic paths

Key facts:

- ownership transferred to raw pointer
- reclaim required exactly once
- drop glue is runtime cleanup, not user FFI bug

IR evidence:

- calls to `__rust_alloc`, `__rust_alloc_zeroed`, `__rust_dealloc`, `__rust_realloc`
- Rust mangled functions and drop glue symbols
- calls that look like `Box::into_raw`, `Box::from_raw`, `CString::into_raw`, `CString::from_raw`
- panic/unwind cleanup blocks

Priority tests:

- clean Rust -> C passthrough with pointer args
- Rust allocation reclaimed by Rust dealloc
- Rust raw pointer handed to C and freed by C
- C allocation reclaimed through Rust raw ownership path
- panic/drop cleanup suppressing false leak

### C/C++

Focus:

- `malloc/calloc/realloc/free`
- `new/delete`, `new[]/delete[]`
- destructors, smart pointers, RAII cleanup
- exception cleanup paths

Key facts:

- scalar vs array allocation family
- RAII cleanup suppresses leak
- C++ ABI runtime is not user boundary unless linked to wrapper

IR evidence:

- `malloc/calloc/realloc/free`
- `_Znwm`, `_Znam`, `_ZdlPv`, `_ZdaPv`, MSVC equivalents where available
- constructor/destructor calls and EH cleanup landing pads
- C wrappers calling Itanium/MSVC C++ symbols
- function pointer callback registration with userdata

Priority tests:

- `malloc -> free` clean
- `malloc -> operator delete` mismatch
- `new[] -> delete[]` clean
- `new[] -> free` mismatch
- C bridge calling C++ pure compute without ownership transfer
- callback userdata lifetime escape

### Zig

Focus:

- allocator vtable calls
- `c_allocator`
- `defer` cleanup
- Zig runtime/compiler_rt suppression

Key facts:

- allocator instance matters; raw `free` is not equivalent to allocator free
- defer cleanup can prove release
- runtime internals should not become user-facing FP

IR evidence:

- allocator vtable `alloc`/`free` calls
- `std.heap.c_allocator` and C ABI calls
- Zig namespace-like symbol names and compiler_rt/runtime symbols
- cleanup blocks corresponding to `defer`
- slice pointer/length pairs crossing C ABI

Priority tests:

- Zig allocator alloc/free clean
- Zig allocator allocation freed by raw `free`
- C allocation freed through Zig `c_allocator`
- `defer` cleanup suppressing leak
- Zig runtime/compiler_rt calls suppressed

### Go/CGO

Focus:

- Go pointer to C
- C heap allocation and cleanup
- runtime finalizer/defer cleanup

Key facts:

- Go GC pointer retained by C is unsafe
- C memory must be freed by C-compatible release
- Go runtime allocation is runtime-managed, not a C heap leak

IR evidence:

- `_cgo_*` bridge symbols and exported Go callback wrappers
- Go runtime allocation/finalizer/defer-like cleanup symbols
- C heap calls inside cgo wrappers
- pointer passed from Go-managed allocation to C storage/callback
- handle indirection patterns for safe Go object references

Priority tests:

- C malloc/free inside cgo clean
- C malloc returned to Go and never freed
- Go pointer stored by C callback/userdata
- Go runtime allocation suppressed as runtime-managed
- finalizer/defer cleanup lowering leak confidence

### Python C API

Focus:

- owned/borrowed/stolen refs
- `Py_INCREF` / `Py_DECREF`
- GIL state

Key facts:

- borrowed refs must not be decref'd as owned
- stolen refs transfer ownership to container
- refcount balance is resource semantics, not ordinary heap matching

IR evidence:

- `PyObject_New`, `Py_INCREF`, `Py_DECREF`, `Py_XINCREF`, `Py_XDECREF`
- borrowed APIs such as `PyList_GetItem`, `PyTuple_GetItem`, `PyBytes_AsString`
- stolen-reference APIs such as `PyTuple_SetItem`, `PyList_SetItem`
- `PyGILState_Ensure` / `PyGILState_Release`
- `PyErr_*` exception paths

Priority tests:

- owned ref decref clean
- owned ref leak
- borrowed ref decref invalid
- stolen ref transferred into container
- GIL ensure/release pairing
- Python buffer pointer escaping to C

### JNI

Focus:

- local/global/weak refs
- `NewGlobalRef` / `DeleteGlobalRef`
- local ref lifetime

Key facts:

- local refs auto-release at native frame exit
- global refs require explicit delete
- weak refs require liveness check before use

IR evidence:

- `Java_pkg_Class_method` exported native method names
- `JNIEnv*` calls to `NewGlobalRef`, `DeleteGlobalRef`, `NewLocalRef`, `DeleteLocalRef`
- `GetStringUTFChars` / `ReleaseStringUTFChars`
- `Get<Primitive>ArrayElements` / `Release<Primitive>ArrayElements`
- `ExceptionCheck` / `ExceptionClear` / pending exception paths

Priority tests:

- local refs not reported as leaks at native frame exit
- global ref leak
- global ref delete clean
- string chars get/release clean
- array elements get without release
- exception path skipping cleanup

### C# P/Invoke

Focus:

- `Marshal.AllocHGlobal` / `FreeHGlobal`
- SafeHandle
- Dispose/finalizer

Key facts:

- SafeHandle owns cleanup
- finalizer is fallback cleanup, lower confidence than deterministic release
- raw handles crossing P/Invoke need explicit ownership contract

## 8. Avoiding Large Whitelists

Allowed:

- Small, typed contract entries for external libraries with explicit ownership semantics.
- IR-shape rules such as "argument is stored to global" or "cleanup post-dominates allocation".
- ABI facts such as declaration/external/exported/calling convention/pointer parameter.
- Language-specific ownership rules that map to generic semantic kinds.

Avoid:

- Large "safe function name" lists.
- Suppressing whole functions because one symbol name looks runtime-like.
- Treating every libc call as safe or unsafe.
- Treating every cross-family mismatch as FFI.
- Treating every FFI call as a bug.

The preferred rule form:

```text
IR pattern + resource family + boundary context + semantic confidence
```

not:

```text
function name is in safe/unsafe list
```

## 9. Implementation Phases

### Phase 0: Metrics and Review Fixes

Tasks:

- Keep `accuracy_regression` thresholds meaningful.
- Separate FFI metrics from general resource metrics.
- Split boundary evidence from resource evidence.
- Add separate `SuppressRuntimeInternal` verdict instead of reusing `SuppressRaii`.

Verification:

```bash
cargo test accuracy_regression -- --nocapture
cargo test --test corpus_detection_audit -- --nocapture
```

### Phase 1: Boundary Evidence and FFI Slice

Tasks:

- Add `BoundaryEvidence` to `CachedCallMeta`.
- Add `ffi_slice_depth`, `ffi_relevance`, and `ffi_reason` to function/call metadata.
- Build FFI slice from strong seeds and 2-hop expansion.
- Feed this metadata into raw facts and contract edges.

Expected impact:

- Lower FP from non-boundary internal resource reports.
- Better explanation for FFI reports.

### Phase 2: Cross-Family Matching in ContractGraph

Tasks:

- Same-family FIFO remains first.
- Add controlled same-function cross-family fallback.
- Ensure C++ `new[]` / delete families are correctly classified.
- Add tests for `malloc -> operator delete`, `new[] -> free`, Zig allocator -> raw free.

Expected impact:

- Recover 2-3 TP with small code change.

### Phase 3: IR Semantic Fact Layer

Tasks:

- Extend SRT to support value/resource/call-site keys.
- Emit facts from IR behavior summaries.
- Attach facts to candidate evidence and issue explanations.
- Avoid function-wide suppression when value/resource-specific facts exist.

Expected impact:

- Lower FP from over-broad suppression.
- Improve explainability.

### Phase 4: Post-Release FFI Use

Tasks:

- Add FFI use edges for external/indirect/callback calls.
- Add lightweight alias propagation for bitcast/GEP/local store/load/arg forwarding.
- Extend UAF candidate generation to use post-release FFI use edges.

Expected impact:

- Recover `uaf_through_ffi` and `indirect_uaf` style TP.

### Phase 5: Callback and Ownership Propagation

Tasks:

- Model callback registration, userdata escape, unregister/revoke.
- Add cross-function ownership propagation within FFI slice.
- Add language-specific callback rules for C, Zig, Go, Rust, JNI, C#.

Expected impact:

- Recover callback userdata dangling and managed-runtime pointer escape cases.

### Phase 6: Path Semantics

Tasks:

- Add cleanup-on-all-exits and fallible out-param facts.
- Distinguish definite leak from conditional leak.
- Use post-dominator-like local CFG checks where available.

Expected impact:

- Lower leak FP and recover partial-failure leak FN.

### Phase 7: Multi-Language Adapter Normalization

Tasks:

- Add a shared `LanguageAdapterResult` shape or equivalent builder API.
- Convert Rust, C/C++, Zig, Go/cgo, Python C API, and JNI adapters to emit normalized semantic facts.
- Keep language-specific logic in adapters, but keep candidate generation language-neutral.
- Add adapter timing counters and per-language fact counts.

Expected impact:

- Prevent duplicated ownership logic across passes.
- Make new language support additive instead of changing candidate generation every time.
- Make slow adapter behavior visible before it becomes another loading bottleneck.

### Phase 8: Multi-Language Boundary Regression Suite

Tasks:

- Add generated inline IR corpora for Java/JNI, Zig, Python C API, and Go/cgo.
- Keep large inline corpora self-contained and parser-based.
- Add file-fixture tests only for realistic compiler output after inline tests define expected semantics.
- Record per-language TP/FP/FN separately.

Expected impact:

- Catch regressions in mainstream FFI ecosystems, not only C++/Rust.
- Keep correctness tests fast enough to run locally.
- Separate language semantics failures from loader/backend failures.

## 10. Testing Plan

Focused commands:

```bash
cargo test accuracy_regression -- --nocapture
cargo test --test corpus_detection_audit -- --nocapture
cargo test ffi_analysis_tests
cargo test regression_tests
cargo test --test integration_tests large_inline_cpp_rust_ffi
cargo test --test integration_tests jni
cargo test --test integration_tests zig
cargo test --test integration_tests python
cargo test --test integration_tests go
```

For resource graph changes:

```bash
cargo test contract_graph_builder
cargo test ownership_solver
cargo test resource
```

For semantic changes:

```bash
cargo test semantic_tree
cargo test structural_inference
cargo test issue_gate
```

Use `codegraph affected` to select additional tests after each file change.

Inline IR test requirements:

- Add large generated embedded IR cases rather than relying only on external `.ll` fixtures.
- Cover clean C++ bridge calls, Rust-to-C passthrough calls, C heap paired release, Rust allocator paired release, C++ new/delete paired release, and deliberate mismatches.
- Add equivalent generated corpora for JNI refs, Python refcounts, Zig allocator/defer cleanup, and Go/cgo pointer escape.
- Keep the test self-contained with `IRModule::parse_from_text` so it never invokes the C++ loader.
- Assert both volume (`functions.len()`, `calls.len()`) and semantic result shape, not just "pipeline ran".
- Include enough functions to make accidental O(N^2) pass behavior visible during local runs.

Required language coverage matrix:

| Language area | True positives | True negatives | Scale test |
|---|---|---|---|
| C/C++ | `malloc -> delete`, `new[] -> free`, callback userdata escape | `malloc/free`, `new/delete`, pure C++ compute bridge | generated C/C++ bridge corpus |
| Rust | Rust raw ownership freed by C, C allocation reclaimed wrongly by Rust | Rust alloc/dealloc, Rust -> C passthrough | generated Rust/C FFI corpus |
| Java/JNI | global ref leak, array/string chars missing release, exception cleanup skip | local ref frame cleanup, global delete, get/release pair | generated JNI native corpus |
| Zig | allocator freed by wrong allocator/raw free, missing defer cleanup | allocator alloc/free, `defer` release, runtime suppression | generated Zig allocator corpus |
| Python | owned ref leak, borrowed ref decref, missing GIL release | owned decref, stolen ref transfer, borrowed read-only use | generated Python C API corpus |
| Go/cgo | Go pointer retained by C, C heap leak through cgo | C malloc/free, Go runtime allocation suppression | generated cgo bridge corpus |

Metrics to record after each phase:

```text
FFI TP:
FFI FP:
FFI FN:
FFI Precision:
FFI Recall:
General resource TP/FP/FN:
New TPs:
New FPs:
Suppressed count by reason:
Top remaining FN classes:
```

## 11. Recommended Immediate Next Steps

1. Fix evidence semantics:
   - Separate boundary evidence from resource evidence.
   - Do not let `CrossFamilyRelease` alone satisfy FFI evidence.

2. Add boundary confidence and FFI slice metadata to `ModuleIndex`.

3. Implement controlled cross-family fallback in `ContractGraphBuilder`.

4. Add value/resource keyed semantic facts for alias/provenance.

5. Add FFI use edges and extend UAF detection.

6. Add loader performance instrumentation and cache-hit tests before expanding C++ extraction output.

7. Keep adding large inline IR regression cases for C++/Rust cooperation so correctness tests do not depend on slow C++ IR loading.

8. Extend the same inline-IR strategy to JNI, Zig, Python C API, and Go/cgo before adding more file fixture tests.

This sequence maximizes reuse of existing infrastructure and targets the current highest-yield FN classes before moving into larger callback and path-sensitive work.
