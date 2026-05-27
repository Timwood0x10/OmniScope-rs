# OmniScope-rs Architecture Adjustment Plan

This document defines the architecture direction for the Rust implementation while the project is still early enough to avoid carrying the same patch-style false-positive model from the Zig version.

The goal is not to port every existing rule. The goal is to build a stable semantic foundation where new languages, runtimes, allocators, wrappers, and FFI idioms are represented as resource contracts instead of scattered name checks.

## Development Rules

Follow the repository rules in `aim/rules/rules.md` and keep the same engineering discipline as the Zig project:

- Keep each source file under 500～1000 lines; split modules before they become rule dumps.
- `make check` must return 0 errors before merge.
- Run `make fmt` after each modification.
- Do not silence warnings with `#[allow(dead_code)]` as a substitute for design cleanup.
- Do not use `println!` in tests; use `tracing` / test subscribers when output is needed.
- Public APIs must have doc comments.
- All errors must include module and method context.
- Tests must verify invariants and edge cases, not only happy paths.
- Unsafe code must be isolated, documented, and covered by targeted tests.

## Problem Statement

The anti-pattern to avoid is:

```text
classify_function(callee_name) -> language
if alloc_language != free_language:
    report issue
```

That model treats language as the semantic unit. It is not. The actual semantic units are:

- **Resource family**: which allocator/runtime/resource domain owns the value.
- **Pointer contract**: whether the value is owned, borrowed, transferred, retained, returned, or stored.
- **Function effect**: what a function does to a resource.
- **Escape kind**: how a pointer leaves the current scope.
- **Verification evidence**: why a candidate is a real issue or why it is explained.

Language remains useful for demangling, ABI hints, platform defaults, and report context. It must not be the primary criterion for alloc/free matching.

## Target Architecture

The Rust implementation should be organized around a Resource Contract Graph:

```text
LLVM IR
  -> Raw Facts
  -> Semantic Classification
  -> Function Summary Inference
  -> Resource Contract Graph
  -> Ownership State Solver
  -> Issue Candidate Builder
  -> Issue Verifier
  -> Report
```

Only the verifier should produce reportable issues. Earlier stages produce facts, summaries, graph edges, states, and candidates.

## Workspace Mapping

Use the existing crate layout and add resource-contract modules without creating cross-crate cycles.

| Crate | Responsibility |
|-------|----------------|
| `omniscope-ir` | LLVM IR loading, raw facts, platform/canonical symbol normalization |
| `omniscope-types` | Shared IDs, enums, compact public data types |
| `omniscope-semantics` | Resource family registry, contracts, effects, summaries, evidence |
| `omniscope-dataflow` | Graph traversal, path slicing, ownership state propagation helpers |
| `omniscope-pass` | Analysis passes that build resource graph, candidates, and verifier verdicts |
| `omniscope-pipeline` | Pass scheduling, shared stores, debug trace flags |
| `omniscope-core` | Diagnostics, issue model, errors, profiling, fact storage |
| `omniscope-registry` | Config/model loading and optional project semantic model registry |
| `omniscope-cli` | CLI flags, model mining command, output selection |

## Core Types

Place stable type definitions in `omniscope-types` if they are shared by multiple crates. Place logic and registries in `omniscope-semantics`.

### Resource Family

`ResourceFamily` replaces language-based allocator matching.

```rust
pub struct ResourceFamily {
    pub id: FamilyId,
    pub name: &'static str,
    pub kind: FamilyKind,
    pub lifetime: LifetimeDomain,
    pub compatible_releases: &'static [FamilyId],
}
```

Required families for the first implementation:

- `c_heap`: `malloc`, `calloc`, `realloc` / `free`
- `cpp_new_scalar`: `operator new`, `_Znwm`, `_Znwj` / `operator delete`, `_ZdlPv`
- `cpp_new_array`: `operator new[]`, `_Znam`, `_Znaj` / `operator delete[]`, `_ZdaPv`
- `rust_global`: `__rust_alloc`, `__rust_alloc_zeroed` / `__rust_dealloc`
- `python_object`: `PyObject_New`, `PyObject_NewVar`, `PyType_GenericAlloc` / `PyObject_Del`, `PyObject_Free`
- `python_mem`: `PyMem_Malloc`, `PyMem_Calloc`, `PyMem_Realloc` / `PyMem_Free`
- `python_mem_raw`: `PyMem_RawMalloc`, `PyMem_RawCalloc`, `PyMem_RawRealloc` / `PyMem_RawFree`
- `java_local_ref`: `NewLocalRef` / `DeleteLocalRef`
- `java_global_ref`: `NewGlobalRef` / `DeleteGlobalRef`
- `csharp_hglobal`: `Marshal.AllocHGlobal` / `Marshal.FreeHGlobal`
- `csharp_cotask`: `CoTaskMemAlloc` / `CoTaskMemFree`
- `go_gc`: `runtime.mallocgc`, marked as GC-managed
- `zig_allocator`: initially conservative, modeled through allocator-vtable evidence

### Pointer Contract

`PointerContract` describes ownership, not type syntax.

```rust
pub enum PointerContract {
    Owned,
    Borrowed,
    MaybeOwned,
    Transferred,
    Retained,
    Released,
    ReturnedToCaller,
    StoredInOwner,
    Escaped,
    GcManaged,
    StaticLifetime,
    Unknown,
}
```

### Escape Kind

Use escape classification before reporting leaks.

```rust
pub enum EscapeKind {
    ReturnToCaller,
    OutParam,
    FieldStore,
    GlobalStore,
    Callback,
    Thread,
    Container,
    StaticLifetime,
    Unknown,
}
```

### Effect

Function effects are the shared vocabulary consumed by memory, lifetime, FFI, and dataflow analysis.

```rust
pub enum Effect {
    Acquire { family: FamilyId, result: ValueId },
    Release { family: FamilyId, arg: ArgIndex },
    ConditionalRelease { family: FamilyId, arg: ArgIndex },
    Retain { family: FamilyId, arg: ArgIndex },
    ReturnsOwned { family: FamilyId },
    ReturnsBorrowed,
    ConsumesArg { arg: ArgIndex, family: Option<FamilyId> },
    StoresArgToOwner { arg: ArgIndex, owner: ArgIndex },
    StoresArgToGlobal { arg: ArgIndex },
    InitializesOutParam { arg: ArgIndex, family: FamilyId },
    EscapesToCallback { arg: ArgIndex },
}
```

### Function Summary

Every pass should read `FunctionSummary` instead of re-identifying callee semantics.

```rust
pub struct FunctionSummary {
    pub function: FunctionId,
    pub canonical_name: SymbolId,
    pub language_hint: LanguageHint,
    pub origin: FunctionOrigin,
    pub effects: Vec<Effect>,
    pub confidence: f32,
    pub evidence: Vec<Evidence>,
}
```

### Verifier Verdict

Issue output must be gated by a verdict.

```rust
pub enum VerifierVerdict {
    ConfirmedIssue,
    ProbableIssue,
    Diagnostic,
    ExplainedSafe,
}
```

Default JSON/SARIF output should include only `ConfirmedIssue` and high-confidence `ProbableIssue`. Diagnostics require an explicit debug flag.

## Required Modules

### `omniscope-semantics::resource`

Create the module tree:

```text
crates/omniscope-semantics/src/resource/
  mod.rs
  family.rs
  family_registry.rs
  family_inference.rs
  contract.rs
  effect.rs
  summary.rs
  summary_inference.rs
  ownership_state.rs
  escape.rs
  evidence.rs
```

Responsibilities:

- Built-in resource family registry.
- Symbol canonicalization-aware family lookup.
- Project-inferred family candidates.
- Function summary representation and inference.
- Evidence objects used by verifier and reports.

### `omniscope-pass::resource`

Create the pass module tree:

```text
crates/omniscope-pass/src/resource/
  mod.rs
  raw_fact_collector.rs
  summary_builder.rs
  contract_graph_builder.rs
  ownership_solver.rs
  issue_candidate_builder.rs
  issue_verifier.rs
```

Responsibilities:

- Convert IR facts and summaries into resource instances.
- Build resource contract edges.
- Run ownership state transitions.
- Build issue candidates.
- Verify candidates and attach verdicts.

## Structural Inference Patterns

The following patterns replace language-specific suppression. They should produce summaries and evidence, not directly suppress issues.

### Same-family release

If acquire and release families are the same or explicitly compatible:

```text
family(alloc) == family(release) -> valid release evidence
```

This replaces Python pair suppression, C++ new/delete pair suppression, and many cross-language false positives.

### Destructor / Drop / Dispose

Infer destructor-like summaries when a function:

- has a name/debug marker such as `drop`, `destroy`, `dealloc`, `delete`, `free`, `Dispose`, `finalize`, `__del__`, or C++ destructor mangling;
- takes a pointer-like receiver or argument;
- calls known release functions or releases fields;
- does not return an owned resource.

Generated effects:

```text
ConsumesArg + Release / release-fields evidence
```

This handles Rust Drop calling C free, C++ destructors, C# Dispose, and Python-style finalizers.

### Slice-to-pointer bridge

Infer borrowed-return summary when the body only performs pointer projection:

```text
getelementptr / bitcast / extractvalue / addrspacecast / return
no alloc, no release, no global store
```

Generated effects:

```text
ReturnsBorrowed + bridge-helper evidence
```

This prevents `as_ptr`, `as_mut_ptr`, and FFI helper functions from being treated as ownership escapes.

### Refcount release

Infer conditional release when a function has refcount decrement semantics:

- `Py_DECREF`, `Py_XDECREF`
- `Arc::drop`
- `CFRelease`
- `IUnknown::Release`
- `objc_release`

Generated effect:

```text
ConditionalRelease
```

Do not model this as unconditional `free`.

### Static lifetime sink

When a resource is initialized once and stored in global/static storage, model it as:

```text
EscapeKind::StaticLifetime
LifetimeDomain::ProcessStatic
```

This is not automatic suppression. If allocation happens in a loop or repeated path, keep a leak candidate.

## Issue Policy

Do not report directly from pattern matching. Use this flow:

```text
raw pattern -> IssueCandidate -> IssueVerifier -> report or diagnostic
```

### Candidate kinds

- `CrossFamilyFree`
- `UseAfterRelease`
- `DoubleRelease`
- `ConditionalLeak`
- `BorrowEscape`
- `CallbackEscape`
- `NeedsModel`

### Verification checks

The verifier must check:

- family match or mismatch;
- ownership state;
- valid return/out-param/field/global/callback escape;
- destructor/drop/cleanup release path;
- concrete free-before-use path;
- FFI danger path and boundary distance;
- runtime/compiler origin;
- unknown-family and unknown-cleanup policy.

### Unknown policy

`Unknown` is not a bug. Unknown family, unknown cleanup, or unknown ownership should produce `NeedsModel` diagnostic evidence unless a concrete unsafe path is proven.

## CLI Direction

Add these commands/flags as the architecture matures:

```text
omniscope analyze target.bc --debug-resource-contract
omniscope analyze target.bc --semantic-model omniscope.model.json
omniscope mine-model target.bc > omniscope.model.json
```

Model mining must output auditable evidence. It may add resource families and summaries, but it must not directly suppress findings.

## Implementation Roadmap

### Phase 0: Baseline ✅

- [x] Record current issue output for small Rust FFI, C/C++, Python C API, JNI, and C#/.NET examples.
- [x] Add a debug-only resource trace format.
- [x] Ensure default output is unchanged before semantic layers are enabled.

### Phase 1: Resource family registry ✅

- [x] Add `resource` module under `omniscope-semantics`.
- [x] Implement built-in families listed above.
- [x] Add family lookup tests for same-family and mismatch cases.
- [x] Store language only as hint in family lookup results.

### Phase 2: Function summaries ✅

- [x] Add `Effect` and `FunctionSummary` (renamed to `ResourceSummary`).
- [x] Generate summaries from built-in family registry.
- [x] Add Python owned-reference and DECREF summaries.
- [x] Add JNI and C# resource summaries.
- [x] Share summary store through the pipeline context.

### Phase 3: Resource contract graph ✅

- [x] Add resource instances, contract edges, and ownership states.
- [x] Model acquire, release, retain, transfer, return, out-param, field-store, global-store, and callback escape.
- [x] Link resource edges to CrossLangEdge / FFI boundary evidence.

### Phase 4: Structural inference ✅

- [x] Implement destructor/drop/dispose inference.
- [x] Implement slice-to-pointer bridge inference.
- [x] Implement refcount conditional-release inference.
- [x] Implement static-lifetime sink inference.
- [x] Attach evidence to every inferred summary.

### Phase 5: Issue verifier ✅

- [x] Convert direct reports into issue candidates.
- [x] Implement verifier verdicts.
- [x] Gate JSON/SARIF output by verdict.
- [x] Add risk scoring in one module, not scattered across passes.

### Phase 6: Path-sensitive leak ✅

- [x] Slice CFG from allocation to exits.
- [x] Detect paths that miss same-family release.
- [x] Treat partial-path leaks as `ConditionalLeak`.
- [x] Add path budget to avoid exponential behavior.

### Phase 7: Project model mining

- [ ] Infer `foo_alloc/foo_free`, `foo_create/foo_destroy`, `foo_open/foo_close`, `foo_init/foo_deinit` pairs.
- [ ] Use name prefix, type shape, debug path, and call graph evidence.
- [ ] Emit auditable JSON model with confidence.
- [ ] Load model through `omniscope-registry`.

## Test Matrix

Each phase must include positive, negative, and edge tests.

- [x] `malloc/free` is same-family safe.
- [x] `malloc/delete[]` is cross-family mismatch.
- [x] `new[]/delete[]` is same-family safe.
- [x] `__rust_alloc/free` is cross-family mismatch.
- [x] `PyObject_New/PyObject_Free` is same-family safe.
- [x] `PyMem_Malloc/PyObject_Free` is family mismatch.
- [x] `PyLong_From*` + `Py_DECREF` is conditional release, not leak.
- [x] Rust Drop calling C free is destructor-mediated release.
- [x] `as_ptr` / `as_mut_ptr` bridge returns borrowed pointer.
- [x] JNI local/global ref mismatch is detected.
- [x] HGlobal/CoTaskMem mismatch is detected.
- [x] Return-owned pointer is not a local leak.
- [ ] Out-param initialization is not a local leak.
- [ ] Field-store into owner object is not an immediate leak.
- [x] Global/static initialization is static-lifetime or diagnostic, not default high severity.
- [x] Error-path missing release becomes `ConditionalLeak`.
- [x] Unknown family becomes `NeedsModel` diagnostic unless a concrete unsafe path is proven.

## Acceptance Criteria

- [x] No new language-specific cross-free branch is needed for a new runtime family.
- [x] All reportable issues include resource family, pointer contract, verifier verdict, and evidence.
- [ ] Default SARIF excludes diagnostics.
- [x] Every high/critical issue answers: boundary function, crossing pointer, allocator, releaser, mismatch reason, reachable path.
- [x] Structural inference reduces suppression rules instead of adding new ones.
- [x] `make fmt` passes.
- [x] `make check` passes.
- [x] Tests include edge cases and meaningful assertion messages.

## Output Requirements

### Terminal colored output

All CLI output must use colored formatting:

- **ConfirmedIssue** → red (`\x1b[31m`)
- **ProbableIssue** → yellow (`\x1b[33m`)
- **Diagnostic** → blue (`\x1b[34m`)
- **ExplainedSafe** → green (`\x1b[32m`)
- **Resource family** → cyan (`\x1b[36m`)

Each issue line must display the language transition arrow:

```text
[ERROR] cross-family free: malloc (C ──✕──> C++) released by operator delete
[WARN]  conditional leak: __rust_alloc (Rust) in foo — no RustGlobal release
[NOTE]  needs model: custom_alloc (Unknown) — unknown family
```

The arrow format is: `alloc_language ──✕──> release_language` for mismatches,
`alloc_language ──✓──> release_language` for same-family safe.

When `--no-color` is passed or stdout is not a TTY, fall back to plain text.

### SARIF output

- Default SARIF excludes `Diagnostic` and `ExplainedSafe` verdicts.
- Each result must include: `resourceFamily`, `pointerContract`, `verifierVerdict`, `evidence[]`.

## Graduation Criteria

- [ ] 用 `~/code/researcher/bun` 这个 Rust 项目做真实检测，找到问题，TP > 90%，FN + FP < 10%
- [x] 终端输出彩色 + 语言→语言箭头标注

## Non-goals

- Do not build a general-purpose source-level static analyzer.
- Do not maintain a giant safe-function whitelist.
- Do not treat platform filters as vulnerability decisions.
- Do not let each pass implement its own callee semantic model.
- Do not report `Unknown` as high severity by default.