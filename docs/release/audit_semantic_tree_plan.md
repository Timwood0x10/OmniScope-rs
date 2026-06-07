# Audit: SEMANTIC_TREE_PLAN.md vs current code

**Date:** 2026-06-07
**Commit:** `17bea02ea919fd4682eab2a6f76fd55c9f6a0907` (branch `master`)
**Doc audited:** `SEMANTIC_TREE_PLAN.md` (254 lines, project root)
**Summary:** All five plan phases have shipped. The IR parser, behavior
extractor, semantic engine, and FFIBoundaryPass wiring exist with real
implementations; the file paths and type names in the plan match the
code with minor renames. The doc itself is short, technical, and largely
accurate, but it under-reports the scope of what shipped (multi-key
SemanticKind taxonomy, five language adapters, multiple fact-producing
passes) and over-reports the cleanup of Phase 5 step 4 (the
`SyscallSemantic::classify` whitelist is still present as a fallback).

---

## Per-item status table

| Plan item (doc line ref) | Doc claim | Code reality (file:line) | Status |
|---|---|---|---|
| **Phase 1: IRInstruction struct** (lines 18–26) | 5 fields: `kind`, `dest`, `operands`, `callee`, `atomic_op` | `crates/omniscope-ir/src/instruction_parser.rs:95-131` defines `IRInstruction` with **11 fields** (added `icmp_pred`, `raw_text`, `result_type`, `element_type`, `function_signature`, `conversion_opcode`, `binary_opcode`) | **done + extended** |
| **Phase 1: IRInstructionKind enum** (lines 28–42) | 11 variants (`Alloca` … `Other`) | `crates/omniscope-ir/src/instruction_parser.rs:21-54` has **16 variants** (added `Fcmp`, `IndirectCall`, `Conversion`, `Select`, plus `Other` kept) | **done + extended** |
| **Phase 1: FunctionBody struct** (lines 44–49) | 2 fields: `name`, `instructions` | `crates/omniscope-ir/src/parser.rs:73-78` — exact match. Helpers `count_kind`, `instructions_of_kind`, `ret_instruction`, `call_instructions`, `atomic_rmw_with_op` added (lines 80–120) | **done + extended** |
| **Phase 1: IRModule.function_bodies** (line 53) | `pub function_bodies: HashMap<String, FunctionBody>` | `crates/omniscope-ir/src/parser.rs:132` — exact match | **done** |
| **Phase 1: instruction parsing logic** (lines 57–68) | `alloca`/`load`/`store`/`atomicrmw add/sub`/`getelementptr`/`icmp eq/ne`/`br i1`/`ret`/`phi`/`call`/`add/sub/mul/and/or/xor` | `crates/omniscope-ir/src/ir_model.rs:429-454` `classify_opcode` plus text parser in `parser.rs:170-326`; `cmpxchg` also mapped to `AtomicRmw`, conversions classified | **done** |
| **Phase 2: file `ir_pattern.rs`** (line 74) | `crates/omniscope-semantics/src/resource/ir_pattern.rs` (new) | Exists, 1285 lines | **done** |
| **Phase 2: BehaviorPattern enum** (lines 91–110) | 6 variants: `ConditionalRelease`, `PureComputation`, `OwnershipTransfer`, `InternalBridge`, `PointerProjection`, `Initialization` | `crates/omniscope-semantics/src/resource/ir_pattern.rs:43-210` has **all 6 plus 12 more** (`BorrowedReturn`, `RAiiDropRelease`, `IntoRawTransfer`, `PosixNonMemoryOp`, `NullGuardedRelease`, `NullStoreAfterRelease`, `FallibleOutParamInit`, `OutParamNullOnError`, `OutParamOwnedOnSuccess`, `StoreToOwner`, `StoreToRuntime`, `ResourceEscape`, `ReleaseOnAllExitPaths`). Field names also differ: `ConditionalRelease { atomic_op, threshold }` vs plan's `{ refcount_field, destroy_callee }` | **done + drifted (field names)** |
| **Phase 2: ReturnSource enum** (lines 112–116) | 6 variants: `CallResult`, `LoadedValue`, `GepResult`, `Constant`, `Void`, `Unknown` | `crates/omniscope-semantics/src/resource/ir_pattern.rs:267-282` has **7 variants** — added `Computed` (binary-op result) | **done + extended** |
| **Phase 2: FunctionBehavior struct** (lines 80–89) | 8 fields | `crates/omniscope-semantics/src/resource/ir_pattern.rs:236-259` has **11 fields** (added `gep_count`, `icmp_count`, `branch_count`) | **done + extended** |
| **Phase 2: `extract_behavior(body) -> FunctionBehavior`** (line 121) | Public function | `crates/omniscope-semantics/src/resource/ir_pattern.rs:289` — exact signature | **done** |
| **Phase 2: ConditionalRelease detection logic** (lines 130–141) | `atomicrmw sub → icmp eq → br → call` sequence | `crates/omniscope-semantics/src/resource/ir_pattern.rs:302-305` invokes `detect_conditional_release(body)`; logic present | **done** |
| **Phase 3: file `semantic_engine.rs`** (line 147) | `crates/omniscope-semantics/src/resource/semantic_engine.rs` (new) | Exists, 1852 lines | **done** |
| **Phase 3: FFIVerdict enum** (lines 162–169) | 6 variants: `SafeNoOwnership`, `SafeConditionalRelease`, `SafeInternalBridge`, `SafePointerProjection`, `ConcernOwnershipTransfer`, `Unknown` | `crates/omniscope-semantics/src/resource/semantic_engine.rs:38-53` has **7 variants** (added `SafeInitialization`) | **done + extended** |
| **Phase 3: FFISafetyAssessment struct** (lines 153–160) | Fields: `callee`, `caller_behavior`, `callee_behavior`, `verdict`, `evidence` | `crates/omniscope-semantics/src/resource/semantic_engine.rs:98-111` has **6 fields**; added `caller` name string; both behaviors are `Option<>`-wrapped (signature/contract change) | **done + drifted (signature)** |
| **Phase 3: IREvidence struct** (lines 172–176) | Fields: `instruction_kind`, `instruction_text`, `reasoning` | `crates/omniscope-semantics/src/resource/semantic_engine.rs:88-94` has only **2 fields**: `instruction_kind`, `reasoning`. `instruction_text` was **dropped** | **drifted** |
| **Phase 3: `assess_ffi_safety(callee, caller_body, callee_body, module)`** (lines 182–187) | 4-arg signature taking pre-resolved bodies | `crates/omniscope-semantics/src/resource/semantic_engine.rs:169` is `assess_ffi_safety(callee: &str, caller: &str, module: &IRModule)` — passes names, looks up bodies internally | **done + drifted (signature)** |
| **Phase 3: `derive_from_caller_context`** (line 204) | Fallback when callee body is missing | `crates/omniscope-semantics/src/resource/semantic_engine.rs:652` defined and called from `assess_ffi_safety:562` | **done** |
| **Phase 4: FFIBoundaryPass uses semantic engine** (lines 230–238) | Replace `SyscallSemantic::classify` with `assess_ffi_safety` | `crates/omniscope-pass/src/analysis/mod.rs:371` calls `assess_ffi_safety` when IR module is in ctx; **falls back to `SyscallSemantic::classify` at line 380** when IR not available. Suppression honors `should_suppress_issue` (line 418), with C++ FFI Unknown explicitly excluded from suppression | **done + drifted (whitelist retained as fallback)** |
| **Phase 4: only `ConcernOwnershipTransfer` and `Unknown` emit issues** (line 238) | Other verdicts suppressed | `crates/omniscope-pass/src/analysis/mod.rs:418` calls `assessment.should_suppress_issue()` — true for `SafeNoOwnership`/`SafeConditionalRelease`/`SafeInternalBridge`/`SafePointerProjection`/`SafeInitialization`. So `Concern*` and `Unknown` proceed (matches plan) | **done** |
| **Phase 5 step 1: `cargo test -p omniscope-ir`** (line 243) | Parser tests | `crates/omniscope-ir/src/parser.rs:920-1101` has parser tests; `crates/omniscope-ir/src/ir_model_tests.rs` has 4+ tests; `crates/omniscope-ir/tests/llvm_sys_test.rs` exists | **done** |
| **Phase 5 step 2: `cargo test -p omniscope-semantics`** (line 244) | Behavior extraction tests | `crates/omniscope-semantics/src/resource/ir_pattern_tests.rs` has 22 `#[test]` functions | **done** |
| **Phase 5 step 3: `bun_core.bc` 719 → <20** (line 245) | Empirical validation goal | `docs/release/bun_validation.md:53` mentions "19 issues" on `bun_core.bc` (in the expected range); but `bun_alloc.ll` still emits 19 issues with all classified FP per validation report. Plan's 719 baseline number is not reproduced anywhere | **partial — number landed, FP quality contested** |
| **Phase 5 step 4: delete `SyscallSemantic::classify()` whitelist** (line 246) | Whitelist removal | **Not done.** `SyscallSemantic::classify()` is still defined in `crates/omniscope-semantics/src/resource/semantic_tree/syscall.rs` (re-exported at `lib.rs:65`) and actively used at `crates/omniscope-pass/src/analysis/mod.rs:380` as the no-IR fallback path, plus `semantic_tree/tree.rs:203,229` | **not done** |
| **Phase 5 step 5: keep `_R` / `_Z` prefix patterns** (line 247) | Retained as language detectors | `crates/omniscope-semantics/src/resource/cpp_adapter/mod.rs:564` and `crates/omniscope-pass/src/analysis/mod.rs:415` both check `_Z` prefix as a C++ FFI signal; `_R` (Rust v0) detection elsewhere | **done** |

---

## Language adapter status

The plan itself does **not** mention language adapters at all — these
are README-level promises only. Audited here because the user's
instructions reference the README's `19 variants / 7 languages` claim.

**Note:** Per-language variant counts in the README (5+4+4+3+3 = 19)
match the `SemanticKind` enum exactly (`crates/omniscope-semantics/src/resource/semantic_tree/kind.rs:74-139`).
The total enum has ~45 variants; the language-only subset is 19.

| Language | README says (line 64+) | Real adapter file | Functions impl'd | Stubs / TODO | Verdict |
|---|---|---|---|---|---|
| **Go/CGO** | "Comprehensive Go memory model analysis (GC vs C heap); CGO call convention detection; Go-specific function pattern recognition; FFI safety assessment" | `crates/omniscope-semantics/src/resource/go_adapter.rs` (1115 lines) | `GoAdapter::new`, `analyze_function`, `analyze_function_name`, `analyze_function_body` (IR-instruction scan), `is_cgo_bridge_function`, `determine_ffi_safety`, `to_semantic_facts`. 17 `GoSemanticPattern` variants, 4 `GoFFISafety` verdicts | No `todo!`/`unimplemented!` | **done** |
| **Python** | "Reference counting (Py_INCREF/Py_DECREF); object lifecycle detection; GIL management; Python-specific FFI pattern recognition" | `crates/omniscope-semantics/src/resource/python_adapter/{mod,refcount,gil,memory,exception,patterns}.rs` (~1300+ lines incl. submodules) | `PythonAdapter::new` with ~40 known C API entries, `analyze_function`, `analyze_function_with_ir`, IR-body scanning, `determine_ffi_safety` delegating to GIL/refcount/memory/exception/pattern submodules | Tests in `python_adapter/tests/` cover all 5 areas | **done** |
| **C++** | "unique_ptr, shared_ptr, destructor, exception" (README lines 79–83) | `crates/omniscope-semantics/src/resource/cpp_adapter/{mod,exception,raii,smart_pointer,template}.rs` (~990 lines in mod.rs alone) | `CppAdapter::new`, `analyze_function` (name + IR body), Itanium mangling-aware (C1/C2/D0/D1/D2/CI/aSEOS detection), 27 `CppSemanticPattern` variants, 9 `CppFFISafety` verdicts, `to_semantic_facts` mapping | Has tests in `cpp_adapter/tests/`; no stubs | **done** — README's "Known limitations: C++/C#/Java adapters (full implementation) not done" (README line 333) **contradicts reality** |
| **C#** | "SafeHandle, finalizer, P/Invoke" (README lines 85–88) | `crates/omniscope-semantics/src/resource/csharp_adapter/{mod,dispose,gc,pinvoke}.rs` (682+164+195+261 = 1302 lines) | `CSharpAdapter`-style adapter with 13 `CSharpSemanticPattern` variants covering P/Invoke, Marshal alloc/dealloc, GCHandle, SafeHandle, IDisposable, COM, async; `to_semantic_facts`, FFI safety assessment | Tests in `csharp_adapter/tests/{gc,pinvoke}_tests.rs`; no stubs | **done** — README "Known limitations" claim is stale |
| **Java** | "JNI local / global / weak" (README lines 90–93) | `crates/omniscope-semantics/src/resource/java_adapter/{mod,jni,exception,reference}.rs` (767+461+298+339 = 1865 lines) | `JavaAdapter`, `analyze_function` (name + IR body) with `JavaSemanticPattern` variants, JNI ref tracking, exception handling, `to_semantic_facts` mapping to `JavaLocalRef`/`JavaGlobalRef`/`JavaWeakRef` and more | Tests in `java_adapter/tests/{jni,reference}_tests.rs`; no stubs | **done** — README "Known limitations" claim is stale |

**Language adapter overall:** All five adapters have substantive
implementations (1000–2000 lines each), tests, and consume the
`FunctionBody`/`IRInstruction` IR from Phase 1. They produce
`SemanticFact` records (`FactSource::LanguageAdapter`) wired into the
pipeline via `LanguageAdapterFactPass` (`crates/omniscope-pass/src/resource/language_adapter_fact_pass.rs`, registered in `crates/omniscope-pipeline/src/pipeline.rs:97`).

The README's own "Roadmap" at line 333 — "[ ] C++/C#/Java language
adapters (full implementation)" — does not match the code. Either the
README should mark those boxes checked, or there is an undisclosed
acceptance bar (e.g., "covers >90% of real-world IR") that is being
gated on.

---

## Highest-priority drifts

1. **`SyscallSemantic::classify` was not deleted.** Plan Phase 5 step 4
   says "Delete `SyscallSemantic::classify()` whitelist". In reality
   it is the no-IR fallback at `crates/omniscope-pass/src/analysis/mod.rs:380`
   and is consulted by `semantic_tree/tree.rs:203,229`. The plan's
   own "whitelist vs semantic derivation" framing makes this a
   credibility issue: the doc claims a clean cutover that hasn't
   happened.

2. **`IREvidence.instruction_text` field missing.** Plan promises a
   3-field struct (`instruction_kind`, `instruction_text`, `reasoning`);
   actual is 2-field (`instruction_text` dropped at
   `crates/omniscope-semantics/src/resource/semantic_engine.rs:88-94`).
   Downstream consumers can still reconstruct text from `raw_text` on
   the underlying instruction, but anyone reading the plan and grepping
   for `instruction_text` will be confused.

3. **`assess_ffi_safety` signature changed.** Plan: `(callee, caller_body, callee_body, module)`. Real: `(callee_name: &str, caller_name: &str, module: &IRModule)`. The function now resolves bodies internally. This is a reasonable refactor but the plan is stale.

4. **`ConditionalRelease` field names drifted.** Plan: `{ refcount_field: String, destroy_callee: String }`. Real: `{ atomic_op: String, threshold: String }` (`ir_pattern.rs:43-56`). Same intent, different observed quantities — but a reader following the plan to write a consumer will not compile.

5. **README "Known limitations" list (README:333) lies about adapter status.** README itself claims C++/C#/Java adapters are "[ ] full implementation" — but the files exist with 1000–2000 lines of pattern detection, tests, and `to_semantic_facts` wiring each. The plan doc itself does not lie about this, but it sits next to a README that does.

6. **Plan under-reports scope.** The plan describes 6 `BehaviorPattern`
   variants; the code has 18. The plan describes 6 `FFIVerdict`
   variants; the code has 7. The plan never mentions `SemanticFact`,
   `FactSource::LanguageAdapter`, `LanguageAdapterFactPass`, or
   `IRBehaviorSummaryPass` — all of which are essential to how the
   semantic layer is consumed. A reader given only the plan would
   miss half of the architecture.

7. **Phase 5 step 3 number (719 → <20) is unsubstantiated.**
   `docs/release/bun_validation.md` documents 19 issues on `bun_alloc`
   classified as 100% FP under triage. The "719 baseline" number does
   not appear in any other doc. Either it refers to a now-removed
   measurement, or to a different file than the one validated.

---

## Recommended next actions

**Doc edits (the plan can be kept and updated):**

- Update Phase 3 signatures: `assess_ffi_safety(callee_name, caller_name, module)`, two-field `IREvidence`, `FFISafetyAssessment` with `caller` name field and optional behaviors.
- Update Phase 2 `ConditionalRelease` field names to `{ atomic_op, threshold }`.
- Mark Phase 5 step 4 as **not done**, or change it to "deprecate `SyscallSemantic::classify` for IR-available callers only".
- Add a short appendix listing the additional `BehaviorPattern`/`FFIVerdict` variants that landed beyond the plan, with one-line each. This is the cheapest way to make the doc match reality.
- Cite empirical numbers from `docs/release/bun_validation.md` rather than the unsourced "719".
- Optional: cross-link to `docs/release/release_readiness_v0.2.0.md` so a reader sees the gap between the plan's "expected <20" and the validator's "0 confirmed TPs".

**Code work (if matching the plan literally):**

- Either restore the `instruction_text` field on `IREvidence`, or update the plan.
- Either finish removing `SyscallSemantic::classify` from the FFI path entirely, or mark the plan as descoped on that point.

**Or:** retire `SEMANTIC_TREE_PLAN.md` and replace it with a "Semantic
Architecture" document that describes what actually shipped. The plan
served its purpose — it correctly drove the Phase 1–4 work — but it is
no longer an accurate map of the code.

**Recommendation: edit, don't archive.** The plan's framing (whitelist
vs IR-derived pattern detection) is still the right mental model for
understanding the engine, and most of its content is still correct.
A 30-minute pass updating field names, function signatures, and
Phase 5 honesty would make it accurate.
