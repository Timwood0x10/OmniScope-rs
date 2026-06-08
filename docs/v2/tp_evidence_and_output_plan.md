# TP Evidence Fusion and Output Clarity Plan

This plan defines concrete work to improve true-positive detection by reusing the existing `MemoryGraph`, `SemanticTree`, `ContractGraph`, SRT, and output formatter infrastructure. It also defines a clearer reporting model that explains each issue as a resource ownership story.

## Goals

- Increase TP by requiring a stronger evidence chain instead of single-pass pattern reports.
- Preserve current FP suppressions without hiding cross-family or double-free TPs.
- Make terminal and JSON output understandable to users who do not know the internal pass pipeline.
- Keep changes surgical and compatible with the current pipeline.

## Non-Goals

- Do not add symbol whitelists to recover accuracy.
- Do not replace the current pass architecture.
- Do not delete or rewrite existing output formats.
- Do not make detector passes emit reportable issues directly.

## Architecture Direction

Use this evidence flow:

```text
LLVM IR
  -> RawResourceFact
  -> ContractGraph
  -> OwnershipSolver / MemoryGraph
  -> SemanticTree / SRT facts
  -> EvidenceBundle
  -> IssueCandidate
  -> IssueVerifier
  -> Issue
  -> Rich/JSON/SARIF output
```

The key change is an evidence fusion layer. Individual passes can still produce facts and candidates, but final issue confidence should depend on a joined view of:

- resource identity
- allocation family
- release family
- path reachability
- alias evidence
- semantic suppressions
- boundary evidence
- memory graph state

## Phase 0: Baseline and Guardrails

- [x] Add a baseline command note in `docs/v2/v0.2.0_remaining_items.md` or this file.
  - Command: `cargo test --test corpus_tests`
  - Command: `cargo test -p omniscope-pass`
  - Command when sandbox allows it: `make check && make test`
- [x] Record current known corpus expectations:
  - C: `BUG-C5` must produce `CrossFamilyFree`.
  - C++: `BUG-CPP1`, `BUG-CPP2`, `BUG-CPP5` must produce `CrossFamilyFree`.
  - Python: `BUG-PY3` must produce `CrossFamilyFree`.
  - Go: `BUG-GO2`, `BUG-GO3`, `BUG-GO5` must produce `CrossFamilyFree`.
- [x] Add a regression note that `CrossLanguageFree` evidence must not replace `CrossFamilyFree` when the core bug is family mismatch.
- [x] Verify current issue gate suppressions still preserve existing corpus TPs.

Acceptance:

- [x] Corpus tests pass locally.
- [x] No expected `CrossFamilyFree` TP is downgraded to only `CrossLanguageFree`.
- [ ] No detector emits final reportable issues outside `IssueVerifier`.

Verification notes:

- `cargo test --test corpus_tests` passed after tightening same-language wrapper suppression.
- `cargo test -p omniscope-pass resource::issue_verifier` passed.
- `cargo test --test tp_evidence_boundary_tests` passed with focused C/C++/Python/Go family-mismatch boundary cases.
- `cargo test -p omniscope-pass resource::noreturn` passed after sharing noreturn callee recognition.
- `make test` could not be fully verified in the sandbox when `sccache` required permissions outside the managed environment.

## Phase 1: EvidenceBundle Data Model

Add a small internal context type for verifier-side fusion.

Suggested file:

- `crates/omniscope-pass/src/resource/evidence_bundle.rs`

Tasks:

- [x] Create `EvidenceBundle`.
- [x] Keep it internal to `omniscope-pass` at first.
- [ ] Include these fields:

```rust
pub(crate) struct EvidenceBundle {
    pub candidate_id: u64,
    pub resource_id: Option<u64>,
    pub alloc_family: FamilyId,
    pub release_family: Option<FamilyId>,
    pub alloc_function: String,
    pub release_function: Option<String>,
    pub alloc_caller: Option<String>,
    pub release_caller: Option<String>,
    pub memory_state: Option<ResourceState>,
    pub semantic_kinds: Vec<SemanticKind>,
    pub evidence_kinds: Vec<EvidenceKind>,
    pub has_boundary_evidence: bool,
    pub has_same_resource_evidence: bool,
    pub has_reachable_release: bool,
    pub has_alias_rejection: bool,
}
```

- [x] Add `EvidenceBundle::from_candidate(...)`.
- [x] Pull memory state from existing `MemoryGraph`.
- [x] Pull semantic facts from existing `srt_resolutions`.
- [x] Pull boundary state from existing candidate `boundary` and `ffi_evidence`.
- [x] Pull evidence kinds from existing `candidate.evidence`.
- [x] Do not clone large graphs; pass references.

Tests:

- [x] Bundle from candidate with `resource_id` resolves `MemoryGraph` state.
- [x] Bundle without `resource_id` still builds and does not panic.
- [x] Bundle collects `SemanticKind::RuntimeManagedResource`.
- [x] Bundle marks boundary evidence when candidate has `ffi_evidence`.
- [x] Bundle marks alias rejection when evidence contains `may_alias=NotAlias`.

Acceptance:

- [x] File is under 1000 lines.
- [x] Functions are under 120 lines except rare, justified cases.
- [ ] Public APIs have doc comments if exported.
- [x] Initial data model landed without verifier behavior changes; later Phase 2/3/4 bundle verifier routing is now intentional and tested.

Implementation note:

- Added internal `resource::evidence_bundle` with `EvidenceBundle::from_candidate(...)`.
- The bundle resolves `MemoryGraph` state by `resource_id`, collects SRT semantic facts by symbol and `resource:<id>`, copies candidate evidence kinds, and exposes derived booleans for boundary evidence, same-resource evidence, reachable release evidence, and alias rejection.
- The verifier first used the bundle for trace-only audit context, then Phase 2/3/4 intentionally routed CrossFamily, DoubleFree, and Leak decisions through bundle-based verification.

Verification notes:

- `make fmt` passed after adding `resource::evidence_bundle`.
- `cargo test -p omniscope-pass resource::evidence_bundle` passed with 5 focused unit tests.
- `cargo test -p omniscope-pass resource::issue_verifier` passed after confirming Phase 1 bundle construction and later Phase 2/3/4 routing tests.
- `RUSTC_WRAPPER= make check` passed. Plain `make check` failed in this environment because `RUSTC_WRAPPER=sccache` returned `Operation not permitted`.
- `crates/omniscope-pass/src/resource/evidence_bundle.rs` is 334 lines.

## Phase 2: CrossFamily TP Closure

Goal: make family mismatch the primary issue when alloc and release families differ. Cross-language is evidence, not a replacement issue kind.

Files:

- `crates/omniscope-pass/src/resource/issue_verifier.rs`
- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs`
- optional: `crates/omniscope-pass/src/resource/evidence_bundle.rs`

Tasks:

- [x] Add `verify_cross_family_with_bundle(bundle, registry)`.
- [x] Confirm TP when:
  - allocation family and release family are present
  - families are incompatible in `FamilyRegistry`
  - release is reachable or present in the same resource flow
  - semantic facts do not mark the resource as runtime-managed, static lifetime, stored owner, or returned to caller
- [x] Preserve `CrossFamilyFree` issue kind for family mismatch.
- [x] Attach cross-language evidence as a secondary fact.
- [x] Suppress only when SRT has a real ownership explanation:
  - `RuntimeManagedResource`
  - `StoredToOwner`
  - `StoredToRuntime`
  - `EscapedToCaller`
  - `EscapedToOutParam`
  - `StaticLifetimeSink`
  - destructor/RAII cleanup evidence
- [x] Keep same-language allocator wrapper suppression strict:
  - alloc function itself must be a wrapper body
  - release function itself must be a wrapper body
  - plain `malloc -> delete`, `malloc -> sqlite3_free`, `PyMem_Malloc -> free`, `_cgo_allocate -> free` must not be suppressed

Tests:

- [x] C `malloc -> sqlite3_free` reports `CrossFamilyFree`.
- [x] C++ `_Znam -> _ZdlPv` reports `CrossFamilyFree`.
- [x] C++ `mi_malloc -> free` reports `CrossFamilyFree`.
- [x] Python `PyMem_Malloc -> free` reports `CrossFamilyFree`.
- [x] Go `_cgo_allocate -> free` reports `CrossFamilyFree`.
- [x] Same-language allocator thunk wrapping `mi_malloc/mi_free` is suppressed when both sides are wrappers.
- [x] Cross-language evidence remains attached where applicable.

Acceptance:

- [x] Current corpus `CrossFamilyFree` TPs pass.
- [x] No known clean allocator pair becomes `CrossFamilyFree`.
- [x] No whitelist is added.

Implementation note:

- Tightened `is_same_language_allocator_wrapper_noise` in `issue_verifier.rs` so suppression requires the candidate alloc function and release function themselves to be non-declaration wrapper/runtime bodies. Plain allocator/deallocator names are no longer enough to suppress a family mismatch.
- Added `tests/tp_evidence_boundary_tests.rs` to keep these true positives locked by small, focused IR fixtures.
- Added shared `resource::noreturn` recognition so OOM/abort-path logic can be reused without private cross-module calls.
- `verify_cross_family_with_bundle` now requires reachable release or same-resource evidence before confirming an incompatible family pair; bare family mismatch is only probable.
- Family-mismatched `CrossLanguageFree` candidates are promoted to `CrossFamilyFree` before report emission, with `CrossLanguageFree` retained as secondary evidence.

## Phase 3: DoubleFree TP Closure

Goal: confirm double-free only with same-resource and alias/path evidence.

Files:

- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs`
- `crates/omniscope-pass/src/resource/issue_verifier.rs`
- `crates/omniscope-pass/src/resource/may_alias.rs`
- `crates/omniscope-pass/src/resource/ownership_solver.rs`

Tasks:

- [x] Require same resource instance for confirmed double-release.
- [x] Require `may_alias == MayAlias` or equivalent positive evidence.
- [x] Reject declaration-only releases.
- [x] Reject unrelated releases merged only by family.
- [ ] Track release order when instructions are in the same function.
- [ ] Treat branch-dependent second release as TP when the same pointer can reach both releases.
- [ ] Do not suppress `free(p); if (err) free(p);`.
- [x] Suppress only when:
  - second release is proven null-only
  - pointer was set to null after first release and path state proves that branch
  - alias gate rejects same-resource assumption

Tests:

- [x] `free(p); free(p);` reports confirmed `DoubleFree`.
- [x] `free(p); if (err) free(p);` reports confirmed or probable `DoubleFree`.
- [x] `free(a); free(b);` with independent allocations does not report confirmed `DoubleFree`.
- [x] extern declaration-only `free` does not report `DoubleFree`.
- [x] user-defined wrapper calling extern `free` can report `DoubleFree`.
- [x] null-store-after-release safe pattern is suppressed only with path evidence.

Acceptance:

- [x] Double-free TPs increase or remain stable.
- [x] Declaration-only FPs remain suppressed.
- [x] Boundary tests cover alias rejection and same-pointer confirmation.

Verification notes:

- `cargo test --test tp_evidence_boundary_tests` passed with direct double-free, conditional double-free, independent-allocation FP, and cross-family TP cases.
- `cargo test -p omniscope-pass resource::may_alias` passed.
- `cargo test -p omniscope-pass resource::issue_verifier` passed after keeping declaration-only suppression limited to `DoubleRelease`; cross-family candidates with extern release callees remain eligible for TP reporting.
- `UseAfterFree` evidence alone is not accepted as positive same-instance proof for `DoubleFree`; confirmed `DoubleFree` requires `resource_id` or `MultipleRelease` evidence and no alias rejection.
- `cargo test --test corpus_tests` passed after the Phase 3 boundary additions.

## Phase 4: ConditionalLeak TP Closure

Goal: use memory graph exit state, not only allocation/release counts.

Files:

- `crates/omniscope-pass/src/resource/path_sensitive_leak.rs`
- `crates/omniscope-pass/src/resource/ownership_solver.rs`
- `crates/omniscope-semantics/src/resource/semantic_tree/kind.rs`
- `crates/omniscope-pass/src/resource/issue_verifier.rs`

Tasks:

- [x] Define path exit categories:
  - `OwnedAtExit`
  - `ReleasedAtExit`
  - `EscapedToCaller`
  - `EscapedToOutParam`
  - `StoredToOwner`
  - `RuntimeManaged`
  - `StaticLifetime`
  - `AbortOrUnreachable`
- [x] Reuse existing `PointerStateMap` where possible.
- [x] Treat `OwnedAtExit` on any reachable exit as `ConditionalLeak`.
- [x] Treat all reachable exits owned as `DefiniteLeak`.
- [x] Treat `AbortOrUnreachable` as non-leak terminal.
- [x] Treat `RuntimeManaged`, `StaticLifetime`, `StoredToOwner`, and valid out-param ownership as safe.
- [x] Add evidence describing which exit path leaks.
- [x] Keep counting fallback only when path state is unavailable.

Tests:

- [x] malloc then early return before free reports `ConditionalLeak`.
- [x] malloc then free on all exits reports no leak.
- [x] malloc then return pointer reports no local leak.
- [x] malloc then store to owner reports no local leak.
- [x] malloc then abort/unreachable on OOM path does not report leak.
- [x] nested allocation failure reports leak of first allocation.
- [x] process-lifetime arena is suppressed only with runtime/static semantic evidence.

Acceptance:

- [x] Leak TPs increase on nested allocation and early-return patterns.
- [x] Arena/global lifetime FPs decrease without whitelist.
- [x] Leak output includes leaking path evidence.

Implementation note:

- Enabled `collect_exit_states` + `determine_leak_type` in `LeakDetectionPass::run()`, replacing pure counting-based logic with path-sensitive analysis as primary path and counting as fallback.
- Added `format_exit_state_summary()` and `path_state_label()` helpers for exit state evidence description.
- Added exit-state evidence to both DefiniteLeak and ConditionalLeak candidates, showing the distribution of exit states (e.g. "2 Owned, 1 Released").
- Added `has_leak_suppression()` to `EvidenceBundle` for leak-specific safe exit categories (RuntimeManaged, StaticLifetime, GlobalProvenance, ReturnToCaller, FieldStoreToOwner, etc.).
- Added `verify_definite_leak_with_bundle()` and `verify_conditional_leak_with_bundle()` in issue_verifier.rs with bundle-based evidence fusion.
- Modified `verify_candidate_inner` to route leak candidates through bundle-based verification when bundle is available.

Verification notes:

- `cargo test -p omniscope-pass` passed with 365 tests (18 new Phase 4 tests).
- `cargo test --test corpus_tests` passed.
- `cargo test --test tp_evidence_boundary_tests` passed.
- `cargo test -p omniscope-pass resource::evidence_bundle` passed.

## Phase 5: SemanticTree as Explanation and Suppression Layer

Goal: use semantic facts to explain safe ownership, not to hide issues blindly.

Files:

- `crates/omniscope-semantics/src/resource/semantic_tree/kind.rs`
- `crates/omniscope-pass/src/resource/ir_behavior_summary_pass.rs`
- `crates/omniscope-pass/src/resource/structural_inference_pass.rs`
- `crates/omniscope-pass/src/resource/issue_gate.rs`
- `crates/omniscope-pass/src/resource/issue_verifier.rs`

Tasks:

- [ ] Ensure semantic facts include source and confidence.
- [ ] Normalize existing facts into SRT keys by symbol and resource when possible.
- [ ] Add or verify these semantic kinds:
  - `RuntimeManagedResource`
  - `StoredToOwner`
  - `StoredToRuntime`
  - `EscapedToCaller`
  - `EscapedToOutParam`
  - `StaticLifetimeSink`
  - `AbortOnOom`
  - `RefcountTransfer`
  - `DestructorRelease`
- [ ] Make verifier consume semantic facts through `EvidenceBundle`.
- [ ] Require high-confidence semantic facts for suppression.
- [ ] Use medium-confidence semantic facts only to downgrade confirmed to probable.
- [ ] Preserve issue if resource evidence is stronger than semantic suppression.

Tests:

- [ ] Runtime-managed arena suppresses generic leak.
- [ ] Same arena does not suppress explicit wrong-family release.
- [ ] Refcount transfer suppresses caller-owned lifecycle FP.
- [ ] Refcount over-release still reports.
- [ ] Static lifetime suppresses process-lifetime allocation leak.
- [ ] Static lifetime does not suppress function-local leak.

Acceptance:

- [ ] Semantic facts are visible in debug output.
- [ ] Suppression has a reason string.
- [ ] No suppression occurs without evidence source and confidence.

## Phase 6: Output V2 for Human Readability

Goal: report each issue as a clear resource flow.

Files:

- `crates/omniscope-cli/src/output/rich.rs`
- `crates/omniscope-cli/src/output/json.rs`
- `crates/omniscope-cli/src/output/mod.rs`
- `crates/omniscope-core/src/issue.rs`
- optional: `crates/omniscope-core/src/report.rs`

Tasks:

- [ ] Add display-only `FindingView` or `IssuePresentation`.
- [ ] Do not change `Issue` serialization until compatibility is planned.
- [ ] Generate a title:
  - `malloc buffer released by sqlite3_free`
  - `new[] allocation released with scalar delete`
  - `FFI pointer used before null check`
  - `allocation may leak on error path`
- [ ] Add `resource_flow` for resource issues:
  - step number
  - operation: alloc, use, release, escape, exit
  - function
  - family
  - caller
  - evidence source
- [ ] Add `why` text.
- [ ] Add `fix_hint`.
- [ ] Add `evidence` list.
- [ ] Add `suppression_reason` for suppressed/debug output.
- [ ] Add `confidence_breakdown` in verbose mode only.

Suggested rich output:

```text
[HIGH] OMI-003 Cross-family free
Title: malloc buffer released by sqlite3_free
Function: library_family_mismatch
CWE: 762
Confidence: 94%

Resource flow:
  1. alloc    malloc(len)          family=C_HEAP
  2. release  sqlite3_free(buf)    family=SQLITE_RESOURCE

Why:
  sqlite3_free expects SQLite-owned memory, but this pointer came from malloc.

Evidence:
  + same resource instance
  + incompatible families: C_HEAP -> SQLITE_RESOURCE
  + release is reachable after allocation
  + no runtime-managed or ownership-transfer evidence found

Fix:
  Release malloc memory with free(), or allocate with the matching SQLite allocator.
```

Suggested JSON extension:

```json
{
  "findings_v2": [
    {
      "id": "OMI-003",
      "kind": "cross_family_free",
      "title": "malloc buffer released by sqlite3_free",
      "severity": "high",
      "confidence": 0.94,
      "function": "library_family_mismatch",
      "resource_flow": [
        {
          "step": 1,
          "operation": "alloc",
          "function": "malloc",
          "family": "C_HEAP"
        },
        {
          "step": 2,
          "operation": "release",
          "function": "sqlite3_free",
          "family": "SQLITE_RESOURCE"
        }
      ],
      "why": "Release function expects SQLite-owned memory but allocation came from C heap.",
      "evidence": [
        "same_resource_instance",
        "incompatible_families",
        "reachable_release"
      ],
      "fix_hint": "Release malloc memory with free(), or allocate with the matching SQLite allocator."
    }
  ]
}
```

Tests:

- [ ] Rich output includes title, function, resource flow, why, evidence, and fix.
- [ ] Rich output does not show empty `Function:`.
- [ ] JSON output remains backward-compatible.
- [ ] JSON output includes `findings_v2`.
- [ ] Output for clean result is concise.
- [ ] Output for suppressed/debug mode includes suppression reasons.

Acceptance:

- [ ] Output is readable without knowing pass internals.
- [ ] CI JSON remains machine-readable.
- [ ] Existing SARIF output is not broken.

## Phase 7: Metrics and Audit Output

Goal: make TP/FP/FN movement visible after each change.

Files:

- `tests/accuracy_regression.rs`
- `tests/corpus_detection_audit.rs`
- optional: `tests/fixtures/ffi_accuracy_expectations.json`
- optional: `crates/omniscope-cli/src/main.rs`

Tasks:

- [ ] Add per-fixture expected metadata if not already available:
  - file
  - function substring
  - expected issue kinds
  - expected resource family
  - expected release family
  - expected boundary kind
  - known noise flag
- [ ] Emit audit table:
  - TP
  - FP
  - FN
  - precision
  - recall
  - suppressed count
  - top suppression reasons
- [ ] Split metrics:
  - resource TP/FP/FN
  - FFI TP/FP/FN
  - leak TP/FP/FN
  - double-free TP/FP/FN
- [ ] Add delta output against checked-in baseline.
- [ ] Fail regression only when TP decreases, FN increases, or FP exceeds threshold.

Tests:

- [ ] Audit reports `CrossFamilyFree` TP for C/C++/Python/Go corpus cases.
- [ ] Audit reports suppression reason counts.
- [ ] Audit output is deterministic.
- [ ] Baseline delta catches missing TP.

Acceptance:

- [ ] One command shows accuracy movement.
- [ ] New TP is visible by fixture name.
- [ ] Regression failures identify which expected pattern disappeared.

## Implementation Order

Recommended order:

- [ ] Phase 0: baseline guardrails.
- [ ] Phase 2: CrossFamily TP closure.
- [ ] Phase 3: DoubleFree TP closure.
- [ ] Phase 4: ConditionalLeak TP closure.
- [ ] Phase 1: EvidenceBundle extraction if repeated verifier code grows.
- [ ] Phase 5: SemanticTree suppression confidence.
- [ ] Phase 6: Output V2.
- [ ] Phase 7: Metrics and audit output.

Reasoning:

- CrossFamily, DoubleFree, and ConditionalLeak are the highest-value TP classes.
- EvidenceBundle should remain small and extracted only when duplication becomes real.
- Output V2 is easier once verifier can explain decisions with structured evidence.

## Global Acceptance Checklist

- [ ] File is under 1000 lines.
- [ ] Function is under 120 lines except rare, justified cases.
- [ ] Code is simple and straightforward.
- [ ] All comments are in English.
- [ ] Code-to-comment ratio is approximately 7:3.
- [ ] Tests include boundary cases.
- [ ] No files were deleted without permission.
- [ ] Naming conventions are followed.
- [ ] Code is formatted with `make check && make test`.
- [ ] All tests pass.
- [ ] Public APIs have doc comments.
- [ ] Error handling is appropriate.
- [ ] Memory management is correct.
- [ ] Changes are surgical and minimal.
