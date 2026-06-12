# Audit: docs/ffi_boundary_ir_semantics_plan.md vs current code

> **Historical reference.** Zig support has been withdrawn from the product scope. References to Zig adapter modules in this audit should be read as historical — Zig is no longer planned as a target language.

- Date: 2026-06-07
- Repo SHA: `17bea02ea919fd4682eab2a6f76fd55c9f6a0907` (master, plus four
  uncommitted edits in `module_index.rs`, `noise_reduction.rs`,
  `pass.rs`, `issue_candidate_builder/mod.rs`, `issue_verifier.rs`,
  `structural_inference_pass.rs`; plus the new untracked file
  `crates/omniscope-pass/src/resource/may_alias.rs`).
- Plan length: 1279 lines.
- Audit summary: the plan is **largely aligned with reality** at the
  data-structure level (types, kinds, pass names, FFI evidence buckets
  all match), but it is **partially drifted at the behavior level** —
  several phases are wired but produce wrong answers on the bun and
  ffi-demo corpora. Two language adapters promised in §7 (Rust, Zig)
  do not exist as adapter modules; their semantics live only in the
  family registry/structural inference path. (Zig adapter: withdrawn.)

---

## Phase / Section status table

| Phase / section (line) | Doc claim | Code reality (file:line) | Status |
|---|---|---|---|
| §2 Existing infrastructure inventory (28–39) | Lists `ModuleIndex`, `FFIBoundaryDetector`, `RawFactCollector`, `IRBehaviorSummaryPass`, `ContractGraphBuilder`, `IssueCandidateBuilder`, `IssueVerifier`, `IssueGate`, `SemanticTree`, etc. | All exist with the same names and roles. `pipeline.rs:85-126` registers them. | **Done** |
| §2.5 Multi-language IR loading perf contract (41–109) | `LoadStrategy::AutoFast` is default for `.ll`, `DirectCppFfi` slice, `IrCache` with strategy keys, per-language adapter timings | `crates/omniscope-ir/src/loader_v2.rs:120-167` defines `DirectCppFfi`, `AutoFast`, etc.; `IrCache` exists in `ir_cache.rs`. Per-language adapter timings: `language_adapter_fact_pass.rs:204-211` adds `cpp_facts/python_facts/...` stats. | **Done (infrastructure), partial (instrumentation)** — `LoadedIr.load_ms / backend_ms / deserialize_ms / cache_hit` exist but doc admits they sometimes return None; the language adapter pass does emit per-language counts. |
| §4.1 Replace boolean boundary with `BoundaryEvidence` (159–182) | New struct with kind/caller_lang/callee_lang/confidence/reason; stored in `CachedCallMeta`, `RawResourceFact`, `ContractEdge`, `IssueCandidate` | `omniscope-types/src/boundary.rs:355-408` defines `BoundaryEvidence`; `module_index.rs:80` stores `boundary_evidence: Option<Vec<BoundaryEvidence>>`; `raw_fact_collector.rs:125` propagates; `contract_graph_builder.rs:351,502` propagates to `ContractEdge`. | **Done** |
| §4.2 Boundary seed rules (185–209) | Strong/Weak/Suppression seed rules with 7 strong + 3 weak + 4 suppression categories | `analysis/boundary_seeds.rs:83-351` implements all rules — LLVM intrinsics, runtime intrinsic, libc, internal same-lang are suppression; cross-language, configured, non-C→unknown extern, C→C++ Itanium (excluding Rust `_ZN`), exported wrapper, function pointer, callback registration are strong; same-lang FFI contract, dangerous libc in wrapper, runtime bridge connected are weak. | **Done** |
| §4.2.1 Multi-language boundary matrix (211–230) | 12-row matrix for Rust↔C, C↔C++, JNI↔native, Zig↔C, Python↔C, Go↔C | `boundary_seeds.rs` generates generic `BoundaryEvidence` per row; language-specific shapes consumed by `language_adapter_fact_pass.rs`. No Zig/Rust explicit adapter classes exist — relies on `family_registry` + symbol patterns. (Zig adapter: withdrawn.) | **Partial (Rust not adapter-shaped)** |
| §4.3 Boundary slice (232–258) | `FfiSliceInfo` with `ffi_slice_depth`, `ffi_relevance`, `ffi_reason`; 2-hop expansion + resource-pair + callback closure | `omniscope-types/src/boundary.rs:410-460` defines exactly this struct; `boundary_seeds.rs:415-499` (`FfiSlice::expand_from_seeds`) does the 2-hop expansion and resource-pair closure; `module_index.rs:581-617` wires it. | **Done** |
| §4.4 Two-class candidate gate (260–289) | `Boundary evidence` (6 variants) + `Resource evidence` (5 variants); reporting requires boundary AND resource | `omniscope-types/src/evidence.rs:124-172` defines `BoundaryEvidenceKind` (7 variants — extra `RuntimeBridge`) and `ResourceEvidenceKind` (5 variants exactly). `issue_candidate_builder/mod.rs:332-345, 432-440` enforces dual-evidence gating with `edge_has_boundary_evidence()`. `tests_dual_evidence.rs` covers it. | **Done** |
| §5.1 Unified `SemanticFact` layer (297–313) | Shape `{key, kind, confidence, source, evidence}` | `omniscope-semantics/src/resource/semantic_tree/kind.rs:870-911` defines `SemanticFact` exactly as specified, with `FactSource` enum including `IRPattern`, `ContractDB`, `BehaviorSummary`, `BoundaryDetector`, `LanguageAdapter`, `MemoryGraph`. | **Done** |
| §5.2 Prefer IR behavior over names (315–333) | Enumerated allocation-like / release-like / conditional-release / etc. | `ir_behavior_summary_pass.rs` emits behavior summaries; `structural_inference_pass.rs` prefers them over symbol names. | **Done** |
| §5.3 Value/Resource-level keys and 13 facts (335–362) | `SemanticKey::Value/Resource/Path/Owner/CallSite` + facts: `HeapProvenance`, `GlobalProvenance`, `FromParameter`, `IntoRawTransfer`, `RuntimeManagedResource`, `StoredToOwner`, `StoredToRuntime`, `EscapedToCaller`, `EscapedToOutParam`, `ReleaseOnAllExitPaths`, `AliasOfReleased`, `NonMemoryResource`, `NullOnErrorPath` | `kind.rs:200-355` defines all five `SemanticKey` variants; `kind.rs:37-188` defines every one of the 13 `SemanticKind` variants listed. | **Done** |
| §5.4 Lightweight alias (364–389) | bitcast, GEP-same-base, ptrtoint round-trip, load/store via alloca, phi/select same-family, argument forwarding within slice; emits `AliasOfReleased`/canonical resource ID | `resource/may_alias.rs` (NEW, untracked) implements bitcast + GEP-0 + load chain following + alloca slot tracking + phi-merged alloc roots. Used by `issue_verifier.rs:951-984` as gate for DoubleFree confirmation. Does NOT yet emit `AliasOfReleased` as a `SemanticFact`. | **Partial** — gate-only, no fact emission |
| §5.5 Path semantics (391–409) | `ReleaseOnAllExitPaths`, `FallibleOutParamInit`, `NullOnErrorPath`, `defer`/RAII/drop cleanup | `path_sensitive_leak.rs:215-382` implements paired-release downgrade `DefiniteLeak`→`ConditionalLeak` (NEW, uncommitted). `SemanticKind::ReleaseOnAllExitPaths` and `NullOnErrorPath` exist as types but only `ReleaseOnAllExitPaths` is actively emitted; no `FallibleOutParamInit` variant. | **Partial** — leak-side wired, out-param side missing |
| §6.1 Cross-family matching (414–434) | Same-family FIFO first, then same-function cross-family fallback (single unmatched acquire or nearest within small distance) | `contract_graph_builder.rs:1185-1186, 464-480, 773` implements `is_cross_family = *acquire_family != release_family` with conditional release modeling; no explicit "single unmatched acquire" gate. | **Partial — over-broad** (see bun_alloc validation: paired `malloc`/`free` not recognized, all 6 `DefiniteLeak` are FPs because pairing isn't applied at module level) |
| §6.2 FFI use edges (436–448) | Post-release use edges using `ConsumesArg`/`StoresArgToGlobal`/`StoresArgToOwner`/`EscapesToCallback`; UAF candidate from post-release-use | `issue_candidate_builder/mod.rs:706-745` (`post_release_uses` collection) does this; `Effect::EscapesToCallback` defined in `effect.rs:62`; used to generate `UseAfterFree` candidates. | **Done** |
| §6.3 Callback/userdata edges (450–467) | register→userdata `EscapesToCallback`, optional unregister pair, owner-frees-while-callback-retains | `contract_graph_builder.rs:817-867` emits `EscapesToCallback` for `register_*` patterns; no `unregister`/`revoke` pair tracking. | **Partial** |
| §7 Language adapters (469–688) | Adapters for Rust, C/C++, Zig, Go/cgo, Python, JNI, C# — each emits `LanguageAdapterResult { boundary_facts, semantic_facts, resource_facts, suppressions, confidence }` | `omniscope-semantics/src/resource/` has `cpp_adapter/`, `python_adapter/`, `java_adapter/`, `go_adapter.rs`, `csharp_adapter/`. **No `zig_adapter` or `rust_adapter` modules exist.** `LanguageAdapterFactPass` in `pass/src/resource/language_adapter_fact_pass.rs:87-92` only instantiates `CppAdapter`, `PythonAdapter`, `JavaAdapter`, `GoAdapter`, `CSharpAdapter`. Adapters emit `Vec<SemanticFact>` via `to_semantic_facts()`, not the unified `LanguageAdapterResult` struct from §7. | **Partial (no Rust/Zig adapter modules; result shape differs)** |
| §7.5 Precision implementation playbook (689–809) | Three-step pipeline: boundary recognition → semantic recognition → bug attribution. Rules in §7.5.3. | `boundary_seeds.rs` + `language_adapter_fact_pass.rs` + `issue_candidate_builder` correspond. `FfiEvidence` enum in `omniscope-core/src/issue_candidate.rs:24-43` has 6 variants matching §7.5.3 categories. `has_ffi_evidence()` gate is enforced. | **Done** |
| §7.5.1 Current code integration points table (705–729) | Names the wiring chain `ModuleIndex → RawResourceFact → ContractEdge → IssueCandidate → IssueVerifier/IssueGate` | Exactly matches: `module_index.rs:80, 83`, `raw_fact_collector.rs:44, 125`, `contract_graph_builder.rs:48, 351`, `issue_candidate_builder/mod.rs:325, 432`, `issue_verifier.rs`, `issue_gate.rs`. | **Done** |
| §7.5.6 Development priority (1026–1034) item 1 "Connect boundary_seeds into ModuleIndex" | Populate `CachedCallMeta.boundary_evidence` and `ffi_slice_info` | `module_index.rs:466-617` Phase 2 does this exactly. | **Done** |
| §7.5.6 item 2 "Propagate through RawResourceFact and ContractEdge" | | `raw_fact_collector.rs:125`, `contract_graph_builder.rs:351,502` propagate. | **Done** |
| §7.5.6 item 3 "FFI bug classification requires both boundary and resource" | | `issue_candidate_builder/mod.rs:332-345, 432-440` enforces via `has_boundary && resource-edge` checks; `tests_dual_evidence.rs` covers. | **Done** |
| §7.5.6 item 4 "Local memory bugs reportable without FFI" | | `issue_candidate_builder/mod.rs:1060-1075` keeps non-FFI-evidence candidates as local issues. | **Done** |
| §7.5.6 item 5 "Normalize language adapters" | | Adapters emit `SemanticFact` via `to_semantic_facts()`; downstream is language-neutral. | **Done (shape simplified vs §7)** |
| §7.5.6 item 6 "Embedded IR tests for C/C++, Rust, Python, JNI, Zig, Go" | | `tests/integration_tests.rs` contains `test_jni_*`, `test_go_cgo_*`, `test_zig_alloc_*`, `test_py_*`, `test_large_inline_cpp_rust_ffi_semantics`, etc. — full language matrix exists. | **Done** |
| §7.5.6 item 7 "Loader/cache instrumentation after correctness stable" | | Loader has timing fields; not all kept current per the doc's own §2.5 warning. | **Partial** |
| §8 Avoid large whitelists (1036–1063) | Rules of the form "IR pattern + family + boundary + confidence" | `analysis/noise_reduction.rs:48-101` is mostly small typed patterns; `family_registry.rs` is the main whitelist. Doc rule is followed in spirit but `safe_patterns` is still a string-list (Layer 1 fast filter). | **Partial drift** — the file's own comments admit Layer 1 is kept as a fast pre-filter while SRT rules R-0..R-7 are the authoritative path. |
| §9 Phase 0 — metrics & review fixes; `SuppressRuntimeInternal` separate from `SuppressRaii` (1067–1081) | | `issue_gate.rs:58, 72` defines both variants distinctly; used at lines 145, 178, 199, 307, 369, 398. Top-level `dedup_dropped` counter in `result.rs:39, 70, 102` exposes lossy aggregation. | **Done** |
| §9 Phase 1 — boundary evidence + FFI slice (1083–1095) | | Wired end-to-end via `module_index.rs` Phase 2, `boundary_seeds.rs`, propagated. | **Done** |
| §9 Phase 2 — cross-family matching (1097–1108) | Same-family FIFO + controlled cross-family fallback; tests for `malloc→operator delete`, `new[]→free`, Zig allocator→raw free | `contract_graph_builder.rs:1185-1186` does coarse `is_cross_family` flagging; **lacks the "controlled fallback" / "nearest unmatched within small distance" gating**. Result: still produces FPs on bun_alloc (`mi_malloc/mi_free`, `malloc/free` paired in same TU but flagged as `DefiniteLeak`). Integration tests exist (`integration_tests.rs:1925`, `1885`). | **Drifted** — type is there, behavior is too aggressive |
| §9 Phase 3 — IR semantic fact layer (1110–1122) | Extend SRT to value/resource/call-site keys; emit from IR behavior summaries | `SemanticKey` types complete; `LanguageAdapterFactPass` + `IRBehaviorSummaryPass` populate. | **Done** |
| §9 Phase 4 — post-release FFI use (1124–1134) | FFI use edges for external/indirect/callback calls + lightweight alias propagation for bitcast/GEP/local store/load/arg forwarding | `issue_candidate_builder/mod.rs:706-745` post-release use; `may_alias.rs` lightweight alias (NEW). UAF candidate generation uses these. | **Done** |
| §9 Phase 5 — callback ownership propagation (1136–1146) | Model callback registration, userdata escape, unregister/revoke; cross-function ownership propagation; language-specific callback rules | `EscapesToCallback` modeled and used; no `unregister`/`revoke` pairing; no cross-function ownership propagation within FFI slice. | **Partial** |
| §9 Phase 6 — path semantics (1148–1158) | Cleanup-on-all-exits + fallible out-param + distinguish definite from conditional leak + post-dominator | `DefiniteLeak` vs `ConditionalLeak` exist as `IssueCandidateKind` variants; `path_sensitive_leak.rs` downgrades `DefiniteLeak`→`ConditionalLeak` when paired release sites exist (NEW). No `FallibleOutParamInit` and no real post-dominator analysis. | **Partial** |
| §9 Phase 7 — multi-language adapter normalization (1160–1173) | `LanguageAdapterResult` shape; per-language fact counts; adapter timing counters | Adapters emit `Vec<SemanticFact>` not `LanguageAdapterResult`; per-language counts in `language_adapter_fact_pass.rs:204-211` (`cpp_facts`, `python_facts`, `java_facts`, `go_facts`, `csharp_facts`). No Zig/Rust counts. | **Partial** |
| §9 Phase 8 — multi-language regression suite (1175–1188) | Generated inline IR corpora for JNI/Zig/Python/Go; per-language TP/FP/FN | `tests/integration_tests.rs` has tests for all six languages; `tests/accuracy_regression.rs` exists; per-language precision/recall captured in `docs/release/ffi_demo_validation.md` (NOT in test output). | **Partial — tests yes, per-language metrics no** |
| §11 Recommended immediate next steps items 1–5 | Separate boundary from resource; boundary confidence on `ModuleIndex`; cross-family fallback; value/resource keyed facts; FFI use edges | All five exist as types and wiring; items 3 (cross-family) and parts of 4 (alias not yet emitting facts) are still behaviorally weak. | **Mostly done** |

---

## Sections that are largely done

- §2 / §2.5 / §4.1 / §4.2 / §4.2.1 (modeling) / §4.3 / §4.4 — boundary
  detection model end-to-end matches the plan: types, kinds, slice
  expansion, dual-evidence gate. See `omniscope-types/src/boundary.rs`,
  `omniscope-types/src/evidence.rs`, `boundary_seeds.rs`,
  `module_index.rs:466-617`.
- §5.1 / §5.2 / §5.3 — `SemanticFact`, `SemanticKey`, `FactSource`, all
  13 `SemanticKind` variants, and `IRBehaviorSummaryPass` are in place
  (`semantic_tree/kind.rs:37-911`).
- §6.2 — Post-release FFI use edges produce `UseAfterFree` candidates
  (`issue_candidate_builder/mod.rs:706-745`).
- §7.5.1 — Wiring chain is intact end-to-end.
- §7.5.3 — `FfiEvidence` enum (`omniscope-core/src/issue_candidate.rs:24-43`)
  and `has_ffi_evidence()` gate implemented with tests
  (`tests_dual_evidence.rs`).
- §7.5.6 items 1–5 — all five priority items materialized.
- §9 Phase 0 — `SuppressRuntimeInternal` distinct from `SuppressRaii`
  (`issue_gate.rs:58, 72`); top-level dedup with `dedup_dropped`
  counter (`pipeline/src/result.rs:39, 70, 102`).
- §9 Phase 1 — boundary evidence + FFI slice end-to-end wired.
- §9 Phase 3 — semantic fact layer wired.
- §9 Phase 4 — alias-gated DoubleFree + post-release-use UAF.

## Sections that are still stubs or aspirational

| Section | What's missing | Severity for v0.2.0-rc |
|---|---|---|
| §6.1 Cross-family matching with controlled fallback | "Single unmatched acquire OR nearest unmatched acquire within small distance" gate is absent. Current code coarsely flags any `acquire_family != release_family`. Drives bun_alloc 0% precision (`docs/release/bun_validation.md` items 14–16, 19). | **High** |
| §6.3 Callback unregister/revoke pair | `unregister`/`revoke` linkage not modeled. | Medium |
| §7 Rust adapter as a distinct module | No `rust_adapter/` — Rust semantics rely on `family_registry.rs` + `rust_drop_tracker.rs` + `rust_stdlib_whitelist`. Drives the "rust_hash.ll/rust_merkle.ll → 0 issues" recall miss in `docs/release/ffi_demo_validation.md` blocker #3. | **High** |
| §7 Zig adapter as a distinct module | No `zig_adapter/`. **(Withdrawn — Zig removed from product scope.)** The `zig_ffi_bridge.ll` allocator-shaped FP cluster and bun_alloc FPs are now historical observations. | **N/A (withdrawn)** |
| §7 `LanguageAdapterResult` shape | Adapters emit `Vec<SemanticFact>`, not the full struct `{ boundary_facts, semantic_facts, resource_facts, suppressions, confidence }`. Cosmetic for now since downstream consumes facts directly. | Low |
| §9 Phase 5 cross-function ownership propagation within FFI slice | Not implemented. Drives `ffi_make_token`/allocator-factory FPs in `docs/release/ffi_demo_validation.md`. | **High** |
| §9 Phase 6 fallible out-param semantics + real post-dominator | `FallibleOutParamInit` is not in `SemanticKind`. Post-dominator analysis would fix the bun_alloc DoubleFree FP and the `c_merkle_tree` UAF/DF FPs. | **High** |
| §9 Phase 7 adapter timing/per-language counts for Rust | No Rust adapter, so no counters; doc cannot be evaluated. (Zig withdrawn.) | Medium |
| §8 No-large-whitelists discipline | `noise_reduction.rs` retains a string-pattern list as Layer 1 fast filter. Doc says "Allowed", but the list keeps growing per commit `b0e00b6` and the new `17bea02`. | Medium |
| §2.5 Per-language adapter timing isolated from load time | `LoadedIr.backend_ms`/`deserialize_ms` sometimes return `None`; doc itself warns this is not sufficient for perf work. | Low |
| Plan's "Recommended Immediate Next Steps" item 6 (loader perf instrumentation tests) | No counted-backend-seam regression test; the spec at §2.5 lines 108–109 is aspirational. | Low |

## Highest-priority drifts

1. **Plan §6.1 claims controlled cross-family matching; code marks every
   `acquire_family != release_family` as cross-family** without the
   "single unmatched acquire" / "small distance" gating from lines
   417–433. This is the root cause of 6 of the 19 bun_alloc FPs
   (`DefiniteLeak` on `mi_malloc`/`mi_realloc`/`malloc` when their
   matching `mi_free`/`free` lives in the same TU — see
   `docs/release/bun_validation.md` items 14–16, 19) and the
   `c_fft_c_bridge.ll` confirmed-DoubleFree FP. A new reader of the
   plan would expect the "controlled fallback" to suppress these.

2. **Plan §7 promises Rust and Zig adapter modules with explicit IR
   evidence catalogs**; the code has only C++/Python/Java/Go/C# adapter
   modules. Rust and Zig semantics are scattered across
   `family_registry.rs`, `rust_stdlib_whitelist/`,
   `rust_drop_tracker.rs`, `language_detector.rs`. **(Zig adapter:
   withdrawn — no longer planned.)** The result is the
   "single-language Rust modules report 0 issues / suppress 13 ffi-gate
   candidates" symptom in `docs/release/ffi_demo_validation.md` blocker
   #3 and `docs/release/bun_validation.md` blocker #3. A new contributor
   reading §7 will hunt for `crates/omniscope-semantics/src/resource/rust_adapter/`
   and find nothing except the Rust adapter gap.

3. **Plan §4.4 / §7.5.3 say "do not let a single signal report an FFI
   bug by itself"; behavior on the bun_alloc and ffi-demo corpora shows
   the inverse on `DoubleFree`**: a single signal ("two `free()` call
   sites in the module") still produces `severity = Error,
   confidence = High` reports. `may_alias.rs` (just added) is the
   intended fix, but it gates only at `IssueVerifier::verify_double_release`;
   the unconditional `MayAlias` default when no IR module is provided
   (`may_alias.rs:87-89, 100-108`) means many synthetic and IR-light
   paths still pass through.

4. **Plan §5.4 promises emitted facts `AliasOfReleased` and "canonical
   resource ID for acquire/release/use edges"**; `may_alias.rs`
   implements the alias check but never produces a `SemanticFact` with
   `SemanticKind::AliasOfReleased` (the variant exists at
   `kind.rs:188`). Downstream verifiers cannot weigh alias evidence in
   their explanations.

5. **Plan §2.5 claims `Empty FFI slices are a soft result, not a reason
   to rerun full C++ extraction`** and §11 item 6 calls for
   loader/cache instrumentation tests. There is no
   counted-backend-seam test, and `LoadedIr.backend_ms`/`deserialize_ms`
   return `None` in many paths. The doc itself flags this at
   lines 84–85; the gap remains.

---

## Recommended next actions

### Edits to the plan (read-only doc fixes)

- **§7 (line 469 onward)**: add a "Status" column to the per-language
  table. Mark Rust as "no adapter module yet; semantics live
  in `family_registry.rs` + `rust_stdlib_whitelist/` +
  `rust_drop_tracker.rs`". Mark Zig as "withdrawn — not planned."
  A new contributor will otherwise expect
  symmetric `rust_adapter/` and `zig_adapter/` directories.
- **§7 LanguageAdapterResult shape (475–484)**: clarify that
  adapters today return `Vec<SemanticFact>` via `to_semantic_facts()`
  and the full result struct is aspirational. Either retrofit the
  struct or downgrade the spec.
- **§6.1 (414–433)**: tighten the language: explicitly state that
  current `contract_graph_builder.rs` does NOT yet have the controlled
  fallback. Cite the bun_alloc validation result as a known regression.
- **§5.4 (364–389)**: note that `may_alias.rs` provides the alias gate
  but does not yet emit `AliasOfReleased` facts. Add as Phase 4b.
- **§9 Phase 2 (1097)**: reword "Recover 2-3 TP with small code
  change" — production behavior is currently emitting FPs rather than
  TPs because the fallback is uncontrolled.
- **§11 item 1**: already done — strike "Separate boundary evidence
  from resource evidence" or mark complete.
- **§11 items 3, 5**: partially done — qualify.

### Code work needed to actually realize the plan (NOT for this audit)

- Implement controlled cross-family fallback (§6.1) — gate on
  "single unmatched acquire in same function" before flagging.
- Add `crates/omniscope-semantics/src/resource/rust_adapter/` to
  match §7 and unblock the rust_*.ll validation gaps.
  (Zig adapter: withdrawn — NOT PLANNED.)
- Emit `SemanticFact { kind: AliasOfReleased, ... }` from `may_alias.rs`
  hits so the SRT can record the evidence.
- Add `FallibleOutParamInit` to `SemanticKind` and wire from path
  analysis (§5.5).
- Add cross-function ownership propagation within the FFI slice
  (§9 Phase 5) — this is the single fix that would close the
  "allocator-shaped factory function is flagged as its own leak"
  family of FPs (4/19 bun_alloc, 5 in ffi-demo).
- Add a counted-backend-seam regression test (§2.5 closing paragraph)
  to lock in the "0 C++ backend invocations on warm unchanged input"
  contract.
