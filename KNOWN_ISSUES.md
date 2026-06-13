# OmniScope-rs Known Issues & Development Plan

**Date:** 2026-06-12
**Binary:** `target/release/omniscope` (version 0.1.0)
**Acceptance Criteria:** Overall TP > 80% across all test corpora

---

## P0: Detection Gaps (red_team corpus, 17 files, Zig excluded)

### Summary (updated 2026-06-12)

| Detection Type | Files with TP | Files with Expected | Hit Rate | Status |
|---------------|--------------|-------------------|----------|--------|
| CrossLanguageFree | 3 | ~12 | 25% | Needs improvement |
| UseAfterFree | 0 | ~6 | 0% | Needs dataflow analysis |
| DoubleFree | 8 | ~12 | 67% | Improved (+1 from cpp_operator_new) |
| CrossFamilyFree | 6 | ~10 | 60% | Partial |
| Zig support | — | — | — | Removed |

### Progress since last update
- `cpp_operator_new_ffi_bugs`: now detects DoubleFree (was 0) — C++ mangled symbol detection fix
- `classify_seed()` now uses family registry SymbolEffect — fixes CrossLanguageFree for Go/Python allocators
- `cs_memory_leak_bug2` TP regression fixed — `Marshal_AllocHGlobal` now recognized
- WriteToImmutable downgraded to Note severity — reduces noise
- UAF detection for freed-pointer-as-argument added (basic SSA-level, needs global load/store chain improvement)

### CrossLanguageFree — only Go/Python work

| File | Expected | Detected | Root Cause |
|------|----------|----------|------------|
| cross_lang_free_bugs | Yes | No | `rust_box_new` not in family registry |
| rust_ffi_bugs | Yes | No | Rust alloc functions not recognized as cross-lang |
| cpp_operator_new_ffi_bugs | Yes | No | `_Znwm`/`_ZdaPv` not linked to cross-lang detection |
| java_jni_bugs | Yes | No | JNI alloc patterns not in family registry |
| csharp_ffi_bugs | Yes | No | `Marshal_AllocHGlobal` seed classification fails |
| zig_* (3 files) | — | — | Zig support removed |
| go_cgo_bugs | Yes | Yes | Working |
| python_capi/cffi_bugs | Yes | Yes | Working |

**Fix approach:** The family registry already has C/C++/Rust/Go/Python allocators. The issue is in `classify_seed()` — it doesn't check `SymbolEffect::Acquire` from the registry to promote weak seeds to strong seeds. Fix: pass `symbol_effect` into `SeedContext` and promote to strong when callee has `Acquire` effect.

**Files:**
- `crates/omniscope-pass/src/analysis/boundary_seeds.rs` — add `symbol_effect` to `SeedContext`
- `crates/omniscope-pass/src/module_index.rs` — pass `symbol_effect` from registry lookup

### UseAfterFree — 0% detection rate

The analyzer detects UAF in ffi-demo (12 UAF in zig_main.ll) but 0 in red_team. The difference: ffi-demo UAF patterns use `load` after `free` on the same SSA value, while red_team UAF patterns pass freed pointers to functions/callbacks.

**Root cause:** The verifier's UAF detection (`verify_candidate_inner`) only checks if a freed pointer is used in a `load` instruction. It doesn't check if a freed pointer is passed as an argument to another function (callback/FFI pattern).

**Fix approach:** In the issue candidate builder, when a `free` is followed by a call instruction that uses the same register as an argument, generate a UAF candidate. Use the existing SSA root tracing from `may_alias.rs` to track freed pointer usage.

**Files:**
- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs` — add freed-pointer-as-argument detection
- `crates/omniscope-pass/src/resource/issue_verifier/mod.rs` — verify UAF candidates from argument-pass pattern

### DoubleFree — partial detection

| File | Expected | Detected | Root Cause |
|------|----------|----------|------------|
| cross_lang_free_bugs | Yes | No | `rust_box_new` not recognized, so no double-release candidate |
| cpp_operator_new_ffi_bugs | Yes | No | C++ allocators not generating candidates |
| rust_ffi_bugs | Yes | No | Rust allocators not generating candidates |
| zig_* (3 files) | — | — | Zig support removed |
| java_jni_bugs | Yes | Yes | Working |
| go_cgo_bugs | Yes | Yes | Working |
| python_cffi_bugs | Yes | Yes | Working |

**Fix approach:** Same as CrossLanguageFree — fix `classify_seed()` to promote allocators from registry. Once allocators generate candidates, the existing `verify_double_release` logic will detect double-free.

### CrossFamilyFree — partial detection

Same root cause as CrossLanguageFree. The contract graph needs acquire/release pairs to detect cross-family mismatches. If the allocator isn't recognized, no pair is formed.

---

## P0: Zig Support Removal

Zig support is completely removed from the project. This includes:

1. Remove Zig language variant from `Language` enum (if present)
2. Remove Zig-specific patterns from language detector
3. Remove Zig test fixtures from corpus (already gitignored)
4. Remove Zig mentions from README and documentation
5. Skip Zig test files in corpus tests

**Files to clean:**
- `crates/omniscope-types/src/config.rs` — remove Zig variant
- `crates/omniscope-semantics/src/resource/language_detector.rs` — remove Zig patterns
- `crates/omniscope-pass/src/analysis/boundary_seeds.rs` — remove Zig bridge detection
- `tests/corpus_tests.rs` — remove `test_zig_corpus_hidden_bugs`
- README.md / README_CN.md — remove Zig mentions

---

## P1: Precision Issues (52.4% → target 80%+)

### WriteToImmutable noise (~4000+ issues across all corpora)

| Project | Total | WriteToImmutable | % Noise |
|---------|-------|-----------------|---------|
| zstd-rs | 971 | 969 | 99.8% |
| abseil2024 | 2969 | 2922 | 98.4% |
| ripgrep141 | 60 | 58 | 96.7% |
| cpp_hash | 50 | 49 | 98.0% |
| rust_merkle | 20 | 20 | 100.0% |

**Fix approach:** WriteToImmutable is a diagnostic, not a memory safety bug. Lower its severity or move it to a separate diagnostic category that doesn't count toward precision metrics.

**Files:**
- `crates/omniscope-core/src/issue.rs` — add `Diagnostic` category for WriteToImmutable
- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs` — set lower severity

### bun_alloc FP (20 issues, all FP)

All 20 issues are FFI boundary detections (CrossLanguageFree, OwnershipViolation) for intentional mimalloc usage.

**Fix approach:** When an allocator family (e.g., MIMALLOC) has both acquire and release in the same module, and the caller intentionally uses the foreign allocator, suppress the FFI boundary issue. Use the existing contract graph pairing — if acquire/release are paired, the cross-language free is intentional.

**Files:**
- `crates/omniscope-pass/src/resource/issue_verifier/mod.rs` — suppress CrossLanguageFree when contract graph shows paired release

### cs_memory_leak_bug2 TP regression

Root cause: `classify_seed()` doesn't check `SymbolEffect::Acquire` from family registry. Same fix as CrossLanguageFree detection gap.

---

## P2: Real-World Ground Truth

| Project | Source | Issues | Verified |
|---------|--------|--------|----------|
| bun_alloc | ~/code/researcher/bun/src/bun_alloc/ | 20 | 0 TP / 20 FP |
| llhttp | /tmp/bun_ll/llhttp.ll | 0 | Correct |
| go-sqlite3 | corpus/real_project_test/ | 57 | 5 mem safety (all FP per source) |
| sqlite3 | corpus/real_world/other/ | 292 | 8 mem safety (all FP per source) |
| rust_sqlite | corpus/real_world/other/ | 56 | 5 mem safety (all FP per source) |
| zstd-rs | corpus/real_project_test/ | 971 | Mostly WriteToImmutable noise |
| abseil2024 | corpus/real_world/other/ | 2969 | Mostly WriteToImmutable noise |
| ripgrep141 | corpus/real_world/other/ | 60 | Mostly WriteToImmutable noise |
| openssl_wrapper | corpus/ffi-dense/ | 8 | Unverified |
| xxhash | corpus/real_project_test/ | 6 | 3 ConditionalLeak, unverified |

### sqlite3 source comparison

Source: `~/code/researcher/bun/src/jsc/bindings/sqlite/sqlite3.c`

| OmniScope Issue | Function | Source Line | Verdict |
|----------------|----------|-------------|---------|
| DoubleFree | sqlite3VdbeExec | 97268 | FP — conditional free paths |
| UseAfterFree | sqlite3Realloc | 31952 | FP — realloc(p,0) standard pattern |
| UseAfterFree | fts5FreeCursorComponents | 260449 | FP — cleanup pattern |
| UseAfterFree | sqlite3VdbeFreeCursorNN | 90461 | FP — cursor close dispatch |
| InvalidFree | sqlite3_realloc64 | 32008 | FP — realloc interface |

---

## Fix Priority

| # | Task | Impact | Effort | Files |
|---|------|--------|--------|-------|
| 1 | Fix `classify_seed()` to use registry `SymbolEffect` | Fixes CrossLanguageFree + DoubleFree + cs_memory_leak_bug2 | Small | boundary_seeds.rs, module_index.rs |
| 2 | Remove Zig support | Cleanup | Small | config.rs, language_detector.rs, tests, README |
| 3 | Add freed-pointer-as-argument UAF detection | Fixes UAF detection | Medium | issue_candidate_builder, issue_verifier |
| 4 | Suppress WriteToImmutable from precision metrics | Precision 52% → ~70% | Small | issue.rs, issue_candidate_builder |
| 5 | Suppress intentional FFI allocator patterns | Fixes bun_alloc FP | Small | issue_verifier |
| 6 | Verify real-world project ground truth | Accuracy validation | Large | Manual review |

## Acceptance Criteria

- [ ] red_team corpus: CrossLanguageFree detection in ≥ 8/12 expected files
- [ ] red_team corpus: UseAfterFree detection in ≥ 3/6 expected files
- [ ] red_team corpus: DoubleFree detection in ≥ 10/12 expected files
- [ ] ffi-demo corpus: TP ≥ 80% (currently 84.6% recall, need precision ≥ 80%)
- [ ] Overall precision ≥ 80% across all corpora
- [ ] No Zig references in codebase
- [ ] `make fmt && make check && make test` all pass
