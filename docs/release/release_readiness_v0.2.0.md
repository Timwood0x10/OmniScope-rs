# OmniScope-rs v0.2.0 Release Readiness Verdict

**Date:** 2026-06-07
**Binary tested:** `target/release/omniscope` (reports version `0.1.0`)
**Method:** Two parallel validation agents ran the binary on:
- `~/code/ffi-demo/output/*.ll` (10 files, hand-crafted bug corpus with `BUG[...]` source tags)
- `/tmp/bun_ll/bun_alloc-*.ll`, `llhttp.ll`, `ffi_mixed.ll` (bun + synthetic mix)

Each issue was cross-checked against the actual source. Full per-file details:
- [`docs/release/ffi_demo_validation.md`](./ffi_demo_validation.md)
- [`docs/release/bun_validation.md`](./bun_validation.md)

---

## TL;DR — Do NOT ship v0.2.0 yet

Both validations independently surface the **same three root-cause bugs**. The user's gut feeling ("我心里还是没底") was correct.

### Headline numbers

| Corpus | Issues reported | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| ffi-demo (10 files) | 47 | 32 | 15 | 20 | **68 %** | **62 %** |
| ffi-demo minus the best file (`zig_main.ll`) | 27 | 12 | 14 | 19 | **~43 %** | ~39 % |
| bun_alloc.ll | 19 | **0** | 19 | n/a | **0 %** | n/a |
| llhttp.ll | 0 | 0 | 0 | 0 | n/a | n/a |

The headline 68 % precision is carried almost entirely by **one** file (`zig_main.ll`: 20 TP / 1 FP). Outside of Zig, the analyzer's precision is ~43 % on ffi-demo and **0 % on bun_alloc**. That's not "production-grade".

---

## Three root-cause bugs (both validations independently hit these)

### Blocker #1 — `DoubleFree` is flow-insensitive

**Symptom seen in:** ffi-demo `c_fft_c_bridge.ll`, `c_merkle_tree.ll`; bun `bun_alloc.ll`.

Any module that contains ≥ 2 `call @free` instructions gets a `[confirmed] DoubleFree`. There's no must-alias / dominator / value-flow check. In `bun_alloc.ll` the two free sites are `Z::free` and `fallback::free_without_size`, each on its own pointer — the report is structurally guaranteed to fire on any non-trivial allocator.

**Fix:** before emitting `DoubleFree`, require that the two `free` calls operate on values that may alias (same SSA root, or same `@global`, or same allocator-return reaching both). Cheap heuristic for now: same `phi`-induced value or dominator-related blocks.

**Files:** `crates/omniscope-pass/src/resource/issue_candidate_builder/`, `issue_verifier.rs`.

### Blocker #2 — Single-language module gate kills FFI passes incorrectly

**Symptom seen in:** ffi-demo `rust_hash.ll`, `rust_merkle.ll` (zero issues despite documented bugs); bun `bun_alloc.ll` (zero issues with `--boundary-only` even though the IR declares `mi_malloc`, `mi_free`, `malloc`, `free`, `mmap`, `aligned_alloc` as C externs).

`ModuleIndex` decides "single-language Rust" purely from mangled-name dominance and turns off FFI seed generation. The recent commit `bd21984 feat (analysis): Single-language module skips FFI detection` is the culprit. It's too aggressive — declared C externs ARE FFI evidence and should keep the FFI passes on.

**Fix:** in `crates/omniscope-pass/src/module_index.rs`, when classifying as single-language, also count declared (non-defined) externs whose name does not match the dominant-language mangling scheme. If ≥ 3 such externs exist, demote to "mixed".

### Blocker #3 — `DefiniteLeak` ignores pairing data that's already computed

**Symptom seen in:** bun `bun_alloc.ll` reports leak on `mi_malloc`/`malloc` while `mi_free`/`free` pairing is in the same IR (6+ call sites). ffi-demo agent calls this out as "5 specific bugs" — the allocator-factory functions are reported as leaks instead of their callers.

The contract graph already pairs allocator/deallocator families. The leak pass is reading the leak side without joining the deallocator side.

**Fix:** `crates/omniscope-pass/src/analysis/leak_detection.rs` — before reporting a leak on an allocator return value, query the contract graph for a paired-deallocator that is reachable from the same call site. If yes, downgrade to `LeakSuspect` or drop entirely.

---

## Secondary issues (not blockers, but ship-impacting)

4. **Top-level `issues` array is lossy.** ffi-demo agent observed `IssueVerifier.issues_found=7` vs `total_issues=5` in `c_ffi_traps.json`. Deduplication kills real findings before user sees them. Look at the merge step in the verifier/reporter.

5. **Empty function-name strings** appear in output (`function: ""`). Cosmetic but undermines trust.

6. **`info --passes` lies.** Lists `NoiseReduction`, `PrecisionMetrics`, `MemorySafety`, `PointerOwnership`, `BufferOverflow` — none of these are actually registered passes. (See `crates/omniscope-cli/src/main.rs:785-805` vs `crates/omniscope-pipeline/src/pipeline.rs:85-126`.)

7. **README factual drift** — independently flagged by both doc agents and both validation agents:
   - "23 issue kinds" → actual 28 (`crates/omniscope-core/src/issue.rs:27-96`)
   - "20+ passes" → actual exactly 20
   - "Plan A/B/C three-tier loading" → actual 8 `LoadStrategy` variants
   - **"Real bugs found in bun"** — `bun_jsc` and `bun_boringssl` are not real crate names in the bun repo (`src/jsc/`, `src/boringssl/` exist; the crate names in the README do not). The "100 % precision on bun_alloc (1/1)" claim does NOT reproduce on the shipped `bun_alloc-7abe075f8accee73.ll` (0/19 TP). These claims are misleading and should be removed or rewritten with reproducible recipes before v0.2.0 ships.

---

## Recommended path to v0.2.0

In rough effort order (smaller bugs first, biggest impact last):

1. **(1 day)** Remove or rewrite the bun bug claims in README.md / README_CN.md. Either commit the IR + a runnable recipe that reproduces them, or pull the claims.
2. **(1 day)** Fix the empty `function: ""` in output + sync `info --passes` text with the real pass list.
3. **(2-3 days)** Fix the lossy issue dedup in the reporter (#4).
4. **(2-3 days)** Tighten the single-language gate (#2) — count externs.
5. **(3-5 days)** Add must-alias check before `DoubleFree` (#1).
6. **(3-5 days)** Join leak detection with the contract graph's deallocator side (#3).
7. **Then re-run both validation suites.** Target: precision ≥ 80 % on ffi-demo overall (not just Zig), recall ≥ 75 %, and ≥ 1 reproducible TP on bun_alloc.

When those numbers hit, ship as `v0.2.0`. Until then, the realistic options are:

- **`v0.2.0-rc.1`** — pre-release, README claims softened, validation reports linked, "known limitations" section added.
- **`v0.1.x` patch line** — keep iterating without committing to a "stable" tag yet.

The current state is closer to "interesting prototype on Zig↔C" than to "production-grade FFI analyzer for 8 languages".

---

## What still works well

To be fair to the project:

- **Zig↔C analysis is genuinely good** — 95 % precision, 100 % recall on `zig_main.ll`.
- **`llhttp.ll` correctly produced zero issues** — no false alarms on a clean vendored parser.
- **The IR loader survives all 13 test files** without crashing — no OOMs, no panics, no hangs.
- **CI infrastructure** is now functional (sccache removed, mold/LLVM 22 wired in, release.yml builds 4 targets).

Lead with these in marketing; tighten the analyzer before claiming the rest.
