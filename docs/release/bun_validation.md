# Bun Validation Report (vs OmniScope v0.1.0 binary)

Generated 2026-06-07 by independent validation of the release binary
`target/release/omniscope` (version 0.1.0, master branch as of f533a4d).

The aim was to verify three concrete claims the README makes about bun,
and to honestly score the analyzer's detections on three IR files the
caller named: `bun_alloc-7abe075f8accee73.ll`, `llhttp.ll`, `ffi_mixed.ll`
(plus the larger `zig_main.ll` that lives alongside them).

## Per-IR-file analyzer behavior

| File | Bytes | Funcs / Decls / Calls | Loader | Total wall | Pipeline | Verdict |
|------|------:|-----------------------|--------|-----------:|---------:|---------|
| `bun_alloc-7abe075f8accee73.ll` | 511 KB | 63 / 59 / 179 | text-parser | ~10 ms | 6 ms | OK |
| `llhttp.ll` | 1.5 MB | 61 / 31 / 106 | text-parser | 22 ms | 14 ms | OK |
| `ffi_mixed.ll` | 40 KB | 10 / 6 / 25 | text-parser | 2 ms | 1 ms | OK |
| `zig_main.ll` | 10.8 MB | 721 / 93 / 16749 | text-parser (fast path) | ~1.9 s | ~1.9 s | OK |

No crashes, no hangs, no panics. `--format rich` and `--boundary-only`
also completed cleanly on every file. Memory was well under 1 GB at all
times.

### Caveat about the input set

- `llhttp.ll` is genuine bun source (`src/jsc/bindings/node/http/llhttp/llhttp.c`).
- `bun_alloc-7abe075f8accee73.ll` is genuine bun source (the `bun_alloc`
  crate, compiled from `src/bun_alloc/lib.rs` + siblings — mangled names
  contain `Cs9SN9c7tmF9T_9bun_alloc...`).
- `ffi_mixed.ll`'s LLVM `source_filename` is `/tmp/bun_ll/ffi_mixed.c`.
  Its symbols (`buffer_new`, `process_ffi_data`, `py_bug_pattern`,
  `py_decref`, `py_create`, `py_bug_pattern`) do **not** appear anywhere
  in the bun source tree. **This is a synthetic OmniScope test fixture,
  not bun code.** Including it in a bun-validation suite is misleading.
- `zig_main.ll` similarly references `main.crossLanguageFreeDemo`,
  `main.useAfterFreeDemo`, `main.doubleFreeDemo`, `c_alloc_buffer` etc.
  — a Zig test corpus, not bun.

So strictly speaking only **two** of the supplied files are bun: `llhttp`
and `bun_alloc`. The other two are deliberately-buggy fixtures.

## Detection results

| File | Issues | Definite | Conditional | Double-Free | FFI / Cross-Lang | Unchecked |
|------|-------:|---------:|------------:|------------:|-----------------:|----------:|
| `bun_alloc` | 19 | 6 leaks | 12 leaks | 1 | 0 | 0 |
| `llhttp` | 0 | 0 | 0 | 0 | 0 | 0 |
| `ffi_mixed` | 9 | 2 | 7 | 0 | 0 | 0 |
| `zig_main` | 26 | 2 | 5 | 4 | 11 (4 cross-lang free, 7 ownership) | 5 |

### bun_alloc triage

The 19 issues map to the following bun symbols, which I cross-checked
against `/Users/scc/code/researcher/bun/src/bun_alloc/`.

| # | Kind | OmniScope description | bun source mapping | Verdict |
|---|------|----------------------|--------------------|---------|
| 1 | ConditionalLeak | `malloc_set_zone_name` in `heap_breakdown::Zone::init` | `heap_breakdown.rs` (Zone setup, calls macOS `malloc_set_zone_name` — does **not** allocate, just names a zone) | **FP**. `malloc_set_zone_name` is a *labelling* call, not an allocator. Treating it as an acquisition is wrong. |
| 2 | ConditionalLeak | `aligned_alloc` in `fallback::z::Z::alloc` | `src/bun_alloc/fallback/z.rs:25`, `fallback.rs:32` (`libc::aligned_alloc` inside `raw_alloc`) | **FP**. Pointer is returned to the caller — ownership transfer through return value. OmniScope cannot follow the return edge. |
| 3 | ConditionalLeak | `malloc` in `Z::alloc` | same as #2 (alternate path through `libc::malloc`) | **FP**, same reason. |
| 4 | ConditionalLeak | `malloc_set_zone_name` in `heap_breakdown::get_zone` | `heap_breakdown.rs` (registers a zone label) | **FP**, same as #1. |
| 5 | **DoubleFree** | "double release in `free` [confirmed]" | The IR has only **two** `call @free` sites: `Z::free` (z.rs:72) and `fallback::free_without_size` (fallback.rs:131). Each frees its own argument, not the same pointer. | **FP**. The analyzer is counting "two call sites of `free()` in the module" as a double-free, not aliasing of the pointer. |
| 6, 7 | ConditionalLeak (`mmap`) | `bss_arena_bump`, `bss_arena_bump::map_arena` | `lib.rs:1967` and `lib.rs:1981`. Source comments explicitly say "process-wide `.bss` arena" with `MAP_NORESERVE` — intentional process-lifetime allocation. | **FP** (or at best "noise"). Documented intentional static arena. |
| 8 | ConditionalLeak | `realloc_raw` family `18` | `lib.rs:898` — returns reallocated pointer | **FP**. Realloc transfers ownership to caller. |
| 9 | ConditionalLeak | `default_dupe` family `18` | `lib.rs:1676` — returns `&'static [u8]` lifetime-extended | **FP**. Static lifetime — intentional. |
| 10 | ConditionalLeak | `realloc_slice` family `18` | `lib.rs:876` — returns reallocated buffer | **FP**, ownership transfer. |
| 11 | ConditionalLeak | `MimallocAllocator::alloc_with_default_allocator` | `basic.rs:63` | **FP**, allocator vtable callback. |
| 12 | ConditionalLeak | `mimalloc_arena::global_vtable_alloc` | `MimallocArena.rs:762` | **FP**, vtable callback. |
| 13 | ConditionalLeak | `c_thunks::mi_malloc_items` | `c_thunks.rs:21` (`extern "C"` thunk) | **FP**, returns the pointer. |
| 14–16 | DefiniteLeak | `mi_realloc`, `mi_malloc`, `mi_malloc_aligned` "no same-family release" | mimalloc functions declared at top of IR | **FP at the module level**. These are external mimalloc symbols whose paired `mi_free` lives in the same IR (and is called 6+ times). The analyzer has the data to pair them and chose not to — same-family release exists. |
| 17 | DefiniteLeak | `malloc_set_zone_name` | (a no-op labelling call) | **FP**, as #1. |
| 18 | DefiniteLeak | `aligned_alloc` | same as #2 | **FP**. |
| 19 | DefiniteLeak | `malloc` | external libc, paired with `free` in `fallback::free_without_size` | **FP**. The pairing exists in the same module. |

**bun_alloc score: 0 TP / 19 FP / 0 cannot-verify.**

The root cause of the cluster: OmniScope's `ModuleIndex` classified the
file as "single-language Rust" and *skipped* FFI-boundary classification
entirely (`ModuleIndex: single-language module detected (Rust) — FFI
passes will be skipped`). Yet the IR declares `mi_malloc`, `mi_free`,
`malloc`, `free`, `mmap`, `aligned_alloc`, `malloc_set_zone_name`,
`malloc_zone_memalign`, `Bun__WTFStringImpl__destroy`, etc. — every one
of those is a C ABI extern. The "single-language" gate is the wrong
question for a Rust IR: of course the *defined* functions are all Rust,
but the FFI boundary is the *declared* C functions.

Consequence: with `--boundary-only`, `bun_alloc` reports **0** issues.
The headline use case for the README ("100% precision on bun_alloc leak
analysis 1/1") is not reproducible here — the analyzer produced 19
issues, none of which I could classify as a true positive against the
source.

### llhttp triage

0 issues. llhttp is a pure parser state machine with no heap allocations
in this translation unit (all storage is caller-supplied). Zero issues
is correct — but trivially so, the module exercises almost nothing in
the analyzer.

### ffi_mixed triage

Not bun source — synthetic test fixture. Reports look semantically
correct against the obvious bugs in the fixture (paths that `malloc`
then return without freeing on the early-exit path). Cannot be counted
toward bun validation.

### zig_main triage

Not bun source — Zig test fixture with intentional bugs in functions
named `*Demo`. Reports match the obvious bug patterns (cross-language
free, ownership violation, double free, unchecked return). Cannot be
counted toward bun validation.

## README claim verification

| Claim (README.md lines 19-22) | Status |
|-------------------------------|--------|
| "Command injection in `bun_jsc` (CRITICAL)" | **Unverifiable / no evidence.** There is no crate named `bun_jsc` in bun (only `src/jsc/...`). No IR for any jsc binding was supplied. The OmniScope repo's own docs do not contain a writeup, IR file, or reproduction recipe for this finding. The kind `CommandInjection` does not appear in `IssueKind`. |
| "Cross-language memory leak in `bun_boringssl` (HIGH)" | **Unverifiable / no evidence.** There is no `bun_boringssl` crate in bun (only `src/boringssl` and `src/boringssl_sys`). No IR for either was supplied. No writeup exists in the repo. |
| "100% precision on `bun_alloc` leak analysis (1/1)" | **Not reproduced.** On the supplied `bun_alloc-7abe075f8accee73.ll`, the analyzer emits 19 issues. Manual triage classifies all 19 as false positives against the bun source. Precision = 0/19, not 1/1. The "1/1" denominator suggests an earlier private corpus that is not the file shipped here. |

In summary: **all three real-world bun claims in the README cannot be
reproduced from the artifacts in this repo plus the IR files in /tmp.**
This does not necessarily mean the analyzer has never found anything
real on bun — it means the public claims are unsupported and a user
following the README cannot verify them.

## Fix suggestions (TPs only)

There are no confirmed true positives in this run, so there is nothing
to forward to bun upstream. The fixes need to be in OmniScope itself:

1. **Stop skipping FFI passes for single-language modules whose IR
   contains C-ABI extern declarations.** `crates/omniscope-pass/src/module_index.rs`
   currently treats a module as single-language based on the language of
   *defined* functions, ignoring whether `declarations` contain
   C-mangled extern symbols. For a Rust module that declares `malloc`,
   `free`, `mi_malloc`, `mmap`, etc., the FFI boundary is the
   Rust→C call edge, even though there are no C functions defined here.
   Suggested change: if `module.declarations` contains at least one
   non-mangled symbol that matches a known allocator/system family,
   keep FFI passes enabled.

2. **Pair allocators and deallocators within the same family before
   reporting `DefiniteLeak`.** `mi_malloc` paired with `mi_free` and
   `malloc` paired with `free` are both present in this IR; the leak
   detector ignored the pairing. See `crates/omniscope-pass/src/analysis/`.

3. **`DoubleFree` should require a *shared allocation site*, not two
   distinct call sites of the deallocator.** The current rule fires on
   any module that has two `free()` calls, which is a near-universal
   pattern. See the "double release in `free` [confirmed]" report on
   bun_alloc — every C/Rust binary has ≥ 2 frees.

4. **Suppress reports on allocators whose return value flows directly
   to a `ret` instruction** (intra-procedural escape). Items 2, 3, 8–13
   in the bun_alloc table all trip this. The fix lives in
   `noise_reduction.rs` (currently being modified per `git status`).

5. **Treat `malloc_set_zone_name`, `malloc_default_zone`, `mi_heap_new`,
   `mi_heap_visit_blocks` and similar non-allocating system calls as
   *not* allocators.** They appear in the resource-family table as if
   they acquired memory.

## Release blockers

1. **The headline real-world claims are not reproducible from the
   shipping artifacts.** A user who clones the repo and follows the
   README cannot reproduce "command injection in bun_jsc" or
   "cross-language memory leak in bun_boringssl" — there is no IR, no
   writeup, no reproduction script. This is a credibility problem at
   minimum, a possible accuracy problem at worst.

2. **0% precision on the only real bun crate it was actually run
   against.** On bun_alloc, 19/19 reports are false positives. With
   `--boundary-only` the analyzer goes silent on a module that genuinely
   has Rust↔C FFI all over it.

3. **`ModuleIndex` single-language gate is too aggressive.** The
   message `ModuleIndex: single-language module detected (Rust) — FFI
   passes will be skipped` appeared on every file but `zig_main`.
   `llhttp.ll` (a C-only TU) skipping FFI is fine; `bun_alloc.ll`
   skipping FFI is wrong. There is no documented way to override this
   from CLI.

4. **`DoubleFree` rule produces a confirmed-severity report on
   essentially any module with two `free()` call sites.** This will
   generate noise on every binary in existence.

## Verdict for v0.2.0

**No-go on the current trajectory.**

The pipeline runs fast, never crashes, and the output formats look
clean — those are real wins. But the substantive question, "does it
correctly detect real bugs?", currently gets an unhappy answer:

- On the one real bun module it was tested against, every single
  finding was incorrect on inspection.
- The README's three concrete claims about real-world bun bugs cannot
  be reproduced from the materials shipped with the repo.
- A core gating decision (`ModuleIndex` single-language) silently
  disables the analyzer's main job on most useful inputs.

Recommended path to a defensible v0.2.0:

1. Fix the `ModuleIndex` gate so a Rust IR that declares C externs
   still gets FFI analysis.
2. Make leak detection pair allocators with deallocators of the same
   family that are present *in the same module*. Suppress definite
   leaks when the pairing exists.
3. Tighten `DoubleFree` to require an aliasing analysis, not just two
   syntactic occurrences of `free`.
4. Either reproduce the README's bun claims with a committed IR file
   + reproduction script, or remove them from the README. Replace with
   a smaller honest claim ("found 0 confirmed issues in bun_alloc;
   pipeline executes cleanly on llhttp.c") plus the wasmtime case if
   that one is real.
5. Re-run this validation. If the bun_alloc precision goes from 0/19
   to even 1/3 (say, after the noise fixes), v0.2.0 is defensible.

Until at least items 1–3 are addressed, the user's instinct ("我心里
还是没底") is correct — there is real work left before this is a
stable release.
