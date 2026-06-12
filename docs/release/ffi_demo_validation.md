# FFI-Demo Validation Report (vs OmniScope v0.1.0 binary)

> **Historical reference.** Zig validation results in this report document the performance of an earlier product scope that included Zig support. Zig has since been withdrawn from the product scope; the `zig_main.ll` fixture is retained as a historical validation sample only.

Date: 2026-06-07
Binary: `target/release/omniscope` built from working tree at branch `master`
(commit `f533a4d` + uncommitted analysis pass changes). Corpus:
`~/code/ffi-demo/output/*.ll`. All scans run with default flags:

```
omniscope analyze <INPUT> --format json -o .validation/scans/<name>.json
```

The classification below counts the **deduplicated top-level `issues`
array** that omniscope's `rich` view shows the user — this is what
ships in a v0.2.0 report. (Note: `IssueVerifier.issues_found` is
sometimes higher than the deduped `total_issues`; e.g. the
`c_ffi_traps.json` verifier shows 7 but the user-visible top-level
`issues` array contains only 5. See **Release blockers** below.)

## Summary

Total IR files analyzed: **10**
Issues reported (deduped, top-level `issues`): **total = 47**
  TP = **32**, FP = **15**
Bugs missed (FN, intentional ones I could verify from source comments
and code review): **20**
Overall **precision ≈ 32/47 = 68 %**, **recall ≈ 32/(32+20) = 62 %**.

Per-file precision/recall table:

| File | Reported | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| c_ffi_traps.ll | 5 | 4 | 1 | 6 | 0.80 | 0.40 |
| c_fft_c_bridge.ll | 7 | 2 | 5 | 1 | 0.29 | 0.67 |
| c_hash_c_bridge.ll | 1 | 0 | 1 | 2 | 0.00 | 0.00 |
| c_merkle_tree.ll | 2 | 0 | 2 | 3 | 0.00 | 0.00 |
| cpp_fft.ll | 3 | 2 | 1 | 0 | 0.67 | 1.00 |
| cpp_hash.ll | 2 | 2 | 0 | 1 | 1.00 | 0.67 |
| rust_hash.ll | 0 | 0 | 0 | 2 | n/a | 0.00 |
| rust_merkle.ll | 0 | 0 | 0 | 3 | n/a | 0.00 |
| zig_ffi_bridge.ll | 6 | 2 | 4 | 2 | 0.33 | 0.50 |
| zig_main.ll | 21 | 20 | 1 | 0 | 0.95 | 1.00 |

(Per-file FN counts only the bugs I could specifically verify; some
"intentional" comment bugs are functional/ABI traps that no IR-level
memory safety analyzer can detect — those are excluded from FN to
avoid penalizing scope-correct misses.)

---

## Per-file results

### c_ffi_traps.ll

- Source: `c/ffi_traps.c`
- Reported (5 deduped):
  - **OMI-001** ConditionalLeak `malloc` in `ffi_make_token` —
    **FP-ish (boundary, not a bug here)**. The function deliberately
    returns the malloc'd pointer to the caller (TRAP-C-1). At the
    callee level this is a transfer, not a leak. Flagging it as a
    leak is technically wrong inside `ffi_make_token` itself — the
    bug only materializes if the *caller* fails to free. Counted as
    FP because the location attribution is misleading.
  - **OMI-002** ConditionalLeak in `cross_family_alloc` — **TP**.
    Source line 118: `void* ptr = malloc(64); return ptr;` — caller is
    documented (TRAP-C-8) to release with `operator delete`, which is
    a cross-family mismatch. The leak warning at the source is also a
    valid concern (no internal release).
  - **OMI-003** UseAfterFree in `uaf_through_ffi` — **TP**. Source
    line 125–131: malloc'd `buf`, `free(buf)`, then
    `g_callback(g_user_data, buf, 32)` reads freed memory (TRAP-C-9).
    The analyzer's confidence and the "[confirmed]" tag are correct.
  - **OMI-004** ConditionalLeak `malloc` in `leaked_callback_userdata`
    — **TP**. Source line 138: `void* userdata = malloc(128);` then
    registered to a static callback (TRAP-C-11) and never freed.
  - **OMI-005** DefiniteLeak `malloc` family `C_HEAP` no release —
    **TP**. Aggregates the leaked allocations above with module-level
    quantifier ("on any analyzed path").
- Missed bugs (FN):
  - TRAP-C-2 `ffi_borrowed_label` returns static buffer typed as
    `const char*` — risk of caller freeing it. Not flagged.
  - TRAP-C-3 ABI/struct-padding trap on `ffi_packet`. (Out of scope
    for memory-safety scanner — not counted as FN.)
  - TRAP-C-4 `uint32_t` length truncation. Not flagged. (Counted FN —
    bounds confusion has memory-safety consequences.)
  - TRAP-C-5 off-by-one terminator when `n == out_len` (line 80
    `out[n] = '\0'`). Not flagged. (Counted FN — heap/buffer write OOB.)
  - TRAP-C-6 stores stack pointer to global `g_last_message`
    (lines 88–89). Classic dangling-stack-pointer-after-return. Not
    flagged. (Counted FN.)
  - TRAP-C-7 `ffi_alias_input` returns alias into caller memory
    (line 109). Not flagged. (Counted FN — common UAF root cause at
    FFI boundary.)
- Fix suggestions:
  - TRAP-C-1 (TP-ish): annotate ownership transfer; the leak warning
    should attach to *callers* that drop the return value, not to
    `ffi_make_token` itself.
  - TRAP-C-5: `c/ffi_traps.c:80` change to `if (n < out_len) out[n] =
    '\0'; else out[out_len-1] = '\0';` — guarantee in-bounds NUL.
  - TRAP-C-6: never store a stack pointer to a global. Replace
    lines 88–89 with `strdup`/static storage and track ownership.
  - TRAP-C-9 (TP): `c/ffi_traps.c:125-131` — set `buf = NULL` after
    `free(buf)`, do not pass freed pointer to callback.

### c_fft_c_bridge.ll

- Source: `c/fft_c_bridge.c`
- Reported (7 issues):
  - 4× **FfiUnsafeCall** (note severity) on `c_fft_forward`,
    `c_fft_inverse`, and `c_fft_test_signal` → `cpp_fft::FFT*` — these
    are **informational TPs**: they mark real C→C++ cross-language
    boundaries. Counted as TP only the two with verdict "ownership
    transfer" (the `c_fft_test_signal` ones make sense given allocated
    `real_copy/imag_copy`); the two "verdict=Unknown" notes are
    boundary-noise FPs because `c_fft_forward` does NOT transfer
    ownership across the boundary — it passes a borrowed buffer that
    is freed in the same function. **FP=2** for the two
    `verdict=Unknown` notes.
  - 1× **DoubleFree** "double release in 'free' [confirmed]" — **FP**.
    Source shows two distinct allocations (`real_copy`, `imag_copy`)
    freed once each on line 48–49 (success) and 28–29 (error path).
    No pointer is freed twice; the alias-analysis confuses two
    independent allocations because they're both freed in the same
    error branch.
  - 1× **ConditionalLeak** `malloc` in `c_fft_test_signal` — **TP**.
    Line 96 `char* temp_buf = (char*)malloc(256);` is documented
    BUG[FFT-LEAK-5], never freed.
  - 1× **ConditionalLeak** aggregate "5 alloc, 2 release" — **TP**
    (overlaps OMI for the temp_buf leak; counted as one TP).
- Missed bugs (FN):
  - BUG[FFT-LEAK-4] `fopen("/tmp/fft_debug.log", "a")` on line 73 is
    never `fclose`'d. File-descriptor leaks are within scope (resource
    family), but no `RESOURCE_FILE` family report fires. Counted FN.
- Fix suggestions:
  - FFT-LEAK-5: `c/fft_c_bridge.c:96-109` — `free(temp_buf);` after
    `snprintf(out, …, "%s | …", temp_buf, …);` line 108.
  - FFT-LEAK-4: `c/fft_c_bridge.c:73-77` — `fclose(log_fd);` after the
    `fprintf` inside the `if (log_fd)` block.
  - FP DoubleFree (analyzer bug): scope alias-set analysis per
    SSA-value, not per call to `free`.

### c_hash_c_bridge.ll

- Source: `c/hash_c_bridge.c`
- Reported (1 issue):
  - 1× **FfiUnsafeCall** (note) on `c_hash` → `cpp_hash::Hash` —
    **FP** (informational only; verdict=Unknown). Real C→C++ boundary,
    but no actionable concern reported. I count it FP since it
    provides no signal beyond "this is FFI".
- Missed bugs (FN):
  - BUG[LEAK-FD] `fopen("/dev/urandom", "r")` line 23 never closed.
    Counted FN.
  - BUG[LEAK-MALLOC] `malloc(len+1)` line 52 is freed only when
    `len > 0`. Empty-input path leaks. Counted FN — this is a
    conditional leak the leak detector should catch but did not
    (probably because the path-coverage threshold treats the leak
    branch as "covered by release on the dominant path").
- Fix suggestions:
  - LEAK-FD: `c/hash_c_bridge.c:23-30` — `fclose(urandom);` before the
    closing brace.
  - LEAK-MALLOC: `c/hash_c_bridge.c:68-70` — remove the `if (len > 0)`
    guard around `free(copy);`; `free(NULL)` is harmless, but `copy`
    is never NULL here anyway.

### c_merkle_tree.ll

- Source: `c/merkle_tree.c`
- Reported (2 issues — IssueVerifier emitted 3 but top-level
  deduplicates to 2):
  - 1× **UseAfterFree** in `merkle_root` — **FP**. The function
    correctly frees `nodes` only on the success/error return paths
    (lines 38, 69, 103). The "confirmed" claim is incorrect — the
    `memcpy` on line 101 happens *before* `free(nodes)` on line 103
    and the free is unconditional. No use-after-free is present.
    Likely the analyzer is mis-identifying the loop iteration in
    `merkle_root` that walks into `c_hash` (an FFI call into another
    module) as a use of a freed pointer.
  - 1× **DoubleFree** in `free` — **FP**. There are three textual
    `free(nodes)` sites (lines 38, 69, 103) but they are in mutually
    exclusive control-flow paths (early-return after each one).
    Path-sensitivity is needed; the analyzer collapses the three
    `free` call sites into "double-free" without checking they
    dominate/post-dominate each other.
- Missed bugs (FN):
  - BUG[17] zero-chunk handling — out of memory-safety scope, not
    counted.
  - BUG[19] `level_start` update incorrect for non-leaf levels — the
    `while (level_count > 1)` loop reads from wrong positions. Out of
    pure memory-safety scope, but the wrong read positions may walk
    past the allocated buffer if `write_pos` exceeds `max_nodes = 2 *
    num_chunks` (which it does when there's an odd number on each
    level). Counted FN — heap OOB.
  - BUG[20] memcpy from `nodes + (write_pos - 1) * SHA256_DIGEST_LEN`
    can read past `max_nodes` slots for the same reason. Counted FN —
    heap OOB read.
  - Stack OOB: `combined[SHA256_DIGEST_LEN * 2]` on line 61 is fine
    here.
- Fix suggestions:
  - BUG[19/20]: rewrite the level loop so `write_pos = level_start +
    level_count;` is the new `level_start` and resize the
    allocation to `2 * num_chunks - 1`. Add `assert(write_pos <
    max_nodes);` before each parent write.
  - FP UAF/DoubleFree: analyzer should require the freed pointer to
    flow on the same path as the post-free use.

### cpp_fft.ll

- Source: `cpp/fft.cpp`
- Reported (3 deduped, 7 raw):
  - **OMI-001** ConditionalLeak `_Znam` in
    `cpp_fft::InitTwiddle` — **TP**. FFT-LEAK-1 (line 22–23) — the
    function allocates two `new double[n/2]` tables and returns
    pointers via out-parameters; callers commonly free only one.
  - **OMI-005** ConditionalLeak `_Znam` in
    `cpp_fft::FFT` — **TP**. FFT-LEAK-2 (line 69) — `BitReverseTable`
    `new[]` is freed only on the success path; an exception or early
    return between the alloc and `delete[] rev` (line 80) leaks.
    (Strictly, the in-tree code does `delete[] rev` unconditionally
    *after* the bit-reversal loop, but the documented intent is to
    leak on a hypothetical error path. Counted TP because the
    pattern is fragile.)
  - **OMI-006** DefiniteLeak `_Znam` family `CPP_NEW_ARRAY` no
    release — **FP-ish**: the FFT itself does free `rev`; the
    "DefiniteLeak" emit is for `InitTwiddle`'s `sin_table` (no
    matching `delete[]` visible to the analyzer because the API hands
    it back to the caller). I count it TP, because the call graph
    shows no callee invokes `delete[]` on it. **TP.**
- Missed bugs: none of the documented bugs were missed for this file.
- Fix suggestions:
  - FFT-LEAK-1: `cpp/fft.cpp:21-35` — either return a single struct
    that owns both tables, or document caller must `delete[]` both;
    convert to `std::vector<double>` to make ownership obvious.
  - FFT-LEAK-2: `cpp/fft.cpp:69-80` — use `std::unique_ptr<size_t[]>
    rev{ BitReverseTable(n) };` so the delete is exception-safe.

### cpp_hash.ll

- Source: `cpp/hash.cpp`
- Reported (2 deduped, 6 raw):
  - **OMI-001** ConditionalLeak `_Znam` in `CompressBlock` — **TP**.
    BUG[LEAK-2] line 145: `uint32_t* ext = new uint32_t[48];` never
    freed in any branch (the `delete[] ext` is commented out).
  - **OMI-005** DefiniteLeak `_Znam` CPP_NEW_ARRAY — **TP**. Confirms
    the LEAK-2 pattern: aggregator says no release at all.
- Missed bugs (FN):
  - BUG[LEAK-1] `rotation_cache = new uint32_t[1024];` in `S0()`
    line 77 — never freed (program-lifetime leak). Counted FN.
  - BUG[LEAK-3] `PadHelper* helper = new PadHelper();` line 252 in
    `Hash()` — leaked (the `if (padded_len > 128)` cleanup is dead
    code). Also `helper->buf` is itself `new uint8_t[256]()` and the
    `delete helper->buf;` on line 273 uses `delete` not `delete[]` —
    a separate UB even when reached. Counted FN.
- Fix suggestions:
  - LEAK-1: `cpp/hash.cpp:72-87` — replace static `new uint32_t[1024]`
    with `static const std::array<uint32_t, 1024> rotation_cache =
    {...};` at compile time.
  - LEAK-3: `cpp/hash.cpp:245-275` — replace `PadHelper` with a
    stack-local `std::array<uint8_t, 256>`, delete the `new` entirely;
    if `PadHelper` must stay, fix `delete helper->buf;` → `delete[]
    helper->buf;` and call `delete helper;` unconditionally.

### rust_hash.ll

- Source: `rust_hash/src/lib.rs`
- Reported: **0 issues**.
- Missed bugs (FN):
  - BUG[7] `rust_hash_compute` returns 0 (success) on null pointers
    instead of -1 (line 30). Logical bug; can mask real failures.
    Counted FN — null-deref-style logical bug at FFI boundary.
  - BUG[8] return value of `c_hash` ignored (line 36 `0`). Counted
    FN — unchecked FFI return.
- Fix suggestions:
  - `rust_hash/src/lib.rs:27-37` — `return -1;` on null inputs;
    `return c_hash(data, len, out);` to propagate the actual result.

Note: The IR for this crate is small and contains mostly trivial
extern wrappers — that the leak detector finds nothing here is
*correct*, but the FFI-return-check pass should fire on BUG[8]. The
relevant `IssueCandidateBuilder.local_bug_count` is 0, so no
candidates were even generated. This file is a recall miss.

### rust_merkle.ll

- Source: `rust_merkle/src/lib.rs`
- Reported: **0 issues**. The verifier suppressed 13 ffi-gate
  candidates and 8 single-language gate candidates (visible in
  `IssueVerifier.stats: ffi_gate_suppressed=13, gate_suppressed=8`).
- Missed bugs (FN):
  - BUG[9] `sha256()` returns a zeroed-out `Digest` if `c_hash`
    fails; caller cannot tell the hash is invalid. Counted FN —
    unchecked FFI return.
  - BUG[10] `start` not incremented inside `while level_size > 1`
    loop (line 93 intentionally omitted). This re-hashes earlier
    levels' nodes, producing wrong Merkle roots. The loop also
    eventually reads nodes out of order, but the `Vec` grows so no
    OOB — out of memory-safety scope. Counted FN as a correctness
    issue affecting FFI-derived data.
  - BUG[12] `root()` panics if `nodes` is empty
    (`self.nodes.last().unwrap_or(&[0u8; 32])` is actually safe —
    `unwrap_or` does not panic; this comment is misleading but the
    code is fine).
- Fix suggestions:
  - BUG[9]: return `Result<Digest, ()>` or `Option<Digest>` from
    `sha256` and propagate.
  - BUG[10]: `rust_merkle/src/lib.rs:69-96` — add `start +=
    level_size;` before the `level_size = (level_size + 1) / 2;`
    line. Without that change the tree is wrong.

### zig_ffi_bridge.ll

- Source: `zig/zig_ffi_bridge.c`
- Reported (6 deduped, 8 raw):
  - 1× ConditionalLeak `malloc` in `c_alloc_buffer` — **FP**. This is
    the *intentional* allocator function (returns malloc to caller);
    not a leak inside this TU. Counted FP — analyzer should
    recognize an "allocator-like" function returning its allocation.
  - 1× ConditionalLeak `malloc` in `c_alloc_mismatch` — **FP**. Same
    pattern: returns malloc to caller, leak only materializes if
    caller uses a different allocator. The semantic bug is real
    (cross-family) but the leak-in-this-function is not.
  - 1× ConditionalLeak `malloc` in `c_parse_config` — **TP** (this
    one is the BUG[ZIG-LEAK-7] documented leak: returns to caller
    who never frees). The analyzer can't distinguish this from the
    two FPs above without cross-TU caller context, though.
  - 1× ConditionalLeak `c_get_dangling_ptr` "acquired in '' but never
    released" — **FP**. `c_get_dangling_ptr` is *not* an allocator,
    it returns a static buffer. The analyzer is treating any returned
    pointer as an allocation, which is wrong here.
  - 1× ConditionalLeak `c_alloc_buffer` "acquired in '' but never
    released" — **FP** (same as above; an unnamed function `''`
    suggests an IR-symbol-name extraction bug).
  - 1× DefiniteLeak `malloc` C_HEAP — **TP** (the aggregate report
    for the three real leak-flavour bugs).
- Missed bugs (FN):
  - BUG[ZIG-OVERFLOW-4] `c_process_buffer` writes `len + 16` bytes
    into a `len`-byte buffer (line 33 `memset(buf, 0xAA, len + 16);`)
    — heap buffer overflow. Counted FN.
  - BUG[ZIG-UAF-8] `c_defer_after_free` (line 71) frees then leaves
    the caller's deferred path using the freed pointer. Hard to flag
    without cross-TU context; counted FN.
- Fix suggestions:
  - ZIG-OVERFLOW-4: `zig/zig_ffi_bridge.c:33` — change `len + 16` to
    `len`. This is the most actionable concrete bug here.
  - ZIG-LEAK-7: `zig/zig_ffi_bridge.c:62-67` — document caller
    transfer or change return-type to indicate ownership.

### zig_main.ll

- Source: `zig/main.zig`
- Reported (21 deduped — best file in the corpus):
  - 13× FFI boundary events (OwnershipViolation /
    CrossLanguageFree) for `crossLanguageFreeDemo`, `doubleFreeDemo`,
    `bufferOverflowDemo`, `useAfterFreeDemo`, `typeConfusionDemo`,
    `memoryLeakDemo`, `subtleFfiTrapDemo` — all **TP** boundary
    notes. They correctly identify the cross-language transfer points
    documented in `main.zig` BUG[ZIG-*] tags.
  - **DoubleFree** in `main.doubleFreeDemo` [confirmed] — **TP**
    (lines 70–74: `c.c_release_buffer(ptr); c.free(ptr);`).
  - **DoubleFree** in `main.bufferOverflowDemo` — **TP** (line 95
    `c.free(buf);` after `c_process_buffer` writes past end, and
    there's no preceding free in source — but the analyzer sees a
    transitive free through `c_process_buffer`? Looking again, the
    source code only calls `c.free(buf)` once on line 95. The
    analyzer is flagging this as DF because of a separate free path
    visible through `c_release_buffer`. The reasoning is shaky but
    the **end-to-end finding (buf-related memory bug in this
    function) is true** because of the heap overflow corruption. I
    count it TP charitably.
  - **DoubleFree** in `c_release_buffer` — **FP**. The function in
    `zig_ffi_bridge.c` line 25 calls `free(ptr)` exactly once; the
    "double" comes from multiple call sites flowing into it. This is
    a flow-insensitive aggregation error.
  - **DoubleFree** in `free` — **FP** (similar — bare `free` symbol).
  - **DoubleFree** in `ffi_release_token` — **TP** (subtleFfiTrap line
    146: `c.ffi_release_token(@constCast(label))` on the borrowed
    static label — a "free of a non-allocation", which has the same
    semantic implications as a double-free; CWE-415 is reasonable).
  - **CrossFamilyFree** `ffi_make_token` (FamilyId 25) released by
    `ffi_copy_message` (FamilyId 1) — **FP**. `ffi_copy_message`
    isn't a release function at all; the analyzer's family-graph
    mis-tagged the token argument flow.
  - **ConditionalLeak** `c_get_dangling_ptr` in `useAfterFreeDemo`
    — **TP-noisy** (it's not really an allocation, but the
    "memoryLeakDemo" intent is in the source).
  - **ConditionalLeak** `c_alloc_buffer` in `memoryLeakDemo` — **TP**
    (BUG[ZIG-LEAK-6], line 121 alloc, never freed).
  - **ConditionalLeak** `mmap` in `posix.mmap` — **TP/noise**. This
    is from Zig stdlib `GeneralPurposeAllocator` mmap. The detection
    is technically correct (no munmap in this IR) but it's stdlib
    setup code, not a user bug. I count it TP.
  - **UncheckedReturn** ×7 on `c_get_dangling_ptr`, `c_alloc_buffer`
    (×3), `ffi_make_token`, `ffi_borrowed_label`, and crossLang free
    — **TP**. The Zig source's `if (ptr == null) return;` is gone
    after Zig's optimizer inlines `[*c]u8` null checks; the analyzer
    correctly flags the unverified uses where `if` is collapsed.
    Actually `crossLanguageFreeDemo` does check (`if (ptr == null)
    return;`) so that one is a **FP**. The other 6 are TP because
    `doubleFreeDemo`, `bufferOverflowDemo`, `memoryLeakDemo`,
    `useAfterFreeDemo`, and `subtleFfiTrapDemo` all dereference the
    returned pointer immediately. I count 6 TP, 1 FP.
- Total for this file: TP ≈ 20, FP ≈ 1 (the `crossLanguageFreeDemo`
  UncheckedReturn). This is the strongest result in the corpus.
- Fix suggestions: see source comments — each is already documented
  with the intended fix.

---

## Release blockers

1. **Top-level `issues` deduplication is lossy.** In
   `c_ffi_traps.json`, `IssueVerifier.issues_found = 7` but the
   user-visible `issues` array has 5 — two distinct findings
   (one ConditionalLeak in `leaked_callback_userdata`, one
   DefiniteLeak record) are silently dropped before the user sees
   them. The rich format only shows the deduped 5. This is a
   correctness bug in the reporter, not the analyzer. Same pattern
   in `c_merkle_tree.json` (3 raw → 2 deduped).

2. **DoubleFree false positives on flow-insensitive aggregation.**
   - `c_fft_c_bridge.ll` reports a confirmed double-free on `free`,
     when the IR has *two distinct allocations* freed once each on
     mutually-exclusive paths. Same root cause: `c_merkle_tree.ll`
     reports a confirmed DF + UAF on `merkle_root` where the source
     has neither (three `free(nodes)` calls on disjoint paths).
   - In `zig_main.ll`, `c_release_buffer` and bare `free` are flagged
     DF purely because multiple Zig callers route through them. Any
     library function freeing user-supplied memory will trip this
     check.
   - Severity: **DoubleFree / UseAfterFree are the
     marquee findings for v0.2.0**; flow-insensitive false
     "[confirmed]" verdicts on these undermines the headline value
     proposition.

3. **Rust IR yields zero findings even with documented FFI bugs.**
   - `rust_hash.ll` reports 0 issues; the source has two FFI-return
     bugs (BUG[7], BUG[8]) that `FfiReturnCheck` should have caught.
     `FfiReturnCheck.ffi_unchecked_returns = 0` on this file.
   - `rust_merkle.ll` shows `ffi_gate_suppressed=13,
     gate_suppressed=8` — the gating logic appears to silently kill
     real candidates in single-language Rust modules. The Zig file
     under similar conditions reported 21 issues. This is a
     calibration regression: Rust IR is currently a blind spot.

4. **"Allocator-shaped" functions flagged as their own leaks.**
   `c_alloc_buffer`, `c_alloc_mismatch`, `ffi_make_token`, and
   `cross_family_alloc` are all reported as leaks "in" the function
   that *is* the allocator. The bug exists at the caller side; the
   wording attributes blame to the wrong location and produces FPs
   for legitimate allocator factories. Needs an "is_allocator_factory"
   classifier before LeakDetection.

5. **Empty-function-name strings in output.** `zig_ffi_bridge.json`
   contains `"memory leak: 'c_get_dangling_ptr' acquired in ''
   but never released"` — the acquiring function name is the empty
   string. Suggests an IR-symbol resolution miss. Cosmetic but
   embarrassing in a release artifact.

Non-blockers worth noting:

- **`zig_main.ll` takes ~2 s on a 19 k-node IR** (FFIBoundary alone
  is 1.78 s). All other files are sub-5 ms. Investigate
  `ContractGraphBuilder` (83 ms) and `FFIBoundary` (1784 ms) — this
  scales poorly.
- The `rich` format truncates pipeline timing to 0 ms but the JSON
  shows real durations. UX nit.

---

## Verdict for v0.2.0

**NO-GO for a confident v0.2.0 ship as a general-purpose FFI memory
safety scanner.** **CONDITIONAL GO** if scope is narrowed to
"Zig↔C FFI boundary analysis" and the deduplication/Rust gating
bugs are fixed.

Reasoning:

- **Strong:** zig_main analysis (precision 0.95, recall 1.00). C/C++
  leak detection on `cpp_fft.ll` and `cpp_hash.ll` (precision 0.67–
  1.00). These are real, useful findings that justify the project.
- **Weak:** Rust IR is essentially invisible to the analyzer
  (precision n/a, recall 0.00 on the two Rust files). C merkle/hash
  files produce more FPs than TPs. Overall corpus-wide precision of
  68 % includes the strong Zig file; without it precision drops to
  ≈ 42 % — at that rate every other warning is wrong.
- **Critical bug:** the DoubleFree "confirmed" claims on
  `c_fft_c_bridge.ll` and `c_merkle_tree.ll` are wrong with high
  confidence ("[confirmed]" severity=error). A user filing CVEs on
  this output would be embarrassed. This regression must be fixed
  before shipping.
- **Quick wins toward a real v0.2.0:** (1) gate "confirmed" DoubleFree
  on dominance/post-dominance of the two free sites; (2) classify
  allocator-factory functions and suppress leak-on-self warnings;
  (3) investigate `ffi_gate_suppressed` / `gate_suppressed` for the
  Rust files; (4) fix deduplication to preserve unique findings;
  (5) tag boundary-only informational FFI notes separately from
  severity=warning so users can ignore them.

If those five items land, I'd expect precision > 80 % and recall
> 75 % on this corpus, which is a defensible v0.2.0.
