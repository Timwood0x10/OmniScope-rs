# Audit: PLATFORM_SUPPORT.md vs current code

- Date: 2026-06-07
- Working tree commit: `17bea02` (with uncommitted `.github/workflows/release.yml` edit removing sccache; matrix unchanged)
- Doc audited: `PLATFORM_SUPPORT.md` (141 lines)
- Companion files audited: `platform_filters.toml`, `BUILD_ENV.md`
- Summary: The doc is **substantially aspirational**. It describes a "platform-aware FFI filter" subsystem (per-platform safe API lists, a platform-detection flow, platform-keyed false-positive metrics, a verbose CLI output, and `platform_filters.toml` configuration). **None of those features exist in code.** The actual platform-awareness in the codebase is two things: (a) the LLVM-IR parser captures `target triple` as an `Option<String>` field, and (b) the resource-family registry hard-codes Win32/Zig/POSIX-flavored allocator names. Doc-claimed `POSIX` and `Apple/macOS` resource families do not exist as `FamilyId` constants. The release pipeline does not produce a Windows binary despite Windows being listed first-class in the doc.

---

## 1. Supported OS / arch matrix (claim vs reality)

| OS      | Arch     | Doc claim (`PLATFORM_SUPPORT.md`)       | CI test (`ci.yml`)                                  | Release binary (`release.yml`)                       | Reality           |
|---------|----------|------------------------------------------|------------------------------------------------------|-------------------------------------------------------|-------------------|
| macOS   | x86_64   | Listed L13–14 (`x86_64-apple-darwin`)    | ci.yml:73 `macos-latest` is arm64 → x86_64 NOT exercised | release.yml:54-56 `macos-13` builds `x86_64-apple-darwin` | build-only (no native CI test) |
| macOS   | aarch64  | Listed L15 (`aarch64-apple-darwin`, `arm64-apple-macosx*`) | ci.yml:73 `macos-latest` (arm64 since 2024)         | release.yml:57-59 `macos-14`                          | fully             |
| Linux   | x86_64   | Listed L27 (`x86_64-unknown-linux-gnu`)  | ci.yml:73 `ubuntu-latest` w/ `--all-features` (stable+beta) | release.yml:47-49                                   | fully             |
| Linux   | x86_64-musl | Listed L28 (`x86_64-unknown-linux-musl`) | not tested                                           | not built                                              | aspirational      |
| Linux   | aarch64  | Listed L29 (`aarch64-unknown-linux-gnu`) | not tested                                           | release.yml:50-53 cross-compiled (gcc-aarch64-linux-gnu) | build-only (cross, never run) |
| Windows | x86_64-msvc | Listed L40 (`x86_64-pc-windows-msvc`)  | ci.yml:73 `windows-latest`, **default features only** (ci.yml:109-111, no `--all-features`, no LLVM 22 dev libs — comment ci.yml:104) | NOT built                                              | partial: tests run on a feature-stripped build; no release artifact |
| Windows | x86_64-gnu  | Listed L41 (`x86_64-w64-windows-gnu`)   | not tested                                           | not built                                              | aspirational      |
| Windows | i686-msvc   | Listed L42 (`i686-pc-windows-msvc`)     | not tested                                           | not built                                              | aspirational      |

Cross-checks:

- `rust-toolchain.toml:4` declares `targets = ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-apple-darwin"]` — does not pre-install any aarch64-linux or Windows target. (release.yml works around this with `dtolnay/rust-toolchain@stable` `targets:` input.)
- CI matrix `windows-latest` is configured `ci.yml:73-80`, but uses a Windows runner without LLVM 22 (`ci.yml:104` comment: "Windows has no easy llvm-22-dev; build/test without llvm-backend feature"). So the Windows test never exercises the actual IR-loading path that requires LLVM. It mostly verifies that the workspace still type-checks on a Windows host with default features.

## 2. Resource family matrix (claim vs reality)

The doc structures itself by "Safe APIs" per platform (macOS / Linux / Windows zone allocators, TLS, exception handling, dynamic linking). It does NOT use the word "resource family" — but the user's audit question maps the macOS/POSIX/Win32 buckets onto the codebase's `FamilyId` constants in `crates/omniscope-types/src/resource_family.rs`.

| Doc bucket / family             | Doc lines  | Code (`crates/omniscope-types/src/resource_family.rs`)                 | Status                |
|---------------------------------|-----------|-------------------------------------------------------------------------|------------------------|
| Win32 heap (`HeapAlloc`/`HeapFree`/`HeapReAlloc`) | L45         | `FamilyId::WIN32_HEAP` (L91), `FAMILY_WIN32_HEAP` (L478–484)            | implemented            |
| Win32 virtual memory (`VirtualAlloc`/`VirtualFree`) | L45 (implied; doc says only Heap/Local/Global) | `FamilyId::WIN32_VIRTUAL` (L96), `FAMILY_WIN32_VIRTUAL` (L490–496) | implemented (code goes further than doc) |
| Win32 local/global (`LocalAlloc`, `GlobalAlloc`)   | L45         | No dedicated family; folded into the "system allocator" name list in `omniscope-semantics/src/resource/allocator_shim.rs:1017` | partial: name recognition only, not a separate family |
| Win32 TLS (`TlsAlloc`/`TlsGetValue`/`TlsSetValue`) | L46         | No `WIN32_TLS` family; no name list; no test                            | **not implemented** (claim has no backing code) |
| Win32 exception handling (`__CxxThrowException`, `_except_handler3`) | L47 | No code reference (grep returns 0 hits)                                 | **not implemented**     |
| Win32 dynamic loading (`LoadLibrary`/`GetProcAddress`) | L48     | No code reference (grep returns 0 hits)                                 | **not implemented**     |
| Win32 DLL ops (`dllimport`/`dllexport`/`__imp_`)  | L49         | No code reference                                                       | **not implemented**     |
| **POSIX family**                | implied by §"Linux" L31–35 | No `POSIX` `FamilyId` (search of `resource_family.rs` for `POSIX` returns 0). `FAMILY_FILE_DESCRIPTOR` (L454-460) covers fd-based syscalls generically; not POSIX-keyed. | **not implemented as a family** |
| POSIX glibc allocators (`__libc_malloc`, `__libc_free`, `mallopt`) | L32 | No code reference (grep 0 hits)                                         | **not implemented**     |
| POSIX TLS (`__tls_get_addr`, `__cxa_thread_atexit`) | L33      | No code reference                                                       | **not implemented**     |
| POSIX dynamic linker (`dlopen`, `dlsym`, `dlclose`) | L35      | No code reference inside analysis                                       | **not implemented**     |
| POSIX unwind (`_Unwind_RaiseException`, `_Unwind_Resume`) | L34   | No code reference                                                       | **not implemented**     |
| **Apple / macOS family**        | implied by §"macOS" L18–22 | No `APPLE` / `MACH` / `CFRunLoop` `FamilyId`. One whitelist hit at `omniscope-semantics/src/resource/family_registry.rs:264` for `malloc_set_zone_name` only. | **not implemented as a family** |
| Apple zone allocators (`malloc_zone_malloc`, `malloc_zone_free`) | L19 | No name list, no family                                                | **not implemented**     |
| Apple TLS (`_tlv_atexit`, `_tlv_bootstrap`)      | L20         | No code reference                                                       | **not implemented**     |
| Apple dyld (`dyld_*`, `_dyld_*`)                 | L22         | No code reference                                                       | **not implemented**     |
| Cross-platform: LLVM intrinsics (`llvm.memcpy`, `llvm.lifetime.*`) | L55 | Recognized by IR parser generally; not modeled as a "safe API" list    | partially implemented (intrinsics flow through general parser) |
| Cross-platform: `_chk` suffix    | L56         | No code reference                                                       | **not implemented**     |
| Cross-platform: C++ ABI `__cxa_*`, `_Zn*` | L57    | C++ adapter recognizes `_Zn*` mangling but not the "_chk-like" safety rule the doc implies | partial (mangling parser, not a safety filter) |
| Cross-platform: stack-protect (`__stack_chk_fail`, `__fortify_fail`) | L58 | No code reference                                                       | **not implemented**     |

Built-in `FamilyId` count: 24 (matches `BUILTIN_FAMILIES.len()` test at `resource_family.rs:577-582`). Names: C_HEAP, CPP_NEW_SCALAR, CPP_NEW_ARRAY, RUST_GLOBAL, PYTHON_OBJECT, PYTHON_MEM, PYTHON_MEM_RAW, JAVA_LOCAL_REF, JAVA_GLOBAL_REF, CSHARP_HGLOBAL, CSHARP_COTASK, GO_GC, ZIG_ALLOCATOR, ZLIB_STREAM, OPENSSL_RESOURCE, SQLITE_RESOURCE, GO_CGO, MIMALLOC, CSHARP_COM, RUST_RAW_OWNERSHIP, FILE_DESCRIPTOR, UNKNOWN, WIN32_HEAP, WIN32_VIRTUAL.

Of those, only `WIN32_HEAP` and `WIN32_VIRTUAL` are platform-keyed in the way the doc implies. There is no `POSIX_*`, no `APPLE_*`, no `MACH`, no `CFRunLoop`, no Win32 TLS / exception / dynlib family. The user-supplied claim about `f533a4d` adding "Win32/Zig resource families" is correct: those two Win32 families + ZIG_ALLOCATOR are present in `BUILTIN_FAMILIES` at `resource_family.rs:540-569`.

## 3. Platform filter logic (claim vs reality)

Doc claims (PLATFORM_SUPPORT.md L102-109):
1. Parse `target triple` from IR metadata.
2. Extract platform from triple string.
3. Load platform-specific safe API list.
4. Apply filtering during FFI analysis.

Reality:
- (1) **Implemented**: `crates/omniscope-ir/src/parser.rs:768` `extract_target_triple()`; `llvm_sys_adapter.rs:184-193` extracts it via LLVM-sys.
- (2) **Not implemented**: no code maps the triple string to a `Platform` enum. Search for `detect_platform`, `Platform::Macos`, `Platform::Linux`, `Platform::Windows` all return 0 hits in `crates/`.
- (3) **Not implemented**: there is no "platform-specific safe API list" in code. There is no `safe_apis: HashSet<&str>` keyed by platform. The closest thing is `omniscope-semantics/src/resource/rust_stdlib_whitelist/` (Rust stdlib whitelist) and `family_registry.rs` (allocator name registration), neither of which is platform-keyed.
- (4) **Not implemented**: no filtering pass consumes a platform value.

The companion file `platform_filters.toml` (40 lines) declares `[platforms.macos]`, `[platforms.linux]`, `[platforms.windows]`, `[common]`, `[custom]` sections — but the file is unused. Grep for `platform_filters` across `crates/` and the whole repo returns **0 hits** outside `PLATFORM_SUPPORT.md` itself, which (line 138) lists "Configuration file support (platform_filters.toml)" under "Future Enhancements". So the doc admits this in its TODO section while simultaneously describing the feature elsewhere as if it works.

There IS a configuration file in code: `omniscope.toml` (loaded by `omniscope-types/src/config.rs:446`, CLI default `crates/omniscope-cli/src/main.rs:201,221`). That is a separate file from `platform_filters.toml` and does not contain any platform-keyed safe-API lists.

## 4. Calling-convention support (claim vs reality)

Doc L113-117 claims 11 calling conventions recognized: `fastcc`, `coldcc`, `webkit_jscc`, `anyregcc`, `preserve_mostcc`, `preserve_allcc`, `swiftcc`, `aarch64_sve_vector_pcs`, `aarch64_vector_pcs`, `amdgpu_kernel`, `spir_kernel`.

Reality:
- The text parser at `crates/omniscope-ir/src/parser.rs:811-821` lists exactly those 11 names. **Accurate.**
- The LLVM-sys adapter at `crates/omniscope-ir/src/llvm_sys_adapter.rs:732-738` only maps IDs 8–16 (fastcc through swiftcc) — the aarch64/amdgpu/spir conventions are not handled via LLVM-sys. Partial.
- `crates/omniscope-pass/src/resource/ffi_return_check.rs:362-368` recognizes only 7 of them as skip-tokens.

## 5. CLI example output (claim vs reality)

Doc L74-84 shows:
```
Parsing LLVM IR...
✓ 1582 functions, 110 declarations, 13248 calls
Target triple: arm64-apple-macosx15.0.0
Pointer size: 32 bits
Endianness: Little
Analyzing FFI boundaries...
✓ Target platform: macOS
✓ 4230 FFI boundaries detected
```

Reality: grep for the literal strings `"Target platform"`, `"FFI boundaries detected"` returns 0 hits in `crates/`. The only hit is `"FFI boundaries:"` at `omniscope-cli/src/main.rs:897`. The example output in the doc is **fabricated** — it does not match what the binary prints with or without `--verbose`. The "Pointer size: 32 bits" line in the doc is also nonsensical for an arm64 triple (would be 64).

The "False Positive Reduction" table at L96-100 (macOS 462 → 0; Linux/Windows "Unknown" → "< 0.1%") has no backing measurement in the repo (no benchmark output, no validation report references this table). Validation docs that DO exist (`docs/release/bun_validation.md`, `ffi_demo_validation.md`) measure different things.

## 6. Build-instruction accuracy (`BUILD_ENV.md`)

| Section | Claim | Reality |
|---|---|---|
| BUILD_ENV.md L13 | `brew install zstd llvm@12` | **Wrong LLVM version.** ci.yml:96 installs `llvm@22`, env `LLVM_SYS_221_PREFIX` (ci.yml:24) confirms llvm-sys 22.1. README and code expect LLVM 22, not 12. |
| BUILD_ENV.md L23 | `sudo apt-get install -y libzstd-dev llvm-12-dev` | Wrong: ci.yml:90-91 installs `llvm-22-dev` via apt.llvm.org bootstrap. |
| BUILD_ENV.md L33 | `sudo dnf install -y zstd-devel llvm-devel` | Untested; unlikely to pull LLVM 22 by default on RHEL repos. |
| BUILD_ENV.md L60-62 | "CI: Linux: llvm-12-dev, macOS: llvm@12 via Homebrew" | Stale: CI now uses LLVM 22 (ci.yml:55-56, 96-97). |
| BUILD_ENV.md L80 | "Install LLVM: `brew install llvm@12`" | Wrong version. |
| BUILD_ENV.md L101-103 | `llvm-config --version  # Should output: 12.x.x` | Wrong version. |
| BUILD_ENV.md (Windows) | Not mentioned at all. | Yet PLATFORM_SUPPORT.md treats Windows as first-class. **Major gap.** |

## 7. Highest-priority drifts

1. **`platform_filters.toml` has no parser.** The file ships at repo root and the doc describes a platform-filter pipeline that consumes it. There is zero code that loads it. The doc itself contradicts this in its own "Future Enhancements" (L138).
2. **POSIX and Apple/macOS resource families don't exist as code constants.** Only `WIN32_HEAP` and `WIN32_VIRTUAL` are platform-keyed families. The doc's per-platform "Safe APIs" lists (zone allocators, dyld, glibc internals, dlopen, TLS, Unwind) appear nowhere in `family_registry.rs`, `allocator_shim.rs`, or `family_inference.rs`.
3. **Windows is over-promised.** Doc lists 3 Windows triples and 6 Windows API families. Reality: CI runs on `windows-latest` but with default features only (no LLVM backend, no `--all-features`); release pipeline does not produce a Windows binary at all (release.yml:46-59 only 4 targets, all *nix). BUILD_ENV.md has no Windows section.
4. **The "Example Output" in the doc is fabricated.** The strings "Target platform: macOS" and "✓ N FFI boundaries detected" are not present anywhere in the codebase, so the doc shows output the binary cannot produce.
5. **BUILD_ENV.md is stale by ~10 major LLVM versions.** It still says LLVM 12 throughout; CI and Cargo features have moved to LLVM 22 (llvm-sys 221).
6. **The False-Positive Reduction table (L96-100) has no measurement source.** The numbers (macOS 462→0, Linux/Windows "<0.1%") are not produced by any benchmark or validation script in `benches/` or `tests/`.

## 8. Recommended next actions

Doc edits (`PLATFORM_SUPPORT.md`):
- Move §"Supported Platforms" Windows-only API claims (TLS, exception handling, dynamic loading, DLL ops) into a "Roadmap" or "Aspirational" section, OR add the corresponding `FamilyId`s and registrations.
- Replace the §"Example Output" block with real `omniscope analyze --verbose` output captured from the current binary.
- Drop or rewrite §"False Positive Reduction" — back it with a script under `tests/` or `benches/`, or delete the table.
- Reconcile §"Implementation Details / Platform Detection Flow" with the absence of a platform detector: either describe the actual flow (capture-only triple, no filtering) or implement the four steps and re-state the doc.
- Add a Windows section to §"Supported Platforms" that calls out: CI is feature-stripped, no release binary, no `BUILD_ENV.md` instructions yet.

Doc edits (`BUILD_ENV.md`):
- Replace every `llvm@12` / `llvm-12-dev` / `12.x.x` with the LLVM 22 strings actually used in CI (`llvm-22-dev` via apt.llvm.org bootstrap, `llvm@22` via brew, `LLVM_SYS_221_PREFIX=…`).
- Add a Windows section, or explicitly document that Windows is build-only without the LLVM backend feature.

Code work (only if the doc claims should stand):
- Implement `platform_filters.toml` loading in `omniscope-types/src/config.rs`, keyed by platform with a HashSet of safe-API names per platform.
- Add `POSIX_LIBC`, `POSIX_DYNLINK`, `POSIX_UNWIND`, `POSIX_TLS`, `APPLE_ZONE`, `APPLE_TLS`, `APPLE_DYLD`, `WIN32_TLS`, `WIN32_DYNLINK`, `WIN32_EXCEPTION` families (or use a non-family "safe API filter" subsystem) and a `detect_platform_from_triple()` helper.
- Add a Windows job to `release.yml` (or document the deliberate omission).
- If `f533a4d` was meant to be the "platform support GA" commit, add at least the macOS zone-allocator name list to `family_registry.rs` so the macOS column of the matrix is not empty.
