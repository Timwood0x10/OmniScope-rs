# OmniScope-rs 0.9.0

> OmniScope-rs — an LLVM IR-based static analyzer for cross-language FFI security review.

**[OmniScope-rs 0.9.0 Tarball](https://github.com/Timwood0x10/OmniScope-rs/releases/tag/v0.9.0)**

---

## What's New

### Cross-Module Resource Analysis
- Implemented a reconciliation layer between the contract graph and issue verifier, unifying resource ownership facts from multiple
  LLVM IR modules.
- The `ContractGraphBuilder` now merges cross-module contract data, making ownership transfer chains visible across language
  boundaries.
- This is the foundation for future whole-project analysis (currently still operating on one IR file at a time per invocation).

### Noise-Reduced Cross-Language Precision
- Re-wired the family-registry `SymbolEffect` into allocator seed classification, improving cross-language allocator detection accuracy
  and reducing false positives on mixed-language allocator patterns.
- Added `NullChecked` pattern suppression, eliminating `null_dereference` false positives from runtime null-guard code.
- Suppressed `double_free` false positives on thin wrapper functions through the updated verifier.
- Downgraded `WriteToImmutable` to `Note` severity; real world counts dropped from 4525 to ~8 (-99.8%).
- `ffi_unsafe_call` false positives eliminated (-100%). `borrow_escape` reduced by 88%.

### Expanded Language Support
- **Node.js native**: added `node-ffi-napi` corpus fixtures and FFI surface classification patterns.
- **Python refcount**: added refcount-aware suppression rules and transitive call-graph propagation for CPython extension patterns.
- **C# interop**: improved `PInvoke` boundary detection and marshalling context analysis.
- **Zig**: removed Zig support and its corpus fixture; the prior `zig_main.ll` validation results are archived for historical
  reference only.

### Path-Sensitive Analysis
- Added path-sensitive double-free and use-after-free (UAF) verification, replacing the prior purely flow-insensitive verifier.
- "Freed pointer passed as argument" UAF pattern is now detected.
- `ConditionalLeak` issues are downgraded to `Note` when detection confidence is low.

### Leak Detection
- `LeakDetection` pass extended to leak candidates derived from the contract graph, capturing more subtle resource escape patterns.
- Conditional leak handling now respects path evidence before promoting to confirmed `Warning` severity.

### CLI & Output
- Three output formats: `rich` terminal, `json` machine-readable, and `sarif` for GitHub Code Scanning integration.
- `--boundary-only` and `--cross FROM:TO` boundary filters are supported.
- `--strategy` flag lets callers pick one of seven IR loading strategies explicitly.
- `omniscope info --passes` lists all 21 registered passes with their execution order.

---

## Supported Languages

| Language Pair | Status | Validated Projects |
|---------------|--------|-------------------|
| Rust → C | Stable | rusqlite, rustls-ffi, napi-rs, duckdb-rs |
| Rust → Python | Stable | pyo3 |
| Go → C | Stable | go-sqlite3, CGO |
| Java → C | Stable | JNA |
| Python → C | Stable | CPython extensions |
| C# → C | Beta | dotnet/pinvoke |
| Node.js → C | Beta | node-ffi-napi |

---

## Real-World Validation

9 real-world projects across 5 languages were analyzed. Confirmed true bugs found:

| Project | Bug | CWE |
|---------|-----|-----|
| duckdb-rs | 3× null pointer dereference | CWE-476 |
| rusqlite | 2× null pointer dereference | CWE-476 |
| rustls-ffi | double free | CWE-415 |
| JNA | double free | CWE-415 |

Inline IR regression tests covering key FFI patterns from each project are in `tests/accuracy_regression/`.

---

## Architecture

OmniScope-rs is a Rust workspace of 8 focused crates:

- `omniscope-cli` — CLI (`analyze`, `audit`, `info`, `init`, `validate`)
- `omniscope-pipeline` — 21-pass orchestration
- `omniscope-pass` — analysis passes and issue construction
- `omniscope-semantics` — language/resource semantics and structural inference
- `omniscope-ir` — LLVM IR loading, parsing, and caching
- `omniscope-dataflow` — generic dataflow framework
- `omniscope-core` — issues, diagnostics, reports, scoring, profiler
- `omniscope-types` — shared config, ABI, evidence, resource-family, and boundary types

The 21 registered passes are: `CallGraph`, `FFIBoundary`, `SurfaceClassifier`, `DangerSurface`, `RawFactCollector`,
`IRBehaviorSummary`, `LanguageAdapterFact`, `AbiLayout`, `SummaryBuilder`, `StructuralInference`, `ContractGraphBuilder`,
`OwnershipSolver`, `IssueCandidateBuilder`, `IssueVerifier`, `LeakDetection`, `RaiiDrop`, `InteriorMutability`,
`HeapProvenance`, `BorrowEscape`, `WriteToImmutable`, and `FfiReturnCheck`.

---

## Noise Reduction

| Category | Before | After | Change |
|----------|--------|-------|--------|
| `write_to_immutable` | 4525 | ~8 | -99.8% |
| `ffi_unsafe_call` | 142 | 0 | -100% |
| `borrow_escape` | 51 | 7 | -88% |
| `ownership_violation` (pyo3) | 68 | 0 | -100% |
| `null_dereference` FP | — | suppressed | `NullChecked` pattern |
| `double_free` FP | — | suppressed | thin wrappers |

---

## Build Requirements

- **Rust** 1.75+
- **LLVM** 22 (required for optional `llvm-backend` loading path)
- `make`, CMake, and a C++ compiler (required for `direct-cpp` and `cpp-pass` loading paths)
- Optional: **JDK 21+** for Java FFI analysis, **.NET 8+** for C# FFI analysis

```bash
cargo build --workspace
make build   # release binary at ./build/omniscope
make test    # nextest, all features, all crates
cargo bench
```

---

## Input Format

**Use `.ll` (text IR), not `.bc` (bitcode).** In real-world measurements `.bc` loading dominates runtime at ~98% of
a 30-second analysis run. `.ll` parses 100–1000× faster with identical analysis output.

```bash
# recommended
clang -emit-llvm -S -o output.ll source.c
omniscope analyze output.ll

# same analysis quality, ~100× slower load
omniscope analyze output.bc
```

Output formats: `rich`, `json`, `sarif`.

---

## Known Limits

- This is not a formal verification tool.
- It should not be used as the only security gate for production code.
- It analyzes one IR file at a time; full whole-program / whole-crate cross-module analysis is not yet implemented (cross-module
  contract merging is in progress).
- Path-sensitive double-free and leak detection has improved, but flow-sensitive alias analysis remains limited in some edge cases.
- Leak reporting can miss deallocator pairing information already present in the contract graph.
- Single-language module gating may suppress FFI evidence when C `extern` declarations appear alongside native-code bodies.
- Pure C/C++ memory safety auditing is not the main target and can still be noisy.
- Some language adapters are pattern-based semantic helpers rather than complete language frontends.

The safest current use is non-blocking CI, security-review triage, FFI surface mapping, and research prototyping.

---

## Comparison With Original OmniScope

OmniScope-rs is a Rust implementation that extends the original project idea into a broader multi-language architecture. It is
not a drop-in replacement.

| Area | Original OmniScope | OmniScope-rs 0.9.0 |
|------|--------------------|----------------------|
| Implementation | Zig project | Rust workspace (8 crates) |
| Core input | LLVM IR | LLVM IR |
| Main focus | Multi-language unsafe/FFI | Cross-language FFI ownership/resource |
| Architecture | Analyzer implementation | Explicit passes, typed issue model, contract graph |
| Output | Upstream formats | `rich`, `json`, `sarif` |
| IR loading | Upstream path | 8 strategies (C++/llvm-sys/text/msgpack) |
| Maturity | Existing release line | 0.9.0 — experimental/pre-1.0 |

---

## Acknowledgements

This project is built on the original OmniScope design: <https://github.com/Timwood0x10/OmniScope>

Special thanks to @[icehawk-hyb](https://github.com/icehawk-hyb) for guidance on cross-language security analysis.

---

## License

Apache-2.0. See [LICENSE](LICENSE).
