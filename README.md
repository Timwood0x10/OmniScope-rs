# OmniScope-rs

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![LLVM](https://img.shields.io/badge/LLVM-17%2B-green.svg)](https://llvm.org)

A production-grade static analyzer built on LLVM IR for **cross-language FFI (Foreign Function Interface) security auditing**. Detect memory safety bugs — use-after-free, double-free, leaks, unchecked null returns, and ownership escape — at language boundary crossings.

> One semantic tree. Many languages. Zero-config detection.

## Why OmniScope?

FFI boundaries are blind spots for every traditional tool. When C calls into Rust, when Zig calls Go, or when Python embeds C — memory ownership semantics dissolve across ABI boundaries. OmniScope bridges this gap by analyzing LLVM IR directly, making language-barrier memory bugs first-class citizens.

### Real Bugs Found

| Project | Issue | Severity |
|---------|-------|----------|
| [bun](https://github.com/oven-sh/bun) | Command injection in `bun_jsc` | CRITICAL |
| [bun](https://github.com/oven-sh/bun) | Cross-language memory leak in `bun_boringssl` | HIGH |
| [wasmtime](https://github.com/bytecodealliance/wasmtime) | 1720 issues analyzed, 1 confirmed CRITICAL | — |
| [bun_alloc](https://github.com/oven-sh/bun) | 100% precision on leak analysis (1/1) | — |

## Supported Languages

C, C++, Rust, Zig, Go, Python, Java — with automatic language detection from IR metadata such as mangled names and calling conventions.

## Architecture

```
User IR (.ll / .bc)
       │
       ├── Plan A: SafetyExportPass.so (C++ LLVM Pass → enriched JSON)
       ├── Plan C: llvm-sys C API (direct IR model construction)
       └── Plan B (fallback): Pure-text IR parser (zero deps)
```

```
Raw Facts → IR Behavior Summary → Structural Inference
       → Contract Graph → Ownership Solver → Issue Candidates → Verifier
```

### Crates

| Crate | Role |
|-------|------|
| `omniscope-cli` | User-facing CLI (`analyze`, `audit`, `info` commands) |
| `omniscope-pipeline` | Top-level pipeline orchestration, pass scheduling |
| `omniscope-pass` | 20+ analysis passes (FFI boundary, RAII, borrow escape, contract graph, ownership solver) |
| `omniscope-semantics` | Semantic derivation engine, structural inference, language detection |
| `omniscope-ir` | LLVM IR loader, parser, IR model (three-tier loading strategy) |
| `omniscope-dataflow` | Generic forward/backward dataflow analysis framework |
| `omniscope-core` | Diagnostics, issue model (23 issue kinds), profiler, memory pool |
| `omniscope-types` | Shared type definitions, ResourceFamily system, ABI types |

## Key Features

### Resource Contract Architecture (v0.2.0)

Unified `ResourceFamily` abstraction covering every known allocator: C heap, C++ `new`, Rust ownership, Zig allocators, Go GC, Python refcount, JNI references, and more.

| Inference | Detects |
|-----------|---------|
| Destructor summary | C++ D0/D2 destructors |
| Refcount release | `Py_DECREF`, `Arc::drop` |
| `into_raw` ownership transfer | `Box::into_raw`, `CString::into_raw` |
| Bridge/projection | `as_ptr()`, `getelementptr` bodies |
| POSIX syscall semantics | File/network ops vs memory management |
| Library allocator pairs | mimalloc, zlib, openssl, sqlite, JNI |
| Parameter attributes | `readonly`/`noalias` (suppresses write-to-immutable FP) |
| Drop glue | RAII tail-position dealloc detection |

### False Positive Suppression

- **R-0**: Write-to-immutable suppression via LLVM parameter attributes
- **R-1**: Heap provenance classification (dominated-with-use-alloc → safe)
- **R-2**: Interior mutability detection (Rust `UnsafeCell` / C++ `mutable`)
- **R-3**: RAII drop glue (suppresses false double-reclaim)
- **R-4**: POSIX syscall semantics (non-memory syscalls)
- **R-6**: `Box::into_raw` / `CString::into_raw` ownership transfer
- **SRT Gate**: Suppression / Review / Track gate on every emitted issue (88% precision threshold)

### Parallel Pass Execution

Passes are topologically sorted into dependency levels; within each level, Rayon runs them in parallel. Each pass receives an independent `clone_for_parallel()` context. Shared data is zero-copy `Arc`-wrapped. Results merge after completion.

### No-Cost Reporting Formats

- **rich** — colorized terminal output with detection trace
- **json** — machine-readable for CI ingestion
- **sarif** — GitHub Code Scanning standard format

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Rust 1.75+ (Edition 2021) |
| IR Backend | llvm-sys 221 (optional) / C++ SafetyExportPass / Text parser |
| Dataflow | Custom forward/backward framework |
| Parallelism | Rayon (work-stealing) |
| Memory | bumpalo arena allocator, SmallVec |
| Error handling | thiserror, anyhow, miette |
| Serialization | serde / serde_json / toml |
| CLI | clap (derive + color) |
| Benchmarking | Criterion 0.5 |

## Build

### Prerequisites

- Rust 1.75.0 (stable)
- LLVM 17+ (auto-detected via `llvm-config` or `LLVM_SYS_221_PREFIX`)
- Make (C++ pass compilation)
- Optional: `zld` (macOS), `mold` (Linux), `sccache`

### Quick Start

```bash
# Rust-only build (no LLVM required)
cargo build --release

# Full build (Rust + C++ pass)
make build

# Binary output: ./build/omniscope
```

### Development Commands

```bash
make dev        # fmt + check + test
make check      # clippy + C++ lint
make fmt        # rustfmt
make test       # run all tests
make test-verbose
make pass-build # compile SafetyExportPass.so
```

## Usage

```bash
# Analyze an IR file
omniscope analyze -i target/release/project.bc -o report.json --format json

# FFI-focused audit of a dynamic library
omniscope audit -i /usr/lib/libfoo.dylib

# Show config and registered passes
omniscope info

# Specify loading strategy
omniscope analyze -i file.ll --load-strategy text-parser

# Output as SARIF for GitHub Code Scanning
omniscope analyze -i file.bc --format sarif -o results.sarif

# Only show FFI boundary issues (cross-language memory safety)
omniscope analyze -i file.bc --boundary-only

# Boundary-only with short flag
omniscope analyze -i file.bc -b
```

## Test Suite

```bash
make test                    # all tests
cargo test --workspace       # without integration tests
cargo test --workspace --all-features
```

| Test Category | Location | Description |
|---------------|----------|-------------|
| Integration | `tests/integration_tests.rs` | Cross-language FFI corpus (C/C++/Rust/Zig/Go/Python) |
| FFI Analysis | `tests/ffi_analysis_tests.rs` | Real-world FFI bug regression |
| Corpus | `tests/corpus_tests.rs` | LLVM IR corpus regression |
| Plan A/C | `tests/plan_a_c_integration.rs` | C++ Pass / llvm-sys integration |
| Union-Find | `tests/union_find_test.rs` | Ownership solver data structure |
| Inline unit | `crates/omniscope-pass/src/.../tests.rs` | Per-module unit tests |

## Benchmarks

```bash
cargo bench
```

| Benchmark | Focus |
|-----------|-------|
| `ir_parsing` | IR text/binary parsing throughput |
| `pipeline` | End-to-end latency (5 fixtures) |
| `resource_analysis` | Resource contract inference |
| `bugfix_regression` | Post-fix correctness |
| `cpp_rust_accuracy` | C++/Rust cross-language accuracy |
| `context_clone` | Parallel context clone performance |

## CI/CD

GitHub Actions runs on every push and PR across `ubuntu-latest`, `macos-latest`, `windows-latest` — stable and beta toolchains:

- `fmt` — rustfmt check
- `clippy` — lint with `-D warnings`
- `test` — full test matrix
- `build-release` — release builds + artifact upload
- `docs` — `cargo doc --no-deps`
- `audit` — `cargo audit` (vuln scanning)
- `miri` — unsafe code verification
- `bench` — `cargo bench --no-run` (compile-only)

## Roadmap

- [x] Project infrastructure & workspace setup
- [x] LLVM IR parser (text & binary)
- [x] Call graph construction
- [x] FFI boundary detection
- [x] Dataflow analysis framework
- [x] Semantic derivation engine
- [x] Resource contract architecture (Phases 0–4)
- [x] Ownership solver with cycle detection
- [x] False positive suppression (R-0 to R-6)
- [x] SARIF output
- [x] C++ LLVM Pass integration (Plan A)
- [x] Cross-language corpus (C/C++/Rust/Zig/Go/Python)
- [x] Benchmarks & CI/CD
- [ ] v1.0 stable release
- [ ] Incremental analysis cache
- [ ] IDE / LSP integration
- [ ] WASM/JS FFI support

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow and commit conventions.

Branch naming: `feature/description` or `bugfix/description`

```
feat(pass): add new ownership detector
fix: handle null pointer in call parsing
refactor(parser): optimize IR tokenization
perf: reduce allocation in issue builder
```

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
