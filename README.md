# OmniScope-rs

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![LLVM](https://img.shields.io/badge/LLVM-17%2B-green.svg)](https://llvm.org)

A production-grade static analyzer built on LLVM IR for **cross-language FFI (Foreign Function Interface) security auditing**. Detect memory safety bugs — use-after-free, double-free, leaks, unchecked null returns, and ownership escape — at language boundary crossings.

> One semantic tree. Many languages. Zero-config detection.

## Why OmniScope?

FFI boundaries are blind spots for every traditional tool. When C calls into Rust, when Go calls Python, or when Python embeds C — memory ownership semantics dissolve across ABI boundaries. OmniScope bridges this gap by analyzing LLVM IR directly, making language-barrier memory bugs first-class citizens.

### Real Bugs Found

| Project | Status | Notes |
|---|---|---|
| ffi-demo (cross-language corpus) | 68% precision, 62% recall across IR files | See per-file table in validation report. |
| bun `bun_alloc` | Currently 0/19 TP — known regression after single-language gate change (`bd21984`). Tracked for v0.3.0. | See `docs/release/bun_validation.md`. |
| wasmtime | Earlier scan: 1720 candidates, 1 confirmed CRITICAL (not re-verified for v0.2.0). | Re-validation pending. |

> Note: earlier drafts of this README claimed independent bun findings in `bun_jsc` and `bun_boringssl`. Triage could not reproduce those (no such crate names exist in bun, and no IR / repro was shipped). The table above replaces those claims.

## Supported Languages

C, C++, Rust, Go, Python, Java, C# — with automatic language detection from IR metadata such as mangled names and calling conventions.

## Architecture

```mermaid
flowchart TD
    A["User IR (.ll / .bc)"] --> B{"Load Strategy"}
    B -->|"Plan C<br/>llvm-sys C API"| C["Direct IRModule Construction"]
    B -->|"Plan A<br/>SafetyExportPass.so"| D["C++ LLVM Pass<br/>→ Enriched JSON"]
    B -->|"Plan B<br/>(fallback)"| E["Pure-text IR Parser<br/>(zero deps)"]
    C --> F["OmniScope Pipeline"]
    D --> F
    E --> F
    F --> G["Raw Facts"]
    G --> H["IR Behavior Summary"]
    H --> I["Structural Inference"]
    I --> J["Contract Graph"]
    J --> K["Ownership Solver"]
    K --> L["Issue Candidates"]
    L --> M["Issue Verifier"]
```

> The loader actually exposes 8 `LoadStrategy` variants — Plan A/B/C is the high-level narrative. See `docs/en/architecture.md` for all 8 strategies.

```mermaid
flowchart LR
    A["Raw Facts"] --> B["IR Behavior Summary"]
    B --> C["Structural Inference"]
    C --> D["Contract Graph"]
    D --> E["Ownership Solver"]
    E --> F["Issue Candidates"]
    F --> G["Issue Verifier"]
```

### Crates

| Crate | Role |
|-------|------|
| `omniscope-cli` | User-facing CLI (`analyze`, `audit`, `info` commands) |
| `omniscope-pipeline` | Top-level pipeline orchestration, pass scheduling |
| `omniscope-pass` | 20 default analysis passes (FFI boundary, RAII, borrow escape, contract graph, ownership solver) |
| `omniscope-semantics` | Semantic derivation engine, structural inference, language detection |
| `omniscope-ir` | LLVM IR loader, parser, IR model (three-tier loading strategy) |
| `omniscope-dataflow` | Generic forward/backward dataflow analysis framework |
| `omniscope-core` | Diagnostics, issue model (28 issue kinds), profiler, memory pool |
| `omniscope-types` | Shared type definitions, ResourceFamily system, ABI types |

## New Features (v0.2.0-rc, preview)

### Multi-Language Semantic Extensions

OmniScope now supports comprehensive semantic analysis for 7 programming languages with 19 new semantic variants:

#### Python (5 variants)
- `PythonRefcountInc` - Py_INCREF reference count increment
- `PythonRefcountDec` - Py_DECREF reference count decrement
- `PythonBorrowedRef` - PyList_GetItem borrowed reference
- `PythonOwnedRef` - PyBytes_FromString owned reference
- `PythonGilProtected` - PyGILState_Ensure/Release GIL protection

#### Go (4 variants)
- `GoDeferCleanup` - defer C.free(ptr) deferred cleanup
- `GoFinalizer` - runtime.SetFinalizer finalizer pattern
- `GoCgoWrapper` - _Cgo_* wrapper function
- `GoRuntimeAlloc` - runtime.mallocgc runtime allocation

#### C++ (4 variants)
- `CppUniquePtr` - std::unique_ptr exclusive ownership
- `CppSharedPtr` - std::shared_ptr shared ownership
- `CppDestructor` - ~ClassName() destructor pattern
- `CppExceptionPath` - try/catch exception path

#### C# (3 variants)
- `CsharpSafeHandle` - SafeHandle.ReleaseHandle safe handle
- `CsharpFinalizer` - ~Destructor() finalizer
- `CsharpPinvokeMarshal` - P/Invoke marshalling interop

#### Java (3 variants)
- `JavaLocalRef` - JNI LocalRef local reference
- `JavaGlobalRef` - JNI GlobalRef global reference
- `JavaWeakRef` - JNI WeakGlobalRef weak global reference

### Language Adapters

#### Go/CGO Adapter
- Comprehensive Go memory model analysis (GC vs C heap)
- CGO call convention detection and pointer passing rules
- Go-specific function pattern recognition (runtime, cgo)
- FFI safety assessment for Go functions

#### Python C API Adapter
- Python reference counting analysis (Py_INCREF/Py_DECREF)
- Object lifecycle detection (creation, borrowing, stealing)
- GIL (Global Interpreter Lock) management analysis
- Python-specific FFI pattern recognition

### Known limitations

v0.2.0 is shipped as a release candidate, not a stable release. Known regressions
(notably `bun_alloc` precision after the single-language gate change) and pending
re-validation work are tracked in
[`docs/release/release_readiness_v0.2.0.md`](docs/release/release_readiness_v0.2.0.md).

## Key Features

### Resource Contract Architecture (v0.2.0)

Unified `ResourceFamily` abstraction covering every known allocator: C heap, C++ `new`, Rust ownership, Go GC, Python refcount, JNI references, and more.

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

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `analyze` | Analyze an LLVM IR file for memory safety issues |
| `audit`   | FFI-focused audit of a dynamic library |
| `info`    | Show configuration and registered passes |

### Common Workflows

#### Basic Analysis
```bash
# Analyze a single IR file
omniscope analyze -i file.ll -o report.json

# Quick analysis with terminal output (rich format)
omniscope analyze -i file.bc
```

#### FFI Security Audit
```bash
# Focus on cross-language boundary issues
omniscope analyze -i project.bc --boundary-only
omniscope analyze -i project.bc -b  # short flag

# Audit a dynamic library
omniscope audit -i /usr/lib/libfoo.dylib
```

#### CI Integration (SARIF output)
```bash
# Generate SARIF for GitHub Code Scanning
omniscope analyze -i file.bc --format sarif -o results.sarif
```

#### Loading Strategy Control
```bash
# Use specific IR loading strategy
omniscope analyze -i file.ll --load-strategy text-parser
omniscope analyze -i file.bc --load-strategy llvm-sys
```

### Output Formats
- **rich** — colorized terminal output with detection trace (default)
- **json** — machine-readable for CI ingestion
- **sarif** — GitHub Code Scanning standard format

## Configuration

OmniScope can be configured via a `omniscope.toml` file in the project root:

```toml
[analysis]
# Analysis options
boundary_only = false
load_strategy = "auto"  # "auto", "text-parser", "safety-export-pass", "llvm-sys"

[boundary]
# FFI boundary configuration
declare_boundary = [
    { from = "Rust", to = "C" },
    { from = "C", to = "Rust" },
    { from = "Python", to = "C" },
]

[boundary.patterns]
# Pattern-based boundary detection
patterns = [
    { from = "Rust", to = "C", pattern = "*_ffi_*" },
    { from = "C", to = "Rust", pattern = "*_rs_*" },
]

[suppression]
# FP suppression rules
enable_r0 = true   # Mutable parameter suppression
enable_r1 = true   # Heap provenance classification
enable_r2 = true   # Interior mutability detection
enable_r3 = true   # RAII drop glue
enable_r4 = true   # POSIX syscall semantics
enable_r6 = true   # Box::into_raw / CString::into_raw
enable_r13 = true  # C/C++ caller WTI suppression
enable_r14 = true  # Rust allocator internal suppression
enable_r15 = true  # RawVec/buffer write suppression

[output]
# Output configuration
format = "rich"    # "rich", "json", "sarif"
color = true
verbose = false
```

## API Documentation

Generate and view the API documentation:

```bash
# Generate documentation
cargo doc --open

# Or view specific crate documentation
cargo doc -p omniscope-semantics --open
```

### Key APIs

#### Language Adapters

- **GoAdapter**: Go/CGO semantic analysis
- **PythonAdapter**: Python C API semantic analysis
- **SemanticKind**: Multi-language semantic variants (19 variants across 7 languages)

#### Semantic Analysis

```rust
use omniscope_semantics::resource::go_adapter::GoAdapter;
use omniscope_semantics::resource::python_adapter::PythonAdapter;
use omniscope_semantics::resource::semantic_tree::SemanticKind;

// Go analysis
let go_adapter = GoAdapter::new();
let go_analysis = go_adapter.analyze_function("runtime.mallocgc", None);

// Python analysis
let python_adapter = PythonAdapter::new();
let python_analysis = python_adapter.analyze_function("Py_INCREF");

// Semantic kind detection
let kind = SemanticKind::from_function_name("std::unique_ptr");
```

For detailed API documentation, see the [Usage Guide](docs/usage_guide.md).

## Test Suite

```bash
make test                    # all tests
cargo test --workspace       # without integration tests
cargo test --workspace --all-features
```

| Test Category | Location | Description |
|---------------|----------|-------------|
| Integration | `tests/integration_tests.rs` | Cross-language FFI corpus (C/C++/Rust/Go/Python) |
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
- [x] Multi-language semantic extensions (Python, Go, C++, C#, Java)
- [x] Go/CGO adapter with memory model analysis
- [x] Python C API adapter with reference counting analysis
- [ ] v1.0 stable release
- [ ] Incremental analysis cache
- [ ] IDE / LSP integration
- [ ] WASM/JS FFI support
- [ ] Cross-function lifetime tracking
- [ ] C++/C#/Java language adapters (full implementation)

## Limitations

OmniScope has important limitations. Please read [LIMITATIONS.md](LIMITATIONS.md) before using in production.

**Quick summary:**
- ❌ Not a formal verification tool
- ❌ Not suitable for pure C/C++ memory safety auditing
- ❌ Not a standalone security solution
- ✅ CI/CD informational check (non-blocking)
- ✅ Security auditor's first-pass triage tool
- ✅ Educational FFI surface mapping

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

---

## 限制说明 (中文)

使用前请阅读 [LIMITATIONS.md](LIMITATIONS.md) 了解完整限制。

**快速总结：**
- ❌ 不是形式化验证工具
- ❌ 不适合纯 C/C++ 内存安全审计
- ❌ 不能作为唯一的安全保障
- ✅ CI/CD 参考检查（不阻断构建）
- ✅ 安全审计员初筛工具
- ✅ 教学/学术 FFI Surface 映射
