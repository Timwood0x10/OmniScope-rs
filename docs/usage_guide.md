# OmniScope-rs Usage Guide

This guide provides detailed usage instructions for OmniScope-rs.

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [CLI Commands](#cli-commands)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Language Adapters](#language-adapters)
- [Troubleshooting](#troubleshooting)

## Installation

### Build from source

```bash
git clone https://github.com/your-username/OmniScope-rs.git
cd OmniScope-rs
make build
```

### Prerequisites

- Rust 1.75.0 or later
- LLVM 17+ (for full functionality, including `llvm-backend` feature and `SafetyExportPass` plugin)
- `make` for invoking Makefile targets
- Optional: `cargo-nextest` (used by `make test`)

### Build targets

```bash
make build        # cargo build --release, copies binary to ./build/omniscope
make pass-build   # cmake-builds pass/SafetyExportPass.{so,dylib}
make test         # cargo nextest run --workspace --all-features
make check        # clippy + clang-tidy
make fmt          # cargo fmt --all
```

The CLI binary is named `omniscope` (declared in `crates/omniscope-cli/Cargo.toml:12-14`).

## Basic Usage

### Analyze an IR file

```bash
# Basic analysis with default rich output
omniscope analyze ./mylib.ll

# JSON output to a file
omniscope analyze ./mylib.bc --format json --output report.json

# SARIF for GitHub Code Scanning
omniscope analyze ./mylib.bc --format sarif --output results.sarif

# Only FFI boundary issues
omniscope analyze ./mylib.bc --boundary-only
```

## CLI Commands

`omniscope` exposes five subcommands:

```
omniscope analyze   - run the analysis pipeline on an IR file
omniscope audit     - run the pipeline with audit-style output
omniscope info      - print version and the pass list
omniscope init      - generate a default omniscope.toml config
omniscope validate  - validate an omniscope.toml config
```

### analyze

Full options:

| Flag | Default | Description |
|---|---|---|
| `<INPUT>` | required | Path to `.ll`, `.bc`, or `.msgpack` |
| `-o, --output <FILE>` | stdout | Output file; stdout when omitted |
| `-f, --format <FMT>` | `rich` | `rich`, `json`, `sarif` |
| `-l, --language <LANG>` | none | Target language hint |
| `--cross <FROM:TO>` | empty | Repeatable cross-language boundary |
| `--config <PATH>` | search default | Explicit TOML config file |
| `-v, --verbose` | false | Per-pass pipeline metrics |
| `--timing` | false | Detailed timing report |
| `--debug` | false | `omniscope=trace` log level |
| `--parallel` | false | Enable parallel pass execution |
| `--strategy <S>` | `auto-fast` | IR loader strategy |
| `-b, --boundary-only` | false | Only emit FFI-boundary issues |

Strategy values: `auto-fast`, `auto`, `direct-cpp-ffi` (also `ffi`), `direct-cpp`, `llvm-sys`, `cpp-pass`, `text-parser` (also `text`), `msgpack`.

### audit

```
omniscope audit -l <LANG> [--audit-type TYPE] [--strategy S] <INPUT>
```

Required: `-l, --language <LANG>`. Optional: `-t, --audit-type <TYPE>` (default `ffi`; accepts `ffi`, `memory`, `concurrency`).

Note: `audit` reuses the full pipeline and only prints an issue count summary.

### info

```
omniscope info             # version + description
omniscope info --passes    # also prints a hard-coded pass list
```

### init

```
omniscope init [--output omniscope.toml] [--force] [--name NAME] [--description TEXT]
```

Writes a default config produced by `OmniScopeConfig::generate_default`.

### validate

```
omniscope validate [--config omniscope.toml]
```

Loads the file with `OmniScopeConfig::load_from_file` and prints a summary.

## Output Formats

### rich (default)

Colored terminal output with severity badges and detection paths. Source: `crates/omniscope-cli/src/output/rich.rs`.

### json

Machine-readable JSON output. Source: `crates/omniscope-cli/src/output/json.rs`. Top-level fields: `pass_results`, `total_issues`, `total_nodes`, `duration`, `stats`, `issues`, `pass_timings`, `dedup_dropped`.

### sarif

SARIF v2.1.0 for GitHub Code Scanning. Each rule ID is prefixed with `OMNI/` followed by the snake_case issue kind label. Source: `crates/omniscope-cli/src/output/sarif.rs`.

## Configuration

See [docs/en/configuration.md](en/configuration.md) for the full `omniscope.toml` reference.

## Language Adapters

OmniScope-rs includes semantic adapters for multiple languages. These provide language-specific pattern recognition for:

### Go/CGO Adapter
- Go memory model analysis (GC-managed vs C heap)
- CGO call convention detection
- Go-specific patterns (`runtime.*`, `_cgo_*`, `_Cfunc_*`)

### Python C API Adapter
- Reference counting analysis (Py_INCREF/Py_DECREF)
- Object lifecycle detection (borrowed vs owned references)
- GIL management analysis

### Other adapters
- **C++ Adapter**: RAII, unique_ptr/shared_ptr, destructor patterns
- **Java JNI Adapter**: Local/global/weak reference management
- **C# Adapter**: SafeHandle, P/Invoke marshalling

## Troubleshooting

### LLVM not found

```bash
# Set LLVM prefix
export LLVM_SYS_221_PREFIX=/path/to/llvm
```

### Debug mode

```bash
# Enable debug logging
RUST_LOG=omniscope=debug omniscope analyze -i input.bc

# Enable specific module logging
RUST_LOG=omniscope_pass=debug,omniscope_pipeline=info omniscope analyze foo.ll
```

### Performance tuning

- Use `--parallel` for multi-threaded pass execution
- Use `--boundary-only` for focused FFI analysis
- Use `--strategy text-parser` for `.ll` files without LLVM dependencies

## API Reference

For detailed API documentation:

```bash
cargo doc --open
```

Or visit the generated documentation at `target/doc/omniscope/`.

## Further reading

- [Architecture](en/architecture.md) - Crate layout and pipeline design
- [Analysis passes](en/passes.md) - All 21 registered passes
- [FFI detection](en/ffi_detection.md) - Cross-language boundary detection
- [Issue model](en/issue_model.md) - IssueKind, Severity, Confidence, VerifierVerdict
- [Configuration](en/configuration.md) - omniscope.toml reference
- [FP suppression](en/fp_suppression.md) - SRT gate and R-N rules
- [Extending](extending.md) - Developer extension guide