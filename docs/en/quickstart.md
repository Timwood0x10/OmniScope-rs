# Quickstart

How to install, build, and run OmniScope-rs. Every command below is taken
from the actual `Makefile`, `Cargo.toml`, or CLI source.

## Prerequisites

From `README.md:158-164`:

- Rust 1.75.0 stable (see `rust-toolchain.toml`).
- LLVM 17+ — only required if you want the optional `llvm-backend` feature
  or the C++ `SafetyExportPass` plugin. The pure-Rust text parser works
  without any LLVM toolchain.
- `make` for invoking `Makefile` targets.
- Optional: `cargo-nextest` (used by `make test`,
  `Makefile:65-68`).

## Build

### Cargo (Rust only)

```bash
cargo build --workspace --release
```

This builds the workspace. The CLI binary `omniscope` ends up at
`target/release/omniscope` because that name is declared in
`crates/omniscope-cli/Cargo.toml:12-14`:

```toml
[[bin]]
name = "omniscope"
path = "src/main.rs"
```

There is no separate `omniscope-rs` binary — the executable name is
`omniscope`.

### Cargo with the optional LLVM backend

```bash
cargo build --workspace --release --features llvm-backend
```

This activates the workspace feature defined at `Cargo.toml:14-16`, which
forwards to `omniscope-ir/llvm-backend` and pulls in `llvm-sys = 221`
(`crates/omniscope-ir/Cargo.toml:14-23`). LLVM development libraries must
be locatable via `llvm-config` or `LLVM_SYS_221_PREFIX`.

### Makefile

```bash
make build        # cargo build --workspace --release, then copies binary to ./build/omniscope
make pass-build   # cmake-builds pass/SafetyExportPass.{so,dylib}
make test         # cargo nextest run --workspace --all-features
make check        # clippy + clang-tidy
make fmt          # cargo fmt --all
make dev          # fmt + check + test
```

`make build` (`Makefile:52-61`) places the binary at `./build/omniscope`.
`make pass-build` (`Makefile:146-158`) requires `LLVM_PREFIX`. The default
search order tries Homebrew `llvm@22` down to `llvm@17` and finally
`llvm-config --prefix` (`Makefile:27-32`).

## CLI commands

`omniscope` exposes five subcommands declared at
`crates/omniscope-cli/src/main.rs:100-116`:

```
omniscope analyze   - run the analysis pipeline on an IR file
omniscope audit     - run the pipeline with audit-style output
omniscope info      - print version and the pass list
omniscope init      - generate a default omniscope.toml config
omniscope validate  - validate an omniscope.toml config
```

`analyze` and `audit` are the two execution modes. `info`, `init`, and
`validate` are utility commands.

### analyze

Source: `crates/omniscope-cli/src/main.rs:118-169` (arg parsing) and
`main.rs:268-426` (`run_analyze`).

```
omniscope analyze [OPTIONS] <INPUT>
```

Options:

| Flag | Default | Source line | Meaning |
|---|---|---|---|
| `<INPUT>` | required | `main.rs:121-122` | Path to `.ll`, `.bc`, or `.msgpack` |
| `-o, --output <FILE>` | stdout | `main.rs:125-126` | Output file; stdout when omitted |
| `-f, --format <FMT>` | `rich` | `main.rs:128-130` | `rich`, `json`, `sarif` |
| `-l, --language <LANG>` | none | `main.rs:132-134` | Target language hint |
| `--cross <FROM:TO>` | empty | `main.rs:136-139` | Repeatable cross-language boundary |
| `--config <PATH>` | search default | `main.rs:142-144` | Explicit TOML config file |
| `-v, --verbose` | false | `main.rs:146-148` | Per-pass pipeline metrics |
| `--timing` | false | `main.rs:150-152` | Detailed timing report |
| `--debug` | false | `main.rs:154-156` | `omniscope=trace` log level |
| `--parallel` | false | `main.rs:158-160` | Enable parallel pass execution |
| `--strategy <S>` | `auto-fast` | `main.rs:162-164` | IR loader strategy |
| `-b, --boundary-only` | false | `main.rs:166-168` | Only emit FFI-boundary issues |

Strategy values accepted by `--strategy`
(`main.rs:589-600`): `auto-fast`, `auto`, `direct-cpp-ffi` (also `ffi`),
`direct-cpp`, `llvm-sys`, `cpp-pass`, `text-parser` (also `text`),
`msgpack`. Unknown values fall through to `Auto`.

Examples:

```bash
# Basic analysis with default rich output
omniscope analyze ./mylib.ll

# JSON output to a file
omniscope analyze ./mylib.bc --format json --output report.json

# SARIF for GitHub Code Scanning
omniscope analyze ./mylib.bc --format sarif --output results.sarif

# Only FFI boundary issues
omniscope analyze ./mylib.bc --boundary-only

# Two explicit boundaries
omniscope analyze ./mylib.bc --cross C:Cpp --cross Zig:C (historical)

# Force the text parser
omniscope analyze ./mylib.ll --strategy text-parser

# Parallel mode with per-pass timing
omniscope analyze ./mylib.bc --parallel --timing
```

### audit

Source: `main.rs:171-188` and `main.rs:533-586`.

```
omniscope audit [OPTIONS] <INPUT>
```

Required:

- `-l, --language <LANG>` — `main.rs:177-178`
- `<INPUT>` — `main.rs:174-175`

Optional:

- `-t, --audit-type <TYPE>` — default `ffi`; documented values include
  `ffi`, `memory`, `concurrency` (`main.rs:181-183`).
- `--strategy <S>` — same set as `analyze`, default `auto-fast`.

`run_audit` only prints a summary (`issues found`, timings) — it does **not**
write a structured report. For machine-readable output use `analyze --format
json`.

### info

Source: `main.rs:190-195` and `run_info` at `main.rs:772-808`.

```
omniscope info             # version + description
omniscope info --passes    # also prints a hard-coded pass list
```

The pass list printed by `info --passes` (`main.rs:785-805`) is a static
string. It includes names like `NoiseReduction` and `PrecisionMetrics` that
are **not** actually registered as passes in
`Pipeline::register_default_passes`. See `docs/en/passes.md` for the real
list.

### init

Source: `main.rs:197-215` and `run_init` at `main.rs:811-879`.

```
omniscope init [--output omniscope.toml] [--force] [--name NAME] [--description TEXT]
```

Writes a default config produced by `OmniScopeConfig::generate_default`
(declared in `omniscope-types`). Default content includes two example
`[[ffi_boundary]]` entries (C→C++ and Rust→C — see test
`main.rs:1198-1237`) and one example `[[resource_family]]` entry named
`custom_allocator`.

### validate

Source: `main.rs:217-223` and `run_validate` at `main.rs:882-969`.

```
omniscope validate [--config omniscope.toml]
```

Loads the file with `OmniScopeConfig::load_from_file` and prints a summary
of declared FFI boundaries, resource families, and analysis flags.

## Configuration file resolution

`load_config` at `main.rs:435-475`:

1. If `--config <PATH>` is passed, load only that file.
2. Otherwise, `OmniScopeConfig::load_default()` searches
   `./omniscope.toml` then `~/.config/omniscope/config.toml`.
3. If none is found, use `OmniScopeConfig::default_config()`.
4. CLI `--cross` boundaries are appended last.

## Output formats

### rich (default)

Source: `crates/omniscope-cli/src/output/rich.rs`. Colored text intended
for terminals. Uses the `colored` crate.

### json

Source: `crates/omniscope-cli/src/output/json.rs:34-44`. Implemented by
`serde_json::to_string` / `to_string_pretty` over `PipelineResult`. When
writing to a file, compact mode is used; for stdout, pretty mode is
default (`main.rs:369-378`). The serialized schema is whatever `serde`
produces for `omniscope_pipeline::PipelineResult` — top-level fields are
`pass_results`, `total_issues`, `total_nodes`, `duration`, `stats`,
`issues`, `pass_timings`
(`crates/omniscope-pipeline/src/result.rs`).

### sarif

Source: `crates/omniscope-cli/src/output/sarif.rs`. Emits SARIF v2.1.0
(see comment at `sarif.rs:1-6`). Each rule ID is prefixed with `OMNI/`
followed by the snake_case `issue_kind_label`
(`sarif.rs:62-63`, snake-case mapping at
`crates/omniscope-cli/src/output/mod.rs:58-90`). Compatible with GitHub
Code Scanning ingestion.

## Where the binary ends up

| How you built it | Path |
|---|---|
| `cargo build --release` | `target/release/omniscope` |
| `make build` | `build/omniscope` (copied from `target/release/`) |
| `cargo install --path crates/omniscope-cli` | `$CARGO_HOME/bin/omniscope` |

There is no published crate on crates.io referenced in the repo.

## Environment variables

The IR loader consults a few env vars (`crates/omniscope-ir/src/loader_v2.rs`):

- `IR_EXTRACTOR` — explicit path to the `ir_extractor` binary
  (`loader_v2.rs:721-727`).
- `LLVM_OPT` — explicit path to `opt` (`loader_v2.rs:763-769`).
- `SAFETY_PASS_PLUGIN` — explicit path to
  `libSafetyExportPass.{so,dylib}` (`loader_v2.rs:821-827`).
- `OMNISCOPE_IR_TIMING` — when set, passes `-t` to `ir_extractor`
  (`loader_v2.rs:552`, `646`).
- `LLVM_SYS_221_PREFIX` — consumed at build time by `llvm-sys = 221`,
  needed for the `llvm-backend` feature.
- `RUST_LOG` — overrides the `--debug`/`--verbose` log level mapping
  (`main.rs:232-238`).
