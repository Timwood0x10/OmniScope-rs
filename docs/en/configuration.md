# Configuration

OmniScope-rs uses a TOML configuration file (`omniscope.toml`) for declaring
FFI boundaries, resource families, and analysis options.

## Configuration file resolution

`load_config` at `crates/omniscope-cli/src/main.rs:435-475`:

1. If `--config <PATH>` is passed, load only that file.
2. Otherwise, `OmniScopeConfig::load_default()` searches
   `./omniscope.toml` then `~/.config/omniscope/config.toml`.
3. If none is found, use `OmniScopeConfig::default_config()`.
4. CLI `--cross` boundaries are appended last.

## Schema

The configuration is defined by `OmniScopeConfig`
(`crates/omniscope-types/src/config.rs`):

```toml
[project]
name = "my_project"
description = "My cross-language project"

[analysis]
language = "rust"           # Target language hint
output_format = "rich"      # rich | json | sarif
parallel = false            # Enable parallel pass execution
timeout = 300               # Analysis timeout in seconds
max_memory = 4096           # Maximum memory in MB
verbose = false
threads = 0                 # 0 = auto

# Declare explicit FFI boundaries
[[ffi_boundary]]
from = "C"
to = "Cpp"
functions = ["malloc", "free"]
pattern = "exact"

[[ffi_boundary]]
from = "Rust"
to = "C"
pattern = "prefix"

# Declare custom resource families
[[resource_family]]
name = "my_allocator"
alloc_functions = ["my_malloc", "my_calloc"]
free_functions = ["my_free"]
compatible_with = ["C_HEAP"]

# Enable/disable specific passes
[passes]
enable = ["CallGraph", "FFIBoundary", "RawFactCollector"]
disable = ["DangerSurface"]
```

### Fields

#### `[project]`

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | — | Project name |
| `description` | string | — | Project description |

#### `[analysis]`

| Field | Type | Default | Description |
|---|---|---|---|
| `language` | string | — | Target language (c, cpp, rust, go, python, java, csharp) |
| `output_format` | string | `rich` | Output format (`rich`, `json`, `sarif`) |
| `parallel` | bool | `false` | Enable parallel pass execution |
| `timeout` | integer | `300` | Analysis timeout in seconds |
| `max_memory` | integer | `4096` | Maximum memory in MB |
| `verbose` | bool | `false` | Enable verbose output |
| `threads` | integer | `0` | Number of threads (0 = auto) |

#### `[[ffi_boundary]]`

| Field | Type | Default | Description |
|---|---|---|---|
| `from` | string | required | Source language |
| `to` | string | required | Target language |
| `functions` | string[] | — | Specific function names for this boundary |
| `pattern` | string | `exact` | Match pattern (`exact`, `prefix`, `suffix`, `contains`) |

#### `[[resource_family]]`

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Family name (hashed to `FamilyId::custom(name)`) |
| `alloc_functions` | string[] | — | Allocation function names |
| `free_functions` | string[] | — | Deallocation function names |
| `compatible_with` | string[] | — | Families this is compatible with |

#### `[passes]`

| Field | Type | Default | Description |
|---|---|---|---|
| `enable` | string[] | all | Passes to enable |
| `disable` | string[] | — | Passes to disable |

> **Design Philosophy: Why TOML (Not YAML/JSON)?**
>
> TOML was chosen over YAML and JSON for three practical reasons:
> 1. **No significant indentation errors** — YAML is notoriously brittle; a single misaligned space silently breaks parsing. TOML's bracket-based structure avoids this class of bug entirely.
> 2. **Comments are supported** — JSON does not allow comments, making it unsuitable for a human-edited config file that needs inline documentation. TOML supports `#` comments.
> 3. **Native Rust tooling** — The `toml` and `serde` crates provide first-class deserialization into Rust structs with minimal boilerplate. No external schema validator or codegen step is required.
>
> The `[[ffi_boundary]]` array-of-tables syntax maps directly to `Vec<FFIBoundaryConfig>` in Rust (see `config.rs`), making deserialization a one-line `toml::from_str` call. The `pattern` field (`exact`, `prefix`, `suffix`, `contains`) was added because real-world FFI boundaries are rarely exact matches — a C library may expose `my_lib_open`, `my_lib_read`, `my_lib_close` and grouping them under `pattern = "prefix"` with `functions = ["my_lib"]` is far more ergonomic than listing every symbol.

## Generating default config

```bash
# Write default config to ./omniscope.toml
omniscope init

# Force overwrite existing file
omniscope init --force

# Specify name and description
omniscope init --name myproj --description "demo"
```

`run_init` (`crates/omniscope-cli/src/main.rs:811-878`) calls
`OmniScopeConfig::generate_default` which produces two example
`[[ffi_boundary]]` entries (C→C++ and Rust→C) and one example
`[[resource_family]]` entry named `custom_allocator`.

## Validating config

```bash
# Validate default config location
omniscope validate

# Validate specific file
omniscope validate --config my.toml
```

`run_validate` (`crates/omniscope-cli/src/main.rs:881-969`) loads the file
with `OmniScopeConfig::load_from_file` and prints a summary of declared
FFI boundaries, resource families, and analysis flags.

> **Design Philosophy: Configuration as Code, Not as Annotation**
>
> OmniScope uses an external config file rather than in-source annotations for two reasons:
> 1. **Users should not modify third-party library source** — adding annotation macros to `libcurl` or `libuv` is impractical and creates a fork burden.
> 2. **OmniScope analyzes LLVM IR, not source** — annotations written in C/C++ source (e.g., `__attribute__`) are stripped by the compiler before IR emission. A standalone TOML file survives compilation unchanged.
>
> The `init` subcommand generates example boundaries for C→C++ and Rust→C because these are the two most common cross-language pairs in practice (see `main.rs:1198-1237`). The `infer_boundaries` subcommand is intentionally conservative — it produces fewer edges than explicit config to avoid false positives in automated environments (see `boundary_inference.rs:26`).

## Source files

| Type | File |
|---|---|
| `OmniScopeConfig` | `crates/omniscope-types/src/config.rs` |
| `AnalysisConfig` | `crates/omniscope-types/src/config.rs:14-40` |
| `FFIBoundaryConfig` | `crates/omniscope-types/src/config.rs` |
| `ResourceFamilyConfig` | `crates/omniscope-types/src/config.rs` |
| Config loading (CLI) | `crates/omniscope-cli/src/main.rs:435-475` |
| `init` subcommand | `crates/omniscope-cli/src/main.rs:811-878` |
| `validate` subcommand | `crates/omniscope-cli/src/main.rs:881-969` |

## Honest Limitations

1. **Static boundary description only** — The configuration file describes FFI boundaries statically. Runtime-dynamic FFI (e.g., `dlopen` + `dlsym`) cannot be expressed in the TOML schema because the target symbols are not known until execution.

2. **Heuristic inference** — `infer_boundaries` uses only LLVM module metadata and function names to guess cross-language calls. This is a heuristic and can misclassify functions, especially when symbol naming conventions overlap between languages (e.g., C++ functions with `extern "C"` linkage).

3. **Custom resource family ID visibility** — Custom resource families start at ID 256 (see `resource_family.rs:99`), but there is no CLI command to view allocated IDs. Debugging which ID maps to which family requires reading the source code.

4. **CLI granularity** — The `--cross FROM:TO` flag applies to all functions in the module and offers no per-function granularity. To specify individual functions on a boundary, the full TOML config with `[[ffi_boundary]]` entries is required.