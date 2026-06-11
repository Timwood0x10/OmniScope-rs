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