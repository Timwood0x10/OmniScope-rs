# 配置文件

OmniScope-rs 使用 TOML 格式的配置文件（`omniscope.toml`）声明 FFI 边界、资源族和分析选项。

## 配置文件搜索顺序

`load_config` 在 `crates/omniscope-cli/src/main.rs:435-475`：

1. 如果指定了 `--config <PATH>`，仅加载该文件
2. 否则，`OmniScopeConfig::load_default()` 依次搜索 `./omniscope.toml` 和 `~/.config/omniscope/config.toml`
3. 如果都未找到，使用 `OmniScopeConfig::default_config()`
4. CLI 的 `--cross` 边界最后追加

## 配置格式

配置由 `OmniScopeConfig`（`crates/omniscope-types/src/config.rs`）定义：

```toml
[project]
name = "my_project"
description = "My cross-language project"

[analysis]
language = "rust"           # 目标语言提示
output_format = "rich"      # rich | json | sarif
parallel = false            # 启用并行 Pass 执行
timeout = 300               # 分析超时秒数
max_memory = 4096           # 最大内存 MB
verbose = false
threads = 0                 # 0 = 自动

# 声明显式 FFI 边界
[[ffi_boundary]]
from = "C"
to = "Cpp"
functions = ["malloc", "free"]
pattern = "exact"

[[ffi_boundary]]
from = "Rust"
to = "C"
pattern = "prefix"

# 声明自定义资源族
[[resource_family]]
name = "my_allocator"
alloc_functions = ["my_malloc", "my_calloc"]
free_functions = ["my_free"]
compatible_with = ["C_HEAP"]

# 启用/禁用特定 Pass
[passes]
enable = ["CallGraph", "FFIBoundary", "RawFactCollector"]
disable = ["DangerSurface"]
```

### 字段说明

#### `[project]`

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `name` | string | — | 项目名称 |
| `description` | string | — | 项目描述 |

#### `[analysis]`

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `language` | string | — | 目标语言（c/cpp/rust/go/python/java/csharp） |
| `output_format` | string | `rich` | 输出格式（`rich`、`json`、`sarif`） |
| `parallel` | bool | `false` | 启用并行 Pass 执行 |
| `timeout` | integer | `300` | 分析超时秒数 |
| `max_memory` | integer | `4096` | 最大内存 MB |
| `verbose` | bool | `false` | 启用详细输出 |
| `threads` | integer | `0` | 线程数（0 = 自动） |

#### `[[ffi_boundary]]`

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `from` | string | 必填 | 源语言 |
| `to` | string | 必填 | 目标语言 |
| `functions` | string[] | — | 此边界的特定函数名 |
| `pattern` | string | `exact` | 匹配模式（`exact`、`prefix`、`suffix`、`contains`） |

#### `[[resource_family]]`

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `name` | string | 必填 | 族名（通过 `FamilyId::custom(name)` 哈希） |
| `alloc_functions` | string[] | — | 分配函数名 |
| `free_functions` | string[] | — | 释放函数名 |
| `compatible_with` | string[] | — | 兼容的资源族 |

#### `[passes]`

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `enable` | string[] | 所有 | 启用的 Pass |
| `disable` | string[] | — | 禁用的 Pass |

## 生成默认配置

```bash
# 将默认配置写入 ./omniscope.toml
omniscope init

# 强制覆盖已有文件
omniscope init --force

# 指定名称和描述
omniscope init --name myproj --description "demo"
```

`run_init`（`crates/omniscope-cli/src/main.rs:811-878`）调用 `OmniScopeConfig::generate_default`，生成包含两个示例 `[[ffi_boundary]]` 条目（C→C++ 和 Rust→C）和一个示例 `[[resource_family]]` 条目 `custom_allocator` 的默认配置。

## 验证配置

```bash
# 验证默认路径的配置
omniscope validate

# 验证指定文件
omniscope validate --config my.toml
```

`run_validate`（`crates/omniscope-cli/src/main.rs:881-969`）使用 `OmniScopeConfig::load_from_file` 加载文件并打印声明的 FFI 边界、资源族和分析标志摘要。

## 源码文件索引

| 类型 | 文件 |
|---|---|
| `OmniScopeConfig` | `crates/omniscope-types/src/config.rs` |
| `AnalysisConfig` | `crates/omniscope-types/src/config.rs:14-40` |
| `FFIBoundaryConfig` | `crates/omniscope-types/src/config.rs` |
| `ResourceFamilyConfig` | `crates/omniscope-types/src/config.rs` |
| 配置加载（CLI） | `crates/omniscope-cli/src/main.rs:435-475` |
| `init` 子命令 | `crates/omniscope-cli/src/main.rs:811-878` |
| `validate` 子命令 | `crates/omniscope-cli/src/main.rs:881-969` |