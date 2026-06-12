# 快速开始

本文档说明如何从源码构建、运行 OmniScope-rs，以及解读它的输出。所有命令与字段都来自实际源码（CLI 在 `crates/omniscope-cli/src/main.rs`）。

## 1. 环境要求

- **Rust 1.75+** (`rust-version = "1.75"`，定义在 `crates/omniscope-core/Cargo.toml:5`、`crates/omniscope-types/Cargo.toml:5`、`crates/omniscope-ir/Cargo.toml:5`)
- **Cargo nextest**（可选，用于 `make test`，见 `Makefile:17,68`）
- **LLVM 17+**（仅当需要 `llvm-backend` feature 或 C++ Pass 时；`Makefile:26-32` 优先探测 Homebrew `llvm@22 → llvm@17`）
- **CMake 与 C++17 编译器**（仅当构建 `SafetyExportPass` 插件时；见 `pass/CMakeLists.txt`）
- **macOS / Linux**（C++ Pass 插件名 `.dylib` / `.so`，Windows 仅文本解析器与 MsgPack 后端可用，`crates/omniscope-ir/src/loader_v2.rs:808-818`）

## 2. 构建

### 2.1 纯 Rust 构建（无 LLVM 依赖）

```bash
cargo build --workspace --release
```

输出二进制：`target/release/omniscope`。二进制名由 `crates/omniscope-cli/Cargo.toml:13-15` 的 `[[bin]] name = "omniscope"` 决定，**不是** “omniscope-rs”。

### 2.2 通过 Makefile 构建并复制到 `./build/`

`Makefile:53-61` 的 `build` 目标会：

```bash
make build
# 等价于：
#   cargo build --workspace --release
#   mkdir -p build && cp -f target/release/omniscope build/omniscope
#   chmod +x build/omniscope
```

### 2.3 启用 `llvm-backend` feature

`omniscope-ir/Cargo.toml:14-15` 把 `llvm-backend` feature 映射到 `llvm-sys = "221"`。顶级 `Cargo.toml:16` 转发：

```bash
cargo build --release --features llvm-backend
```

需事先安装 LLVM 22 开发包，并设置 `LLVM_SYS_221_PREFIX`（或允许 `llvm-sys` 通过 `llvm-config` 自动探测）。

### 2.4 构建 C++ Pass 插件（Plan A）

```bash
make pass-build
```

定义在 `Makefile:145-158`：用 CMake 构建 `pass/SafetyExportPass.cpp`，输出 `pass/build/SafetyExportPass.dylib`（macOS）或 `.so`（Linux）。`omniscope-ir` 的 `find_pass_plugin`（`crates/omniscope-ir/src/loader_v2.rs:806-857`）会自动从这个路径加载插件。

### 2.5 构建 `ir_extractor`（DirectCpp / DirectCppFfi 后端）

源代码在 `tools/ir_extractor/`，自带 CMake 构建脚本。构建后二进制位置 `tools/ir_extractor/build/ir_extractor`，由 `find_ir_extractor`（`crates/omniscope-ir/src/loader_v2.rs:719-752`）自动发现。

## 3. 其它常用 make 目标

完整列表见 `Makefile`，常用项：

| 目标 | 说明 | 实现位置 |
|---|---|---|
| `make test` | `cargo nextest --workspace --all-features` | `Makefile:65-68` |
| `make test-verbose` | nextest + `--no-fail-fast` | `Makefile:72-74` |
| `make test-release` | release 模式跑测试 | `Makefile:78-80` |
| `make check` | clippy + C++ format/lint | `Makefile:84-87` |
| `make check-strict` | 加上 `clippy::pedantic` 与 `clippy::nursery` | `Makefile:92-94` |
| `make fmt` | `cargo fmt --all` | `Makefile:98-100` |
| `make pass-build` | 构建 C++ Pass 插件 | `Makefile:145-158` |
| `make pass-clean` | 删除 `pass/build/` | `Makefile:160-164` |
| `make clean` | cargo clean + pass-clean | `Makefile:170-174` |
| `make doc` | `cargo doc` | `Makefile:176-179` |

## 4. CLI 命令总览

`crates/omniscope-cli/src/main.rs:92-116` 定义了五个子命令：

```text
omniscope analyze    # 全流水线分析（最常用）
omniscope audit      # 针对特定语言的 FFI 审计
omniscope info       # 显示版本与 Pass 列表
omniscope init       # 生成默认 omniscope.toml
omniscope validate   # 校验 omniscope.toml
```

> README 中提到 `analyze` / `audit` / `info` 三个命令，但源码实际还提供 `init` 与 `validate`（`main.rs:111-115`）。

### 4.1 `analyze` —— 主入口

完整参数（`main.rs:118-169`）：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `INPUT` | 位置参数 | `.ll` / `.bc` / `.msgpack` 文件路径 |
| `-o, --output PATH` | stdout | 输出文件路径 |
| `-f, --format FMT` | `rich` | `rich` / `json` / `sarif` |
| `-l, --language LANG` | — | 目标语言提示（c/cpp/rust/zig(historical)/go/python/java） |
| `--cross FROM:TO` | — | FFI 边界，可重复（例：`--cross C:Cpp --cross Zig:C`(historical)） |
| `--config PATH` | 自动搜索 | 指定 `omniscope.toml` 路径 |
| `-v, --verbose` | false | 打印 pipeline 指标 |
| `--timing` | false | 详细时间报告（每 Pass 拆分） |
| `--debug` | false | 启用 `omniscope=trace` 日志 |
| `--parallel` | false | 启用并行 Pass 调度 |
| `--strategy STR` | `auto-fast` | 见 §4.4 |
| `-b, --boundary-only` | false | 只输出 FFI 边界类 Issue |

支持的 `--cross` 语言名（`main.rs:63-75`，大小写不敏感）：`c`、`cpp` / `c++`、`rust` / `rs`、`zig`、`go`、`python` / `py`、`java`、`csharp` / `c#` / `cs`。

### 4.2 `audit`

参数（`main.rs:171-188`）：

| 参数 | 说明 |
|---|---|
| `INPUT` | IR 文件路径 |
| `-l, --language LANG` | **必填**，目标语言 |
| `-t, --audit-type TYPE` | 默认 `ffi`；接受 `ffi` / `memory` / `concurrency` |
| `--strategy STR` | 同 analyze |

注意：`audit` 在 `main.rs:534-586` 实现上**复用了完整 pipeline**（与 `analyze` 共用 `Pipeline::register_default_passes`），仅在命令行打印了 issue 计数，**没有真正按 `-t` 类型过滤输出**。

### 4.3 `info`

`main.rs:191-195`、`main.rs:772-808`：

- `omniscope info` —— 仅打印版本和描述。
- `omniscope info --passes` —— 额外打印一个**硬编码**的 Pass 列表与输出格式说明（注意：该列表是手写的描述性文本，与 `Pipeline::register_default_passes` 实际注册的 20 个 Pass 名字**不完全一致**，例如它列出 `MemorySafety`、`PointerOwnership`、`BufferOverflow` 这些并不存在的 Pass 名）。

### 4.4 IR 加载策略字符串

`parse_strategy`（`main.rs:589-600`）接受的字符串（大小写不敏感，支持下划线与连字符变体）：

| 字符串 | 枚举值（`crates/omniscope-ir/src/loader_v2.rs:120-155`） |
|---|---|
| `direct-cpp-ffi` / `ffi` | `DirectCppFfi` |
| `direct-cpp` | `DirectCpp` |
| `llvm-sys` | `LlvmSys`（需要 `--features llvm-backend`） |
| `cpp-pass` | `CppPass`（需要 `opt` + `SafetyExportPass.so`） |
| `text-parser` / `text` | `TextParser`（纯 Rust 兜底） |
| `msgpack` | `MsgPack` |
| `auto-fast` | `AutoFast`（**默认值**） |
| 其它任何字符串 | `Auto` |

`AutoFast`（`loader_v2.rs:333-375`）针对 `.ll` 文件优先用文本解析器（更快）；大于 10MB 的 `.ll` 文件强制走文本路径。

## 5. 配置文件 `omniscope.toml`

`OmniScopeConfig::load_default`（`crates/omniscope-types/src/config.rs`）按以下顺序搜索：

1. `./omniscope.toml`
2. `~/.config/omniscope/config.toml`

也可以用 `--config PATH` 强制指定。

### 5.1 生成模板

```bash
omniscope init                            # 写入 ./omniscope.toml
omniscope init --output my.toml --force   # 强制覆盖
omniscope init --name myproj --description "demo"
```

`run_init`（`main.rs:811-878`）的核心实现是 `OmniScopeConfig::generate_default`，模板会包含 2 个示例 FFI 边界（C→C++ 等）与 1 个示例自定义资源族 `custom_allocator`（断言见 `main.rs:1199-1237`）。

### 5.2 校验

```bash
omniscope validate                      # 默认读 ./omniscope.toml
omniscope validate --config my.toml
```

`run_validate`（`main.rs:881-969`）打印边界、资源族与分析开关。

## 6. 典型用法

### 6.1 文本 IR 分析（无 LLVM 依赖）

```bash
omniscope analyze examples/simple.ll --strategy text-parser
```

### 6.2 输出 JSON 给 CI 接入

```bash
omniscope analyze target/release/project.bc \
    --format json \
    --output report.json \
    --strategy auto-fast
```

文件输出时使用紧凑 JSON（`main.rs:368-376`），无 pretty-print。

### 6.3 输出 SARIF 给 GitHub Code Scanning

```bash
omniscope analyze libfoo.bc \
    --format sarif \
    --output results.sarif
```

SARIF 版本固定 v2.1.0（`crates/omniscope-cli/src/output/sarif.rs:1-6`），rule id 形如 `OMNI/cross_language_free`（`sarif.rs:63`）。

### 6.4 显式声明 FFI 边界

```bash
omniscope analyze libfoo.bc \
    --cross C:Cpp \
    --cross Zig:C (historical) \
    --cross Rust:C
```

无 `--cross` 时 CLI 会调用 `omniscope_pass::infer_boundaries`（`main.rs:317`）自动推断。

### 6.5 性能分析

```bash
omniscope analyze libfoo.bc --timing --verbose --parallel
```

`--timing` 触发 `print_detailed_timing_report`（`main.rs:636-769`），输出每个 Pass 的耗时与 Issue 数；`--verbose` 在 stderr 追加 “Pipeline Metrics” 段（`main.rs:409-421`）。`--parallel` 设置 `PassManager::set_parallel(true)`。

### 6.6 仅看 FFI 边界 Issue

```bash
omniscope analyze libfoo.bc -b -f json
```

`filter_boundary_issues`（`main.rs:482-531`）会过滤掉非 FFI 类的 Issue：保留 `is_ffi_boundary()` 返回 true 的 8 种（见 ffi_detection.md §5）。

## 7. 输出格式细节

### 7.1 Rich（默认）

`crates/omniscope-cli/src/output/rich.rs` 实现：

- 自动检测终端是否支持 ANSI 颜色（`rich.rs:18-24`）。
- 每个 Issue 显示 `[HIGH]/[LOW]` 严重性徽章（`rich.rs:60-68`）。
- 资源契约类 Issue 显示 “语言1 ──✕──> 语言2” 箭头（不兼容跨族 free）或 “──✓──>” 箭头（同族），见 `rich.rs:70-87`。
- 显示 OMI-NNN 格式的 Issue ID（`output/mod.rs:44-46`）。
- 置信度文本：HIGH (100%) / MEDIUM (85%) / HEURISTIC (50%)（`output/mod.rs:93-100`）。

### 7.2 JSON

直接对 `PipelineResult`（`crates/omniscope-pipeline/src/result.rs:11-29`）做 `serde_json::to_string`，stdout 输出时 pretty，文件输出时 compact。

JSON 主要字段：

```json
{
  "pass_results": [{ "name": "...", "issues_found": 0, "nodes_analyzed": 0,
                     "duration_ms": 0, "stats": {}, "issues": [...] }],
  "total_issues": 0,
  "total_nodes": 0,
  "duration": { "secs": 0, "nanos": 0 },
  "stats": { ... },
  "issues": [...],
  "pass_timings": [
    { "pass_name": "CallGraph", "duration_ms": 1, "issues_found": 0 }
  ]
}
```

每个 `issues[]` 元素由 `omniscope_core::Issue`（`crates/omniscope-core/src/issue.rs`）的 `serde` 派生定义，含：`id`、`kind`、`severity`、`description`、`location`、`symbol`、`confidence`、`cwe_id`、`ffi_boundary`、`trace` 等。

### 7.3 SARIF v2.1.0

`crates/omniscope-cli/src/output/sarif.rs` 直接构造 `serde_json::Value`：

- `runs[0].tool.driver.name = "OmniScope"`、`version = env!("CARGO_PKG_VERSION")`。
- 每个 Issue → `results[i]` 项，含 `ruleId`、`level`（`error`/`warning`/`note` 映射自 `Severity`）、`message`、`locations`、可选 `properties.cwe`。
- ISO 8601 时间戳由 `sarif.rs:17-53` 用纯 `std::time` 计算（不依赖 chrono）。

## 8. 调试与日志

- `--debug` 设置默认日志级别为 `omniscope=trace`（`main.rs:233-238`）。
- `--verbose` 设置为 `omniscope=debug`。
- 默认级别 `omniscope=warn`。
- `RUST_LOG` 环境变量永远优先于这些 flag。

例：

```bash
RUST_LOG=omniscope_pass=debug,omniscope_pipeline=info omniscope analyze foo.ll
```

`OMNISCOPE_IR_TIMING=1` 会让 `DirectCpp` / `DirectCppFfi` 后端在 stderr 打印 `ir_extractor` 内部的 timing（`crates/omniscope-ir/src/loader_v2.rs:551-555,645-648`）。

## 9. 二进制名澄清

与 README 一致：CLI 二进制名为 **`omniscope`**（不是 `omniscope-rs`）。包名（顶级 `Cargo.toml:2`）和工作区都叫 `omniscope`/`omniscope-*`；`omniscope-rs` 仅是 GitHub 仓库名。
