# OmniScope-rs 使用指南

本文档提供 OmniScope-rs 的详细使用说明。

## 目录

- [安装](#安装)
- [基本用法](#基本用法)
- [CLI 命令](#cli-命令)
- [输出格式](#输出格式)
- [配置文件](#配置文件)
- [语言适配器](#语言适配器)
- [故障排除](#故障排除)

## 安装

### 从源码构建

```bash
git clone https://github.com/your-username/OmniScope-rs.git
cd OmniScope-rs
make build
```

### 环境要求

- Rust 1.75.0 或更高版本
- LLVM 17+（仅当需要 `llvm-backend` 功能或 `SafetyExportPass` 插件时）
- `make` 用于调用 Makefile 目标
- 可选：`cargo-nextest`（用于 `make test`）

### 构建目标

```bash
make build        # cargo build --release，复制二进制到 ./build/omniscope
make pass-build   # cmake 构建 pass/SafetyExportPass.{so,dylib}
make test         # cargo nextest run --workspace --all-features
make check        # clippy + clang-tidy
make fmt          # cargo fmt --all
```

CLI 二进制名为 `omniscope`（声明于 `crates/omniscope-cli/Cargo.toml:12-14`）。

## 基本用法

### 分析 IR 文件

```bash
# 使用默认 rich 输出的基本分析
omniscope analyze ./mylib.ll

# JSON 输出到文件
omniscope analyze ./mylib.bc --format json --output report.json

# SARIF 输出用于 GitHub Code Scanning
omniscope analyze ./mylib.bc --format sarif --output results.sarif

# 仅输出 FFI 边界问题
omniscope analyze ./mylib.bc --boundary-only
```

## CLI 命令

`omniscope` 暴露五个子命令：

```
omniscope analyze   - 对 IR 文件运行分析流水线
omniscope audit     - 以审计模式运行流水线
omniscope info      - 打印版本和 Pass 列表
omniscope init      - 生成默认 omniscope.toml 配置
omniscope validate  - 校验 omniscope.toml 配置
```

### analyze

完整选项：

| 标志 | 默认值 | 说明 |
|---|---|---|
| `<INPUT>` | 必填 | `.ll`、`.bc` 或 `.msgpack` 文件路径 |
| `-o, --output <FILE>` | stdout | 输出文件；省略时输出到 stdout |
| `-f, --format <FMT>` | `rich` | `rich`、`json`、`sarif` |
| `-l, --language <LANG>` | 无 | 目标语言提示 |
| `--cross <FROM:TO>` | 空 | 可重复的跨语言边界声明 |
| `--config <PATH>` | 搜索默认 | 显式指定 TOML 配置文件 |
| `-v, --verbose` | false | 各 Pass 流水线指标 |
| `--timing` | false | 详细时间报告 |
| `--debug` | false | `omniscope=trace` 日志级别 |
| `--parallel` | false | 启用并行 Pass 执行 |
| `--strategy <S>` | `auto-fast` | IR 加载策略 |
| `-b, --boundary-only` | false | 仅输出 FFI 边界问题 |

策略值：`auto-fast`、`auto`、`direct-cpp-ffi`（也可用 `ffi`）、`direct-cpp`、`llvm-sys`、`cpp-pass`、`text-parser`（也可用 `text`）、`msgpack`。

### audit

```
omniscope audit -l <LANG> [--audit-type TYPE] [--strategy S] <INPUT>
```

必填：`-l, --language <LANG>`。可选：`-t, --audit-type <TYPE>`（默认 `ffi`；接受 `ffi`、`memory`、`concurrency`）。

注意：`audit` 复用完整流水线，仅打印问题计数摘要。

### info

```
omniscope info             # 版本 + 描述
omniscope info --passes    # 同时打印硬编码的 Pass 列表
```

### init

```
omniscope init [--output omniscope.toml] [--force] [--name NAME] [--description TEXT]
```

写入由 `OmniScopeConfig::generate_default` 生成的默认配置。

### validate

```
omniscope validate [--config omniscope.toml]
```

使用 `OmniScopeConfig::load_from_file` 加载文件并打印摘要。

## 输出格式

### rich（默认）

带严重性徽章和检测路径的彩色终端输出。源码：`crates/omniscope-cli/src/output/rich.rs`。

### json

机器可读的 JSON 输出。源码：`crates/omniscope-cli/src/output/json.rs`。顶层字段：`pass_results`、`total_issues`、`total_nodes`、`duration`、`stats`、`issues`、`pass_timings`、`dedup_dropped`。

### sarif

用于 GitHub Code Scanning 的 SARIF v2.1.0。每条规则 ID 以 `OMNI/` 为前缀，后接下划线分隔的问题类型标签。源码：`crates/omniscope-cli/src/output/sarif.rs`。

## 配置文件

参见 [docs/zh/configuration.md](configuration.md) 获取完整的 `omniscope.toml` 参考。

## 语言适配器

OmniScope-rs 包含多种语言的语义适配器，提供语言特定的模式识别：

### Go/CGO 适配器
- Go 内存模型分析（GC 管理 vs C 堆）
- CGO 调用约定检测
- Go 特定模式（`runtime.*`、`_cgo_*`、`_Cfunc_*`）

### Python C API 适配器
- 引用计数分析（Py_INCREF/Py_DECREF）
- 对象生命周期检测（借用的 vs 拥有的引用）
- GIL 管理分析

### 其他适配器
- **C++ 适配器**：RAII、unique_ptr/shared_ptr、析构函数模式
- **Java JNI 适配器**：本地/全局/弱引用管理
- **C# 适配器**：SafeHandle、P/Invoke 封送处理

## 故障排除

### LLVM 未找到

```bash
# 设置 LLVM 前缀
export LLVM_SYS_221_PREFIX=/path/to/llvm
```

### 调试模式

```bash
# 启用调试日志
RUST_LOG=omniscope=debug omniscope analyze -i input.bc

# 启用特定模块日志
RUST_LOG=omniscope_pass=debug,omniscope_pipeline=info omniscope analyze foo.ll
```

### 性能调优

- 使用 `--parallel` 开启多线程 Pass 执行
- 使用 `--boundary-only` 聚焦 FFI 分析
- 对于 `.ll` 文件，使用 `--strategy text-parser` 避免 LLVM 依赖

## API 参考

获取详细 API 文档：

```bash
cargo doc --open
```

或访问 `target/doc/omniscope/` 目录下的生成文档。

## 延伸阅读

- [架构](architecture.md) - Crate 布局和流水线设计
- [分析 Pass](passes.md) - 全部 21 个注册 Pass
- [FFI 检测](ffi_detection.md) - 跨语言边界检测
- [Issue 模型](issue_model.md) - IssueKind、Severity、Confidence、VerifierVerdict
- [配置文件](configuration.md) - omniscope.toml 参考
- [FP 抑制](fp_suppression.md) - SRT 门控和 R-N 规则
- [扩展指南](extending.md) - 开发者扩展指南