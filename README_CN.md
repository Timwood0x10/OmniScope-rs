# OmniScope-rs

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![LLVM](https://img.shields.io/badge/LLVM-17%2B-green.svg)](https://llvm.org)

一套基于 LLVM IR 的生产级静态分析器，专注于**跨语言 FFI（外部函数接口）安全审计**。在语言调用边界上检测内存安全漏洞——use-after-free、double-free、内存泄漏、未检查的 null 返回值、所有权逃逸等。

> 一种语义树，多种语言，零配置检测。

## 为什么需要 OmniScope？

传统工具的盲区就在 FFI 边界。当 C 调用 Rust、当 Zig 调用 Go、当 Python 嵌入 C 时，内存所有权语义在 ABI 边界上消失了。OmniScope 通过直接分析 LLVM IR，将语言屏障下的内存漏洞提升为"一  等公民"。

### 已发现真实漏洞

| 项目 | 问题 | 严重程度 |
|-------|------|---------|
| [bun](https://github.com/oven-sh/bun) | `bun_jsc` 中的命令注入 | CRITICAL |
| [bun](https://github.com/oven-sh/bun) | `bun_boringssl` 中的跨语言内存泄漏 | HIGH |
| [wasmtime](https://github.com/bytecodealliance/wasmtime) | 1720 个 issue 中确认 1 个 CRITICAL | — |
| [bun_alloc](https://github.com/oven-sh/bun) | 泄漏分析 100% 准确率 (1/1) | — |

## 支持的语言

C、C++、Rust、Zig、Go、Python、Java、C# — 通过 IR 元数据（mangled name、调用约定等）自动识别语言。

## 架构

```
用户 IR 文件（.ll / .bc）
       │
       ├── Plan C: llvm-sys C API（feature-gated，直接构建 IRModule）
       ├── Plan A: SafetyExportPass.so（C++ LLVM Pass → 增强型 JSON）
       └── Plan B（回退）：纯文本解析（零外部依赖）
```

```
原始事实 → IR 行为摘要 → 结构推断
     → 契约图 → 所有权求解器 → 问题候选 → 验证器
```

### Workspace Crate 结构

| Crate | 职责 |
|-------|------|
| `omniscope-cli` | 用户 CLI 入口（`analyze`、`audit`、`info` 子命令） |
| `omniscope-pipeline` | 分析流水线编排，Pass 调度 |
| `omniscope-pass` | 20+ 分析 Pass（FFI 边界、RAII、borrow escape、契约图、所有权求解器） |
| `omniscope-semantics` | 语义推导引擎，结构推断，语言检测 |
| `omniscope-ir` | LLVM IR 加载器、解析器、IR Model（三层加载策略） |
| `omniscope-dataflow` | 通用前向/后向数据流分析框架 |
| `omniscope-core` | 诊断、Issue 模型（23 类问题）、Profiler、内存池 |
| `omniscope-types` | 公共类型定义、ResourceFamily 系统、ABI 类型 |

## 新功能（v0.2.0）

### 多语言语义扩展

OmniScope 现在支持 7 种编程语言的 19 个语义变体：

#### Python（5 个变体）
- `PythonRefcountInc` - Py_INCREF 引用计数增加
- `PythonRefcountDec` - Py_DECREF 引用计数减少
- `PythonBorrowedRef` - PyList_GetItem 借用引用
- `PythonOwnedRef` - PyBytes_FromString 拥有引用
- `PythonGilProtected` - PyGILState_Ensure/Release GIL 保护

#### Go（4 个变体）
- `GoDeferCleanup` - defer C.free(ptr) 延迟清理
- `GoFinalizer` - runtime.SetFinalizer 终结器
- `GoCgoWrapper` - _Cgo_* 包装函数
- `GoRuntimeAlloc` - runtime.mallocgc 运行时分配

#### C++（4 个变体）
- `CppUniquePtr` - std::unique_ptr 独占所有权
- `CppSharedPtr` - std::shared_ptr 共享所有权
- `CppDestructor` - ~ClassName() 析构函数
- `CppExceptionPath` - try/catch 异常路径

#### C#（3 个变体）
- `CsharpSafeHandle` - SafeHandle.ReleaseHandle 安全句柄
- `CsharpFinalizer` - ~Destructor() 终结器
- `CsharpPinvokeMarshal` - P/Invoke marshalling 互操作

#### Java（3 个变体）
- `JavaLocalRef` - JNI LocalRef 本地引用
- `JavaGlobalRef` - JNI GlobalRef 全局引用
- `JavaWeakRef` - JNI WeakGlobalRef 弱全局引用

### 语言适配器

#### Go/CGO 适配器
- 全面的 Go 内存模型分析（GC vs C 堆）
- CGO 调用约定检测和指针传递规则
- Go 特定函数模式识别（runtime、cgo）
- Go 函数的 FFI 安全评估

#### Python C API 适配器
- Python 引用计数分析（Py_INCREF/Py_DECREF）
- 对象生命周期检测（创建、借用、窃取）
- GIL（全局解释器锁）管理分析
- Python 特定 FFI 模式识别

## 核心特性

### 资源契约架构（v0.2.0）

统一的 `ResourceFamily` 抽象，覆盖所有语言的已知分配器：C heap、C++ `new`、Rust 所有权、Zig 分配器、Go GC、Python 引用计数、JNI references 等。

| 推断机制 | 检测目标 |
|----------|---------|
| 析构函数摘要 | C++ D0/D2 析构函数 |
| 引用计数释放 | `Py_DECREF`、`Arc::drop` |
| `into_raw` 所有权转移 | `Box::into_raw`、`CString::into_raw` |
| 桥接/指针投影 | `as_ptr()`、`getelementptr` body |
| POSIX 系统调用语义 | 文件/网络/进程操作 vs 内存管理 |
| 第三方库分配器对 | mimalloc、zlib、openssl、sqlite、JNI |
| 参数属性 | `readonly`/`noalias`（抑制 write-to-immutable FP） |
| Drop glue | RAII 尾位置 dealloc 检测 |

### 误报抑制机制

- **R-0**：通过 LLVM 参数属性抑制 write-to-immutable
- **R-1**：堆指针来源分类（dominated-with-use-alloc → 安全）
- **R-2**：内部可变性检测（Rust `UnsafeCell` / C++ `mutable`）
- **R-3**：RAII drop glue（抑制虚假 double-reclaim）
- **R-4**：POSIX 系统调用语义（非内存 syscall 不报错）
- **R-6**：`Box::into_raw` / `CString::into_raw` 所有权转移识别
- **SRT Gate**：每个 Issue 发出前经过 Suppression / Review / Track 门控（88% 精度阈值）

### 并行 Pass 执行

Pass 按拓扑排序到依赖层级，同层级内由 Rayon 并行执行。每个 Pass 获得独立的 `clone_for_parallel()` 上下文。共享数据为零拷贝 `Arc` 封装，执行结束后合并结果。

### 三种输出格式

- **rich** — 彩色终端输出，附带检测路径
- **json** — 机器可读，便于 CI 接入
- **sarif** — GitHub Code Scanning 标准格式

## 技术栈

| 层次 | 技术 |
|------|------|
| 语言 | Rust 1.75+（Edition 2021） |
| IR 后端 | llvm-sys 221（可选）/ C++ SafetyExportPass / 文本解析器 |
| 数据流 | 自定义前向/后向分析框架 |
| 并行 | Rayon（工作窃取） |
| 内存管理 | bumpalo arena，SmallVec |
| 错误处理 | thiserror、anyhow、miette |
| 序列化 | serde / serde_json / toml |
| CLI | clap（derive + color） |
| 基准测试 | Criterion 0.5 |

## 构建

### 环境要求

- Rust 1.75.0（stable）
- LLVM 17+（通过 `llvm-config` 或环境变量 `LLVM_SYS_221_PREFIX` / `/opt/homebrew/opt/llvm@22` 自动检测）
- Make（C++ pass 编译）
- 可选：`zld`（macOS）、`mold`（Linux）、`sccache`

### 快速开始

```bash
# 纯 Rust 构建（无需 LLVM）
cargo build --release

# 完整构建（Rust + C++ pass）
make build

# 输出到 ./build/omniscope
```

### 开发命令

```bash
make dev         # fmt + check + test
make check       # clippy + C++ lint
make fmt         # rustfmt 格式化
make test        # 运行全部测试
make test-verbose
make pass-build  # 编译 SafetyExportPass.so
```

## 用法

```bash
# 分析 IR 文件
omniscope analyze -i target/release/project.bc -o report.json --format json

# 对动态库做 FFI 专项审计
omniscope audit -i /usr/lib/libfoo.dylib

# 查看配置和 Pass 列表
omniscope info

# 指定加载策略
omniscope analyze -i file.ll --load-strategy text-parser

# 输出 SARIF 格式，供 GitHub Code Scanning 使用
omniscope analyze -i file.bc --format sarif -o results.sarif
```

## 测试体系

```bash
make test                      # 全部测试
cargo test --workspace         # 排除集成测试
cargo test --workspace --all-features
```

| 测试分类 | 位置 | 说明 |
|---------|------|------|
| 集成测试 | `tests/integration_tests.rs` | 跨语言 FFI 语料（C/C++/Rust/Zig/Go/Python） |
| FFI 专项 | `tests/ffi_analysis_tests.rs` | 真实 FFI bug 回归 |
| 语料回归 | `tests/corpus_tests.rs` | LLVM IR 语料回归 |
| Plan A/C | `tests/plan_a_c_integration.rs` | C++ Pass / llvm-sys 集成 |
| Union-Find | `tests/union_find_test.rs` | 所有权求解器数据结构 |
| 单元测试 | `crates/omniscope-pass/src/.../tests.rs` | 各模块内联测试 |

## 基准测试

```bash
cargo bench
```

| 基准 | 关注点 |
|------|--------|
| `ir_parsing` | IR 文本/二进制解析吞吐量 |
| `pipeline` | 端到端流水线延迟（5 个 fixture） |
| `resource_analysis` | 资源契约推理性能 |
| `bugfix_regression` | 修复后正确性验证 |
| `cpp_rust_accuracy` | C++/Rust 跨语言准确率 |
| `context_clone` | 并行上下文克隆性能 |

## CI/CD

GitHub Actions 在每次 push/PR 时，于 `ubuntu-latest`、`macos-latest`、`windows-latest` 运行 stable 和 beta 双工具链矩阵：

- `fmt` — rustfmt 检查
- `clippy` — 带 `-D warnings` 的 lint
- `test` — 完整测试矩阵
- `build-release` — release 构建 + artifact 上传
- `docs` — `cargo doc --no-deps`
- `audit` — `cargo audit`（漏洞扫描）
- `miri` — unsafe 代码验证
- `bench` — `cargo bench --no-run`（仅编译检查）

## 路线图

- [x] 项目基础设施 & Workspace 建立
- [x] LLVM IR 解析器（文本 & 二进制）
- [x] Call Graph 构建
- [x] FFI 边界检测
- [x] 数据流分析框架
- [x] 语义推导引擎
- [x] 资源契约架构（Phases 0–4）
- [x] 带循环检测的所有权求解器
- [x] 误报抑制（R-0 至 R-6）
- [x] SARIF 输出
- [x] C++ LLVM Pass 集成（Plan A）
- [x] 跨语言语料（C/C++/Rust/Zig/Go/Python）
- [x] 基准测试 & CI/CD
- [x] 多语言语义扩展（Python、Go、C++、C#、Java）
- [x] Go/CGO 适配器（内存模型分析）
- [x] Python C API 适配器（引用计数分析）
- [ ] v1.0 稳定版发布
- [ ] 增量分析缓存
- [ ] IDE / LSP 集成
- [ ] WASM/JS FFI 支持
- [ ] 跨函数生命周期追踪
- [ ] C++/C#/Java 语言适配器（完整实现）

## 贡献

参见 [CONTRIBUTING.md](CONTRIBUTING.md) 了解开发流程和 Commit 规范。

分支命名：`feature/功能名` 或 `bugfix/修复名`

```
feat(pass): add new ownership detector
fix: handle null pointer in call parsing
refactor(parser): optimize IR tokenization
perf: reduce allocation in issue builder
```

## 许可证

Apache-2.0。详见 [LICENSE](LICENSE)。
