# OmniScope-RS Dependencies & File Structure

## 📦 核心依赖 (Cargo.toml)

```toml
[package]
name = "omniscope"
version = "0.1.9"
edition = "2021"
rust-version = "1.75"
authors = ["OmniScope Team"]
description = "LLVM IR-based static analyzer for cross-language FFI security auditing"
license = "MIT OR Apache-2.0"

[workspace]
members = [
    "crates/omniscope-core",
    "crates/omniscope-ir",
    "crates/omniscope-dataflow",
    "crates/omniscope-types",
    "crates/omniscope-pass",
    "crates/omniscope-semantics",
    "crates/omniscope-registry",
    "crates/omniscope-pipeline",
    "crates/omniscope-cli",
]

[dependencies]
# === LLVM Bindings ===
inkwell = { version = "0.4", features = ["llvm22-0"] }  # LLVM 22 bindings

# === Serialization ===
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"

# === Error Handling ===
thiserror = "1.0"
anyhow = "1.0"
miette = { version = "5.10", features = ["fancy"] }  # Beautiful error reports

# === CLI ===
clap = { version = "4.4", features = ["derive", "color"] }

# === Parallelism ===
rayon = "1.8"  # Data parallelism
crossbeam = "0.8"  # Concurrent data structures

# === Memory Management ===
bumpalo = "3.14"  # Arena allocator
typed-arena = "2.0"  # Typed arena

# === Collections ===
dashmap = "5.5"  # Concurrent HashMap
indexmap = "2.2"  # Ordered HashMap
smallvec = "1.11"  # Small vector optimization
bitvec = "1.0"  # Bit vectors

# === Lazy & Caching ===
once_cell = "1.19"
lru = "0.12"

# === Logging & Profiling ===
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tracing-flame = "0.2"  # Flamegraph support

# === String Processing ===
regex = "1.10"
glob = "0.3"
unicode-segmentation = "1.10"

# === File System ===
walkdir = "2.4"
tempfile = "3.9"

# === Compression ===
libz-sys = "1.1"  # zlib bindings

# === Date/Time ===
chrono = { version = "0.4", features = ["serde"] }

# === UUID ===
uuid = { version = "1.6", features = ["v4", "serde"] }

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }  # Benchmarking
proptest = "1.4"  # Property-based testing
quickcheck = "1.0"
assert_matches = "1.5"
pretty_assertions = "1.4"

[profile.release]
opt-level = 3
lto = "fat"  # Link Time Optimization
codegen-units = 1  # Better optimization
strip = true  # Strip symbols

[profile.dev]
opt-level = 0
debug = true

[profile.bench]
inherits = "release"
debug = true  # Keep debug info for profiling
```

## 📁 文件目录结构

```
OmniScope-rs/
├── Cargo.toml                          # Workspace configuration
├── Cargo.lock                          # Dependency lock
├── README.md                           # Project documentation
├── LICENSE                             # License file
├── .gitignore                          # Git ignore rules
├── rust-toolchain.toml                 # Rust version pinning
│
├── crates/                             # Workspace members
│   ├── omniscope-core/                 # Layer 1: Core infrastructure
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # Module root
│   │       ├── error.rs                # Error types (thiserror)
│   │       ├── result.rs               # Result types
│   │       ├── diagnostics.rs          # Diagnostic aggregation
│   │       ├── fact.rs                 # Fact system
│   │       ├── fact_store.rs           # Fact storage (dashmap)
│   │       ├── profiler.rs             # Performance profiling (tracing)
│   │       ├── memory_pool.rs          # Memory pooling (bumpalo)
│   │       └── config.rs               # Configuration types
│   │
│   ├── omniscope-ir/                   # Layer 2: IR abstraction
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── loader.rs               # IR loader (inkwell)
│   │       ├── llvm_raw.rs             # Raw LLVM bindings
│   │       ├── llvm_safe.rs            # Safe wrapper
│   │       ├── view.rs                 # IR view abstractions
│   │       ├── debug_info.rs           # Debug info extraction
│   │       ├── location.rs             # Source location tracking
│   │       └── instruction_ext.rs      # Instruction extensions
│   │
│   ├── omniscope-dataflow/             # Layer 3: Dataflow engine
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── graph.rs                # Data flow graph
│   │       ├── node.rs                 # Data nodes
│   │       ├── edge.rs                 # Data edges
│   │       ├── function_summary.rs     # Inter-procedural summaries
│   │       ├── path_condition.rs       # Path-sensitive analysis
│   │       ├── guard_propagation.rs    # Guard propagation
│   │       ├── null_check_guard.rs     # Null check guards
│   │       ├── value_id_map.rs         # Value ID mapping
│   │       └── stats.rs                # Dataflow statistics
│   │
│   ├── omniscope-types/                # Type definitions
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── abi_types.rs            # ABI types
│   │       ├── alias_types.rs          # Alias types
│   │       ├── call_graph_types.rs     # Call graph types
│   │       ├── callback_escape_types.rs # Callback escape types
│   │       ├── ownership_types.rs      # Ownership types
│   │       ├── memory_graph_types.rs   # Memory graph types
│   │       ├── lock_types.rs           # Lock types
│   │       ├── cpp_fp_types.rs         # C++ false positive types
│   │       └── main_config.rs          # Main configuration
│   │
│   ├── omniscope-pass/                 # Layer 5: Analysis passes
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── pass.rs                 # Pass trait definition
│   │       ├── manager.rs              # Pass manager
│   │       ├── context.rs              # Pass context
│   │       │
│   │       ├── foundation/             # Foundation passes
│   │       │   ├── mod.rs
│   │       │   ├── cfg.rs              # Control Flow Graph
│   │       │   ├── dfg.rs              # Data Flow Graph
│   │       │   └── alias.rs            # Alias analysis
│   │       │
│   │       ├── analysis/               # Analysis passes
│   │       │   ├── mod.rs
│   │       │   ├── call_graph.rs       # Call graph construction
│   │       │   ├── surface_classifier.rs # Surface classification
│   │       │   ├── danger_surface.rs   # Danger surface detection
│   │       │   ├── pointer_ownership.rs # Pointer ownership
│   │       │   ├── provenance.rs       # Provenance analysis
│   │       │   ├── steensgaard.rs      # Steensgaard alias analysis
│   │       │   ├── lock.rs             # Lock analysis
│   │       │   ├── thread_crossing.rs  # Thread crossing analysis
│   │       │   ├── callback_escape.rs  # Callback escape analysis
│   │       │   ├── abi_mismatch.rs     # ABI mismatch detection
│   │       │   ├── buffer_overflow.rs  # Buffer overflow detection
│   │       │   ├── transmute_detection.rs # Transmute detection
│   │       │   ├── debug_info.rs       # Debug info analysis
│   │       │   │
│   │       │   ├── ffi/                # FFI-specific passes
│   │       │   │   ├── mod.rs
│   │       │   │   ├── ffi_analysis.rs # FFI analysis
│   │       │   │   ├── ffi_boundary.rs # FFI boundary detection
│   │       │   │   ├── ffi_detector.rs # FFI detector
│   │       │   │   ├── ffi_type_checker.rs # FFI type checking
│   │       │   │   ├── ffi_type_mismatch.rs # FFI type mismatch
│   │       │   │   ├── ffi_safety_checker.rs # FFI safety checking
│   │       │   │   ├── ffi_semantics.rs # FFI semantics
│   │       │   │   ├── ffi_zone_check.rs # FFI zone checking
│   │       │   │   ├── ffi_noise_filter.rs # FFI noise filtering
│   │       │   │   ├── ffi_helpers.rs  # FFI helpers
│   │       │   │   └── ffi_utils.rs    # FFI utilities
│   │       │   │
│   │       │   ├── taint/              # Taint analysis
│   │       │   │   ├── mod.rs
│   │       │   │   ├── taint_propagation.rs # Taint propagation
│   │       │   │   ├── taint_state.rs  # Taint state
│   │       │   │   └── flow_path.rs    # Flow path tracking
│   │       │   │
│   │       │   ├── ptr_lifetime/       # Pointer lifetime
│   │       │   │   ├── mod.rs
│   │       │   │   ├── ptr_lifetime.rs # Pointer lifetime analysis
│   │       │   │   ├── allocation_classifier.rs # Allocation classification
│   │       │   │   ├── value_tracking.rs # Value tracking
│   │       │   │   ├── ptr_lifetime_violations.rs # Lifetime violations
│   │       │   │   ├── ptr_lifetime_helpers.rs # Helpers
│   │       │   │   └── ptr_lifetime_utils.rs # Utilities
│   │       │   │
│   │       │   ├── issue/              # Issue detection
│   │       │   │   ├── mod.rs
│   │       │   │   ├── ffi_unsafe.rs   # FFI unsafe patterns
│   │       │   │   ├── ffi_body_check.rs # FFI body checking
│   │       │   │   ├── memory_safety.rs # Memory safety issues
│   │       │   │   ├── buffer_overflow.rs # Buffer overflow
│   │       │   │   ├── integer_overflow.rs # Integer overflow
│   │       │   │   ├── malloc_check.rs # Malloc checking
│   │       │   │   ├── free_validation.rs # Free validation
│   │       │   │   └── return_check.rs # Return value checking
│   │       │   │
│   │       │   ├── rust_ffi/           # Rust FFI specific
│   │       │   │   ├── mod.rs
│   │       │   │   ├── rust_ffi_auditor.rs # Rust FFI auditor
│   │       │   │   └── rust_ffi_helpers.rs # Rust FFI helpers
│   │       │   │
│   │       │   └── noise/              # Noise reduction
│   │       │       ├── mod.rs
│   │       │       ├── noise_reduction.rs # Noise reduction
│   │       │       ├── cpp_fp_reduction.rs # C++ FP reduction
│   │       │       ├── issue_suppression.rs # Issue suppression
│   │       │       ├── severity_rules.rs # Severity rules
│   │       │       └── vulnerability_rules.rs # Vulnerability rules
│   │       │
│   │       ├── filter/                 # Pass filters
│   │       │   ├── mod.rs
│   │       │   ├── fp_precision_guard.rs # FP precision guard
│   │       │   └── fp_whitelist.rs     # FP whitelist
│   │       │
│   │       └── instrumentation/        # Instrumentation
│   │           ├── mod.rs
│   │           └── planner.rs          # Instrumentation planner
│   │
│   ├── omniscope-semantics/            # Layer 4: Semantic analysis
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── language_detector.rs    # Language detection
│   │       ├── zone_classifier.rs      # Zone classification
│   │       ├── noise_filter.rs         # Noise filtering
│   │       ├── path_filter.rs          # Path-based filtering
│   │       ├── behavior_filter.rs      # Behavior-based filtering
│   │       ├── intrinsic_filter.rs     # Intrinsic filtering
│   │       ├── surface_classifier.rs   # Surface classification
│   │       ├── semantic_tree.rs        # Semantic tree
│   │       ├── semantic_patterns.rs    # Pattern matching
│   │       ├── resolution_engine.rs    # Resolution engine
│   │       ├── memory_graph.rs         # Memory graph
│   │       ├── memory_relations.rs     # Memory relations
│   │       ├── allocator_kb.rs         # Allocator knowledge base
│   │       ├── rust_drop_semantics.rs  # Rust drop semantics
│   │       └── call_graph.rs           # Semantic call graph
│   │
│   ├── omniscope-registry/             # Function registries
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── semantic_registry.rs    # Semantic registry
│   │       ├── sanitizer_registry.rs   # Sanitizer registry
│   │       ├── config_loader.rs        # Config loader
│   │       ├── dynamic_loading_reg.rs  # Dynamic loading registry
│   │       ├── hooks.rs                # Registry hooks
│   │       │
│   │       ├── layers/                 # Layer registries
│   │       │   ├── mod.rs
│   │       │   ├── layer1_reg.rs       # Layer 1 registry
│   │       │   ├── layer2_reg.rs       # Layer 2 registry
│   │       │   ├── layer3_reg.rs       # Layer 3 registry
│   │       │   ├── layer4_reg.rs       # Layer 4 registry
│   │       │   ├── layer5_reg.rs       # Layer 5 registry
│   │       │   └── layer6_reg.rs       # Layer 6 registry
│   │       │
│   │       ├── language/               # Language-specific registries
│   │       │   ├── mod.rs
│   │       │   ├── posix_io_reg.rs     # POSIX I/O registry
│   │       │   ├── posix_thread_reg.rs # POSIX thread registry
│   │       │   ├── python_c_api_reg.rs # Python C API registry
│   │       │   └── jni_reg.rs          # JNI registry
│   │       │
│   │       └── types.rs                # Registry types
│   │
│   ├── omniscope-pipeline/             # Layer 6: Pipeline orchestration
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── pipeline.rs             # Pipeline manager
│   │       ├── scheduler.rs            # Pass scheduler
│   │       ├── dependency.rs           # Dependency resolution
│   │       └── result.rs               # Pipeline result
│   │
│   └── omniscope-cli/                  # Layer 7: CLI & Output
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs                 # Entry point
│           ├── cli.rs                  # CLI parser (clap)
│           ├── commands/               # Command handlers
│           │   ├── mod.rs
│           │   ├── analyze.rs          # Analyze command
│           │   ├── audit.rs            # Audit command
│           │   └── config.rs           # Config command
│           │
│           └── output/                 # Output formatters
│               ├── mod.rs
│               ├── formatter.rs        # Generic formatter
│               ├── json.rs             # JSON output
│               ├── sarif.rs            # SARIF output
│               ├── lsp.rs              # LSP server
│               └── cli.rs              # CLI output
│
├── config/                             # Configuration files
│   ├── languages/                      # Language configs
│   │   ├── c.json
│   │   ├── rust.json
│   │   ├── go.json
│   │   ├── java.json
│   │   ├── python.json
│   │   └── zig.json
│   └── semantic_config.example.json    # Example config
│
├── tests/                              # Integration tests
│   ├── integration/                    # Integration tests
│   │   ├── mod.rs
│   │   ├── ir_loading_test.rs
│   │   ├── pipeline_test.rs
│   │   └── issue_verification_test.rs
│   │
│   ├── stability/                      # Stability tests
│   │   ├── mod.rs
│   │   ├── crash_free_test.rs
│   │   └── malformed_input_test.rs
│   │
│   ├── stress/                         # Stress tests
│   │   ├── mod.rs
│   │   ├── large_scale_test.rs
│   │   └── boundary_test.rs
│   │
│   ├── e2e/                            # End-to-end tests
│   │   ├── mod.rs
│   │   └── full_pipeline_test.rs
│   │
│   └── fixtures/                       # Test fixtures
│       ├── simple.c
│       ├── ffi_rust.rs
│       └── ...
│
├── benches/                            # Benchmarks
│   ├── ir_loading.rs                   # IR loading benchmark
│   ├── pass_execution.rs               # Pass execution benchmark
│   └── full_analysis.rs                # Full analysis benchmark
│
├── examples/                           # Examples
│   ├── demo_analysis.rs                # Demo analysis
│   └── custom_pass.rs                  # Custom pass example
│
├── scripts/                            # Build scripts
│   ├── install_deps.sh                 # Install dependencies
│   ├── benchmark.sh                    # Run benchmarks
│   ├── regression_test.sh              # Regression tests
│   └── release.sh                      # Release script
│
└── docs/                               # Documentation
    ├── ARCHITECTURE.md                 # Architecture doc
    ├── DEPENDENCIES.md                 # Dependencies doc
    ├── IMPLEMENTATION_PLAN.md          # Implementation plan
    └── api/                            # API documentation
        └── ...
```

## 🔧 模块依赖关系图

```
omniscope-cli
    ├── omniscope-pipeline
    │   ├── omniscope-pass
    │   │   ├── omniscope-semantics
    │   │   │   ├── omniscope-dataflow
    │   │   │   │   ├── omniscope-ir
    │   │   │   │   │   └── omniscope-core
    │   │   │   │   └── omniscope-types
    │   │   │   └── omniscope-registry
    │   │   └── omniscope-types
    │   └── omniscope-core
    └── omniscope-types
```

## 📊 模块职责划分

### 1. **omniscope-core** (基础设施)
- 错误类型定义
- 诊断系统
- Fact 存储
- 性能分析
- 内存池

### 2. **omniscope-ir** (IR 抽象)
- LLVM IR 加载
- 安全包装器
- IR 视图抽象
- 调试信息提取

### 3. **omniscope-dataflow** (数据流引擎)
- 数据流图构建
- 路径敏感分析
- 函数摘要
- 守卫传播

### 4. **omniscope-types** (类型定义)
- 所有公共类型定义
- 配置类型
- 分析结果类型

### 5. **omniscope-pass** (分析 Pass)
- Pass trait 定义
- Pass 管理器
- 25+ 分析 pass 实现

### 6. **omniscope-semantics** (语义分析)
- 语言检测
- 区域分类
- 噪声过滤
- 语义解析

### 7. **omniscope-registry** (函数注册表)
- 语义注册表
- 语言特定注册表
- 配置加载

### 8. **omniscope-pipeline** (流水线)
- Pass 调度
- 依赖解析
- 结果聚合

### 9. **omniscope-cli** (命令行)
- CLI 解析
- 命令处理
- 输出格式化

## 🎯 关键设计决策

### 1. **Workspace 结构**
- 使用 Cargo workspace 管理多 crate
- 每个 crate 职责单一，边界清晰
- 避免循环依赖

### 2. **错误处理策略**
- `thiserror` 定义错误类型
- `anyhow` 用于应用层错误传播
- `miette` 提供美观的错误报告

### 3. **并发策略**
- `rayon` 实现数据并行
- `dashmap` 实现并发 HashMap
- `crossbeam` 实现并发队列

### 4. **内存管理**
- `bumpalo` 实现 arena allocation
- `typed-arena` 实现类型化 arena
- 减少频繁分配/释放

### 5. **性能优化**
- `lto = "fat"` 启用完整 LTO
- `codegen-units = 1` 优化整个 crate
- `strip = true` 减小二进制大小

## 📈 预期代码量

| 模块 | 预估代码行数 | 说明 |
|------|-------------|------|
| omniscope-core | ~3,000 | 基础设施 |
| omniscope-ir | ~5,000 | IR 抽象 |
| omniscope-dataflow | ~8,000 | 数据流引擎 |
| omniscope-types | ~6,000 | 类型定义 |
| omniscope-pass | ~45,000 | 分析 pass (最大) |
| omniscope-semantics | ~12,000 | 语义分析 |
| omniscope-registry | ~8,000 | 注册表 |
| omniscope-pipeline | ~4,000 | 流水线 |
| omniscope-cli | ~5,000 | CLI |
| **总计** | **~96,000** | 比 Zig 版本多 ~20% |

## 🚀 构建命令

```bash
# 开发构建
cargo build

# Release 构建 (优化)
cargo build --release

# 运行测试
cargo test

# 运行基准测试
cargo bench

# 文档生成
cargo doc --open

# 代码格式化
cargo fmt

# 代码检查
cargo clippy

# 运行分析
cargo run -- analyze input.ll

# 运行审计
cargo run -- audit --lang rust input.ll
```

## 📦 发布流程

```bash
# 1. 运行所有测试
cargo test --all

# 2. 运行 clippy 检查
cargo clippy --all-targets --all-features -- -D warnings

# 3. 格式化代码
cargo fmt --all -- --check

# 4. 构建发布版本
cargo build --release

# 5. 生成文档
cargo doc --no-deps

# 6. 发布到 crates.io
cargo publish
```
