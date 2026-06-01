# OmniScope-rs 架构文档

> 内部开发者参考文档 — 非面向用户教程

---

## 1. 项目简介

OmniScope-rs 是一个基于 LLVM IR 的静态分析器，专注于跨语言 FFI（Foreign Function Interface）安全审计。它能够检测以下类别的内存安全与边界问题：

- **内存安全**：堆内存泄漏、双重释放、悬空指针、use-after-free
- **所有权违规**：跨 FFI 边界的所有权语义错误
- **逃逸分析**：借用/裸指针跨边界逃逸
- **资源追踪**：RAII 对象的 drop 路径分析

支持语言：**Rust / C / C++ / Python / Go / Java / C#**（通过各语言适配器 + LLVM IR 统一中间表示）

---

## 2. Crate 依赖图

工作区（workspace）包含 8 个 crate，依赖关系如下：

```
omniscope-cli
    │
    ├──► omniscope-pipeline
    │        │
    │        ├──► omniscope-pass
    │        │        │
    │        │        ├──► omniscope-semantics
    │        │        │        │
    │        │        │        ├──► omniscope-ir
    │        │        │        │        │
    │        │        │        │        └──► omniscope-types
    │        │        │        │
    │        │        │        ├──► omniscope-types
    │        │        │        └──► omniscope-core
    │        │        │
    │        │        ├──► omniscope-ir
    │        │        ├──► omniscope-types
    │        │        ├──► omniscope-core
    │        │        └──► omniscope-dataflow
    │        │                 │
    │        │                 ├──► omniscope-types
    │        │                 └──► omniscope-core
    │        │
    │        ├──► omniscope-ir
    │        ├──► omniscope-types
    │        └──► omniscope-core
    │
    ├──► omniscope-pipeline（同上）
    └──► omniscope-types

────────────────────────────────────────────────
叶节点（无内部依赖）：
  omniscope-types  — 纯类型定义
  omniscope-core   — Issue / Fact / MemoryPool
```

依赖层级汇总：

| 层级 | Crate | 说明 |
|------|-------|------|
| L0（叶） | `omniscope-types` | 原始类型，无任何内部依赖 |
| L0（叶） | `omniscope-core` | 诊断/事实/内存池，无内部依赖 |
| L1 | `omniscope-ir` | IR 模型与解析，仅依赖 types |
| L1 | `omniscope-dataflow` | 数据流图，依赖 types + core |
| L2 | `omniscope-semantics` | 语义引擎，依赖 ir + types + core |
| L3 | `omniscope-pass` | 分析 Pass，依赖 semantics + ir + types + core + dataflow |
| L4 | `omniscope-pipeline` | 编排 Pass，依赖 pass + ir + types + core |
| L5（根） | `omniscope-cli` | 用户入口，依赖 pipeline + types |

---

## 3. 目录结构

```
OmniScope-rs/
│
├── Cargo.toml                          # Workspace 根清单
├── platform_filters.toml              # 平台过滤配置（按目标三元组过滤 IR）
│
├── crates/
│   │
│   ├── omniscope-cli/
│   │   └── src/
│   │       ├── main.rs                # CLI 入口，clap 参数解析，调用 Pipeline
│   │       └── output/
│   │           ├── mod.rs             # 输出格式分发器（JSON / Rich / SARIF 路由）
│   │           ├── json.rs            # JSON 输出格式实现
│   │           ├── rich.rs            # 富文本终端输出（颜色/表格）
│   │           └── sarif.rs           # SARIF 2.1.0 静态分析结果格式输出
│   │
│   ├── omniscope-pipeline/
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── pipeline.rs            # Pipeline 结构体，注册并运行所有默认 Pass
│   │       └── result.rs             # PipelineResult：汇总所有 Pass 输出
│   │
│   ├── omniscope-pass/
│   │   └── src/
│   │       ├── pass.rs               # Pass trait、PassContext（共享状态）、PassResult
│   │       ├── manager.rs            # PassManager：拓扑排序依赖，顺序执行 Pass
│   │       │
│   │       ├── analysis/
│   │       │   ├── mod.rs            # FFIBoundaryPass（主要 FFI 检测入口）
│   │       │   ├── borrow_escape.rs  # 借用逃逸检测
│   │       │   ├── call_graph.rs     # 调用图构建与分析
│   │       │   ├── danger_surface.rs # 危险接触面识别
│   │       │   ├── heap_provenance.rs # 堆内存来源追踪
│   │       │   ├── interior_mutability.rs  # 内部可变性分析（Cell/RefCell/Mutex）
│   │       │   ├── noise_reduction.rs      # 误报抑制与噪声过滤
│   │       │   ├── raii_drop.rs            # RAII drop 路径分析
│   │       │   ├── surface_classifier_pass.rs  # 调用 semantics 的边界分类 Pass
│   │       │   └── write_to_immutable.rs  # 写入不可变内存检测
│   │       │
│   │       └── resource/
│   │           ├── contract_graph_builder.rs      # 构建 ContractGraph（资源边图）
│   │           ├── ownership_solver.rs             # 在 ContractGraph 上传播所有权状态
│   │           ├── issue_candidate_builder/        # 从 ResourceInstance 构建候选问题
│   │           ├── issue_gate.rs                  # SRT gate，R-0~R-8 suppressions
│   │           ├── issue_verifier.rs              # 验证并分级候选问题（转为正式 Issue）
│   │           ├── raw_fact_collector.rs          # 从 IR 指令序列收集原始事实
│   │           ├── ir_behavior_summary_pass.rs    # 提取函数行为摘要
│   │           ├── structural_inference_pass.rs   # 结构推断 Pass
│   │           ├── summary_builder.rs             # 构建函数 ResourceSummary
│   │           ├── ffi_return_check.rs            # FFI 返回值安全检查
│   │           ├── path_sensitive_leak.rs         # 路径敏感的泄漏检测
│   │           ├── risk_scoring.rs                # 问题风险分级打分
│   │           ├── rust_drop_tracker.rs           # Rust drop glue 追踪
│   │           └── union_find.rs                  # Union-Find（用于别名集合合并）
│   │
│   ├── omniscope-semantics/
│   │   └── src/
│   │       ├── language_detector.rs              # 加权投票语言识别（从 IR 符号推断源语言）
│   │       ├── surface_classifier.rs             # 函数边界分类（Safe / Boundary / Internal）
│   │       └── resource/
│   │           ├── semantic_engine.rs            # FFI 安全评估核心，assess_ffi_safety
│   │           ├── semantic_tree/                # SRT（语义解析树），存储 R-0~R-8 标签
│   │           ├── structural_inference/         # 结构推断（drop glue/into_raw/POSIX/库函数对）
│   │           ├── ffi_contract/                 # FFI 函数契约数据库（OpenSSL/SQLite/JNI 等）
│   │           ├── family_registry.rs            # ResourceFamily 注册表（全局单例）
│   │           ├── family_inference.rs           # 从函数名推断 FamilyId
│   │           ├── ir_pattern.rs                 # BehaviorPattern：从指令序列提取行为模式
│   │           ├── cross_function_lifetime.rs    # 跨函数生命周期追踪
│   │           ├── confidence_scorer.rs          # 问题置信度打分
│   │           ├── ownership_state.rs            # ResourceInstance 状态机（Owned/Borrowed/…）
│   │           ├── escape.rs                     # Escape 分类（Stack/Heap/FFI/Return 等）
│   │           ├── summary.rs                    # ResourceSummary + SummaryStore
│   │           ├── summary_inference.rs          # 从行为推断 ResourceSummary
│   │           ├── *_adapter/                    # Python / Go / C++ / C# / Java 语言适配器
│   │           ├── rust_stdlib_whitelist/        # Rust 标准库白名单（trie 结构）
│   │           └── allocator_shim.rs             # 分配器 shim（对齐跨语言堆分配语义）
│   │
│   ├── omniscope-ir/
│   │   └── src/
│   │       ├── ir_model.rs           # IRModule / IRFunction / IRBasicBlock / IRInstruction 模型
│   │       ├── parser.rs             # 文本 LLVM IR 解析器（Plan B 路径）
│   │       ├── loader_v2.rs          # IRModule 加载器（JSON Plan A 优先，降级到 Plan B）
│   │       ├── instruction_parser.rs # 单条指令文本解析
│   │       ├── location.rs           # 源码位置信息（文件/行/列）
│   │       ├── platform.rs           # 平台信息（ABI、目标三元组）
│   │       └── llvm_sys_adapter.rs   # 可选 llvm-sys 后端适配器（feature-gated）
│   │
│   ├── omniscope-types/
│   │   └── src/
│   │       ├── effect.rs             # Effect 枚举（资源操作原语：Alloc/Free/Borrow/…）
│   │       ├── pointer_contract.rs   # PointerContract（所有权语义合约）
│   │       ├── resource_family.rs    # FamilyId + ResourceFamily（资源族定义）
│   │       ├── config.rs             # AnalysisConfig（全局分析配置）
│   │       ├── escape.rs             # EscapeKind（逃逸种类枚举）
│   │       ├── evidence.rs           # Evidence（支撑 Issue 的证据链）
│   │       └── call_graph_types.rs   # FunctionId + CallEdge（调用图基础类型）
│   │
│   ├── omniscope-core/
│   │   └── src/
│   │       ├── issue.rs              # Issue + IssueKind + IssueLocation（最终输出单元）
│   │       ├── diagnostics.rs        # Diagnostic + Severity（诊断信息与严重级别）
│   │       ├── fact.rs               # Fact（Pass 间原始事实传递载体）
│   │       ├── issue_candidate.rs    # IssueCandidate（待验证候选问题）
│   │       ├── memory_pool.rs        # bumpalo 内存池封装
│   │       └── risk_score.rs         # RiskScore（风险分值类型）
│   │
│   └── omniscope-dataflow/
│       └── src/
│           ├── graph.rs              # 数据流图（DataflowGraph：节点/边/格结构）
│           └── analysis.rs          # 数据流分析算法（不动点迭代）
│
├── tests/                            # 集成测试（跨 crate 端到端测试）
├── benches/                          # Criterion 性能基准
└── docs/                             # 开发者文档（含本文件）
```

---

## 4. 两条 IR 加载路径

`omniscope-ir` 支持两种加载方式，由 `loader_v2.rs` 统一调度：

### Plan A — JSON（优先路径）

```
C++ LLVM Pass（编译期插件）
        │
        │  生成 JSON 序列化的 IR 结构
        ▼
  *.ir.json 文件
        │
        │  IRModuleModel::from_json_str()
        ▼
  IRModuleModel（中间序列化模型）
        │
        │  Into<IRModule>（类型转换）
        ▼
    IRModule（内存中统一 IR 表示）
```

- **优点**：保留完整类型信息、调试信息（DWARF）、语言元数据；解析速度快
- **适用场景**：与 clang/rustc 构建集成的 CI 流水线

### Plan B — 文本 `.ll`（降级路径）

```
  *.ll 文件（LLVM IR 文本格式）
        │
        │  parser.rs（手写递归下降解析器）
        │  instruction_parser.rs（逐条指令解析）
        ▼
    IRModule（内存中统一 IR 表示）
```

- **优点**：无需 C++ LLVM Pass，可直接处理 `llvm-dis` 输出；适合离线/单文件分析
- **限制**：部分元数据（调试符号、语言标签）可能缺失，影响语言识别准确率

### 加载优先级

`loader_v2.rs` 按以下顺序决定加载路径：

```
输入路径
    │
    ├─ 存在对应 .ir.json 文件？ ──是──► Plan A（JSON 加载）
    │
    └─ 否 ──────────────────────────► Plan B（文本解析）
```

两条路径最终均产出相同的 `IRModule` 结构，下游 Pass 无需感知来源差异。

---

## 5. 关键数据流（端到端）

```
CLI 参数（文件路径 / 配置）
        │
        ▼
   Pipeline::run()
        │
        ├──► loader_v2（IR 加载，Plan A 或 Plan B）
        │          │
        │          └──► IRModule
        │
        ├──► PassManager（拓扑顺序执行 Pass）
        │          │
        │          ├── SurfaceClassifierPass
        │          │       └── language_detector + surface_classifier
        │          │
        │          ├── IRBehaviorSummaryPass
        │          │       └── ir_pattern + family_inference
        │          │
        │          ├── StructuralInferencePass
        │          │       └── structural_inference + ffi_contract
        │          │
        │          ├── FFIBoundaryPass
        │          │       └── semantic_engine::assess_ffi_safety
        │          │           └── SRT（R-0~R-8 标签）
        │          │
        │          ├── ContractGraphBuilder + OwnershipSolver
        │          │       └── ContractGraph（资源边图 + 所有权传播）
        │          │
        │          ├── IssueCandidateBuilder
        │          │       └── ResourceInstance 状态机 → IssueCandidate
        │          │
        │          └── IssueGate + IssueVerifier
        │                  └── SRT suppressions → Issue（最终输出）
        │
        └──► PipelineResult
                   │
                   ▼
           OutputFormatter（JSON / Rich / SARIF）
```

---

*文档版本：内部草稿 — 与代码同步更新*
