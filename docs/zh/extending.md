# OmniScope-rs 扩展指南

本文档面向希望扩展 OmniScope-rs 的开发者，涵盖添加新的分析 Pass、FP 抑制规则、语言适配器、FFI 契约库、FamilyId 扩展、输出格式以及 SemanticEngine 优化等内容。

---

## 1. 添加新的分析 Pass

分析 Pass 是 OmniScope 流水线的基本单元。所有静态分析逻辑都组织并调度为 Pass。

### 1.1 选择放置位置

Pass 源文件位于 `crates/omniscope-pass/src/` 下：

- `analysis/` — FFI 边界识别、函数表面分类、结构分析 Pass
- `resource/` — 资源契约验证、所有权状态跟踪、分配/释放配对

### 1.2 实现 Pass trait

每个 Pass 必须实现 `Pass` trait：

- `name() -> &'static str` — 唯一字符串标识符（用作拓扑排序键）
- `kind() -> PassKind` — `Foundation`、`Analysis` 或 `Transformation`
- `dependencies() -> Vec<&'static str>` — 此 Pass 依赖的其他 Pass 名称
- `run(&self, ctx: &mut PassContext) -> Result<PassResult>` — 核心逻辑

在 `run()` 中：
- 读取上游输出：`ctx.get::<T>("key")`
- 发出 Issue：**必须**使用 `ctx.emit_issue(issue)`，切勿直接推送到 `ctx.issues`（这会绕过 SRT 门控）

### 1.3 导出并注册

1. 在 `crates/omniscope-pass/src/lib.rs` 中添加 `pub use`
2. 在 `crates/omniscope-pipeline/src/pipeline.rs` 的 `register_default_passes()` 中添加注册

## 2. 添加新的 R-N FP 抑制规则

FP 抑制系统基于 SRT（语义解析树）门控。

### 2.1 扩展 SemanticKind

在 `crates/omniscope-semantics/src/resource/semantic_tree/kind.rs` 添加新变体。

### 2.2 扩展 GateVerdict

在 `crates/omniscope-pass/src/resource/issue_gate.rs` 添加对应的 `Suppress*` 变体。

### 2.3 添加抑制条件

在 `issue_gate::check_issue()` 中添加匹配分支，将 `IssueKind` + `SemanticKind` 组合映射到新判定。

### 2.4 实现结构推断

在 `crates/omniscope-semantics/src/resource/structural_inference/` 中添加推断函数，遵循 `infer_<pattern>_summary()` 命名约定。

### 2.5 接入 StructuralInferencePass

在 `StructuralInferencePass::run()` 中调用新的推断函数。

## 3. 添加新的语言适配器

语言适配器将语言特定的 FFI 约定桥接到 OmniScope 的统一分析框架。现有适配器（Python、Go、C++、C#、Java）位于 `crates/omniscope-semantics/src/resource/<lang>_adapter/`。

步骤：
1. 在 `resource/` 下创建适配器目录
2. 实现语言特定逻辑（名称修饰、分配器语义、FamilyId 映射）
3. 在 `FamilyRegistry::new()` 中注册符号
4. 在 `LanguageDetector::build_patterns()` 中添加模式
5. 在 `crates/omniscope-semantics/src/lib.rs` 中导出适配器

## 4. 添加新的 FFI 契约库

FFI 契约数据库位于 `crates/omniscope-semantics/src/resource/ffi_contract/`，记录已知 C 库的所有权语义。

步骤：
1. 在 `ffi_contract/builtin/` 中创建契约文件
2. 为每个函数定义 `FFIContract` 条目
3. 在 `ffi_contract/builtin/mod.rs` 中注册
4. 在 `FamilyRegistry` 中添加对应的 `FamilyId` 和符号

## 5. 扩展 FamilyId

`FamilyId` 是一个 `u16` 包装。内置 ID 范围为 1 到 24（当前代码库）。用户定义家族从 `USER_FAMILY_START = 256` 开始。

```rust
// 在 crates/omniscope-types/src/resource_family.rs 中
pub const CUSTOM_FAMILY: FamilyId = FamilyId(25); // 下一个可用 ID
```

然后在 `crates/omniscope-semantics/src/resource/family_registry.rs` 中注册该家族。

## 6. PassContext KV 键约定

`PassContext.shared` 使用字符串键控的类型擦除存储。已建立的键：

| 键 | 类型 | 写入者 | 读取者 |
|---|---|---|---|
| `"contract_graph"` | `ContractGraph` | ContractGraphBuilderPass | OwnershipSolverPass |
| `"summary_store"` | `SummaryStore` | SummaryBuilderPass | ContractGraphBuilderPass |
| `"ownership_states"` | `Vec<ResourceInstance>` | OwnershipSolverPass | IssueCandidateBuilderPass、LeakDetectionPass |
| `"issue_candidates"` | `Vec<IssueCandidate>` | IssueCandidateBuilderPass | IssueVerifierPass |
| `"behavior_summaries"` | `HashMap<String, FunctionBehavior>` | IRBehaviorSummaryPass | SummaryBuilderPass |
| `"structural_summaries"` | `Vec<ResourceSummary>` | StructuralInferencePass | ContractGraphBuilderPass |
| `"semantic_tree"` | `SemanticTree` | 多个 Level 1 Pass | IssueVerifierPass、issue_gate |
| `"surface_map"` | `HashMap<String, FunctionSurface>` | SurfaceClassifierPass | DangerSurfacePass、FFIBoundaryPass |
| `"call_graph"` | `CallGraph` | CallGraphPass | FFIBoundaryPass、SurfaceClassifierPass |
| `"raw_facts"` | `Vec<RawResourceFact>` | RawFactCollectorPass | 多个下游 Pass |
| `"module_index"` | `ModuleIndex` | PassManager | FFIBoundaryPass、LanguageAdapterFactPass |
| `"boundary_context"` | `BoundaryContext` | PassManager | IssueVerifierPass、IssueCandidateBuilderPass |
| `"cross_lang_edges"` | `Vec<CrossLangEdge>` | CallGraphPass | FFIBoundaryPass、SurfaceClassifierPass、DangerSurfacePass |
| `"srt_resolutions"` | `HashMap<String, Vec<SemanticKind>>` | StructuralInferencePass | PassContext::emit_issue（SRT 门控） |

## 7. 添加新的输出格式

输出格式化器位于 `crates/omniscope-cli/src/output/`。

步骤：
1. 在新文件中实现格式化函数（例如 `html.rs`）
2. 在 `output/mod.rs` 中添加格式变体
3. 在 `crates/omniscope-cli/src/main.rs` 中添加 CLI 参数

## 8. 扩展 SemanticEngine 的 FFIVerdict

`FFIVerdict` 在 `crates/omniscope-semantics/src/resource/semantic_engine.rs` 中。

步骤：
1. 为 `FFIVerdict` 添加新变体
2. 为新变体实现 `safety_score()` 和 `is_safe()`
3. 在 `assess_ffi_safety()` 中添加识别逻辑
4. 更新 `crates/omniscope-pass/src/analysis/mod.rs` 中所有 `FFIVerdict` 匹配分支

## 常见陷阱

1. **直接操作 `ctx.issues`** 会绕过 SRT 门控 — 始终使用 `ctx.emit_issue()`
2. **混淆 `ConditionalRelease` 和 `Release`** 会在 OwnershipSolver 中导致大量 UAF 假阳性
3. **忘记在 `register_default_passes()` 中注册 Pass** 会导致静默失败 — Pass 永远不会被执行
4. **KV 键拼写错误** 在 `ctx.get::<T>("key")` 中会静默返回 `None`
5. **`FamilyId(0)` 无效** 但不会 panic — 它会静默失败所有家族相关检查