# OmniScope-rs Code Review — 潜在 BUG 清单

> 审计日期: 2026-05-30 | 审计范围: 全部 8 个 crate + LLVM C++ Pass

---

## BUG-1: FCmp 误分类为 Icmp [严重]

**位置:** `crates/omniscope-ir/src/llvm_sys_adapter.rs:477`

**问题:**
```rust
LLVMOpcode::LLVMFCmp => Some(IRInstructionKind::Icmp),
```
浮点比较指令 `FCmp` 被映射为 `IRInstructionKind::Icmp`（整数比较）。这会导致下游所有基于 `Icmp` 类型的分析（如 null-check 检测、条件释放模式匹配）在浮点比较指令上产生误报或漏报。

**影响:** FFI return check 会将浮点 null 比较识别为安全 null check，可能导致 use-after-null-check 漏报。

**修复:**
```rust
LLVMOpcode::LLVMFCmp => Some(IRInstructionKind::FCmp),  // 新增 FCmp 变体
```

---

## BUG-2: 并行模式下 PassContext 数据丢失 [严重]

**位置:** `crates/omniscope-pass/src/manager.rs:157-162`

**问题:**
```rust
.map(|idx| {
    let pass = &self.passes[idx];
    let mut local_ctx = PassContext::new(); // ← 空上下文！
    ...
})
```
并行模式下，同依赖级别的每个 pass 以空 `PassContext` 启动。同级别 pass 无法访问上一级别 pass 产生的数据（如 `contract_graph`、`ownership_states`）。merge 操作只在同级别所有 pass 完成后才将结果写回主上下文，但下一级别的 pass 又以新空上下文启动。

**影响:** 并行模式下所有 pass 链式分析完全失效。实际上只有 `RawFactCollector`（无依赖）能正常工作，其他 pass 都读不到上游数据。

**修复:** `local_ctx` 应从主 `ctx` 继承已有数据，或并行模式禁止 pass 间数据依赖。

---

## BUG-3: PathSensitiveLeakPass 实际未做路径分析 [严重]

**位置:** `crates/omniscope-pass/src/resource/path_sensitive_leak.rs`

**问题:**
定义了完整的 `LeakPath`、`PathAnalysisResult`、`PathAnalysisResult::leak_confidence()` 等路径敏感分析基础设施，但 `run()` 方法从未使用它们。实际逻辑仅是简单的 `check_release_in_facts()` + `check_release_in_summaries()` 存在性检查，根本不是路径敏感的。报错信息也自称为 "path-sensitive"，"allocation has no same-family release on any analyzed path"，但实际没有分析任何路径。

**影响:** ConditionalLeak 检测不具备路径敏感能力，无法区分"所有路径都泄漏"和"部分路径泄漏"。

**修复:** 实现真正的 CFG 路径遍历，或重命名 pass 去除 "PathSensitive" 前缀。

---

## BUG-4: Evidence 缺少 escape 字段导致 `has_escape_evidence` 永远返回 false [严重] [已勘误]

> **⚠️ 勘误 (2026-05-30):** 此 BUG 为**误报**。`Evidence` 结构体在 `crates/omniscope-types/src/evidence.rs:98` 确实有 `pub escape: Option<EscapeKind>` 字段。`e.escape.is_some()` 是合法的 Rust 代码。保留此条目作为审计记录。

**位置:** `crates/omniscope-pass/src/resource/issue_verifier.rs:308-313`

**原始问题(已确认是误报):**
```rust
fn has_escape_evidence(candidate: &IssueCandidate, kind: EvidenceKind) -> bool {
    candidate.evidence.iter().any(|e| e.kind == kind && e.escape.is_some())
}
```
`Evidence` 结构体定义在 `evidence.rs:85-104`，字段包括 `escape: Option<EscapeKind>`。`e.escape.is_some()` 能够正常编译和运行。无修复必要。

---

## BUG-13: ContractGraphBuilder 函数 ID 空间与 RawFactCollector 不连续 [中]

**位置:**
- `crates/omniscope-pass/src/resource/raw_fact_collector.rs:67-68`
- `crates/omniscope-pass/src/resource/contract_graph_builder.rs:213`

**问题:**
RawFactCollector 从 `0` 开始分配函数 ID，ContractGraphBuilder 在扫描 IRModule 时从 `1` 开始分配自己的函数 ID。当同一函数在 RawFactCollector 生成的 fact 中有 ID `X`，在 ContractGraphBuilder 的 IR 扫描中又有 ID `Y`，会产生同一个函数对应两个不同 ID，可能导致 edges 分组错误。

**影响:** 跨 pass 的函数级聚合分析可能产生不一致结果。

---

## BUG-14: Evidence 字段名不一致 [低] [已勘误]

> **⚠️ 勘误 (2026-05-30):** 与 BUG-4 同为误报。`Evidence.escape` 字段确实存在。此条目可忽略。

---

## BUG-15: C++ LLVM Pass 中内存泄漏 [低]

**位置:** `pass/SafetyExportPass.cpp`

**问题:** 需要检查 `SafetyExportPass.cpp` 中 LLVM 对象的 RAII 管理。`llvm::json::Value` 的使用是否正确处理了所有 LLVM 类型引用，以及 LLVM pass 插件在卸载时是否释放了所有分配的资源。

---

## BUG-16: Platform Filters 未应用 [低]

**位置:** 所有 analysis passes

**问题:** 项目根目录存在 `platform_filters.toml`，表明设计上有平台过滤机制。但所有分析 pass 的 `run()` 方法中均未读取或使用该配置。跨平台差异（如 Windows 调用约定、类型大小差异）未被考虑。

---

## BUG-17: `classify_opcode` 在 ir_model 与 instruction_parser 之间不一致 [高] (回归)

**位置:** `crates/omniscope-ir/src/ir_model.rs:414`

**问题:**
本次 diff 修改了 `instruction_parser.rs:262` 和 `llvm_sys_adapter.rs:477`，将 `fcmp` 映射为 `IRInstructionKind::Fcmp`。但 `ir_model.rs:classify_opcode()` 仍保持 `"fcmp" => IRInstructionKind::Icmp`。

```rust
// ir_model.rs:414 — 未更新
"icmp" | "fcmp" => IRInstructionKind::Icmp,
```

**影响:**
1. `IRInstructionModel::to_ir_instruction()` (ir_model.rs:354) 对 `fcmp` 指令返回 `Icmp` 而不是 `Fcmp`，与 instruction_parser 的结果不一致。
2. 测试 `ir_model_tests.rs:553` 和 `plan_a_c_integration.rs:782` 期望 `("fcmp", IRInstructionKind::Icmp)`，与新的 parser 行为矛盾。
3. 下游代码同时使用两种 parser 路径时，同一 `fcmp` 指令可能被赋予不同的 `IRInstructionKind`，导致 `kind` 匹配分析结果不一致。

**修复:** `classify_opcode` 的第 414 行改为 `"icmp" => IRInstructionKind::Icmp, "fcmp" => IRInstructionKind::Fcmp,`，并更新对应的测试用例。

---

## BUG-18: `to_ir_instruction` 在 `classify_opcode` 修复后会丢失 fcmp 的 icmp_pred [中] (潜在)

**位置:** `crates/omniscope-ir/src/ir_model.rs:371-376`

**问题:**
```rust
let icmp_pred = if kind == IRInstructionKind::Icmp {
    extract_icmp_pred_from_raw(&self.raw)
} else {
    None
};
```
当 `classify_opcode` 修复（BUG-17）后返回 `Fcmp` 时，`kind != Icmp`，因此 `extract_icmp_pred_from_raw` 不会执行，icmp_pred 为 `None`。但 `fcmp` 指令的浮点比较谓词（oeq, olt, ord, uno 等）对 null-check 检测很重要。

**影响:** 仅影响通过 `IRInstructionModel::to_ir_instruction()` 路径处理 fcmp 的代码。instruction_parser.rs 路径 call `extract_icmp_pred` 不受影响。ffi_return_check.rs 已正确处理 `Icmp | Fcmp` 分支。

---

## BUG-19: CallGraphPass / SurfaceClassifierPass / DangerSurfacePass 未注册到 Pipeline [严重]

**位置:** `crates/omniscope-pipeline/src/pipeline.rs:56-73`

**问题:**
3 个完全实现的 Pass 结构体（实现 `Pass` trait，含完整的 `run()` 实现）**从未**在 `Pipeline::register_default_passes()` 中注册：

| Pass | 文件位置 | 功能 |
|------|---------|------|
| `CallGraphPass` | `crates/omniscope-pass/src/analysis/call_graph.rs:27` | 构建调用图、检测跨语言边界 |
| `SurfaceClassifierPass` | `crates/omniscope-pass/src/analysis/surface_classifier_pass.rs:24` | L1+L2+L3 函数表面分类 |
| `DangerSurfacePass` | `crates/omniscope-pass/src/analysis/danger_surface.rs:22` | 危险表面分析 |

**影响链:**
```
CallGraphPass 未注册
  → cross_lang_edges 始终为空
  → SurfaceClassifierPass 的 L3 升级 (第84-117行) 永远收不到 FFI 边界数据
  → function_surfaces 缺少 Boundary 分类
  → NoiseReduction 的 SRT 层 (should_suppress_by_srt) 无有效输入
  
CallGraphPass 未注册
  → FFIBoundaryPass 依赖的 cross_lang_edges 为空
  → FFI 边界检测退化到 name-based 启发式
```

**影响:** 约 30% 的 pass 功能是死代码。Pipeline 在 `test_pipeline_with_default_passes` 中断言 `pass_count() == 11`，加上这 3 个 pass 后应为 14。

---

## BUG-20: NoiseReduction 是生产环境死代码 [中]

**位置:** `crates/omniscope-pass/src/analysis/noise_reduction.rs`

**问题:**
`NoiseReduction` 提供了两层 FP 抑制机制：
- `should_suppress()` — 字符串匹配快速预滤
- `should_suppress_by_srt()` — SRT 语义判别

但这两方法**在 production 代码路径中从未被调用**。仅在测试和基准测试中使用。

`grep` 确认：所有 `NoiseReduction::` 调用仅在 `noise_reduction.rs` 自身的测试模块和 `analysis_passes.rs` benchmark 中出现。

**影响:** FP 抑制完全未生效。IssueGate 是唯一的 FP 拦截点，缺少 NoiseReduction 的协同。

---

## 工作树 Diff 分析 (13 个修改文件 + 1 个新增)

### 已修复的 BUG
| BUG | 状态 | 修复文件 |
|-----|------|---------|
| BUG-1 (FCmp) | ✅ 已修复 | `instruction_parser.rs`, `llvm_sys_adapter.rs` |
| BUG-2 (并行上下文) | ✅ 已修复 | `manager.rs`, `pass.rs` (Clone) |
| BUG-3 (路径敏感误称) | ✅ 已修复 | `path_sensitive_leak.rs` (更名为 LeakDetectionPass) |
| BUG-6 (write_to_immutable) | ✅ 已修复 | `write_to_immutable.rs` (遍历 function_bodies) |
| BUG-8 (check_release_in_facts) | ✅ 已修复 | `path_sensitive_leak.rs` (添加 function_name 匹配) |
| BUG-9 (wrapping_add) | ✅ 已修复 | `raw_fact_collector.rs` (改为 saturating_add) |
| BUG-10 (FFI 名称检测) | ✅ 已修复 | `ffi_return_check.rs` (允许 CamelCase) |
| BUG-11 (除法溢出) | ✅ 已修复 | `profiler.rs` (空值检查 + .max(1)) |
| BUG-12 (时间戳冲突) | ✅ 已修复 | `profiler.rs` (改用单调 ID) |

### 新增回归
| 问题 | 类型 | 详情 |
|------|------|------|
| BUG-17 | 回归 | `classify_opcode` 未更新 (见上) |
| BUG-18 | 潜在 | `to_ir_instruction` 在 Fcmp 时丢失谓词 (见上) |

### 新增文件
- `benches/bugfix_regression.rs` — 对 7 个已修复 BUG 的基准测试，确保性能无退化。使用 `IRInstructionKind::Fcmp`（正确）。

---

## 严重性汇总 (已更新)

| 严重性 | 数量 | BUG-ID |
|--------|------|--------|
| 严重 (Critical) | 4 | BUG-1, BUG-2, BUG-3, BUG-19 |
| 高 (High) | 5 | BUG-5, BUG-6, BUG-7, BUG-8, BUG-17 |
| 中 (Medium) | 6 | BUG-9, BUG-10, BUG-11, BUG-12, BUG-13, BUG-20 |
| 低 (Low) | 2 | BUG-15, BUG-16 |
| 勘误 (误报) | 2 | ~~BUG-4~~, ~~BUG-14~~ |

---

## 系统性问题

1. **Name-based 启发式分析泛滥** — 5 个分析 pass 严重依赖函数名字符串匹配来判断语义属性（堆/栈/全局、内部可变性、是否参数等）。这是最突出的系统性问题，导致所有基于 SRT 的抑制机制（R-0 到 R-8）不可靠。

2. **IR 分析与实际指令不匹配** — `WriteToImmutablePass` 曾遍历 `calls` 而非 `store` 指令（BUG-6 已修复），`llvm_sys_adapter` 映射 FCmp → Icmp（BUG-1 已修复）。但 `classify_opcode` 仍不一致（BUG-17）。

3. **并行模式不可用** — PassManager 的并行模式存在根本性的数据隔离问题（BUG-2 已修复 — `ctx.clone()` + `#[derive(Clone)]`）。

4. **Pass 注册缺失 → 大量死代码** — `CallGraphPass`、`SurfaceClassifierPass`、`DangerSurfacePass` 完全实现但从未注册到 Pipeline（BUG-19）。`NoiseReduction` 的 FP 抑制逻辑从未在生产中调用（BUG-20）。这是目前最严重的架构问题，约 30% pass 功能不可达。

5. **文档与实现不同步** — 多处函数注释描述的行为与实际代码实现不一致（BUG-8 已修复）。
