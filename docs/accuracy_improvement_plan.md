# OmniScope Accuracy Improvement Plan

> 基于当前评测结果制定：TP=4、FP=9、FN=16、Precision=30.8%、Recall=20.0%、F1=24.2%。

---

## 1. 当前结论

当前 OmniScope 在 `DoubleFree` 上已有可用能力，但跨语言内存安全问题召回不足，且 `WriteToImmutable` 在 Zig runtime 内部产生较多噪音。

### 指标基线

| 指标 | 数值 |
|------|------|
| TP（真阳性） | 4 |
| FP（假阳性） | 9 |
| FN（假阴性） | 16 |
| Precision（精确率） | 4/13 = 30.8% |
| Recall（召回率） | 4/20 = 20.0% |
| F1 Score | 24.2% |

### 关键发现

1. `DoubleFree` 检测表现较好，已能命中 `zig_main.bc` 中的 double-free。
2. 内存泄漏检测有限，目前更容易报 `ConditionalLeak`，明确泄漏召回不足。
3. FFI 边界问题召回不足，跨语言释放、非法释放借用指针等未充分检测。
4. `WriteToImmutable` 噪音严重，大量误报来自 Zig runtime 内部 store。

---

## 2. 目标

### 短期目标

- 将 FP 从 9 降到 3 以下，优先压制 Zig runtime 的 `WriteToImmutable` 噪音。
- 将 FN 从 16 降到 8 以下，优先补跨语言释放、非法释放借用指针、明确泄漏。

### 中期目标

- 增加文件描述符/句柄类资源泄漏检测。
- 将资源检测从 heap-only 扩展到 `FILE_DESCRIPTOR` / library resource / allocator-vtable resource。

### 验收目标

| 指标 | 目标 |
|------|------|
| Precision | ≥ 60% |
| Recall | ≥ 50% |
| F1 Score | ≥ 55% |

---

## 3. 现有代码基础

当前代码已经具备资源分析主链路，后续开发应优先复用现有结构，而不是另起一套 detector。

### 核心链路

```text
RawFactCollector
    → ContractGraphBuilder
    → OwnershipSolver
    → IssueCandidateBuilder
    → IssueVerifier
    → PipelineResult / OutputFormatter
```

### 关键文件

| 文件 | 当前职责 |
|------|----------|
| `crates/omniscope-types/src/resource_family.rs` | `FamilyId` / `ResourceFamily`，定义资源族与兼容关系 |
| `crates/omniscope-core/src/issue.rs` | `IssueKind`，定义最终输出的问题类型 |
| `crates/omniscope-pass/src/resource/raw_fact_collector.rs` | 从 IR/module index 收集 alloc/free/resource 原始事实 |
| `crates/omniscope-pass/src/resource/contract_graph_builder.rs` | 将 raw facts 转换为资源契约图 |
| `crates/omniscope-pass/src/resource/ownership_solver.rs` | 在契约图上求解资源实例状态 |
| `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs` | 从状态和边生成候选问题 |
| `crates/omniscope-pass/src/resource/issue_verifier.rs` | 将候选问题验证并映射成 `Issue` |
| `crates/omniscope-pass/src/analysis/write_to_immutable.rs` | 检测不可变内存写入，也是当前主要 FP 来源 |
| `crates/omniscope-pass/src/module_index.rs` | 预计算函数分类、语言识别、资源族查找等缓存 |

---

## 4. 数据结构改动计划

### 4.1 Resource Family

修改文件：`crates/omniscope-types/src/resource_family.rs`

任务：

- 新增 `FamilyId::FILE_DESCRIPTOR`。
- 可选新增 `FamilyId::POSIX_FILE`，用于 `fopen/fclose` 这类 `FILE*`。
- 注册 acquire/release 规则：
  - acquire: `open`, `creat`, `socket`, `accept`, `dup`, `pipe`
  - release: `close`
- 明确 Zig allocator family 的兼容关系，避免无法识别时默认落到 `C_HEAP`。

### 4.2 RawResourceFact

修改文件：`crates/omniscope-pass/src/resource/raw_fact_collector.rs`

建议扩展字段：

```rust
pub struct RawResourceFact {
    pub function: u64,
    pub function_name: String,
    pub caller_name: String,
    pub family: Option<FamilyId>,
    pub is_acquire: bool,
    pub contract: PointerContract,
    pub arg_index: Option<usize>,

    // proposed
    pub value_id: Option<u64>,
    pub return_value: Option<String>,
    pub language: Option<Language>,
    pub is_runtime_internal: bool,
    pub confidence: f32,
}
```

目的：

- 让后续图构建知道“谁分配、谁释放、释放哪个参数、是否 runtime 内部调用”。
- 支持 borrowed pointer free、fd leak、allocator mismatch 等更细粒度判断。

### 4.3 ContractGraph Edge Metadata

修改文件：`crates/omniscope-pass/src/resource/contract_graph_builder.rs`

任务：

- 在 edge 上补足或新增：
  - `caller_language`
  - `callee_language`
  - `boundary_kind`
  - `runtime_scope`
  - `confidence`
- 将 acquire/release 通过 `value_id`、返回值、参数索引或启发式别名连接到同一资源实例。

### 4.4 Issue Candidate Kind

修改文件：`crates/omniscope-types/src/evidence.rs`

建议新增或细分候选：

- `InvalidBorrowedFree`
- `DefiniteLeak`
- `FileDescriptorLeak`

说明：最终 `IssueKind` 可以先复用现有类型：

- `InvalidBorrowedFree` → `IssueKind::InvalidFree` 或 `IssueKind::OwnershipViolation`
- `DefiniteLeak` → `IssueKind::MemoryLeak`
- `FileDescriptorLeak` → 短期映射 `IssueKind::MemoryLeak`，长期可新增 `ResourceLeak`

---

## 5. 具体开发任务

## Task 1：建立可重复评测基线

优先级：P0

修改/新增文件：

- `tests/corpus_detection_audit.rs`
- `tests/accuracy_regression.rs`
- 可选：`tests/fixtures/accuracy_expectations.json`

任务：

1. 将当前 TP/FP/FN 样本固化成 golden expectations。
2. 每个 fixture 标注 expected issue：`kind`、函数名、资源族、是否 runtime noise。
3. 输出 TP/FP/FN/Precision/Recall/F1。
4. 加回归阈值：Precision 不低于 30.8%，Recall 不低于 20.0%。

验收：

- `cargo test accuracy_regression` 能稳定输出当前指标。
- 后续 detector 改动可以量化是否改善。

---

## Task 2：压制 Zig `WriteToImmutable` 噪音

优先级：P0

修改/新增文件：

- `crates/omniscope-pass/src/analysis/write_to_immutable.rs`
- `crates/omniscope-pass/src/module_index.rs`
- 新增 `crates/omniscope-pass/src/analysis/runtime_filter.rs`

任务：

1. 增加 runtime/internal 过滤：识别 Zig 标准库、编译器生成函数、allocator/runtime 初始化路径。
2. 基于 debug path、mangled name、caller/callee 前缀识别 runtime glue。
3. 在 `ModuleIndex` 缓存 `is_runtime_internal`，避免每个 pass 重复字符串判断。
4. `WriteToImmutablePass` 对 runtime internal store 默认 suppress 或降置信度。

候选规则：

- debug path 包含 Zig stdlib/runtime 路径。
- 函数名属于 `std.*`、`builtin`、`compiler_rt`、Zig allocator/runtime glue。
- store 目标来自 runtime global 或 allocator internal state。

测试：

- Zig runtime 内部 store 不应报 `WriteToImmutable`。
- 用户代码对真正 immutable memory 的 store 仍应报。

验收：

- FP 从 9 显著下降。
- `WriteToImmutable` 不再主导误报列表。

---

## Task 3：增强跨语言释放检测

优先级：P0/P1

修改文件：

- `crates/omniscope-pass/src/resource/raw_fact_collector.rs`
- `crates/omniscope-pass/src/resource/contract_graph_builder.rs`
- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs`
- `crates/omniscope-pass/src/resource/issue_verifier.rs`
- `crates/omniscope-types/src/resource_family.rs`

任务：

1. 补全 alloc/free 函数识别：
   - C: `malloc`, `calloc`, `realloc`, `free`
   - Rust: `__rust_alloc`, `__rust_dealloc`, `Box::into_raw`, `Box::from_raw`
   - C++: `operator new`, `operator delete`, `new[]`, `delete[]`
   - Zig: allocator vtable alloc/free/realloc
   - Go/cgo: `_cgo_allocate`, `_cgo_free`, `_Cfunc_*`
2. 记录 release 参数索引。
3. 通过资源族兼容关系判断 allocator mismatch。
4. FFI 边界上 family mismatch 时生成 `CrossLanguageFree`。
5. 非 FFI 场景 family mismatch 时保留 `CrossFamilyFree`。

验收：

- 能检测 Rust alloc + C free、C malloc + Rust dealloc、Zig allocator mismatch 等场景。
- 不把兼容 family 的释放误报为 cross-language free。

---

## Task 4：检测非法释放借用指针

优先级：P0

修改文件：

- `crates/omniscope-types/src/evidence.rs`
- `crates/omniscope-pass/src/resource/ownership_solver.rs`
- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs`
- `crates/omniscope-pass/src/resource/issue_verifier.rs`

任务：

1. 在候选层新增或标记 `InvalidBorrowedFree`。
2. `OwnershipSolver` 中，当 `PointerContract::Borrowed` 遇到 `Effect::Release`，标记异常状态或记录 evidence。
3. `IssueCandidateBuilder` 中，如果 borrowed instance 出现 release edge，生成候选。
4. `IssueVerifier` 中：
   - FFI 边界场景优先映射 `IssueKind::OwnershipViolation`。
   - 非 FFI 场景映射 `IssueKind::InvalidFree`。

验收：

- 能检测“非法释放借用指针”。
- 不把 owned pointer 的正常释放误判为 invalid borrowed free。

---

## Task 5：补明确内存泄漏检测

优先级：P1

修改文件：

- `crates/omniscope-pass/src/resource/path_sensitive_leak.rs`
- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs`
- `crates/omniscope-pass/src/resource/issue_verifier.rs`

任务：

1. 区分 `DefiniteLeak` 与 `ConditionalLeak`。
2. acquire 后所有可见路径都无 release → `MemoryLeak`。
3. 部分路径 release、部分路径未 release → `ConditionalLeak`。
4. 排除 GC-managed、process-static、RAII drop 已覆盖资源。

测试：

- malloc-no-free：应报 `MemoryLeak`。
- early-return leak：应报 `ConditionalLeak` 或 path-sensitive leak。
- RAII cleanup：不应误报。

验收：

- 明确泄漏不再只表现为 `ConditionalLeak`。
- 不显著增加 FP。

---

## Task 6：添加文件描述符泄漏检测

优先级：P2

修改/新增文件：

- `crates/omniscope-types/src/resource_family.rs`
- `crates/omniscope-pass/src/resource/raw_fact_collector.rs`
- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs`
- `crates/omniscope-pass/src/resource/issue_verifier.rs`
- 新增 `tests/corpus/fd_leak.ll`

任务：

1. 新增 `FILE_DESCRIPTOR` resource family。
2. 识别 fd acquire/release：
   - acquire: `open`, `creat`, `socket`, `accept`, `dup`, `pipe`
   - release: `close`
3. 支持 int fd 作为 resource id，而不只支持 pointer。
4. fd acquire 无 close 时生成 leak candidate。
5. 短期映射为 `IssueKind::MemoryLeak`；长期考虑新增 `IssueKind::ResourceLeak` 或 `FileDescriptorLeak`。

测试：

- open-close：不报。
- open-no-close：报 leak。
- close twice：报 double release 或 invalid close。

验收：

- fd leak 成为可检测类别。
- heap leak 与 fd leak 共享资源族/契约图机制。

---

## Task 7：PassContext / IRModule 零拷贝清理

优先级：P2

修改文件：

- `crates/omniscope-pass/src/pass.rs`
- `crates/omniscope-pass/src/resource/raw_fact_collector.rs`
- `crates/omniscope-pass/src/analysis/write_to_immutable.rs`
- `crates/omniscope-pass/src/analysis/borrow_escape.rs`
- `crates/omniscope-pass/src/analysis/heap_provenance.rs`

问题：

- `PassContext` 已有 `get_ir_module()` 零拷贝 API，但多个 pass 仍通过 `ctx.get("ir_module")` 克隆 `IRModule`。

任务：

1. 统一改成 `ctx.get_ref::<IRModule>("ir_module")` 或真正使用 dedicated `set_ir_module/get_ir_module`。
2. 减少大型 IRModule 克隆。
3. 为更复杂的跨函数/路径敏感分析降低运行成本。

验收：

- `cargo check --workspace` 通过。
- pass 行为不变。
- 大型 fixture 上内存/耗时不回退。

---

## 6. 推荐排期

| 周期 | 任务 | 目标 |
|------|------|------|
| Week 1 | Task 1 + Task 2 | 固化指标，优先降低 FP |
| Week 2 | Task 3 + Task 4 | 主攻 FFI FN：跨语言释放、借用指针非法释放 |
| Week 3 | Task 5 | 补明确内存泄漏检测 |
| Week 4 | Task 6 + Task 7 | 扩展 fd 资源，清理性能债 |

---

## 7. 优先级总览

### P0

- 建立 accuracy regression。
- 压制 Zig runtime `WriteToImmutable` 噪音。
- 检测非法释放 borrowed pointer。

### P1

- 增强跨语言 allocator pairing。
- 区分 definite leak 与 conditional leak。

### P2

- 添加 fd/resource leak。
- 清理 `PassContext` / `IRModule` 克隆路径。

### P3

- 更复杂的跨函数别名分析。
- 更完整的路径敏感控制流建模。
- 更丰富的语言 runtime 模型。

---

## 8. 每阶段验证命令

基础检查：

```bash
RUSTC_WRAPPER= cargo check --workspace
```

精度回归：

```bash
cargo test accuracy_regression
```

相关集成测试：

```bash
cargo test corpus_detection_audit
cargo test corpus_regression
cargo test integration_tests
```

---

## 9. 风险与注意事项

- 不要用“语言不同”直接判定 cross-language free；应以 `ResourceFamily` 兼容关系为主，以 FFI boundary 作为增强证据。
- `ConditionalRelease` 不能简单当作 `Release`，否则会制造 double-free / use-after-free FP。
- Zig runtime 过滤不能过宽，否则可能漏掉用户代码中的真实 immutable write。
- fd 是整数资源，不是 pointer；不要强行套用 pointer-only identity。
- 优先把评测基线固化，否则无法判断 Precision/Recall 是否真实改善。
