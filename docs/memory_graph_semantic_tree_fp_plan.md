# MemoryGraph + SemanticTree 通用降 FP 方案

## 目标

不用白名单补救，而是把上下文补全：

```text
Raw Facts -> MemoryGraph -> SemanticTree -> IssueCandidate -> Verifier -> Issue
```

核心原则：

- Detector 只产候选，不直接报 issue。
- MemoryGraph 解释资源状态和流向。
- SemanticTree 解释 symbol/value/resource/path 的语义。
- Verifier 统一查询图和语义树，决定 `Confirmed / Probable / Diagnostic / ExplainedSafe`。

## 当前问题

### FP 根因

- `LeakDetectionPass` 直接 emit issue，没等语义解释完成。
- `FfiReturnCheckPass` 直接 emit issue，缺少 owner/path 上下文。
- `IssueGate` 主要按 `issue.symbol` 查询，无法表达 resource/path/value 级事实。
- leak 判断仍偏 alloc/release 计数，不能理解 owner store、runtime-managed、out-param escape。

### FN 根因

- CrossFamilyFree 配对按 family 分组，跨 family 错配容易漏。
- UseAfterFree 缺少 alias/value tracking。
- BorrowEscape 缺少 stack/heap/global/from-param provenance 的统一图表示。

## 总体设计

### MemoryGraph

新增或增强资源图，表达资源类别、状态、边和路径事实。

建议落点：

- `crates/omniscope-semantics/src/resource/memory_graph.rs`
- `crates/omniscope-pass/src/resource/contract_graph_builder.rs`
- `crates/omniscope-pass/src/resource/ownership_solver.rs`

核心类型：

```rust
enum ResourceClass {
    HeapMemory,
    MmapRegion,
    FileDescriptor,
    Socket,
    ProcessHandle,
    ThreadHandle,
    RuntimeManaged,
    Unknown,
}

enum ResourceState {
    Unknown,
    Null,
    Owned,
    Released,
    EscapedToCaller,
    EscapedToOutParam,
    StoredToOwner,
    StoredToRuntime,
    RuntimeManaged,
}

enum MemoryEdgeKind {
    Acquire,
    Release,
    StoreToOwner,
    StoreToRuntime,
    ReturnToCaller,
    InitOutParam,
    NullOnErrorPath,
    Alias,
    Use,
}
```

### SemanticTree

从 symbol-only 升级成多 key 查询：

```text
symbol:<name>
value:<ssa-reg>
resource:<id>
path:<function>:<path-id>
owner:<value-or-symbol>
```

建议扩展 `SemanticKind`：

```rust
RuntimeManagedResource,
NonMemoryResource,
StoredToOwner,
StoredToRuntime,
EscapedToCaller,
EscapedToOutParam,
FallibleOutParamInit,
NullOnErrorPath,
ReleaseOnAllExitPaths,
AliasOfReleased,
```

落点：

- `crates/omniscope-semantics/src/resource/semantic_tree/kind.rs`
- `crates/omniscope-pass/src/resource/structural_inference_pass.rs`
- `crates/omniscope-pass/src/resource/issue_gate.rs`

### Verifier

Verifier 是唯一下结论的位置。

规则示例：

```text
Owned at all exits                         => DefiniteLeak
Owned at some exits                        => ConditionalLeak
Released before later use/alias use         => UseAfterFree
Alloc family != release family              => CrossFamilyFree
EscapedToCaller / EscapedToOutParam          => ExplainedSafe
StoredToOwner with owner cleanup             => ExplainedSafe
StoredToRuntime / RuntimeManagedResource     => ExplainedSafe or Diagnostic
NonMemoryResource in memory-leak detector    => ExplainedSafe
Unknown state                                => NeedsModel / Diagnostic
```

落点：

- `crates/omniscope-pass/src/resource/issue_verifier.rs`
- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs`

## Task 1：禁止直接 emit issue

目标：所有 pass 只产候选，统一交给 verifier。

修改：

- `crates/omniscope-pass/src/resource/path_sensitive_leak.rs`
- `crates/omniscope-pass/src/resource/ffi_return_check.rs`

做法：

1. 移除或旁路 `ctx.emit_issue(...)`。
2. 生成 `IssueCandidate`，附带 evidence。
3. 存入 context，例如：

```rust
ctx.store("leak_candidates", candidates);
ctx.store("ffi_return_candidates", candidates);
```

验收：

- Pipeline issue 输出只来自 verifier。
- 直接 emit 的 pass 数量减少到 0 或仅保留非资源类 diagnostic。

## Task 2：建立 MemoryGraph 基础类型

目标：统一表达 resource class、state、edge。

修改：

- 新增 `crates/omniscope-semantics/src/resource/memory_graph.rs`
- 更新 `crates/omniscope-semantics/src/resource/mod.rs`

做法：

1. 定义 `ResourceClass`、`ResourceState`、`MemoryNode`、`MemoryEdge`、`MemoryGraph`。
2. 支持按 resource id 查询状态。
3. 支持按 value/alias 查询 resource id。

验收：

- 单元测试覆盖 acquire/release/escape/store/alias/use。
- 不改变现有检测结果，只新增数据结构。

## Task 3：ContractGraph 写入 MemoryGraph

目标：构图时同时生成更完整的 MemoryGraph。

修改：

- `crates/omniscope-pass/src/resource/contract_graph_builder.rs`

做法：

1. Acquire 写入 `MemoryEdgeKind::Acquire`。
2. Release 写入 `MemoryEdgeKind::Release`。
3. out-param 初始化写入 `InitOutParam`。
4. return/store/callback 写入 escape/store edge。
5. 将 `memory_graph` 存入 context。

验收：

- 现有 `contract_graph` 仍可用。
- 新增 `memory_graph` 可被 `OwnershipSolver` 查询。

## Task 4：资源类别通用分类

目标：区分 memory 和非 memory，不靠库白名单。

修改：

- `crates/omniscope-semantics/src/resource/family_registry.rs`
- `crates/omniscope-types/src/resource_family.rs`
- `crates/omniscope-pass/src/resource/contract_graph_builder.rs`

做法：

1. 给 family/resource 增加 `ResourceClass` 映射。
2. POSIX fd/socket/process 映射到非 memory class。
3. mmap 映射为 `MmapRegion`，paired release 是 `munmap`。
4. heap allocator 映射为 `HeapMemory`。

验收：

- `open/openat/dup2/pipe/socket/accept` 不再进入 memory leak 结论。
- `mmap` 仍能被 `munmap` 配对，不被粗暴忽略。

## Task 5：SemanticTree 多 key 化

目标：不只按 symbol 查询语义。

修改：

- `crates/omniscope-pass/src/pass.rs`
- `crates/omniscope-pass/src/resource/issue_gate.rs`
- `crates/omniscope-semantics/src/resource/semantic_tree/kind.rs`

做法：

1. 定义统一 key：`symbol:*`、`resource:*`、`value:*`、`path:*`。
2. `srt_resolutions` 从 `HashMap<String, Vec<SemanticKind>>` 保持兼容，但 key 规范化。
3. `Issue` 或 `IssueCandidate` 携带 resource/value/path key。

验收：

- Gate 可以查询 resource/path/value 语义。
- 旧 symbol 查询不破坏。

## Task 6：SemanticTree 写入 owner/runtime 语义

目标：解释“资源被谁拥有”。

修改：

- `crates/omniscope-pass/src/resource/structural_inference_pass.rs`
- `crates/omniscope-semantics/src/resource/ir_pattern.rs`
- `crates/omniscope-semantics/src/resource/summary_inference.rs`

做法：

1. 检测 store-to-owner pattern。
2. 检测 store-to-runtime/global owner pattern。
3. 检测 out-param success/error pattern。
4. 写入：

```text
resource:<id> -> StoredToOwner / StoredToRuntime / EscapedToOutParam
owner:<id>    -> RuntimeManagedResource
path:<id>     -> NullOnErrorPath / EscapedToCaller
```

验收：

- runtime/std allocator 管理路径解释为 owner transfer，不是 local leak。
- out-param 成功路径不是 leak，失败路径 NULL 不是 leak。

## Task 7：Verifier 查询 MemoryGraph + SemanticTree

目标：把 FP 解释为 safe，而不是 filter 掉。

修改：

- `crates/omniscope-pass/src/resource/issue_verifier.rs`

做法：

1. `verify_definite_leak` 查询 resource exit states。
2. `verify_conditional_leak` 查询 per-path state。
3. `verify_double_release` 查询 second release 的 value state。
4. `verify_cross_family_free` 查询 alloc/release family 和 ownership transfer。
5. `verify_use_after_free` 查询 alias/use edge。

验收：

- `StoredToOwner`、`EscapedToCaller`、`EscapedToOutParam` 返回 `ExplainedSafe`。
- `Unknown` 返回 `Diagnostic/NeedsModel`，不默认高危。

## Task 8：修 CrossFamilyFree 漏报

目标：跨 family 配对不能被 family 分组吞掉。

修改：

- `crates/omniscope-pass/src/resource/contract_graph_builder.rs`

做法：

1. 同 family queue 找不到 release 对象时，在同一 function 的其他 family queue 中找 oldest acquire。
2. 找到后生成 cross-family release edge。
3. candidate builder 只产 `CrossFamilyFree` 候选。

验收：

- `malloc + operator delete` 可检测。
- `new[] + free/delete scalar` 可检测。
- same-family clean case 不回归。

## Task 9：修 UseAfterFree alias 漏报

目标：free 后别名使用也能检测。

修改：

- `crates/omniscope-ir/src/parser.rs`
- `crates/omniscope-ir/src/llvm_sys_adapter.rs`
- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs`

做法：

1. `CallInstruction` 增加 `args`、`result`。
2. MemoryGraph 记录 `Alias` edge。
3. Release 后，任意 alias 出现 call/load/store/gep/use，生成 UAF candidate。

验收：

- `free(p); ffi(alias(p))` 可检测。
- indirect call 里的 freed pointer 可检测。

## Task 10：准确率回归测试

目标：每一步都能量化 Precision/Recall/F1。

修改：

- `tests/accuracy_regression.rs`

做法：

1. 给 FP 大类加 expected-safe 标记。
2. 给 FN 大类加 expected-bug 标记。
3. 每个 task 后跑 accuracy regression。
4. 输出：TP/FP/FN/Precision/Recall/F1。

验收目标：

```text
第一阶段：FP 明显下降，不牺牲 TP
第二阶段：CrossFamilyFree TP 上升
第三阶段：UseAfterFree TP 上升
```

## 推荐执行顺序

```text
1. 直接 emit -> candidate-only
2. MemoryGraph 基础类型
3. ContractGraph 写入 MemoryGraph
4. ResourceClass 通用分类
5. SemanticTree 多 key 化
6. owner/runtime/out-param 语义写入
7. Verifier 查询图和语义树
8. CrossFamilyFree 跨 family 配对
9. UseAfterFree alias tracking
10. accuracy regression 固化
```

## 第一轮目标

先解决 FP 主因：

```text
NonMemoryResource 不报 memory leak
StoredToOwner / StoredToRuntime 不报 local leak
EscapedToCaller / EscapedToOutParam 不报 local leak
Unknown 不直接 confirmed
```

预期效果：

- `zig_main.ll` 的 runtime/std 资源管理 FP 大幅下降。
- 不需要对 `Io.Threaded.*` 做名字白名单。
- 为后续 CrossFamilyFree/UAF 补 TP 打基础。

## 第二轮目标

补 TP：

```text
CrossFamilyFree: 跨 family pairing
UseAfterFree: alias + post-release use
BorrowEscape: provenance + stack/global/heap/from-param
```

## 结论

这套方案的核心不是“抑制某些名字”，而是让分析器回答三个通用问题：

```text
这个资源是什么类型？
这个资源现在归谁所有？
这条 issue 对应的路径上资源状态是什么？
```

只有这三个问题回答完，Verifier 才能下结论。
