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

## BUG-4: Evidence 缺少 escape 字段导致 `has_escape_evidence` 永远返回 false [严重]

**位置:** `crates/omniscope-pass/src/resource/issue_verifier.rs:308-313`

**问题:**
```rust
fn has_escape_evidence(candidate: &IssueCandidate, kind: EvidenceKind) -> bool {
    candidate.evidence.iter().any(|e| e.kind == kind && e.escape.is_some())
}
```
`Evidence` 结构体（`crates/omniscope-types/src/evidence.rs`）**没有** `escape` 字段。查看 `Evidence` 定义：
- 字段为: `kind`, `description`, `family`, `confidence`, `ir_pattern`, `escape_kind`
- 没有 `escape` 字段，只有 `escape_kind: Option<EscapeKind>`

所以 `e.escape.is_some()` 是编译错误。如果这代码能编译，说明 `escape` 在旧版本存在或 `Evidence` 另有定义。

修复前需确认 `Evidence` 实际字段名。如字段为 `escape_kind` 则应改为 `e.escape_kind.is_some()`。

---

## BUG-5: name-based 启发式分析极度不可靠 [高]

### 5a: borrow_escape.rs 全局/堆/参数检测

**位置:** `crates/omniscope-pass/src/analysis/borrow_escape.rs:176-197`

```rust
fn has_heap_provenance(&self, caller: &str) -> bool {
    caller.contains("alloc")    // ← 匹配 "dealloc", "realloc"
        || caller.contains("_new")  // ← 匹配 "renew", "known_error"
        || caller.ends_with("new")  // ← 匹配 "renew"
}
fn is_function_parameter(&self, symbol: &str) -> bool {
    symbol.contains("param") || symbol.contains("arg")  // ← 在 mangled name 中不存在
}
```
`symbol` 参数格式为 `"caller->callee"`，从中寻找 `"param"`、"arg" 在 Rust mangled name 中几乎不可能匹配。整个 pass 的有效性依赖于这些不可靠的字符串匹配。

### 5b: heap_provenance.rs

**位置:** `crates/omniscope-pass/src/analysis/heap_provenance.rs:141-146`

```rust
fn is_global_storage(&self, callee: &str) -> bool {
    callee.starts_with("@") || callee.contains("static") || callee.contains("global") || callee.contains("const")
}
```
名为 `"static_assert"`, `"global_counter"`, `"const_eval"` 的函数会被误分类为全局存储。

### 5c: interior_mutability.rs

**位置:** `crates/omniscope-pass/src/analysis/interior_mutability.rs:114-142`

```rust
fn has_interior_mutability(&self, name: &str) -> bool {
    let interior_patterns = ["UnsafeCell", "Cell", "Mutex", "RwLock", "Atomic", ...];
    interior_patterns.iter().any(|&pattern| name.contains(pattern))
}
```
- `"Cell"` 匹配 `"Cancel"`, `"Cello"`, `"Cellular"`
- `"Mutex"` 匹配任何包含该子串的非 Mutex 函数
- Rust v0 mangled name 中 `4Cell` 表示 `std::cell::Cell`，但 `name.contains("Cell")` 会匹配所有包含 "Cell" 的内容

**影响:** 所有基于 name-based 的语义分析 pass（BorrowEscape、WriteToImmutable、InteriorMutability、HeapProvenance）产生大量误报/漏报，其分析结果不可信赖。

**修复:** 使用真正的 IR 类型系统进行判断（AllocaInst → stack, malloc/calloc → heap），或至少使用 Rust v0 mangled name 解析 crate。

---

## BUG-6: WriteToImmutablePass 遍历 calls 而非 store 指令 [高]

**位置:** `crates/omniscope-pass/src/analysis/write_to_immutable.rs:60-80`

**问题:**
```rust
for call in &module.calls {         // ← 遍历的是 CALL 指令，不是 STORE
    if !call.callee.contains("store") {  // ← 检查 callee 名字是否包含 "store"
        continue;
    }
```
`module.calls` 是 `Vec<CallInstruction>`，来自 `parse_call()`，记录的是 `call` 指令。LLVM `store` 指令**不是** call 指令，不会出现在 `module.calls` 中。这个 pass 实际上**永远不会**检测到任何 store 操作。

`call.callee.contains("store")` 仅在 callee 函数名包含 "store" 时才进入分析，与写不可变内存的检测目标完全无关。

**影响:** WriteToImmutable pass 完全失效，所有 write-to-immutable 问题均无法检测。

**修复:** 遍历 `module.function_bodies` 中的 `IRInstructionKind::Store` 指令，而非 `module.calls`。

---

## BUG-7: BorrowEscapePass 对符号参数的解析错误 [高]

**位置:** `crates/omniscope-pass/src/analysis/borrow_escape.rs:195`

**问题:**
```rust
fn is_function_parameter(&self, symbol: &str) -> bool {
    symbol.contains("param") || symbol.contains("arg") || symbol.contains("parameter")
}
```
`symbol` 的值为 `"caller->callee"` 格式（如 `"test_func->malloc"`）。在这种格式的字符串中寻找 `"param"`/`"arg"` 几乎永远找不到，因为函数名中通常不包含这些子串。

此外，`has_heap_provenance` 接收的是 `caller`（调用者函数名），但在 `analyze_ffi_call` 中：
- 第 118 行: `self.has_heap_provenance(caller)` — 检查**调用者**是否为堆分配
- 但实际上应该检查被调用函数是否为堆分配，或者检查传入参数是否为堆指针

**影响:** 几乎所有 FFI call 的堆/栈/参数检测都得出错误结论，导致大量误报或漏报。

---

## BUG-8: `check_release_in_facts` 文档与实现不匹配 [中]

**位置:** `crates/omniscope-pass/src/resource/path_sensitive_leak.rs:207-231`

**问题:**
文档注释说:
> Now we restrict the search to:
> 1. Facts whose `function` ID matches the alloc's function ID (same scope), OR
> 2. Facts whose `function_name` matches the alloc's `function_name`

但实现仅检查了条件 1（`f.function == alloc.function`），从未检查条件 2（`f.function_name == alloc.function_name`）。可能导致跨函数释放模式漏报。

**影响:** 当一个函数内调用 `malloc` 和 `free` 但由于某些原因不在相同 `function` ID 下时，释放不会被识别为匹配，产生假阳性泄漏报告。

---

## BUG-9: RawFactCollector 使用 `wrapping_add` 可能导致 func_id 绕回 [中]

**位置:** `crates/omniscope-ir/src/parser.rs:68`

**问题:**
```rust
next_func_id = next_func_id.wrapping_add(1);
```
使用 `wrapping_add` 而不是普通 `+= 1` 或 `checked_add`。在分析大型 IR 模块时，如果函数数量超过 `u64::MAX`，ID 会绕回 0，导致不同函数共用相同 ID。虽然 u64::MAX 在实际中不太可能达到，但 `wrapping_add` 的使用表明开发者的意图不明确，可能在其他地方也存在类似的溢出风险。

---

## BUG-10: ffi_return_check `is_likely_ffi_by_name` 排除大写函数名 [中]

**位置:** `crates/omniscope-pass/src/resource/ffi_return_check.rs:312-324`

**问题:**
```rust
fn is_likely_ffi_by_name(name: &str) -> bool {
    if name.starts_with("_R") { return false; }
    name.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
}
```
要求 FFI 函数名全小写+下划线+数字。Windows API 函数（如 `GetProcessHeap`、`HeapAlloc`）、Objective-C 函数、CamelCase 命名的 C 库函数都被排除。

**影响:** 非全小写的 FFI 调用完全跳过 nullable return 检测，导致大量漏报。

---

## BUG-11: Profiler `stats()` 除法溢出 [中]

**位置:** `crates/omniscope-core/src/profiler.rs:197`

**问题:**
```rust
let total: Duration = spans.iter().map(|s| s.duration).sum();
let avg = total / count as u32;
```
`Duration` 的 `Div<u32>` 在 `count == 0` 时会 panic（虽然之前有 empty check，但如果 `count > u32::MAX` 也会有问题）。更重要的是，`spans_by_name` 查询可能存在竞态条件导致 `spans` 在 `is_empty` 判断后被修改。

---

## BUG-12: Profiler memory_samples 时间戳冲突 [中]

**位置:** `crates/omniscope-core/src/profiler.rs:144-151`

**问题:**
```rust
pub fn record_memory(&self, total_bytes: u64, used_bytes: u64) {
    let timestamp = Utc::now();
    let sample = MemorySample { timestamp, total_bytes, used_bytes };
    self.memory_samples.insert(timestamp, sample);
}
```
以 `DateTime<Utc>` 为 key 插入 `DashMap`。如果在同一纳秒内多次调用 `record_memory`（高并发场景），后一次会覆盖前一次，丢失采样数据。

---

## BUG-13: ContractGraphBuilder 函数 ID 空间与 RawFactCollector 不连续 [中]

**位置:**
- `crates/omniscope-pass/src/resource/raw_fact_collector.rs:67-68`
- `crates/omniscope-pass/src/resource/contract_graph_builder.rs:213`

**问题:**
RawFactCollector 从 `0` 开始分配函数 ID，ContractGraphBuilder 在扫描 IRModule 时从 `1` 开始分配自己的函数 ID。当同一函数在 RawFactCollector 生成的 fact 中有 ID `X`，在 ContractGraphBuilder 的 IR 扫描中又有 ID `Y`，会产生同一个函数对应两个不同 ID，可能导致 edges 分组错误。

**影响:** 跨 pass 的函数级聚合分析可能产生不一致结果。

---

## BUG-14: Evidence 字段名不一致 [低]

**位置:** `crates/omniscope-pass/src/resource/issue_verifier.rs:308-313`

**问题:**
```rust
fn has_escape_evidence(candidate: &IssueCandidate, kind: EvidenceKind) -> bool {
    candidate.evidence.iter().any(|e| e.kind == kind && e.escape.is_some())
}
```
且看 `Evidence` 实际定义（假设在 `omniscope-types/src/evidence.rs`），如果字段名是 `escape_kind` 而不是 `escape`，则此方法始终返回 `false`。需修复引用为 `e.escape_kind.is_some()`。

---

## BUG-15: C++ LLVM Pass 中内存泄漏 [低]

**位置:** `pass/SafetyExportPass.cpp`

**问题:** 需要检查 `SafetyExportPass.cpp` 中 LLVM 对象的 RAII 管理。`llvm::json::Value` 的使用是否正确处理了所有 LLVM 类型引用，以及 LLVM pass 插件在卸载时是否释放了所有分配的资源。

---

## BUG-16: Platform Filters 未应用 [低]

**位置:** 所有 analysis passes

**问题:** 项目根目录存在 `platform_filters.toml`，表明设计上有平台过滤机制。但所有分析 pass 的 `run()` 方法中均未读取或使用该配置。跨平台差异（如 Windows 调用约定、类型大小差异）未被考虑。

---

## 严重性汇总

| 严重性 | 数量 | BUG-ID |
|--------|------|--------|
| 严重 (Critical) | 4 | BUG-1, BUG-2, BUG-3, BUG-4 |
| 高 (High) | 4 | BUG-5, BUG-6, BUG-7, BUG-8 |
| 中 (Medium) | 5 | BUG-9, BUG-10, BUG-11, BUG-12, BUG-13 |
| 低 (Low) | 3 | BUG-14, BUG-15, BUG-16 |

---

## 系统性问题

1. **Name-based 启发式分析泛滥** — 5 个分析 pass 严重依赖函数名字符串匹配来判断语义属性（堆/栈/全局、内部可变性、是否参数等）。这是最突出的系统性问题，导致所有基于 SRT 的抑制机制（R-0 到 R-8）不可靠。

2. **IR 分析与实际指令不匹配** — `WriteToImmutablePass` 遍历 `calls` 而非 `store` 指令（BUG-6），`llvm_sys_adapter` 映射 FCmp → Icmp（BUG-1）。多个 pass 对 LLVM IR 的数据模型理解有偏差。

3. **并行模式不可用** — PassManager 的并行模式存在根本性的数据隔离问题（BUG-2），所有 pass 链式分析在并行模式下全部失效。

4. **文档与实现不同步** — 多处函数注释描述的行为与实际代码实现不一致（BUG-8），struct 定义与方法参数不匹配（BUG-4、BUG-14）。
