# FFI Slice Filter 优化方案（修正版）

## 0. 先说明：谁才是真正的慢路径

当前仓库中有三条 C++ 加载路径：

| 路径 | 实现 | 当前 auto 优先级 |
|---|---|---|
| `DirectCpp` | `tools/ir_extractor/build/ir_extractor`（独立可执行文件） | **第 1 优先** |
| `llvm-sys` | Rust 进程内链接 libLLVM（需 `--features llvm-backend`） | 第 2 |
| `cpp-pass` | `opt -load-pass-plugin SafetyExportPass.so`（子进程） | 第 3 |
| `text-parser` | Rust 纯文本解析 | 最后 fallback |

已测量的实际耗时（`rust_sqlite.ll`，13 MB / 344k 行）：

```
DirectCpp (ir_extractor):    ⚠️  尚未测量，这是最大未知数
llvm-sys:                    ❌ 未启用（无 llvm-backend feature）
cpp-pass (opt + plugin):     ✅ ~25.8s（已确认是 26s 的元凶）
text-parser:                 ✅ ~0.36s（已确认）
```

`ir_extractor` 二进制已存在于 `tools/ir_extractor/build/ir_extractor`，且 `find_ir_extractor()` 能找到它。当前 `auto` 会**优先走 DirectCpp**。因此，`ir_extractor` 的真实耗时是规划任何优化之前的首要已知量。

---

## 1. 核心目标

在保留 C++ 解析精度的前提下，先把大型 `.ll` 文件的端到端加载时间从几十秒压到 2~5s 区间；当 FFI slice 足够小、缓存命中或后续切换 fact-level export 后，再冲击 sub-second。

具体分两个方向：

**方向 A：测量并优化 `ir_extractor` 自身**
- 先测出 `ir_extractor` 在 `rust_sqlite.ll` 上的真实耗时
- 如果已经 <3s，slice 优化的 ROI 就很低
- 如果 >5s，再引入 FFI slice filter 减少序列化量

**方向 B：让 `cpp-pass` 不再被盲选**
- 当前 `auto` 把 `cpp-pass` 放在 `DirectCpp` 后面，但只要 `ir_extractor` 失败就会 fallback 到 `opt`
- 需要让 CLI 能明确感知"这次会走 opt，预计 25s"，而不是静默等待
- 同时补齐 CLI 对 `direct-cpp` 的显式解析，避免用户指定 `--strategy direct-cpp` 时意外落回 `auto`

---

## 2. 前置步骤：Benchmark `ir_extractor`（必须先做，否则所有后续 ROI 估算都是空谈）

在 `tools/ir_extractor/ir_extractor.cpp` 已有 `-t`（timing）和 `-v`（verbose）参数，可直接使用：

```bash
tools/ir_extractor/build/ir_extractor -t -v \
  ~/code/zigcode/OmniScope/corpus/real_world/other/rust_sqlite.ll \
  -o /tmp/sqlite_full.json
```

记录以下指标：

```
parse_time_ms
serialize_time_ms
total_time_ms
json_bytes
functions_emitted
declarations_emitted
```

**判断分支：**

- 如果 `total_time_ms < 3000` → 方向 A 优先级降级，优先做方向 B（用户可见性 + auto-fast）
- 如果 `total_time_ms > 5000` → 方向 A 值得做，进入阶段 1（FFI slice）

---

## 3. 阶段 1：FFI Slice Filter（仅当 ir_extractor >5s 时执行）

### 3.1 目标

将全量 JSON 导出替换为 FFI 相关子图导出：

```
全量：1582 functions / 43MB JSON / ~Xs
  →  slice：几十~几百 functions / 几MB JSON / ~Xs
```

### 3.2 架构：两阶段提取

**阶段 1a：轻量索引（无指令序列化）**

遍历 `llvm::Module`，仅收集：

```cpp
struct FunctionSummary {
  std::string name;
  bool is_declaration;
  bool is_exported_like;     // 基于 LLVM linkage/visibility/name pattern 的近似判断
  bool has_external_call;
  bool has_indirect_call;
  bool has_invoke;
  bool has_function_pointer_arg;
  bool returns_pointer;
  std::vector<std::string> callee_names;
  std::vector<std::string> external_callee_names;
};
```

这个阶段**不调用** `typeToString` / `valueToString` / `printAsOperand`，只用 LLVM 结构 API：
- `Function::isDeclaration()`
- `CallBase::getCalledFunction()`
- `CallBase::getCalledOperand()`
- `Type::isPointerTy()`
- `GlobalValue::getLinkage()`
- `GlobalValue::getVisibility()`
- `GlobalValue::getDLLStorageClass()`

注意：`no_mangle` / `extern "C"` 在 LLVM IR 中不一定能直接可靠还原。第一版只做 `is_exported_like` 近似判断，综合 linkage、visibility、DLL storage class、section、calling convention 和 symbol name pattern。

**阶段 1b：FFI Seed 识别**

强 seed（直接纳入 slice）：
- 被模块内函数调用的 external declaration
- 名称匹配常见 FFI 前缀：`sqlite3_*`, `malloc`, `calloc`, `realloc`, `free`, `pthread_*`, `open`, `close`, `Py_*`, `JNI_*` 等
- 导出符号 + 带 pointer 参数/返回值
- 存在 indirect call / invoke 的函数

**阶段 1c：闭包扩展**

```
Backward：纳入调用 seed 的 caller（捕获 FFI wrapper）
Forward：纳入 selected function 调用的 helper（捕获释放逻辑）
Resource：allocator pair（malloc/free、open/close）互相纳入
Callback：将函数指针传给 external API 时，保守纳入附近 helper
```

Hop 限制：默认 2 层。Resource/callback/indirect-call 可突破 hops，以 fixed point 或上限为界。

**阶段 1d：选择性序列化**

```cpp
for (const Function &F : *M) {
  if (shouldSkipFunction(F)) continue;
  if (F.isDeclaration()) {
    if (isSelectedDeclaration(F))
      Declarations.push_back(serializeDeclaration(F));
    continue;
  }
  if (isSelectedFunction(F))
    Functions.push_back(serializeFunction(F));
}
```

保守策略（第一版）：
- `named_struct_types`：保留全部（避免类型缺失误判）
- `global_variables`：保留全部
- `declarations`：保留 selected functions 直接调用的 external declarations + 全部强 seed declarations
- `functions`：仅 selected functions

### 3.3 CLI 参数

```text
--slice=none       默认，全量导出
--slice=ffi        只导出 FFI 相关 slice
--slice-hops=N     调用图扩展层数，默认 2
--slice-stats      stderr 输出过滤统计（不污染 stdout JSON）
```

Rust CLI 后续可选择两种接入方式：

```text
--strategy direct-cpp-ffi
```

或更通用的组合：

```text
--strategy direct-cpp --ir-slice ffi
```

同时需要补齐现有 CLI strategy 解析：

```text
direct-cpp / direct_cpp / directcpp -> LoadStrategy::DirectCpp
auto-fast / auto_fast / autofast     -> LoadStrategy::AutoFast
```

否则用户显式传入 `--strategy direct-cpp` 时会落入默认 `Auto`，不利于 benchmark 和问题定位。

统计输出（stderr）：

```
[ffi-slice] total_functions: 1582
[ffi-slice] selected_functions: 143
[ffi-slice] total_instructions: 120000
[ffi-slice] selected_instructions: 9000
[ffi-slice] json_bytes: 4.8MB
[ffi-slice] parse_ms: 130
[ffi-slice] index_ms: 80
[ffi-slice] slice_ms: 15
[ffi-slice] serialize_ms: 3200
[ffi-slice] total_ms: 3500
```

### 3.4 精度验证

同一输入分别跑 full 和 sliced：

```bash
# Full（oracle）
tools/ir_extractor/build/ir_extractor rust_sqlite.ll -o /tmp/full.json

# Sliced
tools/ir_extractor/build/ir_extractor \
  --slice=ffi --slice-hops=2 --slice-stats \
  rust_sqlite.ll -o /tmp/slice.json

# Rust 侧对比
omniscope analyze rust_sqlite.ll --strategy direct-cpp    > /tmp/full_issues.json
omniscope analyze rust_sqlite.ll --strategy direct-cpp-ffi > /tmp/slice_issues.json
```

对比指标（issue-level 对比，不比较 issue ID）：

```
FFI 相关 issue recall  ≥ 99%（不允许漏掉高置信 FFI issue）
resource pair recall    ≥ 95%
call edge recall         ≥ 95%
```

**通过标准：** FFI-related issue recall ≥ 99%。允许多报（selected functions 偏多），不允许漏报。

---

## 4. 阶段 2：让 `cpp-pass` 路径的用户体验变诚实（不依赖阶段 1）

无论 `ir_extractor` 多快，当前有一个独立的 UX 问题：当 `auto` fallback 到 `cpp-pass`（opt）时，用户要等 25s 才知道结果，且 CLI 报告的 "Analysis time: 318ms" 严重误导。

### 4.1 分阶段计时（P0）

在 CLI 层（不是 Pipeline 层）记录：

```rust
struct CliTiming {
    load_ms: u64,
    pipeline_ms: u64,
    format_ms: u64,
    total_ms: u64,
    load_strategy: &'static str,
}
```

`PipelineResult::duration` 保持原义（仅 pipeline 耗时）。CLI 侧叠加 `load_ms` 后输出完整时间线。

### 4.2 Loader Strategy 元数据暴露（P0）

`LoadStrategy::Auto` 实际选了哪个 backend 是透明黑盒。让 `load_ir()` 返回：

```rust
pub struct LoadedIr {
    pub module: IRModule,
    pub strategy: LoadStrategy,
    pub load_ms: u64,
}
```

CLI 输出：

```text
Loaded via: direct-cpp (ir_extractor)    2ms
Pipeline:                              278ms
Total:                                 280ms
```

如果 fallback 到 cpp-pass：

```text
Loaded via: cpp-pass (opt + SafetyExportPass.so)   25830ms
Pipeline:                                           318ms
Total:                                            26148ms
```

### 4.3 `auto-fast` 策略（P1）

新增 `LoadStrategy::AutoFast`，对 `.ll` 输入优先 text-parser，对大文件尤其有效。

注意：text-parser 是 best-effort parser，很多精度缺失不会表现为“解析失败”。因此 `AutoFast` 不能只依赖 parser error 做 fallback，还需要引入 parse confidence / completeness 指标。

```
auto-fast for .ll:
  text-parser → confidence check → DirectCpp / cpp-pass fallback

auto-fast for .bc:
  DirectCpp → llvm-sys → cpp-pass → text-parser via llvm-dis
```

`Auto`（旧）保持行为不变。`AutoFast` 是 opt-in，默认不改变现有用户习惯。

建议的 confidence 指标：

```text
unknown_instruction_ratio
unresolved_call_count
indirect_call_count
missing_debug_loc_ratio
unsupported_opcode_count
has_invoke_or_landingpad
has_function_pointer_escape
```

如果 confidence 低于阈值，或者用户显式要求 high-precision，则 fallback 到 `DirectCpp`；只有 `DirectCpp` 不可用时才考虑 `cpp-pass`。

---

## 5. 阶段 3：C++ Pass 缓存（P1）

对 `cpp-pass` 路径，缓存 `SafetyExportPass` 的 JSON 输出：

```
cache key = canonical_path + size + mtime_ns + full_xxh3_64(file)
cache location = target/omniscope-cache/<fingerprint>.ir.json
```

首次运行 ~25s，后续命中 sub-second。缓存失效：文件 fingerprint 变化时自动失效。

如果担心大文件全量 hash 增加额外开销，可先用 `size + mtime_ns` 做快速候选命中，再异步或按需校验 full hash。不要只 hash 文件开头 4KB，否则文件中后部变化可能导致缓存误命中。

---

## 6. 阶段 4：减少工具发现开销（P2）

`can_use_cpp_pass()` 调用 `find_opt()` + `find_pass_plugin()`，`load_via_cpp_pass()` 又调用一次。合并为单次探测：

```rust
struct CppPassBackend { opt: PathBuf, plugin: PathBuf }
```

探测结果缓存到 `OnceCell`，避免每次 load 重复 filesystem 扫描。

---

## 7. 推荐执行顺序

| 顺序 | 步骤 | 判断依据 |
|------|------|----------|
| **S0** | Benchmark `ir_extractor` 在 `rust_sqlite.ll` 上的真实耗时 | 所有 ROI 估算的前提 |
| **S1** | 分阶段计时 + `direct-cpp` 显式解析 + `AutoFast` 草案 | 计时和显式解析零精度风险；`AutoFast` 需配合 confidence gate 后再启用 |
| **S2** | C++ pass 缓存 | 对反复分析的 CI 场景有明确收益 |
| **S3** | 如果 `ir_extractor >5s`：FFI Slice Filter | 有实际加速空间才做 |
| **S4** | 工具发现去重 | 小改进，随时可插 |

---

## 8. 精度安全政策

1. `auto` 行为不改动；`AutoFast` 是独立 opt-in 策略
2. FFI slice 必须有 full DirectCpp fallback（slice 失败、低置信或命中未知高风险结构时，用 `ir_extractor --slice=none` 全量重跑）；只有 DirectCpp 不可用时才考虑 cpp-pass
3. 缓存按文件 fingerprint 失效，不按 TTL
4. 精度验证必须自动化：每个 fixture 跑 full + slice，对比 FFI-related issue recall
5. 任何 slice 策略变更必须通过 `accuracy_regression` 测试门槛

---

## 9. 与 accuracy_improvement_plan.md 的协调

本方案中的以下内容与 `accuracy_improvement_plan.md` 的 Task 7 直接复用，应统一跟踪，避免双份：

- `ctx.get_ref::<IRModule>("ir_module")` / `get_ir_module()` 零拷贝迁移
- `ModuleIndex` 作为共享轻量索引（同时服务于 FFI slice 和 pass 过滤）

如有冲突，以 `accuracy_improvement_plan.md` 的 Task 7 为准。
