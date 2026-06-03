# C++ IR 加载性能优化方案

## 背景

当前大文件分析的主要耗时不在 Rust pass pipeline，而在 IR loading 阶段。已有 `rust_sqlite.ll` 案例显示：

```text
总耗时:        ~26s
Pipeline:      ~0.3s
IR loading:    ~25s+
```

如果观察到“20s 里 99% 都在 load ir”，需要先区分两类成本：

1. LLVM 解析 `.ll` / `.bc` 成 `Module` 的成本。
2. 遍历 `Module` 并序列化 JSON/MsgPack，再由 Rust 反序列化的成本。

对当前 C++ 侧实现而言，第一类成本通常是最大头。

## 当前代码路径

### Rust loader

文件：`crates/omniscope-ir/src/loader_v2.rs`

`LoadStrategy::Auto` 当前优先级：

```text
DirectCppFfi -> DirectCpp -> llvm-sys -> CppPass -> TextParser
```

相关位置：

- `LoadStrategy` 定义：`crates/omniscope-ir/src/loader_v2.rs:114`
- `load_auto`：`crates/omniscope-ir/src/loader_v2.rs:242`
- `load_auto_fast`：`crates/omniscope-ir/src/loader_v2.rs:324`
- `load_via_direct_cpp_ffi`：`crates/omniscope-ir/src/loader_v2.rs:507`
- `load_via_direct_cpp`：`crates/omniscope-ir/src/loader_v2.rs:589`

### C++ extractor

文件：`tools/ir_extractor/ir_extractor.cpp`

当前加载核心：

```cpp
LLVMContext Context;
SMDiagnostic Err;
std::unique_ptr<Module> M = parseIRFile(InputFile, Err, Context);
```

位置：`tools/ir_extractor/ir_extractor.cpp:1315`

也就是说，无论后续是否做 FFI slice，都必须先完整 parse 整个 IR 文件。

### C++ 输出格式

当前 extractor 支持：

```text
--format=json      默认
--format=msgpack   二进制输出
```

位置：`tools/ir_extractor/ir_extractor.cpp:174`

但 Rust 的 `load_via_direct_cpp` / `load_via_direct_cpp_ffi` 现在仍然默认调用 JSON 输出并 `from_json_str` 反序列化。

## 主要瓶颈判断

### 如果 99% 在 `parseIRFile`

那说明瓶颈是 LLVM 文本 IR parser 本身。

这种情况下，下面优化收益有限：

- JSON 换 MsgPack。
- 减少 `writeInstruction` 字段。
- FFI slice 减少输出函数。

原因：这些都发生在 `parseIRFile` 之后。

真正有效的方向是：

```text
避免走 LLVM parseIRFile
或避免每次都 parse 全量文本 IR
或让输入变成更快解析的 bitcode / cached binary model
```

### 如果 99% 在 serialization / Rust deserialize

那才优先做：

- MsgPack。
- 字段裁剪。
- 流式反序列化。
- slice 先行。

因此第一步必须增加分段计时，不然容易优化错地方。

## Phase 0：先把计时打准

### C++ extractor 总是暴露 timing

现在 C++ 端已有 `-t` 参数，会输出：

```text
[ir-timing] parse_ms
[ir-timing] index_ms
[ir-timing] seed_detection_ms
[ir-timing] closure_computation_ms
[ir-timing] serialization_ms
[ir-timing] total_ms
```

建议 Rust 调用 C++ extractor 时，在 debug/timing 模式自动加 `-t`。

修改文件：`crates/omniscope-ir/src/loader_v2.rs`

涉及函数：

- `load_via_direct_cpp_ffi`
- `load_via_direct_cpp`

伪代码：

```rust
let mut cmd = std::process::Command::new(&extractor);

if std::env::var_os("OMNISCOPE_IR_TIMING").is_some() {
    cmd.arg("-t");
}
```

### Rust loader 拆分 timing

现在 `LoadedIr` 只有 `load_ms`。建议扩展：

```rust
pub struct LoadedIr {
    pub module: IRModule,
    pub strategy: LoadStrategy,
    pub load_ms: u64,
    pub backend_ms: Option<u64>,
    pub deserialize_ms: Option<u64>,
    pub cache_hit: bool,
}
```

对应文件：`crates/omniscope-ir/src/loader_v2.rs`

这样可以区分：

```text
C++ process wall time
stdout UTF-8 conversion
JSON/MsgPack deserialize
IRModuleModel -> IRModule conversion
```

## Phase 1：默认路径先别走 C++ 全量 parse

### 建议一：把 CLI 默认策略从 `auto` 改成 `auto-fast`

当前 CLI 默认：

```rust
#[arg(long, default_value = "auto")]
strategy: String,
```

位置：

- `crates/omniscope-cli/src/main.rs:91`
- `crates/omniscope-cli/src/main.rs:114`

建议改成：

```rust
#[arg(long, default_value = "auto-fast")]
strategy: String,
```

原因：`auto-fast` 已经存在，并且对 `.ll` 优先 text parser：

```text
.ll -> text-parser first
.bc -> normal auto
```

这对大 `.ll` 文件收益最大，因为 text parser 不走 LLVM `parseIRFile`，已有案例从 26s 降到 0.36s。

风险：text parser 的元数据精度低于 C++/LLVM backend。

缓解：保留显式 `--strategy auto` / `--strategy direct-cpp` 作为 precision-first 模式。

### 建议二：让 `auto` 本身带大 `.ll` 熔断

如果不想改默认策略，可以在 `load_auto` 里加保守 heuristic：

```text
if input extension == .ll && file_size > 10MB:
  try text-parser first
  if coverage acceptable:
    return text-parser
  else:
    fallback to current auto
```

coverage gate：

```text
functions > 0
calls > 0 for non-empty IR
declarations > 0 when file contains declare
parser_errors == 0, or malformed ratio below threshold
```

修改文件：`crates/omniscope-ir/src/loader_v2.rs`

建议新增函数：

```rust
fn can_trust_text_parser(module: &IRModule, path: &Path) -> bool
```

### 建议三：用户显式需要深度语义时再走 C++

新增模式：

```text
--strategy precise
```

映射：

```text
precise -> DirectCppFfi -> DirectCpp -> LlvmSys -> CppPass -> TextParser
fast    -> TextParser for .ll, DirectCppFfi/MsgPack for cached/generated models
```

现在的 `auto` 命名比较模糊，用户不知道它是 precision-first 还是 speed-first。

## Phase 2：C++ extractor 输出用 MsgPack，不再默认 JSON

### 现状

C++ 已支持 `--format=msgpack`，但 Rust direct-cpp 路径没有用。

当前调用：

```rust
Command::new(&extractor)
    .arg(path)
    .output()?;

let json_str = String::from_utf8(output.stdout)?;
let model = IRModuleModel::from_json_str(&json_str)?;
```

位置：

- `crates/omniscope-ir/src/loader_v2.rs:533`
- `crates/omniscope-ir/src/loader_v2.rs:615`

### 修改建议

改为：

```rust
Command::new(&extractor)
    .arg("--format=msgpack")
    .arg(path)
    .output()?;

let model = IRModuleModel::from_msgpack_slice(&output.stdout)?;
```

需要补：

```rust
impl IRModuleModel {
    pub fn from_msgpack_slice(bytes: &[u8]) -> Result<Self>
}
```

或者复用已有 msgpack loader，但避免落盘临时文件。

### 缓存也改成二进制

当前 cache 存 JSON。建议支持：

```text
.json cache    legacy
.msgpack cache preferred
```

修改文件：`crates/omniscope-ir/src/ir_cache.rs`

新增：

```rust
save_to_cache_bytes(path, format, bytes)
load_cached_bytes(entry)
```

预期收益：

```text
parseIRFile 占大头时：收益有限
deserialize/IO 占大头时：明显收益，通常 2x-10x
```

## Phase 3：避免重复完整 parse

如果 input 没变，最有效的是不再跑 C++。

### 当前已有 cache，但仍是 JSON 模型

`load_via_direct_cpp` 和 `load_via_direct_cpp_ffi` 已经查 cache：

```rust
cache.check_cache(path)
cache.load_cached_json(&entry)
```

问题：

- cache miss 时仍然完整 C++ parse。
- cache hit 仍然 JSON parse。
- cache key 需要包含 extractor version、strategy、slice 参数、output schema version。

### 建议 cache key 扩展

cache key 应包含：

```text
input path
input mtime / size / content hash
strategy
slice mode
slice hops
schema version
extractor version
llvm version
```

否则换了 extractor 或 LLVM 后，可能复用旧模型。

### 建议默认缓存 MsgPack IRModuleModel

优先级：

```text
cache .msgpack hit -> Rust 直接反序列化
cache .json hit    -> legacy fallback
cache miss         -> C++ extractor --format=msgpack
```

这样重复分析同一大 IR 时，完全绕过 `parseIRFile`。

## Phase 4：生成/输入侧优先使用 bitcode 或 cached model

如果必须走 LLVM parser，`.bc` 通常比 `.ll` 文本更合适。

建议支持输入优先级：

```text
.omni.msgpack  -> 直接加载模型，最快
.bc            -> LLVM bitcode reader
.ll            -> text-parser fast path，precise 模式再 parseIRFile
```

可以新增命令：

```bash
omniscope cache-ir input.ll -o input.omni.msgpack
omniscope analyze input.omni.msgpack
```

或：

```bash
ir_extractor --format=msgpack input.ll -o input.omni.msgpack
omniscope analyze --strategy msgpack input.omni.msgpack
```

已有 `LoadStrategy::MsgPack`，但目前更像“用户自己传 msgpack 文件”。可以把它产品化成正式预编译缓存。

## Phase 5：C++ extractor 内部减负

如果分段计时显示 serialization/index 占比高，再优化 C++ 内部。

### 5.1 FFI slice 要尽早裁剪输出，但不能减少 parseIRFile

当前 FFI slice 在 parse 完整 module 后：

```text
parseIRFile full module
buildModuleIndex full module
detect seeds
compute closure
serialize selected functions
```

它能减少输出/deserialize，但不能减少 LLVM parse 成本。

因此它不是解决 99% parseIRFile 的主手段。

### 5.2 `buildModuleIndex` 避免重复字符串拷贝

如果 index 时间高，检查：

- `std::set<std::string>` 改 `llvm::StringSet` / `DenseSet<StringRef>`。
- `std::map` / `std::set` 改 `DenseMap` / `DenseSet`。
- callee names 尽量保存 `StringRef` 或 interned ID。

目标文件：`tools/ir_extractor/ir_extractor.cpp`

### 5.3 JSON Writer 保留，但 direct path 默认 MsgPack

JSON 适合 debug，不适合作为默认大文件数据通道。

建议：

```text
direct-cpp / direct-cpp-ffi 默认 --format=msgpack
用户 debug 时显式 --format=json
```

### 5.4 指令字段按 pass demand 导出

现在 `writeInstruction` / `mpWriteInstruction` 会导出大量字段。可以分 profile：

```text
--profile=minimal
  functions/declarations/calls/basic instruction kind

--profile=resource
  call args/result, store/load/icmp/br/ret, type basics

--profile=full
  all instruction fields, debug loc, operands, types
```

Rust 侧根据启用的 pass 选择 profile。

## Phase 6：真正的 streaming / lazy loading

这是长期方案。

目标：不要一次构建完整 `IRModule`。

### 方案 A：C++ 输出 Function stream

C++ extractor 按 function 输出 record：

```text
ModuleHeader
Declaration records
Function record 1
Function record 2
...
```

Rust 侧边读边构建 `ModuleIndex` 和需要的 summaries。

优点：减少峰值内存和 Rust 反序列化等待。

缺点：复杂度较高，现有 `IRModule` 假设全量存在。

### 方案 B：两阶段加载

第一阶段只提取轻量 index：

```text
functions
declarations
call graph
external calls
alloc/free symbol calls
```

第二阶段只对 selected functions 读取 full body。

问题：LLVM `parseIRFile` 仍然要 full parse，除非输入是自定义 cached model 或自研文本索引。

因此对 `.ll` 大文件，二阶段真正有效的实现应基于 text scanner，而不是 LLVM Module。

## 推荐落地顺序

### P0：马上做

1. CLI 默认改 `auto-fast`，或者在 `auto` 对大 `.ll` 先 text parser。
2. Rust 调 C++ extractor 时支持 `OMNISCOPE_IR_TIMING=1` 自动加 `-t`。
3. `LoadedIr` 增加 backend/deserialize/cache timing。

预期收益：

```text
大 .ll 默认分析从 20s+ 降到亚秒级或几秒内
```

### P1：短期做

1. direct-cpp/direct-cpp-ffi 默认使用 `--format=msgpack`。
2. cache 改支持 `.msgpack` bytes。
3. cache key 加 schema/extractor/LLVM/version/slice 参数。

预期收益：

```text
C++ 路径 cache hit 更快
serialization/deserialize 明显下降
```

### P2：中期做

1. `--profile=resource|minimal|full` 控制 C++ 导出字段。
2. `buildModuleIndex` 改 DenseMap/DenseSet/StringRef，减少字符串拷贝。
3. `direct-cpp-ffi` 对 no FFI seeds 的情况快速返回 diagnostic，不 fallback 全量 DirectCpp。

预期收益：

```text
C++ parse 后处理时间和输出体积下降
```

### P3：长期做

1. `omniscope cache-ir` 生成 `.omni.msgpack`。
2. 分析默认优先 cached model。
3. streaming function records / lazy body loading。

预期收益：

```text
重复分析完全绕过 LLVM parseIRFile
大项目交互式分析体验明显改善
```

## 不建议优先做的事

### 不建议先优化 JSON 字符串拼接来解决 99% load

如果 timing 显示 `parse_ms` 占 99%，JSON 优化不会解决根因。

### 不建议指望 FFI slice 解决 parseIRFile

slice 发生在 full module parse 之后，只能减少输出和 Rust 侧处理。

### 不建议对每个库做 loader 特判

性能问题也应该通用解决：输入格式、缓存、策略选择、数据通道、lazy loading。

## 建议最终策略矩阵

```text
Input .omni.msgpack:
  MsgPack loader

Input .ll, default:
  auto-fast -> text-parser -> optional precise fallback

Input .ll, --strategy precise:
  direct-cpp-ffi -> direct-cpp -> llvm-sys -> cpp-pass -> text-parser

Input .bc, default:
  llvm-sys/direct-cpp if available -> text via llvm-dis fallback

Repeated analysis:
  cache msgpack model first
```

## 总结

如果 20s 的 99% 都在 C++ load IR，优先级应该是：

```text
1. 大 .ll 默认不要走 LLVM parseIRFile
2. 重复分析用 msgpack cache 绕过 C++ parse
3. C++ 输出通道从 JSON 切到 MsgPack
4. C++ 后处理再做字段裁剪和 DenseMap/StringRef 优化
5. 长期做 cached model / streaming / lazy loading
```

最关键的一句：如果瓶颈是 `parseIRFile`，那优化 C++ pass 里的遍历和 JSON 都不是主菜；主菜是避免全量 LLVM 文本 IR parse，或者只在用户明确要 precise 模式时才 parse。
