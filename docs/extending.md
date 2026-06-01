# OmniScope-rs 扩展开发指南

本文档面向需要扩展 OmniScope-rs 功能的开发者，涵盖新增分析 Pass、FP 抑制规则、语言适配器、FFI 契约库、FamilyId 扩展、输出格式以及 SemanticEngine 细化等常见场景。文档中不包含代码示例，重点描述扩展点的位置、约定和注意事项。

---

## 1. 新增一个分析 Pass

分析 Pass 是 OmniScope-rs 执行流水线的基本单元，所有静态分析逻辑都以 Pass 的形式组织和调度。

### 1.1 选择放置位置

Pass 源文件位于 `crates/omniscope-pass/src/` 下，按分析职责分为两个子目录：

- `analysis/` — 面向 FFI 边界识别、函数表面分类等结构性分析 Pass，适合读取 IR 结构信息、分类函数角色的场景。
- `resource/` — 面向资源契约验证、所有权状态追踪的分析 Pass，适合处理分配/释放配对、跨函数所有权流转的场景。

根据新 Pass 的职责选择合适的子目录，在其中新建一个 `.rs` 文件。

### 1.2 实现 Pass trait

每个 Pass 必须实现 `Pass` trait，需要提供以下方法：

- `name() -> &'static str`：Pass 的唯一字符串标识符。这个名称同时作为 `PassContext` KV 存储的键名前缀约定，命名应具有描述性且全局唯一，避免与已有 Pass 名称冲突。
- `kind() -> PassKind`：声明 Pass 的类别，选择 `Foundation`（基础信息收集）、`Analysis`（分析逻辑）或 `Transformation`（结构变换）之一，PassManager 据此安排调度顺序。
- `dependencies() -> Vec<&'static str>`：列出该 Pass 依赖的其他 Pass 名称列表，PassManager 会根据依赖关系进行拓扑排序，确保依赖 Pass 先于当前 Pass 执行。若依赖链有环则会在初始化时报错。
- `run(&self, ctx: &mut PassContext) -> Result<PassResult>`：Pass 的核心执行逻辑，从 `ctx` 读取上游输出、执行分析、将结果写入 `ctx`，并通过 `ctx.emit_issue()` 发射问题。

在 `run()` 中与 `PassContext` 交互时：

- 读取上游 Pass 输出：使用 `ctx.get::<T>("key")` 按键名取出对应类型的数据。若返回 `None`，说明上游 Pass 未执行或键名错误，应在 `dependencies()` 中声明依赖并检查键名拼写。
- 发射问题：必须通过 `ctx.emit_issue(issue)` 发射，不能直接操作 `ctx.issues`。`emit_issue()` 内部会经过 SRT Gate 过滤，直接推入 `ctx.issues` 会绕过 FP 抑制机制，导致假阳性混入输出。

### 1.3 导出和注册

完成 Pass 实现后，需要完成两步接入：

1. 在 `crates/omniscope-pass/src/lib.rs` 中使用 `pub use` 将新 Pass 导出到 crate 公共 API。
2. 在 `crates/omniscope-pipeline/src/pipeline.rs` 的 `register_default_passes()` 函数中将新 Pass 实例注册到流水线。遗漏这一步会导致 Pass 永远不会被执行，且不会有任何错误提示。

---

## 2. 新增一个 R-N FP 抑制规则

OmniScope-rs 的误报抑制体系基于语义推断树（SRT）和 Gate 机制。当前 R-0 到 R-8 已覆盖主要误报模式，若需要识别新的语义模式并抑制对应误报，按以下步骤扩展。

### 2.1 扩展 SemanticKind 枚举

在 `crates/omniscope-semantics/src/resource/semantic_tree/kind.rs` 的 `SemanticKind` 枚举中新增一个变体，并在注释中注明对应的 R 编号（如 R-9）及其语义含义。变体名称应清晰描述检测到的语义模式，避免使用通用名称。

### 2.2 扩展 GateVerdict 枚举

在 `crates/omniscope-pass/src/resource/issue_gate.rs` 的 `GateVerdict` 枚举中新增对应的 `Suppress*` 变体（命名遵循 `SuppressR9<Description>` 的格式），并实现 `reason()` 方法，返回简洁的人类可读说明，用于日志输出和诊断。

### 2.3 添加抑制条件

在 `issue_gate::check_issue()` 的 match 逻辑中新增分支，明确指定：当问题类型（`IssueKind`）为某种特定类型，且 SRT 中检测到新的 `SemanticKind` 变体时，返回新的 `Suppress*` verdict，从而触发抑制。条件应尽可能精确，避免过度抑制。

### 2.4 实现结构推断模块

新增一个结构推断模块，建议放在 `crates/omniscope-semantics/src/resource/structural_inference/` 目录下，文件名对应新模式的名称。该模块负责从 IR 模式推断出新的 `SemanticKind`，即将底层 IR 特征转化为语义标记。

推断函数的命名约定为 `infer_<pattern>_summary()`，返回类型为对应的 `<Pattern>InferenceResult` 结构体，该结构体包含推断得到的 `SemanticKind` 及置信度相关信息。

### 2.5 接入 StructuralInferencePass

在 `StructuralInferencePass` 的 `run()` 方法中调用新增的推断函数，并将推断结果写入 SRT。写入后 Gate 才能在后续步骤中读取到新的语义信息。

---

## 3. 新增一个语言适配器

语言适配器负责将特定编程语言的 FFI 约定和内存管理模式接入 OmniScope-rs 的统一分析框架。现有适配器（Python、Go、C++、C#、Java）位于 `crates/omniscope-semantics/src/resource/<lang>_adapter/` 目录下。

以新增 Zig 语言适配器为例，步骤如下：

### 3.1 创建适配器目录

在 `crates/omniscope-semantics/src/resource/` 下创建新目录 `zig_adapter/`，目录结构参考 Python 适配器的组织方式。

目录的核心文件为 `mod.rs`，定义 `ZigAdapter` 结构体及该语言特定的分析入口函数。若该语言的内存管理模式较复杂（如 Zig 的 allocator vtable 机制），可按需添加子模块分别处理不同关注点。

### 3.2 实现语言特定逻辑

在 `ZigAdapter` 中需要实现以下三类语言特定逻辑：

- **函数名 mangling 识别**：Zig 有其特定的符号命名规则，需要实现用于 `LanguageDetector` 的 mangling 模式匹配，帮助探测器识别 Zig 编译出的 IR。
- **分配器语义**：Zig 采用 allocator vtable 模式管理内存，需要实现对 vtable 调用模式的识别，将其映射到 OmniScope-rs 的所有权语义。
- **FamilyId 映射**：将 Zig 的分配器符号映射到 `FamilyId::ZIG_ALLOCATOR`（已预留），确保 family 匹配逻辑能正确归类 Zig 的资源操作。

### 3.3 注册至 FamilyRegistry

在 `FamilyRegistry::new()` 中注册 Zig 相关的 symbol 到 `FamilyEntry` 的映射，使资源家族系统能够识别和追踪 Zig 分配的资源。

### 3.4 接入 LanguageDetector

在 `LanguageDetector` 的加权投票机制中添加 Zig 特有的特征权重，包括：Zig 特有的符号 mangling 特征和路径特征（如 Zig 标准库路径前缀等）。这些权重影响语言检测的准确率，应根据特征的区分度合理设置。

### 3.5 导出适配器

在 `crates/omniscope-semantics/src/lib.rs` 中使用 `pub use` 将新适配器导出，完成接入。

---

## 4. 新增一个 FFI 契约库

FFI 契约数据库记录了已知 C 库函数的所有权语义，位于 `crates/omniscope-semantics/src/resource/ffi_contract/`。现有内置契约涵盖 OpenSSL、SQLite、JNI、Python C API、POSIX、zlib、libuv、GLib 等。

以新增 `libcurl` 为例，步骤如下：

### 4.1 创建契约文件

在 `ffi_contract/builtin/` 目录下新建 `libcurl.rs` 文件，专门存放该库的 FFI 契约定义。

### 4.2 定义 FFI 契约

为库中每个需要分析的函数定义一个 `FFIContract` 条目，填写以下字段：

- `name`：函数的符号名称，与 IR 中的函数名一致。
- `contract_type`：函数在所有权模型中的角色，选择 `Allocator`（分配资源）、`Deallocator`（释放资源）、`Borrower`（借用不转移所有权）、`Transfer`（转移所有权给调用者）、`Retainer`（增加引用计数）或 `Releaser`（减少引用计数）之一。
- `ownership`：描述所有权归属，选择 `CallerOwns`、`CalleeOwns`、`Borrowed`、`Transferred`、`Received` 或 `ReferenceCounted` 之一。
- `paired_with`：与该函数配对的函数名，例如 `curl_easy_init` 应配对 `curl_easy_cleanup`。配对信息用于泄漏检测和 UAF 分析。
- `source`：契约来源标注，通常填入库的官方文档引用或规范依据。

### 4.3 注册契约

在 `ffi_contract/builtin/mod.rs` 中使用 `mod` 声明新文件，并在 `register_builtin_contracts()` 函数中调用该库的注册逻辑，将契约条目批量写入契约数据库。

### 4.4 同步 FamilyRegistry

若新库引入了新的资源家族语义，需要在 `FamilyRegistry` 中为其添加对应的 `FamilyId` 和 symbol 映射。若需要新的内置 `FamilyId`，从当前已用最大值（21）之后选取未使用的值，或从 `USER_FAMILY_START`（100）开始分配用户自定义 ID。

---

## 5. 扩展 FamilyId

`FamilyId` 是资源家族的唯一数值标识符，当前内置 ID 范围为 1 到 21，用户自定义从 100 开始。

### 5.1 新增内置 FamilyId 常量

在 `crates/omniscope-types/src/resource_family.rs` 的 `FamilyId` 常量块中新增一个常量，取值选用 22 或更高的未使用整数。常量命名应体现对应的库或资源类型，保持与现有常量命名风格一致。

### 5.2 在 FamilyRegistry 中注册

在 `crates/omniscope-semantics/src/resource/family_registry.rs` 的 `FamilyRegistry::new()` 中为新 FamilyId 注册对应的 `ResourceFamilyOwned`，需要明确声明该 family 与哪些其他 family 兼容（`compatible_with` 字段）。兼容性声明影响跨 family 资源配对的检测精度，应参照相关库的实际资源互操作性来设置。

### 5.3 更新文档

在本文档末尾的 FamilyId 参考表格中新增对应行，记录新 ID 的取值、名称和对应的库。

---

## 6. 理解 PassContext 的 KV 键约定

`PassContext.shared` 是一个 `HashMap<String, Arc<dyn Any>>`，在运行时以字符串键名存储 Pass 间共享的数据。由于没有编译期类型安全保证，所有 Pass 之间的数据交换完全依赖键名和类型的约定。

以下是当前已建立的键名约定：

| 键名 | 存储类型 | 写入 Pass | 读取 Pass |
|------|----------|-----------|-----------|
| `"contract_graph"` | `ContractGraph` | ContractGraphBuilderPass | OwnershipSolverPass |
| `"summary_store"` | `SummaryStore` | SummaryBuilderPass | ContractGraphBuilderPass |
| `"ownership_states"` | `Vec<ResourceInstance>` | OwnershipSolverPass | IssueCandidateBuilderPass、LeakDetectionPass |
| `"issue_candidates"` | `Vec<IssueCandidate>` | IssueCandidateBuilderPass | IssueVerifierPass |
| `"behavior_summaries"` | `HashMap<String, FunctionBehavior>` | IRBehaviorSummaryPass | SummaryBuilderPass |
| `"structural_summaries"` | `Vec<ResourceSummary>` | StructuralInferencePass | ContractGraphBuilderPass |
| `"semantic_tree"` | `SemanticTree` | 多个 Layer 1 Pass | IssueVerifierPass、issue_gate |
| `"surface_map"` | `HashMap<String, FunctionSurface>` | SurfaceClassifierPass | DangerSurfacePass、FFIBoundaryPass |
| `"call_graph"` | `CallGraph` | CallGraphPass | FFIBoundaryPass、SurfaceClassifierPass |

新 Pass 若要读取上游输出，必须使用上表中的键名，并在 `dependencies()` 中声明对写入该键的 Pass 的依赖。

若要在两个 Pass 之间引入新的共享数据，应在本表中新增一行，明确记录键名、类型、写入方和所有读取方。修改已有键名时，没有编译器会发出警告，必须手动使用 `grep -r "\"key_name\""` 在整个代码库中搜索确认所有引用点，并同时更新写入方和所有读取方。

---

## 7. 新增输出格式

输出格式模块位于 `crates/omniscope-cli/src/output/`，当前支持 JSON、SARIF 和富文本三种格式。

以新增 HTML 报告格式为例，步骤如下：

### 7.1 实现格式化函数

在 `output/` 目录下新建对应的格式文件（如 `html.rs`），在其中实现格式化函数，接收 `issues: &[Issue]` 和 `config: &OutputConfig` 作为输入，返回格式化后的字符串输出。函数内部负责将问题数据转换为目标格式的字节序列或字符串。

### 7.2 接入格式分发器

在 `output/mod.rs` 的格式分发逻辑中，为新格式添加枚举变体和对应的分发分支，将格式枚举值路由到新建的格式化函数。

### 7.3 添加 CLI 参数支持

在 `crates/omniscope-cli/src/main.rs` 的命令行参数解析逻辑中，为 `--format` 选项新增对应的接受值（如 `"html"`），并将解析结果映射到格式枚举变体。

---

## 8. 扩展 SemanticEngine 的 FFIVerdict

`FFIVerdict` 是 SemanticEngine 对 FFI 安全性的综合判定结果，当现有变体的粒度不足以描述新的 FFI 模式时，可以细化 `Unknown` 或新增专用变体。

### 8.1 扩展 FFIVerdict 枚举

在 `crates/omniscope-semantics/src/resource/semantic_engine.rs` 的 `FFIVerdict` 枚举中新增变体，变体命名应明确表达对应的安全判定类别。

### 8.2 实现安全评分逻辑

在 `safety_score()` 方法中为新变体返回合适的分数值，在 `is_safe()` 方法中根据分数阈值决定是否判定为安全。评分应与现有变体的分数分布保持一致的语义。

### 8.3 接入 assess_ffi_safety()

在 `assess_ffi_safety()` 函数中添加对应的识别逻辑，描述在什么 IR 条件或语义条件下应返回新的 `FFIVerdict` 变体。

### 8.4 更新 FFIVerdict match 分支

在 `crates/omniscope-pass/src/analysis/mod.rs` 中（第 351 行附近）的 `FFIVerdict` match 表达式中处理新变体，确保所有 match 分支覆盖完整，避免非穷尽匹配引发编译错误。

---

## 常见陷阱

以下是在扩展 OmniScope-rs 时容易犯的错误，每一条都可能导致难以察觉的行为异常。

**1. 直接操作 `ctx.issues` 绕过 Gate**

在 Pass 的 `run()` 方法中直接将问题推入 `ctx.issues`，而不是通过 `ctx.emit_issue()` 发射，会完全绕过 SRT Gate 的 FP 抑制逻辑。所有经 R-0 到 R-N 规则应当被抑制的误报都会混入最终输出，导致假阳性大幅增加且无法通过 Gate 规则来修复。始终使用 `emit_issue()`。

**2. `ConditionalRelease` 与 `Release` 混用**

在定义 FFI 契约或资源语义时，将 `ConditionalRelease`（仅在特定条件下释放资源）误用为 `Release`（无条件释放），或反之，会导致 OwnershipSolver 对所有权状态的推断出现大量误判。最典型的后果是产生大量 UAF（Use After Free）假阳性，因为分析器认为资源已在某个分支中释放，但实际上该释放受到条件约束。在定义契约时需要严格区分这两种语义。

**3. 新 Pass 忘记在 `register_default_passes()` 中注册**

实现并导出新 Pass 后，若忘记在 `crates/omniscope-pipeline/src/pipeline.rs` 的 `register_default_passes()` 中添加注册调用，该 Pass 永远不会被 PassManager 调度执行。这个错误不会产生编译错误或运行时 panic，表现为新功能静默失效，排查时需要检查注册列表。

**4. `PassContext` KV 键名拼写错误**

`ctx.get::<T>("key_name")` 在键名不存在时返回 `None`，不会报错或 panic。若 Pass 对 `None` 的处理是直接跳过分析，则整个 Pass 会静默地什么都不做，且下游依赖该 Pass 输出的所有分析也会因数据缺失而失效。键名错误通常很难察觉，调试时应优先检查 `get()` 的返回值，并与第 6 节的键名约定表对照。

**5. `FamilyId(0)` 无效但不会 panic**

`FamilyId(0)` 是保留的无效值，不对应任何已注册的资源家族。若因疏忽将某个资源的 FamilyId 初始化为 0（例如遗漏了常量引用），`FamilyRegistry` 的查找不会 panic，而是静默返回无匹配，导致该资源的所有 family 相关检测全部失效，包括配对分析和兼容性检查。初始化 FamilyId 时必须使用已在常量块中定义的具名常量，不要使用字面量 `0` 或未经定义的整数值。
