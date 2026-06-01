# OmniScope-rs 核心数据结构文档

本文档描述 OmniScope-rs 项目的核心数据结构，涵盖字段语义、结构间关系及不变式约束。

---

## 目录

1. [IR 层数据结构 (omniscope-ir)](#1-ir-层数据结构-omniscope-ir)
2. [Issue 及相关类型 (omniscope-core)](#2-issue-及相关类型-omniscope-core)
3. [Effect 枚举 (omniscope-types)](#3-effect-枚举-omniscope-types)
4. [PointerContract 枚举 (omniscope-types)](#4-pointercontract-枚举-omniscope-types)
5. [FamilyId / ResourceFamily (omniscope-types)](#5-familyid--resourcefamily-omniscope-types)
6. [ContractGraph / ContractEdge (omniscope-pass)](#6-contractgraph--contractedge-omniscope-pass)
7. [SemanticKind 与 SRT (omniscope-semantics)](#7-semantickind-与-srt-omniscope-semantics)
8. [PassContext (omniscope-pass)](#8-passcontext-omniscope-pass)
9. [FFIVerdict / FFISafetyAssessment (omniscope-semantics)](#9-ffiversdict--ffisafetyassessment-omniscope-semantics)
10. [BehaviorPattern (omniscope-semantics/ir_pattern.rs)](#10-behaviorpattern-omniscope-semanticsir_patternrs)
11. [数据流关系图](#数据流关系图)
12. [关键不变式](#关键不变式)

---

## 1. IR 层数据结构 (omniscope-ir)

### IRModuleModel

LLVM IR 模块的完整表示，由 C++ LLVM Pass 序列化为 JSON 后加载。是精确分析路径的顶层入口。

| 字段 | 类型 | 说明 |
|------|------|------|
| `target_triple` | `Option<String>` | 目标平台三元组，如 `"x86_64-apple-darwin"`，None 表示未知平台 |
| `data_layout` | `Option<String>` | LLVM 数据布局字符串，描述字段对齐、指针宽度等 ABI 细节 |
| `functions` | `Vec<IRFunction>` | 有函数体的定义列表，代表当前模块实际编译的函数 |
| `declarations` | `Vec<IRDeclaration>` | 无函数体的外部声明，是潜在的 FFI 调用点，可用于跨语言边界识别 |
| `named_struct_types` | `HashMap<String, Vec<String>>` | 具名结构体类型表，key 为类型名，value 为字段类型字符串列表，用于结构体布局分析 |
| `global_variables` | `Vec<IRGlobalVariable>` | 模块级全局变量，包括静态字符串、vtable、线程局部存储等 |

**关系**：`IRModuleModel` 是新模型路径的根节点，其 `functions` 字段展开为 `IRFunction` 树形结构。`declarations` 与 `functions` 共同构成模块的完整符号集合。

---

### IRFunction

表示一个有函数体的 LLVM IR 函数定义。

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | `String` | 函数名，不含前缀 `@`，以 mangled 形式存储（如 `_ZN3foo3barEi`） |
| `demangled` | `Option<String>` | C++ demangled 名称，如 `"foo::bar(int)"`，None 表示名称未做 demangle（C 函数或 Rust 函数） |
| `return_type` | `String` | LLVM IR 返回类型字符串，如 `"i32"`、`"ptr"`、`"void"` |
| `param_types` | `Vec<String>` | 参数类型列表，顺序与函数签名一致 |
| `calling_convention` | `String` | 调用约定，默认为 `"ccc"`（C 调用约定），跨语言边界可能出现 `"fastcc"`、`"swiftcc"` 等 |
| `blocks` | `Vec<IRBasicBlock>` | 基本块列表，按内存布局顺序排列，第一个块为函数入口 |
| `linkage` | `Option<String>` | 链接类型，如 `"internal"` 表示文件内可见，`"external"` 表示跨模块可见 |

**关系**：`IRFunction` 包含 `Vec<IRBasicBlock>`，通过块内的 `successors` 字段构建函数内部的控制流图（CFG）。`linkage` 为 `"external"` 的函数与 `IRModuleModel.declarations` 共同定义 FFI 边界。

---

### IRBasicBlock

控制流图的最小单元，块内指令顺序执行，块间通过终止指令跳转。

| 字段 | 类型 | 说明 |
|------|------|------|
| `label` | `String` | 块标签，如 `"entry"` 表示函数入口块，`"loop.header"` 等为编译器生成名称 |
| `instructions` | `Vec<IRInstructionModel>` | 块内指令列表，最后一条指令必须为终止指令（`br`/`ret`/`switch` 等） |
| `successors` | `Vec<String>` | **CFG 边**：后继块的标签列表，由终止指令决定。空列表表示函数出口块 |

**关系**：`successors` 字段是构建函数级控制流图的直接数据源。分析 Pass 通过遍历 `successors` 实现前向数据流分析；反向遍历可用于支配树构建。

---

### IRInstructionModel

LLVM IR 单条指令的结构化表示，是 IR 分析的最细粒度单元。

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | `Option<u64>` | 指令在块内的索引，从 0 开始，None 表示未编号（旧格式兼容） |
| `opcode` | `String` | 操作码字符串，如 `"call"`、`"load"`、`"store"`、`"br"`、`"getelementptr"` |
| `result_type` | `Option<String>` | 指令结果的类型；`store`/`br`/`ret void` 等无返回值指令为 `None` |
| `operand_types` | `Vec<String>` | 各操作数的类型列表，顺序与 `operands` 一一对应 |
| `operands` | `Vec<String>` | 操作数字符串，包含寄存器名（如 `%0`）、常量（如 `42`）、全局名（如 `@malloc`） |
| `callee` | `Option<String>` | 仅 `call`/`invoke` 指令有效：被调用函数名，不含前缀 `@`；间接调用时为 `None` |
| `is_indirect` | `bool` | 是否为函数指针间接调用，`true` 时 `callee` 为 `None`，调用目标在运行时确定 |
| `debug_loc` | `Option<String>` | 调试位置信息，格式为 `"/path/src/main.c:42:5"`（文件:行:列） |
| `raw` | `String` | 原始 LLVM IR 文本，用于调试和日志输出 |
| `source_type` | `Option<String>` | `bitcast`/`inttoptr` 链追踪后的原始类型，用于 FFI 类型恢复和类型混淆检测 |
| `gep_details` | `Option<IRGepDetails>` | 仅 `getelementptr` 指令有效：结构体字段访问的详细信息，包括基础类型和字段索引 |

**关系**：`callee` 字段直接对应 `IRModuleModel.functions` 中的某个函数名（已定义）或 `declarations` 中的某个声明（外部函数，即 FFI 调用点）。`is_indirect` 为 `true` 时，需通过 `source_type` 和上下文推断实际目标。

---

### 双模型说明

IR 层存在两套并行模型，在架构迁移期间共存：

**新模型**（`IRModuleModel` / `IRFunction` / `IRBasicBlock` / `IRInstructionModel`）：
- 由 C++ LLVM Pass 在编译期序列化为 JSON
- 字段完整，保留调试信息、GEP 细节、类型链等
- 用于精确分析（所有新 Pass 应优先使用此路径）

**旧模型**（`IRModule` legacy）：
- 通过文本 `.ll` 文件解析获得
- 包含 `.calls: Vec<IRCall>` 扁平化调用列表和 `.functions: Vec<FunctionBody>`
- 部分旧 Pass 仍在使用，新开发不应依赖此模型

两套模型在 `PassContext.ir_module` 中共存，分析 Pass 需明确自己消费的是哪套模型。

---

## 2. Issue 及相关类型 (omniscope-core)

### Issue

分析发现的安全问题的完整表示，是 OmniScope 的核心输出单元。

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | `IssueId` | 全局单调递增 ID，由 `PassContext::next_issue_id()` 分配，保证唯一性 |
| `kind` | `IssueKind` | 问题分类，决定问题的语义类别和 CWE 映射 |
| `severity` | `Severity` | 严重级别：`Error`（必须修复）/ `Warning`（应审查）/ `Info`（参考信息） |
| `confidence` | `Confidence` | 置信度：`High`(1.0) / `Medium`(0.66) / `Low`(0.33)，影响输出优先级 |
| `description` | `String` | 人类可读的问题描述，应包含具体的函数名和操作语义 |
| `location` | `Option<IssueLocation>` | 问题发生的源码位置，包含文件路径、行号、列号、函数名 |
| `ffi_boundary` | `Option<FFIBoundary>` | FFI 边界元数据，仅跨语言问题有效 |
| `trace` | `Vec<TraceEntry>` | 推理路径，记录从资源分配到问题点的完整操作序列，用于生成 SARIF `codeFlows` |
| `cwe_id` | `Option<u32>` | CWE 编号，由 `IssueKind::cwe_id()` 自动填充，无需手动设置 |
| `symbol` | `String` | **关键字段**：SRT（SemanticTree）查询键，通常为 callee 或当前函数名，Gate 以此为 key 查询语义标签 |

**不变式**：`symbol` 字段必须在调用 `issue_gate::check_issue()` 之前显式设置。未设置时的防御性默认值为 `"<unresolved-{kind:?}>"`，以便在 Gate 查询时可被识别为未解析状态而非错误地匹配到真实符号。

---

### IssueKind 分组

IssueKind 按功能域分为四组，反映分析覆盖的问题空间：

**FFI 边界问题（核心，占约 90% 的检测目标）**：
- `CrossLanguageFree` — 跨语言分配器不匹配（如 Rust 分配、C 释放）
- `OwnershipViolation` — 跨语言所有权语义违反
- `FfiTypeMismatch` — FFI 调用类型签名不匹配
- `AbiMismatch` — 调用约定或数据布局不兼容
- `UncheckedReturn` — FFI 调用返回值未检查（如 errno 风格错误）
- `FfiUnsafeCall` — 在不安全上下文中调用 FFI 函数
- `CallbackEscape` — 回调函数指针逃逸到外部语言运行时
- `LengthTruncation` — 长度/大小截断（如 `usize → uint32_t`、`size_t → int`），跨 FFI 边界传递时可能导致缓冲区溢出或内存越界

**本地内存问题（辅助，约 10%）**：
- `DoubleFree` / `UseAfterFree` / `InvalidFree` — 经典内存安全问题
- `MemoryLeak` — 资源泄漏
- `BufferOverflow` / `NullDereference` / `IntegerOverflow` — 内存访问安全

**资源契约问题（新架构）**：
- `CrossFamilyFree` — 不同资源族之间的错误释放
- `ConditionalLeak` — 引用计数路径下的条件性泄漏
- `BorrowEscape` — 借用引用逃逸出有效生命周期
- `WriteToImmutable` — 向不可变内存区域写入
- `DoubleReclaim` — 资源被两次回收所有权
- `OwnershipEscapeLeak` — `into_raw` 后未配对 `from_raw` 导致泄漏

**并发问题**：
- `DataRace` / `LockOrderViolation` / `ThreadCrossing` — 多线程资源共享安全

---

### FFIBoundary

描述 FFI 调用的跨语言边界元数据。

| 字段 | 类型 | 说明 |
|------|------|------|
| `caller_name` | `String` | 调用方函数名 |
| `callee_name` | `String` | 被调用方函数名 |
| `caller_lang` | `Language` | 调用方语言 |
| `callee_lang` | `Language` | 被调用方语言 |
| `boundary_kind` | `BoundaryKind` | 边界方向枚举：`RustToC` / `CToRust` / `GoToC` / `PythonToC` / `JavaToC` / `CSharpToC` / `ZigToC` |

**关系**：`FFIBoundary` 作为 `Issue.ffi_boundary` 的可选字段存在，仅在 `IssueKind` 属于 FFI 边界分组时有意义。`boundary_kind` 决定适用哪套 ABI 规则进行验证。

---

## 3. Effect 枚举 (omniscope-types)

`Effect` 是资源操作的语义原语。所有 Pass 通过 `Effect` 描述函数对资源的影响，以避免直接依赖函数名模式匹配（脆弱且不可扩展）。

| 变体 | 字段 | 语义 |
|------|------|------|
| `Acquire` | `family: FamilyId, result: ValueId` | 分配资源，`result` 为接收所有权的 value ID |
| `Release` | `family: FamilyId, arg: usize` | **无条件释放**，`arg` 为持有资源的参数索引 |
| `ConditionalRelease` | `family: FamilyId, arg: usize` | **条件释放**：仅在引用计数归零时才真正释放，如 `Py_DECREF` / `Arc::drop` |
| `Retain` | `family: FamilyId, arg: usize` | 引用计数递增，如 `Py_INCREF` / `CFRetain` |
| `ReturnsOwned` | `family: FamilyId` | 工厂函数返回拥有所有权的资源（调用方负责释放） |
| `ReturnsBorrowed` | — | 返回借用引用，无所有权转移（调用方不得释放） |
| `ConsumesArg` | `arg: usize, family: FamilyId` | 消耗参数但不释放（move 语义，所有权转移给被调用方） |
| `StoresArgToOwner` | `arg: usize, owner: ValueId` | 将参数存入 `owner` 对象的字段，owner 负责生命周期 |
| `StoresArgToGlobal` | `arg: usize` | 参数存入全局/静态存储，生命周期延伸至程序结束 |
| `InitializesOutParam` | `arg: usize, family: FamilyId` | 初始化输出参数（out-parameter 模式） |
| `EscapesToCallback` | `arg: usize` | 参数逃逸到回调函数，生命周期不可静态确定 |
| `OwnershipEscape` | `family: FamilyId, result: ValueId` | `Box::into_raw` / `CString::into_raw` / `Vec::into_raw`，所有权转移给原始指针 |
| `OwnershipReclaim` | `family: FamilyId, result: ValueId` | `Box::from_raw` / `CString::from_raw` / `Vec::from_raw`，所有权回到 Rust 类型系统 |

**关系**：`Effect` 枚举是 `ContractEdge.effect` 字段的类型，也是 `BehaviorPattern` 的推断依据。SummaryStore 以 `Effect[]` 形式存储每个函数的行为摘要，供 `ContractGraphBuilderPass` 消费。

**不变式**：`ConditionalRelease` 不能被建模为 `Release`。引用计数递减操作（`Py_DECREF`、`Arc::drop`）在大多数调用点不会真正释放内存，若建模为 `Release` 则后续每次调用都会触发 `UseAfterFree` / `DoubleFree` 误报，产生大量假阳性。

---

## 4. PointerContract 枚举 (omniscope-types)

描述指针的所有权语义，关注的是"谁负责释放"这一契约，而非指针的类型语法。

| 变体 | 语义 |
|------|------|
| `Owned` | 持有者拥有完全所有权，负责最终释放 |
| `Borrowed` | 借用引用，持有者不负责释放，不得在 owner 的生命周期之外使用 |
| `MaybeOwned` | 证据不足，无法确定所有权归属，保守处理（倾向于报告潜在问题） |
| `Transferred` | 所有权已转交给其他方（对应 `into_raw` 之后的状态） |
| `Retained` | 引用计数已递增，持有者对此次递增负责配对递减 |
| `Released` | 引用计数已递减，或已调用释放函数，资源不可再使用 |
| `ReturnedToCaller` | 工厂函数返回值，所有权移交给调用方 |
| `StoredInOwner` | 已存入某个 owner 字段，生命周期由 owner 管理，当前引用不独立负责 |
| `Escaped` | 已逃逸当前作用域（泄漏候选，需进一步分析是否确实泄漏） |
| `GcManaged` | 由垃圾回收器管理，无需（也不应）手动释放 |
| `StaticLifetime` | 静态生命周期资源，程序结束前始终有效，不释放 |
| `Unknown` | 无法通过静态分析确定所有权状态 |

**关系**：`PointerContract` 是 `ResourceInstance` 的状态字段类型，由 `OwnershipSolverPass` 通过状态机转换维护。状态转换由 `ContractEdge.effect` 驱动，从 `Owned` 出发，根据 `Effect` 变体转换到相应的终止状态。

---

## 5. FamilyId / ResourceFamily (omniscope-types)

`FamilyId(u16)` 是资源族的唯一标识符，用于替代语言级函数名匹配，实现分配/释放配对规则的统一管理。

**配对规则**：资源的分配方和释放方必须满足 `family(alloc) == family(release)`，或在 `ResourceFamily` 中显式声明兼容性。

### 内置 FamilyId 表

| ID | 常量名 | 对应的分配/释放函数 |
|----|--------|-------------------|
| 1 | `C_HEAP` | `malloc` / `calloc` / `realloc` + `free` |
| 2 | `CPP_NEW_SCALAR` | `operator new` / `operator delete` |
| 3 | `CPP_NEW_ARRAY` | `operator new[]` / `operator delete[]` |
| 4 | `RUST_GLOBAL` | `__rust_alloc` / `__rust_dealloc` |
| 5 | `PYTHON_OBJECT` | `PyObject_New` / `PyObject_Free` |
| 6 | `PYTHON_MEM` | `PyMem_Malloc` / `PyMem_Free` |
| 7 | `PYTHON_MEM_RAW` | `PyMem_RawMalloc` / `PyMem_RawFree` |
| 8 | `JAVA_LOCAL_REF` | `NewLocalRef` / `DeleteLocalRef` |
| 9 | `JAVA_GLOBAL_REF` | `NewGlobalRef` / `DeleteGlobalRef` |
| 10 | `CSHARP_HGLOBAL` | `Marshal.AllocHGlobal` / `FreeHGlobal` |
| 11 | `CSHARP_COTASK` | `CoTaskMemAlloc` / `CoTaskMemFree` |
| 12 | `GO_GC` | `runtime.mallocgc`（GC 管理，通常不需手动释放） |
| 13 | `ZIG_ALLOCATOR` | Zig allocator vtable 接口 |
| 14 | `ZLIB_STREAM` | `inflateInit_` / `inflateEnd` |
| 15 | `OPENSSL_RESOURCE` | `EVP_CIPHER_CTX_new` / `EVP_CIPHER_CTX_free` 等 |
| 16 | `SQLITE_RESOURCE` | `sqlite3_open` / `sqlite3_close` 等 |
| 17 | `GO_CGO` | `_cgo_allocate` / `_cgo_free` |
| 18 | `MIMALLOC` | `mi_malloc` / `mi_free` |
| 19 | `JNI_OBJECT` | JNI 对象引用管理 |
| 20 | `LIBUV_HANDLE` | `uv_*_init` / `uv_close` |
| 21 | `GLIB_OBJECT` | `g_object_new` / `g_object_unref` |
| 100+ | 用户自定义 | `user_family_start` 起始，由配置文件或插件定义 |

**不变式**：`FamilyId(0)` 为无效值，保留作哨兵，不得在任何 `Effect`、`ContractEdge` 或 `ResourceFamily` 中使用。使用 ID 0 的分析结果视为数据损坏。

**关系**：`FamilyId` 出现在 `Effect`（描述操作所属资源族）、`ContractEdge.family`（边级资源族）、`ResourceFamily`（声明兼容性规则）三处。`CrossFamilyFree` 问题的检测依赖于比对分配端和释放端的 `FamilyId` 是否兼容。

---

## 6. ContractGraph / ContractEdge (omniscope-pass)

`ContractGraph` 是资源生命周期的有向图，对整个模块的资源流动进行建模。

- **节点**：resource instance ID（`u64`），唯一标识一次资源分配事件
- **边**：`ContractEdge`，描述两个资源实例之间的操作语义
- **用途**：`OwnershipSolverPass` 在此图上运行状态机，推导每个资源实例的最终 `PointerContract`

### ContractEdge

| 字段 | 类型 | 说明 |
|------|------|------|
| `source` | `u64` | 源 resource instance ID，表示操作作用于哪个资源 |
| `target` | `u64` | 目标 ID；`0` 表示终端节点（该资源在此边后无后继，即已释放或逃逸） |
| `effect` | `Effect` | 边的语义，决定状态机的转换方向 |
| `function` | `FunctionId` | 边所在的函数 ID，用于跨函数分析 |
| `function_name` | `String` | 函数名，仅用于诊断输出（不参与匹配逻辑） |
| `caller_name` | `String` | 调用方函数名，用于在 `Issue.location` 中定位问题 |
| `family` | `Option<FamilyId>` | 资源族标识，已知时填充；`None` 表示类型推断尚未完成 |

**关系**：`ContractGraph` 存储在 `PassContext.shared` 中，以约定键名 `"contract_graph"` 访问。`ContractGraphBuilderPass` 写入，`OwnershipSolverPass` 读取并运行状态机，`IssueCandidateBuilderPass` 在此基础上构建候选问题。

---

## 7. SemanticKind 与 SRT (omniscope-semantics)

`SemanticKind` 是 R-0 至 R-8 系列的假阳性（FP）抑制标签体系。由 Layer 1 探测器（语义探测 Pass）写入 `SemanticTree`（SRT），由 `issue_gate` 在 Issue 发射前查询，决定是否抑制当前候选 Issue。

### SemanticKind 标签表

| 标签 | R 编号 | 语义含义 | 抑制的 IssueKind |
|------|--------|---------|-----------------|
| `MutableParam` | R-0 | LLVM `mutable` param attribute，对应 Rust `&mut T` | `WriteToImmutable` |
| `ReadonlyParam` | R-0 | LLVM `readonly` attribute，对应 Rust `&T` | —（用于推断，不直接抑制） |
| `HeapProvenance` | R-1 | 堆分配来源追踪（`Box`/`Arc`/`Vec` 等 Rust 堆类型） | `BorrowEscape` |
| `GlobalProvenance` | R-1 | 全局/静态存储来源，生命周期为程序级 | `BorrowEscape` |
| `InteriorMutability` | R-2 | `UnsafeCell` 类型链（`Cell`/`RefCell`/`Mutex`/`RwLock` 等） | `WriteToImmutable` |
| `RaiiDropRelease` | R-3 | 编译器插入的 `drop_in_place` 调用或函数尾部的 `__rust_dealloc` | `UseAfterFree` / `DoubleFree` |
| `FileOperation` | R-4 | POSIX 文件操作语义（`open`/`close`/`read`/`write`），非内存管理 | `CrossLanguageFree` |
| `NetworkOperation` | R-4 | POSIX 网络操作语义（`socket`/`connect`/`send`/`recv`） | `CrossLanguageFree` |
| `ProcessOperation` | R-4 | POSIX 进程操作语义（`fork`/`exec`/`waitpid`） | `CrossLanguageFree` |
| `IntoRawTransfer` | R-6 | `Box::into_raw` / `CString::into_raw` / `Vec::into_raw` 所有权显式转移 | `CrossLanguageFree` |
| `LibraryRelease` | R-7 | 库级分配器的释放操作（`mi_free`/`inflateEnd`/`sqlite3_close` 等） | `CrossLanguageFree` |
| `FromParameter` | R-8 | 函数参数指针，非当前栈帧分配，逃逸分析不适用 | `BorrowEscape` |

### SemanticTree (SRT)

`SemanticTree` 是以 `symbol`（函数名字符串）为 key、`Vec<SemanticResolution>` 为 value 的多值映射。

- **写入**：语义探测 Pass（Layer 1）通过 `srt.insert(symbol, kind)` 写入
- **查询**：`issue_gate::check_issue()` 通过 `srt.has_kind(symbol, kind)` 查询，返回 `bool`
- **关系**：SRT 存储在 `PassContext.shared` 中，以约定键名 `"semantic_tree"` 访问

---

## 8. PassContext (omniscope-pass)

Pass 间共享状态的中央容器，作为分析 Pass 的运行时环境。

**线程模型**：`PassContext` 不可跨线程共享（无 `Send + Sync`）。所有 Pass 按拓扑排序顺序在单线程上依次执行。

| 字段 | 类型 | 说明 |
|------|------|------|
| `ir_module` | `Option<Arc<IRModule>>` | 被分析的 IR 模块（旧模型路径），以 `Arc` 包裹支持 `&IRModule` 引用共享 |
| `shared` | `Arc<HashMap<String, Arc<dyn Any + Send + Sync>>>` | **类型化 KV 存储**：Pass 通过 `ctx.store("key", value)` 写入，`ctx.get::<T>("key")` 读取；键名为字符串约定 |
| `diagnostics` | `Vec<Diagnostic>` | Pass 产生的调试诊断信息，不进入最终输出 |
| `facts` | `Vec<Fact>` | Pass 间传递的原始事实（轻量级断言），供后续 Pass 消费 |
| `issues` | `Vec<Issue>` | 通过 Gate 验证的最终问题列表，写入输出报告 |
| `suppressed_issues` | `Vec<Issue>` | 被 SRT Gate 抑制的候选问题，保留用于调试和 FP 分析 |
| `next_issue_id` | `u64` | 单调递增 Issue ID 计数器，由 `next_issue_id()` 方法原子递增后返回 |
| `pool` | `MemoryPool` | bumpalo 内存池，用于 Pass 内临时分配；每个 Pass 完成后重置，避免内存积压 |

### 主要共享键（约定）

以下键名为跨 Pass 通信的接口约定，无编译期类型检查：

| 键名 | 值类型 | 写入方 | 读取方 |
|------|--------|--------|--------|
| `"contract_graph"` | `ContractGraph` | `ContractGraphBuilderPass` | `OwnershipSolverPass` |
| `"summary_store"` | `SummaryStore` | `StructuralInferencePass` | `ContractGraphBuilderPass` |
| `"semantic_tree"` | `SemanticTree` | 语义探测 Pass | `issue_gate` |
| `"ownership_states"` | `Vec<ResourceInstance>` | `OwnershipSolverPass` | `IssueCandidateBuilderPass` |

**不变式**：`PassContext.shared` 的键名是字符串约定，不受编译器检查。修改任意键名需全局搜索所有写入点（`ctx.store(...)`）和读取点（`ctx.get::<T>(...)`），遗漏将导致运行时 `None` 返回，Pass 静默跳过分析。

---

## 9. FFIVerdict / FFISafetyAssessment (omniscope-semantics)

`FFIVerdict` 是语义引擎对单次 FFI 调用安全性的最终判定。

| 变体 | 语义 | 安全分数 |
|------|------|---------|
| `SafeNoOwnership` | 纯计算操作，对资源所有权无影响 | 0.95 |
| `SafeConditionalRelease` | 引用计数条件释放，不构成真正的无条件释放 | 0.90 |
| `SafeInternalBridge` | 同项目内部 FFI 桥接，上下文可控 | 0.85 |
| `SafePointerProjection` | `as_ptr()` 风格借用，仅返回裸指针引用 | 0.90 |
| `SafeInitialization` | 构造函数模式，仅初始化字段，不涉及释放 | 0.85 |
| `ConcernOwnershipTransfer` | 所有权转移，需结合 `CrossFamilyFree` 分析确认 | 0.30 |
| `Unknown` | 信息不足，无法判定 | 0.50 |

### FFISafetyAssessment

对单次 FFI 调用的完整安全评估报告。

| 字段 | 说明 |
|------|------|
| `callee` | 被调用的 FFI 函数名 |
| `caller` | 发起调用的函数名 |
| `caller_behavior` | 调用方的行为分析（`BehaviorPattern` 序列） |
| `callee_behavior` | 被调用方的行为分析（`BehaviorPattern` 序列） |
| `verdict` | `FFIVerdict` 最终判定 |
| `ir_evidence` | 支持判定的 IR 证据列表（指令引用、类型信息等） |

**关系**：`FFISafetyAssessment` 是 `SemanticEngine::assess_ffi_safety()` 的输出，其结果写入 `SemanticTree`，影响后续 `issue_gate` 的 Gate 决策。

---

## 10. BehaviorPattern (omniscope-semantics/ir_pattern.rs)

`BehaviorPattern` 是从指令序列中提取的函数级行为模式，**不依赖函数名字符串匹配**，而是通过 IR 指令结构推断语义。

| 变体 | 关键 IR 特征 | 语义 |
|------|-------------|------|
| `ConditionalRelease { atomic_op, threshold }` | `atomicrmw sub` + `icmp eq` + `br` + `call @destroy` 序列 | 引用计数条件释放（RC 归零才真正释放） |
| `PureComputation` | 返回值仅用于算术运算或 `store`，从不传给 `free`/`dealloc` | 纯计算，无副作用 |
| `OwnershipTransfer { is_acquire }` | 返回指针被传给 `free`/`dealloc`，或跨 FFI 边界存储 | 所有权转移（is_acquire=true 为分配，false 为释放） |
| `PointerProjection` | 仅有 `getelementptr` + `bitcast` + `ret`，无其他副作用 | `as_ptr()` 风格借用，不转移所有权 |
| `Initialization` | 仅有 `store` 到结构体字段 + `ret void`，无 `call` | 构造函数模式，仅初始化，不管理生命周期 |
| `InternalBridge` | 所有 `call` 目标均为同项目函数（非外部声明） | 内部 FFI 桥，无跨语言边界 |
| `BorrowedReturn { from_readonly_param }` | 返回值派生自 `readonly` 参数（R-0） | 借用返回，返回值生命周期受参数约束 |
| `RAiiDropRelease { is_drop_in_place }` | 编译器插入的 `drop_in_place` 或函数尾部的 `__rust_dealloc`（R-3） | RAII 自动析构，非显式 double-free |
| `IntoRawOwnershipTransfer` | `Box::into_raw` / `CString::into_raw` / `Vec::into_raw` 特征指令序列（R-6） | 所有权显式转移给原始指针 |

**关系**：`BehaviorPattern` 由 `IRBehaviorSummaryPass` 写入 `SummaryStore`，以函数为单位存储。`SemanticEngine` 消费 `BehaviorPattern` 生成 `FFISafetyAssessment`，`issue_gate` 最终参考这些模式决定是否发射 `Issue`。

---

## 数据流关系图

```
IRModuleModel（新模型，C++ Pass 序列化）
    │
    ├─── IRFunction → IRBasicBlock → IRInstructionModel（结构化 IR）
    │
    ▼
IRModule legacy（旧模型，.ll 文本解析）
    │   .calls: Vec<IRCall>（扁平调用列表）
    │   .functions: Vec<FunctionBody>
    │
    ├─── RawFactCollectorPass ──────────────→ Fact[] → PassContext.facts
    │
    ├─── IRBehaviorSummaryPass ─────────────→ BehaviorPattern[] → SummaryStore
    │
    ├─── StructuralInferencePass ───────────→ ResourceSummary → SummaryStore
    │         （识别 drop_glue / into_raw / POSIX / lib_pairs）
    │
    ├─── ContractGraphBuilderPass
    │         │  消费 SummaryStore，构建资源生命周期边
    │         │  产出 ContractGraph（nodes: u64, edges: ContractEdge[]）
    │         │  每条边携带 Effect + FamilyId + function context
    │         ▼
    │    OwnershipSolverPass
    │         │  在 ContractGraph 上运行 PointerContract 状态机
    │         │  产出 Vec<ResourceInstance>（每个资源的最终契约状态）
    │         ▼
    │    IssueCandidateBuilderPass
    │         │  将非正常终止状态（Escaped/MaybeOwned等）转为 IssueCandidate
    │         ▼
    │    IssueVerifierPass
    │         │  对候选问题做二次验证（排除已知安全模式）
    │         ▼
    │    issue_gate::check_issue(issue, SemanticTree)
    │         │  R-0~R-8 标签查询：has_kind(issue.symbol, kind)
    │         │  通过 → PassContext.issues
    │         │  抑制 → PassContext.suppressed_issues（调试保留）
    │
    └─── SemanticEngine（Layer 1，并行运行）
              │  assess_ffi_safety(callee, caller, ir_module)
              │  → FFISafetyAssessment { FFIVerdict, IREvidence[] }
              │  → BehaviorPattern 序列
              ▼
         SemanticTree（SRT）
              │  symbol → Vec<SemanticKind>
              │  多值映射，支持同一函数携带多个语义标签
              ▼
         issue_gate（Gate 查询终点）
```

---

## 关键不变式

以下约束是 OmniScope-rs 分析正确性的基础，违反任何一条都可能导致大量假阳性/假阴性或运行时错误。

### 不变式 1：ConditionalRelease 不能建模为 Release

引用计数递减操作（`Py_DECREF`、`Arc::drop`、`CFRelease` 等）在绝大多数调用点**不会**实际释放内存，只有在计数归零时才触发真正的 `free`。

若将其建模为 `Release`，则每次调用该函数之后，`OwnershipSolverPass` 都会将资源状态转为 `Released`，导致后续所有使用点被错误标记为 `UseAfterFree` 或 `DoubleFree`，产生无法控制的假阳性洪流。

正确建模方式：始终使用 `Effect::ConditionalRelease`，由 `OwnershipSolverPass` 通过 `BehaviorPattern::ConditionalRelease` 的 `threshold` 条件分支处理。

### 不变式 2：FamilyId(0) 无效，不得使用

`FamilyId(0)` 是保留的哨兵值，表示"未初始化"或"无效资源族"。任何 `Effect`、`ContractEdge` 或 `ResourceFamily` 中出现 `FamilyId(0)` 均视为数据损坏。

分析代码在读取 `FamilyId` 时应断言 `id.0 != 0`；写入时应使用具名常量（如 `C_HEAP`、`PYTHON_OBJECT`）或用户自定义 ID（`>= 100`）。

### 不变式 3：Issue.symbol 必须在 Gate 查询前设置

`issue_gate::check_issue()` 使用 `Issue.symbol` 作为 SRT 查询键。若 `symbol` 未设置，则保留默认的防御占位符 `"<unresolved-{kind:?}>"`，Gate 将无法找到对应的语义标签，导致所有 R-0~R-8 抑制规则失效，使本应抑制的 Issue 穿透 Gate 进入输出。

`symbol` 应在构造 `Issue` 时即设置为 `callee`（对 FFI 调用问题）或当前函数名（对内部内存问题）。

### 不变式 4：PassContext.shared 的键名是纯字符串约定，无编译期保障

`PassContext.shared` 是 `HashMap<String, Arc<dyn Any + Send + Sync>>`，类型擦除后通过 `downcast` 恢复。键名（如 `"contract_graph"`、`"semantic_tree"`）是 Pass 间的接口契约，但完全不受编译器检查。

以下操作必须进行全局搜索验证：
- **重命名键名**：需同时修改所有 `ctx.store("old_key", ...)` 写入点和 `ctx.get::<T>("old_key")` 读取点
- **修改值类型**：需同时修改写入时的类型参数和所有读取时的 `downcast` 目标类型
- **新增键**：需在本文档的"主要共享键"表中登记，说明写入方和读取方

遗漏任何一处修改将导致读取方在运行时收到 `None`，Pass 静默跳过分析，不产生任何错误提示，极难排查。
