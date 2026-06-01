# OmniScope-rs 调用链文档

本文档描述 OmniScope-rs 系统内部各主要执行路径的调用链。OmniScope-rs 是一个基于 LLVM IR 的静态分析器，专用于跨语言 FFI 安全审计。

---

## 1. 顶层入口链：CLI → Pipeline → PassManager

用户执行 `omniscope analyze` 时，程序控制流经过以下路径进入核心分析逻辑：

```
omniscope-cli/src/main.rs
  └── clap 参数解析（analyze 子命令）
      └── Pipeline::with_config(config)
          └── pipeline.register_default_passes()
              ├── CallGraphPass            （构建调用图）
              ├── FFIBoundaryPass          （识别 FFI 边界）
              ├── SurfaceClassifierPass    （表面类型分类）
              ├── DangerSurfacePass        （危险表面检测）
              ├── RawFactCollectorPass     （原始事实收集）
              ├── IRBehaviorSummaryPass    （行为摘要提取）
              ├── SummaryBuilderPass       （资源摘要构建）
              ├── StructuralInferencePass  （结构推断）
              ├── ContractGraphBuilderPass （契约图构建）
              ├── OwnershipSolverPass      （所有权求解）
              ├── IssueCandidateBuilderPass（问题候选生成）
              ├── IssueVerifierPass        （问题验证/过滤）
              ├── LeakDetectionPass        （泄漏检测）
              ├── RaiiDropPass             （RAII Drop 分析）
              ├── InteriorMutabilityPass   （内部可变性分析）
              ├── HeapProvenancePass       （堆来源追踪）
              ├── BorrowEscapePass         （借用逃逸检测）
              ├── WriteToImmutablePass     （写不可变量检测）
              └── FfiReturnCheckPass       （FFI 返回值检查）
          └── pipeline.run()
              └── PassManager::run_all_with_ir(ir_module)
                  └── 拓扑排序所有已注册 Pass
                      └── 按依赖顺序依次调用 pass.run(ctx)
```

**拓扑排序机制**：每个 Pass 实现 `fn dependencies() -> Vec<&'static str>` 方法，声明本 Pass 依赖哪些 Pass 的输出。PassManager 在执行前根据这些声明构建有向无环图（DAG），然后进行拓扑排序，确保依赖 Pass 先于当前 Pass 执行。若存在循环依赖，PassManager 在注册阶段报错并中止。

---

## 2. 资源契约分析主链（核心）

这是整个分析系统中最核心的执行路径，从原始 IR 事实出发，经过多层 Pass 的逐步转化，最终生成经过验证的安全问题。

```
RawFactCollectorPass.run(ctx)
  └── 遍历 IRModule.calls（所有调用指令）
      └── 模式匹配：识别 acquire / release / retain 语义调用
          └── 写入 ctx.facts[]
              （每条 Fact 包含：call_site、symbol、fact_kind）

IRBehaviorSummaryPass.run(ctx)
  └── 读取 ctx.facts（依赖 RawFactCollector 的输出）
      └── 对每个函数调用 extract_behavior(function_body)
          └── 返回 FunctionBehavior {
                  patterns: Vec<BehaviorPattern>,
                  return_source: ReturnSource,
              }
          └── 写入 ctx.store("behavior_summaries", Map<Symbol, FunctionBehavior>)

SummaryBuilderPass.run(ctx)
  └── 读取 ctx.store("behavior_summaries")
      └── 对每个 (symbol, behavior) 调用 infer_summary_for_symbol(symbol, behavior)
          └── 调用 behavior_to_summary(behavior)
              └── 将 BehaviorPattern 映射为 Effect（Acquire / Release / Escape / Transfer）
              └── 返回 ResourceSummary { effects: Vec<Effect>, family: ResourceFamily, ... }
      └── 写入 ctx.store("summary_store", SummaryStore)

StructuralInferencePass.run(ctx)
  └── 读取 ctx.facts（依赖 RawFactCollector 的输出）
      └── 对每个函数运行多组结构推断规则：
          ├── infer_drop_glue_summary()
          │     └── 识别 drop_in_place / __rust_dealloc 模式
          │         → 生成 R-3 RaiiDropRelease 摘要
          ├── infer_into_raw_summary()
          │     └── 识别 into_raw / from_raw 配对
          │         → 生成 R-6 IntoRawTransfer 摘要
          ├── infer_posix_syscall_summary()
          │     └── 识别 open / socket / fork 等 POSIX 调用
          │         → 生成 R-4 FileOperation / NetworkOperation / ProcessOperation 摘要
          ├── infer_library_alloc_summary()
          │     └── 识别 malloc / free / jemalloc 等调用
          │         → 生成 R-7 LibraryRelease 摘要
          ├── infer_param_attr_summary()
          │     └── 分析函数参数访问模式
          │         → 生成 R-0 MutableParam / ReadonlyParam 摘要
          └── infer_refcount_release_summary()
                └── 识别引用计数递减并条件释放模式
                    → 生成 ConditionalRelease 摘要
      └── 写入 ctx.store("structural_summaries", Map<Symbol, ResourceSummary>)
      └── 同步写入语义解析树（SRT）（见第 4 节）

ContractGraphBuilderPass.run(ctx)
  └── 读取 ctx.store("summary_store")
      └── 读取 ctx.store("structural_summaries")
          └── 合并两类摘要，对每个函数调用点遍历 SummaryStore
              └── 对每个 Effect 构建一条 ContractEdge：
                  ContractEdge {
                      source:  调用者 Symbol,
                      target:  被调用者 Symbol,
                      effect:  Effect（Acquire/Release/Escape/Transfer）,
                      call_site: IRCallSite,
                  }
              └── graph.add_edge(ContractEdge)
      └── 写入 ctx.store("contract_graph", ContractGraph)

OwnershipSolverPass.run(ctx)
  └── 读取 ctx.store("contract_graph")
      └── 第一遍（Acquire 边）：
          └── 对每条 Acquire 边创建 ResourceInstance：
              ResourceInstance {
                  id:       唯一资源标识符,
                  family:   ResourceFamily（Heap / File / Net / ...）,
                  contract: PointerContract::Owned,
              }
      └── 第二遍（其他边）：
          └── 对每条 Release / Escape / Transfer 边调用状态转换：
              ResourceInstance.apply_event(OwnershipEvent)
              └── 所有权状态机：
                  Owned ──Release──► Released
                  Owned ──Escape───► Escaped
                  Owned ──Transfer─► Transferred
                  Released ──Release──► DoubleFree（标记异常）
      └── 写入 ctx.store("ownership_states", Vec<ResourceInstance>)

IssueCandidateBuilderPass.run(ctx)
  └── 读取 ctx.store("ownership_states")
      └── 对每个 ResourceInstance 进行模式判断：
          ├── contract == Escaped
          │     → 生成 ConditionalLeak 候选
          ├── 同一资源出现两次 Released（DoubleFree 标记）
          │     → 生成 DoubleFree 候选
          └── Release 边的调用方 family 与 ResourceInstance.family 不匹配
                → 生成 CrossFamilyFree 候选
      └── 写入 ctx.store("issue_candidates", Vec<IssueCandidate>)

IssueVerifierPass.run(ctx)
  └── 读取 ctx.store("issue_candidates")
      └── 读取 ctx.get_srt()（语义解析树）
          └── 对每个 IssueCandidate 调用语义门控：
              issue_gate::check_issue(candidate, |sym, kind| srt.has_kind(sym, kind))
              ├── GateVerdict::Allow
              │     → issue 写入 ctx.issues
              │     → 返回 EmitOutcome::Allowed { id }
              └── GateVerdict::Suppress* （含 SuppressRaii / SuppressKnownSafe 等）
                    → issue 写入 ctx.suppressed_issues
                    → 返回 EmitOutcome::Suppressed { id, reason }
```

**数据流总结**：

```
IRModule
  │
  ├──► RawFactCollectorPass ──────────────────► facts[]
  │
  ├──► IRBehaviorSummaryPass ─────────────────► behavior_summaries
  │         (依赖 facts)
  │
  ├──► SummaryBuilderPass ────────────────────► summary_store
  │         (依赖 behavior_summaries)
  │
  ├──► StructuralInferencePass ───────────────► structural_summaries + SRT
  │         (依赖 facts)
  │
  ├──► ContractGraphBuilderPass ──────────────► contract_graph
  │         (依赖 summary_store + structural_summaries)
  │
  ├──► OwnershipSolverPass ───────────────────► ownership_states
  │         (依赖 contract_graph)
  │
  ├──► IssueCandidateBuilderPass ─────────────► issue_candidates
  │         (依赖 ownership_states)
  │
  └──► IssueVerifierPass ─────────────────────► issues[] + suppressed_issues[]
            (依赖 issue_candidates + SRT)
```

---

## 3. FFI 边界检测链（FFIBoundaryPass）

FFIBoundaryPass 独立于主资源契约链运行，专门识别跨语言调用并评估其安全性：

```
FFIBoundaryPass.run(ctx)
  └── 读取 IRModule.calls（依赖 CallGraph）
      └── 对每个 IRCall 执行以下分析：
          │
          ├── 识别调用者语言
          │     └── LanguageDetector::detect(caller_name, caller_function)
          │           （详见第 5 节）
          │
          ├── 识别被调用者语言
          │     └── 检查 IRModule.declarations 中的外部函数声明
          │         └── LanguageDetector::detect(callee_name, callee_decl)
          │
          ├── 比较调用者语言 vs 被调用者语言
          │     ├── 语言相同 → 不是 FFI 边界，跳过
          │     └── 语言不同 → 疑似 FFI 边界，继续分析
          │
          └── assess_ffi_safety(callee, caller, module)
                （位于 semantic_engine.rs）
                │
                ├── 从 FamilyRegistry 查找 callee 的 FamilyEntry
                │     └── FamilyEntry 包含该函数的已知资源语义
                │
                ├── extract_behavior(callee_body) → FunctionBehavior + BehaviorPattern[]
                │
                ├── extract_behavior(caller_body) → FunctionBehavior
                │
                └── 根据 BehaviorPattern 匹配返回 FFIVerdict：
                    ├── ConditionalRelease → FFIVerdict::SafeConditionalRelease
                    │     （调用方有条件地释放，受控安全）
                    ├── PureComputation    → FFIVerdict::SafeNoOwnership
                    │     （纯计算，无资源所有权转移）
                    ├── PointerProjection  → FFIVerdict::SafePointerProjection
                    │     （仅指针投影，不转移所有权）
                    ├── InternalBridge     → FFIVerdict::SafeInternalBridge
                    │     （同一 crate 内部桥接，可信）
                    ├── OwnershipTransfer  → FFIVerdict::ConcernOwnershipTransfer
                    │     （所有权跨 FFI 边界转移，需报告）
                    └── 其他              → FFIVerdict::Unknown
                          （行为模式无法识别）

          根据 FFIVerdict 决定后续处理：
          │
          ├── verdict.is_safe() == true
          │     → 跳过，不生成 Issue
          │
          ├── verdict == ConcernOwnershipTransfer
          │     → 构建 CrossFamilyFree Issue（HIGH severity）
          │         并通过 ctx.emit_issue() 进入验证链
          │
          └── verdict == Unknown 且 FamilyEntry 存在
                → 降级处理，生成 LOW severity Issue
                    （已知函数但行为不确定，保守报告）
```

---

## 4. 语义解析树（SRT）写入链

语义解析树（SemanticResolutionTree，SRT）是一个全局的语义注解存储，由多个 Layer 1 Pass 写入，最终统一被 IssueVerifierPass 通过 `issue_gate` 查询以决定是否抑制误报。

**写入阶段**（各 Pass 独立写入，不相互依赖）：

```
RaiiDropPass.run(ctx)
  └── 扫描函数体中的 drop_in_place / __rust_dealloc 调用模式
      └── 对匹配符号调用：
          srt.add_resolution(symbol, SemanticResolution {
              kind: SemanticKind::RaiiDropRelease,
              confidence: High,
          })
          （标注该符号具有 RAII 析构释放语义，后续验证中可抑制泄漏误报）

HeapProvenancePass.run(ctx)
  └── 扫描 Box::new / Arc::new / Rc::new / malloc / calloc / operator new 等调用
      └── 对匹配符号调用：
          srt.add_resolution(symbol, SemanticResolution {
              kind: SemanticKind::HeapProvenance,
              source: alloc_site,
          })
          （标注该符号的堆分配来源，用于区分栈变量与堆变量）

InteriorMutabilityPass.run(ctx)
  └── 扫描类型链中的 UnsafeCell<T> / Cell<T> / RefCell<T> / Mutex<T> 使用
      └── 对匹配符号调用：
          srt.add_resolution(symbol, SemanticResolution {
              kind: SemanticKind::InteriorMutability,
              wrapper_type: type_name,
          })
          （标注该符号通过内部可变性模式进行写操作，避免误报 WriteToImmutable）

StructuralInferencePass.run(ctx)
  └── 在写入 structural_summaries 的同时，同步写入 SRT：
      ├── infer_param_attr_summary() 匹配后：
      │     srt.add_resolution(symbol, MutableParam)   （参数被写入）
      │     srt.add_resolution(symbol, ReadonlyParam)  （参数只读）
      ├── infer_into_raw_summary() 匹配后：
      │     srt.add_resolution(symbol, IntoRawTransfer)
      │     （标注所有权通过 into_raw/from_raw 显式转移，抑制泄漏报告）
      ├── infer_posix_syscall_summary() 匹配后：
      │     srt.add_resolution(symbol, FileOperation)
      │     srt.add_resolution(symbol, NetworkOperation)
      │     srt.add_resolution(symbol, ProcessOperation)
      └── infer_library_alloc_summary() 匹配后：
            srt.add_resolution(symbol, LibraryRelease)
            （标注该符号使用非 Rust 标准分配器，影响释放路径判断）
```

**查询阶段**（IssueVerifierPass 读取 SRT）：

```
IssueVerifierPass.run(ctx)
  └── 对每个 IssueCandidate 调用：
      issue_gate::check_issue(
          candidate,
          |sym, kind| ctx.get_srt().has_kind(sym, kind)
      )
      └── issue_gate 内部逻辑示例：
          ├── 若 candidate.kind == ConditionalLeak
          │   且 srt.has_kind(sym, RaiiDropRelease) == true
          │     → GateVerdict::SuppressRaii（已有析构器处理，不是真实泄漏）
          ├── 若 candidate.kind == WriteToImmutable
          │   且 srt.has_kind(sym, InteriorMutability) == true
          │     → GateVerdict::SuppressKnownSafe（内部可变性模式，合法写操作）
          └── 否则 → GateVerdict::Allow
```

**SRT 数据流**：

```
RaiiDropPass ──────────────┐
HeapProvenancePass ─────────┤
InteriorMutabilityPass ─────┼──► SRT (语义解析树)
StructuralInferencePass ────┘         │
                                      │ has_kind(sym, kind) 查询
                                      ▼
                              IssueVerifierPass
                              └── issue_gate::check_issue()
                                  └── GateVerdict → Allow / Suppress
```

---

## 5. 语言检测链

`LanguageDetector::detect` 被 FFIBoundaryPass 调用，用于判断一个 IR 函数属于哪种源语言。检测采用加权投票机制，综合多种启发式信息：

```
LanguageDetector::detect(function_name: &str, ir_function: &IRFunction)
  │
  └── 初始化投票计数器：Map<Language, Score>
      │
      ├── [规则 1] Name Mangling 模式匹配（权重：高）
      │     ├── 前缀 "_ZN" 且含 "17h" 哈希后缀  → Rust   +3
      │     ├── 前缀 "_ZN" 无 Rust 后缀           → C++    +3
      │     ├── 前缀 "_Z" 无命名空间              → C++    +2
      │     ├── 含 "PyObject" / "PyArg_"          → Python +3
      │     ├── 含 "Java_" 前缀                   → Java   +3
      │     ├── 含 "JNIEnv"                       → Java   +2
      │     └── 无 mangling（纯 C 风格名称）      → C      +1
      │
      ├── [规则 2] 调用约定分析（权重：中）
      │     ├── fastcc                            → Rust   +2
      │     ├── ccc                               → C/C++  +1
      │     └── win64cc / arm_aapcscc             → C      +1
      │
      ├── [规则 3] 参数类型特征（权重：高）
      │     ├── 参数含 "JNIEnv*" 类型             → Java   +3
      │     ├── 参数含 "GoInt" / "GoString" 类型  → Go     +3
      │     ├── 参数含 "PyObject*" 类型           → Python +3
      │     └── 参数含 "GCHandle" 类型            → CSharp +3
      │
      └── [规则 4] Debug Location 路径后缀（权重：中）
            ├── debug_loc 路径以 ".go" 结尾       → Go     +2
            ├── debug_loc 路径以 ".py" 结尾       → Python +2
            ├── debug_loc 路径以 ".cs" 结尾       → CSharp +2
            ├── debug_loc 路径以 ".java" 结尾     → Java   +2
            └── debug_loc 路径以 ".zig" 结尾      → Zig    +2

  └── 统计得分，取最高分对应的语言
      └── 若最高分 < 阈值（不足以置信）→ Language::Unknown
      └── 返回 Language::{Rust | C | Cpp | Python | Java | CSharp | Go | Zig | Unknown}
```

**语言检测结果用途**：

- 在 FFIBoundaryPass 中判断调用者与被调用者是否属于不同语言
- 语言差异触发 FFI 边界分析流程
- 检测结果写入 IRCall.metadata，供后续 Pass 查询

---

## 6. Issue 发射链（单个 Pass 视角）

所有需要报告安全问题的 Pass 均遵循统一的发射流程。以下描述单个 Pass 内部发射一条 Issue 的完整路径：

```
pass.run(ctx)
  │
  └── 发现疑似问题后，构建 Issue 对象：
      Issue {
          id:         唯一标识符（UUID）,
          kind:       IssueKind（如 ConditionalLeak / DoubleFree / ...）,
          severity:   Severity（Critical / High / Medium / Low）,
          symbol:     关联的 Symbol（函数或变量名）,
          call_site:  触发位置（IRCallSite { file, line, column }）,
          message:    人类可读描述,
      }
      │
      └── 调用 ctx.emit_issue(issue)
          │
          └── 内部调用语义门控：
              issue_gate::check_issue(
                  &issue,
                  |sym, kind| ctx.get_srt().has_kind(sym, kind)
              )
              │
              ├── GateVerdict::Allow
              │     ├── 将 issue 写入 ctx.issues（已确认问题列表）
              │     └── 返回 EmitOutcome::Allowed { id: issue.id }
              │
              └── GateVerdict::Suppress(reason)
                    ├── 将 issue 写入 ctx.suppressed_issues（被抑制问题列表）
                    │     （保留用于调试和审计，--verbose 模式下可查看）
                    └── 返回 EmitOutcome::Suppressed { id: issue.id, reason }
      │
      └── 调用方检查发射结果：
          if outcome.is_allowed() {
              result.add_issue(issue_clone)
              // 将已确认 Issue 加入本 Pass 的运行结果
          }
          // 若被抑制，则静默跳过，不影响 Pass 的正常执行
```

**Issue 生命周期总览**：

```
构建 Issue 对象
      │
      ▼
ctx.emit_issue(issue)
      │
      ▼
issue_gate::check_issue()
      │
      ├──[Allow]──────► ctx.issues[]            （最终输出到用户）
      │
      └──[Suppress*]──► ctx.suppressed_issues[] （调试模式下可见）
```

---

## 7. Pass 依赖关系表

下表列出每个主要 Pass 通过 `fn dependencies() -> Vec<&'static str>` 声明的直接依赖关系。PassManager 使用这些声明构建拓扑排序，确保每个 Pass 执行时其所有依赖已完成。

| Pass 名称 | 依赖的 Pass |
|---|---|
| CallGraphPass | （无依赖，最早执行） |
| FFIBoundaryPass | CallGraph |
| SurfaceClassifierPass | CallGraph |
| DangerSurfacePass | SurfaceClassifier |
| RawFactCollectorPass | （无依赖，最早执行） |
| IRBehaviorSummaryPass | RawFactCollector |
| SummaryBuilderPass | IRBehaviorSummary |
| StructuralInferencePass | RawFactCollector |
| ContractGraphBuilderPass | SummaryBuilder, StructuralInference |
| OwnershipSolverPass | ContractGraphBuilder |
| IssueCandidateBuilderPass | OwnershipSolver |
| IssueVerifierPass | IssueCandidateBuilder |
| LeakDetectionPass | OwnershipSolver |
| RaiiDropPass | RawFactCollector |
| InteriorMutabilityPass | RawFactCollector |
| HeapProvenancePass | RawFactCollector |
| BorrowEscapePass | RawFactCollector |
| WriteToImmutablePass | RawFactCollector |
| FfiReturnCheckPass | FFIBoundary |

**依赖图（简化 ASCII 表示）**：

```
CallGraphPass ──────────────────────────────► FFIBoundaryPass
                                               └── FfiReturnCheckPass
              └── SurfaceClassifierPass
                    └── DangerSurfacePass

RawFactCollectorPass ──────────────────────► IRBehaviorSummaryPass
                    │                              └── SummaryBuilderPass ──┐
                    │                                                        │
                    └──────────────────────► StructuralInferencePass ───────┤
                    │                                                        │
                    │                              ContractGraphBuilderPass ◄┘
                    │                                    └── OwnershipSolverPass
                    │                                          ├── IssueCandidateBuilderPass
                    │                                          │       └── IssueVerifierPass
                    │                                          └── LeakDetectionPass
                    │
                    ├──────────────────────► RaiiDropPass
                    ├──────────────────────► InteriorMutabilityPass
                    ├──────────────────────► HeapProvenancePass
                    ├──────────────────────► BorrowEscapePass
                    └──────────────────────► WriteToImmutablePass
```

**执行阶段划分**（按拓扑层次）：

```
第 0 层（无依赖）：
  CallGraphPass, RawFactCollectorPass

第 1 层（依赖第 0 层）：
  FFIBoundaryPass, SurfaceClassifierPass
  IRBehaviorSummaryPass, StructuralInferencePass
  RaiiDropPass, InteriorMutabilityPass, HeapProvenancePass
  BorrowEscapePass, WriteToImmutablePass

第 2 层（依赖第 1 层）：
  DangerSurfacePass, SummaryBuilderPass
  ContractGraphBuilderPass, FfiReturnCheckPass

第 3 层（依赖第 2 层）：
  OwnershipSolverPass

第 4 层（依赖第 3 层）：
  IssueCandidateBuilderPass, LeakDetectionPass

第 5 层（依赖第 4 层）：
  IssueVerifierPass
```

---

*本文档描述的是系统设计层面的调用链结构，不涉及具体实现代码。如需了解各 Pass 的详细逻辑，请参阅 `docs/architecture.md` 及各 Pass 源文件。*
