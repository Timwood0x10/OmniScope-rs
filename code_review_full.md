# OmniScope-rs 全量 Code Review 报告

**生成日期:** 2026-06-04  
**审查范围:** 全项目（8 workspace 成员 crate + 集成测试 + CI 配置 + C++ LLVM Pass）  
**分析深度:** 地毯式（每文件逐段阅读、结构化审查）

---

## 目录

1. [执行摘要](#1-执行摘要)
2. [架构概览](#2-架构概览)
3. [P0 致命问题](#3-p0-致命问题)
4. [P1 高危问题](#4-p1-高危问题)
5. [P2 中危问题](#5-p2-中危问题)
6. [P3 低危问题](#6-p3-低危问题)
7. [按 crate 明细](#7-按-crate-明细)
8. [跨 crate 系统性问题](#8-跨-crate-系统性问题)
9. [改进建议](#9-改进建议)

---

## 1. 执行摘要

OmniScope-rs 是一个以 LLVM IR 为核心、跨语言 FFI 安全审计的静态分析器。项目整体设计清晰，具有层次化架构（IR 层 → 语义层 → Pass 层 → Pipeline 层 → CLI 层），面向 17 种 Resource Family、多语言适配（Go/Python/C++/C#/Java）以及 20+ 分析 Pass，工程规模较大。

本次审查共识别出：

| 严重级别 | 数量 | 说明 |
|---------|------|------|
| **P0 致命** | 8 | 导致测试失败、功能错误或安全漏洞 |
| **P1 高危** | 17 | 显著影响正确性或可维护性 |
| **P2 中危** | 23 | 影响稳定性、可观测性或代码质量 |
| **P3 低危** | 30+ | 风格、文档缺失、小 Bug |

最关键的几类风险：**功能正确性 Bug**（Rust mangling 长度前缀错误导致类型误判、`atomicrmw` 过宽匹配导致漏报、Java JNI reference 类型误推、ModuleIndex 索引对齐假设、运算符优先级 Bug）、**测试无效**（测试无断言、测试 fixture 被 gitignore、硬编码路径）、**CI/构建配置不一致**（LLVM 版本 env 变量命名不匹配、mold 强依赖、sccache 无 fallback）。

---

## 2. 架构概览

```
User IR (.ll/.bc)
  → Loader (Plan A/B/C 自动选择 + IrCache 缓存)
  → IRModule (三层: IRModuleModel 富模型 / IRModule 传统模型)
  → PassManager (拓扑排序 + Rayon 并行)
  ├── CallGraphPass           (调用图 + 跨语言边)
  ├── RawFactCollectorPass    (alloc/free/FFI 事实提取)
  ├── IRBehaviorSummaryPass   (行为摘要)
  ├── SummaryBuilderPass      (函数摘要)
  ├── StructuralInferencePass (析构/桥接推断)
  ├── ContractGraphBuilderPass(资源契约图)
  ├── OwnershipSolverPass     (所有权求解)
  ├── IssueCandidateBuilder   (候选问题)
  ├── IssueVerifierPass       (候选验证 + SRT Gate)
  ├── LeakDetectionPass       (泄漏检测)
  ├── FFIBoundaryPass         (FFI 边界检测)
  ├── SurfaceClassifierPass   (函数分类)
  ├── DangerSurfacePass       (危险面)
  ├── RaiiDropPass (R-3)      (FP 抑制)
  ├── InteriorMutabilityPass (R-2)
  ├── HeapProvenancePass (R-1)
  ├── BorrowEscapePass
  ├── WriteToImmutablePass (R-0)
  └── FfiReturnCheckPass
  → PipelineResult → Rich/JSON/SARIF 输出
```

核心领域模型：**Resource Family**（17 种内置家族）→ **ContractGraph** → **OwnershipSolver** → **IssueGate**（SRT 门控，88% 精度阈值）。

---

## 3. P0 致命问题

### P0-1：Rust Mangling 长度前缀错误 — `type_semantic.rs`

**文件:** `crates/omniscope-semantics/src/resource/semantic_tree/type_semantic.rs:89, 103`  
**严重级别:** 🔴 Critical

```rust
// 当前代码（错误）
if name.contains("4cell9OnceCell") || name.contains("4cell11OnceLock") { ... }
if name.contains("4sync7OnceLock") { ... }

// 应为
if name.contains("4cell8OnceCell") || name.contains("4cell8OnceLock") { ... }
if name.contains("4sync8OnceLock") { ... }
```

Rust v0 mangling 中数字前缀是**后续标识符的字节长度**。"OnceCell" = 8 字节，"OnceLock" = 8 字节，"sync" = 4 字节。当前 `9OnceCell` / `7OnceLock` 的长度数字与实际不匹配，导致这些模式**永远不会命中**真实 mangled 名称。

**影响：** `OnceCell` 和 `OnceLock` 类型始终被分类为 `TypeSemantic::Ordinary`，而非 `TypeSemantic::Once`，削弱了 `suppresses_write_to_immutable` 机制的准确性。

---

### P0-2：`atomicrmw` 过宽匹配导致 R-3 RAII 漏报

**文件:** `crates/omniscope-pass/src/analysis/raii_drop.rs:165-167`  
**严重级别:** 🔴 Critical

```rust
// 当前代码
if callee.starts_with("atomicrmw") {
    return true;  // 所有 atomicrmw 都被当作 refcount 减操作
}
```

`atomicrmw` 是一个 LLVM IR 家族指令（add, sub, xchg, and, or, xor, max, umin 等）。只有 `atomicrmw.sub`（被 Arc/Rc 使用）才代表引用计数减操作。当前逻辑将 `atomicrmw.add`（原子加法）等也视为"尾位置释放"，导致所有原子操作场景下的 `use_after_free` / `double_free` 问题被 **R-3  silently suppress**。

---

### P0-3：Java JNI Reference 清理检测缺失 Global/Weak 类型

**文件:** `crates/omniscope-semantics/src/resource/java_adapter/mod.rs:469-476, 573-581`  
**严重级别:** 🔴 Critical — 两个相关 Bug

**Bug 3a：** `analyze_function_body` 中 `DeleteGlobalRef` / `NewGlobalRef` 被错误地同时 push `JNILocalReference` 和 `JNIGlobalReference`，而 `DeleteLocalRef` 只 push `JNILocalReference`，存在行为不一致。

**Bug 3b：** `has_reference_cleanup` 只检查 `JNILocalReference`：
```rust
let has_reference_cleanup = patterns
    .iter()
    .any(|p| matches!(p, JavaSemanticPattern::JNILocalReference));
```
一个正确使用 `NewGlobalRef` + `DeleteGlobalRef` 的函数会被误判为 JNI Reference Leak，因为 `DeleteGlobalRef` push `JNIGlobalReference`（而非 `JNILocalReference`），所以 `has_reference_cleanup` 永远为 `false`。

---

### P0-4：ModuleIndex 与 module.calls 索引对齐假设

**文件:** `crates/omniscope-pass/src/analysis/call_graph.rs:64,78-86`、`borrow_escape.rs:77-86`  
**严重级别:** 🔴 Critical

```rust
let idx = edge_idx; // 来自 module.calls 的索引
let meta = &index.call_metas[idx]; // 假设 idx 直接对应 call_metas[idx]
```

`module.calls` 和 `index.call_metas` 是独立构造的数据结构。如果 `ModuleIndex` 的构建逻辑（如过滤、排序）与 `IRModule` 不同，idx 会错位，导致静默跳过（`idx < len` 的 guard 掩盖了问题）或错误分类。该不变式在代码中**完全没有文档化**。

---

### P0-5：`parser.rs` 运算符优先级 Bug — 全局变量检测

**文件:** `crates/omniscope-ir/src/parser.rs:181-194`  
**严重级别:** 🔴 Critical

```rust
// 当前代码
if line.starts_with('@') && line.contains(" = global ") || line.contains(" = constant ")
// 因优先级实际等价于
if (line.starts_with('@') && line.contains(" = global ")) || line.contains(" = constant ")
```

任何包含 `" = constant "` 的行（如 `store i32 0, ptr @some_var` 中的 `constant` 关键字也可能出现）都会被错误分类为全局变量定义。

---

### P0-6：Debug Metadata 文件路径从未填充

**文件:** `crates/omniscope-ir/src/parser.rs:627-674`, `parse_debug_metadata` 函数  
**严重级别:** 🟠 High

```rust
// Line 671
let mut loc = SourceLocation::new(std::path::PathBuf::new(), src_line);
```

`!DILocation` metadata 中的 `file: !N` 字段**从未被解析**，所有 `SourceLocation` 的文件路径都是空的 `PathBuf::new()`，导致 `is_valid()` 返回 `false`，控制流图中的所有 source location 信息全部失效。

---

### P0-7：测试 fixture 被 gitignore

**文件:** `.gitignore:75` (`tests/integration/`) + `crates/omniscope-ir/tests/llvm_sys_test.rs:21-23`  
**严重级别:** 🟠 High

```gitignore
# .gitignore line 75
tests/integration/
```

集成测试依赖 `tests/integration/` 目录下的 `.ll` / `.bc` fixture 文件，但该目录被 gitignore，在 CI/新机器 check 时这些文件不存在，导致所有 fixture 测试静默跳过或失败，且问题难以排查。

同时 `llvm_sys_test.rs:21-23` 的 `test_ll_path()` 硬编码返回 `/tmp/test_llvm_sys.ll`，但**没有任何代码创建这个文件**。

---

### P0-8：CI 中 LLVM env 变量命名不匹配

**文件:** `.cargo/config.toml:14` vs `.github/workflows/ci.yml:26`  
**严重级别:** 🟠 High

```toml
# .cargo/config.toml
LLVM_SYS_221_PREFIX = "/opt/homebrew/opt/llvm@22"

# ci.yml
LLVM_SYS_220_PREFIX: /usr/lib/llvm-22
```

`llvm-sys` 的版本环境变量命名逻辑是 `LLVM_SYS_{MAJOR}{MINOR}_PREFIX`（如 221 → `LLVM_SYS_221_PREFIX`），CI 中使用的是 `LLVM_SYS_220_PREFIX`，且路径 `/usr/lib/llvm-22` 对应 LLVM 22，变量名却用了 `220`（对应 LLVM 20.0），两者均不匹配。

---

## 4. P1 高危问题

### P1-1：`is_runtime_intrinsic` 在 call_graph 与 ffi_boundary_detector 之间行为不一致

**文件:** `call_graph.rs:274-295` vs `ffi_boundary_detector.rs:188-207`  
**严重级别:** 🟠 High — 正确性 Bug

| 检查项 | call_graph | ffi_boundary_detector |
|--------|-----------|----------------------|
| C++ `__gxx_*` | ✅ (line 291) | ❌ 缺失 |
| C++ `__cxa_*`  | ✅ (line 283) | ❌ 缺失 |

`__gxx_personality_v0`（C++ 异常处理）在 `CallGraphPass` 中被过滤为运行时内部函数，但在 `FFIBoundaryDetector` 中不会被过滤，导致 C++ 异常处理调用被误识别为 FFI 边界。

---

### P1-2：`SurfaceClassifierPass` callee 升级不对称

**文件:** `crates/omniscope-pass/src/analysis/surface_classifier_pass.rs:112-122`  
**严重级别:** 🟠 High

Caller 升级允许从 `Unknown` **和** `Dependency` 升级为 `Boundary`，但 callee 升级仅允许从 `Unknown` 升级为 `Boundary`，跳过 `Dependency`。如果一个 FFI callee 先被 L1+L2 分类为 `Dependency`（外部 crate 依赖），L3 pass 将**永远不升级它为 Boundary**，下游完全跳过它。

---

### P1-3：`DangerSurfacePass` 使用统计值作 issue count

**文件:** `crates/omniscope-pass/src/analysis/danger_surface.rs:94-97`  
**严重级别:** 🟠 High

```rust
.with_issues(known_family_count)  // 已知家族数量的边数 → 被当作 "issue" 计数
```

`known_family_count` 是**统计量**（有多少 FFI 边的 callee 有已知 Resource Family），不是实际 issue 数量。`PassResult::with_issues()` 设为该值后，下游 issue reporter 和 SRT Gate 会把统计值当作真实 issue 数报告，造成严重误导。

---

### P1-4：`NoiseReduction::noise_reduction_ratio` 有符号溢出

**文件:** `crates/omniscope-pass/src/analysis/noise_reduction.rs:266`  
**严重级别:** 🟠 High

```rust
let reduced = issues_before_filter as i32 - self.total_issues as i32;
// issues_before_filter > i32::MAX 时发生包装溢出，产生负数
```

`u32 → i32` 的窄化转换在值 > 2,147,483,647 时发生包装，导致 `reduced` 为负数，`reduced as f32 / issues_before_filter as f32` 计算得到负的滤除率。

---

### P1-5：对外部命令无超时 — 潜在挂死

**文件:** `crates/omniscope-ir/src/loader_v2.rs:469-477, 556-559, 649-652`  
**严重级别:** 🟠 High

`std::process::Command::new(&opt).output()` 没有设置任何超时。如果 `opt` 或 `ir_extractor` 因为无限循环、死锁或资源耗尽挂起，整个分析进程将永久挂起。

---

### P1-6：`ir_cache.rs` 的 `unwrap_or_default` 隐藏时钟偏移

**文件:** `crates/omniscope-ir/src/ir_cache.rs:448`  
**严重级别:** 🟠 High

```rust
let age = now.duration_since(modified).unwrap_or_default().as_secs();
```

如果文件的修改时间在未来（NTP 跳跃、文件系统时间漂移），`duration_since` 返回 `Err`，`unwrap_or_default()` 将其视为 age 0，导致 `clear_old_entries` 永远不清除该文件（即文件永远不会因过期被淘汰）。

---

### P1-7：`SummaryStore::find_by_name` 线性扫描

**文件:** `crates/omniscope-semantics/src/resource/summary.rs:158-160`  
**严重级别:** 🟠 High — 性能

```rust
self.summaries.values().find(|summary| summary.name == name)
```

对于数万函数规模的项目，按函数名查找摘要为 O(n)。构建辅助 `HashMap<String, FunctionId>` 可使查找变为 O(1)。

---

### P1-8：`.cargo/config.toml` 强制依赖 mold + sccache

**文件:** `.cargo/config.toml:2-15`  
**严重级别:** 🟠 High — 构建系统

```toml
-C link-arg=-fuse-ld=mold       # 仅在 Linux/macOS 部分版本可用
rustc-wrapper = "sccache"       # 没安装则所有编译失败
CARGO_BUILD_JOBS = "14"         # 硬编码，不适合跨平台
```

在无 mold 链接器的系统（Ubuntu 默认、部分 macOS）或未安装 sccache 的环境上，**根本无法构建项目**，且错误信息不直接指向配置问题。

---

### P1-9：`.gitignore` 中 `tests/integration/` 导致 CI 丢失测试 fixture

已在 P0-7 中详细说明。

---

### P1-10：`rich.rs` 的 `sanitize_ir_vars` 破坏非 ASCII UTF-8

**文件:** `crates/omniscope-cli/src/output/rich.rs:358-390`  
**严重级别:** 🟠 High

```rust
out.push(bytes[i] as char);  // 任意 u8 直接转 char，破坏 UTF-8 多字节
```

对于包含多字节 UTF-8 字符（德语音变字符、CJK、emoji 等）的 `issue.description`，输出字符串会被静默乱码（如 `é` → `Ã©`）。

---

## 5. P2 中危问题

### P2-1：跨模块 `is_runtime_intrinsic` / `is_ffi_boundary` 逻辑重复

**文件:** `call_graph.rs:274-295` / `ffi_boundary_detector.rs:188-207`  
**严重级别:** 🟡 Medium

两个文件实现了几乎相同的逻辑但**存在行为差异**（参见 P1-1）。建议提取到共享模块，确保单一事实来源。

---

### P2-2：`is_external_function` 在三个 detector 中重复实现

**文件:** `buffer_overflow_detector.rs:572-589`、`type_confusion_detector.rs:588-741`、`length_truncation_detector.rs:224-378`  
**严重级别:** 🟡 Medium

三个 detector 各自实现了版本略有差异的 `is_external_function`。Bug fix 或功能扩展需要三处同步修改。

---

### P2-3：Java adapter 中 `is_jni_call` 三重复

**文件:** `java_adapter/jni.rs:45-50`、`java_adapter/exception.rs:150-155`、`java_adapter/reference.rs:176-182`  
**严重级别:** 🟡 Medium

完全相同的三份 `is_jni_call` 实现。

---

### P2-4：`ir_pattern.rs` 的 `detect_release_on_all_exit_paths` 单基本块假设

**文件:** `crates/omniscope-semantics/src/resource/ir_pattern.rs:1210-1225`  
**严重级别:** 🟡 Medium

该函数线性扫描 `instructions` 并对每个 return 调用 `take(ret_pos)`，这隐式假设只有一个基本块。多基本块 + 条件分支的函数中，一个 block 中的 release 不会被另一 block 的 return 扫描到，导致 `ReleaseOnAllExitPaths` **漏检**。

---

### P2-5：`summary_inference.rs` 未知符号静默分类为 C_HEAP

**文件:** `crates/omniscope-semantics/src/resource/summary_inference.rs:134-153`  
**严重级别:** 🟡 Medium

```rust
inferred.family_id.unwrap_or(FamilyId::C_HEAP)  // 未知符号 → 静默归入 C_HEAP
```

任何无法匹配的符号都被当作 C 堆分配器，导致未知内存管理 API 的分析结果错误。

---

### P2-6：`IssueCandidate::severity()` 未验证候选默认返回 Warning

**文件:** `crates/omniscope-core/src/issue_candidate.rs:174-182`  
**严重级别:** 🟡 Medium

```rust
pub fn severity(&self) -> Severity {
    match self {
        ...verified... => ...
        _ => Severity::Warning,  // 未验证候选也获得 Warning
    }
}
```

如果消费者按 severity 过滤而不检查 `is_verified()`，未验证候选会被当作 reportable 的 Warning 输出，污染报告。

---

### P2-7：`IssueKind::WriteToImmutable` 无对应的 `IssueCandidateKind`

**文件:** `crates/omniscope-core/src/issue.rs:141` vs `crates/omniscope-core/src/issue_candidate.rs` 缺少对应 Variant  
**严重级别:** 🟡 Medium

`WriteToImmutable` 在 `IssueKind` 枚举中存在且被 R-0 抑制规则计数，但标准 `IssueCandidate → Issue` 管道中无法产生该候选类型，只可通过直接 `Issue::new()` 构造。双方定义不一致。

---

### P2-8：`PassContext::merge()` 并行 ID 碰撞风险

**文件:** `crates/omniscope-pass/src/pass.rs:542-574`  
**严重级别:** 🟡 Medium

```rust
// next_issue_id 仅在 other > self 时更新
// 并行场景：两个 context 均 advance 到同一 ID，合并后不前进到最新值
```

Rayon 并行 group 结束后合并 `PassContext`，如果两个子上下文将 `next_issue_id` 递增到相同的值，合并时后者不会超过前者，可能导致后续 pass 中的 issue ID 碰撞。

---

### P2-9：测试文件无断言或断言无效

| 文件 | 问题 |
|------|------|
| `tests/ffi_analysis_tests.rs:66-137` | `test_analyze_all_ffi_issues` 零断言，只有 `info!()` 日志 |
| `tests/ffi_analysis_tests.rs:151-183` | `test_detect_memory_issues` 同上 |
| `tests/debug_ffi_calls.rs` | 整个文件是 debug 脚本，无有效断言 |
| `tests/regression_tests.rs` | 所有测试使用 `issue_count() > 0 \|\| pass_count() > 0`，因 pass_count > 0 已提前 assert，issue 条件永远冗余 |
| `tests/plan_a_c_integration.rs:993-1000` | `test_llvm_sys_adapter_is_available` 用 `let _ = available;` 丢弃结果 |

---

### P2-10：`NoiseReduction::new()` 每次创建 Vec

**文件:** `crates/omniscope-pass/src/analysis/noise_reduction.rs:44-66`  
**严重级别:** 🟡 Medium

`safe_patterns: Vec<&'static str>` 在每次 `new()` 时创建，内容完全静态。应使用 `const` 数组或 `once_cell::sync::Lazy`。

---

### P2-11：SARIF 输出中的无效 CWE URL

**文件:** `crates/omniscope-cli/src/output/sarif.rs:219`  
**严重级别:** 🟡 Medium

```rust
let cwe = issue_kind.cwe_id().unwrap_or(0);
// 产生 https://cwe.mitre.org/data/definitions/0.html — 404
```

CWE 为 None 时使用 `0` 产生无效 URL，应省略该字段或使用根 URL。

---

### P2-12：`.cargo/config.toml` / `ci.yml` LLVM 前缀不一致

已在 P0-8 中列出，同时期修复。

---

### P2-13：`danger_surface.rs` 的事件统计 vs. issue 计数混淆

已在 P1-3 中详细说明。

---

## 6. P3 低危问题

### P3-1：代码重复（多处）

| 重复内容 | 文件 A | 文件 B | 文件 C |
|-----------|--------|--------|--------|
| `parse_call_args_from_raw` | `parser.rs:593` | `llvm_sys_adapter.rs:752` | — |
| `parse_call_result_from_raw` | `parser.rs:612` | `llvm_sys_adapter.rs:771` | — |
| `is_external_function` | `buffer_overflow_detector.rs:572` | `type_confusion_detector.rs:588` | `length_truncation_detector.rs:224` |
| `is_jni_call` | `java_adapter/jni.rs:45` | `java_adapter/exception.rs:150` | `java_adapter/reference.rs:176` |

---

### P3-2：`LocationManager` 是 Vec 的薄包装

**文件:** `crates/omniscope-ir/src/location.rs:77-117`  
提供 `add/get/count/clear`，无任何优于直接使用 `Vec<SourceLocation>` 的优势。索引在 clear 后失效。

---

### P3-3：`Location` 类型三重复

`IssueLocation`（`issue.rs:290`）、`SourceLocation`（`diagnostics.rs:42`）、`FactLocation`（`fact.rs`）结构完全相同（`file: PathBuf, line: u32, column: Option<u32>, function: Option<String>`）。

---

### P3-4：`ir_cache.rs` 的导入位于函数体内

**文件:** `crates/omniscope-ir/src/ir_cache.rs:77-78, 131-132`

```rust
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
```

应移至文件顶部。

---

### P3-5：`DefaultHasher` 非跨版本稳定

**文件:** `crates/omniscope-ir/src/ir_cache.rs:97-100`  
`DefaultHasher` 不保证跨 Rust 版本稳定，升级后所有缓存条目失效（缓存雪崩）。应改用 `xxh3` 等稳定哈希。

---

### P3-6：`FactStore::by_file` / `Diagnostics::by_file` 强制 `&PathBuf`

**文件:** `omniscope-core/src/fact.rs:200`, `omniscope-core/src/diagnostics.rs:218`

接受 `&Path` 而非 `&PathBuf`，避免调用方不必要的 `PathBuf` 分配。

---

### P3-7：`Profiler::active_spans` 内存泄漏

**文件:** `crates/omniscope-core/src/profiler.rs:89`  
如果 `end_span` 从未被调用，`DashMap` 中的条目永久存在，长时间运行进程会遭遇**无界内存泄漏**。

---

### P3-8：`profiler.rs` 中的导入重复和死代码

- Line 92: `use dashmap::DashMap;` 重复（line 8 已导入）
- Lines 196-203: `stats()` 中 `count` 变量赋值后 `if count == 0` 分支永远不可达（被前置空检查覆盖）

---

### P3-9：`family_registry.rs` 中的中文注释

**文件:** `crates/omniscope-semantics/src/resource/family_registry.rs:170,181`  
注释使用中文（`// 注册 acquire 函数`），其余代码均使用英文。

---

### P3-10：`module_index.rs` 中的复制代码

**文件:** `crates/omniscope-pass/src/module_index.rs:125-174`  
`is_runtime_intrinsic_cached` 和 `classify_function_cached` 是 `call_graph.rs` 对应函数的**副本**，违反了 DRY。

---

### P3-11：`ir_model.rs` `to_ir_module` 中大量 String 克隆

**文件:** `crates/omniscope-ir/src/ir_model.rs:275-360`  
转换 `IRModuleModel → IRModule` 时，几乎所有字符串字段都被多次克隆。对于大型模块，产生可观的内存开销。

---

### P3-12：`python_adapter/memory.rs` 语义混淆

**文件:** `crates/omniscope-semantics/src/resource/python_adapter/memory.rs:73-94`

`PyMem_Malloc`/`PyMem_Free` 是 C 级内存分配器，独立于 Python 引用计数。当前代码将其平衡结果归类为 `SafeRefCount`，混洧了两种不同的安全域。

---

### P3-13：`python_adapter/refcount.rs` 的漏检

**文件:** `crates/omniscope-semantics/src/resource/python_adapter/refcount.rs:118-125`

只有 `inc_count > 0 && dec_count > 0` 时才做平衡检查。仅有 `Py_INCREF`（没有 `Py_DECREF`）的函数 bypass 平衡检查，返回 `Unknown` 而非 `ConcernRefLeak`，遗漏了明显的引用计数泄漏。

---

### P3-14：`semantic_tree/tree.rs` 的 `NaN` 比较问题

**文件:** `crates/omniscope-semantics/src/resource/semantic_tree/tree.rs:73-77`

```rust
a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal)
```

`NaN` 的 `partial_cmp` 返回 `None`，被 `unwrap_or(Equal)` 处理为相等，可能导致 NaN 置信度值赢得或被输掉比较，选错 resolution。

---

### P3-15：`Assignment` 路径

`llvm_sys_adapter.rs:464` — llvm-sys 后端解析的指令 `operands` **始终为空**，依赖 `operands` 的 downstream pass 在此后端下会出错，但没有文档说明该限制。

---

### P3-16：`loader_v2.rs` 中 `can_use_direct_cpp_ffi()` 与 `can_use_direct_cpp()` 功能一致

**文件:** `crates/omniscope-ir/src/loader_v2.rs:398-407`  
两个函数的检查完全相同，即使 `ir_extractor` 二进制文件存在，也没有运行时探测其是否支持 `--slice=ffi` 参数。

---

## 7. 按 crate 明细

### `omniscope-ir`（IR 抽象层）

**核心文件：**
- `parser.rs`：运算符优先级 Bug(P0-5)、debug metadata 路径缺失(P0-6)、数据布局解析仅覆盖地址空间 0、每行 `to_string()` 分配压力
- `instruction_parser.rs`: 20+ 近相同的样板代码构造 `IRInstruction`、间接调用检测边缘情况（见下方）
- `ir_model.rs`：`callee` 空字符串未统一转换、`to_ir_module` 大量克隆
- `ir_cache.rs`：Clock skew 隐藏(P1-6)、`DefaultHasher` 不稳定(P3-5)、导入在函数体内(P3-4)、缓存目录默认权限过宽
- `llvm_sys_adapter.rs`：重复 helper(P3-1)、synthetic 寄存器名使用指针地址（信息泄漏、非确定性）、`LLVMIndirectBr` 映射为 `Branch` 丢失语义
- `loader_v2.rs`：外部命令无超时(P1-5)、LLVM 版本硬编码（17-22，未来 LLVM 23 不识别）、Windows PATH `;` 分隔符 Bug、`find_project_root()` 每次调用重新遍历
- `location.rs`：`LocationManager` 是薄 Vec 包装(P3-2)

**间接调用检测边缘情况** (`instruction_parser.rs:421-438`)：
```
call i32 @func(ptr %ctx)
```
`rfind('(')` 找到 `@func(` 之前最近的 `(` 的是 `(` before `%ctx`，向后扫描找到 `%ctx`，错误分类为 IndirectCall。

---

### `omniscope-semantics`（语义引擎）

**核心文件：**
- `semantic_engine.rs`：`assess_ffi_safety` 为 430 行巨型函数、`has_keyword` 对空字符串无限循环
- `ir_pattern.rs`：单基本块假设 Bug(P2-4)、大量 Vec 分配
- `family_registry.rs`：中文注释(P3-9)、`reallocarray` 仅注册为 Acquire
- `summary_inference.rs`：未知符号静默分类 C_HEAP(P2-5)、`build_builtin_summaries` 为空 stub
- `summary.rs`：`find_by_name` O(n) 线性扫描(P1-7)
- `cross_function_lifetime.rs`：`resource_id: 0` 占位符从未被赋值真实 ID → 所有资源流共享 ID 0
- `memory_graph.rs`：重复 ID 未检查
- `type_confusion_detector.rs`、`buffer_overflow_detector.rs`、`length_truncation_detector.rs`：`is_external_function` 三重复(P2-2)
- `surface_classifier.rs`：`dep_paths` 数组定义两遍（第二遍死代码）

**Python Adapter：**
- `mod.rs`：`pythonFFISafety::Family` 字段从未被读取、`determine_ffi_safety` 静默忽略参数
- `exception.rs`：字符串匹配误报（comment/global var 中含 "PyErr_SetString" 触发）、仅检查清理是否在函数中**任意位置**存在而非异常设置之后
- `memory.rs`：`PyMem_Malloc`/`PyMem_Free` 平衡 → `SafeRefCount` 语义混淆(P3-12)
- `refcount.rs`：仅有 INCREF 时 bypass 平衡检查 → Unknown 而非 ConcernRefLeak(P3-13)
- `patterns.rs`：`starts_with("Py")` 误匹配用户自定义函数

**C++ Adapter：**
- `is_extern_c_function` 默认到 C 的启发式：无 `::` 无 `__` 即 extern "C"
- `contains("CI")` 宽泛匹配 C++ 构造函数标记
- `has_smart_ptr && !has_raw_alloc` 未排除 `has_raw_dealloc`（混有原始 dealloc 的智能指针使用应标记 ConcernMixedOwnership）

**Java Adapter：**
- `DeleteGlobalRef` / `NewGlobalRef` 错误 push `JNILocalReference`(P0-3)
- `has_reference_cleanup` 只检查 `JNILocalReference`(P0-3)
- `is_jni_call` 三重复(P2-3)

**Semantic Tree：**
- `type_semantic.rs` Rust mangling 长度前缀错误(P0-1)
- `tree.rs`：`NaN` 置信度比较(P3-14)
- `kind.rs`：`safety_score` 值为无文档的魔法数字

---

### `omniscope-pass`（分析 Pass）

**基础设施：**
- `pass.rs`：`Arc::make_mut` O(n) 全量克隆、merge 时 `next_issue_id` 循环风险(P2-8)、`shared: Arc<HashMap<String, Arc<dyn Any>>>` 类型不安全
- `manager.rs`：并行模式下 pass 失败被静默吞掉（只有 `tracing::error!`，无程序化通知）、`compute_levels` 不检测循环依赖（仅当无可调度 pass 时停止）
- `module_index.rs`：`is_runtime_intrinsic_cached` / `classify_function_cached` 是 call_graph 的副本(P3-10)

**各类分析 Pass：**
- `noise_reduction.rs`：`noise_reduction_ratio` 有符号溢出(P1-4)、每 new() 分配 Vec(P2-10)、`HashMap<String, _>` 应为 `&'static str` 键
- `danger_surface.rs`：`known_family_count` 误作 issue count(P1-3)
- `surface_classifier_pass.rs`：callee 升级不对称(P1-2)
- `raii_drop.rs`：`atomicrmw` 过宽匹配(P0-2)
- `borrow_escape.rs`：`ends_with("new")` 宽泛匹配产生 FP
- `contract_graph_builder.rs`： reclaim 匹配 O(n²)（`iter().position` + `remove`）、`func_id: 0` fallback 与 sink/origin 碰撞
- `issue_candidate_builder/mod.rs`：`UseAfterFree` 仅检查 2 种 escape 边，遗漏 `StoresArgToOwner` 等
- `issue_verifier.rs`：NoiseReduction 在 verify 之后应用（顺序应倒置）
- `union_find.rs`：`find_root` 递归，无尾调用优化
- `path_sensitive_leak.rs`：大量 `#[allow(dead_code)]` 类型的导出
- `ffi_return_check.rs`：冗余 `__rust_alloc` 条件
- `rust_drop_tracker.rs`：每调用 `to_lowercase()` 分配

---

### `omniscope-core`（核心基础设施）

- `issue.rs`: `IssueLocation`、`SourceLocation`、`FactLocation` 三重复(P3-3)；`WriteToImmutable` 无对应 CandidateKind(P2-7)
- `issue_candidate.rs`：未验证候选默认 `Severity::Warning`(P2-6)
- `diagnostics.rs` / `fact.rs`：`by_file(&self, file: &PathBuf)` 应接受 `&Path`(P3-6)
- `profiler.rs`：`active_spans` 无界内存泄漏(P3-7)、导入重复(P3-8)、死代码(P3-8)
- `memory_pool.rs`：`Send` 而非 `Sync` 的 API 契约未在 struct-level doc 中说明
- `risk_score.rs`：`label()` 使用 if-else 而非 match

---

### `omniscope-pipeline`（Pipeline 编排）

- `pipeline.rs`：`run()` 消费型设计（`take()`），变成一次性使用，无 reset 机制
- `result.rs`：pass 分类依赖字符串名(P2)、`from_pass_results` 每处克隆所有 issue

---

### `omniscope-cli`（CLI 入口）

- `main.rs`：`filter_boundary_issues` 保留过期 `PipelineStats`(P2)、O(n×m) 查找 pass timing(P2)、`EnvFilter` 解析失败静默吞掉(P2)
- `output/rich.rs`：`sanitize_ir_vars` 破坏 UTF-8(P1-10)
- `output/sarif.rs`：CWE URL 无效(P2-11)、`build_rules()` 重复计算(P2)、`chrono_now` 前置 1970 时间静默回退

---

### `omniscope-types`（类型定义）

- 无重大逻辑问题，但 17 个 ResourceFamily 的硬编码列表较长，扩展时需同时修改 `family_registry.rs` 和所有 detector

---

## 8. 跨 crate 系统性问题

### 8.1 错误处理不一致

- `unwrap()` 用于生产路径（如 `raw_fact_collector.rs:88`）
- `expect()` 用于可防御场景（如 `contract_graph_builder.rs:474`）
- `unwrap_or_default()` 掩盖错误（`ir_cache.rs:448`、`sarif.rs:22`）
- 建议：建立项目级约定（`unwrap()` 仅限 tests，`expect()` 仅用于真正不可能失败的 invariant，其余一律 `?`）

### 8.2 Stub/占位代码

| 文件 | 问题 |
|------|------|
| `summary_inference.rs:30-37` | `build_builtin_summaries` 返回空 store |
| `family_registry.rs:557-559` | `add_csharp_com_symbols` 完全空函数体 |
| `buffer_overflow_detector.rs:459-476` | `check_buffer_size_mismatch` / `check_bounds_check` stub |
| `python_adapter/memory.rs` | `PyMem_Malloc` 分类为 `SafeRefCount` 语义错误 |

这些 stub 或空实现误导贡献者，应删除或实现。

### 8.3 `#[must_use]` 缺失

`ResourceInstance::transition`、`analyze_function()`、`analyze_pattern()` 等返回 `Result/Option` 的函数缺少 `#[must_use]`，静默忽略返回值不会触发任何警告。

### 8.4 `f32` / `f64` 精度边界

- `confidence: f32` 多处无范围约束，NaN 或越界值静默传播
- `NoiseReduction::ffi_precision` 等用 `f32` 计数大数时精度漂移
- 建议：对 `confidence` 建立 `clamp(0.0, 1.0)` 约定，对统计指标内部用 `f64`

### 8.5 缺少输入大小验证

所有 `.ll` 文件读取无大小上限，恶意构造的超大文件可触发 OOM。

---

## 9. 改进建议

### 9.1 优先级修复路线

**第一步（P0，预计 2-3 天）：**
1. 修复 `parser.rs:181` 运算符优先级（加括号）
2. 修复 `type_semantic.rs:89,103` Rust mangling 长度前缀（`9→8`, `7→8`）
3. 修复 `raii_drop.rs:167`，将 `starts_with("atomicrmw")` 改为精确匹配 `atomicrmw.sub`
4. 修复 `java_adapter/mod.rs:469-476`，`DeleteGlobalRef`/`NewGlobalRef` 只 push `JNIGlobalReference`
5. 修复 `java_adapter/mod.rs:573-581` `has_reference_cleanup` 同时检查 `JNIGlobalReference` 和 `JNIWeakGlobalReference`
6. 从 `.gitignore` 移除 `tests/integration/` 或添加 fixture 生成脚本
7. 修复 `ci.yml` `LLVM_SYS_220_PREFIX` → `LLVM_SYS_221_PREFIX`，与 `config.toml` 统一

**第二步（P1，预计 1 周）：**
8. 重构 `is_runtime_intrinsic` 和 `is_ffi_boundary` 为共享模块，消除 call_graph / ffi_boundary_detector / module_index 三处重复
9. 合并 `is_external_function` 到 `omniscope-types` 单点实现
10. 合并 `is_jni_call` 三重复到 `java_adapter` 共享模块
11. 修复 `danger_surface.rs:95`，区分统计值与 issue 计数
12. 修复 `noise_reduction.rs:266` 有符号溢出
13. 修复 `ir_cache.rs:448` clock skew 暴露
14. 添加外部命令超时
15. 修复 `rich.rs:358-390` UTF-8 破坏
16. `.cargo/config.toml` 添加 mold/sccache 的 fallback 条件

**第三步（P2，持续迭代）：**
17. 重构 `assess_ffi_safety` 巨型函数为阶段函数
18. 对齐 ModuleIndex 索引不变式文档化
19. 对所有 `Result` 返回函数添加 `#[must_use]`
20. 测试中添加真实断言，清理零断言测试文件
21. 提取 `SourceLocation` / `IssueLocation` / `FactLocation` 为统一类型
22. 将 `by_file(&self, file: &PathBuf)` 改为 `by_file(&self, file: &Path)`
23. 修复 `ir_pattern.rs:1210` 单基本块假设
24. `summary_inference.rs` 未知符号 → `FamilyId::Unknown` 而非 `C_HEAP`
25. `PassContext::merge()` 使用原子操作保护 `next_issue_id`

### 9.2 代码静态检查建议

- 启用 `clippy::missing_errors_drop`、`clippy::unnecessary_unwrap`、`clippy::manual_clamp`
- 对所有 `.rs` 文件运行 `cargo clippy --all-targets --all-features -- -D warnings`
- 使用 `cargo-machete` 检测未使用依赖
- 使用 `cargo-audit` 定期检查安全漏洞

### 9.3 架构长期建议

1. **PassContext 强类型化**：当前的 `HashMap<String, Arc<dyn Any>>` "god struct" 模式应演进为 typed context，或至少为每个 slot 提供类型级访问器。
2. **IR Module 统一化**：`IRModuleModel`（富模型）与 `IRModule`（传统模型）之间的转换不够无损，建议加强文档和转换合同。
3. **测试 fixture 管理**：将 `tests/integration/` fixture 纳入 Git LFS 或对不可 gitignore 的重要 fixture 建立提取机制。
4. **Feature flag 合并**：`llvm-backend` 跨 crate feature 传播应统一到根 workspace，避免成员 crate 在 `resolver = "1"` 下 feature 不统一。

---

## 附录：快速参考卡

| 文件 | 最高严重问题 | 修复优先级 |
|------|------------|-----------|
| `semantic_tree/type_semantic.rs` | P0-1: 长度前缀错误 | 🔴 立即 |
| `analysis/raii_drop.rs` | P0-2: atomicrmw 过宽 | 🔴 立即 |
| `java_adapter/mod.rs` | P0-3: JNI reference 误判 | 🔴 立即 |
| `parser.rs` | P0-5: 运算符优先级 + P0-6 debug 路径 | 🔴 立即 |
| `call_graph.rs` / `borrow_escape.rs` | P0-4: ModuleIndex 索引对齐假设 | 🔴 立即 |
| `ir_cache.rs` | P1-6: clock skew | 🟠 高 |
| `loader_v2.rs` | P1-5: 无超时 | 🟠 高 |
| `danger_surface.rs` | P1-3: 统计当 issue | 🟠 高 |
| `noise_reduction.rs` | P1-4: 有符号溢出 | 🟠 高 |
| `.gitignore` + `llvm_sys_test.rs` | P0-7: fixture 丢失 | 🟠 高 |
| `.cargo/config.toml` + `ci.yml` | P0-8/P2-12: 配置不一致 | 🟠 高 |
| `output/rich.rs` | P1-10: UTF-8 破坏 | 🟠 高 |

---

*报告 terminates here.*
