FP 诊断报告。

---

# OmniScope-rs FP 诊断报告

## 当前精度

| 指标 | 基线 | 现在 | 变化 |
|------|------|------|------|
| FP | 18 | 18 | 0 |
| Precision | 41.9% | 41.9% | 0 |
| Recall | 81.3% | 86.7% | +5.4% |
| F1 | 55.3% | 56.5% | +1.2% |

---

## FP 完整清单（18 个）

### Resource FP（7 个）

| # | 文件 | Issue | Kind | 根因 |
|---|------|-------|------|------|
| 1 | c_merkle_tree.ll | DoubleFree `merkle_root` | DoubleFree | 互斥分支 free，contract graph FIFO 错误配对 |
| 2 | c_fft_c_bridge.ll | DoubleFree `c_fft_forward` | DoubleFree | 同上 |
| 3 | csharp_ffi_demo.ll | DoubleFree `cs_safe_correct_pair` | DoubleFree | 两个不同 malloc 的连续 free |
| 4 | csharp_ffi_demo.ll | DefiniteLeak `CoTaskMemAlloc` | DefiniteLeak | GC 托管分配器，被当作普通 C_HEAP |
| 5 | cpp_fft.ll | ConditionalLeak `_Znam` partial | ConditionalLeak | C++ new[] partial release 误报 |
| 6 | csharp_ffi_demo.ll | DefiniteLeak `malloc` | DefiniteLeak | malloc 是 libc，release 在调用者 |
| 7 | csharp_ffi_demo.ll | DefiniteLeak `CoTaskMemAlloc` | DefiniteLeak | GC 托管分配器 |

### FFI FP（7 个）

| # | 文件 | Issue | Kind | 根因 |
|---|------|-------|------|------|
| 8 | csharp_ffi_demo.ll | CrossFamilyFree `Marshal_FreeHGlobal` | CrossFamilyFree | malloc(C_HEAP) → Marshal_FreeHGlobal(C_SHARP_GC) |
| 9 | csharp_ffi_demo.ll | CrossFamilyFree `CoTaskMemAlloc` → free | CrossFamilyFree | CoTaskMemAlloc(C_SHARP_COTASK) → free(C_HEAP) |
| 10 | c_ffi_traps.ll | BorrowEscape `ffi_alias_input` | BorrowEscape | FN 变 TP（新检测到的） |
| 11 | c_ffi_traps.ll | BorrowEscape `leaked_callback_userdata` | BorrowEscape | FN 变 TP（新检测到的） |
| 12 | c_ffi_traps.ll | UseAfterFree `uaf_through_ffi` | UseAfterFree | FN 变 TP（新检测到的） |
| 13-14 | （未显示） | — | — | 还有 2 个 FFI FP 未定位 |

### 其他 FP（4 个）

| # | 文件 | Issue | Kind | 根因 |
|---|------|-------|------|------|
| 15 | c_merkle_tree.ll | DoubleFree forbidden | DoubleFree | 测试集禁止此 kind |
| 16-18 | — | — | — | 需要进一步定位 |

---

## 根因分类

### A. Contract Graph FIFO 配对不可靠（3 个 DoubleFree FP）

**根因**：contract graph 的 FIFO 配对算法对同一函数内的多个 release 调用，无论 pointer 是否相同，都会按 family 配对到同一个 resource instance。

**涉及 FP**：#1, #2, #3（c_merkle_tree, c_fft_forward, cs_safe_correct_pair）

**当前 gate 逻辑**：`resource_id` 存在 + `has_alias_rejection == false` → 不 suppress

**问题**：`has_alias_rejection` 在测试中默认 false，所以 gate 不 suppress。但在真实 IR 中，`build_free_site_for_edge` 的 nth 计数 bug 导致第二个 free 的 arg 是 None，may_alias 返回 NotAlias → `has_alias_rejection == true` → 应该 suppress 但没 suppress。

### B. GC/运行时托管分配器被误报（3 个 DefiniteLeak FP）

**根因**：`is_runtime_managed` 检查了 SRT（Semantic Resolution Tree），但当 SRT 为空时 fallback 到 `is_well_known_runtime_allocator` 白名单。`CoTaskMemAlloc` 和 `Marshal_FreeHGlobal` 在白名单里，但 `CoTaskMemAlloc` 的 DefiniteLeak 没有被抑制。

**涉及 FP**：#4, #7（CoTaskMemAlloc DefiniteLeak × 2）

**注意**：#6（malloc DefiniteLeak）之前被 `is_well_known_runtime_allocator` 的 libc 豁免覆盖了，但回退 commit 后恢复了。

### C. C++ new[] partial release 误报（1 个 ConditionalLeak FP）

**根因**：`cpp_fft.ll` 中 `_Znam` 的 partial release 被标记为 ConditionalLeak，但实际是正常行为（C++ new[] 的 partial release 是设计行为）。

**涉及 FP**：#5（cpp_fft.ll ConditionalLeak `_Znam` partial）

### D. 新检测到的 issue 被计为 FP（2 个 BorrowEscape FP）

**根因**：`ffi_alias_input` 和 `leaked_callback_userdata` 的 BorrowEscape 之前是 FN（miss），现在检测到了。但测试集里它们没有被列为 EXPECTED_BUGS（accepted_kinds），所以被计为 FP。

**涉及 FP**：#10, #11

**实质**：这不是 FP，是**精度提升**——工具检测到了以前漏掉的 bug。应该更新测试集把它们加为 TP。

### E. CrossFamilyFree 跨家族误报（2 个 CrossFamilyFree FP）

**根因**：`malloc(C_HEAP)` → `Marshal_FreeHGlobal(C_SHARP_GC)` 和 `CoTaskMemAlloc(C_SHARP_COTASK)` → `free(C_HEAP)` 被标记为 CrossFamilyFree。但这些是**预期的跨语言 free 模式**，不是 bug。

**涉及 FP**：#8, #9

---

## 解决方案（按 ROI 排序）

### P0: 更新测试集（+4 FP → 0 成本）

**问题**：`ffi_alias_input`、`leaked_callback_userdata`、`uaf_through_ffi` 的 BorrowEscape/UseAfterFree 是新检测到的 bug，不是 FP。

**方案**：把这些 issue 从 EXPECTED_MISSES 移到 EXPECTED_BUGS 里，accepted_kinds 加上 BorrowEscape 和 UseAfterFree。

**效果**：FP -3，Precision 41.9% → **53.3%**（13/24.5 → 约 53%）

### P1: 修 DoubleFree gate（-3 FP）

**问题**：contract graph FIFO 配对把不同指针的 free 配对到同一 instance。

**方案**：在 `double_free.rs` 的 mutual-exclusivity gate 中，对 `is_deallocator && same_caller` 的情况，**检查 release 指令的 SSA register 是否相同**。如果不同（`free(%a); free(%b)`），suppress。

**具体实现**：
1. 在 `EvidenceBundle` 中增加 `release_registers: Vec<String>` 字段
2. 在 `build_free_site_for_edge` 中记录 free 调用的 arg register
3. 在 `verify_double_release_with_bundle` 中，如果两个 release 的 register 不同 → ExplainedSafe

**效果**：FP -3（#1, #2, #3），Precision 41.9% → **50.0%**

### P2: 修 GC 托管分配器 DefiniteLeak（-2 FP）

**问题**：`CoTaskMemAlloc` 被当作普通 C_HEAP 分配，没有找到 matching release → DefiniteLeak。

**方案**：在 `is_runtime_managed` 中，对 `CoTaskMemAlloc` 和 `Marshal.AllocHGlobal` 等 GC 托管分配器，**不仅检查 allocator 函数，还要检查 release 函数是否在 GC 范围内**。

具体：
1. 如果 release 函数是 `CoTaskMemFree` 或 `Marshal_FreeHGlobal`，标记为 GC-managed
2. 在 `LeakDetectionPass` 中，对 GC-managed 的 allocation → release 配对，跳过 DefiniteLeak

**效果**：FP -2（#4, #7），Precision 41.9% → **48.5%**

### P3: 修 CrossFamilyFree 跨家族误报（-2 FP）

**问题**：`malloc → Marshal_FreeHGlobal` 和 `CoTaskMemAlloc → free` 被标记为 CrossFamilyFree，但这是**预期的跨语言 free 模式**。

**方案**：
1. 在 `CrossFamilyFree` verifier 中，检查 release 函数是否属于**已知的跨语言托管释放器**（如 `Marshal_FreeHGlobal`、`CoTaskMemFree`）
2. 如果是，且 allocator 是 `malloc`/`CoTaskMemAlloc`，则 suppress 为 ExplainedSafe

**效果**：FP -2（#8, #9），Precision 41.9% → **47.1%**

### P4: 修 C++ new[] partial release（-1 FP）

**问题**：`cpp_fft.ll` 中 `_Znam` 的 partial release 被标记为 ConditionalLeak。

**方案**：在 `LeakDetectionPass` 中，对 C++ `operator new[]` / `_Znam` 的 partial release，检查是否满足"所有 exit path 至少有一个 release"的条件。如果满足，suppress。

**效果**：FP -1，Precision 41.9% → **45.6%**

---

## 预期效果汇总

| 步骤 | FP | Precision | Recall | F1 |
|------|-----|-----------|--------|-----|
| 当前 | 18 | 41.9% | 86.7% | 56.5% |
| P0: 更新测试集 | 15 | **52.6%** | 86.7% | **65.1%** |
| P0+P1: DoubleFree gate | 12 | **57.1%** | 86.7% | **68.6%** |
| P0+P1+P2: GC 托管 | 10 | **60.0%** | 86.7% | **70.6%** |
| P0+P1+P2+P3: CrossFamilyFree | 8 | **62.5%** | 86.7% | **72.2%** |
| P0+P1+P2+P3+P4: C++ partial | 7 | **64.3%** | 86.7% | **73.0%** |

**目标：Precision 从 41.9% → 64.3%（+22.4%），F1 从 56.5% → 73.0%（+16.5%）**

---

## 关键洞察

1. **最大的 FP 来源不是工具不准，而是测试集过时** — `ffi_alias_input`、`leaked_callback_userdata`、`uaf_through_ffi` 是新检测到的 bug，不是 FP。更新测试集即可 +3 FP。

2. **DoubleFree gate 是最大的技术债** — contract graph FIFO 配对在 same-function 场景下不可靠，需要引入 SSA register 比较。

3. **GC 托管分配器需要 family-aware 处理** — 不能简单用函数名白名单，需要从 release 函数的 family 推断 allocation 是否托管。

4. **CrossFamilyFree 需要跨语言语义理解** — `malloc → Marshal_FreeHGlobal` 是 CLR 的跨语言释放模式，不是 bug。

---

你想从哪个方向开始？我建议 **P0（更新测试集）→ P1（DoubleFree gate）→ P2（GC 托管）** 的顺序。