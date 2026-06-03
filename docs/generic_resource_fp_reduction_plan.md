# 通用资源分析 FP 降低方案

## 背景

当前 OmniScope 的资源分析已经具备 `FunctionBehavior`、`ResourceSummary`、`ContractGraph`、`OwnershipSolver`、`IssueVerifier` 等框架，但 FP 仍然偏高，核心原因不是缺少某个库的白名单，而是通用 IR 行为事实没有被用到正确位置。

典型表现：

- 只根据“同一 resource instance 出现多次 release edge”判断 double-free。
- 只根据 alloc/release 计数判断 definite leak / conditional leak。
- 没有证明第二次 release 的实参是否已经变成 NULL。
- 没有把 out-param 的成功路径 ownership transfer 和失败路径 NULL 初始化纳入资源图。

本方案不做大量库白名单，而是通过通用 IR 模式推导 API 语义，并把这些语义接入资源图和验证器。

## 关键原则

### 1. NULL-safe 不等于 double-free safe

`free(NULL)` 安全只说明传入 NULL 时是 no-op，不说明同一个非 NULL 指针释放两次安全。

正确判断：

```text
Release(p)       where p == Owned      => Released
Release(p)       where p == Null       => SafeNoOp
Release(p)       where p == Released   => double_free
Release(p)       where p == Unknown    => needs_model / probable
```

因此，看到释放函数内部有 NULL guard 不能直接 suppress double-free。只有当调用点能证明第二次实参为 NULL 时，才能解释为安全。

### 2. leak 判断必须看出口状态

不能用 `alloc_count > release_count` 直接推断 leak。需要按路径追踪资源状态：

```text
所有出口仍 Owned       => DefiniteLeak
部分出口仍 Owned       => ConditionalLeak
所有出口 Released      => Safe
所有出口 EscapedOutParam / ReturnToCaller => Safe
```

out-param 成功返回给 caller，不是当前函数 leak。

### 3. 函数名只做 fallback

正确优先级应为：

```text
IR-derived behavior summary
  > structural inference
  > registry / known symbol model
  > name-pattern fallback
```

现有 pipeline 中部分位置仍然优先消费 raw symbol facts，导致通用行为 summary 没有发挥作用。

## 当前代码落点

### 行为模式提取

文件：`crates/omniscope-semantics/src/resource/ir_pattern.rs`

现状：已有 `BehaviorPattern`，能表达 `ConditionalRelease`、`OwnershipTransfer`、`PointerProjection`、`Initialization` 等。

需要新增通用模式：

```rust
pub enum BehaviorPattern {
    // existing variants ...

    NullGuardedRelease {
        arg_index: u32,
    },

    NullStoreAfterRelease {
        arg_index: u32,
    },

    FallibleOutParamInit {
        out_arg_index: u32,
    },

    OutParamNullOnError {
        out_arg_index: u32,
    },

    OutParamOwnedOnSuccess {
        out_arg_index: u32,
    },
}
```

这些模式必须从 IR 结构推导，不根据函数名判断。

### summary 转换

文件：`crates/omniscope-semantics/src/resource/summary_inference.rs`

现状：`behavior_to_summary` 已经把 `BehaviorPattern` 转成 `Effect` 和 `Evidence`。

需要在 `behavior_to_summary` 中处理新增模式：

```rust
BehaviorPattern::NullGuardedRelease { arg_index } => {
    summary.add_effect(Effect::NullGuardedRelease {
        family: FamilyId::UNKNOWN,
        arg: *arg_index,
    });
    summary.add_evidence(Evidence::new(
        EvidenceKind::IrPattern,
        "IR pattern: null check before release",
    ));
}

BehaviorPattern::OutParamOwnedOnSuccess { out_arg_index } => {
    summary.add_effect(Effect::OutParamOwnedOnSuccess {
        family: FamilyId::UNKNOWN,
        arg: *out_arg_index,
    });
    summary.add_evidence(Evidence::new(
        EvidenceKind::OwnershipTransfer,
        "IR pattern: out-param receives owned resource on success",
    ));
}

BehaviorPattern::OutParamNullOnError { out_arg_index } => {
    summary.add_effect(Effect::OutParamNullOnError {
        arg: *out_arg_index,
    });
    summary.add_evidence(Evidence::new(
        EvidenceKind::IrPattern,
        "IR pattern: out-param is set to null on error path",
    ));
}
```

如果当前没有 `FamilyId::UNKNOWN`，可先用 `Option<FamilyId>` 承载未知 family，或者新增 `NeedsModel` 证据，避免把 unknown family 强行落到 `C_HEAP`。

### Effect 扩展

文件：`crates/omniscope-types/src/effect.rs`

现状：`Release` 和 `ConditionalRelease` 表达力不足，无法区分 NULL-guarded release、out-param 成功返回、错误路径 NULL 初始化。

建议新增：

```rust
pub enum Effect {
    // existing variants ...

    NullGuardedRelease {
        family: FamilyId,
        arg: u32,
    },

    OutParamOwnedOnSuccess {
        family: FamilyId,
        arg: u32,
    },

    OutParamNullOnError {
        arg: u32,
    },
}
```

如果希望改动更小，也可以先不新增 `Effect`，而是通过 `EvidenceKind` 传递事实。但长期看，资源图和 ownership solver 应该消费 `Effect`，因此推荐扩展 `Effect`。

### Evidence 扩展

文件：`crates/omniscope-types/src/evidence.rs`

建议新增：

```rust
pub enum EvidenceKind {
    // existing variants ...

    NullGuardedRelease,
    NullStoreAfterRelease,
    OutParamOwnedOnSuccess,
    OutParamNullOnError,
    PathStateRefinement,
}
```

这些 evidence 用于 verifier 解释为什么某个候选不是 issue。

### 资源图构建

文件：`crates/omniscope-pass/src/resource/contract_graph_builder.rs`

现状：构图主要消费 raw facts、family registry、FFI contract DB。问题是 IR-derived summary 没有成为第一优先级。

需要调整：

1. 在 `run` 开始处读取 `summary_store`。
2. 处理每个 call 时优先按 callee 的 `ResourceSummary.effects` 建边。
3. 只有没有 summary 时才 fallback 到 registry / FFI contract / name pattern。

伪代码：

```rust
let summary_store: SummaryStore = ctx.get("summary_store").unwrap_or_default();

if let Some(summary) = summary_store.find_by_name(callee) {
    for effect in &summary.effects {
        graph.add_edge(effect_to_contract_edge(effect, call_context));
    }
    continue;
}

// fallback: registry / ffi contract / symbol pattern
```

当前 `SummaryStore` 主要按 `FunctionId` 查找，如果没有按 name 查找能力，需要在 `crates/omniscope-semantics/src/resource/summary.rs` 增加：

```rust
pub fn find_by_name(&self, name: &str) -> Option<&ResourceSummary> {
    self.summaries.values().find(|summary| summary.name == name)
}
```

### ownership solver

文件：`crates/omniscope-pass/src/resource/ownership_solver.rs`

现状：状态机跟踪 resource instance，但没有充分跟踪调用点 pointer value 是否为 NULL。

需要引入 pointer slot/value 状态：

```rust
enum PointerValueState {
    Unknown,
    Null,
    Owned {
        instance: u64,
        family: FamilyId,
    },
    Released {
        instance: u64,
    },
    Escaped {
        instance: u64,
    },
}
```

释放规则：

```text
NullGuardedRelease(p):
  p == Null                 => safe no-op
  p == Owned(instance)      => Released(instance)
  p == Released(instance)   => double_free
  p == Unknown              => needs_model / probable

Release(p):
  p == Owned(instance)      => Released(instance)
  p == Released(instance)   => double_free
  p == Null                 => invalid unless release function is null-guarded
  p == Unknown              => needs_model / probable
```

重要点：NULL guard 是 release 函数语义，真正 suppress double-free 还需要调用点证明实参为 NULL。

### issue candidate builder

文件：`crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs`

现状：double release 候选生成逻辑过粗：

```rust
if release_indices.len() > 1 {
    IssueCandidateKind::DoubleRelease
}
```

需要改成基于 ownership/path state 的结论：

```text
如果第二次 release 的 pointer state == Null 且 release 是 NullGuardedRelease：
  不生成 DoubleRelease，或生成 ExplainedSafe diagnostic

如果第二次 release 的 pointer state == Released(instance)：
  生成 DoubleRelease

如果 pointer state == Unknown：
  生成 NeedsModel 或 ProbableIssue，不要 ConfirmedIssue
```

也就是说，candidate builder 不应该只数边，而应该消费 solver 给出的状态转移错误或 path facts。

### issue verifier

文件：`crates/omniscope-pass/src/resource/issue_verifier.rs`

现状：`DoubleRelease` 被硬编码为 confirmed：

```rust
IssueCandidateKind::DoubleRelease => {
    VerifierVerdict::ConfirmedIssue
}
```

需要改成证据驱动：

```rust
IssueCandidateKind::DoubleRelease => verify_double_release(candidate)
```

伪代码：

```rust
fn verify_double_release(candidate: &IssueCandidate) -> VerifierVerdict {
    if has_evidence(candidate, EvidenceKind::PathStateRefinement)
        && has_evidence(candidate, EvidenceKind::NullGuardedRelease)
        && has_evidence(candidate, EvidenceKind::NullStoreAfterRelease)
    {
        return VerifierVerdict::ExplainedSafe;
    }

    if has_evidence(candidate, EvidenceKind::Insufficient) {
        return VerifierVerdict::Diagnostic;
    }

    VerifierVerdict::ConfirmedIssue
}
```

### path-sensitive leak pass

文件：`crates/omniscope-pass/src/resource/path_sensitive_leak.rs`

现状：实现并不是真正 path-sensitive，而是：

```rust
if !has_release_in_summaries && release_count == 0 {
    DefiniteLeak
}

if !has_release_in_summaries && release_count > 0 && release_count < alloc_count {
    ConditionalLeak
}
```

需要改为出口状态判断：

```rust
struct PathExitState {
    resource_state: ResourcePathState,
    evidence: Vec<Evidence>,
}

enum ResourcePathState {
    Owned,
    Released,
    EscapedToCaller,
    EscapedOutParam,
    Null,
    Unknown,
}
```

判断规则：

```text
all exits Owned                         => DefiniteLeak
some exits Owned                        => ConditionalLeak
all exits Released                      => Safe
all exits EscapedToCaller/EscapedOutParam => Safe
unknown only                            => NeedsModel / Diagnostic
```

对 out-param 初始化函数，成功路径一般是 `EscapedOutParam`，失败路径是 `Null`，都不应该算当前函数 leak。

### IR call args/result

文件：`crates/omniscope-ir/src/parser.rs`

现状：

```rust
pub struct CallInstruction {
    pub callee: String,
    pub caller: String,
    pub is_external: bool,
    pub location: Option<SourceLocation>,
}
```

缺少 args/result，导致无法精确追踪 `free(p)` 和 `free(q)`，也无法确认 out-param 是哪个参数。

建议改为：

```rust
pub struct CallInstruction {
    pub callee: String,
    pub caller: String,
    pub is_external: bool,
    pub location: Option<SourceLocation>,
    pub args: Vec<String>,
    pub result: Option<String>,
}
```

`crates/omniscope-ir/src/llvm_sys_adapter.rs` 构造 `CallInstruction` 时填入：

- `result`：call instruction 的 dest。
- `args`：call operands 中除 callee 以外的实参。

短期可以从 `IRInstruction.raw_text` 解析；长期应使用 LLVM operand API。

## 通用检测模式细节

### NullGuardedRelease

目标 IR 结构：

```llvm
%is_null = icmp eq ptr %p, null
br i1 %is_null, label %return, label %release

release:
  call void @dealloc(ptr %p)
  ret void

return:
  ret void
```

推导：

```text
function has NullGuardedRelease(arg_index = p)
```

语义：

```text
Release(NULL) is safe no-op.
Release(non-null already released pointer) is still double-free.
```

### NullStoreAfterRelease

目标 IR 结构：

```llvm
%p = load ptr, ptr %slot
call void @dealloc(ptr %p)
store ptr null, ptr %slot
```

推导：

```text
slot state becomes Null after release
```

这个模式才是 suppress “release called twice” FP 的关键。

### FallibleOutParamInit

目标 IR 结构：

```llvm
store ptr null, ptr %out
%rc = call i32 @inner(..., ptr %out)
%is_err = icmp ne i32 %rc, 0
br i1 %is_err, label %fail, label %ok

fail:
  store ptr null, ptr %out
  ret i32 %rc

ok:
  ret i32 0
```

推导：

```text
error path: out-param is Null
success path: out-param may hold caller-owned resource
```

语义：

```text
success exit => EscapedOutParam
error exit   => Null
```

所以当前函数不 leak。

## 推荐实施顺序

### Phase 1：行为模式和 summary

修改：

- `crates/omniscope-semantics/src/resource/ir_pattern.rs`
- `crates/omniscope-semantics/src/resource/summary_inference.rs`
- `crates/omniscope-types/src/effect.rs`
- `crates/omniscope-types/src/evidence.rs`

目标：能从函数体 IR 推导 `NullGuardedRelease`、`OutParamNullOnError`、`OutParamOwnedOnSuccess`。

### Phase 2：summary 优先接入资源图

修改：

- `crates/omniscope-semantics/src/resource/summary.rs`
- `crates/omniscope-pass/src/resource/contract_graph_builder.rs`

目标：构图优先使用 IR-derived `ResourceSummary`，registry/name pattern 只做 fallback。

### Phase 3：pointer/path state

修改：

- `crates/omniscope-pass/src/resource/ownership_solver.rs`
- `crates/omniscope-pass/src/resource/path_sensitive_leak.rs`

目标：double-free 和 leak 都基于路径状态判断，而不是 release edge 数量或 alloc/release 计数。

### Phase 4：验证器证据化

修改：

- `crates/omniscope-pass/src/resource/issue_candidate_builder/mod.rs`
- `crates/omniscope-pass/src/resource/issue_verifier.rs`

目标：candidate builder 只提出候选，verifier 根据 path evidence 判断 confirmed / probable / diagnostic / explained safe。

### Phase 5：IR call identity

修改：

- `crates/omniscope-ir/src/parser.rs`
- `crates/omniscope-ir/src/llvm_sys_adapter.rs`
- 依赖 `CallInstruction` 的测试和构造点

目标：准确追踪调用实参、返回值、out-param，避免把不同指针混成同一个 instance。

## 预期效果

### double-free FP 降低

以前：

```text
release edge count > 1 => DoubleRelease
```

以后：

```text
release same non-null released pointer => DoubleRelease
release proven-null pointer through null-guarded release => ExplainedSafe
unknown pointer state => NeedsModel / ProbableIssue
```

### definite leak FP 降低

以前：

```text
alloc exists, release_count == 0 => DefiniteLeak
```

以后：

```text
success path escaped to caller/out-param => Safe
error path null => Safe
all exits owned => DefiniteLeak
some exits owned => ConditionalLeak
```

### conditional leak FP 降低

以前：

```text
release_count < alloc_count => ConditionalLeak
```

以后：

```text
only paths retaining Owned at function exit are leak paths
out-param transfer / return-to-caller / global owner store are valid escapes
```

## 总结

这个问题不应该靠 SQLite、OpenSSL、glib、custom allocator 的大量白名单解决。

正确修法是：

```text
函数体 IR 行为模式
  => ResourceSummary
  => ContractGraph
  => Ownership/path state
  => IssueCandidate
  => Evidence-driven verifier
```

也就是把“函数名模型”升级成“行为 summary + 调用点路径状态”。这样同一套逻辑可以覆盖 SQLite、自定义 allocator、wrapper 函数、错误路径 out-param、NULL-safe release 等通用场景。
