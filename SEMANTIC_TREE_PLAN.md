# 语义树精确实施计划（基于 IR 指令模式推导，非白名单）

## 核心原则

**白名单**：按函数名硬编码分类 → `if name == "strlen" → DataQuery`
**语义推导**：从 IR 指令模式推导行为 → `if call 返回值仅用于算术/store → PureComputation`

差别：白名单遇到未知函数就分类失败；语义推导对任何函数都能从指令行为推导。

---

## Phase 1: 增强 IR Parser — 解析函数体指令流

### 文件: `crates/omniscope-ir/src/parser.rs`

### 新增数据结构

```rust
#[derive(Debug, Clone)]
pub struct IRInstruction {
    pub kind: IRInstructionKind,
    pub dest: Option<String>,       // 目标寄存器 (%3)
    pub operands: Vec<String>,      // 操作数
    pub callee: Option<String>,     // call 的函数名
    pub atomic_op: Option<String>,  // atomicrmw 的操作 (add/sub)
}

#[derive(Debug, Clone, PartialEq)]
pub enum IRInstructionKind {
    Alloca,         // alloca → stack 分配
    Load,           // load → 读内存
    Store,          // store → 写内存
    AtomicRmw,      // atomicrmw add/sub → refcount
    GetElementPtr,  // getelementptr → 指针运算
    Icmp,           // icmp eq/ne → 条件比较
    Branch,         // br i1 → 条件分支
    Call,           // call @func
    Ret,            // ret
    Phi,            // phi
    BinaryOp,       // add/sub/mul/and/or/xor
    Other,
}

#[derive(Debug, Clone)]
pub struct FunctionBody {
    pub name: String,
    pub instructions: Vec<IRInstruction>,
}
```

### 修改 IRModule

在 `IRModule` 中增加 `pub function_bodies: HashMap<String, FunctionBody>`

### 解析逻辑

当 `current_function` 非空时，每行尝试匹配:
- `alloca` → Alloca
- `load` / `load atomic` → Load
- `store` / `store atomic` → Store
- `atomicrmw add/sub` → AtomicRmw + 提取操作类型
- `getelementptr` → GetElementPtr
- `icmp eq/ne` → Icmp
- `br i1` → Branch
- `ret` → Ret
- `phi` → Phi
- `call` → 复用现有 parse_call + Call
- `add/sub/mul/and/or/xor` → BinaryOp

---

## Phase 2: 指令模式提取

### 文件: `crates/omniscope-semantics/src/resource/ir_pattern.rs` (新建)

### 数据结构

```rust
#[derive(Debug, Clone)]
pub struct FunctionBehavior {
    pub name: String,
    pub alloca_count: usize,
    pub call_count: usize,
    pub atomic_rmw_count: usize,
    pub load_count: usize,
    pub store_count: usize,
    pub patterns: Vec<BehaviorPattern>,
    pub return_source: ReturnSource,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BehaviorPattern {
    /// atomicrmw sub + icmp eq + 条件 call → refcount conditional release
    ConditionalRelease { refcount_field: String, destroy_callee: String },

    /// getelementptr + load + 算术 + ret → strlen/memcmp 等纯计算
    PureComputation,

    /// call @malloc 返回 ptr / call @free(ptr) → 所有权转移
    OwnershipTransfer { is_acquire: bool },

    /// 同项目内的 FFI bridge
    InternalBridge,

    /// 仅 getelementptr/bitcast + ret → as_ptr()
    PointerProjection,

    /// store 到 struct 字段 → 构造器
    Initialization,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReturnSource {
    CallResult(String), LoadedValue, GepResult, Constant, Void, Unknown,
}
```

### 核心提取逻辑

```rust
pub fn extract_behavior(body: &FunctionBody) -> FunctionBehavior {
    // 1. 统计指令频率
    // 2. 检测 ConditionalRelease: 搜索 atomicrmw sub → icmp eq → br → call
    // 3. 检测 PureComputation: call 返回值仅用于算术/store，不传给 free
    // 4. 检测 OwnershipTransfer: call @malloc/free (参数含 ptr)
    // 5. 检测 PointerProjection: 函数体仅 getelementptr + bitcast + ret
}
```

### 关键洞察: ConditionalRelease 检测 (IR 模式)

```llvm
%22 = atomicrmw sub ptr %string_impl, i32 2 monotonic  ← 模式起点
%23 = icmp eq i32 %22, 2                               ← 条件比较
br i1 %23, label %bb5, label %exit                      ← 条件分支
bb5:
  tail call void @Bun__WTFStringImpl__destroy(...)      ← 条件释放
```

不管 destroy 函数叫什么，这三条指令序列都表示 ConditionalRelease。
**这就是从 IR 推导语义，不是白名单。**

---

## Phase 3: 语义推导引擎

### 文件: `crates/omniscope-semantics/src/resource/semantic_engine.rs` (新建)

### 数据结构

```rust
#[derive(Debug, Clone)]
pub struct FFISafetyAssessment {
    pub callee: String,
    pub caller_behavior: FunctionBehavior,
    pub callee_behavior: Option<FunctionBehavior>,
    pub verdict: FFIVerdict,
    pub evidence: Vec<IREvidence>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FFIVerdict {
    SafeNoOwnership,          // 纯计算，不涉及所有权
    SafeConditionalRelease,   // refcount 条件释放
    SafeInternalBridge,       // 同项目 FFI bridge
    SafePointerProjection,    // as_ptr() 类借用
    ConcernOwnershipTransfer, // malloc/free → 需 CrossFamilyFree 检查
    Unknown,                  // 无法推导 → 保守 LOW
}

#[derive(Debug, Clone)]
pub struct IREvidence {
    pub instruction_kind: IRInstructionKind,
    pub instruction_text: String,
    pub reasoning: String,
}
```

### 推导逻辑

```rust
pub fn assess_ffi_safety(
    callee: &str,
    caller_body: &FunctionBody,
    callee_body: Option<&FunctionBody>,
    module: &IRModule,
) -> FFISafetyAssessment {
    let caller_behavior = extract_behavior(caller_body);
    let callee_behavior = callee_body.map(extract_behavior);

    // 有函数体 → 精确推导
    if let Some(ref cb) = callee_behavior {
        if cb.patterns.contains(&BehaviorPattern::PureComputation) {
            return SafeNoOwnership;
        }
        if cb.patterns.contains(&BehaviorPattern::ConditionalRelease) {
            return SafeConditionalRelease;
        }
        // ...
    }

    // 无函数体 (外部声明) → 分析 caller 侧指令模式
    derive_from_caller_context(callee, caller_body, module)
}
```

### Caller 侧推导 (当 callee 无函数体时)

```
模式1: call @getenv → icmp eq null → strlen → add/store
       → 读环境变量模式, SafeNoOwnership

模式2: call @strlen → add/store
       → 纯计算, SafeNoOwnership

模式3: atomicrmw sub → icmp eq → br → call @unknown_destroy
       → ConditionalRelease, SafeConditionalRelease

模式4: call @unknown → void 返回 → 不影响所有权
       → SafeNoOwnership (初始化/配置)

模式5: call @unknown → ptr 返回 → 传给 free/dealloc
       → ConcernOwnershipTransfer
```

---

## Phase 4: 重构 FFIBoundaryPass

### 文件: `crates/omniscope-pass/src/analysis/mod.rs`

```
旧: SyscallSemantic::classify(callee_name) → 白名单过滤
新: assess_ffi_safety(callee, caller_body, callee_body, module) → IR 推导
```

仅 `ConcernOwnershipTransfer` 和 `Unknown` 报 issue。

---

## Phase 5: 验证 + 清理

1. `cargo test -p omniscope-ir` — parser 新增测试
2. `cargo test -p omniscope-semantics` — behavior extraction 测试
3. `omniscope analyze bun_core.bc` — 719 → 预期 <20
4. 删除 `SyscallSemantic::classify()` 白名单
5. 保留 `_R` / `_Z` 前缀模式（语言检测，不是白名单）

---

## 依赖关系

```
Phase 1 (parser) → Phase 2 (pattern) → Phase 3 (engine) → Phase 4 (pass) → Phase 5 (验证)
```