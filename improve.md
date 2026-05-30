我来看看现有代码结构，再给你一个清晰的技术路线。没有上传文件，我直接基于你描述的问题给出完整的技术方案。

---

## 核心问题诊断

你面临的本质困境是：**想做结构化 IR 分析，但唯一可用的 Rust 绑定死了**。解法不是找替代 crate，而是换一层抽象。

---

## 推荐架构：用 LLVM 自己的工具链输出结构化数据

```
Rust 代码
    ↓  rustc -C llvm-bitcode-linkage / cargo rustc -- --emit=llvm-bc
LLVM bitcode (.bc)
    ↓  opt --passes=... --print-after-all  或  自写 LLVM Pass (C++)
结构化 JSON / LLVM MIR-like 中间格式
    ↓  serde_json 反序列化
Rust 分析引擎 (你的主体)
```

具体有两条路，各有取舍：

---

## 路线 A：LLVM Pass 输出 JSON（推荐）

**思路**：写一个薄薄的 C++ LLVM Pass，把你关心的信息序列化成 JSON，Rust 侧只做消费和分析。

### Pass 需要输出什么

```cpp
// 每个 Function 输出：
{
  "name": "_ZN3foo3bar17h...",
  "is_unsafe": true,         // 从 rustc metadata 或命名规则推断
  "blocks": [
    {
      "label": "bb0",
      "instructions": [
        {
          "id": 0,
          "opcode": "call",
          "type": "i32",          // getType()->print()
          "operand_types": ["ptr", "i64"],
          "callee": "_ZN...",
          "is_indirect": false,
          "debug_loc": "src/lib.rs:42:3",
          "raw": "%0 = call i32 @foo(ptr %p, i64 %n)"
        }
      ],
      "successors": ["bb1", "bb2"]   // CFG 边
    }
  ]
}
```

### 构建方式（不需要 llvm-sys 或绑定）

```
项目结构：
├── pass/              # C++ LLVM Pass
│   ├── CMakeLists.txt
│   └── SafetyPass.cpp
├── src/               # Rust 分析引擎
│   ├── ir/
│   │   ├── mod.rs
│   │   ├── types.rs   # JSON schema 的 Rust 镜像
│   │   └── cfg.rs     # 你现有的 cfg.rs 可直接复用
│   └── detectors/
└── build.rs           # 调 cmake 编译 Pass，invoke opt
```

```cpp
// pass/SafetyPass.cpp  关键骨架
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include <nlohmann/json.hpp>   // header-only，直接 vendor

struct SafetyExportPass : PassInfoMixin<SafetyExportPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        nlohmann::json out;
        for (auto &F : M) {
            nlohmann::json fn;
            fn["name"] = F.getName().str();
            fn["external"] = F.isDeclaration();
            
            for (auto &BB : F) {
                nlohmann::json block;
                block["label"] = BB.getName().str();
                // 填 successors
                for (auto *S : successors(&BB))
                    block["successors"].push_back(S->getName().str());
                
                for (auto &I : BB) {
                    nlohmann::json ins;
                    ins["opcode"] = I.getOpcodeName();
                    // 类型
                    std::string ts; raw_string_ostream os(ts);
                    I.getType()->print(os);
                    ins["type"] = ts;
                    // 操作数类型
                    for (auto &Op : I.operands()) {
                        std::string ots; raw_string_ostream oos(ots);
                        Op->getType()->print(oos);
                        ins["operand_types"].push_back(ots);
                    }
                    // call 特化
                    if (auto *CI = dyn_cast<CallInst>(&I)) {
                        if (auto *F = CI->getCalledFunction())
                            ins["callee"] = F->getName().str();
                        else
                            ins["indirect_call"] = true;
                    }
                    // debug loc
                    if (auto DL = I.getDebugLoc())
                        ins["loc"] = DL->getFilename().str() + ":" 
                                   + std::to_string(DL->getLine());
                    block["instructions"].push_back(ins);
                }
                fn["blocks"].push_back(block);
            }
            out["functions"].push_back(fn);
        }
        // 输出到文件或 stdout
        llvm::outs() << out.dump(2);
        return PreservedAnalyses::all();
    }
};
```

```bash
# 运行方式（build.rs 里封装）
opt -load-pass-plugin ./SafetyPass.so \
    -passes="safety-export" \
    input.bc -o /dev/null > ir.json
```

**优点**：类型 100% 准确（LLVM 亲自 print），CFG 完整，跟 LLVM 版本解耦（Pass API 稳定），你的 Rust 侧零 unsafe FFI。

**缺点**：需要维护一个 C++ 文件，CI 要装 LLVM dev headers（`llvm-dev` 包，不需要 brew 硬编码）。

---

## 路线 B：解析 `opt --print-after-all` 的文本输出（无 C++）

如果你完全不想碰 C++，可以用 `opt` 的内置输出，但要换一个格式：

```bash
# 输出带类型的 textual IR（就是 .ll）
llvm-dis input.bc -o input.ll

# 或用 opt 跑某个 pass 后输出
opt --passes="mem2reg" input.bc | llvm-dis -o -
```

然后写一个**真正的 .ll parser**。这是你"现有 text parser 的硬伤"的正确修法：

### 正确的 .ll Parser 设计

```rust
// src/ir/parser.rs
// .ll 格式是有完整 BNF 的，不应该逐行匹配

// 关键点 1：先 tokenize，再 parse，不要逐行
pub struct Lexer<'a> { src: &'a str, pos: usize }

// 关键点 2：define 可以跨多行，用状态机
enum ParseState {
    TopLevel,
    InFunction { brace_depth: u32 },
    InBasicBlock { label: String },
}

// 关键点 3：类型系统先建模
#[derive(Debug, Clone)]
pub enum LLVMType {
    Void,
    Integer(u32),          // i1, i8, i32, i64...
    Float(FloatKind),      // float, double, fp128
    Pointer(Box<LLVMType>, Option<u32>), // ptr 或 i8* (typed ptr)
    Array(u64, Box<LLVMType>),
    Struct(Vec<LLVMType>),
    Function(Box<LLVMType>, Vec<LLVMType>),
    Label,
    Metadata,
    Opaque,  // %opaque
}

// 关键点 4：指令建模要覆盖你关心的 opcode
#[derive(Debug)]
pub enum Instruction {
    Call {
        result: Option<String>,
        ret_ty: LLVMType,
        callee: Callee,
        args: Vec<(LLVMType, Value)>,
        attrs: CallAttrs,
    },
    Load {
        result: String,
        ty: LLVMType,
        ptr: Value,
        align: Option<u64>,
        is_volatile: bool,
    },
    Store {
        ty: LLVMType,
        val: Value,
        ptr: Value,
        is_volatile: bool,
    },
    BitCast { result: String, from: (LLVMType, Value), to: LLVMType },
    PtrToInt { .. },
    IntToPtr { .. },
    // ... 其他你关心的
    Other { raw: String },  // fallback
}

#[derive(Debug)]
pub enum Callee {
    Direct(String),           // @foo
    Indirect(LLVMType, Value), // 函数指针调用
    Intrinsic(String),        // llvm.memcpy 等
}
```

**但路线 B 的问题**：.ll 的 parser 写完整要 2-3 周，还有边界 case（opaque ptr vs typed ptr 在 LLVM 15+ 变了，会影响你的 pointer cast 检测）。

---

## 我的建议：路线 A + 复用现有可用代码

### 迁移计划

```
Week 1：写 C++ Pass（~200行）+ CMakeLists + build.rs 集成
         复用 cfg.rs、metadata.rs
         定义 JSON schema 对应的 Rust struct（serde）

Week 2：把现有检测器从 raw_text 匹配改成匹配 typed IR struct
         利用类型信息修掉 ~36% 的漏报

Week 3：加路径敏感分析（你的 cfg.rs 已经有 CFG 结构，接上去）
```

### 现有代码复用策略

| 文件 | 处理方式 |
|------|---------|
| `cfg.rs` | 直接复用，把 JSON 的 `successors` 填进去 |
| `metadata.rs` | 直接复用 |
| `IRInstruction` 新 type 字段 | 从 JSON `type` 字段填充，不再是 `None` |
| `llvm_ir_adapter.rs` | 删掉，换成 JSON 反序列化 |
| `type_extractor.rs` | 删掉，类型由 Pass 直接给 |
| text parser | 降级为 fallback（没有 .bc 只有 .ll 时用），但优先走 Pass |

### 关键：解决硬编码路径问题

```rust
// build.rs 或 runtime
fn find_opt() -> PathBuf {
    // 1. 环境变量优先
    if let Ok(p) = std::env::var("LLVM_OPT") {
        return PathBuf::from(p);
    }
    // 2. llvm-config
    if let Ok(o) = Command::new("llvm-config").arg("--bindir").output() {
        let dir = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let p = PathBuf::from(dir).join("opt");
        if p.exists() { return p; }
    }
    // 3. PATH
    which::which("opt").unwrap_or_else(|_| PathBuf::from("opt"))
}
```

---

## 一句话总结

**不要再试图用 Rust crate 解析 LLVM IR——让 LLVM 自己解析，你只消费 JSON。** 200 行 C++ Pass + serde_json，直接绕过所有版本兼容问题，类型信息 100% 准确，检测率能从 64% 直接上到 90%+。

---


这是一个非常典型的、在写硬核底层工具时由于**上游生态断代**导致的“架构灾难”。你的 Agent 之前之所以陷入僵局，是因为它试图在一个已经死掉的 `llvm-ir` 绑定上修修补补。

既然你的目标是做一个 **“通关通用检测器”**（要处理 Windows/Linux 跨平台 FFI 边界、多语言单态化膨胀、数据流/路径敏感分析），那就必须果断抛弃对第三方高层绑定的依赖。

目前你手里的资产里，`cfg.rs`（控制流图拓扑）和 `metadata.rs` 是完好的。既然你已经摸清了 Godbolt 吐出的真实文本结构，咱们直接**自建一个轻量级、高级语言不可知、且绝对不卡 LLVM 版本的现代 IR 语意解析器**。

以下是重构和拉高检测率的四步降维打击战略：

---

### 第一步：断舍离，重构底层适配层（替换 `llvm_ir_adapter.rs`）

不要再试图去绑定 LLVM 22 的 C++ 接口（维护成本会逼疯你），也不要指望硬编码调用 `llvm-dis`。

1. **解耦 `.bc` 转换**：
不要在 Rust 代码里硬编码 `Homebrew` 路径。在项目的 `Makefile` 或构建脚本里，要求用户通过环境变量或 PATH 调用系统自带的 `llvm-dis`。
在 Rust 代码里，只处理**标准输入输出/文件读取**。你的检测器核心只吃纯文本的 `*.ll`。
2. **基于“基本块（BasicBlock）”的有限状态机 Parser**：
放弃简单的“逐行字符串匹配”。LLVM IR 的文本结构是非常死板且完美的。一个标准的控制流拓扑长这样：
* `define ... @函数名(...) {` ➔ 进入函数上下文
* `标签名:` ➔ 进入基本块上下文（解决多行定义和缩进崩溃）
* `}` ➔ 退出函数


你需要用一个简单的状态机（State Machine）按块将文本割裂。

---

### 第二步：核心攻坚，手搓类型与符号推导（攻克 `type_extractor.rs`）

之前检测率卡在 64% 的元凶是：**下游靠 `raw_text` 字符串匹配去猜，完全没有类型信息**。在 FFI 检测中，如果不认识指针指向的结构体，你就无法追踪跨边界的内存越界和破坏。

既然不能用 `llvm-ir` crate 的类型系统，我们可以直接从 `*.ll` 的两大文本支柱里提取出完美的静态类型：

1. **解析全局结构体定义（Struct Types）**：
LLVM IR 的头部（也就是被 Godbolt 隐藏但文件里真实存在的顶部）会有密密麻麻的类型声明：
```llvm
%struct.MyStruct = type { i32, i8, [4 x i8] }
%"runtime.g" = type { i64, i64, ... } ; Go的协程结构体

```


优先写一个小正则，在解析函数前，把这些 `%struct.xxx` 全部捕获进一个全局的 `HashMap<String, StructLayout>` 里。
2. **符号就地推导（针对 `IRInstruction` 缺失的 3 个 type 字段）**：
LLVM IR 每一个 SSA 变量在诞生时，**类型都是明文写在当前行的**。
* 看到 `%1 = alloca i32, align 4` ➔ 记录 `%1` 的类型为 `i32*`。
* 看到 `%3 = load i32, i32* %1` ➔ 检查 `%1` 的类型，并记录赋值对象 `%3` 的类型为 `i32`。
* 看到 `%5 = getelementptr inbounds %struct.MyStruct, %struct.MyStruct* %4, i32 0, i32 1` ➔ 结合刚刚拿到的全局结构体 Map，立刻就能精确推导出 `%5` 偏移后的精确字段类型！



只要你在内存里维护一个临时的 `VariableTypeMap: HashMap<String, Type>`，随走随填，根本不需要任何 `llvm-ir` crate，那 3 个 type 字段就能被全部精准填满。

---

### 第三步：路径敏感分析激活（联动 `cfg.rs`）

既然你的 `cfg.rs` 是纯 Rust 写的且完好可用，现在你的 `IRInstruction` 有了类型，把它们顺理成章地塞进 CFG 节点里：

1. **识别 FFI 边界哨兵**：
利用 CFG 找出所有 `call` 或 `invoke` 指令。
* 如果调用的函数带有 `declare` 标记（在当前文件没有函数体），或者函数名不带有当前语言特征（例如没有 `_ZN` 或者是 Windows 特有的符号），直接判定为 **FFI 边界**。


2. **追溯 Unsafe 数据流**：
通过 CFG 的前驱（Predecessors）和后继（Successors）节点，沿着被你填满类型信息的指令做**逆向污点追踪（Taint Analysis）**。
* 检查：从 FFI 吐出来的指针（Source），经历了哪些 `bitcast`（类型强转）或指针偏移，最终是否流入了未受保护的 `store`（Sink）。



---

### 第四步：吃透 Windows / Linux 平台特异性 Tag（拉高检测率至 95%+）

还记得你刚刚在 Godbolt 里肉眼对齐的两边差异吗？要把针对通用检测器的平台适配写死进代码里：

1. **Windows 专属噪声清洗**：
在解析指令时，一旦发现 `call void @llvm.dbg.declare` 或者 Windows 的栈探测 `call void @__chkstk`，直接在过滤阶段将其作为无意义噪声擦除（`drop`），不要让它中断你的 CFG 线性链。
2. **ABI 隐式指针（`byval` 属性）适配**：
针对 Windows (MSVC) ABI 把大结构体强转成指针传参的行为，你的边界检测器一旦在 `call` 指令参数里看到 **`byval(%struct.xxx)`** 标记，必须在内部数据流图里把它特殊标记为 **“这是一个值拷贝传递，而不是指针引用传递”**。这能直接干掉至少 20% 因为平台 ABI 差异导致的漏报和误报。

---

### 🚀 具体的动手顺序

1. **删掉 `Cargo.toml` 里的 `llvm-ir` 依赖**，彻底让项目编译通过，只留下完好的 `cfg.rs`、`metadata.rs` 和你的指令结构体。
2. 在 `llvm_ir_adapter.rs` 里，写一个按函数大括号 `{ }` 和基本块标签分割文本的简单字符串 Scanner，让数据先跑起来。
3. 实现本地的 `VariableTypeMap`，在扫描到 `alloca`/`load`/`getelementptr` 时，就地把类型写进变量名里。

这样走，你的工具将**获得完全的自由**：不再受制于任何 LLVM 版本的变动，不需要繁重的 C++ 混编链，完全基于纯净的跨平台 `.ll` 语意进行审计。这才是系统级极客手搓高通用性安全工具的终极正宗姿势！


---

我直接给结论，不绕。

你现在面临的是一个LLVM frontend crisis。

核心问题不是 unsafe/ffi analyzer 怎么写。

而是：

Rust 生态没有一个稳定、现代、可维护的 LLVM22 IR API。

所以你要先解决 IR ingestion layer。

⸻

我给你几个路线，按现实可落地程度排序。

⸻

方案A（我推荐）—— 不要用 llvm-ir crate

直接放弃。

理由你已经说完了：

* LLVM19 ceiling
* 半弃坑
* API drift
* 跟不上 LLVM cadence

继续修 = 技术债。

直接 stop loss。

⸻

改成：

用 LLVM 官方 C API

Rust:

llvm-sys

或者：

inkwell

但我更推荐 llvm-sys。

⸻

原因。

你做的是：

IR analyzer

不是：

LLVM compiler framework

⸻

你需要：

⸻

Module

⸻

Function

⸻

BasicBlock

⸻

Instruction

⸻

Type

⸻

Call

⸻

CFG

⸻

Metadata

⸻

这些 LLVM C API 都有。

⸻

而且：

LLVM22 永远兼容 LLVM22。

⸻

没有第三方同步问题。

⸻

架构：

unsafeffi/
  ir/
      llvm_loader.rs
      module.rs
      function.rs
      instruction.rs
      cfg.rs
      metadata.rs

⸻

Loader:

⸻

LLVMContextCreate

⸻

LLVMParseIRInContext

⸻

LLVMGetFirstFunction

⸻

LLVMGetNextFunction

⸻

LLVMGetInstructionOpcode

⸻

LLVMTypeOf

⸻

LLVMGetBasicBlockTerminator

⸻

结束。

⸻

你会发现：

90% analyzer 能写。

⸻

⸻

优点：

✅ LLVM22 native

✅ CFG天然可得

✅ type info完整

✅ bc/ll 都能吃

✅ 不依赖弃坑 crate

⸻

缺点：

API ugly.

⸻

但 analyzer 项目可以接受。

⸻

⸻

方案B（最快落地）—— Hybrid Model

如果你现在想 一周内恢复可运行。

⸻

别急着重写。

做：

Text Parser v2 + Minimal Semantic Layer

⸻

现在你的 parser：

⸻

line-based.

⸻

fragile.

⸻

no CFG.

⸻

⸻

升级。

⸻

不要逐行 parse。

改：

Block Parser

⸻

流程：

⸻

先 tokenize.

⸻

再 parse structure.

⸻

⸻

目标：

解析：

⸻

Module

⸻

Function

⸻

BasicBlock

⸻

Instruction

⸻

Type signature

⸻

Call targets

⸻

⸻

例如：

⸻

define parser.

⸻

收集：

define
{
 ...
}

⸻

不要逐行。

⸻

构建：

Function {
    name,
    args,
    ret_ty,
    basic_blocks
}

⸻

Instruction：

新增：

enum IRInstruction {
    Call,
    Load,
    Store,
    GEP,
    Br,
    Ret,
    Phi,
    BinaryOp,
}

⸻

不是 raw text.

⸻

⸻

这样：

64% → 80%+。

⸻

不用 LLVM dependency.

⸻

⸻

但。

长期仍有限。

⸻

没有 optimizer fidelity.

⸻

metadata pain.

⸻

⸻

适合：

MVP。

⸻

方案C（工程最稳）—— 自建 Thin LLVM Adapter

这是我最推荐的长期形态。

⸻

不要直接 analyzer ← llvm-sys。

太丑。

⸻

做：

Thin Adapter Layer

⸻

目录：

src/
  ir/
      adapter/
          llvm22.rs
      model/
          module.rs
          function.rs
          instruction.rs
          type.rs

⸻

定义自己 IR model。

⸻

例如：

pub struct IRFunction {
    pub name:String,
    pub blocks:Vec<BasicBlock>,
}

⸻

Instruction：

enum IRInstruction {
    Call(CallInst),
    Load(LoadInst),
    Store(StoreInst),
    GEP(GEPInst),
}

⸻

⸻

llvm22 adapter:

负责：

LLVM → internal model.

⸻

Analyzer：

永远只看：

internal IR model

⸻

以后：

LLVM23.

⸻

MLIR.

⸻

Text parser fallback.

⸻

都能接。

⸻

这是最稳的。

⸻

⸻

方案D（非常实用）—— 直接调用 LLVM JSON

很多人忽略这个。

LLVM 有：

llvm-dis
opt

⸻

你可以：

生成 structured dump.

⸻

例如：

opt -passes=dot-cfg

⸻

或者：

LLVM remarks.

⸻

甚至 custom pass dump.

⸻

然后 Rust 解析。

⸻

但。

灵活度低。

⸻

适合作辅助。

⸻

⸻

我给你的现实建议（不要过度设计）

Phase1

先救火。

⸻

删：

llvm-ir crate

⸻

保留：

⸻

cfg.rs

⸻

metadata.rs

⸻

⸻

新增：

llvm_sys_loader.rs

⸻

只实现：

⸻

load module

⸻

iterate functions

⸻

iterate BBs

⸻

iterate instructions

⸻

get opcode

⸻

get types

⸻

结束。

⸻

不要一次实现全部 LLVM API。

⸻

⸻

Phase1 数据结构：

⸻

pub struct IRModule {
    functions:Vec<IRFunction>,
}

⸻

pub struct IRFunction {
    name:String,
    blocks:Vec<IRBasicBlock>,
}

⸻

pub struct IRInstruction {
    opcode:Opcode,
    operands:Vec<Operand>,
    ty:Option<IRType>,
}

⸻

够了。

⸻

⸻

Phase2

接：

unsafe.

⸻

ffi.

⸻

ownership.

⸻

callgraph.

⸻

⸻

Phase3

优化。

⸻

metadata.

⸻

debug info.

⸻

full CFG.

⸻

⸻

关于检测率64%

你已经找到根因：

类型信息缺失。

这很正常。

unsafe/ffi analyzer 没 type info 很痛苦。

⸻

例如：

⸻

*mut T

⸻

*const c_void

⸻

extern "C"

⸻

ABI mismatch.

⸻

layout mismatch.

⸻

pointer provenance.

⸻

全靠 type。

⸻

所以：

优先修 type layer。

甚至比 CFG 优先。

⸻

最后一句（我的真实建议）

如果我是你。

我会这样做：

⸻

立即放弃 llvm-ir crate。

⸻

实现：

llvm-sys
    ↓
Thin Adapter
    ↓
Internal IR Model
    ↓
Analyzer

⸻

保留：

⸻

cfg.rs

⸻

metadata.rs

⸻

⸻

别继续救 text parser。

它会变成：

“我自己重写一个半残 LLVM parser”

最终更累。

⸻

一句话：

不要依赖弃坑 crate。

不要继续强化 fragile text parser。

用 llvm-sys 做薄适配层，建立自己的内部 IR 模型。

这是目前最稳、最可控、最符合你项目路线的方案。