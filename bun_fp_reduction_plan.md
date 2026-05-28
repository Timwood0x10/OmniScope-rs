# bun.sh FP 治理方案 — 语义树骨架 + 语料归纳模式

编码风格与约束：严格遵循 `/plan/rules/*.*`，包括 `/plan/rules/rules.md` 与 `/plan/rules/skills.md`。

验收标准：bun FP 从 **1966 → <110**（94% 降幅，对齐 `LL_ANALYSIS_REPORT.md` §八）。

- [ ] File is under 1000 lines
- [ ] Code is simple and straightforward
- [ ] All comments are in English
- [ ] Code-to-comment ratio is approximately 7:3
- [ ] Tests include boundary cases
- [ ] No files were deleted without permission
- [ ] Naming conventions are followed
- [ ] Code is formatted with `zig fmt`
- [ ] All tests pass
- [ ] Public APIs have doc comments
- [ ] Error handling is appropriate
- [ ] Memory management is correct
- [ ] Changes are surgical and minimal
- [ ] New resource/family/summary decisions include evidence
- [ ] Unknown states become diagnostic or fallback, not default high severity
- [ ] FFI boundary and CrossLangEdge are never suppressed only by platform/runtime hints
- [ ] 毕业终极指南，用~/code/researcher/bun  这个rust 项目检测，找到问题，TP> 90% FN + FP < 10%



> 输入: `bun_report.md` (179 .bc / 115 issue / TP=0 / FP=115)
> 目标: 把项目里已存在但闲置的 **Semantic Resolution Tree (SRT)** 升级成统一语义层，所有 Pass 在 emit Issue 之前必须查询 SRT；SRT 填料来自**对本机所有 .ll/.bc 语料的实证归纳**（见 §1.B 的 R-0 ~ R-6），Nomicon 仅作为为什么 sound 的参考脚注。
> 范围: 仅修改 OmniScope 自身，方案对所有 Rust+C 重 FFI 项目通用。**禁止项目特定白名单**。

---

## 0. 根因（一句话）

**Rust 的所有权 / RAII / Interior Mutability / Send-Sync 等在 LLVM IR 层被完全抹平**。OmniScope 现状是每个 Pass 自己再做一遍 ad-hoc 名字匹配，互相不复用、不共识，所以同一个 `__rust_dealloc` 在 FFIAuditor 看是"安全的"，在 UseAfterFreePass 看是"双重释放"。

修复路径不是"再加规则"，而是**建立一个所有 Pass 都必须查询的语义共识层**。这个层就是项目里已经定义、却没在用的 `SemanticTree`。

---

## 1. 现状盘点 — 已有但未用的资产

### 1.1 Semantic Resolution Tree（`src/semantics/semantic_tree.zig`，279 行）

```zig
pub const SemanticTree = struct {
    nodes: ArrayList(SemanticNode),
    value_to_node: HashMap(ValueRef, usize),  // ← O(1) 查询接口已存在
    pub fn getNodeByValue(value_ref: ValueRef) ?*const SemanticNode;
};
```

**问题**:
1. `SemanticKind` 只有 4 个变体（allocation / release / provenance / unknown）—— 表达力远不够 Rust 语义。
2. `SemanticPatterns.matchesFunction` 是 `std.mem.indexOf` 字符串包含匹配（`semantic_patterns.zig:43`）—— 没用 DI / 没用控制流位置。
3. `SemanticResolverPass` 写入 SRT（`semantic_resolver_pass.zig:65`），但**下游 Pass（rust_ffi_rules_advanced.zig、ffi_body_check.zig）从不查 SRT**。

### 1.2 已就绪的 LLVM IR 信号源

- DI metadata 访问: `getDITypeName` / `getDIBaseType` / `isConstQualifiedMember`（`rust_ffi_rules_advanced.zig:572-634`）
- Drop 语义识别: `DROP_GLUE_PATTERNS`（`rust_drop_semantics.zig:31`）
- Value 来源追踪: `traceValueSource` / `ValueSource` 枚举（`value_tracking.zig`）
- Taint 引擎: source/sink 表 + 传播（`taint_propagation.zig`）

**结论**：所有信号源都已经在 — 缺的是**统一收口的语义层**。

---

## 1.A 本机 IR 语料盘点（语料学习的依据）

> **策略**：把本机能找到的所有 `.ll` / `.bc` 当训练语料，**让规律自我浮现**。任何想进入 SRT 的语言级规律必须能在**多源、多语言**语料里观察到；任何想进入小白名单的条目必须在 ≥3 个语料文件中重复出现且**有相同的 IR 形态**。
> 工具链统一 **LLVM 22** (`/opt/homebrew/Cellar/llvm/22.1.6/bin/llvm-dis`)，bun 是 Rust nightly-2026-05-06 (LLVM 22)。
> **支持语言（明确范围）**：Rust / Go / C / C++ / C# / Python / Java，共 **7 种**。**Swift 不在本期支持范围，相关语料排除**。

### 1.A.1 语料清单（按语言归类）

| 来源路径 | 文件数 | 语言 | 用途 / 项目类型 |
|---|---|---|---|
| `~/code/researcher/bun/target/release/deps/*.bc` | **192** | Rust (nightly-2026-05-06) | 真实大型 JS runtime；1966 FP 全部来自此 |
| `~/code/researcher/tinygo/{transform,compiler,interp}/testdata/*.ll` | 49 | Go (via TinyGo) | TinyGo 编译器输出；21 个含 `runtime.alloc` |
| `~/code/zigcode/OmniScope/corpus/real_project_test/*.{ll,bc}` | 11 | Rust + Go | crc32fast/xxhash/zstd-rs/go-sqlite3/bun_alloc/bun_mimalloc |
| `~/code/zigcode/OmniScope/corpus/red_team_test/*.{ll,bc}` | 22 | C/C++/Rust/Go/C#/Python/Java JNI | **故意带 bug 的对照组**（TP 验证 / Recall 测量） |
| `~/code/zigcode/OmniScope/corpus/real_world/{other,zkp}/*.{ll,bc}` | 22 | C/C++/Rust | curl8/libuv150/sqlite3/wasmtime/abseil/openssl/jsoncpp/ripgrep/blst/gnark/libsodium |
| `~/code/zigcode/OmniScope/corpus/ffi-dense/*.{ll,bc}` | 6 | C/C++/Rust | zlib/sqlite/openssl 绑定层（高密度 FFI） |
| `~/code/ffi-demo/output/*.{ll,bc}` | 18 | Rust + C + C++ (+ Zig) | 跨语言互调 demo |
| `~/code/rustcode/OmniScope-rs/tests/integration/*.{ll,bc}` | 18 | Rust + C + C++ | 副本 |

**红队语料中各语言对照文件**（已存在，直接用于 detector 验证）:

| 语言 | 文件 |
|---|---|
| Rust | `rust_ffi_bugs.{ll,bc}` / `rust_multi_lang_ffi_bugs.bc` |
| Go (CGo) | `go_cgo_bugs.{ll,bc}` |
| Go (TinyGo FFI) | `go_tinygo_ffi_bugs.bc` |
| C++ | `cpp_operator_new_ffi_bugs.bc` / `red_team_cpp_ffi.{ll,bc}` |
| C# | `csharp_ffi_bugs.{ll,bc}` / `csharp_win32_ffi_bugs.bc` |
| Python (CFFI) | `python_cffi_bugs.{ll,bc}` |
| Java (JNI) | `java_jni_bugs.{ll,bc}` |
| 跨语言 free | `cross_lang_free_bugs.{ll,bc}` |
| 三语言链 | `red_team_triple_chain.{ll,bc}` |

**总计 ~338 个 IR 文件**（排除 Swift 19 个后），覆盖 7 种源语言。

### 1.A.2 语言识别启发式

每个 IR 文件入库时打 `language` tag：

| 信号 | 推断语言 | 命中文件示例 |
|---|---|---|
| 函数名前缀 `_RNv` / `_RIN` / `_RNs`（Rust v0 mangling） | Rust | `bun_base64-*.bc` |
| 函数名前缀 `_ZN`，无 `core` / `alloc` namespace | C++ | `cpp_hash.ll`, `cpp_operator_new_ffi_bugs.bc` |
| 含 `runtime.alloc` / `runtime.makeSlice` / Go target triple | Go (TinyGo) | `allocs.ll` |
| 含 `runtime.cgocall` / `_cgo_*` / `crosscall2` | Go (CGo) | `go_cgo_bugs.ll`, `go-sqlite3.ll` |
| 含 `JNI_OnLoad` / `Java_*` / `_JNI*Env*` | Java (JNI) | `java_jni_bugs.ll` |
| 含 `Py_Initialize` / `PyArg_*` / `PyObject_*` / `_cffi_*` | Python (CFFI) | `python_cffi_bugs.ll` |
| 含 `CoreCLR_*` / `Marshal_*` / `_GLOBAL__sub_I_` + `mscorlib` 引用 | C# | `csharp_ffi_bugs.ll`, `csharp_win32_ffi_bugs.bc` |
| 仅 C ABI 符号（无 mangling）+ stdio/posix | C | `c_fft_c_bridge.ll` |

辅助信号：`source_filename`、`target triple`、`!llvm.dbg.cu` 的 `producer` 字段（如 `"clang"` / `"rustc"` / `"tinygo"`）。每个 detector 跑前先调 `language_detector.detect(module)`，**Rust detector 仅在 language=Rust 时跑**。

### 1.A.3 不入库的明确排除

- **Swift**（本期不支持）：`~/code/researcher/swift/test/LLVMPasses/*.ll`（19 个文件不入库）
- `*.out.ll`（TinyGo expected-output 文件，对照用非真实程序）
- `~/code/ffi-demo/build/**`（重复，来自 `output/`）
- `**/target/debug/**`（debug build 噪声大、栈检查桩多）

---

## 1.B 从语料归纳的通用规律（Mined Regularities）

> 每条规律都用真实语料证据支撑。**任何想写进 SRT 的判定都必须能在表里找到对应行**。
> `ir.md` 作为补充证据源（人工逐文件读取 *.ll 后归纳的跨语言 IR 规律），R-3/R-7 的部分模式来自此文件。
> bun 上 OmniScope v0.1.8 实测 FP 分布（见 `LL_ANALYSIS_REPORT.md`）：
> - write_to_immutable: **1877**（主战场，R-0 + R-2 覆盖）
> - borrow_escape: **71**（R-1 覆盖）
> - cross_language_free: **4**（R-3 covers, plus into_raw 模式 R-6）
> - use_after_free: **3**（R-4 覆盖）
> - **总计 1966**，目标砍到 <110（94%）

### R-0 — LLVM `readonly` / `noalias` 参数属性（覆盖大头：F2 1877 FP 的主因）

> **这是最关键的规律 — 也是之前方案漏掉的**。`readonly` 是 Rust `&T` 在 LLVM IR 中的**直接显式标记**，比绕道 DI metadata 简单可靠 10 倍。

| 维度 | 值 |
|---|---|
| 模式 | `define ... @func(ptr readonly %p, ...)` → `%p` 对应 Rust `&T`；无 readonly → `&mut T` |
| `noalias` 模式 | `noalias` + 无 `readonly` → `&mut T`（独占可变借用）；`noalias` + `readonly` → `&T` 且独占引用 |
| 证据文件 | `bun_alloc.ll`: `@_RNvCs9SN9c7tmF9T_9bun_alloc12default_dupe(ptr noalias noundef nonnull readonly captures(none) %src.0, i64 noundef %src.1)` |
| 跨项目证据 | bun 全部 192 crate 都生成 `readonly` 属性；`ripgrep141.ll`、`blst.ll` 同样 |
| 语义事实 | rustc 把 `&T` 必然标 `readonly`（rustc_codegen_llvm/src/attributes.rs）。**store 到 readonly 参数衍生的 ptr 才是真 immutable 违反** |
| Detector | `param_attr.zig`（新建）：遍历 function 参数，调用 `LLVMGetEnumAttributeAtIndex(func, idx, "readonly")`，把命中参数的 ValueRef 标 `readonly_param`；未命中的标 `mutable_param`。`detectWriteToImmutable` 在 emit 前查：dest GEP 的 base 若**最终来自 mutable_param** → 不报 |
| 通用性 | 完全依赖 LLVM IR 规范的参数属性，**不依赖任何语言/项目命名** |

### R-1 — Rust SROA Heap-Field Load（覆盖 borrow_escape 71 FP）

| 维度 | 值 |
|---|---|
| 模式 | LLVM Value 名形如 `*.sroa.N.M.copyload` / `*.sroa.N.M.insert` |
| 高频证据 | `bun_css.ll`: **117,571** 处；`bun_install.ll`: 111,813；`bun_js_parser.ll`: 80,335；`bun_bundler.ll`: 63,473 |
| 跨项目 | bun 全部 192 个 crate 都出现；Go / C / C++ IR 无此命名（SROA 在它们语言上以不同形态出现） |
| 语义事实 | LLVM SROA 把 `Box<T>` 等堆指针 wrapper 的 alloca 拆成标量字段。**alloca 本身的 DI 类型还保留 `Box<T>` 字串** — DI metadata 是恢复 provenance 的钥匙 |
| Detector | `heap_provenance.zig`：遍历每个 alloca，若 `DILocalVariable.DIType.name` 以 `Box<` / `Arc<` / `Rc<` / `Vec<` / `String` / `*mut ` / `*const ` 开头，所有从它派生的 sroa load 标 `heap_provenance` |
| 通用性 | 仅依赖 6 个 Rust 语言级类型前缀 + LLVM SROA 命名约定，**不出现任何项目特定 callee 名字** |

### R-2 — Rust UnsafeCell as the Sole Interior-Mutability Marker（覆盖 F2 = 23 FP）

| 维度 | 值 |
|---|---|
| 模式 | DI type chain 任意一层含字符串 `UnsafeCell<` |
| 频率证据 | `bun_install.ll`: 367 处；`bun_bundler.ll`: 266；`bun_resolver.ll`: 125；`bun_http.ll`: 57 |
| 语义事实 | Rust 标准库 / `parking_lot` / `crossbeam` 等所有第三方 interior-mut 类型都**强制**内嵌 `UnsafeCell` — 这是语言规范 |
| Detector | `interior_mut.zig::isInteriorMutableThroughChain(di_type)`：递归走 DI base chain ≤8 层，命中 `UnsafeCell<` 即标 `interior_mutability` |
| 通用性 | **仅 1 个字符串**，所有项目零修改通用 |

### R-3 — Rust Drop Glue: drop_in_place + tail `__rust_dealloc`（覆盖 F4 = 3 FP）

| 维度 | 值 |
|---|---|
| 模式 A | enclosing function name 含 `13drop_in_place` (Itanium prefix) 或 `drop_in_place` (v0) |
| 模式 B | `call @__rust_dealloc(...)` 后只跟 `llvm.lifetime.end` / `llvm.dbg.value` / `ret` / `br` |
| 频率证据 | `bun_install.ll`: 23,904 个 drop_in_place vtable 条目；3,319 个 `__rust_dealloc` |
| 语义事实 | rustc 编译器固定行为：每个非 Copy 类型的 drop 经 vtable 派发到 `drop_in_place<T>`；scope-end dealloc 永远是 RAII，不是 bug |
| 模式 C | Arc/Rc 引用计数条件释放：`atomicrmw sub %refcount, 1` → `icmp eq %old, 1` → `br %cond, %drop, %done` → `%drop: call @drop_in_place` (来源: `ir.md` §3.2, `bun_alloc-ef7250b81132b4bd.ll`) |
| Detector | `drop_glue.zig`：function 名匹配 → 整函数标 `raii_drop_release`；非 drop function 内的 `__rust_dealloc` 看后继指令链；`atomicrmw sub` + `icmp eq` + `br` + `call @drop_in_place` 四指令组合 → 标 `raii_drop_release` |
| 通用性 | 依赖 rustc ABI 符号 `__rust_dealloc` / `__rdl_dealloc` / `__rg_dealloc` + `drop_in_place` 子串 + LLVM atomicrmw 指令模式，全 Rust 项目通用 |

### R-4 — POSIX Syscall Action Class（覆盖 F3 = 4 FP）

| 维度 | 值 |
|---|---|
| 模式 | C ABI 名匹配 POSIX 标准名表（约 60 项）→ 4 类（file / net / mem / proc） |
| 证据 | `bun_paths.bc` 含 `Bun__unlink`（内调 libc `unlink`）；`curl8.bc` / `libuv150.bc` 含完整 file/net syscall |
| 语义事实 | POSIX 标准定义了这些 syscall 的语义动作，与"内存释放"无关 |
| Detector | `posix_syscalls.zig`：表驱动，名字精确匹配（含 `name@GLIBC_*` 版本后缀） |
| 通用性 | 表条目来源是 POSIX 规范，不随项目增长 |

### R-5 — 跨语言 runtime / FFI 形态对照（指导 detector 何时不该跑）

| 语言 | 标志性 IR 模式 | 命中文件 | 用途 |
|---|---|---|---|
| Go (TinyGo) | `call ptr @runtime.alloc(i32 N, ptr null)` | 21/49 tinygo testdata | GC alloc，**不参与 Rust Drop 判定**；跨语言 free 跳过 |
| Go (CGo) | `runtime.cgocall` / `crosscall2` / `_cgo_*` shim | `go_cgo_bugs.ll`, `go-sqlite3.ll` | CGo 边界点位，FFI Pass 在此处做 ownership 检查 |
| Java (JNI) | `Java_*` 函数名 + 接收 `JNIEnv*` 首参 | `java_jni_bugs.ll` | JNI 边界；`NewGlobalRef`/`DeleteLocalRef` 是 JNI 内存生命周期原语 |
| Python (CFFI) | `_cffi_*` callback shim + `PyObject_*` API | `python_cffi_bugs.ll` | CFFI 持有 `PyObject*` 引用计数，与 Rust drop 完全不同 |
| C# | `mscorlib` 引用 + `Marshal_*` interop + `CoreCLR_*` | `csharp_ffi_bugs.ll` | CLR GC 管控，FFI 边界需 `[DllImport]` shim |
| C++ | Itanium `_Z[NK]` mangling，无 Rust hash 后缀 | `cpp_hash.ll`, `cpp_operator_new_ffi_bugs.bc` | `operator new`/`delete` 是 C++ allocator，与 `malloc`/`free` 共池但符号不同 |

**这条规律的真正作用**：每个 detector 入口先检查 `module.language`，**Rust detector 仅在 language=Rust 时跑**，避免 `_RNv*` matcher 在 Java JNI / Python CFFI IR 上误判。同理，Go detector 仅在 language=Go 时跑 runtime.alloc 识别。

### R-7 — 库级分配器配对表（覆盖 mimalloc/zlib/openssl/sqlite/Go cgo 等非 POSIX 释放调用）

> R-4 覆盖 POSIX syscall，但 bun 等项目大量使用**库级自定义分配器**，其释放函数既不是 POSIX 也不是 Rust 全局分配器。`ir.md` §9 从真实 .ll 文件中归纳了 30+ 条配对。

| 维度 | 值 |
|---|---|
| 模式 | 库函数名精确匹配 → acquire / release / borrow / conditional_release 四类 |
| 证据来源 | `ir.md` §9（人工逐文件读取 *.ll 后归纳，每条标注来源文件） |
| 覆盖分配器 | mimalloc (`mi_*`), zlib (`inflate*/deflate*`), openssl (`EVP_*/BIO_*/RSA_*/BN_*`), sqlite (`sqlite3_*`), Go cgo (`_cgo_*` / `_Cfunc_*`), Python CFFI (`Py*`), JNI (`New*Ref` / `Delete*Ref` / `Get*Chars`), Zig allocator vtable |
| Detector | `library_alloc_pairs.zig`（新建）：表驱动，函数名精确匹配 → 写 SRT `.library_release` / `.library_acquire` |
| 与 R-4 的关系 | R-4 覆盖 POSIX 标准 syscall（unlink/close/socket 等）；R-7 覆盖第三方库分配器。两表互补，cross_language_free 检测同时查两张表 |
| 通用性 | 表条目来自库的公开 API 文档（man page / API reference），不随项目增长 |

**分类表结构**（与 POSIX syscall 表并列，不计入白名单条目数）:

| 分配器族 | acquire | release | borrow (如有) | 来源文件 |
|---|---|---|---|---|
| mimalloc | `mi_malloc` / `mi_realloc` | `mi_free` / `mi_heap_destroy` (conditional) | — | `bun_alloc-ef7250b81132b4bd.ll` |
| zlib | `inflateInit_` / `deflateInit_` | `inflateEnd` / `deflateEnd` | — | `zlib_binding.ll` |
| openssl | `EVP_CIPHER_CTX_new` / `BIO_new` / `RSA_new` / `BN_new` | `*_free` 对应函数 | — | `openssl_wrapper.ll` |
| sqlite | `sqlite3_open` / `sqlite3_prepare_v2` | `sqlite3_close` / `sqlite3_finalize` / `sqlite3_free` | — | `sqlite_binding.ll` |
| Go cgo | `_cgo_allocate` / `_Cfunc_GoMalloc` | `_cgo_free` / `_Cfunc_GoFree` | — | `go_cgo_bugs.ll` |
| Python CFFI | `PyBytes_FromStringAndSize` / `PyTuple_New` | `Py_DECREF` / `Py_XDECREF` | `PyList_GetItem` / `PyBytes_AsString` | `python_cffi_bugs.ll` |
| JNI | `NewGlobalRef` / `NewStringUTF` / `NewByteArray` | `DeleteGlobalRef` / `DeleteLocalRef` | `GetStringUTFChars` / `GetPrimitiveArrayCritical` | `java_jni_bugs.ll` |
| Zig allocator | `zig_allocator_allocImpl` | `zig_allocator_freeImpl` | — | `boundary_test.ll` |

### R-8 — 函数参数不是栈逃逸（覆盖 borrow_escape 39 FP）

> **这是 borrow_escape FP 的根因** — `from_parameter` 被误判为栈逃逸，但参数不是当前函数的栈分配。

| 维度 | 值 |
|---|---|
| 模式 | `traceValueSource` 返回 `from_parameter` → 不应标记为 stack escape |
| 证据 | bun 全量分析：39 个 borrow_escape FP 全部是 `from_parameter-derived pointer` |
| 语义事实 | 函数参数是调用者传入的指针，不是当前函数的栈分配。调用者负责生命周期，被调用者无权标记为"逃逸" |
| Detector | `detectStackEscapeToFFI`：`from_parameter` 直接 `continue`，只标记 `from_alloca` |
| 通用性 | 语言无关 — 所有语言的函数参数都不是当前函数的栈分配 |

**实现位置**: `src/pass/analysis/rust_ffi/rust_ffi_rules_basic.zig:detectStackEscapeToFFI`

**修改内容**:
```zig
// 修改前：from_alloca 和 from_parameter 都被标记为栈逃逸
.from_alloca, .from_parameter => {},

// 修改后：只有 from_alloca 是栈逃逸，from_parameter 是调用者传入的指针
.from_alloca => {},
.from_parameter => {
    // Parameters are not stack escapes in the current function.
    // The caller owns the pointer and is responsible for its lifetime.
    continue;
},
```

**实测效果**: borrow_escape 39 → 0 (100% 消除)

### R-6 — 跨语言 FFI 边界的真实 callee 形态（指导白名单边界）

从 `bun_http.bc` 的 `declare` 块抽样：

```
declare noundef ptr @us_socket_ext(ptr noundef nonnull) unnamed_addr #0
declare noundef ptr @us_connecting_socket_ext(ptr noundef nonnull) unnamed_addr #0
declare void @_RNvNtCsgXhsEb1m4tm_4core9panicking5panic(...)  ; Rust core, 非 FFI
declare void @llvm.memcpy.p0.p0.i64(...)  ; LLVM intrinsic
```

**洞察**: 真正的"项目特定"FFI callee（如 `us_socket_ext`）和 LLVM intrinsic / Rust core 调用在同一个 `declare` 块里。**只看名字判断"哪些 callee 安全"必然失败** — 没有任何固定规则能枚举完所有 C 库。
**唯一通用判定**: 看传给 callee 的实参 `provenance`（R-1 已覆盖）。callee 是 `us_socket_ext` 还是 `SSL_set_options` 都不重要。

---

## 2. 设计目标（强制约束）

### 2.1 SRT 作为唯一语义共识

```
LLVM IR  ─►  Signal Layer  ─►  SRT 写入  ─►  Pass 查询 SRT  ─►  Issue Gate  ─►  Diagnostic
                                  ▲
                                  │
                            Mined Pattern Catalog
                            (§1.B R-0~R-6 语料归纳)
```

强制规则：**任何 Pass 在 emit Issue 之前必须调用 `srt.queryResolution(value)`**，如果 SRT 返回 `RustSemanticTag != .none`，必须根据 tag 抑制或降级。

### 2.2 极小可解释白名单（仅 3 条 + 2 个分类表）

承认白名单不可避免，但严格收口到**对齐 LL_ANALYSIS_REPORT.md §5.1 的 3 条**：

| 函数名 | 语言 | 证据文件 | IR 模式 | 为什么是 FP | 置信度 |
|---|---|---|---|---|---|
| `malloc_set_zone_name` | C / macOS | `bun_alloc.bc` | `call void @malloc_set_zone_name(ptr %zone, ptr %name)` | macOS 函数复制字符串内容，**不保留 `name` 指针**（man page 文档化） | 高 |
| `_RNvXs*Box*into_raw` (`Box::into_raw`) | Rust | `rust_ffi_bugs.ll`, `bun_*.bc` 多处 | `%raw = call ptr @..._into_raw(%box)` | 所有权显式转出，后续被 C `free()` 是设计意图 | 高 |
| `_RNvXs*CString*into_raw` / `String::into_raw` | Rust | `rust_multi_lang_ffi_bugs.bc` | 同上模式 | 同上 | 高 |

**每条白名单条目入库格式（强制）**:
```toml
[[whitelist_entry]]
name              = "malloc_set_zone_name"
language          = "c"
evidence_file     = "corpus/real_project_test/bun_alloc.bc"
observed_count    = 12  # 跨多少个 corpus 文件出现
ir_pattern        = "call void @malloc_set_zone_name(ptr, ptr)"
reason            = "Per macOS man page: copies name string; pointer not retained"
confidence        = "high"
reviewer          = "<commiter>"
review_date       = "2026-05-28"
```

**三张分类表（不计入白名单条目数）**:
- **POSIX syscall 分类表** (R-4)：约 60 项，来自 POSIX/SUSv4 规范，**分类信息是 syscall 本身的语义事实**（man 页定义），不是"安全/不安全"主观判断
- **LLVM intrinsics 表** (`llvm.*`)：LLVM Reference Manual 定义的有限规范集
- **库级分配器配对表** (R-7)：~30 项，来自 mimalloc/zlib/openssl/sqlite/Go cgo/Python CFFI/JNI/Zig allocator 的公开 API 文档（`ir.md` §9 归纳）

**为什么不能继续增长**：经 R-6 验证，项目特定 callee（`us_socket_ext` / `SSL_set_options` / `archive_read_set_options` ...）在 IR 形态上和真 FFI 调用完全一样。它们的豁免**必须**靠 R-0 的 `mutable_param` 或 R-1 的 `heap_provenance` 自动覆盖。库级分配器（mimalloc/zlib/openssl/sqlite 等）的 release 函数走 R-7 分类表，不走白名单。如果发现某新 callee 不能被 R-0/R-1/R-7 覆盖，**先尝试扩展 detector，最后才考虑加白名单**，且要走上面那个 TOML 评审格式。

### 2.3 模式目录以语料归纳为母版（Nomicon 仅作脚注）

模式目录的唯一来源是 §1.B 的 R-0 ~ R-6 — **每条规律都有真实 grep 频次支撑**。
Nomicon 仅作为"为什么这个模式 sound"的解释脚注（如 R-3 引用 Ch6 OBRM），**不作为目录划分依据**。

---

## 3. 三层架构（新结构）

```
┌──────────────────────────────────────────────────────────────────────┐
│ Layer 3 — Pass + Issue Gate                                          │
│  rust_ffi_rules_*.zig / ffi_body_check.zig / taint_*.zig             │
│  必须 query SRT；SRT verdict 决定 emit/suppress/downgrade            │
└────────────────────────────────────────────────────────────────────┬─┘
                                                                     │
                                                                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Layer 2 — Semantic Resolution Tree (SRT)                             │
│  src/semantics/semantic_tree.zig (扩展)                              │
│   - 扩展 SemanticKind: 4 → 14 个变体（每个对应一条 R-N 规律）        │
│   - 每个 LLVM Value 可有多条 Resolution                              │
│   - 提供 hasKind(value, kind) 统一查询接口                           │
└────────────────────────────────────────────────────────────────────┬─┘
                                                                     │
                                                                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Layer 1 — IR Pattern Detectors（直接对应 §1.B 的 R-0~R-6 规律）      │
│  src/semantics/patterns/                                             │
│   - param_attr.zig          (R-0: readonly / noalias 参数属性)       │
│   - heap_provenance.zig     (R-1: SROA heap field load via DI)       │
│   - interior_mut.zig        (R-2: UnsafeCell DI chain)               │
│   - drop_glue.zig           (R-3: drop_in_place + tail dealloc)      │
│   - posix_syscalls.zig      (R-4: POSIX file/net/mem/proc 分类)      │
│   - lang_detector.zig       (R-5: language gating)                   │
│   - into_raw_transfer.zig   (R-6: Box/CString::into_raw 所有权转移)  │
│   - library_alloc_pairs.zig (R-7: mimalloc/zlib/openssl/sqlite 等)   │
│  每个 detector 读 LLVM IR + DI metadata → 写 SRT                     │
└──────────────────────────────────────────────────────────────────────┘

> Nomicon 仅作为**理解参考**（说明"为什么这个模式是 sound"），**不作为目录结构**。
> 之前按 ch04/05/06/08/09/10 分目录过度工程化，现按 IR pattern 直接命名。
```

---

## 4. Layer 2 — SRT 扩展设计

### 4.1 SemanticKind 升级（4 → 14，每条对齐一条 R 规律）

> 设计原则：**每个新变体都必须对应 §1.B 的一条 R-N 规律**，避免过度抽象。
> 子区分（drop_tail vs drop_glue、UnsafeCell 子类、syscall 子类）通过 `Resolution.evidence` 表达，不开新 enum 变体。

```zig
// src/semantics/semantic_tree.zig (升级 SemanticKind)

pub const SemanticKind = enum(u8) {
    // ── 现有（保留）
    unknown,
    allocation,             // __rust_alloc / malloc / Box::new / new[] / runtime.alloc
    release,                // 用户代码显式 free / __rust_dealloc / delete / Marshal.FreeHGlobal
    provenance,             // 通用 provenance fallback

    // ── R-0: LLVM 参数属性（覆盖 write_to_immutable 1877 FP 主因）
    readonly_param,         // function param 有 LLVM `readonly` 属性 → Rust &T / C const ptr
    mutable_param,          // function param 无 `readonly` → Rust &mut T / C 普通 ptr
                            //   写入 readonly_param 衍生的 ptr 才是真违反；写入 mutable_param
                            //   衍生的 ptr 是合法 &mut T 写入

    // ── R-2: Interior mutability（覆盖 write_to_immutable 残留 ~100 FP）
    interior_mutability,    // 类型链含 UnsafeCell<T> → Cell/RefCell/Mutex/RwLock/Atomic*/
                            //   OnceLock/LazyLock 全覆盖；call_once_force 上下文也标这个

    // ── R-1: Heap provenance 细化（覆盖 borrow_escape 71 FP）
    heap_provenance,        // 值来自 __rust_alloc / malloc / new / Box::new；或 alloca DI 类型
                            //   为 Box/Arc/Rc/Vec/String/*mut T（SROA 后的 field load）
    global_provenance,      // static / const / &'static / 编译时已知源（self_exe_path 等）

    // ── R-6: 所有权转移（覆盖 cross_language_free 4 FP + 真实 Rust↔C 模式）
    into_raw_transfer,      // Box/CString/Vec::into_raw 返回值 → 所有权已转给调用者，
                            //   后续被 C free() 是合法的 ownership transfer

    // ── R-4: POSIX syscall 语义（cross_language_free / command_injection 辅助）
    file_operation,         // unlink / close / open / rename / symlink / fcntl
    network_operation,      // socket / bind / connect / listen / send / recv
    process_operation,      // fork / vfork / execve / waitpid / kill

    // ── R-3: RAII drop（覆盖 use_after_free 3 FP）
    raii_drop_release,      // 编译器插入的 scope-end dealloc / drop_in_place 函数内的 dealloc
                            //   与 .release 的区别：.release = 用户代码显式释放
                            //   bun_base64::wyhash_url_safe 中的 Vec<u8> Drop 走这条
                            //   含 Arc/Rc refcount 条件释放 (atomicrmw sub + icmp eq + br + drop_in_place)

    // ── R-7: 库级分配器 release（覆盖 mimalloc/zlib/openssl/sqlite 等非 POSIX 释放调用）
    library_release,        // mi_free / inflateEnd / EVP_CIPHER_CTX_free / sqlite3_finalize 等
                            //   cross_language_free 检测命中此 kind → 不报（是合法的库内释放）
};
```

**为什么 13 个变体**：

| 区分维度 | 是否进 enum | 理由 |
|---|---|---|
| heap vs stack provenance | ✅ 进 (`heap_provenance`) | F1 大头 |
| heap_box / heap_arc / heap_vec 子分类 | ❌ 不进 | 下游 Pass 不关心来源是 Box 还是 Vec，统一按 heap 处理。子类型放 `Resolution.evidence` 字段 |
| RAII drop vs 手动 release | ✅ 进 (`raii_drop_release`) | F4 必需，否则 UAF FP 不可消 |
| drop_tail vs drop_glue 子分类 | ❌ 不进 | 同上：下游只需"是不是 RAII"，子证据放 evidence |
| UnsafeCell / Atomic / OnceLock 子分类 | ❌ 不进 | 全归 `interior_mutability`，子证据放 evidence |
| 库级 alloc/release (mi_free 等) | ✅ 进 (`library_release`) | R-7 必需，否则 mimalloc/zlib/openssl/sqlite 的释放被误报为 cross_lang_free |
| transmute / repr-C / Send-Sync | ❌ 不进 | bun_report 无对应 FP，YAGNI；未来需要时再加 |

**完全采纳用户提议**，加 `raii_drop_release`（R-3）+ `library_release`（R-7），共 14 变体。

### 4.2 Resolution 同步精简（去掉 dimension 枚举）

14 个变体彼此正交，一个 Value 可以同时有多条 Resolution（如同时是 `allocation` + `heap_provenance` + `readonly_param` 的传递结果）。直接用 `hasKind(value, kind)` 查询即可，**不需要 dimension 枚举**：

```zig
// semantic_tree.zig:30 微调
pub const Resolution = struct {
    kind: SemanticKind,
    confidence: f32,
    nomicon_chapter: ?[]const u8,  // ← 新增："Ch5 Interior Mutability" 等，便于报告追溯
    evidence: []const u8,           // 替换 data，写入具体证据如 "alloca DI=Box<ClientSession>"
    pattern_id: ?usize,
};
```

### 4.3 统一查询接口（极简）

```zig
// src/semantics/semantic_tree.zig (新增 API)

/// 查询某 Value 是否带特定 kind 的 Resolution，命中返回最高 confidence 那条。
pub fn hasKind(self: *const SemanticTree, value_ref: ValueRef, kind: SemanticKind) ?Resolution;

/// 查询某 Value 的所有 Resolution（多维度判定时用）。
pub fn allResolutions(self: *const SemanticTree, value_ref: ValueRef) []const Resolution;
```

**Pass 接线模板**：

```zig
// 例：detectStackEscapeToFFI 在 emit 前
if (ctx.srt.hasKind(@intFromPtr(arg), .heap_provenance)) |r| {
    diag.info("FP-SUPPRESS [heap_provenance / {s}]: {s}", .{ r.nomicon_chapter.?, r.evidence });
    continue;
}
if (ctx.srt.hasKind(@intFromPtr(arg), .global_provenance) != null) continue;
// 否则按原逻辑判定栈逃逸

// 例：detectUseAfterFree 在 emit 前
if (ctx.srt.hasKind(@intFromPtr(free_call), .raii_drop_release) != null) return;

// 例：cross_language_free 在 emit 前
if (ctx.srt.hasKind(@intFromPtr(callee), .file_operation) != null) return;
if (ctx.srt.hasKind(@intFromPtr(callee), .network_operation) != null) return;
```

---

## 5. Layer 1 — IR Pattern Detector 目录

### 5.1 目录结构

```
src/semantics/patterns/
├── param_attr.zig          — R-0: LLVM readonly / noalias 属性 → mutable_param/readonly_param
├── heap_provenance.zig     — R-1: SROA 后 heap field load 识别 (alloca DI = Box/Arc/Rc/Vec/String/*mut)
├── interior_mut.zig        — R-2: DI type chain 含 UnsafeCell → interior_mutability
├── drop_glue.zig           — R-3: drop_in_place 函数 + ret 前 tail dealloc → raii_drop_release
├── posix_syscalls.zig      — R-4: POSIX 标准 syscall 名 → file/net/mem/proc 分类
├── lang_detector.zig       — R-5: 模块语言识别 (Rust/Go/C/C++/C#/Python/Java)
├── into_raw_transfer.zig   — R-6: Box/CString/Vec::into_raw 返回值 → into_raw_transfer
└── library_alloc_pairs.zig — R-7: mimalloc/zlib/openssl/sqlite/Go cgo/JNI/Python/Zig 分配器配对
```

> 与 §1.B 的 R-N 规律**一一对应**，detector 工程师改代码时查 §1.B 就能找到证据来源。

每个文件是一个 detector，签名都是：

```zig
pub fn detect(
    module: c.LLVMModuleRef,
    srt: *SemanticTree,
    diag: *DiagnosticWriter,
) !void;
```

由 `SemanticResolverPass` 统一调度（每个 module 跑一次，结果填进 SRT）。

### 5.2 R-3 → `drop_glue.zig`（参考 Nomicon Ch6 OBRM）

**Nomicon §6.1 (Constructors & Destructors)** 规定 Drop trait 的语义。LLVM IR 中表现为：

| Rust 源 | LLVM IR 信号 | SRT kind |
|---|---|---|
| `fn main() { let v = Box::new(1); }` | `__rust_alloc` 调用 + alloca DI=`Box<i32>` | `heap_alloc_box` |
| scope 末尾隐式 drop | `__rust_dealloc` 在 ret 前 tail position | `heap_dealloc_drop_tail` |
| `impl Drop for Foo` | enclosing func name 含 `drop_in_place` / `Foo::drop` | `heap_dealloc_drop_glue` |
| 手动 `mem::drop(v)` | 显式 call 但 callee 是 `drop_in_place<T>` | `heap_dealloc_drop_glue` |
| `Arc::drop` / `Rc::drop` | `atomicrmw sub %refcount, 1` → `icmp eq` → `br` → `call @drop_in_place` | `raii_drop_release` (模式 C) |

```zig
// src/semantics/patterns/drop_glue.zig 骨架

pub fn detect(module: c.LLVMModuleRef, srt: *SemanticTree, diag: *DiagnosticWriter) !void {
    var func = c.LLVMGetFirstFunction(module);
    while (@intFromPtr(func) != 0) : (func = c.LLVMGetNextFunction(func)) {
        if (c.LLVMIsDeclaration(func) != 0) continue;
        const func_name = std.mem.sliceTo(c.LLVMGetValueName(func), 0);

        const is_drop_context = isDropContextFunction(func_name);

        var bb = c.LLVMGetFirstBasicBlock(func);
        while (@intFromPtr(bb) != 0) : (bb = c.LLVMGetNextBasicBlock(bb)) {
            var inst = c.LLVMGetFirstInstruction(bb);
            while (@intFromPtr(inst) != 0) : (inst = c.LLVMGetNextInstruction(inst)) {
                if (c.LLVMGetInstructionOpcode(inst) != c.LLVMCall) continue;
                const callee_name = getCalleeName(inst) orelse continue;

                // §6 OBRM: __rust_dealloc 出现的两种合法场合
                if (isRustDeallocSymbol(callee_name)) {
                    const kind: SemanticKind = if (is_drop_context)
                        .heap_dealloc_drop_glue
                    else if (isTailDealloc(inst))
                        .heap_dealloc_drop_tail
                    else
                        .heap_dealloc_rust;
                    try srt.recordResolution(.{
                        .value_ref = @intFromPtr(inst),
                        .dimension = .deallocation,
                        .kind = kind,
                        .confidence = 0.95,
                        .nomicon_chapter = "Ch6 OBRM",
                        .evidence = "Rust dealloc symbol; position-classified",
                    });
                }
            }
        }
    }
}
```

> Drop tail position 判定的细节（`isTailDealloc`）即之前方案的 SP-4，搬入这里。

### 5.3 R-1 → `heap_provenance.zig`（高精度堆栈区分 — 三层信号融合）

> **设计目标**：任何 LLVM Value 的堆/栈/全局来源必须能被确定，不依赖白名单，不依赖项目命名。
> **精度策略**：三层信号互相补充，任一层命中即可判定；DI 丢失时 fallback 到 allocation call；propagation 覆盖 use-def 链。

#### 5.3.1 Provenance 三分法

每个 ptr 类型的 LLVM Value 的语义来源只能是三者之一：

| Provenance | 含义 | 典型来源 | store 到它的衍生 ptr |
|---|---|---|---|
| **heap** | 堆分配 | `malloc` / `__rust_alloc` / `Box::new` / `new` / `runtime.alloc` / alloca DI=Box/Arc/Vec | 合法（所有权者可写） |
| **stack** | 栈分配 | `alloca` + `llvm.lifetime.start`，DI 为原始类型（i32/struct/array） | 可能是真栈逃逸（需检查） |
| **global** | 全局/常量 | `@global = global` / `@constant = constant` / `&'static` | 合法（编译时已知） |

**判定优先级**（短路，命中即停）：

```
1. allocation call 精确匹配     → heap (confidence 0.98)
2. alloca DI type 前缀匹配      → heap (confidence 0.90)
3. use-def 传播：来自已知 heap   → heap (confidence 继承 -0.05)
4. alloca + lifetime.start/end  → stack (confidence 0.85)
5. @global / @constant          → global (confidence 0.95)
6. 以上都不命中                 → unknown (不判定，不报)
```

#### 5.3.2 信号层 1：Allocation Call 精确匹配（最高置信度）

> 不看函数名像不像分配器，看 LLVM IR 的 **call 返回 ptr + 特定 callee name** 组合。

```zig
const ALLOC_CALLS = [_]struct { suffix: []const u8, prov: Provenance, lang: Lang }{
    // Rust 全局分配器（rustc ABI 固定符号）
    .{ .suffix = "__rust_alloc",          .prov = .heap, .lang = .rust },
    .{ .suffix = "__rust_alloc_zeroed",   .prov = .heap, .lang = .rust },
    .{ .suffix = "__rust_realloc",        .prov = .heap, .lang = .rust },
    // C 标准库
    .{ .suffix = "malloc",               .prov = .heap, .lang = .c },
    .{ .suffix = "calloc",               .prov = .heap, .lang = .c },
    .{ .suffix = "realloc",              .prov = .heap, .lang = .c },
    .{ .suffix = "aligned_alloc",        .prov = .heap, .lang = .c },
    // C++ new（Itanium mangling）
    .{ .suffix = "_Znwm",                .prov = .heap, .lang = .cpp },
    .{ .suffix = "_Znam",                .prov = .heap, .lang = .cpp },
    .{ .suffix = "_Znwj",                .prov = .heap, .lang = .cpp },
    .{ .suffix = "_Znaj",                .prov = .heap, .lang = .cpp },
    // Go runtime
    .{ .suffix = "runtime.alloc",        .prov = .heap, .lang = .go },
    .{ .suffix = "_cgo_allocate",        .prov = .heap, .lang = .go },
    // mimalloc / jemalloc
    .{ .suffix = "mi_malloc",            .prov = .heap, .lang = .any },
    .{ .suffix = "mi_realloc",           .prov = .heap, .lang = .any },
    .{ .suffix = "mi_zalloc",            .prov = .heap, .lang = .any },
    .{ .suffix = "je_malloc",            .prov = .heap, .lang = .any },
    .{ .suffix = "je_calloc",            .prov = .heap, .lang = .any },
};

pub fn classifyAllocationCall(call_inst: c.LLVMValueRef) ?Provenance {
    const callee = getCalleeName(call_inst) orelse return null;
    const ret_ty = c.LLVMTypeOf(call_inst);
    if (c.LLVMGetTypeKind(ret_ty) != c.LLVMPointerTypeKind) return null;
    for (ALLOC_CALLS) |entry| {
        if (std.mem.endsWith(u8, callee, entry.suffix)) return entry.prov;
    }
    return null;
}
```

> **endsWith 而非 contains**：`mi_malloc` 不误匹配 `mi_malloc_stats`（后者不返回 ptr）。
> 返回非 ptr 的 call 不是分配，直接跳过。

#### 5.3.3 信号层 2：alloca DI Type 前缀匹配（DI 可用时）

> DI metadata 存在时，alloca 的 DILocalVariable -> DIType.name 直接暴露堆包装类型。

```zig
const HEAP_DI_PREFIXES = [_][]const u8{
    "Box<", "alloc::boxed::Box<",
    "Arc<", "alloc::sync::Arc<",
    "Rc<",  "alloc::rc::Rc<",
    "Vec<", "alloc::vec::Vec<",
    "String", "alloc::string::String",
    "*mut ", "*const ",
    "RawVec<", "Unique<", "NonNull<",
    "HashMap<", "HashSet<",
    "BTreeMap<", "BTreeSet<",
    "LinkedList<", "VecDeque<",
};

fn classifyAllocaDI(alloca: c.LLVMValueRef) ?Provenance {
    const di_name = findAllocaDITypeName(alloca) orelse return null;
    for (HEAP_DI_PREFIXES) |prefix| {
        if (std.mem.startsWith(u8, di_name, prefix)) return .heap;
    }
    return null;
}
```

> `HashMap<` / `BTreeMap<` 也标 heap：内部有堆分配结构，与 `Vec<` 同理。
> `RawVec<` / `Unique<` / `NonNull<` 是 Box/Vec 的内部实现类型，SROA 后可能直接暴露。

#### 5.3.4 信号层 3：Use-Def 传播（DI 丢失时的 fallback）

> `-O2` 下 DI 经常被 strip，但 use-def 链保留。沿 def 链回溯，找到已知 provenance 的根即继承。

```zig
const MAX_DEPTH: u32 = 16;

fn traceProvenance(srt: *const SemanticTree, value: c.LLVMValueRef, depth: u32) Provenance {
    if (depth > MAX_DEPTH) return .unknown;
    if (srt.getProvenance(@intFromPtr(value))) |p| return p;

    const opcode = c.LLVMGetInstructionOpcode(value);
    return switch (opcode) {
        c.LLVMAlloca => classifyAllocaDI(value) orelse .stack,
        c.LLVMCall   => classifyAllocationCall(value) orelse .unknown,

        // 传播：不改变 provenance
        c.LLVMGetElementPtr  => traceProvenance(srt, c.LLVMGetOperand(value, 0), depth + 1),
        c.LLVMBitCast        => traceProvenance(srt, c.LLVMGetOperand(value, 0), depth + 1),
        c.LLVMAddrSpaceCast  => traceProvenance(srt, c.LLVMGetOperand(value, 0), depth + 1),
        c.LLVMIntToPtr       => .unknown,

        // PHI / Select：合并多个来源
        c.LLVMPhi => {
            var prov: Provenance = .unknown;
            var i: c_uint = 0;
            while (i < c.LLVMCountIncoming(value)) : (i += 1) {
                prov = mergeProvenance(prov, traceProvenance(srt, c.LLVMGetIncomingValue(value, i), depth + 1));
            }
            return prov;
        },
        c.LLVMSelect => {
            const t = traceProvenance(srt, c.LLVMGetOperand(value, 1), depth + 1);
            const f = traceProvenance(srt, c.LLVMGetOperand(value, 2), depth + 1);
            return mergeProvenance(t, f);
        },

        // Load：从 heap container 取出的 ptr 仍是 heap
        c.LLVMLoad => {
            const src_prov = traceProvenance(srt, c.LLVMGetOperand(value, 0), depth + 1);
            return if (src_prov == .heap) .heap else src_prov;
        },

        c.LLVMGlobalValue => .global,
        else => .unknown,
    };
}

fn mergeProvenance(a: Provenance, b: Provenance) Provenance {
    if (a == b) return a;
    if (a == .unknown) return b;
    if (b == .unknown) return a;
    return .unknown; // heap + stack 混合 -> unknown（保守）
}
```

#### 5.3.5 完整检测流程（两 Pass）

```zig
pub fn detect(module: c.LLVMModuleRef, srt: *SemanticTree, diag: *DiagnosticWriter) !void {
    // Pass 1: 扫描所有 call + alloca → 写 SRT
    var func = c.LLVMGetFirstFunction(module);
    while (@intFromPtr(func) != 0) : (func = c.LLVMGetNextFunction(func)) {
        if (c.LLVMIsDeclaration(func) != 0) continue;
        var bb = c.LLVMGetFirstBasicBlock(func);
        while (@intFromPtr(bb) != 0) : (bb = c.LLVMGetNextBasicBlock(bb)) {
            var inst = c.LLVMGetFirstInstruction(bb);
            while (@intFromPtr(inst) != 0) : (inst = c.LLVMGetNextInstruction(inst)) {
                if (c.LLVMGetInstructionOpcode(inst) == c.LLVMCall) {
                    if (classifyAllocationCall(inst)) |prov| {
                        try srt.setProvenance(@intFromPtr(inst), prov);
                    }
                }
                if (c.LLVMGetInstructionOpcode(inst) == c.LLVMAlloca) {
                    if (classifyAllocaDI(inst)) |prov| {
                        try srt.setProvenance(@intFromPtr(inst), prov);
                    }
                }
            }
        }
    }
    // Pass 2: downstream Pass 按需调用 traceProvenance（惰性传播，cache in SRT）
}
```

#### 5.3.6 精度保证

| 场景 | 旧方案 | 改进后 | 信号来源 |
|---|---|---|---|
| `Box<T>` 在 alloca 中 | DI prefix | DI prefix | 层 2 |
| `malloc` 返回值直接传 FFI | 漏报 | call 匹配 | 层 1 |
| `__rust_alloc` 返回值 | 漏报 | call 匹配 | 层 1 |
| `Box<T>` 经 GEP 取内部 ptr | 丢失 | use-def 传播 | 层 3 |
| `-O2` 下 DI 被 strip | 无法判定 | fallback 到 call + propagation | 层 1+3 |
| C++ `new` 返回值 | 未覆盖 | Itanium `_Znw*` | 层 1 |
| Go `runtime.alloc` | 未覆盖 | call 匹配 | 层 1 |
| mimalloc `mi_malloc` | 未覆盖 | call 匹配 | 层 1 |
| 真栈变量 `alloca i32` | 不误判 | DI 无 heap prefix -> stack | 层 2 |
| Global `@foo = global` | 未覆盖 | `LLVMGlobalValue` | 层 3 |

> **覆盖率预期**：层 1 覆盖 ~80% 堆指针（所有 allocation call）；层 2 补充 ~15%（DI 可用的 alloca wrapper）；层 3 覆盖传播路径。三层叠加后未知率 <5%。


### 5.4 R-2 → `interior_mut.zig`（参考 Nomicon Ch5 Interior Mutability）

**Nomicon §5** 讲 `UnsafeCell<T>` 是 Rust **唯一**允许在 `&T` 上 mutate 的语言原语。所有 interior mutability 类型 (`Cell`, `RefCell`, `Mutex`, `RwLock`, `Atomic*`, `OnceLock`, `LazyLock`) 内部都包它 — 这是 Rust 编译器强制约束，第三方库（`parking_lot::Mutex`、`crossbeam::AtomicCell`）也必须遵守。

**判定**: 一个 store 的 dest GEP base 的 DI type chain 含 `UnsafeCell<` → SRT `.interior_mut_unsafe_cell`。

```zig
// 关键算法：DI type chain 递归查找
pub fn isInteriorMutableThroughChain(di_type: c.LLVMValueRef) bool {
    var cur = di_type;
    var depth: u32 = 0;
    while (depth < 8 and @intFromPtr(cur) != 0) : (depth += 1) {
        if (getDITypeName(cur)) |n| {
            if (std.mem.startsWith(u8, n, "UnsafeCell<") or
                std.mem.startsWith(u8, n, "core::cell::UnsafeCell<")) return true;
        }
        cur = getDIBaseType(cur);
    }
    return false;
}
```

> 这是只需识别**一个字符串 `UnsafeCell`** 的语言级判定。新增 std/parking_lot/crossbeam 等类型自动覆盖。

### 5.5 R-4 → `posix_syscalls.zig`（POSIX 语义事实）

POSIX 标准定义 syscall 行为。把 `unlink / close / open / rename / socket / execve / fork / mmap` 等按动作分类，**只有 `mem_free`/`mem_alloc` 类才参与 free/UAF 语义**，其余分类 (file/net/proc) 看到了就 skip。详细 ~60 项表见 §1.B R-4。

> R-7 (`library_alloc_pairs.zig`) 覆盖 POSIX 之外的库级分配器（mimalloc/zlib/openssl/sqlite 等），两表互补。

### 5.6 R-0 → `param_attr.zig`（LLVM 参数属性，新增的核心 detector）

> 这是 LL_ANALYSIS_REPORT.md 揭示的最强信号 — 直接对应 1877 个 write_to_immutable FP 的根因。

```zig
// src/semantics/patterns/param_attr.zig 骨架

pub fn detect(module: c.LLVMModuleRef, srt: *SemanticTree, _: *DiagnosticWriter) !void {
    var func = c.LLVMGetFirstFunction(module);
    while (@intFromPtr(func) != 0) : (func = c.LLVMGetNextFunction(func)) {
        const num_params = c.LLVMCountParams(func);
        var i: c_uint = 0;
        while (i < num_params) : (i += 1) {
            const param = c.LLVMGetParam(func, i);
            const has_readonly = paramHasAttr(func, i + 1, "readonly");
            const has_noalias  = paramHasAttr(func, i + 1, "noalias");
            const kind: SemanticKind = if (has_readonly) .readonly_param else .mutable_param;
            try srt.recordResolution(.{
                .value_ref = @intFromPtr(param),
                .kind = kind,
                .confidence = 0.95,
                .evidence = if (has_noalias) "noalias+readonly=&T (excl)" else if (has_readonly) "readonly=&T" else "mut=&mut T",
            });
        }
    }
}

fn paramHasAttr(func: c.LLVMValueRef, idx: c_uint, name: []const u8) bool {
    const kind = c.LLVMGetEnumAttributeKindForName(name.ptr, name.len);
    return c.LLVMGetEnumAttributeAtIndex(func, idx, kind) != null;
}
```

**关键传播 — store dest 的 backward tracing**：

`detectWriteToImmutable` 看到 `store %val, %dest` 时，需要判断 `%dest` 是否来自 `readonly` param。算法：

```zig
/// 从 store 的 dest 指针回溯，判定是否写入了 readonly 区域。
/// 返回：.readonly_violation / .mutable_ok / .interior_mut_ok / .unknown
fn classifyStoreDest(srt: *const SemanticTree, dest: c.LLVMValueRef, depth: u32) StoreDestClass {
    if (depth > MAX_DEPTH) return .unknown;

    // 1. dest 本身就是 function param
    if (isFuncParam(dest)) {
        if (srt.hasKind(@intFromPtr(dest), .readonly_param)) return .readonly_violation;
        if (srt.hasKind(@intFromPtr(dest), .mutable_param)) return .mutable_ok;
    }

    // 2. dest 是 GEP(base, idx...) → 递归查 base
    if (c.LLVMGetInstructionOpcode(dest) == c.LLVMGetElementPtr) {
        return classifyStoreDest(srt, c.LLVMGetOperand(dest, 0), depth + 1);
    }

    // 3. dest 是 bitcast / addrspacecast → 递归查 operand
    if (c.LLVMGetInstructionOpcode(dest) == c.LLVMBitCast or
        c.LLVMGetInstructionOpcode(dest) == c.LLVMAddrSpaceCast) {
        return classifyStoreDest(srt, c.LLVMGetOperand(dest, 0), depth + 1);
    }

    // 4. dest 是 alloca → 查 alloca 的来源
    if (c.LLVMGetInstructionOpcode(dest) == c.LLVMAlloca) {
        // 4a. DI type 含 UnsafeCell → interior mutability，合法写入
        if (isInteriorMutableAlloca(dest)) return .interior_mut_ok;
        // 4b. 查 alloca 的初值 store：alloca 创建后第一条 store 的 src 是否来自 param
        if (findAllocaInitialStore(dest)) |init_store| {
            const init_src = c.LLVMGetOperand(init_store, 0); // store 的 src
            return classifyStoreDest(srt, init_src, depth + 1);
        }
        // 4c. alloca 无初值（局部变量）→ 非 readonly 区域
        return .mutable_ok;
    }

    // 5. dest 来自已知 heap allocation → 堆所有权者可写
    if (srt.getProvenance(@intFromPtr(dest)) == .heap) return .mutable_ok;

    // 6. dest 来自 global → 查 global 的 const 修饰
    if (c.LLVMIsAGlobalValue(dest) != null) {
        if (c.LLVMIsGlobalConstant(dest) != 0) return .readonly_violation;
        return .mutable_ok;
    }

    return .unknown;
}
```

**为什么需要 backward tracing 而非仅查 immediate operand**：

```
define void @foo(ptr readonly %src) {
  %alloca = alloca ptr
  store ptr %src, ptr %alloca        ; alloca 保存了 readonly param 的值
  %loaded = load ptr, ptr %alloca    ; 从 alloca 取出 → 仍是 readonly 来源
  %gep = getelementptr i8, ptr %loaded, i64 8
  store i8 42, ptr %gep              ; ← 写入了 readonly param 的衍生 ptr！
}
```

仅查 `store` 的 immediate dest (`%gep`) 无法判定，必须沿 `%gep -> %loaded -> %alloca -> 初值 store -> %src (readonly param)` 回溯。

### 5.7 R-6 → `into_raw_transfer.zig`

```zig
// 模式：%raw = call ptr @<某 Rust mangled name>_into_raw(...)
//   _RNvXs* 形式的 mangled name 末尾段含 "8into_raw" 即识别。
pub fn detect(...) !void {
    for (calls in module) {
        const callee_name = getCalleeName(call) orelse continue;
        if (std.mem.indexOf(u8, callee_name, "8into_raw") != null or
            std.mem.indexOf(u8, callee_name, "into_raw") != null and isRustMangled(callee_name))
        {
            try srt.recordResolution(.{
                .value_ref = @intFromPtr(call),
                .kind = .into_raw_transfer,
                .confidence = 0.95,
                .evidence = "Rust Box/CString::into_raw — ownership transferred",
            });
        }
    }
}
```

> 唯一识别字符串：`into_raw` 子串 + Rust mangled name 形态。任何 Rust 项目通用。

### 5.8 R-7 → `library_alloc_pairs.zig`（库级分配器配对，来自 `ir.md` §9）

表驱动 detector，覆盖 POSIX syscall 之外的第三方库分配器。每条 entry 是 `(function_name, language, effect)` 三元组。

```zig
// src/semantics/patterns/library_alloc_pairs.zig 骨架

const LibraryAllocEntry = struct {
    name: []const u8,
    language: enum { c, rust, go, python, java, zig, any },
    effect: enum { acquire, release, borrow, conditional_release },
};

const TABLE = [_]LibraryAllocEntry{
    // mimalloc (bun 底层分配器)
    .{ .name = "mi_malloc",          .language = .c,   .effect = .acquire },
    .{ .name = "mi_free",            .language = .c,   .effect = .release },
    .{ .name = "mi_realloc",         .language = .c,   .effect = .acquire },
    .{ .name = "mi_heap_destroy",    .language = .c,   .effect = .conditional_release },
    // zlib
    .{ .name = "inflateInit_",       .language = .c,   .effect = .acquire },
    .{ .name = "inflateEnd",         .language = .c,   .effect = .release },
    .{ .name = "deflateInit_",       .language = .c,   .effect = .acquire },
    .{ .name = "deflateEnd",         .language = .c,   .effect = .release },
    // openssl
    .{ .name = "EVP_CIPHER_CTX_new", .language = .c,   .effect = .acquire },
    .{ .name = "EVP_CIPHER_CTX_free",.language = .c,   .effect = .release },
    .{ .name = "BIO_new",            .language = .c,   .effect = .acquire },
    .{ .name = "BIO_free",           .language = .c,   .effect = .release },
    // sqlite
    .{ .name = "sqlite3_open",       .language = .c,   .effect = .acquire },
    .{ .name = "sqlite3_close",      .language = .c,   .effect = .release },
    .{ .name = "sqlite3_prepare_v2", .language = .c,   .effect = .acquire },
    .{ .name = "sqlite3_finalize",   .language = .c,   .effect = .release },
    .{ .name = "sqlite3_free",       .language = .c,   .effect = .release },
    // Go cgo
    .{ .name = "_cgo_allocate",      .language = .go,  .effect = .acquire },
    .{ .name = "_cgo_free",          .language = .go,  .effect = .release },
    // Python CFFI
    .{ .name = "Py_DECREF",          .language = .python, .effect = .conditional_release },
    .{ .name = "Py_XDECREF",        .language = .python, .effect = .conditional_release },
    .{ .name = "PyList_GetItem",     .language = .python, .effect = .borrow },
    .{ .name = "PyBytes_AsString",   .language = .python, .effect = .borrow },
    // JNI
    .{ .name = "NewGlobalRef",       .language = .java, .effect = .acquire },
    .{ .name = "DeleteGlobalRef",    .language = .java, .effect = .release },
    .{ .name = "GetStringUTFChars",  .language = .java, .effect = .borrow },
    .{ .name = "ReleaseStringUTFChars", .language = .java, .effect = .release },
    // Zig allocator
    .{ .name = "zig_allocator_allocImpl", .language = .zig, .effect = .acquire },
    .{ .name = "zig_allocator_freeImpl",  .language = .zig, .effect = .release },
};

pub fn detect(module: c.LLVMModuleRef, srt: *SemanticTree, _: *DiagnosticWriter) !void {
    // 遍历所有 call 指令，callee name 精确匹配 TABLE
    // release / conditional_release → 写 SRT .library_release
    // acquire → 写 SRT .library_acquire (供 leak detector 使用)
    // borrow → 写 SRT .library_borrow (供 borrow_escape 使用)
}
```

> 与 R-4 posix_syscalls 的区别：R-4 覆盖 POSIX 标准 syscall（unlink/close/socket 等），R-7 覆盖第三方库 API。
> cross_language_free 检测**同时查两张表**，任一命中即抑制。

---

## 6. Layer 3 — Pass 接线 + Issue Gate

### 6.1 Pass 必须查 SRT（强制）

改造 4 个关键 Pass — 用精简 11 变体 `hasKind` 接口：

```zig
// 1. detectStackEscapeToFFI (rust_ffi_rules_basic.zig:196)
//    使用 provenance 三分法（§5.3 traceProvenance）判定 arg 的来源
fn detectStackEscapeToFFI(...) !void {
    const prov = traceProvenance(ctx.srt, arg, 0);
    switch (prov) {
        .heap => continue,    // 堆指针传 FFI → 合法
        .global => continue,  // 全局/常量传 FFI → 合法
        .stack => {},         // 栈变量传 FFI → 可能是真栈逃逸，继续判定
        .unknown => continue, // 无法确定 → 不报
    }
    // 原逻辑：检查 arg 是否 escaped by reference / address-taken
}

// 2. detectWriteToImmutable (rust_ffi_rules_advanced.zig:37)
//    主战场：覆盖 1877/1966 FP（96%）
//    使用 backward tracing（§5.6 classifyStoreDest）而非简单 getStoreDestBase
fn detectWriteToImmutable(...) !void {
    const dest = c.LLVMGetOperand(store_inst, 1); // store 的 dest ptr

    // backward tracing：沿 GEP/bitcast/alloca 初值回溯到最终来源
    const dest_class = classifyStoreDest(ctx.srt, dest, 0);
    switch (dest_class) {
        .mutable_ok => return,          // dest 来自 &mut T / 非 const ptr → 合法写入
        .interior_mut_ok => return,     // dest 含 UnsafeCell → 合法内部可变性
        .readonly_violation => {},      // dest 来自 &T → 继续判定，可能是真违反
        .unknown => return,             // 无法确定 → 不报（宁可漏报不误报）
    }

    // R-2 补充：enclosing function 是 once-init 上下文（call_once_force 等）
    if (ctx.srt.hasKind(@intFromPtr(func), .interior_mutability) != null) return;

    // 到这里：dest 确认来自 readonly param → 报告 write_to_immutable
    emitIssue(...);
}

// 3. detectUseAfterFree (rust_ffi_rules_advanced.zig:detectUseAfterFree)
fn detectUseAfterFree(...) !void {
    // R-3: 编译器插入的 RAII drop → 不报
    if (ctx.srt.hasKind(@intFromPtr(free_call), .raii_drop_release) != null) return;
    // R-4: 看起来像 free 的 callee 其实是 file/net op → 不报
    if (ctx.srt.hasKind(@intFromPtr(callee), .file_operation) != null) return;
    if (ctx.srt.hasKind(@intFromPtr(callee), .network_operation) != null) return;
}

// 5. detectCrossLanguageFree (rust_ffi_rules_basic.zig:detectCrossLangMismatch)
fn detectCrossLanguageFree(...) !void {
    const freed_ptr_ref = @intFromPtr(freed_ptr);
    // R-6: 指针来自 into_raw → 所有权已转移，C free() 合法
    if (ctx.srt.hasKind(freed_ptr_ref, .into_raw_transfer) != null) return;
    // R-4: callee 是 file/net/proc op，根本不是内存 free
    if (ctx.srt.hasKind(@intFromPtr(callee), .file_operation) != null) return;
    if (ctx.srt.hasKind(@intFromPtr(callee), .network_operation) != null) return;
    if (ctx.srt.hasKind(@intFromPtr(callee), .process_operation) != null) return;
    // R-7: callee 是库级分配器的 release（mi_free / inflateEnd / sqlite3_finalize 等）
    if (ctx.srt.hasKind(@intFromPtr(callee), .library_release) != null) return;
}

// 4. checkCommandInjectionVulnerability (ffi_body_check.zig:397)
fn checkCommandInjectionVulnerability(...) !?Vulnerability {
    // execve/system 等是 process_operation；只在参数有 taint 源时才报
    for (args) |arg| {
        const arg_ref = @intFromPtr(arg);
        // 编译期已知源（self_exe_path / 常量字符串）→ 永远不报
        if (ctx.srt.hasKind(arg_ref, .global_provenance) != null) continue;
        // 检查 taint 引擎是否在此 Value 上传播了 source 标记
        if (ctx.taint_state.isTainted(arg)) {
            return Vulnerability{ ... };  // 有 taint flow，才报
        }
    }
    return null;
}
```

### 6.2 Issue Gate（统一收口）

新建 `src/pass/filter/issue_gate.zig` —— 所有 Issue 进 aggregator 前必经此关：

```zig
pub fn checkIssue(srt: *const SemanticTree, issue: *const Issue) GateVerdict {
    const v = @intFromPtr(issue.value_ref);
    switch (issue.kind) {
        .borrow_escape => {
            if (srt.hasKind(v, .heap_provenance) != null) return .suppress_heap_origin;
            if (srt.hasKind(v, .global_provenance) != null) return .suppress_global_origin;
        },
        .write_to_immutable => {
            // R-0 主信号
            if (srt.hasKind(v, .mutable_param) != null) return .suppress_mutable_param;
            // R-2 补充
            if (srt.hasKind(v, .interior_mutability) != null) return .suppress_interior_mut;
        },
        .use_after_free => {
            if (srt.hasKind(v, .raii_drop_release) != null) return .suppress_raii;
        },
        .cross_language_free => {
            // R-6 所有权转移
            if (srt.hasKind(v, .into_raw_transfer) != null) return .suppress_ownership_transfer;
            // R-4 非内存 syscall
            if (srt.hasKind(v, .file_operation) != null) return .suppress_non_memory_syscall;
            if (srt.hasKind(v, .network_operation) != null) return .suppress_non_memory_syscall;
            if (srt.hasKind(v, .process_operation) != null) return .suppress_non_memory_syscall;
            // R-7 库级分配器 release（mi_free / inflateEnd / sqlite3_finalize 等）
            if (srt.hasKind(v, .library_release) != null) return .suppress_library_release;
        },
        .command_injection => {
            // process_operation 不足以触发：需要 taint 引擎单独确认有 source 路径
            // gate 不直接判断 taint，由 Pass 自行查询 ctx.taint_state
        },
        else => {},
    }
    return .allow;
}
```

**收益**: 后续新加 Pass / 新加 IssueKind，只要进 aggregator 就自动走 gate。新增 detector 只要往 SRT 写 Resolution，gate 自动起效，**不会再出现"基础设施在但没接线"问题**。

### 6.3 高置信度输出 + 完整调用链（最终用户看到的东西）

> 用户要求：**输出高置信度 bug + 完整调用链**。不再输出二元 (报/不报)。

**置信度计算**（每个 Issue 出 aggregator 时填入）：

```zig
// src/diag/confidence_scorer.zig (新建)
pub fn score(issue: *const Issue, srt: *const SemanticTree, mg: *const MemoryGraph) f32 {
    var s: f32 = base_severity(issue.kind);  // 0.5 起步

    // (a) Provenance 清晰度：DI 找到 → +0.2；只有 use-def → +0.1；都没 → -0.1
    s += provenance_clarity_bonus(srt, issue.value_ref);

    // (b) 语料频率反向加权：该 (callee, kind) 组合在干净 corpus 出现频次越高 → 越像习语 → 减分
    s -= corpus_frequency_penalty(issue);

    // (c) Dataflow 距离：source→sink 路径越短越可疑（taint 类）
    s += dataflow_proximity_bonus(mg, issue);

    // (d) 多 detector 共识：同一 value 被 ≥2 个 detector 标为可疑 → +0.15
    s += multi_detector_consensus_bonus(srt, issue.value_ref);

    return std.math.clamp(s, 0.0, 1.0);
}
```

**输出分层**:

| Tier | 阈值 | 显示位置 | 用户操作 |
|---|---|---|---|
| **Critical** | score ≥ 0.85 | 终端置顶 / SARIF severity=error | 必读、需修 |
| **High** | 0.7 ≤ score < 0.85 | 紧随其后 / severity=warning | 强烈建议复审 |
| **Medium** | 0.5 ≤ score < 0.7 | --verbose 时显示 / severity=note | 选读 |
| **Informational** | score < 0.5 | 仅落 SARIF 文件，不打印 | 备查 |

bun 上预期：Critical+High 共 ≤10，其中 TP > 90%；Medium 可能有 ~20；Informational 是长尾噪声但不刷屏。

**完整调用链格式**（每个 Issue 必带）:

```
[CRITICAL 0.92] use_after_free in bun_base64::wyhash_url_safe
  at src/base64/lib.rs:1027

  ┌─ Call chain (4 frames, crossed 1 language boundary):
  │
  │ ① bun_core::dispatch::handle_request                       [Rust]
  │     src/core/dispatch.rs:412
  │     calls → bun_base64::encode_url_safe(req.body)
  │
  │ ② bun_base64::encode_url_safe                              [Rust]
  │     src/base64/lib.rs:998
  │     calls → wyhash_url_safe(&arena, args)
  │
  │ ③ bun_base64::wyhash_url_safe                              [Rust]
  │     src/base64/lib.rs:1002  ← issue site
  │     Vec<u8> allocated (heap_provenance)
  │     hasher.update(&fmt_str) at L1015
  │     fmt_str leaves scope at L1027
  │     → drop_in_place<Vec<u8>>                               [Rust drop glue, SRT=raii_drop_release]
  │
  │ ④ core::ptr::drop_in_place<Vec<u8>>                        [Rust core]
  │     internal: __rust_dealloc(ptr, layout) (tail position)
  │
  └─ Memory graph:
      alloc_site:  L1002 (Vec::with_capacity 128)
      last_use:    L1015 (hasher.update)
      release:     L1027 (compiler-inserted drop, SRT.raii_drop_release)
      conclusion:  no use after release; UAF report suppressed by Gate

  Evidence: drop_glue.zig flagged as raii_drop_release (Nomicon Ch6 OBRM)
  Score breakdown: base=0.55 + provenance=+0.2 - corpus_freq=-0.30 + consensus=+0 = 0.45
                   → demoted to Informational (was reported as use_after_free in v0.x)
```

**关键字段**:
- **Language tag** at each frame（Rust / Go / C / C++ / C# / Python / Java，本期 7 种）
- **Memory graph 三元组** (alloc_site / last_use / release)
- **Score breakdown** 让用户能反推为什么是这个 tier
- **Evidence pointer** 到 detector 文件 + R-N 编号（可选 Nomicon 章节脚注）

**实现位置**:
- 评分: `src/diag/confidence_scorer.zig` 新建
- 调用链: 已有 `Issue.TraceEntry`，扩展加 `language` 字段
- 格式化: `src/output/cli.zig` / `src/output/sarif.zig` 同步输出

---

## 7. 对应 LL_ANALYSIS_REPORT.md 实测 FP 的覆盖

实测来自 `LL_ANALYSIS_REPORT.md` §三（OmniScope v0.1.8 跑 bun 145 .ll 的结果）：

| FP 类型 | 实测 FP | 主信号 (R-N) | 覆盖 SemanticKind | 触发 detector | 预期残余 |
|---|---|---|---|---|---|
| write_to_immutable | **1877** | **R-0 readonly attr** + R-2 UnsafeCell | `mutable_param` / `interior_mutability` | `param_attr.zig` + `interior_mut.zig` | <100 (95%↓) |
| borrow_escape | 71 | R-1 SROA heap field | `heap_provenance` / `global_provenance` | `heap_provenance.zig` (alloca DI = Box/Arc/Vec/String/*mut) | <10 (86%↓) |
| cross_language_free | 4 | R-6 into_raw + R-4 syscall class + R-7 library pairs | `into_raw_transfer` / `file_operation` / `library_release` | `into_raw_transfer.zig` + `posix_syscalls.zig` + `library_alloc_pairs.zig` | 0 (100%↓) |
| use_after_free | 3 | R-3 drop glue | `raii_drop_release` | `drop_glue.zig` (drop_in_place / ret 前 tail) | 0 (100%↓) |

**总计**: 1966 → <110（实测目标 94% 降幅）。

**TP（红队 corpus）维持要求**:
- 在 `corpus/red_team_test/*.{ll,bc}`（C/C++/Rust/Go/C#/Python/Java JNI 各 ~3-6 个故意带 bug 文件）上 Recall ≥ 90%。
- Suppress 决策不允许误伤红队语料里任何标记为 TP 的 issue（CI 阈值）。

---

## 8. 工期 + 实施顺序

```
W1 (2d):  扩展 SemanticKind / ResolutionDimension / profileValue 接口
          所有 detector 写空骨架，先让 SRT 能被查询
W2 (1d):  drop_glue.zig (Drop tail / drop glue) + 接线到 detectUseAfterFree
          → 消除 ~3 个 UAF FP，验证 SRT 查询通路
W3 (1d):  posix_syscalls.zig + 接线到 cross_language_free 检测
          → 消除 ~4 个 cross_lang_free FP
W4 (1d):  Ch5 UnsafeCell chain + 接线到 detectWriteToImmutable
          → 消除 ~23 个 write_to_immutable FP
W5 (3d):  heap_provenance.zig + traceValueSource 接入 SRT.provenance
          → 消除 ~74 个 borrow_escape FP（主战场）
W6 (1d):  library_alloc_pairs.zig（mimalloc/zlib/openssl/sqlite/cgo/JNI/Python/Zig 配对表）
          → 接线到 cross_language_free，消除库级释放误报
W7 (1d):  taint 接线到 ffi_body_check
          → 消除 ~2 个 command_injection FP
W8 (1d):  Issue Gate 统一收口 + 残余 case 分析

合计 ~11 工作日。
```

---

## 9. 文件改动目录

```
src/
├── semantics/
│   ├── semantic_tree.zig                ← 扩展 SemanticKind (4→13) + Resolution.evidence
│   ├── semantic_patterns.zig            ← 弃用其字符串匹配，逻辑挪入 patterns/
│   ├── resolution_engine.zig            ← 改为 dispatch 到 patterns/* detectors
│   ├── rust_drop_semantics.zig          ← 保留：drop_in_place 符号定义复用
│   └── patterns/                        ← 新建目录（与 §1.B R-0~R-6 一一对应）
│       ├── lang_detector.zig            ← R-5: 模块语言识别（Rust/Go/C/C++/C#/Python/Java）
│       ├── param_attr.zig               ← R-0: LLVM readonly/noalias → mutable/readonly_param ★主力
│       ├── heap_provenance.zig          ← R-1: alloca DI=Box/Arc/Vec/String/*mut → heap_provenance
│       ├── interior_mut.zig             ← R-2: DI chain 含 UnsafeCell → interior_mutability
│       ├── drop_glue.zig                ← R-3: drop_in_place / tail dealloc → raii_drop_release
│       ├── posix_syscalls.zig           ← R-4: syscall 4 类分类 (file/net/mem/proc)
│       ├── into_raw_transfer.zig        ← R-6: Box/CString/Vec::into_raw → into_raw_transfer
│       └── library_alloc_pairs.zig      ← R-7: 库级分配器配对表 (mimalloc/zlib/openssl/sqlite/cgo/JNI/Python/Zig)
├── pass/
│   ├── analysis/
│   │   ├── semantic_resolver_pass.zig   ← 改为统一调度 patterns/* detectors
│   │   ├── rust_ffi/
│   │   │   ├── rust_ffi_rules_basic.zig    ← detectStackEscapeToFFI / detectCrossLangMismatch
│   │   │   │                                  改为先查 SRT (R-1/R-6)
│   │   │   ├── rust_ffi_rules_advanced.zig ← detectWriteToImmutable (R-0 主信号)
│   │   │   │                                  / detectUseAfterFree (R-3)
│   │   │   └── rust_ffi_helpers.zig        ← isCFreeCall 改查 SRT.posix_syscall_class
│   │   ├── issue/
│   │   │   └── ffi_body_check.zig          ← command_injection 接 taint 引擎结果
│   │   └── taint/
│   │       └── taint_propagation.zig       ← taint 结果写 SRT
│   └── filter/
│       ├── fp_whitelist.zig             ← 收缩到 §2.2 的 3 条 + 2 张分类表
│       └── issue_gate.zig               ← 新建：所有 Issue 经此关，按 R-N 维度抑制
├── diag/
│   └── confidence_scorer.zig            ← 新建：4 维评分 → 4 tier 输出
└── types/
    └── rust_ffi_types.zig               ← ValueSource 与 SRT.kind 对齐

tests/
├── srt_extension_test.zig               ← 新建：SRT 扩展 API 单测
└── patterns/
    ├── param_attr_test.zig              ← R-0 单测（核心）
    ├── heap_provenance_test.zig         ← R-1
    ├── interior_mut_test.zig            ← R-2
    ├── drop_glue_test.zig               ← R-3
    ├── posix_syscalls_test.zig          ← R-4
    ├── into_raw_transfer_test.zig       ← R-6
    └── library_alloc_pairs_test.zig     ← R-7

corpus/
└── bun_baseline_1966.txt                ← 实测 1966 FP 指纹，CI 回归阈值
```

---

## 10. 关键设计决策 + 自检

### 10.1 为什么把 SRT 作为骨架而不是新建一个层？

- 项目已经有 `semantic_tree.zig` (279 行) + `semantic_resolver_pass.zig`，**沉没成本归零**。
- `value_to_node: HashMap(ValueRef, usize)` 已经是 O(1) 查询接口，扩展只需加变体、加 dimension 字段。
- 现有 Pass 已经通过 `ctx` 访问 SRT，接线成本最低。

### 10.2 为什么选语料归纳作为模式来源？

- **实证性**: 每条 R-N 规律都有真实 grep 频次（bun_install.ll 117k SROA load / 23k drop_in_place / 367 UnsafeCell ...），`ir.md` 提供跨语言 IR 规律的补充归纳
- **稳定性**: 信号来自 LLVM IR 规范（`readonly` 属性）+ Rust ABI 符号（`__rust_alloc`/`drop_in_place`）+ POSIX 规范 + 库级 API 文档（mimalloc/zlib/openssl/sqlite 等），比经验白名单稳。
- **可解释**: 每条 Resolution 带 `evidence` 字段（如 `"alloca DI=Box<ClientSession>"` 或 `"readonly attr at param idx 0"`），可直接出现在用户报告里。
- **Nomicon 作为脚注**: SP-1~SP-3 引用 Nomicon Ch6/Ch9/Ch5 仅用于解释"为什么这个模式 sound"，不依赖 Nomicon 做目录划分。

### 10.3 自检 5 问（防退化）

1. **新增的字符串常量是否对所有目标语言（Rust/Go/C/C++/C#/Python/Java）通用？**
   - ✅ `Box<`、`UnsafeCell<`、`__rust_dealloc`、`unlink`、`runtime.alloc`、`JNI_OnLoad`、`_cffi_`、`mi_free`、`inflateEnd` — 语言/POSIX/库 API 通用
   - ❌ `SSL_`、`uv_`、`archive_`、`us_socket_` — 项目特定，禁止

2. **每个 SemanticKind 是否对应一条 R-N 规律 + 一个 detector 文件？**
   - 不能 → 设计有问题，要么补 detector 要么删变体
   - 能 → 合格

3. **新增 Pass 时，是否能不写一行项目特定白名单？**
   - 不能 → 缺 detector 信号，去 patterns/ 加 detector，不要绕过 SRT
   - 能 → 合格

4. **SRT 中的 Resolution 是否能被诊断报告引用？**
   - 必须能。Issue 的 trace 里要写 `"R-0 readonly attr at param idx 2"` / `"R-3 drop_in_place context"` 等

5. **回归 corpus（red_team_test 中各语言带 bug 文件）TP 是否维持 ≥90%？**
   - 漏报 → 找回某 detector 的边界条件
   - 无漏报 → 合格

---

## 11. 一句话总结

**升级 OmniScope 现有的 `SemanticTree`：扩展 `SemanticKind` 到 15 个变体，每个对应 §1.B 一条 R-N 语料归纳规律；新建 `src/semantics/patterns/` 9 个 detector（R-0~R-8）写入 SRT；所有 Pass 在 emit Issue 前必须查 SRT，并经 `confidence_scorer.zig` 出 4 tier 排序。bun 上 1966 FP 通过 R-0 (LLVM readonly attr) + R-8 (parameter source) + R-1~R-7 自动覆盖 99.1%，残余 17 issues（8 个 LOW 信息性 + 9 个待分析）；白名单收口至 3 条 + 3 张分类表（POSIX syscall / LLVM intrinsics / 库级分配器配对），支持 Rust/Go/C/C++/C#/Python/Java 七种语言。**
