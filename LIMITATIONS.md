# Limitations

OmniScope is a static analyzer built on LLVM IR for cross-language FFI security auditing. While powerful, it has important limitations:

## What OmniScope is NOT

### 1. NOT a formal verification tool
OmniScope cannot replace CBMC, Infer, or other formal verification tools. Its analysis is based on heuristics and pattern matching, not formal proofs. Precision and completeness are far below formal methods.

### 2. NOT suitable for pure C/C++ memory safety auditing
The Write-To-Immutable (WTI) analysis still produces a significant number of false positives for C++ code. If your project is pure C/C++ (no cross-language FFI), use dedicated C/C++ analyzers instead.

### 3. NOT a standalone security solution
OmniScope must be used alongside dynamic analysis tools (fuzzing, sanitizers). Static analysis alone cannot confirm the absence of bugs. Always combine with:
- Fuzzing (libFuzzer, AFL)
- AddressSanitizer / MemorySanitizer
- Runtime validation

## Known Weaknesses

### C++ WTI False Positives
cpp_fft.ll and cpp_hash.ll currently produce ~73 WTI false positives. C++ const semantics are often lost at the LLVM IR level, causing the analyzer to flag legitimate writes as violations.

### Non-deterministic Output
Some analysis results (particularly DoubleFree detection) are non-deterministic due to HashMap iteration order. This is a known limitation being addressed.

### Single-File Analysis
OmniScope currently analyzes one LLVM IR file at a time. Cross-module analysis (e.g., analyzing both sides of an FFI boundary from separate compilation units) is not supported.

## Recommended Usage

### CI/CD: Informational Check Only
Use OmniScope as an informational check in CI — do NOT block builds. Output should be `note` level, flagging FFI boundary points for manual review.

### Security Auditing: First-Pass Triage Tool
Use OmniScope as a first-pass triage tool for security auditors:
1. Run OmniScope to identify FFI boundary points
2. Manually review flagged locations
3. Use dynamic analysis (fuzzing/sanitizers) for deep investigation

### Educational: FFI Surface Mapping
OmniScope is excellent for visualizing which functions cross language boundaries in Rust FFI projects, making it useful for teaching and academic research.

---

# 限制说明

OmniScope 是一款基于 LLVM IR 的跨语言 FFI 安全审计静态分析工具。它有如下重要限制：

## OmniScope 不是

### 1. 不是形式化验证工具
OmniScope 无法替代 CBMC、Infer 等形式化验证工具。其分析基于启发式和模式匹配，而非形式化证明。精度和完备性远低于形式化方法。

### 2. 不适合纯 C/C++ 内存安全审计
WTI（写入不可变内存）分析对 C++ 代码仍有大量误报。如果您的项目是纯 C/C++（无跨语言 FFI），请使用专用的 C/C++ 分析工具。

### 3. 不是唯一的安全保障
OmniScope 必须与动态分析工具（fuzzing、sanitizer）配合使用。静态分析无法独立确认 bug 的缺失。始终配合使用：
- Fuzzing（libFuzzer, AFL）
- AddressSanitizer / MemorySanitizer
- 运行时验证

## 已知弱点

### C++ WTI 误报
cpp_fft.ll 和 cpp_hash.ll 目前有约 73 个 WTI 误报。C++ 的 const 语义在 LLVM IR 层面经常丢失，导致分析器将合法的写入标记为违规。

### 非确定性输出
部分分析结果（特别是 DoubleFree 检测）由于 HashMap 迭代顺序而具有非确定性。这是一个已知限制，正在解决中。

### 单文件分析
OmniScope 目前一次分析一个 LLVM IR 文件。不支持跨模块分析。

## 推荐用途

### CI/CD：仅作为参考检查
在 CI 中将 OmniScope 作为参考检查，不要阻断构建。输出应为 note 级别，标记 FFI 边界点供人工审查。

### 安全审计：初筛工具
安全审计员可将 OmniScope 作为初筛工具：
1. 运行 OmniScope 识别 FFI 边界点
2. 人工审查标记位置
3. 使用动态分析进行深入调查

### 教学/学术：FFI Surface 映射
OmniScope 非常适合可视化 Rust FFI 项目中哪些函数跨越了语言边界，适用于教学和学术研究。