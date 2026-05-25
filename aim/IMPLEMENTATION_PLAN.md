# OmniScope-RS Implementation Plan

> **目标**: 用 Rust 1:1 复刻 OmniScope (Zig)，实现更强大的静态分析能力

## 📋 总体策略

### 实施原则
1. **渐进式迁移**: 从底层到高层，逐步实现
2. **测试驱动**: 每个模块实现前先写测试
3. **功能对等**: 确保 Rust 版本功能不弱于 Zig 版本
4. **性能优化**: 利用 Rust 特性实现更优性能

### 迁移顺序
```
Layer 1 (Core) → Layer 2 (IR) → Layer 3 (Dataflow) → 
Layer 4 (Semantics) → Layer 5 (Passes) → Layer 6 (Pipeline) → Layer 7 (CLI)
```

---

## 🎯 Phase 1: 核心基础设施 (Layer 1)

**目标**: 建立项目骨架和核心工具

### 1.1 项目初始化
- [ ] 创建 Cargo workspace 结构
- [ ] 配置 `Cargo.toml` (所有依赖)
- [ ] 设置 `rust-toolchain.toml` (Rust 1.75+)
- [ ] 配置 `.gitignore`, `LICENSE`, `README.md`
- [ ] 设置 CI/CD (GitHub Actions)

### 1.2 omniscope-core crate
- [ ] **错误类型系统** (`error.rs`)
  ```rust
  // 对应 Zig 的 error union
  #[derive(Debug, thiserror::Error)]
  pub enum OmniScopeError {
      #[error("IR loading failed: {0}")]
      IRLoadError(#[from] IRLoadError),
      
      #[error("Analysis failed: {0}")]
      AnalysisError(#[from] AnalysisError),
      
      #[error("Invalid configuration: {0}")]
      ConfigError(String),
  }
  ```

- [ ] **诊断系统** (`diagnostics.rs`)
  ```rust
  // 对应 Zig 的 diag/issue.zig
  #[derive(Debug, Clone, Serialize)]
  pub struct Diagnostic {
      pub severity: Severity,
      pub code: String,
      pub message: String,
      pub location: SourceLocation,
      pub hints: Vec<String>,
  }
  
  pub struct DiagnosticAggregator {
      diagnostics: Vec<Diagnostic>,
      // 使用 dashmap 实现并发安全
      by_file: DashMap<PathBuf, Vec<Diagnostic>>,
  }
  ```

- [ ] **Fact 系统** (`fact.rs`, `fact_store.rs`)
  ```rust
  // 对应 Zig 的 fact/fact.zig
  #[derive(Debug, Clone)]
  pub enum FactKind {
      AllocSite,
      DeallocSite,
      TaintSource,
      TaintSink,
      FFIBoundary,
  }
  
  pub struct Fact {
      pub kind: FactKind,
      pub location: SourceLocation,
      pub metadata: HashMap<String, String>,
  }
  
  // 使用 dashmap 实现并发 Fact 存储
  pub struct FactStore {
      facts: DashMap<FactId, Fact>,
      by_kind: DashMap<FactKind, Vec<FactId>>,
  }
  ```

- [ ] **性能分析** (`profiler.rs`)
  ```rust
  // 对应 Zig 的 perf/profiler.zig
  pub struct Profiler {
      spans: Vec<Span>,
      memory_samples: Vec<MemorySample>,
  }
  
  pub struct ScopedTimer<'a> {
      profiler: &'a Profiler,
      start: Instant,
      name: &'static str,
  }
  ```

- [ ] **内存池** (`memory_pool.rs`)
  ```rust
  // 对应 Zig 的 perf/memory_pool.zig
  pub struct MemoryPool {
      arena: Bump,
  }
  
  impl MemoryPool {
      pub fn alloc<T>(&self, value: T) -> &mut T {
          self.arena.alloc(value)
      }
  }
  ```

### 1.3 omniscope-types crate
- [ ] **ABI 类型** (`abi_types.rs`)
- [ ] **所有权类型** (`ownership_types.rs`)
- [ ] **调用图类型** (`call_graph_types.rs`)
- [ ] **回调逃逸类型** (`callback_escape_types.rs`)
- [ ] **内存图类型** (`memory_graph_types.rs`)
- [ ] **锁类型** (`lock_types.rs`)
- [ ] **配置类型** (`main_config.rs`)

**验收标准**:
- ✅ 所有类型编译通过
- ✅ 单元测试覆盖率 > 80%
- ✅ 文档注释完整

---

## 🎯 Phase 2: IR 抽象层 (Layer 2)

**目标**: 实现 LLVM IR 的安全抽象

### 2.1 omniscope-ir crate
- [ ] **IR 加载器** (`loader.rs`)
  ```rust
  // 对应 Zig 的 engine/loader.zig
  pub struct IRLoader {
      context: Context,
      module: Option<Module>,
  }
  
  impl IRLoader {
      pub fn load_from_file(&mut self, path: &Path) -> Result<&Module, IRLoadError> {
          // 使用 inkwell 加载 LLVM IR
          let module = self.context.create_module_from_ir(path)?;
          self.module = Some(module);
          Ok(self.module.as_ref().unwrap())
      }
      
      pub fn load_from_memory(&mut self, ir: &[u8]) -> Result<&Module, IRLoadError> {
          // 从内存加载 IR
      }
  }
  ```

- [ ] **安全包装器** (`llvm_safe.rs`)
  ```rust
  // 对应 Zig 的 ir/llvm_safe.zig
  pub struct SafeModule<'ctx> {
      inner: Module<'ctx>,
  }
  
  pub struct SafeFunction<'ctx> {
      inner: FunctionValue<'ctx>,
  }
  
  pub struct SafeBasicBlock<'ctx> {
      inner: BasicBlock<'ctx>,
  }
  
  // 提供安全的遍历接口
  impl<'ctx> SafeModule<'ctx> {
      pub fn functions(&self) -> impl Iterator<Item = SafeFunction<'ctx>> {
          self.inner.get_functions().map(SafeFunction::new)
      }
  }
  ```

- [ ] **IR 视图** (`view.rs`)
  ```rust
  // 对应 Zig 的 ir/view.zig
  pub struct FunctionView<'ctx> {
      func: SafeFunction<'ctx>,
      cfg: Option<CFG>,
  }
  
  pub struct InstructionView<'ctx> {
      inst: InstructionValue<'ctx>,
      location: SourceLocation,
  }
  ```

- [ ] **调试信息提取** (`debug_info.rs`)
  ```rust
  // 对应 Zig 的 ir/debug_info.zig
  pub struct DebugInfoExtractor<'ctx> {
      module: &'ctx Module<'ctx>,
  }
  
  impl<'ctx> DebugInfoExtractor<'ctx> {
      pub fn extract_location(&self, inst: &InstructionValue) -> Option<SourceLocation> {
          // 提取源码位置信息
      }
      
      pub fn extract_type_info(&self, value: &AnyValue) -> Option<TypeInfo> {
          // 提取类型信息
      }
  }
  ```

- [ ] **源码位置追踪** (`location.rs`)
  ```rust
  #[derive(Debug, Clone, Serialize)]
  pub struct SourceLocation {
      pub file: PathBuf,
      pub line: u32,
      pub column: Option<u32>,
      pub function: Option<String>,
  }
  ```

**验收标准**:
- ✅ 能成功加载 LLVM IR 文件 (.ll, .bc)
- ✅ 安全遍历所有 IR 元素
- ✅ 正确提取调试信息
- ✅ 性能测试：加载 10K 行 IR < 1s

---

## 🎯 Phase 3: 数据流引擎 (Layer 3)

**目标**: 实现数据流分析基础设施

### 3.1 omniscope-dataflow crate
- [ ] **数据流图** (`graph.rs`)
  ```rust
  // 对应 Zig 的 dataflow/graph.zig
  pub struct DataFlowGraph {
      nodes: Vec<DataNode>,
      edges: Vec<DataEdge>,
      entry_node: NodeId,
      exit_node: NodeId,
  }
  
  impl DataFlowGraph {
      pub fn build_from_function(&mut self, func: &FunctionView) {
          // 构建函数内数据流图
      }
      
      pub fn forward_analysis<T: AnalysisDomain>(&self, analysis: &T) -> T::Result {
          // 前向数据流分析
      }
      
      pub fn backward_analysis<T: AnalysisDomain>(&self, analysis: &T) -> T::Result {
          // 后向数据流分析
      }
  }
  ```

- [ ] **数据节点** (`node.rs`)
  ```rust
  #[derive(Debug, Clone)]
  pub struct DataNode {
      pub id: NodeId,
      pub value_type: ValueType,
      pub location: SourceLocation,
      pub incoming: Vec<EdgeId>,
      pub outgoing: Vec<EdgeId>,
  }
  
  #[derive(Debug, Clone)]
  pub enum ValueType {
      Variable(String),
      Temporary(u32),
      Constant(Constant),
      Memory(MemoryLocation),
  }
  ```

- [ ] **数据边** (`edge.rs`)
  ```rust
  #[derive(Debug, Clone)]
  pub struct DataEdge {
      pub id: EdgeId,
      pub from: NodeId,
      pub to: NodeId,
      pub edge_type: EdgeType,
  }
  
  #[derive(Debug, Clone)]
  pub enum EdgeType {
      Assignment,
      Parameter(u32),
      Return,
      FieldAccess(String),
      ArrayIndex,
  }
  ```

- [ ] **函数摘要** (`function_summary.rs`)
  ```rust
  // 对应 Zig 的 dataflow/function_summary.zig
  pub struct FunctionSummary {
      pub inputs: Vec<AbstractValue>,
      pub outputs: Vec<AbstractValue>,
      pub side_effects: Vec<SideEffect>,
  }
  
  impl FunctionSummary {
      pub fn compute(&mut self, func: &FunctionView) {
          // 计算函数摘要（过程间分析）
      }
  }
  ```

- [ ] **路径敏感分析** (`path_condition.rs`)
  ```rust
  // 对应 Zig 的 dataflow/path_condition.zig
  pub struct PathCondition {
      conditions: Vec<Condition>,
  }
  
  impl PathCondition {
      pub fn add_condition(&mut self, cond: Condition) {
          // 添加路径条件
      }
      
      pub fn is_satisfiable(&self) -> bool {
          // 检查路径条件是否可满足（使用 SMT solver）
      }
  }
  ```

- [ ] **守卫传播** (`guard_propagation.rs`, `null_check_guard.rs`)
  ```rust
  pub struct GuardPropagation {
      guards: HashMap<NodeId, Guard>,
  }
  
  pub struct NullCheckGuard {
      checked_values: HashSet<ValueId>,
  }
  ```

**验收标准**:
- ✅ 数据流图构建正确
- ✅ 前向/后向分析正确
- ✅ 函数摘要计算准确
- ✅ 路径敏感分析有效

---

## 🎯 Phase 4: 语义分析引擎 (Layer 4)

**目标**: 实现语言检测和语义理解

### 4.1 omniscope-semantics crate
- [ ] **语言检测** (`language_detector.rs`)
  ```rust
  // 对应 Zig 的 semantics/language_detector.zig
  pub struct LanguageDetector {
      patterns: Vec<LanguagePattern>,
  }
  
  impl LanguageDetector {
      pub fn detect(&self, module: &Module) -> Language {
          // 基于特征检测源语言
          // C/C++/Rust/Zig/Go/Python/Java
      }
  }
  ```

- [ ] **区域分类** (`zone_classifier.rs`)
  ```rust
  // 对应 Zig 的 semantics/zone_classifier.zig
  pub struct ZoneClassifier {
      cache: ZoneCache,
  }
  
  impl ZoneClassifier {
      pub fn classify(&self, func: &FunctionView) -> ZoneKind {
          // 分类函数为安全/危险区域
          // 实现 64% 代码跳过优化
      }
  }
  
  #[derive(Debug, Clone)]
  pub enum ZoneKind {
      Safe,    // 可跳过分析
      Risky,   // 需要分析
      Unknown, // 需要保守分析
  }
  ```

- [ ] **噪声过滤** (`noise_filter.rs`, `path_filter.rs`, `behavior_filter.rs`)
  ```rust
  // 对应 Zig 的 semantics/noise_filter.zig
  pub struct NoiseFilter {
      name_filter: NameBasedFilter,
      path_filter: PathBasedFilter,
      behavior_filter: BehaviorFilter,
  }
  
  impl NoiseFilter {
      pub fn should_filter(&self, func: &FunctionView) -> bool {
          // 判断是否应该过滤（减少假阳性）
      }
  }
  ```

- [ ] **语义解析引擎** (`resolution_engine.rs`, `semantic_tree.rs`)
  ```rust
  pub struct ResolutionEngine {
      patterns: PatternRegistry,
  }
  
  impl ResolutionEngine {
      pub fn resolve(&self, func: &FunctionView) -> Resolution {
          // 解析函数语义
      }
  }
  ```

- [ ] **内存图** (`memory_graph.rs`, `memory_relations.rs`)
  ```rust
  // 对应 Zig 的 semantics/memory_graph.zig
  pub struct MemoryGraph {
      nodes: Vec<MemoryNode>,
      edges: Vec<MemoryEdge>,
  }
  
  impl MemoryGraph {
      pub fn build(&mut self, func: &FunctionView) {
          // 构建内存关系图
      }
  }
  ```

### 4.2 omniscope-registry crate
- [ ] **语义注册表** (`semantic_registry.rs`)
  ```rust
  // 对应 Zig 的 registry/semantic_registry.zig
  pub struct SemanticRegistry {
      functions: HashMap<String, FunctionSemantics>,
      dangerous_sinks: HashSet<String>,
      safe_functions: HashSet<String>,
  }
  ```

- [ ] **语言特定注册表** (layer1-6_reg.rs, posix_io_reg.rs, etc.)
  ```rust
  // 对应 Zig 的 registry/layer1_reg.zig 等
  pub struct Layer1Registry {
      // C 标准库函数语义
  }
  
  pub struct PosixIORegistry {
      // POSIX I/O 函数语义
  }
  ```

- [ ] **配置加载** (`config_loader.rs`)
  ```rust
  pub struct DynamicRegistry {
      config: SemanticConfig,
  }
  
  impl DynamicRegistry {
      pub fn load_from_file(path: &Path) -> Result<Self, ConfigError> {
          // 从 JSON/TOML 加载配置
      }
  }
  ```

**验收标准**:
- ✅ 语言检测准确率 > 95%
- ✅ 区域分类减少 60%+ 分析量
- ✅ 噪声过滤减少 50%+ 假阳性
- ✅ 所有注册表加载正确

---

## 🎯 Phase 5: 分析 Pass 系统 (Layer 5)

**目标**: 实现 25+ 分析 pass

### 5.1 Pass 基础设施
- [ ] **Pass trait 定义** (`pass.rs`)
  ```rust
  // 对应 Zig 的 pass/pass.zig
  pub trait Pass: Send + Sync {
      fn name(&self) -> &'static str;
      fn kind(&self) -> PassKind;
      fn dependencies(&self) -> Vec<TypeId>;
      
      fn run(&self, ctx: &mut PassContext) -> Result<PassResult, PassError>;
  }
  
  #[derive(Debug, Clone)]
  pub enum PassKind {
      Foundation,
      Analysis,
      Transformation,
  }
  ```

- [ ] **Pass 管理器** (`manager.rs`)
  ```rust
  // 对应 Zig 的 pass/manager.zig
  pub struct PassManager {
      passes: Vec<Box<dyn Pass>>,
      execution_order: Vec<TypeId>,
  }
  
  impl PassManager {
      pub fn register<P: Pass + 'static>(&mut self, pass: P) {
          // 注册 pass
      }
      
      pub fn run_all(&mut self, ctx: &mut PassContext) -> Result<Vec<PassResult>, PassError> {
          // 按依赖顺序执行所有 pass
          // 使用 rayon 并行执行无依赖的 pass
      }
  }
  ```

- [ ] **Pass 上下文** (`context.rs`)
  ```rust
  pub struct PassContext<'a> {
      module: &'a Module<'a>,
      fact_store: &'a FactStore,
      diagnostics: &'a DiagnosticAggregator,
      profiler: &'a Profiler,
      // Pass 间共享数据
      shared: DashMap<TypeId, Box<dyn Any + Send + Sync>>,
  }
  ```

### 5.2 基础 Pass (Foundation Passes)
- [ ] **CFG Pass** (`foundation/cfg.rs`)
  ```rust
  pub struct CFGPass;
  
  impl Pass for CFGPass {
      fn run(&self, ctx: &mut PassContext) -> Result<PassResult, PassError> {
          // 构建控制流图
      }
  }
  ```

- [ ] **DFG Pass** (`foundation/dfg.rs`)
- [ ] **Alias Analysis Pass** (`foundation/alias.rs`)

### 5.3 FFI 分析 Pass
- [ ] **FFI Boundary Detection** (`analysis/ffi/ffi_boundary.rs`)
  ```rust
  // 对应 Zig 的 pass/analysis/ffi/ffi_boundary.zig
  pub struct FFIBoundaryPass;
  
  impl Pass for FFIBoundaryPass {
      fn run(&self, ctx: &mut PassContext) -> Result<PassResult, PassError> {
          // 检测 FFI 边界
      }
  }
  ```

- [ ] **FFI Type Mismatch** (`analysis/ffi/ffi_type_mismatch.rs`)
- [ ] **FFI Safety Checker** (`analysis/ffi/ffi_safety_checker.rs`)
- [ ] **FFI Body Check** (`analysis/issue/ffi_body_check.rs`)
- [ ] **Rust FFI Auditor** (`analysis/rust_ffi/rust_ffi_auditor.rs`)

### 5.4 内存安全 Pass
- [ ] **Pointer Ownership** (`analysis/pointer_ownership.rs`)
- [ ] **Pointer Lifetime** (`analysis/ptr_lifetime/ptr_lifetime.rs`)
- [ ] **Buffer Overflow** (`analysis/buffer_overflow.rs`)
- [ ] **Memory Safety** (`analysis/issue/memory_safety.rs`)
- [ ] **Malloc Check** (`analysis/issue/malloc_check.rs`)
- [ ] **Free Validation** (`analysis/issue/free_validation.rs`)

### 5.5 数据流 & 污点分析 Pass
- [ ] **Taint Propagation** (`analysis/taint/taint_propagation.rs`)
  ```rust
  // 对应 Zig 的 pass/analysis/taint/taint_propagation.zig
  pub struct TaintPropagationPass;
  
  impl Pass for TaintPropagationPass {
      fn run(&self, ctx: &mut PassContext) -> Result<PassResult, PassError> {
          // 污点传播分析
      }
  }
  ```

- [ ] **Flow Path Tracking** (`analysis/taint/flow_path.rs`)

### 5.6 并发 & 其他 Pass
- [ ] **Lock Analysis** (`analysis/lock.rs`)
- [ ] **Thread Crossing** (`analysis/thread_crossing.rs`)
- [ ] **Callback Escape** (`analysis/callback_escape.rs`)
- [ ] **Integer Overflow** (`analysis/issue/integer_overflow.rs`)
- [ ] **Transmute Detection** (`analysis/transmute_detection.rs`)
- [ ] **ABI Mismatch** (`analysis/abi_mismatch.rs`)

### 5.7 噪声过滤 Pass
- [ ] **Noise Reduction** (`analysis/noise/noise_reduction.rs`)
- [ ] **C++ FP Reduction** (`analysis/noise/cpp_fp_reduction.rs`)
- [ ] **Issue Suppression** (`analysis/noise/issue_suppression.rs`)

**验收标准**:
- ✅ 所有 pass 实现完成
- ✅ Pass 依赖正确解析
- ✅ 并行执行无数据竞争
- ✅ 每个 pass 有独立测试

---

## 🎯 Phase 6: Pipeline 编排 (Layer 6)

**目标**: 实现 pass 调度和结果聚合

### 6.1 omniscope-pipeline crate
- [ ] **Pipeline Manager** (`pipeline.rs`)
  ```rust
  // 对应 Zig 的 pipeline/pipeline.zig
  pub struct Pipeline {
      pass_manager: PassManager,
      config: PipelineConfig,
  }
  
  impl Pipeline {
      pub fn new() -> Self {
          // 创建默认 pipeline
      }
      
      pub fn run(&mut self, module: &Module) -> Result<PipelineResult, PipelineError> {
          // 执行完整分析流程
      }
  }
  ```

- [ ] **Pass 调度器** (`scheduler.rs`)
  ```rust
  pub struct PassScheduler {
      dependency_graph: DiGraph<TypeId, ()>,
  }
  
  impl PassScheduler {
      pub fn schedule(&self) -> Vec<Vec<TypeId>> {
          // 拓扑排序，返回可并行执行的 pass 层级
      }
  }
  ```

- [ ] **结果聚合** (`result.rs`)
  ```rust
  #[derive(Debug, Serialize)]
  pub struct PipelineResult {
      pub diagnostics: Vec<Diagnostic>,
      pub stats: AnalysisStats,
      pub duration: Duration,
  }
  ```

**验收标准**:
- ✅ Pass 调度正确
- ✅ 并行执行有效
- ✅ 结果聚合完整

---

## 🎯 Phase 7: CLI & 输出 (Layer 7)

**目标**: 实现命令行接口和输出格式化

### 7.1 omniscope-cli crate
- [ ] **CLI 解析** (`cli.rs`)
  ```rust
  // 使用 clap
  #[derive(Parser)]
  #[command(name = "omniscope")]
  #[command(about = "LLVM IR static analyzer")]
  struct Cli {
      #[command(subcommand)]
      command: Commands,
  }
  
  #[derive(Subcommand)]
  enum Commands {
      Analyze(AnalyzeCommand),
      Audit(AuditCommand),
      Config(ConfigCommand),
  }
  ```

- [ ] **分析命令** (`commands/analyze.rs`)
  ```rust
  pub struct AnalyzeCommand {
      #[arg(value_name = "INPUT")]
      input: PathBuf,
      
      #[arg(short, long)]
      output: Option<PathBuf>,
      
      #[arg(short = 'f', long)]
      format: OutputFormat,
  }
  
  impl AnalyzeCommand {
      pub fn run(&self) -> Result<()> {
          // 执行分析
      }
  }
  ```

- [ ] **输出格式化** (`output/formatter.rs`, `output/json.rs`, `output/sarif.rs`)
  ```rust
  pub trait OutputFormatter {
      fn format(&self, result: &PipelineResult) -> Result<String>;
  }
  
  pub struct JsonFormatter;
  pub struct SarifFormatter;
  pub struct CliFormatter;
  ```

- [ ] **LSP Server** (`output/lsp.rs`)
  ```rust
  // 使用 tower-lsp
  pub struct OmniScopeLspServer;
  
  #[tower_lsp::async_trait]
  impl LanguageServer for OmniScopeLspServer {
      async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
          // 初始化 LSP 服务器
      }
  }
  ```

**验收标准**:
- ✅ CLI 功能完整
- ✅ 输出格式正确
- ✅ LSP 服务器可用

---

## 🧪 测试策略

### 单元测试
- 每个 crate 都有 `#[cfg(test)]` 模块
- 使用 `cargo test` 运行
- 目标覆盖率: > 80%

### 集成测试
- `tests/integration/` 目录
- 测试完整分析流程
- 使用真实 IR 文件

### 性能测试
- `benches/` 目录
- 使用 `criterion`
- 对比 Zig 版本性能

### 稳定性测试
- `tests/stability/` 目录
- 测试崩溃恢复
- 测试畸形输入处理

### 压力测试
- `tests/stress/` 目录
- 大规模 IR 分析
- 边界条件测试

---

## 📊 性能优化清单

### 编译期优化
- [ ] 启用 LTO (`lto = "fat"`)
- [ ] 减少代码单元 (`codegen-units = 1`)
- [ ] 优化级别 3 (`opt-level = 3`)

### 运行时优化
- [ ] 使用 `rayon` 并行化
- [ ] 使用 `bumpalo` 内存池
- [ ] 使用 `dashmap` 并发 HashMap
- [ ] 实现 Zone Classification (64% 跳过)
- [ ] 实现增量分析

### 内存优化
- [ ] 使用 `smallvec` 减少分配
- [ ] 使用 `bitvec` 压缩存储
- [ ] 实现对象池

---

## 📈 里程碑

### Milestone 1: 核心基础设施 (2 周)
- Phase 1 完成
- 能编译通过
- 基础测试通过

### Milestone 2: IR 抽象 (2 周)
- Phase 2 完成
- 能加载 LLVM IR
- IR 遍历正确

### Milestone 3: 数据流引擎 (3 周)
- Phase 3 完成
- 数据流分析正确
- 性能达标

### Milestone 4: 语义分析 (3 周)
- Phase 4 完成
- 语言检测准确
- 噪声过滤有效

### Milestone 5: 分析 Pass (6 周)
- Phase 5 完成
- 所有 pass 实现
- 功能对等 Zig 版本

### Milestone 6: Pipeline & CLI (2 周)
- Phase 6-7 完成
- CLI 可用
- 输出正确

### Milestone 7: 优化 & 发布 (2 周)
- 性能优化
- 文档完善
- 发布 v0.1.0

**总计**: 约 20 周 (5 个月)

---

## 🎯 成功标准

### 功能对等
- ✅ 所有 Zig 版本功能都已实现
- ✅ 分析结果与 Zig 版本一致
- ✅ 支持所有语言 (C/C++/Rust/Zig/Go/Python/Java)

### 性能提升
- ✅ 分析速度 ≥ Zig 版本
- ✅ 内存占用 ≤ Zig 版本
- ✅ 编译时间可接受 (< 5min)

### 质量保证
- ✅ 测试覆盖率 > 80%
- ✅ 无 clippy 警告
- ✅ 文档完整

### 易用性
- ✅ CLI 友好
- ✅ 错误信息清晰
- ✅ 文档详细

---

## 🚀 后续扩展

### 短期 (v0.2.0)
- [ ] 增量分析
- [ ] 更多输出格式 (HTML, Markdown)
- [ ] IDE 插件 (VSCode, Vim)

### 中期 (v0.3.0)
- [ ] 插件系统
- [ ] 自定义规则
- [ ] 机器学习辅助

### 长期 (v1.0.0)
- [ ] 符号执行
- [ ] 约束求解
- [ ] 形式化验证

---

## 📝 注意事项

### 关键风险
1. **LLVM 绑定兼容性**: inkwell 对 LLVM 22 的支持
2. **编译时间**: Rust 编译慢，需优化
3. **内存占用**: 需注意内存管理
4. **并发安全**: 确保无数据竞争

### 缓解措施
1. 使用稳定的 LLVM 版本
2. 增量编译，缓存中间结果
3. 使用内存池，减少分配
4. 严格使用 `Send + Sync` 约束

---

## 🎉 总结

这个实施计划确保:
- ✅ **功能完整**: 1:1 复刻 Zig 版本
- ✅ **架构清晰**: 7 层分层设计
- ✅ **性能优异**: 利用 Rust 优势
- ✅ **质量可靠**: 测试驱动开发
- ✅ **易于维护**: 模块化设计

**最终目标**: 打造一个比 Zig 版本更强大、更安全、更易用的静态分析工具！
