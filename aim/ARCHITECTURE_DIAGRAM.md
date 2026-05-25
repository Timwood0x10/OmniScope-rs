# OmniScope-RS Architecture Diagrams

## 🏗️ 系统架构图

```mermaid
graph TB
    subgraph Layer7["Layer 7: CLI & Output"]
        CLI[CLI Parser<br/>clap]
        Formatter[Formatter<br/>JSON/SARIF]
        LSP[LSP Server<br/>tower-lsp]
    end
    
    subgraph Layer6["Layer 6: Pipeline"]
        Pipeline[Pipeline Manager]
        Scheduler[Pass Scheduler]
        Result[Result Aggregator]
    end
    
    subgraph Layer5["Layer 5: Analysis Passes"]
        Foundation[Foundation Passes<br/>CFG/DFG/Alias]
        FFI[FFI Analysis<br/>Boundary/Type/Safety]
        Memory[Memory Safety<br/>Ownership/Lifetime]
        Taint[Taint Analysis<br/>Propagation/Flow]
        Concurrency[Concurrency<br/>Lock/Thread]
        Noise[Noise Reduction<br/>FP Filtering]
    end
    
    subgraph Layer4["Layer 4: Semantics"]
        LangDetect[Language Detector]
        ZoneClass[Zone Classifier<br/>64% skip]
        NoiseFilter[Noise Filter]
        SemEngine[Semantic Engine]
    end
    
    subgraph Layer3["Layer 3: Dataflow"]
        DFG[Data Flow Graph]
        PathCond[Path Condition]
        FuncSum[Function Summary]
        Guard[Guard Propagation]
    end
    
    subgraph Layer2["Layer 2: IR Abstraction"]
        Loader[IR Loader<br/>inkwell]
        SafeWrap[Safe Wrapper]
        IRView[IR View]
        DebugInfo[Debug Info]
    end
    
    subgraph Layer1["Layer 1: Core"]
        Error[Error Types<br/>thiserror]
        Diag[Diagnostics<br/>miette]
        Fact[Fact Store<br/>dashmap]
        Profiler[Profiler<br/>tracing]
        MemPool[Memory Pool<br/>bumpalo]
    end
    
    subgraph External["External Dependencies"]
        LLVM[LLVM 22<br/>inkwell]
        Zlib[zlib<br/>libz-sys]
    end
    
    CLI --> Pipeline
    Formatter --> Pipeline
    LSP --> Pipeline
    
    Pipeline --> Scheduler
    Scheduler --> Foundation
    Scheduler --> FFI
    Scheduler --> Memory
    Scheduler --> Taint
    Scheduler --> Concurrency
    Scheduler --> Noise
    
    Foundation --> LangDetect
    FFI --> LangDetect
    Memory --> LangDetect
    Taint --> LangDetect
    Concurrency --> LangDetect
    Noise --> NoiseFilter
    
    LangDetect --> ZoneClass
    ZoneClass --> NoiseFilter
    NoiseFilter --> SemEngine
    
    SemEngine --> DFG
    DFG --> PathCond
    DFG --> FuncSum
    DFG --> Guard
    
    PathCond --> Loader
    FuncSum --> Loader
    Guard --> Loader
    
    Loader --> SafeWrap
    SafeWrap --> IRView
    IRView --> DebugInfo
    
    DebugInfo --> Error
    DebugInfo --> Diag
    DebugInfo --> Fact
    DebugInfo --> Profiler
    DebugInfo --> MemPool
    
    Loader --> LLVM
    Loader --> Zlib
    
    style Layer7 fill:#e1f5ff
    style Layer6 fill:#fff4e1
    style Layer5 fill:#ffe1f5
    style Layer4 fill:#e1ffe1
    style Layer3 fill:#fff1e1
    style Layer2 fill:#f1e1ff
    style Layer1 fill:#ffe1e1
    style External fill:#f0f0f0
```

## 🔄 数据流图

```mermaid
flowchart TD
    Input[IR File<br/>.ll/.bc] --> Load[IR Loader]
    Load --> Parse[Parse & Validate]
    Parse --> BuildIR[Build IR View]
    
    BuildIR --> Detect[Language Detection]
    Detect --> Classify[Zone Classification]
    
    Classify --> Schedule{Schedule Passes}
    
    Schedule --> Foundation[Foundation Passes]
    Schedule --> Analysis[Analysis Passes]
    
    Foundation --> CFG[CFG Construction]
    Foundation --> DFG[DFG Construction]
    Foundation --> Alias[Alias Analysis]
    
    Analysis --> FFI[FFI Analysis]
    Analysis --> Memory[Memory Safety]
    Analysis --> Taint[Taint Propagation]
    Analysis --> Concurrency[Concurrency Analysis]
    
    CFG --> Aggregate[Aggregate Results]
    DFG --> Aggregate
    Alias --> Aggregate
    FFI --> Aggregate
    Memory --> Aggregate
    Taint --> Aggregate
    Concurrency --> Aggregate
    
    Aggregate --> Filter[Noise Filtering]
    Filter --> Diag[Generate Diagnostics]
    Diag --> Output[Format Output<br/>JSON/SARIF]
    
    style Input fill:#e1f5ff
    style Output fill:#e1f5ff
    style Schedule fill:#fff4e1
    style Aggregate fill:#fff4e1
```

## 📦 模块依赖图

```mermaid
graph LR
    CLI[omniscope-cli] --> Pipeline[omniscope-pipeline]
    Pipeline --> Pass[omniscope-pass]
    Pass --> Semantics[omniscope-semantics]
    Pass --> Types[omniscope-types]
    Semantics --> Dataflow[omniscope-dataflow]
    Dataflow --> IR[omniscope-ir]
    Dataflow --> Types
    IR --> Core[omniscope-core]
    Semantics --> Registry[omniscope-registry]
    Registry --> Core
    
    style CLI fill:#e1f5ff
    style Pipeline fill:#fff4e1
    style Pass fill:#ffe1f5
    style Semantics fill:#e1ffe1
    style Dataflow fill:#fff1e1
    style IR fill:#f1e1ff
    style Core fill:#ffe1e1
    style Registry fill:#f0f0f0
    style Types fill:#f0f0f0
```

## 🎯 Pass 系统架构

```mermaid
graph TB
    subgraph PassManager["Pass Manager"]
        Register[Register Passes]
        Resolve[Resolve Dependencies]
        Schedule[Schedule Execution]
        Execute[Execute Passes]
    end
    
    subgraph FoundationPasses["Foundation Passes"]
        CFG[CFG Pass]
        DFG[DFG Pass]
        Alias[Alias Pass]
        CallGraph[Call Graph Pass]
    end
    
    subgraph AnalysisPasses["Analysis Passes"]
        FFIBoundary[FFI Boundary]
        FFISafety[FFI Safety]
        PointerOwner[Pointer Ownership]
        PtrLifetime[Pointer Lifetime]
        TaintProp[Taint Propagation]
        BufferOverflow[Buffer Overflow]
        LockAnalysis[Lock Analysis]
        ThreadCrossing[Thread Crossing]
        ABIMismatch[ABI Mismatch]
        RustFFI[Rust FFI Auditor]
    end
    
    subgraph FilterPasses["Filter Passes"]
        NoiseReduction[Noise Reduction]
        FPFilter[False Positive Filter]
        IssueSuppress[Issue Suppression]
    end
    
    Register --> Resolve
    Resolve --> Schedule
    Schedule --> Execute
    
    Execute --> CFG
    Execute --> DFG
    Execute --> Alias
    Execute --> CallGraph
    
    CFG --> FFIBoundary
    CFG --> PointerOwner
    DFG --> TaintProp
    Alias --> PtrLifetime
    CallGraph --> RustFFI
    
    FFIBoundary --> FFISafety
    PointerOwner --> BufferOverflow
    TaintProp --> LockAnalysis
    PtrLifetime --> ThreadCrossing
    
    FFISafety --> NoiseReduction
    BufferOverflow --> NoiseReduction
    LockAnalysis --> NoiseReduction
    ThreadCrossing --> NoiseReduction
    ABIMismatch --> NoiseReduction
    RustFFI --> NoiseReduction
    
    NoiseReduction --> FPFilter
    FPFilter --> IssueSuppress
    
    style PassManager fill:#e1f5ff
    style FoundationPasses fill:#fff4e1
    style AnalysisPasses fill:#ffe1f5
    style FilterPasses fill:#e1ffe1
```

## 🔍 语义分析流程

```mermaid
flowchart TD
    Func[Function] --> Detect{Detect Language}
    
    Detect -->|C/C++| Cpp[C++ Semantics]
    Detect -->|Rust| Rust[Rust Semantics]
    Detect -->|Zig| Zig[Zig Semantics]
    Detect -->|Go| Go[Go Semantics]
    Detect -->|Python| Python[Python Semantics]
    Detect -->|Java| Java[Java Semantics]
    
    Cpp --> Classify[Classify Zone]
    Rust --> Classify
    Zig --> Classify
    Go --> Classify
    Python --> Classify
    Java --> Classify
    
    Classify --> Safe{Safe Zone?}
    Safe -->|Yes| Skip[Skip Analysis<br/>64% optimization]
    Safe -->|No| Risky[Analyze Risky Zone]
    
    Risky --> Filter[Apply Noise Filters]
    Filter --> NameFilter[Name-based Filter]
    Filter --> PathFilter[Path-based Filter]
    Filter --> BehaviorFilter[Behavior-based Filter]
    
    NameFilter --> Resolve[Resolve Semantics]
    PathFilter --> Resolve
    BehaviorFilter --> Resolve
    
    Resolve --> Memory[Build Memory Graph]
    Memory --> Result[Semantic Result]
    
    style Detect fill:#e1f5ff
    style Classify fill:#fff4e1
    style Safe fill:#ffe1f5
    style Filter fill:#e1ffe1
```

## 🧵 并发执行模型

```mermaid
graph TB
    subgraph Sequential["Sequential Execution"]
        P1[Pass 1] --> P2[Pass 2]
        P2 --> P3[Pass 3]
        P3 --> P4[Pass 4]
    end
    
    subgraph Parallel["Parallel Execution (rayon)"]
        PP1[Pass 1] --> PP3[Pass 3]
        PP2[Pass 2] --> PP4[Pass 4]
    end
    
    subgraph Scheduler["Pass Scheduler"]
        Analyze[Analyze Dependencies]
        Build[Build Dependency Graph]
        Topo[Topological Sort]
        Group[Group by Level]
        Exec[Execute by Level]
    end
    
    Analyze --> Build
    Build --> Topo
    Topo --> Group
    Group --> Exec
    
    Exec --> Level1[Level 1<br/>Independent Passes]
    Level1 --> Level2[Level 2<br/>Dependent Passes]
    Level2 --> Level3[Level 3<br/>Final Passes]
    
    Level1 -.->|rayon| Parallel
    Level2 -.->|rayon| Parallel
    Level3 -.->|rayon| Parallel
    
    style Sequential fill:#ffe1e1
    style Parallel fill:#e1ffe1
    style Scheduler fill:#e1f5ff
```

## 📊 性能优化策略

```mermaid
graph TB
    subgraph CompileTime["Compile-time Optimization"]
        LTO[Link Time Optimization<br/>lto = fat]
        CodeGen[Single Codegen Unit<br/>codegen-units = 1]
        OptLevel[Optimization Level 3<br/>opt-level = 3]
        Strip[Strip Symbols<br/>strip = true]
    end
    
    subgraph RunTime["Runtime Optimization"]
        Parallel[Data Parallelism<br/>rayon]
        MemPool[Memory Pooling<br/>bumpalo]
        ConcMap[Concurrent HashMap<br/>dashmap]
        ZoneSkip[Zone Skipping<br/>64% reduction]
        Lazy[Lazy Evaluation<br/>once_cell]
    end
    
    subgraph Memory["Memory Optimization"]
        SmallVec[Small Vector<br/>smallvec]
        BitVec[Bit Vector<br/>bitvec]
        Arena[Arena Allocator<br/>typed-arena]
        Cache[Caching<br/>lru]
    end
    
    CompileTime --> Fast[Fast Binary]
    RunTime --> Fast
    Memory --> LowMem[Low Memory]
    
    Fast --> Perf[High Performance]
    LowMem --> Perf
    
    style CompileTime fill:#e1f5ff
    style RunTime fill:#fff4e1
    style Memory fill:#ffe1f5
    style Perf fill:#e1ffe1
```

## 🛡️ 安全保证

```mermaid
graph TB
    subgraph TypeSafety["Type Safety"]
        Strong[Strong Type System]
        Generic[Generic Constraints]
        Trait[Trait Bounds]
    end
    
    subgraph MemorySafety["Memory Safety"]
        Owner[Ownership System]
        Borrow[Borrow Checker]
        Lifetime[Lifetime Annotations]
    end
    
    subgraph ThreadSafety["Thread Safety"]
        Send[Send Trait]
        Sync[Sync Trait]
        Arc[Arc/Mutex]
    end
    
    subgraph ErrorSafety["Error Safety"]
        Result[Result Type]
        ErrorProp[Error Propagation<br/>? operator]
        NoPanic[No Unchecked Exceptions]
    end
    
    TypeSafety --> Safe[Safe Code]
    MemorySafety --> Safe
    ThreadSafety --> Safe
    ErrorSafety --> Safe
    
    Safe --> NoUB[No Undefined Behavior]
    NoUB --> Reliable[Reliable Software]
    
    style TypeSafety fill:#e1f5ff
    style MemorySafety fill:#fff4e1
    style ThreadSafety fill:#ffe1f5
    style ErrorSafety fill:#e1ffe1
    style Reliable fill:#f1e1ff
```

## 🔄 CI/CD 流程

```mermaid
flowchart TD
    Commit[Git Commit] --> Lint[Run Clippy]
    Lint --> Format[Check Formatting]
    Format --> Test[Run Tests]
    Test --> Bench[Run Benchmarks]
    Bench --> Coverage[Check Coverage]
    
    Coverage --> Doc[Generate Docs]
    Doc --> Build[Build Release]
    Build --> Package[Package Binary]
    
    Package --> Integration[Integration Tests]
    Integration --> E2E[E2E Tests]
    
    E2E --> Publish{Publish?}
    Publish -->|Yes| CratesIO[Publish to crates.io]
    Publish -->|Yes| GitHub[GitHub Release]
    Publish -->|No| Skip[Skip]
    
    style Commit fill:#e1f5ff
    style Publish fill:#fff4e1
    style CratesIO fill:#e1ffe1
    style GitHub fill:#e1ffe1
```

## 📈 性能对比

```mermaid
graph LR
    subgraph ZigVersion["Zig Version"]
        Z1[Compile: ~10s]
        Z2[Incremental: 1-3s]
        Z3[Runtime: Baseline]
        Z4[Memory: Baseline]
    end
    
    subgraph RustVersion["Rust Version"]
        R1[Compile: 2-5min]
        R2[Incremental: 10-30s]
        R3[Runtime: Same or Better]
        R4[Memory: Same or Lower]
    end
    
    Z1 -->|"12-30x slower"| R1
    Z2 -->|"5-10x slower"| R2
    Z3 -->|"≈"| R3
    Z4 -->|"≤"| R4
    
    style ZigVersion fill:#e1f5ff
    style RustVersion fill:#fff4e1
```

## 🎯 关键指标

| 指标 | 目标值 | 说明 |
|------|--------|------|
| **分析速度** | > 10K LOC/s | 每秒分析代码行数 |
| **内存占用** | < 500MB | 单次分析最大内存 |
| **准确率** | > 95% | 真阳性 / (真阳性 + 假阳性) |
| **召回率** | > 90% | 真阳性 / (真阳性 + 假阴性) |
| **编译时间** | < 5min | 首次编译（release） |
| **增量编译** | < 30s | 修改后重新编译 |
| **测试覆盖率** | > 80% | 代码覆盖率 |
| **Zone 跳过率** | > 60% | 安全区域跳过比例 |

---

## 📝 使用说明

### 查看架构图
1. 将上述 Mermaid 代码复制到支持 Mermaid 的编辑器
2. 推荐工具：
   - VSCode + Mermaid 插件
   - GitHub Markdown 预览
   - Mermaid Live Editor: https://mermaid.live/

### 导出为图片
```bash
# 使用 mermaid-cli
npm install -g @mermaid-js/mermaid-cli
mmdc -i ARCHITECTURE_DIAGRAM.md -o architecture.png
```

### 在文档中使用
- GitHub/GitLab 自动渲染 Mermaid
- 需要确保 Markdown 文件扩展名为 `.md`
