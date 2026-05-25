# OmniScope-RS 重构方案总结

> **项目目标**: 用 Rust 1:1 复刻 OmniScope (Zig)，实现更强大的跨语言 FFI 安全审计工具

对标： [Zig 版 OmniScope](https://github.com/Timwood0x10/OmniScope/tree/dev)

## 📚 文档导航

| 文档 | 说明 | 重要性 |
|------|------|--------|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | 系统架构设计 | ⭐⭐⭐⭐⭐ |
| [ARCHITECTURE_DIAGRAM.md](./ARCHITECTURE_DIAGRAM.md) | 可视化架构图 | ⭐⭐⭐⭐ |
| [DEPENDENCIES.md](./DEPENDENCIES.md) | 依赖和文件结构 | ⭐⭐⭐⭐⭐ |
| [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) | 详细实施计划 | ⭐⭐⭐⭐⭐ |

## 🎯 核心设计亮点

### 1. **分层架构 (7 层)**
```
Layer 7: CLI & Output
Layer 6: Pipeline Orchestration
Layer 5: Analysis Pass System (25+ passes)
Layer 4: Semantic Analysis Engine
Layer 3: Dataflow Engine
Layer 2: IR Abstraction Layer
Layer 1: Core Infrastructure
```

### 2. **功能对等**
- ✅ 所有 Zig 版本功能都已规划
- ✅ 25+ 分析 pass 完整复刻
- ✅ 7 种语言支持 (C/C++/Rust/Zig/Go/Python/Java)
- ✅ Zone Classification (64% 代码跳过优化)

### 3. **性能优化**
- ✅ 并行分析 (rayon)
- ✅ 内存池 (bumpalo)
- ✅ 并发数据结构 (dashmap)
- ✅ 增量分析
- ✅ Zone Classification

### 4. **安全保证**
- ✅ 类型安全 (编译期检查)
- ✅ 内存安全 (所有权系统)
- ✅ 线程安全 (Send + Sync)
- ✅ 错误安全 (Result<T, E>)

## 📊 关键指标对比

| 指标 | Zig 版本 | Rust 版本 (预估) | 变化 |
|------|---------|-----------------|------|
| **代码行数** | 7.5 万 | 9-10 万 | +20-33% |
| **首次编译** | ~10 秒 | 2-5 分钟 | 慢 12-30 倍 |
| **增量编译** | 1-3 秒 | 10-30 秒 | 慢 5-10 倍 |
| **运行性能** | 基准 | 持平或更优 | 无显著差异 |
| **内存占用** | 基准 | 持平或更低 | 无显著差异 |
| **类型安全** | 运行时 | 编译期 | ✅ 更早发现错误 |
| **并发安全** | 手动保证 | 编译期检查 | ✅ 无数据竞争 |
| **生态成熟度** | 较小 | 成熟 | ✅ 更多库选择 |
| **IDE 支持** | 有限 | rust-analyzer | ✅ 更好体验 |

## 🚀 实施路线图

### Phase 1: 核心基础设施 (2 周)
- 项目骨架
- 错误类型系统
- 诊断系统
- Fact 系统

### Phase 2: IR 抽象层 (2 周)
- LLVM IR 加载
- 安全包装器
- IR 视图抽象

### Phase 3: 数据流引擎 (3 周)
- 数据流图
- 路径敏感分析
- 函数摘要

### Phase 4: 语义分析引擎 (3 周)
- 语言检测
- 区域分类
- 噪声过滤

### Phase 5: 分析 Pass 系统 (6 周)
- 25+ 分析 pass
- Pass 管理器
- 并行执行

### Phase 6: Pipeline 编排 (2 周)
- Pass 调度
- 结果聚合

### Phase 7: CLI & 输出 (2 周)
- 命令行接口
- 输出格式化
- LSP 服务器

**总计**: 约 20 周 (5 个月)

## 🎨 技术栈

### 核心依赖
- **inkwell**: LLVM 22 绑定
- **rayon**: 数据并行
- **dashmap**: 并发 HashMap
- **bumpalo**: Arena 分配器
- **thiserror**: 错误类型定义
- **miette**: 美观错误报告
- **clap**: CLI 解析
- **serde**: 序列化

### 开发工具
- **rust-analyzer**: IDE 支持
- **clippy**: 代码检查
- **rustfmt**: 代码格式化
- **criterion**: 性能测试
- **proptest**: 属性测试

## 📈 预期收益

### 相比 Zig 版本的优势

1. **更早发现错误**
   - 编译期类型检查
   - 所有权系统防止内存错误
   - 借用检查器防止数据竞争

2. **更好的开发体验**
   - rust-analyzer 提供强大的 IDE 支持
   - 自动补全、类型提示、重构
   - 内联错误提示

3. **更成熟的生态**
   - 丰富的第三方库
   - 活跃的社区支持
   - 完善的文档

4. **更安全的并发**
   - 编译期并发安全检查
   - 无需手动保证
   - 无数据竞争

### 需要接受的代价

1. **编译速度慢**
   - 首次编译 2-5 分钟
   - 增量编译 10-30 秒
   - 需要优化编译流程

2. **代码量增加**
   - 生命周期标注
   - 错误处理更冗长
   - 约 20-30% 代码增加

3. **学习曲线**
   - 所有权和借用概念
   - 生命周期标注
   - trait 系统

## 🎯 成功标准

### 功能完整性
- ✅ 所有 Zig 功能都已实现
- ✅ 分析结果一致
- ✅ 支持所有语言

### 性能指标
- ✅ 分析速度 ≥ Zig 版本
- ✅ 内存占用 ≤ Zig 版本
- ✅ 准确率 > 95%
- ✅ 召回率 > 90%

### 质量保证
- ✅ 测试覆盖率 > 80%
- ✅ 无 clippy 警告
- ✅ 文档完整

### 易用性
- ✅ CLI 友好
- ✅ 错误信息清晰
- ✅ 文档详细

## 🚨 风险与缓解

### 风险 1: LLVM 绑定兼容性
- **风险**: inkwell 对 LLVM 22 支持不完善
- **缓解**: 使用稳定 LLVM 版本，必要时降级

### 风险 2: 编译时间过长
- **风险**: 影响开发效率
- **缓解**: 
  - 增量编译
  - 缓存中间结果
  - 使用 sccache

### 风险 3: 内存占用过高
- **风险**: 大项目分析内存不足
- **缓解**:
  - 内存池优化
  - 流式处理
  - 增量分析

### 风险 4: 并发安全问题
- **风险**: 数据竞争导致未定义行为
- **缓解**:
  - 严格使用 Send + Sync
  - 充分测试
  - 使用 ThreadSanitizer

## 📝 下一步行动

### 立即开始
1. ✅ 阅读所有设计文档
2. ✅ 理解架构和模块划分
3. ✅ 熟悉依赖选择

### Phase 1 启动
1. 创建 Cargo workspace
2. 配置所有依赖
3. 实现核心基础设施
4. 编写单元测试

### 持续改进
1. 定期性能测试
2. 对比 Zig 版本结果
3. 优化编译时间
4. 完善文档


### 输出格式


```shell
═══════════════════════════════════════════════════════════════
  OmniScope — Cross-Language Memory Safety Analysis
═══════════════════════════════════════════════════════════════

Coverage
───────────────────────────────────────────────────────────────
  Functions:          15
  Issues detected:    5
  Actionable:         3

Findings
───────────────────────────────────────────────────────────────
  High:     3
  Low:      2

  [HIGH] OMI-001
    Type:       invalid_free
    Confidence: MEDIUM (85%)
    Function:   tc2_c_malloc_cpp_delete
    Detail:     operator_delete() called on non-heap source pointer (confidence: 0.85% [cross-FFI alias detected])
    ┌─ Detection Path ──
    ├── [1] Free called on non-heap pointer
    ├── [2] Pointer origin: from malloc()
    └── [3] Passed to operator_delete() which requires heap-allocated pointer  ✗
    └──────────────────
    ┌─ Call Graph ──
    ├── Free called on non-heap pointer
    ├── Pointer origin: from malloc()
    └── Passed to operator_delete() which requires heap-allocated pointer
    └─────────────

  [HIGH] OMI-002
    Type:       invalid_free
    Confidence: MEDIUM (85%)
    Function:   tc7_mixed_ccpp_ffi
    Detail:     operator_delete() called on non-heap source pointer (confidence: 0.85% [cross-FFI alias detected])
    ┌─ Detection Path ──
    ├── [1] Free called on non-heap pointer
    ├── [2] Pointer origin: from malloc()
    └── [3] Passed to operator_delete() which requires heap-allocated pointer  ✗
    └──────────────────
    ┌─ Call Graph ──
    ├── Free called on non-heap pointer
    ├── Pointer origin: from malloc()
    └── Passed to operator_delete() which requires heap-allocated pointer
    └─────────────

  [LOW] OMI-003
    Type:       memory_leak
    Confidence: MEDIUM (70%)
    Function:   tc2_c_malloc_cpp_delete
    Detail:     Memory leak: 1 malloc/calloc without matching free in tc2_c_malloc_cpp_delete (CWE-401)

  [HIGH] OMI-004
    Type:       null_dereference
    Confidence: MEDIUM (85%)
    Function:   tc2_c_malloc_cpp_delete
    Detail:     Potential null dereference: pointer used without null check

  [LOW] OMI-005
    Type:       memory_leak
    Confidence: HEURISTIC (50%)
    Function:   tc7_mixed_ccpp_ffi
    Detail:     Potential memory leak: heap allocation in tc7_mixed_ccpp_ffi() was never freed

Summary
───────────────────────────────────────────────────────────────
  ⚡ 3 high-severity issue(s) found.
  Analysis time: 16 ms
  (use --verbose for pipeline metrics, --debug for full trace)
═══════════════════════════════════════════════════════════════
```

## 🎉 总结

这个重构方案确保：

- **功能完整**: 1:1 复刻 Zig 版本，不遗漏任何功能
- **架构清晰**: 7 层分层设计，职责明确
- **性能优异**: 利用 Rust 特性实现更优性能
- **质量可靠**: 测试驱动开发，严格质量保证
- **易于维护**: 模块化设计，文档完善

**最终目标**: 打造一个比 Zig 版本更强大、更安全、更易用的跨语言 FFI 安全审计工具！

---

## 📞 联系方式

如有疑问或建议，请：
1. 提交 GitHub Issue
2. 发送邮件到项目维护者
3. 在项目 Discord/Slack 讨论

**让我们一起打造最好的静态分析工具！** 🚀
