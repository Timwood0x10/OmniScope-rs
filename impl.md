P0 — IssueGate 补齐 Leak 类 SRT 抑制（预计 FP -3~5）

issue_gate.rs 中 ConditionalLeak/DefiniteLeak/OwnershipEscapeLeak 走到 _ => {} 分支，零抑制
应新增抑制信号：
CppDestructor / CppUniquePtr → C++ RAII 自动释放，非 leak
GoDeferCleanup / GoFinalizer → Go defer 清理，非 leak
RaiiDropRelease → Rust/RAII drop 已释放，非 leak
RuntimeInternal → 运行时内部包装器（如 heap.c_allocator_impl），非 leak
风险极低：只是增加 SRT 门控，不影响 TP 检测
P1 — NoiseReduction Layer 1 → SRT 迁移

noise_reduction.rs safe_patterns 硬编码16个字符串，扩展性差
将 heap.c_allocator_impl 等已可被 SemanticKind::RuntimeInternal 覆盖的模式从 Layer 1 迁移到 Layer 2（SRT 检测器）
Layer 1 降级为纯快速预过滤，权威判断由 SRT 负责
收益：架构简化，新增抑制模式只需添加 SRT 检测器，无需改 safe_patterns
P2 — 跨函数 FIFO 配对扩展（预计 FN -2~3）

当前 
contract_graph_builder
 按 (func_id, family) 分组
不同函数的 new[] + free 无法配对 → 误报 CrossFamilyFree
解决方案：在 RawFactCollector 阶段记录跨函数的 acquire/release 事实，ContractGraph 支持跨函数 instance 边
二、性能提升（3个方案，按收益排序）
P0 — InstCache 指令缓存层（预计耗时 -40~50s）

perf_analysis.md 详细方案：单次遍历缓存 opcode/num_operands/callee_name_hash/flags
消除 ~1900万次 FFI 调用（减少97%），预估 100s → 50-60s
注意：这是 Zig 侧实现（src/ir/inst_cache.zig），不是 Rust 侧
P1 — Pass 内部遍历合并（预计耗时 -23s）

cross_lang_dataflow 有5次独立全量遍历，合并为1次
pointer-ownership 调用 ownership_analysis 有2次遍历，合并为1次
预估节省 23% 时间
P2 — 独立 Pass 并行化（预计耗时 -5~10s）

RaiiDrop / InteriorMutability / HeapProvenance / BorrowEscape / WriteToImmutable 这5个 pass 互相独立
可并行执行，预估节省 5-10% 时间
复杂度最高，需改造 Pipeline 执行器
三、建议执行顺序
IssueGate Leak 抑制（Rust 侧，1-2h，精度收益最大）
InstCache（Zig 侧，性能收益最大，需先确认 Zig 侧架构）
NoiseReduction 迁移（Rust 侧，架构改善）
Pass 合并（Zig 侧，性能改善）
跨函数 FIFO / 并行化（长期方向）