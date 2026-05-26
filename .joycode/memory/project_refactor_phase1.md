---
name: project_refactor_phase1
description: OmniScope-rs 架构重构 Phase 0-1 完成状态
type: project
---

OmniScope-rs 已完成架构重构的 Phase 0 和 Phase 1。

**Why:** 按照 ARCHITECTURE_ADJUSTMENT.md 的规划，用 Resource Family 替代语言匹配模型。

**How to apply:** 
- Phase 0 已完成：`make check` = 0 errors, `cargo test` = all pass
- Phase 1 已完成：在 `omniscope-types` 中添加了 6 个新核心类型文件（resource_family.rs, pointer_contract.rs, escape.rs, effect.rs, evidence.rs），在 `omniscope-semantics` 中添加了 resource 模块（family_registry, family_inference, summary, summary_inference, ownership_state, escape）
- FamilyRegistry 包含 13 个内置 family，50+ 个符号映射
- 测试矩阵覆盖了文档要求的全部场景（malloc/free safe, malloc/delete mismatch, __rust_alloc/free mismatch, Python/JNI/C# 等）
- 旧代码保留为 fallback，新旧并行过渡
- 下一步：Phase 2（FunctionSummary 替换 + SummaryStore 共享）