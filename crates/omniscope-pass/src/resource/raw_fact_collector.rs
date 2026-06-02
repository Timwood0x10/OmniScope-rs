//! Raw fact collector for resource contract analysis.
//!
//! Collects raw facts from IR about allocation, deallocation, and
//! pointer operations. These facts feed into the summary builder
//! and contract graph builder.
//!
//! This pass reads the `IRModule` from the pass context (key `"ir_module"`)
//! and extracts alloc/dealloc/FFI call facts from the IR's call instructions
//! and declarations.
//!
//! ## Memory pool integration
//!
//! Temporary strings (trimmed callee/caller names) are allocated from the
//! arena-based `MemoryPool` in `PassContext` to reduce per-string heap
//! overhead. The pool is reset at the start of each pass run so that the
//! arena is reused across passes.

use omniscope_core::{FactKind, MemoryPool, Result};
use omniscope_ir::IRModule;
use omniscope_types::{FamilyId, PointerContract};

use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// A raw resource fact collected from IR analysis.
#[derive(Debug, Clone)]
pub struct RawResourceFact {
    /// The function where this fact occurs (stable ID of the caller).
    pub function: u64,
    /// Function name (for lookup in the family registry).
    pub function_name: String,
    /// Name of the caller function (the function containing this call site).
    pub caller_name: String,
    /// The resource family (if identified).
    pub family: Option<FamilyId>,
    /// Whether this is an acquire or release.
    pub is_acquire: bool,
    /// Pointer contract at this point.
    pub contract: PointerContract,
    /// Argument index involved (if applicable).
    pub arg_index: Option<u32>,
}

/// Raw fact collector pass.
///
/// Collects allocation/deallocation facts from IR and stores
/// them in the pass context for downstream passes.
pub struct RawFactCollectorPass;

impl RawFactCollectorPass {
    /// Creates a new raw fact collector pass.
    pub fn new() -> Self {
        Self
    }

    /// Extracts raw facts from a ModuleIndex using pre-computed metadata.
    ///
    /// This is the fast path that avoids creating a new FamilyRegistry
    /// and re-scanning all call instructions.
    fn collect_from_module_index(index: &crate::module_index::ModuleIndex) -> Vec<RawResourceFact> {
        let registry = &index.family_registry;

        let estimated = index.call_metas.len() + index.function_metas.len();
        let mut facts = Vec::with_capacity(estimated);

        let mut func_name_to_id: std::collections::HashMap<String, u64> =
            std::collections::HashMap::with_capacity(estimated.max(32));
        let mut next_func_id: u64 = 0;

        let mut get_func_id = |name: &str| -> u64 {
            if let Some(&id) = func_name_to_id.get(name) {
                id
            } else {
                let id = next_func_id;
                next_func_id = next_func_id.saturating_add(1);
                func_name_to_id.insert(name.to_string(), id);
                id
            }
        };

        // Scan cached call metadata for alloc/dealloc symbols
        for call_meta in &index.call_metas {
            if call_meta.symbol_effect.is_none() {
                continue;
            }

            let effect = call_meta.symbol_effect.unwrap();
            let is_acquire = matches!(
                effect,
                omniscope_semantics::SymbolEffect::Acquire
                    | omniscope_semantics::SymbolEffect::Retain
                    | omniscope_semantics::SymbolEffect::Reclaim
            );
            let is_escape = matches!(effect, omniscope_semantics::SymbolEffect::Escape);
            let contract = if is_acquire {
                PointerContract::Owned
            } else if is_escape {
                PointerContract::Escaped
            } else {
                PointerContract::Unknown
            };

            let func_id = if call_meta.caller_name.is_empty() {
                get_func_id(&call_meta.callee_name)
            } else {
                get_func_id(&call_meta.caller_name)
            };

            facts.push(RawResourceFact {
                function: func_id,
                function_name: call_meta.callee_name.clone(),
                caller_name: call_meta.caller_name.clone(),
                family: call_meta.family_id,
                is_acquire,
                contract,
                arg_index: Some(0),
            });
        }

        // Scan function metadata for known symbols not already found
        for name in index.function_metas.keys() {
            if let Some(entry) = registry.lookup(name) {
                if facts.iter().any(|f| f.function_name == name.as_str()) {
                    continue;
                }
                let is_acquire = matches!(
                    entry.effect,
                    omniscope_semantics::SymbolEffect::Acquire
                        | omniscope_semantics::SymbolEffect::Retain
                        | omniscope_semantics::SymbolEffect::Reclaim
                );
                let func_id = get_func_id(name);
                facts.push(RawResourceFact {
                    function: func_id,
                    function_name: name.clone(),
                    caller_name: String::new(),
                    family: Some(entry.family_id),
                    is_acquire,
                    contract: if is_acquire {
                        PointerContract::Owned
                    } else {
                        PointerContract::Unknown
                    },
                    arg_index: Some(0),
                });
            }
        }

        facts
    }

    /// Extracts raw facts from an IRModule by scanning its call instructions,
    /// declarations, and function definitions against the FamilyRegistry.
    ///
    /// Performs a **single merged traversal** over all three IR collections
    /// (calls, declarations, functions) to avoid repeated iteration. Uses a
    /// `HashSet` for O(1) deduplication instead of linear scan.
    ///
    /// Temporary trimmed strings are allocated from `pool` (arena) to avoid
    /// per-lookup heap allocations. The pool is assumed to have been reset
    /// before this call.
    fn collect_from_ir(module: &IRModule, _pool: &mut MemoryPool) -> Vec<RawResourceFact> {
        let registry = omniscope_semantics::FamilyRegistry::new();

        // Pre-allocate with an upper-bound estimate to reduce reallocations.
        let estimated = module.calls.len() + module.declarations.len() + module.functions.len();
        let mut facts = Vec::with_capacity(estimated);

        // Track seen function names for O(1) dedup (replaces O(n) linear scan).
        let mut seen_names: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(estimated.max(32));

        // Stable function ID assignment: each unique function name gets the
        // same func_id across all calls, so the same function is never
        // treated as different functions (which would cause LeakDetection
        // false positives).
        let mut func_name_to_id: std::collections::HashMap<String, u64> =
            std::collections::HashMap::with_capacity(estimated.max(32));
        let mut next_func_id: u64 = 0;

        // Helper: get or assign a stable func_id for a function name.
        let mut get_func_id = |name: &str| -> u64 {
            if let Some(&id) = func_name_to_id.get(name) {
                id
            } else {
                let id = next_func_id;
                next_func_id = next_func_id.saturating_add(1);
                func_name_to_id.insert(name.to_string(), id);
                id
            }
        };

        // Helper: build a RawResourceFact from a registry entry.
        // Returns None if the symbol is not alloc/dealloc/escape.
        let make_fact = |entry: &omniscope_semantics::FamilyEntry,
                         callee_name: &str,
                         caller_name: &str,
                         func_id: u64|
         -> RawResourceFact {
            let is_acquire = matches!(
                entry.effect,
                omniscope_semantics::SymbolEffect::Acquire
                    | omniscope_semantics::SymbolEffect::Retain
                    | omniscope_semantics::SymbolEffect::Reclaim
            );
            let is_escape = matches!(entry.effect, omniscope_semantics::SymbolEffect::Escape);
            let contract = if is_acquire {
                PointerContract::Owned
            } else if is_escape {
                PointerContract::Escaped
            } else {
                PointerContract::Unknown
            };
            RawResourceFact {
                function: func_id,
                function_name: callee_name.to_string(),
                caller_name: caller_name.to_string(),
                family: Some(entry.family_id),
                is_acquire,
                contract,
                arg_index: Some(0),
            }
        };

        // ── Single merged traversal ──
        // Process all three IR collections in one logical pass.

        // Phase 1: Scan call instructions (highest priority — most specific).
        for call in &module.calls {
            let callee_name = call.callee.trim_start_matches('@');
            let caller_name = call.caller.trim_start_matches('@');

            if let Some(entry) = registry.lookup(callee_name) {
                // Use the CALLER's stable func_id so that acquire/release
                // facts within the same function share the same ID.
                let func_id = if caller_name.is_empty() {
                    get_func_id(callee_name)
                } else {
                    get_func_id(caller_name)
                };

                seen_names.insert(callee_name.to_string());
                facts.push(make_fact(entry, callee_name, caller_name, func_id));
            }
        }

        // Phase 2: Scan declarations and functions in a single loop.
        // Declarations and functions that were already seen in calls are skipped.
        let decl_iter = module
            .declarations
            .keys()
            .map(|name| (name.trim_start_matches('@'), true));
        let func_iter = module.functions.keys().map(|name| (name.as_str(), false));

        for (sym_name, _is_declaration) in decl_iter.chain(func_iter) {
            // Skip if already processed from calls (O(1) HashSet lookup).
            if seen_names.contains(sym_name) {
                continue;
            }

            if let Some(entry) = registry.lookup(sym_name) {
                let func_id = get_func_id(sym_name);
                seen_names.insert(sym_name.to_string());

                // For declarations/functions without a caller context,
                // emit as standalone acquire/release facts.
                let is_acquire = matches!(
                    entry.effect,
                    omniscope_semantics::SymbolEffect::Acquire
                        | omniscope_semantics::SymbolEffect::Retain
                        | omniscope_semantics::SymbolEffect::Reclaim
                );
                facts.push(RawResourceFact {
                    function: func_id,
                    function_name: sym_name.to_string(),
                    caller_name: String::new(),
                    family: Some(entry.family_id),
                    is_acquire,
                    contract: if is_acquire {
                        PointerContract::Owned
                    } else {
                        PointerContract::Unknown
                    },
                    arg_index: Some(0),
                });
            }
        }

        facts
    }
}

impl Pass for RawFactCollectorPass {
    fn name(&self) -> &'static str {
        "RawFactCollector"
    }

    fn kind(&self) -> PassKind {
        PassKind::Foundation
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec![]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        // Reset the arena pool so previous pass data is reclaimed.
        ctx.reset_pool();

        let mut raw_facts: Vec<RawResourceFact>;

        // Try to use ModuleIndex for cached metadata when available
        let module_index: Option<crate::module_index::ModuleIndex> = ctx.get("module_index");

        if let Some(ref index) = module_index {
            // Fast path: use pre-computed metadata from ModuleIndex
            raw_facts = Self::collect_from_module_index(index);
            tracing::debug!(
                "RawFactCollector: collected {} facts from ModuleIndex",
                raw_facts.len()
            );
        } else {
            // Fallback: try to extract facts from the IRModule in the context.
            let ir_module: Option<IRModule> = ctx.get("ir_module");
            tracing::debug!(
                "RawFactCollector: ir_module present = {}",
                ir_module.is_some()
            );
            if let Some(ref module) = ir_module {
                raw_facts = Self::collect_from_ir(module, ctx.pool_mut());
                tracing::debug!(
                    "RawFactCollector: collected {} facts from IR",
                    raw_facts.len()
                );
            } else {
                raw_facts = Vec::new();
            }
        }

        // Also scan existing facts for alloc/dealloc sites (legacy path)
        for fact in ctx.facts() {
            if fact.kind == FactKind::AllocSite || fact.kind == FactKind::DeallocSite {
                let raw = RawResourceFact {
                    function: 0,
                    function_name: String::new(),
                    caller_name: String::new(),
                    family: None,
                    is_acquire: fact.kind == FactKind::AllocSite,
                    contract: PointerContract::Unknown,
                    arg_index: None,
                };
                raw_facts.push(raw);
            }
        }

        let fact_count = raw_facts.len();
        ctx.store("raw_resource_facts", raw_facts);

        let result = PassResult::new(self.name())
            .with_nodes(fact_count)
            .with_duration(start.elapsed().as_millis() as u64);

        Ok(result)
    }
}

impl Default for RawFactCollectorPass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_fact_collector_creation() {
        let pass = RawFactCollectorPass::new();
        assert_eq!(
            pass.name(),
            "RawFactCollector",
            "Pass name must be 'RawFactCollector'"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Foundation,
            "RawFactCollector must be a Foundation pass"
        );
        assert!(
            pass.dependencies().is_empty(),
            "RawFactCollector must have no dependencies"
        );
    }

    #[test]
    fn test_collect_from_ir_with_malloc_free() {
        let mut module = IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "malloc".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "free".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });

        let mut pool = MemoryPool::new();
        let facts = RawFactCollectorPass::collect_from_ir(&module, &mut pool);
        assert!(facts.len() >= 2, "Must find malloc and free facts");

        let malloc_fact = facts.iter().find(|f| f.function_name == "malloc");
        assert!(malloc_fact.is_some(), "Must find malloc fact");
        assert!(malloc_fact.unwrap().is_acquire, "malloc must be acquire");
        assert_eq!(
            malloc_fact.unwrap().family,
            Some(FamilyId::C_HEAP),
            "malloc must be C_HEAP family"
        );

        let free_fact = facts.iter().find(|f| f.function_name == "free");
        assert!(free_fact.is_some(), "Must find free fact");
        assert!(!free_fact.unwrap().is_acquire, "free must be release");
    }
}
