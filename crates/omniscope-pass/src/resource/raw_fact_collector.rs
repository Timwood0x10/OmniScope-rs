//! Raw fact collector for resource contract analysis.
//!
//! Collects raw facts from IR about allocation, deallocation, and
//! pointer operations. These facts feed into the summary builder
//! and contract graph builder.
//!
//! This pass reads the `IRModule` from the pass context (key `"ir_module"`)
//! and extracts alloc/dealloc/FFI call facts from the IR's call instructions
//! and declarations.

use omniscope_core::{FactKind, Result};
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

    /// Extracts raw facts from an IRModule by scanning its call instructions
    /// and declarations against the FamilyRegistry.
    fn collect_from_ir(module: &IRModule) -> Vec<RawResourceFact> {
        let registry = omniscope_semantics::FamilyRegistry::new();
        let mut facts = Vec::new();

        // Stable function ID assignment: each unique function name gets the
        // same func_id across all calls, so the same function is never
        // treated as different functions (which would cause PathSensitiveLeak
        // false positives).
        let mut func_name_to_id: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        let mut next_func_id: u64 = 0;

        // Helper: get or assign a stable func_id for a function name.
        let mut get_func_id = |name: &str| -> u64 {
            if let Some(&id) = func_name_to_id.get(name) {
                id
            } else {
                let id = next_func_id;
                next_func_id = next_func_id.wrapping_add(1);
                func_name_to_id.insert(name.to_string(), id);
                id
            }
        };

        // Scan all call instructions for known alloc/dealloc symbols
        for call in &module.calls {
            // Strip LLVM name decoration: @name → name
            let callee_name = call.callee.trim_start_matches('@');
            let caller_name = call.caller.trim_start_matches('@');

            if let Some(entry) = registry.lookup(callee_name) {
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

                // Use the CALLER's stable func_id so that acquire/release
                // facts within the same function share the same ID.
                let func_id = if caller_name.is_empty() {
                    get_func_id(callee_name)
                } else {
                    get_func_id(caller_name)
                };

                facts.push(RawResourceFact {
                    function: func_id,
                    function_name: callee_name.to_string(),
                    caller_name: caller_name.to_string(),
                    family: Some(entry.family_id),
                    is_acquire,
                    contract,
                    arg_index: Some(0),
                });
            }
        }

        // Scan declarations for external alloc/dealloc symbols
        for name in module.declarations.keys() {
            let sym_name = name.trim_start_matches('@');
            if let Some(entry) = registry.lookup(sym_name) {
                // Avoid duplicates from calls
                if facts.iter().any(|f| f.function_name == sym_name) {
                    continue;
                }
                let is_acquire = matches!(
                    entry.effect,
                    omniscope_semantics::SymbolEffect::Acquire
                        | omniscope_semantics::SymbolEffect::Retain
                        | omniscope_semantics::SymbolEffect::Reclaim
                );
                let func_id = get_func_id(sym_name);
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

        // Also scan function definitions for calls within them
        for func_name in module.functions.keys() {
            // Check if the function itself is a known symbol
            if let Some(entry) = registry.lookup(func_name) {
                if facts.iter().any(|f| f.function_name == func_name.as_str()) {
                    continue;
                }
                let is_acquire = matches!(
                    entry.effect,
                    omniscope_semantics::SymbolEffect::Acquire
                        | omniscope_semantics::SymbolEffect::Retain
                        | omniscope_semantics::SymbolEffect::Reclaim
                );
                let func_id = get_func_id(func_name);
                facts.push(RawResourceFact {
                    function: func_id,
                    function_name: func_name.clone(),
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

        let mut raw_facts: Vec<RawResourceFact> = Vec::new();

        // First: try to extract facts from the IRModule in the context
        let ir_module: Option<IRModule> = ctx.get("ir_module");
        tracing::debug!(
            "RawFactCollector: ir_module present = {}",
            ir_module.is_some()
        );
        if let Some(ref module) = ir_module {
            raw_facts = Self::collect_from_ir(module);
            tracing::debug!(
                "RawFactCollector: collected {} facts from IR",
                raw_facts.len()
            );
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

        // Keep the IRModule in context for downstream passes
        if let Some(module) = ir_module {
            ctx.store("ir_module", module);
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
        assert_eq!(pass.name(), "RawFactCollector");
        assert_eq!(pass.kind(), PassKind::Foundation);
        assert!(pass.dependencies().is_empty());
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

        let facts = RawFactCollectorPass::collect_from_ir(&module);
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
