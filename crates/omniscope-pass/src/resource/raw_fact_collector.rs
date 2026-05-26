//! Raw fact collector for resource contract analysis.
//!
//! Collects raw facts from IR about allocation, deallocation, and
//! pointer operations. These facts feed into the summary builder
//! and contract graph builder.

use omniscope_core::{FactKind, Result};
use omniscope_types::{FamilyId, PointerContract};

use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// A raw resource fact collected from IR analysis.
#[derive(Debug, Clone)]
pub struct RawResourceFact {
    /// The function where this fact occurs.
    pub function: u64,
    /// Function name (for lookup in the family registry).
    pub function_name: String,
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

        // Build the family registry and collect facts from
        // existing IR facts in the context.
        let _registry = omniscope_semantics::FamilyRegistry::new();
        let mut raw_facts: Vec<RawResourceFact> = Vec::new();

        // Scan existing facts for alloc/dealloc sites
        for fact in ctx.facts() {
            if fact.kind == FactKind::AllocSite || fact.kind == FactKind::DeallocSite {
                // In a full implementation, we would extract the function name
                // from the fact's location and look it up in the registry.
                // For now, we store the fact as-is.
                let raw = RawResourceFact {
                    function: 0,
                    function_name: String::new(),
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
        assert_eq!(pass.name(), "RawFactCollector");
        assert_eq!(pass.kind(), PassKind::Foundation);
        assert!(pass.dependencies().is_empty());
    }
}
