//! Interior mutability detection pass.
//!
//! This pass detects types that contain UnsafeCell<T> and other interior
//! mutability patterns to suppress false positive write-to-immutable issues.
//!
//! Based on R-2 pattern from bun_fp_reduction_plan.md:
//! - UnsafeCell<T> → Cell/RefCell/Mutex/RwLock/Atomic*/OnceLock/LazyLock
//! - Writing through &T is safe when type has interior mutability

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::Result;
use omniscope_ir::IRModule;
use omniscope_semantics::{SemanticKind, SemanticResolution, SemanticTree};

/// Interior mutability detection pass.
///
/// Analyzes IR to detect interior mutability patterns and add semantic
/// resolutions for downstream passes.
pub struct InteriorMutabilityPass;

impl InteriorMutabilityPass {
    /// Creates a new interior mutability detection pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for InteriorMutabilityPass {
    fn name(&self) -> &'static str {
        "InteriorMutability"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["RawFactCollector"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        // Get IR module for analysis
        let ir_module: Option<IRModule> = ctx.get("ir_module");
        let Some(module) = ir_module else {
            return Ok(PassResult::new(self.name())
                .with_issues(0)
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64));
        };

        let mut semantic_tree = SemanticTree::new();
        let mut nodes_analyzed = 0;

        // Analyze all calls for interior mutability patterns
        for call in &module.calls {
            nodes_analyzed += 1;

            let symbol = format!("{}->{}", call.caller, call.callee);

            // Detect interior mutability in caller/callee names
            self.detect_interior_mutability(
                &symbol,
                &call.caller,
                &call.callee,
                &mut semantic_tree,
            );
        }

        // Store semantic tree for downstream passes
        ctx.store("interior_mutability_tree", semantic_tree);

        Ok(PassResult::new(self.name())
            .with_issues(0) // This pass doesn't emit issues, only adds semantic info
            .with_nodes(nodes_analyzed)
            .with_duration(start.elapsed().as_millis() as u64))
    }
}

impl InteriorMutabilityPass {
    /// Detects interior mutability patterns and adds semantic resolutions.
    fn detect_interior_mutability(
        &self,
        symbol: &str,
        caller: &str,
        callee: &str,
        semantic_tree: &mut SemanticTree,
    ) {
        // Check caller for interior mutability types
        if self.has_interior_mutability(caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::InteriorMutability,
                confidence: 0.95,
                evidence: format!("Caller contains interior mutability type: {}", caller),
                pattern_id: "R-2",
            };
            semantic_tree.add_resolution(symbol, resolution);
        }

        // Check callee for interior mutability types
        if self.has_interior_mutability(callee) {
            let resolution = SemanticResolution {
                kind: SemanticKind::InteriorMutability,
                confidence: 0.90,
                evidence: format!("Callee contains interior mutability type: {}", callee),
                pattern_id: "R-2",
            };
            semantic_tree.add_resolution(symbol, resolution);
        }
    }

    /// Checks if a name contains interior mutability patterns.
    fn has_interior_mutability(&self, name: &str) -> bool {
        // Core interior mutability types
        let interior_patterns = [
            "UnsafeCell",
            "Cell",
            "RefCell",
            "Mutex",
            "RwLock",
            "Atomic",
            "OnceLock",
            "LazyLock",
            "OnceCell",
            "AtomicBool",
            "AtomicI8",
            "AtomicI16",
            "AtomicI32",
            "AtomicI64",
            "AtomicIsize",
            "AtomicU8",
            "AtomicU16",
            "AtomicU32",
            "AtomicU64",
            "AtomicUsize",
        ];

        interior_patterns
            .iter()
            .any(|&pattern| name.contains(pattern))
    }
}

impl Default for InteriorMutabilityPass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interior_mutability_pass_creation() {
        let pass = InteriorMutabilityPass::new();
        assert_eq!(
            pass.name(),
            "InteriorMutability",
            "Expected values to be equal"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Expected values to be equal"
        );
    }

    #[test]
    fn test_has_interior_mutability() {
        let pass = InteriorMutabilityPass::new();
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell10UnsafeCell"),
            "Expected condition to be true"
        );
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4sync5Mutex"),
            "Expected condition to be true"
        );
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std6Atomic"),
            "Expected condition to be true"
        );
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell4Cell"),
            "Expected condition to be true"
        );
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell7RefCell"),
            "Expected condition to be true"
        );
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4sync7OnceLock"),
            "Expected condition to be true"
        );
        assert!(
            !pass.has_interior_mutability("_RNvNtCsgXhsEb1m4tm_4core9panicking5panic"),
            "Expected condition to be true"
        );
    }

    #[test]
    fn test_interior_mutability_detection() {
        let pass = InteriorMutabilityPass::new();
        let mut semantic_tree = SemanticTree::new();

        pass.detect_interior_mutability(
            "test_symbol",
            "_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell10UnsafeCell",
            "some_callee",
            &mut semantic_tree,
        );

        let resolutions = semantic_tree.all_resolutions("test_symbol");
        assert!(!resolutions.is_empty(), "Expected condition to be true");
        assert_eq!(
            resolutions[0].kind,
            SemanticKind::InteriorMutability,
            "Expected values to be equal"
        );
    }
}
