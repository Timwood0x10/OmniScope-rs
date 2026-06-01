//! RAII drop detection pass.
//!
//! This pass detects compiler-inserted RAII drop operations to suppress
//! false positive use-after-free issues.
//!
//! Based on R-3 pattern from bun_fp_reduction_plan.md:
//! - drop_in_place<T> calls
//! - Tail-position __rust_dealloc in function returns
//! - Arc/Rc refcount decrement + conditional deallocation

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::Result;
use omniscope_ir::IRModule;
use omniscope_semantics::{SemanticKind, SemanticResolution, SemanticTree};

/// RAII drop detection pass.
///
/// Analyzes IR to detect compiler-inserted RAII drop operations and
/// add semantic resolutions for downstream passes.
pub struct RaiiDropPass;

impl RaiiDropPass {
    /// Creates a new RAII drop detection pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for RaiiDropPass {
    fn name(&self) -> &'static str {
        "RaiiDrop"
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

        // Analyze all calls for RAII drop patterns
        for call in &module.calls {
            nodes_analyzed += 1;

            let symbol = format!("{}->{}", call.caller, call.callee);

            // Detect RAII drop patterns
            self.detect_raii_drop(&symbol, &call.callee, &mut semantic_tree);
        }

        // Store semantic tree for downstream passes
        ctx.store("raii_drop_tree", semantic_tree);

        Ok(PassResult::new(self.name())
            .with_issues(0) // This pass doesn't emit issues, only adds semantic info
            .with_nodes(nodes_analyzed)
            .with_duration(start.elapsed().as_millis() as u64))
    }
}

impl RaiiDropPass {
    /// Detects RAII drop patterns and adds semantic resolutions.
    fn detect_raii_drop(&self, symbol: &str, callee: &str, semantic_tree: &mut SemanticTree) {
        // Pattern 1: drop_in_place<T> calls
        if self.is_drop_in_place(callee) {
            let resolution = SemanticResolution {
                kind: SemanticKind::RaiiDropRelease,
                confidence: 0.98,
                evidence: format!("Compiler-inserted drop_in_place: {}", callee),
                pattern_id: "R-3",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return;
        }

        // Pattern 2: Tail-position __rust_dealloc
        if self.is_tail_dealloc(callee) {
            let resolution = SemanticResolution {
                kind: SemanticKind::RaiiDropRelease,
                confidence: 0.95,
                evidence: format!("Tail-position RAII dealloc: {}", callee),
                pattern_id: "R-3",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return;
        }

        // Pattern 3: Arc/Rc refcount decrement + conditional deallocation
        if self.is_refcount_decrement(callee) {
            let resolution = SemanticResolution {
                kind: SemanticKind::RaiiDropRelease,
                confidence: 0.90,
                evidence: format!("Arc/Rc refcount decrement: {}", callee),
                pattern_id: "R-3",
            };
            semantic_tree.add_resolution(symbol, resolution);
        }
    }

    /// Checks if a callee is a drop_in_place function.
    ///
    /// Uses precise matching to avoid false positives from names like
    /// "dropdown", "dropshadow", "floodrop", etc.
    fn is_drop_in_place(&self, callee: &str) -> bool {
        // Exact match for bare "drop" (Rust Drop trait impl)
        if callee == "drop" {
            return true;
        }

        // Rust Drop::drop trait path: ends with "::drop"
        if callee.ends_with("::drop") {
            return true;
        }

        // Rust mangled Drop: _RNv...Drop (uppercase D, trait name)
        if callee.contains("Drop") && callee.starts_with("_RNv") {
            return true;
        }

        // drop_in_place (compiler-inserted destructor glue)
        if callee.contains("drop_in_place") {
            return true;
        }

        // C++ destructor mangled: _ZN...D[012]Ev
        if callee.starts_with("_ZN")
            && (callee.contains("D0Ev") || callee.contains("D1Ev") || callee.contains("D2Ev"))
        {
            return true;
        }

        false
    }

    /// Checks if a callee is a tail-position __rust_dealloc.
    ///
    /// Uses precise matching to avoid false positives from names like
    /// "custom_dealloc" which may not be RAII-related.
    fn is_tail_dealloc(&self, callee: &str) -> bool {
        callee == "__rust_dealloc"
            || callee == "__rust_free"
            || callee == "_ZN9alloc1raw8dealloc17h" // Rust alloc::raw::dealloc mangled prefix
    }

    /// Checks if a callee is an Arc/Rc refcount decrement operation.
    ///
    /// Uses word-boundary-aware matching to avoid false positives from
    /// names containing "atomic" that aren't refcount operations.
    fn is_refcount_decrement(&self, callee: &str) -> bool {
        // LLVM atomicrmw instruction — exact match
        if callee.starts_with("atomicrmw") {
            return true;
        }

        // Rust Arc/Rc Drop impl via mangled name: _R...5alloc3arc3Arc3Drop or similar
        if callee.contains("Arc") && callee.contains("drop") && callee.starts_with("_R") {
            return true;
        }
        if callee.contains("Rc") && callee.contains("drop") && callee.starts_with("_R") {
            return true;
        }

        // Demangled: Arc::<T>::drop or Rc::<T>::drop
        if (callee.contains("Arc") || callee.contains("Rc")) && callee.ends_with("::drop") {
            return true;
        }

        false
    }
}

impl Default for RaiiDropPass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raii_drop_pass_creation() {
        let pass = RaiiDropPass::new();
        assert_eq!(pass.name(), "RaiiDrop", "Expected values to be equal");
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Expected values to be equal"
        );
    }

    #[test]
    fn test_is_drop_in_place() {
        let pass = RaiiDropPass::new();
        // Exact "drop" match
        assert!(
            pass.is_drop_in_place("drop"),
            "Expected condition to be true"
        );
        // drop_in_place (compiler-inserted)
        assert!(
            pass.is_drop_in_place("_RNvNtCsgXhsEb1m4tm_4core3ptr13drop_in_place"),
            "Expected condition to be true"
        );
        // Rust mangled Drop trait
        assert!(
            pass.is_drop_in_place("_RNvMNtCsgXhsEb1m4tm_4alloc3box3Box3Drop"),
            "Expected condition to be true"
        );
        // C++ destructor
        assert!(
            pass.is_drop_in_place("_ZN3FooD1Ev"),
            "Expected condition to be true"
        );
        // ::drop suffix
        assert!(
            pass.is_drop_in_place("std::mem::drop"),
            "Expected condition to be true"
        );
        // Negative: bare "drop" substring in unrelated names
        assert!(
            !pass.is_drop_in_place("dropdown"),
            "Expected condition to be true"
        );
        assert!(
            !pass.is_drop_in_place("dropshadow"),
            "Expected condition to be true"
        );
        assert!(
            !pass.is_drop_in_place("floodrop"),
            "Expected condition to be true"
        );
        assert!(
            !pass.is_drop_in_place("malloc"),
            "Expected condition to be true"
        );
    }

    #[test]
    fn test_is_tail_dealloc() {
        let pass = RaiiDropPass::new();
        assert!(
            pass.is_tail_dealloc("__rust_dealloc"),
            "Expected condition to be true"
        );
        assert!(
            pass.is_tail_dealloc("__rust_free"),
            "Expected condition to be true"
        );
        // custom_dealloc should NOT match — it's not a compiler RAII dealloc
        assert!(
            !pass.is_tail_dealloc("custom_dealloc"),
            "Expected condition to be true"
        );
        assert!(
            !pass.is_tail_dealloc("malloc"),
            "Expected condition to be true"
        );
    }

    #[test]
    fn test_is_refcount_decrement() {
        let pass = RaiiDropPass::new();
        // atomicrmw instruction prefix
        assert!(
            pass.is_refcount_decrement("atomicrmw"),
            "Expected condition to be true"
        );
        assert!(
            pass.is_refcount_decrement("atomicrmw.sub.i64"),
            "Expected condition to be true"
        );
        // Demangled Arc/Rc drop
        assert!(
            pass.is_refcount_decrement("Arc<i32>::drop"),
            "Expected condition to be true"
        );
        assert!(
            pass.is_refcount_decrement("Rc<i32>::drop"),
            "Expected condition to be true"
        );
        // Mangled Arc/Rc drop
        assert!(
            pass.is_refcount_decrement("_RNvXsNtC4alloc3arc3Arc3drop"),
            "Expected condition to be true"
        );
        // Negative: "atomic" alone is not a refcount op
        assert!(
            !pass.is_refcount_decrement("atomic_flag_clear"),
            "Expected condition to be true"
        );
        // Negative: "Arc_drop" without mangled prefix or ::drop suffix
        assert!(
            !pass.is_refcount_decrement("Arc_drop"),
            "Expected condition to be true"
        );
        assert!(
            !pass.is_refcount_decrement("malloc"),
            "Expected condition to be true"
        );
    }
}
