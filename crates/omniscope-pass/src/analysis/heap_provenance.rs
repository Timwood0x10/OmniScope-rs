//! Heap provenance detection pass.
//!
//! This pass detects the origin of pointer values to determine if they
//! come from heap allocation (safe for FFI) vs stack allocation (unsafe).
//!
//! Based on R-1 pattern from bun_fp_reduction_plan.md:
//! - Heap provenance: malloc, __rust_alloc, Box::new, Vec::with_capacity
//! - Global provenance: static, const, &'static
//! - Stack provenance: alloca, local variables

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::Result;
use omniscope_ir::IRModule;
use omniscope_semantics::{SemanticKind, SemanticResolution, SemanticTree};

/// Heap provenance detection pass.
///
/// Analyzes IR to classify pointer provenance and add semantic resolutions
/// for downstream passes.
pub struct HeapProvenancePass;

impl HeapProvenancePass {
    /// Creates a new heap provenance detection pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for HeapProvenancePass {
    fn name(&self) -> &'static str {
        "HeapProvenance"
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

        // Analyze all calls for provenance information
        for call in &module.calls {
            nodes_analyzed += 1;

            let symbol = format!("{}->{}", call.caller, call.callee);

            // Determine provenance based on callee name and patterns
            self.analyze_provenance(&symbol, &call.callee, &mut semantic_tree);
        }

        // Store semantic tree for downstream passes
        ctx.store("heap_provenance_tree", semantic_tree);

        Ok(PassResult::new(self.name())
            .with_issues(0) // This pass doesn't emit issues, only adds semantic info
            .with_nodes(nodes_analyzed)
            .with_duration(start.elapsed().as_millis() as u64))
    }
}

impl HeapProvenancePass {
    /// Analyzes a symbol to determine its provenance and add semantic resolutions.
    fn analyze_provenance(&self, symbol: &str, callee: &str, semantic_tree: &mut SemanticTree) {
        // Layer 1: Allocation call patterns (highest confidence)
        if self.is_heap_allocation_call(callee) {
            let resolution = SemanticResolution {
                kind: SemanticKind::HeapProvenance,
                confidence: 0.98,
                evidence: format!("Heap allocation call: {}", callee),
                pattern_id: "R-1",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return;
        }

        // Layer 2: Global/static patterns
        if self.is_global_storage(callee) {
            let resolution = SemanticResolution {
                kind: SemanticKind::GlobalProvenance,
                confidence: 0.95,
                evidence: format!("Global/static storage: {}", callee),
                pattern_id: "R-1",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return;
        }

        // Layer 3: Stack allocation patterns
        if self.is_stack_allocation(callee) {
            // Note: We don't add a specific SemanticKind for stack provenance
            // as the absence of heap/global provenance implies stack provenance
            // in the context of borrow escape detection
        }
    }

    /// Checks if a callee is a heap allocation function.
    fn is_heap_allocation_call(&self, callee: &str) -> bool {
        let heap_patterns = [
            "__rust_alloc",
            "__rust_alloc_zeroed",
            "__rust_realloc",
            "malloc",
            "calloc",
            "realloc",
            "aligned_alloc",
            "_Znwm",         // C++ operator new
            "_Znam",         // C++ operator new[]
            "_Znwj",         // C++ operator new (32-bit)
            "_Znaj",         // C++ operator new[] (32-bit)
            "runtime.alloc", // Go
            "_cgo_allocate", // Go cgo
            "mi_malloc",     // mimalloc
            "mi_realloc",
            "mi_zalloc",
            "je_malloc", // jemalloc
            "je_calloc",
        ];

        heap_patterns
            .iter()
            .any(|&pattern| callee.contains(pattern))
    }

    /// Checks if a callee represents global/static storage.
    fn is_global_storage(&self, callee: &str) -> bool {
        callee.starts_with("@")
            || callee.contains("static")
            || callee.contains("global")
            || callee.contains("const")
    }

    /// Checks if a callee represents stack allocation.
    fn is_stack_allocation(&self, callee: &str) -> bool {
        callee.contains("alloca") || callee.contains("local") || callee.contains("stack")
    }
}

impl Default for HeapProvenancePass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heap_provenance_pass_creation() {
        let pass = HeapProvenancePass::new();
        assert_eq!(
            pass.name(),
            "HeapProvenance",
            "Pass should have correct name"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Pass should be Analysis kind"
        );
    }

    #[test]
    fn test_is_heap_allocation_call() {
        let pass = HeapProvenancePass::new();
        assert!(
            pass.is_heap_allocation_call("__rust_alloc"),
            "__rust_alloc should be recognized as heap allocation"
        );
        assert!(
            pass.is_heap_allocation_call("malloc"),
            "malloc should be recognized as heap allocation"
        );
        assert!(
            pass.is_heap_allocation_call("_Znwm"),
            "_Znwm (C++ new) should be recognized as heap allocation"
        ); // C++ new
        assert!(
            pass.is_heap_allocation_call("runtime.alloc"),
            "runtime.alloc should be recognized as heap allocation"
        );
        assert!(
            !pass.is_heap_allocation_call("strlen"),
            "strlen should NOT be recognized as heap allocation"
        );
    }

    #[test]
    fn test_is_global_storage() {
        let pass = HeapProvenancePass::new();
        assert!(
            pass.is_global_storage("@global_var"),
            "@global_var should be recognized as global storage"
        );
        assert!(
            pass.is_global_storage("static_config"),
            "static_config should be recognized as global storage"
        );
        assert!(
            pass.is_global_storage("global_buffer"),
            "global_buffer should be recognized as global storage"
        );
        assert!(
            !pass.is_global_storage("local_var"),
            "local_var should NOT be recognized as global storage"
        );
    }

    #[test]
    fn test_is_stack_allocation() {
        let pass = HeapProvenancePass::new();
        assert!(
            pass.is_stack_allocation("alloca"),
            "alloca should be recognized as stack allocation"
        );
        assert!(
            pass.is_stack_allocation("local_var"),
            "local_var should be recognized as stack allocation"
        );
        assert!(
            pass.is_stack_allocation("stack_buffer"),
            "stack_buffer should be recognized as stack allocation"
        );
        assert!(
            !pass.is_stack_allocation("malloc"),
            "malloc should NOT be recognized as stack allocation"
        );
    }
}
