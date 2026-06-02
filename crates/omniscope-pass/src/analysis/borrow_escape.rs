//! Borrow escape detection pass.
//!
//! This pass detects when stack-allocated memory is passed across FFI
//! boundaries, which can lead to use-after-free when the callee stores
//! the pointer and uses it after the function returns.
//!
//! The pass uses semantic tree analysis to suppress false positives:
//! - If the value has heap provenance → not a stack escape (R-1)
//! - If the value has global provenance → not a stack escape (R-1)
//! - If the value comes from parameters → not a stack escape (R-8)

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::{Issue, IssueKind, Result, Severity};
use omniscope_semantics::{SemanticKind, SemanticResolution, SemanticTree};

/// Borrow escape detection pass.
///
/// Analyzes IR instructions to detect stack pointer escapes across FFI boundaries.
/// Uses semantic tree to suppress false positives based on R-0~R-8 patterns.
pub struct BorrowEscapePass;

impl BorrowEscapePass {
    /// Creates a new borrow escape detection pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for BorrowEscapePass {
    fn name(&self) -> &'static str {
        "BorrowEscape"
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
        let Some(module) = ctx.get_ir_module() else {
            return Ok(PassResult::new(self.name())
                .with_issues(0)
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64));
        };

        let mut issues = Vec::new();
        let mut nodes_analyzed = 0;

        // Build semantic tree for R-0~R-8 pattern suppression
        let mut semantic_tree = SemanticTree::new();

        // Try to use ModuleIndex for FFI call pre-filtering
        let module_index: Option<crate::module_index::ModuleIndex> = ctx.get("module_index");

        // Collect FFI calls to analyze (avoid borrow conflicts)
        let mut ffi_calls = Vec::new();
        for (idx, call) in module.calls.iter().enumerate() {
            nodes_analyzed += 1;

            // Skip LLVM intrinsics
            if call.callee.starts_with("llvm.") {
                continue;
            }

            // Check if this is an external call (potential FFI boundary)
            if !call.is_external {
                continue;
            }

            // Use ModuleIndex to check if this call is an FFI boundary
            if let Some(ref index) = module_index {
                if idx < index.call_metas.len() {
                    let meta = &index.call_metas[idx];
                    // Skip non-FFI boundary calls
                    if !meta.is_ffi_boundary {
                        continue;
                    }
                }
            }

            // Check for positive stack provenance evidence:
            // the caller name suggests a local/stack-allocated variable
            // passed across the FFI boundary.
            if !self.has_stack_provenance(&call.caller) {
                continue;
            }

            ffi_calls.push((call.caller.clone(), call.callee.clone()));
        }

        // Now process FFI calls without borrow conflicts
        for (caller, callee) in ffi_calls {
            let call_symbol = format!("{}->{}", caller, callee);

            self.analyze_ffi_call(
                ctx,
                &mut semantic_tree,
                &call_symbol,
                &caller,
                &callee,
                &mut issues,
            );
        }

        // Store semantic tree for downstream passes
        ctx.store("borrow_escape_tree", semantic_tree);

        let issues_found = issues.len();
        let mut result = PassResult::new(self.name())
            .with_issues(issues_found)
            .with_nodes(nodes_analyzed)
            .with_duration(start.elapsed().as_millis() as u64);

        for issue in issues {
            result.add_issue(issue);
        }

        Ok(result)
    }
}

impl BorrowEscapePass {
    /// Analyzes an FFI call for potential borrow escape issues.
    fn analyze_ffi_call(
        &self,
        ctx: &mut PassContext,
        semantic_tree: &mut SemanticTree,
        symbol: &str,
        caller: &str,
        callee: &str,
        issues: &mut Vec<Issue>,
    ) {
        // Add semantic resolutions based on IR patterns

        // R-1: Check for heap provenance (suppresses false positives)
        if self.has_heap_provenance(caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::HeapProvenance,
                confidence: 0.95,
                evidence: "Value originates from heap allocation".to_string(),
                pattern_id: "R-1",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - heap pointers are safe to pass
        }

        // R-1: Check for global provenance (suppresses false positives)
        if self.has_global_provenance(caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::GlobalProvenance,
                confidence: 0.90,
                evidence: "Value originates from global/static storage".to_string(),
                pattern_id: "R-1",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - global pointers are safe to pass
        }

        // R-8: Check for function parameters (suppresses false positives)
        if self.is_function_parameter(symbol) {
            let resolution = SemanticResolution {
                kind: SemanticKind::FromParameter,
                confidence: 0.95,
                evidence: "Value comes from function parameter, not stack escape".to_string(),
                pattern_id: "R-8",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - parameters are caller-owned
        }

        // If none of the suppression patterns match, emit the issue
        let issue_id = ctx.next_issue_id();
        let location = omniscope_core::IssueLocation::new(std::path::PathBuf::from("<ffi>"), 0)
            .with_function(caller);
        let issue = Issue::new(
            issue_id,
            IssueKind::BorrowEscape,
            Severity::Warning,
            format!(
                "Potential stack pointer escape across FFI boundary: {} -> {} [symbol={}]",
                caller, callee, symbol
            ),
        )
        .with_symbol(symbol)
        .with_location(location);

        let outcome = ctx.emit_issue(issue.clone());
        if outcome.is_allowed() {
            issues.push(issue);
        }
    }

    /// Checks if a value has heap provenance.
    fn has_heap_provenance(&self, caller: &str) -> bool {
        // Heuristic: heap-allocated values typically come from Box, Vec, malloc, etc.
        // Avoid bare "new" to prevent false matches against "renew", "knew", etc.
        caller.contains("alloc")
            || caller.contains("Box")
            || caller.contains("Vec")
            || caller.contains("malloc")
            || caller.contains("_new")
            || caller.ends_with("new")
    }

    /// Checks if a value has global provenance.
    fn has_global_provenance(&self, caller: &str) -> bool {
        // Heuristic: global/static values
        caller.contains("static") || caller.contains("global") || caller.starts_with("@")
    }

    /// Checks if a caller function has positive stack provenance evidence.
    ///
    /// Unlike the absence of heap/global provenance, this requires POSITIVE
    /// evidence that the value originates from the stack (alloca or local
    /// address patterns). Without positive evidence, we default to silence
    /// rather than flagging every external call as a potential escape.
    fn has_stack_provenance(&self, caller: &str) -> bool {
        caller.contains("alloca")
            || caller.contains("stack_addr")
            || caller.contains("local_buf")
            || caller.contains("_on_stack")
    }

    /// Checks if a symbol represents a function parameter.
    fn is_function_parameter(&self, symbol: &str) -> bool {
        // Heuristic: symbols containing function parameter patterns
        symbol.contains("param") || symbol.contains("arg") || symbol.contains("parameter")
    }
}

impl Default for BorrowEscapePass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_borrow_escape_pass_creation() {
        let pass = BorrowEscapePass::new();
        assert_eq!(pass.name(), "BorrowEscape", "Pass should have correct name");
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Pass should be Analysis kind"
        );
    }

    #[test]
    fn test_has_heap_provenance() {
        let pass = BorrowEscapePass::new();
        assert!(
            pass.has_heap_provenance("_RNvNtCsgXhsEb1m4tm_4core9panicking5alloc"),
            "Mangled alloc function should be recognized as heap provenance"
        );
        assert!(
            pass.has_heap_provenance("malloc_wrapper"),
            "malloc_wrapper should be recognized as heap provenance"
        );
        assert!(
            pass.has_heap_provenance("Box_new"),
            "Box_new should be recognized as heap provenance"
        );
        assert!(
            !pass.has_heap_provenance("local_var"),
            "local_var should NOT be recognized as heap provenance"
        );
    }

    #[test]
    fn test_has_global_provenance() {
        let pass = BorrowEscapePass::new();
        assert!(
            pass.has_global_provenance("static_var"),
            "static_var should be recognized as global provenance"
        );
        assert!(
            pass.has_global_provenance("global_config"),
            "global_config should be recognized as global provenance"
        );
        assert!(
            pass.has_global_provenance("@global"),
            "@global should be recognized as global provenance"
        );
        assert!(
            !pass.has_global_provenance("local_var"),
            "local_var should NOT be recognized as global provenance"
        );
    }

    #[test]
    fn test_is_function_parameter() {
        let pass = BorrowEscapePass::new();
        assert!(
            pass.is_function_parameter("func->param"),
            "func->param should be recognized as function parameter"
        );
        assert!(
            pass.is_function_parameter("func->arg"),
            "func->arg should be recognized as function parameter"
        );
        assert!(
            !pass.is_function_parameter("func->local"),
            "func->local should NOT be recognized as function parameter"
        );
    }
}
