//! Write-to-immutable detection pass.
//!
//! This pass detects attempts to write to immutable memory locations,
//! which is a common source of undefined behavior in FFI code.
//!
//! The pass uses semantic tree analysis to suppress false positives:
//! - If the target has MutableParam semantic → not an error (R-0)
//! - If the target has InteriorMutability semantic → not an error (R-2)
//! - If the target is from a function parameter → not a stack escape (R-8)

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::{Issue, IssueKind, Result, Severity};
use omniscope_semantics::{SemanticKind, SemanticResolution, SemanticTree};

/// Write-to-immutable detection pass.
///
/// Analyzes IR instructions to detect stores to immutable memory.
/// Uses semantic tree to suppress false positives based on R-0~R-8 patterns.
pub struct WriteToImmutablePass;

impl WriteToImmutablePass {
    /// Creates a new write-to-immutable detection pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for WriteToImmutablePass {
    fn name(&self) -> &'static str {
        "WriteToImmutable"
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
        let ir_module: Option<omniscope_ir::IRModule> = ctx.get("ir_module");
        let Some(module) = ir_module else {
            return Ok(PassResult::new(self.name())
                .with_issues(0)
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64));
        };

        let mut issues = Vec::new();
        let mut nodes_analyzed = 0;

        // Build semantic tree for R-0~R-8 pattern suppression
        let mut semantic_tree = SemanticTree::new();

        // Scan for store instructions that might be writing to immutable memory
        for call in &module.calls {
            nodes_analyzed += 1;

            // Skip if this is not a store operation
            if !call.callee.contains("store") {
                continue;
            }

            // Check if we're writing to a potentially immutable location
            let target_symbol = format!("{}->{}", call.caller, call.callee);

            // Analyze the store target for semantic context
            self.analyze_store_target(
                ctx,
                &mut semantic_tree,
                &target_symbol,
                &call.caller,
                &call.callee,
                &mut issues,
            );
        }

        // Store semantic tree for downstream passes
        ctx.store("write_to_immutable_tree", semantic_tree);

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

impl WriteToImmutablePass {
    /// Analyzes a store instruction target for write-to-immutable violations.
    fn analyze_store_target(
        &self,
        ctx: &mut PassContext,
        semantic_tree: &mut SemanticTree,
        symbol: &str,
        caller: &str,
        callee: &str,
        issues: &mut Vec<Issue>,
    ) {
        // Add semantic resolutions based on IR patterns

        // R-0: Check for mutable parameters (suppresses false positives)
        if self.is_mutable_parameter(caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::MutableParam,
                confidence: 0.95,
                evidence: "Function parameter lacks readonly attribute".to_string(),
                pattern_id: "R-0",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - parameter is mutable
        }

        // R-2: Check for interior mutability types (suppresses false positives)
        if self.has_interior_mutability(caller) {
            let resolution = SemanticResolution {
                kind: SemanticKind::InteriorMutability,
                confidence: 0.90,
                evidence: "Type contains UnsafeCell for interior mutability".to_string(),
                pattern_id: "R-2",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - interior mutability is safe
        }

        // R-8: Check for function parameters (suppresses false positives)
        if self.is_function_parameter(symbol) {
            let resolution = SemanticResolution {
                kind: SemanticKind::FromParameter,
                confidence: 0.95,
                evidence: "Target is a function parameter, not stack escape".to_string(),
                pattern_id: "R-8",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - parameter is caller-owned
        }

        // If none of the suppression patterns match, emit the issue
        let issue_id = ctx.next_issue_id();
        let issue = Issue::new(
            issue_id,
            IssueKind::WriteToImmutable,
            Severity::Warning,
            format!(
                "Potential write to immutable memory: {} -> {} [symbol={}]",
                caller, callee, symbol
            ),
        )
        .with_symbol(symbol);

        let outcome = ctx.emit_issue(issue.clone());
        if outcome.is_allowed() {
            issues.push(issue);
        }
    }

    /// Checks if a function parameter is mutable (lacks readonly attribute).
    fn is_mutable_parameter(&self, caller: &str) -> bool {
        // Heuristic: Rust functions with &mut parameters are typically mutable
        // For now, we assume most Rust functions have mutable parameters unless marked readonly
        caller.starts_with("_R") && !caller.contains("readonly")
    }

    /// Checks if a type has interior mutability (contains UnsafeCell).
    fn has_interior_mutability(&self, caller: &str) -> bool {
        // Check for interior mutability patterns in mangled names
        caller.contains("UnsafeCell")
            || caller.contains("Cell")
            || caller.contains("RefCell")
            || caller.contains("Mutex")
            || caller.contains("RwLock")
            || caller.contains("sync")
            || caller.contains("atomic")
    }

    /// Checks if a symbol represents a function parameter.
    fn is_function_parameter(&self, symbol: &str) -> bool {
        // Heuristic: symbols containing function parameter patterns
        symbol.contains("param") || symbol.contains("arg") || symbol.contains("parameter")
    }
}

impl Default for WriteToImmutablePass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_to_immutable_pass_creation() {
        let pass = WriteToImmutablePass::new();
        assert_eq!(pass.name(), "WriteToImmutable");
        assert_eq!(pass.kind(), PassKind::Analysis);
    }

    #[test]
    fn test_is_mutable_parameter() {
        let pass = WriteToImmutablePass::new();
        assert!(pass.is_mutable_parameter("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell4Cell"));
        assert!(!pass.is_mutable_parameter("_RNvNtCsgXhsEb1m4tm_4core9panicking5panic_readonly"));
    }

    #[test]
    fn test_has_interior_mutability() {
        let pass = WriteToImmutablePass::new();
        assert!(pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell10UnsafeCell"));
        assert!(pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4sync5mutex"));
        assert!(pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4sync7atomic"));
        assert!(!pass.has_interior_mutability("_RNvNtCsgXhsEb1m4tm_4core9panicking5panic"));
    }

    #[test]
    fn test_is_function_parameter() {
        let pass = WriteToImmutablePass::new();
        assert!(pass.is_function_parameter("func->param"));
        assert!(pass.is_function_parameter("func->arg"));
        assert!(!pass.is_function_parameter("func->local"));
    }
}
