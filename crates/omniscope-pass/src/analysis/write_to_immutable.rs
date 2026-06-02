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

        // Try to use ModuleIndex for function pre-filtering
        let module_index: Option<crate::module_index::ModuleIndex> = ctx.get("module_index");

        // Scan for store instructions that might be writing to immutable memory.
        // Store instructions live in function_bodies, not in module.calls.
        for (func_name, body) in &module.function_bodies {
            // Use ModuleIndex to skip functions without store instructions
            if let Some(ref index) = module_index {
                let trimmed_name = func_name.trim_start_matches('@');
                if let Some(meta) = index.function_meta(trimmed_name) {
                    if !meta.has_stores {
                        continue;
                    }
                }
            }

            for inst in body.instructions_of_kind(omniscope_ir::IRInstructionKind::Store) {
                nodes_analyzed += 1;

                // Build a target symbol from the function name and store operands.
                // Store instructions don't have a callee; use the raw text for context.
                // Find a byte boundary for ~80 chars to bound allocation without
                // collecting an intermediate String.
                let byte_end = inst
                    .raw_text
                    .char_indices()
                    .nth(80)
                    .map_or(inst.raw_text.len(), |(i, _)| i);
                let raw_prefix = &inst.raw_text[..byte_end];
                let target_symbol = format!("{}->store:{}", func_name, raw_prefix);

                // Analyze the store target for semantic context
                self.analyze_store_target(
                    ctx,
                    &mut semantic_tree,
                    &target_symbol,
                    func_name,
                    &inst.raw_text,
                    &mut issues,
                );
            }
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

        // R-10: Check for stores to local SSA values (alloca'd stack
        // variables, function parameters, or heap pointers). In LLVM IR,
        // local SSA values (prefixed with `%`) are derived from alloca
        // instructions, function parameters, or heap allocations — none
        // of which are immutable. Truly immutable stores target global
        // constants (`@` prefixed with `constant` keyword).
        if self.is_store_to_local_ssa(callee) {
            let resolution = SemanticResolution {
                kind: SemanticKind::HeapProvenance,
                confidence: 0.90,
                evidence: "Store destination is a local SSA value (stack/param/heap)".to_string(),
                pattern_id: "R-10",
            };
            semantic_tree.add_resolution(symbol, resolution);
            return; // Not a violation - local SSA values are mutable
        }

        // If none of the suppression patterns match, emit the issue
        let issue_id = ctx.next_issue_id();
        let location = omniscope_core::IssueLocation::new(std::path::PathBuf::from("<ffi>"), 0)
            .with_function(caller);
        let issue = Issue::new(
            issue_id,
            IssueKind::WriteToImmutable,
            Severity::Warning,
            format!(
                "Potential write to immutable memory: {} -> {} [symbol={}]",
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

    /// Checks if a function parameter is mutable (has &mut indicator).
    fn is_mutable_parameter(&self, caller: &str) -> bool {
        // R-0: Rust mangled names with explicit mut reference pattern indicate mutable params.
        // Interior mutability (R-2) is a separate concept and is checked independently.
        caller.starts_with("_R") && caller.contains("mut")
    }

    /// Checks if a type has interior mutability (contains UnsafeCell).
    fn has_interior_mutability(&self, caller: &str) -> bool {
        // Check for interior mutability patterns in mangled names.
        // Use specific prefixes to avoid false matches (e.g. "Cell" matching "Cancel",
        // "sync" matching "async").
        caller.contains("UnsafeCell")
            || caller.contains("RefCell")
            || caller.contains("_Cell")
            || caller.contains("4Cell")
            || caller.contains("Mutex")
            || caller.contains("RwLock")
            || caller.contains("_sync")
            || caller.contains("4sync")
            || caller.contains("_atomic")
            || caller.contains("7atomic")
    }

    /// Checks if a symbol represents a function parameter.
    fn is_function_parameter(&self, symbol: &str) -> bool {
        // Heuristic: symbols containing function parameter patterns
        symbol.contains("param") || symbol.contains("arg") || symbol.contains("parameter")
    }

    /// Checks if a store instruction targets a local SSA value.
    ///
    /// In LLVM IR, store instructions have the form:
    /// ```text
    /// store <type> <value>, ptr <dest>, <attributes>
    /// ```
    ///
    /// If `<dest>` is a local SSA value (prefixed with `%`), the store
    /// targets stack memory (alloca), a function parameter, or a heap
    /// pointer — all of which are mutable. Truly immutable stores target
    /// global constants (`@` prefixed with `constant`).
    fn is_store_to_local_ssa(&self, raw_text: &str) -> bool {
        // Parse "store ..., ptr %N, ..." pattern
        // Find "ptr " followed by the destination operand
        if let Some(ptr_pos) = raw_text.find(" ptr ") {
            let after_ptr = &raw_text[ptr_pos + 5..];
            // The destination operand follows "ptr "
            // It starts with "%" for local SSA values or "@" for globals
            let trimmed = after_ptr.trim_start();
            trimmed.starts_with('%')
        } else {
            // If we can't parse the store format, don't suppress
            false
        }
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
        assert_eq!(
            pass.name(),
            "WriteToImmutable",
            "Pass name should be WriteToImmutable"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Pass kind should be Analysis"
        );
    }

    #[test]
    fn test_is_mutable_parameter() {
        let pass = WriteToImmutablePass::new();
        // A Rust mangled name with "mut" and _R prefix is a mutable parameter
        assert!(
            pass.is_mutable_parameter("_RNvMNtCsg1bLsEOY8ZL_3foo3mut"),
            "Rust mangled name with mut must be mutable parameter"
        );
        // Cell type has interior mutability but is NOT a mutable parameter
        assert!(
            !pass.is_mutable_parameter("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell4Cell"),
            "Cell type is not a mutable parameter"
        );
        assert!(
            !pass.is_mutable_parameter("_RNvNtCsgXhsEb1m4tm_4core9panicking5panic_readonly"),
            "Readonly parameter must not be mutable"
        );
    }

    #[test]
    fn test_has_interior_mutability() {
        let pass = WriteToImmutablePass::new();
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell10UnsafeCell"),
            "UnsafeCell must have interior mutability"
        );
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4cell4Cell"),
            "std::cell::Cell must have interior mutability"
        );
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4sync5mutex"),
            "std::sync::Mutex must have interior mutability"
        );
        assert!(
            pass.has_interior_mutability("_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std4sync7atomic"),
            "std::sync::atomic must have interior mutability"
        );
        assert!(
            !pass.has_interior_mutability("_RNvNtCsgXhsEb1m4tm_4core9panicking5panic"),
            "panicking must not have interior mutability"
        );
    }

    #[test]
    fn test_is_function_parameter() {
        let pass = WriteToImmutablePass::new();
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

    /// Objective: Verify stores to local SSA values are suppressed.
    /// Invariants: Stores to `%` prefixed destinations (alloca, params, heap) must be suppressed.
    #[test]
    fn test_is_store_to_local_ssa() {
        let pass = WriteToImmutablePass::new();
        // Stores to local SSA values (alloca, function params, heap pointers)
        assert!(
            pass.is_store_to_local_ssa("store i8 -128, ptr %12, align 1, !tbaa !5"),
            "Store to alloca-derived %12 must be local SSA"
        );
        assert!(
            pass.is_store_to_local_ssa("store i8 %41, ptr %2, align 1, !tbaa !5"),
            "Store to function param %2 must be local SSA"
        );
        assert!(
            pass.is_store_to_local_ssa("store <8 x i8> %29, ptr %18, align 1, !tbaa !5"),
            "Store to GEP-derived %18 must be local SSA"
        );
        assert!(
            pass.is_store_to_local_ssa("store i32 %116, ptr %1, align 4, !tbaa !10"),
            "Store to param %1 must be local SSA"
        );
        // Stores to global constants are NOT local SSA
        assert!(
            !pass.is_store_to_local_ssa("store i32 42, ptr @global_const, align 4"),
            "Store to global @global_const must NOT be local SSA"
        );
    }
}
