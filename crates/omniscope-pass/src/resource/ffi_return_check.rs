//! FFI nullable return unchecked detector.
//!
//! Detects FFI functions that return a pointer whose value is used
//! (load/store/gep/call-sink) without a preceding null check (icmp eq/ne).
//!
//! # Detection Logic
//!
//! For each function body:
//! 1. Find `call ptr @external_c_api(...)` that stores into `%dest`
//! 2. Track which registers have been null-checked via `icmp eq/ne %reg, null`
//! 3. If `%dest` is used by a dangerous instruction (load/store/gep/call-sink)
//!    before being null-checked, emit an issue.
//!
//! # Scope
//!
//! - Only applies to calls to **external declarations** (FFI boundary)
//! - Skips known non-null APIs (Rust runtime, allocators, drop glue)
//! - Skips `Box::into_raw` / `from_raw` (Rust raw ownership, already tracked)

use omniscope_core::{Issue, Result};
use omniscope_ir::{FunctionBody, IRInstruction, IRInstructionKind, IRModule};

use crate::pass::{Pass, PassContext, PassKind, PassResult};

/// FFI nullable return unchecked detector pass.
///
/// Scans function bodies for FFI call results used without null checks.
pub struct FfiReturnCheckPass;

impl FfiReturnCheckPass {
    /// Creates a new FFI return check pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for FfiReturnCheckPass {
    fn name(&self) -> &'static str {
        "FfiReturnCheck"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec![] // No dependencies — reads IRModule directly
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();

        let mut issues: Vec<Issue> = Vec::new();

        // Retrieve the IRModule from context
        let ir_module: Option<IRModule> = ctx.get("ir_module");
        if let Some(ref module) = ir_module {
            for (func_name, body) in &module.function_bodies {
                scan_function_body(module, func_name, body, &mut issues, ctx);
            }
        }

        let issue_count = issues.len();
        let mut result =
            PassResult::new(self.name()).with_duration(start.elapsed().as_millis() as u64);

        for issue in issues {
            let outcome = ctx.emit_issue(issue.clone());
            if outcome.is_allowed() {
                result.add_issue(issue);
            }
        }

        result.add_stat("ffi_unchecked_returns", issue_count);

        Ok(result)
    }
}

impl Default for FfiReturnCheckPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Scans a single function body for unchecked FFI nullable returns.
fn scan_function_body(
    module: &IRModule,
    func_name: &str,
    body: &FunctionBody,
    issues: &mut Vec<Issue>,
    ctx: &mut PassContext,
) {
    // Track which registers have been null-checked.
    let mut null_checked: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Track which registers are FFI call results (potential null).
    let mut ffi_return_regs: std::collections::HashSet<String> = std::collections::HashSet::new();

    for inst in &body.instructions {
        match inst.kind {
            IRInstructionKind::Call => {
                if let Some(ref callee) = inst.callee {
                    let callee_name = callee.trim_start_matches('@');

                    // Check if this is an external FFI call
                    if !module.declarations.contains_key(callee_name)
                        && !is_likely_ffi_by_name(callee_name)
                    {
                        // Not an external call — skip
                        continue;
                    }

                    // Skip known non-null APIs
                    if is_non_null_api(callee_name) {
                        continue;
                    }

                    // If the call returns into a register, track it
                    if let Some(ref dest) = inst.dest {
                        ffi_return_regs.insert(dest.clone());
                    }

                    // Also check if an unchecked FFI return is passed
                    // as an argument to a null-sink function
                    if is_null_sink(callee_name) {
                        // Call operands are not populated by the parser,
                        // so we extract registers from raw_text instead.
                        for word in inst
                            .raw_text
                            .split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')')
                        {
                            let op = word.trim();
                            if op.starts_with('%')
                                && ffi_return_regs.contains(op)
                                && !null_checked.contains(op)
                            {
                                let issue_id = ctx.next_issue_id();
                                let issue = Issue::new(
                                    issue_id,
                                    omniscope_core::IssueKind::NullDereference,
                                    omniscope_core::diagnostics::Severity::Error,
                                    format!(
                                        "FFI return value '{}' passed to null-sink '{}' without null check in '{}'",
                                        op, callee, func_name
                                    ),
                                )
                                .with_symbol(op.to_string());

                                issues.push(issue);
                                null_checked.insert(op.to_string());
                            }
                        }
                    }
                }
            }

            IRInstructionKind::Icmp => {
                // If this is an icmp eq/ne %reg, null, mark %reg as checked
                if let Some(ref pred) = inst.icmp_pred {
                    if pred == "eq" || pred == "ne" {
                        // Check if one operand is the register and the other is null
                        for operand in &inst.operands {
                            let op = operand.trim();
                            if op.starts_with('%') && ffi_return_regs.contains(op) {
                                null_checked.insert(op.to_string());
                            }
                        }
                    }
                }
            }

            IRInstructionKind::Load
            | IRInstructionKind::Store
            | IRInstructionKind::GetElementPtr => {
                // Check if any operand is an unchecked FFI return register
                for operand in &inst.operands {
                    let op = operand.trim();
                    if op.starts_with('%')
                        && ffi_return_regs.contains(op)
                        && !null_checked.contains(op)
                    {
                        // Found an unchecked use! Emit an issue.
                        let issue_id = ctx.next_issue_id();
                        let issue = Issue::new(
                            issue_id,
                            omniscope_core::IssueKind::UncheckedReturn,
                            omniscope_core::diagnostics::Severity::Warning,
                            format!(
                                "FFI return value '{}' used without null check in '{}' ({:?})",
                                op, func_name, inst.kind
                            ),
                        )
                        .with_symbol(op.to_string());

                        issues.push(issue);

                        // Mark as checked to avoid duplicate reports for the same register
                        null_checked.insert(op.to_string());
                    }
                }
            }

            _ => {}
        }
    }
}

/// Returns true if the callee name looks like an FFI function.
///
/// Heuristic: C-style names (lowercase, underscores) that aren't
/// Rust mangled names.
fn is_likely_ffi_by_name(name: &str) -> bool {
    // Rust v0 mangled names start with _RNv or _RINv
    if name.starts_with("_R") {
        return false;
    }
    // Rust legacy mangled names contain ::
    if name.contains("::") {
        return false;
    }
    // C-style names: lowercase with underscores
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
}

/// Known APIs that are guaranteed to return non-null.
///
/// Calling these without null checks is safe — they abort on failure
/// rather than returning null.
fn is_non_null_api(name: &str) -> bool {
    // Rust allocator wrappers (abort on OOM)
    if name.starts_with("__rust_alloc")
        || name.starts_with("__rdl_alloc")
        || name.starts_with("__rg_alloc")
    {
        return true;
    }
    // C allocators (may return null, but the Rust wrappers don't)
    if name == "malloc" || name == "calloc" || name == "realloc" {
        return true; // These are usually wrapped by Rust's allocator
    }
    // Rust raw ownership — already tracked by RUST_RAW_OWNERSHIP family
    if name.contains("into_raw") || name.contains("from_raw") {
        return true;
    }
    // Drop glue / RAII — never returns null
    if name.contains("drop_in_place") || name.contains("__rust_dealloc") {
        return true;
    }
    false
}

/// Functions that are null-sinks — passing a null pointer to them
/// is undefined behavior or a crash.
fn is_null_sink(name: &str) -> bool {
    matches!(
        name,
        "strlen"
            | "strnlen"
            | "memcpy"
            | "memmove"
            | "memset"
            | "strcpy"
            | "strncpy"
            | "free"
            | "printf"
            | "fprintf"
            | "sprintf"
            | "snprintf"
            | "puts"
            | "fputs"
            | "fwrite"
            | "fread"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_return_check_pass_creation() {
        let pass = FfiReturnCheckPass::new();
        assert_eq!(pass.name(), "FfiReturnCheck");
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert!(pass.dependencies().is_empty());
    }

    #[test]
    fn test_is_non_null_api() {
        assert!(is_non_null_api("malloc"));
        assert!(is_non_null_api("__rust_alloc"));
        assert!(is_non_null_api("Box::into_raw"));
        assert!(!is_non_null_api("ffi_get_buffer"));
    }

    #[test]
    fn test_is_null_sink() {
        assert!(is_null_sink("strlen"));
        assert!(is_null_sink("free"));
        assert!(is_null_sink("memcpy"));
        assert!(!is_null_sink("some_other_func"));
    }

    #[test]
    fn test_is_likely_ffi_by_name() {
        assert!(is_likely_ffi_by_name("ffi_get_buffer"));
        assert!(is_likely_ffi_by_name("curl_easy_init"));
        assert!(!is_likely_ffi_by_name("_RNvCsome_rust_mangled"));
        assert!(!is_likely_ffi_by_name("Some::rust_func"));
    }

    /// TP: FFI call returning ptr, immediately load without null check
    #[test]
    fn test_e2e_ffi_return_unchecked_load_tp() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        // Parse LLVM IR that simulates:
        // %p = call ptr @ffi_get()
        // %v = load i8, ptr %p  (no null check before load!)
        let ir = r#"
            declare ptr @ffi_get()

            define void @unsafe_func() {
                %p = call ptr @ffi_get()
                %v = load i8, ptr %p
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let result = FfiReturnCheckPass::new().run(&mut ctx).unwrap();

        let unchecked_issues: Vec<_> = result
            .get_issues()
            .iter()
            .filter(|i| i.kind == omniscope_core::IssueKind::UncheckedReturn)
            .collect();
        assert!(
            !unchecked_issues.is_empty(),
            "FFI return value used in load without null check MUST produce UncheckedReturn issue, got {} issues",
            result.get_issues().len()
        );
    }

    /// TP: FFI call returning ptr, passed to strlen without null check
    #[test]
    fn test_e2e_ffi_return_unchecked_strlen_tp() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        // Parse LLVM IR that simulates:
        // %p = call ptr @ffi_get()
        // call i64 @strlen(ptr %p)  (null-sink, no check!)
        let ir = r#"
            declare ptr @ffi_get()
            declare i64 @strlen(ptr)

            define i64 @unsafe_strlen() {
                %p = call ptr @ffi_get()
                %len = call i64 @strlen(ptr %p)
                ret i64 %len
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let result = FfiReturnCheckPass::new().run(&mut ctx).unwrap();

        let null_deref_issues: Vec<_> = result
            .get_issues()
            .iter()
            .filter(|i| i.kind == omniscope_core::IssueKind::NullDereference)
            .collect();
        assert!(
            !null_deref_issues.is_empty(),
            "FFI return value passed to strlen without null check MUST produce NullDereference issue, got {} issues",
            result.get_issues().len()
        );
    }

    /// FP guard: null-checked FFI return is safe to use
    #[test]
    fn test_e2e_ffi_return_null_checked_no_false_positive() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        // Parse LLVM IR that simulates:
        // %p = call ptr @ffi_get()
        // %isnull = icmp eq ptr %p, null
        // br i1 %isnull, label %null, label %ok
        // ok:
        //   %v = load i8, ptr %p  (safe — null-checked first!)
        let ir = r#"
            declare ptr @ffi_get()

            define void @safe_func() {
                %p = call ptr @ffi_get()
                %isnull = icmp eq ptr %p, null
                br i1 %isnull, label %null, label %ok
            null:
                ret void
            ok:
                %v = load i8, ptr %p
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let result = FfiReturnCheckPass::new().run(&mut ctx).unwrap();

        assert!(
            result.get_issues().is_empty(),
            "Null-checked FFI return must NOT produce issues, got {} issues: {:?}",
            result.get_issues().len(),
            result
                .get_issues()
                .iter()
                .map(|i| i.kind)
                .collect::<Vec<_>>()
        );
    }

    /// FP guard: Box::into_raw is skipped (raw ownership, not FFI null)
    #[test]
    fn test_e2e_box_into_raw_no_false_positive() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        // Box::into_raw should be skipped by is_non_null_api
        let ir = r#"
            declare ptr @Box::into_raw(ptr)

            define void @raw_owner() {
                %p = call ptr @Box::into_raw(ptr %box)
                %v = load i8, ptr %p
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let result = FfiReturnCheckPass::new().run(&mut ctx).unwrap();

        assert!(
            result.get_issues().is_empty(),
            "Box::into_raw must NOT produce FFI unchecked return issues, got {} issues",
            result.get_issues().len()
        );
    }
}
