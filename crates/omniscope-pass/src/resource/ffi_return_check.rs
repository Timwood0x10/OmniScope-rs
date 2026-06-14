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

use omniscope_core::issue_candidate::FfiEvidence;
use omniscope_core::{IssueCandidate, Result};
use omniscope_ir::{IRInstruction, IRInstructionKind, IRModule};
use omniscope_types::{Evidence, EvidenceKind, FamilyId, IssueCandidateKind, VerifierVerdict};

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use crate::resource::noreturn::is_noreturn_callee;

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

        let mut candidates: Vec<IssueCandidate> = Vec::new();
        let mut next_id = 1u64;

        // Retrieve the IRModule from context
        let ir_module: Option<IRModule> = ctx.get("ir_module");
        if let Some(ref module) = ir_module {
            // Try to use ModuleIndex for FFI function pre-filtering
            let module_index: Option<crate::module_index::ModuleIndex> = ctx.get("module_index");

            // Collect function bodies to scan (avoid borrow conflicts)
            let mut functions_to_scan = Vec::new();

            if let Some(ref index) = module_index {
                // Fast path: only scan functions that have FFI calls
                let ffi_functions = index.ffi_functions();
                let ffi_set: std::collections::HashSet<&str> =
                    ffi_functions.iter().map(|s| s.as_str()).collect();

                for (func_name, body) in &module.function_bodies {
                    let trimmed_name = func_name.trim_start_matches('@');
                    // Skip functions that don't have FFI calls
                    if !ffi_set.contains(trimmed_name) {
                        continue;
                    }
                    let instructions = body.instructions.clone();
                    functions_to_scan.push((func_name.clone(), instructions));
                }
            } else {
                // Fallback: scan all function bodies
                for (func_name, body) in &module.function_bodies {
                    let instructions = body.instructions.clone();
                    functions_to_scan.push((func_name.clone(), instructions));
                }
            }

            // Now scan function bodies without borrow conflicts
            // Track functions that have null-checked FFI returns for SRT suppression.
            let mut null_checked_functions: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for (func_name, instructions) in functions_to_scan {
                let had_null_checks = scan_function_body(
                    module,
                    &func_name,
                    &instructions,
                    &mut candidates,
                    &mut next_id,
                );
                if had_null_checks {
                    null_checked_functions.insert(func_name.clone());
                }
            }
            // Store null-checked functions for the IssueGate to suppress
            // NullDereference/UncheckedReturn false positives via SRT.
            if !null_checked_functions.is_empty() {
                ctx.store("null_checked_functions", null_checked_functions);
            }
        }

        let candidate_count = candidates.len();
        let mut result =
            PassResult::new(self.name()).with_duration(start.elapsed().as_millis() as u64);

        // Store candidates in context for IssueVerifier
        ctx.store("ffi_return_candidates", candidates);

        result.add_stat("ffi_unchecked_returns", candidate_count);

        Ok(result)
    }
}

impl Default for FfiReturnCheckPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Scans a single function body for unchecked FFI nullable returns.
///
/// Returns `true` if any null-check patterns (`icmp eq/ne ptr %x, null` + `br`)
/// were detected — indicating the function is null-aware. This is used by the
/// IssueGate to suppress NullDereference false positives via SRT NullChecked facts.
fn scan_function_body(
    module: &IRModule,
    func_name: &str,
    instructions: &[IRInstruction],
    candidates: &mut Vec<IssueCandidate>,
    next_id: &mut u64,
) -> bool {
    // Track whether any null-check patterns were found in this function.
    let mut found_null_check = false;
    // ── OOM-termination pre-check ──
    // If this function has a noreturn exit path (abort/unreachable/out_of_memory),
    // then unchecked FFI returns are likely on the OOM path — downgrade them
    // to Diagnostic instead of reporting as full issues.
    let has_oom_termination = instructions.iter().any(|i| match i.kind {
        IRInstructionKind::Other => i.raw_text.trim().starts_with("unreachable"),
        IRInstructionKind::Call => i.callee.as_deref().is_some_and(is_noreturn_callee),
        _ => false,
    });

    // Track which registers have been null-checked.
    let mut null_checked: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut pending_null_checks: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // Track which registers are FFI call results (potential null).
    // Maps register name -> callee name (for evidence context).
    let mut ffi_return_regs: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // Track which registers come from `noundef` FFI calls — these are
    // guaranteed non-null by the compiler and should not produce
    // UncheckedFfiReturn, but may still produce NullDereference if
    // passed to a null-sink function (defensive check).
    let mut noundef_return_regs: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for inst in instructions {
        match inst.kind {
            IRInstructionKind::Call | IRInstructionKind::IndirectCall => {
                if let Some(ref callee) = inst.callee {
                    let callee_name = callee.trim_start_matches('@');

                    // Check if this is an external FFI call
                    let is_declared = module.declarations.contains_key(callee_name);
                    let is_ffi = is_likely_ffi_by_name(callee_name);
                    if is_declared || is_ffi {
                        // Only track pointer-returning calls — non-pointer returns can't be null
                        if returns_pointer(inst) {
                            // Skip known non-null APIs and system allocators
                            // System allocators (malloc, calloc, etc.) generate excessive
                            // noise when flagged for unchecked returns because OOM handling
                            // is typically done at a higher layer.
                            if !is_non_null_api(callee_name) && !is_system_allocator(callee_name) {
                                // If the call returns into a register, track it
                                if let Some(ref dest) = inst.dest {
                                    ffi_return_regs.insert(dest.clone(), callee_name.to_string());
                                    // Track noundef returns separately — they are
                                    // guaranteed non-null but still checked for
                                    // NullDereference when passed to null-sinks.
                                    if has_noundef_return(inst) {
                                        noundef_return_regs.insert(dest.clone());
                                    }
                                }
                            }
                        }

                        // Check if an unchecked FFI return is passed
                        // as an argument to a null-sink function.
                        // This check applies regardless of return type.
                        if is_null_sink(callee_name) {
                            // Call operands are not populated by the text parser,
                            // so we extract registers from raw_text instead.
                            // Ensure raw_text is populated (handles --no-raw mode from C++ extractor).
                            let mut inst_clone = inst.clone();
                            inst_clone.ensure_raw();
                            for word in inst_clone.raw_text.split(|c: char| {
                                c.is_whitespace() || c == ',' || c == '(' || c == ')'
                            }) {
                                let op = word.trim();
                                if op.starts_with('%')
                                    && ffi_return_regs.contains_key(op)
                                    && !null_checked.contains(op)
                                {
                                    let id = *next_id;
                                    *next_id += 1;
                                    let callee_name = ffi_return_regs
                                        .get(op)
                                        .expect("op verified in ffi_return_regs");
                                    let source_callee = callee_name.trim_start_matches('@');
                                    let mut candidate = IssueCandidate::new(
                                        id,
                                        IssueCandidateKind::NullDereference,
                                        FamilyId::UNKNOWN,  // Not necessarily heap
                                        func_name,  // Enclosing function as alloc_function
                                    )
                                    .with_release_function(source_callee)  // FFI callee as release_function
                                    .with_alloc_caller(func_name)
                                    .with_description(format!(
                                        "FFI return value '{}' from '{}' passed to null-sensitive function '{}' without check",
                                        op, source_callee, callee
                                    ))
                                    .with_ffi_evidence(
                                        FfiEvidence::FfiReturnUnchecked {
                                            callee: source_callee.to_string(),
                                        }
                                    );

                                    // Add evidence
                                    candidate.add_evidence(Evidence::new(
                                        EvidenceKind::FfiReturnNullCheck,
                                        format!("Return value from '{}' at register '{}' passed to '{}' without null check",
                                                source_callee, op, callee),
                                    ));

                                    // If the function has OOM-termination paths (abort/unreachable),
                                    // the null deref is likely on the OOM path — downgrade.
                                    if has_oom_termination {
                                        candidate.verdict = Some(VerifierVerdict::Diagnostic);
                                        candidate.add_evidence(Evidence::new(
                                            EvidenceKind::PathStateRefinement,
                                            "function has OOM/abort exit path; null deref may be on abort path".to_string(),
                                        ));
                                    }

                                    candidates.push(candidate);
                                    null_checked.insert(op.to_string());
                                }
                            }
                        }
                    }
                }
            }

            IRInstructionKind::Icmp | IRInstructionKind::Fcmp if is_null_compare(inst) => {
                // Mark function as null-aware for SRT suppression.
                found_null_check = true;
                // A comparison only proves a null check once control flow
                // branches on the comparison result. This avoids treating
                // dead/unused `icmp` instructions as guards while still
                // handling parsers that do not populate structured operands.
                if let Some(checked_reg) = compared_ffi_return_register(inst, &ffi_return_regs) {
                    if let Some(ref dest) = inst.dest {
                        pending_null_checks.insert(dest.clone(), checked_reg);
                    } else {
                        null_checked.insert(checked_reg);
                    }
                }
            }

            IRInstructionKind::Branch => {
                let mut inst_clone = inst.clone();
                inst_clone.ensure_raw();
                let raw = inst_clone.raw_text.as_str();
                let used_checks: Vec<String> = pending_null_checks
                    .iter()
                    .filter_map(|(cmp_reg, checked_reg)| {
                        if raw_contains_register(raw, cmp_reg) {
                            Some(checked_reg.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                for checked_reg in used_checks {
                    null_checked.insert(checked_reg);
                }
            }

            IRInstructionKind::Load
            | IRInstructionKind::Store
            | IRInstructionKind::GetElementPtr => {
                // Check if any operand is an unchecked FFI return register
                for operand in &inst.operands {
                    let op = operand.trim();
                    if op.starts_with('%')
                        && ffi_return_regs.contains_key(op)
                        && !null_checked.contains(op)
                        && !noundef_return_regs.contains(op)
                    {
                        // Found an unchecked use! Create a candidate.
                        let id = *next_id;
                        *next_id += 1;
                        let callee_name = ffi_return_regs
                            .get(op)
                            .expect("op verified in ffi_return_regs");
                        let source_callee = callee_name.trim_start_matches('@');
                        let mut candidate = IssueCandidate::new(
                            id,
                            IssueCandidateKind::UncheckedFfiReturn,
                            FamilyId::UNKNOWN, // Not necessarily heap
                            func_name,         // Enclosing function as alloc_function
                        )
                        .with_release_function(source_callee) // FFI callee as release_function
                        .with_alloc_caller(func_name)
                        .with_description(format!(
                            "FFI return value '{}' from '{}' used without null check in '{}'",
                            op, source_callee, func_name
                        ))
                        .with_ffi_evidence(
                            FfiEvidence::FfiReturnUnchecked {
                                callee: source_callee.to_string(),
                            },
                        );

                        // Add evidence
                        candidate.add_evidence(Evidence::new(
                            EvidenceKind::FfiReturnNullCheck,
                            format!("Return value from '{}' at register '{}' has no null check before use in '{}'", 
                                    source_callee, op, func_name),
                        ));

                        // If the function has OOM-termination paths (abort/unreachable),
                        // the unchecked return is likely on the OOM path — downgrade.
                        if has_oom_termination {
                            candidate.verdict = Some(VerifierVerdict::Diagnostic);
                            candidate.add_evidence(Evidence::new(
                                EvidenceKind::PathStateRefinement,
                                "function has OOM/abort exit path; unchecked return may be on abort path".to_string(),
                            ));
                        }

                        candidates.push(candidate);

                        // Mark as checked to avoid duplicate reports for the same register
                        null_checked.insert(op.to_string());
                    }
                }
            }

            _ => {}
        }
    }

    found_null_check
}

fn is_null_compare(inst: &IRInstruction) -> bool {
    if let Some(ref pred) = inst.icmp_pred {
        if pred == "eq" || pred == "ne" {
            return inst.operands.iter().any(|op| op.trim() == "null")
                || inst.raw_text.contains(" null");
        }
    }

    let mut inst_clone = inst.clone();
    inst_clone.ensure_raw();
    let raw = inst_clone.raw_text.as_str();
    (raw.contains(" icmp eq ") || raw.contains(" icmp ne "))
        && (raw.contains(", null") || raw.contains(" null,"))
}

fn compared_ffi_return_register(
    inst: &IRInstruction,
    ffi_return_regs: &std::collections::HashMap<String, String>,
) -> Option<String> {
    for operand in &inst.operands {
        let op = operand.trim();
        if op.starts_with('%') && ffi_return_regs.contains_key(op) {
            return Some(op.to_string());
        }
    }

    let mut inst_clone = inst.clone();
    inst_clone.ensure_raw();
    extract_registers(&inst_clone.raw_text)
        .into_iter()
        .find(|reg| ffi_return_regs.contains_key(reg))
}

fn extract_registers(raw: &str) -> Vec<String> {
    raw.split(|c: char| !(c.is_ascii_alphanumeric() || c == '%' || c == '_' || c == '.'))
        .filter(|token| token.starts_with('%') && token.len() > 1)
        .map(ToString::to_string)
        .collect()
}

fn raw_contains_register(raw: &str, register: &str) -> bool {
    extract_registers(raw).iter().any(|r| r == register)
}

/// Returns true if the call instruction returns a pointer type.
///
/// Uses the structured `result_type` field when available (from C++ extractor),
/// otherwise falls back to parsing the raw text for the `call ptr @` pattern.
/// Non-pointer returns (i32, i64, void, etc.) cannot be null and should not
/// be tracked.
fn returns_pointer(inst: &IRInstruction) -> bool {
    // Fast path: use structured result_type field when available
    if let Some(ref result_type) = inst.result_type {
        return result_type == "ptr";
    }

    // Fallback: parse raw text for pointer return pattern
    returns_pointer_from_raw(&inst.raw_text)
}

/// Returns true if the raw text of a call instruction indicates a pointer
/// return type.
///
/// This is the raw-text parsing fallback used when the structured
/// `result_type` field is not available (text parser path).
fn returns_pointer_from_raw(raw_text: &str) -> bool {
    let text = raw_text.trim();

    // Strip "tail " / "musttail " / "notail " prefix
    let text = text
        .strip_prefix("tail ")
        .or_else(|| text.strip_prefix("musttail "))
        .or_else(|| text.strip_prefix("notail "))
        .unwrap_or(text);

    // Find "call " keyword
    if let Some(call_pos) = text.find("call ") {
        let after_call = &text[call_pos + 5..];

        // The return type is the first token after "call".
        // For pointer returns: "ptr @func" — "ptr" is the immediate next word
        // For variadic: "i32 (ptr, ptr, ...) @func" — return type is "i32"
        // We need to find the immediate return type, not types inside parens.

        // Skip optional calling convention keywords (fastcc, ccc, etc.)
        let after_call = skip_calling_conventions(after_call);

        // The return type is either:
        // - A simple type: "ptr @func" → "ptr"
        // - A complex type: "i32 (ptr, ...) @func" → "i32"
        // - With qualifiers: "noundef ptr @func" → "ptr"
        //
        // Strategy: find the position of '@' and work backwards.
        // Everything between "call" and "@" is the return type + qualifiers.
        if let Some(at_pos) = after_call.find('@') {
            let ret_part = &after_call[..at_pos];

            // If the return type part contains parentheses (function type),
            // the actual return type is before the first '('
            let ret_type = if let Some(paren_pos) = ret_part.find('(') {
                &ret_part[..paren_pos]
            } else {
                ret_part
            };

            // Check if the return type is "ptr" (possibly with qualifiers like "noundef")
            let ret_type = ret_type.trim();
            // The last token before qualifiers should be the type itself
            // e.g., "noundef ptr" → last word is "ptr"
            // e.g., "ptr" → "ptr"
            let last_word = ret_type.split_whitespace().next_back().unwrap_or("");
            return last_word == "ptr";
        }
    }

    false
}

/// Returns true if the call instruction has `noundef` on its return value.
///
/// In LLVM IR, `noundef` on a pointer return indicates the function guarantees
/// a valid (non-null) return value. This is a strong signal from the compiler
/// that the function panics/aborts on error rather than returning null.
///
/// Pattern: `call noundef ptr @func(...)` or `tail call noundef ptr @func(...)`
fn has_noundef_return(inst: &IRInstruction) -> bool {
    let mut inst_clone = inst.clone();
    inst_clone.ensure_raw();
    let raw = inst_clone.raw_text.trim();

    // Strip "tail " / "musttail " / "notail " prefix
    let raw = raw
        .strip_prefix("tail ")
        .or_else(|| raw.strip_prefix("musttail "))
        .or_else(|| raw.strip_prefix("notail "))
        .unwrap_or(raw);

    // After stripping prefix, check for "call noundef ptr" pattern
    // The pattern is: "call [calling_conv] noundef ptr @func(...)"
    if let Some(call_pos) = raw.find("call ") {
        let after_call = &raw[call_pos + 5..];
        // Skip calling conventions
        let after_call = skip_calling_conventions(after_call);
        // Check if "noundef" appears before "ptr"
        return after_call.starts_with("noundef ");
    }

    false
}

/// Skips optional calling convention keywords after "call".
fn skip_calling_conventions(s: &str) -> &str {
    let conventions = [
        "ccc ",
        "fastcc ",
        "coldcc ",
        "webkit_jscc ",
        "anyregcc ",
        "preserve_mostcc ",
        "preserve_allcc ",
        "swiftcc ",
        "swifttailcc ",
        "cfguard_checkcc ",
    ];
    let mut s = s;
    loop {
        let mut found = false;
        for cc in &conventions {
            if s.starts_with(cc) {
                s = &s[cc.len()..];
                found = true;
                break;
            }
        }
        if !found {
            break;
        }
    }
    s
}

/// Returns true if the callee name looks like an FFI function.
///
/// Heuristic: C-style names (alphanumeric + underscores) that aren't
/// Rust mangled names. Supports both lowercase (POSIX) and CamelCase
/// (Windows API, Objective-C) naming conventions.
fn is_likely_ffi_by_name(name: &str) -> bool {
    // Rust v0 mangled names start with _RNv or _RINv
    if name.starts_with("_R") {
        return false;
    }
    // Rust legacy mangled names contain ::
    if name.contains("::") {
        return false;
    }
    // C-style names: alphanumeric with underscores (allows CamelCase for Windows APIs)
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
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
    // NOTE: malloc/calloc/realloc are NOT non-null — they return null on OOM!
    // Only the Rust __rust_alloc wrappers abort on failure.
    // Rust raw ownership — already tracked by RUST_RAW_OWNERSHIP family
    if name.contains("into_raw") || name.contains("from_raw") {
        return true;
    }
    // Drop glue / RAII — never returns null
    if name.contains("drop_in_place") || name.contains("__rust_dealloc") {
        return true;
    }
    // Platform-specific thread-local errno pointer — never null
    if name == "__error" || name == "__errno_location" || name == "___errno" {
        return true;
    }
    false
}

/// Known system and library allocator functions.
///
/// These are standard memory allocation APIs whose return values are
/// commonly used without explicit null checks in production code.
/// Reporting unchecked returns for these generates excessive noise
/// (false positives) because:
/// - OOM handling is often done at a higher layer (panic handler, abort)
/// - Allocation wrappers handle null returns internally
/// - The code pattern may include checks the static analyzer cannot see
///
/// This is NOT a whitelist — it covers well-known system-level allocator
/// APIs that are structurally identical across all codebases.
fn is_system_allocator(name: &str) -> bool {
    matches!(
        name,
        // C standard library allocators
        "malloc" | "calloc" | "realloc" | "aligned_alloc"
            | "posix_memalign" | "valloc" | "pvalloc" | "memalign"
            // Windows allocators
            | "HeapAlloc" | "HeapReAlloc" | "LocalAlloc" | "LocalReAlloc"
            | "GlobalAlloc" | "GlobalReAlloc" | "VirtualAlloc"
            // mimalloc
            | "mi_malloc" | "mi_calloc" | "mi_realloc" | "mi_zalloc"
            | "mi_malloc_aligned" | "mi_realloc_aligned"
            | "mi_malloc_aligned_ctz"
            // jemalloc
            | "je_malloc" | "je_calloc" | "je_realloc" | "je_mallocx"
            | "je_rallocx" | "je_xallocx"
            // tcmalloc
            | "tc_malloc" | "tc_calloc" | "tc_realloc"
            | "tc_malloc_skip_new_handler" | "tc_malloc_nothrow"
    ) || name.starts_with("__rust_alloc")
        || name.starts_with("mi_")
        || name.starts_with("je_")
        || name.starts_with("tc_")
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
        assert_eq!(
            pass.name(),
            "FfiReturnCheck",
            "Pass should have correct name"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Pass should be Analysis kind"
        );
        assert!(
            pass.dependencies().is_empty(),
            "Pass should have no dependencies"
        );
    }

    #[test]
    fn test_is_non_null_api() {
        assert!(
            is_non_null_api("__rust_alloc"),
            "__rust_alloc should be recognized as non-null API"
        );
        assert!(
            is_non_null_api("Box::into_raw"),
            "Box::into_raw should be recognized as non-null API"
        );
        // malloc is NOT non-null — it can return null!
        assert!(
            !is_non_null_api("malloc"),
            "malloc should NOT be recognized as non-null API"
        );
        assert!(
            !is_non_null_api("calloc"),
            "calloc should NOT be recognized as non-null API"
        );
        assert!(
            !is_non_null_api("ffi_get_buffer"),
            "ffi_get_buffer should NOT be recognized as non-null API"
        );
    }

    #[test]
    fn test_is_null_sink() {
        assert!(
            is_null_sink("strlen"),
            "strlen should be recognized as null sink"
        );
        assert!(
            is_null_sink("free"),
            "free should be recognized as null sink"
        );
        assert!(
            is_null_sink("memcpy"),
            "memcpy should be recognized as null sink"
        );
        assert!(
            !is_null_sink("some_other_func"),
            "some_other_func should NOT be recognized as null sink"
        );
    }

    #[test]
    fn test_is_likely_ffi_by_name() {
        assert!(
            is_likely_ffi_by_name("ffi_get_buffer"),
            "ffi_get_buffer should be recognized as likely FFI"
        );
        assert!(
            is_likely_ffi_by_name("curl_easy_init"),
            "curl_easy_init should be recognized as likely FFI"
        );
        assert!(
            !is_likely_ffi_by_name("_RNvCsome_rust_mangled"),
            "Rust mangled names should NOT be recognized as likely FFI"
        );
        assert!(
            !is_likely_ffi_by_name("Some::rust_func"),
            "Rust qualified names should NOT be recognized as likely FFI"
        );
    }

    #[test]
    fn test_returns_pointer() {
        assert!(
            returns_pointer_from_raw("  %p = call ptr @ffi_get()"),
            "call ptr @ffi_get() should be recognized as returning pointer"
        );
        assert!(
            returns_pointer_from_raw("  %p = tail call ptr @malloc(i64 %n)"),
            "tail call ptr @malloc should be recognized as returning pointer"
        );
        assert!(
            returns_pointer_from_raw("  %p = call noundef ptr @fopen(ptr %s, ptr %m)"),
            "call noundef ptr @fopen should be recognized as returning pointer"
        );
        assert!(
            !returns_pointer_from_raw("  %r = call i32 @c_hash(ptr %p, i64 %n)"),
            "call i32 should NOT be recognized as returning pointer"
        );
        assert!(
            !returns_pointer_from_raw("  %t = call i64 @time(ptr null)"),
            "call i64 should NOT be recognized as returning pointer"
        );
        assert!(
            !returns_pointer_from_raw("  call void @free(ptr %p)"),
            "call void should NOT be recognized as returning pointer"
        );
        // Variadic: return type is i32, not ptr
        assert!(
            !returns_pointer_from_raw(
                "  %16 = tail call i32 (ptr, ptr, ...) @fprintf(ptr %f, ptr %s)"
            ),
            "variadic call returning i32 should NOT be recognized as returning pointer"
        );
        assert!(
            !returns_pointer_from_raw(
                "  %112 = tail call i32 (ptr, i64, ptr, ...) @snprintf(ptr %b, i64 %n, ptr %f)"
            ),
            "variadic call returning i32 should NOT be recognized as returning pointer"
        );
    }

    /// TP: FFI call returning ptr, immediately load without null check
    #[test]
    fn test_e2e_ffi_return_unchecked_load_tp() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

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

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        let unchecked_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::UncheckedFfiReturn)
            .collect();
        assert!(
            !unchecked_candidates.is_empty(),
            "FFI return value used in load without null check MUST produce UncheckedFfiReturn candidate, got {} candidates",
            candidates.len()
        );
    }

    /// TP: FFI call returning ptr, passed to strlen without null check
    #[test]
    fn test_e2e_ffi_return_unchecked_strlen_tp() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

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

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        let null_deref_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::NullDereference)
            .collect();
        assert!(
            !null_deref_candidates.is_empty(),
            "FFI return value passed to strlen without null check MUST produce NullDereference candidate, got {} candidates",
            candidates.len()
        );
    }

    /// FP guard: null-checked FFI return is safe to use
    #[test]
    fn test_e2e_ffi_return_null_checked_no_false_positive() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

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

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        let unchecked_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::UncheckedFfiReturn)
            .collect();
        assert!(
            unchecked_candidates.is_empty(),
            "Null-checked FFI return must NOT produce UncheckedFfiReturn candidates, got {} candidates",
            unchecked_candidates.len()
        );
    }

    /// FP guard with raw/parser edge: null comparison must be used by a branch.
    /// A dead `icmp %p, null` must not suppress a later unsafe load.
    #[test]
    fn test_e2e_dead_null_compare_still_reports() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

        let ir = r#"
            declare ptr @ffi_get()

            define void @dead_compare() {
                %p = call ptr @ffi_get()
                %isnull = icmp eq ptr %p, null
                %v = load i8, ptr %p
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        assert!(
            candidates
                .iter()
                .any(|c| c.kind == IssueCandidateKind::UncheckedFfiReturn),
            "dead null comparison must not suppress unchecked load"
        );
    }

    /// FP guard: branching on an unrelated compare must not mark the FFI
    /// return as null-checked.
    #[test]
    fn test_e2e_unrelated_branch_compare_still_reports() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

        let ir = r#"
            declare ptr @ffi_get()

            define void @wrong_branch(ptr %q) {
                %p = call ptr @ffi_get()
                %qnull = icmp eq ptr %q, null
                br i1 %qnull, label %null, label %ok
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

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        assert!(
            candidates
                .iter()
                .any(|c| c.kind == IssueCandidateKind::UncheckedFfiReturn),
            "branching on a different pointer must not suppress unchecked FFI return"
        );
    }

    /// TP guard: use-before-check is still unsafe even if a later branch checks
    /// the same pointer.
    #[test]
    fn test_e2e_use_before_late_null_check_reports() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

        let ir = r#"
            declare ptr @ffi_get()

            define void @late_check() {
                %p = call ptr @ffi_get()
                %v = load i8, ptr %p
                %isnull = icmp eq ptr %p, null
                br i1 %isnull, label %null, label %ok
            null:
                ret void
            ok:
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        assert!(
            candidates
                .iter()
                .any(|c| c.kind == IssueCandidateKind::UncheckedFfiReturn),
            "null check after the first dereference must not suppress the report"
        );
    }

    /// FP guard: a null-sensitive sink after a real branch guard should not
    /// produce NullDereference.
    #[test]
    fn test_e2e_null_sink_after_branch_guard_no_false_positive() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

        let ir = r#"
            declare ptr @ffi_get()
            declare i64 @strlen(ptr)

            define i64 @safe_strlen() {
                %p = call ptr @ffi_get()
                %isnull = icmp eq ptr %p, null
                br i1 %isnull, label %null, label %ok
            null:
                ret i64 0
            ok:
                %len = call i64 @strlen(ptr %p)
                ret i64 %len
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        assert!(
            !candidates
                .iter()
                .any(|c| c.kind == IssueCandidateKind::NullDereference),
            "null-sensitive sink after a branch guard must not report NullDereference"
        );
    }

    /// FP guard: Box::into_raw is skipped (raw ownership, not FFI null)
    #[test]
    fn test_e2e_box_into_raw_no_false_positive() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

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

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        let unchecked_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::UncheckedFfiReturn)
            .collect();
        assert!(
            unchecked_candidates.is_empty(),
            "Box::into_raw must NOT produce UncheckedFfiReturn candidates, got {} candidates",
            unchecked_candidates.len()
        );
    }

    /// FP guard: System allocators (malloc, calloc, aligned_alloc) are skipped
    /// to suppress malloc_unchecked noise. OOM handling is typically at a higher layer.
    #[test]
    fn test_e2e_system_allocator_suppressed() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

        // malloc without null check — should NOT produce UncheckedReturn
        let ir = r#"
            declare ptr @malloc(i64)
            declare ptr @calloc(i64, i64)
            declare ptr @aligned_alloc(i64, i64)

            define void @alloc_patterns() {
                %p1 = call ptr @malloc(i64 100)
                %v1 = load i8, ptr %p1
                %p2 = call ptr @calloc(i64 10, i64 10)
                %v2 = load i8, ptr %p2
                %p3 = call ptr @aligned_alloc(i64 16, i64 256)
                %v3 = load i8, ptr %p3
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        let unchecked_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::UncheckedFfiReturn)
            .collect();
        assert!(
            unchecked_candidates.is_empty(),
            "System allocators (malloc/calloc/aligned_alloc) must NOT produce UncheckedFfiReturn candidates, got {} candidates",
            unchecked_candidates.len()
        );
    }

    /// FP guard: mimalloc / jemalloc / tcmalloc allocators are skipped.
    #[test]
    fn test_e2e_custom_allocator_suppressed() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

        let ir = r#"
            declare ptr @mi_malloc(i64)
            declare ptr @je_malloc(i64)
            declare ptr @tc_malloc(i64)

            define void @custom_alloc() {
                %p1 = call ptr @mi_malloc(i64 64)
                %v1 = load i8, ptr %p1
                %p2 = call ptr @je_malloc(i64 128)
                %v2 = load i8, ptr %p2
                %p3 = call ptr @tc_malloc(i64 256)
                %v3 = load i8, ptr %p3
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        let unchecked_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::UncheckedFfiReturn)
            .collect();
        assert!(
            unchecked_candidates.is_empty(),
            "Custom allocators (mi_malloc/je_malloc/tc_malloc) must NOT produce UncheckedFfiReturn candidates, got {} candidates",
            unchecked_candidates.len()
        );
    }

    /// FP guard: FFI calls with `noundef` on the return value are skipped for
    /// UncheckedFfiReturn. `noundef` indicates the compiler guarantees a non-null
    /// return (e.g., Rust wrappers that panic/abort on error).
    #[test]
    fn test_e2e_noundef_return_suppressed() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

        let ir = r#"
            declare ptr @duckdb_vector_get_data(ptr)

            define void @noundef_test(ptr %vec) {
                %p = call noundef ptr @duckdb_vector_get_data(ptr %vec)
                %v = load i8, ptr %p
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        let unchecked_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::UncheckedFfiReturn)
            .collect();
        assert!(
            unchecked_candidates.is_empty(),
            "FFI calls with noundef return must NOT produce UncheckedFfiReturn candidates, got {} candidates",
            unchecked_candidates.len()
        );
    }

    /// TP guard: `noundef` FFI returns passed to null-sink functions still
    /// produce NullDereference. Even though the compiler guarantees non-null,
    /// defensive null-sink checks are still valuable.
    #[test]
    fn test_e2e_noundef_null_sink_still_detected() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

        let ir = r#"
            declare ptr @duckdb_vector_get_data(ptr)
            declare i64 @strlen(ptr)

            define i64 @noundef_strlen(ptr %vec) {
                %p = call noundef ptr @duckdb_vector_get_data(ptr %vec)
                %len = call i64 @strlen(ptr %p)
                ret i64 %len
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        let null_deref_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::NullDereference)
            .collect();
        assert!(
            !null_deref_candidates.is_empty(),
            "noundef FFI return passed to strlen MUST produce NullDereference candidate, got {} candidates",
            candidates.len()
        );
    }

    /// TP: Non-allocator FFI calls returning ptr still produce UncheckedReturn.
    #[test]
    fn test_e2e_non_allocator_still_detected() {
        use crate::pass::PassContext;
        use omniscope_core::IssueCandidate;
        use omniscope_ir::IRModule;
        use omniscope_types::IssueCandidateKind;

        // fopen is NOT an allocator — should still be flagged
        let ir = r#"
            declare ptr @fopen(ptr, ptr)

            define void @file_open() {
                %f = call ptr @fopen(ptr %path, ptr %mode)
                %v = load i8, ptr %f
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let candidates: Vec<IssueCandidate> = ctx.get("ffi_return_candidates").unwrap_or_default();
        let unchecked_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.kind == IssueCandidateKind::UncheckedFfiReturn)
            .collect();
        assert!(
            !unchecked_candidates.is_empty(),
            "Non-allocator FFI (fopen) must still produce UncheckedFfiReturn candidate, got 0 candidates",
        );
    }

    /// Objective: Verify null_checked_functions is populated when a function has
    /// null-check patterns (icmp eq ptr + br).
    /// Invariants: Functions with null-checked FFI returns must be tracked for
    /// SRT-based NullChecked suppression in the IssueGate.
    #[test]
    fn test_e2e_null_checked_functions_populated() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        // Function with null-check pattern: icmp + br + use in non-null arm
        let ir = r#"
            declare ptr @ffi_get()

            define void @null_aware_func() {
                %p = call ptr @ffi_get()
                %isnull = icmp eq ptr %p, null
                br i1 %isnull, label %null, label %ok
            null:
                ret void
            ok:
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let null_checked: std::collections::HashSet<String> =
            ctx.get("null_checked_functions").unwrap_or_default();
        assert!(
            null_checked.contains("null_aware_func") || null_checked.contains("@null_aware_func"),
            "Function with icmp+br null-check pattern must be in null_checked_functions, got: {:?}",
            null_checked
        );
    }

    /// Objective: Verify null_checked_functions is NOT populated when a function
    /// has no null-check patterns.
    /// Invariants: Functions without null-check patterns must not be tracked.
    #[test]
    fn test_e2e_null_checked_functions_not_populated_without_check() {
        use crate::pass::PassContext;
        use omniscope_ir::IRModule;

        // Function without null-check pattern: direct use of FFI return
        let ir = r#"
            declare ptr @ffi_get()

            define void @unaware_func() {
                %p = call ptr @ffi_get()
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let mut ctx = PassContext::new();
        ctx.store("ir_module", module);

        let _result = FfiReturnCheckPass::new()
            .run(&mut ctx)
            .expect("FfiReturnCheckPass run failed");

        let null_checked: std::collections::HashSet<String> =
            ctx.get("null_checked_functions").unwrap_or_default();
        assert!(
            !null_checked.contains("unaware_func") && !null_checked.contains("@unaware_func"),
            "Function without null-check pattern must NOT be in null_checked_functions, got: {:?}",
            null_checked
        );
    }
}
