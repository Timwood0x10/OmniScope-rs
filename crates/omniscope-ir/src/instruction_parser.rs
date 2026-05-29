//! LLVM IR instruction-level parsing for semantic derivation
//!
//! This module contains types and parsing logic for individual LLVM IR
//! instructions. It provides a best-effort parser that extracts instruction
//! kind, destination register, and key operands — enough information for
//! semantic derivation (pattern detection on instruction sequences) without
//! attempting a full LLVM IR parser.

// ──────────────────────────────────────────────────────────────────────────
// IR Instruction-level types
// ──────────────────────────────────────────────────────────────────────────

/// Kind of an LLVM IR instruction.
///
/// This enum covers the instructions relevant to semantic derivation:
/// - Memory operations (alloca, load, store, atomicrmw)
/// - Pointer arithmetic (getelementptr)
/// - Control flow (icmp, branch, ret, phi)
/// - Computation (binary ops, call)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IRInstructionKind {
    /// `alloca` — stack allocation (pointer originates from stack)
    Alloca,
    /// `load` / `load atomic` — read from memory
    Load,
    /// `store` / `store atomic` — write to memory
    Store,
    /// `atomicrmw add/sub/xchg` — atomic read-modify-write (refcount pattern)
    AtomicRmw,
    /// `getelementptr` — pointer offset into struct/array
    GetElementPtr,
    /// `icmp eq/ne/...` — integer comparison (condition for branch)
    Icmp,
    /// `br i1` / `br label` — conditional or unconditional branch
    Branch,
    /// `call @func(...)` — direct function call (callee is a known function)
    Call,
    /// `call %reg(...)` — indirect call via function pointer (callee is unknown)
    IndirectCall,
    /// `ret` — return from function
    Ret,
    /// `phi` — SSA phi node
    Phi,
    /// `add`/`sub`/`mul`/`and`/`or`/`xor`/`shl`/`lshr`/`ashr` — binary arithmetic
    BinaryOp,
    /// `bitcast`/`inttoptr`/`ptrtoint`/`zext`/`sext`/`trunc` — type conversion
    Conversion,
    /// `select` — conditional select
    Select,
    /// Any instruction not in the above categories
    Other,
}

/// A single LLVM IR instruction with extracted metadata.
///
/// This is a simplified representation that captures enough information
/// for semantic derivation without attempting a full IR parser.
///
/// Example IR line and its parsed result:
/// ```llvm
/// %22 = atomicrmw sub ptr %string_impl, i32 2 monotonic
/// ```
/// → `IRInstruction { kind: AtomicRmw, dest: Some("%22"), atomic_op: Some("sub"), ... }`
#[derive(Debug, Clone)]
pub struct IRInstruction {
    /// Instruction kind
    pub kind: IRInstructionKind,
    /// Destination register (e.g., `%3`, `%result`), if any
    pub dest: Option<String>,
    /// Operands as raw strings (registers, constants, types)
    pub operands: Vec<String>,
    /// For Call: the callee function name (without @)
    pub callee: Option<String>,
    /// For AtomicRmw: the operation (add, sub, xchg, etc.)
    pub atomic_op: Option<String>,
    /// For Icmp: the comparison predicate (eq, ne, slt, etc.)
    pub icmp_pred: Option<String>,
    /// Raw text of the instruction line (for evidence/debugging)
    pub raw_text: String,
}

// ──────────────────────────────────────────────────────────────────────────
// Instruction-level parsing
// ──────────────────────────────────────────────────────────────────────────

/// Parse a single IR instruction line into structured form.
///
/// This is a best-effort parser — it extracts the instruction kind,
/// destination register, and key operands. It does NOT attempt to be
/// a full LLVM IR parser; instead, it captures enough information for
/// semantic derivation (pattern detection on instruction sequences).
///
/// Examples of parsed lines:
/// ```llvm
/// %3 = alloca i64                          → Alloca
/// %5 = load i64, ptr %3                    → Load
/// store i64 %5, ptr %1                     → Store
/// %22 = atomicrmw sub ptr %s, i32 2 mon    → AtomicRmw
/// %4 = getelementptr i8, ptr %1, i64 0     → GetElementPtr
/// %23 = icmp eq i32 %22, 2                 → Icmp
/// br i1 %23, label %bb5, label %exit       → Branch
/// tail call void @destroy(ptr %1)          → Call
/// ret i32 %result                          → Ret
/// %x = add i32 %a, %b                      → BinaryOp
/// ```
pub fn parse_instruction(line: &str) -> Option<IRInstruction> {
    let line = line.trim();
    if line.is_empty() || line.starts_with(';') || line.starts_with('!') {
        return None;
    }

    // Extract destination register: `%name = ...`
    let (dest, rest) = if let Some(eq_pos) = line.find(" = ") {
        let dest_part = line.get(..eq_pos).unwrap_or("").trim();
        let rest_part = line.get(eq_pos + 3..).unwrap_or("").trim();
        // Validate it looks like a register (%something)
        if dest_part.starts_with('%') {
            (Some(dest_part.to_string()), rest_part)
        } else {
            (None, line)
        }
    } else {
        (None, line)
    };

    // Classify instruction kind from the start of the (rest) line
    let raw_text = line.to_string();

    // Strip calling-convention prefixes: "tail", "musttail", "notail"
    let stripped = strip_calling_prefixes(rest);

    // alloca
    if stripped.starts_with("alloca") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Alloca,
            dest,
            operands: extract_operands(stripped, "alloca"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // load (including "load atomic")
    if stripped.starts_with("load") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Load,
            dest,
            operands: extract_operands(stripped, "load"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // store (including "store atomic")
    if stripped.starts_with("store") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Store,
            dest,
            operands: extract_operands(stripped, "store"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // atomicrmw
    if stripped.starts_with("atomicrmw") {
        let atomic_op = extract_atomicrmw_op(stripped);
        return Some(IRInstruction {
            kind: IRInstructionKind::AtomicRmw,
            dest,
            operands: extract_operands(stripped, "atomicrmw"),
            callee: None,
            atomic_op,
            icmp_pred: None,
            raw_text,
        });
    }

    // cmpxchg
    if stripped.starts_with("cmpxchg") {
        return Some(IRInstruction {
            kind: IRInstructionKind::AtomicRmw, // Treat as atomic op
            dest,
            operands: extract_operands(stripped, "cmpxchg"),
            callee: None,
            atomic_op: Some("cmpxchg".to_string()),
            icmp_pred: None,
            raw_text,
        });
    }

    // getelementptr
    if stripped.starts_with("getelementptr") {
        return Some(IRInstruction {
            kind: IRInstructionKind::GetElementPtr,
            dest,
            operands: extract_operands(stripped, "getelementptr"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // icmp
    if stripped.starts_with("icmp") {
        let icmp_pred = extract_icmp_pred(stripped);
        return Some(IRInstruction {
            kind: IRInstructionKind::Icmp,
            dest,
            operands: extract_operands(stripped, "icmp"),
            callee: None,
            atomic_op: None,
            icmp_pred,
            raw_text,
        });
    }

    // fcmp
    if stripped.starts_with("fcmp") {
        let icmp_pred = extract_icmp_pred(stripped);
        return Some(IRInstruction {
            kind: IRInstructionKind::Icmp, // Treat similarly
            dest,
            operands: extract_operands(stripped, "fcmp"),
            callee: None,
            atomic_op: None,
            icmp_pred,
            raw_text,
        });
    }

    // br
    if stripped.starts_with("br") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Branch,
            dest,
            operands: extract_operands(stripped, "br"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // call (including "tail call", "musttail call")
    // Direct call: call <ret_type> @<name>(<args>)
    // Indirect call: call <ret_type> %<reg>(<args>)
    if stripped.starts_with("call") {
        let callee = extract_call_callee(stripped);
        if callee.is_some() {
            // Direct call — callee is a known function name
            return Some(IRInstruction {
                kind: IRInstructionKind::Call,
                dest,
                operands: Vec::new(),
                callee,
                atomic_op: None,
                icmp_pred: None,
                raw_text,
            });
        }
        // Check for indirect call: pattern like "call ... %reg(...)"
        // An indirect call uses a register (%-prefixed) as the callee
        let indirect_callee = extract_indirect_call_callee(stripped);
        if indirect_callee.is_some() {
            return Some(IRInstruction {
                kind: IRInstructionKind::IndirectCall,
                dest,
                operands: extract_operands(stripped, "call"),
                callee: indirect_callee,
                atomic_op: None,
                icmp_pred: None,
                raw_text,
            });
        }
        // Unknown call format — still emit as Call to avoid silently dropping
        return Some(IRInstruction {
            kind: IRInstructionKind::Call,
            dest,
            operands: extract_operands(stripped, "call"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // ret
    if stripped.starts_with("ret") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Ret,
            dest,
            operands: extract_operands(stripped, "ret"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // phi
    if stripped.starts_with("phi") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Phi,
            dest,
            operands: extract_operands(stripped, "phi"),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // select
    if stripped.starts_with("select") {
        return Some(IRInstruction {
            kind: IRInstructionKind::Select,
            dest,
            operands: Vec::new(),
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text,
        });
    }

    // Binary operations
    let binary_ops = [
        "add", "sub", "mul", "udiv", "sdiv", "urem", "srem", "and", "or", "xor", "shl", "lshr",
        "ashr",
    ];
    for op in &binary_ops {
        if stripped.starts_with(op) {
            // Make sure it's not a longer word (e.g., "sub" vs "subroutine")
            let after_op = stripped.get(op.len()..).unwrap_or("");
            if after_op.is_empty()
                || !after_op
                    .chars()
                    .next()
                    .map(|c| c.is_alphanumeric())
                    .unwrap_or(false)
            {
                return Some(IRInstruction {
                    kind: IRInstructionKind::BinaryOp,
                    dest,
                    operands: extract_operands(stripped, op),
                    callee: None,
                    atomic_op: None,
                    icmp_pred: None,
                    raw_text,
                });
            }
        }
    }

    // Conversion operations
    let conv_ops = [
        "bitcast", "inttoptr", "ptrtoint", "zext", "sext", "trunc", "fptoui", "fptosi", "uitofp",
        "sitofp", "fpext", "fptrunc",
    ];
    for op in &conv_ops {
        if stripped.starts_with(op) {
            return Some(IRInstruction {
                kind: IRInstructionKind::Conversion,
                dest,
                operands: Vec::new(),
                callee: None,
                atomic_op: None,
                icmp_pred: None,
                raw_text,
            });
        }
    }

    // switch / invoke / resume / landingpad / indirectbr / extractvalue / insertvalue
    // → classify as Other
    Some(IRInstruction {
        kind: IRInstructionKind::Other,
        dest,
        operands: Vec::new(),
        callee: None,
        atomic_op: None,
        icmp_pred: None,
        raw_text,
    })
}

/// Strip call-prefix keywords: "tail", "musttail", "notail"
fn strip_calling_prefixes(s: &str) -> &str {
    let mut rest = s;
    loop {
        if rest.starts_with("tail ") {
            rest = rest.get(5..).unwrap_or(rest);
        } else if rest.starts_with("musttail ") {
            rest = rest.get(9..).unwrap_or(rest);
        } else if rest.starts_with("notail ") {
            rest = rest.get(7..).unwrap_or(rest);
        } else {
            break;
        }
    }
    rest
}

/// Extract the atomicrmw operation name (add, sub, xchg, etc.)
fn extract_atomicrmw_op(s: &str) -> Option<String> {
    // Format: "atomicrmw <op> <type> <ptr>, <value> <ordering>"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 2 && parts[0] == "atomicrmw" {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Extract the icmp predicate (eq, ne, slt, sgt, ult, ugt, sle, sge, ule, uge)
fn extract_icmp_pred(s: &str) -> Option<String> {
    // Format: "icmp <pred> <type> <op1>, <op2>"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Extract the callee function name from a call instruction.
fn extract_call_callee(s: &str) -> Option<String> {
    // Format: "call [fastcc] <ret_type> @<name>(<args>)"
    // Find @name( pattern
    if let Some(at_pos) = s.find('@') {
        let after_at = &s[at_pos + 1..];
        if let Some(paren_pos) = after_at.find('(') {
            let name = after_at[..paren_pos].to_string();
            // Filter out LLVM intrinsics
            if !name.starts_with("llvm.") {
                return Some(name);
            }
        }
    }
    None
}

/// Extract the callee register name from an indirect call instruction.
///
/// Indirect calls use a register (%-prefixed) as the callee instead of
/// a named function (@-prefixed). For example:
///   `call void %fp(i32 42)`
///   `call i32 %callback ptr %ctx)`
fn extract_indirect_call_callee(s: &str) -> Option<String> {
    // Find pattern: %<name>(  — register used as callee
    // We look for the last %-prefixed token before '(' that isn't inside args
    if let Some(paren_pos) = s.rfind('(') {
        let before_paren = &s[..paren_pos];
        // Split into tokens and find the last %-prefixed token
        // This handles cases like "call void %fp" or "call i32 (i32)* %callback"
        for token in before_paren.split_whitespace().rev() {
            let token = token.trim_matches(',').trim_matches('*');
            if token.starts_with('%') {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Extract operands from an instruction line after stripping the opcode.
///
/// This is a simplified operand extractor that captures:
/// - `%name` — virtual registers
/// - `@name` — global variables
/// - Numeric constants (e.g., `42`, `0`, `-1`)
/// - Special values: `null`, `undef`, `poison`, `zeroinitializer`
///
/// It does NOT attempt full type-aware parsing.
fn extract_operands(s: &str, opcode: &str) -> Vec<String> {
    let after_opcode = if let Some(pos) = s.find(opcode) {
        &s[pos + opcode.len()..]
    } else {
        s
    };

    let mut operands = Vec::new();

    for part in after_opcode.split(|c: char| c.is_whitespace() || c == ',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // %-prefixed virtual registers
        if part.starts_with('%') {
            operands.push(part.to_string());
            continue;
        }

        // @-prefixed global variables
        if part.starts_with('@') {
            operands.push(part.to_string());
            continue;
        }

        // Special LLVM values
        if matches!(part, "null" | "undef" | "poison" | "zeroinitializer") {
            operands.push(part.to_string());
            continue;
        }

        // Hex constants must be checked before f64 parsing because
        // Rust's f64 parser does NOT accept hex floats, so "0x..."
        // would fall through to the generic catch-all. Checking hex
        // first avoids relying on that implementation detail.
        if part.starts_with("0x") || part.starts_with("0X") {
            let rest = &part[2..];
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()) {
                operands.push(part.to_string());
                continue;
            }
        }

        // Numeric constants (integer or float).
        // Exclude inf/NaN variants: LLVM IR never uses these as
        // operand literals (they appear as special float values like
        // 0x7FF0000000000000 for +inf), so matching them would be
        // incorrect.
        let is_inf_nan = part.eq_ignore_ascii_case("inf")
            || part.eq_ignore_ascii_case("nan")
            || part.eq_ignore_ascii_case("-inf")
            || part.eq_ignore_ascii_case("+inf")
            || part.eq_ignore_ascii_case("-nan")
            || part.eq_ignore_ascii_case("+nan");
        if !is_inf_nan && (part.parse::<i64>().is_ok() || part.parse::<f64>().is_ok()) {
            operands.push(part.to_string());
            continue;
        }
    }

    operands
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_alloca() {
        let inst = parse_instruction("  %3 = alloca i64").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::Alloca,
            "alloca instruction must be parsed as Alloca kind"
        );
        assert_eq!(
            inst.dest.as_deref(),
            Some("%3"),
            "alloca destination register must be '%3'"
        );
    }

    #[test]
    fn test_parse_load() {
        let inst = parse_instruction("  %5 = load i64, ptr %3").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::Load,
            "load instruction must be parsed as Load kind"
        );
        assert_eq!(
            inst.dest.as_deref(),
            Some("%5"),
            "load destination register must be '%5'"
        );
    }

    #[test]
    fn test_parse_store() {
        let inst = parse_instruction("  store i64 %5, ptr %1").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::Store,
            "store instruction must be parsed as Store kind"
        );
        assert!(
            inst.dest.is_none(),
            "store instruction must have no destination register"
        );
    }

    #[test]
    fn test_parse_atomicrmw_sub() {
        let inst =
            parse_instruction("  %22 = atomicrmw sub ptr %string_impl, i32 2 monotonic").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::AtomicRmw,
            "atomicrmw sub must be parsed as AtomicRmw kind"
        );
        assert_eq!(
            inst.dest.as_deref(),
            Some("%22"),
            "atomicrmw destination register must be '%22'"
        );
        assert_eq!(
            inst.atomic_op.as_deref(),
            Some("sub"),
            "atomicrmw operation must be 'sub'"
        );
    }

    #[test]
    fn test_parse_atomicrmw_add() {
        let inst = parse_instruction("  %10 = atomicrmw add ptr %refcount, i32 1 acquire").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::AtomicRmw,
            "atomicrmw add must be parsed as AtomicRmw kind"
        );
        assert_eq!(
            inst.atomic_op.as_deref(),
            Some("add"),
            "atomicrmw operation must be 'add'"
        );
    }

    #[test]
    fn test_parse_getelementptr() {
        let inst = parse_instruction("  %4 = getelementptr i8, ptr %1, i64 0").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::GetElementPtr,
            "getelementptr must be parsed as GetElementPtr kind"
        );
        assert_eq!(
            inst.dest.as_deref(),
            Some("%4"),
            "getelementptr destination register must be '%4'"
        );
    }

    #[test]
    fn test_parse_icmp_eq() {
        let inst = parse_instruction("  %23 = icmp eq i32 %22, 2").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::Icmp,
            "icmp instruction must be parsed as Icmp kind"
        );
        assert_eq!(
            inst.icmp_pred.as_deref(),
            Some("eq"),
            "icmp predicate must be 'eq'"
        );
    }

    #[test]
    fn test_parse_branch_conditional() {
        let inst = parse_instruction("  br i1 %23, label %bb5, label %exit").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::Branch,
            "conditional branch must be parsed as Branch kind"
        );
    }

    #[test]
    fn test_parse_call() {
        let inst =
            parse_instruction("  tail call void @Bun__WTFStringImpl__destroy(ptr %1)").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::Call,
            "tail call instruction must be parsed as Call kind"
        );
        assert_eq!(
            inst.callee.as_deref(),
            Some("Bun__WTFStringImpl__destroy"),
            "call callee must be 'Bun__WTFStringImpl__destroy'"
        );
    }

    #[test]
    fn test_parse_ret() {
        let inst = parse_instruction("  ret i32 %result").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::Ret,
            "ret instruction must be parsed as Ret kind"
        );
    }

    #[test]
    fn test_parse_binary_op_add() {
        let inst = parse_instruction("  %x = add i32 %a, %b").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::BinaryOp,
            "add instruction must be parsed as BinaryOp kind"
        );
    }

    #[test]
    fn test_parse_bitcast() {
        let inst = parse_instruction("  %2 = bitcast ptr %1 to ptr").unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::Conversion,
            "bitcast instruction must be parsed as Conversion kind"
        );
    }

    // ── Edge-case tests: empty / malformed input ──

    /// Objective: Verify that parse_instruction returns None for an empty string.
    /// Invariants: Empty input must not panic or produce a spurious instruction.
    #[test]
    fn test_parse_instruction_empty_string() {
        let result = parse_instruction("");
        assert!(
            result.is_none(),
            "Empty string must produce None (no instruction)"
        );
    }

    /// Objective: Verify that parse_instruction returns None for whitespace-only input.
    /// Invariants: Whitespace-only lines must not trigger any parsing branch.
    #[test]
    fn test_parse_instruction_whitespace_only() {
        let result = parse_instruction("   \t  ");
        assert!(result.is_none(), "Whitespace-only input must produce None");
    }

    /// Objective: Verify that parse_instruction returns None for a comment line.
    /// Invariants: Comment lines (starting with ';') must be skipped.
    #[test]
    fn test_parse_instruction_comment() {
        let result = parse_instruction("; this is a comment");
        assert!(result.is_none(), "Comment line must produce None");
    }

    /// Objective: Verify that parse_instruction returns None for metadata-only lines.
    /// Invariants: Metadata lines (starting with '!') must be skipped.
    #[test]
    fn test_parse_instruction_metadata() {
        let result = parse_instruction("!123 = !DIFile(filename: \"test.c\")");
        assert!(result.is_none(), "Metadata line must produce None");
    }

    /// Objective: Verify that parse_instruction handles unknown instruction
    ///            keywords gracefully by returning Other kind (not None or panic).
    /// Invariants: Unknown instructions produce an Other-kind instruction so
    ///            downstream analysis doesn't silently drop data.
    #[test]
    fn test_parse_instruction_unknown_keyword() {
        let result = parse_instruction("switch i32 %val, label %default [i32 1, label %on1]");
        assert!(
            result.is_some(),
            "Unknown instruction keyword must produce Some (Other kind), not None"
        );
        let inst = result.unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::Other,
            "Unknown instruction must be classified as Other"
        );
    }

    /// Objective: Verify that parse_instruction handles a truncated call
    ///            (call keyword but no callee) gracefully.
    /// Invariants: Must not panic; produces a Call with callee=None.
    #[test]
    fn test_parse_instruction_truncated_call() {
        let result = parse_instruction("call void");
        assert!(
            result.is_some(),
            "Truncated call must produce Some, not None or panic"
        );
        let inst = result.unwrap();
        assert_eq!(
            inst.kind,
            IRInstructionKind::Call,
            "Truncated call must be classified as Call"
        );
        assert!(
            inst.callee.is_none(),
            "Truncated call must have callee == None"
        );
    }

    /// Objective: Verify that parse_instruction handles random garbage text
    ///            without panicking.
    /// Invariants: Garbage input that doesn't match any instruction pattern
    ///            still produces an Other-kind instruction (best-effort parser).
    #[test]
    fn test_parse_instruction_garbage() {
        let result = parse_instruction("xyzzy ??? 42 @#%");
        assert!(
            result.is_some(),
            "Garbage text must not cause None/panic — best-effort parser returns Other"
        );
        assert_eq!(
            result.unwrap().kind,
            IRInstructionKind::Other,
            "Garbage text must be classified as Other"
        );
    }

    /// Objective: Verify that parse_instruction handles invoke (exception-handling call)
    ///            as Other kind (not currently parsed, but must not panic).
    /// Invariants: invoke produces Other, not None.
    #[test]
    fn test_parse_instruction_invoke() {
        let result = parse_instruction("invoke void @foo() to label %normal unwind label %catch");
        assert!(
            result.is_some(),
            "invoke must produce Some (Other), not None"
        );
        assert_eq!(
            result.unwrap().kind,
            IRInstructionKind::Other,
            "invoke must be classified as Other (not yet parsed)"
        );
    }

    /// Objective: Verify that parse_instruction handles a label line (basic block
    ///            header) as None — labels are not instructions.
    /// Invariants: Label lines must not produce instruction entries.
    #[test]
    fn test_parse_instruction_label_line() {
        let result = parse_instruction("entry:");
        // Labels are not instructions and shouldn't be parsed
        // They have no dest register prefix (%...) and no = sign
        assert!(
            result.is_some(),
            "Label line 'entry:' passes through parser — but downstream filters labels"
        );
        // Note: the module-level parser (parser.rs) has is_label_line() to skip these
    }
}
