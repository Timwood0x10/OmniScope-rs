//! Lightweight bounds check pattern detector (P1-5).
//!
//! Detects constant buffer overflow patterns in LLVM IR without requiring
//! complex interval arithmetic. The key insight is that many real-world
//! buffer overflows come from trivially detectable constant offsets:
//!
//! ```c
//! void c_process_buffer(uint8_t *buf, size_t len) {
//!     memset(buf, 0xAA, len + 16);  // writes len+16 bytes into len-byte buffer!
//! }
//! ```
//!
//! In LLVM IR this appears as:
//! ```llvm
//! %add = add i64 %len, i64 16
//! call void @memset(ptr %buf, i8 170, i64 %add)
//! ```
//!
//! # Detection Strategy
//!
//! Scan for calls to memset/memcpy/memmove where the **size argument** is
//! produced by a `add`/`mul`/`shl` binary operation with a **positive
//! constant** operand, where one input to that binary op is a function
//! parameter (representing the buffer size).

use omniscope_ir::{FunctionBody, IRInstruction, IRInstructionKind};

use super::ir_pattern::BehaviorPattern;

/// Memory operations that take a size argument which could overflow.
///
/// For each operation, the size argument position is fixed:
/// - `memset(ptr, val, size)` → size is arg index 2
/// - `memcpy(dst, src, size)` → size is arg index 2
/// - `memmove(dst, src, size)` → size is arg index 2
const MEMORY_OPS: &[&str] = &["memset", "memcpy", "memmove"];

/// Binary opcodes that can produce an overflowing size when combined with
/// a positive constant.
const OVERFLOW_OPCODES: &[&str] = &["add", "mul", "shl"];

/// Detect constant overflow patterns in a function body.
///
/// Scans all call instructions targeting memory operations (memset/memcpy/
/// memmove) and checks if the size argument is derived from a binary
/// operation (`add`/`mul`/`shl`) of a function parameter with a positive
/// constant.
///
/// Returns `Some(BufferOverflow)` on first match, or `None` if no overflow
/// pattern is detected.
pub fn detect_constant_overflow(body: &FunctionBody) -> Option<BehaviorPattern> {
    // Collect parameter registers — these are registers that appear as operands
    // but are never defined by any instruction in the body.
    let param_regs = collect_parameter_registers(body);
    if param_regs.is_empty() {
        return None;
    }

    // Build a register → defining instruction map for binary ops.
    // We only care about BinaryOp instructions that could produce overflow sizes.
    let binary_ops: std::collections::HashMap<&str, &IRInstruction> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::BinaryOp)
        .filter_map(|i| i.dest.as_deref().map(|d| (d, i)))
        .collect();

    if binary_ops.is_empty() {
        return None;
    }

    // Scan for memory operation calls
    for inst in &body.instructions {
        if inst.kind != IRInstructionKind::Call {
            continue;
        }
        let callee = inst.callee.as_deref()?;
        if !MEMORY_OPS.contains(&callee) {
            continue;
        }

        // Extract the size argument (3rd operand for memset/memcpy/memmove)
        let size_reg = extract_size_arg(inst, callee)?;
        if !size_reg.starts_with('%') {
            continue;
        }

        // Check if the size reg is defined by a binary op with a constant + param
        let bin_inst = binary_ops.get(size_reg.as_str())?;
        let opcode = bin_inst.binary_opcode.as_deref()?;

        if !OVERFLOW_OPCODES.contains(&opcode) {
            continue;
        }

        // Parse the constant operand from the binary instruction
        let overflow_amount = extract_positive_constant(bin_inst)?;
        if overflow_amount == 0 {
            continue;
        }

        // Verify at least one operand is a function parameter (the "buffer size")
        let has_param_operand = bin_inst
            .operands
            .iter()
            .any(|op| param_regs.contains(op.as_str()));

        if !has_param_operand {
            continue;
        }

        return Some(BehaviorPattern::BufferOverflow {
            callee: callee.to_string(),
            overflow_amount,
            opcode: opcode.to_string(),
        });
    }

    None
}

/// Extract the size argument register from a memory operation call.
///
/// For `memset(ptr, val, size)` / `memcpy(dst, src, size)` /
/// `memmove(dst, src, size)`, the size is always the 3rd argument.
/// Tries structured operands first, then falls back to raw text parsing.
fn extract_size_arg(inst: &IRInstruction, _callee: &str) -> Option<String> {
    // Try structured operands: look for %-prefixed registers
    // The size argument for memset/memcpy/memmove is the 3rd argument
    let ptr_regs: Vec<&String> = inst
        .operands
        .iter()
        .filter(|op| op.starts_with('%'))
        .collect();

    // memset has 2 register args (ptr, size) — val is often a constant
    // memcpy/memmove have 3 register args (dst, src, size)
    if !ptr_regs.is_empty() {
        // Return the last register argument (size)
        return Some(ptr_regs.last().unwrap().to_string());
    }

    // Fallback: parse from raw text
    let mut inst_clone = inst.clone();
    inst_clone.ensure_raw();
    let raw = &inst_clone.raw_text;

    extract_last_ptr_reg(raw)
}

/// Extract the last `%register` from an instruction's raw text.
///
/// Used as fallback when structured operands don't capture all arguments
/// (e.g., when LLVM inserts attributes between type and value).
/// Returns the register name **with** the `%` prefix (e.g., `"%add"`).
fn extract_last_ptr_reg(raw: &str) -> Option<String> {
    let mut last_reg = None;
    let mut search_from = 0;
    while let Some(pct_pos) = raw[search_from..].find('%') {
        let abs_pos = search_from + pct_pos;
        let rest = &raw[abs_pos + 1..];
        let end = rest
            .find(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
            .unwrap_or(rest.len());
        if end > 0 {
            // Include the % prefix to match dest/operand conventions
            last_reg = Some(format!("%{}", &rest[..end]));
        }
        search_from = abs_pos + 1 + end;
    }
    last_reg
}

/// Extract a positive integer constant from a binary instruction's operands.
///
/// For `%add = add i64 %len, i64 16`, returns `Some(16)`.
/// Returns `None` if no positive constant operand is found.
fn extract_positive_constant(inst: &IRInstruction) -> Option<u64> {
    for op in &inst.operands {
        if let Ok(val) = op.parse::<u64>() {
            if val > 0 {
                return Some(val);
            }
        }
    }

    // Fallback: parse from raw text for constants that may not be
    // extracted as structured operands (e.g., `i64 16`)
    let mut inst_clone = inst.clone();
    inst_clone.ensure_raw();
    let raw = &inst_clone.raw_text;

    // Look for integer literals that aren't registers
    for token in raw.split_whitespace() {
        if let Ok(val) = token.parse::<u64>() {
            if val > 0 && val < 10_000_000 {
                return Some(val);
            }
        }
    }

    None
}

/// Collect registers that are function parameters (never defined by any instruction).
///
/// Parameters are registers that appear as operands but are never the destination
/// of any instruction in the function body.
fn collect_parameter_registers(body: &FunctionBody) -> std::collections::HashSet<&str> {
    let all_defined: std::collections::HashSet<&str> = body
        .instructions
        .iter()
        .filter_map(|i| i.dest.as_deref())
        .collect();

    let mut params = std::collections::HashSet::new();
    for inst in &body.instructions {
        for op in &inst.operands {
            if op.starts_with('%') && !all_defined.contains(op.as_str()) {
                params.insert(op.as_str());
            }
        }
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_ir::IRModule;

    /// Helper: parse IR text and run detect_constant_overflow on the first function.
    fn detect_from_ir(ir: &str) -> Option<BehaviorPattern> {
        let module = IRModule::parse_from_text(ir);
        let body = module.function_bodies.values().next();
        body.map(detect_constant_overflow).unwrap_or(None)
    }

    /// Objective: Verify memset(ptr, val, len + N) is detected as overflow.
    /// Invariants: BufferOverflow pattern with correct overflow_amount and opcode.
    #[test]
    fn test_detect_memset_add_overflow() {
        let ir = r#"
            define void @c_process_buffer(ptr %buf, i64 %len) {
            entry:
                %add = add i64 %len, i64 16
                call void @memset(ptr %buf, i8 170, i64 %add)
                ret void
            }
        "#;

        let pattern = detect_from_ir(ir);
        assert!(
            pattern.is_some(),
            "Should detect BufferOverflow for memset(buf, len+16)"
        );

        if let Some(BehaviorPattern::BufferOverflow {
            callee,
            overflow_amount,
            opcode,
        }) = pattern.as_ref()
        {
            assert_eq!(callee, "memset", "Callee should be memset");
            assert_eq!(
                *overflow_amount, 16,
                "Overflow amount should be 16, got {}",
                overflow_amount
            );
            assert_eq!(opcode, "add", "Opcode should be add, got {}", opcode);
        } else {
            panic!("Should detect BufferOverflow for memset(buf, len+16)");
        }
    }

    /// Objective: Verify memcpy with size = param * N is detected as overflow.
    /// Invariants: BufferOverflow pattern with mul opcode.
    #[test]
    fn test_detect_memcpy_mul_overflow() {
        let ir = r#"
            define void @copy_with_overflow(ptr %dst, ptr %src, i64 %count) {
            entry:
                %mul = mul i64 %count, i64 2
                call void @memcpy(ptr %dst, ptr %src, i64 %mul)
                ret void
            }
        "#;

        let pattern = detect_from_ir(ir);
        assert!(
            pattern.is_some(),
            "Should detect BufferOverflow for memcpy with count*2"
        );

        if let Some(BehaviorPattern::BufferOverflow {
            callee,
            overflow_amount,
            ..
        }) = pattern.as_ref()
        {
            assert_eq!(callee, "memcpy");
            assert_eq!(*overflow_amount, 2);
        } else {
            panic!("Expected BufferOverflow, got {:?}", pattern);
        }
    }

    /// Objective: Verify normal memset(ptr, val, len) is NOT flagged.
    /// Invariants: No pattern detected when size equals parameter exactly.
    #[test]
    fn test_normal_memset_no_flag() {
        let ir = r#"
            define void @safe_buffer_init(ptr %buf, i64 %len) {
            entry:
                call void @memset(ptr %buf, i8 0, i64 %len)
                ret void
            }
        "#;

        let pattern = detect_from_ir(ir);
        assert!(
            pattern.is_none(),
            "Normal memset(ptr, val, len) should NOT be flagged, got {:?}",
            pattern
        );
    }

    /// Objective: Verify memcpy with exact size parameter is NOT flagged.
    /// Invariants: No false positive for correct memcpy usage.
    #[test]
    fn test_memcpy_exact_size_no_flag() {
        let ir = r#"
            define void @safe_copy(ptr %dst, ptr %src, i64 %n) {
            entry:
                call void @memcpy(ptr %dst, ptr %src, i64 %n)
                ret void
            }
        "#;

        let pattern = detect_from_ir(ir);
        assert!(
            pattern.is_none(),
            "memcpy with exact size parameter should NOT be flagged, got {:?}",
            pattern
        );
    }

    /// Objective: Verify shl (shift left) overflow is detected.
    /// Invariants: BufferOverflow pattern with shl opcode.
    #[test]
    fn test_detect_shl_overflow() {
        let ir = r#"
            define void @shift_overflow(ptr %buf, i64 %len) {
            entry:
                %shl = shl i64 %len, i64 3
                call void @memset(ptr %buf, i8 0, i64 %shl)
                ret void
            }
        "#;

        let pattern = detect_from_ir(ir);
        if let Some(BehaviorPattern::BufferOverflow { opcode, .. }) = pattern.as_ref() {
            assert_eq!(opcode, "shl", "Opcode should be shl");
        } else {
            panic!("Expected BufferOverflow for shl pattern, got {:?}", pattern);
        }
    }

    /// Objective: Verify zero-offset add is NOT flagged.
    /// Invariants: `len + 0` is not an overflow.
    #[test]
    fn test_zero_offset_not_flagged() {
        let ir = r#"
            define void @zero_add(ptr %buf, i64 %len) {
            entry:
                %add = add i64 %len, i64 0
                call void @memset(ptr %buf, i8 0, i64 %add)
                ret void
            }
        "#;

        let pattern = detect_from_ir(ir);
        assert!(
            pattern.is_none(),
            "len + 0 should NOT be flagged as overflow, got {:?}",
            pattern
        );
    }

    /// Objective: Verify memmove overflow is also detected.
    /// Invariants: All three memory ops (memset, memcpy, memmove) are checked.
    #[test]
    fn test_detect_memmove_overflow() {
        let ir = r#"
            define void @overlapping_move(ptr %dst, ptr %src, i64 %n) {
            entry:
                %add = add i64 %n, i64 8
                call void @memmove(ptr %dst, ptr %src, i64 %add)
                ret void
            }
        "#;

        let pattern = detect_from_ir(ir);
        if let Some(BehaviorPattern::BufferOverflow { callee, .. }) = pattern.as_ref() {
            assert_eq!(callee, "memmove");
        } else {
            panic!("Expected BufferOverflow for memmove, got {:?}", pattern);
        }
    }

    /// Objective: Verify non-parameter binary ops are NOT flagged.
    /// Invariants: Overflow detection only fires when one operand is a function param.
    #[test]
    fn test_non_param_binary_op_not_flagged() {
        let ir = r#"
            define void @local_computation(ptr %buf) {
            entry:
                %a = alloca i64
                %val = load i64, ptr %a
                %add = add i64 %val, i64 16
                call void @memset(ptr %buf, i8 0, i64 %add)
                ret void
            }
        "#;

        let pattern = detect_from_ir(ir);
        assert!(
            pattern.is_none(),
            "Binary op without parameter operand should NOT be flagged, got {:?}",
            pattern
        );
    }

    /// Objective: Verify function with no memory ops produces no pattern.
    /// Invariants: Empty/arith-only functions don't crash or false-positive.
    #[test]
    fn test_no_memory_ops() {
        let ir = r#"
            define i64 @pure_math(i64 %x, i64 %y) {
            entry:
                %sum = add i64 %x, i64 %y
                ret i64 %sum
            }
        "#;

        let pattern = detect_from_ir(ir);
        assert!(
            pattern.is_none(),
            "Function with no memory ops should have no pattern, got {:?}",
            pattern
        );
    }
}
