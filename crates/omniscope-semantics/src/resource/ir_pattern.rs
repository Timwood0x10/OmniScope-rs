//! IR instruction pattern extraction for semantic derivation.
//!
//! This module extracts **behavior patterns** from function bodies by
//! analyzing sequences of IR instructions. This is the core difference
//! from the old whitelist approach:
//!
//! **Whitelist**: `if name == "strlen" → DataQuery` (fails on unknown functions)
//! **Pattern**: `if call returns value only used in arithmetic → PureComputation`
//!
//! # Key Patterns
//!
//! 1. **ConditionalRelease**: `atomicrmw sub + icmp eq + br + call`
//!    → refcount conditional release (safe pattern, not ownership transfer)
//!
//! 2. **PureComputation**: call returns value → value only in arithmetic/store
//!    → no ownership implications (e.g., strlen, memcmp, getenv)
//!
//! 3. **OwnershipTransfer**: call returns ptr → ptr passed to free/dealloc
//!    → CrossFamilyFree concern
//!
//! 4. **PointerProjection**: getelementptr + bitcast + ret
//!    → as_ptr() style borrowing, no ownership change
//!
//! 5. **Initialization**: store to struct fields + ret void
//!    → constructor pattern, no ownership leak
//!
//! 6. **InternalBridge**: only calls to same-project functions
//!    → by-design FFI boundary

use omniscope_ir::{FunctionBody, IRInstruction, IRInstructionKind};
use std::collections::HashSet;

// ──────────────────────────────────────────────────────────────────────────
// Behavior Patterns — derived from instruction sequences, NOT function names
// ──────────────────────────────────────────────────────────────────────────

/// A behavior pattern detected from IR instruction sequences.
///
/// Each variant represents a semantic behavior that can be derived
/// WITHOUT knowing the function name — purely from how instructions
/// interact with each other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BehaviorPattern {
    /// Refcount conditional release pattern:
    /// `atomicrmw sub ptr, i32 N` + `icmp eq i32 %old, N` + `br` + `call @destroy`
    ///
    /// This is the key pattern for refcounted types (Arc, Rc, WTFStringImpl).
    /// The atomicrmw sub decrements the refcount; if it reaches zero,
    /// the destroy function is called. This is NOT an ownership transfer —
    /// it's a conditional release following Rust's Drop semantics.
    ConditionalRelease {
        /// The atomic operation (sub for release, add for retain)
        atomic_op: String,
        /// The value compared against in icmp (e.g., 2 for Arc, 1 for Rc)
        threshold: String,
    },

    /// Pure computation pattern:
    /// Call returns value → value only used in arithmetic/store → never
    /// passed to free/dealloc.
    ///
    /// Examples: strlen (returns length → used in add/store),
    /// getenv (returns ptr to env → used in load/icmp null),
    /// memcmp (returns i32 → used in icmp).
    PureComputation,

    /// Ownership transfer pattern:
    /// Call returns ptr → ptr is stored or passed to another function
    /// that could free it (different family).
    ///
    /// This is the ONLY pattern that triggers CrossFamilyFree analysis.
    /// Detected when: call returns ptr type AND (ptr passed to free/dealloc
    /// OR ptr stored to memory that crosses FFI boundary).
    OwnershipTransfer { is_acquire: bool },

    /// Pointer projection pattern:
    /// Function body consists only of getelementptr + bitcast + ret.
    ///
    /// This is the `as_ptr()` / `as_mut_ptr()` pattern — borrowing a
    /// pointer without changing ownership. The pointer is derived from
    /// an existing allocation, not a new allocation.
    PointerProjection,

    /// Initialization pattern:
    /// Function body stores values into struct fields + returns void.
    ///
    /// Constructor/init pattern — writes to memory but doesn't leak
    /// ownership across FFI boundaries.
    Initialization,

    /// Internal bridge pattern:
    /// All calls in the function body are to same-project functions
    /// (not external declarations).
    ///
    /// By-design FFI boundary — the cross-language call is intentional.
    InternalBridge,

    // ── New patterns from bun_fp_reduction_plan R-0~R-6 ──
    /// Borrowed return pattern (R-0 complementary):
    /// Function returns a pointer derived from a `readonly` parameter
    /// or from a field load (not a fresh allocation).
    /// Evidence: bun_fp R-0 — `readonly` param means &T, return is &T derived.
    BorrowedReturn {
        /// Whether the source parameter has `readonly` attribute.
        from_readonly_param: bool,
    },

    /// RAII drop-release pattern (R-3):
    /// Function is a `drop_in_place<T>` or has a tail-position `__rust_dealloc`.
    /// This is compiler-inserted scope-end deallocation, NOT a user bug.
    /// Evidence: bun_fp R-3 — 23,904 drop_in_place entries in bun_install.ll.
    RAiiDropRelease {
        /// Whether this is a drop_in_place context (vs tail dealloc).
        is_drop_in_place: bool,
    },

    /// Ownership transfer via into_raw (R-6):
    /// `Box::into_raw` / `CString::into_raw` / `Vec::into_raw` returns
    /// a raw pointer, transferring ownership to the caller. Subsequent
    /// C `free()` is by-design, NOT a cross_language_free bug.
    /// Evidence: bun_fp R-6 — rust_ffi_bugs.ll, bun_*.bc.
    IntoRawTransfer,

    /// POSIX syscall non-memory operation (R-4):
    /// The callee is a POSIX function that performs file/network/process
    /// operations — NOT memory management. It should not participate in
    /// cross_language_free or use_after_free analysis.
    /// Evidence: bun_fp R-4 — unlink, close, socket, execve, etc.
    PosixNonMemoryOp {
        /// Category: file, network, process, or other non-mem operation.
        category: PosixOpCategory,
    },
}

/// Category for POSIX non-memory operations (R-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PosixOpCategory {
    /// File operations: open, close, read, write, unlink, rename, etc.
    File,
    /// Network operations: socket, bind, connect, listen, send, recv, etc.
    Network,
    /// Process operations: fork, execve, waitpid, kill, etc.
    Process,
    /// Other non-memory operations: time, signal, etc.
    Other,
}

/// Summary of a function's behavior derived from its IR instruction stream.
///
/// This is NOT based on the function name — it's derived entirely from
/// the instruction patterns within the function body.
#[derive(Debug, Clone)]
pub struct FunctionBehavior {
    /// Function name (for reference only, not used for classification)
    pub name: String,
    /// Number of alloca instructions (stack allocations)
    pub alloca_count: usize,
    /// Number of call instructions
    pub call_count: usize,
    /// Number of atomicrmw instructions (refcount operations)
    pub atomic_rmw_count: usize,
    /// Number of load instructions
    pub load_count: usize,
    /// Number of store instructions
    pub store_count: usize,
    /// Number of getelementptr instructions (pointer arithmetic)
    pub gep_count: usize,
    /// Number of icmp instructions (comparisons)
    pub icmp_count: usize,
    /// Number of branch instructions
    pub branch_count: usize,
    /// Detected behavior patterns
    pub patterns: Vec<BehaviorPattern>,
    /// What the return value comes from
    pub return_source: ReturnSource,
}

/// What the function's return value is derived from.
///
/// This helps determine if the function is a pure computation
/// (returns computed value), an accessor (returns loaded/derived value),
/// or an allocation (returns newly allocated pointer).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReturnSource {
    /// Returns the result of a specific call
    CallResult(String),
    /// Returns a value loaded from memory
    LoadedValue,
    /// Returns a pointer computed via getelementptr
    GepResult,
    /// Returns a constant value
    Constant,
    /// Returns void (no value)
    Void,
    /// Returns a binary operation result
    Computed,
    /// Cannot determine return source
    Unknown,
}

/// Extract behavior summary from a function body.
///
/// This is the main entry point for semantic derivation:
/// given the instruction stream, we detect behavior patterns
/// that tell us whether FFI calls from/in this function are safe.
pub fn extract_behavior(body: &FunctionBody) -> FunctionBehavior {
    let alloca_count = body.count_kind(IRInstructionKind::Alloca);
    let call_count =
        body.count_kind(IRInstructionKind::Call) + body.count_kind(IRInstructionKind::IndirectCall);
    let atomic_rmw_count = body.count_kind(IRInstructionKind::AtomicRmw);
    let load_count = body.count_kind(IRInstructionKind::Load);
    let store_count = body.count_kind(IRInstructionKind::Store);
    let gep_count = body.count_kind(IRInstructionKind::GetElementPtr);
    let icmp_count = body.count_kind(IRInstructionKind::Icmp);
    let branch_count = body.count_kind(IRInstructionKind::Branch);

    let mut patterns = Vec::new();

    // 1. Detect ConditionalRelease: atomicrmw sub + icmp eq + br + call
    if let Some(cr_pattern) = detect_conditional_release(body) {
        patterns.push(cr_pattern);
    }

    // 2. Detect OwnershipTransfer: call returns ptr → passed to free/dealloc
    //    This must come BEFORE PureComputation — if a function calls malloc/free,
    //    it's NOT pure computation regardless of other instructions.
    let has_ownership_transfer = if let Some(ot_pattern) = detect_ownership_transfer(body) {
        patterns.push(ot_pattern);
        true
    } else {
        false
    };

    // 3. Detect PureComputation: call returns value → only used in arithmetic
    //    Only if no ownership transfer or conditional release detected
    let has_conditional_release = patterns
        .iter()
        .any(|p| matches!(p, BehaviorPattern::ConditionalRelease { .. }));
    if !has_ownership_transfer && !has_conditional_release && detect_pure_computation(body) {
        patterns.push(BehaviorPattern::PureComputation);
    }

    // 4. Detect PointerProjection: only gep + bitcast + ret
    //    Only if no other patterns detected (mutually exclusive with above)
    if patterns.is_empty() && detect_pointer_projection(body) {
        patterns.push(BehaviorPattern::PointerProjection);
    }

    // 5. Detect Initialization: stores to struct fields + ret void
    if patterns.is_empty() && detect_initialization(body) {
        patterns.push(BehaviorPattern::Initialization);
    }

    // 6. Detect InternalBridge: all calls are to defined functions
    if detect_internal_bridge(body) {
        patterns.push(BehaviorPattern::InternalBridge);
    }

    let return_source = extract_return_source(body);

    FunctionBehavior {
        name: body.name.clone(),
        alloca_count,
        call_count,
        atomic_rmw_count,
        load_count,
        store_count,
        gep_count,
        icmp_count,
        branch_count,
        patterns,
        return_source,
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Pattern detection functions — each operates on instruction sequences
// ──────────────────────────────────────────────────────────────────────────

/// Detect ConditionalRelease pattern:
/// `atomicrmw sub ptr, i32 N` → `icmp eq i32 %old, N` → `br i1` → `call @destroy`
///
/// Key insight: This pattern is detectable from instruction flow regardless
/// of what the destroy function is named. The semantic meaning comes from
/// the instruction sequence, not the names.
fn detect_conditional_release(body: &FunctionBody) -> Option<BehaviorPattern> {
    // Must have at least one atomicrmw and one icmp
    if body.count_kind(IRInstructionKind::AtomicRmw) == 0
        || body.count_kind(IRInstructionKind::Icmp) == 0
    {
        return None;
    }

    // Look for atomicrmw sub → icmp eq sequence
    let atomic_insts: Vec<&IRInstruction> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::AtomicRmw)
        .collect();

    let icmp_insts: Vec<&IRInstruction> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Icmp)
        .collect();

    for atomic in &atomic_insts {
        // atomicrmw sub is the refcount decrement
        if atomic.atomic_op.as_deref() != Some("sub") {
            continue;
        }

        // Check if any icmp eq uses the result of this atomicrmw
        if let Some(ref dest) = atomic.dest {
            for icmp in &icmp_insts {
                if icmp.icmp_pred.as_deref() != Some("eq") {
                    continue;
                }

                // Check if the atomicrmw destination register is used in the icmp
                if icmp.operands.contains(dest) || icmp.raw_text.contains(dest.as_str()) {
                    // Found the pattern: atomicrmw sub + icmp eq
                    // The threshold is the value compared against
                    let threshold = extract_icmp_threshold(&icmp.raw_text);
                    return Some(BehaviorPattern::ConditionalRelease {
                        atomic_op: "sub".to_string(),
                        threshold: threshold.unwrap_or_else(|| "unknown".to_string()),
                    });
                }
            }
        }
    }

    None
}

/// Detect PureComputation pattern:
/// Call returns value → value only used in arithmetic/store → never passed to free/dealloc
///
/// This is the key pattern that replaces the `strlen`/`getenv`/`memcmp`
/// whitelist entries. Instead of checking if the function NAME is a
/// "data query", we check if the function's BEHAVIOR is pure computation.
fn detect_pure_computation(body: &FunctionBody) -> bool {
    let calls: Vec<&IRInstruction> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Call || i.kind == IRInstructionKind::IndirectCall)
        .collect();

    if calls.is_empty() {
        // No calls at all — check if it's just arithmetic
        let has_memory_ops = body.count_kind(IRInstructionKind::Store) > 0
            || body.count_kind(IRInstructionKind::AtomicRmw) > 0;
        let has_arithmetic = body.count_kind(IRInstructionKind::BinaryOp) > 0;

        // Pure computation requires actual arithmetic, not just pointer ops
        return !has_memory_ops && has_arithmetic;
    }

    // Collect all call destination registers
    let call_dests: HashSet<String> = calls.iter().filter_map(|c| c.dest.clone()).collect();

    // Check if any call result is passed to a function that could free memory
    for inst in &body.instructions {
        if inst.kind == IRInstructionKind::Call {
            // Check operands and raw text for any call destination register
            for call_dest in &call_dests {
                // If a call result is passed as argument to another call,
                // check if that call is a memory management function
                if inst.raw_text.contains(call_dest.as_str())
                    && inst.dest != Some(call_dest.clone())
                {
                    if let Some(ref callee) = inst.callee {
                        if is_memory_management_callee(callee) {
                            return false;
                        }
                    }
                }
            }
        }
    }

    // Check if any call result is stored to memory (could leak ownership)
    // Exception: storing to a local alloca is fine (local buffer)
    let alloca_dests: HashSet<String> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Alloca)
        .filter_map(|i| i.dest.clone())
        .collect();

    for inst in &body.instructions {
        if inst.kind == IRInstructionKind::Store {
            // Check if storing a call result to non-local memory
            for call_dest in &call_dests {
                if inst.raw_text.contains(call_dest.as_str()) {
                    // Check if the store target is a local alloca
                    let is_local_store = alloca_dests
                        .iter()
                        .any(|alloca| inst.raw_text.contains(alloca.as_str()));

                    if !is_local_store {
                        // Storing call result to non-local memory — not pure computation
                        return false;
                    }
                }
            }
        }
    }

    // No ownership-transfer patterns detected → this is pure computation
    true
}

/// Detect OwnershipTransfer pattern:
/// Call returns ptr → ptr is stored/passed in a way that could leak ownership
fn detect_ownership_transfer(body: &FunctionBody) -> Option<BehaviorPattern> {
    // Look for calls that return pointers and those pointers are used
    // in ways that suggest ownership transfer
    let calls: Vec<&IRInstruction> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Call || i.kind == IRInstructionKind::IndirectCall)
        .collect();

    for call_inst in &calls {
        if let Some(ref callee) = call_inst.callee {
            if is_memory_management_callee(callee) {
                return Some(BehaviorPattern::OwnershipTransfer {
                    is_acquire: is_alloc_callee(callee),
                });
            }
        }
    }

    None
}

/// Detect PointerProjection pattern:
/// Function body consists only of getelementptr + bitcast + ret
fn detect_pointer_projection(body: &FunctionBody) -> bool {
    // Must have gep and ret, and very few other instructions
    if body.count_kind(IRInstructionKind::GetElementPtr) == 0 {
        return false;
    }

    let total = body.instructions.len();
    let allowed_kinds = [
        IRInstructionKind::GetElementPtr,
        IRInstructionKind::Conversion,
        IRInstructionKind::Ret,
        IRInstructionKind::Phi,
        IRInstructionKind::Load, // May load a pointer to derive from
    ];

    let allowed_count = body
        .instructions
        .iter()
        .filter(|i| allowed_kinds.contains(&i.kind))
        .count();

    // At least 80% of instructions should be allowed kinds
    allowed_count * 10 >= total * 8
        && body.count_kind(IRInstructionKind::Store) == 0
        && body.count_kind(IRInstructionKind::Call) == 0
        && body.count_kind(IRInstructionKind::AtomicRmw) == 0
}

/// Detect Initialization pattern:
/// Function body stores values into struct fields + returns void
fn detect_initialization(body: &FunctionBody) -> bool {
    // Must have stores and ret void, no calls to external functions
    if body.count_kind(IRInstructionKind::Store) == 0 {
        return false;
    }

    // Return source should be void or unknown
    let ret_insts = body.instructions_of_kind(IRInstructionKind::Ret);
    if let Some(ret) = ret_insts.first() {
        if ret.raw_text.contains("void") {
            // Good — returns void
        } else if ret.operands.is_empty() {
            // ret void (no operands)
        } else {
            // Returns a non-void value — might not be just initialization
            return false;
        }
    }

    // Should not call external functions (just stores)
    let calls = body.call_instructions();
    for call in calls {
        if let Some(ref callee) = call.callee {
            if is_memory_management_callee(callee) {
                return false;
            }
        }
    }

    // Store count should be significant (writing to multiple fields)
    body.count_kind(IRInstructionKind::Store) >= 2
}

/// Detect InternalBridge pattern:
/// All calls in the function are to same-project functions
fn detect_internal_bridge(body: &FunctionBody) -> bool {
    let calls = body.call_instructions();
    if calls.is_empty() {
        return false;
    }

    // Check if all callees start with known project prefixes
    // This is a heuristic: project-internal functions often share a prefix
    // like "Bun__", "WTF__", "__bun_dispatch__", etc.
    //
    // Note: This is NOT a whitelist — it's detecting whether the function
    // only calls into the same project, which is a different semantic
    // property than classifying individual function names.
    let project_prefixes = [
        "Bun__",
        "BunString__",
        "WTF__",
        "WTFStringImpl__",
        "__bun_dispatch__",
        "_ZN3bun", // C++ bun namespace
        "_ZN3WTF", // C++ WTF namespace
    ];

    for call in &calls {
        if let Some(ref callee) = call.callee {
            let is_project_internal = project_prefixes
                .iter()
                .any(|prefix| callee.starts_with(prefix));

            if !is_project_internal {
                return false;
            }
        } else {
            // Indirect call (callee unknown) — cannot assume it is
            // project-internal. An indirect call via function pointer
            // might target any external function, so this function
            // cannot be classified as InternalBridge.
            return false;
        }
    }

    true
}

// ──────────────────────────────────────────────────────────────────────────
// Helper functions
// ──────────────────────────────────────────────────────────────────────────

/// Extract the comparison threshold from an icmp instruction.
///
/// Example: `icmp eq i32 %22, 2` → "2"
fn extract_icmp_threshold(raw: &str) -> Option<String> {
    // Find the last operand after the comma
    if let Some(comma_pos) = raw.rfind(',') {
        let after_comma = raw[comma_pos + 1..].trim();
        // Remove any trailing metadata (!dbg, etc.)
        let threshold = after_comma.split('!').next().unwrap_or(after_comma).trim();
        if !threshold.is_empty() {
            return Some(threshold.to_string());
        }
    }
    None
}

/// Determine the return source of a function.
fn extract_return_source(body: &FunctionBody) -> ReturnSource {
    let ret_insts = body.instructions_of_kind(IRInstructionKind::Ret);
    if let Some(ret) = ret_insts.first() {
        // Check if ret has no operands (ret void)
        if ret.raw_text.contains("void") || ret.operands.is_empty() {
            return ReturnSource::Void;
        }

        // Check if the return value is a call result, loaded value, etc.
        if let Some(ret_val) = ret.operands.first() {
            // Check if this register comes from a call
            for inst in &body.instructions {
                if inst.kind == IRInstructionKind::Call
                    && inst.dest.as_deref() == Some(ret_val.as_str())
                {
                    return ReturnSource::CallResult(inst.callee.clone().unwrap_or_default());
                }
                if inst.kind == IRInstructionKind::Load
                    && inst.dest.as_deref() == Some(ret_val.as_str())
                {
                    return ReturnSource::LoadedValue;
                }
                if inst.kind == IRInstructionKind::GetElementPtr
                    && inst.dest.as_deref() == Some(ret_val.as_str())
                {
                    return ReturnSource::GepResult;
                }
                if inst.kind == IRInstructionKind::BinaryOp
                    && inst.dest.as_deref() == Some(ret_val.as_str())
                {
                    return ReturnSource::Computed;
                }
            }
        }

        // Check for constant return
        if ret.raw_text.contains("ret i32 0") || ret.raw_text.contains("ret i64 0") {
            return ReturnSource::Constant;
        }
    }

    ReturnSource::Unknown
}

/// Check if a callee name is a memory management function (alloc/free).
///
/// Note: This is a focused check on the CALLEE of a specific call
/// instruction, not a general classification system. It's used to
/// detect OwnershipTransfer patterns, not to classify all FFI calls.
fn is_memory_management_callee(name: &str) -> bool {
    matches!(
        name,
        "malloc"
        | "calloc"
        | "realloc"
        | "free"
        | "reallocarray"
        | "valloc"
        | "posix_memalign"
        | "pvalloc"
        | "aligned_alloc"
        | "__rust_alloc"
        | "__rust_dealloc"
        | "__rust_realloc"
        | "__rust_alloc_zeroed"
    ) || name.starts_with("_Zdl") // operator delete
      || name.starts_with("_Zda") // operator delete[]
      || name.starts_with("_Znw") // operator new
      || name.starts_with("_Zna") // operator new[]
}

/// Check if a callee name is an allocation function (not free).
fn is_alloc_callee(name: &str) -> bool {
    matches!(
        name,
        "malloc"
        | "calloc"
        | "realloc"
        | "reallocarray"
        | "valloc"
        | "posix_memalign"
        | "pvalloc"
        | "aligned_alloc"
        | "__rust_alloc"
        | "__rust_realloc"
        | "__rust_alloc_zeroed"
    ) || name.starts_with("_Znw") // operator new
      || name.starts_with("_Zna") // operator new[]
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_ir::IRModule;

    fn parse_body(ir: &str) -> FunctionBody {
        let module = IRModule::parse_from_text(ir);
        module
            .function_bodies
            .values()
            .next()
            .expect("ir_pattern::parse_body: no function body found")
            .clone()
    }

    #[test]
    fn test_conditional_release_detection() {
        let ir = r#"
            define void @release_string(ptr %s) {
            entry:
                %22 = atomicrmw sub ptr %s, i32 2 monotonic
                %23 = icmp eq i32 %22, 2
                br i1 %23, label %destroy, label %exit
            destroy:
                tail call void @Bun__WTFStringImpl__destroy(ptr %s)
                ret void
            exit:
                ret void
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert!(
            behavior
                .patterns
                .contains(&BehaviorPattern::ConditionalRelease {
                    atomic_op: "sub".to_string(),
                    threshold: "2".to_string(),
                }),
            "Should detect ConditionalRelease pattern, got: {:?}",
            behavior.patterns
        );
    }

    #[test]
    fn test_pure_computation_detection() {
        let ir = r#"
            define i64 @my_strlen(ptr %s) {
            entry:
                %len = call i32 @strlen(ptr %s)
                %result = zext i32 %len to i64
                ret i64 %result
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert!(
            behavior
                .patterns
                .contains(&BehaviorPattern::PureComputation),
            "Should detect PureComputation pattern, got: {:?}",
            behavior.patterns
        );
    }

    #[test]
    fn test_ownership_transfer_detection() {
        let ir = r#"
            define ptr @alloc_buffer(i64 %size) {
            entry:
                %buf = call ptr @malloc(i64 %size)
                ret ptr %buf
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert!(
            behavior
                .patterns
                .contains(&BehaviorPattern::OwnershipTransfer { is_acquire: true }),
            "Should detect OwnershipTransfer pattern, got: {:?}",
            behavior.patterns
        );
    }

    #[test]
    fn test_pointer_projection_detection() {
        let ir = r#"
            define ptr @get_data_ptr(ptr %obj) {
            entry:
                %data = getelementptr i8, ptr %obj, i64 16
                ret ptr %data
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert!(
            behavior
                .patterns
                .contains(&BehaviorPattern::PointerProjection),
            "Should detect PointerProjection pattern, got: {:?}",
            behavior.patterns
        );
    }

    #[test]
    fn test_no_false_conditional_release() {
        // A simple function without atomicrmw should NOT trigger ConditionalRelease
        let ir = r#"
            define void @simple_func(ptr %p) {
            entry:
                store i32 42, ptr %p
                ret void
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert!(
            !behavior
                .patterns
                .iter()
                .any(|p| matches!(p, BehaviorPattern::ConditionalRelease { .. })),
            "Should NOT detect ConditionalRelease in simple store function, got: {:?}",
            behavior.patterns
        );
    }

    #[test]
    fn test_return_source_call_result() {
        let ir = r#"
            define i32 @wrapper(ptr %s) {
            entry:
                %result = call i32 @strlen(ptr %s)
                ret i32 %result
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert_eq!(
            behavior.return_source,
            ReturnSource::CallResult("strlen".to_string()),
            "Expected values to be equal"
        );
    }

    #[test]
    fn test_return_source_void() {
        let ir = r#"
            define void @init(ptr %p) {
            entry:
                store i32 0, ptr %p
                ret void
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert_eq!(
            behavior.return_source,
            ReturnSource::Void,
            "Expected values to be equal"
        );
    }

    // ── Golden Tests : Unknown function names with recognizable IR patterns ──

    /// golden test: An unknown function with malloc+free IR pattern
    /// should be detected as OwnershipTransfer, even though the function
    /// name "custom_buffer_alloc" is not in any whitelist.
    #[test]
    fn test_golden_unknown_alloc_function() {
        let ir = r#"
            define ptr @custom_buffer_alloc(i64 %size) {
            entry:
                %buf = call ptr @malloc(i64 %size)
                ret ptr %buf
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert!(
            behavior.patterns.contains(&BehaviorPattern::OwnershipTransfer { is_acquire: true }),
            "Unknown function 'custom_buffer_alloc' with malloc call should be OwnershipTransfer, got: {:?}",
            behavior.patterns
        );
    }

    /// An unknown function with atomicrmw sub + icmp eq
    /// should be detected as ConditionalRelease, even though the function
    /// name "mystery_refcount_release" is not in any whitelist.
    #[test]
    fn test_golden_unknown_refcount_release() {
        let ir = r#"
            define void @mystery_refcount_release(ptr %obj) {
            entry:
                %old = atomicrmw sub ptr %obj, i32 1 monotonic
                %cmp = icmp eq i32 %old, 1
                br i1 %cmp, label %drop, label %done
            drop:
                call void @some_destructor(ptr %obj)
                ret void
            done:
                ret void
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert!(
            behavior.patterns.iter().any(|p| matches!(p, BehaviorPattern::ConditionalRelease { .. })),
            "Unknown function 'mystery_refcount_release' with atomicrmw sub + icmp eq should be ConditionalRelease, got: {:?}",
            behavior.patterns
        );
    }

    /// An unknown function with only GEP + ret
    /// should be detected as PointerProjection, even though the function
    /// name "weird_accessor" is not in any whitelist.
    #[test]
    fn test_golden_unknown_pointer_projection() {
        let ir = r#"
            define ptr @weird_accessor(ptr %obj) {
            entry:
                %field = getelementptr i8, ptr %obj, i64 24
                ret ptr %field
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert!(
            behavior.patterns.contains(&BehaviorPattern::PointerProjection),
            "Unknown function 'weird_accessor' with GEP + ret should be PointerProjection, got: {:?}",
            behavior.patterns
        );
    }

    /// An unknown function that only does arithmetic
    /// should be detected as PureComputation, even though the function
    /// name "obscure_math_helper" is not in any whitelist.
    #[test]
    fn test_golden_unknown_pure_computation() {
        let ir = r#"
            define i32 @obscure_math_helper(i32 %x, i32 %y) {
            entry:
                %sum = add i32 %x, %y
                %result = mul i32 %sum, 2
                ret i32 %result
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert!(
            behavior.patterns.contains(&BehaviorPattern::PureComputation),
            "Unknown function 'obscure_math_helper' with only arithmetic should be PureComputation, got: {:?}",
            behavior.patterns
        );
    }

    /// An unknown function with stores to struct fields + ret void
    /// should be detected as Initialization, even though the function
    /// name "custom_init" is not in any whitelist.
    #[test]
    fn test_golden_unknown_initialization() {
        let ir = r#"
            define void @custom_init(ptr %obj, i32 %val) {
            entry:
                %f1 = getelementptr i8, ptr %obj, i64 0
                store i32 %val, ptr %f1
                %f2 = getelementptr i8, ptr %obj, i64 4
                store i32 0, ptr %f2
                ret void
            }
        "#;

        let body = parse_body(ir);
        let behavior = extract_behavior(&body);

        assert!(
            behavior.patterns.contains(&BehaviorPattern::Initialization),
            "Unknown function 'custom_init' with stores + ret void should be Initialization, got: {:?}",
            behavior.patterns
        );
    }
}
