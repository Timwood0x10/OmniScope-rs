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

    /// Release function has NULL guard — release(NULL) is safe no-op.
    /// Pattern: `icmp eq ptr %p, null` → `br` → release call on non-null path.
    /// This is the standard defensive pattern: `if (p) free(p);`
    NullGuardedRelease {
        /// Index of the argument that is NULL-checked before release.
        arg_index: u32,
    },

    /// NULL is stored to pointer slot after release.
    /// Pattern: `call @release(ptr %p)` → `store ptr null, ptr %slot`.
    /// This is the "release-then-null" idiom: `free(p); p = NULL;`
    NullStoreAfterRelease {
        /// Index of the argument whose slot is NULLed after release.
        arg_index: u32,
    },

    /// Function initializes out-param for fallible operation.
    /// Pattern: `store ptr null, ptr %out` → `call @init(ptr %out)` →
    /// `icmp %ret` → `br` → on error: `store ptr null, ptr %out`.
    /// This is the fallible-initialization idiom: `*out = NULL; if (!init(out)) { *out = NULL; }`
    FallibleOutParamInit {
        /// Index of the out-param argument.
        out_arg_index: u32,
    },

    /// Out-param is set to NULL on error path.
    /// Pattern: `icmp %ret` → `br` → error block: `store ptr null, ptr %out`.
    /// This detects defensive NULLing of out-params on failure paths.
    OutParamNullOnError {
        /// Index of the out-param argument.
        out_arg_index: u32,
    },

    /// Out-param receives owned resource on success path.
    /// Pattern: `icmp %ret` → `br` → success block: out-param holds allocation.
    /// This indicates the caller is responsible for releasing the out-param value.
    OutParamOwnedOnSuccess {
        /// Index of the out-param argument.
        out_arg_index: u32,
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

    // 2. Detect NullGuardedRelease: icmp eq ptr → null, br → release call
    //    Must come BEFORE OwnershipTransfer — a null-guarded release is more
    //    specific than a bare release call.
    let has_null_guarded_release = if let Some(ngr) = detect_null_guarded_release(body) {
        patterns.push(ngr);
        true
    } else {
        false
    };

    // 3. Detect NullStoreAfterRelease: release call → store null
    if let Some(nsar) = detect_null_store_after_release(body) {
        patterns.push(nsar);
    }

    // 4. Detect FallibleOutParamInit: null-store → call → icmp → error null-store
    if let Some(foi) = detect_fallible_out_param_init(body) {
        patterns.push(foi);
    }

    // 5. Detect OutParamNullOnError: icmp → br → error block null-store
    if let Some(opno) = detect_out_param_null_on_error(body) {
        patterns.push(opno);
    }

    // 6. Detect OutParamOwnedOnSuccess: icmp → br → success block allocation
    if let Some(opos) = detect_out_param_owned_on_success(body) {
        patterns.push(opos);
    }

    // 7. Detect OwnershipTransfer: call returns ptr → passed to free/dealloc
    //    Skip if already detected as NullGuardedRelease (more specific).
    let has_ownership_transfer = if !has_null_guarded_release {
        if let Some(ot_pattern) = detect_ownership_transfer(body) {
            patterns.push(ot_pattern);
            true
        } else {
            false
        }
    } else {
        false
    };

    // 8. Detect PureComputation: call returns value → only used in arithmetic
    //    Only if no ownership transfer or conditional release detected
    let has_conditional_release = patterns
        .iter()
        .any(|p| matches!(p, BehaviorPattern::ConditionalRelease { .. }));
    if !has_ownership_transfer && !has_conditional_release && detect_pure_computation(body) {
        patterns.push(BehaviorPattern::PureComputation);
    }

    // 9. Detect PointerProjection: only gep + bitcast + ret
    //    Only if no other patterns detected (mutually exclusive with above)
    if patterns.is_empty() && detect_pointer_projection(body) {
        patterns.push(BehaviorPattern::PointerProjection);
    }

    // 10. Detect Initialization: stores to struct fields + ret void
    if patterns.is_empty() && detect_initialization(body) {
        patterns.push(BehaviorPattern::Initialization);
    }

    // 11. Detect InternalBridge: all calls are to defined functions
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
                if icmp.operands.contains(dest) {
                    // Found the pattern: atomicrmw sub + icmp eq
                    // The threshold is the last operand of the icmp (the comparison value)
                    let threshold = icmp.operands.last().cloned();
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

    // If the function itself calls memory management functions (malloc, free, etc.),
    // it manages memory and is NOT pure computation.
    if calls.iter().any(|c| {
        c.callee
            .as_ref()
            .is_some_and(|name| is_memory_management_callee(name))
    }) {
        return false;
    }

    // Collect all call destination registers
    let call_dests: HashSet<String> = calls.iter().filter_map(|c| c.dest.clone()).collect();

    // Check if any call result is passed to a function that could free memory
    for inst in &body.instructions {
        if inst.kind == IRInstructionKind::Call {
            // Check operands for any call destination register
            for call_dest in &call_dests {
                // If a call result is passed as argument to another call,
                // check if that call is a memory management function
                if inst.operands.contains(call_dest) && inst.dest != Some(call_dest.clone()) {
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
                if inst.operands.contains(call_dest) {
                    // Check if the store target is a local alloca
                    // For store instructions, operands[1] is the destination pointer
                    let is_local_store = alloca_dests
                        .iter()
                        .any(|alloca| inst.operands.get(1).is_some_and(|dest| dest == alloca));

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
        // Check if this is a void return: no operands, or result_type is void
        if ret.result_type.as_deref() == Some("void") || ret.operands.is_empty() {
            // Good — returns void
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
// New pattern detectors — NULL-guarded release and out-param patterns
// ──────────────────────────────────────────────────────────────────────────

/// Detect NullGuardedRelease: `icmp eq ptr %p, null` → `br` → release call
/// on non-null path. The defensive idiom: `if (p != NULL) { free(p); }`
fn detect_null_guarded_release(body: &FunctionBody) -> Option<BehaviorPattern> {
    // Need at least one icmp and one call to a release function
    if body.count_kind(IRInstructionKind::Icmp) == 0
        || body.count_kind(IRInstructionKind::Call) == 0
    {
        return None;
    }

    let icmp_insts = body.instructions_of_kind(IRInstructionKind::Icmp);
    let call_insts: Vec<&IRInstruction> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Call)
        .collect();

    // Find icmp eq comparing a pointer to null
    for icmp in &icmp_insts {
        if icmp.icmp_pred.as_deref() != Some("eq") {
            continue;
        }
        // Check if comparing to null/0
        let has_null = icmp
            .operands
            .iter()
            .any(|op| op == "null" || op == "0" || op == "zeroinitializer");
        if !has_null {
            continue;
        }

        // The first operand is typically the pointer being checked
        let checked_ptr = match icmp.operands.first() {
            Some(op) if op != "null" && op != "0" && op != "zeroinitializer" => op.clone(),
            _ => continue,
        };

        // Check if any release/dealloc call uses this pointer
        // Note: For direct calls, operands are empty — we check raw_text instead
        for call in &call_insts {
            if let Some(ref callee) = call.callee {
                if is_release_callee(callee) && call.raw_text.contains(&checked_ptr) {
                    return Some(BehaviorPattern::NullGuardedRelease { arg_index: 0 });
                }
            }
        }
    }

    None
}

/// Detect NullStoreAfterRelease: `call @release(ptr %p)` → `store ptr null, ptr %slot`
/// The "release-then-null" idiom: `free(p); p = NULL;`
fn detect_null_store_after_release(body: &FunctionBody) -> Option<BehaviorPattern> {
    // Find release calls followed by a store of null
    for (idx, inst) in body.instructions.iter().enumerate() {
        if inst.kind != IRInstructionKind::Call {
            continue;
        }
        let callee = match &inst.callee {
            Some(c) => c,
            None => continue,
        };
        if !is_release_callee(callee) {
            continue;
        }

        // Check if a subsequent instruction stores null
        for later in body.instructions.iter().skip(idx + 1) {
            if later.kind == IRInstructionKind::Store {
                // Store of null: first operand is "null" or "0"
                let stores_null = later
                    .operands
                    .first()
                    .is_some_and(|v| v == "null" || v == "0");
                if stores_null {
                    return Some(BehaviorPattern::NullStoreAfterRelease { arg_index: 0 });
                }
            }
            // Stop if we hit another call or branch (different basic block)
            if later.kind == IRInstructionKind::Call
                || later.kind == IRInstructionKind::Branch
                || later.kind == IRInstructionKind::Ret
            {
                break;
            }
        }
    }

    None
}

/// Detect FallibleOutParamInit: `store null` → `call` → `icmp` → `br` → error `store null`
/// The fallible initialization idiom: `*out = NULL; if (!init(out)) { *out = NULL; }`
fn detect_fallible_out_param_init(body: &FunctionBody) -> Option<BehaviorPattern> {
    // Need stores (initialization + error null), a call, and an icmp+branch
    if body.count_kind(IRInstructionKind::Store) < 2
        || body.count_kind(IRInstructionKind::Call) == 0
        || body.count_kind(IRInstructionKind::Icmp) == 0
    {
        return None;
    }

    // Find stores of null to a pointer slot
    let null_store_targets: Vec<String> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Store)
        .filter(|i| i.operands.first().is_some_and(|v| v == "null" || v == "0"))
        .filter_map(|i| i.operands.get(1).cloned())
        .collect();

    if null_store_targets.is_empty() {
        return None;
    }

    // Check if a call instruction writes to one of those targets (out-param)
    // and there's a subsequent icmp + branch + null store to the same target
    let call_insts: Vec<&IRInstruction> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Call)
        .collect();

    for call in &call_insts {
        // Check if the call references a null-store target (out-param)
        // Note: For direct calls, operands are empty — we check raw_text instead
        let out_param = match null_store_targets
            .iter()
            .find(|t| call.raw_text.contains(t.as_str()))
        {
            Some(p) => p.clone(),
            None => continue,
        };

        // Verify there's an icmp + branch after this call
        let call_pos = body
            .instructions
            .iter()
            .position(|i| i.raw_text == call.raw_text && i.kind == call.kind)
            .unwrap_or(0);

        let has_icmp_after = body
            .instructions
            .iter()
            .skip(call_pos + 1)
            .any(|i| i.kind == IRInstructionKind::Icmp);

        let has_null_store_after = body.instructions.iter().skip(call_pos + 1).any(|i| {
            i.kind == IRInstructionKind::Store
                && i.operands.first().is_some_and(|v| v == "null" || v == "0")
                && i.operands.get(1).is_some_and(|t| *t == out_param)
        });

        if has_icmp_after && has_null_store_after {
            return Some(BehaviorPattern::FallibleOutParamInit { out_arg_index: 0 });
        }
    }

    None
}

/// Detect OutParamNullOnError: `icmp` → `br` → error block: `store null, ptr %out`
/// Defensive NULLing of out-params on failure paths.
fn detect_out_param_null_on_error(body: &FunctionBody) -> Option<BehaviorPattern> {
    if body.count_kind(IRInstructionKind::Icmp) == 0
        || body.count_kind(IRInstructionKind::Store) == 0
        || body.count_kind(IRInstructionKind::Branch) == 0
    {
        return None;
    }

    // Find icmp instructions followed by branches
    for (idx, inst) in body.instructions.iter().enumerate() {
        if inst.kind != IRInstructionKind::Icmp {
            continue;
        }

        // Check if there's a branch after this icmp
        let has_branch_after = body
            .instructions
            .iter()
            .skip(idx + 1)
            .take(3)
            .any(|i| i.kind == IRInstructionKind::Branch);
        if !has_branch_after {
            continue;
        }

        // Check if there's a store of null to a pointer after this branch
        for later in body.instructions.iter().skip(idx + 2) {
            if later.kind == IRInstructionKind::Store {
                let stores_null = later
                    .operands
                    .first()
                    .is_some_and(|v| v == "null" || v == "0");
                if stores_null {
                    return Some(BehaviorPattern::OutParamNullOnError { out_arg_index: 0 });
                }
            }
            // Stop at ret or another icmp (different path)
            if later.kind == IRInstructionKind::Ret || later.kind == IRInstructionKind::Icmp {
                break;
            }
        }
    }

    None
}

/// Detect OutParamOwnedOnSuccess: `icmp` → `br` → success block: out-param holds allocation.
/// Combined with OutParamNullOnError: success = owned, error = NULL.
fn detect_out_param_owned_on_success(body: &FunctionBody) -> Option<BehaviorPattern> {
    if body.count_kind(IRInstructionKind::Icmp) == 0
        || body.count_kind(IRInstructionKind::Branch) == 0
    {
        return None;
    }

    // Find icmp + branch patterns
    for (idx, inst) in body.instructions.iter().enumerate() {
        if inst.kind != IRInstructionKind::Icmp {
            continue;
        }

        // Look for a success path after this icmp
        let has_branch = body
            .instructions
            .iter()
            .skip(idx + 1)
            .take(3)
            .any(|i| i.kind == IRInstructionKind::Branch);

        if !has_branch {
            continue;
        }

        // In the success path, check if a store writes a call result
        // or an allocation to a pointer (indicating ownership transfer)
        for later in body.instructions.iter().skip(idx + 2) {
            if later.kind == IRInstructionKind::Store {
                // Check if the stored value comes from a call or allocation
                let stored_value = later.operands.first();
                if let Some(val) = stored_value {
                    // Check if this value was produced by a call or alloca
                    let comes_from_alloc = body.instructions.iter().any(|i| {
                        (i.kind == IRInstructionKind::Call || i.kind == IRInstructionKind::Alloca)
                            && i.dest.as_deref() == Some(val.as_str())
                    });
                    if comes_from_alloc {
                        return Some(BehaviorPattern::OutParamOwnedOnSuccess { out_arg_index: 0 });
                    }
                }
            }
            // Stop at ret or another icmp
            if later.kind == IRInstructionKind::Ret || later.kind == IRInstructionKind::Icmp {
                break;
            }
        }
    }

    None
}

// ──────────────────────────────────────────────────────────────────────────
// Helper functions
// ──────────────────────────────────────────────────────────────────────────

/// Determine the return source of a function.
fn extract_return_source(body: &FunctionBody) -> ReturnSource {
    let ret_insts = body.instructions_of_kind(IRInstructionKind::Ret);
    if let Some(ret) = ret_insts.first() {
        // Check if ret has no operands (ret void) or result_type is void
        if ret.result_type.as_deref() == Some("void") || ret.operands.is_empty() {
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

            // Check for constant zero return (e.g., ret i32 0, ret i64 0)
            if ret_val == "0" || ret_val == "null" {
                return ReturnSource::Constant;
            }
        }
    }

    ReturnSource::Unknown
}

/// Check if a callee is a memory management function (alloc/free).
/// Used to detect OwnershipTransfer patterns.
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

/// Check if a callee is an allocation function (not free).
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

/// Check if a callee is a release/dealloc function (for NULL-guarded release detection).
fn is_release_callee(name: &str) -> bool {
    matches!(
        name,
        "free"
        | "cfree"
        | "__rust_dealloc"
        | "munmap"
        | "VirtualFree"
        | "HeapFree"
        | "LocalFree"
        | "GlobalFree"
    ) || name.starts_with("_Zdl") // operator delete
      || name.starts_with("_Zda") // operator delete[]
      || name.contains("free")
        || name.contains("dealloc")
        || name.contains("release")
        || name.contains("destroy")
}

#[cfg(test)]
#[path = "ir_pattern_tests.rs"]
mod tests;
