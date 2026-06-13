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

    // ── New patterns for multi-key semantic queries ──
    /// Resource is stored to an owner structure (struct field, container).
    /// Pattern: `store ptr %resource, ptr %owner_field`
    /// Indicates ownership transfer to container — not a local leak.
    StoreToOwner {
        /// The owner field or container being stored to.
        owner_field: String,
    },

    /// Resource is stored to runtime-managed structure (GC heap, global).
    /// Pattern: `store ptr %resource, ptr @global` or `store ptr %resource, ptr %gc_root`
    /// Indicates ownership transfer to runtime — not a local leak.
    StoreToRuntime {
        /// The runtime-managed target (global, GC root, etc.).
        runtime_target: String,
    },

    /// Resource escapes to caller via return or out-parameter.
    /// Pattern: `ret ptr %resource` or `store ptr %resource, ptr %out_param`
    /// Caller is responsible for cleanup — not a local leak.
    ResourceEscape {
        /// How the resource escapes: return value or out-parameter.
        escape_type: EscapeType,
    },

    /// Resource is released on all exit paths.
    /// Pattern: `call @release` in all branches before `ret`
    /// No leak — cleanup is complete on all paths.
    ReleaseOnAllExitPaths {
        /// The release function called.
        release_function: String,
    },

    // ── Borrow/Escape detection patterns (Phase 3: truth_classification) ──
    /// Stack-local pointer escapes to global/static storage.
    /// Pattern: `%local = alloca ...; ...; store ptr %local_derived, ptr @global`
    /// After the function returns, the stack frame is gone but the global
    /// still holds the dangling pointer — use-after-return bug.
    /// Evidence: TRAP-C6 in ffi_traps.c (ffi_register_callback).
    StackToGlobalEscape {
        /// The global variable that receives the stack pointer.
        global_target: String,
        /// The alloca register that originates the escaped pointer.
        alloca_reg: String,
    },

    /// Return value aliases an input parameter pointer without ownership transfer.
    /// Pattern: `ret ptr %param` or `ret ptr %gep_result` where the value
    /// traces back to a function parameter (not a fresh allocation).
    /// Caller may incorrectly assume ownership of the returned pointer.
    /// Evidence: TRAP-C7 in ffi_traps.c (ffi_alias_input).
    ReturnAlias {
        /// The parameter register that the return value aliases.
        aliased_param: String,
    },

    /// Free-then-use: a pointer is passed to a release function (free/dealloc)
    /// and subsequently used as an argument to another call instruction.
    /// Pattern: `call void @free(ptr %p)` ... `call void @fn(..., ptr %p, ...)`
    /// This is a use-after-free (CWE-416) — the freed pointer is dereferenced
    /// or passed to a callback that may read/write through it.
    /// Evidence: TRAP-C9 in ffi_traps.c (uaf_through_ffi).
    FreeThenCallbackUse {
        /// The register that was freed and then used.
        freed_reg: String,
        /// Name of the call instruction that uses the freed register (if direct call).
        use_callee: Option<String>,
    },

    // ── Heap-to-global escape pattern (P1-6) ──
    /// Heap/parameter pointer escapes to global/static storage.
    /// Pattern: `store ptr %param, ptr @global_name` where `%param` is a
    /// function argument (not derived from alloca). Unlike StackToGlobalEscape,
    /// the source is a parameter/heap pointer, not a stack allocation.
    ///
    /// This is a potential UAF bug: if the original allocation is later freed
    /// while the global still holds it, any access through the global is UAF.
    /// Evidence: FN-14 (c_register_and_store).
    HeapToGlobalEscape {
        /// The global variable that receives the heap/parameter pointer.
        global_target: String,
        /// The parameter register that originates the escaped pointer.
        param_reg: String,
    },

    // ── Lightweight bounds check pattern (P1-5) ──
    /// Constant buffer overflow detected in memset/memcpy/memmove calls.
    ///
    /// Pattern: when a memory operation's size argument is `add/mul/shl` of a
    /// function parameter with a **positive constant**, AND that parameter
    /// represents the buffer size. Specifically:
    ///
    /// ```llvm
    /// %add = add i64 %len, i64 16          ; overflow by 16 bytes
    /// call void @memset(ptr %buf, i8 170, i64 %add)
    /// ```
    ///
    /// This catches FN-11 (`c_process_buffer` with `memset(buf, len+16)`
    /// overflowing by 16 bytes) — a trivially detectable constant overflow
    /// that needs NO complex interval arithmetic.
    BufferOverflow {
        /// The memory operation function called (memset, memcpy, memmove).
        callee: String,
        /// The constant overflow amount (e.g., 16 for `len + 16`).
        overflow_amount: u64,
        /// The binary operation that produced the overflowing size (add, mul, shl).
        opcode: String,
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

/// How a resource escapes from a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EscapeType {
    /// Resource is returned from the function.
    ReturnValue,
    /// Resource is stored to an out-parameter.
    OutParameter,
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

    // 12. Detect StackToGlobalEscape: alloca-derived pointer stored to global
    if let Some(sge) = detect_stack_to_global_escape(body) {
        patterns.push(sge);
    }

    // 13. Detect ReturnAlias: return value aliases a parameter without ownership transfer
    if let Some(ra) = detect_return_alias(body) {
        patterns.push(ra);
    }

    // 14. Detect FreeThenCallbackUse: freed pointer used as call argument (UAF)
    if let Some(ftcu) = detect_free_then_callback_use(body) {
        patterns.push(ftcu);
    }

    // 15. Detect HeapToGlobalEscape: parameter/heap pointer stored to global
    if let Some(hge) = detect_heap_to_global_escape(body) {
        patterns.push(hge);
    }

    // 16. Detect constant buffer overflow (P1-5): memset/memcpy/memmove with
    //     size = param + N (positive constant overflow)
    if let Some(bo) = super::bounds_check_pattern::detect_constant_overflow(body) {
        patterns.push(bo);
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
///
/// Only matches known C/C++ standard library deallocators. Library-internal
/// cleanup functions (e.g. `pthreadMutexFree`, `sqlite3VdbeFree`) are NOT
/// matched — they have different semantics than C `free()`.
pub fn is_release_callee(name: &str) -> bool {
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
}

// ──────────────────────────────────────────────────────────────────────────
// New pattern detectors for multi-key semantic queries
// ──────────────────────────────────────────────────────────────────────────

/// Detect StoreToOwner pattern: `store ptr %resource, ptr %owner_field`
/// Resource is stored to a struct field or container — ownership transfer.
fn detect_store_to_owner(body: &FunctionBody) -> Option<BehaviorPattern> {
    let store_insts = body.instructions_of_kind(IRInstructionKind::Store);

    for store in &store_insts {
        // Check if storing a pointer to a field (getelementptr result)
        if store.operands.len() >= 2 {
            let stored_value = &store.operands[0];
            let store_target = &store.operands[1];

            // Check if the stored value comes from a call or allocation
            let comes_from_alloc = body.instructions.iter().any(|i| {
                (i.kind == IRInstructionKind::Call || i.kind == IRInstructionKind::Alloca)
                    && i.dest.as_deref() == Some(stored_value.as_str())
            });

            if comes_from_alloc {
                // Check if the target is a field access (getelementptr)
                let is_field_access = body.instructions.iter().any(|i| {
                    i.kind == IRInstructionKind::GetElementPtr
                        && i.dest.as_deref() == Some(store_target.as_str())
                });

                if is_field_access {
                    return Some(BehaviorPattern::StoreToOwner {
                        owner_field: store_target.clone(),
                    });
                }
            }
        }
    }

    None
}

/// Detect StoreToRuntime pattern: `store ptr %resource, ptr @global` or `store ptr %resource, ptr %gc_root`
/// Resource is stored to runtime-managed structure — ownership transfer to runtime.
fn detect_store_to_runtime(body: &FunctionBody) -> Option<BehaviorPattern> {
    let store_insts = body.instructions_of_kind(IRInstructionKind::Store);

    for store in &store_insts {
        if store.operands.len() >= 2 {
            let stored_value = &store.operands[0];
            let store_target = &store.operands[1];

            // Check if the stored value comes from a call or allocation
            let comes_from_alloc = body.instructions.iter().any(|i| {
                (i.kind == IRInstructionKind::Call || i.kind == IRInstructionKind::Alloca)
                    && i.dest.as_deref() == Some(stored_value.as_str())
            });

            if comes_from_alloc {
                // Check if the target is a global variable or GC root
                let is_global = store_target.starts_with('@')
                    || store_target.contains("global")
                    || store_target.contains("gc_root")
                    || store_target.contains("runtime");

                if is_global {
                    return Some(BehaviorPattern::StoreToRuntime {
                        runtime_target: store_target.clone(),
                    });
                }
            }
        }
    }

    None
}

/// Detect ResourceEscape pattern: `ret ptr %resource` or `store ptr %resource, ptr %out_param`
/// Resource escapes to caller — caller is responsible for cleanup.
fn detect_resource_escape(body: &FunctionBody) -> Option<BehaviorPattern> {
    // Check return instructions
    let ret_insts = body.instructions_of_kind(IRInstructionKind::Ret);
    for ret in &ret_insts {
        if let Some(ret_val) = ret.operands.first() {
            // Check if the returned value comes from a call or allocation
            let comes_from_alloc = body.instructions.iter().any(|i| {
                (i.kind == IRInstructionKind::Call || i.kind == IRInstructionKind::Alloca)
                    && i.dest.as_deref() == Some(ret_val.as_str())
            });

            if comes_from_alloc {
                return Some(BehaviorPattern::ResourceEscape {
                    escape_type: EscapeType::ReturnValue,
                });
            }
        }
    }

    // Check store to out-parameters (parameters that are pointers)
    // This is more complex — we need to identify which parameters are out-params
    // For now, we'll use a heuristic: if a store writes to a parameter
    let param_dests: HashSet<String> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Alloca)
        .filter_map(|i| i.dest.clone())
        .collect();

    let store_insts = body.instructions_of_kind(IRInstructionKind::Store);
    for store in &store_insts {
        if store.operands.len() >= 2 {
            let stored_value = &store.operands[0];
            let store_target = &store.operands[1];

            // Check if storing to a parameter (alloca for parameter)
            if param_dests.contains(store_target) {
                // Check if the stored value comes from a call or allocation
                let comes_from_alloc = body.instructions.iter().any(|i| {
                    (i.kind == IRInstructionKind::Call || i.kind == IRInstructionKind::Alloca)
                        && i.dest.as_deref() == Some(stored_value.as_str())
                });

                if comes_from_alloc {
                    return Some(BehaviorPattern::ResourceEscape {
                        escape_type: EscapeType::OutParameter,
                    });
                }
            }
        }
    }

    None
}

/// Detect ReleaseOnAllExitPaths pattern: `call @release` in all branches before `ret`
/// Resource is released on all exit paths — no leak.
fn detect_release_on_all_exit_paths(body: &FunctionBody) -> Option<BehaviorPattern> {
    // This is a complex pattern that requires checking all exit paths
    // For simplicity, we'll check if there's a release call before every ret
    let ret_insts = body.instructions_of_kind(IRInstructionKind::Ret);
    let call_insts: Vec<&IRInstruction> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Call)
        .collect();

    // Check if any release call exists
    let has_release = call_insts.iter().any(|c| {
        c.callee
            .as_ref()
            .is_some_and(|name| is_release_callee(name))
    });

    if !has_release {
        return None;
    }

    // Check if release calls appear before all return instructions
    // This is a simplified check — in practice, we'd need to analyze CFG
    let all_rets_have_release = ret_insts.iter().all(|ret| {
        let ret_pos = body
            .instructions
            .iter()
            .position(|i| i.raw_text == ret.raw_text && i.kind == ret.kind)
            .unwrap_or(0);

        // Check if there's a release call before this ret
        body.instructions.iter().take(ret_pos).any(|i| {
            i.kind == IRInstructionKind::Call
                && i.callee
                    .as_ref()
                    .is_some_and(|name| is_release_callee(name))
        })
    });

    if all_rets_have_release {
        // Find the release function name
        let release_func = call_insts
            .iter()
            .find(|c| {
                c.callee
                    .as_ref()
                    .is_some_and(|name| is_release_callee(name))
            })
            .and_then(|c| c.callee.clone())
            .unwrap_or_default();

        return Some(BehaviorPattern::ReleaseOnAllExitPaths {
            release_function: release_func,
        });
    }

    None
}

/// Detect StackToGlobalEscape: alloca-derived pointer stored to a global variable.
///
/// Pattern:
/// ```llvm
/// %local = alloca [40 x i8]
/// ... (initialize local buffer) ...
/// store ptr %local, ptr @g_global   ; stack pointer escapes to global!
/// ```
///
/// This is a use-after-return bug: when the function returns, the stack
/// frame is destroyed but `@g_global` still holds the dangling pointer.
fn detect_stack_to_global_escape(body: &FunctionBody) -> Option<BehaviorPattern> {
    // Need at least one alloca and one store
    if body.count_kind(IRInstructionKind::Alloca) == 0
        || body.count_kind(IRInstructionKind::Store) == 0
    {
        return None;
    }

    // Collect all alloca destination registers
    let alloca_regs: HashSet<String> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Alloca)
        .filter_map(|i| i.dest.clone())
        .collect();

    if alloca_regs.is_empty() {
        return None;
    }

    // Build a set of registers derived from allocas.
    // A register is "alloca-derived" if it is produced by an instruction
    // (GEP, bitcast, load) that uses an alloca register as input.
    let mut alloca_derived = alloca_regs.clone();
    let mut changed = true;
    while changed {
        changed = false;
        for inst in &body.instructions {
            if let Some(ref dest) = inst.dest {
                if !alloca_derived.contains(dest)
                    && inst.operands.iter().any(|op| alloca_derived.contains(op))
                {
                    alloca_derived.insert(dest.clone());
                    changed = true;
                }
            }
        }
    }

    // Check each store instruction for global target + alloca-derived source
    for store in body.instructions_of_kind(IRInstructionKind::Store) {
        if store.operands.len() >= 2 {
            let stored_value = &store.operands[0];
            let store_target = &store.operands[1];

            // Target must be a global variable (@ prefix)
            if !store_target.starts_with('@') {
                continue;
            }

            // Stored value must be derived from an alloca
            if alloca_derived.contains(stored_value) {
                // Find which alloca this ultimately traces back to
                let origin_alloca = alloca_regs
                    .iter()
                    .find(|a| **a == *stored_value || is_derived_from(body, stored_value, a))
                    .cloned()
                    .unwrap_or_else(|| stored_value.clone());

                return Some(BehaviorPattern::StackToGlobalEscape {
                    global_target: store_target.clone(),
                    alloca_reg: origin_alloca,
                });
            }
        }
    }

    None
}

/// Detect HeapToGlobalEscape: function parameter (non-alloca) pointer stored to
/// a global variable.
///
/// Pattern:
/// ```llvm
/// define void @c_register_and_store(ptr %ptr) {
/// entry:
///     store ptr %ptr, ptr @g_stored_ptr   ; heap/param ptr → global!
///     ret void
/// }
/// ```
///
/// Unlike StackToGlobalEscape, the source is a function parameter (heap pointer
/// passed from caller), not an alloca-derived stack pointer. The risk is that
/// the caller may free the original allocation while `@g_stored_ptr` still
/// holds it — any subsequent access through the global is UAF.
fn detect_heap_to_global_escape(body: &FunctionBody) -> Option<BehaviorPattern> {
    // Need at least one store instruction
    if body.count_kind(IRInstructionKind::Store) == 0 {
        return None;
    }

    // Collect all alloca destination registers (to EXCLUDE them)
    let alloca_regs: HashSet<String> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Alloca)
        .filter_map(|i| i.dest.clone())
        .collect();

    // Build the set of alloca-derived registers (same as StackToGlobalEscape)
    let mut alloca_derived = alloca_regs.clone();
    let mut changed = true;
    while changed {
        changed = false;
        for inst in &body.instructions {
            if let Some(ref dest) = inst.dest {
                if !alloca_derived.contains(dest)
                    && inst.operands.iter().any(|op| alloca_derived.contains(op))
                {
                    alloca_derived.insert(dest.clone());
                    changed = true;
                }
            }
        }
    }

    // Collect parameter registers (registers that appear as operands but are
    // never defined by any instruction in this function body)
    let param_regs: HashSet<&str> = collect_parameter_registers(body);

    if param_regs.is_empty() {
        return None;
    }

    // Check each store instruction for global target + non-alloca source
    for store in body.instructions_of_kind(IRInstructionKind::Store) {
        if store.operands.len() >= 2 {
            let stored_value = &store.operands[0];
            let store_target = &store.operands[1];

            // Target must be a global variable (@ prefix)
            if !store_target.starts_with('@') {
                continue;
            }

            // Stored value must NOT be derived from an alloca (that's StackToGlobalEscape's job)
            if alloca_derived.contains(stored_value) {
                continue;
            }

            // Stored value must be a parameter register (or derived from one)
            if param_regs.contains(stored_value.as_str()) {
                return Some(BehaviorPattern::HeapToGlobalEscape {
                    global_target: store_target.clone(),
                    param_reg: stored_value.clone(),
                });
            }
        }
    }

    None
}

/// Check whether `reg` is transitively derived from `root` through instruction chains.
fn is_derived_from(body: &FunctionBody, reg: &str, root: &str) -> bool {
    if reg == root {
        return true;
    }
    // Walk backwards: find the instruction that produces `reg`, check its operands
    for inst in &body.instructions {
        if inst.dest.as_deref() == Some(reg) {
            return inst
                .operands
                .iter()
                .any(|op| op == root || is_derived_from(body, op, root));
        }
    }
    false
}

/// Detect ReturnAlias: function returns a pointer that aliases an input parameter.
///
/// Pattern:
/// ```llvm
/// define ptr @ffi_alias_input(ptr %data, i64 %len) {
///     ...
///     ret ptr %data          ; direct param return — alias!
/// }
/// ```
/// or:
/// ```llvm
///     %gep = getelementptr ..., ptr %data, ...
///     ret ptr %gep           ; GEP of param return — alias!
/// ```
///
/// This is NOT a bug per se — many legitimate APIs do this. But without
/// ownership annotation, FFI bindings may incorrectly free the result.
///
/// # Return-type filtering
///
/// This detector identifies the *IR-level pattern* of return-value aliasing
/// regardless of the function's return type. The semantic question of whether
/// the return type is actually a pointer (and thus whether this pattern
/// represents a borrow-escape risk) is enforced at the candidate-builder
/// level in `issue_candidate_builder`, which has access to the IR module's
/// function declaration metadata including `return_type`.
fn detect_return_alias(body: &FunctionBody) -> Option<BehaviorPattern> {
    let ret_insts = body.instructions_of_kind(IRInstructionKind::Ret);
    let first_ret = ret_insts.first()?;

    // Must return a non-void value
    let ret_val = first_ret.operands.first()?;

    // Skip constant/null returns
    if ret_val == "null" || ret_val == "0" || !ret_val.starts_with('%') {
        return None;
    }

    // Collect parameter registers (function arguments start with % and appear
    // in the function signature; they are never defined by any instruction)
    let param_regs: HashSet<&str> = collect_parameter_registers(body);

    if param_regs.is_empty() {
        return None;
    }

    // Build a "derived from" map: for each register, track what pointer it comes from.
    // Only tracks derivation through pointer-propagating instructions to avoid
    // following integer arithmetic chains (e.g., %half_len = lshr %len, 1) that
    // would derail pointer-alias analysis.
    //
    // Uses a multi-map (Vec) because an instruction may have multiple register
    // operands (e.g., GEP has base ptr + index, select has condition + values).
    // We try all paths during traversal to find one that leads to a parameter.
    let mut derives_from: std::collections::HashMap<&str, Vec<&str>> =
        std::collections::HashMap::new();

    /// Instruction kinds that preserve pointer identity — their output is a
    /// pointer derived from one of their inputs. Arithmetic/comparison/logical
    /// instructions are excluded because they produce integers, not pointers.
    fn is_pointer_propagating(kind: IRInstructionKind) -> bool {
        matches!(
            kind,
            IRInstructionKind::GetElementPtr
                | IRInstructionKind::Conversion      // bitcast, ptrtoint, inttoptr
                | IRInstructionKind::Load            // loads a pointer value
                | IRInstructionKind::Select          // selects between pointer vals
                | IRInstructionKind::Phi             // phi node joining pointer vals
                | IRInstructionKind::Call            // may return a pointer
                | IRInstructionKind::IndirectCall
        )
    }

    for inst in &body.instructions {
        if let Some(ref dest) = inst.dest {
            // Only track derivation for pointer-propagating instructions
            if !is_pointer_propagating(inst.kind.clone()) {
                continue;
            }

            // Method 1: Use structured operands
            for op in &inst.operands {
                if op.starts_with('%') && !dest.is_empty() {
                    derives_from
                        .entry(dest.as_str())
                        .or_default()
                        .push(op.as_str());
                }
            }

            // Method 2: Parse raw_text for %register references as fallback.
            // This handles select, phi, and other instructions where the text
            // parser may not extract structured operands.
            let mut inst_clone = inst.clone();
            inst_clone.ensure_raw();
            let raw = inst_clone.raw_text.to_string();
            // Find all %register tokens after the destination assignment
            if let Some(eq_pos) = raw.find("= ") {
                let after_eq = &raw[eq_pos + 2..];
                for token in
                    after_eq.split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')')
                {
                    let token = token.trim().to_string();
                    if token.starts_with('%') && token != *dest {
                        let leaked = Box::leak(token.into_boxed_str());
                        derives_from.entry(dest.as_str()).or_default().push(leaked);
                    }
                }
            }
        }
    }

    // Check if ret_val directly or transitively originates from a parameter.
    // Uses BFS-style traversal trying all possible derivation paths.
    let mut to_visit: Vec<&str> = vec![ret_val.as_str()];
    let mut visited = std::collections::HashSet::new();
    while let Some(current) = to_visit.pop() {
        if !visited.insert(current) {
            continue;
        }
        if param_regs.contains(current) {
            return Some(BehaviorPattern::ReturnAlias {
                aliased_param: current.to_string(),
            });
        }
        if let Some(sources) = derives_from.get(current) {
            to_visit.extend(sources.iter().copied());
        }
    }

    None
}

/// Collect registers that are function parameters (never defined by any instruction).
fn collect_parameter_registers(body: &FunctionBody) -> HashSet<&str> {
    let all_defined: HashSet<&str> = body
        .instructions
        .iter()
        .filter_map(|i| i.dest.as_deref())
        .collect();

    // Parameters are registers that appear as operands but are never defined
    let mut params = HashSet::new();
    for inst in &body.instructions {
        for op in &inst.operands {
            if op.starts_with('%') && !all_defined.contains(op.as_str()) {
                params.insert(op.as_str());
            }
        }
    }
    params
}

/// Detect FreeThenCallbackUse: a pointer is freed and then used as an argument
/// to a subsequent call instruction (use-after-free via callback/FFI).
///
/// Pattern (intra-function, cross-basic-block):
/// ```llvm
/// %p = call ptr @malloc(i64 32)
/// ...
/// call void @free(ptr %p)          ; release %p
/// ...
/// call void @callback(..., ptr %p)  ; use %p AFTER free — UAF!
/// ```
///
/// Also catches indirect calls through function pointers:
/// ```llvm
/// %cb = load ptr, ptr @g_callback
/// call void %cb(..., ptr %p)        ; indirect use of freed %p
/// ```
///
/// This is the IR-level manifestation of TRAP-C9 (uaf_through_ffi in ffi_traps.c).
/// The detection scans all instructions for free/dealloc calls, extracts the freed
/// register, then checks if any later call instruction uses that same register.
fn detect_free_then_callback_use(body: &FunctionBody) -> Option<BehaviorPattern> {
    // Need at least one call (for free) and one subsequent call (for use)
    let call_count =
        body.count_kind(IRInstructionKind::Call) + body.count_kind(IRInstructionKind::IndirectCall);
    if call_count < 2 {
        return None;
    }

    // Collect all release (free/dealloc) calls and their freed registers.
    // A "release call" is identified by callee name matching known deallocators.
    struct FreeSite {
        idx: usize,
        freed_reg: String,
    }

    let free_sites: Vec<FreeSite> = body
        .instructions
        .iter()
        .enumerate()
        .filter_map(|(idx, inst)| {
            if inst.kind != IRInstructionKind::Call {
                return None;
            }
            let callee = inst.callee.as_deref()?;
            if !is_release_callee(callee) {
                return None;
            }
            // Extract the first pointer argument from raw_text or operands.
            // For `call void @free(ptr %p)`, we need `%p`.
            let freed_reg = extract_first_ptr_arg(inst)?;
            Some(FreeSite { idx, freed_reg })
        })
        .collect();

    if free_sites.is_empty() {
        return None;
    }

    // For each free site, check if any subsequent *indirect* call uses the
    // freed register.  We target the specific P2c pattern where a freed pointer
    // is passed to an FFI callback (function-pointer invocation), not generic
    // post-free usage which is handled by the ownership solver.
    for free_site in &free_sites {
        for (_idx, inst) in body.instructions.iter().enumerate().skip(free_site.idx + 1) {
            // Only indirect calls (function-pointer / callback invocations)
            if inst.kind != IRInstructionKind::IndirectCall {
                continue;
            }

            // Check if this call's raw_text or operands contain the freed register
            let uses_freed_reg = inst.operands.contains(&free_site.freed_reg)
                || inst.raw_text.contains(&free_site.freed_reg);

            if uses_freed_reg {
                return Some(BehaviorPattern::FreeThenCallbackUse {
                    freed_reg: free_site.freed_reg.clone(),
                    use_callee: inst.callee.clone(),
                });
            }
        }
    }

    None
}

/// Extract the first pointer argument from a call instruction.
///
/// For `call void @free(ptr %p)` → returns `Some("%p")`.
/// Also handles LLVM parameter attributes between `ptr` and the register:
///   `call void @free(ptr noundef nonnull %p)` → returns `Some("%p")`.
/// Tries structured operands first, then falls back to raw text parsing.
fn extract_first_ptr_arg(inst: &IRInstruction) -> Option<String> {
    // Try structured operands: look for %-prefixed registers
    for op in &inst.operands {
        if op.starts_with('%') {
            return Some(op.clone());
        }
    }

    // Fallback: parse from raw_text for a `ptr` keyword followed (eventually)
    // by a %-prefixed register.  LLVM IR may insert parameter attributes
    // (noundef, nonnull, align, etc.) between the type and the value, e.g.:
    //   `call void @free(ptr noundef nonnull %1)`
    let raw = &inst.raw_text;

    // Locate the argument list: everything after '(' that belongs to this call
    if let Some(paren_start) = raw.find('(') {
        let args_region = &raw[paren_start..];
        // Find `ptr` then scan forward for the first %reg
        if let Some(ptr_pos) = args_region.find("ptr") {
            let after_ptr = &args_region[ptr_pos + 3..];
            // Scan for %-register, skipping over attribute words
            for (i, ch) in after_ptr.char_indices() {
                if ch == '%' {
                    // Extract the full register name (%digits or %identifier)
                    let rest = &after_ptr[i..];
                    // Skip the '%' itself; find end of register name
                    let name_part = &rest[1..];
                    let end = name_part
                        .find(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
                        .unwrap_or(name_part.len());
                    return Some(rest[..=end].to_string());
                }
            }
        }
    }

    // Last resort: find any %-register anywhere in the raw text
    if let Some(pct_pos) = raw.find('%') {
        let rest = &raw[pct_pos..];
        let name_part = &rest[1..];
        let end = name_part
            .find(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
            .unwrap_or(name_part.len());
        let reg = rest[..=end].to_string();
        if !reg.is_empty() {
            return Some(reg);
        }
    }

    None
}

/// Check if a function has store-to-owner pattern.
/// Returns the owner field name if found.
pub fn detect_store_to_owner_pattern(body: &FunctionBody) -> Option<String> {
    detect_store_to_owner(body).map(|p| match p {
        BehaviorPattern::StoreToOwner { owner_field } => owner_field,
        _ => unreachable!(),
    })
}

/// Check if a function has store-to-runtime pattern.
/// Returns the runtime target name if found.
pub fn detect_store_to_runtime_pattern(body: &FunctionBody) -> Option<String> {
    detect_store_to_runtime(body).map(|p| match p {
        BehaviorPattern::StoreToRuntime { runtime_target } => runtime_target,
        _ => unreachable!(),
    })
}

/// Check if a function has resource escape pattern.
/// Returns the escape type if found.
pub fn detect_resource_escape_pattern(body: &FunctionBody) -> Option<EscapeType> {
    detect_resource_escape(body).map(|p| match p {
        BehaviorPattern::ResourceEscape { escape_type } => escape_type,
        _ => unreachable!(),
    })
}

/// Check if a function has release-on-all-exit-paths pattern.
/// Returns the release function name if found.
pub fn detect_release_on_all_exit_paths_pattern(body: &FunctionBody) -> Option<String> {
    detect_release_on_all_exit_paths(body).map(|p| match p {
        BehaviorPattern::ReleaseOnAllExitPaths { release_function } => release_function,
        _ => unreachable!(),
    })
}

#[cfg(test)]
#[path = "ir_pattern_tests.rs"]
mod tests;
