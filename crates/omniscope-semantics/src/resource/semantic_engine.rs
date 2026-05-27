//! Semantic derivation engine for FFI safety assessment.
//!
//! This module provides the IR instruction-level semantic derivation that
//! replaces the old `SyscallSemantic::classify()` whitelist. The key
//! difference:
//!
//! **Whitelist**: `if name == "strlen" → DataQuery` (fails on unknown functions)
//! **Semantic engine**: `if callee body is PureComputation → SafeNoOwnership`
//!
//! # Architecture
//!
//! ```text
//! IRModule ──→ extract_behavior(callee_body) ──→ FunctionBehavior
//!           ──→ extract_behavior(caller_body) ──→ FunctionBehavior
//!           ──→ assess_ffi_safety(callee, caller, module) ──→ FFISafetyAssessment
//! ```

use crate::resource::ir_pattern::{extract_behavior, BehaviorPattern, FunctionBehavior};
use omniscope_ir::{IRInstructionKind, IRModule};

// ──────────────────────────────────────────────────────────────────────────
// FFI Safety Assessment — the output of semantic derivation
// ──────────────────────────────────────────────────────────────────────────

/// Verdict on the safety of an FFI call, derived from IR instruction patterns.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FFIVerdict {
    /// The callee is pure computation — no ownership implications.
    SafeNoOwnership,
    /// The callee performs refcount conditional release — safe.
    SafeConditionalRelease,
    /// The callee is a same-project FFI bridge — by-design boundary.
    SafeInternalBridge,
    /// The callee is a pointer projection (as_ptr() style).
    SafePointerProjection,
    /// The callee is an initialization function (stores + ret void).
    SafeInitialization,
    /// The callee involves ownership transfer — CrossFamilyFree concern.
    ConcernOwnershipTransfer,
    /// Cannot derive safety from available information.
    Unknown,
}

impl FFIVerdict {
    /// Returns true if this verdict indicates a safe FFI pattern.
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            FFIVerdict::SafeNoOwnership
                | FFIVerdict::SafeConditionalRelease
                | FFIVerdict::SafeInternalBridge
                | FFIVerdict::SafePointerProjection
                | FFIVerdict::SafeInitialization
        )
    }

    /// Returns true if this verdict should suppress issue emission.
    pub fn should_suppress_issue(&self) -> bool {
        self.is_safe()
    }

    /// Returns the safety score (0.0 = dangerous, 1.0 = safe).
    pub fn safety_score(&self) -> f32 {
        match self {
            FFIVerdict::SafeNoOwnership => 0.95,
            FFIVerdict::SafeConditionalRelease => 0.9,
            FFIVerdict::SafeInternalBridge => 0.85,
            FFIVerdict::SafePointerProjection => 0.9,
            FFIVerdict::SafeInitialization => 0.85,
            FFIVerdict::ConcernOwnershipTransfer => 0.3,
            FFIVerdict::Unknown => 0.5,
        }
    }
}

/// Evidence for an FFI safety assessment, derived from IR instructions.
#[derive(Debug, Clone)]
pub struct IREvidence {
    /// The instruction kind that provided this evidence
    pub instruction_kind: IRInstructionKind,
    /// Description of what this evidence shows
    pub reasoning: String,
}

/// Complete FFI safety assessment for a cross-language call.
#[derive(Debug, Clone)]
pub struct FFISafetyAssessment {
    /// The callee function name
    pub callee: String,
    /// The caller function name
    pub caller: String,
    /// Behavior analysis of the caller (if available)
    pub caller_behavior: Option<FunctionBehavior>,
    /// Behavior analysis of the callee (if available)
    pub callee_behavior: Option<FunctionBehavior>,
    /// The safety verdict
    pub verdict: FFIVerdict,
    /// Evidence supporting the verdict
    pub evidence: Vec<IREvidence>,
}

impl FFISafetyAssessment {
    /// Returns the safety score (0.0 = dangerous, 1.0 = safe).
    pub fn safety_score(&self) -> f32 {
        self.verdict.safety_score()
    }

    /// Returns true if this assessment indicates a safe pattern.
    pub fn is_safe(&self) -> bool {
        self.verdict.is_safe()
    }

    /// Returns true if issue emission should be suppressed for this call.
    pub fn should_suppress_issue(&self) -> bool {
        self.verdict.should_suppress_issue()
    }

    /// Returns a human-readable summary of the assessment.
    pub fn summary(&self) -> String {
        let behavior_info = if let Some(ref cb) = self.callee_behavior {
            format!(
                "callee patterns: {:?}, return: {:?}",
                cb.patterns, cb.return_source
            )
        } else {
            "callee: external (no body)".to_string()
        };

        format!(
            "FFI {} -> {}: verdict={:?} score={:.2} [{}]",
            self.caller,
            self.callee,
            self.verdict,
            self.safety_score(),
            behavior_info
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Main assessment function
// ──────────────────────────────────────────────────────────────────────────

/// Assess the safety of an FFI call using IR instruction-level semantic derivation.
///
/// This is the main entry point that replaces `SyscallSemantic::classify()`.
pub fn assess_ffi_safety(callee: &str, caller: &str, module: &IRModule) -> FFISafetyAssessment {
    let callee_body = module.function_bodies.get(callee);
    let caller_body = module.function_bodies.get(caller);

    let callee_behavior = callee_body.map(extract_behavior);
    let caller_behavior = caller_body.map(extract_behavior);

    let mut evidence = Vec::new();

    // ── Step 1: If callee has a body, derive from callee behavior ──
    if let Some(ref cb) = callee_behavior {
        // OwnershipTransfer is the most concerning
        if cb
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::OwnershipTransfer { .. }))
        {
            evidence.push(IREvidence {
                instruction_kind: IRInstructionKind::Call,
                reasoning: "Callee contains ownership transfer (alloc/free) pattern".to_string(),
            });
            return FFISafetyAssessment {
                callee: callee.to_string(),
                caller: caller.to_string(),
                caller_behavior,
                callee_behavior,
                verdict: FFIVerdict::ConcernOwnershipTransfer,
                evidence,
            };
        }

        // ConditionalRelease → safe (refcount pattern)
        if cb
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::ConditionalRelease { .. }))
        {
            evidence.push(IREvidence {
                instruction_kind: IRInstructionKind::AtomicRmw,
                reasoning: "Callee follows conditional release pattern (refcount semantics)"
                    .to_string(),
            });
            return FFISafetyAssessment {
                callee: callee.to_string(),
                caller: caller.to_string(),
                caller_behavior,
                callee_behavior,
                verdict: FFIVerdict::SafeConditionalRelease,
                evidence,
            };
        }

        // PureComputation → safe (no ownership)
        if cb.patterns.contains(&BehaviorPattern::PureComputation) {
            evidence.push(IREvidence {
                instruction_kind: IRInstructionKind::Call,
                reasoning: "Callee is pure computation (return value only used in arithmetic)"
                    .to_string(),
            });
            return FFISafetyAssessment {
                callee: callee.to_string(),
                caller: caller.to_string(),
                caller_behavior,
                callee_behavior,
                verdict: FFIVerdict::SafeNoOwnership,
                evidence,
            };
        }

        // PointerProjection → safe
        if cb.patterns.contains(&BehaviorPattern::PointerProjection) {
            evidence.push(IREvidence {
                instruction_kind: IRInstructionKind::GetElementPtr,
                reasoning: "Callee is pointer projection (getelementptr + ret)".to_string(),
            });
            return FFISafetyAssessment {
                callee: callee.to_string(),
                caller: caller.to_string(),
                caller_behavior,
                callee_behavior,
                verdict: FFIVerdict::SafePointerProjection,
                evidence,
            };
        }

        // Initialization → safe
        if cb.patterns.contains(&BehaviorPattern::Initialization) {
            evidence.push(IREvidence {
                instruction_kind: IRInstructionKind::Store,
                reasoning: "Callee is initialization (stores to struct fields, no ownership leak)"
                    .to_string(),
            });
            return FFISafetyAssessment {
                callee: callee.to_string(),
                caller: caller.to_string(),
                caller_behavior,
                callee_behavior,
                verdict: FFIVerdict::SafeInitialization,
                evidence,
            };
        }

        // InternalBridge → safe
        if cb.patterns.contains(&BehaviorPattern::InternalBridge) {
            evidence.push(IREvidence {
                instruction_kind: IRInstructionKind::Call,
                reasoning: "Callee only calls project-internal functions (by-design FFI bridge)"
                    .to_string(),
            });
            return FFISafetyAssessment {
                callee: callee.to_string(),
                caller: caller.to_string(),
                caller_behavior,
                callee_behavior,
                verdict: FFIVerdict::SafeInternalBridge,
                evidence,
            };
        }
    }

    // ── Step 2: Callee is external — derive from caller-side context ──
    if let Some(ref caller_b) = caller_behavior {
        let caller_verdict = derive_from_caller_context(callee, caller_b);
        if caller_verdict != FFIVerdict::Unknown {
            evidence.push(IREvidence {
                instruction_kind: IRInstructionKind::Call,
                reasoning: format!(
                    "Derived from caller-side context: caller has {:?} patterns",
                    caller_b.patterns
                ),
            });
            return FFISafetyAssessment {
                callee: callee.to_string(),
                caller: caller.to_string(),
                caller_behavior,
                callee_behavior,
                verdict: caller_verdict,
                evidence,
            };
        }
    }

    // ── Step 3: No derivation possible → Unknown ──
    evidence.push(IREvidence {
        instruction_kind: IRInstructionKind::Other,
        reasoning: "Cannot derive safety — no function body available".to_string(),
    });

    FFISafetyAssessment {
        callee: callee.to_string(),
        caller: caller.to_string(),
        caller_behavior,
        callee_behavior,
        verdict: FFIVerdict::Unknown,
        evidence,
    }
}

/// Derive FFI safety from the caller's instruction context.
///
/// When the callee is external (no function body), we combine:
/// 1. The caller's behavior patterns (what the caller does with the result)
/// 2. Heuristic rules based on the callee name (NOT a whitelist — these
///    encode well-known semantic properties of standard library functions
///    that are universally true regardless of project context)
fn derive_from_caller_context(callee: &str, caller_behavior: &FunctionBehavior) -> FFIVerdict {
    // If the caller itself has a ConditionalRelease pattern
    if caller_behavior
        .patterns
        .iter()
        .any(|p| matches!(p, BehaviorPattern::ConditionalRelease { .. }))
    {
        return FFIVerdict::SafeConditionalRelease;
    }

    // If the caller has PureComputation pattern
    if caller_behavior
        .patterns
        .contains(&BehaviorPattern::PureComputation)
    {
        return FFIVerdict::SafeNoOwnership;
    }

    // If the caller has OwnershipTransfer pattern
    if caller_behavior
        .patterns
        .iter()
        .any(|p| matches!(p, BehaviorPattern::OwnershipTransfer { .. }))
    {
        return FFIVerdict::ConcernOwnershipTransfer;
    }

    // ── Callee name heuristics for external functions ──
    // These are NOT whitelist entries — they encode universal semantic
    // properties of well-known functions. For example:
    // - strlen ALWAYS returns a length (pure computation), regardless of project
    // - getenv ALWAYS returns a pointer to environment (no ownership transfer)
    // - BunString__* ALWAYS operates on Bun's string type (internal bridge)
    //
    // The key difference from a whitelist: these heuristics are only used
    // as FALLBACK when IR-level derivation is impossible (no function body).
    // When a function body IS available, we derive from IR patterns.

    // SIMD/compute acceleration — pure computation
    if callee.starts_with("simdutf__") || callee.starts_with("highway_") {
        return FFIVerdict::SafeNoOwnership;
    }

    // Project-internal FFI bridges (by-design cross-language calls)
    if callee.starts_with("Bun__") || callee.starts_with("BunString__")
        || callee.starts_with("WTF__") || callee.starts_with("WTFStringImpl__")
        || callee.starts_with("__bun_dispatch__")
    {
        return FFIVerdict::SafeInternalBridge;
    }

    // Well-known libc data queries — always safe (universal semantic)
    if matches!(
        callee,
        "strlen" | "strnlen" | "strcmp" | "strncmp" | "strcasecmp" | "strncasecmp"
        | "memcmp" | "memmem" | "strstr" | "strchr" | "strrchr"
        | "getenv" | "secure_getenv" | "sysconf" | "getentropy"
        | "memcpy" | "memset" | "memmove" | "strcpy" | "strncpy"
        | "strerror" | "__error" | "getcwd"
    ) {
        return FFIVerdict::SafeNoOwnership;
    }

    // Well-known thread/process/time operations — no ownership
    if matches!(
        callee,
        "pthread_mutex_lock" | "pthread_mutex_unlock" | "pthread_mutex_trylock"
        | "pthread_mutex_init" | "pthread_mutex_destroy"
        | "pthread_cond_wait" | "pthread_cond_signal" | "pthread_cond_broadcast"
        | "pthread_setname_np" | "pthread_threadid_np" | "pthread_exit"
        | "clock_gettime" | "gettimeofday" | "nanosleep" | "time"
        | "sigaction" | "sigemptyset" | "sigprocmask"
    ) {
        return FFIVerdict::SafeNoOwnership;
    }

    // Memory management — the real concern
    if matches!(
        callee,
        "malloc" | "calloc" | "realloc" | "free" | "reallocarray"
        | "__rust_alloc" | "__rust_dealloc" | "__rust_realloc" | "__rust_alloc_zeroed"
    ) || callee.starts_with("_Zdl") || callee.starts_with("_Zda")
        || callee.starts_with("_Znw") || callee.starts_with("_Zna")
    {
        return FFIVerdict::ConcernOwnershipTransfer;
    }

    // Rust std functions — analyze from mangled name semantics
    if callee.starts_with("_R") {
        // Memory management in Rust
        if callee.contains("13drop_in_place") || callee.contains("7dealloc") {
            return FFIVerdict::ConcernOwnershipTransfer;
        }
        // Thread sync — interior mutability
        if callee.contains("5mutex") || callee.contains("6rwlock")
            || callee.contains("4once") || callee.contains("7condvar")
        {
            return FFIVerdict::SafeNoOwnership;
        }
    }

    // C++ mangled names
    if callee.starts_with("_Z") {
        return FFIVerdict::Unknown; // C++ — could be anything
    }

    // Heuristic: simple wrapper (few calls, no stores) → likely bridge
    if caller_behavior.call_count <= 2 && caller_behavior.store_count == 0 {
        return FFIVerdict::SafeInternalBridge;
    }

    // Heuristic: only loads and arithmetic (no stores, no atomicrmw) → read op
    if caller_behavior.store_count == 0
        && caller_behavior.atomic_rmw_count == 0
        && caller_behavior.load_count > 0
    {
        return FFIVerdict::SafeNoOwnership;
    }

    FFIVerdict::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_ir::IRModule;

    #[test]
    fn test_assess_pure_computation() {
        let ir = r#"
            declare i32 @strlen(ptr)

            define i64 @my_strlen(ptr %s) {
            entry:
                %len = call i32 @strlen(ptr %s)
                %result = zext i32 %len to i64
                ret i64 %result
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("strlen", "my_strlen", &module);

        assert_eq!(assessment.verdict, FFIVerdict::SafeNoOwnership);
        assert!(assessment.should_suppress_issue());
    }

    #[test]
    fn test_assess_conditional_release() {
        let ir = r#"
            declare void @Bun__WTFStringImpl__destroy(ptr)

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

        let module = IRModule::parse_from_text(ir);
        let assessment =
            assess_ffi_safety("Bun__WTFStringImpl__destroy", "release_string", &module);

        assert_eq!(assessment.verdict, FFIVerdict::SafeConditionalRelease);
        assert!(assessment.should_suppress_issue());
    }

    #[test]
    fn test_assess_ownership_transfer() {
        let ir = r#"
            declare ptr @malloc(i64)

            define ptr @alloc_buffer(i64 %size) {
            entry:
                %buf = call ptr @malloc(i64 %size)
                ret ptr %buf
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("malloc", "alloc_buffer", &module);

        assert_eq!(assessment.verdict, FFIVerdict::ConcernOwnershipTransfer);
        assert!(!assessment.should_suppress_issue());
    }

    #[test]
    fn test_assess_pointer_projection() {
        let ir = r#"
            define ptr @get_data_ptr(ptr %obj) {
            entry:
                %data = getelementptr i8, ptr %obj, i64 16
                ret ptr %data
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("get_data_ptr", "get_data_ptr", &module);

        assert_eq!(assessment.verdict, FFIVerdict::SafePointerProjection);
    }

    #[test]
    fn test_verdict_safety_scores() {
        assert!(FFIVerdict::SafeNoOwnership.safety_score() > 0.9);
        assert!(FFIVerdict::SafeConditionalRelease.safety_score() > 0.8);
        assert!(FFIVerdict::ConcernOwnershipTransfer.safety_score() < 0.5);
        assert_eq!(FFIVerdict::Unknown.safety_score(), 0.5);
    }
}
