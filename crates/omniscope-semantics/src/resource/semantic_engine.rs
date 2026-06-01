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
//!           ──→ FamilyRegistry.lookup(callee) ──→ FamilyEntry
//!           ──→ assess_ffi_safety(callee, caller, module) ──→ FFISafetyAssessment
//! ```
//!
//! # R-0~R-6 Integration (bun_fp_reduction_plan)
//!
//! The engine now integrates with:
//! - FamilyRegistry for 20 built-in families (7 new from IR Pattern Atlas)
//! - Structural inference for RAII drop (R-3), into_raw (R-6), POSIX (R-4)
//! - Parameter attribute inference for readonly/mutable (R-0)

use crate::resource::family_registry::FamilyRegistry;
use crate::resource::ir_pattern::{extract_behavior, BehaviorPattern, FunctionBehavior};
use omniscope_ir::{IRInstructionKind, IRModule};
use std::sync::LazyLock;

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

/// Global singleton FamilyRegistry — avoids re-allocating ~100 entries
/// on every `assess_ffi_safety()` call (review-report HIGH #10).
static FAMILY_REGISTRY: LazyLock<FamilyRegistry> = LazyLock::new(FamilyRegistry::new);

/// Assess the safety of an FFI call using IR instruction-level semantic derivation.
///
/// This is the main entry point that replaces `SyscallSemantic::classify()`.
/// Integrates with FamilyRegistry for 20 built-in families and structural
/// inference patterns (R-0~R-6).
pub fn assess_ffi_safety(callee: &str, caller: &str, module: &IRModule) -> FFISafetyAssessment {
    let callee_body = module.function_bodies.get(callee);
    let caller_body = module.function_bodies.get(caller);

    let callee_behavior = callee_body.map(extract_behavior);
    let caller_behavior = caller_body.map(extract_behavior);

    let mut evidence = Vec::new();

    // ── Step 0: Check FamilyRegistry for known symbols ──
    // This covers all 20 families including the 7 new library-managed ones
    // from IR Pattern Atlas (zlib, openssl, sqlite, go_cgo, mimalloc, etc.)
    let registry = &*FAMILY_REGISTRY;
    if let Some(entry) = registry.lookup(callee) {
        use crate::resource::family_registry::SymbolEffect;
        match entry.effect {
            SymbolEffect::Acquire => {
                evidence.push(IREvidence {
                    instruction_kind: IRInstructionKind::Call,
                    reasoning: format!(
                        "Callee '{}' is a known acquire for family {:?}",
                        callee, entry.family_id
                    ),
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
            SymbolEffect::Release | SymbolEffect::ConditionalRelease => {
                // R-7: Library-managed families (zlib/openssl/sqlite/mimalloc)
                // have paired init+end release functions. These are legitimate
                // intra-library releases, NOT cross-language free bugs.
                let is_library_managed = registry
                    .family(entry.family_id)
                    .is_some_and(|f| f.kind == omniscope_types::FamilyKind::LibraryManaged);
                if is_library_managed {
                    evidence.push(IREvidence {
                        instruction_kind: IRInstructionKind::Call,
                        reasoning: format!(
                            "R-7: Callee '{}' is a library-managed release for family {:?} — legitimate intra-library release",
                            callee, entry.family_id
                        ),
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
                evidence.push(IREvidence {
                    instruction_kind: IRInstructionKind::Call,
                    reasoning: format!(
                        "Callee '{}' is a known release for family {:?}",
                        callee, entry.family_id
                    ),
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
            SymbolEffect::Retain => {
                // Retain operations (Py_INCREF, objc_retain) are safe
                evidence.push(IREvidence {
                    instruction_kind: IRInstructionKind::Call,
                    reasoning: format!(
                        "Callee '{}' is a known retain for family {:?} — no ownership transfer",
                        callee, entry.family_id
                    ),
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
            SymbolEffect::Escape => {
                // into_raw: ownership escapes to raw pointer, not a bug
                evidence.push(IREvidence {
                    instruction_kind: IRInstructionKind::Call,
                    reasoning: format!(
                        "Callee '{}' is an ownership escape (into_raw) for family {:?} — intentional transfer",
                        callee, entry.family_id
                    ),
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
            SymbolEffect::Reclaim => {
                // from_raw: ownership reclaimed from raw pointer
                // This is the symmetric counterpart of into_raw (Escape).
                // Both are intentional, safe ownership transfers — not concerns.
                evidence.push(IREvidence {
                    instruction_kind: IRInstructionKind::Call,
                    reasoning: format!(
                        "Callee '{}' is an ownership reclaim (from_raw) for family {:?} — intentional reacquisition",
                        callee, entry.family_id
                    ),
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
    }

    // ── Step 0.5: Check new BehaviorPatterns from R-0~R-6 ──
    if let Some(ref cb) = callee_behavior {
        // R-6: IntoRawTransfer — ownership transferred, C free() is legal
        if cb
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::IntoRawTransfer))
        {
            evidence.push(IREvidence {
                instruction_kind: IRInstructionKind::Call,
                reasoning: "Callee is into_raw transfer — ownership moved to caller".to_string(),
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

        // R-3: RAiiDropRelease — compiler-inserted cleanup, not a bug
        if cb
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::RAiiDropRelease { .. }))
        {
            evidence.push(IREvidence {
                instruction_kind: IRInstructionKind::Call,
                reasoning: "Callee is RAII drop release — compiler-inserted cleanup".to_string(),
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

        // R-4: PosixNonMemoryOp — file/network/process, not memory
        if cb
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::PosixNonMemoryOp { .. }))
        {
            evidence.push(IREvidence {
                instruction_kind: IRInstructionKind::Call,
                reasoning: "Callee is a POSIX non-memory operation — not memory management"
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

        // R-0: BorrowedReturn — returns borrowed pointer from readonly param
        if cb
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::BorrowedReturn { .. }))
        {
            evidence.push(IREvidence {
                instruction_kind: IRInstructionKind::Call,
                reasoning: "Callee returns borrowed pointer — no ownership transfer".to_string(),
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
    }

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

/// Returns true if the callee name strongly suggests a memory release function.
///
/// This is used to prevent the broad caller-side heuristics (wrapper and
/// read-only) from misclassifying a caller that invokes a release function
/// as safe. The FamilyRegistry catches exact matches at Step 0, but
/// unregistered release functions (e.g. project-specific deallocators)
/// would slip through without this guard.
fn callee_name_suggests_release(callee: &str) -> bool {
    let lower = callee.to_lowercase();

    /// Check that `keyword` appears at a word boundary in `s`.
    /// A word boundary means the character before the keyword (if any) is `_` or
    /// the start of the string, and the character after the keyword (if any) is
    /// `_`, end of string, or not an alphanumeric character.
    /// This prevents `_free` from matching `_freeze` and `_drop` from matching `_dropdown`.
    fn has_keyword(s: &str, keyword: &str) -> bool {
        let mut start = 0;
        while let Some(pos) = s[start..].find(keyword) {
            let abs_pos = start + pos;
            let after = abs_pos + keyword.len();

            // Before: must be start-of-string or preceded by '_'
            let before_ok = abs_pos == 0 || s.as_bytes().get(abs_pos - 1) == Some(&b'_');

            // After: must be end-of-string or followed by '_' or non-alphanumeric
            let after_ok = after >= s.len()
                || s.as_bytes().get(after) == Some(&b'_')
                || !s.as_bytes()[after].is_ascii_alphanumeric();

            if before_ok && after_ok {
                return true;
            }
            start = abs_pos + 1;
        }
        false
    }

    has_keyword(&lower, "free")
        || has_keyword(&lower, "drop")
        || has_keyword(&lower, "dealloc")
        || has_keyword(&lower, "destroy")
        || has_keyword(&lower, "release")
        || has_keyword(&lower, "unref")
        || has_keyword(&lower, "cleanup")
        || has_keyword(&lower, "dispose")
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

    // ── R-3: RAII drop glue — compiler-inserted cleanup ──
    // `_4drop` matches Rust mangling where `_` is the separator before
    // length-prefixed identifiers (e.g. `_RNvNt...4drop...`). Using
    // `contains("4drop")` alone could match unrelated substrings like
    // "x4dropbox".
    if (callee.contains("drop_in_place") || callee.contains("_4drop_")) && callee.starts_with("_R")
    {
        return FFIVerdict::SafeConditionalRelease;
    }
    if callee == "__rust_dealloc" || callee == "__rdl_dealloc" || callee == "__rg_dealloc" {
        return FFIVerdict::SafeConditionalRelease;
    }

    // ── R-6: into_raw — ownership transfer (Box/CString/Vec::into_raw) ──
    if callee.contains("into_raw") && (callee.starts_with("_R") || callee.contains("::into_raw")) {
        return FFIVerdict::SafeInternalBridge;
    }

    // ── R-4: POSIX syscall classification ──
    // File operations — not memory management
    if matches!(
        callee,
        "open"
            | "close"
            | "read"
            | "write"
            | "unlink"
            | "rename"
            | "symlink"
            | "mkdir"
            | "rmdir"
            | "stat"
            | "fstat"
            | "lstat"
            | "chmod"
            | "chown"
            | "fcntl"
            | "ioctl"
            | "fsync"
            | "fdatasync"
            | "dup"
            | "dup2"
            | "pipe"
            | "getcwd"
            | "chdir"
            | "opendir"
            | "readdir"
            | "closedir"
            | "access"
            | "faccessat"
            | "truncate"
            | "ftruncate"
            | "realpath"
    ) {
        return FFIVerdict::SafeNoOwnership;
    }
    // Network operations — not memory management
    if matches!(
        callee,
        "socket"
            | "bind"
            | "connect"
            | "listen"
            | "accept"
            | "send"
            | "recv"
            | "sendto"
            | "recvfrom"
            | "shutdown"
            | "getsockname"
            | "getpeername"
            | "getsockopt"
            | "setsockopt"
            | "select"
            | "poll"
            | "epoll_create"
            | "epoll_ctl"
            | "epoll_wait"
            | "kqueue"
            | "kevent"
    ) {
        return FFIVerdict::SafeNoOwnership;
    }
    // Process operations — not memory management
    if matches!(
        callee,
        "fork"
            | "vfork"
            | "execve"
            | "execv"
            | "execl"
            | "waitpid"
            | "wait"
            | "kill"
            | "raise"
            | "exit"
            | "_exit"
            | "getpid"
            | "getppid"
            | "prctl"
            | "ptrace"
            | "getrlimit"
            | "setrlimit"
    ) {
        return FFIVerdict::SafeNoOwnership;
    }

    // SIMD/compute acceleration — pure computation
    if callee.starts_with("simdutf__") || callee.starts_with("highway_") {
        return FFIVerdict::SafeNoOwnership;
    }

    // Project-internal FFI bridges (by-design cross-language calls)
    if callee.starts_with("Bun__")
        || callee.starts_with("BunString__")
        || callee.starts_with("WTF__")
        || callee.starts_with("WTFStringImpl__")
        || callee.starts_with("__bun_dispatch__")
    {
        return FFIVerdict::SafeInternalBridge;
    }

    // Well-known libc data queries — always safe (universal semantic)
    if matches!(
        callee,
        "strlen"
            | "strnlen"
            | "strcmp"
            | "strncmp"
            | "strcasecmp"
            | "strncasecmp"
            | "memcmp"
            | "memmem"
            | "strstr"
            | "strchr"
            | "strrchr"
            | "getenv"
            | "secure_getenv"
            | "sysconf"
            | "getentropy"
            | "memcpy"
            | "memset"
            | "memmove"
            | "strcpy"
            | "strncpy"
            | "strerror"
            | "__error"
    ) {
        return FFIVerdict::SafeNoOwnership;
    }

    // Well-known thread/process/time operations — no ownership
    if matches!(
        callee,
        "pthread_mutex_lock"
            | "pthread_mutex_unlock"
            | "pthread_mutex_trylock"
            | "pthread_mutex_init"
            | "pthread_mutex_destroy"
            | "pthread_cond_wait"
            | "pthread_cond_signal"
            | "pthread_cond_broadcast"
            | "pthread_setname_np"
            | "pthread_threadid_np"
            | "pthread_exit"
            | "clock_gettime"
            | "gettimeofday"
            | "nanosleep"
            | "time"
            | "sigaction"
            | "sigemptyset"
            | "sigprocmask"
    ) {
        return FFIVerdict::SafeNoOwnership;
    }

    // Memory management — C++ mangled new/delete variants NOT in the registry.
    // The exact symbols (malloc, calloc, realloc, free, reallocarray,
    // __rust_alloc, __rust_realloc, __rust_alloc_zeroed) are already handled
    // by the FamilyRegistry lookup at Step 0 and never reach this code.
    // Only C++ mangled name prefixes for overloads not explicitly registered
    // (e.g. _ZdlRKv, _ZdlPvm) fall through here.
    if callee.starts_with("_Zdl")
        || callee.starts_with("_Zda")
        || callee.starts_with("_Znw")
        || callee.starts_with("_Zna")
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
        if callee.contains("5mutex")
            || callee.contains("6rwlock")
            || callee.contains("4once")
            || callee.contains("7condvar")
        {
            return FFIVerdict::SafeNoOwnership;
        }
    }

    // C++ mangled names
    if callee.starts_with("_Z") {
        return FFIVerdict::Unknown; // C++ — could be anything
    }

    // Heuristic: simple wrapper (few calls, no stores) → likely bridge.
    // Guard: exclude callees whose name suggests release semantics — a
    // function like `dangerous_wrapper(ptr p) { free(p); }` has
    // call_count==1 and store_count==0 but is NOT a safe bridge.
    if caller_behavior.call_count <= 2
        && caller_behavior.store_count == 0
        && !callee_name_suggests_release(callee)
    {
        return FFIVerdict::SafeInternalBridge;
    }

    // Heuristic: only loads and arithmetic (no stores, no atomicrmw) → read op.
    // Guard: same reasoning — a load-then-free pattern must not be classified
    // as a safe read operation.
    if caller_behavior.store_count == 0
        && caller_behavior.atomic_rmw_count == 0
        && caller_behavior.load_count > 0
        && !callee_name_suggests_release(callee)
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

        assert_eq!(
            assessment.verdict,
            FFIVerdict::SafeNoOwnership,
            "Expected values to be equal"
        );
        assert!(
            assessment.should_suppress_issue(),
            "Expected condition to be true"
        );
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

        assert_eq!(
            assessment.verdict,
            FFIVerdict::SafeConditionalRelease,
            "Expected values to be equal"
        );
        assert!(
            assessment.should_suppress_issue(),
            "Expected condition to be true"
        );
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

        assert_eq!(
            assessment.verdict,
            FFIVerdict::ConcernOwnershipTransfer,
            "Expected values to be equal"
        );
        assert!(
            !assessment.should_suppress_issue(),
            "Expected condition to be true"
        );
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

        assert_eq!(
            assessment.verdict,
            FFIVerdict::SafePointerProjection,
            "Expected values to be equal"
        );
    }

    #[test]
    fn test_verdict_safety_scores() {
        assert_eq!(
            FFIVerdict::SafeNoOwnership.safety_score(),
            0.95,
            "SafeNoOwnership should have exact score 0.95"
        );
        assert_eq!(
            FFIVerdict::SafeConditionalRelease.safety_score(),
            0.9,
            "SafeConditionalRelease should have exact score 0.9"
        );
        assert_eq!(
            FFIVerdict::SafeInternalBridge.safety_score(),
            0.85,
            "SafeInternalBridge should have exact score 0.85"
        );
        assert_eq!(
            FFIVerdict::SafePointerProjection.safety_score(),
            0.9,
            "SafePointerProjection should have exact score 0.9"
        );
        assert_eq!(
            FFIVerdict::SafeInitialization.safety_score(),
            0.85,
            "SafeInitialization should have exact score 0.85"
        );
        assert_eq!(
            FFIVerdict::ConcernOwnershipTransfer.safety_score(),
            0.3,
            "ConcernOwnershipTransfer should have exact score 0.3"
        );
        assert_eq!(
            FFIVerdict::Unknown.safety_score(),
            0.5,
            "Unknown should have exact score 0.5"
        );
    }

    /// Objective: Verify that assess_ffi_safety returns SafeInternalBridge
    /// when the callee body only calls project-internal functions (Bun__* prefix).
    /// Invariants: The callee must have InternalBridge pattern (all calls to
    /// same-project functions), and no higher-priority pattern (like
    /// OwnershipTransfer or PureComputation) must override it.
    #[test]
    fn test_assess_safe_internal_bridge() {
        let ir = r#"
            declare ptr @Bun__get_string(ptr)

            define void @bridge_wrapper(ptr %out, ptr %input) {
            entry:
                %s = call ptr @Bun__get_string(ptr %input)
                store ptr %s, ptr %out
                ret void
            }

            define void @caller_fn(ptr %out, ptr %input) {
            entry:
                call void @bridge_wrapper(ptr %out, ptr %input)
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("bridge_wrapper", "caller_fn", &module);

        assert_eq!(
            assessment.verdict,
            FFIVerdict::SafeInternalBridge,
            "Callee that only calls project-internal Bun__* functions should be SafeInternalBridge"
        );
        assert!(
            assessment.is_safe(),
            "SafeInternalBridge verdict must report is_safe() == true"
        );
        assert!(
            assessment.should_suppress_issue(),
            "SafeInternalBridge must suppress issue emission"
        );
        assert!(
            !assessment.evidence.is_empty(),
            "Assessment must include evidence for SafeInternalBridge verdict"
        );
    }

    /// Objective: Verify that assess_ffi_safety returns SafeInitialization
    /// when the callee body stores values into struct fields and returns void.
    /// Invariants: The callee must have >= 2 stores, ret void, and no calls to
    /// memory management functions. No higher-priority pattern must override.
    #[test]
    fn test_assess_safe_initialization() {
        let ir = r#"
            define void @init_struct(ptr %obj, i32 %val) {
            entry:
                %f1 = getelementptr i8, ptr %obj, i64 0
                store i32 %val, ptr %f1
                %f2 = getelementptr i8, ptr %obj, i64 4
                store i32 0, ptr %f2
                ret void
            }

            define void @caller_init(ptr %obj) {
            entry:
                call void @init_struct(ptr %obj, i32 42)
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("init_struct", "caller_init", &module);

        assert_eq!(
            assessment.verdict,
            FFIVerdict::SafeInitialization,
            "Callee with stores to struct fields and ret void should be SafeInitialization"
        );
        assert!(
            assessment.is_safe(),
            "SafeInitialization verdict must report is_safe() == true"
        );
        assert!(
            assessment.should_suppress_issue(),
            "SafeInitialization must suppress issue emission"
        );
    }

    /// Objective: Verify is_safe() returns the correct boolean for every verdict variant.
    /// Invariants: All Safe* variants return true; Concern* and Unknown return false.
    #[test]
    fn test_is_safe_all_verdicts() {
        assert!(
            FFIVerdict::SafeNoOwnership.is_safe(),
            "SafeNoOwnership must be safe"
        );
        assert!(
            FFIVerdict::SafeConditionalRelease.is_safe(),
            "SafeConditionalRelease must be safe"
        );
        assert!(
            FFIVerdict::SafeInternalBridge.is_safe(),
            "SafeInternalBridge must be safe"
        );
        assert!(
            FFIVerdict::SafePointerProjection.is_safe(),
            "SafePointerProjection must be safe"
        );
        assert!(
            FFIVerdict::SafeInitialization.is_safe(),
            "SafeInitialization must be safe"
        );
        assert!(
            !FFIVerdict::ConcernOwnershipTransfer.is_safe(),
            "ConcernOwnershipTransfer must NOT be safe"
        );
        assert!(!FFIVerdict::Unknown.is_safe(), "Unknown must NOT be safe");
    }

    /// Objective: Verify should_suppress_issue() correctly identifies which
    /// verdicts should suppress issue emission. Currently delegates to is_safe().
    /// Invariants: All Safe* verdicts suppress issues; Concern* and Unknown do not.
    #[test]
    fn test_should_suppress_issue_all_verdicts() {
        // Safe variants should suppress issue emission
        assert!(
            FFIVerdict::SafeNoOwnership.should_suppress_issue(),
            "SafeNoOwnership should suppress issues"
        );
        assert!(
            FFIVerdict::SafeConditionalRelease.should_suppress_issue(),
            "SafeConditionalRelease should suppress issues"
        );
        assert!(
            FFIVerdict::SafeInternalBridge.should_suppress_issue(),
            "SafeInternalBridge should suppress issues"
        );
        assert!(
            FFIVerdict::SafePointerProjection.should_suppress_issue(),
            "SafePointerProjection should suppress issues"
        );
        assert!(
            FFIVerdict::SafeInitialization.should_suppress_issue(),
            "SafeInitialization should suppress issues"
        );
        // Concern and Unknown variants must NOT suppress
        assert!(
            !FFIVerdict::ConcernOwnershipTransfer.should_suppress_issue(),
            "ConcernOwnershipTransfer must NOT suppress issues"
        );
        assert!(
            !FFIVerdict::Unknown.should_suppress_issue(),
            "Unknown must NOT suppress issues"
        );
    }

    /// Objective: Verify FFISafetyAssessment::summary() produces the correct
    /// format string when callee behavior is available and when it is absent.
    /// Invariants: Summary must contain caller, callee, verdict, score, and
    /// either callee behavior patterns or "external (no body)" indicator.
    #[test]
    fn test_assessment_summary_with_callee_body() {
        let ir = r#"
            define i64 @my_strlen(ptr %s) {
            entry:
                %len = call i32 @strlen(ptr %s)
                %result = zext i32 %len to i64
                ret i64 %result
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("strlen", "my_strlen", &module);
        let summary = assessment.summary();

        // Verify the summary contains the caller and callee names
        assert!(
            summary.contains("my_strlen"),
            "Summary must contain caller name 'my_strlen', got: {}",
            summary
        );
        assert!(
            summary.contains("strlen"),
            "Summary must contain callee name 'strlen', got: {}",
            summary
        );
        // Verify verdict and score are present
        assert!(
            summary.contains("verdict="),
            "Summary must contain 'verdict=', got: {}",
            summary
        );
        assert!(
            summary.contains("score="),
            "Summary must contain 'score=', got: {}",
            summary
        );
    }

    #[test]
    fn test_assessment_summary_without_callee_body() {
        // External callee with no body — summary should indicate external
        let ir = r#"
            declare i32 @external_func(ptr)

            define i32 @my_caller(ptr %p) {
            entry:
                %r = call i32 @external_func(ptr %p)
                ret i32 %r
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("external_func", "my_caller", &module);
        let summary = assessment.summary();

        assert!(
            summary.contains("external (no body)"),
            "Summary for external callee must contain 'external (no body)', got: {}",
            summary
        );
        assert!(
            summary.contains("FFI my_caller -> external_func"),
            "Summary must start with 'FFI caller -> callee' format, got: {}",
            summary
        );
    }

    #[test]
    fn test_assessment_summary_format_with_known_verdict() {
        // Construct assessment directly to verify exact format
        let assessment = FFISafetyAssessment {
            callee: "strlen".to_string(),
            caller: "wrapper".to_string(),
            caller_behavior: None,
            callee_behavior: None,
            verdict: FFIVerdict::SafeNoOwnership,
            evidence: vec![],
        };
        let summary = assessment.summary();

        assert_eq!(
            summary,
            "FFI wrapper -> strlen: verdict=SafeNoOwnership score=0.95 [callee: external (no body)]",
            "Summary format must match exactly for known verdict with no callee body"
        );
    }

    // ── FFIVerdict variant coverage tests ──

    /// Objective: Verify that assess_ffi_safety returns Unknown when no function
    ///            body is available and no heuristics match.
    /// Invariants: Unknown verdict must have is_safe() == false and
    ///            should_suppress_issue() == false.
    #[test]
    fn test_verdict_unknown() {
        // Use a callee that returns a ptr which is stored to non-local memory —
        // this prevents PureComputation from triggering (void calls bypass the
        // call_dests store check, but a non-void call stored to non-alloca
        // memory is detected as ownership-relevant).
        let ir = r#"
            declare ptr @custom_callee(ptr)

            define ptr @caller_fn(ptr %p) {
            entry:
                %r = call ptr @custom_callee(ptr %p)
                store ptr %r, ptr %p
                ret ptr %r
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("custom_callee", "caller_fn", &module);

        // "custom_callee" doesn't match any FamilyRegistry entry, any POSIX/libc
        // heuristic, any project-internal prefix, or any Rust/C++ pattern.
        // The caller stores the call result to non-local memory, so PureComputation
        // is rejected. No ConditionalRelease or OwnershipTransfer either.
        // The result should be Unknown.
        assert_eq!(
            assessment.verdict,
            FFIVerdict::Unknown,
            "Unresolvable external callee with no matching heuristic must produce Unknown, got {:?}",
            assessment.verdict
        );
        assert!(
            !assessment.is_safe(),
            "Unknown verdict must report is_safe() == false"
        );
        assert!(
            !assessment.should_suppress_issue(),
            "Unknown verdict must NOT suppress issue emission"
        );
        assert!(
            !assessment.evidence.is_empty(),
            "Unknown verdict must still have evidence explaining why"
        );
    }

    /// Objective: Verify that ConcernOwnershipTransfer is returned for a known
    ///            memory allocation function (malloc) even with an empty caller body.
    /// Invariants: malloc is in the FamilyRegistry as an Acquire symbol; the
    ///            verdict must be ConcernOwnershipTransfer.
    #[test]
    fn test_verdict_concern_ownership_transfer_malloc() {
        let ir = r#"
            declare ptr @malloc(i64)

            define ptr @alloc_buf(i64 %n) {
            entry:
                %p = call ptr @malloc(i64 %n)
                ret ptr %p
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("malloc", "alloc_buf", &module);

        assert_eq!(
            assessment.verdict,
            FFIVerdict::ConcernOwnershipTransfer,
            "malloc must produce ConcernOwnershipTransfer"
        );
        assert!(
            !assessment.is_safe(),
            "ConcernOwnershipTransfer must report is_safe() == false"
        );
        assert!(
            assessment.safety_score() < 0.5,
            "ConcernOwnershipTransfer safety score must be < 0.5, got {}",
            assessment.safety_score()
        );
    }

    /// Objective: Verify that SafeNoOwnership is returned for a callee that
    ///            matches a POSIX file operation heuristic (external, no body).
    /// Invariants: POSIX file operations produce SafeNoOwnership.
    #[test]
    fn test_verdict_safe_no_ownership_posix() {
        let ir = r#"
            declare i32 @open(ptr, i32)

            define i32 @my_open(ptr %path, i32 %flags) {
            entry:
                %fd = call i32 @open(ptr %path, i32 %flags)
                ret i32 %fd
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("open", "my_open", &module);

        assert_eq!(
            assessment.verdict,
            FFIVerdict::SafeNoOwnership,
            "POSIX 'open' must produce SafeNoOwnership"
        );
        assert!(
            assessment.is_safe(),
            "SafeNoOwnership must report is_safe() == true"
        );
    }

    /// Objective: Verify that SafeConditionalRelease is returned for a known
    ///            library-managed release function (zlib deflateEnd).
    /// Invariants: Library-managed families produce SafeConditionalRelease.
    #[test]
    fn test_verdict_safe_conditional_release_library() {
        let ir = r#"
            declare i32 @deflateEnd(ptr)

            define i32 @cleanup(ptr %s) {
            entry:
                %r = call i32 @deflateEnd(ptr %s)
                ret i32 %r
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("deflateEnd", "cleanup", &module);

        assert_eq!(
            assessment.verdict,
            FFIVerdict::SafeConditionalRelease,
            "Library-managed release (deflateEnd) must produce SafeConditionalRelease"
        );
        assert!(
            assessment.is_safe(),
            "SafeConditionalRelease must report is_safe() == true"
        );
    }

    /// Objective: Verify that SafeInternalBridge is returned for into_raw
    ///            via heuristic (Rust mangled name with _R prefix + into_raw).
    /// Invariants: The into_raw heuristic in derive_from_caller_context checks
    ///            for `_R` prefix + `into_raw` substring, or `::into_raw`.
    #[test]
    fn test_verdict_safe_internal_bridge_into_raw() {
        // Use a Rust mangled name that starts with _R and contains into_raw
        let ir = r#"
            declare ptr @_RINvNtC4core6option15Option9into_raw(ptr)

            define ptr @extract_raw(ptr %opt) {
            entry:
                %raw = call ptr @_RINvNtC4core6option15Option9into_raw(ptr %opt)
                store ptr %raw, ptr %opt
                ret ptr %raw
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety(
            "_RINvNtC4core6option15Option9into_raw",
            "extract_raw",
            &module,
        );

        // The Rust mangled name starts with "_R" and contains "into_raw",
        // which should trigger the R-6 heuristic in derive_from_caller_context.
        assert_eq!(
            assessment.verdict,
            FFIVerdict::SafeInternalBridge,
            "into_raw callee with _R prefix must produce SafeInternalBridge, got {:?}",
            assessment.verdict
        );
    }

    /// Objective: Verify that FFISafetyAssessment correctly propagates the
    ///            verdict's safety_score when constructed directly.
    /// Invariants: assessment.safety_score() must equal verdict.safety_score().
    #[test]
    fn test_assessment_safety_score_propagation() {
        let verdicts = [
            FFIVerdict::SafeNoOwnership,
            FFIVerdict::SafeConditionalRelease,
            FFIVerdict::SafeInternalBridge,
            FFIVerdict::SafePointerProjection,
            FFIVerdict::SafeInitialization,
            FFIVerdict::ConcernOwnershipTransfer,
            FFIVerdict::Unknown,
        ];

        for verdict in verdicts {
            let assessment = FFISafetyAssessment {
                callee: "test".to_string(),
                caller: "caller".to_string(),
                caller_behavior: None,
                callee_behavior: None,
                verdict: verdict.clone(),
                evidence: vec![],
            };
            assert!(
                (assessment.safety_score() - verdict.safety_score()).abs() < f32::EPSILON,
                "Assessment safety_score must match verdict safety_score for {:?}",
                verdict
            );
        }
    }

    /// Objective: Verify that ConcernOwnershipTransfer is returned for free()
    ///            (external memory deallocation function).
    /// Invariants: free must produce ConcernOwnershipTransfer, not a safe verdict.
    #[test]
    fn test_verdict_concern_for_free() {
        let ir = r#"
            declare void @free(ptr)

            define void @my_free(ptr %p) {
            entry:
                call void @free(ptr %p)
                ret void
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("free", "my_free", &module);

        assert_eq!(
            assessment.verdict,
            FFIVerdict::ConcernOwnershipTransfer,
            "free() must produce ConcernOwnershipTransfer"
        );
        assert!(
            !assessment.should_suppress_issue(),
            "ConcernOwnershipTransfer must NOT suppress issue emission"
        );
    }

    /// Objective: Verify that SafeInternalBridge is returned for project-internal
    ///            Bun__ prefixed functions (by-design FFI boundary) via the
    ///            callee-name heuristic in derive_from_caller_context.
    /// Invariants: Bun__* prefix heuristic must produce SafeInternalBridge.
    #[test]
    fn test_verdict_safe_internal_bridge_bun_prefix() {
        // The callee returns a non-void value which is stored — this prevents
        // PureComputation detection (void calls have no dest register, causing
        // call_dests to be empty and bypassing the store-to-non-local check).
        let ir = r#"
            declare ptr @Bun__resolve(ptr, i32)

            define ptr @my_resolve(ptr %ctx, i32 %val) {
            entry:
                store i32 %val, ptr %ctx
                %r = call ptr @Bun__resolve(ptr %ctx, i32 %val)
                store ptr %r, ptr %ctx
                ret ptr %r
            }
        "#;

        let module = IRModule::parse_from_text(ir);
        let assessment = assess_ffi_safety("Bun__resolve", "my_resolve", &module);

        assert_eq!(
            assessment.verdict,
            FFIVerdict::SafeInternalBridge,
            "Bun__* prefix heuristic must produce SafeInternalBridge, got {:?}",
            assessment.verdict
        );
        assert!(
            assessment.is_safe(),
            "SafeInternalBridge must report is_safe() == true"
        );
    }

    // ── Tests for callee_name_suggests_release word-boundary matching ──

    #[test]
    fn test_release_suggest_true_positives() {
        assert!(
            callee_name_suggests_release("c_free"),
            "c_free must be recognized as a release function"
        );
        assert!(
            callee_name_suggests_release("my_dealloc"),
            "my_dealloc must be recognized as a release function"
        );
        assert!(
            callee_name_suggests_release("obj_drop"),
            "obj_drop must be recognized as a release function"
        );
        assert!(
            callee_name_suggests_release("resource_destroy"),
            "resource_destroy must be recognized as a release function"
        );
        assert!(
            callee_name_suggests_release("handle_release"),
            "handle_release must be recognized as a release function"
        );
        assert!(
            callee_name_suggests_release("ref_unref"),
            "ref_unref must be recognized as a release function"
        );
        assert!(
            callee_name_suggests_release("buffer_cleanup"),
            "buffer_cleanup must be recognized as a release function"
        );
        assert!(
            callee_name_suggests_release("widget_dispose"),
            "widget_dispose must be recognized as a release function"
        );
        // Bare keyword at end of name (no delimiter)
        assert!(
            callee_name_suggests_release("free"),
            "bare 'free' must be recognized as a release function"
        );
        assert!(
            callee_name_suggests_release("dealloc"),
            "bare 'dealloc' must be recognized as a release function"
        );
    }

    #[test]
    fn test_release_suggest_false_positives_rejected() {
        assert!(
            !callee_name_suggests_release("freeze"),
            "'freeze' must NOT match as release (false positive on 'free')"
        );
        assert!(
            !callee_name_suggests_release("dropdown"),
            "'dropdown' must NOT match as release (false positive on 'drop')"
        );
        assert!(
            !callee_name_suggests_release("destroyed_already"),
            "'destroyed_already' must NOT match as release (substring 'destroy' mid-word)"
        );
        assert!(
            !callee_name_suggests_release("freezing_point"),
            "'freezing_point' must NOT match as release"
        );
        assert!(
            !callee_name_suggests_release("drops_handler"),
            "'drops_handler' must NOT match as release (no delimiter before 'drop')"
        );
    }

    #[test]
    fn test_release_suggest_case_insensitive() {
        assert!(
            callee_name_suggests_release("C_FREE"),
            "C_FREE must match case-insensitively"
        );
        assert!(
            callee_name_suggests_release("My_Dealloc"),
            "My_Dealloc must match case-insensitively"
        );
    }
}
