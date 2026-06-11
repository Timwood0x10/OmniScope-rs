//! Noise Reduction and FP Precision Guard.
//!
//! This module provides two complementary mechanisms:
//!
//! 1. **NoiseReduction** — Suppresses false positives using a two-layer
//!    approach:
//!    - **Layer 1 (fast)**: String-based safe patterns (drop_in_place,
//!      __rust_alloc, llvm.*, etc.) — used as a quick pre-filter.
//!    - **Layer 2 (semantic)**: SRT-based `SemanticKind` queries —
//!      the authoritative suppression mechanism per bun_fp_reduction_plan.
//!      When SRT data is available, Layer 2 overrides Layer 1.
//!
//! 2. **PrecisionMetrics** — Tracks TP/FP/FN for the hard gate
//!    from the refactoring plan: "You CANNOT remove existing FP
//!    filtering until MemoryGraph ownership precision >= current
//!    FP filtering effect."
//!
//! ## Migration Note
//!
//! The string-based `safe_patterns` list is retained for backward
//! compatibility and as a fast pre-filter. The SRT-based `issue_gate`
//! module (`crate::resource::issue_gate`) is the single choke point
//! for all issue suppression. New suppression logic should go into
//! SRT detectors (R-0~R-7), NOT into this safe_patterns list.

use serde::{Deserialize, Serialize};
use tracing::debug;

/// Noise reduction engine.
///
/// Uses SurfaceClassifier results to suppress false positives.
/// Functions classified as StandardLibrary, CompilerGenerated,
/// or Runtime are skipped entirely. Remaining functions are
/// checked against known safe patterns.
pub struct NoiseReduction {
    /// Patterns that indicate safe operations (not FFI issues).
    safe_patterns: Vec<&'static str>,
    /// Patterns for runtime-internal *caller* functions.
    /// When a generic C function (free/malloc) is called FROM one of these
    /// callers, the resulting issue is a runtime false positive.
    runtime_caller_patterns: Vec<&'static str>,
}

impl NoiseReduction {
    /// Creates a new noise reduction engine with built-in safe patterns.
    pub fn new() -> Self {
        Self {
            safe_patterns: vec![
                // Compiler-generated drop glue
                "drop_in_place",
                // Panic infrastructure
                "panic_fmt",
                "begin_panic",
                // Rust allocator internals
                "__rust_alloc",
                "__rust_dealloc",
                "__rust_realloc",
                "__rust_alloc_zeroed",
                // Rust v0 mangled alloc/core internals
                "_ZN5alloc",
                "_ZN4core",
                // C++ ABI internals
                "__cxa_allocate_exception",
                "__cxa_throw",
                "__cxa_begin_catch",
                "__cxa_end_catch",
                // LLVM intrinsics
                "llvm.",
                // Stack canary
                "__stack_chk_fail",
                "__stack_chk_guard",
                // ── Rust FFI allocator/arena patterns (Bun-specific) ──
                // Bun's allocator crate (mangled with crate hash)
                "bun_alloc",
                "9bun_alloc",
                // Mimalloc arena wrappers used in Bun
                "MimallocArena",
                "mimalloc_arena",
                // ZAllocator — Bun's generic allocator abstraction
                "ZAllocator",
                "zallocator",
                // NullableAllocator / CAllocator
                "NullableAllocator",
                "nullable_allocator",
                "CAllocator",
                "c_allocator",
                // heap_breakdown module (Bun's JS heap zone tracking)
                "heap_breakdown",
                "heap_break",
                // bss_arena_bump (Bun's BSS arena bump allocator)
                "bss_arena_bump",
                "BssArenaBump",
                // c_thunks module (mi_free_bytes, mi_free_opaque, mi_malloc_items)
                "c_thunks",
                "c_thunk",
                // Zone-based allocation (Bun's JS heap zones)
                "Zone::",
                "4zone",
                // SliceCursor / Write trait impls writing to buffers
                "SliceCursor",
                "slice_cursor",
                "WritePtr",
                "write_ptr",
                // RawVec / alloc crate internals
                "RawVec",
                "raw_vec",
                "7raw_vec",
                "finish_grow",
                "grow_one",
                // ── macOS memory zone APIs (non-allocator but misidentified) ──
                "malloc_set_zone_name",
                "malloc_create_zone",
                "malloc_default_zone",
                "malloc_zone_memalign",
                "malloc_zone_from_ptr",
                "malloc_zone_malloc",
                "malloc_zone_free",
                "malloc_zone_realloc",
                "malloc_zone_calloc",
                "malloc_destroy_zone",
                // ── miminaloc API (allocator pair recognition) ──
                "mi_heap_new",
                "mi_heap_destroy",
                "mi_heap_visit_blocks",
                "mi_heap_visit",
                "mi_is_in_heap_region",
                "mi_is_in_heap",
                "mi_malloc",
                "mi_free",
                "mi_realloc",
                "mi_calloc",
                "mi_realpath",
                "mi_strdup",
                "mi_strndup",
                "mi_recalloc",
            ],
            // Patterns for runtime-internal *caller* functions.
            // When a generic C function (free/malloc) is called FROM one of these
            // callers, the resulting issue is a runtime false positive.
            runtime_caller_patterns: vec![
                // Rust FFI allocator/arena internals (Bun-specific)
                "bun_alloc",
                "9bun_alloc",
                "MimallocArena",
                "ZAllocator",
                "NullableAllocator",
                "CAllocator",
                "heap_breakdown",
                "bss_arena_bump",
                "c_thunks",
                "Zone::",
                "RawVec",
                "raw_vec",
                "SliceCursor",
            ],
        }
    }

    /// Checks if an issue should be suppressed as a false positive.
    ///
    /// Returns true if the issue matches a known safe pattern
    /// and should be suppressed (not reported to the user).
    pub fn should_suppress(&self, func_name: &str) -> bool {
        let suppressed = self.safe_patterns.iter().any(|p| func_name.contains(p));
        if suppressed {
            debug!("NoiseReduction: suppressing FP for '{}'", func_name);
        }
        suppressed
    }

    /// Checks if an issue should be suppressed using caller context.
    ///
    /// For generic C functions (free, malloc, etc.) that produce double_free
    /// or use_after_free issues, the function name alone is too generic to
    /// suppress. However, if the *caller* is a known runtime internal
    /// (e.g., Zig's mem.Allocator.reallocAdvanced), the issue is a FP.
    ///
    /// Returns true if the caller matches a runtime-internal pattern.
    pub fn should_suppress_runtime_caller(&self, caller_name: &str) -> bool {
        let suppressed = self
            .runtime_caller_patterns
            .iter()
            .any(|p| caller_name.contains(p));
        if suppressed {
            debug!(
                "NoiseReduction: suppressing FP — runtime caller '{}'",
                caller_name
            );
        }
        suppressed
    }

    /// Static version of `should_suppress_runtime_caller` that doesn't require
    /// an instance. Used by IssueGate fallback rules in pass.rs.
    pub fn runtime_caller_match(caller_name: &str) -> bool {
        static PATTERNS: &[&str] = &[
            // Rust FFI allocator/arena internals (Bun-specific)
            "bun_alloc",
            "9bun_alloc",
            "MimallocArena",
            "ZAllocator",
            "NullableAllocator",
            "CAllocator",
            "heap_breakdown",
            "bss_arena_bump",
            "c_thunks",
            "Zone::",
            "RawVec",
            "raw_vec",
            "SliceCursor",
        ];
        PATTERNS.iter().any(|p| caller_name.contains(p))
    }

    /// Returns the number of safe patterns registered.
    pub fn pattern_count(&self) -> usize {
        self.safe_patterns.len()
    }

    /// Checks if an issue should be suppressed based on SRT semantic kinds.
    ///
    /// This is the Layer 2 (semantic) check. It queries the SRT for
    /// suppression signals (R-0~R-7) and returns true if any signal
    /// indicates the issue is a false positive.
    ///
    /// When SRT data is available, this method is authoritative —
    /// it overrides the string-based `should_suppress` check.
    pub fn should_suppress_by_srt(
        &self,
        symbol: &str,
        issue_kind: &str,
        resolutions: &std::collections::HashMap<String, Vec<omniscope_semantics::SemanticKind>>,
    ) -> bool {
        use omniscope_semantics::SemanticKind;

        let Some(kinds) = resolutions.get(symbol) else {
            return false;
        };

        let suppressed = match issue_kind {
            "borrow_escape" => kinds.iter().any(|k| {
                matches!(
                    k,
                    SemanticKind::HeapProvenance | SemanticKind::GlobalProvenance
                )
            }),
            "use_after_free" | "double_free" => kinds
                .iter()
                .any(|k| matches!(k, SemanticKind::RaiiDropRelease)),
            "cross_language_free" | "cross_family_free" => kinds.iter().any(|k| {
                matches!(
                    k,
                    SemanticKind::IntoRawTransfer
                        | SemanticKind::FileOperation
                        | SemanticKind::NetworkOperation
                        | SemanticKind::ProcessOperation
                        | SemanticKind::LibraryRelease
                )
            }),
            "ffi_unsafe_call" => kinds.iter().any(|k| {
                matches!(
                    k,
                    // R-4: POSIX non-memory syscalls
                    SemanticKind::FileOperation
                        | SemanticKind::NetworkOperation
                        | SemanticKind::ProcessOperation
                        // R-7: Library allocator releases
                        | SemanticKind::LibraryRelease
                        // R-6: Ownership transfer via into_raw
                        | SemanticKind::IntoRawTransfer
                        // R-3: RAII drop/dealloc patterns
                        | SemanticKind::RaiiDropRelease
                        // R-1: Heap/global provenance
                        | SemanticKind::HeapProvenance
                        | SemanticKind::GlobalProvenance
                        // R-8: From function parameter
                        | SemanticKind::FromParameter
                        // C++ RAII patterns
                        | SemanticKind::CppDestructor
                        | SemanticKind::CppUniquePtr
                        | SemanticKind::CppSharedPtr
                        // Go cleanup patterns
                        | SemanticKind::GoDeferCleanup
                        | SemanticKind::GoFinalizer
                        // Python reference counting
                        | SemanticKind::PythonRefcountInc
                        | SemanticKind::PythonRefcountDec
                        | SemanticKind::PythonBorrowedRef
                        | SemanticKind::PythonOwnedRef
                        | SemanticKind::PythonGilProtected
                        // C# SafeHandle and finalizer
                        | SemanticKind::CsharpSafeHandle
                        | SemanticKind::CsharpFinalizer
                        // Java JNI references
                        | SemanticKind::JavaLocalRef
                        | SemanticKind::JavaGlobalRef
                        | SemanticKind::JavaWeakRef
                )
            }),
            // Leak types: suppress when cleanup mechanism detected (RAII, defer, GC, etc.)
            "conditional_leak" | "definite_leak" => kinds.iter().any(|k| {
                matches!(
                    k,
                    // R-3: RAII drop/dealloc — compiler will free
                    SemanticKind::RaiiDropRelease
                        // C++ RAII: destructor/smart-ptr ensures cleanup
                        | SemanticKind::CppDestructor
                        | SemanticKind::CppUniquePtr
                        | SemanticKind::CppSharedPtr
                        // Go: defer/finalizer ensures cleanup
                        | SemanticKind::GoDeferCleanup
                        | SemanticKind::GoFinalizer
                        // Python: refcount ensures cleanup
                        | SemanticKind::PythonRefcountInc
                        | SemanticKind::PythonRefcountDec
                        | SemanticKind::PythonBorrowedRef
                        | SemanticKind::PythonOwnedRef
                        | SemanticKind::PythonGilProtected
                        // C#: SafeHandle/finalizer ensures cleanup
                        | SemanticKind::CsharpSafeHandle
                        | SemanticKind::CsharpFinalizer
                        // Java: JNI reference management ensures cleanup
                        | SemanticKind::JavaLocalRef
                        | SemanticKind::JavaGlobalRef
                        | SemanticKind::JavaWeakRef
                        // R-1: Heap/global provenance — runtime-managed
                        | SemanticKind::HeapProvenance
                        | SemanticKind::GlobalProvenance
                        // Runtime internal wrapper
                        | SemanticKind::RuntimeInternal
                )
            }),
            "ownership_escape_leak" => kinds.iter().any(|k| {
                matches!(
                    k,
                    // R-3: RAII drop
                    SemanticKind::RaiiDropRelease
                        // C++ RAII
                        | SemanticKind::CppDestructor
                        | SemanticKind::CppUniquePtr
                        | SemanticKind::CppSharedPtr
                        // Go cleanup
                        | SemanticKind::GoDeferCleanup
                        | SemanticKind::GoFinalizer
                        // R-6: Ownership transfer via into_raw — by design
                        | SemanticKind::IntoRawTransfer
                        // Runtime internal wrapper
                        | SemanticKind::RuntimeInternal
                )
            }),
            // R-9: Suppress unchecked_return for allocators (malloc_unchecked noise)
            "unchecked_return" => kinds.iter().any(|k| {
                matches!(
                    k,
                    SemanticKind::HeapProvenance | SemanticKind::GoRuntimeAlloc
                )
            }),
            _ => false,
        };

        if suppressed {
            debug!(
                "NoiseReduction(SRT): suppressing FP for '{}' (kind={})",
                symbol, issue_kind
            );
        }
        suppressed
    }
}

impl Default for NoiseReduction {
    fn default() -> Self {
        Self::new()
    }
}

/// Precision metrics for a single analysis run.
///
/// Computed from issue output + ground truth (manual audit).
/// Used by the FP Precision Guard to enforce the hard gate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrecisionMetrics {
    /// Total issues reported by analyzer.
    pub total_issues: u32,
    /// Issues confirmed as true positives (real bugs).
    pub true_positives: u32,
    /// Issues confirmed as false positives (noise).
    pub false_positives: u32,
    /// Real bugs missed by analyzer (from manual audit).
    pub false_negatives: u32,
    /// Total real bugs in target (ground truth).
    pub total_actual_bugs: u32,
    /// Functions analyzed.
    pub functions_analyzed: u32,
    /// Functions skipped by noise reduction.
    pub functions_skipped: u32,
}

impl PrecisionMetrics {
    /// Creates new empty metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// FFI-specific precision: TP / (TP + FP).
    ///
    /// Target: >= 88% (from refactoring plan baseline).
    pub fn ffi_precision(&self) -> f32 {
        let denominator = self.true_positives + self.false_positives;
        if denominator == 0 {
            return 1.0;
        }
        self.true_positives as f32 / denominator as f32
    }

    /// Overall recall: TP / (TP + FN).
    pub fn recall(&self) -> f32 {
        let denominator = self.true_positives + self.false_negatives;
        if denominator == 0 {
            return 1.0;
        }
        self.true_positives as f32 / denominator as f32
    }

    /// F1 score: harmonic mean of precision and recall.
    pub fn f1_score(&self) -> f32 {
        let p = self.ffi_precision();
        let r = self.recall();
        if p + r == 0.0 {
            return 0.0;
        }
        2.0 * p * r / (p + r)
    }

    /// False positive rate: FP / (TP + FP).
    pub fn fp_rate(&self) -> f32 {
        let denominator = self.true_positives + self.false_positives;
        if denominator == 0 {
            return 0.0;
        }
        self.false_positives as f32 / denominator as f32
    }

    /// Noise reduction ratio: (before - after) / before.
    ///
    /// Target: >= 97% on wasmtime (from refactoring plan baseline).
    pub fn noise_reduction_ratio(&self, issues_before_filter: u32) -> f32 {
        if issues_before_filter == 0 {
            return 1.0;
        }
        // Use u32 arithmetic to avoid i32 overflow when values exceed i32::MAX.
        let reduced = issues_before_filter.saturating_sub(self.total_issues);
        reduced as f32 / issues_before_filter as f32
    }

    /// Run the precision gate check against baseline thresholds.
    ///
    /// Returns Ok(()) if precision meets the bar, Err with description
    /// of the failure otherwise.
    pub fn gate_check(&self) -> Result<(), String> {
        const MIN_PRECISION: f32 = 0.88;
        const MAX_FP_RATE: f32 = 0.12;

        let precision = self.ffi_precision();
        let fp_rate = self.fp_rate();

        if precision < MIN_PRECISION {
            return Err(format!(
                "FFI precision {:.1}% below threshold {:.1}% (TP={}, FP={})",
                precision * 100.0,
                MIN_PRECISION * 100.0,
                self.true_positives,
                self.false_positives
            ));
        }

        if fp_rate > MAX_FP_RATE {
            return Err(format!(
                "FP rate {:.1}% above threshold {:.1}%",
                fp_rate * 100.0,
                MAX_FP_RATE * 100.0
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify noise reduction suppresses known safe patterns.
    /// Invariants: drop_in_place, __rust_alloc, llvm.memcpy must be suppressed.
    #[test]
    fn test_noise_reduction_safe_patterns() {
        let nr = NoiseReduction::new();
        assert!(
            nr.should_suppress("drop_in_place"),
            "drop_in_place must be suppressed"
        );
        assert!(
            nr.should_suppress("__rust_alloc"),
            "__rust_alloc must be suppressed"
        );
        assert!(
            nr.should_suppress("llvm.memcpy.p0i8.p0i8.i64"),
            "LLVM intrinsics must be suppressed"
        );
        assert!(
            !nr.should_suppress("my_c_handler"),
            "user functions must NOT be suppressed"
        );
    }

    /// Objective: Verify precision metrics computation.
    /// Invariants: precision=TP/(TP+FP), recall=TP/(TP+FN).
    #[test]
    fn test_precision_metrics_computation() {
        let metrics = PrecisionMetrics {
            total_issues: 10,
            true_positives: 8,
            false_positives: 2,
            false_negatives: 1,
            total_actual_bugs: 9,
            functions_analyzed: 100,
            functions_skipped: 50,
        };

        let precision = metrics.ffi_precision();
        let recall = metrics.recall();

        assert!(
            (precision - 0.8).abs() < 0.01,
            "precision must be 8/10=0.8, got {:.3}",
            precision
        );
        assert!(
            (recall - 8.0 / 9.0).abs() < 0.01,
            "recall must be 8/9≈0.889, got {:.3}",
            recall
        );
    }

    /// Objective: Verify gate check passes with good metrics.
    /// Invariants: 90% precision with 5% FP rate must pass.
    #[test]
    fn test_gate_check_passes() {
        let metrics = PrecisionMetrics {
            total_issues: 20,
            true_positives: 18,
            false_positives: 2,
            false_negatives: 0,
            total_actual_bugs: 18,
            functions_analyzed: 100,
            functions_skipped: 0,
        };

        assert!(
            metrics.gate_check().is_ok(),
            "90% precision with 10% FP rate must pass the gate"
        );
    }

    /// Objective: Verify gate check fails with poor precision.
    /// Invariants: 50% precision must fail the gate.
    #[test]
    fn test_gate_check_fails() {
        let metrics = PrecisionMetrics {
            total_issues: 10,
            true_positives: 5,
            false_positives: 5,
            false_negatives: 0,
            total_actual_bugs: 5,
            functions_analyzed: 100,
            functions_skipped: 0,
        };

        assert!(
            metrics.gate_check().is_err(),
            "50% precision must fail the gate (threshold is 88%)"
        );
    }

    /// Objective: Verify F1 score computation.
    /// Invariants: F1 = 2*P*R/(P+R).
    #[test]
    fn test_f1_score() {
        let metrics = PrecisionMetrics {
            total_issues: 10,
            true_positives: 8,
            false_positives: 2,
            false_negatives: 2,
            total_actual_bugs: 10,
            functions_analyzed: 100,
            functions_skipped: 0,
        };

        let f1 = metrics.f1_score();
        // P=0.8, R=0.8, F1=0.8
        assert!(
            (f1 - 0.8).abs() < 0.01,
            "F1 must be 0.8 when P=R=0.8, got {:.3}",
            f1
        );
    }
}
