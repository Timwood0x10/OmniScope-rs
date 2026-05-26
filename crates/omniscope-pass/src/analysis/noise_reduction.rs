//! Noise Reduction and FP Precision Guard.
//!
//! This module provides two complementary mechanisms:
//!
//! 1. **NoiseReduction** — Suppresses false positives based on
//!    SurfaceClassifier results and known safe patterns.
//!
//! 2. **PrecisionMetrics** — Tracks TP/FP/FN for the hard gate
//!    from the refactoring plan: "You CANNOT remove existing FP
//!    filtering until MemoryGraph ownership precision >= current
//!    FP filtering effect."

use serde::{Deserialize, Serialize};

/// Noise reduction engine.
///
/// Uses SurfaceClassifier results to suppress false positives.
/// Functions classified as StandardLibrary, CompilerGenerated,
/// or Runtime are skipped entirely. Remaining functions are
/// checked against known safe patterns.
pub struct NoiseReduction {
    /// Patterns that indicate safe operations (not FFI issues).
    safe_patterns: Vec<&'static str>,
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
            ],
        }
    }

    /// Checks if an issue should be suppressed as a false positive.
    ///
    /// Returns true if the issue matches a known safe pattern
    /// and should be suppressed (not reported to the user).
    pub fn should_suppress(&self, func_name: &str) -> bool {
        self.safe_patterns.iter().any(|p| func_name.contains(p))
    }

    /// Returns the number of safe patterns registered.
    pub fn pattern_count(&self) -> usize {
        self.safe_patterns.len()
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
        let reduced = issues_before_filter as i32 - self.total_issues as i32;
        if reduced < 0 {
            return 0.0;
        }
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
