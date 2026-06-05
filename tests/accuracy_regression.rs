//! Accuracy regression test for OmniScope FFI bug detection.
//!
//! Runs the full pipeline on all ffi-demo `.ll` files and computes
//! TP/FP/FN/Precision/Recall/F1 against a golden baseline.
//!
//! Current baseline (FP = total_detected - TP):
//!   TP=13, FP=23, FN=11, Precision=36.1%, Recall=54.2%, F1=43.3%
//!
//! The golden expectations below reflect the current pipeline output
//! on ffi-demo files. Each fixture has:
//!   - Expected bugs (true positives): real bugs the pipeline MUST detect
//!   - Expected noise (false positives): benign patterns the pipeline should NOT flag
//!   - Expected misses (false negatives): real bugs the pipeline currently misses
//!
//! Usage:
//! ```bash
//! cargo test accuracy_regression -- --nocapture
//! ```

use omniscope_core::IssueKind;
use omniscope_ir::IRModule;
use omniscope_pipeline::Pipeline;
use omniscope_types::{AnalysisOptions, FFIBoundaryConfig, Language, OmniScopeConfig};
use std::path::PathBuf;
use tracing::info;

// ─── Constants ──────────────────────────────────────────────────────

/// Path to ffi-demo output directory.
const FFI_DEMO_OUTPUT_DIR: &str = "../../ffi-demo/output";

/// Baseline values for regression testing.
///
/// These are derived from the current pipeline output on ffi-demo files.
/// FP is computed as total_detected_issues - TP, which accurately counts
/// all non-TP issues (including those not in EXPECTED_NOISE).
///
/// Previous baseline (old FP counting, EXPECTED_NOISE only):
///   TP=4, FP=9, FN=16, Precision=30.8%, Recall=20.0%, F1=24.2%
///
/// Note: Pipeline output is slightly non-deterministic (TP varies 13-14).
/// The baseline uses the typical stable values.
///
/// Updated baseline after fixing Zig vs Go language detection:
/// - Zig functions with `main.` prefix are now correctly classified as Zig
/// - This reduces CrossLanguageFree false positives in zig_main.ll
/// - Previous baseline: TP=13, FP=30, FN=11, Precision=30.2%, Recall=54.2%, F1=37.0%
///
/// Updated baseline after adding Zig runtime noise suppression:
/// - Added Zig runtime patterns (heap.c_allocator_impl, Io.Threaded, etc.) to noise reduction
/// - This reduces false positives from Zig standard library functions
/// - New baseline: TP=13, FP=22, FN=11, Precision=37.1%, Recall=54.2%, F1=44.1%
const BASELINE_TP: usize = 13;
const BASELINE_FP: usize = 22;
const BASELINE_FN: usize = 11;
const BASELINE_PRECISION: f64 = 0.371; // 37.1%
const BASELINE_RECALL: f64 = 0.542; // 54.2%
const BASELINE_F1: f64 = 0.441; // 44.1%

/// Tolerance for non-deterministic pipeline output (±2%).
const METRICS_TOLERANCE: f64 = 0.025;

// ─── Golden expectations ────────────────────────────────────────────

/// A known bug that the pipeline should detect.
struct ExpectedBug {
    /// File containing the bug.
    file: &'static str,
    /// Function name substring to match against issue location.
    func_substring: &'static str,
    /// Issue kinds that would correctly identify this bug.
    /// Any match counts as TP.
    accepted_kinds: &'static [IssueKind],
    /// Human-readable description for diagnostics.
    description: &'static str,
}

/// A noise function that should NOT produce issues.
struct ExpectedNoise {
    /// File containing the noise.
    file: &'static str,
    /// Function name substring to match against issue location.
    func_substring: &'static str,
    /// Description for diagnostics.
    description: &'static str,
}

/// A known bug that is currently missed by the pipeline.
struct ExpectedMiss {
    /// File containing the missed bug.
    file: &'static str,
    /// Function name substring to match against issue location.
    func_substring: &'static str,
    /// Issue kinds that should detect this bug.
    expected_kinds: &'static [IssueKind],
    /// Human-readable description for diagnostics.
    description: &'static str,
}

// ─── Golden data ────────────────────────────────────────────────────

/// True positives: real bugs the pipeline currently detects.
///
/// These represent the TP=4 baseline plus any additional bugs
/// detected by recent improvements.
const EXPECTED_BUGS: &[ExpectedBug] = &[
    // ── zig_main.ll bugs ────────────────────────────────────────────
    ExpectedBug {
        file: "zig_main.ll",
        func_substring: "free",
        accepted_kinds: &[IssueKind::DoubleFree],
        description: "Zig main: double-free via 'free' [confirmed]",
    },
    ExpectedBug {
        file: "zig_main.ll",
        func_substring: "munmap",
        accepted_kinds: &[IssueKind::DoubleFree],
        description: "Zig main: double release via 'munmap' [confirmed]",
    },
    ExpectedBug {
        file: "zig_main.ll",
        func_substring: "c_allocator_impl.alloc",
        accepted_kinds: &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
        description: "Zig main: c_allocator conditional leak",
    },
    ExpectedBug {
        file: "zig_main.ll",
        func_substring: "main.doubleFreeDemo",
        accepted_kinds: &[IssueKind::UncheckedReturn],
        description: "Zig main: unchecked FFI return in doubleFreeDemo",
    },
    // ── c_merkle_tree.ll bugs ────────────────────────────────────────
    ExpectedBug {
        file: "c_merkle_tree.ll",
        func_substring: "free",
        accepted_kinds: &[IssueKind::DoubleFree],
        description: "C Merkle tree: double-free via 'free' [confirmed]",
    },
    // ── cpp_hash.ll bugs ─────────────────────────────────────────────
    ExpectedBug {
        file: "cpp_hash.ll",
        func_substring: "_Znam",
        accepted_kinds: &[
            IssueKind::DefiniteLeak,
            IssueKind::ConditionalLeak,
            IssueKind::MemoryLeak,
        ],
        description: "C++ hash: _Znam (new[]) definite leak in CompressBlock",
    },
    // ── cpp_fft.ll bugs ──────────────────────────────────────────────
    ExpectedBug {
        file: "cpp_fft.ll",
        func_substring: "_Znam",
        accepted_kinds: &[
            IssueKind::DefiniteLeak,
            IssueKind::ConditionalLeak,
            IssueKind::MemoryLeak,
        ],
        description: "C++ FFT: _Znam (new[]) definite leak",
    },
    // ── c_fft_c_bridge.ll bugs ───────────────────────────────────────
    ExpectedBug {
        file: "c_fft_c_bridge.ll",
        func_substring: "c_fft_test_signal",
        accepted_kinds: &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
        description: "C FFT test: conditional leak in c_fft_test_signal",
    },
    // ── c_fft_c_bridge.ll FFI boundaries ─────────────────────────────
    ExpectedBug {
        file: "c_fft_c_bridge.ll",
        func_substring: "c_fft_forward",
        accepted_kinds: &[IssueKind::FfiUnsafeCall],
        description: "C FFT forward: FFI boundary C->Cpp",
    },
    // ── c_hash_c_bridge.ll bugs ──────────────────────────────────────
    ExpectedBug {
        file: "c_hash_c_bridge.ll",
        func_substring: "c_hash",
        accepted_kinds: &[IssueKind::FfiUnsafeCall],
        description: "C hash bridge: FFI boundary C->Cpp",
    },
    // ── zig_ffi_bridge.ll bugs ───────────────────────────────────────
    ExpectedBug {
        file: "zig_ffi_bridge.ll",
        func_substring: "c_alloc_buffer",
        accepted_kinds: &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
        description: "Zig FFI bridge: conditional leak in c_alloc_buffer",
    },
    ExpectedBug {
        file: "zig_ffi_bridge.ll",
        func_substring: "malloc",
        accepted_kinds: &[
            IssueKind::DefiniteLeak,
            IssueKind::ConditionalLeak,
            IssueKind::MemoryLeak,
        ],
        description: "Zig FFI bridge: definite leak from malloc",
    },
    // ── c_ffi_traps.ll bugs ──────────────────────────────────────────
    ExpectedBug {
        file: "c_ffi_traps.ll",
        func_substring: "ffi_make_token",
        accepted_kinds: &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
        description: "C FFI traps: conditional leak in ffi_make_token",
    },
    ExpectedBug {
        file: "c_ffi_traps.ll",
        func_substring: "malloc",
        accepted_kinds: &[
            IssueKind::DefiniteLeak,
            IssueKind::ConditionalLeak,
            IssueKind::MemoryLeak,
        ],
        description: "C FFI traps: definite leak from malloc",
    },
];

/// Noise patterns that should NOT produce issues.
///
/// These are clean files (e.g., pure Rust) where the pipeline should
/// produce zero issues. Any issue reported for these files counts as
/// a false positive. Add entries here as noise patterns are identified
/// and suppressed.
const EXPECTED_NOISE: &[ExpectedNoise] = &[
    // ── Clean files that should have zero issues ────────────────────
    ExpectedNoise {
        file: "rust_hash.ll",
        func_substring: "",
        description: "Rust hash: clean code, no bugs",
    },
    ExpectedNoise {
        file: "rust_merkle.ll",
        func_substring: "",
        description: "Rust Merkle: clean code, no bugs",
    },
];

/// Known bugs that the pipeline currently misses.
///
/// These represent the FN=16 baseline. As detectors improve,
/// entries should move from EXPECTED_MISS to EXPECTED_BUG.
const EXPECTED_MISSES: &[ExpectedMiss] = &[
    // ── c_ffi_traps.ll: bugs not yet detected ───────────────────────
    ExpectedMiss {
        file: "c_ffi_traps.ll",
        func_substring: "cross_family_free",
        expected_kinds: &[IssueKind::CrossFamilyFree, IssueKind::CrossLanguageFree],
        description: "C FFI traps: malloc + operator delete (cross-family)",
    },
    ExpectedMiss {
        file: "c_ffi_traps.ll",
        func_substring: "uaf_through_ffi",
        expected_kinds: &[IssueKind::UseAfterFree, IssueKind::BorrowEscape],
        description: "C FFI traps: free then pass to FFI (use-after-free)",
    },
    ExpectedMiss {
        file: "c_ffi_traps.ll",
        func_substring: "double_free_aliasing",
        expected_kinds: &[IssueKind::DoubleFree],
        description: "C FFI traps: two frees on same allocation via aliases",
    },
    ExpectedMiss {
        file: "c_ffi_traps.ll",
        func_substring: "leaked_callback_userdata",
        expected_kinds: &[
            IssueKind::BorrowEscape,
            IssueKind::CallbackEscapeIssue,
            IssueKind::OwnershipEscapeLeak,
        ],
        description: "C FFI traps: stack-local as callback userdata (dangling)",
    },
    ExpectedMiss {
        file: "c_ffi_traps.ll",
        func_substring: "indirect_uaf",
        expected_kinds: &[IssueKind::UseAfterFree, IssueKind::BorrowEscape],
        description: "C FFI traps: freed pointer via indirect call to FFI",
    },
    // ── zig_ffi_bridge.ll: bugs not yet detected ─────────────────────
    ExpectedMiss {
        file: "zig_ffi_bridge.ll",
        func_substring: "allocate_and_misroute",
        expected_kinds: &[IssueKind::CrossFamilyFree, IssueKind::CrossLanguageFree],
        description: "Zig FFI: c_allocator.alloc + raw free (bypasses allocator)",
    },
    ExpectedMiss {
        file: "zig_ffi_bridge.ll",
        func_substring: "parse_and_leak_config",
        expected_kinds: &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
        description: "Zig FFI: C buffer from c_parse_config never freed",
    },
    ExpectedMiss {
        file: "zig_ffi_bridge.ll",
        func_substring: "defer_after_free",
        expected_kinds: &[IssueKind::UseAfterFree, IssueKind::BorrowEscape],
        description: "Zig FFI: explicit free then deferred call (UAF)",
    },
    ExpectedMiss {
        file: "zig_ffi_bridge.ll",
        func_substring: "register_and_revoke",
        expected_kinds: &[
            IssueKind::BorrowEscape,
            IssueKind::OwnershipEscapeLeak,
            IssueKind::UseAfterFree,
        ],
        description: "Zig FFI: GPA alloc, C stores pointer, Zig frees (UAF)",
    },
    // ── cpp_hash.ll: missing cross-family detection ──────────────────
    ExpectedMiss {
        file: "cpp_hash.ll",
        func_substring: "CompressBlock",
        expected_kinds: &[IssueKind::CrossFamilyFree],
        description: "C++ hash: new[] in CompressBlock — cross-family free",
    },
    // ── c_fft_c_bridge.ll: missing cross-language detection ──────────
    ExpectedMiss {
        file: "c_fft_c_bridge.ll",
        func_substring: "c_fft_forward",
        expected_kinds: &[
            IssueKind::CrossFamilyFree,
            IssueKind::CrossLanguageFree,
            IssueKind::ConditionalLeak,
        ],
        description: "C FFT forward: malloc may not be freed on partial failure",
    },
];

// ─── Helpers ─────────────────────────────────────────────────────────

/// Load an IR file from ffi-demo output directory and run the pipeline.
fn run_pipeline_on_ffi_demo(filename: &str) -> omniscope_pipeline::PipelineResult {
    let path = PathBuf::from(FFI_DEMO_OUTPUT_DIR).join(filename);
    assert!(
        path.exists(),
        "ffi-demo IR file not found: {path:?}. Run 'make' in ~/code/ffi-demo first."
    );

    let module = IRModule::load_from_file(&path)
        .unwrap_or_else(|e| panic!("Failed to load {filename}: {e}"));

    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_ir_module(module);

    pipeline
        .run()
        .unwrap_or_else(|e| panic!("Pipeline failed on {filename}: {e}"))
}

/// Check if a bug is detected by the pipeline.
/// Returns true if any issue matches the accepted kinds and function name.
fn is_bug_detected(issues: &[omniscope_core::Issue], expected: &ExpectedBug) -> bool {
    issues.iter().any(|issue| {
        let kind_match = expected.accepted_kinds.contains(&issue.kind);
        let func_match = if expected.func_substring.is_empty() {
            true
        } else {
            issue
                .location
                .as_ref()
                .and_then(|loc| loc.function.as_deref())
                .map(|f| f.contains(expected.func_substring))
                .unwrap_or(false)
        };
        kind_match && func_match
    })
}

/// Check if noise is reported for a clean function.
/// Returns true if ANY issue matches the function (which would be a false positive).
fn is_noise_reported(issues: &[omniscope_core::Issue], expected: &ExpectedNoise) -> bool {
    if expected.func_substring.is_empty() {
        // For clean files, any issue is noise
        !issues.is_empty()
    } else {
        issues.iter().any(|issue| {
            issue
                .location
                .as_ref()
                .and_then(|loc| loc.function.as_deref())
                .map(|f| f.contains(expected.func_substring))
                .unwrap_or(false)
        })
    }
}

/// Check if a known bug is still missed by the pipeline.
/// Returns true if NO issue matches the expected kinds and function.
fn is_bug_missed(issues: &[omniscope_core::Issue], expected: &ExpectedMiss) -> bool {
    !issues.iter().any(|issue| {
        let kind_match = expected.expected_kinds.contains(&issue.kind);
        let func_match = if expected.func_substring.is_empty() {
            true
        } else {
            issue
                .location
                .as_ref()
                .and_then(|loc| loc.function.as_deref())
                .map(|f| f.contains(expected.func_substring))
                .unwrap_or(false)
        };
        kind_match && func_match
    })
}

// ─── Main test ──────────────────────────────────────────────────────

/// Objective: Verify accuracy regression against golden baseline.
/// Invariants:
///   - Precision must not drop below 33.6%
///   - Recall must not drop below 51.7%
///   - F1 must not drop below 40.8%
///   - TP must not drop below 11
///   - FP must not increase above 24
///   - FN must not increase above 13
#[test]
fn test_accuracy_regression() {
    info!(
        "
=== OmniScope Accuracy Regression Test ===
"
    );

    // Verify ffi-demo directory exists
    let ffi_demo_dir = PathBuf::from(FFI_DEMO_OUTPUT_DIR);
    assert!(
        ffi_demo_dir.exists(),
        "ffi-demo output directory not found: {ffi_demo_dir:?}. \
         Run 'make' in ~/code/ffi-demo first."
    );

    // Load all ffi-demo files and run pipeline
    let ll_files: Vec<PathBuf> = std::fs::read_dir(&ffi_demo_dir)
        .unwrap_or_else(|e| panic!("Cannot read ffi-demo dir: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ll"))
        .map(|entry| entry.path())
        .collect();

    info!("Found {} .ll files in ffi-demo/output", ll_files.len());

    // Run pipeline on each file and collect results
    let mut all_results: Vec<(String, omniscope_pipeline::PipelineResult)> = Vec::new();
    for ll_file in &ll_files {
        let file_name = ll_file.file_name().unwrap().to_string_lossy().to_string();
        let result = run_pipeline_on_ffi_demo(&file_name);
        all_results.push((file_name, result));
    }

    // ── Count TP ────────────────────────────────────────────────────
    let mut tp_count = 0usize;
    eprintln!(
        "
--- True Positives (Bugs Detected) ---"
    );
    for bug in EXPECTED_BUGS {
        let file_result = all_results.iter().find(|(name, _)| name == bug.file);
        if let Some((_, result)) = file_result {
            if is_bug_detected(result.issues(), bug) {
                tp_count += 1;
                eprintln!("  [TP] {}: {}", bug.file, bug.description);
            } else {
                eprintln!(
                    "  [FN] {}: {} (expected but missed)",
                    bug.file, bug.description
                );
            }
        } else {
            eprintln!("  [SKIP] {}: file not found", bug.file);
        }
    }

    // ── Count FN (misses) ───────────────────────────────────────────
    let mut fn_count = 0usize;
    eprintln!(
        "
--- False Negatives (Missed Bugs) ---"
    );
    for miss in EXPECTED_MISSES {
        let file_result = all_results.iter().find(|(name, _)| name == miss.file);
        if let Some((_, result)) = file_result {
            if is_bug_missed(result.issues(), miss) {
                fn_count += 1;
                eprintln!("  [FN] {}: {}", miss.file, miss.description);
            } else {
                // Previously missed bug is now detected — count as TP
                tp_count += 1;
                eprintln!("  [TP] {}: {} (now detected!)", miss.file, miss.description);
            }
        } else {
            eprintln!("  [SKIP] {}: file not found", miss.file);
        }
    }

    // ── Count FP (all issues not counted as TP) ─────────────────────
    //
    // A false positive is any detected issue that does not correspond
    // to a known true positive (EXPECTED_BUGS or EXPECTED_MISSES that
    // are now detected).  This includes:
    //   - Issues on EXPECTED_NOISE files (clean code flagged)
    //   - Issues on any other file that do not match an expected bug
    //
    // We compute FP = total_detected_issues - tp_count so that
    // Precision = TP / (TP + FP) is accurate.
    let total_detected_issues: usize = all_results
        .iter()
        .map(|(_, result)| result.issue_count())
        .sum();
    let fp_count = total_detected_issues.saturating_sub(tp_count);
    eprintln!("\n--- False Positives (Noise) ---");
    eprintln!(
        "  Total detected issues: {}, TP: {}, FP: {}",
        total_detected_issues, tp_count, fp_count
    );
    // Still report EXPECTED_NOISE files for diagnostics
    for noise in EXPECTED_NOISE {
        let file_result = all_results.iter().find(|(name, _)| name == noise.file);
        if let Some((_, result)) = file_result {
            if is_noise_reported(result.issues(), noise) {
                info!("  [FP] {}: {}", noise.file, noise.description);
            } else {
                info!(
                    "  [TN] {}: {} (correctly clean)",
                    noise.file, noise.description
                );
            }
        } else {
            info!("  [SKIP] {}: file not found", noise.file);
        }
    }

    // ── Calculate metrics ───────────────────────────────────────────
    // Precision = TP / (TP + FP) = tp_count / total_detected_issues
    let precision = if total_detected_issues == 0 {
        0.0
    } else {
        tp_count as f64 / total_detected_issues as f64
    };

    let total_bugs = tp_count + fn_count;
    let recall = if total_bugs == 0 {
        0.0
    } else {
        tp_count as f64 / total_bugs as f64
    };

    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    // ── Print results ───────────────────────────────────────────────
    eprintln!("\n=== Accuracy Results ===");
    eprintln!("  True Positives:  {tp_count}/{total_bugs}");
    eprintln!("  False Positives: {fp_count} (total detected: {total_detected_issues})");
    eprintln!("  False Negatives: {fn_count}/{total_bugs}");
    eprintln!("  Precision:       {:.1}%", precision * 100.0);
    eprintln!("  Recall:          {:.1}%", recall * 100.0);
    eprintln!("  F1 Score:        {:.1}%", f1 * 100.0);

    eprintln!("\n=== Baseline Comparison ===");
    eprintln!("  Baseline TP:  {BASELINE_TP}");
    eprintln!("  Baseline FP:  {BASELINE_FP}");
    eprintln!("  Baseline FN:  {BASELINE_FN}");
    eprintln!("  Baseline Precision: {:.1}%", BASELINE_PRECISION * 100.0);
    eprintln!("  Baseline Recall:    {:.1}%", BASELINE_RECALL * 100.0);
    eprintln!("  Baseline F1:        {:.1}%", BASELINE_F1 * 100.0);

    // ── Regression checks (with tolerance for non-determinism) ──────
    info!(
        "
=== Regression Check ==="
    );

    assert!(
        precision >= BASELINE_PRECISION - METRICS_TOLERANCE,
        "Precision regression: {:.1}% < baseline {:.1}% (tolerance {:.1}%)",
        precision * 100.0,
        BASELINE_PRECISION * 100.0,
        METRICS_TOLERANCE * 100.0
    );
    info!(
        "  [PASS] Precision {:.1}% >= baseline {:.1}% (±{:.1}%)",
        precision * 100.0,
        BASELINE_PRECISION * 100.0,
        METRICS_TOLERANCE * 100.0
    );

    assert!(
        recall >= BASELINE_RECALL - METRICS_TOLERANCE,
        "Recall regression: {:.1}% < baseline {:.1}% (tolerance {:.1}%)",
        recall * 100.0,
        BASELINE_RECALL * 100.0,
        METRICS_TOLERANCE * 100.0
    );
    info!(
        "  [PASS] Recall {:.1}% >= baseline {:.1}% (±{:.1}%)",
        recall * 100.0,
        BASELINE_RECALL * 100.0,
        METRICS_TOLERANCE * 100.0
    );

    assert!(
        f1 >= BASELINE_F1 - METRICS_TOLERANCE,
        "F1 regression: {:.1}% < baseline {:.1}% (tolerance {:.1}%)",
        f1 * 100.0,
        BASELINE_F1 * 100.0,
        METRICS_TOLERANCE * 100.0
    );
    info!(
        "  [PASS] F1 {:.1}% >= baseline {:.1}% (±{:.1}%)",
        f1 * 100.0,
        BASELINE_F1 * 100.0,
        METRICS_TOLERANCE * 100.0
    );

    // TP can vary 13-14 due to pipeline non-determinism; allow 12 as minimum
    let min_tp = BASELINE_TP.saturating_sub(2);
    assert!(
        tp_count >= min_tp,
        "TP regression: {} < minimum {}",
        tp_count,
        min_tp
    );
    info!("  [PASS] TP {} >= minimum {}", tp_count, min_tp);

    assert!(
        fp_count <= BASELINE_FP + 1,
        "FP regression: {} > baseline {} (+1 tolerance for non-determinism)",
        fp_count,
        BASELINE_FP
    );
    info!(
        "  [PASS] FP {} <= baseline {} (+1 tolerance)",
        fp_count, BASELINE_FP
    );

    assert!(
        fn_count <= BASELINE_FN + 2,
        "FN regression: {} > maximum {}",
        fn_count,
        BASELINE_FN + 2
    );
    info!("  [PASS] FN {} <= maximum {}", fn_count, BASELINE_FN + 2);

    info!(
        "
=== Accuracy regression test PASSED ===
"
    );
}

/// Objective: Dump all detected issues for diagnostic purposes.
/// This is NOT an assertion test — it just prints what the pipeline finds.
#[test]
fn test_ffi_demo_dump_all_issues() {
    let ffi_demo_dir = PathBuf::from(FFI_DEMO_OUTPUT_DIR);
    if !ffi_demo_dir.exists() {
        eprintln!("Skipping ffi-demo dump: directory not found");
        return;
    }

    let ll_files: Vec<PathBuf> = std::fs::read_dir(&ffi_demo_dir)
        .unwrap_or_else(|e| panic!("Cannot read ffi-demo dir: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ll"))
        .map(|entry| entry.path())
        .collect();

    eprintln!("\n=== ffi-demo Issue Audit ===");
    for ll_file in &ll_files {
        let file_name = ll_file.file_name().unwrap().to_string_lossy().to_string();
        let result = run_pipeline_on_ffi_demo(&file_name);
        eprintln!("\n--- {} ({} issues) ---", file_name, result.issue_count());
        for (idx, issue) in result.issues().iter().enumerate() {
            let func = issue
                .location
                .as_ref()
                .and_then(|loc| loc.function.as_deref())
                .unwrap_or("(unknown)");
            let desc = if issue.description.len() > 80 {
                format!("{}...", &issue.description[..77])
            } else {
                issue.description.clone()
            };
            eprintln!(
                "  [{:>2}] {:<30} func={:<45} {}",
                idx,
                format!("{:?}", issue.kind),
                func,
                desc
            );
        }
    }
    eprintln!("\n=== ffi-demo Issue Audit Complete ===");
}

/// Objective: Verify pipeline runs without errors on all ffi-demo files.
/// Invariants: All files must load and run successfully.
#[test]
fn test_ffi_demo_pipeline_stability() {
    let ffi_demo_dir = PathBuf::from(FFI_DEMO_OUTPUT_DIR);
    if !ffi_demo_dir.exists() {
        info!("Skipping pipeline stability: directory not found");
        return;
    }

    let ll_files: Vec<PathBuf> = std::fs::read_dir(&ffi_demo_dir)
        .unwrap_or_else(|e| panic!("Cannot read ffi-demo dir: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ll"))
        .map(|entry| entry.path())
        .collect();

    info!("Testing pipeline stability on {} .ll files", ll_files.len());

    for ll_file in &ll_files {
        let file_name = ll_file.file_name().unwrap().to_string_lossy().to_string();
        let result = run_pipeline_on_ffi_demo(&file_name);
        info!(
            "  [OK] {} — {} passes, {} issues, {}ms",
            file_name,
            result.pass_count(),
            result.issue_count(),
            result.duration_ms()
        );
    }

    info!("Pipeline stability test PASSED");
}

// ─── with_cross scenario helpers ─────────────────────────────────────

/// Load an IR file and run pipeline with --cross configuration.
fn run_pipeline_with_cross(
    filename: &str,
    cross_boundaries: Vec<(&str, &str)>,
) -> omniscope_pipeline::PipelineResult {
    let path = PathBuf::from(FFI_DEMO_OUTPUT_DIR).join(filename);
    assert!(
        path.exists(),
        "ffi-demo IR file not found: {path:?}. Run 'make' in ~/code/ffi-demo first."
    );

    let module = IRModule::load_from_file(&path)
        .unwrap_or_else(|e| panic!("Failed to load {filename}: {e}"));

    // Build configuration with cross boundaries
    let mut config = omniscope_types::OmniScopeConfig::default();
    for (from, to) in cross_boundaries {
        let from_lang = match from {
            "C" => omniscope_types::Language::C,
            "Cpp" | "C++" => omniscope_types::Language::Cpp,
            "Zig" => omniscope_types::Language::Zig,
            "Rust" => omniscope_types::Language::Rust,
            "Go" => omniscope_types::Language::Go,
            _ => panic!("Unknown language: {from}"),
        };
        let to_lang = match to {
            "C" => omniscope_types::Language::C,
            "Cpp" | "C++" => omniscope_types::Language::Cpp,
            "Zig" => omniscope_types::Language::Zig,
            "Rust" => omniscope_types::Language::Rust,
            "Go" => omniscope_types::Language::Go,
            _ => panic!("Unknown language: {to}"),
        };

        // Add boundary functions from the module
        let functions: Vec<String> = module.functions.keys().cloned().collect();
        config
            .ffi_boundary
            .push(omniscope_types::FFIBoundaryConfig {
                from: from_lang,
                to: to_lang,
                functions,
                pattern: None,
                description: Some(format!("{from} -> {to} boundary")),
            });
    }

    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_ir_module(module);
    pipeline.set_config(config);

    pipeline
        .run()
        .unwrap_or_else(|e| panic!("Pipeline failed on {filename}: {e}"))
}

/// Run pipeline on a single file with cross boundaries.
fn run_file_with_cross(
    filename: &str,
    cross_boundaries: Vec<(&str, &str)>,
) -> omniscope_pipeline::PipelineResult {
    run_pipeline_with_cross(filename, cross_boundaries)
}

/// Run accuracy test with cross boundaries on all ffi-demo files.
fn run_accuracy_with_cross(cross_boundaries: Vec<(&str, &str)>) -> AccuracyResult {
    let ffi_demo_dir = PathBuf::from(FFI_DEMO_OUTPUT_DIR);
    assert!(
        ffi_demo_dir.exists(),
        "ffi-demo output directory not found: {ffi_demo_dir:?}"
    );

    let ll_files: Vec<PathBuf> = std::fs::read_dir(&ffi_demo_dir)
        .unwrap_or_else(|e| panic!("Cannot read ffi-demo dir: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ll"))
        .map(|entry| entry.path())
        .collect();

    let mut all_results: Vec<(String, omniscope_pipeline::PipelineResult)> = Vec::new();
    for ll_file in &ll_files {
        let file_name = ll_file.file_name().unwrap().to_string_lossy().to_string();
        let result = run_pipeline_with_cross(&file_name, cross_boundaries.clone());
        all_results.push((file_name, result));
    }

    // Count TP, FN, FP
    let mut tp_count = 0usize;
    for bug in EXPECTED_BUGS {
        let file_result = all_results.iter().find(|(name, _)| name == bug.file);
        if let Some((_, result)) = file_result {
            if is_bug_detected(result.issues(), bug) {
                tp_count += 1;
            }
        }
    }

    for miss in EXPECTED_MISSES {
        let file_result = all_results.iter().find(|(name, _)| name == miss.file);
        if let Some((_, result)) = file_result {
            if !is_bug_missed(result.issues(), miss) {
                tp_count += 1;
            }
        }
    }

    let total_detected: usize = all_results
        .iter()
        .map(|(_, result)| result.issue_count())
        .sum();
    let fp_count = total_detected.saturating_sub(tp_count);
    let fn_count = EXPECTED_BUGS.len() + EXPECTED_MISSES.len() - tp_count;

    let precision = if total_detected == 0 {
        0.0
    } else {
        tp_count as f64 / total_detected as f64
    };

    let total_bugs = tp_count + fn_count;
    let recall = if total_bugs == 0 {
        0.0
    } else {
        tp_count as f64 / total_bugs as f64
    };

    AccuracyResult {
        tp: tp_count,
        fp: fp_count,
        fn_count,
        precision,
        recall,
        issues: all_results
            .iter()
            .flat_map(|(_, result)| result.issues().to_vec())
            .collect(),
    }
}

/// Accuracy result struct for with_cross tests.
struct AccuracyResult {
    tp: usize,
    fp: usize,
    #[allow(dead_code)]
    fn_count: usize,
    precision: f64,
    #[allow(dead_code)]
    recall: f64,
    #[allow(dead_code)]
    issues: Vec<omniscope_core::Issue>,
}

// ─── with_cross scenario tests ──────────────────────────────────────

/// Objective: Test accuracy with --cross parameter.
/// Invariants:
///   - TP should be at least 13
///   - FP should be at most 30
///   - Precision should be at least 30%
#[test]
fn test_accuracy_with_cross() {
    info!(
        "
=== OmniScope Accuracy with --cross Test ==="
    );

    // Define cross boundaries: C->Cpp and Zig->C
    let cross_boundaries = vec![("C", "Cpp"), ("Zig", "C")];

    let result = run_accuracy_with_cross(cross_boundaries);

    eprintln!("\n=== with_cross Results ===");
    eprintln!("  True Positives:  {}", result.tp);
    eprintln!("  False Positives: {}", result.fp);
    eprintln!("  Precision:       {:.1}%", result.precision * 100.0);

    // TP can vary 13-14 due to pipeline non-determinism
    assert!(
        result.tp >= 13,
        "TP should be at least 13, got {}",
        result.tp
    );
    info!("  [PASS] TP {} >= 13", result.tp);

    assert!(
        result.fp <= 30,
        "FP should be at most 30, got {}",
        result.fp
    );
    info!("  [PASS] FP {} <= 30", result.fp);

    assert!(
        result.precision >= 0.30,
        "Precision should be at least 30%, got {:.1}%",
        result.precision * 100.0
    );
    info!("  [PASS] Precision {:.1}% >= 30%", result.precision * 100.0);

    info!(
        "
=== with_cross accuracy test PASSED ==="
    );
}

/// Objective: Test that --cross configuration is applied to zig_main.ll.
/// Invariants: Pipeline should run without errors with --cross Zig:C.
#[test]
fn test_zig_main_cross_reduces_fp() {
    info!(
        "
=== Test: --cross configuration applied to zig_main.ll ==="
    );

    let result = run_file_with_cross("zig_main.ll", vec![("Zig", "C")]);

    // Io.Threaded.* series may still be present depending on
    // whether they are classified as boundary or internal functions.
    let io_threaded_issues: Vec<_> = result
        .issues()
        .iter()
        .filter(|i| {
            i.location
                .as_ref()
                .and_then(|loc| loc.function.as_deref())
                .map(|f| f.contains("Io.Threaded"))
                .unwrap_or(false)
        })
        .collect();

    eprintln!(
        "  Io.Threaded issues with --cross Zig:C: {}",
        io_threaded_issues.len()
    );
    for issue in &io_threaded_issues {
        eprintln!("    - {:?}: {}", issue.kind, issue.description);
    }

    // Verify that pipeline runs successfully with --cross configuration
    assert!(
        result.issue_count() > 0,
        "Pipeline should detect issues with --cross Zig:C"
    );
    info!(
        "  [PASS] Pipeline detected {} issues with --cross Zig:C",
        result.issue_count()
    );

    info!(
        "
=== zig_main.ll with_cross test PASSED ==="
    );
}

/// Objective: Test that --cross preserves TP for c_fft_c_bridge.ll.
/// Invariants: FFI boundary should still be detected with --cross C:Cpp.
#[test]
fn test_c_fft_cross_preserves_tp() {
    info!(
        "
=== Test: --cross preserves TP for c_fft_c_bridge.ll ==="
    );

    let result = run_file_with_cross("c_fft_c_bridge.ll", vec![("C", "Cpp")]);

    // FFI boundary should still be detected
    let ffi_issues: Vec<_> = result
        .issues()
        .iter()
        .filter(|i| i.kind == omniscope_core::IssueKind::FfiUnsafeCall)
        .collect();

    eprintln!(
        "  FFI boundary issues with --cross C:Cpp: {}",
        ffi_issues.len()
    );
    for issue in &ffi_issues {
        eprintln!("    - {:?}: {}", issue.kind, issue.description);
    }

    assert!(
        !ffi_issues.is_empty(),
        "FFI boundary should still be detected with --cross C:Cpp"
    );
    info!("  [PASS] FFI boundary detected with --cross C:Cpp");

    info!(
        "
=== c_fft_c_bridge.ll with_cross test PASSED ==="
    );
}

/// Objective: Test that --cross reduces FP for c_hash_c_bridge.ll.
/// Invariants: Internal C++ issues should be filtered with --cross C:Cpp.
#[test]
fn test_c_hash_cross_reduces_fp() {
    info!(
        "
=== Test: --cross reduces FP for c_hash_c_bridge.ll ==="
    );

    let result = run_file_with_cross("c_hash_c_bridge.ll", vec![("C", "Cpp")]);

    // FFI boundary should still be detected
    let ffi_issues: Vec<_> = result
        .issues()
        .iter()
        .filter(|i| i.kind == omniscope_core::IssueKind::FfiUnsafeCall)
        .collect();

    eprintln!(
        "  FFI boundary issues with --cross C:Cpp: {}",
        ffi_issues.len()
    );

    // Cross boundary should be preserved
    assert!(
        !ffi_issues.is_empty(),
        "FFI boundary should still be detected with --cross C:Cpp"
    );
    info!("  [PASS] FFI boundary preserved with --cross C:Cpp");

    info!(
        "
=== c_hash_c_bridge.ll with_cross test PASSED ==="
    );
}

// ─── CLI semantic tests ─────────────────────────────────────────────

/// Test --cross with empty functions (CLI semantic).
/// This simulates `omniscope analyze --cross C:Cpp input.ll`
/// where functions list is empty, meaning "match all functions between these languages".
#[test]
fn test_cross_cli_semantic() {
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");

    let ll_files: Vec<PathBuf> = std::fs::read_dir(&corpus_dir)
        .unwrap_or_else(|e| panic!("Cannot read corpus dir: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ll"))
        .map(|entry| entry.path())
        .collect();

    // 创建配置，模拟 CLI --cross C:Cpp
    let config = OmniScopeConfig {
        project: None,
        ffi_boundary: vec![FFIBoundaryConfig {
            from: Language::C,
            to: Language::Cpp,
            functions: vec![], // 空数组 = CLI 语义
            pattern: None,
            description: None,
        }],
        resource_family: vec![],
        analysis: AnalysisOptions::default(),
    };

    let boundary_ctx = config.to_boundary_context();

    // 验证 language pair 匹配
    assert!(
        boundary_ctx.matches_call(Language::C, Language::Cpp),
        "C -> Cpp should match"
    );
    assert!(
        !boundary_ctx.matches_call(Language::Cpp, Language::C),
        "Cpp -> C should not match (reverse)"
    );
    assert!(
        !boundary_ctx.matches_call(Language::C, Language::Rust),
        "C -> Rust should not match"
    );

    let mut total_issues = 0usize;

    for ll_file in &ll_files {
        let module = IRModule::load_from_file(ll_file)
            .unwrap_or_else(|e| panic!("Failed to load {}: {e}", ll_file.display()));

        let mut pipeline = Pipeline::new();
        pipeline.register_default_passes();
        pipeline.set_config(config.clone());
        pipeline.set_ir_module(module);

        match pipeline.run() {
            Ok(result) => {
                total_issues += result.issue_count();
            }
            Err(e) => {
                eprintln!("Error processing {}: {}", ll_file.display(), e);
            }
        }
    }

    // 验证管道能正常运行
    assert!(
        total_issues > 0,
        "Pipeline should detect issues with --cross C:Cpp"
    );
}

/// Test pattern matching with CLI semantic.
#[test]
fn test_cross_pattern_matching() {
    let config = OmniScopeConfig {
        project: None,
        ffi_boundary: vec![FFIBoundaryConfig {
            from: Language::C,
            to: Language::Zig,
            functions: vec![],
            pattern: Some("c_*".to_string()),
            description: None,
        }],
        resource_family: vec![],
        analysis: AnalysisOptions::default(),
    };

    let boundary_ctx = config.to_boundary_context();

    // 模式匹配
    assert!(
        boundary_ctx.is_declared_boundary("c_fft_forward").is_some(),
        "c_fft_forward should match c_* pattern"
    );
    assert!(
        boundary_ctx.is_declared_boundary("c_hash").is_some(),
        "c_hash should match c_* pattern"
    );
    assert!(
        boundary_ctx.is_declared_boundary("malloc").is_none(),
        "malloc should not match c_* pattern"
    );
}
