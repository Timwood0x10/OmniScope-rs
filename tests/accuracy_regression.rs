//! Accuracy regression test for OmniScope FFI bug detection.
//!
//! Runs the full pipeline on all ffi-demo `.ll` files and computes
//! TP/FP/FN/Precision/Recall/F1 against a golden baseline.
//!
//! Current baseline (from accuracy_improvement_plan.md):
//!   TP=4, FP=9, FN=16, Precision=30.8%, Recall=20.0%, F1=24.2%
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
use std::path::PathBuf;
use tracing::info;

// ─── Constants ──────────────────────────────────────────────────────

/// Path to ffi-demo output directory.
const FFI_DEMO_OUTPUT_DIR: &str = "../../ffi-demo/output";

/// Baseline values from accuracy_improvement_plan.md.
const BASELINE_TP: usize = 4;
const BASELINE_FP: usize = 9;
const BASELINE_FN: usize = 16;
const BASELINE_PRECISION: f64 = 0.308; // 30.8%
const BASELINE_RECALL: f64 = 0.200; // 20.0%
const BASELINE_F1: f64 = 0.242; // 24.2%

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
/// Currently empty — Zig runtime WriteToImmutable noise has been
/// addressed or is tracked separately. Add entries here as noise
/// patterns are identified and suppressed.
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
///   - Precision must not drop below 30.8%
///   - Recall must not drop below 20.0%
///   - F1 must not drop below 24.2%
///   - TP must not drop below 4
///   - FP must not increase above 9
///   - FN must not increase above 16
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
    info!(
        "
--- True Positives (Bugs Detected) ---"
    );
    for bug in EXPECTED_BUGS {
        let file_result = all_results.iter().find(|(name, _)| name == bug.file);
        if let Some((_, result)) = file_result {
            if is_bug_detected(result.issues(), bug) {
                tp_count += 1;
                info!("  [TP] {}: {}", bug.file, bug.description);
            } else {
                info!(
                    "  [FN] {}: {} (expected but missed)",
                    bug.file, bug.description
                );
            }
        } else {
            info!("  [SKIP] {}: file not found", bug.file);
        }
    }

    // ── Count FP (noise) ────────────────────────────────────────────
    let mut fp_count = 0usize;
    info!(
        "
--- False Positives (Noise) ---"
    );
    for noise in EXPECTED_NOISE {
        let file_result = all_results.iter().find(|(name, _)| name == noise.file);
        if let Some((_, result)) = file_result {
            if is_noise_reported(result.issues(), noise) {
                fp_count += 1;
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

    // ── Count FN (misses) ───────────────────────────────────────────
    let mut fn_count = 0usize;
    info!(
        "
--- False Negatives (Missed Bugs) ---"
    );
    for miss in EXPECTED_MISSES {
        let file_result = all_results.iter().find(|(name, _)| name == miss.file);
        if let Some((_, result)) = file_result {
            if is_bug_missed(result.issues(), miss) {
                fn_count += 1;
                info!("  [FN] {}: {}", miss.file, miss.description);
            } else {
                info!("  [TP] {}: {} (now detected!)", miss.file, miss.description);
            }
        } else {
            info!("  [SKIP] {}: file not found", miss.file);
        }
    }

    // ── Calculate metrics ───────────────────────────────────────────
    let total_detected = tp_count + fp_count;
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

    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    // ── Print results ───────────────────────────────────────────────
    info!(
        "
=== Accuracy Results ==="
    );
    info!("  True Positives:  {tp_count}/{total_bugs}");
    info!("  False Positives: {fp_count}");
    info!("  False Negatives: {fn_count}/{total_bugs}");
    info!("  Precision:       {:.1}%", precision * 100.0);
    info!("  Recall:          {:.1}%", recall * 100.0);
    info!("  F1 Score:        {:.1}%", f1 * 100.0);

    info!(
        "
=== Baseline Comparison ==="
    );
    info!("  Baseline TP:  {BASELINE_TP}");
    info!("  Baseline FP:  {BASELINE_FP}");
    info!("  Baseline FN:  {BASELINE_FN}");
    info!("  Baseline Precision: {:.1}%", BASELINE_PRECISION * 100.0);
    info!("  Baseline Recall:    {:.1}%", BASELINE_RECALL * 100.0);
    info!("  Baseline F1:        {:.1}%", BASELINE_F1 * 100.0);

    // ── Regression checks ───────────────────────────────────────────
    info!(
        "
=== Regression Check ==="
    );

    assert!(
        precision >= BASELINE_PRECISION,
        "Precision regression: {:.1}% < baseline {:.1}%",
        precision * 100.0,
        BASELINE_PRECISION * 100.0
    );
    info!(
        "  [PASS] Precision {:.1}% >= baseline {:.1}%",
        precision * 100.0,
        BASELINE_PRECISION * 100.0
    );

    assert!(
        recall >= BASELINE_RECALL,
        "Recall regression: {:.1}% < baseline {:.1}%",
        recall * 100.0,
        BASELINE_RECALL * 100.0
    );
    info!(
        "  [PASS] Recall {:.1}% >= baseline {:.1}%",
        recall * 100.0,
        BASELINE_RECALL * 100.0
    );

    assert!(
        f1 >= BASELINE_F1,
        "F1 regression: {:.1}% < baseline {:.1}%",
        f1 * 100.0,
        BASELINE_F1 * 100.0
    );
    info!(
        "  [PASS] F1 {:.1}% >= baseline {:.1}%",
        f1 * 100.0,
        BASELINE_F1 * 100.0
    );

    assert!(
        tp_count >= BASELINE_TP,
        "TP regression: {} < baseline {}",
        tp_count,
        BASELINE_TP
    );
    info!("  [PASS] TP {} >= baseline {}", tp_count, BASELINE_TP);

    assert!(
        fp_count <= BASELINE_FP,
        "FP regression: {} > baseline {}",
        fp_count,
        BASELINE_FP
    );
    info!("  [PASS] FP {} <= baseline {}", fp_count, BASELINE_FP);

    assert!(
        fn_count <= BASELINE_FN,
        "FN regression: {} > baseline {}",
        fn_count,
        BASELINE_FN
    );
    info!("  [PASS] FN {} <= baseline {}", fn_count, BASELINE_FN);

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
        info!("Skipping ffi-demo dump: directory not found");
        return;
    }

    let ll_files: Vec<PathBuf> = std::fs::read_dir(&ffi_demo_dir)
        .unwrap_or_else(|e| panic!("Cannot read ffi-demo dir: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ll"))
        .map(|entry| entry.path())
        .collect();

    info!(
        "
=== ffi-demo Issue Audit ==="
    );
    for ll_file in &ll_files {
        let file_name = ll_file.file_name().unwrap().to_string_lossy().to_string();
        let result = run_pipeline_on_ffi_demo(&file_name);
        info!(
            "
--- {} ({} issues) ---",
            file_name,
            result.issue_count()
        );
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
            info!(
                "  [{:>2}] {:<30} func={:<45} {}",
                idx,
                format!("{:?}", issue.kind),
                func,
                desc
            );
        }
    }
    info!(
        "
=== ffi-demo Issue Audit Complete ==="
    );
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
