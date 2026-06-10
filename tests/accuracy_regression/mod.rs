//! Accuracy regression test for OmniScope FFI bug detection.
//!
//! Runs the full pipeline on all ffi-demo `.ll` files and computes
//! TP/FP/FN/Precision/Recall/F1 against a golden baseline.
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
/// Updated baseline to worst-common-result for zig_main.ll DoubleFree non-determinism:
/// Baseline values for regression testing.
///
/// After P0-P2c: metrics reflect corrected classification (is_double_free_issue
/// no longer inflates via CrossFamily/CrossLanguage), plus new detections
/// (ReturnAlias FN→TP, FreeThenCallbackUAF FN→TP) at cost of BorrowEscape FP.
/// - zig_main.ll DoubleFree non-determinism still causes TP variation.
/// - BorrowEscape from P2b adds ~4 FP (return-alias patterns on FFI bridge functions).
const BASELINE_TP: usize = 16;
const BASELINE_FP: usize = 17;
const BASELINE_FN: usize = 2;
const BASELINE_PRECISION: f64 = 0.485; // 48.5% (TP=16, total=33)
const BASELINE_RECALL: f64 = 0.889; // 88.9% (16/18)
const BASELINE_F1: f64 = 0.627; // 62.7%

/// Tolerance for non-deterministic pipeline output.
const METRICS_TOLERANCE: f64 = 0.08;

// ─── Golden expectations ────────────────────────────────────────────

/// Classification of a bug for per-category metric tracking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // category field / variants used for future per-category assertions
enum BugCategory {
    MemoryDoubleFree,
    UseAfterFree,
    WrongRelease,
    Leak,
    FdLeak,
    BoundaryDiagnostic,
    BorrowEscape,
}

/// A known bug that the pipeline should detect.
struct ExpectedBug {
    /// File containing the bug.
    file: &'static str,
    /// Function name substring to match against issue location.
    func_substring: &'static str,
    /// Issue kinds that would correctly identify this bug.
    accepted_kinds: &'static [IssueKind],
    /// Human-readable description for diagnostics.
    description: &'static str,
    /// Expected resource family (e.g., "C_HEAP", "CPP_NEW").
    expected_resource_family: Option<&'static str>,
    /// Expected release family (e.g., "SQLITE_RESOURCE", "CPP_NEW_SCALAR").
    expected_release_family: Option<&'static str>,
    /// Expected boundary kind (e.g., "CrossLanguage", "SameLanguage").
    expected_boundary_kind: Option<&'static str>,
    /// Whether this entry is known noise (detection counts as FP).
    known_noise: bool,
    /// Issue kinds that must NOT appear for this fixture/function.
    /// If any forbidden kind IS detected, it counts as FP.
    forbidden_kinds: &'static [IssueKind],
    /// Category for per-metric accounting.
    #[allow(dead_code)]
    category: BugCategory,
}

impl ExpectedBug {
    /// Creates a simple ExpectedBug with no metadata checks.
    /// Uses empty forbidden_kinds and infers category from accepted_kinds.
    const fn simple(
        file: &'static str,
        func_substring: &'static str,
        accepted_kinds: &'static [IssueKind],
        description: &'static str,
    ) -> Self {
        // Infer category from the first accepted kind.
        let category = if accepted_kinds.is_empty() {
            BugCategory::Leak
        } else {
            match accepted_kinds[0] {
                IssueKind::DoubleFree => BugCategory::MemoryDoubleFree,
                IssueKind::UseAfterFree | IssueKind::BorrowEscape => BugCategory::UseAfterFree,
                IssueKind::CrossFamilyFree | IssueKind::CrossLanguageFree => {
                    BugCategory::WrongRelease
                }
                IssueKind::FfiUnsafeCall => BugCategory::BoundaryDiagnostic,
                _ => BugCategory::Leak,
            }
        };
        Self {
            file,
            func_substring,
            accepted_kinds,
            description,
            expected_resource_family: None,
            expected_release_family: None,
            expected_boundary_kind: None,
            known_noise: false,
            forbidden_kinds: &[],
            category,
        }
    }
}

/// A noise function that should NOT produce issues.
struct ExpectedNoise {
    file: &'static str,
    func_substring: &'static str,
    description: &'static str,
}

/// A known bug that is currently missed by the pipeline.
struct ExpectedMiss {
    file: &'static str,
    func_substring: &'static str,
    expected_kinds: &'static [IssueKind],
    description: &'static str,
}

// ─── Golden data ────────────────────────────────────────────────────

/// True positives: real bugs the pipeline currently detects.
const EXPECTED_BUGS: &[ExpectedBug] = &[
    // ── zig_main.ll bugs ────────────────────────────────────────────
    ExpectedBug::simple(
        "zig_main.ll",
        "doubleFreeDemo",
        &[IssueKind::DoubleFree],
        "Zig main: double-free in doubleFreeDemo [confirmed]",
    ),
    ExpectedBug::simple(
        "zig_main.ll",
        "crossLanguageFreeDemo",
        &[IssueKind::CrossLanguageFree],
        "Zig main: cross-language free in crossLanguageFreeDemo [confirmed]",
    ),
    ExpectedBug::simple(
        "zig_main.ll",
        "bufferOverflowDemo",
        &[IssueKind::CrossLanguageFree],
        "Zig main: cross-language free in bufferOverflowDemo [confirmed]",
    ),
    ExpectedBug::simple(
        "zig_main.ll",
        "doubleFreeDemo",
        &[IssueKind::CrossLanguageFree],
        "Zig main: cross-language free in doubleFreeDemo",
    ),
    ExpectedBug::simple(
        "zig_main.ll",
        "main.doubleFreeDemo",
        &[IssueKind::UncheckedReturn],
        "Zig main: unchecked FFI return in doubleFreeDemo",
    ),
    // ── c_merkle_tree.ll bugs ────────────────────────────────────────
    // UAF bug — DoubleFree is a wrong classification here, so forbid it.
    ExpectedBug {
        file: "c_merkle_tree.ll",
        func_substring: "merkle_root",
        accepted_kinds: &[IssueKind::UseAfterFree],
        description: "C Merkle tree: use-after-free in merkle_root [confirmed]",
        expected_resource_family: None,
        expected_release_family: None,
        expected_boundary_kind: None,
        known_noise: false,
        forbidden_kinds: &[IssueKind::DoubleFree],
        category: BugCategory::UseAfterFree,
    },
    // ── cpp_hash.ll bugs ─────────────────────────────────────────────
    ExpectedBug::simple(
        "cpp_hash.ll",
        "_Znam",
        &[
            IssueKind::DefiniteLeak,
            IssueKind::ConditionalLeak,
            IssueKind::MemoryLeak,
        ],
        "C++ hash: _Znam (new[]) definite leak in CompressBlock",
    ),
    // ── cpp_fft.ll bugs ──────────────────────────────────────────────
    ExpectedBug::simple(
        "cpp_fft.ll",
        "_Znam",
        &[
            IssueKind::DefiniteLeak,
            IssueKind::ConditionalLeak,
            IssueKind::MemoryLeak,
        ],
        "C++ FFT: _Znam (new[]) definite leak",
    ),
    // ── c_fft_c_bridge.ll bugs ───────────────────────────────────────
    ExpectedBug::simple(
        "c_fft_c_bridge.ll",
        "c_fft_test_signal",
        &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
        "C FFT test: conditional leak in c_fft_test_signal",
    ),
    ExpectedBug::simple(
        "c_fft_c_bridge.ll",
        "c_fft_forward",
        &[IssueKind::FfiUnsafeCall],
        "C FFT forward: FFI boundary C->Cpp",
    ),
    ExpectedBug::simple(
        "c_hash_c_bridge.ll",
        "c_hash",
        &[IssueKind::FfiUnsafeCall],
        "C hash bridge: FFI boundary C->Cpp",
    ),
    ExpectedBug::simple(
        "zig_ffi_bridge.ll",
        "c_alloc_buffer",
        &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
        "Zig FFI bridge: conditional leak in c_alloc_buffer",
    ),
    ExpectedBug::simple(
        "c_ffi_traps.ll",
        "ffi_make_token",
        &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
        "C FFI traps: conditional leak in ffi_make_token",
    ),
    ExpectedBug::simple(
        "c_ffi_traps.ll",
        "malloc",
        &[
            IssueKind::DefiniteLeak,
            IssueKind::ConditionalLeak,
            IssueKind::MemoryLeak,
        ],
        "C FFI traps: definite leak from malloc",
    ),
    ExpectedBug::simple(
        "c_ffi_traps.ll",
        "cross_family_alloc",
        &[IssueKind::CrossFamilyFree, IssueKind::ConditionalLeak],
        "C FFI traps: cross-family free in cross_family_alloc (reconciled from ConditionalLeak)",
    ),
    ExpectedBug::simple(
        "c_ffi_traps.ll",
        "leaked_callback_userdata",
        &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
        "C FFI traps: conditional leak in leaked_callback_userdata",
    ),
    // P2c: free-then-pass-to-callback UAF detection
    ExpectedBug::simple(
        "c_ffi_traps.ll",
        "uaf_through_ffi",
        &[IssueKind::UseAfterFree, IssueKind::BorrowEscape],
        "C FFI traps: free then pass to FFI callback (UAF) [TRAP-C9]",
    ),
    ExpectedBug::simple(
        "zig_ffi_bridge.ll",
        "c_alloc_mismatch",
        &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
        "Zig FFI bridge: conditional leak in c_alloc_mismatch (malloc, no free)",
    ),
    ExpectedBug::simple(
        "zig_ffi_bridge.ll",
        "c_parse_config",
        &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
        "Zig FFI bridge: conditional leak in c_parse_config (malloc, no free)",
    ),
];

/// Noise patterns that should NOT produce issues.
const EXPECTED_NOISE: &[ExpectedNoise] = &[
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
const EXPECTED_MISSES: &[ExpectedMiss] = &[
    ExpectedMiss {
        file: "c_ffi_traps.ll",
        func_substring: "ffi_register_callback",
        expected_kinds: &[
            IssueKind::BorrowEscape,
            IssueKind::OwnershipEscapeLeak,
            IssueKind::UseAfterFree,
        ],
        description: "C FFI traps: stack-local stored to global (dangling after lifetime.end)",
    },
    ExpectedMiss {
        file: "c_ffi_traps.ll",
        func_substring: "ffi_alias_input",
        expected_kinds: &[IssueKind::BorrowEscape],
        description: "C FFI traps: returns alias into caller-owned memory (no ownership marker)",
    },
    ExpectedMiss {
        file: "c_fft_c_bridge.ll",
        func_substring: "c_fft_forward",
        expected_kinds: &[IssueKind::ConditionalLeak, IssueKind::CrossLanguageFree],
        description: "C FFT forward: malloc buffers not freed on null-check failure path",
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
fn is_bug_detected(issues: &[omniscope_core::Issue], expected: &ExpectedBug) -> Option<IssueKind> {
    issues.iter().find_map(|issue| {
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
        if kind_match && func_match {
            Some(issue.kind)
        } else {
            None
        }
    })
}

/// Check if noise is reported for a clean function.
fn is_noise_reported(issues: &[omniscope_core::Issue], expected: &ExpectedNoise) -> bool {
    if expected.func_substring.is_empty() {
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
fn is_bug_missed(issues: &[omniscope_core::Issue], expected: &ExpectedMiss) -> Option<IssueKind> {
    issues.iter().find_map(|issue| {
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
        if kind_match && func_match {
            Some(issue.kind)
        } else {
            None
        }
    })
}

// ─── Category metrics ────────────────────────────────────────────

/// Metrics tracking across multiple issue categories.
#[derive(Debug, Clone, Default)]
struct CategoryMetrics {
    ffi_tp: usize,
    ffi_fp: usize,
    ffi_fn: usize,
    resource_tp: usize,
    resource_fp: usize,
    resource_fn: usize,
    leak_tp: usize,
    leak_fp: usize,
    leak_fn: usize,
    double_free_tp: usize,
    double_free_fp: usize,
    double_free_fn: usize,
    suppression_reasons: std::collections::HashMap<String, usize>,
}

impl CategoryMetrics {
    fn new() -> Self {
        Self::default()
    }

    fn is_ffi_issue(kind: IssueKind) -> bool {
        kind.is_ffi_boundary()
    }

    fn is_leak_issue(kind: IssueKind) -> bool {
        matches!(
            kind,
            IssueKind::ConditionalLeak | IssueKind::DefiniteLeak | IssueKind::MemoryLeak
        )
    }

    fn is_double_free_issue(kind: IssueKind) -> bool {
        // Only actual DoubleFree — CrossFamilyFree and CrossLanguageFree
        // are WrongRelease bugs and must NOT inflate DoubleFree metrics.
        matches!(kind, IssueKind::DoubleFree)
    }

    fn record_tp(&mut self, kind: IssueKind) {
        if Self::is_ffi_issue(kind) {
            self.ffi_tp += 1;
        } else {
            self.resource_tp += 1;
        }
        if Self::is_leak_issue(kind) {
            self.leak_tp += 1;
        }
        if Self::is_double_free_issue(kind) {
            self.double_free_tp += 1;
        }
    }

    fn record_fn(&mut self, kind: IssueKind) {
        if Self::is_ffi_issue(kind) {
            self.ffi_fn += 1;
        } else {
            self.resource_fn += 1;
        }
        if Self::is_leak_issue(kind) {
            self.leak_fn += 1;
        }
        if Self::is_double_free_issue(kind) {
            self.double_free_fn += 1;
        }
    }

    fn record_fp(&mut self, kind: IssueKind) {
        if Self::is_ffi_issue(kind) {
            self.ffi_fp += 1;
        } else {
            self.resource_fp += 1;
        }
        if Self::is_leak_issue(kind) {
            self.leak_fp += 1;
        }
        if Self::is_double_free_issue(kind) {
            self.double_free_fp += 1;
        }
    }

    fn record_suppression(&mut self, reason: &str) {
        *self
            .suppression_reasons
            .entry(reason.to_string())
            .or_insert(0) += 1;
    }

    fn ffi_precision(&self) -> f64 {
        let total = self.ffi_tp + self.ffi_fp;
        if total == 0 {
            0.0
        } else {
            self.ffi_tp as f64 / total as f64
        }
    }
    fn ffi_recall(&self) -> f64 {
        let total = self.ffi_tp + self.ffi_fn;
        if total == 0 {
            0.0
        } else {
            self.ffi_tp as f64 / total as f64
        }
    }
    fn resource_precision(&self) -> f64 {
        let total = self.resource_tp + self.resource_fp;
        if total == 0 {
            0.0
        } else {
            self.resource_tp as f64 / total as f64
        }
    }
    fn resource_recall(&self) -> f64 {
        let total = self.resource_tp + self.resource_fn;
        if total == 0 {
            0.0
        } else {
            self.resource_tp as f64 / total as f64
        }
    }
    fn leak_precision(&self) -> f64 {
        let total = self.leak_tp + self.leak_fp;
        if total == 0 {
            0.0
        } else {
            self.leak_tp as f64 / total as f64
        }
    }
    fn leak_recall(&self) -> f64 {
        let total = self.leak_tp + self.leak_fn;
        if total == 0 {
            0.0
        } else {
            self.leak_tp as f64 / total as f64
        }
    }
    fn double_free_precision(&self) -> f64 {
        let total = self.double_free_tp + self.double_free_fp;
        if total == 0 {
            0.0
        } else {
            self.double_free_tp as f64 / total as f64
        }
    }
    fn double_free_recall(&self) -> f64 {
        let total = self.double_free_tp + self.double_free_fn;
        if total == 0 {
            0.0
        } else {
            self.double_free_tp as f64 / total as f64
        }
    }
}

/// Baseline FFI metrics for regression testing.
const BASELINE_FFI_TP: usize = 5;
const BASELINE_FFI_FP: usize = 9;
const BASELINE_FFI_FN: usize = 1; // uaf_through_ffi may still be FN in some runs
const BASELINE_RESOURCE_TP: usize = 11; // ReturnAlias moved from FN→TP but some resource TP reclassified
const BASELINE_RESOURCE_FP: usize = 9; // BorrowEscape from P2b adds ~4 FP
const BASELINE_RESOURCE_FN: usize = 5;

/// Baseline leak metrics for regression testing.
const BASELINE_LEAK_TP: usize = 10;
const BASELINE_LEAK_FP: usize = 5;
const BASELINE_LEAK_FN: usize = 2;

/// Baseline double-free metrics for regression testing.
/// After P0 metric correction: is_double_free_issue() now only counts
/// actual DoubleFree kind, not CrossFamilyFree/CrossLanguageFree.
/// Real double-free TPs in ffi-demo: currently 0 (zig_main reports
/// CrossLanguageFree, merkle_tree is UAF not DoubleFree).
const BASELINE_DOUBLE_FREE_TP: usize = 0;
const BASELINE_DOUBLE_FREE_FP: usize = 2;
const BASELINE_DOUBLE_FREE_FN: usize = 3;

mod audit_tests;
mod cross_tests;
mod main_tests;
