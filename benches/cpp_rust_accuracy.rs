//! C++ and Rust FFI accuracy & performance benchmark.
//!
//! Measures both detection accuracy (TP/FP/FN) and per-pass timing
//! for C++ and Rust FFI bug patterns using corpus fixtures.
//!
//! Ground truth:
//!   C++ corpus (cpp_hidden_bugs.ll): 5 bugs + 2 noise
//!     BUG-CPP1: new[] + scalar delete (cross-family)
//!     BUG-CPP2: malloc + operator delete (cross-family)
//!     BUG-CPP3: new + array delete inverted (cross-family)
//!     BUG-CPP4: leak in exception path (conditional leak)
//!     BUG-CPP5: mimalloc + free (cross-family)
//!     NOISE-N1: proper new + delete (safe)
//!     NOISE-N2: proper new[] + delete[] (safe)
//!
//!   Rust corpus (rust_hidden_bugs.ll): 5 bugs + 2 noise
//!     BUG-R1: __rust_alloc leak (ownership escape leak)
//!     BUG-R2: Box::into_raw without from_raw (ownership escape leak)
//!     BUG-R3: double from_raw reclaim (double reclaim)
//!     BUG-R4: __rust_alloc + free (cross-family)
//!     BUG-R5: CString::into_raw leak (ownership escape leak)
//!     NOISE-N1: __rust_alloc + __rust_dealloc (safe)
//!     NOISE-N2: __rust_alloc_zeroed + __rust_dealloc (safe)
//!
//! Run: `cargo bench --bench cpp_rust_accuracy`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use omniscope_core::IssueKind;
use omniscope_ir::IRModule;
use omniscope_pipeline::Pipeline;

const CPP_CORPUS: &str = include_str!("../tests/corpus/cpp_hidden_bugs.ll");
const RUST_CORPUS: &str = include_str!("../tests/corpus/rust_hidden_bugs.ll");

// Also test the larger integration fixtures for performance scaling
const CPP_HASH: &str = include_str!("../tests/integration/cpp_hash.ll");
const RUST_FFI_BUGS: &str = include_str!("../tests/integration/rust_ffi_bugs.ll");
const RUST_MERKLE: &str = include_str!("../tests/integration/rust_merkle.ll");

// ========================================================================
// Accuracy measurement
// ========================================================================

/// Expected C++ bug patterns and the issue kinds that should detect them.
struct ExpectedBug {
    label: &'static str,
    /// Issue kinds that would correctly identify this bug.
    /// Multiple kinds are acceptable (e.g., CrossFamilyFree or ConditionalLeak).
    expected_kinds: &'static [IssueKind],
}

/// Noise (safe) patterns that should NOT generate issues.
struct ExpectedNoise {
    #[allow(dead_code)]
    label: &'static str,
    /// Function name substring that identifies this noise pattern.
    func_substring: &'static str,
}

const CPP_BUGS: &[ExpectedBug] = &[
    ExpectedBug {
        label: "CPP1: new[]+scalar_delete",
        expected_kinds: &[IssueKind::CrossFamilyFree, IssueKind::ConditionalLeak],
    },
    ExpectedBug {
        label: "CPP2: malloc+op_delete",
        expected_kinds: &[IssueKind::CrossFamilyFree],
    },
    ExpectedBug {
        label: "CPP3: new+array_delete",
        expected_kinds: &[IssueKind::CrossFamilyFree],
    },
    ExpectedBug {
        label: "CPP4: exception_path_leak",
        expected_kinds: &[IssueKind::ConditionalLeak, IssueKind::OwnershipEscapeLeak],
    },
    ExpectedBug {
        label: "CPP5: mimalloc+free",
        expected_kinds: &[IssueKind::CrossFamilyFree],
    },
];

const CPP_NOISE: &[ExpectedNoise] = &[
    ExpectedNoise { label: "N1: proper_new_delete", func_substring: "noise_n1" },
    ExpectedNoise { label: "N2: proper_new_array_delete_array", func_substring: "noise_n2" },
];

const RUST_BUGS: &[ExpectedBug] = &[
    ExpectedBug {
        label: "R1: __rust_alloc_leak",
        expected_kinds: &[IssueKind::OwnershipEscapeLeak, IssueKind::ConditionalLeak],
    },
    ExpectedBug {
        label: "R2: box_into_raw_leak",
        expected_kinds: &[IssueKind::OwnershipEscapeLeak, IssueKind::ConditionalLeak],
    },
    ExpectedBug {
        label: "R3: double_from_raw",
        expected_kinds: &[IssueKind::DoubleReclaim, IssueKind::DoubleFree],
    },
    ExpectedBug {
        label: "R4: __rust_alloc+free",
        expected_kinds: &[IssueKind::CrossFamilyFree],
    },
    ExpectedBug {
        label: "R5: cstring_into_raw_leak",
        expected_kinds: &[IssueKind::OwnershipEscapeLeak, IssueKind::ConditionalLeak],
    },
];

const RUST_NOISE: &[ExpectedNoise] = &[
    ExpectedNoise { label: "N1: __rust_alloc+dealloc", func_substring: "noise_n1" },
    ExpectedNoise { label: "N2: __rust_alloc_zeroed+dealloc", func_substring: "noise_n2" },
];

fn run_pipeline(ir: &str) -> omniscope_pipeline::PipelineResult {
    let module = IRModule::parse_from_text(ir);
    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_ir_module(module);
    pipeline.run().unwrap()
}

/// Check if any issue matches one of the expected kinds and optionally
/// mentions the function containing the bug.
fn bug_detected(issues: &[omniscope_core::Issue], bug: &ExpectedBug) -> bool {
    issues.iter().any(|i| bug.expected_kinds.contains(&i.kind))
}

/// Count issues that fire on noise functions (false positives).
fn count_fp_on_noise(issues: &[omniscope_core::Issue], noise: &[ExpectedNoise]) -> usize {
    let mut fp = 0;
    for n in noise {
        let is_fp = issues.iter().any(|i| {
            // Check if the issue's symbol or description mentions the noise function
            let sym_match = i.symbol.contains(n.func_substring);
            let desc_match = i.description.contains(n.func_substring);
            sym_match || desc_match
        });
        if is_fp {
            fp += 1;
        }
    }
    fp
}

/// Print an accuracy report for a given corpus.
fn print_accuracy_report(label: &str, issues: &[omniscope_core::Issue], bugs: &[ExpectedBug], noise: &[ExpectedNoise]) {
    eprintln!("\n{}", "=".repeat(60));
    eprintln!("  ACCURACY REPORT: {label}");
    eprintln!("{}", "=".repeat(60));

    let mut tp = 0;
    let mut fn_count = 0;
    for bug in bugs {
        let detected = bug_detected(issues, bug);
        if detected {
            tp += 1;
            eprintln!("  [TP] {} — detected", bug.label);
        } else {
            fn_count += 1;
            eprintln!("  [FN] {} — MISSED", bug.label);
        }
    }

    let fp = count_fp_on_noise(issues, noise);

    eprintln!("\n  Summary:");
    eprintln!("    True Positives:  {tp}/{}", bugs.len());
    eprintln!("    False Negatives: {fn_count}/{}", bugs.len());
    eprintln!("    False Positives: {fp}/{}", noise.len());

    let recall = if bugs.is_empty() { 1.0 } else { tp as f64 / bugs.len() as f64 };
    let precision = if (tp + fp) == 0 { 1.0 } else { tp as f64 / (tp + fp) as f64 };
    let f1 = if (precision + recall) == 0.0 { 0.0 } else { 2.0 * precision * recall / (precision + recall) };

    eprintln!("    Recall:    {:.1}%", recall * 100.0);
    eprintln!("    Precision: {:.1}%", precision * 100.0);
    eprintln!("    F1 Score:  {:.1}%", f1 * 100.0);

    eprintln!("\n  All issues by kind:");
    let mut kind_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for i in issues {
        *kind_counts.entry(format!("{:?}", i.kind)).or_default() += 1;
    }
    for (kind, count) in kind_counts.iter() {
        eprintln!("    {kind}: {count}");
    }
}

// ========================================================================
// Benchmark: C++ corpus accuracy + performance
// ========================================================================

fn bench_cpp_accuracy(c: &mut Criterion) {
    let mut group = c.benchmark_group("cpp_accuracy");
    group.sample_size(20);

    group.bench_function("detect_cpp_5bugs_2noise", |b| {
        b.iter(|| {
            let result = run_pipeline(CPP_CORPUS);
            black_box(result.issues().len());
            black_box(result.total_issues);
        });
    });

    group.finish();
}

// ========================================================================
// Benchmark: Rust corpus accuracy + performance
// ========================================================================

fn bench_rust_accuracy(c: &mut Criterion) {
    let mut group = c.benchmark_group("rust_accuracy");
    group.sample_size(20);

    group.bench_function("detect_rust_5bugs_2noise", |b| {
        b.iter(|| {
            let result = run_pipeline(RUST_CORPUS);
            black_box(result.issues().len());
            black_box(result.total_issues);
        });
    });

    group.finish();
}

// ========================================================================
// Benchmark: C++ scaling with fixture size
// ========================================================================

fn bench_cpp_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("cpp_scaling");
    group.sample_size(15);

    let fixtures = vec![
        ("cpp_corpus_4KB", CPP_CORPUS),
        ("cpp_hash_23KB", CPP_HASH),
    ];

    for (name, ir) in fixtures {
        let module = IRModule::parse_from_text(ir);
        let func_count = module.functions.len() + module.declarations.len();
        let call_count = module.calls.len();

        group.bench_with_input(
            BenchmarkId::new("pipeline", format!("{name}_{func_count}f_{call_count}c")),
            &module,
            |b, module| {
                b.iter(|| {
                    let mut pipeline = Pipeline::new();
                    pipeline.register_default_passes();
                    pipeline.set_ir_module(module.clone());
                    let result = pipeline.run().unwrap();
                    black_box(result.issues().len());
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: Rust scaling with fixture size
// ========================================================================

fn bench_rust_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("rust_scaling");
    group.sample_size(15);

    let fixtures = vec![
        ("rust_corpus_5KB", RUST_CORPUS),
        ("rust_ffi_bugs_30KB", RUST_FFI_BUGS),
        ("rust_merkle_44KB", RUST_MERKLE),
    ];

    for (name, ir) in fixtures {
        let module = IRModule::parse_from_text(ir);
        let func_count = module.functions.len() + module.declarations.len();
        let call_count = module.calls.len();

        group.bench_with_input(
            BenchmarkId::new("pipeline", format!("{name}_{func_count}f_{call_count}c")),
            &module,
            |b, module| {
                b.iter(|| {
                    let mut pipeline = Pipeline::new();
                    pipeline.register_default_passes();
                    pipeline.set_ir_module(module.clone());
                    let result = pipeline.run().unwrap();
                    black_box(result.issues().len());
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// One-time accuracy report (not a benchmark, but runs once to print)
// ========================================================================

fn accuracy_report(c: &mut Criterion) {
    // C++ accuracy
    let cpp_result = run_pipeline(CPP_CORPUS);
    print_accuracy_report("C++ (cpp_hidden_bugs.ll)", cpp_result.issues(), CPP_BUGS, CPP_NOISE);

    // Rust accuracy
    let rust_result = run_pipeline(RUST_CORPUS);
    print_accuracy_report("Rust (rust_hidden_bugs.ll)", rust_result.issues(), RUST_BUGS, RUST_NOISE);

    // Also report for the larger integration fixtures
    let rust_ffi_result = run_pipeline(RUST_FFI_BUGS);
    eprintln!("\n--- rust_ffi_bugs_30KB ---");
    eprintln!("  Total issues: {}", rust_ffi_result.issues().len());
    eprintln!("  Issue kinds: {:?}", rust_ffi_result.issues().iter().map(|i| format!("{:?}", i.kind)).collect::<Vec<_>>());

    let cpp_hash_result = run_pipeline(CPP_HASH);
    eprintln!("\n--- cpp_hash_23KB ---");
    eprintln!("  Total issues: {}", cpp_hash_result.issues().len());
    eprintln!("  Issue kinds: {:?}", cpp_hash_result.issues().iter().map(|i| format!("{:?}", i.kind)).collect::<Vec<_>>());

    // Dummy benchmark so criterion doesn't complain
    let mut group = c.benchmark_group("accuracy_report");
    group.bench_function("compute_and_print", |b| {
        b.iter(|| {
            let _ = run_pipeline(CPP_CORPUS);
            let _ = run_pipeline(RUST_CORPUS);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_cpp_accuracy,
    bench_rust_accuracy,
    bench_cpp_scaling,
    bench_rust_scaling,
    accuracy_report,
);
criterion_main!(benches);