//! Benchmarks for OmniScope analysis passes.
//!
//! Measures performance of core analysis infrastructure:
//! - SemanticRegistry lookup (hot path for FFI boundary analysis)
//! - NoiseReduction suppression check
//! - SurfaceClassifier classification
//! - PrecisionMetrics computation
//! - PassContext issue collection
//!
//! Run: `cargo bench -p omniscope-pass`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use omniscope_pass::*;
use omniscope_registry::SemanticRegistry;
use omniscope_semantics::SurfaceClassifier;
use omniscope_types::config::Language;

// ========================================================================
// SemanticRegistry benchmarks
// ========================================================================

fn bench_registry_lookup(c: &mut Criterion) {
    let registry = SemanticRegistry::new();
    let functions = [
        "malloc",
        "free",
        "strcpy",
        "Py_DECREF",
        "PyObject_New",
        "PyLong_FromLong",
        "into_raw",
        "from_raw",
        "GetByteArrayElements",
        "open",
        "close",
        "system",
        "PyArg_ParseTuple",
    ];

    let mut group = c.benchmark_group("registry_lookup");
    for func in &functions {
        group.bench_with_input(BenchmarkId::new("lookup", func), func, |b, func| {
            b.iter(|| black_box(registry.lookup(black_box(func))));
        });
    }
    group.finish();
}

fn bench_registry_is_high_risk(c: &mut Criterion) {
    let registry = SemanticRegistry::new();
    let mut group = c.benchmark_group("registry_high_risk");
    group.bench_function("is_high_risk_hot_path", |b| {
        b.iter(|| {
            for name in [
                "malloc",
                "strcpy",
                "Py_DECREF",
                "system",
                "strlen",
                "my_func",
                "PyObject_New",
            ] {
                black_box(registry.is_high_risk(black_box(name)));
            }
        });
    });
    group.finish();
}

// ========================================================================
// NoiseReduction benchmarks
// ========================================================================

fn bench_noise_reduction(c: &mut Criterion) {
    let nr = NoiseReduction::new();
    let names = [
        "drop_in_place<MyStruct>",
        "__rust_alloc",
        "llvm.memcpy.p0i8.p0i8.i64",
        "__cxa_throw",
        "__stack_chk_fail",
        "malloc",
        "my_c_function",
        "Py_DECREF",
    ];

    let mut group = c.benchmark_group("noise_reduction");
    for name in &names {
        group.bench_with_input(BenchmarkId::new("suppress", name), name, |b, name| {
            b.iter(|| black_box(nr.should_suppress(black_box(name))));
        });
    }
    group.finish();
}

// ========================================================================
// SurfaceClassifier benchmarks
// ========================================================================

fn bench_surface_classifier(c: &mut Criterion) {
    let classifier = SurfaceClassifier::new();

    let mut group = c.benchmark_group("surface_classifier");
    group.bench_function("classify_rust_stdlib", |b| {
        b.iter(|| {
            black_box(classifier.classify(
                black_box("core::ptr::drop_in_place"),
                black_box(Language::Rust),
                black_box(None),
            ))
        });
    });
    group.bench_function("classify_python_api", |b| {
        b.iter(|| {
            black_box(classifier.classify(
                black_box("PyLong_FromLong"),
                black_box(Language::Python),
                black_box(None),
            ))
        });
    });
    group.bench_function("classify_with_source_path", |b| {
        b.iter(|| {
            black_box(classifier.classify(
                black_box("my_func"),
                black_box(Language::Rust),
                black_box(Some(
                    "/home/user/.cargo/registry/src/github.com/serde-1.0/src/lib.rs",
                )),
            ))
        });
    });
    group.finish();
}

// ========================================================================
// PrecisionMetrics benchmarks
// ========================================================================

fn bench_precision_metrics(c: &mut Criterion) {
    let metrics = PrecisionMetrics {
        total_issues: 100,
        true_positives: 88,
        false_positives: 12,
        false_negatives: 5,
        total_actual_bugs: 93,
        functions_analyzed: 500,
        functions_skipped: 200,
    };

    let mut group = c.benchmark_group("precision_metrics");
    group.bench_function("ffi_precision", |b| {
        b.iter(|| black_box(metrics.ffi_precision()));
    });
    group.bench_function("gate_check", |b| {
        b.iter(|| black_box(metrics.gate_check()));
    });
    group.bench_function("f1_score", |b| {
        b.iter(|| black_box(metrics.f1_score()));
    });
    group.finish();
}

// ========================================================================
// PassContext benchmarks
// ========================================================================

fn bench_pass_context_issue_collection(c: &mut Criterion) {
    let mut group = c.benchmark_group("pass_context");
    group.bench_function("emit_issue_100", |b| {
        b.iter(|| {
            let mut ctx = PassContext::new();
            for _i in 0..100 {
                let id = ctx.next_issue_id();
                let issue = omniscope_core::Issue::new(
                    id,
                    omniscope_core::IssueKind::FfiUnsafeCall,
                    omniscope_core::Severity::Warning,
                    "test issue",
                );
                ctx.emit_issue(issue);
            }
            black_box(ctx.issue_count());
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_registry_lookup,
    bench_registry_is_high_risk,
    bench_noise_reduction,
    bench_surface_classifier,
    bench_precision_metrics,
    bench_pass_context_issue_collection,
);

criterion_main!(benches);
