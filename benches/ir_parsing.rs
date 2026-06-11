//! Benchmarks for IR parsing (`IRModule::parse_from_text`).
//!
//! Measures parse throughput across different IR file sizes using
//! fixture files from `tests/integration/`. Each benchmark reports
//! functions/second as a throughput metric.
//!
//! Run: `cargo bench --bench ir_parsing`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use omniscope_ir::IRModule;
use std::path::PathBuf;

/// Load a fixture `.ll` file from `tests/integration/` at runtime.
/// Returns None if the file is not found (CI / fresh clone).
fn load_fixture(relative_path: &str) -> Option<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    std::fs::read_to_string(&path).ok()
}

/// Describes a fixture for parameterized benchmarking.
struct Fixture {
    name: &'static str,
    path: &'static str,
}

/// All fixtures sorted roughly by size (small to large).
fn fixture_specs() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "rust_hash_2KB",
            path: "tests/integration/rust_hash.ll",
        },
        Fixture {
            name: "c_hash_bridge_7KB",
            path: "tests/integration/c_hash_c_bridge.ll",
        },
        Fixture {
            name: "python_ffi_7KB",
            path: "tests/integration/python_ffi_bugs.ll",
        },
        Fixture {
            name: "go_ffi_8KB",
            path: "tests/integration/go_ffi_bugs.ll",
        },
        Fixture {
            name: "c_ffi_bugs_17KB",
            path: "tests/integration/c_ffi_bugs.ll",
        },
        Fixture {
            name: "cpp_hash_23KB",
            path: "tests/integration/cpp_hash.ll",
        },
        Fixture {
            name: "rust_ffi_bugs_30KB",
            path: "tests/integration/rust_ffi_bugs.ll",
        },
    ]
}

// ========================================================================
// Benchmark: parse_from_text with real fixture files
// ========================================================================

fn bench_parse_fixture_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("ir_parse_fixture");
    group.sample_size(50);

    for spec in fixture_specs() {
        let ir = match load_fixture(spec.path) {
            Some(ir) => ir,
            None => continue,
        };
        group.bench_with_input(BenchmarkId::new("parse", spec.name), &ir, |b, ir_text| {
            b.iter(|| {
                let module = IRModule::parse_from_text(black_box(ir_text));
                black_box(module.functions.len());
                black_box(module.calls.len());
            });
        });
    }

    group.finish();
}

// ========================================================================
// Benchmark: parse_from_text throughput (bytes/second)
// ========================================================================

fn bench_parse_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("ir_parse_throughput");
    group.sample_size(50);

    for spec in fixture_specs() {
        let ir = match load_fixture(spec.path) {
            Some(ir) => ir,
            None => continue,
        };
        let size_bytes = ir.len();
        group.throughput(criterion::Throughput::Bytes(size_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("throughput", spec.name),
            &ir,
            |b, ir_text| {
                b.iter(|| {
                    let module = IRModule::parse_from_text(black_box(ir_text));
                    black_box(&module);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: parse_from_text throughput (functions/second)
// ========================================================================

fn bench_parse_functions_per_second(c: &mut Criterion) {
    let mut group = c.benchmark_group("ir_parse_funcs_per_sec");
    group.sample_size(50);

    for spec in fixture_specs() {
        let ir = match load_fixture(spec.path) {
            Some(ir) => ir,
            None => continue,
        };
        // Pre-count functions for throughput metric.
        let module = IRModule::parse_from_text(&ir);
        let func_count = (module.functions.len() + module.declarations.len()) as u64;
        group.throughput(criterion::Throughput::Elements(func_count));
        group.bench_with_input(
            BenchmarkId::new("functions", spec.name),
            &ir,
            |b, ir_text| {
                b.iter(|| {
                    let module = IRModule::parse_from_text(black_box(ir_text));
                    black_box(&module);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: parse_from_text with synthetic IR of varying sizes
// ========================================================================

/// Generates synthetic LLVM IR text with `n` functions, each containing
/// a malloc call and a free call (typical pattern for resource analysis).
fn generate_synthetic_ir(num_functions: usize) -> String {
    let mut ir = String::with_capacity(num_functions * 200);
    ir.push_str("target triple = \"x86_64-unknown-linux-gnu\"\n\n");

    // External declarations
    ir.push_str("declare ptr @malloc(i64)\n");
    ir.push_str("declare void @free(ptr)\n\n");

    for i in 0..num_functions {
        ir.push_str(&format!(
            "define void @func_{i}(i64 %size) {{\n\
             entry:\n\
               %ptr = call ptr @malloc(i64 %size)\n\
               call void @free(ptr %ptr)\n\
               ret void\n\
             }}\n\n"
        ));
    }

    ir
}

fn bench_parse_synthetic_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("ir_parse_synthetic");
    group.sample_size(20);

    for n in [10, 50, 100, 500, 1000] {
        let ir = generate_synthetic_ir(n);
        let size_bytes = ir.len();
        group.throughput(criterion::Throughput::Bytes(size_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("parse", format!("{n}_funcs")),
            ir.as_str(),
            |b, ir_text| {
                b.iter(|| {
                    let module = IRModule::parse_from_text(black_box(ir_text));
                    black_box(&module);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_fixture_files,
    bench_parse_throughput,
    bench_parse_functions_per_second,
    bench_parse_synthetic_sizes,
);
criterion_main!(benches);
