//! Benchmarks for the full analysis pipeline.
//!
//! Measures end-to-end latency of `Pipeline::new() -> register_default_passes()
//! -> set_ir_module() -> run()` using real `.ll` fixture files.
//!
//! Run: `cargo bench --bench pipeline`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use omniscope_ir::IRModule;
use omniscope_pipeline::Pipeline;

// Fixture files embedded at compile time.
const C_FFI_BUGS: &str = include_str!("../tests/integration/c_ffi_bugs.ll");
const RUST_FFI_BUGS: &str = include_str!("../tests/integration/rust_ffi_bugs.ll");
const CPP_HASH: &str = include_str!("../tests/integration/cpp_hash.ll");
const C_HASH_BRIDGE: &str = include_str!("../tests/integration/c_hash_c_bridge.ll");
const ZIG_FFI_BUGS: &str = include_str!("../tests/integration/zig_ffi_bugs.ll");

/// Describes a fixture for parameterized benchmarking.
struct Fixture {
    name: &'static str,
    ir: &'static str,
}

fn fixtures() -> Vec<Fixture> {
    vec![
        Fixture {
            name: "c_hash_bridge_7KB",
            ir: C_HASH_BRIDGE,
        },
        Fixture {
            name: "zig_ffi_14KB",
            ir: ZIG_FFI_BUGS,
        },
        Fixture {
            name: "c_ffi_bugs_17KB",
            ir: C_FFI_BUGS,
        },
        Fixture {
            name: "cpp_hash_23KB",
            ir: CPP_HASH,
        },
        Fixture {
            name: "rust_ffi_bugs_30KB",
            ir: RUST_FFI_BUGS,
        },
    ]
}

// ========================================================================
// Benchmark: full pipeline end-to-end latency
// ========================================================================

fn bench_pipeline_e2e(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_e2e");
    group.sample_size(20);

    for fixture in fixtures() {
        let module = IRModule::parse_from_text(fixture.ir);
        let func_count = module.functions.len() + module.declarations.len();

        group.bench_with_input(
            BenchmarkId::new("run", format!("{}_{}", fixture.name, func_count)),
            &module,
            |b, module| {
                b.iter(|| {
                    let mut pipeline = Pipeline::new();
                    pipeline.register_default_passes();
                    pipeline.set_ir_module(module.clone());
                    let result = pipeline.run().unwrap();
                    black_box(result.issues().len());
                    black_box(result.pass_count());
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: pipeline creation + pass registration (no run)
// ========================================================================

fn bench_pipeline_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_setup");

    group.bench_function("new_and_register", |b| {
        b.iter(|| {
            let mut pipeline = Pipeline::new();
            pipeline.register_default_passes();
            black_box(pipeline.pass_count());
        });
    });

    group.finish();
}

// ========================================================================
// Benchmark: pipeline with synthetic IR of varying complexity
// ========================================================================

/// Generates synthetic LLVM IR with `n` functions, each containing
/// alloc/release pairs that exercise the full resource analysis path.
fn generate_synthetic_ir(num_functions: usize) -> String {
    let mut ir = String::with_capacity(num_functions * 300);
    ir.push_str("target triple = \"x86_64-unknown-linux-gnu\"\n\n");
    ir.push_str("declare ptr @malloc(i64)\n");
    ir.push_str("declare void @free(ptr)\n");
    ir.push_str("declare ptr @_Znwm(i64)\n");
    ir.push_str("declare void @_ZdlPv(ptr)\n\n");

    for i in 0..num_functions {
        ir.push_str(&format!(
            "define void @func_{i}(i64 %size) {{\n\
             entry:\n\
               %ptr = call ptr @malloc(i64 %size)\n\
               %ptr2 = call ptr @_Znwm(i64 %size)\n\
               call void @free(ptr %ptr)\n\
               call void @_ZdlPv(ptr %ptr2)\n\
               ret void\n\
             }}\n\n"
        ));
    }

    ir
}

fn bench_pipeline_synthetic_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_synthetic");
    group.sample_size(10);

    for n in [5, 10, 50, 100] {
        let ir = generate_synthetic_ir(n);
        let module = IRModule::parse_from_text(&ir);

        group.bench_with_input(
            BenchmarkId::new("run", format!("{n}_funcs")),
            &module,
            |b, module| {
                b.iter(|| {
                    let mut pipeline = Pipeline::new();
                    pipeline.register_default_passes();
                    pipeline.set_ir_module(module.clone());
                    let result = pipeline.run().unwrap();
                    black_box(&result);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_pipeline_e2e,
    bench_pipeline_setup,
    bench_pipeline_synthetic_scaling,
);
criterion_main!(benches);
