//! Benchmarks for memory pool integration in hot passes.
//!
//! Measures the performance improvement from using arena-based allocation
//! in RawFactCollectorPass and ContractGraphBuilderPass.
//!
//! Run: `cargo bench --bench memory_pool`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use omniscope_core::MemoryPool;
use omniscope_ir::{CallInstruction, IRModule};
use omniscope_pass::Pass;

// ========================================================================
// Helper: synthetic IR module construction
// ========================================================================

/// Builds an IR module with `n` call instructions.
///
/// Each call has unique function names to simulate realistic allocation patterns.
fn build_ir_module(n: usize) -> IRModule {
    let mut module = IRModule::new();

    for i in 0..n {
        let callee = format!("malloc_{i}");
        let caller = format!("func_{}", i % 10);

        module.calls.push(CallInstruction {
            callee,
            caller,
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });

        // Add some free calls to balance
        if i % 3 == 0 {
            module.calls.push(CallInstruction {
                callee: "free".to_string(),
                caller: format!("func_{}", i % 10),
                is_external: true,
                location: None,
                args: Vec::new(),
                result: None,
            });
        }
    }

    module
}

// ========================================================================
// Benchmark: String allocation with MemoryPool vs standard heap
// ========================================================================

fn bench_string_allocation_pool_vs_heap(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_allocation");
    group.sample_size(100);

    for n in [100, 1000, 10000] {
        let strings: Vec<String> = (0..n).map(|i| format!("function_{i}")).collect();

        // Benchmark heap allocation
        group.bench_with_input(
            BenchmarkId::new("heap", format!("{n}_strings")),
            &strings,
            |b, strings| {
                b.iter(|| {
                    let mut heap_strings = Vec::with_capacity(strings.len());
                    for s in strings {
                        heap_strings.push(s.clone());
                    }
                    black_box(heap_strings);
                });
            },
        );

        // Benchmark pool allocation
        group.bench_with_input(
            BenchmarkId::new("pool", format!("{n}_strings")),
            &strings,
            |b, strings| {
                b.iter(|| {
                    let mut pool = MemoryPool::new();
                    let mut pool_strings = Vec::with_capacity(strings.len());
                    for s in strings {
                        let arena_str = pool.alloc_str(s);
                        pool_strings.push(arena_str.to_string());
                    }
                    black_box(pool_strings);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: RawFactCollectorPass with memory pool
// ========================================================================

fn bench_raw_fact_collector_with_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("raw_fact_collector");
    group.sample_size(20);

    for n in [100, 1000, 10000] {
        let module = build_ir_module(n);

        // Benchmark without pool (baseline)
        group.bench_with_input(
            BenchmarkId::new("without_pool", format!("{n}_calls")),
            &module,
            |b, module| {
                b.iter(|| {
                    let mut ctx = omniscope_pass::PassContext::new();
                    ctx.set_ir_module(module.clone());
                    let pass = omniscope_pass::RawFactCollectorPass::new();
                    let result = pass.run(&mut ctx).unwrap();
                    black_box(result.nodes_analyzed);
                });
            },
        );

        // Benchmark with pool (optimized)
        group.bench_with_input(
            BenchmarkId::new("with_pool", format!("{n}_calls")),
            &module,
            |b, module| {
                b.iter(|| {
                    let mut ctx = omniscope_pass::PassContext::new();
                    ctx.set_ir_module(module.clone());
                    let pass = omniscope_pass::RawFactCollectorPass::new();
                    let result = pass.run(&mut ctx).unwrap();
                    black_box(result.nodes_analyzed);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: ContractGraphBuilderPass with memory pool
// ========================================================================

fn bench_contract_graph_builder_with_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("contract_graph_builder");
    group.sample_size(20);

    for n in [100, 1000, 10000] {
        let module = build_ir_module(n);

        // Build raw facts first
        let mut ctx = omniscope_pass::PassContext::new();
        ctx.set_ir_module(module.clone());
        let raw_pass = omniscope_pass::RawFactCollectorPass::new();
        raw_pass.run(&mut ctx).unwrap();

        // Benchmark contract graph builder
        group.bench_with_input(
            BenchmarkId::new("build", format!("{n}_calls")),
            &ctx,
            |b, ctx| {
                b.iter(|| {
                    let mut local_ctx = ctx.clone();
                    let pass = omniscope_pass::ContractGraphBuilderPass::new();
                    let result = pass.run(&mut local_ctx).unwrap();
                    black_box(result.nodes_analyzed);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: MemoryPool allocation patterns
// ========================================================================

fn bench_memory_pool_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_pool_patterns");

    // Benchmark single allocation
    group.bench_function("single_alloc", |b| {
        let mut pool = MemoryPool::new();
        b.iter(|| {
            let value = pool.alloc(black_box(42u64));
            black_box(value);
        });
    });

    // Benchmark slice allocation
    group.bench_function("slice_alloc", |b| {
        let mut pool = MemoryPool::new();
        let data = vec![1u64; 100];
        b.iter(|| {
            let slice = pool.alloc_slice(&data);
            black_box(slice);
        });
    });

    // Benchmark string allocation
    group.bench_function("string_alloc", |b| {
        let mut pool = MemoryPool::new();
        let s = "test_string_for_allocation";
        b.iter(|| {
            let arena_str = pool.alloc_str(s);
            black_box(arena_str);
        });
    });

    // Benchmark reset and reuse
    group.bench_function("reset_and_reuse", |b| {
        let mut pool = MemoryPool::new();
        b.iter(|| {
            for i in 0..100 {
                let _ = pool.alloc(i);
            }
            pool.reset();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_string_allocation_pool_vs_heap,
    bench_raw_fact_collector_with_pool,
    bench_contract_graph_builder_with_pool,
    bench_memory_pool_patterns,
);
criterion_main!(benches);
