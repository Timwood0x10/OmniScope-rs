//! Benchmarks for PassContext cloning strategies.
//!
//! Measures the performance difference between full clone and
//! lightweight clone_for_parallel for parallel pass execution.
//!
//! Run: `cargo bench --bench context_clone`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use omniscope_core::{Diagnostic, Fact, FactKind, FactLocation, Issue, IssueKind, Severity};
use omniscope_pass::PassContext;
use std::path::PathBuf;

// ========================================================================
// Helpers: create contexts with varying amounts of data
// ========================================================================

/// Creates a PassContext with the specified number of diagnostics, facts, and issues.
fn create_context_with_data(
    diagnostic_count: usize,
    fact_count: usize,
    issue_count: usize,
) -> PassContext {
    let mut ctx = PassContext::new();

    // Add diagnostics
    for i in 0..diagnostic_count {
        ctx.add_diagnostic(Diagnostic::new(
            i as u64,
            Severity::Warning,
            format!("W{i:03}"),
            format!("Warning message {i}"),
        ));
    }

    // Add facts
    let location = FactLocation::new(PathBuf::from("test.rs"), 10);
    for i in 0..fact_count {
        ctx.add_fact(Fact::new(i as u64, FactKind::AllocSite, location.clone()));
    }

    // Add issues
    for i in 0..issue_count {
        let issue = Issue::new(
            i as u64,
            IssueKind::MemoryLeak,
            Severity::Warning,
            format!("Issue {i}: memory leak detected"),
        );
        ctx.emit_issue(issue);
    }

    // Add some shared data to simulate real usage
    ctx.store("test_key_1", "test_value_1".to_string());
    ctx.store("test_key_2", 42u64);
    ctx.store("test_key_3", vec![1, 2, 3, 4, 5]);

    ctx
}

// ========================================================================
// Benchmark: Full clone vs clone_for_parallel
// ========================================================================

fn bench_context_clone_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("context_clone_comparison");

    // Test with different amounts of data
    let test_cases = [
        ("small", 10, 10, 10),
        ("medium", 100, 100, 100),
        ("large", 1000, 1000, 1000),
        ("xlarge", 10000, 10000, 10000),
    ];

    for (name, diagnostic_count, fact_count, issue_count) in test_cases {
        let ctx = create_context_with_data(diagnostic_count, fact_count, issue_count);

        // Benchmark full clone
        group.bench_with_input(BenchmarkId::new("full_clone", name), &ctx, |b, ctx| {
            b.iter(|| {
                let _cloned = black_box(ctx.clone());
            });
        });

        // Benchmark lightweight clone_for_parallel
        group.bench_with_input(
            BenchmarkId::new("clone_for_parallel", name),
            &ctx,
            |b, ctx| {
                b.iter(|| {
                    let _cloned = black_box(ctx.clone_for_parallel());
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: Simulated parallel pass execution
// ========================================================================

fn bench_simulated_parallel_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("simulated_parallel_execution");
    group.sample_size(50);

    // Simulate a context with typical analysis data
    let ctx = create_context_with_data(500, 500, 500);

    // Simulate 4 parallel passes (typical for dependency level)
    let pass_count = 4;

    // Benchmark with full clone (old approach)
    group.bench_function("full_clone_4_passes", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(pass_count);
            for _ in 0..pass_count {
                // Each pass clones the full context
                let mut local_ctx = black_box(ctx.clone());
                // Simulate some work (add a few items)
                local_ctx.add_diagnostic(Diagnostic::new(
                    9999,
                    Severity::Note,
                    "N999",
                    "Simulated pass output",
                ));
                results.push(local_ctx);
            }
            // Simulate merge
            let mut merged = ctx.clone();
            for local_ctx in results {
                merged.merge(local_ctx);
            }
            black_box(merged);
        });
    });

    // Benchmark with lightweight clone (new approach)
    group.bench_function("clone_for_parallel_4_passes", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(pass_count);
            for _ in 0..pass_count {
                // Each pass uses lightweight clone
                let mut local_ctx = black_box(ctx.clone_for_parallel());
                // Simulate some work (add a few items)
                local_ctx.add_diagnostic(Diagnostic::new(
                    9999,
                    Severity::Note,
                    "N999",
                    "Simulated pass output",
                ));
                results.push(local_ctx);
            }
            // Simulate merge
            let mut merged = ctx.clone();
            for local_ctx in results {
                merged.merge(local_ctx);
            }
            black_box(merged);
        });
    });

    group.finish();
}

// ========================================================================
// Benchmark: Memory allocation patterns
// ========================================================================

fn bench_memory_allocation_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_allocation_patterns");

    // Test memory allocation behavior
    let sizes = [100, 1000, 10000];

    for size in sizes {
        let ctx = create_context_with_data(size, size, size);

        // Measure full clone allocation
        group.bench_with_input(
            BenchmarkId::new("full_clone_alloc", size),
            &ctx,
            |b, ctx| {
                b.iter(|| {
                    // Clone multiple times to amplify allocation overhead
                    for _ in 0..10 {
                        let _cloned = black_box(ctx.clone());
                    }
                });
            },
        );

        // Measure lightweight clone allocation
        group.bench_with_input(
            BenchmarkId::new("lightweight_clone_alloc", size),
            &ctx,
            |b, ctx| {
                b.iter(|| {
                    // Clone multiple times to amplify allocation overhead
                    for _ in 0..10 {
                        let _cloned = black_box(ctx.clone_for_parallel());
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_context_clone_comparison,
    bench_simulated_parallel_execution,
    bench_memory_allocation_patterns,
);
criterion_main!(benches);
