//! Benchmarks for the resource analysis passes: contract graph builder and
//! ownership solver.
//!
//! Measures how these passes scale with varying numbers of acquire/release
//! pairs (100, 1000, 10000). Uses synthetic contract graphs to isolate
//! the pass-level performance from IR parsing overhead.
//!
//! Run: `cargo bench --bench resource_analysis`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use omniscope_pass::{
    ContractEdge, ContractGraph, OwnershipSolverPass, Pass, PassContext,
};
use omniscope_types::{Effect, FamilyId};

// ========================================================================
// Helpers: synthetic contract graph construction
// ========================================================================

/// Builds a contract graph with `n` balanced acquire/release pairs.
///
/// Each pair consists of:
///   1. An Acquire edge (source=0, target=new instance)
///   2. A Release edge (source=instance, target=0)
///
/// This models the simplest correct pattern: malloc + free, per function.
fn build_balanced_graph(n: usize) -> ContractGraph {
    let mut graph = ContractGraph::new();

    for _ in 0..n {
        let instance_id = graph.alloc_instance();
        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family: FamilyId::C_HEAP,
                result: instance_id,
            },
            function: 1,
            function_name: "malloc".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
        });
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::Release {
                family: FamilyId::C_HEAP,
                arg: 0,
            },
            function: 2,
            function_name: "free".to_string(),
            caller_name: "test_func".to_string(),
            family: Some(FamilyId::C_HEAP),
        });
    }

    graph
}

/// Builds a contract graph with `n` acquire-only edges (leak pattern).
///
/// Each acquire has no matching release, so every instance becomes
/// a leak candidate for the ownership solver.
fn build_leak_graph(n: usize) -> ContractGraph {
    let mut graph = ContractGraph::new();

    for _ in 0..n {
        let instance_id = graph.alloc_instance();
        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family: FamilyId::C_HEAP,
                result: instance_id,
            },
            function: 1,
            function_name: "malloc".to_string(),
            caller_name: "leaky_func".to_string(),
            family: Some(FamilyId::C_HEAP),
        });
    }

    graph
}

/// Builds a contract graph with `n` acquire/release pairs across
/// multiple resource families. This exercises the family-matching
/// logic in the ownership solver.
fn build_multi_family_graph(n: usize) -> ContractGraph {
    let mut graph = ContractGraph::new();
    let families = [
        FamilyId::C_HEAP,
        FamilyId::CPP_NEW_SCALAR,
        FamilyId::RUST_GLOBAL,
        FamilyId::PYTHON_OBJECT,
        FamilyId::JAVA_LOCAL_REF,
    ];

    for i in 0..n {
        let family = families[i % families.len()];
        let instance_id = graph.alloc_instance();

        // Acquire edge
        graph.add_edge(ContractEdge {
            source: 0,
            target: instance_id,
            effect: Effect::Acquire {
                family,
                result: instance_id,
            },
            function: (i as u64) + 1,
            function_name: format!("alloc_{i}"),
            caller_name: format!("func_{}", i % 10),
            family: Some(family),
        });

        // Release edge (same family)
        graph.add_edge(ContractEdge {
            source: instance_id,
            target: 0,
            effect: Effect::Release {
                family,
                arg: 0,
            },
            function: (i as u64) + 1,
            function_name: format!("release_{i}"),
            caller_name: format!("func_{}", i % 10),
            family: Some(family),
        });
    }

    graph
}

/// Builds a contract graph with `n` pairs that include escape and
/// reclaim edges (into_raw/from_raw pattern). This exercises the
/// OwnershipEscape and OwnershipReclaim transitions.
fn build_escape_reclaim_graph(n: usize) -> ContractGraph {
    let mut graph = ContractGraph::new();

    for _ in 0..n {
        let acquire_id = graph.alloc_instance();
        let escape_id = graph.alloc_instance();
        let reclaim_id = graph.alloc_instance();

        // Acquire
        graph.add_edge(ContractEdge {
            source: 0,
            target: acquire_id,
            effect: Effect::Acquire {
                family: FamilyId::RUST_GLOBAL,
                result: acquire_id,
            },
            function: 1,
            function_name: "__rust_alloc".to_string(),
            caller_name: "box_new".to_string(),
            family: Some(FamilyId::RUST_GLOBAL),
        });

        // Escape (into_raw)
        graph.add_edge(ContractEdge {
            source: acquire_id,
            target: 0,
            effect: Effect::OwnershipEscape {
                family: FamilyId::RUST_GLOBAL,
                result: escape_id,
            },
            function: 2,
            function_name: "into_raw".to_string(),
            caller_name: "box_new".to_string(),
            family: Some(FamilyId::RUST_GLOBAL),
        });

        // Reclaim (from_raw) — releases escaped instance and creates new one
        graph.add_edge(ContractEdge {
            source: acquire_id,
            target: reclaim_id,
            effect: Effect::OwnershipReclaim {
                family: FamilyId::RUST_GLOBAL,
                result: reclaim_id,
            },
            function: 3,
            function_name: "from_raw".to_string(),
            caller_name: "box_new".to_string(),
            family: Some(FamilyId::RUST_GLOBAL),
        });

        // Final release of reclaimed instance
        graph.add_edge(ContractEdge {
            source: reclaim_id,
            target: 0,
            effect: Effect::Release {
                family: FamilyId::RUST_GLOBAL,
                arg: 0,
            },
            function: 4,
            function_name: "__rust_dealloc".to_string(),
            caller_name: "box_new".to_string(),
            family: Some(FamilyId::RUST_GLOBAL),
        });
    }

    graph
}

// ========================================================================
// Benchmark: OwnershipSolver with balanced acquire/release graphs
// ========================================================================

fn bench_ownership_solver_balanced(c: &mut Criterion) {
    let mut group = c.benchmark_group("ownership_solver_balanced");
    group.sample_size(20);

    for n in [100, 1000, 10000] {
        let graph = build_balanced_graph(n);
        group.bench_with_input(
            BenchmarkId::new("solve", format!("{n}_pairs")),
            &graph,
            |b, graph| {
                b.iter(|| {
                    let mut ctx = PassContext::new();
                    ctx.store("contract_graph", graph.clone());
                    let pass = OwnershipSolverPass::new();
                    let result = pass.run(&mut ctx).unwrap();
                    let states: Option<Vec<omniscope_semantics::ResourceInstance>> =
                        ctx.get("ownership_states");
                    black_box(states.as_ref().map(|s| s.len()));
                    black_box(result.nodes_analyzed);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: OwnershipSolver with leak graphs (acquire-only)
// ========================================================================

fn bench_ownership_solver_leak(c: &mut Criterion) {
    let mut group = c.benchmark_group("ownership_solver_leak");
    group.sample_size(20);

    for n in [100, 1000, 10000] {
        let graph = build_leak_graph(n);
        group.bench_with_input(
            BenchmarkId::new("solve", format!("{n}_acquires")),
            &graph,
            |b, graph| {
                b.iter(|| {
                    let mut ctx = PassContext::new();
                    ctx.store("contract_graph", graph.clone());
                    let pass = OwnershipSolverPass::new();
                    let result = pass.run(&mut ctx).unwrap();
                    let states: Option<Vec<omniscope_semantics::ResourceInstance>> =
                        ctx.get("ownership_states");
                    let leak_count = states
                        .as_ref()
                        .map(|s| s.iter().filter(|i| i.is_leak_candidate()).count())
                        .unwrap_or(0);
                    black_box(leak_count);
                    black_box(result.nodes_analyzed);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: OwnershipSolver with multi-family graphs
// ========================================================================

fn bench_ownership_solver_multi_family(c: &mut Criterion) {
    let mut group = c.benchmark_group("ownership_solver_multi_family");
    group.sample_size(20);

    for n in [100, 1000, 10000] {
        let graph = build_multi_family_graph(n);
        group.bench_with_input(
            BenchmarkId::new("solve", format!("{n}_pairs")),
            &graph,
            |b, graph| {
                b.iter(|| {
                    let mut ctx = PassContext::new();
                    ctx.store("contract_graph", graph.clone());
                    let pass = OwnershipSolverPass::new();
                    let result = pass.run(&mut ctx).unwrap();
                    let states: Option<Vec<omniscope_semantics::ResourceInstance>> =
                        ctx.get("ownership_states");
                    black_box(states.as_ref().map(|s| s.len()));
                    black_box(result.nodes_analyzed);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: OwnershipSolver with escape/reclaim graphs
// ========================================================================

fn bench_ownership_solver_escape_reclaim(c: &mut Criterion) {
    let mut group = c.benchmark_group("ownership_solver_escape_reclaim");
    group.sample_size(20);

    for n in [100, 1000, 10000] {
        let graph = build_escape_reclaim_graph(n);
        group.bench_with_input(
            BenchmarkId::new("solve", format!("{n}_cycles")),
            &graph,
            |b, graph| {
                b.iter(|| {
                    let mut ctx = PassContext::new();
                    ctx.store("contract_graph", graph.clone());
                    let pass = OwnershipSolverPass::new();
                    let result = pass.run(&mut ctx).unwrap();
                    let states: Option<Vec<omniscope_semantics::ResourceInstance>> =
                        ctx.get("ownership_states");
                    black_box(states.as_ref().map(|s| s.len()));
                    black_box(result.nodes_analyzed);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Benchmark: ContractGraph construction overhead
// ========================================================================

fn bench_contract_graph_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("contract_graph_construction");

    for n in [100, 1000, 10000] {
        group.bench_with_input(
            BenchmarkId::new("build_balanced", format!("{n}_pairs")),
            &n,
            |b, &n| {
                b.iter(|| {
                    let graph = build_balanced_graph(black_box(n));
                    black_box(graph.edge_count());
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_ownership_solver_balanced,
    bench_ownership_solver_leak,
    bench_ownership_solver_multi_family,
    bench_ownership_solver_escape_reclaim,
    bench_contract_graph_construction,
);
criterion_main!(benches);
