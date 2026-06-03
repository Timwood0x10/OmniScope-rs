//! Benchmarks for bug-fix regression and core pass performance.
//!
//! Covers the fixed code paths:
//!   BUG-1: FCmp instruction classification
//!   BUG-2: Parallel PassContext inheritance
//!   BUG-6: WriteToImmutablePass store scanning
//!   BUG-8: check_release_in_facts with function_name
//!   BUG-9: saturating_add for func_id
//!   BUG-10: is_likely_ffi_by_name with uppercase
//!   BUG-12: Profiler memory_samples with monotonic IDs
//!
//! Also measures individual pass throughput and the full pipeline
//! end-to-end with real .ll fixture files.
//!
//! Run: `cargo bench --bench bugfix_regression`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use omniscope_core::Profiler;
use omniscope_ir::{FunctionBody, IRInstruction, IRInstructionKind, IRModule};
use omniscope_pass::{
    analysis::WriteToImmutablePass, ContractEdge, ContractGraph, FfiReturnCheckPass,
    LeakDetectionPass, OwnershipSolverPass, Pass, PassContext, RawFactCollectorPass,
};
use omniscope_types::{Effect, FamilyId};

// Fixture files embedded at compile time.
const C_FFI_BUGS: &str = include_str!("../tests/integration/c_ffi_bugs.ll");
const RUST_FFI_BUGS: &str = include_str!("../tests/integration/rust_ffi_bugs.ll");
const CPP_HASH: &str = include_str!("../tests/integration/cpp_hash.ll");
const C_HASH_BRIDGE: &str = include_str!("../tests/integration/c_hash_c_bridge.ll");
const ZIG_FFI_BUGS: &str = include_str!("../tests/integration/zig_ffi_bugs.ll");
const RUST_MERKLE: &str = include_str!("../tests/integration/rust_merkle.ll");

// ========================================================================
// BUG-1: FCmp instruction classification
// ========================================================================

/// Build a synthetic IRModule with N store + N fcmp instructions.
/// Measures the overhead of classifying and counting both kinds.
fn build_module_with_fcmp(n: usize) -> IRModule {
    let mut module = IRModule::new();

    let mut instructions = Vec::with_capacity(n * 2);
    for i in 0..n {
        // Store instruction
        instructions.push(IRInstruction {
            kind: IRInstructionKind::Store,
            dest: Some(format!("%ptr_{i}")),
            operands: vec![format!("%val_{i}"), format!("%ptr_{i}")],
            callee: None,
            atomic_op: None,
            icmp_pred: None,
            raw_text: format!("store i32 %val_{i}, i32* %ptr_{i}"),
            result_type: None,
            element_type: None,
            function_signature: None,
            conversion_opcode: None,
            binary_opcode: None,
        });
        // FCmp instruction
        instructions.push(IRInstruction {
            kind: IRInstructionKind::Fcmp,
            dest: Some(format!("%cmp_{i}")),
            operands: vec![format!("%x_{i}"), "0.0".to_string()],
            callee: None,
            atomic_op: None,
            icmp_pred: Some("oeq".to_string()),
            raw_text: format!("%cmp_{i} = fcmp oeq double %x_{i}, 0.0"),
            result_type: None,
            element_type: None,
            function_signature: None,
            conversion_opcode: None,
            binary_opcode: None,
        });
    }

    let body = FunctionBody {
        name: "test_fcmp_func".to_string(),
        instructions,
    };
    module
        .function_bodies
        .insert("test_fcmp_func".to_string(), body);
    module
}

fn bench_fcmp_classification(c: &mut Criterion) {
    let mut group = c.benchmark_group("bug1_fcmp_classification");
    group.sample_size(30);

    for n in [100, 1000, 5000] {
        let module = build_module_with_fcmp(n);
        group.bench_with_input(
            BenchmarkId::new("count_kinds", format!("{n}_mixed")),
            &module,
            |b, module| {
                b.iter(|| {
                    let mut store_count = 0usize;
                    let mut fcmp_count = 0usize;
                    let mut icmp_count = 0usize;
                    for body in module.function_bodies.values() {
                        for inst in &body.instructions {
                            match inst.kind {
                                IRInstructionKind::Store => store_count += 1,
                                IRInstructionKind::Fcmp => fcmp_count += 1,
                                IRInstructionKind::Icmp => icmp_count += 1,
                                _ => {}
                            }
                        }
                    }
                    black_box((store_count, fcmp_count, icmp_count));
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// BUG-6: WriteToImmutablePass store scanning via function_bodies
// ========================================================================

fn bench_write_to_immutable(c: &mut Criterion) {
    let mut group = c.benchmark_group("bug6_write_to_immutable");
    group.sample_size(20);

    for n in [100, 1000, 5000] {
        let module = build_module_with_fcmp(n);
        group.bench_with_input(
            BenchmarkId::new("store_scan", format!("{n}_stores")),
            &module,
            |b, module| {
                b.iter(|| {
                    let mut ctx = PassContext::new();
                    ctx.store("ir_module", module.clone());
                    let pass = WriteToImmutablePass::new();
                    let result = pass.run(&mut ctx).unwrap();
                    black_box(result.nodes_analyzed);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// BUG-8 + BUG-9: LeakDetectionPass (formerly PathSensitiveLeakPass)
//   - check_release_in_facts with function_name matching
//   - saturating_add for func_id
// ========================================================================

fn build_raw_facts_for_leak(
    n: usize,
) -> (
    Vec<omniscope_pass::resource::raw_fact_collector::RawResourceFact>,
    ContractGraph,
) {
    use omniscope_pass::resource::raw_fact_collector::RawResourceFact;
    use omniscope_types::PointerContract;

    let mut facts = Vec::with_capacity(n * 2);
    let mut graph = ContractGraph::new();

    for i in 0..n {
        // Acquire fact
        let alloc = RawResourceFact {
            function: (i / 10) as u64,
            function_name: format!("malloc_{i}"),
            caller_name: format!("func_{}", i % 10),
            family: Some(FamilyId::C_HEAP),
            is_acquire: true,
            contract: PointerContract::Owned,
            arg_index: Some(0),
        };
        facts.push(alloc);

        // Release fact (same function for 80% of pairs → no leak)
        if i % 5 != 0 {
            let release = RawResourceFact {
                function: (i / 10) as u64,
                function_name: format!("free_{i}"),
                caller_name: format!("func_{}", i % 10),
                family: Some(FamilyId::C_HEAP),
                is_acquire: false,
                contract: PointerContract::Released,
                arg_index: Some(0),
            };
            facts.push(release);

            // Add edges to graph
            let instance_id = graph.alloc_instance();
            graph.add_edge(ContractEdge {
                source: 0,
                target: instance_id,
                effect: Effect::Acquire {
                    family: FamilyId::C_HEAP,
                    result: instance_id,
                },
                function: (i / 10) as u64,
                function_name: format!("malloc_{i}"),
                caller_name: format!("func_{}", i % 10),
                family: Some(FamilyId::C_HEAP),
            });
            graph.add_edge(ContractEdge {
                source: instance_id,
                target: 0,
                effect: Effect::Release {
                    family: FamilyId::C_HEAP,
                    arg: 0,
                },
                function: (i / 10) as u64,
                function_name: format!("free_{i}"),
                caller_name: format!("func_{}", i % 10),
                family: Some(FamilyId::C_HEAP),
            });
        }
    }

    (facts, graph)
}

fn bench_leak_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("bug8_leak_detection");
    group.sample_size(20);

    for n in [100, 1000, 5000] {
        let (facts, graph) = build_raw_facts_for_leak(n);
        group.bench_with_input(
            BenchmarkId::new("run", format!("{n}_facts")),
            &(facts, graph),
            |b, (facts, graph)| {
                b.iter(|| {
                    let mut ctx = PassContext::new();
                    ctx.store("raw_resource_facts", facts.clone());
                    ctx.store("contract_graph", graph.clone());
                    let pass = LeakDetectionPass::new();
                    let result = pass.run(&mut ctx).unwrap();
                    black_box(result.nodes_analyzed);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// BUG-10: FfiReturnCheckPass with mixed-case FFI names
// ========================================================================

fn bench_ffi_return_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("bug10_ffi_return_check");
    group.sample_size(20);

    // Use real fixture files for realistic benchmarking
    let fixtures = vec![
        ("c_ffi_bugs_17KB", C_FFI_BUGS),
        ("cpp_hash_23KB", CPP_HASH),
        ("rust_ffi_bugs_30KB", RUST_FFI_BUGS),
    ];

    for (name, ir) in fixtures {
        let module = IRModule::parse_from_text(ir);
        group.bench_with_input(
            BenchmarkId::new("ffi_return_check", name),
            &module,
            |b, module| {
                b.iter(|| {
                    let mut ctx = PassContext::new();
                    ctx.store("ir_module", module.clone());
                    // RawFactCollector must run first
                    let raw_pass = RawFactCollectorPass::new();
                    raw_pass.run(&mut ctx).unwrap();
                    let pass = FfiReturnCheckPass::new();
                    let result = pass.run(&mut ctx).unwrap();
                    black_box(result.nodes_analyzed);
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// BUG-12: Profiler memory_samples with monotonic IDs
// ========================================================================

fn bench_profiler_memory_samples(c: &mut Criterion) {
    let mut group = c.benchmark_group("bug12_profiler_memory_samples");
    group.sample_size(30);

    for n in [100, 1000, 10000] {
        group.bench_with_input(
            BenchmarkId::new("record_memory", format!("{n}_samples")),
            &n,
            |b, &n| {
                b.iter(|| {
                    let profiler = Profiler::new();
                    for i in 0..n {
                        profiler.record_memory(black_box(1024 * 1024), black_box((i * 100) as u64));
                    }
                    let history = profiler.memory_history();
                    black_box(history.len());
                });
            },
        );
    }

    group.finish();
}

// ========================================================================
// Full pipeline end-to-end with real fixture files
// ========================================================================

fn bench_pipeline_e2e(c: &mut Criterion) {
    use omniscope_pipeline::Pipeline;

    let mut group = c.benchmark_group("pipeline_e2e");
    group.sample_size(15);

    let fixtures = vec![
        ("c_hash_bridge_7KB", C_HASH_BRIDGE),
        ("zig_ffi_14KB", ZIG_FFI_BUGS),
        ("c_ffi_bugs_17KB", C_FFI_BUGS),
        ("cpp_hash_23KB", CPP_HASH),
        ("rust_ffi_bugs_30KB", RUST_FFI_BUGS),
        ("rust_merkle_44KB", RUST_MERKLE),
    ];

    for (name, ir) in fixtures {
        let module = IRModule::parse_from_text(ir);
        let func_count = module.functions.len() + module.declarations.len();
        let call_count = module.calls.len();

        group.bench_with_input(
            BenchmarkId::new("run", format!("{name}_{func_count}f_{call_count}c")),
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
// Individual pass throughput (post-fix regression)
// ========================================================================

fn bench_ownership_solver_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("ownership_solver_throughput");
    group.sample_size(20);

    // Build balanced graphs at scale
    for n in [100, 1000, 10000] {
        let mut graph = ContractGraph::new();
        for i in 0..n {
            let instance_id = graph.alloc_instance();
            graph.add_edge(ContractEdge {
                source: 0,
                target: instance_id,
                effect: Effect::Acquire {
                    family: FamilyId::C_HEAP,
                    result: instance_id,
                },
                function: (i / 10) as u64 + 1,
                function_name: format!("malloc_{i}"),
                caller_name: format!("func_{}", i % 10),
                family: Some(FamilyId::C_HEAP),
            });
            graph.add_edge(ContractEdge {
                source: instance_id,
                target: 0,
                effect: Effect::Release {
                    family: FamilyId::C_HEAP,
                    arg: 0,
                },
                function: (i / 10) as u64 + 1,
                function_name: format!("free_{i}"),
                caller_name: format!("func_{}", i % 10),
                family: Some(FamilyId::C_HEAP),
            });
        }

        group.bench_with_input(
            BenchmarkId::new("solve", format!("{n}_pairs")),
            &graph,
            |b, graph| {
                b.iter(|| {
                    let mut ctx = PassContext::new();
                    ctx.store("contract_graph", graph.clone());
                    let pass = OwnershipSolverPass::new();
                    let result = pass.run(&mut ctx).unwrap();
                    black_box(result.nodes_analyzed);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_fcmp_classification,
    bench_write_to_immutable,
    bench_leak_detection,
    bench_ffi_return_check,
    bench_profiler_memory_samples,
    bench_pipeline_e2e,
    bench_ownership_solver_throughput,
);
criterion_main!(benches);
