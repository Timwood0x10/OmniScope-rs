//! Performance regression benchmarks for semantic analysis and whitelist matching.
//!
//! This benchmark suite establishes performance baselines for critical
//! semantic analysis components to detect performance regressions.
//!
//! ## Benchmark Categories
//!
//! 1. **Language Detection**: Measures performance of language detection
//!    from function names and module names.
//!
//! 2. **Surface Classification**: Measures performance of function surface
//!    classification (user code, stdlib, boundary, etc.).
//!
//! 3. **Whitelist Matching**: Measures performance of Rust stdlib whitelist
//!    pattern matching with trie-based lookup.
//!
//! 4. **Cross-function Analysis**: Measures performance of cross-function
//!    lifetime tracking and resource flow analysis.
//!
//! ## Usage
//!
//! Run all benchmarks:
//! ```bash
//! cargo bench --bench regression_bench
//! ```
//!
//! Run specific benchmark group:
//! ```bash
//! cargo bench --bench regression_bench -- "language_detection"
//! ```
//!
//! Run with baseline comparison:
//! ```bash
//! cargo bench --bench regression_bench -- --save-baseline main
//! cargo bench --bench regression_bench -- --baseline main
//! ```

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use omniscope_semantics::{
    CrossFunctionTracker, FlowType, FunctionInfo, LanguageDetector, ParamInfo, ResourceFlow,
    ReturnInfo, RustStdlibWhitelist, SurfaceClassifier,
};
use omniscope_types::{FamilyId, Language, PointerContract};

// ============================================================================
// Test Data: Function names for language detection benchmarks
// ============================================================================

/// Rust function names (various mangling styles)
const RUST_FUNCTION_NAMES: &[&str] = &[
    "_ZN3vec3Vec3new17h1234567890abcdefE",
    "_ZN3arc3Arc3new17habcdef1234567890E",
    "_ZN6string6String3new17h9876543210abcdefE",
    "_ZN7hashmap7HashMap3new17habcdef9876543210E",
    "_ZN5tokio4task5spawn17habcdef1234567890E",
    "_ZN5serde10Serialize9serialize17habcdef1234567890E",
    "_RNvNtC...3Vec3new",
    "_RNvNtC...3Arc3new",
    "_RNvNtC...6String3new",
    "alloc::vec::Vec::new",
    "std::sync::Arc::new",
    "std::collections::HashMap::new",
];

/// C++ function names (Itanium mangling)
const CPP_FUNCTION_NAMES: &[&str] = &[
    "_ZNSt6vectorIiSaIiEEC1Ev",
    "_ZNSt3mapIiiSt4lessIiESaISt4pairIKiiEEEC1Ev",
    "_ZNSt12basic_stringIcSt11char_traitsIcESaIcEEC1Ev",
    "_ZNSt10unique_ptrIiSt14default_deleteIiEEC1Ev",
    "_ZNSt10shared_ptrIiEC1Ev",
    "_ZNSt12__shared_ptrIiLN9__gnu_cxx12_Lock_policyE2EEC1Ev",
    "std::vector<int>::push_back",
    "std::map<int, int>::insert",
    "std::string::append",
];

/// Go function names
const GO_FUNCTION_NAMES: &[&str] = &[
    "main.myFunction",
    "runtime.mallocgc",
    "runtime.newobject",
    "runtime.growslice",
    "fmt.Println",
    "os.Open",
    "io.ReadAll",
    "net/http.Get",
];

/// Python function names (with module prefixes)
const PYTHON_FUNCTION_NAMES: &[&str] = &[
    "PyObject_Malloc",
    "PyMem_Malloc",
    "Py_Initialize",
    "Py_Finalize",
    "_Py_NewReference",
    "_Py_Dealloc",
    "PyList_New",
    "PyDict_New",
];

/// C function names (no mangling)
const C_FUNCTION_NAMES: &[&str] = &[
    "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset", "strlen", "strcpy",
    "strcat",
];

/// Zig function names
const ZIG_FUNCTION_NAMES: &[&str] = &[
    "zig.heap.page_allocator",
    "zig.heap.FixedBufferAllocator",
    "zig.mem.Allocator",
    "zig.math.log2",
];

// ============================================================================
// Test Data: Module names for language detection benchmarks
// ============================================================================

/// Module names for language detection from file names
const MODULE_NAMES: &[&str] = &[
    "main.rs",
    "lib.rs",
    "utils.rs",
    "server.cpp",
    "client.cc",
    "helper.c",
    "runtime.go",
    "handler.py",
    "Service.java",
    "Program.cs",
    "build.zig",
    "unknown.xyz",
];

// ============================================================================
// Test Data: Whitelist function names for pattern matching
// ============================================================================

/// Known whitelisted function names (should match)
const WHITELISTED_FUNCTIONS: &[&str] = &[
    "_ZN3vec3Vec3new",
    "_ZN3arc3Arc3new",
    "_ZN6string6String3new",
    "_ZN7hashmap7HashMap3new",
    "_ZN5tokio4task5spawn",
    "_ZN5serde10Serialize9serialize",
    "_ZN3box3Box3new",
    "_ZN3box3Box8into_raw",
    "_ZN3sys5mutex5Mutex3new",
    "_ZN3sys5mutex5Mutex4lock",
    "Vec::new",
    "Arc::new",
    "String::new",
    "HashMap::new",
    "Box::new",
    "Mutex::new",
];

/// Unknown function names (should NOT match)
const UNKNOWN_FUNCTIONS: &[&str] = &[
    "unknown_function_xyz",
    "_ZN9unknown_crate9SomeType10some_method",
    "my_custom_allocator",
    "internal_helper",
    "process_data",
    "handle_request",
    "validate_input",
    "transform_output",
];

// ============================================================================
// Test Data: Function info for cross-function analysis benchmarks
// ============================================================================

/// Creates a simple function info for benchmarking.
///
/// Uses `PointerContract::Owned` as a default contract for test data.
fn create_function_info(name: &str, id: u64) -> FunctionInfo {
    FunctionInfo {
        name: name.to_string(),
        id,
        param_types: vec![
            ParamInfo {
                position: 0,
                name: "ptr".to_string(),
                is_pointer: true,
                is_reference: false,
                is_const: false,
                family: Some(FamilyId::C_HEAP),
                contract: PointerContract::Owned,
            },
            ParamInfo {
                position: 1,
                name: "size".to_string(),
                is_pointer: false,
                is_reference: false,
                is_const: true,
                family: None,
                contract: PointerContract::Borrowed,
            },
        ],
        return_type: Some(ReturnInfo {
            is_pointer: true,
            family: Some(FamilyId::C_HEAP),
            contract: PointerContract::Owned,
            is_new_allocation: true,
        }),
        is_external: false,
        is_library: false,
    }
}

/// Creates a list of function infos for benchmarking.
///
/// Alternates between malloc/free/realloc/calloc wrapper patterns
/// to simulate realistic function registries.
fn create_function_infos(count: usize) -> Vec<FunctionInfo> {
    (0..count)
        .map(|i| {
            let name = match i % 4 {
                0 => format!("malloc_wrapper_{i}"),
                1 => format!("free_wrapper_{i}"),
                2 => format!("realloc_wrapper_{i}"),
                3 => format!("calloc_wrapper_{i}"),
                _ => unreachable!(),
            };
            create_function_info(&name, i as u64)
        })
        .collect()
}

// ============================================================================
// Benchmark: Language Detection Performance
// ============================================================================

/// Objective: Measure language detection performance from function names.
/// Invariants: Detection should complete in < 1µs per function name.
fn bench_language_detection_from_function(c: &mut Criterion) {
    let mut group = c.benchmark_group("language_detection");
    group.sample_size(100);

    let detector = LanguageDetector::new();

    // Benchmark Rust function detection
    group.bench_function("rust_functions", |b| {
        b.iter(|| {
            for name in RUST_FUNCTION_NAMES {
                let lang = detector.detect_from_function(black_box(name));
                black_box(lang);
            }
        })
    });

    // Benchmark C++ function detection
    group.bench_function("cpp_functions", |b| {
        b.iter(|| {
            for name in CPP_FUNCTION_NAMES {
                let lang = detector.detect_from_function(black_box(name));
                black_box(lang);
            }
        })
    });

    // Benchmark Go function detection
    group.bench_function("go_functions", |b| {
        b.iter(|| {
            for name in GO_FUNCTION_NAMES {
                let lang = detector.detect_from_function(black_box(name));
                black_box(lang);
            }
        })
    });

    // Benchmark Python function detection
    group.bench_function("python_functions", |b| {
        b.iter(|| {
            for name in PYTHON_FUNCTION_NAMES {
                let lang = detector.detect_from_function(black_box(name));
                black_box(lang);
            }
        })
    });

    // Benchmark C function detection
    group.bench_function("c_functions", |b| {
        b.iter(|| {
            for name in C_FUNCTION_NAMES {
                let lang = detector.detect_from_function(black_box(name));
                black_box(lang);
            }
        })
    });

    // Benchmark Zig function detection
    group.bench_function("zig_functions", |b| {
        b.iter(|| {
            for name in ZIG_FUNCTION_NAMES {
                let lang = detector.detect_from_function(black_box(name));
                black_box(lang);
            }
        })
    });

    group.finish();
}

/// Objective: Measure language detection performance from module names.
/// Invariants: Detection should complete in < 100ns per module name.
fn bench_language_detection_from_module(c: &mut Criterion) {
    let mut group = c.benchmark_group("language_detection_module");
    group.sample_size(100);

    let detector = LanguageDetector::new();

    group.bench_function("module_names", |b| {
        b.iter(|| {
            for name in MODULE_NAMES {
                let lang = detector.detect_from_module(black_box(name));
                black_box(lang);
            }
        })
    });

    group.finish();
}

/// Objective: Measure language detection from multiple function names (weighted voting).
/// Invariants: Voting should complete in < 10µs for 100 functions.
fn bench_language_detection_weighted_voting(c: &mut Criterion) {
    let mut group = c.benchmark_group("language_detection_voting");
    group.sample_size(50);

    let detector = LanguageDetector::new();

    // Create mixed function name lists of varying sizes
    for size in [10, 50, 100, 500] {
        let mut names = Vec::with_capacity(size);
        for i in 0..size {
            match i % 5 {
                0 => names.push(RUST_FUNCTION_NAMES[i % RUST_FUNCTION_NAMES.len()]),
                1 => names.push(CPP_FUNCTION_NAMES[i % CPP_FUNCTION_NAMES.len()]),
                2 => names.push(GO_FUNCTION_NAMES[i % GO_FUNCTION_NAMES.len()]),
                3 => names.push(PYTHON_FUNCTION_NAMES[i % PYTHON_FUNCTION_NAMES.len()]),
                4 => names.push(C_FUNCTION_NAMES[i % C_FUNCTION_NAMES.len()]),
                _ => unreachable!(),
            }
        }

        group.bench_with_input(
            BenchmarkId::new("voting", format!("{size}_functions")),
            &names,
            |b, names| {
                b.iter(|| {
                    let lang = detector.detect_from_functions(black_box(names));
                    black_box(lang);
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Benchmark: Surface Classification Performance
// ============================================================================

/// Objective: Measure surface classification performance.
/// Invariants: Classification should complete in < 500ns per function.
fn bench_surface_classification(c: &mut Criterion) {
    let mut group = c.benchmark_group("surface_classification");
    group.sample_size(100);

    let classifier = SurfaceClassifier::new();

    // Test function names with different expected surfaces and languages.
    // (name, language) pairs for realistic classification.
    let test_functions: Vec<(&str, Language)> = vec![
        ("main", Language::Unknown),
        ("my_helper_function", Language::Unknown),
        ("_ZNSt6vectorIiSaIiEEC1Ev", Language::Cpp),
        ("malloc", Language::C),
        ("free", Language::C),
        ("JNI_OnLoad", Language::Java),
        ("PyObject_Malloc", Language::Python),
        ("__rust_alloc", Language::Rust),
        ("drop_in_place", Language::Rust),
        ("unknown_xyz", Language::Unknown),
    ];

    group.bench_function("classify_functions", |b| {
        b.iter(|| {
            for (name, lang) in &test_functions {
                let surface = classifier.classify(black_box(name), *lang, None);
                black_box(surface);
            }
        })
    });

    // Benchmark with varying numbers of functions
    for size in [10, 50, 100, 500] {
        let functions: Vec<(&str, Language)> = (0..size)
            .map(|i| match i % 5 {
                0 => ("my_function", Language::Unknown),
                1 => ("_ZNSt6vectorIiSaIiEEC1Ev", Language::Cpp),
                2 => ("malloc", Language::C),
                3 => ("JNI_OnLoad", Language::Java),
                4 => ("unknown_xyz", Language::Unknown),
                _ => unreachable!(),
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("classify_batch", format!("{size}_functions")),
            &functions,
            |b, functions| {
                b.iter(|| {
                    for (name, lang) in functions {
                        let surface = classifier.classify(black_box(name), *lang, None);
                        black_box(surface);
                    }
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Benchmark: Whitelist Matching Performance
// ============================================================================

/// Objective: Measure whitelist creation performance.
/// Invariants: Whitelist creation should complete in < 10ms.
fn bench_whitelist_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("whitelist_creation");
    group.sample_size(50);

    group.bench_function("new_whitelist", |b| {
        b.iter(|| {
            let whitelist = RustStdlibWhitelist::new();
            black_box(whitelist.len());
        })
    });

    group.finish();
}

/// Objective: Measure whitelist lookup performance (known functions).
/// Invariants: Lookup should complete in < 100ns per function.
fn bench_whitelist_lookup_known(c: &mut Criterion) {
    let mut group = c.benchmark_group("whitelist_lookup");
    group.sample_size(100);

    let whitelist = RustStdlibWhitelist::new();

    group.bench_function("known_functions", |b| {
        b.iter(|| {
            for name in WHITELISTED_FUNCTIONS {
                let is_whitelisted = whitelist.is_whitelisted(black_box(name));
                black_box(is_whitelisted);
            }
        })
    });

    // Benchmark category retrieval for known functions
    group.bench_function("category_retrieval", |b| {
        b.iter(|| {
            for name in WHITELISTED_FUNCTIONS {
                let category = whitelist.get_category(black_box(name));
                black_box(category);
            }
        })
    });

    group.finish();
}

/// Objective: Measure whitelist lookup performance (unknown functions).
/// Invariants: Lookup should complete in < 100ns per function (negative case).
fn bench_whitelist_lookup_unknown(c: &mut Criterion) {
    let mut group = c.benchmark_group("whitelist_lookup_unknown");
    group.sample_size(100);

    let whitelist = RustStdlibWhitelist::new();

    group.bench_function("unknown_functions", |b| {
        b.iter(|| {
            for name in UNKNOWN_FUNCTIONS {
                let is_whitelisted = whitelist.is_whitelisted(black_box(name));
                black_box(is_whitelisted);
            }
        })
    });

    group.finish();
}

/// Objective: Measure trie pattern matching performance.
/// Invariants: Pattern matching should complete in < 200ns per function.
fn bench_whitelist_pattern_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("whitelist_pattern_matching");
    group.sample_size(100);

    let whitelist = RustStdlibWhitelist::new();

    // Test pattern matching with various function name formats
    let pattern_test_cases = vec![
        // Mangled Rust names (should match)
        "_ZN3vec3Vec3new17h1234567890abcdefE",
        "_ZN3arc3Arc3new17habcdef1234567890E",
        // Demangled names (should match)
        "Vec::new",
        "Arc::new",
        "String::from",
        // Unknown patterns (should not match)
        "unknown_function_xyz",
        "_ZN9unknown_crate9SomeType10some_method",
        // Partial matches (should not match)
        "Vec",
        "new",
        "alloc",
    ];

    group.bench_function("pattern_matching", |b| {
        b.iter(|| {
            for name in &pattern_test_cases {
                let matches = whitelist.is_whitelisted(black_box(name));
                black_box(matches);
            }
        })
    });

    // Benchmark with varying numbers of pattern checks
    for size in [10, 50, 100, 500] {
        let names: Vec<&str> = (0..size)
            .map(|i| match i % 4 {
                0 => "_ZN3vec3Vec3new17h1234567890abcdefE",
                1 => "Vec::new",
                2 => "unknown_function_xyz",
                3 => "Vec",
                _ => unreachable!(),
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("pattern_batch", format!("{size}_patterns")),
            &names,
            |b, names| {
                b.iter(|| {
                    for name in names {
                        let matches = whitelist.is_whitelisted(black_box(name));
                        black_box(matches);
                    }
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Benchmark: Cross-function Analysis Performance
// ============================================================================

/// Objective: Measure cross-function tracker creation performance.
/// Invariants: Tracker creation should complete in < 1ms.
fn bench_cross_function_tracker_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cross_function_tracker");
    group.sample_size(50);

    group.bench_function("new_tracker", |b| {
        b.iter(|| {
            let tracker = CrossFunctionTracker::new();
            black_box(&tracker);
        })
    });

    group.finish();
}

/// Objective: Measure function registration performance.
/// Invariants: Registration should complete in < 10µs per function.
fn bench_cross_function_registration(c: &mut Criterion) {
    let mut group = c.benchmark_group("cross_function_registration");
    group.sample_size(50);

    // Benchmark single function registration
    group.bench_function("single_function", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            let func_info = create_function_info("test_function", counter);
            let mut tracker = CrossFunctionTracker::new();
            tracker.add_function(black_box(func_info));
            counter += 1;
            black_box(&tracker);
        })
    });

    // Benchmark batch function registration
    for size in [10, 50, 100, 500] {
        let functions = create_function_infos(size);

        group.bench_with_input(
            BenchmarkId::new("batch_registration", format!("{size}_functions")),
            &functions,
            |b, functions| {
                b.iter(|| {
                    let mut tracker = CrossFunctionTracker::new();
                    for func_info in functions.clone() {
                        tracker.add_function(func_info);
                    }
                    black_box(&tracker);
                })
            },
        );
    }

    group.finish();
}

/// Objective: Measure resource flow tracking performance.
/// Invariants: Flow tracking should complete in < 100µs per flow.
fn bench_cross_function_flow_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("cross_function_flow");
    group.sample_size(50);

    // Benchmark single resource flow addition
    group.bench_function("single_flow", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            let mut tracker = CrossFunctionTracker::new();
            let flow = ResourceFlow {
                from_function: "malloc_wrapper_0".to_string(),
                to_function: "free_wrapper_1".to_string(),
                resource_id: counter,
                family: FamilyId::C_HEAP,
                flow_type: FlowType::ParameterPassing,
                transfers_ownership: true,
                call_site: None,
            };
            tracker.add_flow(black_box(flow));
            counter += 1;
            black_box(&tracker);
        })
    });

    // Benchmark batch flow tracking
    for size in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("batch_flows", format!("{size}_flows")),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut tracker = CrossFunctionTracker::new();
                    let functions = create_function_infos(100);
                    for func_info in functions {
                        tracker.add_function(func_info);
                    }

                    for i in 0..size {
                        let flow = ResourceFlow {
                            from_function: format!("malloc_wrapper_{}", i % 100),
                            to_function: format!("free_wrapper_{}", (i + 1) % 100),
                            resource_id: i as u64,
                            family: FamilyId::C_HEAP,
                            flow_type: FlowType::ParameterPassing,
                            transfers_ownership: true,
                            call_site: None,
                        };
                        tracker.add_flow(flow);
                    }
                    black_box(&tracker);
                })
            },
        );
    }

    group.finish();
}

/// Objective: Measure analysis result generation performance.
/// Invariants: Analysis should complete in < 10ms for 100 functions.
fn bench_cross_function_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("cross_function_analysis");
    group.sample_size(20);

    for size in [10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("analyze", format!("{size}_functions")),
            &size,
            |b, &size| {
                b.iter(|| {
                    let mut tracker = CrossFunctionTracker::new();
                    let functions = create_function_infos(size);
                    for func_info in functions {
                        tracker.add_function(func_info);
                    }

                    // Add call edges between functions
                    for i in 0..size {
                        let from = format!("malloc_wrapper_{}", i % size);
                        let to = format!("free_wrapper_{}", (i + 1) % size);
                        tracker.add_call_edge(&from, &to);
                    }

                    // Add resource flows
                    for i in 0..size {
                        tracker.track_resource_creation(
                            i as u64,
                            &format!("malloc_wrapper_{}", i % size),
                        );
                        tracker.track_resource_release(
                            i as u64,
                            &format!("free_wrapper_{}", (i + 1) % size),
                        );
                    }

                    let result = tracker.analyze();
                    black_box(&result);
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Benchmark: Integrated Performance (End-to-End)
// ============================================================================

/// Objective: Measure end-to-end semantic analysis performance.
/// Invariants: Full analysis should complete in < 50ms for typical inputs.
fn bench_integrated_semantic_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("integrated_analysis");
    group.sample_size(20);

    let detector = LanguageDetector::new();
    let classifier = SurfaceClassifier::new();
    let whitelist = RustStdlibWhitelist::new();

    // Simulate analyzing a typical C++ file with mixed functions
    let typical_functions: Vec<(&str, Language)> = vec![
        ("_ZNSt6vectorIiSaIiEEC1Ev", Language::Cpp),
        ("_ZNSt6vectorIiSaIiEE9push_backERKi", Language::Cpp),
        ("_ZNSt6vectorIiSaIiEED1Ev", Language::Cpp),
        ("malloc", Language::C),
        ("free", Language::C),
        ("memcpy", Language::C),
        ("my_custom_allocator", Language::Unknown),
        ("process_data", Language::Unknown),
        ("JNI_OnLoad", Language::Java),
        ("unknown_helper", Language::Unknown),
    ];

    group.bench_function("typical_cpp_file", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(typical_functions.len());

            for (name, expected_lang) in &typical_functions {
                // Step 1: Language detection
                let lang = detector.detect_from_function(black_box(name));
                let effective_lang = if lang == Language::Unknown {
                    *expected_lang
                } else {
                    lang
                };

                // Step 2: Surface classification
                let surface = classifier.classify(black_box(name), effective_lang, None);

                // Step 3: Whitelist check (for Rust functions)
                let is_whitelisted = if lang == Language::Rust {
                    whitelist.is_whitelisted(black_box(name))
                } else {
                    false
                };

                results.push((lang, surface, is_whitelisted));
            }

            black_box(results);
        })
    });

    // Simulate analyzing a typical Rust file
    let typical_rust_functions: Vec<(&str, Language)> = vec![
        ("_ZN3vec3Vec3new17h1234567890abcdefE", Language::Rust),
        ("_ZN3vec3Vec4push17habcdef1234567890E", Language::Rust),
        ("_ZN3vec3Vec3pop17h9876543210abcdefE", Language::Rust),
        ("_ZN3arc3Arc3new17habcdef1234567890E", Language::Rust),
        ("_ZN3arc3Arc5clone17habcdef9876543210E", Language::Rust),
        ("_ZN6string6String3new17habcdef1234567890E", Language::Rust),
        (
            "_ZN7hashmap7HashMap3new17habcdef1234567890E",
            Language::Rust,
        ),
        ("_ZN5tokio4task5spawn17habcdef1234567890E", Language::Rust),
        ("my_custom_function", Language::Rust),
        ("internal_helper", Language::Rust),
    ];

    group.bench_function("typical_rust_file", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(typical_rust_functions.len());

            for (name, expected_lang) in &typical_rust_functions {
                let lang = detector.detect_from_function(black_box(name));
                let effective_lang = if lang == Language::Unknown {
                    *expected_lang
                } else {
                    lang
                };
                let surface = classifier.classify(black_box(name), effective_lang, None);
                let is_whitelisted = if lang == Language::Rust {
                    whitelist.is_whitelisted(black_box(name))
                } else {
                    false
                };

                results.push((lang, surface, is_whitelisted));
            }

            black_box(results);
        })
    });

    group.finish();
}

// ============================================================================
// Criterion Groups and Main
// ============================================================================

criterion_group!(
    benches,
    bench_language_detection_from_function,
    bench_language_detection_from_module,
    bench_language_detection_weighted_voting,
    bench_surface_classification,
    bench_whitelist_creation,
    bench_whitelist_lookup_known,
    bench_whitelist_lookup_unknown,
    bench_whitelist_pattern_matching,
    bench_cross_function_tracker_creation,
    bench_cross_function_registration,
    bench_cross_function_flow_tracking,
    bench_cross_function_analysis,
    bench_integrated_semantic_analysis,
);
criterion_main!(benches);
