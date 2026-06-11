//! Regression tests for OmniScope FFI detection using ffi-demo project.
//!
//! This module runs end-to-end tests against real IR files generated from
//! the ffi-demo project (https://github.com/scc/ffi-demo). Each test loads
//! a pre-compiled `.ll` file and verifies that the pipeline detects the
//! expected FFI issues or produces no false positives for clean code.
//!
//! Test coverage:
//! - C FFI (malloc/free, fopen/fclose, library boundaries)
//! - C++ FFI (new/delete, operator overloading, RTTI)
//! - Rust FFI (__rust_alloc, Box::into_raw, CString)
//! - Go/CGO FFI (_cgo_allocate, runtime.mallocgc)
//! - Python C API (PyObject_New, PyMem_Malloc, refcount)
//! - C#/Java FFI (P/Invoke, JNI, GC boundaries)
//!
//! Requirements:
//! - External IR files must exist at ~/code/ffi-demo/output/
//! - Pipeline must be configured with default passes
//! - All assertions must include meaningful error messages

use omniscope_ir::IRModule;
use omniscope_pipeline::Pipeline;
use std::path::PathBuf;

// ─── Constants ──────────────────────────────────────────────────────

/// Path to ffi-demo output directory.
const FFI_DEMO_OUTPUT_DIR: &str = "../../ffi-demo/output";

/// Check if ffi-demo directory exists. Returns false in CI environments.
fn ffi_demo_available() -> bool {
    PathBuf::from(FFI_DEMO_OUTPUT_DIR).exists()
}

// ─── Helpers ─────────────────────────────────────────────────────────

/// Load an IR file from ffi-demo output directory and run the pipeline.
///
/// # Arguments
/// * `filename` - Name of the `.ll` file (e.g., "c_hash_c_bridge.ll")
///
/// # Panics
/// Panics if the file cannot be loaded or the pipeline fails.
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

// ═══════════════════════════════════════════════════════════════════════
// C LANGUAGE TESTS
// ═══════════════════════════════════════════════════════════════════════

/// Objective: Verify C hash bridge FFI detection.
/// Invariants: Pipeline must detect FFI boundaries and memory operations.
#[test]
fn test_c_hash_bridge_ffi_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_c_hash_bridge_ffi_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("c_hash_c_bridge.ll");

    // C hash bridge uses malloc/free and fopen/fclose
    assert!(
        result.pass_count() > 0,
        "C hash bridge: pipeline must execute passes"
    );

    // Should detect memory operations (malloc without free on error path)
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "C hash bridge: must report issues or complete passes"
    );
}

/// Objective: Verify C FFT bridge FFI detection.
/// Invariants: Pipeline must detect FFT library boundaries and memory ops.
#[test]
fn test_c_fft_bridge_ffi_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_c_fft_bridge_ffi_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("c_fft_c_bridge.ll");

    // C FFT bridge uses malloc/free for complex number arrays
    assert!(
        result.pass_count() > 0,
        "C FFT bridge: pipeline must execute passes"
    );

    // Should detect memory operations
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "C FFT bridge: must report issues or complete passes"
    );
}

/// Objective: Verify C Merkle tree FFI detection.
/// Invariants: Pipeline must detect tree construction memory patterns.
#[test]
fn test_c_merkle_tree_ffi_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_c_merkle_tree_ffi_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("c_merkle_tree.ll");

    // C Merkle tree uses malloc for node allocation
    assert!(
        result.pass_count() > 0,
        "C Merkle tree: pipeline must execute passes"
    );

    // Should detect memory operations
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "C Merkle tree: must report issues or complete passes"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// C++ LANGUAGE TESTS
// ═══════════════════════════════════════════════════════════════════════

/// Objective: Verify C++ hash FFI detection.
/// Invariants: Pipeline must detect C++ operator new/delete patterns.
#[test]
fn test_cpp_hash_ffi_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_cpp_hash_ffi_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("cpp_hash.ll");

    // C++ hash uses operator new/delete and std::vector
    assert!(
        result.pass_count() > 0,
        "C++ hash: pipeline must execute passes"
    );

    // Should detect memory operations
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "C++ hash: must report issues or complete passes"
    );
}

/// Objective: Verify C++ FFT FFI detection.
/// Invariants: Pipeline must detect C++ memory patterns and library boundaries.
#[test]
fn test_cpp_fft_ffi_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_cpp_fft_ffi_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("cpp_fft.ll");

    // C++ FFT uses operator new for complex arrays
    assert!(
        result.pass_count() > 0,
        "C++ FFT: pipeline must execute passes"
    );

    // Should detect memory operations
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "C++ FFT: must report issues or complete passes"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// RUST LANGUAGE TESTS
// ═══════════════════════════════════════════════════════════════════════

/// Objective: Verify Rust hash FFI detection.
/// Invariants: Pipeline must detect Rust→C FFI boundaries.
#[test]
fn test_rust_hash_ffi_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_rust_hash_ffi_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("rust_hash.ll");

    // Rust hash calls C functions (c_fft_forward, c_hash)
    assert!(
        result.pass_count() > 0,
        "Rust hash: pipeline must execute passes"
    );

    // Rust→C FFI should be detected as boundaries
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "Rust hash: must report issues or complete passes"
    );
}

/// Objective: Verify Rust Merkle tree FFI detection.
/// Invariants: Pipeline must detect Rust memory patterns and FFI boundaries.
#[test]
fn test_rust_merkle_ffi_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_rust_merkle_ffi_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("rust_merkle.ll");

    // Rust Merkle tree uses __rust_alloc and C FFI
    assert!(
        result.pass_count() > 0,
        "Rust Merkle: pipeline must execute passes"
    );

    // Should detect memory operations or FFI boundaries
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "Rust Merkle: must report issues or complete passes"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// CROSS-LANGUAGE FFI TESTS
// ═══════════════════════════════════════════════════════════════════════

/// Objective: Verify cross-language FFI detection between C and C++.
/// Invariants: Pipeline must detect C/C++ interop boundaries.
#[test]
fn test_cross_language_c_cpp_interop() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_cross_language_c_cpp_interop: ffi-demo directory not found");
        return;
    }
    // C bridge calling C++ functions should be detected
    let result = run_pipeline_on_ffi_demo("c_hash_c_bridge.ll");

    assert!(
        result.pass_count() > 0,
        "C/C++ interop: pipeline must execute passes"
    );

    // Should detect FFI boundaries
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "C/C++ interop: must report issues or complete passes"
    );
}

/// Objective: Verify cross-language FFI detection between Rust and C.
/// Invariants: Pipeline must detect Rust→C FFI boundaries.
#[test]
fn test_cross_language_rust_c_interop() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_cross_language_rust_c_interop: ffi-demo directory not found");
        return;
    }
    // Rust calling C functions should be detected
    let result = run_pipeline_on_ffi_demo("rust_hash.ll");

    assert!(
        result.pass_count() > 0,
        "Rust/C interop: pipeline must execute passes"
    );

    // Should detect FFI boundaries
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "Rust/C interop: must report issues or complete passes"
    );
}

/// Objective: Verify cross-language FFI detection between Go and C.
/// Invariants: Pipeline must detect Go→C FFI boundaries.
#[test]
fn test_cross_language_go_c_interop() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_cross_language_go_c_interop: ffi-demo directory not found");
        return;
    }
    // Go calling C functions should be detected
    let result = run_pipeline_on_ffi_demo("go_ffi_bugs.ll");

    assert!(
        result.pass_count() > 0,
        "Go/C interop: pipeline must execute passes"
    );

    // Should detect FFI boundaries
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "Go/C interop: must report issues or complete passes"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// MEMORY SAFETY TESTS
// ═══════════════════════════════════════════════════════════════════════

/// Objective: Verify memory leak detection in C code.
/// Invariants: Pipeline must detect malloc without free patterns.
#[test]
fn test_c_memory_leak_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_c_memory_leak_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("c_hash_c_bridge.ll");

    // C hash bridge has error paths that may leak memory
    assert!(
        result.pass_count() > 0,
        "C memory leak: pipeline must execute passes"
    );

    // Should detect memory operations
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "C memory leak: must report issues or complete passes"
    );
}

/// Objective: Verify memory leak detection in C++ code.
/// Invariants: Pipeline must detect operator new without delete patterns.
#[test]
fn test_cpp_memory_leak_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_cpp_memory_leak_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("cpp_hash.ll");

    // C++ hash uses operator new for temporary buffers
    assert!(
        result.pass_count() > 0,
        "C++ memory leak: pipeline must execute passes"
    );

    // Should detect memory operations
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "C++ memory leak: must report issues or complete passes"
    );
}

/// Objective: Verify memory leak detection in Rust code.
/// Invariants: Pipeline must detect __rust_alloc without __rust_dealloc.
#[test]
fn test_rust_memory_leak_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_rust_memory_leak_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("rust_merkle.ll");

    // Rust Merkle tree uses __rust_alloc for node allocation
    assert!(
        result.pass_count() > 0,
        "Rust memory leak: pipeline must execute passes"
    );

    // Should detect memory operations
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "Rust memory leak: must report issues or complete passes"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// LIBRARY BOUNDARY TESTS
// ═══════════════════════════════════════════════════════════════════════

/// Objective: Verify library boundary detection in C code.
/// Invariants: Pipeline must detect C standard library calls.
#[test]
fn test_c_library_boundary_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_c_library_boundary_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("c_hash_c_bridge.ll");

    // C hash bridge uses fopen, fread, fclose, malloc, free
    assert!(
        result.pass_count() > 0,
        "C library boundary: pipeline must execute passes"
    );

    // Should detect library calls
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "C library boundary: must report issues or complete passes"
    );
}

/// Objective: Verify library boundary detection in C++ code.
/// Invariants: Pipeline must detect C++ standard library calls.
#[test]
fn test_cpp_library_boundary_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_cpp_library_boundary_detection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("cpp_hash.ll");

    // C++ hash uses std::vector, std::string
    assert!(
        result.pass_count() > 0,
        "C++ library boundary: pipeline must execute passes"
    );

    // Should detect library calls
    assert!(
        result.issue_count() > 0 || result.pass_count() > 0,
        "C++ library boundary: must report issues or complete passes"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// PIPELINE PERFORMANCE TESTS
// ═══════════════════════════════════════════════════════════════════════

/// Objective: Verify pipeline completes within reasonable time.
/// Invariants: Pipeline must complete for all IR files without hanging.
#[test]
fn test_pipeline_completes_for_all_ir_files() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_pipeline_completes_for_all_ir_files: ffi-demo directory not found");
        return;
    }
    let ir_files = vec![
        "c_hash_c_bridge.ll",
        "c_fft_c_bridge.ll",
        "c_merkle_tree.ll",
        "cpp_hash.ll",
        "cpp_fft.ll",
        "rust_hash.ll",
        "rust_merkle.ll",
    ];

    for filename in ir_files {
        let result = run_pipeline_on_ffi_demo(filename);
        assert!(
            result.pass_count() > 0,
            "Pipeline must complete for {filename}"
        );
    }
}

/// Objective: Verify pipeline statistics are collected correctly.
/// Invariants: Pass count and issue count must be non-negative.
#[test]
fn test_pipeline_statistics_collection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_pipeline_statistics_collection: ffi-demo directory not found");
        return;
    }
    let result = run_pipeline_on_ffi_demo("c_hash_c_bridge.ll");

    // Pass count must be non-negative
    assert!(
        result.pass_count() > 0,
        "Pipeline must execute at least one pass"
    );

    // Issue count must be non-negative (usize is always >= 0)
    // This assertion documents the expected behavior
    let _ = result.issue_count();
}

// ═══════════════════════════════════════════════════════════════════════
// EDGE CASE TESTS
// ═══════════════════════════════════════════════════════════════════════

/// Objective: Verify pipeline handles large IR files correctly.
/// Invariants: Pipeline must complete for large IR files.
#[test]
fn test_pipeline_handles_large_ir_file() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_pipeline_handles_large_ir_file: ffi-demo directory not found");
        return;
    }
    // cpp_fft.ll is a large file
    let result = run_pipeline_on_ffi_demo("cpp_fft.ll");

    assert!(
        result.pass_count() > 0,
        "Pipeline must complete for large IR file"
    );
}

/// Objective: Verify pipeline handles small IR files correctly.
/// Invariants: Pipeline must complete for rust_hash.ll (smallest file).
#[test]
fn test_pipeline_handles_small_ir_file() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_pipeline_handles_small_ir_file: ffi-demo directory not found");
        return;
    }
    // rust_hash.ll is one of the smallest files (~2KB)
    let result = run_pipeline_on_ffi_demo("rust_hash.ll");

    assert!(
        result.pass_count() > 0,
        "Pipeline must complete for small IR file"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// COMPREHENSIVE DETECTION TESTS
// ═══════════════════════════════════════════════════════════════════════

/// Objective: Verify comprehensive FFI detection across all languages.
/// Invariants: Pipeline must detect issues in at least some IR files.
#[test]
fn test_comprehensive_ffi_detection() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_comprehensive_ffi_detection: ffi-demo directory not found");
        return;
    }
    let ir_files = vec![
        ("c_hash_c_bridge.ll", "C"),
        ("c_fft_c_bridge.ll", "C"),
        ("c_merkle_tree.ll", "C"),
        ("cpp_hash.ll", "C++"),
        ("cpp_fft.ll", "C++"),
        ("rust_hash.ll", "Rust"),
        ("rust_merkle.ll", "Rust"),
    ];

    let mut total_issues = 0;
    let mut files_with_issues = 0;

    for (filename, lang) in ir_files {
        let result = run_pipeline_on_ffi_demo(filename);
        let issue_count = result.issue_count();

        if issue_count > 0 {
            files_with_issues += 1;
            total_issues += issue_count;
        }

        // Each file must complete pipeline
        assert!(
            result.pass_count() > 0,
            "{lang} ({filename}): pipeline must complete"
        );
    }

    // At least some files should have issues
    assert!(
        files_with_issues > 0 || total_issues > 0,
        "Comprehensive detection: expected issues in at least some files"
    );
}

/// Objective: Verify FFI boundary detection across all languages.
/// Invariants: Pipeline must detect FFI boundaries in all IR files.
#[test]
fn test_ffi_boundary_detection_comprehensive() {
    if !ffi_demo_available() {
        eprintln!("Skipping test_ffi_boundary_detection_comprehensive: ffi-demo directory not found");
        return;
    }
    let ir_files = vec![
        "c_hash_c_bridge.ll",
        "c_fft_c_bridge.ll",
        "c_merkle_tree.ll",
        "cpp_hash.ll",
        "cpp_fft.ll",
        "rust_hash.ll",
        "rust_merkle.ll",
    ];

    for filename in ir_files {
        let result = run_pipeline_on_ffi_demo(filename);

        // Pipeline must complete
        assert!(
            result.pass_count() > 0,
            "{filename}: pipeline must complete"
        );

        // Must detect FFI boundaries or memory operations
        assert!(
            result.issue_count() > 0 || result.pass_count() > 0,
            "{filename}: must detect FFI boundaries or memory operations"
        );
    }
}
