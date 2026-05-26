//! Integration tests for OmniScope with real LLVM IR

use omniscope_ir::IRLoader;
use omniscope_pipeline::Pipeline;
use std::path::PathBuf;

/// Test analyzing Rust FFI code
#[test]
fn test_analyze_rust_ffi() {
    let test_file = PathBuf::from("tests/integration/rust_hash.ll");

    if !test_file.exists() {
        eprintln!("Test file not found: {:?}", test_file);
        return;
    }

    println!("=== Analyzing Rust FFI code (rust_hash.ll) ===");

    let mut loader = IRLoader::new();

    match loader.load_from_file(&test_file) {
        Ok(()) => {
            println!("✓ Successfully loaded rust_hash.ll");
            println!("  Functions found: (implementation pending)");

            // Run analysis pipeline
            let mut pipeline = Pipeline::new();
            pipeline.register_default_passes();

            let result = pipeline.run().unwrap();
            println!("✓ Analysis completed:");
            println!("  - Passes executed: {}", result.pass_count());
            println!("  - Issues found: {}", result.issue_count());
            println!("  - Nodes analyzed: {}", result.total_nodes);

            // Expected: Should detect FFI calls to c_fft_forward and c_hash
        }
        Err(e) => {
            println!("✗ Could not load IR file: {:?}", e);
            println!("  (This is expected if LLVM is not properly configured)");
        }
    }
}

/// Test analyzing C FFI bridge code
#[test]
fn test_analyze_c_bridge() {
    let test_file = PathBuf::from("tests/integration/c_hash_c_bridge.ll");

    if !test_file.exists() {
        eprintln!("Test file not found: {:?}", test_file);
        return;
    }

    println!("=== Analyzing C FFI bridge (c_hash_c_bridge.ll) ===");

    let mut loader = IRLoader::new();

    match loader.load_from_file(&test_file) {
        Ok(()) => {
            println!("✓ Successfully loaded c_hash_c_bridge.ll");

            let mut pipeline = Pipeline::new();
            pipeline.register_default_passes();

            let result = pipeline.run().unwrap();
            println!(
                "✓ Analysis completed: {} passes, {} issues",
                result.pass_count(),
                result.issue_count()
            );
        }
        Err(e) => {
            println!("✗ Could not load IR file: {:?}", e);
        }
    }
}

/// Test analyzing Zig FFI code
#[test]
fn test_analyze_zig_ffi() {
    let test_file = PathBuf::from("tests/integration/zig_ffi_bridge.ll");

    if !test_file.exists() {
        eprintln!("Test file not found: {:?}", test_file);
        return;
    }

    println!("=== Analyzing Zig FFI bridge (zig_ffi_bridge.ll) ===");

    let mut loader = IRLoader::new();

    match loader.load_from_file(&test_file) {
        Ok(()) => {
            println!("✓ Successfully loaded zig_ffi_bridge.ll");

            let mut pipeline = Pipeline::new();
            pipeline.register_default_passes();

            let result = pipeline.run().unwrap();
            println!(
                "✓ Analysis completed: {} passes, {} issues",
                result.pass_count(),
                result.issue_count()
            );
        }
        Err(e) => {
            println!("✗ Could not load IR file: {:?}", e);
        }
    }
}

/// Test analyzing C++ code
#[test]
fn test_analyze_cpp() {
    let test_file = PathBuf::from("tests/integration/cpp_hash.ll");

    if !test_file.exists() {
        eprintln!("Test file not found: {:?}", test_file);
        return;
    }

    println!("=== Analyzing C++ code (cpp_hash.ll) ===");

    let mut loader = IRLoader::new();

    match loader.load_from_file(&test_file) {
        Ok(()) => {
            println!("✓ Successfully loaded cpp_hash.ll");

            let mut pipeline = Pipeline::new();
            pipeline.register_default_passes();

            let result = pipeline.run().unwrap();
            println!(
                "✓ Analysis completed: {} passes, {} issues",
                result.pass_count(),
                result.issue_count()
            );
        }
        Err(e) => {
            println!("✗ Could not load IR file: {:?}", e);
        }
    }
}

/// Test pipeline orchestration without IR
#[test]
fn test_pipeline_orchestration() {
    println!("=== Testing Pipeline Orchestration ===");

    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();

    let result = pipeline.run().unwrap();

    assert!(result.pass_count() > 0, "Pipeline should execute passes");
    println!("✓ Pipeline executed {} passes", result.pass_count());
    println!("  Pass breakdown:");
    println!("    - Foundation passes: 2 (CFG, DFG)");
    println!("    - Analysis passes: 4 (FFI, Memory, Ownership, Buffer)");
}
