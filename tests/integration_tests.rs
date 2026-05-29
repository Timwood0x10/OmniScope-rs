//! Integration tests for OmniScope with real LLVM IR

use omniscope_ir::IRLoader;
use omniscope_pipeline::Pipeline;
use std::path::PathBuf;

/// Test analyzing Rust FFI code
#[test]
fn test_analyze_rust_ffi() {
    let test_file = PathBuf::from("tests/integration/rust_hash.ll");
    assert!(
        test_file.exists(),
        "Test file not found: {:?} - integration test fixtures must be present",
        test_file
    );

    eprintln!("=== Analyzing Rust FFI code (rust_hash.ll) ===");

    let mut loader = IRLoader::new();

    match loader.load_from_file(&test_file) {
        Ok(()) => {
            eprintln!("Successfully loaded rust_hash.ll");

            // Run analysis pipeline
            let mut pipeline = Pipeline::new();
            pipeline.register_default_passes();

            let result = pipeline.run().unwrap();
            assert!(
                result.pass_count() > 0,
                "Pipeline should execute at least one pass on rust_hash.ll"
            );

            // Expected: Should detect FFI calls to c_fft_forward and c_hash
        }
        Err(e) => {
            panic!("Could not load IR file {:?}: {:?}", test_file, e);
        }
    }
}

/// Test analyzing C FFI bridge code
#[test]
fn test_analyze_c_bridge() {
    let test_file = PathBuf::from("tests/integration/c_hash_c_bridge.ll");
    assert!(
        test_file.exists(),
        "Test file not found: {:?} - integration test fixtures must be present",
        test_file
    );

    eprintln!("=== Analyzing C FFI bridge (c_hash_c_bridge.ll) ===");

    let mut loader = IRLoader::new();

    match loader.load_from_file(&test_file) {
        Ok(()) => {
            let mut pipeline = Pipeline::new();
            pipeline.register_default_passes();

            let result = pipeline.run().unwrap();
            assert!(
                result.pass_count() > 0,
                "Pipeline should execute at least one pass on c_hash_c_bridge.ll"
            );
        }
        Err(e) => {
            panic!("Could not load IR file {:?}: {:?}", test_file, e);
        }
    }
}

/// Test analyzing Zig FFI code
#[test]
fn test_analyze_zig_ffi() {
    let test_file = PathBuf::from("tests/integration/zig_ffi_bridge.ll");
    assert!(
        test_file.exists(),
        "Test file not found: {:?} - integration test fixtures must be present",
        test_file
    );

    eprintln!("=== Analyzing Zig FFI bridge (zig_ffi_bridge.ll) ===");

    let mut loader = IRLoader::new();

    match loader.load_from_file(&test_file) {
        Ok(()) => {
            let mut pipeline = Pipeline::new();
            pipeline.register_default_passes();

            let result = pipeline.run().unwrap();
            assert!(
                result.pass_count() > 0,
                "Pipeline should execute at least one pass on zig_ffi_bridge.ll"
            );
        }
        Err(e) => {
            panic!("Could not load IR file {:?}: {:?}", test_file, e);
        }
    }
}

/// Test analyzing C++ code
#[test]
fn test_analyze_cpp() {
    let test_file = PathBuf::from("tests/integration/cpp_hash.ll");
    assert!(
        test_file.exists(),
        "Test file not found: {:?} - integration test fixtures must be present",
        test_file
    );

    eprintln!("=== Analyzing C++ code (cpp_hash.ll) ===");

    let mut loader = IRLoader::new();

    match loader.load_from_file(&test_file) {
        Ok(()) => {
            let mut pipeline = Pipeline::new();
            pipeline.register_default_passes();

            let result = pipeline.run().unwrap();
            assert!(
                result.pass_count() > 0,
                "Pipeline should execute at least one pass on cpp_hash.ll"
            );
        }
        Err(e) => {
            panic!("Could not load IR file {:?}: {:?}", test_file, e);
        }
    }
}

/// Test pipeline orchestration without IR
#[test]
fn test_pipeline_orchestration() {
    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();

    let result = pipeline.run().unwrap();

    assert!(
        result.pass_count() > 0,
        "Pipeline should execute at least one pass"
    );
}
