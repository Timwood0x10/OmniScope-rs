//! Real FFI analysis tests with actual bug detection

use omniscope_ir::IRModule;
use std::path::PathBuf;
use tracing::info;

/// Analyze rust_hash.ll for FFI issues
#[test]
fn test_detect_rust_ffi_boundaries() {
    let test_file = PathBuf::from("tests/integration/rust_hash.ll");

    if !test_file.exists() {
        info!("Test file not found: {:?}", test_file);
        return;
    }

    info!(
        "
=== Analyzing rust_hash.ll for FFI boundaries ===
"
    );

    // Parse the IR file
    let module = IRModule::load_from_file(&test_file).expect("Failed to load IR file");

    info!("Functions defined: {}", module.functions.len());
    for name in module.functions.keys() {
        info!("  - {} (defined)", name);
    }

    info!("\nExternal declarations: {}", module.declarations.len());
    for name in module.declarations.keys() {
        info!("  - {} (extern)", name);
    }

    info!("\nCall instructions: {}", module.calls.len());
    for call in &module.calls {
        let status = if call.is_external { "FFI" } else { "internal" };
        info!("  - call to {} ({})", call.callee, status);
    }

    // Find FFI boundaries
    let ffi_calls = module.ffi_boundaries();
    info!("\n✓ FFI boundaries detected: {}", ffi_calls.len());

    // Expected FFI calls
    let expected_ffi = vec!["c_fft_forward", "c_hash"];
    let mut found_count = 0;

    for expected in &expected_ffi {
        let found = ffi_calls.iter().any(|call| call.callee == *expected);
        if found {
            info!("  ✓ Found FFI call to: {}", expected);
            found_count += 1;
        } else {
            info!("  ✗ Missing expected FFI call to: {}", expected);
        }
    }

    assert!(found_count > 0, "Should detect at least one FFI call");
    info!("\n✓ Successfully detected {} FFI boundaries", found_count);
}

/// Analyze all IR files and report FFI issues
#[test]
fn test_analyze_all_ffi_issues() {
    let test_files = vec![
        ("tests/integration/rust_hash.ll", "Rust"),
        ("tests/integration/c_hash_c_bridge.ll", "C"),
        ("tests/integration/cpp_hash.ll", "C++"),
    ];

    info!(
        "
=== FFI Analysis Report ===
"
    );

    let mut total_ffi_calls = 0;
    let mut total_issues = 0;

    for (path, lang) in test_files {
        let test_file = PathBuf::from(path);

        if !test_file.exists() {
            info!("⚠ {} file not found: {}", lang, path);
            continue;
        }

        info!("📄 {} ({})", lang, path);

        match IRModule::load_from_file(&test_file) {
            Ok(module) => {
                let ffi_calls = module.ffi_boundaries();

                info!("  Functions: {}", module.functions.len());
                info!("  Declarations: {}", module.declarations.len());
                info!("  FFI calls: {}", ffi_calls.len());

                // Report FFI calls
                for call in &ffi_calls {
                    info!("    → FFI: {}", call.callee);
                    total_ffi_calls += 1;

                    // Check for dangerous FFI patterns
                    if is_dangerous_ffi(&call.callee) {
                        info!("      ⚠ POTENTIAL ISSUE: Dangerous FFI function");
                        total_issues += 1;
                    }
                }

                info!("");
            }
            Err(e) => {
                info!("  ✗ Failed to parse: {:?}\n", e);
            }
        }
    }

    info!("=== Summary ===");
    info!("Total FFI calls: {}", total_ffi_calls);
    info!("Potential issues: {}", total_issues);

    if total_issues > 0 {
        info!(
            "
⚠ Found {} potential FFI safety issues!",
            total_issues
        );
    } else {
        info!(
            "
✓ No obvious FFI safety issues detected"
        );
    }
}

/// Check if an FFI function is potentially dangerous
fn is_dangerous_ffi(func_name: &str) -> bool {
    let dangerous_patterns = vec![
        "malloc", "free", "realloc", "calloc", "strcpy", "strcat", "sprintf", "vsprintf", "gets",
        "scanf", "fscanf", "memcpy", "memmove",
    ];

    dangerous_patterns.iter().any(|p| func_name.contains(p))
}

/// Test C bridge for memory safety issues
#[test]
fn test_detect_memory_issues() {
    let test_file = PathBuf::from("tests/integration/c_hash_c_bridge.ll");

    if !test_file.exists() {
        info!("Test file not found");
        return;
    }

    info!("\n=== Memory Safety Analysis ===\n");

    let module = IRModule::load_from_file(&test_file).expect("Failed to load");

    // Look for memory-related functions
    let memory_funcs = vec!["malloc", "free", "realloc", "calloc"];

    for call in &module.calls {
        for mem_func in &memory_funcs {
            if call.callee.contains(mem_func) {
                info!("⚠ Memory operation: {}", call.callee);

                // Check for common issues
                if *mem_func == "free" {
                    info!("  → Potential: use-after-free, double-free");
                }
                if *mem_func == "malloc" {
                    info!("  → Potential: memory leak, null dereference");
                }
            }
        }
    }

    info!("\n✓ Memory analysis complete");
}
