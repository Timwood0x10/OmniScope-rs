//! Debug test to dump all calls from c_fft_c_bridge.ll and c_hash_c_bridge.ll
//! This helps identify why FfiUnsafeCall detections are missing for these functions.

use omniscope_ir::IRModule;
use std::path::PathBuf;

#[test]
fn dump_calls_from_c_fft_c_bridge() {
    let path = PathBuf::from("../../ffi-demo/output/c_fft_c_bridge.ll");
    assert!(path.exists(), "c_fft_c_bridge.ll not found at {:?}", path);

    let module = IRModule::load_from_file(&path)
        .unwrap_or_else(|e| panic!("Failed to load c_fft_c_bridge.ll: {}", e));

    println!("\n=== c_fft_c_bridge.ll ===");
    println!("Functions: {}", module.functions.len());
    println!("Declarations: {}", module.declarations.len());
    println!("Calls: {}", module.calls.len());

    // Check what assess_ffi_safety returns
    println!("\n--- FFI Safety Assessment for c_fft_forward ---");
    let fft_forward_calls: Vec<_> = module
        .calls
        .iter()
        .filter(|c| c.caller == "c_fft_forward" && c.callee.contains("_Z"))
        .collect();
    for call in &fft_forward_calls {
        let callee_name = call.callee.trim_start_matches('@');
        let caller_name = call.caller.trim_start_matches('@');

        let assessment = omniscope_semantics::assess_ffi_safety(callee_name, caller_name, &module);
        println!(
            "  callee={:?} caller={:?} verdict={:?} should_suppress={}",
            callee_name,
            caller_name,
            assessment.verdict,
            assessment.should_suppress_issue()
        );
        println!("  evidence: {:?}", assessment.evidence);
    }

    println!("\n--- FFI Safety Assessment for c_fft_test_signal ---");
    let test_signal_calls: Vec<_> = module
        .calls
        .iter()
        .filter(|c| c.caller == "c_fft_test_signal" && c.callee.contains("_Z"))
        .collect();
    for call in &test_signal_calls {
        let callee_name = call.callee.trim_start_matches('@');
        let caller_name = call.caller.trim_start_matches('@');

        let assessment = omniscope_semantics::assess_ffi_safety(callee_name, caller_name, &module);
        println!(
            "  callee={:?} caller={:?} verdict={:?} should_suppress={}",
            callee_name,
            caller_name,
            assessment.verdict,
            assessment.should_suppress_issue()
        );
        println!("  evidence: {:?}", assessment.evidence);
    }

    // Check function bodies
    println!("\n--- Function Bodies ---");
    for (name, body) in &module.function_bodies {
        println!("  {}: {} instructions", name, body.instructions.len());
    }

    assert!(
        !module.calls.is_empty(),
        "No calls found in c_fft_c_bridge.ll"
    );
}

#[test]
fn dump_calls_from_c_hash_c_bridge() {
    let path = PathBuf::from("../../ffi-demo/output/c_hash_c_bridge.ll");
    assert!(path.exists(), "c_hash_c_bridge.ll not found at {:?}", path);

    let module = IRModule::load_from_file(&path)
        .unwrap_or_else(|e| panic!("Failed to load c_hash_c_bridge.ll: {}", e));

    println!("\n=== c_hash_c_bridge.ll ===");
    println!("Functions: {}", module.functions.len());
    println!("Declarations: {}", module.declarations.len());
    println!("Calls: {}", module.calls.len());

    // Check what assess_ffi_safety returns
    println!("\n--- FFI Safety Assessment for c_hash ---");
    let hash_calls: Vec<_> = module
        .calls
        .iter()
        .filter(|c| c.caller == "c_hash" && c.callee.contains("_Z"))
        .collect();
    for call in &hash_calls {
        let callee_name = call.callee.trim_start_matches('@');
        let caller_name = call.caller.trim_start_matches('@');

        let assessment = omniscope_semantics::assess_ffi_safety(callee_name, caller_name, &module);
        println!(
            "  callee={:?} caller={:?} verdict={:?} should_suppress={}",
            callee_name,
            caller_name,
            assessment.verdict,
            assessment.should_suppress_issue()
        );
        println!("  evidence: {:?}", assessment.evidence);
    }

    // Check function bodies
    println!("\n--- Function Bodies ---");
    for (name, body) in &module.function_bodies {
        println!("  {}: {} instructions", name, body.instructions.len());
    }

    assert!(
        !module.calls.is_empty(),
        "No calls found in c_hash_c_bridge.ll"
    );
}
