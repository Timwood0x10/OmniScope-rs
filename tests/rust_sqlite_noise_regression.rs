//! Regression test for FFI noise reduction on Rust+SQLite mixed projects.
//!
//! Verifies that C library internal functions (sqlite3Malloc, pcache1Free, etc.)
//! are properly suppressed and don't produce false positive borrow_escape,
//! use_after_free, or double_free findings.

use omniscope_ir::IRModule;
use omniscope_pipeline::Pipeline;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Run analysis on a .ll file and return issue counts by kind.
fn analyze_and_count(path: &Path) -> HashMap<String, usize> {
    let module = IRModule::load_from_file(path).expect("Failed to load IR file");
    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_ir_module(module);
    let result = pipeline.run().expect("Pipeline run failed");

    let mut counts: HashMap<String, usize> = HashMap::new();
    for issue in result.issues() {
        let kind = format!("{:?}", issue.kind);
        *counts.entry(kind).or_insert(0) += 1;
    }
    counts
}

#[test]
fn test_rust_sqlite_noise_reduction() {
    // rust_sqlite.ll is an external corpus file — skip if absent.
    let path = PathBuf::from(
        std::env::var("RUST_SQLITE_LL")
            .unwrap_or_else(|_| "../../ffi-demo/output/rust_sqlite.ll".to_string()),
    );
    if !path.exists() {
        eprintln!("Skipping: rust_sqlite.ll not found at {:?}", path);
        return;
    }

    let counts = analyze_and_count(&path);

    let borrow_escape = counts.get("BorrowEscape").copied().unwrap_or(0);
    let use_after_free = counts.get("UseAfterFree").copied().unwrap_or(0);
    let double_free = counts.get("DoubleFree").copied().unwrap_or(0);
    let invalid_free = counts.get("InvalidFree").copied().unwrap_or(0);
    let total: usize = counts.values().sum();

    // Before the fix: 51 borrow_escape, 4 UAF, 1 DF, 1 invalid_free = 57 total
    // After the fix: borrow_escape should be <= 10, UAF/DF/invalid_free == 0
    assert!(
        borrow_escape <= 10,
        "borrow_escape noise too high: {} (expected <= 10)",
        borrow_escape
    );
    assert_eq!(
        use_after_free, 0,
        "use_after_free should be fully suppressed, got {}",
        use_after_free
    );
    assert_eq!(
        double_free, 0,
        "double_free should be fully suppressed, got {}",
        double_free
    );
    assert_eq!(
        invalid_free, 0,
        "invalid_free should be fully suppressed, got {}",
        invalid_free
    );
    assert!(
        total <= 15,
        "total findings too high: {} (expected <= 15)",
        total
    );

    eprintln!("rust_sqlite.ll noise regression: borrow_escape={}, uaf={}, df={}, invalid_free={}, total={}",
        borrow_escape, use_after_free, double_free, invalid_free, total);
}
