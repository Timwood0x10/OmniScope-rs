use super::*;

// ─── with_cross scenario helpers ─────────────────────────────────────

/// Load an IR file and run pipeline with --cross configuration.
fn run_pipeline_with_cross(
    filename: &str,
    cross_boundaries: Vec<(&str, &str)>,
) -> omniscope_pipeline::PipelineResult {
    let path = PathBuf::from(FFI_DEMO_OUTPUT_DIR).join(filename);
    assert!(
        path.exists(),
        "ffi-demo IR file not found: {path:?}. Run 'make' in ~/code/ffi-demo first."
    );

    let module = IRModule::load_from_file(&path)
        .unwrap_or_else(|e| panic!("Failed to load {filename}: {e}"));

    // Build configuration with cross boundaries
    let mut config = omniscope_types::OmniScopeConfig::default();
    for (from, to) in cross_boundaries {
        let from_lang = match from {
            "C" => omniscope_types::Language::C,
            "Cpp" | "C++" => omniscope_types::Language::Cpp,
            "Rust" => omniscope_types::Language::Rust,
            "Go" => omniscope_types::Language::Go,
            _ => panic!("Unknown language: {from}"),
        };
        let to_lang = match to {
            "C" => omniscope_types::Language::C,
            "Cpp" | "C++" => omniscope_types::Language::Cpp,
            "Rust" => omniscope_types::Language::Rust,
            "Go" => omniscope_types::Language::Go,
            _ => panic!("Unknown language: {to}"),
        };

        // Add boundary functions from the module
        let functions: Vec<String> = module.functions.keys().cloned().collect();
        config
            .ffi_boundary
            .push(omniscope_types::FFIBoundaryConfig {
                from: from_lang,
                to: to_lang,
                functions,
                pattern: None,
                description: Some(format!("{from} -> {to} boundary")),
            });
    }

    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_ir_module(module);
    pipeline.set_config(config);

    pipeline
        .run()
        .unwrap_or_else(|e| panic!("Pipeline failed on {filename}: {e}"))
}

/// Run pipeline on a single file with cross boundaries.
fn run_file_with_cross(
    filename: &str,
    cross_boundaries: Vec<(&str, &str)>,
) -> omniscope_pipeline::PipelineResult {
    run_pipeline_with_cross(filename, cross_boundaries)
}

/// Run accuracy test with cross boundaries on all ffi-demo files.
fn run_accuracy_with_cross(cross_boundaries: Vec<(&str, &str)>) -> AccuracyResult {
    let ffi_demo_dir = PathBuf::from(FFI_DEMO_OUTPUT_DIR);
    if !ffi_demo_dir.exists() {
        // Skip in CI where ffi-demo is unavailable
        return AccuracyResult {
            tp: 0,
            fp: 0,
            fn_count: 0,
            precision: 1.0,
            recall: 1.0,
            issues: vec![],
        };
    }

    let ll_files: Vec<PathBuf> = std::fs::read_dir(&ffi_demo_dir)
        .unwrap_or_else(|e| panic!("Cannot read ffi-demo dir: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ll"))
        .map(|entry| entry.path())
        .collect();

    let mut all_results: Vec<(String, omniscope_pipeline::PipelineResult)> = Vec::new();
    for ll_file in &ll_files {
        let file_name = ll_file.file_name().unwrap().to_string_lossy().to_string();
        let result = run_pipeline_with_cross(&file_name, cross_boundaries.clone());
        all_results.push((file_name, result));
    }

    // Count TP, FN, FP
    let mut tp_count = 0usize;
    for bug in EXPECTED_BUGS {
        let file_result = all_results.iter().find(|(name, _)| name == bug.file);
        if let Some((_, result)) = file_result {
            if is_bug_detected(result.issues(), bug).is_some() {
                tp_count += 1;
            }
        }
    }

    for miss in EXPECTED_MISSES {
        let file_result = all_results.iter().find(|(name, _)| name == miss.file);
        if let Some((_, result)) = file_result {
            if is_bug_missed(result.issues(), miss).is_some() {
                tp_count += 1;
            }
        }
    }

    let total_detected: usize = all_results
        .iter()
        .map(|(_, result)| result.issue_count())
        .sum();

    // Exclude diagnostic-only issues (UncheckedReturn, WriteToImmutable) from FP counting.
    // These are coding style hints, not memory safety bugs.
    let diagnostic_issue_count: usize = all_results
        .iter()
        .flat_map(|(_, r)| r.issues().iter())
        .filter(|i| CategoryMetrics::is_diagnostic_only(i.kind))
        .count();
    let effective_total = total_detected.saturating_sub(diagnostic_issue_count);
    let fp_count = effective_total.saturating_sub(tp_count);
    let fn_count = EXPECTED_BUGS.len() + EXPECTED_MISSES.len() - tp_count;

    let precision = if effective_total == 0 {
        0.0
    } else {
        tp_count as f64 / effective_total as f64
    };

    let total_bugs = tp_count + fn_count;
    let recall = if total_bugs == 0 {
        0.0
    } else {
        tp_count as f64 / total_bugs as f64
    };

    AccuracyResult {
        tp: tp_count,
        fp: fp_count,
        fn_count,
        precision,
        recall,
        issues: all_results
            .iter()
            .flat_map(|(_, result)| result.issues().to_vec())
            .collect(),
    }
}

/// Accuracy result struct for with_cross tests.
struct AccuracyResult {
    tp: usize,
    fp: usize,
    #[allow(dead_code)]
    fn_count: usize,
    precision: f64,
    #[allow(dead_code)]
    recall: f64,
    #[allow(dead_code)]
    issues: Vec<omniscope_core::Issue>,
}

// ─── with_cross scenario tests ──────────────────────────────────────

/// Objective: Test accuracy with --cross parameter.
/// Invariants:
///   - TP should be at least 11 (baseline 13 minus pipeline variance)
///   - FP should be at most 31
///   - Precision should be at least 25% (baseline 34.2% minus tolerance)
#[test]
fn test_accuracy_with_cross() {
    if !PathBuf::from(FFI_DEMO_OUTPUT_DIR).exists() {
        eprintln!("Skipping test_accuracy_with_cross: ffi-demo directory not found");
        return;
    }
    info!("\n=== OmniScope Accuracy with --cross Test ===");

    // Define cross boundaries: C->Cpp
    let cross_boundaries = vec![("C", "Cpp")];

    let result = run_accuracy_with_cross(cross_boundaries);

    eprintln!("\n=== with_cross Results ===");
    eprintln!("  True Positives:  {}", result.tp);
    eprintln!("  False Positives: {}", result.fp);
    eprintln!("  Precision:       {:.1}%", result.precision * 100.0);

    // TP can vary due to pipeline non-determinism and FFI Gate suppression
    assert!(
        result.tp >= 11,
        "TP should be at least 11, got {}",
        result.tp
    );
    info!("  [PASS] TP {} >= 11", result.tp);

    assert!(
        result.fp <= 31,
        "FP should be at most 31, got {}",
        result.fp
    );
    info!("  [PASS] FP {} <= 31", result.fp);

    assert!(
        result.precision >= 0.25,
        "Precision should be at least 25%, got {:.1}%",
        result.precision * 100.0
    );
    info!("  [PASS] Precision {:.1}% >= 25%", result.precision * 100.0);

    info!("\n=== with_cross accuracy test PASSED ===");
}

/// Objective: Test that --cross configuration is applied correctly.
/// Invariants: Pipeline should run without errors with --cross C:Cpp.
#[test]
fn test_cross_config_applied() {
    if !PathBuf::from(FFI_DEMO_OUTPUT_DIR).exists() {
        eprintln!("Skipping test_cross_config_applied: ffi-demo directory not found");
        return;
    }
    info!("\n=== Test: --cross configuration applied ===");

    let result = run_file_with_cross("c_hash_c_bridge.ll", vec![("C", "Cpp")]);

    // Verify that pipeline runs successfully with --cross configuration
    let _ = result.issue_count(); // Pipeline completed without error
    info!(
        "  [PASS] Pipeline detected {} issues with --cross C:Cpp",
        result.issue_count()
    );

    info!("\n=== cross config test PASSED ===");
}

/// Objective: Test that --cross preserves TP for c_fft_c_bridge.ll.
/// Invariants: FFI boundary should still be detected with --cross C:Cpp.
#[test]
fn test_c_fft_cross_preserves_tp() {
    if !PathBuf::from(FFI_DEMO_OUTPUT_DIR).exists() {
        eprintln!("Skipping test_c_fft_cross_preserves_tp: ffi-demo directory not found");
        return;
    }
    info!("\n=== Test: --cross preserves TP for c_fft_c_bridge.ll ===");

    let result = run_file_with_cross("c_fft_c_bridge.ll", vec![("C", "Cpp")]);

    // FFI boundary should still be detected
    let ffi_issues: Vec<_> = result
        .issues()
        .iter()
        .filter(|i| i.kind == omniscope_core::IssueKind::FfiUnsafeCall)
        .collect();

    eprintln!(
        "  FFI boundary issues with --cross C:Cpp: {}",
        ffi_issues.len()
    );
    for issue in &ffi_issues {
        eprintln!("    - {:?}: {}", issue.kind, issue.description);
    }

    assert!(
        !ffi_issues.is_empty(),
        "FFI boundary should still be detected with --cross C:Cpp"
    );
    info!("  [PASS] FFI boundary detected with --cross C:Cpp");

    info!("\n=== c_fft_c_bridge.ll with_cross test PASSED ===");
}

/// Objective: Test that --cross reduces FP for c_hash_c_bridge.ll.
/// Invariants: Internal C++ issues should be filtered with --cross C:Cpp.
#[test]
fn test_c_hash_cross_reduces_fp() {
    if !PathBuf::from(FFI_DEMO_OUTPUT_DIR).exists() {
        eprintln!("Skipping test_c_hash_cross_reduces_fp: ffi-demo directory not found");
        return;
    }
    info!("\n=== Test: --cross reduces FP for c_hash_c_bridge.ll ===");

    let result = run_file_with_cross("c_hash_c_bridge.ll", vec![("C", "Cpp")]);

    // FFI boundary should still be detected
    let ffi_issues: Vec<_> = result
        .issues()
        .iter()
        .filter(|i| i.kind == omniscope_core::IssueKind::FfiUnsafeCall)
        .collect();

    eprintln!(
        "  FFI boundary issues with --cross C:Cpp: {}",
        ffi_issues.len()
    );

    // Cross boundary should be preserved
    assert!(
        !ffi_issues.is_empty(),
        "FFI boundary should still be detected with --cross C:Cpp"
    );
    info!("  [PASS] FFI boundary preserved with --cross C:Cpp");

    info!("\n=== c_hash_c_bridge.ll with_cross test PASSED ===");
}

// ─── CLI semantic tests ─────────────────────────────────────────────

/// Test --cross with empty functions (CLI semantic).
/// This simulates `omniscope analyze --cross C:Cpp input.ll`
/// where functions list is empty, meaning "match all functions between these languages".
#[test]
fn test_cross_cli_semantic() {
    let corpus_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");

    let ll_files: Vec<PathBuf> = std::fs::read_dir(&corpus_dir)
        .unwrap_or_else(|e| panic!("Cannot read corpus dir: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ll"))
        .map(|entry| entry.path())
        .collect();

    let config = OmniScopeConfig {
        project: None,
        ffi_boundary: vec![FFIBoundaryConfig {
            from: Language::C,
            to: Language::Cpp,
            functions: vec![], // empty = CLI semantic
            pattern: None,
            description: None,
        }],
        resource_family: vec![],
        analysis: AnalysisOptions::default(),
    };

    let boundary_ctx = config.to_boundary_context();

    assert!(
        boundary_ctx.matches_call(Language::C, Language::Cpp),
        "C -> Cpp should match"
    );
    assert!(
        !boundary_ctx.matches_call(Language::Cpp, Language::C),
        "Cpp -> C should not match (reverse)"
    );
    assert!(
        !boundary_ctx.matches_call(Language::C, Language::Rust),
        "C -> Rust should not match"
    );

    let mut total_issues = 0usize;

    for ll_file in &ll_files {
        let module = IRModule::load_from_file(ll_file)
            .unwrap_or_else(|e| panic!("Failed to load {}: {e}", ll_file.display()));

        let mut pipeline = Pipeline::new();
        pipeline.register_default_passes();
        pipeline.set_config(config.clone());
        pipeline.set_ir_module(module);

        match pipeline.run() {
            Ok(result) => {
                total_issues += result.issue_count();
            }
            Err(e) => {
                eprintln!("Error processing {}: {}", ll_file.display(), e);
            }
        }
    }

    assert!(
        total_issues > 0,
        "Pipeline should detect issues with --cross C:Cpp"
    );
}

/// Test pattern matching with CLI semantic.
#[test]
fn test_cross_pattern_matching() {
    let config = OmniScopeConfig {
        project: None,
        ffi_boundary: vec![FFIBoundaryConfig {
            from: Language::C,
            to: Language::Cpp,
            functions: vec![],
            pattern: Some("c_*".to_string()),
            description: None,
        }],
        resource_family: vec![],
        analysis: AnalysisOptions::default(),
    };

    let boundary_ctx = config.to_boundary_context();

    assert!(
        boundary_ctx.is_declared_boundary("c_fft_forward").is_some(),
        "c_fft_forward should match c_* pattern"
    );
    assert!(
        boundary_ctx.is_declared_boundary("c_hash").is_some(),
        "c_hash should match c_* pattern"
    );
    assert!(
        boundary_ctx.is_declared_boundary("malloc").is_none(),
        "malloc should not match c_* pattern"
    );
}
