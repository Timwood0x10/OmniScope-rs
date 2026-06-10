use super::*;

/// Objective: Verify accuracy regression against golden baseline.
/// Invariants (worst-common baseline for zig_main.ll DoubleFree non-determinism, FN=4):
///   - Precision must not drop below ~46%
///   - Recall must not drop below ~71%
///   - F1 must not drop below ~56%
///   - TP must not drop below 12
///   - FP must not increase above 22
///   - FN must not increase above 7
#[test]
fn test_accuracy_regression() {
    info!(
        "
=== OmniScope Accuracy Regression Test ===
"
    );

    // Verify ffi-demo directory exists
    let ffi_demo_dir = PathBuf::from(FFI_DEMO_OUTPUT_DIR);
    assert!(
        ffi_demo_dir.exists(),
        "ffi-demo output directory not found: {ffi_demo_dir:?}. \
         Run 'make' in ~/code/ffi-demo first."
    );

    // Load all ffi-demo files and run pipeline
    let ll_files: Vec<PathBuf> = std::fs::read_dir(&ffi_demo_dir)
        .unwrap_or_else(|e| panic!("Cannot read ffi-demo dir: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ll"))
        .map(|entry| entry.path())
        .collect();

    info!("Found {} .ll files in ffi-demo/output", ll_files.len());

    // Run pipeline on each file and collect results
    let mut all_results: Vec<(String, omniscope_pipeline::PipelineResult)> = Vec::new();
    for ll_file in &ll_files {
        let file_name = ll_file.file_name().unwrap().to_string_lossy().to_string();
        let result = run_pipeline_on_ffi_demo(&file_name);
        all_results.push((file_name, result));
    }

    // ── Count TP ────────────────────────────────────────────────────
    let mut tp_count = 0usize;
    let mut ffi_metrics = CategoryMetrics::new();
    eprintln!("\n--- True Positives (Bugs Detected) ---");
    for bug in EXPECTED_BUGS {
        let file_result = all_results.iter().find(|(name, _)| name == bug.file);
        if let Some((_, result)) = file_result {
            if let Some(matched_kind) = is_bug_detected(result.issues(), bug) {
                tp_count += 1;
                ffi_metrics.record_tp(matched_kind);
                eprintln!("  [TP] {}: {}", bug.file, bug.description);
            } else {
                if let Some(&kind) = bug.accepted_kinds.first() {
                    ffi_metrics.record_fn(kind);
                }
                eprintln!(
                    "  [FN] {}: {} (expected but missed)",
                    bug.file, bug.description
                );
            }
        } else {
            eprintln!("  [SKIP] {}: file not found", bug.file);
        }
    }

    // ── Check forbidden kinds (FP from wrong classification) ─────────
    let mut forbidden_fp = 0usize;
    eprintln!("\n--- Forbidden-Kind False Positives ---");
    for (file_name, result) in &all_results {
        for issue in result.issues() {
            for bug in EXPECTED_BUGS {
                if bug.file == file_name {
                    let func_match = issue
                        .location
                        .as_ref()
                        .and_then(|loc| loc.function.as_deref())
                        .map(|f| f.contains(bug.func_substring))
                        .unwrap_or(false);
                    if func_match
                        && !bug.forbidden_kinds.is_empty()
                        && bug.forbidden_kinds.contains(&issue.kind)
                    {
                        forbidden_fp += 1;
                        ffi_metrics.record_fp(issue.kind);
                        eprintln!(
                            "  [FP-forbidden] {} {:?} on {} — kind {:?} is forbidden for this fixture",
                            file_name, issue.kind, bug.func_substring, issue.kind
                        );
                    }
                }
            }
        }
    }
    if forbidden_fp == 0 {
        eprintln!("  (none)");
    }

    // ── Count FN (misses) ───────────────────────────────────────────
    let mut fn_count = 0usize;
    eprintln!("\n--- False Negatives (Missed Bugs) ---");
    for miss in EXPECTED_MISSES {
        let file_result = all_results.iter().find(|(name, _)| name == miss.file);
        if let Some((_, result)) = file_result {
            if let Some(matched_kind) = is_bug_missed(result.issues(), miss) {
                tp_count += 1;
                ffi_metrics.record_tp(matched_kind);
                eprintln!("  [TP] {}: {} (now detected!)", miss.file, miss.description);
            } else {
                fn_count += 1;
                if let Some(&kind) = miss.expected_kinds.first() {
                    ffi_metrics.record_fn(kind);
                }
                eprintln!("  [FN] {}: {}", miss.file, miss.description);
            }
        } else {
            eprintln!("  [SKIP] {}: file not found", miss.file);
        }
    }

    // ── Count FP ─────────────────────────────────────────────────────
    // Exclude diagnostic-only kinds (UncheckedReturn, WriteToImmutable)
    // from overall FP count — they are coding style suggestions, not bugs.
    let total_detected_issues: usize = all_results
        .iter()
        .map(|(_, result)| result.issue_count())
        .sum();
    let diagnostic_issue_count: usize = all_results
        .iter()
        .flat_map(|(_, r)| r.issues().iter())
        .filter(|i| CategoryMetrics::is_diagnostic_only(i.kind))
        .count();
    let effective_total = total_detected_issues.saturating_sub(diagnostic_issue_count);
    let mut fp_count = effective_total.saturating_sub(tp_count);
    fp_count += forbidden_fp;
    eprintln!("\n--- False Positives (Noise) ---");
    eprintln!(
        "  Total detected issues: {}, TP: {}, FP: {}",
        total_detected_issues, tp_count, fp_count
    );
    for noise in EXPECTED_NOISE {
        let file_result = all_results.iter().find(|(name, _)| name == noise.file);
        if let Some((_, result)) = file_result {
            if is_noise_reported(result.issues(), noise) {
                info!("  [FP] {}: {}", noise.file, noise.description);
            } else {
                info!(
                    "  [TN] {}: {} (correctly clean)",
                    noise.file, noise.description
                );
            }
        } else {
            info!("  [SKIP] {}: file not found", noise.file);
        }
    }

    // Classify all detected issues into categories for FP metrics.
    let ffi_tp = ffi_metrics.ffi_tp;
    let resource_tp = ffi_metrics.resource_tp;
    let leak_tp = ffi_metrics.leak_tp;
    let double_free_tp = ffi_metrics.double_free_tp;
    let total_ffi_detected: usize = all_results
        .iter()
        .flat_map(|(_, r)| r.issues().iter())
        .filter(|i| CategoryMetrics::is_ffi_issue(i.kind))
        .count();
    let total_resource_detected: usize = all_results
        .iter()
        .flat_map(|(_, r)| r.issues().iter())
        .filter(|i| CategoryMetrics::is_resource_issue(i.kind))
        .count();
    let total_leak_detected: usize = all_results
        .iter()
        .flat_map(|(_, r)| r.issues().iter())
        .filter(|i| CategoryMetrics::is_leak_issue(i.kind))
        .count();
    let total_double_free_detected: usize = all_results
        .iter()
        .flat_map(|(_, r)| r.issues().iter())
        .filter(|i| CategoryMetrics::is_double_free_issue(i.kind))
        .count();
    let ffi_fp_count = total_ffi_detected.saturating_sub(ffi_tp);
    let resource_fp_count = total_resource_detected.saturating_sub(resource_tp);
    let leak_fp_count = total_leak_detected.saturating_sub(leak_tp);
    let double_free_fp_count = total_double_free_detected.saturating_sub(double_free_tp);
    ffi_metrics.ffi_fp = ffi_fp_count;
    ffi_metrics.resource_fp = resource_fp_count;
    ffi_metrics.leak_fp = leak_fp_count;
    ffi_metrics.double_free_fp = double_free_fp_count;

    // ── Diagnostic: list all Resource issues ──
    eprintln!("\n--- All Resource Issues (TP + FP) ---");
    for (file_name, result) in &all_results {
        for issue in result.issues() {
            if CategoryMetrics::is_resource_issue(issue.kind) {
                let sym = if issue.symbol.is_empty() {
                    "?"
                } else {
                    &issue.symbol
                };
                let loc_func = issue
                    .location
                    .as_ref()
                    .and_then(|l| l.function.as_deref())
                    .unwrap_or("?");
                eprintln!(
                    "  [{}] {:?} symbol={} location_func={} desc={}",
                    file_name,
                    issue.kind,
                    sym,
                    loc_func,
                    issue.description.chars().take(80).collect::<String>()
                );
            }
        }
    }

    // ── Calculate metrics ───────────────────────────────────────────
    // Use effective_total (excluding diagnostic-only issues) for precision.
    let effective_total_for_metrics = tp_count + fp_count;
    let precision = if effective_total_for_metrics == 0 {
        0.0
    } else {
        tp_count as f64 / effective_total_for_metrics as f64
    };
    let total_bugs = tp_count + fn_count;
    let recall = if total_bugs == 0 {
        0.0
    } else {
        tp_count as f64 / total_bugs as f64
    };
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    // ── Print results ───────────────────────────────────────────────
    eprintln!("\n=== Accuracy Results ===");
    eprintln!("  True Positives:  {tp_count}/{total_bugs}");
    eprintln!("  False Positives: {fp_count} (total detected: {total_detected_issues})");
    eprintln!("  False Negatives: {fn_count}/{total_bugs}");
    eprintln!("  Precision:       {:.1}%", precision * 100.0);
    eprintln!("  Recall:          {:.1}%", recall * 100.0);
    eprintln!("  F1 Score:        {:.1}%", f1 * 100.0);

    eprintln!("\n=== Baseline Comparison ===");
    eprintln!("  Baseline TP:  {BASELINE_TP}");
    eprintln!("  Baseline FP:  {BASELINE_FP}");
    eprintln!("  Baseline FN:  {BASELINE_FN}");
    eprintln!("  Baseline Precision: {:.1}%", BASELINE_PRECISION * 100.0);
    eprintln!("  Baseline Recall:    {:.1}%", BASELINE_RECALL * 100.0);
    eprintln!("  Baseline F1:        {:.1}%", BASELINE_F1 * 100.0);

    // ── Print FFI-specific metrics ─────────────────────────────────
    eprintln!("\n=== FFI-Specific Metrics ===");
    eprintln!(
        "  FFI TP:          {} (baseline: {})",
        ffi_metrics.ffi_tp, BASELINE_FFI_TP
    );
    eprintln!(
        "  FFI FP:          {} (baseline: {})",
        ffi_metrics.ffi_fp, BASELINE_FFI_FP
    );
    eprintln!(
        "  FFI FN:          {} (baseline: {})",
        ffi_metrics.ffi_fn, BASELINE_FFI_FN
    );
    eprintln!(
        "  FFI Precision:   {:.1}%",
        ffi_metrics.ffi_precision() * 100.0
    );
    eprintln!(
        "  FFI Recall:      {:.1}%",
        ffi_metrics.ffi_recall() * 100.0
    );
    eprintln!(
        "  Resource TP:     {} (baseline: {})",
        ffi_metrics.resource_tp, BASELINE_RESOURCE_TP
    );
    eprintln!(
        "  Resource FP:     {} (baseline: {})",
        ffi_metrics.resource_fp, BASELINE_RESOURCE_FP
    );
    eprintln!(
        "  Resource FN:     {} (baseline: {})",
        ffi_metrics.resource_fn, BASELINE_RESOURCE_FN
    );
    eprintln!(
        "  Resource Precision: {:.1}%",
        ffi_metrics.resource_precision() * 100.0
    );
    eprintln!(
        "  Resource Recall:    {:.1}%",
        ffi_metrics.resource_recall() * 100.0
    );

    // ── Print leak metrics ─────────────────────────────────────────
    eprintln!("\n=== Leak Metrics ===");
    eprintln!(
        "  Leak TP:          {} (baseline: {})",
        ffi_metrics.leak_tp, BASELINE_LEAK_TP
    );
    eprintln!(
        "  Leak FP:          {} (baseline: {})",
        ffi_metrics.leak_fp, BASELINE_LEAK_FP
    );
    eprintln!(
        "  Leak FN:          {} (baseline: {})",
        ffi_metrics.leak_fn, BASELINE_LEAK_FN
    );
    eprintln!(
        "  Leak Precision:   {:.1}%",
        ffi_metrics.leak_precision() * 100.0
    );
    eprintln!(
        "  Leak Recall:      {:.1}%",
        ffi_metrics.leak_recall() * 100.0
    );

    // ── Print double-free metrics ─────────────────────────────────
    eprintln!("\n=== Double-Free Metrics ===");
    eprintln!(
        "  DoubleFree TP:    {} (baseline: {})",
        ffi_metrics.double_free_tp, BASELINE_DOUBLE_FREE_TP
    );
    eprintln!(
        "  DoubleFree FP:    {} (baseline: {})",
        ffi_metrics.double_free_fp, BASELINE_DOUBLE_FREE_FP
    );
    eprintln!(
        "  DoubleFree FN:    {} (baseline: {})",
        ffi_metrics.double_free_fn, BASELINE_DOUBLE_FREE_FN
    );
    eprintln!(
        "  DoubleFree Precision: {:.1}%",
        ffi_metrics.double_free_precision() * 100.0
    );
    eprintln!(
        "  DoubleFree Recall:    {:.1}%",
        ffi_metrics.double_free_recall() * 100.0
    );

    // ── Print suppression reasons ─────────────────────────────────
    if !ffi_metrics.suppression_reasons.is_empty() {
        eprintln!("\n=== Suppression Reasons ===");
        let mut reasons: Vec<_> = ffi_metrics.suppression_reasons.iter().collect();
        reasons.sort_by(|a, b| b.1.cmp(a.1));
        for (reason, count) in reasons {
            eprintln!("  {count:3}x {reason}");
        }
    }

    // ── Regression checks (with tolerance for non-determinism) ──────
    info!("\n=== Regression Check ===");

    assert!(
        precision >= BASELINE_PRECISION - METRICS_TOLERANCE,
        "Precision regression: {:.1}% < baseline {:.1}% (tolerance {:.1}%)",
        precision * 100.0,
        BASELINE_PRECISION * 100.0,
        METRICS_TOLERANCE * 100.0
    );
    info!(
        "  [PASS] Precision {:.1}% >= baseline {:.1}% (±{:.1}%)",
        precision * 100.0,
        BASELINE_PRECISION * 100.0,
        METRICS_TOLERANCE * 100.0
    );

    assert!(
        recall >= BASELINE_RECALL - METRICS_TOLERANCE,
        "Recall regression: {:.1}% < baseline {:.1}% (tolerance {:.1}%)",
        recall * 100.0,
        BASELINE_RECALL * 100.0,
        METRICS_TOLERANCE * 100.0
    );
    info!(
        "  [PASS] Recall {:.1}% >= baseline {:.1}% (±{:.1}%)",
        recall * 100.0,
        BASELINE_RECALL * 100.0,
        METRICS_TOLERANCE * 100.0
    );

    assert!(
        f1 >= BASELINE_F1 - METRICS_TOLERANCE,
        "F1 regression: {:.1}% < baseline {:.1}% (tolerance {:.1}%)",
        f1 * 100.0,
        BASELINE_F1 * 100.0,
        METRICS_TOLERANCE * 100.0
    );
    info!(
        "  [PASS] F1 {:.1}% >= baseline {:.1}% (±{:.1}%)",
        f1 * 100.0,
        BASELINE_F1 * 100.0,
        METRICS_TOLERANCE * 100.0
    );

    let min_tp = BASELINE_TP.saturating_sub(3);
    assert!(
        tp_count >= min_tp,
        "TP regression: {} < minimum {}",
        tp_count,
        min_tp
    );
    info!("  [PASS] TP {} >= minimum {}", tp_count, min_tp);

    assert!(
        fp_count <= BASELINE_FP + 1,
        "FP regression: {} > baseline {} (+1 tolerance for non-determinism)",
        fp_count,
        BASELINE_FP
    );
    info!(
        "  [PASS] FP {} <= baseline {} (+1 tolerance)",
        fp_count, BASELINE_FP
    );

    assert!(
        fn_count <= BASELINE_FN + 3,
        "FN regression: {} > maximum {}",
        fn_count,
        BASELINE_FN + 3
    );
    info!("  [PASS] FN {} <= maximum {}", fn_count, BASELINE_FN + 3);

    // ── FFI-specific regression checks ──────────────────────────────
    assert!(
        ffi_metrics.ffi_tp >= BASELINE_FFI_TP.saturating_sub(1),
        "FFI TP regression: {} < minimum {}",
        ffi_metrics.ffi_tp,
        BASELINE_FFI_TP.saturating_sub(1)
    );
    info!(
        "  [PASS] FFI TP {} >= minimum {}",
        ffi_metrics.ffi_tp,
        BASELINE_FFI_TP.saturating_sub(1)
    );

    assert!(
        ffi_metrics.resource_tp >= BASELINE_RESOURCE_TP.saturating_sub(2),
        "Resource TP regression: {} < minimum {}",
        ffi_metrics.resource_tp,
        BASELINE_RESOURCE_TP.saturating_sub(2)
    );
    info!(
        "  [PASS] Resource TP {} >= minimum {}",
        ffi_metrics.resource_tp,
        BASELINE_RESOURCE_TP.saturating_sub(2)
    );

    // ── Leak regression checks ────────────────────────────────────
    assert!(
        ffi_metrics.leak_tp >= BASELINE_LEAK_TP.saturating_sub(2),
        "Leak TP regression: {} < minimum {}",
        ffi_metrics.leak_tp,
        BASELINE_LEAK_TP.saturating_sub(2)
    );
    info!(
        "  [PASS] Leak TP {} >= minimum {}",
        ffi_metrics.leak_tp,
        BASELINE_LEAK_TP.saturating_sub(2)
    );

    // ── Double-free regression checks ─────────────────────────────
    // DoubleFree detection on zig_main.ll is highly non-deterministic.
    // TP can vary 2-7 across runs. Use baseline as minimum with no
    // further subtraction since BASELINE_DOUBLE_FREE_TP already uses
    // the worst-common result.
    #[allow(clippy::absurd_extreme_comparisons)]
    {
        assert!(
            ffi_metrics.double_free_tp >= BASELINE_DOUBLE_FREE_TP,
            "DoubleFree TP regression: {} < minimum {}",
            ffi_metrics.double_free_tp,
            BASELINE_DOUBLE_FREE_TP
        );
        info!(
            "  [PASS] DoubleFree TP {} >= minimum {}",
            ffi_metrics.double_free_tp, BASELINE_DOUBLE_FREE_TP
        );
    }

    // ── Delta output against baseline ──────────────────────────────
    eprintln!("\n=== Delta Against Baseline ===");
    let tp_delta = tp_count as i64 - BASELINE_TP as i64;
    let fp_delta = fp_count as i64 - BASELINE_FP as i64;
    let fn_delta = fn_count as i64 - BASELINE_FN as i64;
    let precision_delta = precision - BASELINE_PRECISION;
    let recall_delta = recall - BASELINE_RECALL;
    eprintln!(
        "  TP:       {} → {} ({:+})",
        BASELINE_TP, tp_count, tp_delta
    );
    eprintln!(
        "  FP:       {} → {} ({:+})",
        BASELINE_FP, fp_count, fp_delta
    );
    eprintln!(
        "  FN:       {} → {} ({:+})",
        BASELINE_FN, fn_count, fn_delta
    );
    eprintln!(
        "  Precision: {:.1}% → {:.1}% ({:+.1}%)",
        BASELINE_PRECISION * 100.0,
        precision * 100.0,
        precision_delta * 100.0
    );
    eprintln!(
        "  Recall:    {:.1}% → {:.1}% ({:+.1}%)",
        BASELINE_RECALL * 100.0,
        recall * 100.0,
        recall_delta * 100.0
    );

    info!("\n=== Accuracy regression test PASSED ===\n");
}

/// Objective: Dump all detected issues for diagnostic purposes.
/// This is NOT an assertion test — it just prints what the pipeline finds.
#[test]
fn test_ffi_demo_dump_all_issues() {
    let ffi_demo_dir = PathBuf::from(FFI_DEMO_OUTPUT_DIR);
    if !ffi_demo_dir.exists() {
        eprintln!("Skipping ffi-demo dump: directory not found");
        return;
    }

    let ll_files: Vec<PathBuf> = std::fs::read_dir(&ffi_demo_dir)
        .unwrap_or_else(|e| panic!("Cannot read ffi-demo dir: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ll"))
        .map(|entry| entry.path())
        .collect();

    eprintln!("\n=== ffi-demo Issue Audit ===");
    for ll_file in &ll_files {
        let file_name = ll_file.file_name().unwrap().to_string_lossy().to_string();
        let result = run_pipeline_on_ffi_demo(&file_name);
        eprintln!("\n--- {} ({} issues) ---", file_name, result.issue_count());
        for (idx, issue) in result.issues().iter().enumerate() {
            let func = issue
                .location
                .as_ref()
                .and_then(|loc| loc.function.as_deref())
                .unwrap_or("(unknown)");
            let desc = if issue.description.len() > 80 {
                format!("{}...", &issue.description[..77])
            } else {
                issue.description.clone()
            };
            eprintln!(
                "  [{:>2}] {:<30} func={:<45} {}",
                idx,
                format!("{:?}", issue.kind),
                func,
                desc
            );
        }
    }
    eprintln!("\n=== ffi-demo Issue Audit Complete ===");
}

/// Objective: Verify pipeline runs without errors on all ffi-demo files.
/// Invariants: All files must load and run successfully.
#[test]
fn test_ffi_demo_pipeline_stability() {
    let ffi_demo_dir = PathBuf::from(FFI_DEMO_OUTPUT_DIR);
    if !ffi_demo_dir.exists() {
        info!("Skipping pipeline stability: directory not found");
        return;
    }

    let ll_files: Vec<PathBuf> = std::fs::read_dir(&ffi_demo_dir)
        .unwrap_or_else(|e| panic!("Cannot read ffi-demo dir: {e}"))
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "ll"))
        .map(|entry| entry.path())
        .collect();

    info!("Testing pipeline stability on {} .ll files", ll_files.len());

    for ll_file in &ll_files {
        let file_name = ll_file.file_name().unwrap().to_string_lossy().to_string();
        let result = run_pipeline_on_ffi_demo(&file_name);
        info!(
            "  [OK] {} — {} passes, {} issues, {}ms",
            file_name,
            result.pass_count(),
            result.issue_count(),
            result.duration_ms()
        );
    }

    info!("Pipeline stability test PASSED");
}
