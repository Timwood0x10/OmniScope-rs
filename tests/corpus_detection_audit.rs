//! Detection audit: runs the OmniScope pipeline on every corpus `.ll` file
//! and reports a per-function breakdown of what was detected vs what is expected.
//!
//! This is a pure audit — it never fails on missing detections. It only fails
//! if the pipeline itself crashes or a fixture file is missing.
//!
//! Results are written to `/tmp/corpus_audit_report.txt`.
//! Run with: `cargo test --test corpus_detection_audit`

use omniscope_core::IssueKind;
use omniscope_ir::IRModule;
use omniscope_pipeline::Pipeline;
use std::io::Write;
use tracing::info;

// ─── Helpers ─────────────────────────────────────────────────────────

/// Load an external `.ll` fixture and run the default pipeline.
fn run_pipeline_on_fixture(relative_path: &str) -> omniscope_pipeline::PipelineResult {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(manifest_dir).join(relative_path);
    let module = IRModule::load_from_file(&path)
        .unwrap_or_else(|e| panic!("Failed to load fixture {relative_path}: {e}"));
    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_ir_module(module);
    pipeline
        .run()
        .unwrap_or_else(|e| panic!("Pipeline failed on {relative_path}: {e}"))
}

/// An entry in the audit table for a single expected bug.
struct ExpectedBug {
    function: &'static str,
    description: &'static str,
    expected_kinds: &'static [IssueKind],
}

/// An entry for a noise function that should NOT produce issues.
struct NoiseFunction {
    function: &'static str,
    description: &'static str,
}

/// Run the audit for one fixture file, appending results to the writer.
fn audit_fixture(
    w: &mut impl Write,
    relative_path: &str,
    expected_bugs: &[ExpectedBug],
    noise_functions: &[NoiseFunction],
) {
    let _ = writeln!(w);
    let _ = writeln!(w, "{}", "-".repeat(110));
    let _ = writeln!(w, "AUDIT: {relative_path}");
    let _ = writeln!(w, "{}", "-".repeat(110));

    let result = run_pipeline_on_fixture(relative_path);
    let _ = writeln!(
        w,
        "  Pipeline: {} passes, {} issues, {}ms",
        result.pass_count(),
        result.issue_count(),
        result.duration_ms()
    );

    if result.issue_count() == 0 {
        let _ = writeln!(w, "  ** NO ISSUES DETECTED AT ALL **");
    }

    // Print all detected issues
    let _ = writeln!(w);
    let _ = writeln!(w, "  DETECTED ISSUES:");
    if result.issues().is_empty() {
        let _ = writeln!(w, "    (none)");
    } else {
        for (idx, issue) in result.issues().iter().enumerate() {
            let func_name = issue
                .location
                .as_ref()
                .and_then(|loc| loc.function.as_deref())
                .unwrap_or("(unknown)");
            let desc_short = if issue.description.chars().count() > 70 {
                format!(
                    "{}...",
                    issue.description.chars().take(67).collect::<String>()
                )
            } else {
                issue.description.clone()
            };
            let _ = writeln!(
                w,
                "    [{:>2}] {:<25} func={:<45} {}",
                idx,
                format!("{:?}", issue.kind),
                func_name,
                desc_short
            );
        }
    }

    // Check each expected bug
    let _ = writeln!(w);
    let _ = writeln!(w, "  EXPECTED BUGS:");
    for bug in expected_bugs {
        let detected = result.issues().iter().any(|i| {
            bug.expected_kinds.contains(&i.kind)
                && i.location
                    .as_ref()
                    .and_then(|loc| loc.function.as_deref())
                    .map(|f| f.contains(bug.function))
                    .unwrap_or(false)
        });
        let detected_by_kind_only = result
            .issues()
            .iter()
            .any(|i| bug.expected_kinds.contains(&i.kind));

        let status = if detected {
            "DETECTED"
        } else if detected_by_kind_only {
            "DETECTED (kind only)"
        } else {
            "MISSED"
        };

        let kinds_str: Vec<String> = bug
            .expected_kinds
            .iter()
            .map(|k| format!("{k:?}"))
            .collect();
        let _ = writeln!(
            w,
            "    [{status:>18}] {:<30} {} (expect: {})",
            bug.function,
            bug.description,
            kinds_str.join(" | ")
        );
    }

    // Check noise functions
    let _ = writeln!(w);
    let _ = writeln!(w, "  NOISE FUNCTIONS:");
    for noise in noise_functions {
        let has_issues = result.issues().iter().any(|i| {
            i.location
                .as_ref()
                .and_then(|loc| loc.function.as_deref())
                .map(|f| f.contains(noise.function))
                .unwrap_or(false)
        });
        let status = if has_issues {
            "FALSE POSITIVE"
        } else {
            "CLEAN"
        };
        let _ = writeln!(
            w,
            "    [{status:>14}] {:<30} {}",
            noise.function, noise.description
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// AUDIT TEST
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn corpus_detection_audit() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let report_path = format!("{manifest_dir}/target/corpus_audit_report.txt");
    let mut buf = Vec::new();

    let _ = writeln!(buf, "{}", "=".repeat(110));
    let _ = writeln!(buf, "  OMNISCOPE CORPUS DETECTION AUDIT");
    let _ = writeln!(
        buf,
        "  Each function is checked: bugs should be DETECTED, noise should be CLEAN."
    );
    let _ = writeln!(buf, "{}", "=".repeat(110));

    // ─── 1. c_ffi_bugs.ll ─────────────────────────────────────────────
    audit_fixture(
        &mut buf,
        "tests/integration/c_ffi_bugs.ll",
        &[
            ExpectedBug {
                function: "cross_family_free",
                description: "malloc + operator delete (C_HEAP vs CPP_NEW_SCALAR)",
                expected_kinds: &[IssueKind::CrossFamilyFree, IssueKind::CrossLanguageFree],
            },
            ExpectedBug {
                function: "conditional_release_leak",
                description: "fopen without fclose on error path",
                expected_kinds: &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
            },
            ExpectedBug {
                function: "uaf_through_ffi",
                description: "free then pass to FFI function (use-after-free)",
                expected_kinds: &[IssueKind::UseAfterFree, IssueKind::BorrowEscape],
            },
            ExpectedBug {
                function: "double_free_aliasing",
                description: "two aliases, two frees on same allocation",
                expected_kinds: &[IssueKind::DoubleFree],
            },
            ExpectedBug {
                function: "leaked_callback_userdata",
                description: "stack-local passed as callback userdata (dangling pointer)",
                expected_kinds: &[
                    IssueKind::BorrowEscape,
                    IssueKind::CallbackEscapeIssue,
                    IssueKind::CallbackEscape,
                    IssueKind::OwnershipEscapeLeak,
                ],
            },
            ExpectedBug {
                function: "indirect_uaf",
                description: "freed pointer passed through indirect call to FFI",
                expected_kinds: &[IssueKind::UseAfterFree, IssueKind::BorrowEscape],
            },
        ],
        &[
            NoiseFunction {
                function: "pure_strlen_like",
                description: "pure computation, no alloc/free/FFI",
            },
            NoiseFunction {
                function: "safe_raii_pattern",
                description: "correct alloc/use/free on all paths",
            },
        ],
    );

    // ─── 2. rust_ffi_bugs.ll ──────────────────────────────────────────
    audit_fixture(
        &mut buf,
        "tests/integration/rust_ffi_bugs.ll",
        &[
            ExpectedBug {
                function: "box_into_raw_leak",
                description: "Box::into_raw without from_raw (leak)",
                expected_kinds: &[
                    IssueKind::OwnershipEscapeLeak,
                    IssueKind::ConditionalLeak,
                    IssueKind::MemoryLeak,
                ],
            },
            ExpectedBug {
                function: "cross_family_free",
                description: "__rust_alloc + C free (cross-family)",
                expected_kinds: &[IssueKind::CrossFamilyFree, IssueKind::CrossLanguageFree],
            },
            ExpectedBug {
                function: "double_reclaim",
                description: "Box::from_raw called twice (double reclaim)",
                expected_kinds: &[IssueKind::DoubleReclaim, IssueKind::DoubleFree],
            },
            ExpectedBug {
                function: "conditional_into_raw_leak",
                description: "into_raw on error path not reclaimed",
                expected_kinds: &[
                    IssueKind::OwnershipEscapeLeak,
                    IssueKind::ConditionalLeak,
                    IssueKind::MemoryLeak,
                ],
            },
            ExpectedBug {
                function: "cstring_leak",
                description: "CString::into_raw without from_raw (leak)",
                expected_kinds: &[
                    IssueKind::OwnershipEscapeLeak,
                    IssueKind::ConditionalLeak,
                    IssueKind::MemoryLeak,
                ],
            },
        ],
        &[
            NoiseFunction {
                function: "safe_raii_no_leak",
                description: "Box allocated and dropped via __rust_dealloc",
            },
            NoiseFunction {
                function: "safe_ffi_no_flag",
                description: "read-only FFI call with no ownership transfer",
            },
        ],
    );

    // ─── 3. zig_ffi_bugs.ll ───────────────────────────────────────────
    audit_fixture(
        &mut buf,
        "tests/integration/zig_ffi_bugs.ll",
        &[
            ExpectedBug {
                function: "allocate_and_misroute",
                description: "c_allocator.alloc + raw free (bypasses allocator)",
                expected_kinds: &[IssueKind::CrossFamilyFree, IssueKind::CrossLanguageFree],
            },
            ExpectedBug {
                function: "parse_and_leak_config",
                description: "C buffer from c_parse_config never freed",
                expected_kinds: &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
            },
            ExpectedBug {
                function: "defer_after_free",
                description: "explicit free then deferred call to c_validate (UAF)",
                expected_kinds: &[IssueKind::UseAfterFree, IssueKind::BorrowEscape],
            },
            ExpectedBug {
                function: "register_and_revoke",
                description: "GPA alloc, C stores pointer, Zig frees (UAF across FFI)",
                expected_kinds: &[
                    IssueKind::BorrowEscape,
                    IssueKind::OwnershipEscapeLeak,
                    IssueKind::UseAfterFree,
                    IssueKind::CallbackEscapeIssue,
                ],
            },
        ],
        &[
            NoiseFunction {
                function: "pure_zig_compute",
                description: "pure Zig, no FFI or alloc/free",
            },
            NoiseFunction {
                function: "safe_ffi_compare",
                description: "read-only C calls (strlen, strcmp)",
            },
        ],
    );

    // ─── 4. python_ffi_bugs.ll ────────────────────────────────────────
    audit_fixture(
        &mut buf,
        "tests/integration/python_ffi_bugs.ll",
        &[
            ExpectedBug {
                function: "py_decref_without_incref",
                description: "Py_DECREF without matching Py_INCREF (refcount underflow)",
                expected_kinds: &[
                    IssueKind::ConditionalLeak,
                    IssueKind::DoubleFree,
                    IssueKind::UseAfterFree,
                    IssueKind::CrossFamilyFree,
                    IssueKind::BorrowEscape,
                ],
            },
            ExpectedBug {
                function: "borrowed_ref_as_owned",
                description: "borrowed ref from PyList_GetItem DECREF'd (refcount corruption)",
                expected_kinds: &[
                    IssueKind::ConditionalLeak,
                    IssueKind::DoubleFree,
                    IssueKind::UseAfterFree,
                    IssueKind::BorrowEscape,
                ],
            },
            ExpectedBug {
                function: "stolen_ref_double_decref",
                description: "PyTuple_SetItem steals ref + extra DECREF (premature free)",
                expected_kinds: &[
                    IssueKind::DoubleFree,
                    IssueKind::ConditionalLeak,
                    IssueKind::UseAfterFree,
                ],
            },
        ],
        &[
            NoiseFunction {
                function: "proper_refcount_clean",
                description: "Py_INCREF + Py_DECREF properly paired",
            },
            NoiseFunction {
                function: "process_python_object",
                description: "read-only Python object inspection",
            },
        ],
    );

    // ─── 5. go_ffi_bugs.ll ────────────────────────────────────────────
    audit_fixture(
        &mut buf,
        "tests/integration/go_ffi_bugs.ll",
        &[
            ExpectedBug {
                function: "go_ptr_escape_to_c",
                description: "Go GC pointer escapes to C (dangling after GC move)",
                expected_kinds: &[
                    IssueKind::BorrowEscape,
                    IssueKind::OwnershipEscapeLeak,
                    IssueKind::UseAfterFree,
                ],
            },
            ExpectedBug {
                function: "c_buffer_leak",
                description: "malloc buffer leaked on error return",
                expected_kinds: &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
            },
            ExpectedBug {
                function: "double_free_cgo",
                description: "explicit free + deferred cleanup (double free)",
                expected_kinds: &[IssueKind::DoubleFree],
            },
        ],
        &[
            NoiseFunction {
                function: "cgo_alloc_clean",
                description: "malloc + free properly paired",
            },
            NoiseFunction {
                function: "go_cleanup_handler",
                description: "defer handler that frees (called by runtime)",
            },
        ],
    );

    // ─── 6. c_hash_c_bridge.ll ────────────────────────────────────────
    audit_fixture(
        &mut buf,
        "tests/integration/c_hash_c_bridge.ll",
        &[ExpectedBug {
            function: "c_hash",
            description: "fopen may not be fclose'd, conditional malloc/free paths",
            expected_kinds: &[
                IssueKind::ConditionalLeak,
                IssueKind::MemoryLeak,
                IssueKind::CrossFamilyFree,
                IssueKind::CrossLanguageFree,
            ],
        }],
        &[],
    );

    // ─── 7. cpp_hash.ll ───────────────────────────────────────────────
    audit_fixture(
        &mut buf,
        "tests/integration/cpp_hash.ll",
        &[ExpectedBug {
            function: "CompressBlock",
            description: "_Znam (new[]) in CompressBlock -- allocation leak or mismanagement",
            expected_kinds: &[
                IssueKind::ConditionalLeak,
                IssueKind::MemoryLeak,
                IssueKind::CrossFamilyFree,
                IssueKind::BorrowEscape,
                IssueKind::OwnershipEscapeLeak,
            ],
        }],
        &[],
    );

    // ─── 8. c_fft_c_bridge.ll ─────────────────────────────────────────
    audit_fixture(
        &mut buf,
        "tests/integration/c_fft_c_bridge.ll",
        &[
            ExpectedBug {
                function: "c_fft_forward",
                description: "malloc may not be freed on partial alloc failure",
                expected_kinds: &[
                    IssueKind::ConditionalLeak,
                    IssueKind::MemoryLeak,
                    IssueKind::CrossFamilyFree,
                    IssueKind::CrossLanguageFree,
                ],
            },
            ExpectedBug {
                function: "c_fft_test_signal",
                description: "fopen may not be fclose'd, malloc for snprintf buffer",
                expected_kinds: &[IssueKind::ConditionalLeak, IssueKind::MemoryLeak],
            },
        ],
        &[],
    );

    // Write report to file
    let _ = writeln!(buf);
    let _ = writeln!(buf, "{}", "=".repeat(110));
    let _ = writeln!(buf, "  AUDIT COMPLETE");
    let _ = writeln!(buf, "{}", "=".repeat(110));

    std::fs::write(report_path, &buf).expect("Failed to write audit report");
    // Also print to stdout so it appears in test output
    let report = String::from_utf8_lossy(&buf);
    for line in report.lines() {
        info!("{line}");
    }
}
