#[cfg(test)]
mod tests {
    use omniscope_core::IssueKind;
    use omniscope_ir::IRModule;
    use crate::Pipeline;

    /// Full Pipeline diagnostic: run the actual Pipeline on c_ffi_traps.ll
    /// and trace whether the UAF issue for uaf_through_ffi survives to final output.
    ///
    /// Objective: Identify where the UAF issue is lost in the FULL pipeline
    /// (which has 20 passes including SRT population).
    /// Invariants: Pipeline result contains a UseAfterFree issue for uaf_through_ffi.
    #[test]
    fn test_free_then_callback_use_full_pipeline_diagnostic() {
        let paths = [
            "../../ffi-demo/output/c_ffi_traps.ll",
            "../../../ffi-demo/output/c_ffi_traps.ll",
            "/Users/scc/code/ffi-demo/output/c_ffi_traps.ll",
        ];
        let mut loaded = None;
        for p in &paths {
            if let Ok(m) = IRModule::load_from_file(std::path::Path::new(p)) {
                loaded = Some(m);
                break;
            }
        }
        let m = match loaded {
            Some(m) => m,
            None => {
                eprintln!("[SKIP] c_ffi_traps.ll not found");
                return;
            }
        };

        // Run the FULL pipeline (20 passes)
        let mut pipeline = Pipeline::new();
        pipeline.register_default_passes();
        pipeline.set_ir_module(m);
        let result = pipeline.run().unwrap();

        // Dump ALL issues from pipeline result
        eprintln!("[FULL-PIPELINE] Total issues: {}", result.issues().len());
        for i in result.issues() {
            eprintln!(
                "[FULL-PIPELINE]   ISSUE kind={:?} symbol='{}' location_func={} desc={}",
                i.kind,
                i.symbol.as_str(),
                i.location
                    .as_ref()
                    .and_then(|l| l.function.as_deref())
                    .unwrap_or("<none>"),
                i.description
            );
        }

        // Look specifically for UAF on uaf_through_ffi
        let uaf_issues: Vec<_> = result
            .issues()
            .iter()
            .filter(|i| {
                i.kind == IssueKind::UseAfterFree
                    && i.location
                        .as_ref()
                        .and_then(|l| l.function.as_deref())
                        .is_some_and(|f| f.contains("uaf_through_ffi"))
            })
            .collect();
        eprintln!(
            "[FULL-PIPELINE] UseAfterFree issues for uaf_through_ffi: {}",
            uaf_issues.len()
        );
        for i in &uaf_issues {
            eprintln!(
                "[FULL-PIPELINE]   UAF-ISSUE kind={:?} symbol='{}' desc={}",
                i.kind,
                i.symbol.as_str(),
                i.description
            );
        }

        // Also check all pass results for any UAF-related data
        eprintln!("[FULL-PIPELINE] Pass results: {}", result.pass_count());
        for pr in &result.pass_results {
            if !pr.issues.is_empty() {
                eprintln!(
                    "[FULL-PIPELINE]   PASS '{}' has {} issues",
                    pr.name,
                    pr.issues.len()
                );
                for i in &pr.issues {
                    if i.kind == IssueKind::UseAfterFree {
                        eprintln!(
                            "[FULL-PIPELINE]     PASS-UAF kind={:?} symbol='{}' loc={}",
                            i.kind,
                            i.symbol.as_str(),
                            i.location
                                .as_ref()
                                .and_then(|l| l.function.as_deref())
                                .unwrap_or("<none>")
                        );
                    }
                }
            }
        }

        // Check if there's an IssueVerifier pass result with stats
        if let Some(verifier_result) = result.get_pass_result("IssueVerifier") {
            eprintln!(
                "[FULL-PIPELINE] IssueVerifier stats: {:?}",
                verifier_result.stats
            );
            for (key, value) in &verifier_result.stats {
                eprintln!("[FULL-PIPELINE]   STAT {}={}", key, value);
            }
        }

        // Diagnostic: dump what we can about why UAF was suppressed
        // The stats show semantic_suppressed=5, meaning 5 candidates were suppressed
        // by EvidenceBundle semantic suppression. The UAF candidate is likely among them.
        eprintln!("[FULL-PIPELINE] === DIAGNOSTIC: UAF SUPPRESSION ROOT CAUSE ===");
        eprintln!("[FULL-PIPELINE] semantic_suppressed=5 means EvidenceBundle found suppressing SemanticKinds");
        eprintln!("[FULL-PIPELINE] For UAF candidate (alloc_function='uaf_through_ffi'), the bundle looks up");
        eprintln!("[FULL-PIPELINE] srt_resolutions['uaf_through_ffi'] which may contain suppressing kinds");
        eprintln!("[FULL-PIPELINE] Suppressing kinds: RuntimeManagedResource, StoredToOwner, StoredToRuntime,");
        eprintln!("[FULL-PIPELINE]   EscapedToCaller, EscapedToOutParam, RaiiDropRelease, CppDestructor, DestructorRelease");

        // Assert: the full pipeline should produce at least one UAF for uaf_through_ffi
        assert!(
            !uaf_issues.is_empty(),
            "Full pipeline should emit UseAfterFree for uaf_through_ffi, got {} total issues. Issues: {:?}",
            result.issues().len(),
            result.issues().iter().map(|i| format!("{:?}({})", i.kind, i.symbol.as_str())).collect::<Vec<_>>()
        );
    }
}