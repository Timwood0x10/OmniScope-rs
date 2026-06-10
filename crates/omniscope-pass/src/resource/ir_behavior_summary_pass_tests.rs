#[cfg(test)]
mod tests {
    // NOTE: Tests below mix unit tests (no external deps) with E2E diagnostic
    // tests that load .ll fixtures from ~/code/ffi-demo/output/. The E2E
    // tests (free_then_callback_use_real_ll, _e2e_candidate, etc.) should
    // eventually migrate to tests/integration_tests.rs for consistency.
    use crate::pass::{Pass, PassContext, PassKind};
    use crate::resource::ir_behavior_summary_pass::IRBehaviorSummaryPass;
    use omniscope_ir::IRModule;
    use omniscope_semantics::{BehaviorPattern, FunctionBehavior, SemanticFact};

    #[test]
    fn test_ir_behavior_summary_pass_creation() {
        let pass = IRBehaviorSummaryPass::new();
        assert_eq!(
            pass.name(),
            "IRBehaviorSummary",
            "Pass name should be IRBehaviorSummary"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Pass kind should be Analysis"
        );
        assert_eq!(
            pass.dependencies(),
            vec!["RawFactCollector"],
            "Dependencies should be RawFactCollector"
        );
    }

    #[test]
    fn test_ir_behavior_summary_pass_no_ir_module() {
        let mut ctx = PassContext::new();
        let pass = IRBehaviorSummaryPass::new();
        let result = pass.run(&mut ctx).unwrap();
        assert_eq!(
            result.stats.get("behaviors_extracted"),
            Some(&0),
            "No IR module should result in 0 behaviors extracted"
        );
    }

    #[test]
    fn test_ir_behavior_summary_pass_with_conditional_release() {
        let mut ctx = PassContext::new();
        let ir = r#"
            define void @release_string(ptr %s) {
            entry:
                %22 = atomicrmw sub ptr %s, i32 2 monotonic
                %23 = icmp eq i32 %22, 2
                br i1 %23, label %destroy, label %exit
            destroy:
                tail call void @Bun__WTFStringImpl__destroy(ptr %s)
                ret void
            exit:
                ret void
            }
        "#;
        let module = IRModule::parse_from_text(ir);
        ctx.store("ir_module", module);

        let pass = IRBehaviorSummaryPass::new();
        let result = pass.run(&mut ctx).unwrap();

        assert_eq!(
            result.stats.get("conditional_release"),
            Some(&1),
            "Conditional release should be detected"
        );
        assert_eq!(
            result.stats.get("summaries_from_behavior"),
            Some(&1),
            "Should generate 1 summary from behavior"
        );

        // Verify that behaviors were stored in context
        let behaviors: Vec<FunctionBehavior> = ctx.get("function_behaviors").unwrap();
        assert_eq!(behaviors.len(), 1, "Should have 1 behavior extracted");
    }

    /// Objective: Verify that HeapToGlobalEscape is detected from param→global store.
    /// Invariants: semantic_facts contains HeapToGlobalEscape evidence text.
    #[test]
    fn test_ir_behavior_summary_pass_heap_to_global_escape() {
        let mut ctx = PassContext::new();
        let ir = r#"
            define void @c_register_and_store(ptr %ptr) {
            entry:
                store ptr %ptr, ptr @g_stored_ptr, align 8
                ret void
            }
        "#;
        let module = IRModule::parse_from_text(ir);
        ctx.store("ir_module", module);

        let pass = IRBehaviorSummaryPass::new();
        let _result = pass.run(&mut ctx).unwrap();

        // Verify semantic facts contain HeapToGlobalEscape
        let facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap();
        let hge_fact = facts
            .iter()
            .find(|f| f.evidence.contains("HeapToGlobalEscape"));
        assert!(
            hge_fact.is_some(),
            "Should emit HeapToGlobalEscape semantic fact, got: {:?}",
            facts.iter().map(|f| &f.evidence).collect::<Vec<_>>()
        );

        // Verify function behaviors include the pattern
        let behaviors: Vec<FunctionBehavior> = ctx.get("function_behaviors").unwrap();
        let hge_behavior = behaviors.iter().find(|b| b.name == "c_register_and_store");
        assert!(
            hge_behavior.is_some(),
            "Should have behavior for c_register_and_store, got: {:?}",
            behaviors.iter().map(|b| &b.name).collect::<Vec<_>>()
        );
        let hge_pattern = hge_behavior
            .unwrap()
            .patterns
            .iter()
            .find(|p| matches!(p, BehaviorPattern::HeapToGlobalEscape { .. }));
        assert!(
            hge_pattern.is_some(),
            "c_register_and_store should have HeapToGlobalEscape pattern, got: {:?}",
            hge_behavior.unwrap().patterns
        );
    }

    /// Objective: Verify that FreeThenCallbackUse is detected from the exact IR
    ///            produced by clang for uaf_through_ffi in c_ffi_traps.c (TRAP-C-9).
    /// Invariants: semantic_facts contains FreeThenCallbackUse evidence text.
    #[test]
    fn test_ir_behavior_summary_pass_free_then_callback_use() {
        let mut ctx = PassContext::new();
        // Exact IR from c_ffi_traps.ll — note the `tail` prefix on calls and
        // the cross-basic-block structure (free in block 3, use in block 6).
        let ir = r#"
            define void @uaf_through_ffi() local_unnamed_addr {
entry:
                %1 = tail call dereferenceable_or_null(32) ptr @malloc(i64 noundef 32)
                %2 = icmp eq ptr %1, null
                br i1 %2, label %8, label %3
3:
                tail call void @free(ptr noundef nonnull %1)
                %4 = load ptr, ptr @g_callback, align 8
                %5 = icmp eq ptr %4, null
                br i1 %5, label %8, label %6
6:
                %7 = load ptr, ptr @g_user_data, align 8
                tail call void %4(ptr noundef %7, ptr noundef nonnull %1, i64 noundef 32)
                br label %8
8:
                ret void
            }
        "#;
        let module = IRModule::parse_from_text(ir);
        ctx.store("ir_module", module.clone());

        let pass = IRBehaviorSummaryPass::new();
        let _result = pass.run(&mut ctx).unwrap();

        // Verify that semantic facts were emitted
        let facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap();

        // Debug: print detected patterns and facts on failure
        let behaviors: Vec<FunctionBehavior> = ctx.get("function_behaviors").unwrap();
        for b in &behaviors {
            if b.name == "uaf_through_ffi" {
                for p in &b.patterns {
                    eprintln!("[DEBUG] Pattern: {:?}", p);
                }
            }
        }
        for f in &facts {
            eprintln!("[DEBUG] Fact: {:?} | {}", f.kind, f.evidence);
        }

        let ftcu_fact = facts
            .iter()
            .find(|f| f.evidence.contains("FreeThenCallbackUse"));
        assert!(
            ftcu_fact.is_some(),
            "Should emit FreeThenCallbackUse semantic fact, got: {:?}",
            facts.iter().map(|f| &f.evidence).collect::<Vec<_>>()
        );

        // Verify function behaviors include the pattern
        let behaviors: Vec<FunctionBehavior> = ctx.get("function_behaviors").unwrap();
        let uaf_behavior = behaviors.iter().find(|b| b.name == "uaf_through_ffi");
        assert!(
            uaf_behavior.is_some(),
            "Should have behavior for uaf_through_ffi, got: {:?}",
            behaviors.iter().map(|b| &b.name).collect::<Vec<_>>()
        );
        let ftcu_pattern = uaf_behavior
            .unwrap()
            .patterns
            .iter()
            .find(|p| matches!(p, BehaviorPattern::FreeThenCallbackUse { .. }));
        assert!(
            ftcu_pattern.is_some(),
            "uaf_through_ffi should have FreeThenCallbackUse pattern, got: {:?}",
            uaf_behavior.unwrap().patterns
        );
    }

    /// Load the ACTUAL c_ffi_traps.ll from disk and verify FreeThenCallbackUse fires.
    /// This tests the real file (not hand-crafted IR) to catch any parsing differences.
    #[test]
    fn test_ir_behavior_summary_pass_free_then_callback_use_real_ll() {
        // Try multiple possible paths for ffi-demo output
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
                eprintln!("[SKIP] c_ffi_traps.ll not found in any search path");
                return;
            }
        };

        let mut ctx = PassContext::new();
        ctx.store("ir_module", m.clone());
        let pass = IRBehaviorSummaryPass::new();
        let _result = pass.run(&mut ctx).unwrap();

        let behaviors: Vec<FunctionBehavior> = ctx.get("function_behaviors").unwrap();
        let uaf_behavior = behaviors.iter().find(|b| b.name == "uaf_through_ffi");

        if let Some(b) = uaf_behavior {
            for p in &b.patterns {
                eprintln!("[REAL-LL] Pattern: {:?}", p);
            }
            let ftcu = b
                .patterns
                .iter()
                .find(|p| matches!(p, BehaviorPattern::FreeThenCallbackUse { .. }));
            assert!(
                ftcu.is_some(),
                "Real .ll file: uaf_through_ffi should have FreeThenCallbackUse, got: {:?}",
                b.patterns
            );
        } else {
            panic!(
                "Real .ll file: uaf_through_ffi not found in behaviors. Functions: {:?}",
                behaviors.iter().map(|b| &b.name).collect::<Vec<_>>()
            );
        }

        let facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap();
        for f in &facts {
            if let omniscope_semantics::SemanticKey::Symbol(name) = &f.key {
                if name.contains("uaf_through_ffi") {
                    eprintln!("[REAL-LL] Fact: {:?} | {}", f.kind, f.evidence);
                }
            }
        }
    }

    /// End-to-end test: run IRBehaviorSummaryPass + IssueCandidateBuilderPass on
    /// real c_ffi_traps.ll to verify FreeThenCallbackUse produces a candidate.
    #[test]
    fn test_free_then_callback_use_e2e_candidate() {
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

        // Run IRBehaviorSummaryPass
        let mut ctx = PassContext::new();
        ctx.store("ir_module", m.clone());
        let pass1 = IRBehaviorSummaryPass::new();
        let _ = pass1.run(&mut ctx).unwrap();

        // Check semantic facts
        let facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap_or_default();
        let ftcu_facts: Vec<_> = facts
            .iter()
            .filter(|f| f.evidence.contains("FreeThenCallbackUse"))
            .collect();
        eprintln!(
            "[E2E] FreeThenCallbackUse semantic facts: {}",
            ftcu_facts.len()
        );
        for f in &ftcu_facts {
            eprintln!("[E2E]   {:?}", f.evidence);
        }

        // Run IssueCandidateBuilderPass (need minimum context)
        use crate::resource::issue_candidate_builder::IssueCandidateBuilderPass;
        let pass2 = IssueCandidateBuilderPass::new();
        let result = pass2.run(&mut ctx);
        eprintln!(
            "[E2E] IssueCandidateBuilderPass result: {:?}",
            result.is_ok()
        );

        // Check candidates
        use omniscope_types::IssueCandidateKind;
        let candidates: Vec<omniscope_core::IssueCandidate> =
            ctx.get("issue_candidates").unwrap_or_default();
        let ftcu_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| {
                c.kind == IssueCandidateKind::UseAfterFree
                    && c.description
                        .as_deref()
                        .is_some_and(|d| d.contains("callback"))
            })
            .collect();
        eprintln!(
            "[E2E] FreeThenCallbackUse candidates: {}",
            ftcu_candidates.len()
        );
        for c in &ftcu_candidates {
            eprintln!(
                "[E2E]   kind={:?} func={} verdict={:?} ffi_evidence={:?}",
                c.kind, c.alloc_function, c.verdict, c.ffi_evidence
            );
        }

        assert!(
            !ftcu_facts.is_empty(),
            "Expected at least one FreeThenCallbackUse semantic fact"
        );
        assert!(
            !ftcu_candidates.is_empty(),
            "Expected at least one FreeThenCallbackUse candidate, total candidates: {}",
            candidates.len()
        );
    }

    /// Full-pipeline diagnostic: run all passes on c_ffi_traps.ll and trace
    /// the FreeThenCallbackUse candidate through builder → verifier → reconcile → emit.
    ///
    /// Objective: Identify where the UAF candidate is lost in the full pipeline.
    /// Invariants: After full pipeline, a UseAfterFree issue for uaf_through_ffi exists.
    #[test]
    fn test_free_then_callback_use_full_pipeline_trace() {
        use crate::resource::issue_candidate_builder::IssueCandidateBuilderPass;
        use crate::resource::issue_verifier::IssueVerifierPass;
        use omniscope_core::IssueKind;

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

        // Run IRBehaviorSummaryPass
        let mut ctx = PassContext::new();
        ctx.store("ir_module", m.clone());
        let pass1 = IRBehaviorSummaryPass::new();
        let _ = pass1.run(&mut ctx).unwrap();

        // Check semantic facts
        let facts: Vec<SemanticFact> = ctx.get("semantic_facts").unwrap_or_default();
        let ftcu_facts: Vec<_> = facts
            .iter()
            .filter(|f| f.evidence.contains("FreeThenCallbackUse"))
            .collect();
        eprintln!(
            "[PIPELINE] FreeThenCallbackUse semantic facts: {}",
            ftcu_facts.len()
        );

        // Run IssueCandidateBuilderPass
        let pass2 = IssueCandidateBuilderPass::new();
        let _ = pass2.run(&mut ctx);

        let candidates: Vec<omniscope_core::IssueCandidate> =
            ctx.get("issue_candidates").unwrap_or_default();
        let uaf_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| {
                c.kind == omniscope_types::IssueCandidateKind::UseAfterFree
                    && c.alloc_function.contains("uaf_through_ffi")
            })
            .collect();
        eprintln!(
            "[PIPELINE] UseAfterFree candidates after builder: {}",
            uaf_candidates.len()
        );
        for c in &uaf_candidates {
            eprintln!(
                "[PIPELINE]   id={} kind={:?} func={} verdict={:?} ffi_evidence={:?} resource_id={:?}",
                c.id, c.kind, c.alloc_function, c.verdict, c.ffi_evidence, c.resource_id
            );
        }

        // Run IssueVerifierPass
        let pass3 = IssueVerifierPass::new();
        let result = pass3.run(&mut ctx);
        eprintln!("[PIPELINE] IssueVerifierPass result: {:?}", result.is_ok());
        if let Ok(ref r) = result {
            eprintln!("[PIPELINE]   PassResult stats: {:?}", r.stats);
            eprintln!("[PIPELINE]   PassResult issues: {}", r.issues.len());
            for i in &r.issues {
                eprintln!(
                    "[PIPELINE]     PR-ISSUE kind={:?} symbol={}",
                    i.kind,
                    i.symbol.as_str()
                );
            }
        }

        // Check verified candidates
        let verified: Vec<omniscope_core::IssueCandidate> =
            ctx.get("verified_candidates").unwrap_or_default();
        let uaf_verified: Vec<_> = verified
            .iter()
            .filter(|c| {
                c.kind == omniscope_types::IssueCandidateKind::UseAfterFree
                    && c.alloc_function.contains("uaf_through_ffi")
            })
            .collect();
        eprintln!(
            "[PIPELINE] UseAfterFree verified for uaf: {}",
            uaf_verified.len()
        );
        for c in &uaf_verified {
            eprintln!(
                "[PIPELINE]   id={} kind={:?} func={} verdict={:?} desc={:?}",
                c.id, c.kind, c.alloc_function, c.verdict, c.description
            );
        }

        // Check final issues
        let issues: Vec<omniscope_core::Issue> = ctx.get("issues").unwrap_or_default();
        let uaf_issues: Vec<_> = issues
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
            "[PIPELINE] UseAfterFree issues for uaf: {}",
            uaf_issues.len()
        );
        for i in &uaf_issues {
            eprintln!(
                "[PIPELINE]   kind={:?} symbol={} desc={}",
                i.kind,
                i.symbol.as_str(),
                i.description
            );
        }

        // Dump ALL issues for context
        eprintln!("[PIPELINE] Total issues: {}", issues.len());

        // Check suppressed issues too
        let suppressed: Vec<omniscope_core::Issue> =
            ctx.get("suppressed_issues").unwrap_or_default();
        eprintln!("[PIPELINE] Suppressed issues: {}", suppressed.len());
        for i in &suppressed {
            eprintln!(
                "[PIPELINE]   SUPPRESSED kind={:?} symbol={}",
                i.kind,
                i.symbol.as_str()
            );
        }

        // Extended diagnostics: dump ALL candidates and verified state
        eprintln!("[PIPELINE] === TOTAL CANDIDATES: {} ===", candidates.len());
        for (idx, c) in candidates.iter().enumerate() {
            eprintln!(
                "[PIPELINE]   [{}] kind={:?} func={} verdict={:?} reportable={} ffi={}",
                idx,
                c.kind,
                c.alloc_function,
                c.verdict,
                c.is_reportable(),
                c.has_ffi_evidence()
            );
        }
        eprintln!("[PIPELINE] === TOTAL VERIFIED: {} ===", verified.len());
        for (idx, c) in verified.iter().enumerate() {
            eprintln!(
                "[PIPELINE]   [{}] kind={:?} func={} verdict={:?} reportable={}",
                idx,
                c.kind,
                c.alloc_function,
                c.verdict,
                c.is_reportable()
            );
        }

        // Check reconcile actions by running reconcile manually
        use std::collections::HashSet;
        let reportable_set: HashSet<usize> = verified
            .iter()
            .enumerate()
            .filter(|(_idx, c)| c.is_reportable())
            .map(|(idx, _)| idx)
            .collect();
        eprintln!("[PIPELINE] reportable_set: {:?}", reportable_set);

        // We can't easily call reconcile_candidates from here since it's crate-private,
        // but we can check groupings
        eprintln!("[PIPELINE] === RESOURCE KEY GROUPING ===");
        use std::collections::HashMap;
        let mut key_groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, c) in verified.iter().enumerate() {
            let key = if let Some(rid) = c.resource_id {
                format!("Instance({})", rid)
            } else {
                format!(
                    "AllocSite(caller={}, fn={})",
                    c.alloc_caller.as_deref().unwrap_or(&c.alloc_function),
                    c.alloc_function
                )
            };
            key_groups.entry(key).or_default().push(idx);
        }
        for (key, indices) in &key_groups {
            eprintln!("[PIPELINE]   {}: {:?}", key, indices);
        }
        for i in &issues {
            eprintln!(
                "[PIPELINE]   kind={:?} symbol={} location_func={}",
                i.kind,
                i.symbol.as_str(),
                i.location
                    .as_ref()
                    .and_then(|l| l.function.as_deref())
                    .unwrap_or("<none>")
            );
        }

        // Assert: we expect at least one fact and one candidate
        assert!(
            !ftcu_facts.is_empty(),
            "Expected FreeThenCallbackUse semantic facts"
        );
        assert!(
            !uaf_candidates.is_empty(),
            "Expected UseAfterFree candidates from builder"
        );
    }

    /// Full Pipeline diagnostic: run the actual Pipeline on c_ffi_traps.ll
    /// and trace whether the UAF issue for uaf_through_ffi survives to final output.
    ///
    /// Objective: Identify where the UAF issue is lost in the FULL pipeline
    /// (which has 20 passes including SRT population).
    /// Invariants: Pipeline result contains a UseAfterFree issue for uaf_through_ffi.
    #[test]
    fn test_free_then_callback_use_full_pipeline_diagnostic() {
        use omniscope_core::IssueKind;
        use omniscope_pipeline::Pipeline;

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
