use super::*;
use omniscope_ir::IRModule;

fn parse_body(ir: &str) -> FunctionBody {
    let module = IRModule::parse_from_text(ir);
    module
        .function_bodies
        .values()
        .next()
        .expect("ir_pattern::parse_body: no function body found")
        .clone()
}

// ── Original tests ──

#[test]
fn test_conditional_release_detection() {
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

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior
            .patterns
            .contains(&BehaviorPattern::ConditionalRelease {
                atomic_op: "sub".to_string(),
                threshold: "2".to_string(),
            }),
        "Should detect ConditionalRelease pattern, got: {:?}",
        behavior.patterns
    );
}

#[test]
fn test_pure_computation_detection() {
    let ir = r#"
        define i64 @my_strlen(ptr %s) {
        entry:
            %len = call i32 @strlen(ptr %s)
            %result = zext i32 %len to i64
            ret i64 %result
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior
            .patterns
            .contains(&BehaviorPattern::PureComputation),
        "Should detect PureComputation pattern, got: {:?}",
        behavior.patterns
    );
}

#[test]
fn test_ownership_transfer_detection() {
    let ir = r#"
        define ptr @alloc_buffer(i64 %size) {
        entry:
            %buf = call ptr @malloc(i64 %size)
            ret ptr %buf
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior
            .patterns
            .contains(&BehaviorPattern::OwnershipTransfer { is_acquire: true }),
        "Should detect OwnershipTransfer pattern, got: {:?}",
        behavior.patterns
    );
}

#[test]
fn test_pointer_projection_detection() {
    let ir = r#"
        define ptr @get_data_ptr(ptr %obj) {
        entry:
            %data = getelementptr i8, ptr %obj, i64 16
            ret ptr %data
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior
            .patterns
            .contains(&BehaviorPattern::PointerProjection),
        "Should detect PointerProjection pattern, got: {:?}",
        behavior.patterns
    );
}

#[test]
fn test_no_false_conditional_release() {
    // A simple function without atomicrmw should NOT trigger ConditionalRelease
    let ir = r#"
        define void @simple_func(ptr %p) {
        entry:
            store i32 42, ptr %p
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        !behavior
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::ConditionalRelease { .. })),
        "Should NOT detect ConditionalRelease in simple store function, got: {:?}",
        behavior.patterns
    );
}

#[test]
fn test_return_source_call_result() {
    let ir = r#"
        define i32 @wrapper(ptr %s) {
        entry:
            %result = call i32 @strlen(ptr %s)
            ret i32 %result
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert_eq!(
        behavior.return_source,
        ReturnSource::CallResult("strlen".to_string()),
        "Return from strlen call must be classified as CallResult"
    );
}

#[test]
fn test_return_source_void() {
    let ir = r#"
        define void @init(ptr %p) {
        entry:
            store i32 0, ptr %p
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert_eq!(
        behavior.return_source,
        ReturnSource::Void,
        "Void function must have Void return source"
    );
}

// ── Golden Tests : Unknown function names with recognizable IR patterns ──

/// golden test: An unknown function with malloc+free IR pattern
/// should be detected as OwnershipTransfer, even though the function
/// name "custom_buffer_alloc" is not in any whitelist.
#[test]
fn test_golden_unknown_alloc_function() {
    let ir = r#"
        define ptr @custom_buffer_alloc(i64 %size) {
        entry:
            %buf = call ptr @malloc(i64 %size)
            ret ptr %buf
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior.patterns.contains(&BehaviorPattern::OwnershipTransfer { is_acquire: true }),
        "Unknown function 'custom_buffer_alloc' with malloc call should be OwnershipTransfer, got: {:?}",
        behavior.patterns
    );
}

/// An unknown function with atomicrmw sub + icmp eq
/// should be detected as ConditionalRelease, even though the function
/// name "mystery_refcount_release" is not in any whitelist.
#[test]
fn test_golden_unknown_refcount_release() {
    let ir = r#"
        define void @mystery_refcount_release(ptr %obj) {
        entry:
            %old = atomicrmw sub ptr %obj, i32 1 monotonic
            %cmp = icmp eq i32 %old, 1
            br i1 %cmp, label %drop, label %done
        drop:
            call void @some_destructor(ptr %obj)
            ret void
        done:
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior.patterns.iter().any(|p| matches!(p, BehaviorPattern::ConditionalRelease { .. })),
        "Unknown function 'mystery_refcount_release' with atomicrmw sub + icmp eq should be ConditionalRelease, got: {:?}",
        behavior.patterns
    );
}

/// An unknown function with only GEP + ret
/// should be detected as PointerProjection, even though the function
/// name "weird_accessor" is not in any whitelist.
#[test]
fn test_golden_unknown_pointer_projection() {
    let ir = r#"
        define ptr @weird_accessor(ptr %obj) {
        entry:
            %field = getelementptr i8, ptr %obj, i64 24
            ret ptr %field
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior
            .patterns
            .contains(&BehaviorPattern::PointerProjection),
        "Unknown function 'weird_accessor' with GEP + ret should be PointerProjection, got: {:?}",
        behavior.patterns
    );
}

/// An unknown function that only does arithmetic
/// should be detected as PureComputation, even though the function
/// name "obscure_math_helper" is not in any whitelist.
#[test]
fn test_golden_unknown_pure_computation() {
    let ir = r#"
        define i32 @obscure_math_helper(i32 %x, i32 %y) {
        entry:
            %sum = add i32 %x, %y
            %result = mul i32 %sum, 2
            ret i32 %result
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior.patterns.contains(&BehaviorPattern::PureComputation),
        "Unknown function 'obscure_math_helper' with only arithmetic should be PureComputation, got: {:?}",
        behavior.patterns
    );
}

/// An unknown function with stores to struct fields + ret void
/// should be detected as Initialization, even though the function
/// name "custom_init" is not in any whitelist.
#[test]
fn test_golden_unknown_initialization() {
    let ir = r#"
        define void @custom_init(ptr %obj, i32 %val) {
        entry:
            %f1 = getelementptr i8, ptr %obj, i64 0
            store i32 %val, ptr %f1
            %f2 = getelementptr i8, ptr %obj, i64 4
            store i32 0, ptr %f2
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior.patterns.contains(&BehaviorPattern::Initialization),
        "Unknown function 'custom_init' with stores + ret void should be Initialization, got: {:?}",
        behavior.patterns
    );
}

// ── Debug test for operand parsing ──

/// Debug test to understand how operands are parsed for store and call instructions
#[test]
fn test_operand_parsing_debug() {
    let ir = r#"
        define i32 @try_init(ptr %out) {
        entry:
            store ptr null, ptr %out
            %ret = call i32 @do_init(ptr %out)
            %ok = icmp eq i32 %ret, 0
            br i1 %ok, label %success, label %error
        error:
            store ptr null, ptr %out
            ret i32 %ret
        success:
            ret i32 0
        }
    "#;

    let body = parse_body(ir);

    // Print all instructions with their operands
    for (i, inst) in body.instructions.iter().enumerate() {
        println!(
            "Instruction {}: kind={:?}, operands={:?}, callee={:?}, dest={:?}",
            i, inst.kind, inst.operands, inst.callee, inst.dest
        );
    }

    // Check store instructions
    let stores: Vec<_> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Store)
        .collect();

    println!("\nStore instructions:");
    for (i, store) in stores.iter().enumerate() {
        println!("  Store {}: operands={:?}", i, store.operands);
        println!("    First operand (value): {:?}", store.operands.first());
        println!("    Second operand (target): {:?}", store.operands.get(1));
    }

    // Check call instructions
    let calls: Vec<_> = body
        .instructions
        .iter()
        .filter(|i| i.kind == IRInstructionKind::Call)
        .collect();

    println!("\nCall instructions:");
    for (i, call) in calls.iter().enumerate() {
        println!(
            "  Call {}: operands={:?}, callee={:?}",
            i, call.operands, call.callee
        );
    }
}

// ── New pattern tests ──

/// Test NullGuardedRelease detection:
/// Pattern: icmp eq ptr %p, null → br → release call on non-null path
#[test]
fn test_null_guarded_release_detection() {
    let ir = r#"
        define void @safe_free(ptr %p) {
        entry:
            %is_null = icmp eq ptr %p, null
            br i1 %is_null, label %skip, label %release
        release:
            call void @free(ptr %p)
            br label %skip
        skip:
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::NullGuardedRelease { .. })),
        "Should detect NullGuardedRelease pattern for 'if (p) free(p)', got: {:?}",
        behavior.patterns
    );
}

/// Test NullGuardedRelease does NOT trigger on non-null checks
#[test]
fn test_null_guarded_release_no_false_positive() {
    let ir = r#"
        define void @no_guard(ptr %p) {
        entry:
            call void @free(ptr %p)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        !behavior
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::NullGuardedRelease { .. })),
        "Should NOT detect NullGuardedRelease without icmp null check, got: {:?}",
        behavior.patterns
    );
}

/// Test NullStoreAfterRelease detection:
/// Pattern: call @free(ptr %p) → store ptr null, ptr %slot
#[test]
fn test_null_store_after_release_detection() {
    let ir = r#"
        define void @free_and_null(ptr %p, ptr %slot) {
        entry:
            call void @free(ptr %p)
            store ptr null, ptr %slot
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::NullStoreAfterRelease { .. })),
        "Should detect NullStoreAfterRelease pattern for 'free(p); p = NULL', got: {:?}",
        behavior.patterns
    );
}

/// Test NullStoreAfterRelease does NOT trigger when no null store follows release
#[test]
fn test_null_store_after_release_no_false_positive() {
    let ir = r#"
        define void @free_no_null(ptr %p, ptr %slot) {
        entry:
            call void @free(ptr %p)
            store i32 42, ptr %slot
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        !behavior
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::NullStoreAfterRelease { .. })),
        "Should NOT detect NullStoreAfterRelease when store is not null, got: {:?}",
        behavior.patterns
    );
}

/// Test FallibleOutParamInit detection:
/// Pattern: store null → call → icmp → error null-store
#[test]
fn test_fallible_out_param_init_detection() {
    let ir = r#"
        define i32 @try_init(ptr %out) {
        entry:
            store ptr null, ptr %out
            %ret = call i32 @do_init(ptr %out)
            %ok = icmp eq i32 %ret, 0
            br i1 %ok, label %success, label %error
        error:
            store ptr null, ptr %out
            ret i32 %ret
        success:
            ret i32 0
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::FallibleOutParamInit { .. })),
        "Should detect FallibleOutParamInit pattern, got: {:?}",
        behavior.patterns
    );
}

/// Test OutParamNullOnError detection:
/// Pattern: icmp → br → error block: store null to out-param
#[test]
fn test_out_param_null_on_error_detection() {
    let ir = r#"
        define i32 @create_resource(ptr %out) {
        entry:
            %ret = call i32 @allocate(ptr %out)
            %ok = icmp eq i32 %ret, 0
            br i1 %ok, label %success, label %error
        error:
            store ptr null, ptr %out
            ret i32 %ret
        success:
            ret i32 0
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::OutParamNullOnError { .. })),
        "Should detect OutParamNullOnError pattern, got: {:?}",
        behavior.patterns
    );
}

/// Test OutParamOwnedOnSuccess detection:
/// Pattern: icmp → br → success block: out-param holds allocation
#[test]
fn test_out_param_owned_on_success_detection() {
    let ir = r#"
        define i32 @create_buffer(ptr %out, i64 %size) {
        entry:
            %ret = call i32 @validate(i64 %size)
            %ok = icmp eq i32 %ret, 0
            br i1 %ok, label %success, label %error
        success:
            %buf = call ptr @malloc(i64 %size)
            store ptr %buf, ptr %out
            ret i32 0
        error:
            store ptr null, ptr %out
            ret i32 %ret
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::OutParamOwnedOnSuccess { .. })),
        "Should detect OutParamOwnedOnSuccess pattern, got: {:?}",
        behavior.patterns
    );
}

/// Test combined fallible out-param pattern:
/// Both FallibleOutParamInit and OutParamNullOnError should be detected
#[test]
fn test_combined_fallible_out_param_patterns() {
    let ir = r#"
        define i32 @init_widget(ptr %out) {
        entry:
            store ptr null, ptr %out
            %ret = call i32 @widget_create(ptr %out)
            %ok = icmp eq i32 %ret, 0
            br i1 %ok, label %done, label %cleanup
        cleanup:
            store ptr null, ptr %out
            ret i32 %ret
        done:
            ret i32 0
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    assert!(
        behavior
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::FallibleOutParamInit { .. })),
        "Should detect FallibleOutParamInit, got: {:?}",
        behavior.patterns
    );

    assert!(
        behavior
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::OutParamNullOnError { .. })),
        "Should detect OutParamNullOnError, got: {:?}",
        behavior.patterns
    );
}

/// Test that new patterns don't interfere with existing patterns.
/// NullGuardedRelease is more specific than OwnershipTransfer, so when
/// both patterns are present, NullGuardedRelease takes precedence.
#[test]
fn test_new_patterns_coexist_with_existing() {
    // A function that has both OwnershipTransfer (malloc) and NullGuardedRelease (free with null check)
    let ir = r#"
        define void @alloc_or_free(ptr %p, i64 %size) {
        entry:
            %is_null = icmp eq ptr %p, null
            br i1 %is_null, label %alloc, label %release
        alloc:
            %buf = call ptr @malloc(i64 %size)
            ret void
        release:
            call void @free(ptr %p)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    // NullGuardedRelease is more specific — it should be detected
    // (OwnershipTransfer is skipped when NullGuardedRelease is found)
    assert!(
        behavior
            .patterns
            .iter()
            .any(|p| matches!(p, BehaviorPattern::NullGuardedRelease { .. })),
        "Should detect NullGuardedRelease from null check + free, got: {:?}",
        behavior.patterns
    );
}

/// Objective: Verify StackToGlobalEscape detection fires when alloca-derived
/// pointer is stored to a global variable.
/// Invariants:
/// - alloca + store to @global must produce StackToGlobalEscape pattern
/// - The pattern must capture the global target and alloca register
#[test]
fn test_stack_to_global_escape_detection() {
    let ir = r#"
        define void @ffi_register_callback(ptr %cb, ptr %user_data) {
entry:
            %buf = alloca [40 x i8], align 1
            store ptr %cb, ptr @g_callback, align 8
            store ptr %user_data, ptr @g_user_data, align 8
            store ptr %buf, ptr @g_last_message, align 8
            ret void
        }
    "#;
    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    let sge = behavior
        .patterns
        .iter()
        .find(|p| matches!(p, BehaviorPattern::StackToGlobalEscape { .. }));
    assert!(
        sge.is_some(),
        "Should detect StackToGlobalEscape, got: {:?}",
        behavior.patterns
    );

    if let Some(BehaviorPattern::StackToGlobalEscape {
        global_target,
        alloca_reg,
    }) = sge
    {
        assert!(
            global_target.contains("g_last_message"),
            "Global target should be g_last_message, got: {global_target}"
        );
        assert_eq!(
            alloca_reg, "%buf",
            "Alloca register should be %%buf, got: {alloca_reg}"
        );
    }
}

/// Objective: Verify ReturnAlias detection fires when function returns
/// a GEP-derived alias of an input parameter.
/// Invariants:
/// - ret of GEP(param) must produce ReturnAlias pattern
/// - Direct param return must also produce ReturnAlias pattern
#[test]
fn test_return_alias_detection_gep() {
    let ir = r#"
        define ptr @ffi_alias_input(ptr %data, i64 %len) {
entry:
            %is_null = icmp eq ptr %data, null
            %is_zero = icmp eq i64 %len, 0
            %or_cond = or i1 %is_null, %is_zero
            %half_len = lshr i64 %len, 1
            %offset_ptr = getelementptr inbounds nuw i8, ptr %data, i64 %half_len
            %result = select i1 %or_cond, ptr null, ptr %offset_ptr
            ret ptr %result
        }
    "#;
    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    let ra = behavior
        .patterns
        .iter()
        .find(|p| matches!(p, BehaviorPattern::ReturnAlias { .. }));
    assert!(
        ra.is_some(),
        "Should detect ReturnAlias for GEP-of-param, got: {:?}",
        behavior.patterns
    );

    if let Some(BehaviorPattern::ReturnAlias { aliased_param }) = ra {
        assert_eq!(
            aliased_param, "%data",
            "Aliased param should be %%data, got: {aliased_param}"
        );
    }
}

/// Objective: Verify ReturnAlias does NOT fire for functions that return
/// call results (allocations) rather than parameter aliases.
/// Invariants:
/// - ret of malloc() must NOT produce ReturnAlias
#[test]
fn test_return_alias_no_false_positive_on_alloc() {
    let ir = r#"
        define ptr @make_buffer(i64 %size) {
entry:
            %buf = call ptr @malloc(i64 %size)
            ret ptr %buf
        }
    "#;
    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    let has_return_alias = behavior
        .patterns
        .iter()
        .any(|p| matches!(p, BehaviorPattern::ReturnAlias { .. }));
    assert!(
        !has_return_alias,
        "ReturnAlias should NOT fire for allocation returns, got: {:?}",
        behavior.patterns
    );
}

// ── FreeThenCallbackUse detection tests ──

/// Objective: Verify that FreeThenCallbackUse is detected when a register is
///            freed and then passed to a subsequent call (direct or indirect).
/// Invariants: pattern contains FreeThenCallbackUse with correct freed_reg.
#[test]
fn test_free_then_callback_use_detection() {
    // This mirrors the exact IR pattern from uaf_through_ffi in c_ffi_traps.ll
    let ir = r#"
        define void @uaf_through_ffi() {
entry:
            %1 = call ptr @malloc(i64 noundef 32)
            %2 = icmp eq ptr %1, null
            br i1 %2, label %8, label %3

3:
            call void @free(ptr noundef nonnull %1)
            %4 = load ptr, ptr @g_callback, align 8
            %5 = icmp eq ptr %4, null
            br i1 %5, label %8, label %6

6:
            %7 = load ptr, ptr @g_user_data, align 8
            call void %4(ptr noundef %7, ptr noundef nonnull %1, i64 noundef 32)
            br label %8

8:
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    let ftcu = behavior
        .patterns
        .iter()
        .find(|p| matches!(p, BehaviorPattern::FreeThenCallbackUse { .. }));
    assert!(
        ftcu.is_some(),
        "Should detect FreeThenCallbackUse pattern, got: {:?}",
        behavior.patterns
    );
    match ftcu.unwrap() {
        BehaviorPattern::FreeThenCallbackUse {
            freed_reg,
            use_callee,
        } => {
            assert_eq!(
                freed_reg, "%1",
                "Freed register should be %%1, got: {freed_reg}"
            );
            // Indirect call — callee holds the function-pointer register (%4)
            assert_eq!(
                use_callee,
                &Some("%4".to_string()),
                "Indirect call should have callee set to FP register"
            );
        }
        _ => unreachable!("already matched above"),
    }
}

/// Objective: Verify that FreeThenCallbackUse detects indirect calls using freed reg.
/// Invariants: pattern fires with use_callee set to the function-pointer register.
#[test]
fn test_free_then_callback_use_direct_call() {
    let ir = r#"
        define void @buggy_func() {
entry:
            %buf = call ptr @malloc(i64 64)
            %cb = load ptr, ptr @g_callback
            call void @free(ptr %buf)
            call void %cb(ptr %buf, i64 64)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    let ftcu = behavior
        .patterns
        .iter()
        .find(|p| matches!(p, BehaviorPattern::FreeThenCallbackUse { .. }));
    assert!(
        ftcu.is_some(),
        "Should detect FreeThenCallbackUse for indirect call, got: {:?}",
        behavior.patterns
    );
    match ftcu.unwrap() {
        BehaviorPattern::FreeThenCallbackUse {
            freed_reg,
            use_callee,
        } => {
            assert_eq!(freed_reg, "%buf");
            assert_eq!(
                use_callee,
                &Some("%cb".to_string()),
                "use_callee should be the FP register %cb"
            );
        }
        _ => unreachable!(),
    }
}

/// Objective: Verify that FreeThenCallbackUse does NOT fire when there is no
///            post-free use of the freed register.
/// Invariants: no FreeThenCallbackUse pattern in a clean free-only sequence.
#[test]
fn test_free_then_callback_use_no_false_positive_clean_free() {
    let ir = r#"
        define void @clean_func() {
entry:
            %buf = call ptr @malloc(i64 64)
            call void @use_buffer(ptr %buf)
            call void @free(ptr %buf)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    let has_ftcu = behavior
        .patterns
        .iter()
        .any(|p| matches!(p, BehaviorPattern::FreeThenCallbackUse { .. }));
    assert!(
        !has_ftcu,
        "FreeThenCallbackUse should NOT fire for clean free-after-use sequence, got: {:?}",
        behavior.patterns
    );
}

/// Objective: Verify that FreeThenCallbackUse does NOT fire for double-free only.
/// Invariants: two consecutive frees without other use should not trigger this pattern.
#[test]
fn test_free_then_callback_use_no_false_positive_double_free_only() {
    let ir = r#"
        define void @double_free_only() {
entry:
            %buf = call ptr @malloc(i64 64)
            call void @free(ptr %buf)
            call void @free(ptr %buf)
            ret void
        }
    "#;

    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    // Double-free should not produce FreeThenCallbackUse — the second free is
    // a release call itself, which we explicitly skip in the detector.
    let has_ftcu = behavior
        .patterns
        .iter()
        .any(|p| matches!(p, BehaviorPattern::FreeThenCallbackUse { .. }));
    assert!(
        !has_ftcu,
        "FreeThenCallbackUse should NOT fire for double-free-only (no non-release use), \
         got: {:?}",
        behavior.patterns
    );
}

// ── HeapToGlobalEscape detection tests ──

/// Objective: Verify that HeapToGlobalEscape fires when a function parameter
///            (non-alloca pointer) is stored to a global variable.
/// Invariants:
/// - `store ptr %param, ptr @global` must produce HeapToGlobalEscape pattern
/// - The pattern must capture the global target and parameter register
#[test]
fn test_heap_to_global_escape_detection() {
    // Mirrors FN-14 from zig_ffi_bridge.c: c_register_and_store
    let ir = r#"
        define void @c_register_and_store(ptr %ptr) {
entry:
            store ptr %ptr, ptr @g_stored_ptr, align 8
            ret void
        }
    "#;
    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    let hge = behavior
        .patterns
        .iter()
        .find(|p| matches!(p, BehaviorPattern::HeapToGlobalEscape { .. }));
    assert!(
        hge.is_some(),
        "Should detect HeapToGlobalEscape for param→global store, got: {:?}",
        behavior.patterns
    );

    if let Some(BehaviorPattern::HeapToGlobalEscape {
        global_target,
        param_reg,
    }) = hge
    {
        assert!(
            global_target.contains("g_stored_ptr"),
            "Global target should be g_stored_ptr, got: {global_target}"
        );
        assert_eq!(
            param_reg, "%ptr",
            "Param register should be %%ptr, got: {param_reg}"
        );
    }
}

/// Objective: Verify that HeapToGlobalEscape does NOT fire when an alloca-derived
///            pointer is stored to a global — that should be StackToGlobalEscape instead.
/// Invariants:
/// - alloca + store to @global produces StackToGlobalEscape, NOT HeapToGlobalEscape
#[test]
fn test_heap_to_global_escape_no_false_positive_on_alloca() {
    let ir = r#"
        define void @alloca_to_global() {
entry:
            %buf = alloca [40 x i8], align 1
            store ptr %buf, ptr @g_last_message, align 8
            ret void
        }
    "#;
    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    let has_hge = behavior
        .patterns
        .iter()
        .any(|p| matches!(p, BehaviorPattern::HeapToGlobalEscape { .. }));
    assert!(
        !has_hge,
        "HeapToGlobalEscape should NOT fire for alloca→global (that's StackToGlobalEscape), got: {:?}",
        behavior.patterns
    );

    // Should have StackToGlobalEscape instead
    let has_sge = behavior
        .patterns
        .iter()
        .any(|p| matches!(p, BehaviorPattern::StackToGlobalEscape { .. }));
    assert!(
        has_sge,
        "alloca→global should produce StackToGlobalEscape, got: {:?}",
        behavior.patterns
    );
}

/// Objective: Verify that normal local stores are NOT flagged as HeapToGlobalEscape.
/// Invariants:
/// - `store ptr %param, ptr %local_alloca` should NOT produce HeapToGlobalEscape
#[test]
fn test_heap_to_global_escape_no_false_positive_local_store() {
    let ir = r#"
        define void @local_store_only(ptr %ptr) {
entry:
            %slot = alloca ptr, align 8
            store ptr %ptr, ptr %slot, align 8
            ret void
        }
    "#;
    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    let has_hge = behavior
        .patterns
        .iter()
        .any(|p| matches!(p, BehaviorPattern::HeapToGlobalEscape { .. }));
    assert!(
        !has_hge,
        "HeapToGlobalEscape should NOT fire for local (non-global) store, got: {:?}",
        behavior.patterns
    );
}

/// Objective: Verify that a function with both alloca→global AND param→global
///            stores detects BOTH patterns simultaneously.
/// Invariants:
/// - Both StackToGlobalEscape and HeapToGlobalEscape are present
#[test]
fn test_heap_and_stack_to_global_escape_coexist() {
    let ir = r#"
        define void @mixed_escapes(ptr %heap_ptr) {
entry:
            %local = alloca [16 x i8], align 1
            store ptr %local, ptr @g_stack_escape, align 8
            store ptr %heap_ptr, ptr @g_heap_escape, align 8
            ret void
        }
    "#;
    let body = parse_body(ir);
    let behavior = extract_behavior(&body);

    let sge = behavior
        .patterns
        .iter()
        .find(|p| matches!(p, BehaviorPattern::StackToGlobalEscape { .. }));
    assert!(
        sge.is_some(),
        "Should detect StackToGlobalEscape for alloca→global, got: {:?}",
        behavior.patterns
    );

    let hge = behavior
        .patterns
        .iter()
        .find(|p| matches!(p, BehaviorPattern::HeapToGlobalEscape { .. }));
    assert!(
        hge.is_some(),
        "Should detect HeapToGlobalEscape for param→global, got: {:?}",
        behavior.patterns
    );
}

/// Diagnostic: load the REAL c_ffi_traps.ll file and check if patterns are detected.
/// This test is IGNORED by default — run with `cargo test -- --ignored` to execute.
#[test]
#[ignore]
fn diag_real_file_detection() {
    use std::path::PathBuf;
    let path = PathBuf::from("/Users/scc/code/ffi-demo/output/c_ffi_traps.ll");
    assert!(path.exists(), "c_ffi_traps.ll not found at {:?}", path);
    let module = IRModule::load_from_file(&path).expect("failed to load");

    eprintln!(
        "=== Functions in module ({}) ===",
        module.function_bodies.len()
    );
    for name in module.function_bodies.keys() {
        eprintln!("  - {name}");
    }

    for (name, body) in &module.function_bodies {
        if name.contains("ffi_register_callback") || name.contains("ffi_alias_input") {
            eprintln!("\n=== {} ===", name);
            eprintln!("  Instructions ({})", body.instructions.len());
            for (i, inst) in body.instructions.iter().enumerate() {
                eprintln!(
                    "    [{}] kind={:?} dest={:?} ops={:?}",
                    i, inst.kind, inst.dest, inst.operands
                );
            }

            let behavior = extract_behavior(body);
            eprintln!("\n  Patterns detected ({}):", behavior.patterns.len());
            for p in &behavior.patterns {
                eprintln!("    - {:?}", p);
            }
            if behavior.patterns.is_empty() {
                eprintln!("    (NONE!)");
            }
        }
    }
}
