//! Pattern-specific issue candidate generators.
//!
//! Contains candidate generation logic for patterns detected from
//! IR behavior facts (Phase 3 semantic analysis). These were added
//! incrementally by P2b/P2c and P1 agents:
//!
//! - **BorrowEscape** patterns: StackToGlobalEscape, HeapToGlobalEscape, ReturnAlias
//! - **AbiLayoutPadding** / **TypeConfusion** candidates (P1-3)
//! - **FreeThenCallbackUse** candidates (P2b/P2c)
//! - **BufferOverflow** candidates (P1-5)

use omniscope_core::issue_candidate::FfiEvidence;
use omniscope_core::IssueCandidate;
use omniscope_semantics::SemanticFact;
use omniscope_types::{FamilyId, IssueCandidateKind, VerifierVerdict};

use super::helpers::{
    function_returns_pointer, is_known_pointer_projection, looks_like_ffi_or_export,
};

/// Generate pattern-based candidates from semantic facts.
///
/// Iterates over semantic facts and creates `IssueCandidate` entries for
/// recognized IR behavior patterns: StackToGlobalEscape, HeapToGlobalEscape,
/// ReturnAlias, AbiLayoutPadding, TypeConfusion, FreeThenCallbackUse,
/// and BufferOverflow.
///
/// Returns `(candidates, next_id)` where `next_id` is incremented for each
/// generated candidate.
pub(crate) fn generate_pattern_candidates(
    semantic_facts: &[SemanticFact],
    mut next_id: u64,
    ir_module: Option<&omniscope_ir::IRModule>,
) -> Vec<IssueCandidate> {
    let mut candidates = Vec::new();

    for fact in semantic_facts {
        let func_name = match fact.key.as_symbol() {
            Some(name) => name,
            None => continue,
        };

        // ── StackToGlobalEscape ──
        if fact.evidence.contains("StackToGlobalEscape") {
            candidates.push(build_stack_to_global_escape_candidate(
                next_id, func_name, fact,
            ));
            next_id += 1;
        }

        // ── HeapToGlobalEscape ──
        if fact.evidence.contains("HeapToGlobalEscape") {
            candidates.push(build_heap_to_global_escape_candidate(
                next_id, func_name, fact,
            ));
            next_id += 1;
        }

        // ── ReturnAlias ──
        if fact.evidence.contains("ReturnAlias") {
            if let Some(cand) = build_return_alias_candidate(next_id, func_name, fact, ir_module) {
                candidates.push(cand);
                next_id += 1;
            }
        }

        // ── AbiLayoutPadding / AbiLayoutDetection ──
        if fact.kind == omniscope_semantics::SemanticKind::AbiLayoutPadding
            || fact.evidence.contains("AbiLayoutDetection")
        {
            candidates.push(build_abi_layout_padding_candidate(next_id, func_name, fact));
            next_id += 1;
        }

        // ── StructWidthMismatch / TypeWidthMismatch (TypeConfusion) ──
        if fact.evidence.contains("StructWidthMismatch")
            || fact.evidence.contains("TypeWidthMismatch")
        {
            candidates.push(build_type_confusion_candidate(next_id, func_name, fact));
            next_id += 1;
        }

        // ── FreeThenCallbackUse ──
        if fact.evidence.contains("FreeThenCallbackUse") {
            candidates.push(build_free_then_callback_use_candidate(
                next_id, func_name, fact,
            ));
            next_id += 1;
        }

        // ── BufferOverflow ──
        if fact.evidence.contains("BufferOverflow") {
            candidates.push(build_buffer_overflow_candidate(next_id, func_name, fact));
            next_id += 1;
        }
    }

    candidates
}

// ── Individual pattern builders ────────────────────────────────────────

fn build_stack_to_global_escape_candidate(
    id: u64,
    func_name: &str,
    fact: &SemanticFact,
) -> IssueCandidate {
    use omniscope_types::EvidenceKind;

    let mut candidate = IssueCandidate::new(
        id,
        IssueCandidateKind::BorrowEscape,
        FamilyId::UNKNOWN,
        func_name,
    )
    .with_description(format!(
        "stack-local pointer escapes to global in {} — use-after-return",
        func_name
    ))
    .with_alloc_caller(func_name);

    candidate.add_evidence(
        omniscope_types::Evidence::new(
            EvidenceKind::GlobalStore,
            format!("StackToGlobalEscape: {}", fact.evidence),
        )
        .with_confidence(0.75),
    );
    // Pre-set verdict to ProbableIssue — this pattern is strong but
    // may have legitimate uses (e.g., intentional static caching)
    candidate.verdict = Some(VerifierVerdict::ProbableIssue);
    // Stack-to-global escape is inherently a cross-boundary safety issue:
    // the dangling pointer survives beyond the function scope and can be
    // accessed from any code that reads the global.  Set FFI evidence so
    // the single-language filter does not suppress this candidate.
    candidate = candidate.with_ffi_evidence(FfiEvidence::CrossLanguageCall {
        caller_lang: "C".into(),
        callee_lang: "global".into(),
    });

    candidate
}

fn build_heap_to_global_escape_candidate(
    id: u64,
    func_name: &str,
    fact: &SemanticFact,
) -> IssueCandidate {
    use omniscope_types::EvidenceKind;

    let mut candidate = IssueCandidate::new(
        id,
        IssueCandidateKind::BorrowEscape,
        FamilyId::UNKNOWN,
        func_name,
    )
    .with_description(format!(
        "heap/parameter pointer escapes to global in {} — potential UAF",
        func_name
    ))
    .with_alloc_caller(func_name);

    candidate.add_evidence(
        omniscope_types::Evidence::new(
            EvidenceKind::GlobalStore,
            format!("HeapToGlobalEscape: {}", fact.evidence),
        )
        .with_confidence(0.80),
    );
    // Heap-to-global escape is a stronger signal than stack-to-global
    // because heap pointers have indefinite lifetime — storing them to
    // globals creates a dangling global reference when the heap allocation
    // is freed. Pre-set as ProbableIssue.
    candidate.verdict = Some(VerifierVerdict::ProbableIssue);
    // Heap-to-global escape is an FFI-safety issue: the global reference
    // can outlive the allocation and be accessed from any translation unit.
    // Set FFI evidence so the single-language filter does not suppress it.
    candidate = candidate.with_ffi_evidence(FfiEvidence::CrossLanguageCall {
        caller_lang: "C".into(),
        callee_lang: "global".into(),
    });

    candidate
}

/// Build a ReturnAlias BorrowEscape candidate, or return None if filtered.
///
/// Applies three filters before generating the candidate:
/// 1. Known pointer-projection utilities are excluded (never bugs).
/// 2. Non-FFI/export functions are excluded (internal helpers are safe).
/// 3. Non-pointer return types are excluded (value copy, not dangling pointer).
fn build_return_alias_candidate(
    id: u64,
    func_name: &str,
    fact: &SemanticFact,
    ir_module: Option<&omniscope_ir::IRModule>,
) -> Option<IssueCandidate> {
    use omniscope_types::{Evidence, EvidenceKind};

    // Exclude functions that are known pointer-projection utilities
    // (e.g., as_ptr, as_mut_ptr, data() methods)
    if is_known_pointer_projection(func_name) {
        eprintln!(
            "[RA-FILTER] {} skipped: known pointer projection",
            func_name
        );
        return None;
    }

    // Only flag ReturnAlias for functions that look like FFI exports
    // or public API boundaries.
    if !looks_like_ffi_or_export(func_name) {
        return None;
    }

    // Return-type guard: only meaningful when function returns a pointer type
    if !function_returns_pointer(func_name, ir_module) {
        eprintln!(
            "[RA-FILTER] {} skipped: return type is not a pointer — \
             value-copy function cannot produce ReturnAlias borrow escape",
            func_name
        );
        return None;
    }

    let mut candidate = IssueCandidate::new(
        id,
        IssueCandidateKind::BorrowEscape,
        FamilyId::UNKNOWN,
        func_name,
    )
    .with_description(format!(
        "return value aliases input parameter in {} — no ownership transfer annotation",
        func_name
    ))
    .with_alloc_caller(func_name);

    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::IrPattern,
            format!("ReturnAlias: {}", fact.evidence),
        )
        .with_confidence(0.55),
    );
    // Return-alias is lower confidence than stack-to-global because
    // many legitimate APIs return parameter-derived pointers.
    // Mark as Diagnostic — needs human review.
    candidate.verdict = Some(VerifierVerdict::Diagnostic);
    // Return-alias is an FFI boundary concern: the caller may incorrectly
    // assume ownership of the returned pointer and free it.  Set FFI
    // evidence so the single-language filter does not suppress it.
    candidate = candidate.with_ffi_evidence(FfiEvidence::CrossLanguageCall {
        caller_lang: "C".into(),
        callee_lang: "caller".into(),
    });

    Some(candidate)
}

fn build_abi_layout_padding_candidate(
    id: u64,
    func_name: &str,
    fact: &SemanticFact,
) -> IssueCandidate {
    use omniscope_types::{Evidence, EvidenceKind};

    let struct_name = match &fact.key {
        omniscope_semantics::SemanticKey::Symbol(s) => s.as_str(),
        _ => func_name,
    };

    let mut candidate = IssueCandidate::new(
        id,
        IssueCandidateKind::AbiLayoutMismatch,
        FamilyId::UNKNOWN,
        struct_name,
    )
    .with_description(format!(
        "ABI layout mismatch: struct '{}' has padding/alignment issues that cause incorrect field offsets at FFI boundaries — {}",
        struct_name, fact.evidence
    ))
    .with_alloc_caller(func_name);

    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::AbiLayoutMismatch,
            format!("AbiLayoutPadding: {}", fact.evidence),
        )
        .with_confidence(fact.confidence_score()),
    );

    // Set FFI evidence: this is inherently an FFI boundary issue
    candidate = candidate.with_ffi_evidence(FfiEvidence::CrossLanguageCall {
        caller_lang: "C".into(),
        callee_lang: "unknown".into(),
    });
    // Pre-set as ProbableIssue — ABI layout mismatches are real bugs
    // when detected by the layout analyzer, not just theoretical
    candidate.verdict = Some(VerifierVerdict::ProbableIssue);

    candidate
}

fn build_type_confusion_candidate(id: u64, func_name: &str, fact: &SemanticFact) -> IssueCandidate {
    use omniscope_types::{Evidence, EvidenceKind};

    let mut candidate = IssueCandidate::new(
        id,
        IssueCandidateKind::BoundaryMisuse,
        FamilyId::UNKNOWN,
        func_name,
    )
    .with_description(format!(
        "boundary type confusion in {}: {}",
        func_name, fact.evidence
    ))
    .with_alloc_caller(func_name);

    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::CrossLanguageFree,
            format!("TypeConfusion: {}", fact.evidence),
        )
        .with_confidence(fact.confidence_score()),
    );

    // Set FFI evidence — this is inherently a cross-boundary issue
    candidate = candidate.with_ffi_evidence(FfiEvidence::CrossLanguageCall {
        caller_lang: "unknown".into(),
        callee_lang: "unknown".into(),
    });
    // Pre-set as ProbableIssue — struct width mismatches at FFI
    // boundaries cause silent data corruption (FN-8 class bug)
    candidate.verdict = Some(VerifierVerdict::ProbableIssue);

    candidate
}

fn build_free_then_callback_use_candidate(
    id: u64,
    func_name: &str,
    fact: &SemanticFact,
) -> IssueCandidate {
    use omniscope_types::{Evidence, EvidenceKind};

    // Use UNKNOWN family rather than hardcoding C_HEAP.
    // The IR pattern detects "free(reg) then call(cb, reg)" but
    // cannot determine which resource family the free operated on.
    let mut candidate = IssueCandidate::new(
        id,
        IssueCandidateKind::UseAfterFree,
        FamilyId::UNKNOWN,
        func_name,
    )
    .with_description(format!(
        "freed pointer passed to callback/FFI in {} — use-after-free (CWE-416)",
        func_name
    ))
    .with_alloc_caller(func_name);

    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::UseAfterFree,
            format!("FreeThenCallbackUse: {}", fact.evidence),
        )
        .with_confidence(0.85),
    );
    // Mark as FFI-evidenced: this pattern involves passing a freed
    // pointer to a function-pointer invocation (callback/FFI boundary).
    candidate.ffi_evidence = Some(FfiEvidence::CrossLanguageCall {
        caller_lang: "C".into(),
        callee_lang: "callback".into(),
    });
    // Free-then-callback-use is a strong UAF signal — the same register
    // is freed and then passed to another call. Pre-set as ProbableIssue.
    candidate.verdict = Some(VerifierVerdict::ProbableIssue);

    candidate
}

fn build_buffer_overflow_candidate(
    id: u64,
    func_name: &str,
    fact: &SemanticFact,
) -> IssueCandidate {
    use omniscope_types::{Evidence, EvidenceKind};

    let mut candidate = IssueCandidate::new(
        id,
        IssueCandidateKind::DefiniteLeak,
        FamilyId::UNKNOWN,
        func_name,
    )
    .with_description(format!(
        "constant buffer overflow in {} — memory operation writes beyond buffer boundary (CWE-120)",
        func_name
    ))
    .with_alloc_caller(func_name);

    candidate.add_evidence(
        Evidence::new(
            EvidenceKind::IrPattern,
            format!("BufferOverflow: {}", fact.evidence),
        )
        .with_confidence(0.92),
    );
    // Constant overflow is a definitive bug — pre-set as ConfirmedIssue.
    candidate.verdict = Some(VerifierVerdict::ConfirmedIssue);

    candidate
}
