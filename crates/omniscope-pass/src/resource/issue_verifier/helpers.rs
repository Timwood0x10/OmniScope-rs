//! Helper functions for issue verification.
//!
//! Contains predicate functions, candidate classification, deduplication,
//! evidence checks, and verdict description building.

use omniscope_core::IssueCandidate;
use omniscope_semantics::resource::memory_graph::{family_to_resource_class, ResourceClass};
use omniscope_types::{EvidenceKind, FamilyId, IssueCandidateKind, VerifierVerdict};

// ---------------------------------------------------------------------------
// Library function detection (language-agnostic)
// ---------------------------------------------------------------------------

/// Check if a namespace/crate/package name is a known standard library.
///
/// This is language-agnostic — covers C++, Rust, Go, C#, Java, Python, Swift.
fn is_known_stdlib_namespace(ns: &str) -> bool {
    matches!(
        ns,
        // C++ standard library & runtime
        "std" | "__gnu_cxx" | "__cxxabiv1"
        // Rust standard library
        | "core" | "alloc" | "test" | "proc_macro"
        // Go standard library (commonly encountered)
        | "runtime" | "sync" | "time" | "net" | "os" | "fmt" | "strings"
        | "bytes" | "encoding" | "io" | "math" | "sort" | "reflect" | "syscall"
        | "internal" | "unsafe" | "unicode" | "regexp" | "path" | "bufio"
        | "strconv" | "context" | "errors" | "flag" | "hash" | "html" | "image"
        | "log" | "mime" | "rand" | "text" | "archive" | "compress" | "crypto"
        | "database" | "debug" | "embed" | "expvar" | "go" | "index" | "plugin"
        | "testing"
        // C# / .NET standard library
        | "System" | "Microsoft"
        // Java / JVM standard library
        | "java" | "javax" | "jdk" | "com.sun" | "sun"
        // Python standard library
        | "_Py" | "Py"
        // Swift standard library
        | "Swift" | "Foundation"
        // Kotlin standard library
        | "kotlin" | "kotlinx"
    )
}

/// Extract the first namespace/crate/package component from a function name.
///
/// Works for:
/// - Itanium ABI mangled names (C++, Rust): `_ZNSt`, `_ZN4core`, `_ZNKSt`, etc.
/// - Go-style dotted names: `runtime.gc`, `sync.Map`, etc.
/// - Plain names with compiler builtin prefixes: `__clang_*`, `__cxa_*`
///
/// Returns `None` for plain, non-mangled names that don't match a known
/// builtin pattern.
fn first_namespace(name: &str) -> Option<&str> {
    // Itanium ABI: _ZNSt... → std (substitution token)
    if name.starts_with("_ZNSt") || name.starts_with("_ZNKSt") {
        return Some("std");
    }

    // Itanium ABI: _ZN<digits><name>... → extract <name>
    // Examples: _ZN4core... → core, _ZN3std... → std
    if name.starts_with("_ZN") {
        let rest = &name[3..];
        let digits_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(0);
        if digits_end > 0 {
            if let Ok(len) = rest[..digits_end].parse::<usize>() {
                if digits_end + len <= rest.len() {
                    return Some(&rest[digits_end..digits_end + len]);
                }
            }
        }
        return None;
    }

    // Itanium ABI: _ZNK<digits><name>... → extract <name>
    if name.starts_with("_ZNK") {
        let rest = &name[4..];
        let digits_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(0);
        if digits_end > 0 {
            if let Ok(len) = rest[..digits_end].parse::<usize>() {
                if digits_end + len <= rest.len() {
                    return Some(&rest[digits_end..digits_end + len]);
                }
            }
        }
        return None;
    }

    // Go-style: namespace.name
    if let Some(dot_pos) = name.find('.') {
        return Some(&name[..dot_pos]);
    }

    None
}

/// Returns true if the function name belongs to a standard library or
/// third-party library (i.e., not user-defined code).
///
/// Detection strategy:
/// 1. Demangle the function name and extract the first namespace component.
/// 2. Check if the namespace is a known standard-library namespace.
/// 3. Compiler builtins and runtime functions are also excluded.
///
/// This is language-agnostic — works for C++, Rust, Go, C#, Java, etc.
/// Third-party library functions that are external declarations (not defined
/// in the current module) are detected by the caller via `module.declarations`.
pub(crate) fn is_library_function(name: &str) -> bool {
    // Compiler builtins / runtime
    if name.starts_with("__clang") || name.starts_with("__cxx") || name.starts_with("__gnu") {
        return true;
    }

    // Extract the first namespace and check against known library namespaces.
    if let Some(ns) = first_namespace(name) {
        if is_known_stdlib_namespace(ns) {
            return true;
        }
    }

    // Go-style plain names: also check the dotted prefix directly
    if let Some(dot_pos) = name.find('.') {
        let pkg = &name[..dot_pos];
        if is_known_stdlib_namespace(pkg) {
            return true;
        }
    }

    false
}

/// Determines if a resource family represents a leakable resource.
///
/// Leakable resources are those that require explicit release and can
/// leak if not properly released on all code paths. This includes:
/// - Heap memory (malloc/free, new/delete)
/// - Runtime-managed resources with explicit release (JNI refs)
/// - File descriptors (open/close, socket/close) — FD leaks exhaust the
///   per-process fd limit (256 on macOS, 1024 on Linux by default)
///
/// Non-leakable resources (Socket, ProcessHandle, ThreadHandle) and
/// Unknown families are NOT tracked for leaks. Unknown families are
/// conservatively excluded because the ownership solver may not have
/// proper release-evidence support for them (e.g., WIN32_HEAP).
///
/// # Arguments
/// * `family_id` - The resource family identifier to check.
///
/// # Returns
/// `true` if the family represents a leakable resource, `false` otherwise.
pub(crate) fn is_leakable_resource(family_id: FamilyId) -> bool {
    match family_to_resource_class(family_id) {
        ResourceClass::HeapMemory | ResourceClass::RuntimeManaged => true,
        ResourceClass::FileDescriptor => true,
        // Socket, ProcessHandle, ThreadHandle, Unknown — not tracked for leaks.
        // Unknown families are conservatively NOT treated as leakable because
        // the ownership solver may not have proper release tracking for them
        // (e.g., WIN32_HEAP/HeapAlloc+HeapFree). Explicitly-mapped families
        // (FileDescriptor, HeapMemory) are tracked; unknown families are suppressed.
        ResourceClass::Socket
        | ResourceClass::ProcessHandle
        | ResourceClass::ThreadHandle
        | ResourceClass::Unknown
        | ResourceClass::MmapRegion => false,
    }
}

/// Determines if a resource family represents memory resources.
///
/// HeapMemory and RuntimeManaged families are considered memory-like
/// resources because they require explicit release and can leak.
/// FileDescriptor, Socket, ProcessHandle are OS handle resources that
/// should not be reported as memory leaks.
///
/// # Arguments
/// * `family_id` - The resource family identifier to check.
///
/// # Returns
/// `true` if the family represents memory-like resources, `false` otherwise.
pub(crate) fn is_memory_resource(family_id: FamilyId) -> bool {
    // Map family IDs to their resource classes.
    // HeapMemory and RuntimeManaged are memory-like resources.
    // FileDescriptor, Socket, ProcessHandle are OS handles, not memory.
    matches!(
        family_to_resource_class(family_id),
        ResourceClass::HeapMemory | ResourceClass::RuntimeManaged
    )
}

/// Deduplicate leak candidates that share the same resource_id.
///
/// When IssueCandidateBuilder and LeakDetectionPass both detect the same
/// allocation as leaking, we may get duplicate candidates with the same
/// resource_id. This keeps only the strongest leak type per resource_id:
///   DefiniteLeak > ConditionalLeak > OwnershipEscapeLeak
///
/// Non-leak candidates and candidates without resource_id are never removed.
pub(crate) fn deduplicate_leak_candidates(candidates: &mut Vec<IssueCandidate>) {
    fn leak_priority(kind: &IssueCandidateKind) -> u8 {
        match kind {
            IssueCandidateKind::DefiniteLeak => 3,
            IssueCandidateKind::ConditionalLeak => 2,
            IssueCandidateKind::OwnershipEscapeLeak => 1,
            _ => 0,
        }
    }

    /// Returns true if this candidate's alloc_function is a runtime/allocator
    /// function (malloc, _Znam, etc.) — detected by alloc_caller != alloc_function.
    fn is_runtime_alloc_candidate(candidate: &IssueCandidate) -> bool {
        candidate.alloc_caller.is_some()
            && candidate.alloc_caller.as_deref() != Some(&candidate.alloc_function)
    }

    let mut to_remove: std::collections::HashSet<usize> = std::collections::HashSet::new();

    // ── Strategy 1: resource_id overlap ──
    let mut best_per_rid: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (i, candidate) in candidates.iter().enumerate() {
        if !is_leak_candidate(candidate) {
            continue;
        }
        let Some(rid) = candidate.resource_id else {
            continue;
        };
        let priority = leak_priority(&candidate.kind);
        let entry = best_per_rid.entry(rid).or_insert(i);
        let existing_priority = leak_priority(&candidates[*entry].kind);
        if priority > existing_priority {
            *entry = i;
        }
    }
    for (i, candidate) in candidates.iter().enumerate() {
        if !is_leak_candidate(candidate) {
            continue;
        }
        let Some(rid) = candidate.resource_id else {
            continue;
        };
        if let Some(&best_idx) = best_per_rid.get(&rid) {
            if best_idx != i {
                to_remove.insert(i);
            }
        }
    }

    // ── Strategy 2: alloc_caller overlap ──
    // LeakDetectionPass candidates have alloc_function = runtime function (malloc)
    // and alloc_caller = user function. IssueCandidateBuilder candidates have
    // alloc_function = user function. When a runtime candidate's alloc_caller
    // matches a user candidate's alloc_function (same alloc_family), they refer
    // to the same allocation. Remove the runtime candidate if the user candidate
    // is at least as strong (equal or higher priority).
    let mut user_leak_by_func: std::collections::HashMap<(String, FamilyId), usize> =
        std::collections::HashMap::new();
    for (i, candidate) in candidates.iter().enumerate() {
        if !is_leak_candidate(candidate) || to_remove.contains(&i) {
            continue;
        }
        if is_runtime_alloc_candidate(candidate) {
            continue; // skip runtime candidates for this map
        }
        let key = (candidate.alloc_function.clone(), candidate.alloc_family);
        let priority = leak_priority(&candidate.kind);
        let entry = user_leak_by_func.entry(key).or_insert(i);
        let existing_priority = leak_priority(&candidates[*entry].kind);
        if priority > existing_priority {
            *entry = i;
        }
    }

    // Check runtime candidates against the user map.
    for (i, candidate) in candidates.iter().enumerate() {
        if !is_leak_candidate(candidate) || to_remove.contains(&i) {
            continue;
        }
        if !is_runtime_alloc_candidate(candidate) {
            continue;
        }
        let Some(ref caller) = candidate.alloc_caller else {
            continue;
        };
        let key = (caller.clone(), candidate.alloc_family);
        if let Some(&user_idx) = user_leak_by_func.get(&key) {
            let runtime_priority = leak_priority(&candidate.kind);
            let user_priority = leak_priority(&candidates[user_idx].kind);
            // Remove the runtime candidate if the user candidate is at least as
            // strong. The user candidate has a more precise alloc_function name
            // and is better for issue reporting.
            if runtime_priority <= user_priority {
                tracing::debug!(
                    "Dedup (caller overlap): removing runtime #{} ({:?} in '{}', caller='{}') — keeping user #{} ({:?} in '{}')",
                    i, candidate.kind, candidate.alloc_function, caller,
                    user_idx, candidates[user_idx].kind, candidates[user_idx].alloc_function
                );
                to_remove.insert(i);
            }
        }
    }

    if to_remove.is_empty() {
        return;
    }

    tracing::debug!("Deduplicating {} leak candidates", to_remove.len());

    // Remove in reverse order to preserve indices.
    let mut indices: Vec<usize> = to_remove.into_iter().collect();
    indices.sort();
    for idx in indices.iter().rev() {
        candidates.remove(*idx);
    }
}

/// Checks if a function name is a known C/C++ runtime allocator.
///
/// These functions (malloc, calloc, new, etc.) are C/C++ standard library
/// allocators. When they appear as the `alloc_function` in a DoubleRelease /
/// UseAfterFree candidate without FFI evidence, it means the double-free was
/// detected *inside* the runtime allocator itself — typically a false positive
/// from runtime bookkeeping rather than a user bug.
///
/// Note: Pure deallocators (free, _ZdlPv, _ZdaPv) are NOT listed here
/// because if `alloc_function` is a deallocator (e.g., free→free), it's
/// a genuine double-free bug that should be reported.
pub(crate) fn is_runtime_allocator_function(name: &str) -> bool {
    matches!(
        name,
        "malloc" | "calloc" | "realloc" | "mmap"
    ) || name.starts_with("_Znam")   // C++ operator new[]
      || name.starts_with("_Znwm") // C++ operator new
}

/// Checks if a function name is a known C/C++ runtime deallocator.
///
/// Pure deallocators (free, munmap, _ZdlPv, _ZdaPv) when appearing as
/// `alloc_function` indicate a double-release (e.g., free→free).
/// This is only a genuine bug when called from user code; if the caller
/// is also runtime-internal, it's typically a false positive.
pub(crate) fn is_runtime_deallocator_function(name: &str) -> bool {
    matches!(
        name,
        "free" | "munmap" | "__rust_dealloc"
    ) || name.starts_with("_ZdlPv")  // C++ operator delete
      || name.starts_with("_ZdaPv") // C++ operator delete[]
}

/// Checks if a candidate is a leak type issue.
///
/// Leak type issues are those that represent memory leaks or resource leaks.
/// This includes DefiniteLeak, ConditionalLeak, and OwnershipEscapeLeak.
pub(crate) fn is_leak_candidate(candidate: &IssueCandidate) -> bool {
    matches!(
        candidate.kind,
        IssueCandidateKind::DefiniteLeak
            | IssueCandidateKind::ConditionalLeak
            | IssueCandidateKind::OwnershipEscapeLeak
    )
}

/// Checks if a candidate is an FFI-specific issue type.
///
/// These issue types only make sense in the context of cross-language
/// FFI interaction. In single-language modules, they are suppressed.
pub(crate) fn is_ffi_specific_issue(candidate: &IssueCandidate) -> bool {
    matches!(
        candidate.kind,
        IssueCandidateKind::CrossLanguageFree
            | IssueCandidateKind::UncheckedFfiReturn
            | IssueCandidateKind::NullDereference
            | IssueCandidateKind::CallbackEscape
            | IssueCandidateKind::BorrowEscape
    )
}

/// Checks whether an issue candidate refers only to extern declaration
/// functions, not executable code paths.
///
/// This check is intentionally limited to `DoubleRelease`.
/// Cross-family and cross-language candidates can be backed by acquire/release
/// flow evidence even when the release callee is an extern declaration.
pub(crate) fn is_declaration_only_candidate(
    candidate: &IssueCandidate,
    user_defined_functions: &std::collections::HashSet<String>,
    declared_functions: &std::collections::HashSet<String>,
) -> bool {
    if !matches!(candidate.kind, IssueCandidateKind::DoubleRelease) {
        return false;
    }

    // Use map_or rather than is_none_or: MSRV is 1.75,
    // but Option::is_none_or() stabilized in 1.82.
    #[allow(clippy::unnecessary_map_or)]
    {
        let names = [
            Some(candidate.alloc_function.as_str()),
            candidate.release_function.as_deref(),
        ];
        names.into_iter().flatten().any(|name| {
            let trimmed = name.trim_start_matches('@');
            declared_functions.contains(trimmed) && !user_defined_functions.contains(trimmed)
        }) && candidate.alloc_caller.as_deref().map_or(true, |c| {
            !user_defined_functions.contains(c.trim_start_matches('@'))
        }) && candidate.release_caller.as_deref().map_or(true, |c| {
            !user_defined_functions.contains(c.trim_start_matches('@'))
        })
    }
}

/// Checks if a candidate originates from a standard library / third-party function.
///
/// Standard library functions (std::function, std::string, core::*, etc.)
/// manage their own memory internally.  Their internal allocations are not
/// user-code bugs.
///
/// Detection uses a language-agnostic approach:
/// 1. Demangle the function name and extract the first namespace component.
/// 2. Check if the namespace is a known standard-library namespace.
/// 3. Check if the caller/release caller are themselves library functions.
pub(crate) fn is_stdlib_candidate(candidate: &IssueCandidate) -> bool {
    // Check the alloc_function (primary function name).
    if is_library_function(&candidate.alloc_function) {
        return true;
    }
    // Check the alloc caller (function containing the allocation).
    if let Some(ref caller) = candidate.alloc_caller {
        if is_library_function(caller) {
            return true;
        }
    }
    // Check the release caller (function containing the release).
    if let Some(ref caller) = candidate.release_caller {
        if is_library_function(caller) {
            return true;
        }
    }
    false
}

pub(crate) fn is_same_language_allocator_wrapper_noise(
    candidate: &IssueCandidate,
    index: &crate::module_index::ModuleIndex,
) -> bool {
    // Candidates with FFI evidence represent concrete cross-boundary
    // violations (e.g., free-then-callback UAF). They must not be
    // suppressed as "same-language wrapper noise" regardless of caller
    // language analysis.
    if candidate.has_ffi_evidence() {
        return false;
    }

    if !matches!(
        candidate.kind,
        IssueCandidateKind::CrossFamilyFree
            | IssueCandidateKind::CrossLanguageFree
            | IssueCandidateKind::OwnershipEscapeLeak
            | IssueCandidateKind::DoubleRelease
            | IssueCandidateKind::UseAfterFree
    ) {
        return false;
    }

    let alloc_caller = candidate
        .alloc_caller
        .as_deref()
        .unwrap_or(&candidate.alloc_function);
    let release_caller = candidate.release_caller.as_deref().unwrap_or_else(|| {
        candidate
            .release_function
            .as_deref()
            .unwrap_or(&candidate.alloc_function)
    });
    let alloc_func = candidate.alloc_function.as_str();
    let release_func = candidate.release_function.as_deref().unwrap_or(alloc_func);

    let alloc_caller_meta = index.function_meta(alloc_caller);
    let release_caller_meta = index.function_meta(release_caller);
    let alloc_func_meta = index.function_meta(alloc_func);
    let release_func_meta = index.function_meta(release_func);

    let caller_langs: Vec<_> = [alloc_caller_meta, release_caller_meta]
        .into_iter()
        .flatten()
        .filter(|m| m.language != omniscope_types::Language::Unknown)
        .map(|m| m.language)
        .collect();
    if caller_langs.is_empty() || !caller_langs.iter().all(|l| *l == caller_langs[0]) {
        return false;
    }

    let alloc_side_wrapper = alloc_func_meta
        .is_some_and(|m| !m.is_declaration && (m.calls_alloc || m.is_runtime_internal));
    let release_side_wrapper = release_func_meta
        .is_some_and(|m| !m.is_declaration && (m.calls_dealloc || m.is_runtime_internal));

    alloc_side_wrapper && release_side_wrapper
}

/// Checks if the candidate has evidence of a specific kind.
pub(crate) fn has_evidence(candidate: &IssueCandidate, kind: EvidenceKind) -> bool {
    candidate.evidence.iter().any(|e| e.kind == kind)
}

/// Checks if the candidate has an escape-related evidence of a specific kind.
pub(crate) fn has_escape_evidence(candidate: &IssueCandidate, kind: EvidenceKind) -> bool {
    candidate
        .evidence
        .iter()
        .any(|e| e.kind == kind && e.escape.is_some())
}

/// Check if an issue candidate should be suppressed because it originates
/// from an FFI bridge layer / allocator thunk context.
///
/// This handles categories A (CrossLanguageFree) and B (OwnershipViolation)
/// from the bun_alloc FP analysis:
/// - When alloc_caller or release_caller is an allocator thunk, the cross-
///   language call is expected behavior in FFI bridge layers.
/// - UseAfterFree and DoubleFree in vtable/deallocator thunk functions are
///   always FPs — the thunk is just dispatching a free through a vtable.
pub(crate) fn is_ffi_bridge_layer_candidate(
    candidate: &IssueCandidate,
    _ir_module: Option<&omniscope_ir::IRModule>,
) -> bool {
    use crate::analysis::ffi_boundary_detector::{is_allocator_thunk, is_vtable_dealloc_thunk};

    let alloc_caller = candidate
        .alloc_caller
        .as_deref()
        .unwrap_or(&candidate.alloc_function);
    let release_caller = candidate.release_caller.as_deref().unwrap_or(alloc_caller);

    // CrossLanguageFree/CrossFamilyFree in allocator thunk context → FP
    if matches!(
        candidate.kind,
        IssueCandidateKind::CrossLanguageFree | IssueCandidateKind::CrossFamilyFree
    ) && (is_allocator_thunk(release_caller, _ir_module)
        || is_allocator_thunk(alloc_caller, _ir_module))
    {
        return true;
    }

    // UseAfterFree / DoubleRelease in vtable dealloc thunk → FP
    if matches!(
        candidate.kind,
        IssueCandidateKind::UseAfterFree | IssueCandidateKind::DoubleRelease
    ) {
        // Check if the release_function (the free being called) is a vtable thunk
        let release_func = candidate
            .release_function
            .as_deref()
            .unwrap_or(&candidate.alloc_function);
        if is_vtable_dealloc_thunk(release_func, None) {
            return true;
        }
        // Also check caller context
        if is_vtable_dealloc_thunk(release_caller, None)
            || is_vtable_dealloc_thunk(alloc_caller, None)
        {
            return true;
        }
    }

    // DoubleRelease in thin wrapper function → FP
    // When a pure wrapper function (small body, single callee) has a
    // DoubleRelease candidate, the double-free signal comes from the
    // callee's internal memory management (e.g., Arc operations in
    // rustls-ffi's try_with_provider), not from the wrapper itself.
    if candidate.kind == IssueCandidateKind::DoubleRelease {
        use crate::resource::issue_candidate_builder::is_thin_wrapper_function;
        if is_thin_wrapper_function(alloc_caller, _ir_module) {
            tracing::debug!(
                "[FP-SUPPRESS] DoubleRelease suppressed: alloc_caller={} \
                 is thin wrapper function",
                alloc_caller
            );
            return true;
        }
        // Also check release_caller if different
        if alloc_caller != release_caller && is_thin_wrapper_function(release_caller, _ir_module) {
            tracing::debug!(
                "[FP-SUPPRESS] DoubleRelease suppressed: release_caller={} \
                 is thin wrapper function",
                release_caller
            );
            return true;
        }
    }

    false
}

/// Builds a human-readable description for a verified candidate.
pub(crate) fn build_verdict_description(
    candidate: &IssueCandidate,
    verdict: VerifierVerdict,
) -> String {
    let kind_label = match candidate.kind {
        IssueCandidateKind::CrossFamilyFree => "cross-family free",
        IssueCandidateKind::CrossLanguageFree => "cross-language free",
        IssueCandidateKind::UseAfterRelease => "use after release",
        IssueCandidateKind::DoubleRelease => "double release",
        IssueCandidateKind::ConditionalLeak => "conditional leak",
        IssueCandidateKind::DefiniteLeak => "definite leak",
        IssueCandidateKind::BorrowEscape => "borrow escape",
        IssueCandidateKind::CallbackEscape => "callback escape",
        IssueCandidateKind::NeedsModel => "needs model",
        IssueCandidateKind::DoubleReclaim => "double reclaim",
        IssueCandidateKind::OwnershipEscapeLeak => "ownership escape leak",
        IssueCandidateKind::UseAfterFree => "use-after-free",
        IssueCandidateKind::InvalidBorrowedFree => "invalid borrowed free",
        IssueCandidateKind::UncheckedFfiReturn => "unchecked FFI return",
        IssueCandidateKind::NullDereference => "null dereference",
        IssueCandidateKind::AbiLayoutMismatch => "ABI layout mismatch",
        IssueCandidateKind::BoundaryMisuse => "boundary type confusion",
    };

    let verdict_label = match verdict {
        VerifierVerdict::ConfirmedIssue => "confirmed",
        VerifierVerdict::ProbableIssue => "probable",
        VerifierVerdict::Diagnostic => "diagnostic",
        VerifierVerdict::ExplainedSafe => "explained safe",
    };

    match candidate.kind {
        IssueCandidateKind::CrossFamilyFree => {
            let alloc_label = format!("{:?}", candidate.alloc_family);
            let release_label = candidate
                .release_family
                .map_or("unknown".to_string(), |f| format!("{f:?}"));
            format!(
                "{kind_label}: {alloc_label} allocated in '{}' released as {release_label} in '{}' [{verdict_label}]",
                candidate.alloc_function,
                candidate.release_function.as_deref().unwrap_or("unknown")
            )
        }
        IssueCandidateKind::DefiniteLeak => {
            format!(
                "{kind_label}: resource from '{}' ({:?}) has no release on any analyzed path [{verdict_label}]",
                candidate.alloc_function, candidate.alloc_family
            )
        }
        IssueCandidateKind::ConditionalLeak => {
            format!(
                "{kind_label}: resource from '{}' ({:?}) may not be freed on all paths [{verdict_label}]",
                candidate.alloc_function, candidate.alloc_family
            )
        }
        IssueCandidateKind::NeedsModel => {
            format!(
                "{kind_label}: unknown resource family in '{}' [{verdict_label}]",
                candidate.alloc_function
            )
        }
        IssueCandidateKind::InvalidBorrowedFree => {
            format!(
                "{kind_label}: borrowed pointer in '{}' passed to release function [{verdict_label}]",
                candidate.alloc_function
            )
        }
        _ => {
            format!(
                "{kind_label} in '{}' [{verdict_label}]",
                candidate.alloc_function
            )
        }
    }
}
