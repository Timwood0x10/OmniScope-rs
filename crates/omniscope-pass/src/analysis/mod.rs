//! Analysis passes for FFI and memory safety.
//!
//! This module provides analysis passes for detecting FFI issues.
//! The FFIBoundaryPass uses CallGraphPass and FamilyRegistry to
//! produce actionable diagnostics.

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::{
    BoundaryKind, Confidence, FFIBoundary, Fact, FactKind, Issue, IssueKind, Result, Severity,
};
use omniscope_semantics::{
    assess_ffi_safety, FFIVerdict, FamilyRegistry, SymbolEffect, SyscallSemantic,
};
use omniscope_types::call_graph_types::CrossLangEdge;
use std::path::PathBuf;
use tracing::{debug, info};

/// FFI boundary info for emit_ffi_issue.
///
/// Groups caller/callee names and languages to avoid
/// excessive function arguments (clippy::too_many_arguments).
struct FFIBoundaryInfo {
    caller_name: String,
    callee_name: String,
    caller_lang: omniscope_types::config::Language,
    callee_lang: omniscope_types::config::Language,
}

pub mod borrow_escape;
pub mod call_graph;
pub mod danger_surface;
pub mod ffi_boundary_detector;
pub mod heap_provenance;
pub mod interior_mutability;
pub mod noise_reduction;
pub mod raii_drop;
pub mod surface_classifier_pass;
pub mod write_to_immutable;

pub use borrow_escape::BorrowEscapePass;
pub use call_graph::CallGraphPass;
pub use danger_surface::DangerSurfacePass;
pub use heap_provenance::HeapProvenancePass;
pub use interior_mutability::InteriorMutabilityPass;
pub use noise_reduction::{NoiseReduction, PrecisionMetrics};
pub use raii_drop::RaiiDropPass;
pub use surface_classifier_pass::SurfaceClassifierPass;
pub use write_to_immutable::WriteToImmutablePass;

/// FFI boundary detection pass.
///
/// Uses CrossLangEdge data from CallGraphPass and checks each
/// boundary against the FamilyRegistry for resource family classification.
/// Produces Issue entries with FFIBoundary metadata.
pub struct FFIBoundaryPass;

impl FFIBoundaryPass {
    /// Creates a new FFI boundary pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for FFIBoundaryPass {
    fn name(&self) -> &'static str {
        "FFIBoundary"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["RawFactCollector"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();
        let registry = FamilyRegistry::new();

        // Try to get cross-lang edges from CallGraphPass (if registered)
        let cross_lang_edges: Vec<CrossLangEdge> = ctx.get("cross_lang_edges").unwrap_or_default();

        // If no CallGraph edges, infer FFI boundaries from IRModule directly
        let ir_module: Option<omniscope_ir::IRModule> = ctx.get("ir_module");

        let mut issues: Vec<Issue> = Vec::new();
        let mut boundary_count: usize = 0;

        // Track seen boundaries to avoid duplicate issues
        let mut seen_boundaries: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();

        // Process CallGraph-derived edges
        for edge in &cross_lang_edges {
            if !edge.is_ffi_boundary {
                continue;
            }
            let boundary_key = (edge.caller_name.clone(), edge.callee_name.clone());
            if !seen_boundaries.insert(boundary_key) {
                continue;
            }
            boundary_count += 1;
            self.emit_ffi_issue(
                ctx,
                &registry,
                &FFIBoundaryInfo {
                    caller_name: edge.caller_name.clone(),
                    callee_name: edge.callee_name.clone(),
                    caller_lang: edge.caller_lang,
                    callee_lang: edge.callee_lang,
                },
                &mut issues,
            );
        }

        // If no CallGraph edges, scan IRModule for FFI boundaries
        if cross_lang_edges.is_empty() {
            if let Some(ref module) = ir_module {
                // Use language detector to identify function languages
                let detector = omniscope_semantics::LanguageDetector::new();

                for call in &module.calls {
                    let callee_name = call.callee.trim_start_matches('@');
                    let caller_name = call.caller.trim_start_matches('@');

                    // Skip LLVM intrinsics — they are not FFI boundaries
                    if callee_name.starts_with("llvm.") {
                        continue;
                    }

                    // Determine callee language
                    let callee_lang = detector.detect_from_function(callee_name);

                    // Determine caller language
                    // If the caller is a defined function, default to C (common case for .c files)
                    // unless the detector identifies it as something else
                    let caller_lang = if module.functions.contains_key(call.caller.as_str())
                        || module.functions.contains_key(&call.caller)
                    {
                        let detected = detector.detect_from_function(caller_name);
                        // If unknown, assume C (most .ll files from C code)
                        if detected == omniscope_types::config::Language::Unknown {
                            omniscope_types::config::Language::C
                        } else {
                            detected
                        }
                    } else {
                        detector.detect_from_function(caller_name)
                    };

                    // Check if this is a cross-language call
                    let is_cross_lang = caller_lang != callee_lang
                        && callee_lang != omniscope_types::config::Language::Unknown
                        && caller_lang != omniscope_types::config::Language::Unknown;

                    // Check for C++ mangled name called from C — definite FFI boundary
                    let is_cpp_ffi = callee_name.starts_with("_Z")
                        && caller_lang == omniscope_types::config::Language::C;

                    // Check for Rust/Go/Zig/Java calling external C functions
                    // (callee language is Unknown but it's an external call = likely C)
                    let is_ffi_to_c = caller_lang != omniscope_types::config::Language::Unknown
                        && caller_lang != omniscope_types::config::Language::C
                        && callee_lang == omniscope_types::config::Language::Unknown
                        && call.is_external;

                    debug!(
                        "FFI check: {} ({:?}) -> {} ({:?}) ext={} cross={} cpp_ffi={} ffi_to_c={}",
                        caller_name,
                        caller_lang,
                        callee_name,
                        callee_lang,
                        call.is_external,
                        is_cross_lang,
                        is_cpp_ffi,
                        is_ffi_to_c
                    );

                    if is_cross_lang || is_cpp_ffi || is_ffi_to_c {
                        let boundary_key = (caller_name.to_string(), callee_name.to_string());
                        if seen_boundaries.insert(boundary_key) {
                            boundary_count += 1;
                            let final_caller = caller_lang;
                            let final_callee = if is_cpp_ffi {
                                omniscope_types::config::Language::Cpp
                            } else if is_ffi_to_c {
                                omniscope_types::config::Language::C
                            } else {
                                callee_lang
                            };
                            self.emit_ffi_issue(
                                ctx,
                                &registry,
                                &FFIBoundaryInfo {
                                    caller_name: caller_name.to_string(),
                                    callee_name: callee_name.to_string(),
                                    caller_lang: final_caller,
                                    callee_lang: final_callee,
                                },
                                &mut issues,
                            );
                        }
                    }
                }
            }
        }

        let issues_found = issues.len();
        info!(
            "FFIBoundaryPass: {} issues found across {} FFI boundaries",
            issues_found, boundary_count
        );

        // Keep the IRModule in context for downstream passes
        if let Some(module) = ir_module {
            ctx.store("ir_module", module);
        }

        let mut result = PassResult::new(self.name())
            .with_nodes(boundary_count)
            .with_duration(start.elapsed().as_millis() as u64);
        for issue in issues {
            result.add_issue(issue);
        }
        Ok(result)
    }
}

impl FFIBoundaryPass {
    /// Emits an FFI boundary issue for a cross-language call.
    ///
    /// Uses semantic tree analysis to determine severity:
    /// - MemoryManagement syscall → HIGH severity (potential CrossFamilyFree)
    /// - DataQuery/EnvironmentConfig → SUPPRESSED (not a memory safety issue)
    /// - InternalDispatch → SUPPRESSED (by-design FFI boundary)
    /// - ComputeAccelerated → SUPPRESSED (pure computation)
    /// - StringManipulation → SUPPRESSED (caller owns buffer)
    /// - Unknown → LOW severity (conservative, but not noise)
    fn emit_ffi_issue(
        &self,
        ctx: &mut PassContext,
        registry: &FamilyRegistry,
        boundary: &FFIBoundaryInfo,
        issues: &mut Vec<Issue>,
    ) {
        // ── IR instruction-level semantic derivation ──
        let ir_module: Option<omniscope_ir::IRModule> = ctx.get("ir_module");

        let assessment = if let Some(ref module) = ir_module {
            assess_ffi_safety(&boundary.callee_name, &boundary.caller_name, module)
        } else {
            // No IR module available — fall back to name-based heuristic
            let syscall_semantic = SyscallSemantic::classify(&boundary.callee_name);
            let verdict = if syscall_semantic.involves_memory_ownership() {
                FFIVerdict::ConcernOwnershipTransfer
            } else if syscall_semantic == SyscallSemantic::Unknown {
                FFIVerdict::Unknown
            } else {
                FFIVerdict::SafeNoOwnership
            };
            omniscope_semantics::FFISafetyAssessment {
                callee: boundary.callee_name.clone(),
                caller: boundary.caller_name.clone(),
                caller_behavior: None,
                callee_behavior: None,
                verdict,
                evidence: Vec::new(),
            }
        };

        // Store IR module back for downstream passes
        if let Some(module) = ir_module {
            ctx.store("ir_module", module);
        }

        debug!(
            "FFI semantic: {} -> {} verdict={:?} score={:.2}",
            boundary.caller_name,
            boundary.callee_name,
            assessment.verdict,
            assessment.safety_score()
        );

        // Skip FFI boundaries that are semantically safe (derived from IR patterns)
        if assessment.should_suppress_issue() {
            debug!(
                "FFI skip: {} -> {} ({:?}): {}",
                boundary.caller_name,
                boundary.callee_name,
                assessment.verdict,
                assessment
                    .evidence
                    .first()
                    .map(|e| e.reasoning.as_str())
                    .unwrap_or("safe pattern")
            );
            return;
        }

        // ── Severity determination based on semantic assessment ──
        let family_entry = registry.lookup(&boundary.callee_name);

        let (kind, severity, confidence, description) = match assessment.verdict {
            FFIVerdict::ConcernOwnershipTransfer => match family_entry {
                Some(entry) => {
                    let (kind, conf) = match entry.effect {
                        SymbolEffect::Acquire => {
                            (IssueKind::OwnershipViolation, Confidence::Medium)
                        }
                        SymbolEffect::Release => (IssueKind::CrossLanguageFree, Confidence::High),
                        SymbolEffect::ConditionalRelease => {
                            (IssueKind::CrossLanguageFree, Confidence::Medium)
                        }
                        SymbolEffect::Retain => (IssueKind::CrossLanguageFree, Confidence::Low),
                        // Escape (into_raw) is intentional transfer, lower severity
                        SymbolEffect::Escape => (IssueKind::OwnershipViolation, Confidence::Low),
                        // Reclaim (from_raw) re-acquires ownership from raw pointer
                        SymbolEffect::Reclaim => {
                            (IssueKind::OwnershipViolation, Confidence::Medium)
                        }
                    };
                    let family_name = registry
                        .family(entry.family_id)
                        .map(|f| f.name.as_str())
                        .unwrap_or("unknown");
                    (
                            kind,
                            Severity::Warning,
                            conf,
                            format!(
                                "FFI boundary: {} ({:?}) -> {} ({:?}) [family={}, effect={:?}, verdict=OwnershipTransfer]",
                                boundary.caller_name, boundary.caller_lang, boundary.callee_name, boundary.callee_lang,
                                family_name, entry.effect
                            ),
                        )
                }
                None => (
                    IssueKind::FfiUnsafeCall,
                    Severity::Note,
                    Confidence::Medium,
                    format!(
                        "FFI boundary: {} ({:?}) -> {} ({:?}) [ownership transfer, unknown family]",
                        boundary.caller_name,
                        boundary.caller_lang,
                        boundary.callee_name,
                        boundary.callee_lang
                    ),
                ),
            },
            FFIVerdict::Unknown => match family_entry {
                Some(entry) => {
                    let family_name = registry
                        .family(entry.family_id)
                        .map(|f| f.name.as_str())
                        .unwrap_or("unknown");
                    (
                        IssueKind::FfiUnsafeCall,
                        Severity::Note,
                        Confidence::Low,
                        format!(
                            "FFI boundary: {} ({:?}) -> {} ({:?}) [family={}, verdict=Unknown]",
                            boundary.caller_name,
                            boundary.caller_lang,
                            boundary.callee_name,
                            boundary.callee_lang,
                            family_name
                        ),
                    )
                }
                // Unknown verdict with no family entry is low-signal noise.
                // Suppress: these are FFI calls to unknown external functions
                // with no evidence of ownership implications.
                None => {
                    debug!(
                        "FFI suppressed: {} -> {} (Unknown verdict, no family entry)",
                        boundary.caller_name, boundary.callee_name
                    );
                    return;
                }
            },
            // Safe patterns are already filtered out above
            _ => unreachable!(),
        };

        let boundary_kind = classify_boundary(&boundary.caller_lang, &boundary.callee_lang);

        let issue_id = ctx.next_issue_id();
        let location = omniscope_core::IssueLocation::new(std::path::PathBuf::from("<ffi>"), 0)
            .with_function(&boundary.caller_name);
        let issue = Issue::new(issue_id, kind, severity, description)
            .with_confidence(confidence)
            .with_symbol(&boundary.callee_name)
            .with_location(location)
            .with_ffi_boundary(FFIBoundary {
                caller_name: boundary.caller_name.clone(),
                callee_name: boundary.callee_name.clone(),
                caller_lang: boundary.caller_lang,
                callee_lang: boundary.callee_lang,
                boundary_kind,
            });

        ctx.add_fact(Fact::new(
            issue_id,
            FactKind::FFIBoundary,
            omniscope_core::fact::FactLocation::new(PathBuf::from("ffi_analysis"), 0),
        ));

        debug!(
            "FFIBoundary issue: {:?} id={} verdict={:?} score={:.2}",
            issue.kind,
            issue_id,
            assessment.verdict,
            assessment.safety_score()
        );
        let outcome = ctx.emit_issue(issue.clone());
        if outcome.is_allowed() {
            issues.push(issue);
        }
    }
}

impl Default for FFIBoundaryPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify the boundary kind based on the caller/callee languages.
fn classify_boundary(
    caller_lang: &omniscope_types::config::Language,
    callee_lang: &omniscope_types::config::Language,
) -> BoundaryKind {
    use omniscope_types::config::Language;
    match (caller_lang, callee_lang) {
        (Language::Rust, Language::C | Language::Cpp) => BoundaryKind::RustToC,
        (Language::C | Language::Cpp, Language::Rust) => BoundaryKind::CToRust,
        (Language::Zig, Language::C | Language::Cpp) => BoundaryKind::ZigToC,
        (Language::Go, Language::C | Language::Cpp) => BoundaryKind::GoToC,
        (Language::Python, Language::C | Language::Cpp) => BoundaryKind::PythonToC,
        (Language::Java, Language::C | Language::Cpp) => BoundaryKind::JavaToC,
        (Language::C, Language::Cpp) => BoundaryKind::CToRust, // C→C++ bridge
        _ => BoundaryKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_boundary_pass_creation() {
        let pass = FFIBoundaryPass::new();
        assert_eq!(pass.name(), "FFIBoundary");
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert_eq!(pass.dependencies(), vec!["RawFactCollector"]);
    }

    #[test]
    fn test_boundary_kind_classification() {
        use omniscope_types::config::Language;
        assert_eq!(
            classify_boundary(&Language::Rust, &Language::C),
            BoundaryKind::RustToC,
            "Rust→C must be RustToC"
        );
        assert_eq!(
            classify_boundary(&Language::C, &Language::Rust),
            BoundaryKind::CToRust,
            "C→Rust must be CToRust"
        );
        assert_eq!(
            classify_boundary(&Language::Go, &Language::C),
            BoundaryKind::GoToC,
            "Go→C must be GoToC"
        );
    }
}
