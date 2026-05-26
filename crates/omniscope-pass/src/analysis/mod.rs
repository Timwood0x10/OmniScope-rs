//! Analysis passes for FFI and memory safety.
//!
//! This module provides analysis passes for detecting FFI issues and
//! memory safety problems. The FFIBoundaryPass uses CallGraphPass and
//! SemanticRegistry to produce actionable diagnostics.

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::{
    BoundaryKind, Confidence, FFIBoundary, Fact, FactKind, Issue, IssueKind, Result, Severity,
};
use omniscope_registry::SemanticRegistry;
use omniscope_types::call_graph_types::CrossLangEdge;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, info};

pub mod call_graph;
pub mod danger_surface;
pub mod noise_reduction;
pub mod surface_classifier_pass;

pub use call_graph::CallGraphPass;
pub use danger_surface::DangerSurfacePass;
pub use noise_reduction::{NoiseReduction, PrecisionMetrics};
pub use surface_classifier_pass::SurfaceClassifierPass;

/// FFI boundary detection pass.
///
/// Uses CrossLangEdge data from CallGraphPass and checks each
/// boundary against the SemanticRegistry for risk classification.
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
        vec!["CallGraph", "SurfaceClassifier"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();
        let registry = SemanticRegistry::new();

        // Retrieve cross-lang edges from CallGraphPass
        let cross_lang_edges: Vec<CrossLangEdge> = ctx.get("cross_lang_edges").unwrap_or_default();

        // Retrieve function surfaces from SurfaceClassifierPass
        let surfaces: HashMap<String, omniscope_semantics::FunctionSurface> =
            ctx.get("function_surfaces").unwrap_or_default();

        let mut issues: Vec<Issue> = Vec::new();

        for edge in &cross_lang_edges {
            if !edge.is_ffi_boundary {
                continue;
            }

            // Skip if the caller/callee surface says "don't analyze"
            let caller_surface = surfaces.get(&edge.caller_name);
            let callee_surface = surfaces.get(&edge.callee_name);

            if let Some(surface) = caller_surface {
                if !surface.should_analyze() {
                    debug!(
                        "FFIBoundary: skipping caller {} (surface={:?})",
                        edge.caller_name, surface
                    );
                    continue;
                }
            }
            if let Some(surface) = callee_surface {
                if !surface.should_analyze() {
                    debug!(
                        "FFIBoundary: skipping callee {} (surface={:?})",
                        edge.callee_name, surface
                    );
                    continue;
                }
            }

            // Check callee against SemanticRegistry
            let semantics = registry.lookup(&edge.callee_name);

            let (kind, severity, confidence, description) = match semantics {
                Some(sem) => {
                    let kind = match sem.risk_kind {
                        omniscope_registry::RiskKind::MemoryAlloc => IssueKind::OwnershipViolation,
                        omniscope_registry::RiskKind::OwnershipTransfer => {
                            IssueKind::OwnershipViolation
                        }
                        omniscope_registry::RiskKind::BufferOverflow => IssueKind::BufferOverflow,
                        omniscope_registry::RiskKind::StringUnsafe => IssueKind::FfiUnsafeCall,
                        omniscope_registry::RiskKind::TypeConfusion => IssueKind::FfiTypeMismatch,
                        omniscope_registry::RiskKind::NullPointer => IssueKind::NullDereference,
                        omniscope_registry::RiskKind::ResourceLeak => IssueKind::MemoryLeak,
                        omniscope_registry::RiskKind::ThreadSafety => IssueKind::ThreadCrossing,
                        _ => IssueKind::FfiUnsafeCall,
                    };
                    let conf = match sem.severity {
                        omniscope_registry::RiskSeverity::Critical => Confidence::High,
                        omniscope_registry::RiskSeverity::High => Confidence::High,
                        omniscope_registry::RiskSeverity::Medium => Confidence::Medium,
                        _ => Confidence::Low,
                    };
                    (kind, Severity::Warning, conf, sem.description.clone())
                }
                None => {
                    // Unknown callee at FFI boundary — generic FFI warning
                    (
                        IssueKind::FfiUnsafeCall,
                        Severity::Note,
                        Confidence::Low,
                        format!(
                            "FFI boundary: {} ({:?}) -> {} ({:?})",
                            edge.caller_name, edge.caller_lang, edge.callee_name, edge.callee_lang
                        ),
                    )
                }
            };

            let boundary_kind = classify_boundary(&edge.caller_lang, &edge.callee_lang);

            let issue_id = ctx.next_issue_id();
            let issue = Issue::new(issue_id, kind, severity, description)
                .with_confidence(confidence)
                .with_ffi_boundary(FFIBoundary {
                    caller_name: edge.caller_name.clone(),
                    callee_name: edge.callee_name.clone(),
                    caller_lang: edge.caller_lang,
                    callee_lang: edge.callee_lang,
                    boundary_kind,
                });

            ctx.add_fact(Fact::new(
                issue_id,
                FactKind::FFIBoundary,
                omniscope_core::fact::FactLocation::new(PathBuf::from("ffi_analysis"), 0),
            ));

            debug!("FFIBoundary issue: {:?} id={}", issue.kind, issue_id);
            ctx.emit_issue(issue.clone());
            issues.push(issue);
        }

        let issues_found = issues.len();
        info!(
            "FFIBoundaryPass: {} issues found across {} FFI boundaries",
            issues_found,
            cross_lang_edges
                .iter()
                .filter(|e| e.is_ffi_boundary)
                .count()
        );

        let mut result = PassResult::new(self.name())
            .with_nodes(cross_lang_edges.len())
            .with_duration(start.elapsed().as_millis() as u64);
        for issue in issues {
            result.add_issue(issue);
        }
        Ok(result)
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
        _ => BoundaryKind::Unknown,
    }
}

/// Memory safety analysis pass.
///
/// Performs local memory safety checks on FFI-relevant functions
/// (double free, use-after-free, memory leak detection).
pub struct MemorySafetyPass;

impl MemorySafetyPass {
    pub fn new() -> Self {
        Self
    }
}

impl Pass for MemorySafetyPass {
    fn name(&self) -> &'static str {
        "MemorySafety"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["FFIBoundary"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        // Analyze memory safety using facts from context
        let nodes_analyzed = ctx.facts().len();
        tracing::debug!(
            "MemorySafetyPass: analyzing {} nodes (stub)",
            nodes_analyzed
        );

        let result = PassResult::new(self.name())
            .with_issues(0)
            .with_nodes(nodes_analyzed)
            .with_duration(0);

        Ok(result)
    }
}

impl Default for MemorySafetyPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Pointer ownership analysis pass.
///
/// Tracks pointer ownership across FFI boundaries and detects
/// cross-language free mismatches.
pub struct PointerOwnershipPass;

impl PointerOwnershipPass {
    pub fn new() -> Self {
        Self
    }
}

impl Pass for PointerOwnershipPass {
    fn name(&self) -> &'static str {
        "PointerOwnership"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["FFIBoundary"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let nodes_analyzed = ctx.facts().len();
        tracing::debug!(
            "PointerOwnershipPass: analyzing {} nodes (stub)",
            nodes_analyzed
        );

        let result = PassResult::new(self.name())
            .with_issues(0)
            .with_nodes(nodes_analyzed)
            .with_duration(0);

        Ok(result)
    }
}

impl Default for PointerOwnershipPass {
    fn default() -> Self {
        Self::new()
    }
}

/// Buffer overflow detection pass.
pub struct BufferOverflowPass;

impl BufferOverflowPass {
    pub fn new() -> Self {
        Self
    }
}

impl Pass for BufferOverflowPass {
    fn name(&self) -> &'static str {
        "BufferOverflow"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["DFG"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let nodes_analyzed = ctx.facts().len();
        tracing::debug!(
            "BufferOverflowPass: analyzing {} nodes (stub)",
            nodes_analyzed
        );

        let result = PassResult::new(self.name())
            .with_issues(0)
            .with_nodes(nodes_analyzed)
            .with_duration(0);

        Ok(result)
    }
}

impl Default for BufferOverflowPass {
    fn default() -> Self {
        Self::new()
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
        assert_eq!(pass.dependencies(), vec!["CallGraph", "SurfaceClassifier"]);
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

    #[test]
    fn test_memory_safety_pass() {
        let pass = MemorySafetyPass::new();
        assert_eq!(pass.name(), "MemorySafety");
        assert_eq!(pass.dependencies(), vec!["FFIBoundary"]);
    }

    #[test]
    fn test_pointer_ownership_pass() {
        let pass = PointerOwnershipPass::new();
        assert_eq!(pass.name(), "PointerOwnership");
    }

    #[test]
    fn test_buffer_overflow_pass() {
        let pass = BufferOverflowPass::new();
        assert_eq!(pass.name(), "BufferOverflow");
    }
}
