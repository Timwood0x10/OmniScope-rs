//! Danger Surface Pass — Graph-Driven FFI/Unsafe Boundary Analyzer.
//!
//! This pass implements the core architectural shift from "scan everything"
//! to "trace from danger surfaces outward". It is the entry point for
//! Tier 2 (strict) analysis.
//!
//! Execution order: Must run AFTER CallGraphPass and FFIBoundaryPass.
//!
//! Algorithm:
//!   1. Collect all danger surfaces (FFI boundary CrossLangEdge)
//!   2. If no FFI boundaries → early return (pure C project fast path)
//!   3. For each surface, check associated pointers with SemanticRegistry
//!   4. Report danger surfaces with risk classification

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::Result;
use omniscope_registry::SemanticRegistry;
use omniscope_types::call_graph_types::CrossLangEdge;
use tracing::{debug, info};

/// Danger surface pass — traces from FFI boundaries outward.
pub struct DangerSurfacePass;

impl DangerSurfacePass {
    /// Creates a new danger surface pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for DangerSurfacePass {
    fn name(&self) -> &'static str {
        "DangerSurface"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["CallGraph", "FFIBoundary"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();
        let registry = SemanticRegistry::new();

        // Retrieve cross-lang edges from CallGraphPass
        let cross_lang_edges: Vec<CrossLangEdge> = ctx.get("cross_lang_edges").unwrap_or_default();

        // Early return: if no FFI boundaries, skip (pure C fast path)
        let ffi_count = cross_lang_edges
            .iter()
            .filter(|e| e.is_ffi_boundary)
            .count();
        if ffi_count == 0 {
            debug!("DangerSurfacePass: no FFI boundaries found, skipping");
            return Ok(PassResult::new(self.name())
                .with_nodes(0)
                .with_duration(start.elapsed().as_millis() as u64));
        }

        // Analyze each FFI boundary as a potential danger surface
        let mut danger_count = 0usize;
        let mut high_risk_count = 0usize;

        for edge in &cross_lang_edges {
            if !edge.is_ffi_boundary {
                continue;
            }

            danger_count += 1;

            // Check if the callee is high-risk
            if registry.is_high_risk(&edge.callee_name) {
                high_risk_count += 1;
                debug!(
                    "DangerSurface: HIGH RISK at {} -> {}",
                    edge.caller_name, edge.callee_name
                );
            }
        }

        info!(
            "DangerSurfacePass: {} danger surfaces, {} high risk",
            danger_count, high_risk_count
        );

        let mut result = PassResult::new(self.name())
            .with_issues(high_risk_count)
            .with_nodes(danger_count)
            .with_duration(start.elapsed().as_millis() as u64);
        result.add_stat("high_risk", high_risk_count);
        Ok(result)
    }
}

impl Default for DangerSurfacePass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify DangerSurfacePass trait compliance.
    /// Invariants: name="DangerSurface", deps=["CallGraph", "FFIBoundary"].
    #[test]
    fn test_danger_surface_pass_trait() {
        let pass = DangerSurfacePass::new();
        assert_eq!(
            pass.name(),
            "DangerSurface",
            "pass name must be DangerSurface"
        );
        assert_eq!(pass.kind(), PassKind::Analysis);
        assert_eq!(
            pass.dependencies(),
            vec!["CallGraph", "FFIBoundary"],
            "must depend on CallGraph and FFIBoundary"
        );
    }
}
