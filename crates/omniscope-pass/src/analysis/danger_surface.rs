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
//!   3. For each surface, check associated pointers with FamilyRegistry
//!   4. Report danger surfaces with resource family classification

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::Result;
use omniscope_semantics::FamilyRegistry;
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
        let registry = FamilyRegistry::new();

        // Retrieve cross-lang edges from CallGraphPass (reference, no clone
        // when possible — but we need a separate value to avoid borrow conflicts
        // with ctx.emit_issue later).
        let cross_lang_edges: Vec<CrossLangEdge> = ctx
            .get_ref::<Vec<CrossLangEdge>>("cross_lang_edges")
            .cloned()
            .unwrap_or_default();

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
        let mut known_family_count = 0usize;

        for edge in &cross_lang_edges {
            if !edge.is_ffi_boundary {
                continue;
            }

            danger_count += 1;

            // Check if the callee has a known resource family
            if registry.lookup(&edge.callee_name).is_some() {
                known_family_count += 1;
                debug!(
                    "DangerSurface: known resource family at {} -> {}",
                    edge.caller_name, edge.callee_name
                );
            }
        }

        info!(
            "DangerSurfacePass: {} danger surfaces, {} with known resource families",
            danger_count, known_family_count
        );

        let mut result = PassResult::new(self.name())
            .with_issues(known_family_count)
            .with_nodes(danger_count)
            .with_duration(start.elapsed().as_millis() as u64);
        result.add_stat("known_family", known_family_count);
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
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Expected values to be equal"
        );
        assert_eq!(
            pass.dependencies(),
            vec!["CallGraph", "FFIBoundary"],
            "must depend on CallGraph and FFIBoundary"
        );
    }
}
