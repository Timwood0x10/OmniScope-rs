//! Surface Classifier Pass — L3 CallGraph Reachability.
//!
//! This pass applies the SurfaceClassifier to each function in the IR
//! module and uses call graph reachability to upgrade classifications
//! from Unknown to Boundary where appropriate.
//!
//! The result is stored in PassContext as a HashMap<String, FunctionSurface>
//! so that downstream passes can skip stdlib/runtime functions.

use crate::pass::{Pass, PassContext, PassKind, PassResult};
use omniscope_core::Result;
use omniscope_ir::parser::IRModule;
use omniscope_semantics::{FunctionSurface, SurfaceClassifier};
use omniscope_types::call_graph_types::CrossLangEdge;
use std::collections::HashMap;
use tracing::{debug, info};

/// Surface classifier pass.
///
/// Applies L1 (linkage) + L2 (source path) heuristics via
/// SurfaceClassifier, then uses L3 (call graph reachability)
/// to upgrade Unknown classifications to Boundary where a
/// function is reachable from a known FFI boundary.
pub struct SurfaceClassifierPass;

impl SurfaceClassifierPass {
    /// Creates a new surface classifier pass.
    pub fn new() -> Self {
        Self
    }
}

impl Pass for SurfaceClassifierPass {
    fn name(&self) -> &'static str {
        "SurfaceClassifier"
    }

    fn kind(&self) -> PassKind {
        PassKind::Analysis
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["CallGraph"]
    }

    fn run(&self, ctx: &mut PassContext) -> Result<PassResult> {
        let start = std::time::Instant::now();
        let classifier = SurfaceClassifier::new();

        // Use cached LanguageDetector from ModuleIndex if available,
        // otherwise create a new one.
        let module_index: Option<crate::module_index::ModuleIndex> = ctx.get("module_index");
        let detector = module_index
            .as_ref()
            .map(|idx| idx.language_detector.clone())
            .unwrap_or_default();

        // Retrieve IR module
        let module: Option<IRModule> = ctx.get("ir_module");
        let module = match module {
            Some(m) => m,
            None => {
                debug!("SurfaceClassifierPass: no IR module, skipping");
                return Ok(PassResult::new(self.name())
                    .with_nodes(0)
                    .with_duration(start.elapsed().as_millis() as u64));
            }
        };

        // Retrieve cross-lang edges from CallGraphPass
        let cross_lang_edges: Vec<CrossLangEdge> = ctx.get("cross_lang_edges").unwrap_or_default();

        // Phase 1: Classify each function using L1 + L2
        let mut surfaces: HashMap<String, FunctionSurface> = HashMap::new();

        // Collect all function names from the module
        let all_names: Vec<String> = module
            .functions
            .keys()
            .chain(module.declarations.keys())
            .cloned()
            .collect();

        for name in &all_names {
            let language = detector.detect_from_function(name);
            let surface = classifier.classify(name, language, None);
            surfaces.insert(name.clone(), surface);
        }

        // Phase 2: L3 — Upgrade Unknown functions reachable from FFI boundaries
        if !cross_lang_edges.is_empty() {
            let ffi_boundary_names: Vec<String> = cross_lang_edges
                .iter()
                .filter(|e| e.is_ffi_boundary)
                .map(|e| e.caller_name.clone())
                .collect();

            // Functions directly involved in FFI boundaries → Boundary
            for name in &ffi_boundary_names {
                if let Some(surface) = surfaces.get_mut(name) {
                    if *surface == FunctionSurface::Unknown
                        || *surface == FunctionSurface::Dependency
                    {
                        debug!(
                            "L3 upgrade: {} from {:?} to Boundary (FFI reachable)",
                            name, surface
                        );
                        *surface = FunctionSurface::Boundary;
                    }
                }
            }

            // Callee names at FFI boundaries → Boundary
            for edge in cross_lang_edges.iter().filter(|e| e.is_ffi_boundary) {
                if let Some(surface) = surfaces.get_mut(&edge.callee_name) {
                    if *surface == FunctionSurface::Unknown {
                        debug!(
                            "L3 upgrade: {} from Unknown to Boundary (FFI callee)",
                            edge.callee_name
                        );
                        *surface = FunctionSurface::Boundary;
                    }
                }
            }
        }

        // Compute statistics
        let total = surfaces.len();
        let user_count = surfaces
            .values()
            .filter(|s| **s == FunctionSurface::UserCode)
            .count();
        let boundary_count = surfaces
            .values()
            .filter(|s| **s == FunctionSurface::Boundary)
            .count();
        let stdlib_count = surfaces
            .values()
            .filter(|s| **s == FunctionSurface::StandardLibrary)
            .count();
        let runtime_count = surfaces
            .values()
            .filter(|s| **s == FunctionSurface::Runtime)
            .count();
        let compiler_count = surfaces
            .values()
            .filter(|s| **s == FunctionSurface::CompilerGenerated)
            .count();
        let unknown_count = surfaces
            .values()
            .filter(|s| **s == FunctionSurface::Unknown)
            .count();

        info!(
            "SurfaceClassifierPass: {} functions classified: {} user, {} boundary, {} stdlib, {} runtime, {} compiler, {} unknown",
            total, user_count, boundary_count, stdlib_count, runtime_count, compiler_count, unknown_count
        );

        // Store results in PassContext
        ctx.store("function_surfaces", surfaces);

        let mut result = PassResult::new(self.name())
            .with_nodes(total)
            .with_duration(start.elapsed().as_millis() as u64);
        result.add_stat("user_code", user_count);
        result.add_stat("boundary", boundary_count);
        result.add_stat("stdlib", stdlib_count);
        result.add_stat("runtime", runtime_count);
        result.add_stat("compiler_gen", compiler_count);
        result.add_stat("unknown", unknown_count);
        Ok(result)
    }
}

impl Default for SurfaceClassifierPass {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify SurfaceClassifierPass creation and trait compliance.
    /// Invariants: name="SurfaceClassifier", kind=Analysis, deps=["CallGraph"].
    #[test]
    fn test_surface_classifier_pass_trait() {
        let pass = SurfaceClassifierPass::new();
        assert_eq!(
            pass.name(),
            "SurfaceClassifier",
            "Pass name should be SurfaceClassifier"
        );
        assert_eq!(
            pass.kind(),
            PassKind::Analysis,
            "Pass kind should be Analysis"
        );
        assert_eq!(
            pass.dependencies(),
            vec!["CallGraph"],
            "Dependencies should be CallGraph"
        );
    }

    /// Objective: Verify FunctionSurface classification categories.
    /// Invariants: Boundary and Unknown should_analyze=true; Runtime=false.
    #[test]
    fn test_function_surface_categories() {
        assert!(
            FunctionSurface::Boundary.should_analyze(),
            "Boundary must be analyzed"
        );
        assert!(
            FunctionSurface::Unknown.should_analyze(),
            "Unknown must be analyzed (conservative)"
        );
        assert!(
            FunctionSurface::UserCode.should_analyze(),
            "UserCode must be analyzed"
        );
        assert!(
            !FunctionSurface::Runtime.should_analyze(),
            "Runtime can be skipped"
        );
        assert!(
            !FunctionSurface::StandardLibrary.should_analyze(),
            "Stdlib can be skipped"
        );
    }
}
