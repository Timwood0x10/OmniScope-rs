//! Pipeline manager for orchestration
//!
//! This module provides the main pipeline for orchestrating analysis passes.

use crate::result::PipelineResult;
use omniscope_core::Result;
use omniscope_ir::IRModule;
use omniscope_pass::{
    CallGraphPass, ContractGraphBuilderPass, DangerSurfacePass, FFIBoundaryPass,
    FfiReturnCheckPass, IRBehaviorSummaryPass, IssueCandidateBuilderPass, IssueVerifierPass,
    LeakDetectionPass, OwnershipSolverPass, PassManager, RawFactCollectorPass,
    StructuralInferencePass, SummaryBuilderPass, SurfaceClassifierPass,
};
use omniscope_types::AnalysisConfig;
use std::time::Instant;

/// Pipeline manager for orchestrating analysis
pub struct Pipeline {
    /// Pass manager
    pass_manager: PassManager,
    /// Configuration
    config: AnalysisConfig,
    /// The IR module to analyze
    ir_module: Option<IRModule>,
}

impl Pipeline {
    /// Creates a new pipeline
    pub fn new() -> Self {
        Self {
            pass_manager: PassManager::new(),
            config: AnalysisConfig::default(),
            ir_module: None,
        }
    }

    /// Creates a pipeline with configuration
    pub fn with_config(config: AnalysisConfig) -> Self {
        Self {
            pass_manager: PassManager::new(),
            config,
            ir_module: None,
        }
    }

    /// Returns the configuration
    pub fn config(&self) -> &AnalysisConfig {
        &self.config
    }

    /// Sets the IR module to analyze
    pub fn set_ir_module(&mut self, module: IRModule) {
        self.ir_module = Some(module);
    }

    /// Registers default passes
    pub fn register_default_passes(&mut self) {
        // Foundation passes (no dependencies)
        self.pass_manager.register(CallGraphPass::new());

        // Analysis passes (depend on CallGraph)
        self.pass_manager.register(FFIBoundaryPass::new());
        self.pass_manager.register(SurfaceClassifierPass::new());
        self.pass_manager.register(DangerSurfacePass::new());

        // Resource contract passes (new architecture)
        self.pass_manager.register(RawFactCollectorPass::new());
        self.pass_manager.register(IRBehaviorSummaryPass::new());
        self.pass_manager.register(SummaryBuilderPass::new());
        self.pass_manager.register(StructuralInferencePass::new());
        self.pass_manager.register(ContractGraphBuilderPass::new());
        self.pass_manager.register(OwnershipSolverPass::new());
        self.pass_manager.register(IssueCandidateBuilderPass::new());
        self.pass_manager.register(IssueVerifierPass::new());
        self.pass_manager.register(LeakDetectionPass::new());

        // FFI nullable return check pass
        self.pass_manager.register(FfiReturnCheckPass::new());
    }

    /// Runs the full analysis pipeline
    pub fn run(&mut self) -> Result<PipelineResult> {
        let start = Instant::now();

        // Run all passes with shared context, injecting IR module if available
        let (pass_results, issues) = self.pass_manager.run_all_with_ir(self.ir_module.take())?;

        // Aggregate results
        let duration = start.elapsed();
        let result = PipelineResult::with_issues(pass_results, duration, issues);

        Ok(result)
    }

    /// Returns the number of registered passes
    pub fn pass_count(&self) -> usize {
        self.pass_manager.pass_count()
    }

    /// Sets parallel execution mode
    pub fn set_parallel(&mut self, parallel: bool) {
        self.pass_manager.set_parallel(parallel);
    }

    /// Clears all passes
    pub fn clear(&mut self) {
        self.pass_manager.clear();
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_creation() {
        let pipeline = Pipeline::new();
        assert_eq!(pipeline.pass_count(), 0);
    }

    #[test]
    fn test_pipeline_with_default_passes() {
        let mut pipeline = Pipeline::new();
        pipeline.register_default_passes();

        assert_eq!(pipeline.pass_count(), 14);
    }

    #[test]
    fn test_pipeline_run() {
        let mut pipeline = Pipeline::new();
        pipeline.register_default_passes();

        let result = pipeline.run().unwrap();
        // Verify result is valid
        assert!(
            result.pass_count() > 0,
            "Pipeline should have executed passes"
        );
    }

    /// Objective: End-to-end pipeline — cross-family malloc→operator delete
    /// must produce a CrossFamilyFree issue in the final pipeline output.
    /// Invariants: Pipeline.run() returns issues that include CrossFamilyFree.
    #[test]
    fn test_pipeline_cross_family_issue() {
        let mut module = omniscope_ir::IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "malloc".to_string(),
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "_ZdlPv".to_string(), // operator delete
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
        });

        let mut pipeline = Pipeline::new();
        pipeline.register_default_passes();
        pipeline.set_ir_module(module);

        let result = pipeline.run().unwrap();

        let cross_family: Vec<_> = result
            .issues()
            .iter()
            .filter(|i| i.kind == omniscope_core::IssueKind::CrossFamilyFree)
            .collect();
        assert!(
            !cross_family.is_empty(),
            "Pipeline must emit CrossFamilyFree for malloc→operator delete, got {} total issues",
            result.issues().len()
        );
    }

    /// Objective: End-to-end pipeline — same-family malloc→free
    /// must NOT produce a CrossFamilyFree issue.
    /// Invariants: Same-family release = no CrossFamilyFree in output.
    #[test]
    fn test_pipeline_same_family_no_cross_family() {
        let mut module = omniscope_ir::IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "malloc".to_string(),
            caller: "safe_func".to_string(),
            is_external: true,
            location: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "free".to_string(),
            caller: "safe_func".to_string(),
            is_external: true,
            location: None,
        });

        let mut pipeline = Pipeline::new();
        pipeline.register_default_passes();
        pipeline.set_ir_module(module);

        let result = pipeline.run().unwrap();

        let cross_family: Vec<_> = result
            .issues()
            .iter()
            .filter(|i| i.kind == omniscope_core::IssueKind::CrossFamilyFree)
            .collect();
        assert!(
            cross_family.is_empty(),
            "Pipeline must NOT emit CrossFamilyFree for same-family malloc→free"
        );
    }
}
