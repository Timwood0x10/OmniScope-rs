//! Pipeline manager for orchestration
//!
//! This module provides the main pipeline for orchestrating analysis passes.

use crate::result::PipelineResult;
use omniscope_core::Result;
use omniscope_ir::IRModule;
use omniscope_pass::{
    AbiLayoutPass, BorrowEscapePass, CallGraphPass, ContractGraphBuilderPass, DangerSurfacePass,
    FFIBoundaryPass, FfiReturnCheckPass, HeapProvenancePass, IRBehaviorSummaryPass,
    InteriorMutabilityPass, IssueCandidateBuilderPass, IssueVerifierPass, LanguageAdapterFactPass,
    LeakDetectionPass, OwnershipSolverPass, PassManager, RaiiDropPass, RawFactCollectorPass,
    StructuralInferencePass, SummaryBuilderPass, SurfaceClassifierPass, WriteToImmutablePass,
};
use omniscope_types::{AnalysisConfig, OmniScopeConfig};
use std::time::Instant;

/// Pipeline manager for orchestrating analysis
pub struct Pipeline {
    /// Pass manager
    pass_manager: PassManager,
    /// Configuration
    config: AnalysisConfig,
    /// The IR module to analyze
    ir_module: Option<IRModule>,
    /// Optional FFI boundary and resource family configuration
    omniscope_config: Option<OmniScopeConfig>,
}

impl Pipeline {
    /// Creates a new pipeline
    pub fn new() -> Self {
        Self {
            pass_manager: PassManager::new(),
            config: AnalysisConfig::default(),
            ir_module: None,
            omniscope_config: None,
        }
    }

    /// Creates a pipeline with configuration
    pub fn with_config(config: AnalysisConfig) -> Self {
        Self {
            pass_manager: PassManager::new(),
            config,
            ir_module: None,
            omniscope_config: None,
        }
    }

    /// Creates a pipeline with full OmniScope configuration
    pub fn with_omniscope_config(
        config: AnalysisConfig,
        omniscope_config: OmniScopeConfig,
    ) -> Self {
        Self {
            pass_manager: PassManager::new(),
            config,
            ir_module: None,
            omniscope_config: Some(omniscope_config),
        }
    }

    /// Returns the configuration
    pub fn config(&self) -> &AnalysisConfig {
        &self.config
    }

    /// Returns the OmniScope configuration, if any
    pub fn omniscope_config(&self) -> Option<&OmniScopeConfig> {
        self.omniscope_config.as_ref()
    }

    /// Sets the OmniScope configuration
    pub fn set_config(&mut self, config: OmniScopeConfig) {
        self.omniscope_config = Some(config);
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
        self.pass_manager.register(LanguageAdapterFactPass::new());
        self.pass_manager.register(AbiLayoutPass::new());
        self.pass_manager.register(SummaryBuilderPass::new());
        self.pass_manager.register(StructuralInferencePass::new());
        // Use configuration-aware pass if available
        if let Some(config) = &self.omniscope_config {
            self.pass_manager
                .register(ContractGraphBuilderPass::with_config(config.clone()));
        } else {
            self.pass_manager.register(ContractGraphBuilderPass::new());
        }
        self.pass_manager.register(OwnershipSolverPass::new());
        self.pass_manager.register(IssueCandidateBuilderPass::new());
        self.pass_manager.register(IssueVerifierPass::new());
        self.pass_manager.register(LeakDetectionPass::new());

        // Semantic analysis passes (depend on RawFactCollector)
        // R-3: RAII drop detection — suppresses FP use-after-free
        self.pass_manager.register(RaiiDropPass::new());
        // R-2: Interior mutability — suppresses FP write-to-immutable
        self.pass_manager.register(InteriorMutabilityPass::new());
        // R-1: Heap provenance — classifies pointer origin
        self.pass_manager.register(HeapProvenancePass::new());
        // Borrow escape — stack pointer escape across FFI
        self.pass_manager.register(BorrowEscapePass::new());
        // Write-to-immutable — stores to immutable memory
        self.pass_manager.register(WriteToImmutablePass::new());

        // FFI nullable return check pass
        self.pass_manager.register(FfiReturnCheckPass::new());
    }

    /// Runs the full analysis pipeline
    pub fn run(&mut self) -> Result<PipelineResult> {
        let start = Instant::now();

        // Run all passes with shared context, injecting IR module and configuration
        let (pass_results, pass_timings, issues) = self
            .pass_manager
            .run_all_with_ir_and_config(self.ir_module.take(), self.omniscope_config.take())?;

        // Aggregate results
        let duration = start.elapsed();
        let result = PipelineResult::with_issues(pass_results, duration, issues, pass_timings);

        Ok(result)
    }

    /// Runs the full analysis pipeline with automatic boundary inference.
    ///
    /// When no explicit `--cross` configuration is provided, this method
    /// automatically infers FFI boundaries from the IR module.
    ///
    /// # Returns
    /// `Result<PipelineResult>` containing analysis results.
    pub fn run_with_auto_inference(&mut self) -> Result<PipelineResult> {
        // Config should already be set before calling this method.
        // Just run the standard pipeline.
        self.run()
    }

    /// Returns the number of registered passes
    pub fn pass_count(&self) -> usize {
        self.pass_manager.pass_count()
    }

    /// Returns the names of all registered passes, in registration order.
    ///
    /// Drives `omniscope info --passes` so the CLI display stays in sync
    /// with `register_default_passes` instead of duplicating the list.
    pub fn registered_pass_names(&self) -> Vec<&'static str> {
        self.pass_manager.pass_names()
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
        assert_eq!(pipeline.pass_count(), 0, "New Pipeline must have 0 passes");
    }

    #[test]
    fn test_pipeline_with_default_passes() {
        let mut pipeline = Pipeline::new();
        pipeline.register_default_passes();

        assert_eq!(
            pipeline.pass_count(),
            20,
            "Pipeline must have 20 default passes registered"
        );
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
            args: Vec::new(),
            result: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "_ZdlPv".to_string(), // operator delete
            caller: "test_func".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
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
            args: Vec::new(),
            result: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "free".to_string(),
            caller: "safe_func".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
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
