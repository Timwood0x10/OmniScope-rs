//! Pipeline manager for orchestration
//!
//! This module provides the main pipeline for orchestrating analysis passes.

use crate::result::PipelineResult;
use omniscope_core::Result;
use omniscope_pass::{
    BufferOverflowPass, CFGPass, DFGPass, FFIBoundaryPass, MemorySafetyPass, PassManager,
    PointerOwnershipPass,
};
use omniscope_types::AnalysisConfig;
use std::time::Instant;

/// Pipeline manager for orchestrating analysis
pub struct Pipeline {
    /// Pass manager
    pass_manager: PassManager,
    /// Configuration
    config: AnalysisConfig,
}

impl Pipeline {
    /// Creates a new pipeline
    pub fn new() -> Self {
        Self {
            pass_manager: PassManager::new(),
            config: AnalysisConfig::default(),
        }
    }

    /// Creates a pipeline with configuration
    pub fn with_config(config: AnalysisConfig) -> Self {
        Self {
            pass_manager: PassManager::new(),
            config,
        }
    }

    /// Returns the configuration
    pub fn config(&self) -> &AnalysisConfig {
        &self.config
    }

    /// Registers default passes
    pub fn register_default_passes(&mut self) {
        // Foundation passes
        self.pass_manager.register(CFGPass::new());
        self.pass_manager.register(DFGPass::new());

        // Analysis passes
        self.pass_manager.register(FFIBoundaryPass::new());
        self.pass_manager.register(MemorySafetyPass::new());
        self.pass_manager.register(PointerOwnershipPass::new());
        self.pass_manager.register(BufferOverflowPass::new());
    }

    /// Runs the full analysis pipeline
    pub fn run(&mut self) -> Result<PipelineResult> {
        let start = Instant::now();

        // Run all passes
        let pass_results = self.pass_manager.run_all()?;

        // Aggregate results
        let duration = start.elapsed();
        let result = PipelineResult::from_pass_results(pass_results, duration);

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

        assert_eq!(pipeline.pass_count(), 6);
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
}
