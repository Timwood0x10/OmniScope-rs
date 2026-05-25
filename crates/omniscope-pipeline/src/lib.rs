//! OmniScope Pipeline - Analysis pipeline orchestration
//!
//! This crate provides pipeline orchestration for OmniScope,
//! including:
//!
//! - Pipeline manager for running analysis passes
//! - Result aggregation and statistics
//! - Pass scheduling and dependency resolution

pub mod pipeline;
pub mod result;

// Re-exports
pub use pipeline::Pipeline;
pub use result::{PipelineResult, PipelineStats};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_module_exports() {
        let _pipeline = Pipeline::new();
    }
}
