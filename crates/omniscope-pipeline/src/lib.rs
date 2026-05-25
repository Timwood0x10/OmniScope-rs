//! OmniScope Pipeline - Analysis pipeline orchestration

pub mod pipeline;

pub use pipeline::Pipeline;

#[cfg(test)]
mod tests {
    #[test]
    fn test_pipeline_module() {
        assert!(true);
    }
}
