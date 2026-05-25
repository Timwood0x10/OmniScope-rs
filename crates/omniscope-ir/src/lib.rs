//! OmniScope IR - LLVM IR abstraction layer
//!
//! This crate provides safe abstractions over LLVM IR for analysis.

pub mod loader;

pub use loader::IRLoader;

#[cfg(test)]
mod tests {
    #[test]
    fn test_ir_module() {
        // Placeholder test
        assert!(true);
    }
}
