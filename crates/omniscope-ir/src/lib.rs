//! OmniScope IR - LLVM IR abstraction layer
//!
//! This crate provides safe abstractions over LLVM IR for analysis,
//! including:
//!
//! - IR loading from .ll and .bc files
//! - Safe wrappers for LLVM types
//! - Debug information extraction
//! - Source location tracking
//! - IR view abstractions
//! - IR text format parsing
//! - Platform-specific filtering
//!
//! # Example
//!
//! ```rust,no_run
//! use omniscope_ir::IRLoader;
//! use std::path::Path;
//!
//! let mut loader = IRLoader::new();
//! // loader.load_from_file(Path::new("test.ll")).unwrap();
//! ```

pub mod debug_info;
pub mod loader;
pub mod location;
pub mod parser;
pub mod platform;
pub mod safe_wrappers;
pub mod view;

// Re-exports
pub use debug_info::{DebugInfoExtractor, TypeInfo};
pub use loader::IRLoader;
pub use location::{LocationManager, SourceLocation};
pub use parser::{
    CallInstruction, Function, FunctionBody, IRInstruction, IRInstructionKind, IRModule,
};
pub use platform::{Architecture, Platform, PlatformFilterRegistry, PlatformInfo};
pub use safe_wrappers::{SafeBasicBlock, SafeFunction, SafeInstruction};
pub use view::{BasicBlockView, FunctionView, InstructionView, ModuleView};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ir_module_exports() {
        // Test that all exports are available
        let _loader = IRLoader::new();
        let _debug_info = DebugInfoExtractor::new();
        let _location_manager = LocationManager::new();
    }
}
