//! OmniScope IR - LLVM IR abstraction layer
//!
//! This crate provides IR parsing and model conversion for analysis:
//!
//! - IR loading from `.ll` files (text parser)
//! - IR loading via C++ SafetyExportPass JSON (Plan A)
//! - IR loading via llvm-sys C API (Plan C, stub)
//! - Source location tracking
//! - Rich IR model with full type information
//!
//! # Example
//!
//! ```rust,no_run
//! use omniscope_ir::IRModule;
//!
//! let module = IRModule::parse_from_text("define void @foo() { ret void }");
//! ```

pub mod instruction_parser;
pub mod ir_cache;
pub mod ir_model;
#[cfg(feature = "llvm-backend")]
pub mod llvm_sys_adapter;
pub mod loader_v2;
pub mod location;
pub mod parser;

// Re-exports
pub use ir_model::{
    load_from_json, load_from_msgpack, parse_from_json, parse_from_msgpack, IRBasicBlock,
    IRDeclaration, IRFunction, IRGepDetails, IRGepIndex, IRGlobalVariable, IRInstructionModel,
    IRModuleModel,
};
pub use loader_v2::{load_ir, LoadStrategy};
pub use location::{LocationManager, SourceLocation};
pub use parser::{
    CallInstruction, Function, FunctionBody, IRInstruction, IRInstructionKind, IRModule,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ir_module_exports() {
        let _location_manager = LocationManager::new();
    }
}
