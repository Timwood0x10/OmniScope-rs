//! OmniScope Pass - Analysis pass infrastructure
//!
//! This crate provides analysis pass infrastructure for OmniScope,
//! including:
//!
//! - Pass trait and context
//! - Foundation passes (CFG, DFG)
//! - Analysis passes (FFI, memory safety)
//! - Pass manager for orchestration

pub mod analysis;
pub mod foundation;
pub mod manager;
pub mod pass;

// Re-exports
pub use analysis::{BufferOverflowPass, FFIBoundaryPass, MemorySafetyPass, PointerOwnershipPass};
pub use foundation::{BasicBlock, CFGEdge, CFGEdgeKind, CFGPass, DFGPass, CFG};
pub use manager::PassManager;
pub use pass::{Pass, PassContext, PassKind, PassResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_module_exports() {
        let _cfg_pass = CFGPass::new();
        let _dfg_pass = DFGPass::new();
        let _ffi_pass = FFIBoundaryPass::new();
        let _mem_pass = MemorySafetyPass::new();
        let _manager = PassManager::new();
    }
}
