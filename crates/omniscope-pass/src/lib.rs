//! OmniScope Pass - Analysis pass infrastructure.
//!
//! This crate provides analysis pass infrastructure for OmniScope,
//! including:
//!
//! - Pass trait and context
//! - Foundation passes (CFG, DFG, CallGraph)
//! - Analysis passes (FFI boundary, surface classifier, danger surface)
//! - Noise reduction and FP precision guard
//! - Pass manager for orchestration

pub mod analysis;
pub mod foundation;
pub mod manager;
pub mod pass;

// Re-exports — Foundation passes
pub use foundation::{BasicBlock, CFGEdge, CFGEdgeKind, CFGPass, DFGPass, CFG};

// Re-exports — Analysis passes
pub use analysis::{
    BufferOverflowPass, CallGraphPass, DangerSurfacePass, FFIBoundaryPass, MemorySafetyPass,
    NoiseReduction, PointerOwnershipPass, PrecisionMetrics, SurfaceClassifierPass,
};

// Re-exports — Infrastructure
pub use manager::PassManager;
pub use pass::{Pass, PassContext, PassKind, PassResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_module_exports() {
        let _cfg_pass = CFGPass::new();
        let _dfg_pass = DFGPass::new();
        let _call_graph = CallGraphPass::new();
        let _ffi_pass = FFIBoundaryPass::new();
        let _surface_pass = SurfaceClassifierPass::new();
        let _danger_pass = DangerSurfacePass::new();
        let _mem_pass = MemorySafetyPass::new();
        let _ownership_pass = PointerOwnershipPass::new();
        let _buffer_pass = BufferOverflowPass::new();
        let _noise = NoiseReduction::new();
        let _manager = PassManager::new();
    }
}
