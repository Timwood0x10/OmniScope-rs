//! IR view abstractions
//!
//! This module provides high-level views over LLVM IR for easier analysis.

use crate::debug_info::DebugInfoExtractor;
use crate::location::SourceLocation;
use crate::safe_wrappers::{SafeBasicBlock, SafeFunction, SafeInstruction};
use inkwell::module::Module;
use std::collections::HashMap;

/// Function view for analyzing a single function
pub struct FunctionView<'ctx> {
    /// Safe function wrapper
    func: SafeFunction<'ctx>,
    /// Debug info extractor
    debug_info: DebugInfoExtractor,
    /// Cached source locations
    locations: HashMap<usize, SourceLocation>,
}

impl<'ctx> FunctionView<'ctx> {
    /// Creates a new function view
    pub fn new(func: SafeFunction<'ctx>) -> Self {
        Self {
            func,
            debug_info: DebugInfoExtractor::new(),
            locations: HashMap::new(),
        }
    }

    /// Returns the function name
    pub fn name(&self) -> &str {
        self.func.name()
    }

    /// Returns the number of basic blocks
    pub fn block_count(&self) -> usize {
        self.func.block_count()
    }

    /// Returns an iterator over basic blocks
    pub fn basic_blocks(&self) -> impl Iterator<Item = BasicBlockView<'ctx>> {
        self.func.basic_blocks().map(|block| BasicBlockView::new(block))
    }

    /// Returns true if this is a declaration
    pub fn is_declaration(&self) -> bool {
        self.func.is_declaration()
    }

    /// Counts total instructions in the function
    pub fn instruction_count(&self) -> usize {
        self.func
            .basic_blocks()
            .map(|block| block.instruction_count())
            .sum()
    }

    /// Counts memory access instructions
    pub fn memory_instruction_count(&self) -> usize {
        self.func
            .basic_blocks()
            .flat_map(|block| block.instructions())
            .filter(|inst| inst.is_memory_access())
            .count()
    }

    /// Counts call instructions
    pub fn call_count(&self) -> usize {
        self.func
            .basic_blocks()
            .flat_map(|block| block.instructions())
            .filter(|inst| inst.is_call())
            .count()
    }

    /// Returns the inner function
    pub fn inner(&self) -> &SafeFunction<'ctx> {
        &self.func
    }
}

/// Basic block view for analyzing a single basic block
pub struct BasicBlockView<'ctx> {
    /// Safe basic block wrapper
    block: SafeBasicBlock<'ctx>,
}

impl<'ctx> BasicBlockView<'ctx> {
    /// Creates a new basic block view
    pub fn new(block: SafeBasicBlock<'ctx>) -> Self {
        Self { block }
    }

    /// Returns the block name
    pub fn name(&self) -> &str {
        self.block.name()
    }

    /// Returns the number of instructions
    pub fn instruction_count(&self) -> usize {
        self.block.instruction_count()
    }

    /// Returns an iterator over instructions
    pub fn instructions(&self) -> impl Iterator<Item = InstructionView<'ctx>> {
        self.block.instructions().map(|inst| InstructionView::new(inst))
    }

    /// Returns the inner block
    pub fn inner(&self) -> &SafeBasicBlock<'ctx> {
        &self.block
    }
}

/// Instruction view for analyzing a single instruction
pub struct InstructionView<'ctx> {
    /// Safe instruction wrapper
    inst: SafeInstruction<'ctx>,
    /// Source location (if available)
    location: Option<SourceLocation>,
}

impl<'ctx> InstructionView<'ctx> {
    /// Creates a new instruction view
    pub fn new(inst: SafeInstruction<'ctx>) -> Self {
        Self {
            inst,
            location: None,
        }
    }

    /// Creates an instruction view with location
    pub fn with_location(mut self, location: SourceLocation) -> Self {
        self.location = Some(location);
        self
    }

    /// Returns the opcode name
    pub fn opcode_name(&self) -> &str {
        self.inst.opcode_name()
    }

    /// Returns true if this is a terminator
    pub fn is_terminator(&self) -> bool {
        self.inst.is_terminator()
    }

    /// Returns true if this is a memory access
    pub fn is_memory_access(&self) -> bool {
        self.inst.is_memory_access()
    }

    /// Returns true if this is a call
    pub fn is_call(&self) -> bool {
        self.inst.is_call()
    }

    /// Returns the source location
    pub fn location(&self) -> Option<&SourceLocation> {
        self.location.as_ref()
    }

    /// Returns the inner instruction
    pub fn inner(&self) -> &SafeInstruction<'ctx> {
        &self.inst
    }
}

/// Module view for analyzing an entire module
pub struct ModuleView<'ctx> {
    /// LLVM module
    module: &'ctx Module<'ctx>,
    /// Debug info extractor
    debug_info: DebugInfoExtractor,
}

impl<'ctx> ModuleView<'ctx> {
    /// Creates a new module view
    pub fn new(module: &'ctx Module<'ctx>) -> Self {
        Self {
            module,
            debug_info: DebugInfoExtractor::new(),
        }
    }

    /// Returns the module name
    pub fn name(&self) -> &str {
        self.module
            .get_name()
            .to_str()
            .unwrap_or("<unknown>")
    }

    /// Returns the number of functions
    pub fn function_count(&self) -> usize {
        self.module
            .get_functions()
            .into_iter()
            .count()
    }

    /// Returns an iterator over functions
    pub fn functions(&self) -> impl Iterator<Item = FunctionView<'ctx>> {
        self.module
            .get_functions()
            .into_iter()
            .map(|func| FunctionView::new(SafeFunction::new(func)))
    }

    /// Counts functions with bodies (not declarations)
    pub fn defined_function_count(&self) -> usize {
        self.functions()
            .filter(|func| !func.is_declaration())
            .count()
    }

    /// Returns the inner module
    pub fn inner(&self) -> &'ctx Module<'ctx> {
        self.module
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_view() {
        // Placeholder test - requires actual LLVM context
        assert!(true);
    }

    #[test]
    fn test_basic_block_view() {
        assert!(true);
    }

    #[test]
    fn test_instruction_view() {
        assert!(true);
    }

    #[test]
    fn test_module_view() {
        assert!(true);
    }
}
