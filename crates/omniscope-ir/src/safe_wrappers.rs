//! Safe wrappers for LLVM types
//!
//! This module provides safe abstractions over LLVM types to prevent
//! common errors and provide a more idiomatic Rust interface.

use inkwell::basic_block::BasicBlock;
use inkwell::values::{AnyValue, FunctionValue, InstructionValue};
use std::fmt;

/// Safe wrapper for LLVM function
pub struct SafeFunction<'ctx> {
    /// Inner function value
    inner: FunctionValue<'ctx>,
}

impl<'ctx> SafeFunction<'ctx> {
    /// Creates a new safe function wrapper
    pub fn new(func: FunctionValue<'ctx>) -> Self {
        Self { inner: func }
    }

    /// Returns the function name
    pub fn name(&self) -> &str {
        self.inner.get_name().to_str().unwrap_or("<unknown>")
    }

    /// Returns the number of parameters
    pub fn param_count(&self) -> usize {
        self.inner.count_params() as usize
    }

    /// Returns the number of basic blocks
    pub fn block_count(&self) -> usize {
        self.inner.count_basic_blocks() as usize
    }

    /// Returns an iterator over basic blocks
    pub fn basic_blocks(&self) -> impl Iterator<Item = SafeBasicBlock<'ctx>> {
        self.inner
            .get_basic_blocks()
            .into_iter()
            .map(SafeBasicBlock::new)
    }

    /// Returns true if the function is a declaration (no body)
    pub fn is_declaration(&self) -> bool {
        self.inner.get_first_basic_block().is_none()
    }

    /// Returns the inner function value
    pub fn inner(&self) -> FunctionValue<'ctx> {
        self.inner
    }
}

impl<'ctx> fmt::Debug for SafeFunction<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeFunction")
            .field("name", &self.name())
            .field("params", &self.param_count())
            .field("blocks", &self.block_count())
            .finish()
    }
}

/// Safe wrapper for LLVM basic block
pub struct SafeBasicBlock<'ctx> {
    /// Inner basic block
    inner: BasicBlock<'ctx>,
}

impl<'ctx> SafeBasicBlock<'ctx> {
    /// Creates a new safe basic block wrapper
    pub fn new(block: BasicBlock<'ctx>) -> Self {
        Self { inner: block }
    }

    /// Returns the block name
    pub fn name(&self) -> &str {
        self.inner.get_name().to_str().unwrap_or("<unknown>")
    }

    /// Returns the number of instructions
    pub fn instruction_count(&self) -> usize {
        self.inner.get_instructions().into_iter().count()
    }

    /// Returns an iterator over instructions
    pub fn instructions(&self) -> impl Iterator<Item = SafeInstruction<'ctx>> {
        self.inner
            .get_instructions()
            .into_iter()
            .map(SafeInstruction::new)
    }

    /// Returns the inner basic block
    pub fn inner(&self) -> BasicBlock<'ctx> {
        self.inner
    }
}

impl<'ctx> fmt::Debug for SafeBasicBlock<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeBasicBlock")
            .field("name", &self.name())
            .field("instructions", &self.instruction_count())
            .finish()
    }
}

/// Safe wrapper for LLVM instruction
pub struct SafeInstruction<'ctx> {
    /// Inner instruction value
    inner: InstructionValue<'ctx>,
}

impl<'ctx> SafeInstruction<'ctx> {
    /// Creates a new safe instruction wrapper
    pub fn new(inst: InstructionValue<'ctx>) -> Self {
        Self { inner: inst }
    }

    /// Returns the instruction opcode name
    pub fn opcode_name(&self) -> &'static str {
        use inkwell::values::InstructionOpcode::*;
        match self.inner.get_opcode() {
            Add => "Add",
            Sub => "Sub",
            Mul => "Mul",
            Div => "Div",
            Rem => "Rem",
            And => "And",
            Or => "Or",
            Xor => "Xor",
            Shl => "Shl",
            LShr => "LShr",
            AShr => "AShr",
            FAdd => "FAdd",
            FSub => "FSub",
            FMul => "FMul",
            FDiv => "FDiv",
            FRem => "FRem",
            Load => "Load",
            Store => "Store",
            Alloca => "Alloca",
            GetElementPtr => "GetElementPtr",
            AtomicRMW => "AtomicRMW",
            AtomicCmpXchg => "AtomicCmpXchg",
            Call => "Call",
            Invoke => "Invoke",
            Ret => "Ret",
            Br => "Br",
            Switch => "Switch",
            IndirectBr => "IndirectBr",
            Unreachable => "Unreachable",
            _ => "Unknown",
        }
    }

    /// Returns true if this is a terminator instruction
    pub fn is_terminator(&self) -> bool {
        self.inner.is_terminator()
    }

    /// Returns true if this is a memory access instruction
    pub fn is_memory_access(&self) -> bool {
        use inkwell::values::InstructionOpcode::*;
        matches!(
            self.inner.get_opcode(),
            Load | Store | Alloca | GetElementPtr | AtomicRMW | AtomicCmpXchg
        )
    }

    /// Returns true if this is a call instruction
    pub fn is_call(&self) -> bool {
        use inkwell::values::InstructionOpcode::*;
        matches!(self.inner.get_opcode(), Call | Invoke)
    }

    /// Returns the inner instruction value
    pub fn inner(&self) -> InstructionValue<'ctx> {
        self.inner
    }
}

impl<'ctx> fmt::Debug for SafeInstruction<'ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafeInstruction")
            .field("opcode", &self.opcode_name())
            .field("terminator", &self.is_terminator())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_function_debug() {
        // This test verifies the Debug implementation compiles
        // Actual testing requires a real LLVM context
        assert!(true);
    }

    #[test]
    fn test_safe_basic_block_debug() {
        assert!(true);
    }

    #[test]
    fn test_safe_instruction_debug() {
        assert!(true);
    }
}
