//! Debug information extraction
//!
//! This module provides functionality to extract debug information
//! from LLVM IR, including source locations and type information.

use crate::location::SourceLocation;
use inkwell::values::InstructionValue;
use std::path::{Path, PathBuf};

/// Debug information extractor
pub struct DebugInfoExtractor {
    /// Base path for resolving relative paths
    base_path: Option<PathBuf>,
}

impl DebugInfoExtractor {
    /// Creates a new debug info extractor
    pub fn new() -> Self {
        Self { base_path: None }
    }

    /// Sets the base path for resolving relative paths
    pub fn with_base_path(mut self, path: PathBuf) -> Self {
        self.base_path = Some(path);
        self
    }

    /// Extracts source location from an instruction
    ///
    /// Note: This is a placeholder implementation. Full implementation
    /// requires proper debug info metadata support from inkwell.
    pub fn extract_location(&self, _inst: &InstructionValue) -> Option<SourceLocation> {
        // TODO: Implement when inkwell provides proper debug info API
        None
    }

    /// Checks if an instruction has debug information
    pub fn has_debug_info(&self, inst: &InstructionValue) -> bool {
        // Check for debug metadata (using metadata ID 0 as placeholder)
        // TODO: Implement proper debug info checking
        inst.get_metadata(0).is_some()
    }

    /// Returns the base path
    pub fn base_path(&self) -> Option<&Path> {
        self.base_path.as_deref()
    }
}

impl Default for DebugInfoExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Type information extracted from debug metadata
#[derive(Debug, Clone)]
pub struct TypeInfo {
    /// Type name
    pub name: String,
    /// Size in bytes
    pub size: u64,
    /// Alignment in bytes
    pub align: u64,
    /// Whether this is a pointer type
    pub is_pointer: bool,
}

impl TypeInfo {
    /// Creates a new type info
    pub fn new(name: String, size: u64, align: u64) -> Self {
        Self {
            name,
            size,
            align,
            is_pointer: false,
        }
    }

    /// Marks this as a pointer type
    pub fn as_pointer(mut self) -> Self {
        self.is_pointer = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_info_extractor_creation() {
        let extractor = DebugInfoExtractor::new();
        assert!(extractor.base_path.is_none());

        let extractor_with_base =
            DebugInfoExtractor::new().with_base_path(PathBuf::from("/project"));
        assert!(extractor_with_base.base_path.is_some());
    }

    #[test]
    fn test_type_info_creation() {
        let type_info = TypeInfo::new("int".to_string(), 4, 4);
        assert_eq!(type_info.name, "int");
        assert_eq!(type_info.size, 4);
        assert_eq!(type_info.align, 4);
        assert!(!type_info.is_pointer);

        let ptr_info = type_info.as_pointer();
        assert!(ptr_info.is_pointer);
    }
}
