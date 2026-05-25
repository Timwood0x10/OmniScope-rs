//! IR loader for LLVM modules
//!
//! This module provides functionality to load LLVM IR from files or memory.

use inkwell::context::Context;
use inkwell::module::Module;
use omniscope_core::{IRLoadError, Result};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use tracing::instrument;

/// IR loader for loading LLVM IR files
pub struct IRLoader {
    /// LLVM context
    context: Rc<Context>,
    /// Loaded module (placeholder)
    module: Option<Module<'static>>,
    /// Path to the loaded file
    path: Option<PathBuf>,
}

impl IRLoader {
    /// Creates a new IR loader
    pub fn new() -> Self {
        Self {
            context: Rc::new(Context::create()),
            module: None,
            path: None,
        }
    }

    /// Loads IR from a file
    ///
    /// Supports both .ll (textual IR) and .bc (bitcode) formats.
    #[instrument(skip(self), fields(path = %path.display()))]
    pub fn load_from_file(&mut self, path: &Path) -> Result<()> {
        // Check file exists
        if !path.exists() {
            return Err(IRLoadError::FileOpen {
                path: path.to_path_buf(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
            }
            .into());
        }

        // Determine format from extension
        let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");

        match extension {
            "ll" | "bc" => {
                // TODO: Implement actual IR loading with inkwell
                // The inkwell API requires specific method calls that vary by version
                // For now, we just validate the file exists and has correct extension
                self.path = Some(path.to_path_buf());
                Ok(())
            }
            _ => Err(IRLoadError::InvalidFormat {
                path: path.to_path_buf(),
                expected: "LLVM IR (.ll or .bc)".to_string(),
                found: format!(".{}", extension),
            }
            .into()),
        }
    }

    /// Returns the loaded module
    pub fn module(&self) -> Option<&Module<'static>> {
        self.module.as_ref()
    }

    /// Returns the path to the loaded file
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Returns the LLVM context
    pub fn context(&self) -> Rc<Context> {
        Rc::clone(&self.context)
    }

    /// Clears the loaded module
    pub fn clear(&mut self) {
        self.module = None;
        self.path = None;
    }
}

impl Default for IRLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_loader_creation() {
        let loader = IRLoader::new();
        assert!(loader.module().is_none());
        assert!(loader.path().is_none());
    }

    #[test]
    fn test_load_nonexistent_file() {
        let mut loader = IRLoader::new();
        let result = loader.load_from_file(Path::new("nonexistent.ll"));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_extension() {
        let mut loader = IRLoader::new();
        let mut temp_file = NamedTempFile::with_suffix(".txt").unwrap();
        writeln!(temp_file, "test").unwrap();

        let result = loader.load_from_file(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_extension() {
        let mut loader = IRLoader::new();
        let temp_file = NamedTempFile::with_suffix(".ll").unwrap();

        let result = loader.load_from_file(temp_file.path());
        assert!(result.is_ok());
        assert!(loader.path().is_some());
    }
}
