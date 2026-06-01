//! Error types for OmniScope
//!
//! This module defines all error types used throughout the OmniScope analyzer.
//! Errors are categorized by component and use `thiserror` for derive-based error handling.

use std::path::PathBuf;
use thiserror::Error;

/// Main error type for OmniScope operations
#[derive(Debug, Error)]
pub enum OmniScopeError {
    /// IR loading errors
    #[error("IR loading failed: {0}")]
    IRLoad(#[from] IRLoadError),

    /// Analysis errors
    #[error("Analysis failed: {0}")]
    Analysis(#[from] AnalysisError),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Diagnostic errors
    #[error("Diagnostic error: {0}")]
    Diagnostic(#[from] DiagnosticError),

    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// IR loading errors
#[derive(Debug, Error)]
pub enum IRLoadError {
    /// Failed to open IR file
    #[error("Failed to open IR file '{path}': {source}")]
    FileOpen {
        /// Path to the IR file
        path: PathBuf,
        /// Underlying I/O error
        source: std::io::Error,
    },

    /// Failed to parse IR
    #[error("Failed to parse IR from '{path}': {message}")]
    ParseError {
        /// Path to the IR file
        path: PathBuf,
        /// Error message
        message: String,
    },

    /// Invalid IR format
    #[error("Invalid IR format in '{path}': expected {expected}, found {found}")]
    InvalidFormat {
        /// Path to the IR file
        path: PathBuf,
        /// Expected format
        expected: String,
        /// Found format
        found: String,
    },

    /// Unsupported LLVM version
    #[error("Unsupported LLVM version: {version}. Supported versions: {supported}")]
    UnsupportedVersion {
        /// LLVM version
        version: String,
        /// Supported versions
        supported: String,
    },

    /// Module verification failed
    #[error("Module verification failed: {message}")]
    VerificationFailed {
        /// Error message
        message: String,
    },
}

/// Analysis errors
#[derive(Debug, Error)]
pub enum AnalysisError {
    /// Pass execution failed
    #[error("Pass '{pass_name}' failed: {message}")]
    PassFailed {
        /// Name of the failed pass
        pass_name: String,
        /// Error message
        message: String,
    },

    /// Dependency not satisfied
    #[error("Dependency not satisfied: pass '{pass_name}' requires '{dependency}'")]
    DependencyNotSatisfied {
        /// Name of the pass
        pass_name: String,
        /// Required dependency
        dependency: String,
    },

    /// Invalid analysis result
    #[error("Invalid analysis result: {message}")]
    InvalidResult {
        /// Error message
        message: String,
    },

    /// Analysis timeout
    #[error("Analysis timeout after {seconds} seconds")]
    Timeout {
        /// Timeout duration in seconds
        seconds: u64,
    },

    /// Resource exhausted
    #[error("Resource exhausted: {resource}. Limit: {limit}, Used: {used}")]
    ResourceExhausted {
        /// Resource type
        resource: String,
        /// Resource limit
        limit: u64,
        /// Used amount
        used: u64,
    },
}

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to load configuration file
    #[error("Failed to load configuration from '{path}': {message}")]
    LoadFailed {
        /// Path to config file
        path: PathBuf,
        /// Error message
        message: String,
    },

    /// Invalid configuration value
    #[error("Invalid configuration value for '{key}': {message}")]
    InvalidValue {
        /// Configuration key
        key: String,
        /// Error message
        message: String,
    },

    /// Missing required configuration
    #[error("Missing required configuration: '{key}'")]
    MissingRequired {
        /// Missing configuration key
        key: String,
    },

    /// Configuration validation failed
    #[error("Configuration validation failed: {message}")]
    ValidationFailed {
        /// Error message
        message: String,
    },
}

/// Diagnostic errors
#[derive(Debug, Error)]
pub enum DiagnosticError {
    /// Failed to emit diagnostic
    #[error("Failed to emit diagnostic: {message}")]
    EmitFailed {
        /// Error message
        message: String,
    },

    /// Invalid diagnostic severity
    #[error("Invalid diagnostic severity: {severity}")]
    InvalidSeverity {
        /// Invalid severity value
        severity: String,
    },

    /// Source location not found
    #[error("Source location not found for {entity_type} '{entity_name}'")]
    LocationNotFound {
        /// Entity type
        entity_type: String,
        /// Entity name
        entity_name: String,
    },
}

/// Result type alias for OmniScope operations
pub type Result<T> = std::result::Result<T, OmniScopeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = IRLoadError::UnsupportedVersion {
            version: "15.0".to_string(),
            supported: "16.0-22.0".to_string(),
        };
        assert!(
            err.to_string().contains("Unsupported LLVM version"),
            "Expected condition to be true"
        );
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: OmniScopeError = io_err.into();
        assert!(
            err.to_string().contains("I/O error"),
            "Expected condition to be true"
        );
    }

    #[test]
    fn test_analysis_error() {
        let err = AnalysisError::PassFailed {
            pass_name: "FFIBoundary".to_string(),
            message: "null pointer".to_string(),
        };
        assert!(
            err.to_string().contains("FFIBoundary"),
            "Expected condition to be true"
        );
    }
}
