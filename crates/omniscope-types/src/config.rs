//! Configuration types for OmniScope
//!
//! This module defines configuration types for controlling analysis behavior.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Target language
    pub language: Language,
    /// Output format
    pub output_format: OutputFormat,
    /// Output path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<PathBuf>,
    /// Enabled passes
    #[serde(default = "default_passes")]
    pub passes: Vec<String>,
    /// Analysis timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Maximum memory in MB
    #[serde(default = "default_max_memory")]
    pub max_memory: u64,
    /// Whether to enable verbose output
    #[serde(default)]
    pub verbose: bool,
    /// Whether to enable parallel analysis
    #[serde(default = "default_parallel")]
    pub parallel: bool,
    /// Number of threads (0 = auto)
    #[serde(default)]
    pub threads: usize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            language: Language::Unknown,
            output_format: OutputFormat::default(),
            output_path: None,
            passes: default_passes(),
            timeout: default_timeout(),
            max_memory: default_max_memory(),
            verbose: false,
            parallel: default_parallel(),
            threads: 0,
        }
    }
}

fn default_passes() -> Vec<String> {
    vec![
        "cfg".to_string(),
        "dfg".to_string(),
        "ffi-boundary".to_string(),
        "memory-safety".to_string(),
    ]
}

fn default_timeout() -> u64 {
    300 // 5 minutes
}

fn default_max_memory() -> u64 {
    4096 // 4 GB
}

fn default_parallel() -> bool {
    true
}

/// Supported source languages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    /// C language
    C,
    /// C++ language
    Cpp,
    /// Rust language
    Rust,
    /// Zig language
    Zig,
    /// Go language
    Go,
    /// Python (via C API)
    Python,
    /// Java (via JNI)
    Java,
    /// Unknown language
    Unknown,
}

impl Language {
    /// Returns true if this is a C-family language
    pub fn is_c_family(&self) -> bool {
        matches!(self, Language::C | Language::Cpp)
    }

    /// Returns true if this language has FFI
    pub fn has_ffi(&self) -> bool {
        matches!(
            self,
            Language::Rust | Language::Zig | Language::Go | Language::Python | Language::Java
        )
    }
}

impl Default for Language {
    fn default() -> Self {
        Language::Unknown
    }
}

/// Output format for analysis results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// JSON format
    Json,
    /// SARIF format (for GitHub)
    Sarif,
    /// Plain text
    Text,
    /// HTML report
    Html,
    /// Markdown
    Markdown,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Json
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_config_default() {
        let config = AnalysisConfig::default();
        assert_eq!(config.language, Language::Unknown);
        assert_eq!(config.output_format, OutputFormat::Json);
        assert!(config.parallel);
        assert_eq!(config.timeout, 300);
    }

    #[test]
    fn test_language_checks() {
        assert!(Language::C.is_c_family());
        assert!(Language::Cpp.is_c_family());
        assert!(!Language::Rust.is_c_family());

        assert!(Language::Rust.has_ffi());
        assert!(Language::Go.has_ffi());
        assert!(!Language::C.has_ffi());
    }

    #[test]
    fn test_output_format_default() {
        assert_eq!(OutputFormat::default(), OutputFormat::Json);
    }
}
