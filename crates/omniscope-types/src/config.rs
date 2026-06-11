//! Configuration types for OmniScope
//!
//! This module defines configuration types for controlling analysis behavior,
//! including TOML configuration file support for custom FFI boundaries,
//! resource families, and analysis options.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::FamilyKind;

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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    /// C language
    C,
    /// C++ language
    Cpp,
    /// Rust language
    Rust,
    /// Go language
    Go,
    /// Python (via C API)
    Python,
    /// Java (via JNI)
    Java,
    /// C# (via P/Invoke)
    CSharp,
    /// Unknown language
    #[default]
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
            Language::Rust | Language::Go | Language::Python | Language::Java | Language::CSharp
        )
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::C => write!(f, "C"),
            Language::Cpp => write!(f, "C++"),
            Language::Rust => write!(f, "Rust"),
            Language::Go => write!(f, "Go"),
            Language::Python => write!(f, "Python"),
            Language::Java => write!(f, "Java"),
            Language::CSharp => write!(f, "C#"),
            Language::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Output format for analysis results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// JSON format
    #[default]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_config_default() {
        let config = AnalysisConfig::default();
        assert_eq!(
            config.language,
            Language::Unknown,
            "Default language should be Unknown"
        );
        assert_eq!(
            config.output_format,
            OutputFormat::Json,
            "Default output format should be JSON"
        );
        assert!(
            config.parallel,
            "Parallel execution should be enabled by default"
        );
        assert_eq!(config.timeout, 300, "Default timeout should be 300 seconds");
    }

    #[test]
    fn test_language_checks() {
        // Test C-family language detection
        assert!(Language::C.is_c_family(), "C should be in C family");
        assert!(Language::Cpp.is_c_family(), "C++ should be in C family");
        assert!(
            !Language::Rust.is_c_family(),
            "Rust should not be in C family"
        );

        // Test FFI capability detection
        assert!(Language::Rust.has_ffi(), "Rust should have FFI capability");
        assert!(Language::Go.has_ffi(), "Go should have FFI capability");
        assert!(
            Language::Python.has_ffi(),
            "Python should have FFI capability"
        );
        assert!(Language::Java.has_ffi(), "Java should have FFI capability");
        assert!(Language::CSharp.has_ffi(), "C# should have FFI capability");
        assert!(
            !Language::C.has_ffi(),
            "C should not have FFI (it IS the FFI target)"
        );
    }

    #[test]
    fn test_output_format_default() {
        assert_eq!(
            OutputFormat::default(),
            OutputFormat::Json,
            "Default output format should be JSON for machine readability"
        );
    }
}

// ============================================================================
// TOML Configuration File Support
// ============================================================================

/// Main configuration structure for OmniScope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OmniScopeConfig {
    /// Project metadata.
    pub project: Option<ProjectConfig>,

    /// FFI boundary definitions.
    #[serde(default)]
    pub ffi_boundary: Vec<FFIBoundaryConfig>,

    /// Custom resource family definitions.
    #[serde(default)]
    pub resource_family: Vec<ResourceFamilyConfig>,

    /// Analysis options.
    #[serde(default)]
    pub analysis: AnalysisOptions,
}

/// Project metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    /// Project name.
    pub name: Option<String>,

    /// Project description.
    pub description: Option<String>,
}

/// FFI boundary configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FFIBoundaryConfig {
    /// Source language.
    pub from: Language,

    /// Target language.
    pub to: Language,

    /// Functions that cross this boundary.
    #[serde(default)]
    pub functions: Vec<String>,

    /// Function name pattern (supports wildcards).
    /// Pattern syntax:
    /// - `*` matches any sequence of characters
    /// - `c_*` matches functions starting with `c_`
    /// - `*_init` matches functions ending with `_init`
    /// - `*malloc*` matches functions containing `malloc`
    /// - `c_fft_*` matches functions starting with `c_fft_`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,

    /// Optional description.
    pub description: Option<String>,
}

/// Custom resource family configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceFamilyConfig {
    /// Family name.
    pub name: String,

    /// Resource kind.
    pub kind: FamilyKind,

    /// Acquire functions.
    #[serde(default)]
    pub acquire: Vec<String>,

    /// Release functions.
    #[serde(default)]
    pub release: Vec<String>,

    /// Compatible release families.
    #[serde(default)]
    pub compatible_releases: Vec<String>,
}

/// Analysis options for configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptions {
    /// Enable cross-language detection.
    #[serde(default = "default_true")]
    pub cross_language: bool,

    /// Enable cross-family detection.
    #[serde(default = "default_true")]
    pub cross_family: bool,

    /// Enable leak detection.
    #[serde(default = "default_true")]
    pub leak_detection: bool,

    /// Enable use-after-free detection.
    #[serde(default = "default_true")]
    pub use_after_free: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            cross_language: true,
            cross_family: true,
            leak_detection: true,
            use_after_free: true,
        }
    }
}

impl OmniScopeConfig {
    /// Create a default configuration with no FFI boundaries.
    ///
    /// Useful as a fallback when no configuration file is found.
    pub fn default_config() -> Self {
        Self::default()
    }

    /// Generate a default configuration with example FFI boundaries and resource families.
    ///
    /// This is useful for generating example configuration files or for testing.
    pub fn generate_default() -> Self {
        Self {
            project: Some(ProjectConfig {
                name: None,
                description: Some("OmniScope project".to_string()),
            }),
            ffi_boundary: vec![FFIBoundaryConfig {
                from: Language::C,
                to: Language::Cpp,
                functions: vec!["example_c_to_cpp".to_string()],
                pattern: None,
                description: Some("Example C to C++ boundary".to_string()),
            }],
            resource_family: vec![ResourceFamilyConfig {
                name: "custom_allocator".to_string(),
                kind: FamilyKind::ManualHeap,
                acquire: vec!["my_alloc".to_string()],
                release: vec!["my_free".to_string()],
                compatible_releases: Vec::new(),
            }],
            analysis: AnalysisOptions::default(),
        }
    }

    /// Load configuration from a TOML file.
    ///
    /// # Arguments
    /// * `path` - Path to the TOML configuration file.
    ///
    /// # Returns
    /// Parsed configuration or error.
    pub fn load_from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(path.display().to_string(), e))?;

        Self::parse_toml(&content)
    }

    /// Parse configuration from a TOML string.
    ///
    /// # Arguments
    /// * `content` - TOML string content.
    ///
    /// # Returns
    /// Parsed configuration or error.
    pub fn parse_toml(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Save configuration to a TOML file.
    ///
    /// # Arguments
    /// * `path` - Path to write the TOML configuration file.
    ///
    /// # Returns
    /// Ok(()) on success, or an error if writing fails.
    pub fn save_to_file(&self, path: &Path) -> Result<(), ConfigError> {
        let content =
            toml::to_string_pretty(self).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        std::fs::write(path, content)
            .map_err(|e| ConfigError::IoError(path.display().to_string(), e))?;
        Ok(())
    }

    /// Parse configuration from a TOML string (convenience method).
    ///
    /// This is a convenience method that panics on error. Use `parse_toml` for
    /// error handling.
    ///
    /// # Arguments
    /// * `content` - TOML string content.
    ///
    /// # Returns
    /// Parsed configuration.
    ///
    /// # Panics
    /// Panics if the TOML content is invalid.
    pub fn from_toml_str(content: &str) -> Self {
        Self::parse_toml(content).expect("Failed to parse TOML config")
    }

    /// Load configuration from default locations.
    ///
    /// Searches for configuration in:
    /// 1. `./omniscope.toml`
    /// 2. `~/.config/omniscope/config.toml`
    ///
    /// # Returns
    /// Configuration if found, None otherwise.
    pub fn load_default() -> Result<Option<Self>, ConfigError> {
        // Try current directory
        let local_config = Path::new("omniscope.toml");
        if local_config.exists() {
            return Ok(Some(Self::load_from_file(local_config)?));
        }

        // Try home config
        if let Some(home) = dirs::home_dir() {
            let home_config = home.join(".config/omniscope/config.toml");
            if home_config.exists() {
                return Ok(Some(Self::load_from_file(&home_config)?));
            }
        }

        Ok(None)
    }

    /// Get all FFI boundary functions as a flat list.
    pub fn ffi_boundary_functions(&self) -> Vec<(&str, Language, Language)> {
        self.ffi_boundary
            .iter()
            .flat_map(|boundary| {
                boundary
                    .functions
                    .iter()
                    .map(move |func| (func.as_str(), boundary.from, boundary.to))
            })
            .collect()
    }

    /// Check if a function is in any FFI boundary.
    pub fn is_ffi_boundary(&self, function: &str) -> Option<(Language, Language)> {
        self.ffi_boundary
            .iter()
            .find(|boundary| boundary.functions.contains(&function.to_string()))
            .map(|boundary| (boundary.from, boundary.to))
    }

    /// Check if a function is in any FFI boundary, supporting language pair matching.
    ///
    /// This method supports:
    /// 1. Explicit function list
    /// 2. Pattern matching
    /// 3. Language pair matching (when functions is empty)
    ///
    /// # Arguments
    /// * `function` - The function name to check.
    /// * `caller_lang` - The language of the caller function.
    /// * `callee_lang` - The language of the callee function.
    ///
    /// # Returns
    /// `Some((from, to))` if the function is in a declared boundary, `None` otherwise.
    pub fn is_ffi_boundary_with_lang(
        &self,
        function: &str,
        caller_lang: Language,
        callee_lang: Language,
    ) -> Option<(Language, Language)> {
        // 先检查显式函数列表和模式匹配
        for boundary in &self.ffi_boundary {
            // 检查显式函数列表
            if boundary.functions.contains(&function.to_string()) {
                return Some((boundary.from, boundary.to));
            }

            // 检查模式匹配（如果有）
            if let Some(pattern) = &boundary.pattern {
                if crate::boundary::matches_pattern(function, pattern) {
                    return Some((boundary.from, boundary.to));
                }
            }
        }

        // 再检查语言对匹配
        for boundary in &self.ffi_boundary {
            if boundary.functions.is_empty()
                && boundary.pattern.is_none()
                && boundary.from == caller_lang
                && boundary.to == callee_lang
            {
                return Some((boundary.from, boundary.to));
            }
        }

        None
    }

    /// Convert configuration to a `BoundaryContext`.
    ///
    /// This creates a `BoundaryContext` from all declared FFI boundaries,
    /// including both exact function names and wildcard patterns.
    ///
    /// # Returns
    /// A `BoundaryContext` ready for boundary detection queries.
    pub fn to_boundary_context(&self) -> crate::boundary::BoundaryContext {
        let mut ctx = crate::boundary::BoundaryContext::new();

        for boundary in &self.ffi_boundary {
            ctx.add_boundary(boundary);
        }

        ctx
    }
}

/// Configuration error types.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error reading {0}: {1}")]
    IoError(String, std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(String),
}

#[cfg(test)]
mod config_tests {
    use super::*;

    /// Objective: Verify that a valid TOML configuration can be parsed.
    /// Invariants: All fields should be correctly deserialized.
    #[test]
    fn test_parse_valid_config() {
        let toml = r#"
[project]
name = "test_project"
description = "A test project"

[[ffi_boundary]]
from = "c"
to = "cpp"
functions = ["c_fft_forward", "c_hash"]
description = "C -> C++ bridge"

[[resource_family]]
name = "custom_allocator"
kind = "ManualHeap"
acquire = ["my_alloc"]
release = ["my_free"]

[analysis]
cross_language = true
cross_family = true
leak_detection = true
use_after_free = false
"#;

        let config = OmniScopeConfig::parse_toml(toml).unwrap();

        assert_eq!(config.project.unwrap().name.unwrap(), "test_project");
        assert_eq!(config.ffi_boundary.len(), 1);
        assert_eq!(config.ffi_boundary[0].from, Language::C);
        assert_eq!(config.ffi_boundary[0].to, Language::Cpp);
        assert_eq!(config.resource_family.len(), 1);
        assert_eq!(config.resource_family[0].kind, FamilyKind::ManualHeap);
        assert!(!config.analysis.use_after_free);
    }

    /// Objective: Verify that FFI boundary functions can be queried.
    /// Invariants: All functions should be found with correct languages.
    #[test]
    fn test_ffi_boundary_functions() {
        let toml = r#"
[[ffi_boundary]]
from = "c"
to = "cpp"
functions = ["func1", "func2"]
"#;

        let config = OmniScopeConfig::parse_toml(toml).unwrap();
        let functions = config.ffi_boundary_functions();

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].0, "func1");
        assert_eq!(functions[0].1, Language::C);
        assert_eq!(functions[0].2, Language::Cpp);
        assert_eq!(functions[1].0, "func2");
    }

    /// Objective: Verify that invalid TOML returns an error.
    /// Invariants: Parse error should be descriptive.
    #[test]
    fn test_parse_invalid_config() {
        let toml = "invalid toml content [[[";
        let result = OmniScopeConfig::parse_toml(toml);
        assert!(result.is_err());
    }
}
