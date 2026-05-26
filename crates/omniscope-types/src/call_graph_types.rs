//! Call graph type definitions
//!
//! Contains pure type definitions, constant arrays, and data structures
//! used by the call graph analysis system. Extracted from the call graph
//! analysis pass for better code organization and single-responsibility.

use serde::{Deserialize, Serialize};

/// Classification of function origin in the call graph.
///
/// Used to determine trust boundaries and FFI transitions.
/// A function's kind affects how it is treated in taint propagation
/// and ownership tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FunctionKind {
    /// Function defined within the analyzed module.
    Internal,
    /// Standard C library function (trusted, not an FFI boundary).
    LibC,
    /// Function with unknown origin (potential FFI boundary).
    ExternalUnknown,
}

/// Node in the call graph representing a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    /// Function name (mangled or demangled).
    pub name: String,
    /// Function kind classification (internal, libc, external).
    pub kind: FunctionKind,
    /// Number of parameters in the function signature.
    pub param_count: usize,
    /// Whether this is a declaration (no body in the IR).
    pub is_declaration: bool,
    /// Source language (if determinable from name patterns).
    pub language: Option<super::config::Language>,
}

/// Edge in the call graph representing a call relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphEdge {
    /// Caller function name.
    pub caller: String,
    /// Callee function name.
    pub callee: String,
    /// Whether this call crosses a language boundary.
    pub is_cross_lang: bool,
    /// Source language of the caller (if known).
    pub caller_lang: Option<super::config::Language>,
    /// Source language of the callee (if known).
    pub callee_lang: Option<super::config::Language>,
}

/// Cross-language edge carrying FFI boundary metadata.
///
/// This is the central data structure for FFI boundary detection.
/// Each CrossLangEdge represents a call site where two different
/// languages meet, which is the focus of OmniScope's analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossLangEdge {
    /// Caller function name.
    pub caller_name: String,
    /// Callee function name.
    pub callee_name: String,
    /// Whether this is confirmed as an FFI boundary crossing.
    pub is_ffi_boundary: bool,
    /// Source language of the caller side.
    pub caller_lang: super::config::Language,
    /// Source language of the callee side.
    pub callee_lang: super::config::Language,
    /// Calling convention used at this boundary (e.g., C, stdcall).
    pub calling_convention: Option<super::abi::CallingConvention>,
}

// ============================================================================
// Trusted / dangerous / source / sink function lists
// ============================================================================

/// Trusted libc functions that are NOT FFI boundaries.
///
/// Source: config/languages/c.json. Dangerous functions like
/// `system`, `exec`, `popen` are deliberately excluded — see
/// DANGEROUS_FUNCTIONS.
pub const LIBC_FUNCTIONS: &[&str] = &[
    "malloc", "free", "calloc", "realloc", "read", "write", "open", "close", "strlen", "strncpy",
    "snprintf", "fgets", "getline", "memcpy", "memmove", "memset", "memcmp", "printf", "fprintf",
    "puts", "fopen", "fclose", "fread", "fwrite",
];

/// Dangerous functions flagged as security risks and treated as FFI boundaries.
pub const DANGEROUS_FUNCTIONS: &[&str] = &[
    "system",
    "exec",
    "execve",
    "execvp",
    "execv",
    "execl",
    "execlp",
    "execle",
    "fexecve",
    "posix_spawn",
    "posix_spawnp",
    "popen",
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "scanf",
    "getenv",
];

/// Taint source functions — where untrusted data enters the program.
pub const SOURCE_FUNCTIONS: &[&str] = &[
    "read", "recv", "gets", "fgets", "fread", "getenv", "getchar", "scanf", "fscanf", "sscanf",
];

/// Taint sink functions — where tainted data reaching them is a vulnerability.
pub const SINK_PATTERNS: &[&str] = &[
    "system", "exec", "popen", "strcpy", "strcat", "sprintf", "memcpy", "write", "printf",
];

/// Check if a function name matches a known libc function (exact match).
pub fn is_libc(func_name: &str) -> bool {
    LIBC_FUNCTIONS.contains(&func_name)
}

/// Check if a function name contains a known dangerous pattern (substring match).
pub fn is_dangerous(func_name: &str) -> bool {
    DANGEROUS_FUNCTIONS.iter().any(|p| func_name.contains(p))
}

/// Check if a function name is a taint source (exact match).
pub fn is_source(func_name: &str) -> bool {
    SOURCE_FUNCTIONS.contains(&func_name)
}

/// Check if a function name matches a taint sink pattern (substring match).
pub fn is_sink(func_name: &str) -> bool {
    SINK_PATTERNS.iter().any(|p| func_name.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libc_exact_match() {
        assert!(is_libc("malloc"), "malloc must be recognized as libc");
        assert!(is_libc("free"), "free must be recognized as libc");
        assert!(!is_libc("system"), "system is dangerous, NOT libc");
        assert!(!is_libc("unknown"), "unknown function is not libc");
    }

    #[test]
    fn test_dangerous_substring_match() {
        assert!(is_dangerous("system"), "system is inherently dangerous");
        assert!(is_dangerous("execl"), "execl is an exec variant");
        assert!(
            is_dangerous("my_system_call"),
            "substring match must detect system embedded in longer name"
        );
        assert!(!is_dangerous("malloc"), "malloc is libc, not dangerous");
    }

    #[test]
    fn test_source_and_sink_classification() {
        assert!(is_source("read"), "read is a standard taint source");
        assert!(
            is_source("fgets"),
            "fgets reads from file/stream → taint source"
        );
        assert!(is_sink("system"), "system executes commands → taint sink");
        assert!(is_sink("sprintf"), "sprintf format string → taint sink");
        assert!(!is_source("malloc"), "malloc is not a data source");
        assert!(!is_sink("strlen"), "strlen is libc, not a sink");
    }
}
