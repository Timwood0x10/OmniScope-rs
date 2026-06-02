//! Unified IR loading strategy
//!
//! This module provides a smart loading pipeline that selects the best
//! available backend for parsing LLVM IR files:
//!
//! 1. **llvm-sys** (Plan C) -- Best type information, works on .bc and .ll.
//! 2. **C++ Pass JSON** (Plan A) -- Rich metadata via `opt` + SafetyExportPass.so.
//! 3. **Text parser** (legacy) -- Zero dependencies, always available.
//!
//! The [`LoadStrategy::Auto`] variant probes for each backend in priority order
//! and gracefully falls back to the next.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tracing::{debug, info, warn};

use crate::parser::IRModule;
use crate::ir_cache::{IrCache, find_project_root};

/// Result of loading an IR module, including timing and strategy metadata.
#[derive(Debug)]
pub struct LoadedIr {
    /// The loaded IR module.
    pub module: IRModule,
    /// The strategy that was actually used (may differ from requested for Auto/AutoFast).
    pub strategy: LoadStrategy,
    /// Time taken to load the IR module in milliseconds.
    pub load_ms: u64,
}

// ---------------------------------------------------------------------------
// Backend cache for tool discovery
// ---------------------------------------------------------------------------

/// Cached paths for C++ pass backend tools.
///
/// This avoids repeated filesystem scans when checking availability
/// or loading IR modules multiple times.
#[derive(Debug, Clone)]
struct CppPassBackend {
    opt: PathBuf,
    plugin: PathBuf,
}

/// Cached paths for direct C++ IR extractor.
#[derive(Debug, Clone)]
struct DirectCppBackend {
    extractor: PathBuf,
}

/// Global cache for backend tool paths.
///
/// Uses `OnceLock` for thread-safe lazy initialization.
/// The cache is populated on first access and reused for subsequent calls.
struct BackendCache {
    cpp_pass: OnceLock<Option<CppPassBackend>>,
    direct_cpp: OnceLock<Option<DirectCppBackend>>,
}

impl BackendCache {
    const fn new() -> Self {
        Self {
            cpp_pass: OnceLock::new(),
            direct_cpp: OnceLock::new(),
        }
    }

    /// Get or compute the C++ pass backend paths.
    ///
    /// Returns `Some(CppPassBackend)` if both `opt` and `SafetyExportPass.so` are found.
    fn get_cpp_pass(&self) -> Option<&CppPassBackend> {
        self.cpp_pass
            .get_or_init(|| {
                let opt = find_opt()?;
                let plugin = find_pass_plugin()?;
                Some(CppPassBackend { opt, plugin })
            })
            .as_ref()
    }

    /// Get or compute the direct C++ backend path.
    ///
    /// Returns `Some(DirectCppBackend)` if `ir_extractor` is found.
    fn get_direct_cpp(&self) -> Option<&DirectCppBackend> {
        self.direct_cpp
            .get_or_init(|| {
                let extractor = find_ir_extractor()?;
                Some(DirectCppBackend { extractor })
            })
            .as_ref()
    }
}

/// Global backend cache instance.
///
/// This is safe to use from multiple threads because `OnceLock` provides
/// thread-safe initialization guarantees.
static BACKEND_CACHE: BackendCache = BackendCache::new();

// ---------------------------------------------------------------------------
// Strategy enum
// ---------------------------------------------------------------------------

/// Strategy for loading LLVM IR files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadStrategy {
    /// Use the direct C++ IR extractor with FFI slice filtering.
    /// Requires: `ir_extractor` binary with --slice=ffi support.
    DirectCppFfi,
    /// Use the direct C++ IR extractor (no opt dependency).
    ///
    /// Requires: `ir_extractor` binary.
    DirectCpp,
    /// Use the `llvm-sys` C API directly.
    ///
    /// Requires: LLVM development libraries installed.
    LlvmSys,
    /// Use the C++ LLVM pass to produce JSON, then deserialize.
    ///
    /// Requires: `opt` binary and `SafetyExportPass.so` plugin.
    CppPass,
    /// Use the legacy text parser (`llvm-dis` + line-by-line parsing).
    ///
    /// Always available but lacks rich type information.
    TextParser,
    /// Auto-detect the best available strategy.
    ///
    /// Priority: DirectCppFfi > DirectCpp > llvm-sys > cpp pass > text parser.
    Auto,
    /// Auto-detect with fast preference for .ll files.
    ///
    /// For .ll files, prefer text parser first (faster).
    /// For .bc files, use normal auto-detection.
    /// Includes confidence gate for large files.
    AutoFast,
}

impl std::fmt::Display for LoadStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadStrategy::DirectCppFfi => write!(f, "direct-cpp-ffi"),
            LoadStrategy::CppPass => write!(f, "cpp-pass"),
            LoadStrategy::DirectCpp => write!(f, "direct-cpp"),
            LoadStrategy::LlvmSys => write!(f, "llvm-sys"),
            LoadStrategy::TextParser => write!(f, "text-parser"),
            LoadStrategy::Auto => write!(f, "auto"),
            LoadStrategy::AutoFast => write!(f, "auto-fast"),
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Load an IR module from a file using the specified strategy.
///
/// This is the **primary entry point** for the CLI and pipeline.  It resolves
/// the chosen strategy, runs the corresponding backend, and returns a fully
/// populated [`LoadedIr`] containing the module, strategy used, and timing.
///
/// # Errors
///
/// Returns an error when the chosen backend is unavailable or the file cannot
/// be parsed.
pub fn load_ir(path: &Path, strategy: LoadStrategy) -> Result<LoadedIr> {
    if !path.exists() {
        bail!("IR file does not exist: {}", path.display());
    }

    info!(
        path = %path.display(),
        strategy = %strategy,
        "Loading IR module"
    );

    let start = Instant::now();
    
    let (module, actual_strategy) = match strategy {
        LoadStrategy::Auto => load_auto(path)?,
        LoadStrategy::AutoFast => load_auto_fast(path)?,
        LoadStrategy::DirectCppFfi => (load_via_direct_cpp_ffi(path)?, LoadStrategy::DirectCppFfi),
        LoadStrategy::CppPass => (load_via_cpp_pass(path)?, LoadStrategy::CppPass),
        LoadStrategy::DirectCpp => (load_via_direct_cpp(path)?, LoadStrategy::DirectCpp),
        LoadStrategy::LlvmSys => (load_via_llvm_sys(path)?, LoadStrategy::LlvmSys),
        LoadStrategy::TextParser => (load_via_text(path)?, LoadStrategy::TextParser),
    };
    
    let load_ms = start.elapsed().as_millis() as u64;
    
    info!(
        path = %path.display(),
        strategy = %actual_strategy,
        load_ms = load_ms,
        "IR module loaded successfully"
    );
    
    Ok(LoadedIr {
        module,
        strategy: actual_strategy,
        load_ms,
    })
}

// ---------------------------------------------------------------------------
// Auto-detection
// ---------------------------------------------------------------------------

/// Probe backends in priority order and fall back gracefully.
///
/// Priority: **DirectCppFfi** > **DirectCpp** > **llvm-sys** > **cpp pass** > **text parser**.
fn load_auto(path: &Path) -> Result<(IRModule, LoadStrategy)> {
    // 1. Try DirectCppFfi
    if can_use_direct_cpp_ffi() {
        debug!("Attempting DirectCppFfi backend");
        match load_via_direct_cpp_ffi(path) {
            Ok(module) => {
                info!("Loaded via DirectCppFfi");
                return Ok((module, LoadStrategy::DirectCppFfi));
            }
            Err(e) => {
                warn!(error = %e, "DirectCppFfi backend failed, falling back");
            }
        }
    } else {
        debug!("DirectCppFfi not available");
    }

    // 2. Try DirectCpp
    if can_use_direct_cpp() {
        debug!("Attempting DirectCpp backend");
        match load_via_direct_cpp(path) {
            Ok(module) => {
                info!("Loaded via DirectCpp");
                return Ok((module, LoadStrategy::DirectCpp));
            }
            Err(e) => {
                warn!(error = %e, "DirectCpp backend failed, falling back");
            }
        }
    } else {
        debug!("DirectCpp not available");
    }

    // 3. Try llvm-sys
    if can_use_llvm_sys() {
        debug!("Attempting llvm-sys backend");
        match load_via_llvm_sys(path) {
            Ok(module) => {
                info!("Loaded via llvm-sys");
                return Ok((module, LoadStrategy::LlvmSys));
            }
            Err(e) => {
                warn!(error = %e, "llvm-sys backend failed, falling back");
            }
        }
    } else {
        debug!("llvm-sys not available");
    }

    // 4. Try C++ pass
    if can_use_cpp_pass() {
        debug!("Attempting C++ pass backend");
        match load_via_cpp_pass(path) {
            Ok(module) => {
                info!("Loaded via C++ pass");
                return Ok((module, LoadStrategy::CppPass));
            }
            Err(e) => {
                warn!(error = %e, "C++ pass backend failed, falling back");
            }
        }
    } else {
        debug!("C++ pass not available");
    }

    // 5. Text parser -- always available
    debug!("Falling back to text parser");
    let module = load_via_text(path)?;
    Ok((module, LoadStrategy::TextParser))
}

// ---------------------------------------------------------------------------
// Backend: llvm-sys (Plan C)
// ---------------------------------------------------------------------------

/// Check whether the `llvm-sys` backend is available.
///
/// Returns `true` only when the `llvm-backend` feature is enabled
/// and the LLVM C API libraries are found at build time.
#[cfg(feature = "llvm-backend")]
fn can_use_llvm_sys() -> bool {
    crate::llvm_sys_adapter::is_available()
}

#[cfg(not(feature = "llvm-backend"))]
fn can_use_llvm_sys() -> bool {
    false
}

/// Check whether the direct C++ IR extractor with FFI slice filtering is available.
///
/// Returns `true` only when the `ir_extractor` binary can be found and supports `--slice=ffi`.
fn can_use_direct_cpp_ffi() -> bool {
    find_ir_extractor().is_some()
}

/// Check whether the direct C++ IR extractor backend is available.
///
/// Returns `true` only when the `ir_extractor` binary can be found.
fn can_use_direct_cpp() -> bool {
    find_ir_extractor().is_some()
}

/// Load IR via the `llvm-sys` C API adapter.
#[cfg(feature = "llvm-backend")]
fn load_via_llvm_sys(path: &Path) -> Result<IRModule> {
    crate::llvm_sys_adapter::parse_with_llvm_sys(path)
}

#[cfg(not(feature = "llvm-backend"))]
fn load_via_llvm_sys(_path: &Path) -> Result<IRModule> {
    anyhow::bail!("llvm-sys backend not enabled — compile with --features llvm-backend")
}

// ---------------------------------------------------------------------------
// Backend: C++ Pass JSON (Plan A)
// ---------------------------------------------------------------------------

/// Check whether the C++ pass backend is available.
///
/// Both `opt` and the SafetyExportPass plugin must be locatable.
fn can_use_cpp_pass() -> bool {
    find_opt().is_some() && find_pass_plugin().is_some()
}

/// Load IR by running `opt -load-pass-plugin SafetyExportPass.so` and
/// deserializing the resulting JSON.
fn load_via_cpp_pass(path: &Path) -> Result<IRModule> {
    let opt = find_opt().context("`opt` binary not found for C++ pass backend")?;
    let plugin =
        find_pass_plugin().context("SafetyExportPass.so plugin not found for C++ pass backend")?;

    debug!(
        opt = %opt.display(),
        plugin = %plugin.display(),
        input = %path.display(),
        "Running C++ pass via opt"
    );

    let output = std::process::Command::new(&opt)
        .arg("-load-pass-plugin")
        .arg(&plugin)
        .arg("-passes=safety-export")
        .arg(path)
        .arg("-o")
        .arg("/dev/null")
        .output()
        .with_context(|| format!("failed to execute opt at {}", opt.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "opt exited with status {}:\n{}",
            output.status,
            stderr.trim()
        );
    }

    let json_str = String::from_utf8(output.stdout).context("opt output is not valid UTF-8")?;

    // Delegate deserialization to the ir_model module (Plan A).
    let model = crate::ir_model::IRModuleModel::from_json_str(&json_str)
        .context("failed to deserialize C++ pass JSON output")?;

    Ok(model.to_ir_module())
}

// ---------------------------------------------------------------------------
// Backend: Direct C++ IR extractor with FFI slice filtering
// ---------------------------------------------------------------------------

/// Load IR using the direct C++ IR extractor with FFI slice filtering.
///
/// This backend runs the `ir_extractor` binary with `--slice=ffi` to focus
/// on FFI boundary code, reducing noise and improving precision for
/// cross-language analysis.
fn load_via_direct_cpp_ffi(path: &Path) -> Result<IRModule> {
    let extractor = find_ir_extractor()
        .context("ir_extractor binary not found for DirectCppFfi backend")?;

    debug!(
        extractor = %extractor.display(),
        input = %path.display(),
        "Running direct C++ IR extractor with FFI slice"
    );

    let output = std::process::Command::new(&extractor)
        .arg("--slice=ffi")
        .arg("--slice-hops=2")
        .arg("--slice-stats")
        .arg(path)
        .output()
        .with_context(|| format!("failed to execute ir_extractor at {}", extractor.display()))?;

    // Print slice stats from stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        debug!(stats = %stderr.trim(), "FFI slice statistics");
    }

    if !output.status.success() {
        bail!(
            "ir_extractor exited with status {}:\n{}",
            output.status,
            stderr.trim()
        );
    }

    let json_str = String::from_utf8(output.stdout)
        .context("ir_extractor output is not valid UTF-8")?;

    let model = crate::ir_model::IRModuleModel::from_json_str(&json_str)
        .context("failed to deserialize ir_extractor JSON output")?;

    Ok(model.to_ir_module())
}

// ---------------------------------------------------------------------------
// Backend: Direct C++ IR extractor
// ---------------------------------------------------------------------------

/// Load IR using the direct C++ IR extractor.
///
/// This backend runs the `ir_extractor` binary which parses LLVM IR directly
/// and outputs JSON. Unlike the C++ pass backend, it does not require `opt`
/// or the SafetyExportPass plugin.
fn load_via_direct_cpp(path: &Path) -> Result<IRModule> {
    let extractor = find_ir_extractor()
        .context("ir_extractor binary not found for DirectCpp backend")?;

    debug!(
        extractor = %extractor.display(),
        input = %path.display(),
        "Running direct C++ IR extractor"
    );

    let output = std::process::Command::new(&extractor)
        .arg(path)
        .output()
        .with_context(|| format!("failed to execute ir_extractor at {}", extractor.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "ir_extractor exited with status {}:\n{}",
            output.status,
            stderr.trim()
        );
    }

    let json_str = String::from_utf8(output.stdout)
        .context("ir_extractor output is not valid UTF-8")?;

    let model = crate::ir_model::IRModuleModel::from_json_str(&json_str)
        .context("failed to deserialize ir_extractor JSON output")?;

    Ok(model.to_ir_module())
}

// ---------------------------------------------------------------------------
// Backend: Text parser (legacy)
// ---------------------------------------------------------------------------

/// Load IR using the legacy text parser (`llvm-dis` + line-by-line parsing).
///
/// This backend always works as long as `llvm-dis` is reachable or the input
/// is already a `.ll` file.
fn load_via_text(path: &Path) -> Result<IRModule> {
    IRModule::load_from_file(path).map_err(|e| anyhow::anyhow!(e))
}

// ---------------------------------------------------------------------------
// Tool discovery helpers
// ---------------------------------------------------------------------------

/// Find the ir_extractor binary path.
///
/// Search order:
/// 1. `IR_EXTRACTOR` environment variable
/// 2. Common build directories (`tools/ir_extractor/build/`)
/// 3. `which ir_extractor` (PATH lookup)
pub fn find_ir_extractor() -> Option<PathBuf> {
    // 1. Environment variable — explicit override always wins
    if let Ok(path) = std::env::var("IR_EXTRACTOR") {
        let p = PathBuf::from(&path);
        if p.is_file() {
            debug!(path = %p.display(), "Found ir_extractor via IR_EXTRACTOR env");
            return Some(p);
        }
    }

    // 2. Look in tools/ir_extractor/build/
    let candidates = [
        "tools/ir_extractor/build/ir_extractor",
        "tools/ir_extractor/build/Release/ir_extractor",
        "tools/ir_extractor/build/Debug/ir_extractor",
    ];

    for candidate in &candidates {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            debug!(path = %p.display(), "Found ir_extractor in build directory");
            return Some(p);
        }
    }

    // 3. Look in PATH
    if let Some(p) = which("ir_extractor") {
        debug!(path = %p.display(), "Found ir_extractor via PATH");
        return Some(p);
    }

    debug!("ir_extractor binary not found");
    None
}

/// Find the `opt` binary path.
///
/// Search order (prefers the newest LLVM version):
/// 1. `LLVM_OPT` environment variable (explicit override)
/// 2. Common Homebrew paths (newest LLVM first: 22, 21, 20, ...)
/// 3. `llvm-config --bindir` + `/opt` (may be an older version on PATH)
/// 4. `which opt` (last resort, often an older version)
pub fn find_opt() -> Option<PathBuf> {
    // 1. Environment variable — explicit override always wins
    if let Ok(path) = std::env::var("LLVM_OPT") {
        let p = PathBuf::from(&path);
        if p.is_file() {
            debug!(path = %p.display(), "Found opt via LLVM_OPT env");
            return Some(p);
        }
    }

    // 2. Homebrew paths — prefer newest version (llvm@22 > llvm@21 > ...)
    let candidates = homebrew_llvm_bin_dirs();
    for dir in candidates {
        let p = dir.join("opt");
        if p.is_file() {
            debug!(path = %p.display(), "Found opt via Homebrew path");
            return Some(p);
        }
    }

    // 3. llvm-config --bindir
    if let Some(dir) = llvm_config_bindir() {
        let p = dir.join("opt");
        if p.is_file() {
            debug!(path = %p.display(), "Found opt via llvm-config");
            return Some(p);
        }
    }

    // 4. which opt — last resort
    if let Some(p) = which("opt") {
        debug!(path = %p.display(), "Found opt via PATH");
        return Some(p);
    }

    debug!("opt binary not found");
    None
}

/// Find the SafetyExportPass shared library plugin.
///
/// Search order:
/// 1. `SAFETY_PASS_PLUGIN` environment variable
/// 2. Relative to project root: `pass/build/libSafetyExportPass.{so,dylib}`
/// 3. Relative to current directory
pub fn find_pass_plugin() -> Option<PathBuf> {
    // Platform-specific shared library extension and prefix.
    #[cfg(target_os = "macos")]
    const LIB_NAMES: &[&str] = &[
        "libSafetyExportPass.dylib",
        "SafetyExportPass.dylib",
        "libSafetyExportPass.so",
        "SafetyExportPass.so",
    ];
    #[cfg(target_os = "linux")]
    const LIB_NAMES: &[&str] = &["libSafetyExportPass.so", "SafetyExportPass.so"];
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    const LIB_NAMES: &[&str] = &["SafetyExportPass.so"];

    // 1. Environment variable
    if let Ok(path) = std::env::var("SAFETY_PASS_PLUGIN") {
        let p = PathBuf::from(&path);
        if p.is_file() {
            debug!(path = %p.display(), "Found plugin via SAFETY_PASS_PLUGIN env");
            return Some(p);
        }
    }

    // 2. Relative to project root (search upward from CWD for Cargo.toml)
    if let Some(root) = find_project_root() {
        for name in LIB_NAMES {
            let candidates = [
                root.join("pass").join("build").join(name),
                root.join("pass").join("build").join("lib").join(name),
                root.join("pass").join("build").join("Release").join(name),
            ];
            for p in &candidates {
                if p.is_file() {
                    debug!(path = %p.display(), "Found plugin relative to project root");
                    return Some(p.clone());
                }
            }
        }
    }

    // 3. Relative to current directory
    for name in LIB_NAMES {
        let local = PathBuf::from(name);
        if local.is_file() {
            debug!(path = %local.display(), "Found plugin in current directory");
            return Some(local);
        }
    }

    debug!("SafetyExportPass plugin not found");
    None
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Run `llvm-config --bindir` and return the path if successful.
fn llvm_config_bindir() -> Option<PathBuf> {
    // Try versioned names first
    let candidates = [
        "llvm-config",
        "llvm-config-22",
        "llvm-config-21",
        "llvm-config-20",
        "llvm-config-19",
        "llvm-config-18",
        "llvm-config-17",
    ];

    for bin in &candidates {
        if let Ok(output) = std::process::Command::new(bin).arg("--bindir").output() {
            if output.status.success() {
                let dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !dir.is_empty() {
                    return Some(PathBuf::from(dir));
                }
            }
        }
    }

    // Also try common Homebrew llvm-config paths
    let homebrew_configs = [
        "/opt/homebrew/opt/llvm@22/bin/llvm-config",
        "/opt/homebrew/opt/llvm@21/bin/llvm-config",
        "/opt/homebrew/opt/llvm@20/bin/llvm-config",
        "/opt/homebrew/opt/llvm@19/bin/llvm-config",
        "/opt/homebrew/opt/llvm@18/bin/llvm-config",
        "/opt/homebrew/opt/llvm@17/bin/llvm-config",
        "/opt/homebrew/opt/llvm/bin/llvm-config",
    ];

    for cfg in &homebrew_configs {
        if let Ok(output) = std::process::Command::new(cfg).arg("--bindir").output() {
            if output.status.success() {
                let dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !dir.is_empty() {
                    return Some(PathBuf::from(dir));
                }
            }
        }
    }

    None
}

/// Search PATH for a binary.
fn which(name: &str) -> Option<PathBuf> {
    let Ok(path_var) = std::env::var("PATH") else {
        return None;
    };

    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

/// Return common Homebrew LLVM bin directories (newest version first).
fn homebrew_llvm_bin_dirs() -> Vec<PathBuf> {
    [
        "/opt/homebrew/opt/llvm@22/bin",
        "/opt/homebrew/opt/llvm@21/bin",
        "/opt/homebrew/opt/llvm@20/bin",
        "/opt/homebrew/opt/llvm@19/bin",
        "/opt/homebrew/opt/llvm@18/bin",
        "/opt/homebrew/opt/llvm@17/bin",
        "/opt/homebrew/opt/llvm/bin",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

/// Walk up from the current directory looking for `Cargo.toml` to locate
/// the project root.
fn find_project_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("Cargo.toml").is_file() {
            return Some(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_display() {
        assert_eq!(
            LoadStrategy::Auto.to_string(),
            "auto",
            "Auto strategy should display as 'auto'"
        );
        assert_eq!(
            LoadStrategy::DirectCppFfi.to_string(),
            "direct-cpp-ffi",
            "DirectCppFfi strategy should display as 'direct-cpp-ffi'"
        );
        assert_eq!(
            LoadStrategy::CppPass.to_string(),
            "cpp-pass",
            "CppPass strategy should display as 'cpp-pass'"
        );
        assert_eq!(
            LoadStrategy::DirectCpp.to_string(),
            "direct-cpp",
            "DirectCpp strategy should display as 'direct-cpp'"
        );
        assert_eq!(
            LoadStrategy::LlvmSys.to_string(),
            "llvm-sys",
            "LlvmSys strategy should display as 'llvm-sys'"
        );
        assert_eq!(
            LoadStrategy::TextParser.to_string(),
            "text-parser",
            "TextParser strategy should display as 'text-parser'"
        );
    }

    #[test]
    fn test_strategy_equality() {
        assert_eq!(
            LoadStrategy::Auto,
            LoadStrategy::Auto,
            "Auto should equal Auto"
        );
        assert_ne!(
            LoadStrategy::Auto,
            LoadStrategy::TextParser,
            "Auto should not equal TextParser"
        );
        assert_ne!(
            LoadStrategy::DirectCppFfi,
            LoadStrategy::DirectCpp,
            "DirectCppFfi should not equal DirectCpp"
        );
        assert_ne!(
            LoadStrategy::DirectCpp,
            LoadStrategy::TextParser,
            "DirectCpp should not equal TextParser"
        );
        assert_ne!(
            LoadStrategy::Auto,
            LoadStrategy::AutoFast,
            "Auto should not equal AutoFast"
        );
        assert_ne!(
            LoadStrategy::AutoFast,
            LoadStrategy::TextParser,
            "AutoFast should not equal TextParser"
        );
    }

    #[test]
    fn test_load_ir_rejects_nonexistent_file() {
        let result = load_ir(Path::new("/nonexistent/path.bc"), LoadStrategy::Auto);
        assert!(result.is_err(), "loading a nonexistent file must fail");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("does not exist"),
            "error should mention file not found, got: {msg}"
        );
    }

    #[test]
    fn test_load_ir_text_parser_empty_file() {
        // The text parser accepts any file content; an empty file produces an
        // empty module rather than an error.
        let tmp = tempfile::NamedTempFile::with_suffix(".ll").unwrap();
        std::fs::write(tmp.path(), "").unwrap();

        let module = load_ir(tmp.path(), LoadStrategy::TextParser).unwrap();
        assert!(
            module.functions.is_empty(),
            "empty file should produce an empty module"
        );
    }

    #[test]
    fn test_homebrew_llvm_bin_dirs_not_empty() {
        let dirs = homebrew_llvm_bin_dirs();
        assert!(
            !dirs.is_empty(),
            "should return at least one candidate path"
        );
    }

    #[test]
    fn test_find_project_root_returns_some() {
        // When run inside the repo, find_project_root should succeed.
        let root = find_project_root();
        assert!(root.is_some(), "should find Cargo.toml in the repo tree");
        assert!(
            root.unwrap().join("Cargo.toml").is_file(),
            "project root must contain Cargo.toml"
        );
    }

    #[test]
    fn test_which_finds_known_binary() {
        // `sh` should exist on any POSIX system
        let result = which("sh");
        assert!(
            result.is_some(),
            "which('sh') should find /bin/sh or similar"
        );
    }

    #[test]
    fn test_which_returns_none_for_garbage() {
        let result = which("__definitely_not_a_real_binary_12345__");
        assert!(
            result.is_none(),
            "which() for a nonexistent binary should return None"
        );
    }

    #[test]
    fn test_find_opt_returns_pathbuf() {
        // We cannot guarantee opt is installed, but the function should
        // not panic regardless.
        let _ = find_opt();
    }

    #[test]
    fn test_find_pass_plugin_returns_pathbuf() {
        let _ = find_pass_plugin();
    }
}
