//! Platform-specific IR filtering for FFI analysis
//!
//! This module provides platform-aware filtering to reduce false positives
//! in FFI safety analysis. Different platforms (macOS, Linux, Windows) have
//! different memory management, threading, and runtime APIs that should not
//! be flagged as dangerous FFI.

use std::fmt;

/// Represents the target platform identified from LLVM IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Apple macOS (Darwin)
    MacOS,
    /// Linux (GNU libc or musl)
    Linux,
    /// Microsoft Windows
    Windows,
    /// Unknown or unsupported platform
    Unknown,
}

/// Represents the target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    /// x86-64 (AMD64)
    X86_64,
    /// ARM 64-bit (AArch64)
    AArch64,
    /// ARM 32-bit
    ARM,
    /// Unknown architecture
    Unknown,
}

/// Platform information extracted from LLVM IR metadata.
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    /// Full target triple (e.g., "x86_64-apple-darwin")
    pub target_triple: String,
    /// Detected platform
    pub platform: Platform,
    /// Detected architecture
    pub arch: Architecture,
}

impl PlatformInfo {
    /// Creates a new PlatformInfo by parsing a target triple.
    ///
    /// # Arguments
    ///
    /// * `target_triple` - The LLVM target triple string
    ///
    /// # Examples
    ///
    /// ```
    /// use omniscope_ir::platform::PlatformInfo;
    ///
    /// let info = PlatformInfo::from_target_triple("x86_64-apple-darwin");
    /// assert_eq!(info.platform, Platform::MacOS);
    /// ```
    pub fn from_target_triple(target_triple: &str) -> Self {
        let platform = Self::detect_platform(target_triple);
        let arch = Self::detect_architecture(target_triple);

        Self {
            target_triple: target_triple.to_string(),
            platform,
            arch,
        }
    }

    /// Detects the platform from a target triple.
    fn detect_platform(triple: &str) -> Platform {
        let triple_lower = triple.to_lowercase();

        // macOS detection
        if triple_lower.contains("darwin")
            || triple_lower.contains("macos")
            || triple_lower.contains("apple")
        {
            Platform::MacOS
        }
        // Windows detection (multiple variants)
        else if triple_lower.contains("windows")
            || triple_lower.contains("msvc")
            || triple_lower.contains("w64-windows")
            || triple_lower.contains("pc-windows")
        {
            Platform::Windows
        }
        // Linux detection
        else if triple_lower.contains("linux") || triple_lower.contains("gnu") {
            Platform::Linux
        } else {
            Platform::Unknown
        }
    }

    /// Detects the architecture from a target triple.
    fn detect_architecture(triple: &str) -> Architecture {
        let triple_lower = triple.to_lowercase();

        if triple_lower.contains("x86_64") || triple_lower.contains("amd64") {
            Architecture::X86_64
        } else if triple_lower.contains("aarch64") || triple_lower.contains("arm64") {
            Architecture::AArch64
        } else if triple_lower.contains("arm") {
            Architecture::ARM
        } else {
            Architecture::Unknown
        }
    }

    /// Returns the default platform info for the current host.
    pub fn current() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::from_target_triple("x86_64-apple-darwin")
        }
        #[cfg(target_os = "linux")]
        {
            Self::from_target_triple("x86_64-unknown-linux-gnu")
        }
        #[cfg(target_os = "windows")]
        {
            Self::from_target_triple("x86_64-pc-windows-msvc")
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Self::from_target_triple("unknown")
        }
    }
}

impl Default for PlatformInfo {
    fn default() -> Self {
        Self::current()
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Platform::MacOS => write!(f, "macOS"),
            Platform::Linux => write!(f, "Linux"),
            Platform::Windows => write!(f, "Windows"),
            Platform::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Registry of platform-specific safe APIs.
///
/// This registry contains lists of functions that are safe on specific platforms
/// and should not be flagged as dangerous FFI calls.
pub struct PlatformFilterRegistry {
    /// macOS-specific safe APIs
    macos_filters: Vec<&'static str>,
    /// Linux-specific safe APIs
    linux_filters: Vec<&'static str>,
    /// Windows-specific safe APIs
    windows_filters: Vec<&'static str>,
    /// Cross-platform safe APIs
    common_filters: Vec<&'static str>,
}

impl PlatformFilterRegistry {
    /// Creates a new registry with default platform-specific filters.
    ///
    /// The registry is populated with known safe APIs for each platform
    /// based on official documentation and common patterns.
    pub fn new() -> Self {
        Self {
            macos_filters: Self::macos_safe_apis(),
            linux_filters: Self::linux_safe_apis(),
            windows_filters: Self::windows_safe_apis(),
            common_filters: Self::cross_platform_safe_apis(),
        }
    }

    /// Checks if a function is safe on the given platform.
    ///
    /// # Arguments
    ///
    /// * `func_name` - The function name to check
    /// * `platform` - The target platform
    ///
    /// # Returns
    ///
    /// `true` if the function is a known safe platform API, `false` otherwise.
    pub fn is_platform_safe(&self, func_name: &str, platform: Platform) -> bool {
        // First check cross-platform safe APIs
        if self.is_in_filters(func_name, &self.common_filters) {
            return true;
        }

        // Then check platform-specific APIs
        let filters = match platform {
            Platform::MacOS => &self.macos_filters,
            Platform::Linux => &self.linux_filters,
            Platform::Windows => &self.windows_filters,
            Platform::Unknown => return false,
        };

        self.is_in_filters(func_name, filters)
    }

    /// Checks if a function name matches any filter pattern.
    fn is_in_filters(&self, func_name: &str, filters: &[&'static str]) -> bool {
        filters.iter().any(|pattern| func_name.contains(pattern))
    }

    /// Returns macOS-specific safe APIs.
    ///
    /// These include:
    /// - Zone allocators (malloc_zone_*)
    /// - Thread-local storage (_tlv_*)
    /// - Exception handling (__cxa_*)
    /// - Dynamic linking (dyld_*)
    fn macos_safe_apis() -> Vec<&'static str> {
        vec![
            // Zone allocators - safe memory management
            "malloc_zone_malloc",
            "malloc_zone_free",
            "malloc_zone_realloc",
            "malloc_zone_calloc",
            "malloc_default_zone",
            "malloc_create_zone",
            "malloc_set_zone_name",
            "malloc_size",
            // Thread-local storage
            "_tlv_atexit",
            "_tlv_bootstrap",
            "_tlv_get_addr",
            // Exception handling
            "__cxa_allocate_exception",
            "__cxa_throw",
            "__cxa_begin_catch",
            "__cxa_end_catch",
            // Dynamic linking
            "dyld_",
            "_dyld_",
        ]
    }

    /// Returns Linux-specific safe APIs.
    ///
    /// These include:
    /// - glibc internals (__libc_*)
    /// - Thread-local storage (__tls_*)
    /// - Exception handling (_Unwind_*)
    /// - Dynamic linking (dl*)
    fn linux_safe_apis() -> Vec<&'static str> {
        vec![
            // glibc internals
            "__libc_malloc",
            "__libc_free",
            "__libc_realloc",
            "mallopt",
            "__malloc_hook",
            // Thread-local storage
            "__tls_get_addr",
            "__cxa_thread_atexit",
            "__cxa_thread_atexit_impl",
            // Exception handling
            "_Unwind_RaiseException",
            "_Unwind_Resume",
            "_Unwind_DeleteException",
            // Dynamic linking
            "dlopen",
            "dlsym",
            "dlclose",
            "dlerror",
        ]
    }

    /// Returns Windows-specific safe APIs.
    ///
    /// These include:
    /// - Heap management (Heap*)
    /// - Thread-local storage (Tls*)
    /// - Exception handling (__Cxx*)
    /// - Dynamic loading (LoadLibrary*)
    /// - DLL operations (dllimport, dllexport)
    fn windows_safe_apis() -> Vec<&'static str> {
        vec![
            // Heap management
            "HeapAlloc",
            "HeapFree",
            "HeapReAlloc",
            "HeapSize",
            "LocalAlloc",
            "LocalFree",
            "GlobalAlloc",
            "GlobalFree",
            // Thread-local storage
            "TlsAlloc",
            "TlsFree",
            "TlsGetValue",
            "TlsSetValue",
            // Exception handling
            "__CxxThrowException",
            "_except_handler3",
            "_except_handler4",
            "RtlUnwind",
            // Dynamic loading
            "LoadLibrary",
            "GetProcAddress",
            "FreeLibrary",
            // DLL operations
            "dllimport",
            "dllexport",
            "__imp_", // Import thunk
        ]
    }

    /// Returns cross-platform safe APIs.
    ///
    /// These are safe on all platforms:
    /// - LLVM intrinsics (llvm.*)
    /// - Bounds-checked variants (*_chk)
    /// - C++ ABI functions (__cxa_, _Zn*)
    fn cross_platform_safe_apis() -> Vec<&'static str> {
        vec![
            // LLVM intrinsics
            "llvm.",
            // Bounds-checked variants
            "_chk",
            // C++ ABI
            "__cxa_",
            "_Znw",  // operator new
            "_Zdl",  // operator delete
            "_Zda",  // operator new[]
            "_ZdaP", // operator delete[]
            // Stack protection
            "__stack_chk_fail",
            "__fortify_fail",
        ]
    }
}

impl Default for PlatformFilterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection_macos() {
        let info = PlatformInfo::from_target_triple("x86_64-apple-darwin");
        assert_eq!(info.platform, Platform::MacOS);
        assert_eq!(info.arch, Architecture::X86_64);
    }

    #[test]
    fn test_platform_detection_linux() {
        let info = PlatformInfo::from_target_triple("x86_64-unknown-linux-gnu");
        assert_eq!(info.platform, Platform::Linux);
        assert_eq!(info.arch, Architecture::X86_64);
    }

    #[test]
    fn test_platform_detection_windows() {
        let info = PlatformInfo::from_target_triple("x86_64-pc-windows-msvc");
        assert_eq!(info.platform, Platform::Windows);
        assert_eq!(info.arch, Architecture::X86_64);
    }

    #[test]
    fn test_platform_detection_windows() {
        let info = PlatformInfo::from_target_triple("x86_64-pc-windows-msvc");
        assert_eq!(info.platform, Platform::Windows);
        assert_eq!(info.arch, Architecture::X86_64);

        // MinGW variant
        let info2 = PlatformInfo::from_target_triple("x86_64-w64-windows-gnu");
        assert_eq!(info2.platform, Platform::Windows);
    }

    #[test]
    fn test_platform_detection_aarch64() {
        let info = PlatformInfo::from_target_triple("aarch64-apple-darwin");
        assert_eq!(info.platform, Platform::MacOS);
        assert_eq!(info.arch, Architecture::AArch64);
    }

    #[test]
    fn test_platform_detection_linux_gnu() {
        let info = PlatformInfo::from_target_triple("x86_64-unknown-linux-gnu");
        assert_eq!(info.platform, Platform::Linux);

        // musl variant
        let info2 = PlatformInfo::from_target_triple("x86_64-unknown-linux-musl");
        assert_eq!(info2.platform, Platform::Linux);
    }

    #[test]
    fn test_macos_zone_allocator_safe() {
        let registry = PlatformFilterRegistry::new();
        assert!(registry.is_platform_safe("malloc_zone_malloc", Platform::MacOS));
        assert!(registry.is_platform_safe("malloc_zone_free", Platform::MacOS));
        assert!(registry.is_platform_safe("malloc_default_zone", Platform::MacOS));
    }

    #[test]
    fn test_linux_glibc_safe() {
        let registry = PlatformFilterRegistry::new();
        assert!(registry.is_platform_safe("__libc_malloc", Platform::Linux));
        assert!(registry.is_platform_safe("__libc_free", Platform::Linux));
    }

    #[test]
    fn test_windows_heap_safe() {
        let registry = PlatformFilterRegistry::new();
        assert!(registry.is_platform_safe("HeapAlloc", Platform::Windows));
        assert!(registry.is_platform_safe("HeapFree", Platform::Windows));
    }

    #[test]
    fn test_cross_platform_safe() {
        let registry = PlatformFilterRegistry::new();
        // LLVM intrinsics are safe on all platforms
        assert!(registry.is_platform_safe("llvm.memcpy", Platform::MacOS));
        assert!(registry.is_platform_safe("llvm.memcpy", Platform::Linux));
        assert!(registry.is_platform_safe("llvm.memcpy", Platform::Windows));

        // Bounds-checked variants are safe
        assert!(registry.is_platform_safe("__memcpy_chk", Platform::MacOS));
        assert!(registry.is_platform_safe("__memcpy_chk", Platform::Linux));
    }

    #[test]
    fn test_dangerous_ffi_not_safe() {
        let registry = PlatformFilterRegistry::new();
        // malloc/free should NOT be marked as safe
        assert!(!registry.is_platform_safe("malloc", Platform::MacOS));
        assert!(!registry.is_platform_safe("free", Platform::Linux));
        assert!(!registry.is_platform_safe("malloc", Platform::Windows));
    }
}
