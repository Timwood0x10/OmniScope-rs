//! Syscall Semantic Classification — NOT a whitelist
//!
//! This module provides the `SyscallSemantic` enum for classifying
//! system/library calls by their semantic behavior on resources.

/// Semantic classification of system/library calls.
///
/// This is NOT a whitelist — it's a semantic model that classifies calls
/// by what they DO to resources. The key insight from analyzing bun's
/// false positives: `getenv()` and `strlen()` are not resource operations,
/// they are data queries. Only calls in the `MemoryManagement` category
/// should be treated as potential ownership operations.
///
/// This classification drives the FFI boundary severity:
/// - `MemoryManagement` → potential ownership violation → HIGH if mismatched
/// - `DataQuery` → no ownership implication → lower severity
/// - `FileOperation` → file descriptor, not memory → not a memory safety issue
/// - etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallSemantic {
    /// Memory management: alloc, free, realloc, dealloc.
    /// These are the ONLY calls that should trigger CrossFamilyFree analysis.
    /// Examples: malloc, free, calloc, realloc, __rust_alloc, __rust_dealloc,
    ///           operator delete, operator new[]
    MemoryManagement,
    /// Data queries: read data without modifying ownership.
    /// Examples: strlen, getenv, memcmp, strncasecmp, memmem
    DataQuery,
    /// File/directory operations: operate on file system, not memory.
    /// Examples: unlink, rename, symlink, readlink, open, close, stat, fstat
    FileOperation,
    /// I/O operations: read/write to file descriptors or streams.
    /// Examples: read, write, poll, select, pipe, dup
    IOOperation,
    /// Network operations: socket, bind, connect, listen, accept.
    NetworkOperation,
    /// Process operations: fork, execve, exit, waitpid, kill.
    ProcessOperation,
    /// Time operations: clock_gettime, gettimeofday, nanosleep.
    TimeOperation,
    /// String/memory manipulation: operates on existing buffers.
    /// Does NOT allocate or free — caller owns the memory.
    /// Examples: memcpy, memset, memmove, strcpy, strncpy
    StringManipulation,
    /// Thread synchronization: mutex, condvar, barrier.
    /// These are InteriorMutability operations, not ownership transfers.
    /// Examples: pthread_mutex_lock, pthread_mutex_unlock
    ThreadSync,
    /// SIMD/compute acceleration: optimized implementations.
    /// These are pure computation, no ownership implications.
    /// Examples: highway_*, simdutf_*
    ComputeAccelerated,
    /// Internal dispatch mechanism: project-specific FFI bridge.
    /// These are by-design FFI calls, not accidental boundaries.
    /// Examples: __bun_dispatch__*, Bun__*, BunString__*
    InternalDispatch,
    /// Environment/configuration: reading config, locale, etc.
    /// Examples: setlocale, getenv, sysconf, getentropy
    EnvironmentConfig,
    /// Cannot classify from available information.
    Unknown,
}

impl SyscallSemantic {
    /// Classifies a function name into its syscall semantic category.
    ///
    /// This uses pattern matching on function names, but the patterns
    /// encode SEMANTIC MEANING, not just string matching. The difference
    /// from a whitelist is:
    ///
    /// 1. Each category has clear semantic criteria (what it does to resources)
    /// 2. New functions can be classified by their semantic, not name
    /// 3. The classification drives analysis behavior, not suppression
    pub fn classify(name: &str) -> Self {
        // ── Pattern-based classification first (for prefix patterns) ──
        // SIMD/compute acceleration
        if name.starts_with("highway_") || name.starts_with("simdutf__") {
            return SyscallSemantic::ComputeAccelerated;
        }
        // Internal dispatch mechanism (project-specific FFI bridge)
        if name.starts_with("__bun_dispatch__")
            || name.starts_with("Bun__")
            || name.starts_with("BunString__")
            || name.starts_with("WTF__")
            || name.starts_with("WTFStringImpl__")
        {
            return SyscallSemantic::InternalDispatch;
        }
        // C++ Itanium mangled names
        if name.starts_with("_Z") {
            if name.starts_with("_Zdl") || name.starts_with("_Zda") {
                return SyscallSemantic::MemoryManagement;
            }
            if name.starts_with("_Znw") || name.starts_with("_Zna") {
                return SyscallSemantic::MemoryManagement;
            }
            return SyscallSemantic::Unknown;
        }
        // Rust standard library functions
        if name.starts_with("_R") {
            // Memory management
            if name.contains("13drop_in_place") || name.contains("7dealloc") {
                return SyscallSemantic::MemoryManagement;
            }
            // alloc::raw_vec — heap allocation (Vec internal)
            if name.contains("7raw_vec") && (name.contains("4grow") || name.contains("8reserve")) {
                return SyscallSemantic::MemoryManagement;
            }
            // Thread synchronization — interior mutability, not ownership
            if name.contains("5mutex")
                || name.contains("6rwlock")
                || name.contains("8once_box")
                || name.contains("4once")
                || name.contains("7condvar")
            {
                return SyscallSemantic::ThreadSync;
            }
            // Panicking — control flow, not resource management
            if name.contains("9panicking") {
                return SyscallSemantic::ProcessOperation;
            }
            // cell — interior mutability
            if name.contains("4cell") {
                return SyscallSemantic::ThreadSync;
            }
            // alloc — memory allocation module
            if name.contains("5alloc") && !name.contains("7raw_vec") {
                return SyscallSemantic::MemoryManagement;
            }
            return SyscallSemantic::Unknown;
        }

        // ── Exact name classification ──
        match name {
            // Memory management — the only category that matters for CrossFamilyFree
            "malloc"
            | "calloc"
            | "realloc"
            | "valloc"
            | "posix_memalign"
            | "pvalloc"
            | "aligned_alloc"
            | "free"
            | "reallocarray"
            | "__rust_alloc"
            | "__rust_dealloc"
            | "__rust_realloc"
            | "__rust_alloc_zeroed"
            | "operator delete"
            | "operator delete[]"
            | "operator new"
            | "operator new[]"
            | "_ZdlPv"
            | "_Znwm"
            | "_Znam"
            | "mmap"
            | "munmap"
            | "mprotect" => SyscallSemantic::MemoryManagement,

            // Data queries — read-only, no ownership
            "strlen" | "strnlen" | "wcslen" | "strcmp" | "strncmp" | "strcasecmp"
            | "strncasecmp" | "memcmp" | "memmem" | "strstr" | "strchr" | "strrchr" | "index"
            | "rindex" => SyscallSemantic::DataQuery,

            // Environment/config
            "getenv" | "secure_getenv" | "setenv" | "unsetenv" | "putenv" | "sysconf"
            | "getentropy" => SyscallSemantic::EnvironmentConfig,

            // String/memory manipulation — caller owns buffer
            "memcpy" | "memset" | "memmove" | "strcpy" | "strncpy" | "strcat" | "strncat" => {
                SyscallSemantic::StringManipulation
            }

            // File operations
            "open" | "openat" | "close" | "read" | "write" | "pread" | "pwrite" | "lseek"
            | "stat" | "fstat" | "lstat" | "fstatat" | "unlink" | "rename" | "symlink"
            | "readlink" | "link" | "chmod" | "fchmod" | "chown" | "fchown" | "mkdir" | "rmdir"
            | "opendir" | "readdir" | "closedir" | "access" | "faccessat" | "truncate"
            | "ftruncate" | "sync" | "fsync" | "fdatasync" | "getcwd" => {
                SyscallSemantic::FileOperation
            }

            // I/O operations
            "poll" | "select" | "pselect" | "ppoll" | "epoll_create" | "epoll_wait"
            | "epoll_ctl" | "pipe" | "pipe2" | "dup" | "dup2" | "fcntl" | "ioctl" | "msync" => {
                SyscallSemantic::IOOperation
            }

            // Network operations
            "socket" | "bind" | "connect" | "listen" | "accept" | "accept4" | "recv" | "send"
            | "recvfrom" | "sendto" | "recvmsg" | "sendmsg" | "shutdown" | "getsockname"
            | "getpeername" | "getsockopt" | "setsockopt" | "ares_inet_pton" => {
                SyscallSemantic::NetworkOperation
            }

            // Process operations
            "fork"
            | "vfork"
            | "execve"
            | "execvp"
            | "execl"
            | "execlp"
            | "exit"
            | "_exit"
            | "abort"
            | "kill"
            | "raise"
            | "waitpid"
            | "wait4"
            | "posix_spawn"
            | "posix_spawnp"
            | "pthread_exit"
            | "pthread_setname_np"
            | "pthread_threadid_np"
            | "sigaction"
            | "sigemptyset"
            | "sigprocmask"
            | "signal" => SyscallSemantic::ProcessOperation,

            // Thread synchronization
            "pthread_mutex_lock"
            | "pthread_mutex_unlock"
            | "pthread_mutex_trylock"
            | "pthread_mutex_init"
            | "pthread_mutex_destroy"
            | "pthread_cond_wait"
            | "pthread_cond_signal"
            | "pthread_cond_broadcast"
            | "pthread_rwlock_rdlock"
            | "pthread_rwlock_wrlock"
            | "pthread_rwlock_unlock" => SyscallSemantic::ThreadSync,

            // Time operations
            "clock_gettime" | "gettimeofday" | "nanosleep" | "clock_nanosleep" | "timespec_get"
            | "time" => SyscallSemantic::TimeOperation,

            // Error reporting
            "__error" | "strerror" | "perror" | "dlerror" => SyscallSemantic::DataQuery,

            _ => SyscallSemantic::Unknown,
        }
    }

    /// Returns whether this syscall semantic involves memory ownership
    /// that could lead to CrossFamilyFree issues.
    ///
    /// Only `MemoryManagement` operations can cause cross-family free.
    /// All other categories are safe from this perspective.
    pub fn involves_memory_ownership(&self) -> bool {
        matches!(self, SyscallSemantic::MemoryManagement)
    }

    /// Returns the FFI safety score for calling this function across
    /// language boundaries.
    ///
    /// Based on Rustonomicon FFI chapter:
    /// - MemoryManagement: potentially dangerous if family mismatched
    /// - DataQuery/StringManipulation: safe (no ownership transfer)
    /// - InternalDispatch: by-design FFI (lower severity)
    pub fn ffi_safety_score(&self) -> f32 {
        match self {
            SyscallSemantic::MemoryManagement => 0.3, // Potentially dangerous
            SyscallSemantic::DataQuery => 0.95,       // Safe: no ownership
            SyscallSemantic::EnvironmentConfig => 0.95, // Safe: read config
            SyscallSemantic::StringManipulation => 0.9, // Safe: caller owns buffer
            SyscallSemantic::FileOperation => 0.85,   // Mostly safe: FD not memory
            SyscallSemantic::IOOperation => 0.85,     // Mostly safe: FD operations
            SyscallSemantic::NetworkOperation => 0.85, // Mostly safe: socket ops
            SyscallSemantic::ProcessOperation => 0.8, // Safe: process lifecycle
            SyscallSemantic::ThreadSync => 0.9,       // Safe: sync primitives
            SyscallSemantic::TimeOperation => 0.95,   // Safe: read time
            SyscallSemantic::ComputeAccelerated => 0.95, // Safe: pure computation
            SyscallSemantic::InternalDispatch => 0.7, // By-design FFI
            SyscallSemantic::Unknown => 0.5,          // Unknown: moderate risk
        }
    }
}
