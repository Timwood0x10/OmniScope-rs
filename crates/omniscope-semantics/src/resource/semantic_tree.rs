//! Semantic tree for Rustonomicon-aware analysis.
//!
//! This module reconstructs high-level Rust semantics from LLVM IR,
//! based on concepts from The Rustonomicon (The Dark Arts of Unsafe Rust).
//!
//! # Architecture
//!
//! ```text
//! LLVM IR ──→ ProvenanceTracker ──→ PointerProvenance
//!         ──→ TypeSemanticExtractor ──→ TypeSemantic
//!         ──→ SyscallClassifier ──→ SyscallSemantic
//!         ──→ SemanticNode ──→ SemanticTree
//! ```
//!
//! # Key Insight
//!
//! The root problem is that LLVM IR flattens Rust's ownership model:
//! - `Box::new()` heap pointer vs `alloca` stack pointer → both become `ptr`
//! - `UnsafeCell<T>` interior mutability vs immutable struct → both become `store`
//! - `unlink()` (file op) vs `free()` (memory release) → both become FFI calls
//!
//! The semantic tree reconstructs these distinctions from:
//! 1. **Mangled name patterns** (Rust v0 mangling encodes type paths)
//! 2. **IR instruction patterns** (alloca, call @malloc, load from global)
//! 3. **Syscall classification** (semantic model, not whitelist)
//!
//! This is NOT a whitelist — it's a semantic understanding layer.

use std::collections::HashMap;

// ──────────────────────────────────────────────────────────────────────────
// Pointer Provenance — where does this pointer come from?
// ──────────────────────────────────────────────────────────────────────────

/// Provenance of a pointer value, reconstructed from IR patterns.
///
/// Based on Rustonomicon's ownership model:
/// - Heap provenance (Box, Vec, Arc) → safe to pass across FFI
/// - Global provenance (static, const) → safe to pass across FFI
/// - Stack provenance (alloca, local) → DANGEROUS to pass across FFI
/// - Unknown → conservative (treat as potentially dangerous)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerProvenance {
    /// Pointer from heap allocation: `call @malloc`, `call @__rust_alloc`,
    /// `call @Box::new`, `call @Vec::with_capacity`, etc.
    /// FFI receiving this: usually safe (ownership transfer pattern).
    Heap,
    /// Pointer from global/static storage: `@alloc_*`, `load from @global`.
    /// FFI receiving this: safe for read, dangerous for write without sync.
    Global,
    /// Pointer from stack allocation: `alloca`, function parameter that
    /// originated from stack. FFI receiving this: DANGEROUS — the pointer
    /// may dangle after the function returns.
    Stack,
    /// Provenance cannot be determined from available IR.
    Unknown,
}

impl PointerProvenance {
    /// Returns how safe it is to pass a pointer of this provenance across FFI.
    ///
    /// Based on Rustonomicon FFI chapter: passing heap/global pointers is
    /// the standard pattern (Box::into_raw, Vec::as_ptr). Stack pointers
    /// require extreme care (the callee must not store the pointer).
    pub fn ffi_safety_score(&self) -> f32 {
        match self {
            PointerProvenance::Heap => 0.9,
            PointerProvenance::Global => 0.8,
            PointerProvenance::Stack => 0.2,
            PointerProvenance::Unknown => 0.5,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Type Semantic — what Rust type concept does this represent?
// ──────────────────────────────────────────────────────────────────────────

/// Semantic classification of a Rust type, extracted from mangled names.
///
/// Based on Rustonomicon chapters on:
/// - Interior mutability (UnsafeCell, Cell, RefCell, Once, Mutex, Atomic*)
/// - Ownership transfer (Box::into_raw, ManuallyDrop, Pin)
/// - Drop semantics (Drop, destructor patterns)
///
/// These are NOT type names — they are **semantic properties** that affect
/// whether an FFI call is safe. For example, writing through `&T` is UB
/// unless `T` contains `UnsafeCell` — the `InteriorMutability` variant
/// captures this distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeSemantic {
    /// Standard Rust type with no special ownership semantics.
    Ordinary,
    /// Contains `UnsafeCell<T>` — allows mutation through `&T`.
    ///
    /// Rustonomicon: "UnsafeCell is the core primitive for interior
    /// mutability." This means writing through a shared reference is
    /// NOT a bug if the type contains UnsafeCell.
    ///
    /// Detected from: `_R...4cell10UnsafeCell`, `_R...3std4sync5mutex`,
    /// `_R...3std4sync7rwlock`, `_R...3std6atomic`, `_R...4cell4Cell`,
    /// `_R...4cell7RefCell`, `_R...4cell11OnceCell`, etc.
    InteriorMutability,
    /// `ManuallyDrop<T>` — delayed destructor, owner must call drop manually.
    ///
    /// Rustonomicon: "ManuallyDrop<T> wraps a value to prevent it from
    /// being dropped." FFI code that takes ownership of a ManuallyDrop
    /// value is a common pattern for C→Rust ownership transfer.
    ManuallyDrop,
    /// `Pin<P>` — self-referential type, cannot be moved after pinning.
    ///
    /// Rustonomicon: "Pin<P> is a wrapper around a pointer that makes
    /// the pointed-to data immovable." FFI must not move pinned data.
    Pin,
    /// `Box<T>` — heap-allocated, unique ownership.
    /// FFI: `Box::into_raw()` / `Box::from_raw()` is the standard FFI pattern.
    Box,
    /// `Vec<T>` — heap-allocated buffer, unique ownership.
    /// FFI: `Vec::as_ptr()` / `Vec::from_raw_parts()` pattern.
    Vec,
    /// Drop trait implementation — destructor.
    /// `_R...4core3ptr13drop_in_place` pattern.
    Drop,
    /// `Once` / `OnceLock` — one-time initialization pattern.
    /// Interior mutability variant: write-once semantics.
    Once,
    /// Unknown or cannot be determined from available information.
    Unknown,
}

impl TypeSemantic {
    /// Returns whether this type semantic implies that writing through `&T`
    /// is safe (i.e., the type contains interior mutability).
    pub fn allows_write_through_shared_ref(&self) -> bool {
        matches!(
            self,
            TypeSemantic::InteriorMutability | TypeSemantic::Once | TypeSemantic::ManuallyDrop
        )
    }

    /// Extracts type semantic from a Rust v0 mangled name.
    ///
    /// The Rust v0 mangling scheme encodes the full type path, which we
    /// can pattern-match against to recover semantic information.
    pub fn from_mangled_name(name: &str) -> Self {
        // Only works for Rust v0 mangled names (_R prefix)
        if !name.starts_with("_R") {
            return TypeSemantic::Unknown;
        }

        // Interior mutability types (order matters: specific before general)
        // UnsafeCell<T> — the core primitive
        if name.contains("4cell10UnsafeCell") {
            return TypeSemantic::InteriorMutability;
        }
        // Cell<T> — safe interior mutability wrapper
        if name.contains("4cell4Cell") {
            return TypeSemantic::InteriorMutability;
        }
        // RefCell<T> — runtime-checked borrowing
        if name.contains("4cell7RefCell") {
            return TypeSemantic::InteriorMutability;
        }
        // OnceCell<T> — one-time write
        if name.contains("4cell9OnceCell") || name.contains("4cell11OnceLock") {
            return TypeSemantic::Once;
        }
        // sync::mutex::Mutex — interior mutability via lock
        if name.contains("4sync5mutex") {
            return TypeSemantic::InteriorMutability;
        }
        // sync::rwlock::RwLock — interior mutability via read/write lock
        if name.contains("4sync6rwlock") {
            return TypeSemantic::InteriorMutability;
        }
        // sync::once — one-time initialization
        if name.contains("4sync4once")
            || name.contains("4sync7OnceLock")
            || name.contains("8once_box")
        {
            return TypeSemantic::Once;
        }
        // Atomic* types — interior mutability via atomic operations
        if name.contains("6atomic") {
            return TypeSemantic::InteriorMutability;
        }

        // Ownership types
        if name.contains("3box3Box") || name.contains("6boxed3Box") {
            return TypeSemantic::Box;
        }
        if name.contains("3vec3Vec") {
            return TypeSemantic::Vec;
        }
        // ManuallyDrop<T>
        if name.contains("12ManuallyDrop") {
            return TypeSemantic::ManuallyDrop;
        }
        // Pin<P>
        if name.contains("3Pin") {
            return TypeSemantic::Pin;
        }
        // drop_in_place — destructor
        if name.contains("13drop_in_place") {
            return TypeSemantic::Drop;
        }

        TypeSemantic::Ordinary
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Syscall Semantic Classification — NOT a whitelist
// ──────────────────────────────────────────────────────────────────────────

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
            | "_Znam" => SyscallSemantic::MemoryManagement,

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
            | "epoll_ctl" | "pipe" | "pipe2" | "dup" | "dup2" | "fcntl" | "ioctl" | "msync"
            | "mmap" | "munmap" | "mprotect" => SyscallSemantic::IOOperation,

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

// ──────────────────────────────────────────────────────────────────────────
// Semantic Kind — R-0~R-6 resolution tags for FP suppression
// ──────────────────────────────────────────────────────────────────────────

/// Semantic kind for a value, derived from IR pattern detectors (R-0~R-6).
///
/// Each variant corresponds to a mined regularity from bun_fp_reduction_plan.
/// These tags are written by Layer 1 detectors and queried by Layer 3 passes
/// before emitting issues. If a value has a suppression tag, the issue is
/// suppressed or downgraded.
///
/// This is NOT a whitelist — each variant has a clear semantic definition
/// derived from IR patterns, not from function names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticKind {
    // ── Existing (preserved for backward compatibility) ──
    /// Unknown or cannot be determined.
    Unknown,

    // ── R-0: LLVM parameter attributes (covers write_to_immutable 1877 FP) ──
    /// Function parameter has LLVM `readonly` attribute → Rust &T / C const ptr.
    /// Writing through a pointer derived from this param is a true violation.
    ReadonlyParam,
    /// Function parameter lacks `readonly` → Rust &mut T / C mutable ptr.
    /// Writing through a pointer derived from this param is legal.
    MutableParam,

    // ── R-2: Interior mutability (covers write_to_immutable residual ~100 FP) ──
    /// Type chain contains UnsafeCell<T> → Cell/RefCell/Mutex/RwLock/Atomic*/OnceLock.
    /// Writing through &T is safe when the type has interior mutability.
    InteriorMutability,

    // ── R-1: Heap provenance (covers borrow_escape 71 FP) ──
    /// Value originates from heap allocation (Box, Arc, Rc, Vec, String, *mut T).
    /// Not a stack escape — passing to FFI is safe.
    HeapProvenance,
    /// Value originates from global/static storage.
    /// Not a stack escape — passing to FFI is safe for read.
    GlobalProvenance,

    // ── R-6: Ownership transfer (covers cross_language_free 4 FP) ──
    /// Value comes from Box/CString/Vec::into_raw — ownership transferred.
    /// Subsequent C free() is by-design, not a cross_language_free bug.
    IntoRawTransfer,

    // ── R-4: POSIX syscall classification ──
    /// POSIX file operation (unlink, close, open, rename, etc.).
    /// Not a memory management operation.
    FileOperation,
    /// POSIX network operation (socket, bind, connect, etc.).
    /// Not a memory management operation.
    NetworkOperation,
    /// POSIX process operation (fork, execve, waitpid, etc.).
    /// Not a memory management operation.
    ProcessOperation,

    // ── R-3: RAII drop (covers use_after_free 3 FP) ──
    /// Compiler-inserted RAII drop/dealloc — not a user bug.
    /// drop_in_place<T> or tail-position __rust_dealloc.
    RaiiDropRelease,

    // ── R-7: Library-level allocator release (covers mimalloc/zlib/openssl/sqlite etc.) ──
    /// Release function from a library-level allocator pair.
    /// mi_free / inflateEnd / EVP_CIPHER_CTX_free / sqlite3_finalize etc.
    /// cross_language_free detection hitting this kind → suppress (legitimate intra-library release).
    LibraryRelease,
}

impl SemanticKind {
    /// Returns true if this kind should suppress write_to_immutable issues.
    pub fn suppresses_write_to_immutable(&self) -> bool {
        matches!(
            self,
            SemanticKind::MutableParam | SemanticKind::InteriorMutability
        )
    }

    /// Returns true if this kind should suppress borrow_escape issues.
    pub fn suppresses_borrow_escape(&self) -> bool {
        matches!(
            self,
            SemanticKind::HeapProvenance | SemanticKind::GlobalProvenance
        )
    }

    /// Returns true if this kind should suppress use_after_free issues.
    pub fn suppresses_use_after_free(&self) -> bool {
        matches!(self, SemanticKind::RaiiDropRelease)
    }

    /// Returns true if this kind should suppress cross_language_free issues.
    pub fn suppresses_cross_language_free(&self) -> bool {
        matches!(
            self,
            SemanticKind::IntoRawTransfer
                | SemanticKind::FileOperation
                | SemanticKind::NetworkOperation
                | SemanticKind::ProcessOperation
                | SemanticKind::LibraryRelease
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Semantic Resolution — a single resolution entry for a value
// ──────────────────────────────────────────────────────────────────────────

/// A resolution entry for a value, recording why it has a particular
/// semantic kind. Multiple resolutions can exist for the same value
/// (e.g., a value can be both HeapProvenance and MutableParam).
#[derive(Debug, Clone)]
pub struct SemanticResolution {
    /// The semantic kind of this resolution.
    pub kind: SemanticKind,
    /// Confidence of this resolution (0.0 - 1.0).
    pub confidence: f32,
    /// Evidence supporting this resolution (e.g., "alloca DI=Box<ClientSession>").
    pub evidence: String,
    /// The R-N pattern that produced this resolution (e.g., "R-0", "R-3").
    pub pattern_id: &'static str,
}

// ──────────────────────────────────────────────────────────────────────────
// Semantic Node — a single semantic annotation for an IR element
// ──────────────────────────────────────────────────────────────────────────

/// A semantic annotation for an IR element (function, call, pointer).
///
/// The semantic tree is built by annotating each FFI boundary with:
/// 1. The provenance of pointers crossing the boundary
/// 2. The type semantics of Rust types involved
/// 3. The syscall semantic of the callee function
/// 4. Semantic resolutions from R-0~R-6 pattern detectors
///
/// These dimensions determine whether the FFI call is safe.
#[derive(Debug, Clone)]
pub struct SemanticNode {
    /// The function or symbol this annotation applies to.
    pub symbol: String,
    /// Provenance of pointers involved (if applicable).
    pub provenance: PointerProvenance,
    /// Type semantic of Rust types involved (if applicable).
    pub type_semantic: TypeSemantic,
    /// Syscall semantic of the callee (for FFI calls).
    pub syscall_semantic: SyscallSemantic,
    /// Semantic resolutions from R-0~R-6 pattern detectors.
    pub resolutions: Vec<SemanticResolution>,
    /// Combined safety score (0.0 = dangerous, 1.0 = safe).
    pub safety_score: f32,
    /// Human-readable reason for the safety score.
    pub reason: String,
}

impl SemanticNode {
    /// Creates a semantic node for an FFI call.
    pub fn for_ffi_call(
        caller: &str,
        callee: &str,
        provenance: PointerProvenance,
        type_semantic: TypeSemantic,
    ) -> Self {
        let syscall_semantic = SyscallSemantic::classify(callee);
        let safety_score = Self::compute_safety_score(provenance, type_semantic, syscall_semantic);
        let reason = Self::compute_reason(provenance, type_semantic, syscall_semantic, callee);

        Self {
            symbol: format!("{} -> {}", caller, callee),
            provenance,
            type_semantic,
            syscall_semantic,
            resolutions: Vec::new(),
            safety_score,
            reason,
        }
    }

    /// Computes the combined safety score from three dimensions.
    fn compute_safety_score(
        provenance: PointerProvenance,
        type_semantic: TypeSemantic,
        syscall_semantic: SyscallSemantic,
    ) -> f32 {
        let prov_score = provenance.ffi_safety_score();
        let syscall_score = syscall_semantic.ffi_safety_score();
        let type_modifier = if type_semantic.allows_write_through_shared_ref() {
            0.1 // Slightly safer: interior mutability is expected
        } else {
            0.0
        };

        // Weighted combination: syscall semantic is the most important factor
        // (if the callee doesn't involve memory ownership, the call is safe
        // regardless of provenance), provenance is secondary.
        let base = syscall_score * 0.6 + prov_score * 0.4;
        (base + type_modifier).min(1.0)
    }

    /// Generates a human-readable reason for the safety score.
    fn compute_reason(
        provenance: PointerProvenance,
        type_semantic: TypeSemantic,
        syscall_semantic: SyscallSemantic,
        callee: &str,
    ) -> String {
        if syscall_semantic.involves_memory_ownership() {
            format!(
                "Memory ownership operation ({:?}) with {:?} provenance — potential CrossFamilyFree",
                syscall_semantic, provenance
            )
        } else if syscall_semantic == SyscallSemantic::InternalDispatch {
            format!(
                "Internal dispatch call ({:?}) — by-design FFI boundary",
                syscall_semantic
            )
        } else if matches!(
            syscall_semantic,
            SyscallSemantic::DataQuery | SyscallSemantic::EnvironmentConfig
        ) {
            format!(
                "Data query/config ({:?}) — no ownership transfer, safe FFI",
                syscall_semantic
            )
        } else if type_semantic.allows_write_through_shared_ref() {
            format!(
                "Interior mutability type ({:?}) — write through &T is safe",
                type_semantic
            )
        } else if provenance == PointerProvenance::Stack {
            format!(
                "Stack pointer passed to {:?} — dangling risk after return",
                syscall_semantic
            )
        } else {
            format!(
                "FFI call to {} ({:?}, {:?} provenance)",
                callee, syscall_semantic, provenance
            )
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Semantic Tree — the complete semantic annotation for a module
// ──────────────────────────────────────────────────────────────────────────

/// The semantic tree for an entire IR module.
///
/// Built by walking the IR and annotating each FFI boundary with
/// provenance, type, syscall semantics, and R-0~R-6 resolutions.
/// Used by downstream passes to make informed decisions about issue
/// severity and FP suppression.
#[derive(Debug, Clone)]
pub struct SemanticTree {
    /// Semantic annotations for each FFI call.
    nodes: Vec<SemanticNode>,
    /// Index from callee symbol to node indices.
    callee_index: HashMap<String, Vec<usize>>,
    /// Resolution index: symbol -> semantic resolutions (R-0~R-6).
    resolution_index: HashMap<String, Vec<SemanticResolution>>,
}

impl SemanticTree {
    /// Creates a new empty semantic tree.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            callee_index: HashMap::new(),
            resolution_index: HashMap::new(),
        }
    }

    /// Adds a semantic node to the tree.
    pub fn add_node(&mut self, node: SemanticNode) {
        let idx = self.nodes.len();
        // Extract callee from symbol format "caller -> callee"
        if let Some(callee) = node.symbol.split(" -> ").nth(1) {
            self.callee_index
                .entry(callee.to_string())
                .or_default()
                .push(idx);
        }
        self.nodes.push(node);
    }

    /// Adds a semantic resolution for a symbol.
    ///
    /// Multiple resolutions can exist for the same symbol (e.g., a value
    /// can be both HeapProvenance and MutableParam).
    pub fn add_resolution(&mut self, symbol: &str, resolution: SemanticResolution) {
        self.resolution_index
            .entry(symbol.to_string())
            .or_default()
            .push(resolution);
    }

    /// Queries whether a symbol has a specific semantic kind.
    ///
    /// Returns the highest-confidence resolution matching the kind,
    /// or None if no such resolution exists.
    pub fn has_kind(&self, symbol: &str, kind: SemanticKind) -> Option<&SemanticResolution> {
        self.resolution_index.get(symbol).and_then(|resolutions| {
            resolutions
                .iter()
                .filter(|r| r.kind == kind)
                .max_by(|a, b| {
                    a.confidence
                        .partial_cmp(&b.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        })
    }

    /// Returns all resolutions for a symbol.
    pub fn all_resolutions(&self, symbol: &str) -> &[SemanticResolution] {
        self.resolution_index
            .get(symbol)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns true if any resolution for the symbol would suppress
    /// write_to_immutable issues.
    pub fn suppresses_write_to_immutable(&self, symbol: &str) -> bool {
        self.resolution_index
            .get(symbol)
            .map(|rs| rs.iter().any(|r| r.kind.suppresses_write_to_immutable()))
            .unwrap_or(false)
    }

    /// Returns true if any resolution for the symbol would suppress
    /// borrow_escape issues.
    pub fn suppresses_borrow_escape(&self, symbol: &str) -> bool {
        self.resolution_index
            .get(symbol)
            .map(|rs| rs.iter().any(|r| r.kind.suppresses_borrow_escape()))
            .unwrap_or(false)
    }

    /// Returns true if any resolution for the symbol would suppress
    /// use_after_free issues.
    pub fn suppresses_use_after_free(&self, symbol: &str) -> bool {
        self.resolution_index
            .get(symbol)
            .map(|rs| rs.iter().any(|r| r.kind.suppresses_use_after_free()))
            .unwrap_or(false)
    }

    /// Returns true if any resolution for the symbol would suppress
    /// cross_language_free issues.
    pub fn suppresses_cross_language_free(&self, symbol: &str) -> bool {
        self.resolution_index
            .get(symbol)
            .map(|rs| rs.iter().any(|r| r.kind.suppresses_cross_language_free()))
            .unwrap_or(false)
    }

    /// Returns all semantic nodes.
    pub fn nodes(&self) -> &[SemanticNode] {
        &self.nodes
    }

    /// Returns semantic nodes for a specific callee.
    pub fn nodes_for_callee(&self, callee: &str) -> Vec<&SemanticNode> {
        self.callee_index
            .get(callee)
            .map(|indices| indices.iter().map(|&i| &self.nodes[i]).collect())
            .unwrap_or_default()
    }

    /// Returns the number of nodes that indicate a genuine safety concern
    /// (safety_score < 0.5).
    pub fn genuine_concern_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.safety_score < 0.5).count()
    }

    /// Returns the number of nodes that are safe FFI patterns
    /// (safety_score >= 0.8).
    pub fn safe_pattern_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.safety_score >= 0.8).count()
    }

    /// Returns nodes that involve memory ownership operations
    /// (potential CrossFamilyFree candidates).
    pub fn memory_ownership_nodes(&self) -> Vec<&SemanticNode> {
        self.nodes
            .iter()
            .filter(|n| n.syscall_semantic.involves_memory_ownership())
            .collect()
    }
}

impl Default for SemanticTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a semantic tree from an IR module's FFI boundaries.
///
/// For each FFI call in the module, this function:
/// 1. Classifies the callee's syscall semantic
/// 2. Infers the type semantic from mangled names
/// 3. Determines pointer provenance from IR patterns
/// 4. Computes a combined safety score
pub fn build_semantic_tree(
    ffi_calls: &[(String, String, bool)], // (caller, callee, is_external)
) -> SemanticTree {
    let mut tree = SemanticTree::new();

    for (caller, callee, _is_external) in ffi_calls {
        // Extract type semantic from caller name (if Rust)
        let type_semantic = TypeSemantic::from_mangled_name(caller);

        // Determine pointer provenance
        // For now, use heuristic: if callee is a known syscall/function,
        // the provenance depends on the call pattern
        let provenance = infer_provenance_from_context(caller, callee);

        let node = SemanticNode::for_ffi_call(caller, callee, provenance, type_semantic);
        tree.add_node(node);
    }

    tree
}

/// Infers pointer provenance from the call context.
///
/// Heuristics based on Rustonomicon FFI patterns:
/// - Calling libc::getenv/strlen → passes pointers to global/heap data → safe
/// - Calling Box::into_raw → heap provenance
/// - Calling BunString__fromBytes → passes slice ptr → heap provenance
/// - Calling malloc/__rust_alloc → returns heap provenance
pub fn infer_provenance_from_context(caller: &str, callee: &str) -> PointerProvenance {
    let syscall = SyscallSemantic::classify(callee);

    match syscall {
        // These return heap pointers
        SyscallSemantic::MemoryManagement => PointerProvenance::Heap,
        // These read from global/process data
        SyscallSemantic::DataQuery | SyscallSemantic::EnvironmentConfig => {
            PointerProvenance::Global
        }
        // These operate on caller-owned buffers (heap)
        SyscallSemantic::StringManipulation | SyscallSemantic::ComputeAccelerated => {
            PointerProvenance::Heap
        }
        // Internal dispatch — by-design FFI, usually heap provenance
        SyscallSemantic::InternalDispatch => PointerProvenance::Heap,
        // File/network ops — FD is an integer, not a pointer
        SyscallSemantic::FileOperation
        | SyscallSemantic::IOOperation
        | SyscallSemantic::NetworkOperation => PointerProvenance::Global,
        // Thread sync — operates on sync primitives (heap or global)
        SyscallSemantic::ThreadSync => PointerProvenance::Heap,
        // Process ops — no pointer passing typically
        SyscallSemantic::ProcessOperation | SyscallSemantic::TimeOperation => {
            PointerProvenance::Unknown
        }
        // Unknown — could be anything
        SyscallSemantic::Unknown => {
            // If the caller is Rust and callee is unknown external, check
            // if the caller involves heap types
            if caller.starts_with("_R") {
                let type_sem = TypeSemantic::from_mangled_name(caller);
                match type_sem {
                    TypeSemantic::Box | TypeSemantic::Vec => PointerProvenance::Heap,
                    TypeSemantic::Drop => PointerProvenance::Heap,
                    _ => PointerProvenance::Unknown,
                }
            } else {
                PointerProvenance::Unknown
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_classify_getenv() {
        assert_eq!(
            SyscallSemantic::classify("getenv"),
            SyscallSemantic::EnvironmentConfig
        );
    }

    #[test]
    fn test_syscall_classify_strlen() {
        assert_eq!(
            SyscallSemantic::classify("strlen"),
            SyscallSemantic::DataQuery
        );
    }

    #[test]
    fn test_syscall_classify_malloc() {
        assert_eq!(
            SyscallSemantic::classify("malloc"),
            SyscallSemantic::MemoryManagement
        );
    }

    #[test]
    fn test_syscall_classify_free() {
        assert_eq!(
            SyscallSemantic::classify("free"),
            SyscallSemantic::MemoryManagement
        );
    }

    #[test]
    fn test_syscall_classify_highway() {
        assert_eq!(
            SyscallSemantic::classify("highway_index_of_char"),
            SyscallSemantic::ComputeAccelerated
        );
    }

    #[test]
    fn test_syscall_classify_bun_dispatch() {
        assert_eq!(
            SyscallSemantic::classify("__bun_dispatch__OutputSink__Sys__quiet_writer_write_all"),
            SyscallSemantic::InternalDispatch
        );
    }

    #[test]
    fn test_syscall_classify_bun_string() {
        assert_eq!(
            SyscallSemantic::classify("BunString__fromBytes"),
            SyscallSemantic::InternalDispatch
        );
    }

    #[test]
    fn test_syscall_classify_wtf_destroy() {
        assert_eq!(
            SyscallSemantic::classify("Bun__WTFStringImpl__destroy"),
            SyscallSemantic::InternalDispatch
        );
    }

    #[test]
    fn test_type_semantic_interior_mutability() {
        // Real mangled name from bun_core: std::sync::mutex::Mutex
        let name = "_RNvMNtNtNtNtNtCsg1bLsEOY8ZL_3std3sys3pal4unix4sync5mutexNtB2_5Mutex4lock";
        assert_eq!(
            TypeSemantic::from_mangled_name(name),
            TypeSemantic::InteriorMutability
        );
    }

    #[test]
    fn test_type_semantic_once() {
        let name = "_RINvMNtNtNtCsg1bLsEOY8ZL_3std3sys4sync8once_boxINtB3_7OnceBox";
        assert_eq!(TypeSemantic::from_mangled_name(name), TypeSemantic::Once);
    }

    #[test]
    fn test_type_semantic_drop() {
        let name = "_RINvNtCsgXhsEb1m4tm_4core3ptr13drop_in_place";
        assert_eq!(TypeSemantic::from_mangled_name(name), TypeSemantic::Drop);
    }

    #[test]
    fn test_type_semantic_non_rust() {
        assert_eq!(
            TypeSemantic::from_mangled_name("Bun__atexit"),
            TypeSemantic::Unknown
        );
    }

    #[test]
    fn test_safety_score_data_query() {
        let node = SemanticNode::for_ffi_call(
            "some_rust_func",
            "strlen",
            PointerProvenance::Heap,
            TypeSemantic::Ordinary,
        );
        // Data query should have high safety score
        assert!(
            node.safety_score > 0.8,
            "strlen call should be safe: {}",
            node.safety_score
        );
    }

    #[test]
    fn test_safety_score_memory_management() {
        let node = SemanticNode::for_ffi_call(
            "some_rust_func",
            "free",
            PointerProvenance::Heap,
            TypeSemantic::Ordinary,
        );
        // free() should have lower safety score than safe patterns
        assert!(
            node.safety_score < 0.6,
            "free call should be concerning: {}",
            node.safety_score
        );
    }

    #[test]
    fn test_safety_score_internal_dispatch() {
        let node = SemanticNode::for_ffi_call(
            "some_rust_func",
            "BunString__fromBytes",
            PointerProvenance::Heap,
            TypeSemantic::Ordinary,
        );
        // Internal dispatch should have moderate-high safety score
        assert!(
            node.safety_score > 0.6,
            "internal dispatch should be moderate: {}",
            node.safety_score
        );
    }

    #[test]
    fn test_semantic_tree_build() {
        let ffi_calls = vec![
            ("rust_func".to_string(), "getenv".to_string(), true),
            ("rust_func".to_string(), "strlen".to_string(), true),
            ("rust_func".to_string(), "free".to_string(), true),
            (
                "rust_func".to_string(),
                "BunString__fromBytes".to_string(),
                true,
            ),
        ];

        let tree = build_semantic_tree(&ffi_calls);
        assert_eq!(tree.nodes().len(), 4);
        assert_eq!(tree.safe_pattern_count(), 2); // getenv + strlen
        assert_eq!(tree.genuine_concern_count(), 0); // free score=0.54 >= 0.5
    }

    #[test]
    fn test_memory_ownership_filtering() {
        let ffi_calls = vec![
            ("rust_func".to_string(), "malloc".to_string(), true),
            ("rust_func".to_string(), "strlen".to_string(), true),
            ("rust_func".to_string(), "free".to_string(), true),
            ("rust_func".to_string(), "getenv".to_string(), true),
        ];

        let tree = build_semantic_tree(&ffi_calls);
        let mem_nodes = tree.memory_ownership_nodes();
        assert_eq!(mem_nodes.len(), 2); // malloc + free
        assert!(mem_nodes
            .iter()
            .all(|n| n.syscall_semantic == SyscallSemantic::MemoryManagement));
    }
}
