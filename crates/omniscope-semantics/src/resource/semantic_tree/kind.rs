//! Semantic Kind — R-0~R-6 resolution tags for FP suppression
//!
//! This module provides the `SemanticKind` enum for classifying
//! values based on their semantic properties that affect issue suppression.

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

    // ── R-8: Function parameter is not stack escape (covers borrow_escape 39 FP) ──
    /// Function parameter is not a stack escape — it's caller-provided pointer.
    /// Parameters are not stack escapes in the current function; caller owns the pointer.
    FromParameter,

    // ── Python: Reference counting and GIL management ──
    /// Python reference count increment (Py_INCREF, Py_XINCREF).
    /// Indicates a borrowed reference that has been promoted to a strong reference.
    PythonRefcountInc,
    /// Python reference count decrement (Py_DECREF, Py_XDECREF).
    /// Indicates a reference that is being released, potentially triggering deallocation.
    PythonRefcountDec,
    /// Python borrowed reference (PyList_GetItem, PyTuple_GetItem, PyDict_GetItem).
    /// The reference is borrowed from the container and should not be decremented.
    PythonBorrowedRef,
    /// Python owned reference (PyBytes_FromString, PyLong_FromLong, PyObject_Call).
    /// The caller owns the reference and is responsible for decrementing it.
    PythonOwnedRef,
    /// Python GIL-protected region (PyGILState_Ensure/Release).
    /// Code within this region is thread-safe for Python operations.
    PythonGilProtected,

    // ── Go: Defer cleanup and CGO wrapper patterns ──
    /// Go defer cleanup pattern (defer C.free(ptr), defer C.free(unsafe.Pointer)).
    /// Indicates that a resource will be cleaned up when the function returns.
    GoDeferCleanup,
    /// Go finalizer pattern (runtime.SetFinalizer).
    /// Indicates that a resource will be cleaned up by the garbage collector.
    GoFinalizer,
    /// Go CGO wrapper function (_Cgo_* prefix).
    /// These are auto-generated wrappers for C function calls from Go.
    GoCgoWrapper,
    /// Go runtime allocation (runtime.mallocgc, runtime.newobject).
    /// Memory allocated by Go's garbage collector runtime.
    GoRuntimeAlloc,

    // ── C++: Smart pointers and RAII patterns ──
    /// C++ std::unique_ptr — exclusive ownership, no sharing.
    /// Memory is automatically freed when the unique_ptr goes out of scope.
    CppUniquePtr,
    /// C++ std::shared_ptr — shared ownership with reference counting.
    /// Memory is freed when the last shared_ptr is destroyed.
    CppSharedPtr,
    /// C++ destructor pattern (~ClassName()).
    /// Compiler-inserted cleanup when object goes out of scope.
    CppDestructor,
    /// C++ exception path (try/catch blocks).
    /// Resources may be cleaned up differently on exception paths.
    CppExceptionPath,

    // ── C#: SafeHandle and P/Invoke patterns ──
    /// C# SafeHandle pattern (SafeHandle.ReleaseHandle).
    /// Provides deterministic cleanup of unmanaged resources.
    CsharpSafeHandle,
    /// C# finalizer pattern (~Destructor()).
    /// Non-deterministic cleanup by the garbage collector.
    CsharpFinalizer,
    /// C# P/Invoke marshalling (DllImport, Marshal.AllocHGlobal).
    /// Manages memory conversion between managed and unmanaged code.
    CsharpPinvokeMarshal,

    // ── Java: JNI reference types ──
    /// Java JNI local reference (NewLocalRef).
    /// Automatically freed when the JNI method returns.
    JavaLocalRef,
    /// Java JNI global reference (NewGlobalRef).
    /// Must be explicitly deleted with DeleteGlobalRef.
    JavaGlobalRef,
    /// Java JNI weak global reference (NewWeakGlobalRef).
    /// May be garbage collected; must check with IsSameObject before use.
    JavaWeakRef,

    // ── Runtime internal functions ──
    /// Runtime-internal function (POSIX mmap/munmap, Rust __rust_*,
    /// C++ __cxa_*, compiler builtins, etc.).
    RuntimeInternal,

    // ── Cross-language boundary classification ──
    /// Function is in a declared cross-language boundary.
    /// Used when --cross parameter specifies FFI boundaries.
    /// Functions at these boundaries should be treated as cross-language calls.
    DeclaredCrossBoundary,

    /// Function is internal to one language (not a boundary).
    /// Functions without cross-language context are classified as internal.
    /// Issues from internal functions may have different severity.
    NonBoundaryInternal,

    // ── New patterns for multi-key semantic queries ──
    /// Resource is managed by a runtime (e.g., GC, reference counting system).
    /// Not a local leak — ownership transferred to runtime.
    RuntimeManagedResource,
    /// Resource is not memory (e.g., file descriptor, socket, handle).
    /// Memory leak detection should not apply.
    NonMemoryResource,
    /// Resource is stored to an owner structure (e.g., struct field, container).
    /// Not a local leak — ownership transferred to container.
    StoredToOwner,
    /// Resource is stored to runtime-managed structure (e.g., GC heap, global).
    /// Not a local leak — ownership transferred to runtime.
    StoredToRuntime,
    /// Resource escapes to caller (returned from function).
    /// Not a local leak — caller is responsible.
    EscapedToCaller,
    /// Resource escapes via out-parameter.
    /// Not a local leak — caller is responsible.
    EscapedToOutParam,
    /// Out-parameter is initialized with fallible operation.
    /// May be NULL on error path — not necessarily a bug.
    FallibleOutParamInit,
    /// Value is NULL on error path (defensive NULLing).
    /// Expected pattern for fallible operations.
    NullOnErrorPath,
    /// Resource is released on all exit paths.
    /// No leak — cleanup is complete.
    ReleaseOnAllExitPaths,
    /// Resource is alias of already-released resource.
    /// Double-free detection should consider this.
    AliasOfReleased,

    // ── Phase 5: Additional semantic kinds for suppression confidence ──
    /// Allocation aborts on OOM (e.g., malloc that calls abort/exit on
    /// failure, or Rust's global allocator which panics). The OOM path
    /// is not a leak — the process terminates.
    AbortOnOom,
    /// Reference count transfer (e.g., Py_INCREF + Py_DECREF pair, or
    /// Rust Arc::into_raw + Arc::from_raw). The resource is managed by
    /// a reference counting system and the transfer is by-design.
    RefcountTransfer,
    /// Resource has static/process lifetime (e.g., global variable init,
    /// __cxx_global_var_init). Not a local leak — the resource outlives
    /// the function and is never expected to be freed.
    StaticLifetimeSink,
    /// Destructor/RAII release pattern (e.g., C++ ~ClassName(), Rust Drop).
    /// The release is compiler-inserted cleanup, not a user bug.
    DestructorRelease,

    // ── Phase 6: ABI layout detection ──
    /// Struct has padding between fields that causes incorrect offsets
    /// when accessed across FFI boundaries (e.g., C struct {u32, u8, ptr}
    /// has 3 bytes padding that packed-layout callers miss).
    AbiLayoutPadding,
}

/// Semantic key for querying the semantic tree.
///
/// Different key types allow querying by different aspects of the program:
/// - Symbol: function/variable name
/// - Value: SSA register name
/// - Resource: allocation site ID
/// - Path: (function_name, path_id) for control-flow-sensitive queries
/// - Owner: owning structure/variable name
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SemanticKey {
    /// Query by symbol name (function, variable, type).
    Symbol(String),
    /// Query by SSA value register name.
    Value(String),
    /// Query by resource allocation site ID.
    Resource(u64),
    /// Query by (function_name, path_id) for path-sensitive analysis.
    Path(String, u64),
    /// Query by owner name (container, structure).
    Owner(String),
    /// Query by call site: (caller, callee, argument_index).
    /// Identifies a specific call within a function for fine-grained
    /// semantic lookup (e.g., "which malloc fed this free?").
    CallSite {
        caller: String,
        callee: String,
        index: u32,
    },
}

impl SemanticKey {
    /// Creates a Symbol key.
    pub fn symbol(name: &str) -> Self {
        Self::Symbol(name.to_string())
    }

    /// Creates a Value key.
    pub fn value(reg: &str) -> Self {
        Self::Value(reg.to_string())
    }

    /// Creates a Resource key.
    pub fn resource(id: u64) -> Self {
        Self::Resource(id)
    }

    /// Creates a Path key.
    pub fn path(func: &str, id: u64) -> Self {
        Self::Path(func.to_string(), id)
    }

    /// Creates an Owner key.
    pub fn owner(name: &str) -> Self {
        Self::Owner(name.to_string())
    }

    /// Creates a CallSite key.
    pub fn call_site(caller: &str, callee: &str, index: u32) -> Self {
        Self::CallSite {
            caller: caller.to_string(),
            callee: callee.to_string(),
            index,
        }
    }

    /// Converts a string key to a SemanticKey (for backward compatibility).
    /// This allows existing code that uses String keys to work with the new system.
    pub fn from_string(key: &str) -> Self {
        // Try to parse as different key types
        if key.starts_with("resource:") {
            if let Some(id_str) = key.strip_prefix("resource:") {
                if let Ok(id) = id_str.parse::<u64>() {
                    return Self::Resource(id);
                }
            }
        } else if key.starts_with("owner:") {
            if let Some(name) = key.strip_prefix("owner:") {
                return Self::Owner(name.to_string());
            }
        } else if key.starts_with("path:") {
            if let Some(rest) = key.strip_prefix("path:") {
                let parts: Vec<&str> = rest.splitn(2, ':').collect();
                if parts.len() == 2 {
                    if let Ok(id) = parts[1].parse::<u64>() {
                        return Self::Path(parts[0].to_string(), id);
                    }
                }
            }
        } else if key.starts_with("value:") {
            if let Some(reg) = key.strip_prefix("value:") {
                return Self::Value(reg.to_string());
            }
        } else if key.starts_with("callsite:") {
            // Format: callsite:<percent-encoded-caller>:<percent-encoded-callee>:<index>
            // Percent-encodes ':' and '%' in caller/callee to avoid ambiguity
            // with the field separator ':'. This is safe for logs, JSON, and
            // CLI output (unlike NUL-byte encoding).
            if let Some(rest) = key.strip_prefix("callsite:") {
                let parts: Vec<&str> = rest.splitn(3, ':').collect();
                if parts.len() == 3 {
                    let caller = percent_decode(parts[0]);
                    let callee = percent_decode(parts[1]);
                    if let Ok(index) = parts[2].parse::<u32>() {
                        return Self::CallSite {
                            caller,
                            callee,
                            index,
                        };
                    }
                }
            }
        }
        // Default to Symbol for backward compatibility
        Self::Symbol(key.to_string())
    }

    /// Converts the key to a string representation.
    pub fn to_key_string(&self) -> String {
        match self {
            Self::Symbol(name) => name.clone(),
            Self::Value(reg) => format!("value:{reg}"),
            Self::Resource(id) => format!("resource:{id}"),
            Self::Path(func, id) => format!("path:{func}:{id}"),
            Self::Owner(name) => format!("owner:{name}"),
            Self::CallSite {
                caller,
                callee,
                index,
            } => {
                // Percent-encode ':' and '%' in caller/callee so the ':'
                // separator is unambiguous. Safe for logs, JSON, CLI.
                format!(
                    "callsite:{}:{}:{index}",
                    percent_encode(caller),
                    percent_encode(callee)
                )
            }
        }
    }

    /// Returns true if this key is a symbol key.
    pub fn is_symbol(&self) -> bool {
        matches!(self, Self::Symbol(_))
    }

    /// Returns the symbol name if this is a Symbol key.
    pub fn as_symbol(&self) -> Option<&str> {
        match self {
            Self::Symbol(name) => Some(name),
            _ => None,
        }
    }

    /// Returns the resource ID if this is a Resource key.
    pub fn as_resource(&self) -> Option<u64> {
        match self {
            Self::Resource(id) => Some(*id),
            _ => None,
        }
    }

    /// Returns the owner name if this is an Owner key.
    pub fn as_owner(&self) -> Option<&str> {
        match self {
            Self::Owner(name) => Some(name),
            _ => None,
        }
    }
}

impl std::fmt::Display for SemanticKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_key_string())
    }
}

/// Percent-encodes `:` and `%` in a string for use as a CallSite key field.
///
/// Only these two characters need encoding because `:` is the field
/// separator and `%` is the escape prefix. All other characters
/// (including arbitrary LLVM symbol characters) pass through unchanged.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            ':' => out.push_str("%3A"),
            '%' => out.push_str("%25"),
            _ => out.push(ch),
        }
    }
    out
}

/// Decodes a percent-encoded string produced by [`percent_encode`].
///
/// Returns the original string. Malformed escape sequences (e.g., `%ZZ`)
/// are passed through unchanged for robustness.
fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hi = chars.next();
            let lo = chars.next();
            match (hi, lo) {
                (Some(h), Some(l)) => {
                    let byte = u8::from_str_radix(&format!("{h}{l}"), 16);
                    match byte {
                        Ok(b) => out.push(b as char),
                        Err(_) => {
                            // Malformed escape — pass through literally
                            out.push('%');
                            out.push(h);
                            out.push(l);
                        }
                    }
                }
                _ => {
                    // Incomplete escape at end of string
                    out.push('%');
                    if let Some(h) = hi {
                        out.push(h);
                    }
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

impl SemanticKind {
    /// Returns true if this kind should suppress write_to_immutable issues.
    pub fn suppresses_write_to_immutable(&self) -> bool {
        matches!(
            self,
            SemanticKind::MutableParam
                | SemanticKind::InteriorMutability
                | SemanticKind::PythonGilProtected
                | SemanticKind::CppUniquePtr
                | SemanticKind::CppSharedPtr
                | SemanticKind::CsharpSafeHandle
                | SemanticKind::RuntimeInternal
                | SemanticKind::StoredToOwner
                | SemanticKind::StoredToRuntime
                | SemanticKind::RuntimeManagedResource
        )
    }

    /// Returns true if this kind should suppress borrow_escape issues.
    pub fn suppresses_borrow_escape(&self) -> bool {
        matches!(
            self,
            SemanticKind::HeapProvenance
                | SemanticKind::GlobalProvenance
                | SemanticKind::FromParameter
                | SemanticKind::PythonBorrowedRef
                | SemanticKind::PythonGilProtected
                | SemanticKind::GoDeferCleanup
                | SemanticKind::GoFinalizer
                | SemanticKind::GoRuntimeAlloc
                | SemanticKind::CppUniquePtr
                | SemanticKind::CppSharedPtr
                | SemanticKind::CppDestructor
                | SemanticKind::CsharpSafeHandle
                | SemanticKind::JavaLocalRef
                | SemanticKind::EscapedToCaller
                | SemanticKind::EscapedToOutParam
                | SemanticKind::StoredToOwner
                | SemanticKind::StoredToRuntime
                | SemanticKind::RuntimeManagedResource
        )
    }

    /// Returns true if this kind should suppress use_after_free issues.
    pub fn suppresses_use_after_free(&self) -> bool {
        matches!(
            self,
            SemanticKind::RaiiDropRelease
                | SemanticKind::PythonRefcountInc
                | SemanticKind::PythonOwnedRef
                | SemanticKind::GoDeferCleanup
                | SemanticKind::GoFinalizer
                | SemanticKind::CppUniquePtr
                | SemanticKind::CppSharedPtr
                | SemanticKind::CppDestructor
                | SemanticKind::CsharpSafeHandle
                | SemanticKind::CsharpFinalizer
                | SemanticKind::JavaGlobalRef
                | SemanticKind::ReleaseOnAllExitPaths
                | SemanticKind::AliasOfReleased
                | SemanticKind::RuntimeManagedResource
        )
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
                | SemanticKind::PythonRefcountDec
                | SemanticKind::PythonOwnedRef
                | SemanticKind::GoDeferCleanup
                | SemanticKind::GoFinalizer
                | SemanticKind::GoRuntimeAlloc
                | SemanticKind::CppUniquePtr
                | SemanticKind::CppSharedPtr
                | SemanticKind::CppDestructor
                | SemanticKind::CsharpSafeHandle
                | SemanticKind::CsharpFinalizer
                | SemanticKind::CsharpPinvokeMarshal
                | SemanticKind::JavaGlobalRef
                | SemanticKind::JavaWeakRef
                | SemanticKind::RuntimeManagedResource
                | SemanticKind::NonMemoryResource
                | SemanticKind::StoredToOwner
                | SemanticKind::StoredToRuntime
                | SemanticKind::ReleaseOnAllExitPaths
                | SemanticKind::AliasOfReleased
        )
    }

    /// Detects the semantic kind from a function name.
    ///
    /// This method uses pattern matching to identify common patterns across
    /// different programming languages. Each pattern is based on real API
    /// conventions and naming patterns.
    ///
    /// # Arguments
    /// * `func_name` - The function name to analyze
    ///
    /// # Returns
    /// The detected semantic kind, or `SemanticKind::Unknown` if no pattern matches.
    pub fn from_function_name(func_name: &str) -> Self {
        // ── Python reference counting patterns ──
        if func_name.contains("Py_INCREF") || func_name.contains("Py_XINCREF") {
            return SemanticKind::PythonRefcountInc;
        }
        if func_name.contains("Py_DECREF") || func_name.contains("Py_XDECREF") {
            return SemanticKind::PythonRefcountDec;
        }
        if func_name.contains("PyList_GetItem")
            || func_name.contains("PyTuple_GetItem")
            || func_name.contains("PyDict_GetItem")
            || func_name.contains("PyList_GET_ITEM")
            || func_name.contains("PyTuple_GET_ITEM")
        {
            return SemanticKind::PythonBorrowedRef;
        }
        if func_name.contains("PyBytes_FromString")
            || func_name.contains("PyLong_FromLong")
            || func_name.contains("PyFloat_FromDouble")
            || func_name.contains("PyObject_Call")
            || func_name.contains("PyUnicode_FromString")
            || func_name.contains("PyBool_FromLong")
        {
            return SemanticKind::PythonOwnedRef;
        }
        if func_name.contains("PyGILState_Ensure") || func_name.contains("PyGILState_Release") {
            return SemanticKind::PythonGilProtected;
        }

        // ── Go defer and CGO patterns ──
        if func_name.contains("defer") && func_name.contains("free") {
            return SemanticKind::GoDeferCleanup;
        }
        if func_name.contains("runtime.SetFinalizer") || func_name.contains("SetFinalizer") {
            return SemanticKind::GoFinalizer;
        }
        if func_name.contains("runtime.mallocgc")
            || func_name.contains("runtime.newobject")
            || func_name.contains("runtime.newarray")
        {
            return SemanticKind::GoRuntimeAlloc;
        }

        // ── C++ smart pointer patterns ──
        if func_name.contains("unique_ptr")
            || func_name.contains("make_unique")
            || func_name.contains("std::unique_ptr")
        {
            return SemanticKind::CppUniquePtr;
        }
        if func_name.contains("shared_ptr")
            || func_name.contains("make_shared")
            || func_name.contains("std::shared_ptr")
        {
            return SemanticKind::CppSharedPtr;
        }
        // C++ destructor pattern: starts with ~ or contains ~ClassName
        if func_name.starts_with('~') || func_name.contains("::~") {
            return SemanticKind::CppDestructor;
        }
        // C++ exception handling
        if func_name.contains("__cxa_throw")
            || func_name.contains("__cxa_begin_catch")
            || func_name.contains("__cxa_end_catch")
            || func_name.contains("__cxa_allocate_exception")
        {
            return SemanticKind::CppExceptionPath;
        }

        // ── Go CGO wrapper patterns (after C++ patterns to avoid conflicts) ──
        if func_name.starts_with("_Cgo_") || func_name.contains("_cgo_") {
            return SemanticKind::GoCgoWrapper;
        }

        // ── C# SafeHandle and P/Invoke patterns ──
        if func_name.contains("SafeHandle")
            || func_name.contains("ReleaseHandle")
            || func_name.contains("CriticalHandle")
        {
            return SemanticKind::CsharpSafeHandle;
        }
        // C# finalizer: ~ClassName pattern
        if func_name.contains("Finalize") || func_name.contains("~Destructor") {
            return SemanticKind::CsharpFinalizer;
        }
        if func_name.contains("DllImport")
            || func_name.contains("Marshal.AllocHGlobal")
            || func_name.contains("Marshal.FreeHGlobal")
            || func_name.contains("P/Invoke")
        {
            return SemanticKind::CsharpPinvokeMarshal;
        }

        // ── Java JNI reference patterns ──
        if func_name.contains("NewLocalRef") || func_name.contains("DeleteLocalRef") {
            return SemanticKind::JavaLocalRef;
        }
        if func_name.contains("NewGlobalRef") || func_name.contains("DeleteGlobalRef") {
            return SemanticKind::JavaGlobalRef;
        }
        if func_name.contains("NewWeakGlobalRef") || func_name.contains("DeleteWeakGlobalRef") {
            return SemanticKind::JavaWeakRef;
        }

        // ── Refcount transfer patterns ──
        if func_name.contains("Arc::into_raw") || func_name.contains("Arc::from_raw") {
            return SemanticKind::RefcountTransfer;
        }

        // ── Default: no pattern matched ──
        SemanticKind::Unknown
    }

    /// Returns the safety score for this semantic kind.
    ///
    /// The safety score indicates how safe it is to assume that a resource
    /// with this semantic kind is being managed correctly:
    /// - 1.0: Completely safe (e.g., RAII cleanup)
    /// - 0.8: Generally safe (e.g., borrowed references)
    /// - 0.6: Moderately safe (e.g., smart pointers)
    /// - 0.4: Potentially unsafe (e.g., finalizers)
    /// - 0.2: High risk (e.g., manual reference counting)
    pub fn safety_score(&self) -> f32 {
        match self {
            // ── Safe patterns (0.8-1.0) ──
            SemanticKind::RaiiDropRelease => 1.0, // Compiler-managed
            SemanticKind::CppUniquePtr => 0.9,    // Exclusive ownership
            SemanticKind::CppSharedPtr => 0.85,   // Shared ownership with refcount
            SemanticKind::CppDestructor => 0.9,   // Deterministic cleanup
            SemanticKind::CsharpSafeHandle => 0.9, // Safe resource management
            SemanticKind::PythonBorrowedRef => 0.8, // Borrowed, no ownership
            SemanticKind::PythonGilProtected => 0.8, // Thread-safe region

            // ── Moderately safe patterns (0.6-0.7) ──
            SemanticKind::HeapProvenance => 0.7,
            SemanticKind::GlobalProvenance => 0.7,
            SemanticKind::FromParameter => 0.6,
            SemanticKind::GoDeferCleanup => 0.7, // Deterministic cleanup
            SemanticKind::GoFinalizer => 0.6,    // GC-managed
            SemanticKind::GoRuntimeAlloc => 0.7, // GC-managed memory

            // ── Potentially unsafe patterns (0.4-0.5) ──
            SemanticKind::MutableParam => 0.5,
            SemanticKind::ReadonlyParam => 0.6,
            SemanticKind::InteriorMutability => 0.5,
            SemanticKind::IntoRawTransfer => 0.4, // Ownership transferred
            SemanticKind::PythonOwnedRef => 0.5,  // Must be decremented
            SemanticKind::JavaLocalRef => 0.5,    // Auto-freed on return
            SemanticKind::JavaGlobalRef => 0.4,   // Must be explicitly deleted
            SemanticKind::JavaWeakRef => 0.3,     // May be GC'd
            SemanticKind::CsharpFinalizer => 0.4, // Non-deterministic
            SemanticKind::CsharpPinvokeMarshal => 0.5, // Manual marshalling

            // ── High risk patterns (0.2-0.3) ──
            SemanticKind::PythonRefcountInc => 0.3, // Manual refcount
            SemanticKind::PythonRefcountDec => 0.3, // Manual refcount
            SemanticKind::CppExceptionPath => 0.4,  // Exception handling
            SemanticKind::GoCgoWrapper => 0.5,      // CGO boundary

            // ── POSIX patterns (0.8-0.9) ──
            SemanticKind::FileOperation => 0.9,
            SemanticKind::NetworkOperation => 0.9,
            SemanticKind::ProcessOperation => 0.8,
            SemanticKind::LibraryRelease => 0.8,

            // ── Runtime internal patterns (0.9) ──
            SemanticKind::RuntimeInternal => 0.9, // Compiler/runtime managed

            // ── Cross-language boundary classification ──
            SemanticKind::DeclaredCrossBoundary => 0.6, // At FFI boundary, moderate risk
            SemanticKind::NonBoundaryInternal => 0.8,   // Internal function, generally safe

            // ── New patterns for multi-key semantic queries ──
            SemanticKind::RuntimeManagedResource => 0.8, // GC-managed, safe
            SemanticKind::NonMemoryResource => 0.9,      // Not memory, safe
            SemanticKind::StoredToOwner => 0.7,          // Ownership transferred
            SemanticKind::StoredToRuntime => 0.7,        // Ownership transferred
            SemanticKind::EscapedToCaller => 0.6,        // Caller responsible
            SemanticKind::EscapedToOutParam => 0.6,      // Caller responsible
            SemanticKind::FallibleOutParamInit => 0.5,   // May be NULL
            SemanticKind::NullOnErrorPath => 0.8,        // Defensive NULLing
            SemanticKind::ReleaseOnAllExitPaths => 0.9,  // Cleanup complete
            SemanticKind::AliasOfReleased => 0.3,        // Double-free risk

            // ── Phase 5: Additional semantic kinds ──
            SemanticKind::AbortOnOom => 0.9, // Process terminates, no leak
            SemanticKind::RefcountTransfer => 0.7, // Refcount-managed transfer
            SemanticKind::StaticLifetimeSink => 0.9, // Process lifetime, safe
            SemanticKind::DestructorRelease => 1.0, // Compiler-managed cleanup

            // ── Default ──
            SemanticKind::Unknown => 0.5,
            // ── Phase 6: ABI layout detection ──
            SemanticKind::AbiLayoutPadding => 0.2, // High risk: real FFI bug pattern
        }
    }

    /// Returns whether this semantic kind indicates a resource that requires
    /// explicit cleanup or deallocation.
    pub fn requires_cleanup(&self) -> bool {
        match self {
            // Python reference counting
            SemanticKind::PythonRefcountInc => true,
            SemanticKind::PythonOwnedRef => true,
            // Go patterns
            SemanticKind::GoRuntimeAlloc => true,
            // C++ patterns
            SemanticKind::CppUniquePtr => true,
            SemanticKind::CppSharedPtr => true,
            // C# patterns
            SemanticKind::CsharpSafeHandle => true,
            SemanticKind::CsharpFinalizer => true,
            SemanticKind::CsharpPinvokeMarshal => true,
            // Java patterns
            SemanticKind::JavaGlobalRef => true,
            SemanticKind::JavaWeakRef => true,
            // Existing patterns
            SemanticKind::HeapProvenance => true,
            SemanticKind::IntoRawTransfer => true,
            _ => false,
        }
    }

    /// Returns whether this semantic kind indicates a borrowed or temporary reference.
    pub fn is_borrowed_or_temporary(&self) -> bool {
        matches!(
            self,
            SemanticKind::PythonBorrowedRef
                | SemanticKind::PythonGilProtected
                | SemanticKind::JavaLocalRef
                | SemanticKind::FromParameter
                | SemanticKind::ReadonlyParam
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
// Semantic Fact — a verified or inferred semantic property
// ──────────────────────────────────────────────────────────────────────────

/// Confidence level for a semantic fact.
///
/// Facts with higher confidence are preferred when resolving conflicts
/// between multiple facts about the same resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FactConfidence {
    /// High confidence: directly observed from IR patterns or verified
    /// by multiple independent sources (e.g., both symbol name and
    /// instruction pattern agree).
    High,
    /// Medium confidence: inferred from a single source or heuristic
    /// (e.g., function name pattern only).
    Medium,
    /// Low confidence: speculative inference or conflicting evidence.
    Low,
}

impl FactConfidence {
    /// Converts confidence to a numeric score for ranking.
    pub fn score(&self) -> f32 {
        match self {
            Self::High => 1.0,
            Self::Medium => 0.6,
            Self::Low => 0.3,
        }
    }
}

impl std::fmt::Display for FactConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

/// Origin of a semantic fact — which analysis pass or data source produced it.
///
/// Knowing the source helps downstream consumers weight facts correctly
/// and detect circular reasoning (e.g., a fact from ContractDB should
/// not reinforce the same contract that created it).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FactSource {
    /// Derived from IR instruction patterns (e.g., ConditionalRelease
    /// from atomicrmw + icmp + branch).
    IRPattern,
    /// Derived from the resource contract database (family registry +
    /// summary inference).
    ContractDB,
    /// Derived from function behavior summary (BehaviorPattern → fact).
    BehaviorSummary,
    /// Derived from FFI boundary detection (cross-language call sites).
    BoundaryDetector,
    /// Derived from language-specific adapters (C++, Python, Java/JNI,
    /// Go, C#, etc.). Each adapter converts its language-specific patterns
    /// into SemanticFacts for unified downstream consumption.
    LanguageAdapter,
    /// Derived from memory graph analysis (ownership flow, aliasing).
    MemoryGraph,
}

impl std::fmt::Display for FactSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IRPattern => write!(f, "ir_pattern"),
            Self::ContractDB => write!(f, "contract_db"),
            Self::BehaviorSummary => write!(f, "behavior_summary"),
            Self::BoundaryDetector => write!(f, "boundary_detector"),
            Self::LanguageAdapter => write!(f, "language_adapter"),
            Self::MemoryGraph => write!(f, "memory_graph"),
        }
    }
}

/// A semantic fact: a verified or inferred property about a resource or
/// operation, produced by analysis passes and consumed by downstream
/// issue candidate builders.
///
/// Unlike `SemanticResolution` (which records *why* a value has a kind),
/// `SemanticFact` records *what* is known about a resource or operation,
/// with explicit provenance (source) and confidence.
///
/// # Example
///
/// ```text
/// SemanticFact {
///     key: SemanticKey::CallSite { caller: "main", callee: "free", index: 0 },
///     kind: SemanticKind::IntoRawTransfer,
///     confidence: FactConfidence::High,
///     source: FactSource::BehaviorSummary,
///     evidence: "Box::into_raw followed by free in same function",
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SemanticFact {
    /// The key identifying what this fact is about.
    pub key: SemanticKey,
    /// The semantic kind this fact asserts.
    pub kind: SemanticKind,
    /// How confident we are in this fact.
    pub confidence: FactConfidence,
    /// Where this fact came from.
    pub source: FactSource,
    /// Human-readable evidence supporting this fact.
    pub evidence: String,
}

impl SemanticFact {
    /// Creates a new semantic fact.
    pub fn new(
        key: SemanticKey,
        kind: SemanticKind,
        confidence: FactConfidence,
        source: FactSource,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            key,
            kind,
            confidence,
            source,
            evidence: evidence.into(),
        }
    }

    /// Returns true if this fact has high confidence.
    pub fn is_high_confidence(&self) -> bool {
        self.confidence == FactConfidence::High
    }

    /// Returns the numeric confidence score.
    pub fn confidence_score(&self) -> f32 {
        self.confidence.score()
    }
}
