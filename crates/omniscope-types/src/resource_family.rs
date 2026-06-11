//! Resource family types for cross-language memory safety analysis.
//!
//! `ResourceFamily` replaces language-based allocator matching. Instead of
//! checking whether `alloc_language == free_language`, we check whether
//! `family(alloc) == family(release)` or if the families are explicitly
//! compatible. This eliminates the vast majority of cross-language false
//! positives while catching real mismatches (e.g. `malloc`/`delete[]`).

use serde::{Deserialize, Serialize};

/// Unique identifier for a resource family.
///
/// Each built-in family has a stable numeric ID. User-inferred families
/// start from `USER_FAMILY_START`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FamilyId(pub u16);

impl FamilyId {
    /// C heap: malloc/calloc/realloc + free
    pub const C_HEAP: FamilyId = FamilyId(1);
    /// C++ scalar new/delete
    pub const CPP_NEW_SCALAR: FamilyId = FamilyId(2);
    /// C++ array new[]/delete[]
    pub const CPP_NEW_ARRAY: FamilyId = FamilyId(3);
    /// Rust global allocator: __rust_alloc / __rust_dealloc
    pub const RUST_GLOBAL: FamilyId = FamilyId(4);
    /// Python object: PyObject_New / PyObject_Free
    pub const PYTHON_OBJECT: FamilyId = FamilyId(5);
    /// Python memory: PyMem_Malloc / PyMem_Free
    pub const PYTHON_MEM: FamilyId = FamilyId(6);
    /// Python raw memory: PyMem_RawMalloc / PyMem_RawFree
    pub const PYTHON_MEM_RAW: FamilyId = FamilyId(7);
    /// JNI local reference: NewLocalRef / DeleteLocalRef
    pub const JAVA_LOCAL_REF: FamilyId = FamilyId(8);
    /// JNI global reference: NewGlobalRef / DeleteGlobalRef
    pub const JAVA_GLOBAL_REF: FamilyId = FamilyId(9);
    /// C# HGlobal: Marshal.AllocHGlobal / Marshal.FreeHGlobal
    pub const CSHARP_HGLOBAL: FamilyId = FamilyId(10);
    /// C# CoTaskMem: CoTaskMemAlloc / CoTaskMemFree
    pub const CSHARP_COTASK: FamilyId = FamilyId(11);
    /// Go GC-managed: runtime.mallocgc
    pub const GO_GC: FamilyId = FamilyId(12);
    /// Zig allocator: zig_allocator_allocImpl/zig_allocator_freeImpl.
    pub const ZIG_ALLOCATOR: FamilyId = FamilyId(13);

    // ── Library-managed families (from IR Pattern Atlas §1.4, §4, §7) ──

    /// zlib stream family: inflateInit_/inflateEnd, deflateInit_/deflateEnd.
    /// Evidence: `zlib_binding.ll` — library-level resource pairing.
    pub const ZLIB_STREAM: FamilyId = FamilyId(14);
    /// OpenSSL resource family: EVP_CIPHER_CTX_new/_free, BIO_new/_free,
    /// RSA_new/_free, BN_new/_free.
    /// Evidence: `openssl_wrapper.ll` — library-level resource pairing.
    pub const OPENSSL_RESOURCE: FamilyId = FamilyId(15);
    /// SQLite resource family: sqlite3_open/_close, sqlite3_prepare_v2/_finalize.
    /// Evidence: `sqlite_binding.ll` — library-level resource pairing.
    pub const SQLITE_RESOURCE: FamilyId = FamilyId(16);
    /// Go cgo internal family: _cgo_allocate/_cgo_free, _Cfunc_GoMalloc/_Cfunc_GoFree.
    /// Evidence: `go_cgo_bugs.ll` — cgo runtime memory management.
    pub const GO_CGO: FamilyId = FamilyId(17);
    /// mimalloc family: mi_malloc/mi_free/mi_realloc/mi_heap_destroy.
    /// Evidence: `bun_alloc-ef7250b81132b4bd.ll` — Bun's custom allocator.
    pub const MIMALLOC: FamilyId = FamilyId(18);
    /// C# COM family: CoTaskMemAlloc/CoTaskMemFree (separate from HGlobal).
    /// Evidence: `csharp_ffi_bugs.ll` — COM interop memory management.
    /// Note: Swift ARC removed — Swift is not in this release's scope
    /// (bun_fp_reduction_plan §1.A.3: Swift excluded).
    pub const CSHARP_COM: FamilyId = FamilyId(19);

    /// Rust raw ownership family: Box::into_raw/from_raw, CString::into_raw/from_raw,
    /// Vec::from_raw_parts. These are Rust-managed resources whose lifecycle
    /// crosses the safe/unsafe boundary via raw pointer conversion.
    /// Compatible with RUST_GLOBAL because both use Rust's global allocator underneath.
    pub const RUST_RAW_OWNERSHIP: FamilyId = FamilyId(20);

    /// File descriptor family: open/creat/socket/accept/dup/pipe + close.
    /// File descriptors are integer handles to OS resources (files, sockets, pipes).
    /// Unlike pointer-based resources, fd values are small integers that cannot
    /// be dereferenced directly. Leak detection applies the same acquire/release
    /// pairing model but uses integer resource IDs instead of pointers.
    pub const FILE_DESCRIPTOR: FamilyId = FamilyId(21);

    /// Unknown family: used when the resource family cannot be determined.
    /// This is a placeholder for FFI returns or other cases where the
    /// resource type is unknown and should not be assumed to be heap memory.
    pub const UNKNOWN: FamilyId = FamilyId(22);

    /// Windows heap family: HeapAlloc/HeapFree/HeapReAlloc.
    /// These use Windows heap handles (PROCESS_HEAP), distinct from C malloc.
    /// Mixing HeapAlloc+free or malloc+HeapFree is a real mismatch.
    pub const WIN32_HEAP: FamilyId = FamilyId(23);

    /// Windows virtual memory family: VirtualAlloc/VirtualFree.
    /// These allocate pages directly from the OS, not from any heap.
    /// Mixing VirtualAlloc+free is a serious mismatch.
    pub const WIN32_VIRTUAL: FamilyId = FamilyId(24);

    /// Starting ID for user-inferred families (from model mining).
    pub const USER_FAMILY_START: u16 = 256;

    /// Create a custom family ID from a name.
    ///
    /// Uses a hash of the name to generate a unique ID that is
    /// above `USER_FAMILY_START` to avoid collisions with built-in IDs.
    ///
    /// # Arguments
    /// * `name` - The name of the custom resource family.
    ///
    /// # Returns
    /// A `FamilyId` with a unique hash-based ID.
    pub fn custom(name: &str) -> Self {
        // 使用 hash 生成唯一 ID
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        let hash = hasher.finish() as u32;
        // 确保 ID 在 USER_FAMILY_START 范围内
        let id = (hash % (u16::MAX as u32 - Self::USER_FAMILY_START as u32))
            + Self::USER_FAMILY_START as u32;
        FamilyId(id as u16)
    }

    /// Returns a human-readable name for well-known family IDs.
    pub fn display_name(self) -> &'static str {
        match self {
            FamilyId::C_HEAP => "C_HEAP",
            FamilyId::CPP_NEW_SCALAR => "CPP_NEW_SCALAR",
            FamilyId::CPP_NEW_ARRAY => "CPP_NEW_ARRAY",
            FamilyId::RUST_GLOBAL => "RUST_GLOBAL",
            FamilyId::PYTHON_OBJECT => "PYTHON_OBJECT",
            FamilyId::PYTHON_MEM => "PYTHON_MEM",
            FamilyId::PYTHON_MEM_RAW => "PYTHON_MEM_RAW",
            FamilyId::JAVA_LOCAL_REF => "JAVA_LOCAL_REF",
            FamilyId::JAVA_GLOBAL_REF => "JAVA_GLOBAL_REF",
            FamilyId::CSHARP_HGLOBAL => "CSHARP_HGLOBAL",
            FamilyId::CSHARP_COTASK => "CSHARP_COTASK",
            FamilyId::GO_GC => "GO_GC",
            FamilyId::ZLIB_STREAM => "ZLIB_STREAM",
            FamilyId::OPENSSL_RESOURCE => "OPENSSL_RESOURCE",
            FamilyId::SQLITE_RESOURCE => "SQLITE_RESOURCE",
            FamilyId::GO_CGO => "GO_CGO",
            FamilyId::MIMALLOC => "MIMALLOC",
            FamilyId::CSHARP_COM => "CSHARP_COM",
            FamilyId::RUST_RAW_OWNERSHIP => "RUST_RAW_OWNERSHIP",
            FamilyId::FILE_DESCRIPTOR => "FILE_DESCRIPTOR",
            FamilyId::UNKNOWN => "UNKNOWN",
            FamilyId::WIN32_HEAP => "WIN32_HEAP",
            FamilyId::WIN32_VIRTUAL => "WIN32_VIRTUAL",
            _ => "unknown",
        }
    }
}

/// Kind of resource family, used to classify the management model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FamilyKind {
    /// Manual heap management (malloc/free, new/delete).
    ManualHeap,
    /// Garbage-collected runtime (Go GC, Java GC).
    GcManaged,
    /// Reference-counted runtime (Python refcount, COM AddRef/Release).
    RefCounted,
    /// Allocator-vtable dispatched (generic vtable-based allocator).
    VtableDispatched,
    /// Runtime handle-based (JNI refs, C# SafeHandle).
    HandleBased,
    /// Library-managed pairing (zlib/openssl/sqlite init+end).
    /// The library internally manages resource lifecycle through
    /// paired init/end functions that cannot be inferred from IR alone.
    LibraryManaged,
    /// User-inferred family from model mining.
    UserDefined,
    /// File descriptor based resource (open/close, dup, pipe).
    /// File descriptors are integer handles to OS resources.
    FileDescriptor,
    /// Socket-based resource (socket/accept/close).
    /// Sockets are network communication endpoints.
    Socket,
    /// Process handle resource (fork/exec/waitpid).
    /// Process handles represent OS processes.
    ProcessHandle,
    /// Runtime-managed resource (Go runtime, Java runtime).
    /// Resources managed by language runtime systems.
    RuntimeManaged,
}

/// Lifetime domain for a resource family.
///
/// Determines how long resources from this family are expected to live
/// and what "leak" means in that context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LifetimeDomain {
    /// Bounded by the current function call (e.g. JNI local refs).
    CallLocal,
    /// Bounded by the current thread (e.g. thread-local allocators).
    ThreadLocal,
    /// Bounded by the owning object's lifetime (e.g. field-stored ptrs).
    OwnerBounded,
    /// Lives until explicitly freed (most manual heap families).
    ExplicitFree,
    /// GC-managed, no explicit free needed.
    GcManaged,
    /// Process-static / global storage.
    ProcessStatic,
    /// Unknown lifetime domain.
    Unknown,
}

/// A resource family describes a group of allocation/deallocation functions
/// that share the same management model and are compatible with each other.
///
/// For example, `malloc`/`calloc`/`realloc` all belong to the `c_heap` family,
/// and `free` is the matching release function. Releasing a `c_heap` allocation
/// with `operator delete` is a family mismatch, regardless of language.
#[derive(Debug, Clone, Serialize)]
#[serde(into = "SerializableResourceFamily")]
pub struct ResourceFamily {
    /// Unique identifier for this family.
    pub id: FamilyId,
    /// Human-readable name (e.g. "c_heap", "cpp_new_scalar").
    pub name: &'static str,
    /// Management model kind.
    pub kind: FamilyKind,
    /// Expected lifetime domain for resources in this family.
    pub lifetime: LifetimeDomain,
    /// Families that are explicitly compatible for release.
    ///
    /// For example, if `c_heap` lists `cpp_new_scalar` as compatible,
    /// then `malloc`/`delete` is not a mismatch (though unusual).
    pub compatible_releases: &'static [FamilyId],
}

impl ResourceFamily {
    /// Returns true if releasing a resource from `other` family using
    /// this family's release function is considered a valid (compatible)
    /// operation.
    pub fn is_compatible_with(&self, other: FamilyId) -> bool {
        if self.id == other {
            return true;
        }
        self.compatible_releases.contains(&other)
    }
}

// ============================================================================
// Built-in resource family definitions
// ============================================================================

/// C heap family: malloc/calloc/realloc + free.
pub static FAMILY_C_HEAP: ResourceFamily = ResourceFamily {
    id: FamilyId::C_HEAP,
    name: "c_heap",
    kind: FamilyKind::ManualHeap,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// C++ scalar new/delete family.
pub static FAMILY_CPP_NEW_SCALAR: ResourceFamily = ResourceFamily {
    id: FamilyId::CPP_NEW_SCALAR,
    name: "cpp_new_scalar",
    kind: FamilyKind::ManualHeap,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// C++ array new[]/delete[] family.
pub static FAMILY_CPP_NEW_ARRAY: ResourceFamily = ResourceFamily {
    id: FamilyId::CPP_NEW_ARRAY,
    name: "cpp_new_array",
    kind: FamilyKind::ManualHeap,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// Rust global allocator family.
pub static FAMILY_RUST_GLOBAL: ResourceFamily = ResourceFamily {
    id: FamilyId::RUST_GLOBAL,
    name: "rust_global",
    kind: FamilyKind::ManualHeap,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// Python object family (PyObject_New / PyObject_Free).
pub static FAMILY_PYTHON_OBJECT: ResourceFamily = ResourceFamily {
    id: FamilyId::PYTHON_OBJECT,
    name: "python_object",
    kind: FamilyKind::RefCounted,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[FamilyId::PYTHON_OBJECT],
};

/// Python memory family (PyMem_Malloc / PyMem_Free).
pub static FAMILY_PYTHON_MEM: ResourceFamily = ResourceFamily {
    id: FamilyId::PYTHON_MEM,
    name: "python_mem",
    kind: FamilyKind::ManualHeap,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// Python raw memory family (PyMem_RawMalloc / PyMem_RawFree).
pub static FAMILY_PYTHON_MEM_RAW: ResourceFamily = ResourceFamily {
    id: FamilyId::PYTHON_MEM_RAW,
    name: "python_mem_raw",
    kind: FamilyKind::ManualHeap,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[FamilyId::C_HEAP],
};

/// JNI local reference family.
pub static FAMILY_JAVA_LOCAL_REF: ResourceFamily = ResourceFamily {
    id: FamilyId::JAVA_LOCAL_REF,
    name: "java_local_ref",
    kind: FamilyKind::HandleBased,
    lifetime: LifetimeDomain::CallLocal,
    compatible_releases: &[],
};

/// JNI global reference family.
pub static FAMILY_JAVA_GLOBAL_REF: ResourceFamily = ResourceFamily {
    id: FamilyId::JAVA_GLOBAL_REF,
    name: "java_global_ref",
    kind: FamilyKind::HandleBased,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// C# HGlobal family.
pub static FAMILY_CSHARP_HGLOBAL: ResourceFamily = ResourceFamily {
    id: FamilyId::CSHARP_HGLOBAL,
    name: "csharp_hglobal",
    kind: FamilyKind::ManualHeap,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// C# CoTaskMem family.
pub static FAMILY_CSHARP_COTASK: ResourceFamily = ResourceFamily {
    id: FamilyId::CSHARP_COTASK,
    name: "csharp_cotask",
    kind: FamilyKind::ManualHeap,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// Go GC family.
pub static FAMILY_GO_GC: ResourceFamily = ResourceFamily {
    id: FamilyId::GO_GC,
    name: "go_gc",
    kind: FamilyKind::GcManaged,
    lifetime: LifetimeDomain::GcManaged,
    compatible_releases: &[],
};

// ── Library-managed families (IR Pattern Atlas §1.4, §4, §7) ──

/// zlib stream family: inflateInit_/inflateEnd, deflateInit_/deflateEnd.
/// Evidence: `zlib_binding.ll` — paired init/end resource management.
pub static FAMILY_ZLIB_STREAM: ResourceFamily = ResourceFamily {
    id: FamilyId::ZLIB_STREAM,
    name: "zlib_stream",
    kind: FamilyKind::LibraryManaged,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// OpenSSL resource family: EVP_CIPHER_CTX_new/_free, BIO_new/_free,
/// RSA_new/_free, BN_new/_free.
/// Evidence: `openssl_wrapper.ll` — paired new/free resource management.
pub static FAMILY_OPENSSL_RESOURCE: ResourceFamily = ResourceFamily {
    id: FamilyId::OPENSSL_RESOURCE,
    name: "openssl_resource",
    kind: FamilyKind::LibraryManaged,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// SQLite resource family: sqlite3_open/_close, sqlite3_prepare_v2/_finalize.
/// Evidence: `sqlite_binding.ll` — paired open/close resource management.
pub static FAMILY_SQLITE_RESOURCE: ResourceFamily = ResourceFamily {
    id: FamilyId::SQLITE_RESOURCE,
    name: "sqlite_resource",
    kind: FamilyKind::LibraryManaged,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// Go cgo internal family: _cgo_allocate/_cgo_free, _Cfunc_GoMalloc/_Cfunc_GoFree.
/// Evidence: `go_cgo_bugs.ll` — cgo runtime memory management.
pub static FAMILY_GO_CGO: ResourceFamily = ResourceFamily {
    id: FamilyId::GO_CGO,
    name: "go_cgo",
    kind: FamilyKind::GcManaged,
    lifetime: LifetimeDomain::GcManaged,
    compatible_releases: &[FamilyId::GO_GC],
};

/// mimalloc family: mi_malloc/mi_free/mi_realloc/mi_heap_destroy.
/// Evidence: `bun_alloc-ef7250b81132b4bd.ll` — Bun's custom allocator.
/// Compatible with C_HEAP because mimalloc is a malloc replacement.
pub static FAMILY_MIMALLOC: ResourceFamily = ResourceFamily {
    id: FamilyId::MIMALLOC,
    name: "mimalloc",
    kind: FamilyKind::ManualHeap,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[FamilyId::C_HEAP],
};

/// C# COM family: CoTaskMemAlloc/CoTaskMemFree.
/// Evidence: `csharp_ffi_bugs.ll` — COM interop memory management.
/// Note: Swift ARC removed — Swift is not in this release's scope
/// (bun_fp_reduction_plan §1.A.3: Swift excluded).
pub static FAMILY_CSHARP_COM: ResourceFamily = ResourceFamily {
    id: FamilyId::CSHARP_COM,
    name: "csharp_com",
    kind: FamilyKind::HandleBased,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[FamilyId::C_HEAP],
};

/// Rust raw ownership family: Box::into_raw/from_raw, CString::into_raw/from_raw,
/// Vec::from_raw_parts. Resources that cross the safe/unsafe boundary
/// via raw pointer conversion. Underlying allocation uses Rust's global
/// allocator, so this family is compatible with RUST_GLOBAL for release.
pub static FAMILY_RUST_RAW_OWNERSHIP: ResourceFamily = ResourceFamily {
    id: FamilyId::RUST_RAW_OWNERSHIP,
    name: "rust_raw_ownership",
    kind: FamilyKind::ManualHeap,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[FamilyId::RUST_GLOBAL],
};

/// File descriptor family: open/creat/socket/accept/dup/pipe + close.
/// File descriptors are integer handles to OS resources (files, sockets, pipes).
/// Unlike pointer-based resources, fd values are small integers that cannot
/// be dereferenced directly. This family uses FileDescriptor kind because
/// file descriptors are handle-based resources, not memory.
/// No compatible releases — fd values from different families cannot be
/// used interchangeably (e.g., socket fd cannot be closed with fclose).
pub static FAMILY_FILE_DESCRIPTOR: ResourceFamily = ResourceFamily {
    id: FamilyId::FILE_DESCRIPTOR,
    name: "file_descriptor",
    kind: FamilyKind::FileDescriptor,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// Unknown family: used when the resource family cannot be determined.
/// This is a placeholder for FFI returns or other cases where the
/// resource type is unknown and should not be assumed to be heap memory.
/// No compatible releases — unknown resources cannot be released safely.
pub static FAMILY_UNKNOWN: ResourceFamily = ResourceFamily {
    id: FamilyId::UNKNOWN,
    name: "unknown",
    kind: FamilyKind::ManualHeap, // Conservative default
    lifetime: LifetimeDomain::Unknown,
    compatible_releases: &[],
};

/// Windows heap family: HeapAlloc/HeapFree/HeapReAlloc.
/// These use Windows heap handles (PROCESS_HEAP), distinct from C malloc.
/// Evidence: Win32 API — HeapAlloc requires a heap handle from GetProcessHeap().
/// Not compatible with C_HEAP: HeapAlloc+free is a real mismatch.
pub static FAMILY_WIN32_HEAP: ResourceFamily = ResourceFamily {
    id: FamilyId::WIN32_HEAP,
    name: "win32_heap",
    kind: FamilyKind::HandleBased,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// Windows virtual memory family: VirtualAlloc/VirtualFree.
/// These allocate pages directly from the OS, not from any heap.
/// Evidence: Win32 API — VirtualAlloc reserves/commits pages.
/// Not compatible with C_HEAP: VirtualAlloc+free is a serious mismatch.
pub static FAMILY_WIN32_VIRTUAL: ResourceFamily = ResourceFamily {
    id: FamilyId::WIN32_VIRTUAL,
    name: "win32_virtual",
    kind: FamilyKind::HandleBased,
    lifetime: LifetimeDomain::ExplicitFree,
    compatible_releases: &[],
};

/// Serializable form of `ResourceFamily` for serde round-tripping.
/// `ResourceFamily` uses `&'static str` and `&'static [FamilyId]` which
/// cannot derive `Deserialize`, so we convert to this owned form.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableResourceFamily {
    id: FamilyId,
    name: String,
    kind: FamilyKind,
    lifetime: LifetimeDomain,
    compatible_releases: Vec<FamilyId>,
}

impl From<ResourceFamily> for SerializableResourceFamily {
    fn from(f: ResourceFamily) -> Self {
        Self {
            id: f.id,
            name: f.name.to_string(),
            kind: f.kind,
            lifetime: f.lifetime,
            compatible_releases: f.compatible_releases.to_vec(),
        }
    }
}

/// Checks whether two family IDs are compatible for release.
///
/// Two families are compatible if they are the same, or if the
/// release family is listed in the acquire family's `compatible_releases`.
/// Returns false for unknown family IDs not found in `BUILTIN_FAMILIES`.
pub fn are_families_compatible(acquire: FamilyId, release: FamilyId) -> bool {
    if acquire == release {
        return true;
    }
    for family in BUILTIN_FAMILIES {
        if family.id == acquire {
            return family.compatible_releases.contains(&release);
        }
    }
    false
}

/// All built-in resource families.
pub static BUILTIN_FAMILIES: &[&ResourceFamily] = &[
    &FAMILY_C_HEAP,
    &FAMILY_CPP_NEW_SCALAR,
    &FAMILY_CPP_NEW_ARRAY,
    &FAMILY_RUST_GLOBAL,
    &FAMILY_PYTHON_OBJECT,
    &FAMILY_PYTHON_MEM,
    &FAMILY_PYTHON_MEM_RAW,
    &FAMILY_JAVA_LOCAL_REF,
    &FAMILY_JAVA_GLOBAL_REF,
    &FAMILY_CSHARP_HGLOBAL,
    &FAMILY_CSHARP_COTASK,
    &FAMILY_GO_GC,
    // Library-managed families (IR Pattern Atlas)
    &FAMILY_ZLIB_STREAM,
    &FAMILY_OPENSSL_RESOURCE,
    &FAMILY_SQLITE_RESOURCE,
    &FAMILY_GO_CGO,
    &FAMILY_MIMALLOC,
    &FAMILY_CSHARP_COM,
    &FAMILY_RUST_RAW_OWNERSHIP,
    // File descriptor family (OS resource handles)
    &FAMILY_FILE_DESCRIPTOR,
    // Unknown family (placeholder for FFI returns)
    &FAMILY_UNKNOWN,
    // Windows platform families
    &FAMILY_WIN32_HEAP,
    &FAMILY_WIN32_VIRTUAL,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_families_count() {
        assert_eq!(
            BUILTIN_FAMILIES.len(),
            23,
            "Must have exactly 23 built-in families (including WIN32_HEAP and WIN32_VIRTUAL)"
        );
    }

    #[test]
    fn test_family_self_compatibility() {
        for family in BUILTIN_FAMILIES {
            assert!(
                family.is_compatible_with(family.id),
                "Family {} must be compatible with itself",
                family.name
            );
        }
    }

    #[test]
    fn test_c_heap_not_compatible_with_cpp_new() {
        assert!(
            !FAMILY_C_HEAP.is_compatible_with(FamilyId::CPP_NEW_SCALAR),
            "c_heap and cpp_new_scalar must NOT be compatible"
        );
        assert!(
            !FAMILY_C_HEAP.is_compatible_with(FamilyId::CPP_NEW_ARRAY),
            "c_heap and cpp_new_array must NOT be compatible"
        );
    }

    #[test]
    fn test_rust_global_not_compatible_with_c_heap() {
        assert!(
            !FAMILY_RUST_GLOBAL.is_compatible_with(FamilyId::C_HEAP),
            "rust_global and c_heap must NOT be compatible — this is a real mismatch"
        );
    }

    #[test]
    fn test_python_mem_raw_compatible_with_c_heap() {
        assert!(
            FAMILY_PYTHON_MEM_RAW.is_compatible_with(FamilyId::C_HEAP),
            "python_mem_raw delegates to C malloc, so it should be compatible with c_heap"
        );
    }

    #[test]
    fn test_go_gc_is_gc_managed() {
        assert_eq!(
            FAMILY_GO_GC.kind,
            FamilyKind::GcManaged,
            "Go GC family must be GcManaged"
        );
        assert_eq!(
            FAMILY_GO_GC.lifetime,
            LifetimeDomain::GcManaged,
            "Go GC family must have GcManaged lifetime"
        );
    }

    #[test]
    fn test_family_ids_are_unique() {
        let mut ids = std::collections::HashSet::new();
        for family in BUILTIN_FAMILIES {
            assert!(
                ids.insert(family.id),
                "Duplicate FamilyId found: {:?}",
                family.id
            );
        }
    }

    #[test]
    fn test_user_family_start_above_builtins() {
        for family in BUILTIN_FAMILIES {
            assert!(
                family.id.0 < FamilyId::USER_FAMILY_START,
                "Built-in family {} has ID >= USER_FAMILY_START",
                family.name
            );
        }
    }
}
