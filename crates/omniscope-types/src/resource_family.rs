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
    /// Zig allocator: modeled through allocator-vtable evidence
    pub const ZIG_ALLOCATOR: FamilyId = FamilyId(13);

    /// Starting ID for user-inferred families (from model mining).
    pub const USER_FAMILY_START: u16 = 256;
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
    /// Allocator-vtable dispatched (Zig std.mem.Allocator).
    VtableDispatched,
    /// Runtime handle-based (JNI refs, C# SafeHandle).
    HandleBased,
    /// User-inferred family from model mining.
    UserDefined,
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

/// Zig allocator family.
pub static FAMILY_ZIG_ALLOCATOR: ResourceFamily = ResourceFamily {
    id: FamilyId::ZIG_ALLOCATOR,
    name: "zig_allocator",
    kind: FamilyKind::VtableDispatched,
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
    &FAMILY_ZIG_ALLOCATOR,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_families_count() {
        assert_eq!(
            BUILTIN_FAMILIES.len(),
            13,
            "Must have exactly 13 built-in families"
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
