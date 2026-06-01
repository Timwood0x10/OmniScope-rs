//! Resource family registry for symbol-to-family lookup.
//!
//! The registry maps canonical symbol names to their resource families.
//! Instead of checking `alloc_language == free_language`, we look up
//! the family for each symbol and check `family(alloc).is_compatible_with(family(free))`.

use std::collections::HashMap;

use omniscope_types::{FamilyId, LanguageHint, BUILTIN_FAMILIES};

/// A symbol-to-family mapping entry.
#[derive(Debug, Clone)]
pub struct FamilyEntry {
    /// The resource family for this symbol.
    pub family_id: FamilyId,
    /// The effect this symbol produces (acquire or release).
    pub effect: SymbolEffect,
    /// Language hint for this symbol.
    pub language_hint: LanguageHint,
}

/// Whether a symbol acquires or releases a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolEffect {
    /// Symbol acquires/allocates a resource.
    Acquire,
    /// Symbol releases/deallocates a resource.
    Release,
    /// Symbol conditionally releases (refcount decrement).
    ConditionalRelease,
    /// Symbol retains (refcount increment).
    Retain,
    /// Symbol escapes ownership (into_raw) — resource leaves Rust's
    /// type system via raw pointer conversion. NOT a release.
    Escape,
    /// Symbol reclaims ownership from a raw pointer (from_raw) —
    /// resource re-enters Rust's type system. This IS an acquire.
    Reclaim,
}

/// Registry mapping symbol names to resource families.
///
/// Built-in entries cover C, C++, Rust, Python, Java/JNI, C#, Go, and Zig
/// allocation/deallocation functions. User-inferred entries can be added
/// from model mining (Phase 7).
#[derive(Debug, Clone)]
pub struct FamilyRegistry {
    /// Symbol name -> FamilyEntry lookup table.
    entries: HashMap<String, FamilyEntry>,
    /// Family ID -> ResourceFamily lookup (includes user-inferred).
    families: HashMap<FamilyId, ResourceFamilyOwned>,
}

/// Owned version of `ResourceFamily` for the registry (no `&'static` refs).
#[derive(Debug, Clone)]
pub struct ResourceFamilyOwned {
    /// Unique identifier.
    pub id: FamilyId,
    /// Human-readable name.
    pub name: String,
    /// Management model kind.
    pub kind: omniscope_types::FamilyKind,
    /// Expected lifetime domain.
    pub lifetime: omniscope_types::LifetimeDomain,
    /// Compatible release families.
    pub compatible_releases: Vec<FamilyId>,
}

impl ResourceFamilyOwned {
    /// Returns true if `other` family is compatible for release.
    pub fn is_compatible_with(&self, other: FamilyId) -> bool {
        if self.id == other {
            return true;
        }
        self.compatible_releases.contains(&other)
    }
}

impl FamilyRegistry {
    /// Creates a new registry populated with all built-in entries.
    pub fn new() -> Self {
        let mut registry = Self {
            entries: HashMap::new(),
            families: HashMap::new(),
        };
        registry.register_builtin_families();
        registry.register_builtin_symbols();
        registry
    }

    /// Looks up the family entry for a symbol name.
    pub fn lookup(&self, symbol: &str) -> Option<&FamilyEntry> {
        self.entries.get(symbol)
    }

    /// Looks up the family for a given family ID.
    pub fn family(&self, id: FamilyId) -> Option<&ResourceFamilyOwned> {
        self.families.get(&id)
    }

    /// Checks if releasing a resource from `alloc_family` using
    /// `release_family` is a valid (compatible) operation.
    pub fn is_compatible_release(&self, alloc_family: FamilyId, release_family: FamilyId) -> bool {
        if alloc_family == release_family {
            return true;
        }
        if let Some(family) = self.families.get(&alloc_family) {
            return family.compatible_releases.contains(&release_family);
        }
        false
    }

    /// Adds a user-inferred family (from model mining).
    pub fn add_user_family(&mut self, family: ResourceFamilyOwned) {
        self.families.insert(family.id, family);
    }

    /// Adds a symbol-to-family mapping.
    pub fn add_symbol(
        &mut self,
        symbol: &str,
        family_id: FamilyId,
        effect: SymbolEffect,
        language_hint: LanguageHint,
    ) {
        self.entries.insert(
            symbol.to_string(),
            FamilyEntry {
                family_id,
                effect,
                language_hint,
            },
        );
    }

    /// Returns the number of registered symbols.
    pub fn symbol_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of registered families.
    pub fn family_count(&self) -> usize {
        self.families.len()
    }

    fn register_builtin_families(&mut self) {
        for family in BUILTIN_FAMILIES {
            self.families.insert(
                family.id,
                ResourceFamilyOwned {
                    id: family.id,
                    name: family.name.to_string(),
                    kind: family.kind,
                    lifetime: family.lifetime,
                    compatible_releases: family.compatible_releases.to_vec(),
                },
            );
        }
    }

    fn register_builtin_symbols(&mut self) {
        // C heap
        self.add_c_heap_symbols();
        // C++ new/delete
        self.add_cpp_symbols();
        // Rust global allocator
        self.add_rust_symbols();
        // Rust raw ownership transfer (Box/CString::into_raw/from_raw)
        self.add_rust_raw_ownership_symbols();
        // Python C API
        self.add_python_symbols();
        // Java/JNI
        self.add_jni_symbols();
        // C#/.NET
        self.add_csharp_symbols();
        // Go (GC + cgo)
        self.add_go_symbols();
        // Library-managed families (IR Pattern Atlas §1.4, §9)
        self.add_zlib_symbols();
        self.add_openssl_symbols();
        self.add_sqlite_symbols();
        self.add_mimalloc_symbols();
        // C# COM interop
        self.add_csharp_com_symbols();
    }

    fn add_c_heap_symbols(&mut self) {
        let f = FamilyId::C_HEAP;
        let lang = LanguageHint::C;
        for sym in &[
            "malloc",
            "calloc",
            "realloc",
            "valloc",
            "pvalloc",
            "memalign",
            "posix_memalign",
            "aligned_alloc",
        ] {
            self.add_symbol(sym, f, SymbolEffect::Acquire, lang);
        }
        self.add_symbol("free", f, SymbolEffect::Release, lang);
        self.add_symbol("reallocarray", f, SymbolEffect::Acquire, lang);
        // Whitelist: macOS malloc_set_zone_name — copies name string content,
        // does NOT retain the `name` pointer (per macOS man page).
        // Evidence: bun_alloc.bc — observed 12 times across corpus.
        // This is a Retain (no ownership change) because the function
        // only copies the string content, not the pointer.
        self.add_symbol("malloc_set_zone_name", f, SymbolEffect::Retain, lang);
    }

    fn add_cpp_symbols(&mut self) {
        let lang = LanguageHint::Cpp;
        // Scalar new/delete
        let f = FamilyId::CPP_NEW_SCALAR;
        for sym in &["_Znwm", "_Znwj", "operator new"] {
            self.add_symbol(sym, f, SymbolEffect::Acquire, lang);
        }
        for sym in &["_ZdlPv", "operator delete"] {
            self.add_symbol(sym, f, SymbolEffect::Release, lang);
        }
        // Array new[]/delete[]
        let f = FamilyId::CPP_NEW_ARRAY;
        for sym in &["_Znam", "_Znaj", "operator new[]"] {
            self.add_symbol(sym, f, SymbolEffect::Acquire, lang);
        }
        for sym in &["_ZdaPv", "operator delete[]"] {
            self.add_symbol(sym, f, SymbolEffect::Release, lang);
        }
    }

    fn add_rust_symbols(&mut self) {
        let f = FamilyId::RUST_GLOBAL;
        let lang = LanguageHint::Rust;
        for sym in &["__rust_alloc", "__rust_alloc_zeroed"] {
            self.add_symbol(sym, f, SymbolEffect::Acquire, lang);
        }
        self.add_symbol("__rust_dealloc", f, SymbolEffect::Release, lang);
        self.add_symbol("__rust_realloc", f, SymbolEffect::Acquire, lang);
        // Rust allocator deallocation symbols (evidence: bun_alloc.ll)
        self.add_symbol("__rdl_dealloc", f, SymbolEffect::Release, lang);
        self.add_symbol("__rg_dealloc", f, SymbolEffect::Release, lang);
        // Zig allocator vtable symbols (evidence: boundary_test.ll, zig_main.ll)
        let zig_f = FamilyId::ZIG_ALLOCATOR;
        let zig_lang = LanguageHint::Zig;
        self.add_symbol(
            "zig_allocator_allocImpl",
            zig_f,
            SymbolEffect::Acquire,
            zig_lang,
        );
        self.add_symbol(
            "zig_allocator_freeImpl",
            zig_f,
            SymbolEffect::Release,
            zig_lang,
        );
    }

    /// Registers Rust raw ownership transfer symbols: Box/CString::into_raw
    /// and Box/CString::from_raw, Vec::from_raw_parts.
    ///
    /// These symbols represent the safe/unsafe boundary where Rust ownership
    /// crosses into or out of raw pointer territory. The RUST_RAW_OWNERSHIP
    /// family is compatible with RUST_GLOBAL for release, since both use the
    /// same underlying allocator.
    fn add_rust_raw_ownership_symbols(&mut self) {
        let f = FamilyId::RUST_RAW_OWNERSHIP;
        let lang = LanguageHint::Rust;

        // ── Box ──
        // into_raw: ownership escapes to raw pointer
        self.add_symbol("Box::into_raw", f, SymbolEffect::Escape, lang);
        // from_raw: ownership reclaimed from raw pointer
        self.add_symbol("Box::from_raw", f, SymbolEffect::Reclaim, lang);

        // ── CString ──
        self.add_symbol("CString::into_raw", f, SymbolEffect::Escape, lang);
        self.add_symbol("CString::from_raw", f, SymbolEffect::Reclaim, lang);

        // ── Vec ──
        // Vec::from_raw_parts reclaims ownership from a raw pointer
        self.add_symbol("Vec::from_raw_parts", f, SymbolEffect::Reclaim, lang);
    }

    fn add_python_symbols(&mut self) {
        let lang = LanguageHint::Python;
        // Python object family
        let obj = FamilyId::PYTHON_OBJECT;
        for sym in &[
            "PyObject_New",
            "PyObject_NewVar",
            "PyType_GenericAlloc",
            // New-ref constructors (evidence: python_cffi_bugs.ll)
            "PyBytes_FromStringAndSize",
            "PyBytes_FromString",
            "PyUnicode_FromString",
            "PyUnicode_FromStringAndSize",
            "PyList_New",
            "PyTuple_New",
            "PyDict_New",
            "PySet_New",
        ] {
            self.add_symbol(sym, obj, SymbolEffect::Acquire, lang);
        }
        for sym in &["PyObject_Del", "PyObject_Free"] {
            self.add_symbol(sym, obj, SymbolEffect::Release, lang);
        }
        // Py_DECREF / Py_XDECREF are conditional releases
        self.add_symbol("Py_DECREF", obj, SymbolEffect::ConditionalRelease, lang);
        self.add_symbol("Py_XDECREF", obj, SymbolEffect::ConditionalRelease, lang);
        // Py_INCREF is a retain
        self.add_symbol("Py_INCREF", obj, SymbolEffect::Retain, lang);
        // Borrowed-ref accessors: return a pointer without transferring ownership.
        // These MUST NOT be treated as Acquire — calling Py_DECREF on a borrowed
        // ref is a bug (over-decrement). Evidence: python_cffi_bugs.ll §5.1.
        self.add_symbol("PyList_GetItem", obj, SymbolEffect::Retain, lang);
        self.add_symbol("PyList_GetItemRef", obj, SymbolEffect::Acquire, lang);
        self.add_symbol("PyBytes_AsString", obj, SymbolEffect::Retain, lang);
        self.add_symbol("PyUnicode_AsUTF8", obj, SymbolEffect::Retain, lang);
        // PyTuple_SetItem steals the reference (no INCREF needed on item).
        self.add_symbol("PyTuple_SetItem", obj, SymbolEffect::Release, lang);
        self.add_symbol("PyList_SetItem", obj, SymbolEffect::Release, lang);
        // Python mem family
        let mem = FamilyId::PYTHON_MEM;
        for sym in &["PyMem_Malloc", "PyMem_Calloc", "PyMem_Realloc"] {
            self.add_symbol(sym, mem, SymbolEffect::Acquire, lang);
        }
        self.add_symbol("PyMem_Free", mem, SymbolEffect::Release, lang);
        // ctypes allocation (evidence: python_cffi_bugs.ll §5.2)
        self.add_symbol("ctypes_alloc", mem, SymbolEffect::Acquire, lang);
        // Python raw mem family
        let raw = FamilyId::PYTHON_MEM_RAW;
        for sym in &["PyMem_RawMalloc", "PyMem_RawCalloc", "PyMem_RawRealloc"] {
            self.add_symbol(sym, raw, SymbolEffect::Acquire, lang);
        }
        self.add_symbol("PyMem_RawFree", raw, SymbolEffect::Release, lang);
    }

    fn add_jni_symbols(&mut self) {
        let lang = LanguageHint::Java;
        // JNI local reference family
        let local = FamilyId::JAVA_LOCAL_REF;
        self.add_symbol("NewLocalRef", local, SymbolEffect::Acquire, lang);
        self.add_symbol("DeleteLocalRef", local, SymbolEffect::Release, lang);
        // JNI borrowed-ref accessors: return pointers that must be released.
        // Evidence: java_jni_bugs.ll §6.1 — GetStringUTFChars is a borrow
        // that must be paired with ReleaseStringUTFChars.
        self.add_symbol("GetStringUTFChars", local, SymbolEffect::Acquire, lang);
        self.add_symbol("ReleaseStringUTFChars", local, SymbolEffect::Release, lang);
        self.add_symbol("GetStringCritical", local, SymbolEffect::Acquire, lang);
        self.add_symbol("ReleaseStringCritical", local, SymbolEffect::Release, lang);
        // JNI critical array access (evidence: java_jni_bugs.ll §6.1)
        self.add_symbol(
            "GetPrimitiveArrayCritical",
            local,
            SymbolEffect::Acquire,
            lang,
        );
        self.add_symbol(
            "ReleasePrimitiveArrayCritical",
            local,
            SymbolEffect::Release,
            lang,
        );
        self.add_symbol("GetByteArrayElements", local, SymbolEffect::Acquire, lang);
        self.add_symbol(
            "ReleaseByteArrayElements",
            local,
            SymbolEffect::Release,
            lang,
        );
        // JNI global reference family
        let global = FamilyId::JAVA_GLOBAL_REF;
        self.add_symbol("NewGlobalRef", global, SymbolEffect::Acquire, lang);
        self.add_symbol("DeleteGlobalRef", global, SymbolEffect::Release, lang);
        // JNI string/object creation (acquire new reference)
        self.add_symbol("NewStringUTF", global, SymbolEffect::Acquire, lang);
        self.add_symbol("NewByteArray", global, SymbolEffect::Acquire, lang);
    }

    fn add_csharp_symbols(&mut self) {
        let lang = LanguageHint::CSharp;
        self.add_symbol(
            "AllocHGlobal",
            FamilyId::CSHARP_HGLOBAL,
            SymbolEffect::Acquire,
            lang,
        );
        self.add_symbol(
            "FreeHGlobal",
            FamilyId::CSHARP_HGLOBAL,
            SymbolEffect::Release,
            lang,
        );
        self.add_symbol(
            "CoTaskMemAlloc",
            FamilyId::CSHARP_COTASK,
            SymbolEffect::Acquire,
            lang,
        );
        self.add_symbol(
            "CoTaskMemFree",
            FamilyId::CSHARP_COTASK,
            SymbolEffect::Release,
            lang,
        );
    }

    fn add_go_symbols(&mut self) {
        let lang = LanguageHint::Go;
        self.add_symbol(
            "runtime.mallocgc",
            FamilyId::GO_GC,
            SymbolEffect::Acquire,
            lang,
        );
        // Go cgo internal (evidence: go_cgo_bugs.ll)
        let cgo = FamilyId::GO_CGO;
        self.add_symbol("_cgo_allocate", cgo, SymbolEffect::Acquire, lang);
        self.add_symbol("_cgo_free", cgo, SymbolEffect::Release, lang);
        self.add_symbol("_Cfunc_GoMalloc", cgo, SymbolEffect::Acquire, lang);
        self.add_symbol("_Cfunc_GoFree", cgo, SymbolEffect::Release, lang);
        // Go TinyGo runtime alloc
        self.add_symbol(
            "runtime.alloc",
            FamilyId::GO_GC,
            SymbolEffect::Acquire,
            lang,
        );
    }

    /// Register zlib stream family symbols.
    /// Evidence: `zlib_binding.ll` — library-level resource pairing.
    fn add_zlib_symbols(&mut self) {
        let f = FamilyId::ZLIB_STREAM;
        let lang = LanguageHint::C;
        self.add_symbol("inflateInit_", f, SymbolEffect::Acquire, lang);
        self.add_symbol("inflateInit2_", f, SymbolEffect::Acquire, lang);
        self.add_symbol("inflateEnd", f, SymbolEffect::Release, lang);
        self.add_symbol("deflateInit_", f, SymbolEffect::Acquire, lang);
        self.add_symbol("deflateInit2_", f, SymbolEffect::Acquire, lang);
        self.add_symbol("deflateEnd", f, SymbolEffect::Release, lang);
    }

    /// Register OpenSSL resource family symbols.
    /// Evidence: `openssl_wrapper.ll` — library-level resource pairing.
    fn add_openssl_symbols(&mut self) {
        let f = FamilyId::OPENSSL_RESOURCE;
        let lang = LanguageHint::C;
        // EVP cipher context
        self.add_symbol("EVP_CIPHER_CTX_new", f, SymbolEffect::Acquire, lang);
        self.add_symbol("EVP_CIPHER_CTX_free", f, SymbolEffect::Release, lang);
        // BIO
        self.add_symbol("BIO_new", f, SymbolEffect::Acquire, lang);
        self.add_symbol("BIO_free", f, SymbolEffect::Release, lang);
        self.add_symbol("BIO_free_all", f, SymbolEffect::Release, lang);
        // RSA
        self.add_symbol("RSA_new", f, SymbolEffect::Acquire, lang);
        self.add_symbol("RSA_free", f, SymbolEffect::Release, lang);
        // BN (bignum)
        self.add_symbol("BN_new", f, SymbolEffect::Acquire, lang);
        self.add_symbol("BN_free", f, SymbolEffect::Release, lang);
        self.add_symbol("BN_clear_free", f, SymbolEffect::Release, lang);
    }

    /// Register SQLite resource family symbols.
    /// Evidence: `sqlite_binding.ll` — library-level resource pairing.
    fn add_sqlite_symbols(&mut self) {
        let f = FamilyId::SQLITE_RESOURCE;
        let lang = LanguageHint::C;
        self.add_symbol("sqlite3_open", f, SymbolEffect::Acquire, lang);
        self.add_symbol("sqlite3_open_v2", f, SymbolEffect::Acquire, lang);
        self.add_symbol("sqlite3_close", f, SymbolEffect::Release, lang);
        self.add_symbol("sqlite3_close_v2", f, SymbolEffect::Release, lang);
        self.add_symbol("sqlite3_prepare_v2", f, SymbolEffect::Acquire, lang);
        self.add_symbol("sqlite3_prepare_v3", f, SymbolEffect::Acquire, lang);
        self.add_symbol("sqlite3_finalize", f, SymbolEffect::Release, lang);
        self.add_symbol("sqlite3_free", f, SymbolEffect::Release, lang);
    }

    /// Register mimalloc family symbols.
    /// Evidence: `bun_alloc-ef7250b81132b4bd.ll` — Bun's custom allocator.
    fn add_mimalloc_symbols(&mut self) {
        let f = FamilyId::MIMALLOC;
        let lang = LanguageHint::C;
        self.add_symbol("mi_malloc", f, SymbolEffect::Acquire, lang);
        self.add_symbol("mi_free", f, SymbolEffect::Release, lang);
        self.add_symbol("mi_realloc", f, SymbolEffect::Acquire, lang);
        self.add_symbol("mi_heap_destroy", f, SymbolEffect::ConditionalRelease, lang);
        self.add_symbol("mi_calloc", f, SymbolEffect::Acquire, lang);
        self.add_symbol("mi_malloc_aligned", f, SymbolEffect::Acquire, lang);
    }

    /// Register C# COM interop family symbols.
    /// Evidence: `csharp_ffi_bugs.ll` — COM interop memory management.
    ///
    /// Note: CoTaskMemAlloc/CoTaskMemFree are already registered in
    /// add_csharp_symbols under CSHARP_COTASK. They must NOT be
    /// re-registered here under CSHARP_COM or the HashMap will overwrite
    /// the COTASK mapping, losing it entirely.
    fn add_csharp_com_symbols(&mut self) {
        // No COM-specific symbols currently — CoTaskMem* are in CSHARP_COTASK.
        // Future COM-specific allocators (e.g., CoCreateInstance) go here.
    }
}

impl Default for FamilyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_populated() {
        let registry = FamilyRegistry::new();
        assert!(
            registry.symbol_count() > 30,
            "Must have many built-in symbols"
        );
        assert_eq!(
            registry.family_count(),
            20,
            "Must have 20 built-in families"
        );
    }

    #[test]
    fn test_malloc_free_same_family() {
        let registry = FamilyRegistry::new();
        let malloc = registry
            .lookup("malloc")
            .expect("family_registry::test_malloc_free_same_family: malloc must be registered");
        let free = registry
            .lookup("free")
            .expect("family_registry::test_malloc_free_same_family: free must be registered");
        assert_eq!(
            malloc.family_id, free.family_id,
            "malloc and free must be same family"
        );
        assert!(
            registry.is_compatible_release(malloc.family_id, free.family_id),
            "malloc and free should be compatible release"
        );
    }

    #[test]
    fn test_malloc_delete_mismatch() {
        let registry = FamilyRegistry::new();
        let malloc = registry
            .lookup("malloc")
            .expect("family_registry::test_malloc_delete_mismatch: malloc must be registered");
        let del = registry.lookup("_ZdlPv").expect(
            "family_registry::test_malloc_delete_mismatch: operator delete must be registered",
        );
        assert_ne!(
            malloc.family_id, del.family_id,
            "malloc and delete must be different families"
        );
        assert!(
            !registry.is_compatible_release(malloc.family_id, del.family_id),
            "malloc and delete should NOT be compatible release"
        );
    }

    #[test]
    fn test_rust_alloc_c_free_mismatch() {
        let registry = FamilyRegistry::new();
        let rust_alloc = registry.lookup("__rust_alloc").expect(
            "family_registry::test_rust_alloc_c_free_mismatch: __rust_alloc must be registered",
        );
        let free = registry
            .lookup("free")
            .expect("family_registry::test_rust_alloc_c_free_mismatch: free must be registered");
        assert!(
            !registry.is_compatible_release(rust_alloc.family_id, free.family_id),
            "Rust alloc and C free should NOT be compatible release"
        );
    }

    #[test]
    fn test_pyobject_new_free_same_family() {
        let registry = FamilyRegistry::new();
        let new = registry.lookup("PyObject_New").expect(
            "family_registry::test_pyobject_new_free_same_family: PyObject_New must be registered",
        );
        let free = registry.lookup("PyObject_Free").expect(
            "family_registry::test_pyobject_new_free_same_family: PyObject_Free must be registered",
        );
        assert_eq!(
            new.family_id, free.family_id,
            "PyObject_New and PyObject_Free should be same family"
        );
    }

    #[test]
    fn test_pymem_malloc_pyobject_free_mismatch() {
        let registry = FamilyRegistry::new();
        let alloc = registry
            .lookup("PyMem_Malloc")
            .expect("family_registry::test_pymem_malloc_pyobject_free_mismatch: PyMem_Malloc must be registered");
        let free = registry
            .lookup("PyObject_Free")
            .expect("family_registry::test_pymem_malloc_pyobject_free_mismatch: PyObject_Free must be registered");
        assert_ne!(
            alloc.family_id, free.family_id,
            "PyMem_Malloc and PyObject_Free must be different families"
        );
    }

    #[test]
    fn test_py_decref_is_conditional_release() {
        let registry = FamilyRegistry::new();
        let decref = registry.lookup("Py_DECREF").expect(
            "family_registry::test_py_decref_is_conditional_release: Py_DECREF must be registered",
        );
        assert_eq!(
            decref.effect,
            SymbolEffect::ConditionalRelease,
            "Py_DECREF should be ConditionalRelease effect"
        );
    }

    #[test]
    fn test_py_incref_is_retain() {
        let registry = FamilyRegistry::new();
        let incref = registry
            .lookup("Py_INCREF")
            .expect("family_registry::test_py_incref_is_retain: Py_INCREF must be registered");
        assert_eq!(
            incref.effect,
            SymbolEffect::Retain,
            "Py_INCREF should be Retain effect"
        );
    }

    #[test]
    fn test_jni_local_global_ref_mismatch() {
        let registry = FamilyRegistry::new();
        let local = registry.lookup("NewLocalRef").expect(
            "family_registry::test_jni_local_global_ref_mismatch: NewLocalRef must be registered",
        );
        let global_del = registry
            .lookup("DeleteGlobalRef")
            .expect("family_registry::test_jni_local_global_ref_mismatch: DeleteGlobalRef must be registered");
        assert_ne!(
            local.family_id, global_del.family_id,
            "Local and global refs are different families"
        );
    }

    #[test]
    fn test_hglobal_cotask_mismatch() {
        let registry = FamilyRegistry::new();
        let hglobal = registry.lookup("AllocHGlobal").expect(
            "family_registry::test_hglobal_cotask_mismatch: AllocHGlobal must be registered",
        );
        let cotask = registry.lookup("CoTaskMemFree").expect(
            "family_registry::test_hglobal_cotask_mismatch: CoTaskMemFree must be registered",
        );
        assert_ne!(
            hglobal.family_id, cotask.family_id,
            "HGlobal and CoTaskMem are different families"
        );
    }

    #[test]
    fn test_cpp_new_array_delete_array_same() {
        let registry = FamilyRegistry::new();
        let new_arr = registry.lookup("_Znam").expect(
            "family_registry::test_cpp_new_array_delete_array_same: _Znam must be registered",
        );
        let del_arr = registry.lookup("_ZdaPv").expect(
            "family_registry::test_cpp_new_array_delete_array_same: _ZdaPv must be registered",
        );
        assert_eq!(
            new_arr.family_id, del_arr.family_id,
            "new[] and delete[] must be same family"
        );
    }
}
