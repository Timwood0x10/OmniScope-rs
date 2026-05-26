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
}

/// Registry mapping symbol names to resource families.
///
/// Built-in entries cover C, C++, Rust, Python, Java/JNI, C#, Go, and Zig
/// allocation/deallocation functions. User-inferred entries can be added
/// from model mining (Phase 7).
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
        // Python C API
        self.add_python_symbols();
        // Java/JNI
        self.add_jni_symbols();
        // C#/.NET
        self.add_csharp_symbols();
        // Go
        self.add_go_symbols();
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
    }

    fn add_python_symbols(&mut self) {
        let lang = LanguageHint::Python;
        // Python object family
        let obj = FamilyId::PYTHON_OBJECT;
        for sym in &["PyObject_New", "PyObject_NewVar", "PyType_GenericAlloc"] {
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
        // Python mem family
        let mem = FamilyId::PYTHON_MEM;
        for sym in &["PyMem_Malloc", "PyMem_Calloc", "PyMem_Realloc"] {
            self.add_symbol(sym, mem, SymbolEffect::Acquire, lang);
        }
        self.add_symbol("PyMem_Free", mem, SymbolEffect::Release, lang);
        // Python raw mem family
        let raw = FamilyId::PYTHON_MEM_RAW;
        for sym in &["PyMem_RawMalloc", "PyMem_RawCalloc", "PyMem_RawRealloc"] {
            self.add_symbol(sym, raw, SymbolEffect::Acquire, lang);
        }
        self.add_symbol("PyMem_RawFree", raw, SymbolEffect::Release, lang);
    }

    fn add_jni_symbols(&mut self) {
        let lang = LanguageHint::Java;
        self.add_symbol(
            "NewLocalRef",
            FamilyId::JAVA_LOCAL_REF,
            SymbolEffect::Acquire,
            lang,
        );
        self.add_symbol(
            "DeleteLocalRef",
            FamilyId::JAVA_LOCAL_REF,
            SymbolEffect::Release,
            lang,
        );
        self.add_symbol(
            "NewGlobalRef",
            FamilyId::JAVA_GLOBAL_REF,
            SymbolEffect::Acquire,
            lang,
        );
        self.add_symbol(
            "DeleteGlobalRef",
            FamilyId::JAVA_GLOBAL_REF,
            SymbolEffect::Release,
            lang,
        );
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
            13,
            "Must have 13 built-in families"
        );
    }

    #[test]
    fn test_malloc_free_same_family() {
        let registry = FamilyRegistry::new();
        let malloc = registry
            .lookup("malloc")
            .expect("malloc must be registered");
        let free = registry.lookup("free").expect("free must be registered");
        assert_eq!(
            malloc.family_id, free.family_id,
            "malloc and free must be same family"
        );
        assert!(registry.is_compatible_release(malloc.family_id, free.family_id));
    }

    #[test]
    fn test_malloc_delete_mismatch() {
        let registry = FamilyRegistry::new();
        let malloc = registry
            .lookup("malloc")
            .expect("malloc must be registered");
        let del = registry
            .lookup("_ZdlPv")
            .expect("operator delete must be registered");
        assert_ne!(
            malloc.family_id, del.family_id,
            "malloc and delete must be different families"
        );
        assert!(!registry.is_compatible_release(malloc.family_id, del.family_id));
    }

    #[test]
    fn test_rust_alloc_c_free_mismatch() {
        let registry = FamilyRegistry::new();
        let rust_alloc = registry
            .lookup("__rust_alloc")
            .expect("__rust_alloc must be registered");
        let free = registry.lookup("free").expect("free must be registered");
        assert!(!registry.is_compatible_release(rust_alloc.family_id, free.family_id));
    }

    #[test]
    fn test_pyobject_new_free_same_family() {
        let registry = FamilyRegistry::new();
        let new = registry
            .lookup("PyObject_New")
            .expect("PyObject_New must be registered");
        let free = registry
            .lookup("PyObject_Free")
            .expect("PyObject_Free must be registered");
        assert_eq!(new.family_id, free.family_id);
    }

    #[test]
    fn test_pymem_malloc_pyobject_free_mismatch() {
        let registry = FamilyRegistry::new();
        let alloc = registry
            .lookup("PyMem_Malloc")
            .expect("PyMem_Malloc must be registered");
        let free = registry
            .lookup("PyObject_Free")
            .expect("PyObject_Free must be registered");
        assert_ne!(
            alloc.family_id, free.family_id,
            "PyMem_Malloc and PyObject_Free must be different families"
        );
    }

    #[test]
    fn test_py_decref_is_conditional_release() {
        let registry = FamilyRegistry::new();
        let decref = registry
            .lookup("Py_DECREF")
            .expect("Py_DECREF must be registered");
        assert_eq!(decref.effect, SymbolEffect::ConditionalRelease);
    }

    #[test]
    fn test_py_incref_is_retain() {
        let registry = FamilyRegistry::new();
        let incref = registry
            .lookup("Py_INCREF")
            .expect("Py_INCREF must be registered");
        assert_eq!(incref.effect, SymbolEffect::Retain);
    }

    #[test]
    fn test_jni_local_global_ref_mismatch() {
        let registry = FamilyRegistry::new();
        let local = registry
            .lookup("NewLocalRef")
            .expect("NewLocalRef must be registered");
        let global_del = registry
            .lookup("DeleteGlobalRef")
            .expect("DeleteGlobalRef must be registered");
        assert_ne!(
            local.family_id, global_del.family_id,
            "Local and global refs are different families"
        );
    }

    #[test]
    fn test_hglobal_cotask_mismatch() {
        let registry = FamilyRegistry::new();
        let hglobal = registry
            .lookup("AllocHGlobal")
            .expect("AllocHGlobal must be registered");
        let cotask = registry
            .lookup("CoTaskMemFree")
            .expect("CoTaskMemFree must be registered");
        assert_ne!(
            hglobal.family_id, cotask.family_id,
            "HGlobal and CoTaskMem are different families"
        );
    }

    #[test]
    fn test_cpp_new_array_delete_array_same() {
        let registry = FamilyRegistry::new();
        let new_arr = registry.lookup("_Znam").expect("_Znam must be registered");
        let del_arr = registry
            .lookup("_ZdaPv")
            .expect("_ZdaPv must be registered");
        assert_eq!(
            new_arr.family_id, del_arr.family_id,
            "new[] and delete[] must be same family"
        );
    }
}
