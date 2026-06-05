//! Type Semantic — what Rust type concept does this represent?
//!
//! This module provides the `TypeSemantic` enum for classifying
//! Rust types based on their semantic properties that affect FFI safety.

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
        matches!(self, TypeSemantic::InteriorMutability | TypeSemantic::Once)
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
        // OnceCell<T> — one-time write ("OnceCell" = 8 bytes, "OnceLock" = 8 bytes)
        if name.contains("4cell8OnceCell") || name.contains("4cell8OnceLock") {
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
        // sync::once — one-time initialization ("OnceLock" = 8 bytes, "once" = 4 bytes)
        if name.contains("4sync4once")
            || name.contains("4sync8OnceLock")
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
