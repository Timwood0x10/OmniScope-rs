//! Pointer provenance — where does this pointer come from?
//!
//! This module provides the `PointerProvenance` enum for classifying
//! the origin of pointer values in LLVM IR, based on Rustonomicon
//! ownership model concepts.

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
