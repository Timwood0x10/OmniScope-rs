//! Semantic Node — a single semantic annotation for an IR element
//!
//! This module provides the `SemanticNode` struct for annotating
//! IR elements with semantic information.

use super::kind::SemanticResolution;
use super::provenance::PointerProvenance;
use super::syscall::SyscallSemantic;
use super::type_semantic::TypeSemantic;

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
