//! Structural inference modules for Phase 4 of the Resource Contract architecture.
//!
//! These inference patterns replace language-specific suppression. They produce
//! summaries and evidence, not directly suppress issues.
//!
//! - `destructor_inference`: Infers destructor/drop/dispose summaries from
//!   naming patterns and call behavior.
//! - `bridge_inference`: Infers borrowed-return summaries for pointer projection
//!   helpers (as_ptr, getelementptr-only bodies).
//! - `refcount_inference`: Infers conditional release for refcount decrement
//!   semantics (Py_DECREF, Arc::drop, CFRelease, etc).
//! - `static_lifetime_inference`: Infers static-lifetime sink for resources
//!   initialized once and stored in global/static storage.
//!
//! ## New from bun_fp_reduction_plan (R-0~R-6)
//!
//! - `param_attr_inference`: R-0 — LLVM readonly/noalias parameter attribute
//!   detection. Primary signal for write_to_immutable FP elimination.
//! - `into_raw_inference`: R-6 — Box/CString/Vec::into_raw ownership transfer.
//!   Eliminates cross_language_free FP for intentional ownership transfer.
//! - `posix_syscall_inference`: R-4 — POSIX syscall semantic classification.
//!   File/network/process ops are not memory management.
//! - `drop_glue_inference`: R-3 — RAII drop glue/tail dealloc detection.
//!   Compiler-inserted cleanup is not a user bug.
//! - `library_alloc_pairs_inference`: R-7 — library-level allocator pair
//!   detection (mimalloc/zlib/openssl/sqlite/cgo/JNI/Python).
//!   Complements R-4 POSIX — covers third-party library APIs.

pub mod bridge_inference;
pub mod destructor_inference;
pub mod drop_glue_inference;
pub mod into_raw_inference;
pub mod library_alloc_pairs_inference;
pub mod param_attr_inference;
pub mod posix_syscall_inference;
pub mod refcount_inference;
pub mod static_lifetime_inference;

pub use bridge_inference::{infer_bridge_summary, BridgeInferenceResult, BridgeKind};
pub use destructor_inference::{
    infer_destructor_summary, DestructorInferenceResult, DestructorKind,
};
pub use drop_glue_inference::{
    infer_drop_glue_summary, is_tail_position_dealloc, DropGlueInferenceResult, DropGlueKind,
};
pub use into_raw_inference::{infer_into_raw_summary, IntoRawInferenceResult, IntoRawKind};
pub use library_alloc_pairs_inference::{
    infer_library_alloc_summary, lookup_library_alloc, LibraryAllocEffect, LibraryAllocEntry,
    LibraryAllocInferenceResult,
};
pub use param_attr_inference::{
    infer_param_attr_summary, ParamAttrInferenceResult, ParamMutability,
};
pub use posix_syscall_inference::{
    infer_posix_syscall_summary, PosixSyscallCategory, PosixSyscallInferenceResult,
};
pub use refcount_inference::{
    infer_refcount_release_summary, RefcountInferenceResult, RefcountKind,
};
pub use static_lifetime_inference::{
    infer_static_lifetime_summary, lifetime_domain_for, pointer_contract_for,
    StaticLifetimeInferenceResult, StaticLifetimeKind,
};
