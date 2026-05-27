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

pub mod bridge_inference;
pub mod destructor_inference;
pub mod refcount_inference;
pub mod static_lifetime_inference;

pub use bridge_inference::{infer_bridge_summary, BridgeInferenceResult, BridgeKind};
pub use destructor_inference::{
    infer_destructor_summary, DestructorInferenceResult, DestructorKind,
};
pub use refcount_inference::{
    infer_refcount_release_summary, RefcountInferenceResult, RefcountKind,
};
pub use static_lifetime_inference::{
    infer_static_lifetime_summary, lifetime_domain_for, pointer_contract_for,
    StaticLifetimeInferenceResult, StaticLifetimeKind,
};
