//! FFI contract database for memory management semantics.
//!
//! This module provides a comprehensive database of FFI function contracts,
//! describing memory management semantics for common libraries. Each contract
//! defines the allocation/deallocation pairing, ownership semantics, and
//! error-prone patterns for FFI functions.
//!
//! The database is used to enhance resource contract analysis by providing
//! accurate ownership semantics for FFI functions that cannot be inferred
//! from IR alone.
//!
//! ## Design Principles
//!
//! 1. **Completeness**: Cover all common FFI libraries with known memory management
//! 2. **Accuracy**: Each contract is based on official documentation or empirical evidence
//! 3. **Extensibility**: Easy to add new contracts for additional libraries
//! 4. **Performance**: Fast lookup for real-time analysis

mod builtin;
mod database;
mod test;
mod types;

pub use database::FFIContractDB;
pub use types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};
