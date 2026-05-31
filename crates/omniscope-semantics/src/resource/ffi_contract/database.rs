//! FFI contract database implementation.
//!
//! This module implements the FFI contract database, providing storage,
//! lookup, and querying capabilities for FFI function contracts.

use std::collections::HashMap;

use omniscope_types::FamilyId;

use super::builtin::register_builtin_contracts;
use super::types::{ContractSource, FFIContract};

/// FFI contract database for memory management semantics.
///
/// Contains contracts for common FFI libraries with accurate memory
/// management semantics. The database is pre-populated with contracts
/// for OpenSSL, SQLite, Python C API, JNI, POSIX, and other common libraries.
#[derive(Debug, Clone)]
pub struct FFIContractDB {
    /// Contracts indexed by function name.
    contracts: HashMap<String, FFIContract>,
    /// Contracts grouped by source library.
    by_source: HashMap<ContractSource, Vec<String>>,
    /// Contracts grouped by family ID.
    by_family: HashMap<FamilyId, Vec<String>>,
}

impl FFIContractDB {
    /// Creates a new FFI contract database with built-in contracts.
    pub fn new() -> Self {
        let mut db = Self {
            contracts: HashMap::new(),
            by_source: HashMap::new(),
            by_family: HashMap::new(),
        };
        register_builtin_contracts(&mut db);
        db
    }

    /// Registers a new FFI contract in the database.
    pub fn register(&mut self, contract: FFIContract) {
        let name = contract.function_name.clone();
        let source = contract.source;
        let family_id = contract.family_id;

        // Index by source
        self.by_source.entry(source).or_default().push(name.clone());

        // Index by family
        if let Some(family) = family_id {
            self.by_family.entry(family).or_default().push(name.clone());
        }

        // Store contract
        self.contracts.insert(name, contract);
    }

    /// Looks up a contract by function name.
    pub fn lookup(&self, function_name: &str) -> Option<&FFIContract> {
        self.contracts.get(function_name)
    }

    /// Returns all contracts for a given source library.
    pub fn by_source(&self, source: ContractSource) -> Vec<&FFIContract> {
        self.by_source
            .get(&source)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|name| self.contracts.get(name))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all contracts for a given family ID.
    pub fn by_family(&self, family_id: FamilyId) -> Vec<&FFIContract> {
        self.by_family
            .get(&family_id)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|name| self.contracts.get(name))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all allocators in the database.
    pub fn allocators(&self) -> Vec<&FFIContract> {
        self.contracts
            .values()
            .filter(|c| c.is_allocator())
            .collect()
    }

    /// Returns all deallocators in the database.
    pub fn deallocators(&self) -> Vec<&FFIContract> {
        self.contracts
            .values()
            .filter(|c| c.is_deallocator())
            .collect()
    }

    /// Returns all error-prone contracts.
    pub fn error_prone(&self) -> Vec<&FFIContract> {
        self.contracts.values().filter(|c| c.error_prone).collect()
    }

    /// Returns the number of contracts in the database.
    pub fn len(&self) -> usize {
        self.contracts.len()
    }

    /// Returns true if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.contracts.is_empty()
    }
}

impl Default for FFIContractDB {
    fn default() -> Self {
        Self::new()
    }
}
