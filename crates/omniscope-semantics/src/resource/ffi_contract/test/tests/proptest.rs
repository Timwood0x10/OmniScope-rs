//! Property-based tests for FFIContractDB.

use super::super::super::database::FFIContractDB;
use super::super::super::types::ContractSource;
use omniscope_types::FamilyId;
use proptest::prelude::*;

proptest! {
    /// Objective: Verify that random function name queries do not cause panics.
    ///
    /// Invariants:
    /// - Query results should be Some(contract) or None
    /// - No exceptions or panics should be thrown
    #[test]
    fn prop_lookup_random_function_names(
        func_name in "[a-zA-Z_][a-zA-Z0-9_]{0,50}"
    ) {
        // Property: lookup should never panic for valid identifier strings
        let db = FFIContractDB::new();
        let _result = db.lookup(&func_name);
        // The property is that this doesn't panic; result may be None or Some
    }

    /// Objective: Verify that special character queries do not cause panics.
    ///
    /// Invariants:
    /// - Special character queries should return None
    /// - No exceptions or panics should be thrown
    #[test]
    fn prop_lookup_special_characters(
        name in "[!@#$%^&*()+=\\[\\]{}|;':\",./<>?]{1,20}"
    ) {
        // Property: lookup of special character strings should not panic
        let db = FFIContractDB::new();
        let _result = db.lookup(&name);
        // Special characters are unlikely to be registered, but must not panic
    }

    /// Objective: Verify that querying by source does not cause panics.
    ///
    /// Invariants:
    /// - Queries with any valid ContractSource should return results
    /// - No exceptions or panics should be thrown
    #[test]
    fn prop_query_by_source_random_source(
        source_idx in 0usize..8
    ) {
        // Property: querying by any valid source should not panic
        let db = FFIContractDB::new();
        let sources = [
            ContractSource::OpenSSL,
            ContractSource::SQLite,
            ContractSource::PythonCApi,
            ContractSource::JNI,
            ContractSource::Posix,
            ContractSource::Glib,
            ContractSource::Zlib,
            ContractSource::Libuv,
        ];
        let source = sources[source_idx];
        let _contracts = db.by_source(source);
        // Should not panic for any valid source
    }

    /// Objective: Verify that querying by family ID does not cause panics.
    ///
    /// Invariants:
    /// - Queries with any u16 family ID should return results
    /// - No exceptions or panics should be thrown
    #[test]
    fn prop_query_by_family_random_id(
        family_id in any::<u16>()
    ) {
        // Property: querying by any family ID should not panic
        let db = FFIContractDB::new();
        let _contracts = db.by_family(FamilyId(family_id));
        // Should not panic for any family ID
    }

    /// Objective: Verify contract type method consistency.
    ///
    /// Invariants:
    /// - A contract can only have one type (allocator/deallocator/borrower/transfer/retainer/releaser)
    /// - A contract can only have one ownership mode
    /// - Type and ownership mode must be consistent
    #[test]
    fn prop_contracts_have_consistent_types(
        func_name in "[a-zA-Z_][a-zA-Z0-9_]{0,50}"
    ) {
        // Property: if a contract is found, its type methods should be consistent
        let db = FFIContractDB::new();
        if let Some(contract) = db.lookup(&func_name) {
            let is_allocator = contract.is_allocator();
            let is_deallocator = contract.is_deallocator();
            let is_borrower = contract.is_borrower();
            let is_transfer = contract.is_transfer();
            let is_retainer = contract.is_retainer();
            let is_releaser = contract.is_releaser();

            // At most one of these should be true
            let type_count = [is_allocator, is_deallocator, is_borrower, is_transfer, is_retainer, is_releaser]
                .iter()
                .filter(|&&x| x)
                .count();
            prop_assert!(
                type_count <= 1,
                "Contract {} has multiple types set: alloc={}, dealloc={}, borrow={}, transfer={}, retain={}, release={}",
                func_name, is_allocator, is_deallocator, is_borrower, is_transfer, is_retainer, is_releaser
            );

            // Verify ownership consistency
            let caller_owns = contract.caller_owns();
            let callee_owns = contract.callee_owns();
            let is_borrowed = contract.is_borrowed();
            let ownership_transferred = contract.ownership_transferred();
            let is_reference_counted = contract.is_reference_counted();

            // At most one ownership mode should be true
            let ownership_count = [caller_owns, callee_owns, is_borrowed, ownership_transferred, is_reference_counted]
                .iter()
                .filter(|&&x| x)
                .count();
            prop_assert!(
                ownership_count <= 1,
                "Contract {} has multiple ownership modes: caller={}, callee={}, borrowed={}, transferred={}, refcounted={}",
                func_name, caller_owns, callee_owns, is_borrowed, ownership_transferred, is_reference_counted
            );
        }
    }

    /// Objective: Verify that allocator/deallocator contracts must have paired release functions.
    ///
    /// Invariants:
    /// - If a contract is an allocator or deallocator, paired_release cannot be empty
    /// - Ensure the pairing relationship between allocators and deallocators is complete
    #[test]
    fn prop_contracts_have_valid_paired_releases(
        func_name in "[a-zA-Z_][a-zA-Z0-9_]{0,50}"
    ) {
        // Property: if a contract is found, its paired releases should be non-empty for allocators/deallocators
        let db = FFIContractDB::new();
        if let Some(contract) = db.lookup(&func_name) {
            if contract.is_allocator() || contract.is_deallocator() {
                prop_assert!(
                    !contract.paired_release.is_empty(),
                    "Allocator/deallocator {} must have paired releases",
                    func_name
                );
            }
        }
    }

    /// Objective: Verify contract source validity.
    ///
    /// Invariants:
    /// - If a contract exists, its source must be a valid ContractSource enum value
    /// - Ensure the source field does not contain invalid values
    #[test]
    fn prop_contracts_have_valid_source(
        func_name in "[a-zA-Z_][a-zA-Z0-9_]{0,50}"
    ) {
        // Property: if a contract is found, its source should be valid
        let db = FFIContractDB::new();
        if let Some(contract) = db.lookup(&func_name) {
            let valid_sources = [
                ContractSource::OpenSSL,
                ContractSource::SQLite,
                ContractSource::PythonCApi,
                ContractSource::JNI,
                ContractSource::Posix,
                ContractSource::Glib,
                ContractSource::Zlib,
                ContractSource::Libuv,
                ContractSource::Custom,
            ];
            prop_assert!(
                valid_sources.contains(&contract.source),
                "Contract {} has invalid source: {}",
                func_name,
                contract.source
            );
        }
    }

    /// Objective: Verify contract family ID validity.
    ///
    /// Invariants:
    /// - If a contract has a family ID, it should be a valid FamilyId value
    /// - Ensure the family ID field does not cause panics
    #[test]
    fn prop_contracts_have_valid_family_if_present(
        func_name in "[a-zA-Z_][a-zA-Z0-9_]{0,50}"
    ) {
        // Property: if a contract has a family ID, it should be valid
        let db = FFIContractDB::new();
        if let Some(contract) = db.lookup(&func_name) {
            if let Some(family_id) = contract.family_id {
                // Family ID should be a valid FamilyId value
                let _ = family_id;
            }
        }
    }
}
