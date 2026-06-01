//! SQLite FFI contract tests.

use super::super::super::database::FFIContractDB;
use super::super::super::types::{ContractSource, ContractType};

/// Objective: Verify that sqlite3_open is correctly registered as a SQLite allocator.
///
/// Invariants:
/// - sqlite3_open should be found in the database
/// - Contract type should be Allocator
/// - Source should be SQLite
/// - Paired release should include sqlite3_close
#[test]
fn test_sqlite3_open() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("sqlite3_open")
        .expect("ffi_contract::test::test_sqlite3_open: sqlite3_open not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert_eq!(
        c.source,
        ContractSource::SQLite,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"sqlite3_close".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that sqlite3_close is correctly registered as a SQLite deallocator.
///
/// Invariants:
/// - sqlite3_close should be found in the database
/// - Contract type should be Deallocator
/// - Source should be SQLite
#[test]
fn test_sqlite3_close() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("sqlite3_close")
        .expect("ffi_contract::test::test_sqlite3_close: sqlite3_close not found");
    assert_eq!(
        c.contract_type,
        ContractType::Deallocator,
        "Expected values to be equal"
    );
    assert_eq!(
        c.source,
        ContractSource::SQLite,
        "Expected values to be equal"
    );
}

/// Objective: Verify that sqlite3_exec is correctly registered as a SQLite borrower.
///
/// Invariants:
/// - sqlite3_exec should be found in the database
/// - Contract type should be Borrower
/// - Source should be SQLite
#[test]
fn test_sqlite3_exec() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("sqlite3_exec")
        .expect("ffi_contract::test::test_sqlite3_exec: sqlite3_exec not found");
    assert_eq!(
        c.contract_type,
        ContractType::Borrower,
        "Expected values to be equal"
    );
    assert_eq!(
        c.source,
        ContractSource::SQLite,
        "Expected values to be equal"
    );
}

/// Objective: Verify that sqlite3_prepare_v2 is correctly registered as a SQLite allocator.
///
/// Invariants:
/// - sqlite3_prepare_v2 should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include sqlite3_finalize
#[test]
fn test_sqlite3_prepare() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("sqlite3_prepare_v2")
        .expect("ffi_contract::test::test_sqlite3_prepare: sqlite3_prepare_v2 not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"sqlite3_finalize".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that sqlite3_finalize is correctly registered as a SQLite deallocator.
///
/// Invariants:
/// - sqlite3_finalize should be found in the database
/// - Contract type should be Deallocator
#[test]
fn test_sqlite3_finalize() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("sqlite3_finalize")
        .expect("ffi_contract::test::test_sqlite3_finalize: sqlite3_finalize not found");
    assert_eq!(
        c.contract_type,
        ContractType::Deallocator,
        "Expected values to be equal"
    );
}

/// Objective: Verify that sqlite3_column_text is correctly registered as a SQLite borrower.
///
/// Invariants:
/// - sqlite3_column_text should be found in the database
/// - Contract type should be Borrower
#[test]
fn test_sqlite3_column_text() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("sqlite3_column_text")
        .expect("ffi_contract::test::test_sqlite3_column_text: sqlite3_column_text not found");
    assert_eq!(
        c.contract_type,
        ContractType::Borrower,
        "Expected values to be equal"
    );
}
