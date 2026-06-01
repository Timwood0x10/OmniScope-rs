//! POSIX FFI contract tests.

use super::super::super::database::FFIContractDB;
use super::super::super::types::{ContractSource, ContractType, OwnershipSemantics};

/// Objective: Verify that malloc is correctly registered as a POSIX allocator.
///
/// Invariants:
/// - malloc should be found in the database
/// - Contract type should be Allocator
/// - Source should be Posix
/// - Paired release should include free
/// - Ownership semantics should be CallerOwns
#[test]
fn test_malloc() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("malloc")
        .expect("ffi_contract::test::test_malloc: malloc not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert_eq!(
        c.source,
        ContractSource::Posix,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"free".to_string()),
        "Expected condition to be true"
    );
    assert_eq!(
        c.ownership,
        OwnershipSemantics::CallerOwns,
        "Expected values to be equal"
    );
}

/// Objective: Verify that free is correctly registered as a POSIX deallocator.
///
/// Invariants:
/// - free should be found in the database
/// - Contract type should be Deallocator
/// - Source should be Posix
#[test]
fn test_free() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("free")
        .expect("ffi_contract::test::test_free: free not found");
    assert_eq!(
        c.contract_type,
        ContractType::Deallocator,
        "Expected values to be equal"
    );
    assert_eq!(
        c.source,
        ContractSource::Posix,
        "Expected values to be equal"
    );
}

/// Objective: Verify that calloc is correctly registered as a POSIX allocator.
///
/// Invariants:
/// - calloc should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include free
#[test]
fn test_calloc() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("calloc")
        .expect("ffi_contract::test::test_calloc: calloc not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"free".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that realloc is correctly registered as a POSIX allocator.
///
/// Invariants:
/// - realloc should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include free
#[test]
fn test_realloc() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("realloc")
        .expect("ffi_contract::test::test_realloc: realloc not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"free".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that strdup is correctly registered as a POSIX allocator.
///
/// Invariants:
/// - strdup should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include free
#[test]
fn test_strdup() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("strdup")
        .expect("ffi_contract::test::test_strdup: strdup not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"free".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that strndup is correctly registered as a POSIX allocator.
///
/// Invariants:
/// - strndup should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include free
#[test]
fn test_strndup() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("strndup")
        .expect("ffi_contract::test::test_strndup: strndup not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"free".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that open is correctly registered as a POSIX allocator.
///
/// Invariants:
/// - open should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include close
#[test]
fn test_open() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("open")
        .expect("ffi_contract::test::test_open: open not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"close".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that close is correctly registered as a POSIX deallocator.
///
/// Invariants:
/// - close should be found in the database
/// - Contract type should be Deallocator
#[test]
fn test_close() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("close")
        .expect("ffi_contract::test::test_close: close not found");
    assert_eq!(
        c.contract_type,
        ContractType::Deallocator,
        "Expected values to be equal"
    );
}

/// Objective: Verify that socket is correctly registered as a POSIX allocator.
///
/// Invariants:
/// - socket should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include close
#[test]
fn test_socket() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("socket")
        .expect("ffi_contract::test::test_socket: socket not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"close".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that fopen is correctly registered as a POSIX allocator.
///
/// Invariants:
/// - fopen should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include fclose
#[test]
fn test_fopen() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("fopen")
        .expect("ffi_contract::test::test_fopen: fopen not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"fclose".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that fclose is correctly registered as a POSIX deallocator.
///
/// Invariants:
/// - fclose should be found in the database
/// - Contract type should be Deallocator
#[test]
fn test_fclose() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("fclose")
        .expect("ffi_contract::test::test_fclose: fclose not found");
    assert_eq!(
        c.contract_type,
        ContractType::Deallocator,
        "Expected values to be equal"
    );
}
