//! libuv FFI contract tests.

use super::super::super::database::FFIContractDB;
use super::super::super::types::{ContractSource, ContractType};

/// Objective: Verify that uv_loop_init is correctly registered as a libuv allocator.
///
/// Invariants:
/// - uv_loop_init should be found in the database
/// - Contract type should be Allocator
/// - Source should be Libuv
/// - Paired release should include uv_loop_close
#[test]
fn test_uv_loop_init() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("uv_loop_init")
        .expect("ffi_contract::test::test_uv_loop_init: uv_loop_init not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert_eq!(c.source, ContractSource::Libuv);
    assert!(c.paired_release.contains(&"uv_loop_close".to_string()));
}

/// Objective: Verify that uv_loop_close is correctly registered as a libuv deallocator.
///
/// Invariants:
/// - uv_loop_close should be found in the database
/// - Contract type should be Deallocator
#[test]
fn test_uv_loop_close() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("uv_loop_close")
        .expect("ffi_contract::test::test_uv_loop_close: uv_loop_close not found");
    assert_eq!(c.contract_type, ContractType::Deallocator);
}

/// Objective: Verify that uv_tcp_init is correctly registered as a libuv allocator.
///
/// Invariants:
/// - uv_tcp_init should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include uv_close
#[test]
fn test_uv_tcp_init() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("uv_tcp_init")
        .expect("ffi_contract::test::test_uv_tcp_init: uv_tcp_init not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"uv_close".to_string()));
}

/// Objective: Verify that uv_timer_init is correctly registered as a libuv allocator.
///
/// Invariants:
/// - uv_timer_init should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include uv_close
#[test]
fn test_uv_timer_init() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("uv_timer_init")
        .expect("ffi_contract::test::test_uv_timer_init: uv_timer_init not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"uv_close".to_string()));
}

/// Objective: Verify that uv_close is correctly registered as a libuv deallocator.
///
/// Invariants:
/// - uv_close should be found in the database
/// - Contract type should be Deallocator
#[test]
fn test_uv_close() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("uv_close")
        .expect("ffi_contract::test::test_uv_close: uv_close not found");
    assert_eq!(c.contract_type, ContractType::Deallocator);
}
