//! GLib FFI contract tests.

use super::super::super::database::FFIContractDB;
use super::super::super::types::{ContractSource, ContractType};

/// Objective: Verify that g_malloc is correctly registered as a GLib allocator.
///
/// Invariants:
/// - g_malloc should be found in the database
/// - Contract type should be Allocator
/// - Source should be Glib
/// - Paired release should include g_free
#[test]
fn test_g_malloc() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("g_malloc")
        .expect("ffi_contract::test::test_g_malloc: g_malloc not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert_eq!(c.source, ContractSource::Glib);
    assert!(c.paired_release.contains(&"g_free".to_string()));
}

/// Objective: Verify that g_new is correctly registered as a GLib allocator.
///
/// Invariants:
/// - g_new should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include g_free
#[test]
fn test_g_new() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("g_new")
        .expect("ffi_contract::test::test_g_new: g_new not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"g_free".to_string()));
}

/// Objective: Verify that g_strdup is correctly registered as a GLib allocator.
///
/// Invariants:
/// - g_strdup should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include g_free
#[test]
fn test_g_strdup() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("g_strdup")
        .expect("ffi_contract::test::test_g_strdup: g_strdup not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"g_free".to_string()));
}

/// Objective: Verify that g_free is correctly registered as a GLib deallocator.
///
/// Invariants:
/// - g_free should be found in the database
/// - Contract type should be Deallocator
#[test]
fn test_g_free() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("g_free")
        .expect("ffi_contract::test::test_g_free: g_free not found");
    assert_eq!(c.contract_type, ContractType::Deallocator);
}

/// Objective: Verify that g_object_ref is correctly registered as a GLib retainer.
///
/// Invariants:
/// - g_object_ref should be found in the database
/// - Contract type should be Retainer
/// - Paired release should include g_object_unref
#[test]
fn test_g_object_ref() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("g_object_ref")
        .expect("ffi_contract::test::test_g_object_ref: g_object_ref not found");
    assert_eq!(c.contract_type, ContractType::Retainer);
    assert!(c.paired_release.contains(&"g_object_unref".to_string()));
}

/// Objective: Verify that g_object_unref is correctly registered as a GLib releaser.
///
/// Invariants:
/// - g_object_unref should be found in the database
/// - Contract type should be Releaser
#[test]
fn test_g_object_unref() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("g_object_unref")
        .expect("ffi_contract::test::test_g_object_unref: g_object_unref not found");
    assert_eq!(c.contract_type, ContractType::Releaser);
}
