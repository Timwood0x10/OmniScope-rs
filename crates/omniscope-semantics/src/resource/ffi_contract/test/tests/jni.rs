//! JNI FFI contract tests.

use super::super::super::database::FFIContractDB;
use super::super::super::types::{ContractSource, ContractType};

/// Objective: Verify that FindClass is correctly registered as a JNI allocator.
///
/// Invariants:
/// - FindClass should be found in the database
/// - Contract type should be Allocator
/// - Source should be JNI
/// - Paired release should include DeleteLocalRef
#[test]
fn test_jni_find_class() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("FindClass")
        .expect("ffi_contract::test::test_jni_find_class: FindClass not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert_eq!(c.source, ContractSource::JNI);
    assert!(c.paired_release.contains(&"DeleteLocalRef".to_string()));
}

/// Objective: Verify that NewStringUTF is correctly registered as a JNI allocator.
///
/// Invariants:
/// - NewStringUTF should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include DeleteLocalRef
#[test]
fn test_jni_new_string() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("NewStringUTF")
        .expect("ffi_contract::test::test_jni_new_string: NewStringUTF not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"DeleteLocalRef".to_string()));
}

/// Objective: Verify that NewObject is correctly registered as a JNI allocator.
///
/// Invariants:
/// - NewObject should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include DeleteLocalRef
#[test]
fn test_jni_new_object() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("NewObject")
        .expect("ffi_contract::test::test_jni_new_object: NewObject not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"DeleteLocalRef".to_string()));
}

/// Objective: Verify that DeleteLocalRef is correctly registered as a JNI deallocator.
///
/// Invariants:
/// - DeleteLocalRef should be found in the database
/// - Contract type should be Deallocator
#[test]
fn test_jni_delete_local_ref() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("DeleteLocalRef")
        .expect("ffi_contract::test::test_jni_delete_local_ref: DeleteLocalRef not found");
    assert_eq!(c.contract_type, ContractType::Deallocator);
}

/// Objective: Verify that NewGlobalRef is correctly registered as a JNI allocator.
///
/// Invariants:
/// - NewGlobalRef should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include DeleteGlobalRef
#[test]
fn test_jni_new_global_ref() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("NewGlobalRef")
        .expect("ffi_contract::test::test_jni_new_global_ref: NewGlobalRef not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"DeleteGlobalRef".to_string()));
}
