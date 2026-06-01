//! Python/C API FFI contract tests.

use super::super::super::database::FFIContractDB;
use super::super::super::types::{ContractSource, ContractType, OwnershipSemantics};

/// Objective: Verify that PyObject_New is correctly registered as a Python/C API allocator.
///
/// Invariants:
/// - PyObject_New should be found in the database
/// - Contract type should be Allocator
/// - Source should be PythonCApi
/// - Paired release should include Py_DECREF
/// - Ownership semantics should be ReferenceCounted
#[test]
fn test_pyobject_new() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("PyObject_New")
        .expect("ffi_contract::test::test_pyobject_new: PyObject_New not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert_eq!(
        c.source,
        ContractSource::PythonCApi,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"Py_DECREF".to_string()),
        "Expected condition to be true"
    );
    assert_eq!(
        c.ownership,
        OwnershipSemantics::ReferenceCounted,
        "Expected values to be equal"
    );
}

/// Objective: Verify that Py_BuildValue is correctly registered as a Python/C API allocator.
///
/// Invariants:
/// - Py_BuildValue should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include Py_DECREF
#[test]
fn test_py_buildvalue() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("Py_BuildValue")
        .expect("ffi_contract::test::test_py_buildvalue: Py_BuildValue not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"Py_DECREF".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that PyUnicode_FromString is correctly registered as a Python/C API allocator.
///
/// Invariants:
/// - PyUnicode_FromString should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include Py_DECREF
#[test]
fn test_py_unicode() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("PyUnicode_FromString")
        .expect("ffi_contract::test::test_py_unicode: PyUnicode_FromString not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"Py_DECREF".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that PyBytes_FromString is correctly registered as a Python/C API allocator.
///
/// Invariants:
/// - PyBytes_FromString should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include Py_DECREF
#[test]
fn test_py_bytes() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("PyBytes_FromString")
        .expect("ffi_contract::test::test_py_bytes: PyBytes_FromString not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"Py_DECREF".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that PyList_New is correctly registered as a Python/C API allocator.
///
/// Invariants:
/// - PyList_New should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include Py_DECREF
#[test]
fn test_py_list() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("PyList_New")
        .expect("ffi_contract::test::test_py_list: PyList_New not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"Py_DECREF".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that PyDict_New is correctly registered as a Python/C API allocator.
///
/// Invariants:
/// - PyDict_New should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include Py_DECREF
#[test]
fn test_py_dict() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("PyDict_New")
        .expect("ffi_contract::test::test_py_dict: PyDict_New not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"Py_DECREF".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that Py_INCREF is correctly registered as a Python/C API retainer.
///
/// Invariants:
/// - Py_INCREF should be found in the database
/// - Contract type should be Retainer
/// - Paired release should include Py_DECREF
#[test]
fn test_py_incref() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("Py_INCREF")
        .expect("ffi_contract::test::test_py_incref: Py_INCREF not found");
    assert_eq!(
        c.contract_type,
        ContractType::Retainer,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"Py_DECREF".to_string()),
        "Expected condition to be true"
    );
}

/// Objective: Verify that Py_DECREF is correctly registered as a Python/C API releaser.
///
/// Invariants:
/// - Py_DECREF should be found in the database
/// - Contract type should be Releaser
#[test]
fn test_py_decref() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("Py_DECREF")
        .expect("ffi_contract::test::test_py_decref: Py_DECREF not found");
    assert_eq!(
        c.contract_type,
        ContractType::Releaser,
        "Expected values to be equal"
    );
}

/// Objective: Verify that PyGILState_Ensure is correctly registered as a Python/C API allocator.
///
/// Invariants:
/// - PyGILState_Ensure should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include PyGILState_Release
#[test]
fn test_pygil_lock() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("PyGILState_Ensure")
        .expect("ffi_contract::test::test_pygil_lock: PyGILState_Ensure not found");
    assert_eq!(
        c.contract_type,
        ContractType::Allocator,
        "Expected values to be equal"
    );
    assert!(
        c.paired_release.contains(&"PyGILState_Release".to_string()),
        "Expected condition to be true"
    );
}
