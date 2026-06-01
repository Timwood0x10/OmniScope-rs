//! Query method tests for FFIContractDB.

use super::super::super::database::FFIContractDB;
use super::super::super::types::ContractSource;

/// Objective: Verify that by_source query returns only OpenSSL contracts.
///
/// Invariants:
/// - Query should return a non-empty list of contracts
/// - All returned contracts should have source set to OpenSSL
#[test]
fn test_by_source_openssl() {
    let db = FFIContractDB::new();
    let contracts = db.by_source(ContractSource::OpenSSL);
    assert!(!contracts.is_empty(), "Must have OpenSSL contracts");
    for c in contracts {
        assert_eq!(
            c.source,
            ContractSource::OpenSSL,
            "Expected values to be equal"
        );
    }
}

/// Objective: Verify that by_source query returns only SQLite contracts.
///
/// Invariants:
/// - Query should return a non-empty list of contracts
/// - All returned contracts should have source set to SQLite
#[test]
fn test_by_source_sqlite() {
    let db = FFIContractDB::new();
    let contracts = db.by_source(ContractSource::SQLite);
    assert!(!contracts.is_empty(), "Must have SQLite contracts");
    for c in contracts {
        assert_eq!(
            c.source,
            ContractSource::SQLite,
            "Expected values to be equal"
        );
    }
}

/// Objective: Verify that by_source query returns only Python/C API contracts.
///
/// Invariants:
/// - Query should return a non-empty list of contracts
/// - All returned contracts should have source set to PythonCApi
#[test]
fn test_by_source_python() {
    let db = FFIContractDB::new();
    let contracts = db.by_source(ContractSource::PythonCApi);
    assert!(!contracts.is_empty(), "Must have Python/C API contracts");
    for c in contracts {
        assert_eq!(
            c.source,
            ContractSource::PythonCApi,
            "Expected values to be equal"
        );
    }
}

/// Objective: Verify that by_source query returns only JNI contracts.
///
/// Invariants:
/// - Query should return a non-empty list of contracts
/// - All returned contracts should have source set to JNI
#[test]
fn test_by_source_jni() {
    let db = FFIContractDB::new();
    let contracts = db.by_source(ContractSource::JNI);
    assert!(!contracts.is_empty(), "Must have JNI contracts");
    for c in contracts {
        assert_eq!(c.source, ContractSource::JNI, "Expected values to be equal");
    }
}

/// Objective: Verify that by_source query returns only POSIX contracts.
///
/// Invariants:
/// - Query should return a non-empty list of contracts
/// - All returned contracts should have source set to Posix
#[test]
fn test_by_source_posix() {
    let db = FFIContractDB::new();
    let contracts = db.by_source(ContractSource::Posix);
    assert!(!contracts.is_empty(), "Must have POSIX contracts");
    for c in contracts {
        assert_eq!(
            c.source,
            ContractSource::Posix,
            "Expected values to be equal"
        );
    }
}

/// Objective: Verify that by_source query returns only GLib contracts.
///
/// Invariants:
/// - Query should return a non-empty list of contracts
/// - All returned contracts should have source set to Glib
#[test]
fn test_by_source_glib() {
    let db = FFIContractDB::new();
    let contracts = db.by_source(ContractSource::Glib);
    assert!(!contracts.is_empty(), "Must have GLib contracts");
    for c in contracts {
        assert_eq!(
            c.source,
            ContractSource::Glib,
            "Expected values to be equal"
        );
    }
}

/// Objective: Verify that by_source query returns only libuv contracts.
///
/// Invariants:
/// - Query should return a non-empty list of contracts
/// - All returned contracts should have source set to Libuv
#[test]
fn test_by_source_libuv() {
    let db = FFIContractDB::new();
    let contracts = db.by_source(ContractSource::Libuv);
    assert!(!contracts.is_empty(), "Must have libuv contracts");
    for c in contracts {
        assert_eq!(
            c.source,
            ContractSource::Libuv,
            "Expected values to be equal"
        );
    }
}

/// Objective: Verify that lookup returns None for non-existent function names.
///
/// Invariants:
/// - Lookup of a non-existent function should return None
#[test]
fn test_lookup_nonexistent() {
    let db = FFIContractDB::new();
    assert!(
        db.lookup("nonexistent_function_xyz").is_none(),
        "Non-existent function should return None"
    );
}

/// Objective: Verify that lookup returns None for empty string.
///
/// Invariants:
/// - Lookup of an empty string should return None
#[test]
fn test_lookup_empty_string() {
    let db = FFIContractDB::new();
    assert!(
        db.lookup("").is_none(),
        "Empty string lookup must return None"
    );
}
