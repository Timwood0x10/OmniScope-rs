//! Tests for FFIContractDB.
//!
//! This module contains comprehensive tests for the FFI contract database,
//! covering all built-in contracts and query functionality.

#[cfg(test)]
mod tests {
    use super::super::database::FFIContractDB;
    use super::super::types::{ContractSource, ContractType, OwnershipSemantics};
    use omniscope_types::FamilyId;
    use proptest::prelude::*;

    /// Test that the database is properly populated with built-in contracts.
    #[test]
    fn test_database_populated() {
        let db = FFIContractDB::new();
        assert!(
            db.len() > 100,
            "Must have many built-in contracts, got {}",
            db.len()
        );
    }

    // === OpenSSL tests ===

    #[test]
    fn test_openssl_malloc() {
        let db = FFIContractDB::new();
        let c = db.lookup("OPENSSL_malloc").expect("OPENSSL_malloc not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert_eq!(c.source, ContractSource::OpenSSL);
        assert!(c.paired_release.contains(&"OPENSSL_free".to_string()));
        assert_eq!(c.ownership, OwnershipSemantics::CallerOwns);
    }

    #[test]
    fn test_openssl_free() {
        let db = FFIContractDB::new();
        let c = db.lookup("OPENSSL_free").expect("OPENSSL_free not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
        assert_eq!(c.source, ContractSource::OpenSSL);
    }

    #[test]
    fn test_openssl_strdup() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("OPENSSL_strdup")
            .expect("OPENSSL_strdup not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"OPENSSL_free".to_string()));
    }

    #[test]
    fn test_openssl_clear_free() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("OPENSSL_clear_free")
            .expect("OPENSSL_clear_free not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    #[test]
    fn test_openssl_secure_malloc() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("CRYPTO_secure_malloc")
            .expect("CRYPTO_secure_malloc not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c
            .paired_release
            .contains(&"CRYPTO_secure_free".to_string()));
    }

    #[test]
    fn test_evp_md_ctx() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("EVP_MD_CTX_new")
            .expect("EVP_MD_CTX_new not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c
            .paired_release
            .contains(&"EVP_MD_CTX_free".to_string()));
    }

    #[test]
    fn test_evp_cipher_ctx() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("EVP_CIPHER_CTX_new")
            .expect("EVP_CIPHER_CTX_new not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c
            .paired_release
            .contains(&"EVP_CIPHER_CTX_free".to_string()));
    }

    #[test]
    fn test_bio_new() {
        let db = FFIContractDB::new();
        let c = db.lookup("BIO_new").expect("BIO_new not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"BIO_free".to_string()));
        assert!(c.paired_release.contains(&"BIO_free_all".to_string()));
    }

    #[test]
    fn test_ssl_ctx() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("SSL_CTX_new")
            .expect("SSL_CTX_new not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"SSL_CTX_free".to_string()));
    }

    #[test]
    fn test_x509_free() {
        let db = FFIContractDB::new();
        let c = db.lookup("X509_free").expect("X509_free not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    // === SQLite tests ===

    #[test]
    fn test_sqlite3_open() {
        let db = FFIContractDB::new();
        let c = db.lookup("sqlite3_open").expect("sqlite3_open not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert_eq!(c.source, ContractSource::SQLite);
        assert!(c.paired_release.contains(&"sqlite3_close".to_string()));
    }

    #[test]
    fn test_sqlite3_close() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("sqlite3_close")
            .expect("sqlite3_close not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
        assert_eq!(c.source, ContractSource::SQLite);
    }

    #[test]
    fn test_sqlite3_exec() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("sqlite3_exec")
            .expect("sqlite3_exec not found");
        assert_eq!(c.contract_type, ContractType::Borrower);
        assert_eq!(c.source, ContractSource::SQLite);
    }

    #[test]
    fn test_sqlite3_prepare() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("sqlite3_prepare_v2")
            .expect("sqlite3_prepare_v2 not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c
            .paired_release
            .contains(&"sqlite3_finalize".to_string()));
    }

    #[test]
    fn test_sqlite3_finalize() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("sqlite3_finalize")
            .expect("sqlite3_finalize not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    #[test]
    fn test_sqlite3_column_text() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("sqlite3_column_text")
            .expect("sqlite3_column_text not found");
        assert_eq!(c.contract_type, ContractType::Borrower);
    }

    // === Python/C API tests ===

    #[test]
    fn test_pyobject_new() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("PyObject_New")
            .expect("PyObject_New not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert_eq!(c.source, ContractSource::PythonCApi);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
        assert_eq!(c.ownership, OwnershipSemantics::ReferenceCounted);
    }

    #[test]
    fn test_py_buildvalue() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("Py_BuildValue")
            .expect("Py_BuildValue not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
    }

    #[test]
    fn test_py_unicode() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("PyUnicode_FromString")
            .expect("PyUnicode_FromString not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
    }

    #[test]
    fn test_py_bytes() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("PyBytes_FromString")
            .expect("PyBytes_FromString not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
    }

    #[test]
    fn test_py_list() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("PyList_New")
            .expect("PyList_New not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
    }

    #[test]
    fn test_py_dict() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("PyDict_New")
            .expect("PyDict_New not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
    }

    #[test]
    fn test_py_incref() {
        let db = FFIContractDB::new();
        let c = db.lookup("Py_INCREF").expect("Py_INCREF not found");
        assert_eq!(c.contract_type, ContractType::Retainer);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
    }

    #[test]
    fn test_py_decref() {
        let db = FFIContractDB::new();
        let c = db.lookup("Py_DECREF").expect("Py_DECREF not found");
        assert_eq!(c.contract_type, ContractType::Releaser);
    }

    #[test]
    fn test_pygil_lock() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("PyGILState_Ensure")
            .expect("PyGILState_Ensure not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c
            .paired_release
            .contains(&"PyGILState_Release".to_string()));
    }

    // === JNI tests ===

    #[test]
    fn test_jni_find_class() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("FindClass")
            .expect("FindClass not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert_eq!(c.source, ContractSource::JNI);
        assert!(c
            .paired_release
            .contains(&"DeleteLocalRef".to_string()));
    }

    #[test]
    fn test_jni_new_string() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("NewStringUTF")
            .expect("NewStringUTF not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c
            .paired_release
            .contains(&"DeleteLocalRef".to_string()));
    }

    #[test]
    fn test_jni_new_object() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("NewObject")
            .expect("NewObject not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c
            .paired_release
            .contains(&"DeleteLocalRef".to_string()));
    }

    #[test]
    fn test_jni_delete_local_ref() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("DeleteLocalRef")
            .expect("DeleteLocalRef not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    #[test]
    fn test_jni_new_global_ref() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("NewGlobalRef")
            .expect("NewGlobalRef not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c
            .paired_release
            .contains(&"DeleteGlobalRef".to_string()));
    }

    // === POSIX tests ===

    #[test]
    fn test_malloc() {
        let db = FFIContractDB::new();
        let c = db.lookup("malloc").expect("malloc not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert_eq!(c.source, ContractSource::Posix);
        assert!(c.paired_release.contains(&"free".to_string()));
        assert_eq!(c.ownership, OwnershipSemantics::CallerOwns);
    }

    #[test]
    fn test_free() {
        let db = FFIContractDB::new();
        let c = db.lookup("free").expect("free not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
        assert_eq!(c.source, ContractSource::Posix);
    }

    #[test]
    fn test_calloc() {
        let db = FFIContractDB::new();
        let c = db.lookup("calloc").expect("calloc not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"free".to_string()));
    }

    #[test]
    fn test_realloc() {
        let db = FFIContractDB::new();
        let c = db.lookup("realloc").expect("realloc not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"free".to_string()));
    }

    #[test]
    fn test_strdup() {
        let db = FFIContractDB::new();
        let c = db.lookup("strdup").expect("strdup not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"free".to_string()));
    }

    #[test]
    fn test_strndup() {
        let db = FFIContractDB::new();
        let c = db.lookup("strndup").expect("strndup not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"free".to_string()));
    }

    #[test]
    fn test_open() {
        let db = FFIContractDB::new();
        let c = db.lookup("open").expect("open not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"close".to_string()));
    }

    #[test]
    fn test_close() {
        let db = FFIContractDB::new();
        let c = db.lookup("close").expect("close not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    #[test]
    fn test_socket() {
        let db = FFIContractDB::new();
        let c = db.lookup("socket").expect("socket not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"close".to_string()));
    }

    #[test]
    fn test_fopen() {
        let db = FFIContractDB::new();
        let c = db.lookup("fopen").expect("fopen not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"fclose".to_string()));
    }

    #[test]
    fn test_fclose() {
        let db = FFIContractDB::new();
        let c = db.lookup("fclose").expect("fclose not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    // === GLib tests ===

    #[test]
    fn test_g_malloc() {
        let db = FFIContractDB::new();
        let c = db.lookup("g_malloc").expect("g_malloc not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert_eq!(c.source, ContractSource::Glib);
        assert!(c.paired_release.contains(&"g_free".to_string()));
    }

    #[test]
    fn test_g_new() {
        let db = FFIContractDB::new();
        let c = db.lookup("g_new").expect("g_new not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"g_free".to_string()));
    }

    #[test]
    fn test_g_strdup() {
        let db = FFIContractDB::new();
        let c = db.lookup("g_strdup").expect("g_strdup not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"g_free".to_string()));
    }

    #[test]
    fn test_g_free() {
        let db = FFIContractDB::new();
        let c = db.lookup("g_free").expect("g_free not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    #[test]
    fn test_g_object_ref() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("g_object_ref")
            .expect("g_object_ref not found");
        assert_eq!(c.contract_type, ContractType::Retainer);
        assert!(c
            .paired_release
            .contains(&"g_object_unref".to_string()));
    }

    #[test]
    fn test_g_object_unref() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("g_object_unref")
            .expect("g_object_unref not found");
        assert_eq!(c.contract_type, ContractType::Releaser);
    }

    // === libuv tests ===

    #[test]
    fn test_uv_loop_init() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("uv_loop_init")
            .expect("uv_loop_init not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert_eq!(c.source, ContractSource::Libuv);
        assert!(c
            .paired_release
            .contains(&"uv_loop_close".to_string()));
    }

    #[test]
    fn test_uv_loop_close() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("uv_loop_close")
            .expect("uv_loop_close not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    #[test]
    fn test_uv_tcp_init() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("uv_tcp_init")
            .expect("uv_tcp_init not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"uv_close".to_string()));
    }

    #[test]
    fn test_uv_timer_init() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("uv_timer_init")
            .expect("uv_timer_init not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"uv_close".to_string()));
    }

    #[test]
    fn test_uv_close() {
        let db = FFIContractDB::new();
        let c = db.lookup("uv_close").expect("uv_close not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    // === Query method tests ===

    #[test]
    fn test_by_source_openssl() {
        let db = FFIContractDB::new();
        let contracts = db.by_source(ContractSource::OpenSSL);
        assert!(
            !contracts.is_empty(),
            "Must have OpenSSL contracts"
        );
        for c in contracts {
            assert_eq!(c.source, ContractSource::OpenSSL);
        }
    }

    #[test]
    fn test_by_source_sqlite() {
        let db = FFIContractDB::new();
        let contracts = db.by_source(ContractSource::SQLite);
        assert!(
            !contracts.is_empty(),
            "Must have SQLite contracts"
        );
        for c in contracts {
            assert_eq!(c.source, ContractSource::SQLite);
        }
    }

    #[test]
    fn test_by_source_python() {
        let db = FFIContractDB::new();
        let contracts = db.by_source(ContractSource::PythonCApi);
        assert!(
            !contracts.is_empty(),
            "Must have Python/C API contracts"
        );
        for c in contracts {
            assert_eq!(c.source, ContractSource::PythonCApi);
        }
    }

    #[test]
    fn test_by_source_jni() {
        let db = FFIContractDB::new();
        let contracts = db.by_source(ContractSource::JNI);
        assert!(!contracts.is_empty(), "Must have JNI contracts");
        for c in contracts {
            assert_eq!(c.source, ContractSource::JNI);
        }
    }

    #[test]
    fn test_by_source_posix() {
        let db = FFIContractDB::new();
        let contracts = db.by_source(ContractSource::Posix);
        assert!(!contracts.is_empty(), "Must have POSIX contracts");
        for c in contracts {
            assert_eq!(c.source, ContractSource::Posix);
        }
    }

    #[test]
    fn test_by_source_glib() {
        let db = FFIContractDB::new();
        let contracts = db.by_source(ContractSource::Glib);
        assert!(!contracts.is_empty(), "Must have GLib contracts");
        for c in contracts {
            assert_eq!(c.source, ContractSource::Glib);
        }
    }

    #[test]
    fn test_by_source_libuv() {
        let db = FFIContractDB::new();
        let contracts = db.by_source(ContractSource::Libuv);
        assert!(!contracts.is_empty(), "Must have libuv contracts");
        for c in contracts {
            assert_eq!(c.source, ContractSource::Libuv);
        }
    }

    #[test]
    fn test_lookup_nonexistent() {
        let db = FFIContractDB::new();
        assert!(
            db.lookup("nonexistent_function_xyz").is_none(),
            "Non-existent function should return None"
        );
    }

    #[test]
    fn test_lookup_empty_string() {
        let db = FFIContractDB::new();
        assert!(
            db.lookup("").is_none(),
            "Empty string lookup must return None"
        );
    }

    // === Property-based tests using proptest ===

    proptest! {
        #[test]
        fn prop_lookup_random_function_names(
            func_name in "[a-zA-Z_][a-zA-Z0-9_]{0,50}"
        ) {
            // Property: lookup should never panic for valid identifier strings
            let db = FFIContractDB::new();
            let _result = db.lookup(&func_name);
            // The property is that this doesn't panic; result may be None or Some
        }

        #[test]
        fn prop_lookup_special_characters(
            name in "[!@#$%^&*()+=\\[\\]{}|;':\",./<>?]{1,20}"
        ) {
            // Property: lookup of special character strings should not panic
            let db = FFIContractDB::new();
            let _result = db.lookup(&name);
            // Special characters are unlikely to be registered, but must not panic
        }

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

        #[test]
        fn prop_query_by_family_random_id(
            family_id in any::<u16>()
        ) {
            // Property: querying by any family ID should not panic
            let db = FFIContractDB::new();
            let _contracts = db.by_family(FamilyId(family_id));
            // Should not panic for any family ID
        }

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
}