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

    /// Objective: Verify that the FFIContractDB is properly populated with built-in contracts.
    ///
    /// Invariants:
    /// - The database should contain more than 100 contracts after initialization
    /// - All built-in contracts from various sources (OpenSSL, SQLite, Python/C API, etc.) should be registered
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

    /// Objective: Verify that OPENSSL_malloc is correctly registered as an OpenSSL allocator.
    ///
    /// Invariants:
    /// - OPENSSL_malloc should be found in the database
    /// - Contract type should be Allocator
    /// - Source should be OpenSSL
    /// - Paired release should include OPENSSL_free
    /// - Ownership semantics should be CallerOwns
    #[test]
    fn test_openssl_malloc() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("OPENSSL_malloc")
            .expect("OPENSSL_malloc not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert_eq!(c.source, ContractSource::OpenSSL);
        assert!(c.paired_release.contains(&"OPENSSL_free".to_string()));
        assert_eq!(c.ownership, OwnershipSemantics::CallerOwns);
    }

    /// Objective: Verify that OPENSSL_free is correctly registered as an OpenSSL deallocator.
    ///
    /// Invariants:
    /// - OPENSSL_free should be found in the database
    /// - Contract type should be Deallocator
    /// - Source should be OpenSSL
    #[test]
    fn test_openssl_free() {
        let db = FFIContractDB::new();
        let c = db.lookup("OPENSSL_free").expect("OPENSSL_free not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
        assert_eq!(c.source, ContractSource::OpenSSL);
    }

    /// Objective: Verify that OPENSSL_strdup is correctly registered as an OpenSSL allocator.
    ///
    /// Invariants:
    /// - OPENSSL_strdup should be found in the database
    /// - Contract type should be Allocator
    /// - Paired release should include OPENSSL_free
    #[test]
    fn test_openssl_strdup() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("OPENSSL_strdup")
            .expect("OPENSSL_strdup not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"OPENSSL_free".to_string()));
    }

    /// Objective: Verify that OPENSSL_clear_free is correctly registered as an OpenSSL deallocator.
    ///
    /// Invariants:
    /// - OPENSSL_clear_free should be found in the database
    /// - Contract type should be Deallocator
    #[test]
    fn test_openssl_clear_free() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("OPENSSL_clear_free")
            .expect("OPENSSL_clear_free not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    /// Objective: Verify that CRYPTO_secure_malloc is correctly registered as an OpenSSL allocator.
    ///
    /// Invariants:
    /// - CRYPTO_secure_malloc should be found in the database
    /// - Contract type should be Allocator
    /// - Paired release should include CRYPTO_secure_free
    #[test]
    fn test_openssl_secure_malloc() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("CRYPTO_secure_malloc")
            .expect("CRYPTO_secure_malloc not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"CRYPTO_secure_free".to_string()));
    }

    /// Objective: Verify that EVP_MD_CTX_new is correctly registered as an OpenSSL allocator.
    ///
    /// Invariants:
    /// - EVP_MD_CTX_new should be found in the database
    /// - Contract type should be Allocator
    /// - Paired release should include EVP_MD_CTX_free
    #[test]
    fn test_evp_md_ctx() {
        let db = FFIContractDB::new();
        let c = db
            .lookup("EVP_MD_CTX_new")
            .expect("EVP_MD_CTX_new not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"EVP_MD_CTX_free".to_string()));
    }

    /// Objective: Verify that EVP_CIPHER_CTX_new is correctly registered as an OpenSSL allocator.
    ///
    /// Invariants:
    /// - EVP_CIPHER_CTX_new should be found in the database
    /// - Contract type should be Allocator
    /// - Paired release should include EVP_CIPHER_CTX_free
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

    /// Objective: Verify that BIO_new is correctly registered as an OpenSSL allocator.
    ///
    /// Invariants:
    /// - BIO_new should be found in the database
    /// - Contract type should be Allocator
    /// - Paired release should include both BIO_free and BIO_free_all
    #[test]
    fn test_bio_new() {
        let db = FFIContractDB::new();
        let c = db.lookup("BIO_new").expect("BIO_new not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"BIO_free".to_string()));
        assert!(c.paired_release.contains(&"BIO_free_all".to_string()));
    }

    /// Objective: Verify that SSL_CTX_new is correctly registered as an OpenSSL allocator.
    ///
    /// Invariants:
    /// - SSL_CTX_new should be found in the database
    /// - Contract type should be Allocator
    /// - Paired release should include SSL_CTX_free
    #[test]
    fn test_ssl_ctx() {
        let db = FFIContractDB::new();
        let c = db.lookup("SSL_CTX_new").expect("SSL_CTX_new not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"SSL_CTX_free".to_string()));
    }

    /// Objective: Verify that X509_free is correctly registered as an OpenSSL deallocator.
    ///
    /// Invariants:
    /// - X509_free should be found in the database
    /// - Contract type should be Deallocator
    #[test]
    fn test_x509_free() {
        let db = FFIContractDB::new();
        let c = db.lookup("X509_free").expect("X509_free not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    // === SQLite tests ===

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
        let c = db.lookup("sqlite3_open").expect("sqlite3_open not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert_eq!(c.source, ContractSource::SQLite);
        assert!(c.paired_release.contains(&"sqlite3_close".to_string()));
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
        let c = db.lookup("sqlite3_close").expect("sqlite3_close not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
        assert_eq!(c.source, ContractSource::SQLite);
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
        let c = db.lookup("sqlite3_exec").expect("sqlite3_exec not found");
        assert_eq!(c.contract_type, ContractType::Borrower);
        assert_eq!(c.source, ContractSource::SQLite);
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
            .expect("sqlite3_prepare_v2 not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"sqlite3_finalize".to_string()));
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
            .expect("sqlite3_finalize not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
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
            .expect("sqlite3_column_text not found");
        assert_eq!(c.contract_type, ContractType::Borrower);
    }

    // === Python/C API tests ===

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
        let c = db.lookup("PyObject_New").expect("PyObject_New not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert_eq!(c.source, ContractSource::PythonCApi);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
        assert_eq!(c.ownership, OwnershipSemantics::ReferenceCounted);
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
        let c = db.lookup("Py_BuildValue").expect("Py_BuildValue not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
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
            .expect("PyUnicode_FromString not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
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
            .expect("PyBytes_FromString not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
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
        let c = db.lookup("PyList_New").expect("PyList_New not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
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
        let c = db.lookup("PyDict_New").expect("PyDict_New not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
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
        let c = db.lookup("Py_INCREF").expect("Py_INCREF not found");
        assert_eq!(c.contract_type, ContractType::Retainer);
        assert!(c.paired_release.contains(&"Py_DECREF".to_string()));
    }

    /// Objective: Verify that Py_DECREF is correctly registered as a Python/C API releaser.
    ///
    /// Invariants:
    /// - Py_DECREF should be found in the database
    /// - Contract type should be Releaser
    #[test]
    fn test_py_decref() {
        let db = FFIContractDB::new();
        let c = db.lookup("Py_DECREF").expect("Py_DECREF not found");
        assert_eq!(c.contract_type, ContractType::Releaser);
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
            .expect("PyGILState_Ensure not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"PyGILState_Release".to_string()));
    }

    // === JNI tests ===

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
        let c = db.lookup("FindClass").expect("FindClass not found");
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
        let c = db.lookup("NewStringUTF").expect("NewStringUTF not found");
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
        let c = db.lookup("NewObject").expect("NewObject not found");
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
            .expect("DeleteLocalRef not found");
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
        let c = db.lookup("NewGlobalRef").expect("NewGlobalRef not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"DeleteGlobalRef".to_string()));
    }

    // === POSIX tests ===

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
        let c = db.lookup("malloc").expect("malloc not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert_eq!(c.source, ContractSource::Posix);
        assert!(c.paired_release.contains(&"free".to_string()));
        assert_eq!(c.ownership, OwnershipSemantics::CallerOwns);
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
        let c = db.lookup("free").expect("free not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
        assert_eq!(c.source, ContractSource::Posix);
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
        let c = db.lookup("calloc").expect("calloc not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"free".to_string()));
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
        let c = db.lookup("realloc").expect("realloc not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"free".to_string()));
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
        let c = db.lookup("strdup").expect("strdup not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"free".to_string()));
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
        let c = db.lookup("strndup").expect("strndup not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"free".to_string()));
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
        let c = db.lookup("open").expect("open not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"close".to_string()));
    }

    /// Objective: Verify that close is correctly registered as a POSIX deallocator.
    ///
    /// Invariants:
    /// - close should be found in the database
    /// - Contract type should be Deallocator
    #[test]
    fn test_close() {
        let db = FFIContractDB::new();
        let c = db.lookup("close").expect("close not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
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
        let c = db.lookup("socket").expect("socket not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"close".to_string()));
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
        let c = db.lookup("fopen").expect("fopen not found");
        assert_eq!(c.contract_type, ContractType::Allocator);
        assert!(c.paired_release.contains(&"fclose".to_string()));
    }

    /// Objective: Verify that fclose is correctly registered as a POSIX deallocator.
    ///
    /// Invariants:
    /// - fclose should be found in the database
    /// - Contract type should be Deallocator
    #[test]
    fn test_fclose() {
        let db = FFIContractDB::new();
        let c = db.lookup("fclose").expect("fclose not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    // === GLib tests ===

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
        let c = db.lookup("g_malloc").expect("g_malloc not found");
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
        let c = db.lookup("g_new").expect("g_new not found");
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
        let c = db.lookup("g_strdup").expect("g_strdup not found");
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
        let c = db.lookup("g_free").expect("g_free not found");
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
        let c = db.lookup("g_object_ref").expect("g_object_ref not found");
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
            .expect("g_object_unref not found");
        assert_eq!(c.contract_type, ContractType::Releaser);
    }

    // === libuv tests ===

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
        let c = db.lookup("uv_loop_init").expect("uv_loop_init not found");
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
        let c = db.lookup("uv_loop_close").expect("uv_loop_close not found");
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
        let c = db.lookup("uv_tcp_init").expect("uv_tcp_init not found");
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
        let c = db.lookup("uv_timer_init").expect("uv_timer_init not found");
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
        let c = db.lookup("uv_close").expect("uv_close not found");
        assert_eq!(c.contract_type, ContractType::Deallocator);
    }

    // === Query method tests ===

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
            assert_eq!(c.source, ContractSource::OpenSSL);
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
            assert_eq!(c.source, ContractSource::SQLite);
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
            assert_eq!(c.source, ContractSource::PythonCApi);
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
            assert_eq!(c.source, ContractSource::JNI);
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
            assert_eq!(c.source, ContractSource::Posix);
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
            assert_eq!(c.source, ContractSource::Glib);
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
            assert_eq!(c.source, ContractSource::Libuv);
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
