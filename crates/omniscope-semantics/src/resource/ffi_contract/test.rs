//! Tests for FFI contract database.
//!
//! This module contains comprehensive tests for the FFI contract database,
//! covering all built-in contracts and query functionality.

#[cfg(test)]
mod tests {
    use super::super::database::FFIContractDB;
    use super::super::types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};
    use omniscope_types::FamilyId;

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

    /// Test OpenSSL contract lookup.
    #[test]
    fn test_openssl_contracts() {
        let db = FFIContractDB::new();

        // Test SSL_CTX_new
        let ssl_ctx_new = db
            .lookup("SSL_CTX_new")
            .expect("SSL_CTX_new must be registered");
        assert!(ssl_ctx_new.is_allocator());
        assert_eq!(ssl_ctx_new.contract_type, ContractType::Allocator);
        assert_eq!(ssl_ctx_new.source, ContractSource::OpenSSL);
        assert_eq!(ssl_ctx_new.ownership, OwnershipSemantics::CallerOwns);
        assert_eq!(ssl_ctx_new.paired_release, vec!["SSL_CTX_free"]);
        assert!(!ssl_ctx_new.error_prone);

        // Test SSL_CTX_free
        let ssl_ctx_free = db
            .lookup("SSL_CTX_free")
            .expect("SSL_CTX_free must be registered");
        assert!(ssl_ctx_free.is_deallocator());
        assert_eq!(ssl_ctx_free.contract_type, ContractType::Deallocator);

        // Test BIO_new
        let bio_new = db.lookup("BIO_new").expect("BIO_new must be registered");
        assert!(bio_new.is_allocator());
        assert_eq!(bio_new.paired_release, vec!["BIO_free", "BIO_free_all"]);

        // Test error-prone pattern
        let ssl_get_peer = db
            .lookup("SSL_get_peer_certificate")
            .expect("SSL_get_peer_certificate must be registered");
        assert!(ssl_get_peer.is_borrower());
        assert!(ssl_get_peer.error_prone);
        assert_eq!(ssl_get_peer.ownership, OwnershipSemantics::Borrowed);
    }

    /// Test SQLite contract lookup.
    #[test]
    fn test_sqlite_contracts() {
        let db = FFIContractDB::new();

        // Test sqlite3_open
        let sqlite3_open = db
            .lookup("sqlite3_open")
            .expect("sqlite3_open must be registered");
        assert!(sqlite3_open.is_allocator());
        assert_eq!(sqlite3_open.source, ContractSource::SQLite);
        assert_eq!(
            sqlite3_open.paired_release,
            vec!["sqlite3_close", "sqlite3_close_v2"]
        );

        // Test sqlite3_prepare_v2
        let sqlite3_prepare = db
            .lookup("sqlite3_prepare_v2")
            .expect("sqlite3_prepare_v2 must be registered");
        assert!(sqlite3_prepare.is_allocator());
        assert_eq!(sqlite3_prepare.paired_release, vec!["sqlite3_finalize"]);

        // Test error-prone borrowed reference
        let sqlite3_column = db
            .lookup("sqlite3_column_text")
            .expect("sqlite3_column_text must be registered");
        assert!(sqlite3_column.is_borrower());
        assert!(sqlite3_column.error_prone);
    }

    /// Test Python C API contract lookup.
    #[test]
    fn test_python_capi_contracts() {
        let db = FFIContractDB::new();

        // Test PyObject_New
        let pyobject_new = db
            .lookup("PyObject_New")
            .expect("PyObject_New must be registered");
        assert!(pyobject_new.is_allocator());
        assert_eq!(pyobject_new.source, ContractSource::PythonCApi);
        assert_eq!(pyobject_new.paired_release, vec!["Py_DECREF", "Py_XDECREF"]);

        // Test Py_DECREF
        let py_decref = db
            .lookup("Py_DECREF")
            .expect("Py_DECREF must be registered");
        assert!(py_decref.is_releaser());
        assert_eq!(py_decref.ownership, OwnershipSemantics::ReferenceCounted);

        // Test borrowed reference (error-prone)
        let pylist_get = db
            .lookup("PyList_GetItem")
            .expect("PyList_GetItem must be registered");
        assert!(pylist_get.is_borrower());
        assert!(pylist_get.error_prone);
        assert_eq!(pylist_get.ownership, OwnershipSemantics::Borrowed);

        // Test steal reference (error-prone)
        let pytuple_set = db
            .lookup("PyTuple_SetItem")
            .expect("PyTuple_SetItem must be registered");
        assert!(pytuple_set.is_transfer());
        assert!(pytuple_set.error_prone);
        assert_eq!(pytuple_set.ownership, OwnershipSemantics::Transferred);
    }

    /// Test JNI contract lookup.
    #[test]
    fn test_jni_contracts() {
        let db = FFIContractDB::new();

        // Test NewLocalRef
        let new_local_ref = db
            .lookup("NewLocalRef")
            .expect("NewLocalRef must be registered");
        assert!(new_local_ref.is_allocator());
        assert_eq!(new_local_ref.source, ContractSource::JNI);
        assert_eq!(new_local_ref.paired_release, vec!["DeleteLocalRef"]);

        // Test NewGlobalRef
        let new_global_ref = db
            .lookup("NewGlobalRef")
            .expect("NewGlobalRef must be registered");
        assert!(new_global_ref.is_allocator());
        assert_eq!(new_global_ref.paired_release, vec!["DeleteGlobalRef"]);

        // Test error-prone pattern
        let get_string = db
            .lookup("GetStringUTFChars")
            .expect("GetStringUTFChars must be registered");
        assert!(get_string.is_allocator());
        assert!(get_string.error_prone);
    }

    /// Test POSIX contract lookup.
    #[test]
    fn test_posix_contracts() {
        let db = FFIContractDB::new();

        // Test open/close
        let open = db.lookup("open").expect("open must be registered");
        assert!(open.is_allocator());
        assert_eq!(open.source, ContractSource::Posix);
        assert_eq!(open.paired_release, vec!["close"]);

        // Test socket/close
        let socket = db.lookup("socket").expect("socket must be registered");
        assert!(socket.is_allocator());
        assert_eq!(socket.paired_release, vec!["close"]);

        // Test mmap/munmap
        let mmap = db.lookup("mmap").expect("mmap must be registered");
        assert!(mmap.is_allocator());
        assert_eq!(mmap.paired_release, vec!["munmap"]);

        let munmap = db.lookup("munmap").expect("munmap must be registered");
        assert!(munmap.is_deallocator());
    }

    /// Test GLib contract lookup.
    #[test]
    fn test_glib_contracts() {
        let db = FFIContractDB::new();

        // Test g_malloc/g_free
        let g_malloc = db.lookup("g_malloc").expect("g_malloc must be registered");
        assert!(g_malloc.is_allocator());
        assert_eq!(g_malloc.source, ContractSource::Glib);
        assert_eq!(g_malloc.paired_release, vec!["g_free"]);

        // Test GObject reference counting
        let g_object_ref = db
            .lookup("g_object_ref")
            .expect("g_object_ref must be registered");
        assert!(g_object_ref.is_retainer());
        assert_eq!(g_object_ref.ownership, OwnershipSemantics::ReferenceCounted);

        let g_object_unref = db
            .lookup("g_object_unref")
            .expect("g_object_unref must be registered");
        assert!(g_object_unref.is_releaser());
    }

    /// Test zlib contract lookup.
    #[test]
    fn test_zlib_contracts() {
        let db = FFIContractDB::new();

        // Test inflateInit_/inflateEnd
        let inflate_init = db
            .lookup("inflateInit_")
            .expect("inflateInit_ must be registered");
        assert!(inflate_init.is_allocator());
        assert_eq!(inflate_init.source, ContractSource::Zlib);
        assert_eq!(inflate_init.paired_release, vec!["inflateEnd"]);

        let inflate_end = db
            .lookup("inflateEnd")
            .expect("inflateEnd must be registered");
        assert!(inflate_end.is_deallocator());

        // Test deflateInit_/deflateEnd
        let deflate_init = db
            .lookup("deflateInit_")
            .expect("deflateInit_ must be registered");
        assert!(deflate_init.is_allocator());
        assert_eq!(deflate_init.paired_release, vec!["deflateEnd"]);
    }

    /// Test libuv contract lookup.
    #[test]
    fn test_libuv_contracts() {
        let db = FFIContractDB::new();

        // Test uv_loop_init/uv_loop_close
        let uv_loop_init = db
            .lookup("uv_loop_init")
            .expect("uv_loop_init must be registered");
        assert!(uv_loop_init.is_allocator());
        assert_eq!(uv_loop_init.source, ContractSource::Libuv);
        assert_eq!(uv_loop_init.paired_release, vec!["uv_loop_close"]);

        // Test error-prone pattern
        let uv_default_loop = db
            .lookup("uv_default_loop")
            .expect("uv_default_loop must be registered");
        assert!(uv_default_loop.is_borrower());
        assert!(!uv_default_loop.error_prone); // default loop is safe to use
    }

    /// Test querying by source library.
    #[test]
    fn test_query_by_source() {
        let db = FFIContractDB::new();

        let openssl_contracts = db.by_source(ContractSource::OpenSSL);
        assert!(
            openssl_contracts.len() > 10,
            "Must have many OpenSSL contracts"
        );

        let sqlite_contracts = db.by_source(ContractSource::SQLite);
        assert!(
            sqlite_contracts.len() > 5,
            "Must have many SQLite contracts"
        );

        let python_contracts = db.by_source(ContractSource::PythonCApi);
        assert!(
            python_contracts.len() > 10,
            "Must have many Python C API contracts"
        );
    }

    /// Test querying by family ID.
    #[test]
    fn test_query_by_family() {
        let db = FFIContractDB::new();

        let openssl_family = db.by_family(FamilyId::OPENSSL_RESOURCE);
        assert!(
            openssl_family.len() > 10,
            "Must have many OpenSSL family contracts"
        );

        let sqlite_family = db.by_family(FamilyId::SQLITE_RESOURCE);
        assert!(
            sqlite_family.len() > 5,
            "Must have many SQLite family contracts"
        );
    }

    /// Test error-prone contracts query.
    #[test]
    fn test_error_prone_contracts() {
        let db = FFIContractDB::new();

        let error_prone = db.error_prone();
        assert!(
            error_prone.len() > 10,
            "Must have many error-prone contracts"
        );

        // Verify specific error-prone patterns
        let pylist_get = db
            .lookup("PyList_GetItem")
            .expect("PyList_GetItem must be registered");
        assert!(pylist_get.error_prone);

        let sqlite_column = db
            .lookup("sqlite3_column_text")
            .expect("sqlite3_column_text must be registered");
        assert!(sqlite_column.error_prone);
    }

    /// Test contract display formatting.
    #[test]
    fn test_contract_display() {
        let db = FFIContractDB::new();

        // Use SSL_CTX_new which is in FFIContractDB
        let ssl_ctx_new = db
            .lookup("SSL_CTX_new")
            .expect("SSL_CTX_new must be registered");
        let display = format!("{}", ssl_ctx_new);
        assert!(display.contains("SSL_CTX_new"));
        assert!(display.contains("openssl"));
    }

    /// Test contract type methods.
    #[test]
    fn test_contract_type_methods() {
        let db = FFIContractDB::new();

        // Test allocator (using SSL_CTX_new from OpenSSL)
        let ssl_ctx_new = db
            .lookup("SSL_CTX_new")
            .expect("SSL_CTX_new must be registered");
        assert!(ssl_ctx_new.is_allocator());
        assert!(!ssl_ctx_new.is_deallocator());
        assert!(!ssl_ctx_new.is_borrower());
        assert!(!ssl_ctx_new.is_transfer());
        assert!(!ssl_ctx_new.is_retainer());
        assert!(!ssl_ctx_new.is_releaser());
        assert!(ssl_ctx_new.caller_owns());
        assert!(!ssl_ctx_new.callee_owns());
        assert!(!ssl_ctx_new.is_borrowed());
        assert!(!ssl_ctx_new.ownership_transferred());
        assert!(!ssl_ctx_new.is_reference_counted());

        // Test deallocator (using SSL_CTX_free from OpenSSL)
        let ssl_ctx_free = db
            .lookup("SSL_CTX_free")
            .expect("SSL_CTX_free must be registered");
        assert!(!ssl_ctx_free.is_allocator());
        assert!(ssl_ctx_free.is_deallocator());

        // Test borrower (using PyList_GetItem from Python C API)
        let pylist_get = db
            .lookup("PyList_GetItem")
            .expect("PyList_GetItem must be registered");
        assert!(!pylist_get.is_allocator());
        assert!(!pylist_get.is_deallocator());
        assert!(pylist_get.is_borrower());
        assert!(pylist_get.is_borrowed());

        // Test retainer (using Py_INCREF from Python C API)
        let py_incref = db
            .lookup("Py_INCREF")
            .expect("Py_INCREF must be registered");
        assert!(py_incref.is_retainer());
        assert!(py_incref.is_reference_counted());

        // Test releaser (using Py_DECREF from Python C API)
        let py_decref = db
            .lookup("Py_DECREF")
            .expect("Py_DECREF must be registered");
        assert!(py_decref.is_releaser());
        assert!(py_decref.is_reference_counted());
    }

    /// Test contract builder methods.
    #[test]
    fn test_contract_builder() {
        let contract = FFIContract::new(
            "test_func",
            ContractType::Allocator,
            vec!["test_free"],
            OwnershipSemantics::CallerOwns,
            false,
            ContractSource::Custom,
        )
        .with_family(FamilyId::C_HEAP)
        .with_notes("Test contract");

        assert_eq!(contract.function_name, "test_func");
        assert_eq!(contract.contract_type, ContractType::Allocator);
        assert_eq!(contract.paired_release, vec!["test_free"]);
        assert_eq!(contract.ownership, OwnershipSemantics::CallerOwns);
        assert!(!contract.error_prone);
        assert_eq!(contract.source, ContractSource::Custom);
        assert_eq!(contract.family_id, Some(FamilyId::C_HEAP));
        assert_eq!(contract.notes, Some("Test contract".to_string()));
    }

    /// Test contract enum display formatting.
    #[test]
    fn test_enum_display() {
        assert_eq!(format!("{}", ContractType::Allocator), "allocator");
        assert_eq!(format!("{}", ContractType::Deallocator), "deallocator");
        assert_eq!(format!("{}", ContractType::Borrower), "borrower");
        assert_eq!(format!("{}", ContractType::Transfer), "transfer");
        assert_eq!(format!("{}", ContractType::Retainer), "retainer");
        assert_eq!(format!("{}", ContractType::Releaser), "releaser");

        assert_eq!(format!("{}", OwnershipSemantics::CallerOwns), "caller_owns");
        assert_eq!(format!("{}", OwnershipSemantics::CalleeOwns), "callee_owns");
        assert_eq!(format!("{}", OwnershipSemantics::Borrowed), "borrowed");
        assert_eq!(
            format!("{}", OwnershipSemantics::Transferred),
            "transferred"
        );
        assert_eq!(format!("{}", OwnershipSemantics::Received), "received");
        assert_eq!(
            format!("{}", OwnershipSemantics::ReferenceCounted),
            "reference_counted"
        );

        assert_eq!(format!("{}", ContractSource::OpenSSL), "openssl");
        assert_eq!(format!("{}", ContractSource::SQLite), "sqlite");
        assert_eq!(format!("{}", ContractSource::PythonCApi), "python_capi");
        assert_eq!(format!("{}", ContractSource::JNI), "jni");
        assert_eq!(format!("{}", ContractSource::Posix), "posix");
        assert_eq!(format!("{}", ContractSource::Glib), "glib");
        assert_eq!(format!("{}", ContractSource::Zlib), "zlib");
        assert_eq!(format!("{}", ContractSource::Libuv), "libuv");
        assert_eq!(format!("{}", ContractSource::Custom), "custom");
    }

    /// Test that all built-in contracts have valid families.
    #[test]
    fn test_contracts_have_families() {
        let db = FFIContractDB::new();

        // Test a sample of contracts from different sources
        let sample_contracts = [
            "SSL_CTX_new",
            "sqlite3_open",
            "PyObject_New",
            "NewLocalRef",
            "open",
            "g_malloc",
            "inflateInit_",
            "uv_loop_init",
        ];

        for name in &sample_contracts {
            let contract = db
                .lookup(name)
                .unwrap_or_else(|| panic!("{} must be registered", name));
            assert!(
                contract.family_id.is_some(),
                "Contract {} must have a family ID",
                name
            );
        }
    }

    /// Test contract source categorization.
    #[test]
    fn test_contract_source_categorization() {
        let db = FFIContractDB::new();

        // Test that we have contracts for each source
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

        for source in &sources {
            let contracts = db.by_source(*source);
            assert!(
                !contracts.is_empty(),
                "Must have contracts for source: {}",
                source
            );
        }
    }
}
