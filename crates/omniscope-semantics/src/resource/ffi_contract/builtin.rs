//! Built-in FFI contract rules.
//!
//! This module contains the built-in FFI contract rules for common libraries,
//! including OpenSSL, SQLite, Python C API, JNI, POSIX, GLib, zlib, and libuv.

use omniscope_types::FamilyId;

use super::database::FFIContractDB;
use super::types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};

/// Registers all built-in FFI contracts into the database.
pub fn register_builtin_contracts(db: &mut FFIContractDB) {
    // OpenSSL contracts
    register_openssl_contracts(db);

    // SQLite contracts
    register_sqlite_contracts(db);

    // Python C API contracts
    register_python_capi_contracts(db);

    // JNI contracts
    register_jni_contracts(db);

    // POSIX contracts
    register_posix_contracts(db);

    // GLib/GObject contracts
    register_glib_contracts(db);

    // zlib contracts
    register_zlib_contracts(db);

    // libuv contracts
    register_libuv_contracts(db);
}

/// Registers OpenSSL library contracts.
fn register_openssl_contracts(db: &mut FFIContractDB) {
    let source = ContractSource::OpenSSL;
    let family = FamilyId::OPENSSL_RESOURCE;

    // SSL context
    db.register(
        FFIContract::new(
            "SSL_CTX_new",
            ContractType::Allocator,
            vec!["SSL_CTX_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Creates a new SSL_CTX object as framework for TLS/SSL functions"),
    );

    db.register(
        FFIContract::new(
            "SSL_CTX_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free an SSL_CTX object"),
    );

    // SSL session
    db.register(
        FFIContract::new(
            "SSL_new",
            ContractType::Allocator,
            vec!["SSL_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new SSL structure for a connection"),
    );

    db.register(
        FFIContract::new(
            "SSL_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free an SSL structure"),
    );

    // BIO (Basic I/O)
    db.register(
        FFIContract::new(
            "BIO_new",
            ContractType::Allocator,
            vec!["BIO_free", "BIO_free_all"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new BIO object"),
    );

    db.register(
        FFIContract::new(
            "BIO_new_connect",
            ContractType::Allocator,
            vec!["BIO_free", "BIO_free_all"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new BIO connection"),
    );

    db.register(
        FFIContract::new(
            "BIO_new_ssl",
            ContractType::Allocator,
            vec!["BIO_free", "BIO_free_all"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new BIO SSL connection"),
    );

    db.register(
        FFIContract::new(
            "BIO_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free a BIO object"),
    );

    db.register(
        FFIContract::new(
            "BIO_free_all",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free a BIO chain"),
    );

    // EVP contexts
    db.register(
        FFIContract::new(
            "EVP_CIPHER_CTX_new",
            ContractType::Allocator,
            vec!["EVP_CIPHER_CTX_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new EVP cipher context"),
    );

    db.register(
        FFIContract::new(
            "EVP_CIPHER_CTX_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free an EVP cipher context"),
    );

    db.register(
        FFIContract::new(
            "EVP_MD_CTX_new",
            ContractType::Allocator,
            vec!["EVP_MD_CTX_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new EVP message digest context"),
    );

    db.register(
        FFIContract::new(
            "EVP_MD_CTX_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free an EVP message digest context"),
    );

    // RSA
    db.register(
        FFIContract::new(
            "RSA_new",
            ContractType::Allocator,
            vec!["RSA_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new RSA structure"),
    );

    db.register(
        FFIContract::new(
            "RSA_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free an RSA structure"),
    );

    // BIGNUM
    db.register(
        FFIContract::new(
            "BN_new",
            ContractType::Allocator,
            vec!["BN_free", "BN_clear_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new BIGNUM"),
    );

    db.register(
        FFIContract::new(
            "BN_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free a BIGNUM"),
    );

    db.register(
        FFIContract::new(
            "BN_clear_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free a BIGNUM and clear sensitive data"),
    );

    // Error-prone patterns
    db.register(
        FFIContract::new(
            "SSL_get_peer_certificate",
            ContractType::Borrower,
            vec![],
            OwnershipSemantics::Borrowed,
            true,
            source,
        )
        .with_family(family)
        .with_notes("Returns borrowed reference; caller must not free"),
    );
}

/// Registers SQLite library contracts.
fn register_sqlite_contracts(db: &mut FFIContractDB) {
    let source = ContractSource::SQLite;
    let family = FamilyId::SQLITE_RESOURCE;

    // Database connection
    db.register(
        FFIContract::new(
            "sqlite3_open",
            ContractType::Allocator,
            vec!["sqlite3_close", "sqlite3_close_v2"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Open a database connection"),
    );

    db.register(
        FFIContract::new(
            "sqlite3_open_v2",
            ContractType::Allocator,
            vec!["sqlite3_close", "sqlite3_close_v2"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Open a database connection with extended options"),
    );

    db.register(
        FFIContract::new(
            "sqlite3_close",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Close a database connection"),
    );

    db.register(
        FFIContract::new(
            "sqlite3_close_v2",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Close a database connection (version 2)"),
    );

    // Prepared statements
    db.register(
        FFIContract::new(
            "sqlite3_prepare_v2",
            ContractType::Allocator,
            vec!["sqlite3_finalize"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Compile SQL into byte-code"),
    );

    db.register(
        FFIContract::new(
            "sqlite3_prepare_v3",
            ContractType::Allocator,
            vec!["sqlite3_finalize"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Compile SQL into byte-code (version 3)"),
    );

    db.register(
        FFIContract::new(
            "sqlite3_finalize",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Destroy a prepared statement"),
    );

    // Memory management
    db.register(
        FFIContract::new(
            "sqlite3_malloc",
            ContractType::Allocator,
            vec!["sqlite3_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Allocate memory using SQLite's allocator"),
    );

    db.register(
        FFIContract::new(
            "sqlite3_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free memory allocated by SQLite"),
    );

    // Error-prone patterns
    db.register(
        FFIContract::new(
            "sqlite3_column_text",
            ContractType::Borrower,
            vec![],
            OwnershipSemantics::Borrowed,
            true,
            source,
        )
        .with_family(family)
        .with_notes("Returns borrowed pointer; caller must not free"),
    );

    db.register(
        FFIContract::new(
            "sqlite3_column_blob",
            ContractType::Borrower,
            vec![],
            OwnershipSemantics::Borrowed,
            true,
            source,
        )
        .with_family(family)
        .with_notes("Returns borrowed pointer; caller must not free"),
    );
}

/// Registers Python C API contracts.
fn register_python_capi_contracts(db: &mut FFIContractDB) {
    let source = ContractSource::PythonCApi;
    let family = FamilyId::PYTHON_OBJECT;

    // Object creation (new reference)
    db.register(
        FFIContract::new(
            "PyObject_New",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new Python object; caller owns reference"),
    );

    db.register(
        FFIContract::new(
            "PyObject_NewVar",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new variable-size Python object"),
    );

    db.register(
        FFIContract::new(
            "PyType_GenericAlloc",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Generic allocation for type objects"),
    );

    // String/bytes creation
    db.register(
        FFIContract::new(
            "PyBytes_FromStringAndSize",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create bytes object from string"),
    );

    db.register(
        FFIContract::new(
            "PyBytes_FromString",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create bytes object from C string"),
    );

    db.register(
        FFIContract::new(
            "PyUnicode_FromString",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create Unicode object from C string"),
    );

    db.register(
        FFIContract::new(
            "PyUnicode_FromStringAndSize",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create Unicode object from string"),
    );

    // Collection creation
    db.register(
        FFIContract::new(
            "PyList_New",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new list object"),
    );

    db.register(
        FFIContract::new(
            "PyTuple_New",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new tuple object"),
    );

    db.register(
        FFIContract::new(
            "PyDict_New",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new dictionary object"),
    );

    db.register(
        FFIContract::new(
            "PySet_New",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new set object"),
    );

    // Reference counting
    db.register(
        FFIContract::new(
            "Py_DECREF",
            ContractType::Releaser,
            vec![],
            OwnershipSemantics::ReferenceCounted,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Decrement reference count"),
    );

    db.register(
        FFIContract::new(
            "Py_XDECREF",
            ContractType::Releaser,
            vec![],
            OwnershipSemantics::ReferenceCounted,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Decrement reference count (NULL-safe)"),
    );

    db.register(
        FFIContract::new(
            "Py_INCREF",
            ContractType::Retainer,
            vec![],
            OwnershipSemantics::ReferenceCounted,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Increment reference count"),
    );

    db.register(
        FFIContract::new(
            "Py_XINCREF",
            ContractType::Retainer,
            vec![],
            OwnershipSemantics::ReferenceCounted,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Increment reference count (NULL-safe)"),
    );

    // Error-prone borrowed references
    db.register(
        FFIContract::new(
            "PyList_GetItem",
            ContractType::Borrower,
            vec![],
            OwnershipSemantics::Borrowed,
            true,
            source,
        )
        .with_family(family)
        .with_notes("Returns borrowed reference; caller must not decrement"),
    );

    db.register(
        FFIContract::new(
            "PyTuple_GetItem",
            ContractType::Borrower,
            vec![],
            OwnershipSemantics::Borrowed,
            true,
            source,
        )
        .with_family(family)
        .with_notes("Returns borrowed reference; caller must not decrement"),
    );

    db.register(
        FFIContract::new(
            "PyDict_GetItem",
            ContractType::Borrower,
            vec![],
            OwnershipSemantics::Borrowed,
            true,
            source,
        )
        .with_family(family)
        .with_notes("Returns borrowed reference; caller must not decrement"),
    );

    // New reference functions
    db.register(
        FFIContract::new(
            "PyList_GetItemRef",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Returns new reference; caller must decrement"),
    );

    db.register(
        FFIContract::new(
            "PyDict_GetItemRef",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Returns new reference; caller must decrement"),
    );

    // Steal reference functions
    db.register(
        FFIContract::new(
            "PyTuple_SetItem",
            ContractType::Transfer,
            vec![],
            OwnershipSemantics::Transferred,
            true,
            source,
        )
        .with_family(family)
        .with_notes("Steals reference; caller must not decrement after call"),
    );

    db.register(
        FFIContract::new(
            "PyList_SetItem",
            ContractType::Transfer,
            vec![],
            OwnershipSemantics::Transferred,
            true,
            source,
        )
        .with_family(family)
        .with_notes("Steals reference; caller must not decrement after call"),
    );

    // Object destruction
    db.register(
        FFIContract::new(
            "PyObject_Del",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free a Python object"),
    );

    db.register(
        FFIContract::new(
            "PyObject_Free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free memory allocated for Python object"),
    );
}

/// Registers JNI (Java Native Interface) contracts.
fn register_jni_contracts(db: &mut FFIContractDB) {
    let source = ContractSource::JNI;
    let local_family = FamilyId::JAVA_LOCAL_REF;
    let global_family = FamilyId::JAVA_GLOBAL_REF;

    // Local references
    db.register(
        FFIContract::new(
            "NewLocalRef",
            ContractType::Allocator,
            vec!["DeleteLocalRef"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(local_family)
        .with_notes("Create a new local reference"),
    );

    db.register(
        FFIContract::new(
            "DeleteLocalRef",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(local_family)
        .with_notes("Delete a local reference"),
    );

    // Global references
    db.register(
        FFIContract::new(
            "NewGlobalRef",
            ContractType::Allocator,
            vec!["DeleteGlobalRef"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(global_family)
        .with_notes("Create a new global reference"),
    );

    db.register(
        FFIContract::new(
            "DeleteGlobalRef",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(global_family)
        .with_notes("Delete a global reference"),
    );

    // String operations (error-prone)
    db.register(
        FFIContract::new(
            "GetStringUTFChars",
            ContractType::Allocator,
            vec!["ReleaseStringUTFChars"],
            OwnershipSemantics::CallerOwns,
            true,
            source,
        )
        .with_family(local_family)
        .with_notes("Get string as UTF-8; must release with ReleaseStringUTFChars"),
    );

    db.register(
        FFIContract::new(
            "ReleaseStringUTFChars",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(local_family)
        .with_notes("Release string obtained from GetStringUTFChars"),
    );

    // Array operations
    db.register(
        FFIContract::new(
            "GetByteArrayElements",
            ContractType::Allocator,
            vec!["ReleaseByteArrayElements"],
            OwnershipSemantics::CallerOwns,
            true,
            source,
        )
        .with_family(local_family)
        .with_notes("Get byte array elements; must release"),
    );

    db.register(
        FFIContract::new(
            "ReleaseByteArrayElements",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(local_family)
        .with_notes("Release byte array elements"),
    );

    // Critical sections
    db.register(
        FFIContract::new(
            "GetPrimitiveArrayCritical",
            ContractType::Allocator,
            vec!["ReleasePrimitiveArrayCritical"],
            OwnershipSemantics::CallerOwns,
            true,
            source,
        )
        .with_family(local_family)
        .with_notes("Get primitive array; must release; no JNI calls in between"),
    );

    db.register(
        FFIContract::new(
            "ReleasePrimitiveArrayCritical",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(local_family)
        .with_notes("Release primitive array"),
    );

    // Object creation
    db.register(
        FFIContract::new(
            "NewStringUTF",
            ContractType::Allocator,
            vec!["DeleteLocalRef"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(local_family)
        .with_notes("Create a new Java string from UTF-8"),
    );

    db.register(
        FFIContract::new(
            "NewByteArray",
            ContractType::Allocator,
            vec!["DeleteLocalRef"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(local_family)
        .with_notes("Create a new byte array"),
    );

    // Auto-freed local references
    db.register(
        FFIContract::new(
            "GetObjectArrayElement",
            ContractType::Borrower,
            vec![],
            OwnershipSemantics::Borrowed,
            false,
            source,
        )
        .with_family(local_family)
        .with_notes("Returns borrowed local reference; auto-freed on return"),
    );
}

/// Registers POSIX standard library contracts.
fn register_posix_contracts(db: &mut FFIContractDB) {
    let source = ContractSource::Posix;
    let family = FamilyId::C_HEAP;

    // File operations
    db.register(
        FFIContract::new(
            "open",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Open a file; returns file descriptor"),
    );

    db.register(
        FFIContract::new(
            "close",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Close a file descriptor"),
    );

    // Socket operations
    db.register(
        FFIContract::new(
            "socket",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a socket; returns file descriptor"),
    );

    db.register(
        FFIContract::new(
            "accept",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Accept a connection; returns new file descriptor"),
    );

    // Memory mapping
    db.register(
        FFIContract::new(
            "mmap",
            ContractType::Allocator,
            vec!["munmap"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Map memory; caller must unmap"),
    );

    db.register(
        FFIContract::new(
            "munmap",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Unmap memory"),
    );

    // Process management
    db.register(
        FFIContract::new(
            "fork",
            ContractType::Allocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a new process"),
    );

    // Pipe operations
    db.register(
        FFIContract::new(
            "pipe",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a pipe; returns two file descriptors"),
    );

    // Error-prone patterns
    db.register(
        FFIContract::new(
            "opendir",
            ContractType::Allocator,
            vec!["closedir"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Open a directory stream"),
    );

    db.register(
        FFIContract::new(
            "closedir",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Close a directory stream"),
    );

    // Thread-local storage
    db.register(
        FFIContract::new(
            "pthread_key_create",
            ContractType::Allocator,
            vec!["pthread_key_delete"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Create a thread-specific data key"),
    );

    db.register(
        FFIContract::new(
            "pthread_key_delete",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Delete a thread-specific data key"),
    );
}

/// Registers GLib/GObject library contracts.
fn register_glib_contracts(db: &mut FFIContractDB) {
    let source = ContractSource::Glib;
    let family = FamilyId::C_HEAP; // GLib uses g_malloc/g_free

    // Memory allocation
    db.register(
        FFIContract::new(
            "g_malloc",
            ContractType::Allocator,
            vec!["g_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Allocate memory"),
    );

    db.register(
        FFIContract::new(
            "g_malloc0",
            ContractType::Allocator,
            vec!["g_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Allocate zero-initialized memory"),
    );

    db.register(
        FFIContract::new(
            "g_realloc",
            ContractType::Allocator,
            vec!["g_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Reallocate memory"),
    );

    db.register(
        FFIContract::new(
            "g_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free memory allocated by GLib"),
    );

    // GObject reference counting
    db.register(
        FFIContract::new(
            "g_object_ref",
            ContractType::Retainer,
            vec![],
            OwnershipSemantics::ReferenceCounted,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Increment GObject reference count"),
    );

    db.register(
        FFIContract::new(
            "g_object_unref",
            ContractType::Releaser,
            vec![],
            OwnershipSemantics::ReferenceCounted,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Decrement GObject reference count"),
    );

    // String operations
    db.register(
        FFIContract::new(
            "g_strdup",
            ContractType::Allocator,
            vec!["g_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Duplicate a string"),
    );

    db.register(
        FFIContract::new(
            "g_strndup",
            ContractType::Allocator,
            vec!["g_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Duplicate a string up to n bytes"),
    );

    // Error-prone patterns
    db.register(
        FFIContract::new(
            "g_object_get_data",
            ContractType::Borrower,
            vec![],
            OwnershipSemantics::Borrowed,
            true,
            source,
        )
        .with_family(family)
        .with_notes("Returns borrowed data; caller must not free"),
    );
}

/// Registers zlib compression library contracts.
fn register_zlib_contracts(db: &mut FFIContractDB) {
    let source = ContractSource::Zlib;
    let family = FamilyId::ZLIB_STREAM;

    // Stream initialization
    db.register(
        FFIContract::new(
            "inflateInit_",
            ContractType::Allocator,
            vec!["inflateEnd"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Initialize inflate stream"),
    );

    db.register(
        FFIContract::new(
            "inflateInit2_",
            ContractType::Allocator,
            vec!["inflateEnd"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Initialize inflate stream with window bits"),
    );

    db.register(
        FFIContract::new(
            "inflateEnd",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("End inflate stream"),
    );

    db.register(
        FFIContract::new(
            "deflateInit_",
            ContractType::Allocator,
            vec!["deflateEnd"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Initialize deflate stream"),
    );

    db.register(
        FFIContract::new(
            "deflateInit2_",
            ContractType::Allocator,
            vec!["deflateEnd"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Initialize deflate stream with all parameters"),
    );

    db.register(
        FFIContract::new(
            "deflateEnd",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("End deflate stream"),
    );
}

/// Registers libuv event loop library contracts.
fn register_libuv_contracts(db: &mut FFIContractDB) {
    let source = ContractSource::Libuv;
    let family = FamilyId::C_HEAP; // libuv uses malloc/free

    // Handle allocation
    db.register(
        FFIContract::new(
            "uv_loop_init",
            ContractType::Allocator,
            vec!["uv_loop_close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Initialize event loop"),
    );

    db.register(
        FFIContract::new(
            "uv_loop_close",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Close event loop"),
    );

    // Handle operations
    db.register(
        FFIContract::new(
            "uv_handle_init",
            ContractType::Allocator,
            vec!["uv_close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Initialize a handle"),
    );

    db.register(
        FFIContract::new(
            "uv_close",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Close a handle"),
    );

    // Request operations
    db.register(
        FFIContract::new(
            "uv_req_init",
            ContractType::Allocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Initialize a request"),
    );

    // Timer operations
    db.register(
        FFIContract::new(
            "uv_timer_init",
            ContractType::Allocator,
            vec!["uv_close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Initialize a timer handle"),
    );

    // Error-prone patterns
    db.register(
        FFIContract::new(
            "uv_default_loop",
            ContractType::Borrower,
            vec![],
            OwnershipSemantics::Borrowed,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Returns default loop; caller must not free"),
    );
}
