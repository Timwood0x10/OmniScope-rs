//! Python C API FFI contracts.

use omniscope_types::FamilyId;

use super::super::database::FFIContractDB;
use super::super::types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};

/// Registers Python C API contracts.
pub fn register_contracts(db: &mut FFIContractDB) {
    let source = ContractSource::PythonCApi;
    let family = FamilyId::PYTHON_OBJECT;

    // Object creation (new reference)
    db.register(
        FFIContract::new(
            "PyObject_New",
            ContractType::Allocator,
            vec!["Py_DECREF", "Py_XDECREF"],
            OwnershipSemantics::ReferenceCounted,
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
            vec!["Py_DECREF"],
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

    // Value creation
    db.register(
        FFIContract::new(
            "Py_BuildValue",
            ContractType::Allocator,
            vec!["Py_DECREF"],
            OwnershipSemantics::ReferenceCounted,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Build a Python value from C values"),
    );

    // GIL management
    db.register(
        FFIContract::new(
            "PyGILState_Ensure",
            ContractType::Allocator,
            vec!["PyGILState_Release"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Ensure GIL is held; returns GIL state"),
    );

    db.register(
        FFIContract::new(
            "PyGILState_Release",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Release GIL"),
    );
}
