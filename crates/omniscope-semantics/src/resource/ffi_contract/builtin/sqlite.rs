//! SQLite library FFI contracts.

use omniscope_types::FamilyId;

use super::super::database::FFIContractDB;
use super::super::types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};

/// Registers SQLite library contracts.
pub fn register_contracts(db: &mut FFIContractDB) {
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

    // SQL execution
    db.register(
        FFIContract::new(
            "sqlite3_exec",
            ContractType::Borrower,
            vec![],
            OwnershipSemantics::Borrowed,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Execute SQL; borrows database connection"),
    );
}
