//! POSIX standard library FFI contracts.

use omniscope_types::FamilyId;

use super::super::database::FFIContractDB;
use super::super::types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};

/// Registers POSIX standard library contracts.
pub fn register_contracts(db: &mut FFIContractDB) {
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
