//! POSIX standard library FFI contracts.

use omniscope_types::FamilyId;

use super::super::database::FFIContractDB;
use super::super::types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};

/// Registers POSIX standard library contracts.
pub fn register_contracts(db: &mut FFIContractDB) {
    let source = ContractSource::Posix;
    let mem_family = FamilyId::C_HEAP;
    let fd_family = FamilyId::FILE_DESCRIPTOR;

    // ── Memory allocation (heap memory) ──
    db.register(
        FFIContract::new(
            "malloc",
            ContractType::Allocator,
            vec!["free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(mem_family)
        .with_notes("Allocate memory"),
    );

    db.register(
        FFIContract::new(
            "free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(mem_family)
        .with_notes("Free allocated memory"),
    );

    db.register(
        FFIContract::new(
            "calloc",
            ContractType::Allocator,
            vec!["free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(mem_family)
        .with_notes("Allocate zero-initialized memory"),
    );

    db.register(
        FFIContract::new(
            "realloc",
            ContractType::Allocator,
            vec!["free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(mem_family)
        .with_notes("Reallocate memory"),
    );

    db.register(
        FFIContract::new(
            "strdup",
            ContractType::Allocator,
            vec!["free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(mem_family)
        .with_notes("Duplicate a string"),
    );

    db.register(
        FFIContract::new(
            "strndup",
            ContractType::Allocator,
            vec!["free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(mem_family)
        .with_notes("Duplicate a string up to n bytes"),
    );

    db.register(
        FFIContract::new(
            "aligned_alloc",
            ContractType::Allocator,
            vec!["free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(mem_family)
        .with_notes("Allocate aligned memory"),
    );

    // ── File descriptor operations (FILE_DESCRIPTOR family) ──
    // Acquire: functions that return a new file descriptor
    db.register(
        FFIContract::new(
            "open",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Open a file; returns file descriptor"),
    );

    db.register(
        FFIContract::new(
            "openat",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Open a file relative to directory fd; returns file descriptor"),
    );

    db.register(
        FFIContract::new(
            "creat",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Create a file; returns file descriptor"),
    );

    // Release: closes a file descriptor
    db.register(
        FFIContract::new(
            "close",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Close a file descriptor"),
    );

    // FD duplication (acquires new fd, releases old fd is caller's responsibility)
    db.register(
        FFIContract::new(
            "dup",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Duplicate a file descriptor; returns new fd"),
    );

    db.register(
        FFIContract::new(
            "dup2",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Duplicate fd to specified number; returns new fd"),
    );

    // FD → FILE* transfer (fdopen wraps an fd into a FILE*)
    // The fd is transferred to stdio ownership; fclose releases both.
    db.register(
        FFIContract::new(
            "fdopen",
            ContractType::Allocator,
            vec!["fclose"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Wrap file descriptor into FILE* stream"),
    );

    // ── FILE* stream operations (stdio) ──
    // fopen/fclose manage FILE* streams (distinct from raw fds but tracked
    // in the same family since fclose releases the underlying fd).
    db.register(
        FFIContract::new(
            "fopen",
            ContractType::Allocator,
            vec!["fclose"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Open a file stream"),
    );

    db.register(
        FFIContract::new(
            "fclose",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Close a file stream (releases underlying fd)"),
    );

    // ── Socket operations (FILE_DESCRIPTOR family) ──
    db.register(
        FFIContract::new(
            "socket",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
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
        .with_family(fd_family)
        .with_notes("Accept a connection; returns new file descriptor"),
    );

    db.register(
        FFIContract::new(
            "accept4",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Accept a connection (flags); returns new file descriptor"),
    );

    // ── Memory mapping (heap memory — returns pointer, not fd) ──
    db.register(
        FFIContract::new(
            "mmap",
            ContractType::Allocator,
            vec!["munmap"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(mem_family)
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
        .with_family(mem_family)
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
        .with_family(mem_family)
        .with_notes("Create a new process"),
    );

    // Pipe operations (returns two fds)
    db.register(
        FFIContract::new(
            "pipe",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Create a pipe; returns two file descriptors"),
    );

    db.register(
        FFIContract::new(
            "pipe2",
            ContractType::Allocator,
            vec!["close"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(fd_family)
        .with_notes("Create a pipe (flags); returns two file descriptors"),
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
        .with_family(fd_family)
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
        .with_family(fd_family)
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
        .with_family(mem_family)
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
        .with_family(mem_family)
        .with_notes("Delete a thread-specific data key"),
    );
}
