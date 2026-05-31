//! libuv event loop library FFI contracts.

use omniscope_types::FamilyId;

use super::super::database::FFIContractDB;
use super::super::types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};

/// Registers libuv event loop library contracts.
pub fn register_contracts(db: &mut FFIContractDB) {
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
