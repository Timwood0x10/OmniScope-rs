//! GLib/GObject library FFI contracts.

use omniscope_types::FamilyId;

use super::super::database::FFIContractDB;
use super::super::types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};

/// Registers GLib/GObject library contracts.
pub fn register_contracts(db: &mut FFIContractDB) {
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
