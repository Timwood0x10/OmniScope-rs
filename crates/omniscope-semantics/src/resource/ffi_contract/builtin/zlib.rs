//! zlib compression library FFI contracts.

use omniscope_types::FamilyId;

use super::super::database::FFIContractDB;
use super::super::types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};

/// Registers zlib compression library contracts.
pub fn register_contracts(db: &mut FFIContractDB) {
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
