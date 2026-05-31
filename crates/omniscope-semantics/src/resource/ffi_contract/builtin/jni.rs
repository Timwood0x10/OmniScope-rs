//! JNI (Java Native Interface) FFI contracts.

use omniscope_types::FamilyId;

use super::super::database::FFIContractDB;
use super::super::types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};

/// Registers JNI (Java Native Interface) contracts.
pub fn register_contracts(db: &mut FFIContractDB) {
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
