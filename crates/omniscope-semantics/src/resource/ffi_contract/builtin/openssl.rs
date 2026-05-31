//! OpenSSL library FFI contracts.

use omniscope_types::FamilyId;

use super::super::database::FFIContractDB;
use super::super::types::{ContractSource, ContractType, FFIContract, OwnershipSemantics};

/// Registers OpenSSL library contracts.
pub fn register_contracts(db: &mut FFIContractDB) {
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

    // Memory allocation
    db.register(
        FFIContract::new(
            "OPENSSL_malloc",
            ContractType::Allocator,
            vec!["OPENSSL_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Allocate memory using OpenSSL's allocator"),
    );

    db.register(
        FFIContract::new(
            "OPENSSL_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free memory allocated by OpenSSL"),
    );

    db.register(
        FFIContract::new(
            "OPENSSL_strdup",
            ContractType::Allocator,
            vec!["OPENSSL_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Duplicate a string using OpenSSL's allocator"),
    );

    db.register(
        FFIContract::new(
            "OPENSSL_clear_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free memory and clear sensitive data"),
    );

    db.register(
        FFIContract::new(
            "CRYPTO_secure_malloc",
            ContractType::Allocator,
            vec!["CRYPTO_secure_free"],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Allocate secure memory"),
    );

    db.register(
        FFIContract::new(
            "CRYPTO_secure_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free secure memory"),
    );

    // X509
    db.register(
        FFIContract::new(
            "X509_free",
            ContractType::Deallocator,
            vec![],
            OwnershipSemantics::CallerOwns,
            false,
            source,
        )
        .with_family(family)
        .with_notes("Free an X509 structure"),
    );
}
