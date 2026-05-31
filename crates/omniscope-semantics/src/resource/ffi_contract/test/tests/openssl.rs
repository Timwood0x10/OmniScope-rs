//! OpenSSL FFI contract tests.

use super::super::super::database::FFIContractDB;
use super::super::super::types::{ContractSource, ContractType, OwnershipSemantics};

/// Objective: Verify that OPENSSL_malloc is correctly registered as an OpenSSL allocator.
///
/// Invariants:
/// - OPENSSL_malloc should be found in the database
/// - Contract type should be Allocator
/// - Source should be OpenSSL
/// - Paired release should include OPENSSL_free
/// - Ownership semantics should be CallerOwns
#[test]
fn test_openssl_malloc() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("OPENSSL_malloc")
        .expect("ffi_contract::test::test_openssl_malloc: OPENSSL_malloc not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert_eq!(c.source, ContractSource::OpenSSL);
    assert!(c.paired_release.contains(&"OPENSSL_free".to_string()));
    assert_eq!(c.ownership, OwnershipSemantics::CallerOwns);
}

/// Objective: Verify that OPENSSL_free is correctly registered as an OpenSSL deallocator.
///
/// Invariants:
/// - OPENSSL_free should be found in the database
/// - Contract type should be Deallocator
/// - Source should be OpenSSL
#[test]
fn test_openssl_free() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("OPENSSL_free")
        .expect("ffi_contract::test::test_openssl_free: OPENSSL_free not found");
    assert_eq!(c.contract_type, ContractType::Deallocator);
    assert_eq!(c.source, ContractSource::OpenSSL);
}

/// Objective: Verify that OPENSSL_strdup is correctly registered as an OpenSSL allocator.
///
/// Invariants:
/// - OPENSSL_strdup should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include OPENSSL_free
#[test]
fn test_openssl_strdup() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("OPENSSL_strdup")
        .expect("ffi_contract::test::test_openssl_strdup: OPENSSL_strdup not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"OPENSSL_free".to_string()));
}

/// Objective: Verify that OPENSSL_clear_free is correctly registered as an OpenSSL deallocator.
///
/// Invariants:
/// - OPENSSL_clear_free should be found in the database
/// - Contract type should be Deallocator
#[test]
fn test_openssl_clear_free() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("OPENSSL_clear_free")
        .expect("ffi_contract::test::test_openssl_clear_free: OPENSSL_clear_free not found");
    assert_eq!(c.contract_type, ContractType::Deallocator);
}

/// Objective: Verify that CRYPTO_secure_malloc is correctly registered as an OpenSSL allocator.
///
/// Invariants:
/// - CRYPTO_secure_malloc should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include CRYPTO_secure_free
#[test]
fn test_openssl_secure_malloc() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("CRYPTO_secure_malloc")
        .expect("ffi_contract::test::test_openssl_secure_malloc: CRYPTO_secure_malloc not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"CRYPTO_secure_free".to_string()));
}

/// Objective: Verify that EVP_MD_CTX_new is correctly registered as an OpenSSL allocator.
///
/// Invariants:
/// - EVP_MD_CTX_new should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include EVP_MD_CTX_free
#[test]
fn test_evp_md_ctx() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("EVP_MD_CTX_new")
        .expect("ffi_contract::test::test_evp_md_ctx: EVP_MD_CTX_new not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"EVP_MD_CTX_free".to_string()));
}

/// Objective: Verify that EVP_CIPHER_CTX_new is correctly registered as an OpenSSL allocator.
///
/// Invariants:
/// - EVP_CIPHER_CTX_new should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include EVP_CIPHER_CTX_free
#[test]
fn test_evp_cipher_ctx() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("EVP_CIPHER_CTX_new")
        .expect("ffi_contract::test::test_evp_cipher_ctx: EVP_CIPHER_CTX_new not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c
        .paired_release
        .contains(&"EVP_CIPHER_CTX_free".to_string()));
}

/// Objective: Verify that BIO_new is correctly registered as an OpenSSL allocator.
///
/// Invariants:
/// - BIO_new should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include both BIO_free and BIO_free_all
#[test]
fn test_bio_new() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("BIO_new")
        .expect("ffi_contract::test::test_bio_new: BIO_new not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"BIO_free".to_string()));
    assert!(c.paired_release.contains(&"BIO_free_all".to_string()));
}

/// Objective: Verify that SSL_CTX_new is correctly registered as an OpenSSL allocator.
///
/// Invariants:
/// - SSL_CTX_new should be found in the database
/// - Contract type should be Allocator
/// - Paired release should include SSL_CTX_free
#[test]
fn test_ssl_ctx() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("SSL_CTX_new")
        .expect("ffi_contract::test::test_ssl_ctx: SSL_CTX_new not found");
    assert_eq!(c.contract_type, ContractType::Allocator);
    assert!(c.paired_release.contains(&"SSL_CTX_free".to_string()));
}

/// Objective: Verify that X509_free is correctly registered as an OpenSSL deallocator.
///
/// Invariants:
/// - X509_free should be found in the database
/// - Contract type should be Deallocator
#[test]
fn test_x509_free() {
    let db = FFIContractDB::new();
    let c = db
        .lookup("X509_free")
        .expect("ffi_contract::test::test_x509_free: X509_free not found");
    assert_eq!(c.contract_type, ContractType::Deallocator);
}
