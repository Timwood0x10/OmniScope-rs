//! Tests for FFIContractDB.
//!
//! This module contains comprehensive tests for the FFI contract database,
//! covering all built-in contracts and query functionality.

#[cfg(test)]
mod tests {
    mod glib;
    mod jni;
    mod libuv;
    mod openssl;
    mod posix;
    mod proptest;
    mod python;
    mod query;
    mod sqlite;

    use super::super::database::FFIContractDB;

    /// Objective: Verify that the FFIContractDB is properly populated with built-in contracts.
    ///
    /// Invariants:
    /// - The database should contain more than 100 contracts after initialization
    /// - All built-in contracts from various sources (OpenSSL, SQLite, Python/C API, etc.) should be registered
    #[test]
    fn test_database_populated() {
        let db = FFIContractDB::new();
        assert!(
            db.len() > 100,
            "Must have many built-in contracts, got {}",
            db.len()
        );
    }
}
