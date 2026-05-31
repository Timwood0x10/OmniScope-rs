//! Built-in FFI contract rules.
//!
//! This module contains the built-in FFI contract rules for common libraries,
//! including OpenSSL, SQLite, Python C API, JNI, POSIX, GLib, zlib, and libuv.

mod glib;
mod jni;
mod libuv;
mod openssl;
mod posix;
mod python;
mod sqlite;
mod zlib;

use super::database::FFIContractDB;

/// Registers all built-in FFI contracts into the database.
pub fn register_builtin_contracts(db: &mut FFIContractDB) {
    // OpenSSL contracts
    openssl::register_contracts(db);

    // SQLite contracts
    sqlite::register_contracts(db);

    // Python C API contracts
    python::register_contracts(db);

    // JNI contracts
    jni::register_contracts(db);

    // POSIX contracts
    posix::register_contracts(db);

    // GLib/GObject contracts
    glib::register_contracts(db);

    // zlib contracts
    zlib::register_contracts(db);

    // libuv contracts
    libuv::register_contracts(db);
}
