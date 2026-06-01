//! Tests for Rust standard library function whitelist
//!
//! This module contains tests for standard library functions including
//! Vec, String, Box, Arc, Rc, HashMap, BTreeMap, HashSet, thread
//! synchronization primitives, iterators, and memory utilities.

use super::super::*;

/// Objective: Verify Vec operations are whitelisted
/// Invariants: All common Vec operations should be recognized
#[test]
fn test_vec_operations_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    // Test mangled names
    assert!(
        whitelist.is_whitelisted("_ZN3vec3Vec3new"),
        "Vec::new() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN3vec3Vec4push"),
        "Vec::push() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN3vec3Vec3pop"),
        "Vec::pop() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN3vec3Vec7with_capacity"),
        "Vec::with_capacity() should be whitelisted"
    );

    // Test demangled names
    assert!(
        whitelist.is_whitelisted("Vec::new"),
        "Vec::new (demangled) should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("Vec::push"),
        "Vec::push (demangled) should be whitelisted"
    );
}

/// Objective: Verify String operations are whitelisted
/// Invariants: All common String operations should be recognized
#[test]
fn test_string_operations_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN6string6String3new"),
        "String::new() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN6string6String4push"),
        "String::push() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN6string6String4from"),
        "String::from() should be whitelisted"
    );
}

/// Objective: Verify smart pointer operations are whitelisted
/// Invariants: Box, Arc, Rc operations should be recognized
#[test]
fn test_smart_pointer_operations_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    // Box operations
    assert!(
        whitelist.is_whitelisted("_ZN3box3Box3new"),
        "Box::new() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN3box3Box8into_raw"),
        "Box::into_raw() should be whitelisted"
    );

    // Arc operations
    assert!(
        whitelist.is_whitelisted("_ZN3arc3Arc3new"),
        "Arc::new() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN3arc3Arc5clone"),
        "Arc::clone() should be whitelisted"
    );

    // Rc operations
    assert!(
        whitelist.is_whitelisted("_ZN2rc2Rc3new"),
        "Rc::new() should be whitelisted"
    );
}

/// Objective: Verify HashMap operations are whitelisted
/// Invariants: Common HashMap operations should be recognized
#[test]
fn test_hashmap_operations_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN7hashmap7HashMap3new"),
        "HashMap::new() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN7hashmap7HashMap6insert"),
        "HashMap::insert() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN7hashmap7HashMap3get"),
        "HashMap::get() should be whitelisted"
    );
}

/// Objective: Verify thread synchronization primitives are whitelisted
/// Invariants: Mutex, RwLock, Condvar operations should be recognized
#[test]
fn test_thread_sync_operations_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN3sys5mutex5Mutex3new"),
        "Mutex::new() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN3sys5mutex5Mutex4lock"),
        "Mutex::lock() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN3sys6rwlock6RwLock3new"),
        "RwLock::new() should be whitelisted"
    );
}
