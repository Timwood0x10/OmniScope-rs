//! Tests for third-party crate function whitelist
//!
//! This module contains tests for common Rust third-party crate functions
//! including serde, tokio, anyhow, thiserror, tracing, rayon, crossbeam,
//! bytes, regex, chrono, and reqwest.

use super::super::*;

/// Objective: Verify third-party crate functions are whitelisted
/// Invariants: serde, tokio, anyhow functions should be recognized
#[test]
fn test_third_party_crates_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    // Serde
    assert!(
        whitelist.is_whitelisted("_ZN5serde10Serialize9serialize"),
        "serde::Serialize::serialize() should be whitelisted"
    );

    // Tokio
    assert!(
        whitelist.is_whitelisted("_ZN5tokio4task5spawn"),
        "tokio::task::spawn() should be whitelisted"
    );

    // Anyhow
    assert!(
        whitelist.is_whitelisted("_ZN6anyhow5Error3new"),
        "anyhow::Error::new() should be whitelisted"
    );
}

/// Objective: Verify serde serialization functions are whitelisted
/// Invariants: All common serde serialization functions should be recognized
#[test]
fn test_serde_serialization_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN5serde10Serialize9serialize"),
        "serde::Serialize::serialize() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5serde12Deserialize11deserialize"),
        "serde::Deserialize::deserialize() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5serde3ser14Serializer14serialize_bool"),
        "Serializer::serialize_bool() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5serde3ser14Serializer14serialize_i32"),
        "Serializer::serialize_i32() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5serde3ser14Serializer15serialize_str"),
        "Serializer::serialize_str() should be whitelisted"
    );
}

/// Objective: Verify tokio async runtime functions are whitelisted
/// Invariants: All common tokio functions should be recognized
#[test]
fn test_tokio_async_runtime_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN5tokio4task5spawn"),
        "tokio::task::spawn() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5tokio4task6spawn_blocking"),
        "tokio::task::spawn_blocking() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5tokio4task5yield_now"),
        "tokio::task::yield_now() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5tokio5timer5sleep"),
        "tokio::timer::sleep() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5tokio5timer7timeout"),
        "tokio::timer::timeout() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5tokio2io5AsyncRead4read"),
        "AsyncRead::read() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5tokio2io6AsyncWrite5write"),
        "AsyncWrite::write() should be whitelisted"
    );
}

/// Objective: Verify error handling crate functions are whitelisted
/// Invariants: anyhow and thiserror functions should be recognized
#[test]
fn test_error_handling_crates_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    // Anyhow
    assert!(
        whitelist.is_whitelisted("_ZN6anyhow5Error3new"),
        "anyhow::Error::new() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN6anyhow5Error7context"),
        "anyhow::Error::context() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN6anyhow6Result6unwrap"),
        "anyhow::Result::unwrap() should be whitelisted"
    );

    // Thiserror
    assert!(
        whitelist.is_whitelisted("_ZN9thiserror5Error9from_source"),
        "thiserror::Error::from_source() should be whitelisted"
    );
}

/// Objective: Verify tracing/logging functions are whitelisted
/// Invariants: Tracing macros should be recognized
#[test]
fn test_tracing_logging_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN5tracing5event5event"),
        "tracing::event!() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5tracing5span5span"),
        "tracing::span!() should be whitelisted"
    );
}

/// Objective: Verify rayon parallel iterator functions are whitelisted
/// Invariants: Rayon parallel operations should be recognized
#[test]
fn test_rayon_parallel_iterators_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN5rayon4iter8Parallel4for_each"),
        "rayon::ParallelIterator::for_each() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5rayon4iter8Parallel3map"),
        "rayon::ParallelIterator::map() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5rayon4iter8Parallel7collect"),
        "rayon::ParallelIterator::collect() should be whitelisted"
    );
}

/// Objective: Verify crossbeam channel functions are whitelisted
/// Invariants: Crossbeam concurrency primitives should be recognized
#[test]
fn test_crossbeam_channels_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN8crossbeam7channel5after"),
        "crossbeam::channel::after() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN8crossbeam7channel5never"),
        "crossbeam::channel::never() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN8crossbeam7channel4tick"),
        "crossbeam::channel::tick() should be whitelisted"
    );
}

/// Objective: Verify bytes crate functions are whitelisted
/// Invariants: Bytes buffer operations should be recognized
#[test]
fn test_bytes_crate_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN5bytes6Bytes3new"),
        "bytes::Bytes::new() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5bytes6Bytes7with_capacity"),
        "bytes::Bytes::with_capacity() should be whitelisted"
    );
}

/// Objective: Verify regex functions are whitelisted
/// Invariants: Regex pattern matching should be recognized
#[test]
fn test_regex_operations_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN5regex5Regex3new"),
        "regex::Regex::new() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5regex5Regex5is_match"),
        "regex::Regex::is_match() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5regex5Regex6find"),
        "regex::Regex::find() should be whitelisted"
    );
}

/// Objective: Verify chrono time functions are whitelisted
/// Invariants: Chrono time operations should be recognized
#[test]
fn test_chrono_time_operations_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN5chrono6Utc3now"),
        "chrono::Utc::now() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN5chrono9NaiveDate14from_ymd_opt"),
        "chrono::NaiveDate::from_ymd_opt() should be whitelisted"
    );
}

/// Objective: Verify reqwest HTTP client functions are whitelisted
/// Invariants: Reqwest HTTP operations should be recognized
#[test]
fn test_reqwest_http_client_whitelisted() {
    let whitelist = RustStdlibWhitelist::new();

    assert!(
        whitelist.is_whitelisted("_ZN7reqwest7Client3new"),
        "reqwest::Client::new() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN7reqwest7Client3get"),
        "reqwest::Client::get() should be whitelisted"
    );
    assert!(
        whitelist.is_whitelisted("_ZN7reqwest7Client4post"),
        "reqwest::Client::post() should be whitelisted"
    );
}
