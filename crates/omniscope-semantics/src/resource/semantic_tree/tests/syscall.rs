//! Tests for SyscallSemantic classification.

use super::super::*;

/// Objective: Verify that getenv is correctly classified as EnvironmentConfig syscall.
///
/// Invariants:
/// - getenv function name should be classified as EnvironmentConfig
#[test]
fn test_syscall_classify_getenv() {
    assert_eq!(
        SyscallSemantic::classify("getenv"),
        SyscallSemantic::EnvironmentConfig
    );
}

/// Objective: Verify that strlen is correctly classified as DataQuery syscall.
///
/// Invariants:
/// - strlen function name should be classified as DataQuery
#[test]
fn test_syscall_classify_strlen() {
    assert_eq!(
        SyscallSemantic::classify("strlen"),
        SyscallSemantic::DataQuery
    );
}

/// Objective: Verify that malloc is correctly classified as MemoryManagement syscall.
///
/// Invariants:
/// - malloc function name should be classified as MemoryManagement
#[test]
fn test_syscall_classify_malloc() {
    assert_eq!(
        SyscallSemantic::classify("malloc"),
        SyscallSemantic::MemoryManagement
    );
}

/// Objective: Verify that free is correctly classified as MemoryManagement syscall.
///
/// Invariants:
/// - free function name should be classified as MemoryManagement
#[test]
fn test_syscall_classify_free() {
    assert_eq!(
        SyscallSemantic::classify("free"),
        SyscallSemantic::MemoryManagement
    );
}

/// Objective: Verify that highway functions are correctly classified as ComputeAccelerated syscall.
///
/// Invariants:
/// - highway_index_of_char function name should be classified as ComputeAccelerated
#[test]
fn test_syscall_classify_highway() {
    assert_eq!(
        SyscallSemantic::classify("highway_index_of_char"),
        SyscallSemantic::ComputeAccelerated
    );
}

/// Objective: Verify that Bun dispatch functions are correctly classified as InternalDispatch syscall.
///
/// Invariants:
/// - __bun_dispatch__OutputSink__Sys__quiet_writer_write_all function name should be classified as InternalDispatch
#[test]
fn test_syscall_classify_bun_dispatch() {
    assert_eq!(
        SyscallSemantic::classify("__bun_dispatch__OutputSink__Sys__quiet_writer_write_all"),
        SyscallSemantic::InternalDispatch
    );
}

/// Objective: Verify that Bun string functions are correctly classified as InternalDispatch syscall.
///
/// Invariants:
/// - BunString__fromBytes function name should be classified as InternalDispatch
#[test]
fn test_syscall_classify_bun_string() {
    assert_eq!(
        SyscallSemantic::classify("BunString__fromBytes"),
        SyscallSemantic::InternalDispatch
    );
}

/// Objective: Verify that WTF destroy functions are correctly classified as InternalDispatch syscall.
///
/// Invariants:
/// - Bun__WTFStringImpl__destroy function name should be classified as InternalDispatch
#[test]
fn test_syscall_classify_wtf_destroy() {
    assert_eq!(
        SyscallSemantic::classify("Bun__WTFStringImpl__destroy"),
        SyscallSemantic::InternalDispatch
    );
}
