//! Exception handling pattern detection for C++.
//!
//! This module provides exception handling-specific semantic analysis, including:
//! - try/catch block detection
//! - throw expression detection
//! - noexcept function detection
//! - Exception safety assessment

use super::CppSemanticPattern;

/// Checks if a function name indicates a throw expression.
///
/// # Objective
/// Detect throw expression patterns in C++ function names. Throw expressions
/// are used to signal exceptional conditions and are identified by
/// __cxa_throw or __cxa_rethrow patterns.
///
/// # Invariants
/// - Returns true for __cxa_throw or __cxa_rethrow patterns.
/// - Returns false for non-throw patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for throw patterns.
///
/// # Returns
/// `true` if the function is identified as a throw expression, `false` otherwise.
pub fn is_throw_expression(function_name: &str) -> bool {
    function_name.contains("__cxa_throw") || function_name.contains("__cxa_rethrow")
}

/// Checks if a function name indicates a catch block.
///
/// # Objective
/// Detect catch block patterns in C++ function names. Catch blocks
/// handle exceptions and are identified by __cxa_begin_catch or
/// __cxa_end_catch patterns.
///
/// # Invariants
/// - Returns true for __cxa_begin_catch or __cxa_end_catch patterns.
/// - Returns false for non-catch patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for catch patterns.
///
/// # Returns
/// `true` if the function is identified as a catch block, `false` otherwise.
pub fn is_catch_block(function_name: &str) -> bool {
    function_name.contains("__cxa_begin_catch") || function_name.contains("__cxa_end_catch")
}

/// Checks if a function name indicates a try block.
///
/// # Objective
/// Detect try block patterns in C++ function names. Try blocks
/// are identified by __cxa_begin_cleanup patterns.
///
/// # Invariants
/// - Returns true for __cxa_begin_cleanup patterns.
/// - Returns false for non-try patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for try patterns.
///
/// # Returns
/// `true` if the function is identified as a try block, `false` otherwise.
pub fn is_try_block(function_name: &str) -> bool {
    function_name.contains("__cxa_begin_cleanup")
}

/// Checks if a function name indicates a noexcept function.
///
/// # Objective
/// Detect noexcept patterns in C++ function names. noexcept functions
/// are guaranteed not to throw exceptions and are identified by
/// "noexcept" or "DnE" patterns.
///
/// # Invariants
/// - Returns true for "noexcept" or "DnE" patterns.
/// - Returns false for non-noexcept patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for noexcept patterns.
///
/// # Returns
/// `true` if the function is identified as noexcept, `false` otherwise.
pub fn is_noexcept(function_name: &str) -> bool {
    function_name.contains("noexcept") || function_name.contains("DnE")
}

/// Checks if a function name indicates a pure virtual function.
///
/// # Objective
/// Detect pure virtual function patterns in C++ function names. Pure
/// virtual functions are abstract class indicators and are identified
/// by __cxa_pure_virtual patterns.
///
/// # Invariants
/// - Returns true for __cxa_pure_virtual or pure_virtual patterns.
/// - Returns false for non-pure-virtual patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for pure virtual patterns.
///
/// # Returns
/// `true` if the function is identified as a pure virtual function, `false` otherwise.
pub fn is_pure_virtual(function_name: &str) -> bool {
    function_name.contains("__cxa_pure_virtual") || function_name.contains("pure_virtual")
}

/// Checks if a function name indicates a virtual function call.
///
/// # Objective
/// Detect virtual function call patterns in C++ function names. Virtual
/// calls are made through vtable pointers and are identified by
/// _vptr or vtable patterns.
///
/// # Invariants
/// - Returns true for _vptr or vtable patterns.
/// - Returns false for non-virtual patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for virtual call patterns.
///
/// # Returns
/// `true` if the function is identified as a virtual call, `false` otherwise.
pub fn is_virtual_call(function_name: &str) -> bool {
    function_name.contains("_vptr") || function_name.contains("vtable")
}

/// Detects exception handling patterns from a function name.
///
/// # Objective
/// Collect all exception handling-related semantic patterns from a function name.
/// This provides a convenient way to get all exception patterns in one call.
///
/// # Arguments
/// * `function_name` - The function name to analyze for exception patterns.
///
/// # Returns
/// A Vec of `CppSemanticPattern` containing detected exception patterns.
pub fn detect_exception_patterns(function_name: &str) -> Vec<CppSemanticPattern> {
    let mut patterns = Vec::new();

    if is_throw_expression(function_name) {
        patterns.push(CppSemanticPattern::ThrowExpression);
    }
    if is_catch_block(function_name) {
        patterns.push(CppSemanticPattern::CatchBlock);
    }
    if is_try_block(function_name) {
        patterns.push(CppSemanticPattern::TryBlock);
    }
    if is_noexcept(function_name) {
        patterns.push(CppSemanticPattern::Noexcept);
    }
    if is_pure_virtual(function_name) {
        patterns.push(CppSemanticPattern::PureVirtual);
    }
    if is_virtual_call(function_name) {
        patterns.push(CppSemanticPattern::VirtualCall);
    }

    patterns
}

/// Checks if a function uses exception handling.
///
/// # Objective
/// Determine whether a function uses any exception handling patterns. This is
/// used for feature flag detection in function analysis.
///
/// # Arguments
/// * `function_name` - The function name to check for exception handling usage.
///
/// # Returns
/// `true` if the function uses exception handling, `false` otherwise.
pub fn uses_exceptions(function_name: &str) -> bool {
    is_throw_expression(function_name)
        || is_catch_block(function_name)
        || is_try_block(function_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_throw_expression_detection() {
        // __cxa_throw
        assert!(
            is_throw_expression("__cxa_throw"),
            "__cxa_throw must be detected as ThrowExpression"
        );
        // __cxa_rethrow
        assert!(
            is_throw_expression("__cxa_rethrow"),
            "__cxa_rethrow must be detected as ThrowExpression"
        );
        // Non-throw
        assert!(
            !is_throw_expression("normal_function"),
            "Non-throw must not be detected"
        );
    }

    #[test]
    fn test_catch_block_detection() {
        // __cxa_begin_catch
        assert!(
            is_catch_block("__cxa_begin_catch"),
            "__cxa_begin_catch must be detected as CatchBlock"
        );
        // __cxa_end_catch
        assert!(
            is_catch_block("__cxa_end_catch"),
            "__cxa_end_catch must be detected as CatchBlock"
        );
        // Non-catch
        assert!(
            !is_catch_block("normal_function"),
            "Non-catch must not be detected"
        );
    }

    #[test]
    fn test_try_block_detection() {
        // __cxa_begin_cleanup
        assert!(
            is_try_block("__cxa_begin_cleanup"),
            "__cxa_begin_cleanup must be detected as TryBlock"
        );
        // Non-try
        assert!(
            !is_try_block("normal_function"),
            "Non-try must not be detected"
        );
    }

    #[test]
    fn test_noexcept_detection() {
        // noexcept
        assert!(
            is_noexcept("noexcept_function"),
            "noexcept must be detected"
        );
        // DnE pattern
        assert!(is_noexcept("_ZN5ClassDnE"), "DnE pattern must be detected");
        // Non-noexcept
        assert!(
            !is_noexcept("normal_function"),
            "Non-noexcept must not be detected"
        );
    }

    #[test]
    fn test_pure_virtual_detection() {
        // __cxa_pure_virtual
        assert!(
            is_pure_virtual("__cxa_pure_virtual"),
            "__cxa_pure_virtual must be detected as PureVirtual"
        );
        // pure_virtual
        assert!(
            is_pure_virtual("pure_virtual_function"),
            "pure_virtual must be detected as PureVirtual"
        );
        // Non-pure-virtual
        assert!(
            !is_pure_virtual("normal_function"),
            "Non-pure-virtual must not be detected"
        );
    }

    #[test]
    fn test_virtual_call_detection() {
        // _vptr
        assert!(
            is_virtual_call("_vptr_call"),
            "_vptr must be detected as VirtualCall"
        );
        // vtable
        assert!(
            is_virtual_call("vtable_access"),
            "vtable must be detected as VirtualCall"
        );
        // Non-virtual
        assert!(
            !is_virtual_call("normal_function"),
            "Non-virtual must not be detected"
        );
    }

    #[test]
    fn test_detect_exception_patterns() {
        // throw
        let patterns = detect_exception_patterns("__cxa_throw");
        assert!(
            patterns.contains(&CppSemanticPattern::ThrowExpression),
            "ThrowExpression must be detected"
        );

        // catch
        let patterns = detect_exception_patterns("__cxa_begin_catch");
        assert!(
            patterns.contains(&CppSemanticPattern::CatchBlock),
            "CatchBlock must be detected"
        );

        // try
        let patterns = detect_exception_patterns("__cxa_begin_cleanup");
        assert!(
            patterns.contains(&CppSemanticPattern::TryBlock),
            "TryBlock must be detected"
        );

        // noexcept
        let patterns = detect_exception_patterns("noexcept_function");
        assert!(
            patterns.contains(&CppSemanticPattern::Noexcept),
            "Noexcept must be detected"
        );
    }

    #[test]
    fn test_uses_exceptions() {
        // throw
        assert!(
            uses_exceptions("__cxa_throw"),
            "throw must be detected as exception"
        );
        // catch
        assert!(
            uses_exceptions("__cxa_begin_catch"),
            "catch must be detected as exception"
        );
        // try
        assert!(
            uses_exceptions("__cxa_begin_cleanup"),
            "try must be detected as exception"
        );
        // Non-exception
        assert!(
            !uses_exceptions("normal_function"),
            "Non-exception must not be detected"
        );
    }
}
