//! Exception handling analysis for Python C API.
//!
//! This module provides analysis for Python exception handling functions,
//! including PyErr_SetString, PyErr_Format, PyErr_Occurred, PyErr_Clear,
//! and related exception management patterns.
//!
//! # Exception Path Analysis
//!
//! Python C API uses exception handling to signal errors. When an exception
//! is set (e.g., via PyErr_SetString), the caller must ensure proper cleanup
//! of resources before returning to Python. This module detects potential
//! resource leaks in exception paths.
//!
//! # Key Functions Analyzed
//!
//! - `PyErr_SetString` - Set exception with string message
//! - `PyErr_Format` - Set exception with formatted message
//! - `PyErr_Occurred` - Check if exception is set
//! - `PyErr_Clear` - Clear current exception
//! - `PyErr_Print` - Print current exception
//! - `PyErr_ExceptionMatches` - Check exception type
//! - `PyErr_GivenExceptionMatches` - Check exception type
//! - `PyErr_NewException` - Create new exception type
//! - `PyErr_NewExceptionWithDoc` - Create new exception type with docs
//! - `PyErr_Fetch` - Fetch current exception state
//! - `PyErr_Restore` - Restore exception state

use super::{PythonFFISafety, PythonPattern, PythonSemantic};

/// Set of function names that set an exception.
const EXCEPTION_SETTERS: &[&str] = &["PyErr_SetString", "PyErr_Format"];

/// Set of function names that check an exception.
const EXCEPTION_CHECKERS: &[&str] = &[
    "PyErr_Occurred",
    "PyErr_ExceptionMatches",
    "PyErr_GivenExceptionMatches",
];

/// Set of function names that clear an exception.
const EXCEPTION_CLEARERS: &[&str] = &["PyErr_Clear", "PyErr_Print"];

/// Set of function names that create exception types.
const EXCEPTION_CREATORS: &[&str] = &["PyErr_NewException", "PyErr_NewExceptionWithDoc"];

/// Set of function names that manage exception state.
const EXCEPTION_STATE_MANAGERS: &[&str] = &["PyErr_Fetch", "PyErr_Restore"];

/// Returns true if the function name is a known exception setter.
fn is_exception_setter(name: &str) -> bool {
    EXCEPTION_SETTERS.contains(&name)
}

/// Returns true if the function name is a known exception clearer.
fn is_exception_clearer(name: &str) -> bool {
    EXCEPTION_CLEARERS.contains(&name)
}

/// Returns true if the function name is a known exception checker.
fn is_exception_checker(name: &str) -> bool {
    EXCEPTION_CHECKERS.contains(&name)
}

/// Returns true if the function name is a known exception creator.
fn is_exception_creator(name: &str) -> bool {
    EXCEPTION_CREATORS.contains(&name)
}

/// Returns true if the function name is a known exception state manager.
fn is_exception_state_manager(name: &str) -> bool {
    EXCEPTION_STATE_MANAGERS.contains(&name)
}

/// Returns true if the function name is any known exception handler.
fn is_any_exception_function(name: &str) -> bool {
    is_exception_setter(name)
        || is_exception_checker(name)
        || is_exception_clearer(name)
        || is_exception_creator(name)
        || is_exception_state_manager(name)
}

/// Builds the `ExceptionHandling` pattern for a given function name.
///
/// Distinguishes between setters and clearers so that downstream
/// safety analysis can reason about cleanup requirements.
fn build_exception_pattern(name: &str) -> PythonPattern {
    PythonPattern::ExceptionHandling {
        is_setter: is_exception_setter(name),
        is_clearer: is_exception_clearer(name),
    }
}

/// Analyzes Python exception handling patterns from function name.
///
/// # Objective
/// Detect Python exception handling functions from their names,
/// identifying patterns that may lead to resource leaks if not
/// properly handled.
///
/// # Invariants
/// - Returns `Some(PythonSemantic)` for all known exception functions.
/// - Pattern is always `PythonPattern::ExceptionHandling { .. }`.
/// - Confidence is 0.95 for known exception functions.
/// - Returns `None` for non-exception functions.
///
/// # Arguments
/// * `function_name` - The Python C API function name to analyze.
///
/// # Returns
/// `Some(PythonSemantic)` if an exception handling pattern is detected,
/// `None` otherwise.
pub fn analyze_exception_pattern(function_name: &str) -> Option<PythonSemantic> {
    if !is_any_exception_function(function_name) {
        return None;
    }

    let is_safe = !is_exception_setter(function_name);
    let category = if is_exception_setter(function_name) {
        "setter"
    } else if is_exception_checker(function_name) {
        "checker"
    } else if is_exception_clearer(function_name) {
        "clearer"
    } else if is_exception_creator(function_name) {
        "creator"
    } else {
        "state manager"
    };

    Some(PythonSemantic {
        function_name: function_name.to_string(),
        pattern: build_exception_pattern(function_name),
        is_safe,
        confidence: 0.95,
        reasoning: format!("Python exception {}: {}", category, function_name),
    })
}

/// Analyzes exception handling patterns from IR instruction callees.
///
/// # Objective
/// Detect Python exception handling functions from IR instruction callees.
///
/// # Invariants
/// - Returns `Some(PythonPattern::ExceptionHandling { .. })` for known exception functions.
/// - Returns `None` for non-exception functions.
///
/// # Arguments
/// * `callee` - The callee function name from IR instruction.
///
/// # Returns
/// `Some(PythonPattern::ExceptionHandling { .. })` if detected, `None` otherwise.
pub fn analyze_exception_from_ir(callee: &str) -> Option<PythonPattern> {
    if is_any_exception_function(callee) {
        Some(build_exception_pattern(callee))
    } else {
        None
    }
}

/// Determines FFI safety based on exception handling patterns.
///
/// # Objective
/// Assess the safety of Python exception handling patterns, detecting
/// potential resource leaks in exception paths.
///
/// # Invariants
/// - Returns `ConcernExceptionLeak` if exception setter found without clearer.
/// - Returns `SafeRefCount` if exception is properly managed (setter + clearer).
/// - Returns `SafeRefCount` if only checkers/creators/managers are present.
/// - Returns `Unknown` if no exception patterns are detected.
///
/// # Arguments
/// * `patterns` - List of detected Python patterns to assess.
///
/// # Returns
/// `PythonFFISafety` assessment based on exception handling patterns.
pub fn determine_exception_safety(patterns: &[&PythonPattern]) -> PythonFFISafety {
    let has_setter = patterns.iter().any(|p| {
        matches!(
            p,
            PythonPattern::ExceptionHandling {
                is_setter: true,
                ..
            }
        )
    });

    let has_clearer = patterns.iter().any(|p| {
        matches!(
            p,
            PythonPattern::ExceptionHandling {
                is_clearer: true,
                ..
            }
        )
    });

    let has_any_exception = patterns
        .iter()
        .any(|p| matches!(p, PythonPattern::ExceptionHandling { .. }));

    if !has_any_exception {
        return PythonFFISafety::Unknown;
    }

    // Setter without clearer indicates possible resource leak
    if has_setter && !has_clearer {
        return PythonFFISafety::ConcernExceptionLeak;
    }

    // Both setter and clearer present, or only non-setter functions
    PythonFFISafety::SafeRefCount
}

/// Detects exception path resource leaks from raw instruction strings.
///
/// # Objective
/// Analyze a sequence of instruction strings for exception path resource
/// leaks. This is a lightweight text-based scan for quick heuristics.
///
/// # Invariants
/// - Returns `Vec<ExceptionLeak>` with detected resource leaks.
/// - Each leak contains the function name, line number, and description.
/// - Returns empty Vec if no leaks are detected.
///
/// # Arguments
/// * `instructions` - List of IR instruction strings to analyze.
/// * `function_name` - The function name being analyzed.
///
/// # Returns
/// `Vec<ExceptionLeak>` with detected resource leaks.
pub fn detect_exception_leaks(instructions: &[&str], function_name: &str) -> Vec<ExceptionLeak> {
    let mut leaks = Vec::new();
    let mut has_exception_setter = false;
    let mut has_cleanup = false;

    // Scan instructions for exception handling patterns
    for (i, instruction) in instructions.iter().enumerate() {
        // Check for exception setting functions
        if instruction.contains("PyErr_SetString") || instruction.contains("PyErr_Format") {
            has_exception_setter = true;
            leaks.push(ExceptionLeak {
                function_name: function_name.to_string(),
                line_number: i + 1,
                description: format!(
                    "Exception set at line {} - ensure resources are cleaned up before returning",
                    i + 1
                ),
                severity: LeakSeverity::Warning,
            });
        }

        // Check for resource cleanup (Py_DECREF, Py_XDECREF)
        if instruction.contains("Py_DECREF") || instruction.contains("Py_XDECREF") {
            has_cleanup = true;
        }

        // Check for exception clearing
        if instruction.contains("PyErr_Clear") || instruction.contains("PyErr_Print") {
            has_cleanup = true;
        }
    }

    // If we have exception setter but no cleanup at all, flag as error
    if has_exception_setter && !has_cleanup {
        leaks.push(ExceptionLeak {
            function_name: function_name.to_string(),
            line_number: 0,
            description: format!(
                "Exception path in function '{}' may leak resources - no cleanup detected",
                function_name
            ),
            severity: LeakSeverity::Error,
        });
    }

    leaks
}

/// Exception path resource leak.
#[derive(Debug, Clone, PartialEq)]
pub struct ExceptionLeak {
    /// The function name where the leak occurs.
    pub function_name: String,
    /// The line number where the leak occurs (0 if unknown).
    pub line_number: usize,
    /// Description of the resource leak.
    pub description: String,
    /// Severity of the leak.
    pub severity: LeakSeverity,
}

/// Severity of an exception path resource leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakSeverity {
    /// Warning: potential resource leak.
    Warning,
    /// Error: definite resource leak.
    Error,
    /// Critical: severe resource leak that may cause crashes.
    Critical,
}

/// Checks if a pattern is related to exception handling.
///
/// # Arguments
/// * `pattern` - The Python pattern to check.
///
/// # Returns
/// `true` if the pattern is related to exception handling.
pub fn is_exception_pattern(pattern: &PythonPattern) -> bool {
    matches!(pattern, PythonPattern::ExceptionHandling { .. })
}

/// Analyzes exception path patterns with detailed type information.
///
/// # Objective
/// Provide detailed analysis of exception handling patterns, including
/// specific function types and their implications for resource management.
///
/// # Arguments
/// * `function_name` - The Python C API function name to analyze.
///
/// # Returns
/// `Some(ExceptionPatternInfo)` if an exception handling pattern is detected,
/// `None` otherwise.
pub fn analyze_exception_pattern_detailed(function_name: &str) -> Option<ExceptionPatternInfo> {
    if !is_any_exception_function(function_name) {
        return None;
    }

    let (pattern_type, is_safe, cleanup_required) = if is_exception_setter(function_name) {
        (ExceptionPatternType::Setter, false, true)
    } else if is_exception_checker(function_name) {
        (ExceptionPatternType::Checker, true, false)
    } else if is_exception_clearer(function_name) {
        (ExceptionPatternType::Clearer, true, false)
    } else if is_exception_creator(function_name) {
        (ExceptionPatternType::Creator, true, false)
    } else {
        (ExceptionPatternType::StateManager, true, false)
    };

    Some(ExceptionPatternInfo {
        function_name: function_name.to_string(),
        pattern_type,
        is_safe,
        description: format!("Python exception {:?}: {}", pattern_type, function_name),
        cleanup_required,
    })
}

/// Exception pattern information.
#[derive(Debug, Clone, PartialEq)]
pub struct ExceptionPatternInfo {
    /// The function name.
    pub function_name: String,
    /// The type of exception pattern.
    pub pattern_type: ExceptionPatternType,
    /// Whether the pattern is safe.
    pub is_safe: bool,
    /// Description of the pattern.
    pub description: String,
    /// Whether cleanup is required after this pattern.
    pub cleanup_required: bool,
}

/// Types of exception patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionPatternType {
    /// Exception setting (PyErr_SetString, PyErr_Format).
    Setter,
    /// Exception checking (PyErr_Occurred, PyErr_ExceptionMatches).
    Checker,
    /// Exception clearing (PyErr_Clear, PyErr_Print).
    Clearer,
    /// Exception creation (PyErr_NewException, PyErr_NewExceptionWithDoc).
    Creator,
    /// Exception state management (PyErr_Fetch, PyErr_Restore).
    StateManager,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== analyze_exception_pattern tests ==========

    #[test]
    fn test_analyze_exception_pattern_setter_string() {
        let result = analyze_exception_pattern("PyErr_SetString");
        assert!(
            result.is_some(),
            "PyErr_SetString should be detected as exception pattern"
        );
        let semantic = result.unwrap();
        assert!(
            matches!(
                semantic.pattern,
                PythonPattern::ExceptionHandling {
                    is_setter: true,
                    ..
                }
            ),
            "PyErr_SetString should have is_setter=true"
        );
        assert!(
            !semantic.is_safe,
            "PyErr_SetString should be marked as unsafe"
        );
        assert!(
            semantic.confidence >= 0.9,
            "Confidence should be high for known exception function"
        );
    }

    #[test]
    fn test_analyze_exception_pattern_setter_format() {
        let result = analyze_exception_pattern("PyErr_Format");
        assert!(
            result.is_some(),
            "PyErr_Format should be detected as exception pattern"
        );
        let semantic = result.unwrap();
        assert!(
            matches!(
                semantic.pattern,
                PythonPattern::ExceptionHandling {
                    is_setter: true,
                    ..
                }
            ),
            "PyErr_Format should have is_setter=true"
        );
        assert!(!semantic.is_safe, "PyErr_Format should be marked as unsafe");
    }

    #[test]
    fn test_analyze_exception_pattern_checker_occurred() {
        let result = analyze_exception_pattern("PyErr_Occurred");
        assert!(
            result.is_some(),
            "PyErr_Occurred should be detected as exception pattern"
        );
        let semantic = result.unwrap();
        assert!(
            matches!(
                semantic.pattern,
                PythonPattern::ExceptionHandling {
                    is_setter: false,
                    is_clearer: false,
                }
            ),
            "PyErr_Occurred should be checker (not setter, not clearer)"
        );
        assert!(semantic.is_safe, "PyErr_Occurred should be marked as safe");
    }

    #[test]
    fn test_analyze_exception_pattern_checker_exception_matches() {
        let result = analyze_exception_pattern("PyErr_ExceptionMatches");
        assert!(
            result.is_some(),
            "PyErr_ExceptionMatches should be detected"
        );
        let semantic = result.unwrap();
        assert!(semantic.is_safe, "PyErr_ExceptionMatches should be safe");
    }

    #[test]
    fn test_analyze_exception_pattern_checker_given_exception_matches() {
        let result = analyze_exception_pattern("PyErr_GivenExceptionMatches");
        assert!(
            result.is_some(),
            "PyErr_GivenExceptionMatches should be detected"
        );
    }

    #[test]
    fn test_analyze_exception_pattern_clearer_clear() {
        let result = analyze_exception_pattern("PyErr_Clear");
        assert!(
            result.is_some(),
            "PyErr_Clear should be detected as exception pattern"
        );
        let semantic = result.unwrap();
        assert!(
            matches!(
                semantic.pattern,
                PythonPattern::ExceptionHandling {
                    is_clearer: true,
                    ..
                }
            ),
            "PyErr_Clear should have is_clearer=true"
        );
        assert!(semantic.is_safe, "PyErr_Clear should be marked as safe");
    }

    #[test]
    fn test_analyze_exception_pattern_clearer_print() {
        let result = analyze_exception_pattern("PyErr_Print");
        assert!(
            result.is_some(),
            "PyErr_Print should be detected as exception pattern"
        );
        let semantic = result.unwrap();
        assert!(
            matches!(
                semantic.pattern,
                PythonPattern::ExceptionHandling {
                    is_clearer: true,
                    ..
                }
            ),
            "PyErr_Print should have is_clearer=true"
        );
    }

    #[test]
    fn test_analyze_exception_pattern_creator() {
        let result = analyze_exception_pattern("PyErr_NewException");
        assert!(result.is_some(), "PyErr_NewException should be detected");
        let semantic = result.unwrap();
        assert!(semantic.is_safe, "PyErr_NewException should be safe");
    }

    #[test]
    fn test_analyze_exception_pattern_creator_with_doc() {
        let result = analyze_exception_pattern("PyErr_NewExceptionWithDoc");
        assert!(
            result.is_some(),
            "PyErr_NewExceptionWithDoc should be detected"
        );
    }

    #[test]
    fn test_analyze_exception_pattern_state_fetch() {
        let result = analyze_exception_pattern("PyErr_Fetch");
        assert!(result.is_some(), "PyErr_Fetch should be detected");
        let semantic = result.unwrap();
        assert!(semantic.is_safe, "PyErr_Fetch should be safe");
    }

    #[test]
    fn test_analyze_exception_pattern_state_restore() {
        let result = analyze_exception_pattern("PyErr_Restore");
        assert!(result.is_some(), "PyErr_Restore should be detected");
    }

    #[test]
    fn test_analyze_exception_pattern_non_exception() {
        let result = analyze_exception_pattern("Py_INCREF");
        assert!(
            result.is_none(),
            "Py_INCREF should not be detected as exception pattern"
        );
    }

    #[test]
    fn test_analyze_exception_pattern_random_function() {
        let result = analyze_exception_pattern("some_random_function");
        assert!(
            result.is_none(),
            "Random function should not be detected as exception pattern"
        );
    }

    // ========== analyze_exception_from_ir tests ==========

    #[test]
    fn test_analyze_exception_from_ir_setter() {
        let result = analyze_exception_from_ir("PyErr_SetString");
        assert!(
            result.is_some(),
            "PyErr_SetString should be detected from IR"
        );
        assert!(
            matches!(
                result.unwrap(),
                PythonPattern::ExceptionHandling {
                    is_setter: true,
                    ..
                }
            ),
            "PyErr_SetString from IR should have is_setter=true"
        );
    }

    #[test]
    fn test_analyze_exception_from_ir_format() {
        let result = analyze_exception_from_ir("PyErr_Format");
        assert!(result.is_some(), "PyErr_Format should be detected from IR");
    }

    #[test]
    fn test_analyze_exception_from_ir_occurred() {
        let result = analyze_exception_from_ir("PyErr_Occurred");
        assert!(
            result.is_some(),
            "PyErr_Occurred should be detected from IR"
        );
    }

    #[test]
    fn test_analyze_exception_from_ir_clear() {
        let result = analyze_exception_from_ir("PyErr_Clear");
        assert!(result.is_some(), "PyErr_Clear should be detected from IR");
    }

    #[test]
    fn test_analyze_exception_from_ir_non_exception() {
        let result = analyze_exception_from_ir("Py_DECREF");
        assert!(
            result.is_none(),
            "Py_DECREF should not be detected as exception pattern"
        );
    }

    // ========== determine_exception_safety tests ==========

    #[test]
    fn test_determine_exception_safety_setter_without_clearer() {
        let patterns = vec![&PythonPattern::ExceptionHandling {
            is_setter: true,
            is_clearer: false,
        }];
        let safety = determine_exception_safety(&patterns);
        assert_eq!(
            safety,
            PythonFFISafety::ConcernExceptionLeak,
            "Setter without clearer should be ConcernExceptionLeak"
        );
    }

    #[test]
    fn test_determine_exception_safety_setter_with_clearer() {
        let patterns = vec![
            &PythonPattern::ExceptionHandling {
                is_setter: true,
                is_clearer: false,
            },
            &PythonPattern::ExceptionHandling {
                is_setter: false,
                is_clearer: true,
            },
        ];
        let safety = determine_exception_safety(&patterns);
        assert_eq!(
            safety,
            PythonFFISafety::SafeRefCount,
            "Setter with clearer should be SafeRefCount"
        );
    }

    #[test]
    fn test_determine_exception_safety_only_clearer() {
        let patterns = vec![&PythonPattern::ExceptionHandling {
            is_setter: false,
            is_clearer: true,
        }];
        let safety = determine_exception_safety(&patterns);
        assert_eq!(
            safety,
            PythonFFISafety::SafeRefCount,
            "Only clearer should be SafeRefCount"
        );
    }

    #[test]
    fn test_determine_exception_safety_only_checker() {
        let patterns = vec![&PythonPattern::ExceptionHandling {
            is_setter: false,
            is_clearer: false,
        }];
        let safety = determine_exception_safety(&patterns);
        assert_eq!(
            safety,
            PythonFFISafety::SafeRefCount,
            "Only checker should be SafeRefCount"
        );
    }

    #[test]
    fn test_determine_exception_safety_no_exception() {
        let patterns = vec![&PythonPattern::NewReference];
        let safety = determine_exception_safety(&patterns);
        assert_eq!(
            safety,
            PythonFFISafety::Unknown,
            "No exception patterns should be Unknown"
        );
    }

    #[test]
    fn test_determine_exception_safety_setter_with_other_patterns() {
        let patterns = vec![
            &PythonPattern::ExceptionHandling {
                is_setter: true,
                is_clearer: false,
            },
            &PythonPattern::NewReference,
        ];
        let safety = determine_exception_safety(&patterns);
        assert_eq!(
            safety,
            PythonFFISafety::ConcernExceptionLeak,
            "Setter with other patterns (but no clearer) should be ConcernExceptionLeak"
        );
    }

    // ========== detect_exception_leaks tests ==========

    #[test]
    fn test_detect_exception_leaks_with_setter_and_cleanup() {
        let instructions = vec![
            "call @PyErr_SetString",
            "call @Py_DECREF",
            "call @PyErr_Clear",
        ];
        let leaks = detect_exception_leaks(&instructions, "test_func");
        // Should have warning for exception setter
        assert!(
            leaks.iter().any(|l| l.severity == LeakSeverity::Warning),
            "Should have warning for exception setter"
        );
        // Should NOT have error for missing cleanup (cleanup exists)
        assert!(
            !leaks.iter().any(|l| l.severity == LeakSeverity::Error),
            "Should not have error when cleanup exists"
        );
    }

    #[test]
    fn test_detect_exception_leaks_without_cleanup() {
        let instructions = vec!["call @PyErr_SetString", "call @PyList_New"];
        let leaks = detect_exception_leaks(&instructions, "test_func");
        // Should have error for missing cleanup
        assert!(
            leaks.iter().any(|l| l.severity == LeakSeverity::Error),
            "Should have error for missing cleanup"
        );
    }

    #[test]
    fn test_detect_exception_leaks_no_exception() {
        let instructions = vec!["call @Py_INCREF", "call @Py_DECREF"];
        let leaks = detect_exception_leaks(&instructions, "test_func");
        assert!(
            leaks.is_empty(),
            "No exception patterns should result in no leaks"
        );
    }

    #[test]
    fn test_detect_exception_leaks_format_with_clear() {
        let instructions = vec!["call @PyErr_Format", "call @PyErr_Clear"];
        let leaks = detect_exception_leaks(&instructions, "test_func");
        assert!(
            leaks.iter().any(|l| l.severity == LeakSeverity::Warning),
            "Should have warning for PyErr_Format"
        );
        assert!(
            !leaks.iter().any(|l| l.severity == LeakSeverity::Error),
            "Should not have error when PyErr_Clear is present"
        );
    }

    #[test]
    fn test_detect_exception_leaks_only_clear_no_leak() {
        let instructions = vec!["call @PyErr_Clear"];
        let leaks = detect_exception_leaks(&instructions, "test_func");
        assert!(
            leaks.is_empty(),
            "Only clearing with no setter should produce no leaks"
        );
    }

    // ========== is_exception_pattern tests ==========

    #[test]
    fn test_is_exception_pattern_setter() {
        let pattern = PythonPattern::ExceptionHandling {
            is_setter: true,
            is_clearer: false,
        };
        assert!(
            is_exception_pattern(&pattern),
            "ExceptionHandling setter should be exception pattern"
        );
    }

    #[test]
    fn test_is_exception_pattern_clearer() {
        let pattern = PythonPattern::ExceptionHandling {
            is_setter: false,
            is_clearer: true,
        };
        assert!(
            is_exception_pattern(&pattern),
            "ExceptionHandling clearer should be exception pattern"
        );
    }

    #[test]
    fn test_is_exception_pattern_new_reference() {
        assert!(
            !is_exception_pattern(&PythonPattern::NewReference),
            "NewReference should not be exception pattern"
        );
    }

    #[test]
    fn test_is_exception_pattern_refcount() {
        let pattern = PythonPattern::RefCountOp {
            is_increment: true,
            is_null_safe: false,
        };
        assert!(
            !is_exception_pattern(&pattern),
            "RefCountOp should not be exception pattern"
        );
    }

    // ========== analyze_exception_pattern_detailed tests ==========

    #[test]
    fn test_analyze_exception_pattern_detailed_setter() {
        let result = analyze_exception_pattern_detailed("PyErr_SetString");
        assert!(
            result.is_some(),
            "PyErr_SetString should be detected as detailed exception pattern"
        );
        let info = result.unwrap();
        assert_eq!(
            info.pattern_type,
            ExceptionPatternType::Setter,
            "PyErr_SetString should be Setter type"
        );
        assert!(!info.is_safe, "Setter should be unsafe");
        assert!(info.cleanup_required, "Setter should require cleanup");
    }

    #[test]
    fn test_analyze_exception_pattern_detailed_format() {
        let result = analyze_exception_pattern_detailed("PyErr_Format");
        assert!(
            result.is_some(),
            "PyErr_Format should be detected as detailed exception pattern"
        );
        let info = result.unwrap();
        assert_eq!(
            info.pattern_type,
            ExceptionPatternType::Setter,
            "PyErr_Format should be Setter type"
        );
        assert!(!info.is_safe, "Setter should be unsafe");
        assert!(info.cleanup_required, "Setter should require cleanup");
    }

    #[test]
    fn test_analyze_exception_pattern_detailed_checker() {
        let result = analyze_exception_pattern_detailed("PyErr_Occurred");
        assert!(
            result.is_some(),
            "PyErr_Occurred should be detected as detailed exception pattern"
        );
        let info = result.unwrap();
        assert_eq!(
            info.pattern_type,
            ExceptionPatternType::Checker,
            "PyErr_Occurred should be Checker type"
        );
        assert!(info.is_safe, "Checker should be safe");
        assert!(!info.cleanup_required, "Checker should not require cleanup");
    }

    #[test]
    fn test_analyze_exception_pattern_detailed_clearer() {
        let result = analyze_exception_pattern_detailed("PyErr_Clear");
        assert!(
            result.is_some(),
            "PyErr_Clear should be detected as detailed exception pattern"
        );
        let info = result.unwrap();
        assert_eq!(
            info.pattern_type,
            ExceptionPatternType::Clearer,
            "PyErr_Clear should be Clearer type"
        );
        assert!(info.is_safe, "Clearer should be safe");
        assert!(!info.cleanup_required, "Clearer should not require cleanup");
    }

    #[test]
    fn test_analyze_exception_pattern_detailed_creator() {
        let result = analyze_exception_pattern_detailed("PyErr_NewException");
        assert!(
            result.is_some(),
            "PyErr_NewException should be detected as detailed exception pattern"
        );
        let info = result.unwrap();
        assert_eq!(
            info.pattern_type,
            ExceptionPatternType::Creator,
            "PyErr_NewException should be Creator type"
        );
        assert!(info.is_safe, "Creator should be safe");
        assert!(!info.cleanup_required, "Creator should not require cleanup");
    }

    #[test]
    fn test_analyze_exception_pattern_detailed_state_manager() {
        let result = analyze_exception_pattern_detailed("PyErr_Fetch");
        assert!(
            result.is_some(),
            "PyErr_Fetch should be detected as detailed exception pattern"
        );
        let info = result.unwrap();
        assert_eq!(
            info.pattern_type,
            ExceptionPatternType::StateManager,
            "PyErr_Fetch should be StateManager type"
        );
        assert!(info.is_safe, "StateManager should be safe");
        assert!(
            !info.cleanup_required,
            "StateManager should not require cleanup"
        );
    }

    #[test]
    fn test_analyze_exception_pattern_detailed_non_exception() {
        let result = analyze_exception_pattern_detailed("Py_INCREF");
        assert!(
            result.is_none(),
            "Py_INCREF should not be detected as detailed exception pattern"
        );
    }

    #[test]
    fn test_analyze_exception_pattern_detailed_random() {
        let result = analyze_exception_pattern_detailed("some_random_function");
        assert!(
            result.is_none(),
            "Random function should not be detected as detailed exception pattern"
        );
    }

    // ========== ExceptionLeak struct tests ==========

    #[test]
    fn test_exception_leak_struct() {
        let leak = ExceptionLeak {
            function_name: "test_func".to_string(),
            line_number: 10,
            description: "Test leak".to_string(),
            severity: LeakSeverity::Warning,
        };
        assert_eq!(
            leak.function_name, "test_func",
            "Function name should match"
        );
        assert_eq!(leak.line_number, 10, "Line number should match");
        assert_eq!(leak.description, "Test leak", "Description should match");
        assert_eq!(
            leak.severity,
            LeakSeverity::Warning,
            "Severity should match"
        );
    }

    #[test]
    fn test_leak_severity_equality() {
        assert_eq!(
            LeakSeverity::Warning,
            LeakSeverity::Warning,
            "Warning should equal Warning"
        );
        assert_eq!(
            LeakSeverity::Error,
            LeakSeverity::Error,
            "Error should equal Error"
        );
        assert_eq!(
            LeakSeverity::Critical,
            LeakSeverity::Critical,
            "Critical should equal Critical"
        );
        assert_ne!(
            LeakSeverity::Warning,
            LeakSeverity::Error,
            "Warning should not equal Error"
        );
    }

    // ========== ExceptionPatternInfo struct tests ==========

    #[test]
    fn test_exception_pattern_info_struct() {
        let info = ExceptionPatternInfo {
            function_name: "PyErr_SetString".to_string(),
            pattern_type: ExceptionPatternType::Setter,
            is_safe: false,
            description: "Test description".to_string(),
            cleanup_required: true,
        };
        assert_eq!(
            info.function_name, "PyErr_SetString",
            "Function name should match"
        );
        assert_eq!(
            info.pattern_type,
            ExceptionPatternType::Setter,
            "Pattern type should match"
        );
        assert!(!info.is_safe, "is_safe should be false");
        assert_eq!(
            info.description, "Test description",
            "Description should match"
        );
        assert!(info.cleanup_required, "cleanup_required should be true");
    }

    #[test]
    fn test_exception_pattern_type_equality() {
        assert_eq!(
            ExceptionPatternType::Setter,
            ExceptionPatternType::Setter,
            "Setter should equal Setter"
        );
        assert_eq!(
            ExceptionPatternType::Checker,
            ExceptionPatternType::Checker,
            "Checker should equal Checker"
        );
        assert_eq!(
            ExceptionPatternType::Clearer,
            ExceptionPatternType::Clearer,
            "Clearer should equal Clearer"
        );
        assert_eq!(
            ExceptionPatternType::Creator,
            ExceptionPatternType::Creator,
            "Creator should equal Creator"
        );
        assert_eq!(
            ExceptionPatternType::StateManager,
            ExceptionPatternType::StateManager,
            "StateManager should equal StateManager"
        );
        assert_ne!(
            ExceptionPatternType::Setter,
            ExceptionPatternType::Checker,
            "Setter should not equal Checker"
        );
    }
}
