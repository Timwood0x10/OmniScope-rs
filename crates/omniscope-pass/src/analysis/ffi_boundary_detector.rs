//! FFI boundary detection utilities.
//!
//! Provides a unified detector for cross-language FFI boundaries,
//! consolidating language detection, boundary classification, and
//! false-positive filtering used by both `FFIBoundaryPass` and
//! `CallGraphPass`.

use omniscope_semantics::LanguageDetector;
use omniscope_types::{call_graph_types::is_libc, config::Language};

/// Result of FFI boundary detection for a single call site.
///
/// Contains the detected languages and whether the call
/// constitutes a genuine FFI boundary crossing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryInfo {
    /// Detected caller language (may be adjusted with C fallback).
    pub caller_lang: Language,
    /// Detected callee language (may be overridden for C++ mangled or external calls).
    pub callee_lang: Language,
    /// Whether this call is a confirmed FFI boundary.
    pub is_ffi_boundary: bool,
}

/// Detects FFI boundaries from IR call instructions.
///
/// Consolidates the language detection, cross-language checking,
/// and false-positive filtering logic shared by `FFIBoundaryPass`
/// and `CallGraphPass`.
pub struct FFIBoundaryDetector {
    detector: LanguageDetector,
}

impl FFIBoundaryDetector {
    /// Creates a new detector with the default language detector.
    pub fn new() -> Self {
        Self {
            detector: LanguageDetector::new(),
        }
    }

    /// Detect the caller language with an optional C fallback.
    ///
    /// When `caller_is_defined` is true and the detected language is
    /// `Unknown`, the language defaults to `C` (common case for `.ll`
    /// files originating from C source).
    pub fn detect_caller_lang(&self, caller: &str, caller_is_defined: bool) -> Language {
        let name = caller.trim_start_matches('@');
        let detected = self.detector.detect_from_function(name);
        if caller_is_defined && detected == Language::Unknown {
            Language::C
        } else {
            detected
        }
    }

    /// Detect the callee language from its function name.
    pub fn detect_callee_lang(&self, callee: &str) -> Language {
        let name = callee.trim_start_matches('@');
        self.detector.detect_from_function(name)
    }

    /// Check if the call is a cross-language boundary (both languages
    /// known and different).
    pub fn is_cross_language(&self, caller_lang: Language, callee_lang: Language) -> bool {
        caller_lang != Language::Unknown
            && callee_lang != Language::Unknown
            && caller_lang != callee_lang
    }

    /// Conservative FFI boundary check used by `CallGraphPass`.
    ///
    /// Requires both languages to be known and different. Filters out
    /// libc, runtime intrinsics, and compiler-generated functions
    /// (`drop_in_place`, `panic`).
    pub fn is_ffi_boundary(
        &self,
        callee: &str,
        caller_lang: Language,
        callee_lang: Language,
    ) -> bool {
        if caller_lang == Language::Unknown || callee_lang == Language::Unknown {
            return false;
        }
        if caller_lang == callee_lang {
            return false;
        }
        !is_filtered_callee(callee, callee_lang)
    }

    /// Aggressive FFI boundary detection used by `FFIBoundaryPass`
    /// when no `CallGraph` edges are available.
    ///
    /// In addition to the standard cross-language check, this method
    /// also detects:
    /// - C++ mangled names (`_Z` prefix) called from C code
    /// - External calls from non-C languages to unknown callees (likely C)
    ///
    /// Returns `Some(BoundaryInfo)` when the call is an FFI boundary,
    /// `None` otherwise.
    pub fn detect_aggressive_boundary(
        &self,
        caller: &str,
        callee: &str,
        is_external: bool,
        caller_is_defined: bool,
    ) -> Option<BoundaryInfo> {
        let callee_name = callee.trim_start_matches('@');
        let caller_name = caller.trim_start_matches('@');

        // Skip LLVM intrinsics — they are not FFI boundaries
        if callee_name.starts_with("llvm.") {
            return None;
        }

        let callee_lang = self.detect_callee_lang(callee_name);
        let caller_lang = self.detect_caller_lang(caller_name, caller_is_defined);

        // Cross-language call (both langs known and different)
        let is_cross_lang = self.is_cross_language(caller_lang, callee_lang);

        // C++ mangled name called from C — definite FFI boundary
        let is_cpp_ffi = callee_name.starts_with("_Z") && caller_lang == Language::C;

        // Non-C language calling external unknown function (likely C)
        let is_ffi_to_c = caller_lang != Language::Unknown
            && caller_lang != Language::C
            && callee_lang == Language::Unknown
            && is_external;

        if !(is_cross_lang || is_cpp_ffi || is_ffi_to_c) {
            return None;
        }

        // Resolve the final callee language for C++ mangled or external calls
        let resolved_callee = if is_cpp_ffi {
            Language::Cpp
        } else if is_ffi_to_c {
            Language::C
        } else {
            callee_lang
        };

        // Apply false-positive filters on the resolved callee
        if is_filtered_callee(callee_name, resolved_callee) {
            return None;
        }

        Some(BoundaryInfo {
            caller_lang,
            callee_lang: resolved_callee,
            is_ffi_boundary: true,
        })
    }
}

impl Default for FFIBoundaryDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether a callee should be filtered out as a false positive.
///
/// Filters:
/// - Known libc functions (trusted C ABI interface)
/// - Language runtime intrinsics (`__rust_*`, `_ZN4core`, `__libc_*`, etc.)
/// - Compiler-generated `drop_in_place` and `panic` functions
fn is_filtered_callee(callee: &str, callee_lang: Language) -> bool {
    is_libc(callee)
        || is_runtime_intrinsic(callee, callee_lang)
        || callee.contains("drop_in_place")
        || callee.contains("panic")
}

/// Check if a function name is a language runtime intrinsic.
///
/// Runtime intrinsics are compiler/language runtime support functions
/// that should not be treated as user FFI boundaries.
pub fn is_runtime_intrinsic(name: &str, language: Language) -> bool {
    match language {
        Language::Rust => {
            name.starts_with("__rust_")
                || name.starts_with("_ZN4core")
                || name.starts_with("_ZN5alloc")
        }
        Language::C => {
            name.starts_with("__libc_")
                || name.starts_with("__cxa_")
                || name.starts_with("_Unwind_")
                || name.starts_with("_tlv_")
        }
        // Note: `_Z` prefix is standard C++ Itanium name mangling and covers ALL
        // C++ functions (not just intrinsics). Only specific ABI/runtime patterns
        // should be flagged as intrinsics.
        Language::Cpp => name.starts_with("__cxxabiv1"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── FFIBoundaryDetector construction ──

    /// Objective: Verify detector implements Default.
    /// Invariants: Default and new() produce equivalent detectors.
    #[test]
    fn test_detector_default() {
        let _d1 = FFIBoundaryDetector::new();
        let _d2 = FFIBoundaryDetector::default();
        // Both must be constructible without panic.
    }

    // ── Runtime intrinsic detection ──

    /// Objective: Verify Rust runtime intrinsics are correctly identified.
    /// Invariants: __rust_* and _ZN4core/* are intrinsics; user functions are not.
    #[test]
    fn test_rust_runtime_intrinsics() {
        assert!(
            is_runtime_intrinsic("__rust_dealloc", Language::Rust),
            "__rust_ prefix must be recognized as Rust runtime intrinsic"
        );
        assert!(
            is_runtime_intrinsic("_ZN4core3ptr7drop_in_place", Language::Rust),
            "_ZN4core prefix must be recognized as Rust runtime intrinsic"
        );
        assert!(
            is_runtime_intrinsic("_ZN5alloc5alloc", Language::Rust),
            "_ZN5alloc prefix must be recognized as Rust runtime intrinsic"
        );
        assert!(
            !is_runtime_intrinsic("my_c_func", Language::C),
            "user functions must not be classified as runtime intrinsics"
        );
    }

    /// Objective: Verify C runtime intrinsics are correctly identified.
    /// Invariants: __libc_*, __cxa_*, _Unwind_* are intrinsics.
    #[test]
    fn test_c_runtime_intrinsics() {
        assert!(
            is_runtime_intrinsic("__libc_start_main", Language::C),
            "__libc_ prefix must be recognized as C runtime intrinsic"
        );
        assert!(
            is_runtime_intrinsic("__cxa_atexit", Language::C),
            "__cxa_ prefix must be recognized as C runtime intrinsic"
        );
        assert!(
            is_runtime_intrinsic("_Unwind_Resume", Language::C),
            "_Unwind_ prefix must be recognized as C runtime intrinsic"
        );
    }

    /// Objective: Verify C++ runtime intrinsics are correctly identified.
    /// Invariants: __cxxabiv1 prefix is intrinsic; _Z is standard mangling (not intrinsic).
    #[test]
    fn test_cpp_runtime_intrinsics() {
        assert!(
            !is_runtime_intrinsic("_Z3fooi", Language::Cpp),
            "_Z prefix is standard C++ mangling, not an intrinsic"
        );
        assert!(
            is_runtime_intrinsic("__cxxabiv1", Language::Cpp),
            "__cxxabiv1 must be recognized as C++ runtime intrinsic"
        );
    }

    // ── Conservative FFI boundary check ──

    /// Objective: Verify conservative FFI boundary detection.
    /// Invariants: Same language → not FFI; libc → not FFI;
    ///             Unknown → not FFI; cross-lang user → FFI.
    #[test]
    fn test_conservative_ffi_boundary() {
        let detector = FFIBoundaryDetector::new();

        // Same language → not FFI
        assert!(
            !detector.is_ffi_boundary("rust_fn", Language::Rust, Language::Rust),
            "same language must not be FFI boundary"
        );

        // libc → not FFI (even if cross-language)
        assert!(
            !detector.is_ffi_boundary("malloc", Language::Rust, Language::C),
            "libc functions must not be flagged as FFI boundary"
        );

        // Runtime intrinsics → not FFI
        assert!(
            !detector.is_ffi_boundary("__rust_dealloc", Language::Rust, Language::Rust),
            "runtime intrinsics must not be flagged as FFI boundary"
        );

        // Unknown language → cannot confirm FFI
        assert!(
            !detector.is_ffi_boundary("c_func", Language::Unknown, Language::C),
            "Unknown caller language must not confirm FFI boundary"
        );

        // Genuine cross-language user function → FFI
        assert!(
            detector.is_ffi_boundary("c_handler", Language::Rust, Language::C),
            "Rust calling C user function must be FFI boundary"
        );
        assert!(
            detector.is_ffi_boundary("c_process", Language::Zig, Language::C),
            "Zig calling C function must be FFI boundary"
        );

        // drop_in_place → filtered out
        assert!(
            !detector.is_ffi_boundary("core::ptr::drop_in_place", Language::C, Language::Rust),
            "drop_in_place must be filtered out"
        );

        // panic → filtered out
        assert!(
            !detector.is_ffi_boundary("core::panicking::panic", Language::C, Language::Rust),
            "panic functions must be filtered out"
        );
    }

    // ── Aggressive FFI boundary detection ──

    /// Objective: Verify aggressive detection catches C++ mangled names from C.
    /// Invariants: _Z prefix from C → FFI with callee_lang=Cpp.
    #[test]
    fn test_aggressive_cpp_mangled_detection() {
        let detector = FFIBoundaryDetector::new();

        let result = detector.detect_aggressive_boundary("c_main", "_Z3fooi", false, true);
        assert!(
            result.is_some(),
            "C calling C++ mangled function must be detected as FFI"
        );
        let info = result.unwrap();
        assert_eq!(info.caller_lang, Language::C);
        assert_eq!(info.callee_lang, Language::Cpp);
        assert!(info.is_ffi_boundary);
    }

    /// Objective: Verify aggressive detection catches external calls from non-C to unknown.
    /// Invariants: Rust calling external unknown → FFI with callee_lang=C.
    #[test]
    fn test_aggressive_external_to_unknown() {
        let detector = FFIBoundaryDetector::new();

        // Use a Rust function name (std prefix) so it's detected as Rust
        let result =
            detector.detect_aggressive_boundary("_ZN3std4main", "unknown_ext", true, false);
        assert!(
            result.is_some(),
            "Rust calling external unknown must be detected as FFI"
        );
        let info = result.unwrap();
        assert_eq!(
            info.caller_lang,
            Language::Rust,
            "Caller must be detected as Rust"
        );
        assert_eq!(
            info.callee_lang,
            Language::C,
            "Callee must be resolved to C"
        );
        assert!(info.is_ffi_boundary);
    }

    /// Objective: Verify aggressive detection skips LLVM intrinsics.
    /// Invariants: llvm.* calls → not FFI boundary.
    #[test]
    fn test_aggressive_skips_llvm_intrinsics() {
        let detector = FFIBoundaryDetector::new();

        let result =
            detector.detect_aggressive_boundary("c_main", "llvm.memcpy.p0i8.p0i8.i64", false, true);
        assert!(
            result.is_none(),
            "LLVM intrinsics must not be detected as FFI boundaries"
        );
    }

    /// Objective: Verify aggressive detection filters libc and runtime intrinsics.
    /// Invariants: malloc, __rust_dealloc → not FFI even in aggressive mode.
    #[test]
    fn test_aggressive_filters_false_positives() {
        let detector = FFIBoundaryDetector::new();

        // libc
        let result = detector.detect_aggressive_boundary("rust_main", "malloc", false, true);
        assert!(
            result.is_none(),
            "malloc must be filtered out in aggressive mode"
        );

        // Runtime intrinsic
        let result = detector.detect_aggressive_boundary("c_main", "__rust_dealloc", false, true);
        assert!(
            result.is_none(),
            "__rust_dealloc must be filtered out in aggressive mode"
        );
    }

    /// Objective: Verify aggressive detection handles non-external unknown calls correctly.
    /// Invariants: Non-external call from Rust to unknown → not ffi_to_c.
    #[test]
    fn test_aggressive_non_external_unknown() {
        let detector = FFIBoundaryDetector::new();

        // Not external → should not trigger ffi_to_c path
        let result = detector.detect_aggressive_boundary("rust_main", "unknown_fn", false, false);
        // This should return None because: callee is Unknown, so not cross-lang;
        // callee doesn't start with _Z, so not cpp_ffi; and is_external is false, so not ffi_to_c.
        assert!(
            result.is_none(),
            "Non-external call to unknown callee must not be FFI boundary"
        );
    }

    // ── Language detection ──

    /// Objective: Verify caller language detection with C fallback.
    /// Invariants: Defined function with Unknown language → C;
    ///             Non-defined function with Unknown → Unknown.
    #[test]
    fn test_caller_lang_c_fallback() {
        let detector = FFIBoundaryDetector::new();

        // Known Rust function (v0 mangling) → Rust regardless of caller_is_defined
        let lang = detector.detect_caller_lang("_RINvNtCsdGVnYXsfTfsL_7example3fooIEC_", true);
        assert_eq!(
            lang,
            Language::Rust,
            "Rust v0 mangled function must be detected as Rust"
        );

        // Known Rust function (Itanium mangling with core prefix) → Rust
        let lang = detector.detect_caller_lang("_ZN4core3ptr7drop_in_place", true);
        assert_eq!(
            lang,
            Language::Rust,
            "Rust Itanium mangled function with core prefix must be detected as Rust"
        );

        // Unknown function with caller_is_defined → C
        let lang = detector.detect_caller_lang("some_unknown_func", true);
        assert_eq!(
            lang,
            Language::C,
            "Unknown defined function must fallback to C"
        );

        // Unknown function without caller_is_defined → Unknown
        let lang = detector.detect_caller_lang("some_unknown_func", false);
        assert_eq!(
            lang,
            Language::Unknown,
            "Unknown non-defined function must stay Unknown"
        );
    }

    // ── Cross-language check ──

    /// Objective: Verify cross-language boundary check.
    /// Invariants: Both known and different → true; same → false;
    ///             either Unknown → false.
    #[test]
    fn test_is_cross_language() {
        let detector = FFIBoundaryDetector::new();

        assert!(
            detector.is_cross_language(Language::Rust, Language::C),
            "Rust→C must be cross-language"
        );
        assert!(
            !detector.is_cross_language(Language::Rust, Language::Rust),
            "Same language must not be cross-language"
        );
        assert!(
            !detector.is_cross_language(Language::Unknown, Language::C),
            "Unknown caller must not be cross-language"
        );
        assert!(
            !detector.is_cross_language(Language::Rust, Language::Unknown),
            "Unknown callee must not be cross-language"
        );
    }

    // ── Specific integration tests as requested ──

    /// Objective: Verify C language detection from caller function name.
    /// Invariants: C functions with typical naming patterns are detected as C;
    ///             Unknown functions with caller_is_defined fallback to C.
    #[test]
    fn test_detect_caller_lang_c() {
        let detector = FFIBoundaryDetector::new();

        // C function with typical C naming (no language prefix)
        let lang = detector.detect_caller_lang("c_function", true);
        assert_eq!(
            lang,
            Language::C,
            "Unknown defined function must fallback to C when caller_is_defined is true"
        );

        // C function with underscore prefix (common in C)
        let lang = detector.detect_caller_lang("_c_function", true);
        assert_eq!(
            lang,
            Language::C,
            "Unknown defined function with underscore prefix must fallback to C"
        );

        // Non-defined C function should not fallback
        let lang = detector.detect_caller_lang("c_function", false);
        assert_eq!(
            lang,
            Language::Unknown,
            "Unknown non-defined function must not fallback to C"
        );
    }

    /// Objective: Verify C++ language detection from caller function name.
    /// Invariants: C++ mangled names (_Z prefix) are correctly detected as C++.
    #[test]
    fn test_detect_caller_lang_cpp() {
        let detector = FFIBoundaryDetector::new();

        // C++ Itanium mangling (_ZN prefix)
        let lang = detector.detect_caller_lang("_ZN3Foo3barEi", true);
        assert_eq!(
            lang,
            Language::Cpp,
            "C++ Itanium mangled name must be detected as C++"
        );

        // C++ short mangling (_Z prefix)
        let lang = detector.detect_caller_lang("_Z3fooi", true);
        assert_eq!(
            lang,
            Language::Cpp,
            "C++ short mangled name must be detected as C++"
        );

        // C++ function with std:: namespace
        let lang = detector.detect_caller_lang("std::vector::push_back", true);
        assert_eq!(
            lang,
            Language::Cpp,
            "Function with std:: namespace must be detected as C++"
        );
    }

    /// Objective: Verify Rust language detection from caller function name.
    /// Invariants: Rust v0 mangling (_R prefix) and Itanium mangling are detected.
    #[test]
    fn test_detect_caller_lang_rust() {
        let detector = FFIBoundaryDetector::new();

        // Rust v0 mangling (modern Rust)
        let lang = detector.detect_caller_lang("_RINvNtCsdGVnYXsfTfsL_7example3fooIEC_", true);
        assert_eq!(
            lang,
            Language::Rust,
            "Rust v0 mangled name must be detected as Rust"
        );

        // Rust Itanium mangling (older Rust)
        let lang = detector.detect_caller_lang("_ZN4core3ptr7drop_in_place", true);
        assert_eq!(
            lang,
            Language::Rust,
            "Rust Itanium mangled name must be detected as Rust"
        );

        // Rust alloc prefix
        let lang = detector.detect_caller_lang("_ZN5alloc5alloc", true);
        assert_eq!(
            lang,
            Language::Rust,
            "Rust alloc prefix must be detected as Rust"
        );
    }

    /// Objective: Verify callee language detection from function name.
    /// Invariants: Various language-specific naming patterns are correctly detected.
    #[test]
    fn test_detect_callee_lang() {
        let detector = FFIBoundaryDetector::new();

        // C++ mangled name
        let lang = detector.detect_callee_lang("_Z3fooi");
        assert_eq!(
            lang,
            Language::Cpp,
            "C++ mangled name must be detected as C++"
        );

        // Rust mangled name
        let lang = detector.detect_callee_lang("_ZN4core3ptr7drop_in_place");
        assert_eq!(
            lang,
            Language::Rust,
            "Rust mangled name must be detected as Rust"
        );

        // Go function
        let lang = detector.detect_callee_lang("main.myFunction");
        assert_eq!(
            lang,
            Language::Go,
            "Go function with main. prefix must be detected as Go"
        );

        // Zig function
        let lang = detector.detect_callee_lang("zig.debug.print");
        assert_eq!(
            lang,
            Language::Zig,
            "Zig function with zig. prefix must be detected as Zig"
        );

        // Python function
        let lang = detector.detect_callee_lang("PyObject_GetAttr");
        assert_eq!(
            lang,
            Language::Python,
            "Python function with Py prefix must be detected as Python"
        );

        // Unknown function
        let lang = detector.detect_callee_lang("unknown_function");
        assert_eq!(
            lang,
            Language::Unknown,
            "Unknown function must be detected as Unknown"
        );
    }

    /// Objective: Verify C++ mangled name detection and handling.
    /// Invariants: _Z prefix indicates C++ mangling; handles various mangled name formats.
    #[test]
    fn test_cpp_mangled_name() {
        let detector = FFIBoundaryDetector::new();

        // Standard C++ Itanium mangling
        let lang = detector.detect_callee_lang("_ZN3Foo3barEi");
        assert_eq!(
            lang,
            Language::Cpp,
            "Standard C++ Itanium mangled name must be detected as C++"
        );

        // Short C++ mangling
        let lang = detector.detect_callee_lang("_Z3fooi");
        assert_eq!(
            lang,
            Language::Cpp,
            "Short C++ mangled name must be detected as C++"
        );

        // C++ local mangling
        let lang = detector.detect_callee_lang("_ZS3foo");
        assert_eq!(
            lang,
            Language::Cpp,
            "C++ local mangling must be detected as C++"
        );

        // Verify aggressive detection catches C++ mangled names from C
        let result = detector.detect_aggressive_boundary("c_main", "_Z3fooi", false, true);
        assert!(
            result.is_some(),
            "C calling C++ mangled function must be detected as FFI boundary"
        );
        let info = result.unwrap();
        assert_eq!(
            info.callee_lang,
            Language::Cpp,
            "Callee must be detected as C++"
        );
    }

    /// Objective: Verify unknown language handling.
    /// Invariants: Unknown language calls are not treated as FFI boundaries;
    ///             Unknown callers don't trigger cross-language detection.
    #[test]
    fn test_unknown_language() {
        let detector = FFIBoundaryDetector::new();

        // Unknown caller with defined function → C fallback
        let lang = detector.detect_caller_lang("unknown_func", true);
        assert_eq!(
            lang,
            Language::C,
            "Unknown defined function must fallback to C"
        );

        // Unknown caller with non-defined function → Unknown
        let lang = detector.detect_caller_lang("unknown_func", false);
        assert_eq!(
            lang,
            Language::Unknown,
            "Unknown non-defined function must stay Unknown"
        );

        // Unknown caller with known callee → not cross-language
        assert!(
            !detector.is_cross_language(Language::Unknown, Language::C),
            "Unknown caller must not be cross-language"
        );

        // Unknown callee with known caller → not cross-language
        assert!(
            !detector.is_cross_language(Language::Rust, Language::Unknown),
            "Unknown callee must not be cross-language"
        );

        // Unknown caller with Unknown callee → not FFI boundary
        assert!(
            !detector.is_ffi_boundary("unknown_func", Language::Unknown, Language::Unknown),
            "Unknown languages must not be FFI boundary"
        );

        // Aggressive detection with non-external unknown → not FFI
        let result =
            detector.detect_aggressive_boundary("unknown_caller", "unknown_callee", false, false);
        assert!(
            result.is_none(),
            "Non-external unknown call must not be detected as FFI"
        );
    }

    /// Objective: Verify same language calls are not FFI boundaries.
    /// Invariants: Same language calls (even with runtime intrinsics) are not FFI;
    ///             Same language user functions are not FFI.
    #[test]
    fn test_same_language_not_ffi() {
        let detector = FFIBoundaryDetector::new();

        // Rust calling Rust user function → not FFI
        assert!(
            !detector.is_ffi_boundary("rust_function", Language::Rust, Language::Rust),
            "Rust calling Rust user function must not be FFI boundary"
        );

        // C calling C user function → not FFI
        assert!(
            !detector.is_ffi_boundary("c_function", Language::C, Language::C),
            "C calling C user function must not be FFI boundary"
        );

        // C++ calling C++ user function → not FFI
        assert!(
            !detector.is_ffi_boundary("cpp_function", Language::Cpp, Language::Cpp),
            "C++ calling C++ user function must not be FFI boundary"
        );

        // Zig calling Zig user function → not FFI
        assert!(
            !detector.is_ffi_boundary("zig_function", Language::Zig, Language::Zig),
            "Zig calling Zig user function must not be FFI boundary"
        );

        // Same language with runtime intrinsic → not FFI (even if it might be filtered)
        assert!(
            !detector.is_ffi_boundary("__rust_dealloc", Language::Rust, Language::Rust),
            "Rust calling Rust runtime intrinsic must not be FFI boundary"
        );

        // Same language with libc function → not FFI
        assert!(
            !detector.is_ffi_boundary("malloc", Language::C, Language::C),
            "C calling C libc function must not be FFI boundary"
        );

        // Verify aggressive detection also respects same language
        let result = detector.detect_aggressive_boundary("rust_main", "rust_helper", false, true);
        assert!(
            result.is_none(),
            "Aggressive detection must not flag same language calls as FFI"
        );
    }
}
