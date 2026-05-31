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
        Language::Cpp => name.starts_with("_Z") || name.starts_with("__cxxabiv1"),
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
    /// Invariants: _Z and __cxxabiv1 prefixes are intrinsics.
    #[test]
    fn test_cpp_runtime_intrinsics() {
        assert!(
            is_runtime_intrinsic("_Z3fooi", Language::Cpp),
            "_Z prefix must be recognized as C++ mangled intrinsic"
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

        let result = detector.detect_aggressive_boundary("rust_main", "unknown_ext", true, false);
        assert!(
            result.is_some(),
            "Rust calling external unknown must be detected as FFI"
        );
        let info = result.unwrap();
        assert_eq!(info.caller_lang, Language::Rust);
        assert_eq!(info.callee_lang, Language::C);
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

        // Known Rust function → Rust regardless of caller_is_defined
        let lang = detector.detect_caller_lang("_ZN4rust_main", true);
        assert_eq!(
            lang,
            Language::Rust,
            "Rust function must be detected as Rust"
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
}
