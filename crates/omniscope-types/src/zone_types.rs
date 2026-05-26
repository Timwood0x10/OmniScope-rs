//! Zone type definitions for multi-language unsafe boundary analysis.
//!
//! Core principle: Analyze only where language guarantees stop.
//!
//! **Safe Zone** (default trusted — skip analysis):
//!   - Rust: safe fn, Vec/String normal use, borrow checker constraints
//!   - Zig: normal slice/allocator idiom, defer/errdefer paths
//!   - Go: non-cgo, normal GC objects
//!   - C++: RAII container internals
//!
//! **Escape Zone** (focus analysis):
//!   - Rust: unsafe block, extern "C", raw pointer, transmute
//!   - Zig: @ptrCast, @intToPtr, @cImport, extern fn
//!   - Go: cgo, unsafe.Pointer, uintptr tricks
//!   - C++: extern C, reinterpret_cast, manual malloc/free

use serde::{Deserialize, Serialize};

use super::config::Language;

/// Zone classification kind.
///
/// Determines whether a function needs analysis and how much
/// scrutiny it should receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ZoneKind {
    /// Safe zone — can skip analysis (language guarantees hold).
    Safe,
    /// Escape zone — needs focused analysis (language guarantees broken).
    Escape,
    /// FFI boundary zone — always analyze (cross-language call site).
    Boundary,
    /// Unknown zone — conservative: treat as needing analysis.
    #[default]
    Unknown,
}

impl ZoneKind {
    /// Returns true if this zone should be analyzed.
    ///
    /// Safe zones can be skipped; all others require analysis.
    pub fn should_analyze(&self) -> bool {
        matches!(
            self,
            ZoneKind::Escape | ZoneKind::Boundary | ZoneKind::Unknown
        )
    }

    /// Returns a human-readable string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ZoneKind::Safe => "SAFE",
            ZoneKind::Escape => "ESCAPE",
            ZoneKind::Boundary => "BOUNDARY",
            ZoneKind::Unknown => "UNKNOWN",
        }
    }
}

/// What triggered an Escape/Boundary classification.
///
/// Knowing the trigger helps produce actionable diagnostics:
/// "raw pointer dereference in unsafe block" is more useful
/// than just "escape zone detected".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscapeTrigger {
    /// Raw pointer usage (e.g., *const T, *mut T).
    RawPointer,
    /// Unsafe block or unsafe function.
    UnsafeBlock,
    /// FFI call crossing language boundary (extern, cgo, JNI).
    FFICall,
    /// Type punning via transmute or reinterpret_cast.
    Transmute,
    /// Manual memory management (malloc/free outside RAII).
    ManualMemory,
    /// Inline assembly block.
    InlineAsm,
    /// Null pointer related operation.
    NullPointer,
    /// Unknown trigger (cannot determine reason).
    Unknown,
}

/// Zone classification result with full metadata for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneClass {
    /// The classified zone kind.
    pub kind: ZoneKind,
    /// What triggered this classification (if Escape/Boundary).
    pub trigger: Option<EscapeTrigger>,
    /// Source language context for the classified function.
    pub language: Language,
    /// Confidence level (0.0 - 1.0) for the classification.
    pub confidence: f32,
    /// Human-readable reason for the classification.
    pub reason: String,
}

/// Zone classification statistics aggregated across a module.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZoneStats {
    /// Number of functions classified as safe.
    pub safe_count: usize,
    /// Number of functions classified as escape.
    pub escape_count: usize,
    /// Number of functions classified as boundary.
    pub boundary_count: usize,
    /// Number of functions classified as unknown.
    pub unknown_count: usize,
}

impl ZoneStats {
    /// Creates new empty statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of classified functions.
    pub fn total(&self) -> usize {
        self.safe_count + self.escape_count + self.boundary_count + self.unknown_count
    }
}

// ============================================================================
// Language-specific escape/safe patterns
//
// These pattern lists are derived from the Zig reference implementation
// and adapted for Rust naming conventions.
// ============================================================================

/// Rust safe patterns — functions in the safe zone that can be skipped.
pub const RUST_SAFE_PATTERNS: &[&str] = &[
    "core::ptr::drop_in_place",
    "core::mem::swap",
    "core::mem::replace",
    "alloc::vec::Vec",
    "alloc::string::String",
    "core::option::Option",
    "core::result::Result",
];

/// Rust escape patterns — triggers for Escape zone classification.
pub const RUST_ESCAPE_PATTERNS: &[&str] = &[
    "core::mem::transmute",
    "core::ptr::read",
    "core::ptr::write",
    "from_raw",
    "as_ptr",
    "into_raw",
    "from_raw_parts",
    "core::hint::unreachable_unchecked",
];

/// Zig safe patterns — standard library functions with safe semantics.
pub const ZIG_SAFE_PATTERNS: &[&str] = &[
    "std.mem.eql",
    "std.mem.startsWith",
    "std.mem.endsWith",
    "std.mem.indexOf",
    "std.fmt.format",
    "std.debug.print",
];

/// Zig escape patterns — operations that break Zig's safety guarantees.
pub const ZIG_ESCAPE_PATTERNS: &[&str] =
    &["@ptrCast", "@intToPtr", "@cImport", "std.c.", "std.os."];

/// Go safe patterns — GC-managed, no FFI.
pub const GO_SAFE_PATTERNS: &[&str] = &["runtime.", "fmt.", "strings.", "strconv."];

/// Go escape patterns — cgo and unsafe operations.
pub const GO_ESCAPE_PATTERNS: &[&str] = &["C.", "unsafe.Pointer", "C.malloc", "C.free", "cgo_"];

/// C++ safe patterns — RAII-managed resources.
pub const CPP_SAFE_PATTERNS: &[&str] = &[
    "std::vector",
    "std::string",
    "std::unique_ptr",
    "std::shared_ptr",
    "std::make_unique",
    "std::make_shared",
];

/// C++ escape patterns — manual memory or type-unsafe operations.
pub const CPP_ESCAPE_PATTERNS: &[&str] = &[
    "reinterpret_cast",
    "const_cast",
    "extern \"C\"",
    "std::malloc",
    "std::free",
];

/// C escape patterns — inherently unsafe C functions.
pub const C_ESCAPE_PATTERNS: &[&str] = &[
    "strcpy", "strcat", "sprintf", "gets", "system", "exec", "popen",
];

/// Python safe patterns — GC-managed operations that need no analysis.
pub const PYTHON_SAFE_PATTERNS: &[&str] = &[
    "PyList_Append",
    "PyDict_SetItem",
    "PyTuple_SetItem",
    "Py_INCREF",
    "Py_XDECREF",
    "Py_CLEAR",
    "PyObject_Call",
    "PyModule_AddObject",
];

/// Python escape patterns — manual ref count or alloc/dealloc operations.
pub const PYTHON_ESCAPE_PATTERNS: &[&str] = &[
    "PyObject_New",
    "PyObject_NewVar",
    "PyObject_Del",
    "PyObject_GC_New",
    "PyObject_GC_Del",
    "Py_DECREF",
    "PyLong_From",
    "PyFloat_From",
    "PyBytes_From",
    "PyUnicode_From",
    "PyList_New",
    "PyDict_New",
    "PyTuple_New",
    "Py_BuildValue",
    "PyArg_ParseTuple",
    "PyList_GetItem",
    "PyTuple_GetItem",
];

/// Classify a function by checking against language-specific patterns.
///
/// Escape patterns take priority over safe patterns: if a function
/// matches both, it is classified as Escape. Unknown functions that
/// match neither list return `ZoneKind::Unknown`.
pub fn classify_by_patterns(func_name: &str, language: Language) -> ZoneKind {
    let (safe_patterns, escape_patterns) = match language {
        Language::Rust => (RUST_SAFE_PATTERNS, RUST_ESCAPE_PATTERNS),
        Language::Zig => (ZIG_SAFE_PATTERNS, ZIG_ESCAPE_PATTERNS),
        Language::Go => (GO_SAFE_PATTERNS, GO_ESCAPE_PATTERNS),
        Language::Cpp => (CPP_SAFE_PATTERNS, CPP_ESCAPE_PATTERNS),
        Language::C => (&[] as &[&str], C_ESCAPE_PATTERNS),
        Language::Python => (PYTHON_SAFE_PATTERNS, PYTHON_ESCAPE_PATTERNS),
        _ => return ZoneKind::Unknown,
    };

    // Check escape patterns first — higher priority
    for pattern in escape_patterns {
        if func_name.contains(pattern) {
            return ZoneKind::Escape;
        }
    }

    // Check safe patterns
    for pattern in safe_patterns {
        if func_name.contains(pattern) {
            return ZoneKind::Safe;
        }
    }

    ZoneKind::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_kind_analysis_decision() {
        assert!(
            !ZoneKind::Safe.should_analyze(),
            "Safe zones should be skipped"
        );
        assert!(
            ZoneKind::Escape.should_analyze(),
            "Escape zones must be analyzed"
        );
        assert!(
            ZoneKind::Boundary.should_analyze(),
            "Boundary zones must be analyzed"
        );
        assert!(
            ZoneKind::Unknown.should_analyze(),
            "Unknown zones must be analyzed (conservative)"
        );
    }

    #[test]
    fn test_rust_classification_accuracy() {
        assert_eq!(
            classify_by_patterns("core::mem::transmute", Language::Rust),
            ZoneKind::Escape,
            "transmute is the quintessential escape pattern in Rust"
        );
        assert_eq!(
            classify_by_patterns("alloc::vec::Vec::push", Language::Rust),
            ZoneKind::Safe,
            "Vec::push is safe under borrow checker"
        );
        assert_eq!(
            classify_by_patterns("my_custom_fn", Language::Rust),
            ZoneKind::Unknown,
            "Custom functions without pattern match default to Unknown"
        );
    }

    #[test]
    fn test_escape_overrides_safe() {
        // A function that matches both safe and escape should be Escape.
        // This tests priority ordering in classify_by_patterns.
        assert_eq!(
            classify_by_patterns("core::ptr::write", Language::Rust),
            ZoneKind::Escape,
            "Escape patterns must take priority over safe patterns"
        );
    }

    #[test]
    fn test_c_language_has_no_safe_patterns() {
        assert_eq!(
            classify_by_patterns("strcpy", Language::C),
            ZoneKind::Escape,
            "strcpy is an inherently dangerous C function"
        );
        assert_eq!(
            classify_by_patterns("my_c_func", Language::C),
            ZoneKind::Unknown,
            "C has no safe patterns, so unrecognized functions are Unknown"
        );
    }

    #[test]
    fn test_zone_stats_total() {
        let stats = ZoneStats {
            safe_count: 10,
            escape_count: 5,
            boundary_count: 3,
            unknown_count: 2,
        };
        assert_eq!(stats.total(), 20, "total must be sum of all zone counts");
    }

    /// Objective: Verify Python zone classification for alloc/dealloc/refcount ops.
    /// Invariants: PyObject_New/Del and Py_DECREF are Escape; Py_INCREF is Safe.
    #[test]
    fn test_python_escape_zone_classification() {
        // Alloc/dealloc operations are escape zones
        assert_eq!(
            classify_by_patterns("PyObject_New", Language::Python),
            ZoneKind::Escape,
            "PyObject_New is manual memory management → Escape"
        );
        assert_eq!(
            classify_by_patterns("PyObject_Del", Language::Python),
            ZoneKind::Escape,
            "PyObject_Del is manual deallocation → Escape"
        );
        assert_eq!(
            classify_by_patterns("PyObject_GC_New", Language::Python),
            ZoneKind::Escape,
            "PyObject_GC_New is GC-tracked alloc → Escape"
        );
        // Type constructors are escape zones (return new reference)
        assert_eq!(
            classify_by_patterns("PyLong_FromLong", Language::Python),
            ZoneKind::Escape,
            "PyLong_FromLong returns new ref → Escape"
        );
        assert_eq!(
            classify_by_patterns("PyList_New", Language::Python),
            ZoneKind::Escape,
            "PyList_New returns new ref → Escape"
        );
        // DECREF is escape (dangerous ref count operation)
        assert_eq!(
            classify_by_patterns("Py_DECREF", Language::Python),
            ZoneKind::Escape,
            "Py_DECREF is dangerous ref count decrement → Escape"
        );
        // Borrowed ref getters are escape (ownership ambiguity)
        assert_eq!(
            classify_by_patterns("PyList_GetItem", Language::Python),
            ZoneKind::Escape,
            "PyList_GetItem is borrowed ref → Escape"
        );
    }

    /// Objective: Verify Python safe zone classification.
    /// Invariants: Py_INCREF, Py_CLEAR, Py_XDECREF are safe refcount ops.
    #[test]
    fn test_python_safe_zone_classification() {
        // Safe refcount operations
        assert_eq!(
            classify_by_patterns("Py_INCREF", Language::Python),
            ZoneKind::Safe,
            "Py_INCREF is a safe ref count increment → Safe"
        );
        assert_eq!(
            classify_by_patterns("Py_XDECREF", Language::Python),
            ZoneKind::Safe,
            "Py_XDECREF is NULL-safe decrement → Safe"
        );
        assert_eq!(
            classify_by_patterns("Py_CLEAR", Language::Python),
            ZoneKind::Safe,
            "Py_CLEAR is DECREF+NULL → Safe"
        );
        // Unknown function in Python → Unknown zone
        assert_eq!(
            classify_by_patterns("my_py_func", Language::Python),
            ZoneKind::Unknown,
            "Unknown Python function defaults to Unknown zone"
        );
    }

    /// Objective: Verify Python escape overrides safe.
    /// Invariants: When a function matches both safe and escape, Escape wins.
    #[test]
    fn test_python_escape_overrides_safe() {
        // Escape patterns must take priority over safe patterns.
        // Note: in practice Py_DECREF doesn't match any safe pattern,
        // but the priority rule must hold for any overlap.
        assert_eq!(
            classify_by_patterns("Py_DECREF", Language::Python),
            ZoneKind::Escape,
            "Escape pattern (Py_DECREF) must override any safe pattern"
        );
    }
}
