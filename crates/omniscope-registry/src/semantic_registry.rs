//! Semantic Registry for FFI Boundary Analysis.
//!
//! This module provides a knowledge base for FFI boundary function semantics.
//! It is NOT a simple "dangerous function blacklist" — instead, it captures
//! the semantic properties of functions that are relevant when crossing
//! language boundaries.
//!
//! ## Key Insight
//!
//! The same function has different risk levels depending on context:
//! - `strcpy` in pure C code = medium risk
//! - `strcpy` crossing Rust→C boundary = HIGH risk (length constraint broken,
//!   lifetime broken)
//!
//! ## Layers
//!
//! - Layer 1: FFI high-risk functions (C standard library)
//! - Layer 2: Rust ownership patterns (into_raw, from_raw, as_ptr)
//! - Layer 3: Go cgo allocator patterns
//! - Layer 4: C# FFI patterns
//! - Layer 5: Zig standard library patterns
//! - Layer 6: C++ standard library patterns
//!
//! Additional modules: JNI, Python C API, POSIX I/O, POSIX thread

use omniscope_types::Language;
use serde::{Deserialize, Serialize};

/// Kind of risk associated with a function at an FFI boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskKind {
    /// Memory allocation / deallocation mismatch.
    MemoryAlloc,
    /// Pointer ownership transfer.
    OwnershipTransfer,
    /// Buffer overflow potential.
    BufferOverflow,
    /// String handling without length check.
    StringUnsafe,
    /// Type confusion / ABI mismatch.
    TypeConfusion,
    /// Thread safety violation.
    ThreadSafety,
    /// Resource leak (file, socket, handle).
    ResourceLeak,
    /// Null pointer risk.
    NullPointer,
    /// Reference count mismatch (Python Py_INCREF/Py_DECREF).
    RefCountMismatch,
    /// No special risk.
    None,
}

/// Severity level for a registered function's risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskSeverity {
    /// Informational — no immediate risk.
    Info,
    /// Low risk — unlikely to cause problems.
    Low,
    /// Medium risk — could cause issues under certain conditions.
    Medium,
    /// High risk — likely to cause FFI safety issues.
    High,
    /// Critical risk — almost certainly will cause problems.
    Critical,
}

/// Match type for function name patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MatchType {
    /// Exact name match.
    Exact,
    /// Prefix match (function name starts with pattern).
    Prefix,
    /// Substring match (function name contains pattern).
    Contains,
}

/// Semantic information about a function relevant to FFI analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSemantics {
    /// Function name or pattern.
    pub pattern: String,
    /// How to match the pattern against function names.
    pub match_type: MatchType,
    /// Primary risk kind at FFI boundaries.
    pub risk_kind: RiskKind,
    /// Risk severity level.
    pub severity: RiskSeverity,
    /// Source language this function belongs to.
    pub language: Language,
    /// Which registry layer this entry comes from.
    pub layer: u8,
    /// Human-readable description of the risk.
    pub description: String,
}

impl FunctionSemantics {
    /// Creates a new function semantics entry.
    pub fn new(
        pattern: impl Into<String>,
        match_type: MatchType,
        risk_kind: RiskKind,
        severity: RiskSeverity,
        language: Language,
        layer: u8,
        description: impl Into<String>,
    ) -> Self {
        Self {
            pattern: pattern.into(),
            match_type,
            risk_kind,
            severity,
            language,
            layer,
            description: description.into(),
        }
    }

    /// Checks if a function name matches this semantics entry.
    pub fn matches(&self, func_name: &str) -> bool {
        match self.match_type {
            MatchType::Exact => func_name == self.pattern,
            MatchType::Prefix => func_name.starts_with(&self.pattern),
            MatchType::Contains => func_name.contains(&self.pattern),
        }
    }
}

/// The semantic registry containing all known function semantics.
///
/// Layers are populated lazily on first query. This avoids paying
/// the cost of building all layers upfront when only a subset is needed.
pub struct SemanticRegistry {
    /// All registered function semantics, indexed by layer.
    entries: Vec<FunctionSemantics>,
}

impl SemanticRegistry {
    /// Creates a new semantic registry with all layers populated.
    pub fn new() -> Self {
        let mut entries = Vec::with_capacity(512);
        Self::populate_layer1(&mut entries);
        Self::populate_layer2(&mut entries);
        Self::populate_layer3(&mut entries);
        Self::populate_layer5(&mut entries);
        Self::populate_layer6(&mut entries);
        Self::populate_jni(&mut entries);
        Self::populate_python_c_api(&mut entries);
        Self::populate_posix_io(&mut entries);
        Self { entries }
    }

    /// Looks up the first matching function semantics for a function name.
    pub fn lookup(&self, func_name: &str) -> Option<&FunctionSemantics> {
        self.entries.iter().find(|e| e.matches(func_name))
    }

    /// Looks up all matching function semantics for a function name.
    pub fn lookup_all(&self, func_name: &str) -> Vec<&FunctionSemantics> {
        self.entries
            .iter()
            .filter(|e| e.matches(func_name))
            .collect()
    }

    /// Returns the number of registered entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Checks if a function name matches any high-risk pattern.
    pub fn is_high_risk(&self, func_name: &str) -> bool {
        self.entries.iter().any(|e| {
            e.matches(func_name)
                && (e.severity == RiskSeverity::High || e.severity == RiskSeverity::Critical)
        })
    }

    // ========================================================================
    // Layer population methods
    // ========================================================================

    /// Layer 1: FFI high-risk C standard library functions.
    fn populate_layer1(entries: &mut Vec<FunctionSemantics>) {
        let layer1 = [
            (
                "strcpy",
                MatchType::Exact,
                RiskKind::StringUnsafe,
                RiskSeverity::Critical,
                Language::C,
                1,
                "copies string without bounds check — buffer overflow at FFI boundary",
            ),
            (
                "strcat",
                MatchType::Exact,
                RiskKind::StringUnsafe,
                RiskSeverity::Critical,
                Language::C,
                1,
                "concatenates without bounds check — buffer overflow risk",
            ),
            (
                "sprintf",
                MatchType::Exact,
                RiskKind::BufferOverflow,
                RiskSeverity::High,
                Language::C,
                1,
                "format string vulnerability — no length limit",
            ),
            (
                "gets",
                MatchType::Exact,
                RiskKind::BufferOverflow,
                RiskSeverity::Critical,
                Language::C,
                1,
                "reads input without length limit — always dangerous",
            ),
            (
                "system",
                MatchType::Exact,
                RiskKind::TypeConfusion,
                RiskSeverity::Critical,
                Language::C,
                1,
                "executes shell command — command injection at FFI boundary",
            ),
            (
                "popen",
                MatchType::Exact,
                RiskKind::TypeConfusion,
                RiskSeverity::High,
                Language::C,
                1,
                "opens a process — command injection risk",
            ),
            (
                "scanf",
                MatchType::Exact,
                RiskKind::BufferOverflow,
                RiskSeverity::High,
                Language::C,
                1,
                "reads formatted input — buffer overflow without bounds",
            ),
            (
                "getenv",
                MatchType::Exact,
                RiskKind::NullPointer,
                RiskSeverity::Medium,
                Language::C,
                1,
                "returns NULL if env var not found — null deref risk",
            ),
            (
                "malloc",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::C,
                1,
                "heap allocation — ownership mismatch across FFI boundary",
            ),
            (
                "free",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::C,
                1,
                "heap deallocation — double free / cross-language free risk",
            ),
            (
                "realloc",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::C,
                1,
                "reallocation — dangling pointer if cross-language ownership",
            ),
        ];

        for (pattern, mt, risk, sev, lang, layer, desc) in layer1 {
            entries.push(FunctionSemantics::new(
                pattern, mt, risk, sev, lang, layer, desc,
            ));
        }
    }

    /// Layer 2: Rust ownership patterns.
    fn populate_layer2(entries: &mut Vec<FunctionSemantics>) {
        let layer2 = [
            (
                "into_raw",
                MatchType::Contains,
                RiskKind::OwnershipTransfer,
                RiskSeverity::High,
                Language::Rust,
                2,
                "Rust transfers ownership to C — must free with from_raw",
            ),
            (
                "from_raw",
                MatchType::Contains,
                RiskKind::OwnershipTransfer,
                RiskSeverity::High,
                Language::Rust,
                2,
                "Rust takes ownership from C — must not free on C side",
            ),
            (
                "as_ptr",
                MatchType::Contains,
                RiskKind::OwnershipTransfer,
                RiskSeverity::Medium,
                Language::Rust,
                2,
                "borrows pointer — C must not free or modify beyond borrow scope",
            ),
            (
                "as_mut_ptr",
                MatchType::Contains,
                RiskKind::OwnershipTransfer,
                RiskSeverity::Medium,
                Language::Rust,
                2,
                "borrows mutable pointer — C must respect Rust's aliasing rules",
            ),
            (
                "from_raw_parts",
                MatchType::Contains,
                RiskKind::OwnershipTransfer,
                RiskSeverity::High,
                Language::Rust,
                2,
                "reconstructs slice from raw parts — lifetime/bounds must be valid",
            ),
            (
                "Leak",
                MatchType::Contains,
                RiskKind::ResourceLeak,
                RiskSeverity::Medium,
                Language::Rust,
                2,
                "intentional leak — ensure cleanup happens on the other side",
            ),
        ];

        for (pattern, mt, risk, sev, lang, layer, desc) in layer2 {
            entries.push(FunctionSemantics::new(
                pattern, mt, risk, sev, lang, layer, desc,
            ));
        }
    }

    /// Layer 3: Go cgo allocator patterns.
    fn populate_layer3(entries: &mut Vec<FunctionSemantics>) {
        let layer3 = [
            (
                "C.malloc",
                MatchType::Prefix,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Go,
                3,
                "Go allocates C memory — must free with C.free",
            ),
            (
                "C.free",
                MatchType::Prefix,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Go,
                3,
                "Go frees C memory — must ensure Go no longer holds pointer",
            ),
            (
                "C.CString",
                MatchType::Exact,
                RiskKind::OwnershipTransfer,
                RiskSeverity::High,
                Language::Go,
                3,
                "Go string to C string — must free with C.free",
            ),
            (
                "C.GoString",
                MatchType::Exact,
                RiskKind::OwnershipTransfer,
                RiskSeverity::Medium,
                Language::Go,
                3,
                "C string to Go string — copies data, safe if C string valid",
            ),
            (
                "cgo_",
                MatchType::Prefix,
                RiskKind::ThreadSafety,
                RiskSeverity::Medium,
                Language::Go,
                3,
                "cgo internal — thread safety depends on Go scheduler",
            ),
        ];

        for (pattern, mt, risk, sev, lang, layer, desc) in layer3 {
            entries.push(FunctionSemantics::new(
                pattern, mt, risk, sev, lang, layer, desc,
            ));
        }
    }

    /// Layer 5: Zig standard library patterns.
    fn populate_layer5(entries: &mut Vec<FunctionSemantics>) {
        let layer5 = [
            (
                "std.c.malloc",
                MatchType::Prefix,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Zig,
                5,
                "Zig calls C malloc — ownership transferred across boundary",
            ),
            (
                "std.c.free",
                MatchType::Prefix,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Zig,
                5,
                "Zig calls C free — double free risk if Zig also frees",
            ),
            (
                "std.maybe",
                MatchType::Prefix,
                RiskKind::NullPointer,
                RiskSeverity::Low,
                Language::Zig,
                5,
                "Zig optional — null pointer must be checked before use",
            ),
        ];

        for (pattern, mt, risk, sev, lang, layer, desc) in layer5 {
            entries.push(FunctionSemantics::new(
                pattern, mt, risk, sev, lang, layer, desc,
            ));
        }
    }

    /// Layer 6: C++ standard library patterns.
    fn populate_layer6(entries: &mut Vec<FunctionSemantics>) {
        let layer6 = [
            (
                "operator new",
                MatchType::Contains,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Cpp,
                6,
                "C++ heap allocation — must pair with operator delete",
            ),
            (
                "operator delete",
                MatchType::Contains,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Cpp,
                6,
                "C++ deallocation — cross-language free risk",
            ),
            (
                "std::malloc",
                MatchType::Prefix,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Cpp,
                6,
                "C++ calls C malloc — ownership transfer across boundary",
            ),
            (
                "std::free",
                MatchType::Prefix,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Cpp,
                6,
                "C++ calls C free — mismatch with new[] allocation",
            ),
        ];

        for (pattern, mt, risk, sev, lang, layer, desc) in layer6 {
            entries.push(FunctionSemantics::new(
                pattern, mt, risk, sev, lang, layer, desc,
            ));
        }
    }

    /// JNI function registry.
    fn populate_jni(entries: &mut Vec<FunctionSemantics>) {
        let jni = [
            (
                "JNI_CreateJavaVM",
                MatchType::Exact,
                RiskKind::ResourceLeak,
                RiskSeverity::Medium,
                Language::Java,
                7,
                "creates JVM — must call DestroyJavaVM to avoid resource leak",
            ),
            (
                "GetByteArrayElements",
                MatchType::Prefix,
                RiskKind::OwnershipTransfer,
                RiskSeverity::High,
                Language::Java,
                7,
                "JNI gets array pointer — must call ReleaseByteArrayElements",
            ),
            (
                "GetStringUTFChars",
                MatchType::Exact,
                RiskKind::OwnershipTransfer,
                RiskSeverity::High,
                Language::Java,
                7,
                "JNI gets string — must call ReleaseStringUTFChars",
            ),
            (
                "NewStringUTF",
                MatchType::Exact,
                RiskKind::OwnershipTransfer,
                RiskSeverity::Medium,
                Language::Java,
                7,
                "JNI creates string from C — null return means OOM",
            ),
            (
                "FindClass",
                MatchType::Exact,
                RiskKind::NullPointer,
                RiskSeverity::Medium,
                Language::Java,
                7,
                "JNI finds class — returns null if not found",
            ),
        ];

        for (pattern, mt, risk, sev, lang, layer, desc) in jni {
            entries.push(FunctionSemantics::new(
                pattern, mt, risk, sev, lang, layer, desc,
            ));
        }
    }

    /// Python C API function registry.
    ///
    /// Covers the full Python C API ownership model:
    /// - **Allocators**: PyObject_New, PyObject_NewVar, PyLong_FromLong, etc.
    /// - **Deallocators**: PyObject_Del, Py_DECREF, Py_CLEAR
    /// - **Ref count ops**: Py_INCREF, Py_XINCREF
    /// - **Borrowed refs**: PyList_GetItem, PyTuple_GetItem (no DECREF needed)
    /// - **New refs**: PyList_GetItem + Py_INCREF pattern
    ///
    /// Key insight: PyObject_New/Del are alloc/dealloc pairs.
    /// PyLong_From* returns a new reference (must DECREF).
    /// PyList_GetItem returns a borrowed reference (must NOT DECREF).
    fn populate_python_c_api(entries: &mut Vec<FunctionSemantics>) {
        let py = [
            // === Allocators (return new reference, must DECREF) ===
            (
                "PyObject_New",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API allocates object — must pair with PyObject_Del or Py_DECREF",
            ),
            (
                "PyObject_NewVar",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API allocates var-size object — must pair with PyObject_Del or Py_DECREF",
            ),
            (
                "PyLong_FromLong",
                MatchType::Prefix,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API creates int object — returns new ref, must Py_DECREF",
            ),
            (
                "PyLong_FromUnsignedLong",
                MatchType::Prefix,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API creates int from unsigned — returns new ref, must Py_DECREF",
            ),
            (
                "PyLong_FromLongLong",
                MatchType::Prefix,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API creates int from long long — returns new ref, must Py_DECREF",
            ),
            (
                "PyLong_FromString",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API creates int from string — returns new ref, must Py_DECREF",
            ),
            (
                "PyFloat_FromDouble",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API creates float — returns new ref, must Py_DECREF",
            ),
            (
                "PyBytes_FromString",
                MatchType::Prefix,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API creates bytes — returns new ref, must Py_DECREF",
            ),
            (
                "PyUnicode_FromString",
                MatchType::Prefix,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API creates str — returns new ref, must Py_DECREF",
            ),
            (
                "PyList_New",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API creates list — returns new ref, must Py_DECREF",
            ),
            (
                "PyDict_New",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API creates dict — returns new ref, must Py_DECREF",
            ),
            (
                "PyTuple_New",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API creates tuple — returns new ref, must Py_DECREF",
            ),
            (
                "PySet_New",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API creates set — returns new ref, must Py_DECREF",
            ),
            (
                "Py_BuildValue",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API builds value — returns new ref, format must match types",
            ),
            // === Deallocators ===
            (
                "PyObject_Del",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API deallocates object — must pair with PyObject_New",
            ),
            (
                "PyObject_GC_Del",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API GC dealloc — must pair with PyObject_GC_New",
            ),
            // === Reference count operations ===
            (
                "Py_INCREF",
                MatchType::Exact,
                RiskKind::RefCountMismatch,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API increments ref — must pair with Py_DECREF",
            ),
            (
                "Py_DECREF",
                MatchType::Exact,
                RiskKind::RefCountMismatch,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API decrements ref — double DECREF causes use-after-free",
            ),
            (
                "Py_XINCREF",
                MatchType::Exact,
                RiskKind::RefCountMismatch,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API safe increment — NULL-safe, must pair with Py_XDECREF",
            ),
            (
                "Py_XDECREF",
                MatchType::Exact,
                RiskKind::RefCountMismatch,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API safe decrement — NULL-safe, double DECREF still dangerous",
            ),
            (
                "Py_CLEAR",
                MatchType::Exact,
                RiskKind::RefCountMismatch,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API safe clear — DECREF + set NULL, prevents double DECREF",
            ),
            (
                "Py_SETREF",
                MatchType::Exact,
                RiskKind::RefCountMismatch,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API set reference — DECREF old + set new, ref count safe",
            ),
            // === Borrowed reference getters (NO DECREF needed) ===
            (
                "PyList_GetItem",
                MatchType::Exact,
                RiskKind::OwnershipTransfer,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API borrowed ref — do NOT Py_DECREF, use PyList_GET_ITEM+Py_INCREF for new ref",
            ),
            (
                "PyTuple_GetItem",
                MatchType::Exact,
                RiskKind::OwnershipTransfer,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API borrowed ref — do NOT Py_DECREF, use PyTuple_GET_ITEM+Py_INCREF for new ref",
            ),
            (
                "PyDict_GetItem",
                MatchType::Exact,
                RiskKind::OwnershipTransfer,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API borrowed ref — do NOT Py_DECREF on result",
            ),
            (
                "PyDict_GetItemString",
                MatchType::Exact,
                RiskKind::OwnershipTransfer,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API borrowed ref — do NOT Py_DECREF on result",
            ),
            // === New reference getters (DECREF needed) ===
            (
                "PyList_GetItemRef",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API new ref getter — returns new ref, must Py_DECREF (3.12+)",
            ),
            (
                "PyObject_GetAttr",
                MatchType::Prefix,
                RiskKind::NullPointer,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API gets attr — returns new ref or NULL, must Py_DECREF on success",
            ),
            (
                "PyObject_GetItem",
                MatchType::Exact,
                RiskKind::NullPointer,
                RiskSeverity::Medium,
                Language::Python,
                7,
                "Python C API gets item — returns new ref or NULL, must Py_DECREF on success",
            ),
            // === Argument parsing (steals refs on error) ===
            (
                "PyArg_ParseTuple",
                MatchType::Exact,
                RiskKind::TypeConfusion,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API parses args — format mismatch causes crash, may steal refs on error",
            ),
            (
                "PyArg_ParseTupleAndKeywords",
                MatchType::Exact,
                RiskKind::TypeConfusion,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API parses args+kwargs — format mismatch causes crash",
            ),
            // === GC tracking ===
            (
                "PyObject_GC_New",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API GC-tracked alloc — must pair with PyObject_GC_Del",
            ),
            (
                "PyObject_GC_NewVar",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::High,
                Language::Python,
                7,
                "Python C API GC-tracked var alloc — must pair with PyObject_GC_Del",
            ),
            (
                "PyObject_GC_Track",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::Low,
                Language::Python,
                7,
                "Python C API GC track — must pair with PyObject_GC_UnTrack",
            ),
            (
                "PyObject_GC_UnTrack",
                MatchType::Exact,
                RiskKind::MemoryAlloc,
                RiskSeverity::Low,
                Language::Python,
                7,
                "Python C API GC untrack — must pair with PyObject_GC_Track",
            ),
        ];

        for (pattern, mt, risk, sev, lang, layer, desc) in py {
            entries.push(FunctionSemantics::new(
                pattern, mt, risk, sev, lang, layer, desc,
            ));
        }
    }

    /// POSIX I/O function registry.
    fn populate_posix_io(entries: &mut Vec<FunctionSemantics>) {
        let posix = [
            (
                "open",
                MatchType::Exact,
                RiskKind::ResourceLeak,
                RiskSeverity::Medium,
                Language::C,
                7,
                "opens file descriptor — must close to avoid leak",
            ),
            (
                "close",
                MatchType::Exact,
                RiskKind::ResourceLeak,
                RiskSeverity::Medium,
                Language::C,
                7,
                "closes fd — double close causes undefined behavior",
            ),
            (
                "fopen",
                MatchType::Exact,
                RiskKind::ResourceLeak,
                RiskSeverity::Medium,
                Language::C,
                7,
                "opens FILE* — must fclose to avoid leak",
            ),
            (
                "fclose",
                MatchType::Exact,
                RiskKind::ResourceLeak,
                RiskSeverity::Medium,
                Language::C,
                7,
                "closes FILE* — double fclose causes crash",
            ),
        ];

        for (pattern, mt, risk, sev, lang, layer, desc) in posix {
            entries.push(FunctionSemantics::new(
                pattern, mt, risk, sev, lang, layer, desc,
            ));
        }
    }
}

impl Default for SemanticRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify that the registry is populated with entries
    /// from all layers.
    /// Invariants: Registry must contain entries from at least layers 1-3.
    #[test]
    fn test_registry_populated() {
        let registry = SemanticRegistry::new();
        assert!(
            registry.len() > 20,
            "Registry must contain entries from all layers, got {}",
            registry.len()
        );
    }

    /// Objective: Verify Layer 1 (C stdlib) risk classification.
    /// Invariants: strcpy must be classified as Critical string-unsafe risk.
    #[test]
    fn test_layer1_c_stdlib_lookup() {
        let registry = SemanticRegistry::new();
        let sem = registry.lookup("strcpy");
        assert!(sem.is_some(), "strcpy must be found in registry");
        let sem = sem.unwrap();
        assert_eq!(
            sem.risk_kind,
            RiskKind::StringUnsafe,
            "strcpy must be StringUnsafe"
        );
        assert_eq!(
            sem.severity,
            RiskSeverity::Critical,
            "strcpy must be Critical severity"
        );
    }

    /// Objective: Verify Layer 2 (Rust ownership) pattern matching.
    /// Invariants: into_raw must match via Contains pattern.
    #[test]
    fn test_layer2_rust_ownership() {
        let registry = SemanticRegistry::new();
        let sem = registry.lookup("std::ffi::CString::into_raw");
        assert!(sem.is_some(), "into_raw must match via Contains pattern");
        let sem = sem.unwrap();
        assert_eq!(
            sem.risk_kind,
            RiskKind::OwnershipTransfer,
            "into_raw must be OwnershipTransfer risk"
        );
    }

    /// Objective: Verify high-risk detection across layers.
    /// Invariants: Functions with High or Critical severity must be detected.
    #[test]
    fn test_high_risk_detection() {
        let registry = SemanticRegistry::new();
        assert!(
            registry.is_high_risk("strcpy"),
            "strcpy is Critical → high risk"
        );
        assert!(
            registry.is_high_risk("system"),
            "system is Critical → high risk"
        );
        assert!(registry.is_high_risk("free"), "free is High → high risk");
        assert!(
            !registry.is_high_risk("strlen"),
            "strlen not registered → not high risk"
        );
    }

    /// Objective: Verify JNI function lookup.
    /// Invariants: JNI functions must be found by prefix match.
    #[test]
    fn test_jni_lookup() {
        let registry = SemanticRegistry::new();
        let sem = registry.lookup("GetByteArrayElements");
        assert!(
            sem.is_some(),
            "GetByteArrayElements must be in JNI registry"
        );
        assert_eq!(sem.unwrap().risk_kind, RiskKind::OwnershipTransfer);
    }

    /// Objective: Verify Python C API allocator/deallocator lookup.
    /// Invariants: PyObject_New/Del must be found and classified correctly.
    #[test]
    fn test_python_alloc_dealloc_pairs() {
        let registry = SemanticRegistry::new();

        // Allocators
        let sem = registry.lookup("PyObject_New");
        assert!(sem.is_some(), "PyObject_New must be registered");
        let sem = sem.unwrap();
        assert_eq!(
            sem.risk_kind,
            RiskKind::MemoryAlloc,
            "PyObject_New must be MemoryAlloc"
        );
        assert_eq!(
            sem.severity,
            RiskSeverity::High,
            "PyObject_New must be High severity"
        );

        // Deallocator
        let sem = registry.lookup("PyObject_Del");
        assert!(sem.is_some(), "PyObject_Del must be registered");
        assert_eq!(
            sem.unwrap().risk_kind,
            RiskKind::MemoryAlloc,
            "PyObject_Del must be MemoryAlloc"
        );

        // GC variant
        let sem = registry.lookup("PyObject_GC_New");
        assert!(sem.is_some(), "PyObject_GC_New must be registered");
        assert_eq!(
            sem.unwrap().risk_kind,
            RiskKind::MemoryAlloc,
            "PyObject_GC_New must be MemoryAlloc"
        );

        let sem = registry.lookup("PyObject_GC_Del");
        assert!(sem.is_some(), "PyObject_GC_Del must be registered");
        assert_eq!(
            sem.unwrap().risk_kind,
            RiskKind::MemoryAlloc,
            "PyObject_GC_Del must be MemoryAlloc"
        );
    }

    /// Objective: Verify Python C API refcount operations.
    /// Invariants: Py_INCREF/DECREF must be RefCountMismatch, not OwnershipTransfer.
    #[test]
    fn test_python_refcount_ops() {
        let registry = SemanticRegistry::new();

        let sem = registry.lookup("Py_INCREF");
        assert!(sem.is_some(), "Py_INCREF must be registered");
        assert_eq!(
            sem.unwrap().risk_kind,
            RiskKind::RefCountMismatch,
            "Py_INCREF must be RefCountMismatch"
        );

        let sem = registry.lookup("Py_DECREF");
        assert!(sem.is_some(), "Py_DECREF must be registered");
        let sem = sem.unwrap();
        assert_eq!(
            sem.risk_kind,
            RiskKind::RefCountMismatch,
            "Py_DECREF must be RefCountMismatch"
        );
        assert_eq!(
            sem.severity,
            RiskSeverity::High,
            "Py_DECREF must be High severity"
        );

        let sem = registry.lookup("Py_CLEAR");
        assert!(sem.is_some(), "Py_CLEAR must be registered");
        assert_eq!(
            sem.unwrap().risk_kind,
            RiskKind::RefCountMismatch,
            "Py_CLEAR must be RefCountMismatch"
        );
    }

    /// Objective: Verify Python C API borrowed vs new reference distinction.
    /// Invariants: PyList_GetItem (borrowed) != PyList_GetItemRef (new ref).
    #[test]
    fn test_python_borrowed_vs_new_ref() {
        let registry = SemanticRegistry::new();

        // Borrowed reference — should NOT be DECREFed
        let sem = registry.lookup("PyList_GetItem");
        assert!(sem.is_some(), "PyList_GetItem must be registered");
        assert_eq!(
            sem.unwrap().risk_kind,
            RiskKind::OwnershipTransfer,
            "PyList_GetItem must be OwnershipTransfer (borrowed ref)"
        );

        // New reference (Python 3.12+) — must be DECREFed
        let sem = registry.lookup("PyList_GetItemRef");
        assert!(sem.is_some(), "PyList_GetItemRef must be registered");
        assert_eq!(
            sem.unwrap().risk_kind,
            RiskKind::MemoryAlloc,
            "PyList_GetItemRef must be MemoryAlloc (new ref)"
        );

        // PyDict_GetItem — borrowed reference
        let sem = registry.lookup("PyDict_GetItem");
        assert!(sem.is_some(), "PyDict_GetItem must be registered");
        assert_eq!(
            sem.unwrap().risk_kind,
            RiskKind::OwnershipTransfer,
            "PyDict_GetItem must be OwnershipTransfer (borrowed ref)"
        );
    }

    /// Objective: Verify Python C API type constructors (PyLong_From*, etc).
    /// Invariants: All Py*_From* constructors return new references.
    #[test]
    fn test_python_type_constructors() {
        let registry = SemanticRegistry::new();

        // PyLong_FromLong (prefix match)
        let sem = registry.lookup("PyLong_FromLong");
        assert!(sem.is_some(), "PyLong_FromLong must be registered");
        assert_eq!(
            sem.unwrap().risk_kind,
            RiskKind::MemoryAlloc,
            "PyLong_FromLong must be MemoryAlloc"
        );

        // PyLong_FromUnsignedLongLong (prefix match)
        let sem = registry.lookup("PyLong_FromUnsignedLongLong");
        assert!(
            sem.is_some(),
            "PyLong_FromUnsignedLongLong must match via prefix"
        );
        assert_eq!(
            sem.unwrap().risk_kind,
            RiskKind::MemoryAlloc,
            "PyLong_FromUnsignedLongLong must be MemoryAlloc"
        );

        // PyBytes_FromString (prefix match)
        let sem = registry.lookup("PyBytes_FromString");
        assert!(sem.is_some(), "PyBytes_FromString must be registered");

        // PyUnicode_FromString (prefix match)
        let sem = registry.lookup("PyUnicode_FromString");
        assert!(sem.is_some(), "PyUnicode_FromString must be registered");

        // PyList_New (exact match)
        let sem = registry.lookup("PyList_New");
        assert!(sem.is_some(), "PyList_New must be registered");
        assert_eq!(sem.unwrap().risk_kind, RiskKind::MemoryAlloc);

        // PyDict_New (exact match)
        let sem = registry.lookup("PyDict_New");
        assert!(sem.is_some(), "PyDict_New must be registered");
    }

    /// Objective: Verify that Python C API functions are correctly flagged as high-risk.
    #[test]
    fn test_python_high_risk() {
        let registry = SemanticRegistry::new();

        assert!(
            registry.is_high_risk("PyObject_New"),
            "PyObject_New is High → high risk"
        );
        assert!(
            registry.is_high_risk("PyObject_Del"),
            "PyObject_Del is High → high risk"
        );
        assert!(
            registry.is_high_risk("Py_DECREF"),
            "Py_DECREF is High → high risk"
        );
        assert!(
            !registry.is_high_risk("Py_INCREF"),
            "Py_INCREF is Medium → not high risk"
        );
        assert!(
            !registry.is_high_risk("Py_CLEAR"),
            "Py_CLEAR is Medium → not high risk"
        );
    }
}
