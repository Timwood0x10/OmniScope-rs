//! Library-level allocator pair inference (R-7).
//!
//! Table-driven detector for third-party library allocation/release pairs.
//! Covers POSIX-syscall-adjacent allocators that are NOT standard POSIX:
//!
//! - mimalloc (`mi_malloc` / `mi_free` / `mi_heap_destroy`)
//! - zlib (`inflateInit_` / `inflateEnd` / `deflateInit_` / `deflateEnd`)
//! - openssl (`EVP_CIPHER_CTX_new` / `EVP_CIPHER_CTX_free`, etc.)
//! - sqlite (`sqlite3_open` / `sqlite3_close`, etc.)
//! - Go cgo (`_cgo_allocate` / `_cgo_free`, etc.)
//! - Python CFFI (`Py_DECREF` / `Py_XDECREF` / `PyList_GetItem`, etc.)
//! - JNI (`NewGlobalRef` / `DeleteGlobalRef` / `GetStringUTFChars`, etc.)
//! - Zig allocator vtable (`zig_allocator_allocImpl` / `zig_allocator_freeImpl`)
//!
//! Evidence source: `ir.md` §9 (manual per-file .ll analysis, each entry
//! annotated with source file). This detector complements R-4 POSIX syscall
//! classification — R-4 covers standard syscalls, R-7 covers library APIs.

use omniscope_types::{Effect, Evidence, EvidenceKind, FunctionId, LanguageHint, SymbolId};

use crate::resource::summary::ResourceSummary;

// ──────────────────────────────────────────────────────────────────────────
// Library alloc pair table entry
// ──────────────────────────────────────────────────────────────────────────

/// Effect classification for a library allocator function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LibraryAllocEffect {
    /// Acquires a resource (e.g., mi_malloc, EVP_CIPHER_CTX_new).
    Acquire,
    /// Releases a resource (e.g., mi_free, inflateEnd).
    Release,
    /// Returns a borrowed reference (e.g., PyList_GetItem, GetStringUTFChars).
    Borrow,
    /// Conditionally releases a resource (e.g., Py_DECREF, mi_heap_destroy).
    ConditionalRelease,
}

/// A single entry in the library allocator pair table.
#[derive(Debug, Clone)]
pub struct LibraryAllocEntry {
    /// Canonical symbol name.
    pub name: &'static str,
    /// Source language.
    pub language: LanguageHint,
    /// Effect classification.
    pub effect: LibraryAllocEffect,
    /// Evidence source file (e.g., "bun_alloc-ef7250b81132b4bd.ll").
    pub evidence_file: &'static str,
}

// ──────────────────────────────────────────────────────────────────────────
// Library allocator pair table (from ir.md §9)
// ──────────────────────────────────────────────────────────────────────────

/// Complete table of library-level allocator pairs.
/// Each entry comes from a real .ll file in the corpus.
/// This table is NOT a whitelist — it encodes public API documentation
/// of well-known libraries. Adding a new library requires evidence
/// from at least one .ll file.
const LIBRARY_ALLOC_TABLE: &[LibraryAllocEntry] = &[
    // ── mimalloc (bun's custom allocator) ──
    // Evidence: bun_alloc-ef7250b81132b4bd.ll
    LibraryAllocEntry {
        name: "mi_malloc",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "bun_alloc-ef7250b81132b4bd.ll",
    },
    LibraryAllocEntry {
        name: "mi_free",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Release,
        evidence_file: "bun_alloc-ef7250b81132b4bd.ll",
    },
    LibraryAllocEntry {
        name: "mi_realloc",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "bun_alloc-ef7250b81132b4bd.ll",
    },
    LibraryAllocEntry {
        name: "mi_heap_destroy",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::ConditionalRelease,
        evidence_file: "bun_alloc-ef7250b81132b4bd.ll",
    },
    // ── zlib ──
    // Evidence: zlib_binding.ll
    LibraryAllocEntry {
        name: "inflateInit_",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "zlib_binding.ll",
    },
    LibraryAllocEntry {
        name: "inflateEnd",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Release,
        evidence_file: "zlib_binding.ll",
    },
    LibraryAllocEntry {
        name: "deflateInit_",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "zlib_binding.ll",
    },
    LibraryAllocEntry {
        name: "deflateEnd",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Release,
        evidence_file: "zlib_binding.ll",
    },
    // ── openssl ──
    // Evidence: openssl_wrapper.ll
    LibraryAllocEntry {
        name: "EVP_CIPHER_CTX_new",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "openssl_wrapper.ll",
    },
    LibraryAllocEntry {
        name: "EVP_CIPHER_CTX_free",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Release,
        evidence_file: "openssl_wrapper.ll",
    },
    LibraryAllocEntry {
        name: "BIO_new",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "openssl_wrapper.ll",
    },
    LibraryAllocEntry {
        name: "BIO_free",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Release,
        evidence_file: "openssl_wrapper.ll",
    },
    LibraryAllocEntry {
        name: "RSA_new",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "openssl_wrapper.ll",
    },
    LibraryAllocEntry {
        name: "RSA_free",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Release,
        evidence_file: "openssl_wrapper.ll",
    },
    LibraryAllocEntry {
        name: "BN_new",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "openssl_wrapper.ll",
    },
    LibraryAllocEntry {
        name: "BN_free",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Release,
        evidence_file: "openssl_wrapper.ll",
    },
    // ── sqlite ──
    // Evidence: sqlite_binding.ll
    LibraryAllocEntry {
        name: "sqlite3_open",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "sqlite_binding.ll",
    },
    LibraryAllocEntry {
        name: "sqlite3_close",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Release,
        evidence_file: "sqlite_binding.ll",
    },
    LibraryAllocEntry {
        name: "sqlite3_prepare_v2",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "sqlite_binding.ll",
    },
    LibraryAllocEntry {
        name: "sqlite3_finalize",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Release,
        evidence_file: "sqlite_binding.ll",
    },
    LibraryAllocEntry {
        name: "sqlite3_free",
        language: LanguageHint::C,
        effect: LibraryAllocEffect::Release,
        evidence_file: "sqlite_binding.ll",
    },
    // ── Go cgo ──
    // Evidence: go_cgo_bugs.ll
    LibraryAllocEntry {
        name: "_cgo_allocate",
        language: LanguageHint::Go,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "go_cgo_bugs.ll",
    },
    LibraryAllocEntry {
        name: "_cgo_free",
        language: LanguageHint::Go,
        effect: LibraryAllocEffect::Release,
        evidence_file: "go_cgo_bugs.ll",
    },
    LibraryAllocEntry {
        name: "_Cfunc_GoMalloc",
        language: LanguageHint::Go,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "go_cgo_bugs.ll",
    },
    LibraryAllocEntry {
        name: "_Cfunc_GoFree",
        language: LanguageHint::Go,
        effect: LibraryAllocEffect::Release,
        evidence_file: "go_cgo_bugs.ll",
    },
    // ── Python CFFI ──
    // Evidence: python_cffi_bugs.ll
    LibraryAllocEntry {
        name: "Py_DECREF",
        language: LanguageHint::Python,
        effect: LibraryAllocEffect::ConditionalRelease,
        evidence_file: "python_cffi_bugs.ll",
    },
    LibraryAllocEntry {
        name: "Py_XDECREF",
        language: LanguageHint::Python,
        effect: LibraryAllocEffect::ConditionalRelease,
        evidence_file: "python_cffi_bugs.ll",
    },
    LibraryAllocEntry {
        name: "PyList_GetItem",
        language: LanguageHint::Python,
        effect: LibraryAllocEffect::Borrow,
        evidence_file: "python_cffi_bugs.ll",
    },
    LibraryAllocEntry {
        name: "PyBytes_AsString",
        language: LanguageHint::Python,
        effect: LibraryAllocEffect::Borrow,
        evidence_file: "python_cffi_bugs.ll",
    },
    LibraryAllocEntry {
        name: "ctypes_alloc",
        language: LanguageHint::Python,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "python_cffi_bugs.ll",
    },
    // ── JNI ──
    // Evidence: java_jni_bugs.ll
    LibraryAllocEntry {
        name: "NewGlobalRef",
        language: LanguageHint::Java,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "java_jni_bugs.ll",
    },
    LibraryAllocEntry {
        name: "DeleteGlobalRef",
        language: LanguageHint::Java,
        effect: LibraryAllocEffect::Release,
        evidence_file: "java_jni_bugs.ll",
    },
    LibraryAllocEntry {
        name: "DeleteLocalRef",
        language: LanguageHint::Java,
        effect: LibraryAllocEffect::Release,
        evidence_file: "java_jni_bugs.ll",
    },
    LibraryAllocEntry {
        name: "GetStringUTFChars",
        language: LanguageHint::Java,
        effect: LibraryAllocEffect::Borrow,
        evidence_file: "java_jni_bugs.ll",
    },
    LibraryAllocEntry {
        name: "ReleaseStringUTFChars",
        language: LanguageHint::Java,
        effect: LibraryAllocEffect::Release,
        evidence_file: "java_jni_bugs.ll",
    },
    LibraryAllocEntry {
        name: "GetPrimitiveArrayCritical",
        language: LanguageHint::Java,
        effect: LibraryAllocEffect::Borrow,
        evidence_file: "java_jni_bugs.ll",
    },
    LibraryAllocEntry {
        name: "ReleasePrimitiveArrayCritical",
        language: LanguageHint::Java,
        effect: LibraryAllocEffect::Release,
        evidence_file: "java_jni_bugs.ll",
    },
    LibraryAllocEntry {
        name: "NewStringUTF",
        language: LanguageHint::Java,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "java_jni_bugs.ll",
    },
    LibraryAllocEntry {
        name: "NewByteArray",
        language: LanguageHint::Java,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "java_jni_bugs.ll",
    },
    LibraryAllocEntry {
        name: "GetByteArrayElements",
        language: LanguageHint::Java,
        effect: LibraryAllocEffect::Borrow,
        evidence_file: "java_jni_bugs.ll",
    },
    LibraryAllocEntry {
        name: "ReleaseByteArrayElements",
        language: LanguageHint::Java,
        effect: LibraryAllocEffect::Release,
        evidence_file: "java_jni_bugs.ll",
    },
    // ── Zig allocator vtable ──
    // Evidence: boundary_test.ll
    LibraryAllocEntry {
        name: "zig_allocator_allocImpl",
        language: LanguageHint::Zig,
        effect: LibraryAllocEffect::Acquire,
        evidence_file: "boundary_test.ll",
    },
    LibraryAllocEntry {
        name: "zig_allocator_freeImpl",
        language: LanguageHint::Zig,
        effect: LibraryAllocEffect::Release,
        evidence_file: "boundary_test.ll",
    },
];

// ──────────────────────────────────────────────────────────────────────────
// Lookup + summary inference
// ──────────────────────────────────────────────────────────────────────────

/// Result of library alloc pair inference for a function.
#[derive(Debug, Clone)]
pub struct LibraryAllocInferenceResult {
    /// Whether this function was found in the library alloc pair table.
    pub matched: bool,
    /// The matched entry from the table (if any).
    pub entry: Option<LibraryAllocEntry>,
    /// Confidence of the inference.
    pub confidence: f32,
}

/// Looks up a symbol name in the library allocator pair table.
/// Returns the matching entry if found, along with a confidence score.
pub fn lookup_library_alloc(name: &str) -> Option<&'static LibraryAllocEntry> {
    LIBRARY_ALLOC_TABLE.iter().find(|e| e.name == name)
}

/// Infers a resource summary for a library-level allocator function.
///
/// This is the R-7 detector: table-driven, each entry is backed by
/// public API documentation and observed in at least one corpus .ll file.
/// cross_language_free detection should check this table alongside
/// the R-4 POSIX syscall table — the two are complementary.
pub fn infer_library_alloc_summary(
    name: &str,
    function: FunctionId,
    canonical_name: SymbolId,
    language_hint: LanguageHint,
) -> (ResourceSummary, LibraryAllocInferenceResult) {
    let mut summary = ResourceSummary::new(function, canonical_name, name);
    summary.language_hint = language_hint;

    let Some(entry) = lookup_library_alloc(name) else {
        let result = LibraryAllocInferenceResult {
            matched: false,
            entry: None,
            confidence: 0.0,
        };
        return (summary, result);
    };

    summary.confidence = 0.95;
    summary.origin = omniscope_types::FunctionOrigin::ThirdParty;

    // Map LibraryAllocEffect to Effect + Evidence
    match entry.effect {
        LibraryAllocEffect::Acquire => {
            summary.add_effect(Effect::ReturnsOwned {
                family: omniscope_types::FamilyId::C_HEAP,
            });
        }
        LibraryAllocEffect::Release => {
            summary.add_effect(Effect::Release {
                family: omniscope_types::FamilyId::C_HEAP,
                arg: 0,
            });
        }
        LibraryAllocEffect::Borrow => {
            summary.add_effect(Effect::ReturnsBorrowed);
        }
        LibraryAllocEffect::ConditionalRelease => {
            summary.add_effect(Effect::ConditionalRelease {
                family: omniscope_types::FamilyId::C_HEAP,
                arg: 0,
            });
        }
    }

    // Attach library-alloc evidence
    summary.add_evidence(
        Evidence::new(
            EvidenceKind::OwnershipTransfer,
            format!(
                "R-7 library alloc pair: '{}' is {:?} for {:?} [evidence: {}]",
                entry.name, entry.effect, entry.language, entry.evidence_file
            ),
        )
        .with_confidence(0.95),
    );

    let result = LibraryAllocInferenceResult {
        matched: true,
        entry: Some(entry.clone()),
        confidence: 0.95,
    };

    (summary, result)
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_mimalloc() {
        let entry = lookup_library_alloc("mi_malloc").expect("mi_malloc must be in table");
        assert_eq!(entry.effect, LibraryAllocEffect::Acquire);
        assert_eq!(entry.language, LanguageHint::C);
    }

    #[test]
    fn test_lookup_zlib() {
        let inflate_end = lookup_library_alloc("inflateEnd").expect("inflateEnd must be in table");
        assert_eq!(inflate_end.effect, LibraryAllocEffect::Release);
        let deflate_init = lookup_library_alloc("deflateInit_").expect("deflateInit_ in table");
        assert_eq!(deflate_init.effect, LibraryAllocEffect::Acquire);
    }

    #[test]
    fn test_lookup_openssl() {
        let ctx_new = lookup_library_alloc("EVP_CIPHER_CTX_new").expect("must be in table");
        assert_eq!(ctx_new.effect, LibraryAllocEffect::Acquire);
        let ctx_free = lookup_library_alloc("EVP_CIPHER_CTX_free").expect("must be in table");
        assert_eq!(ctx_free.effect, LibraryAllocEffect::Release);
    }

    #[test]
    fn test_lookup_sqlite() {
        let open = lookup_library_alloc("sqlite3_open").expect("sqlite3_open in table");
        assert_eq!(open.effect, LibraryAllocEffect::Acquire);
        let close = lookup_library_alloc("sqlite3_close").expect("sqlite3_close in table");
        assert_eq!(close.effect, LibraryAllocEffect::Release);
    }

    #[test]
    fn test_lookup_go_cgo() {
        let alloc = lookup_library_alloc("_cgo_allocate").expect("must be in table");
        assert_eq!(alloc.effect, LibraryAllocEffect::Acquire);
        assert_eq!(alloc.language, LanguageHint::Go);
    }

    #[test]
    fn test_lookup_python() {
        let decref = lookup_library_alloc("Py_DECREF").expect("Py_DECREF in table");
        assert_eq!(decref.effect, LibraryAllocEffect::ConditionalRelease);
        let getitem = lookup_library_alloc("PyList_GetItem").expect("PyList_GetItem in table");
        assert_eq!(getitem.effect, LibraryAllocEffect::Borrow);
    }

    #[test]
    fn test_lookup_jni() {
        let new_ref = lookup_library_alloc("NewGlobalRef").expect("NewGlobalRef in table");
        assert_eq!(new_ref.effect, LibraryAllocEffect::Acquire);
        assert_eq!(new_ref.language, LanguageHint::Java);
        let get_chars = lookup_library_alloc("GetStringUTFChars").expect("in table");
        assert_eq!(get_chars.effect, LibraryAllocEffect::Borrow);
    }

    #[test]
    fn test_lookup_zig() {
        let alloc = lookup_library_alloc("zig_allocator_allocImpl").expect("in table");
        assert_eq!(alloc.effect, LibraryAllocEffect::Acquire);
        assert_eq!(alloc.language, LanguageHint::Zig);
    }

    #[test]
    fn test_lookup_unknown() {
        assert!(
            lookup_library_alloc("some_random_function").is_none(),
            "Unknown function must not match"
        );
    }

    #[test]
    fn test_infer_mimalloc_free() {
        let (summary, result) = infer_library_alloc_summary("mi_free", 1, 100, LanguageHint::C);
        assert!(result.matched, "mi_free must match");
        assert!(result.confidence > 0.9, "Confidence must be high");
        assert!(
            summary
                .evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::OwnershipTransfer),
            "Must have OwnershipTransfer evidence"
        );
    }

    #[test]
    fn test_infer_no_match() {
        let (_, result) = infer_library_alloc_summary("random_func", 2, 200, LanguageHint::C);
        assert!(!result.matched, "random_func must not match");
    }

    #[test]
    fn test_table_completeness() {
        // R-7 table must cover all 8 allocator families from the plan
        let families = [
            ("mi_malloc", "mimalloc"),
            ("inflateInit_", "zlib"),
            ("EVP_CIPHER_CTX_new", "openssl"),
            ("sqlite3_open", "sqlite"),
            ("_cgo_allocate", "go_cgo"),
            ("Py_DECREF", "python"),
            ("NewGlobalRef", "jni"),
            ("zig_allocator_allocImpl", "zig"),
        ];
        for (name, family_name) in &families {
            assert!(
                lookup_library_alloc(name).is_some(),
                "R-7 table must cover {family_name} ({name})"
            );
        }
    }
}
