# Changelog

## [Unreleased]

### Added
- Cross-language FFI testing corpus (9 projects, 5 languages)
- Inline IR regression tests for real-world FFI patterns
- `NullChecked` semantic kind for null-check-before-dereference pattern
- `SuppressWrapperDelegation` gate verdict for thin wrapper functions
- `is_thin_wrapper_function()` for pure delegation detection
- `is_c_library_internal()` for generic C library function recognition
- `is_release_function()` to prevent false double_free suppression
- `noundef` return attribute detection for UncheckedReturn suppression
- Python refcount suppression for OwnershipViolation
- R-16 rule: suppress all stores in Rust mangled functions
- Rust v0 mangling support in `is_runtime_internal()`

### Fixed
- write_to_immutable noise: -99.8% (4525->8 on memscope-rs)
- ffi_unsafe_call noise: -100% (142->0 on omniscope_pass)
- borrow_escape noise: -88% (51->7 on rust_sqlite)
- null_dereference FP from duckdb-rs, rusqlite
- double_free FP from rustls-ffi, JNA thin wrappers
- unchecked_return FP from noundef returns
- ownership_violation FP from Python PyUnicode_FromString
- Borrowed->Escape transition warning flood (downgraded to debug)
- Language detector quote handling for LLVM IR names
- `_Z` prefix checks now exclude Rust Itanium mangling

### Changed
- `is_release_callee()` narrowed: removed `.contains("free")` catch-all
- `is_rust_zn_mangling()` enhanced with stdlib prefix recognition
- Evidence description for library-managed families now includes "library" keyword
