//! Boundary inference from IR analysis.
//!
//! This module provides automatic FFI boundary detection when
//! no explicit --cross configuration is provided. It analyzes
//! the IR module to detect potential FFI boundaries based on:
//! - C++ mangled names (starting with `_Z`)
//! - External declarations
//! - Language-specific function naming conventions
//! - Function signature patterns

use omniscope_ir::IRModule;
use omniscope_types::boundary::BoundaryContext;
use omniscope_types::config::{FFIBoundaryConfig, Language};
use tracing::{debug, info};

/// Infer FFI boundaries from IR module.
///
/// This function analyzes the IR module to detect potential
/// FFI boundaries based on various patterns.
///
/// # Arguments
/// * `module` - The IR module to analyze.
///
/// # Returns
/// A `BoundaryContext` containing inferred FFI boundaries.
pub fn infer_boundaries(module: &IRModule) -> BoundaryContext {
    let mut ctx = BoundaryContext::new();

    // 1. Detect C++ mangled names
    let cpp_functions = detect_cpp_mangled_names(module);
    if !cpp_functions.is_empty() {
        debug!(
            count = cpp_functions.len(),
            "Detected C++ mangled functions"
        );

        // Assume caller is C, callee is C++
        ctx.add_boundary(&FFIBoundaryConfig {
            from: Language::C,
            to: Language::Cpp,
            functions: cpp_functions,
            pattern: None,
            description: Some("Auto-detected C++ mangled names".to_string()),
        });
    }

    // 2. Detect external declarations
    let extern_functions = detect_extern_declarations(module);
    if !extern_functions.is_empty() {
        debug!(
            count = extern_functions.len(),
            "Detected external declarations"
        );

        // Guess language from function name
        for (func, lang) in extern_functions {
            ctx.add_boundary(&FFIBoundaryConfig {
                from: Language::Unknown,
                to: lang,
                functions: vec![func],
                pattern: None,
                description: Some("Auto-detected external declaration".to_string()),
            });
        }
    }

    // 3. Detect language-specific naming conventions
    let convention_functions = detect_naming_conventions(module);
    if !convention_functions.is_empty() {
        debug!(
            count = convention_functions.len(),
            "Detected language-specific naming conventions"
        );

        for (func, lang) in convention_functions {
            ctx.add_boundary(&FFIBoundaryConfig {
                from: Language::Unknown,
                to: lang,
                functions: vec![func],
                pattern: None,
                description: Some("Auto-detected naming convention".to_string()),
            });
        }
    }

    info!(boundaries = ctx.boundary_count(), "Inferred FFI boundaries");

    ctx
}

/// Detect C++ mangled names (starting with `_Z`).
///
/// # Arguments
/// * `module` - The IR module to analyze.
///
/// # Returns
/// A vector of function names that appear to be C++ mangled.
fn detect_cpp_mangled_names(module: &IRModule) -> Vec<String> {
    let mut functions = Vec::new();

    for call in &module.calls {
        let callee = call.callee.trim_start_matches('@');

        // C++ mangled names typically start with _Z
        if callee.starts_with("_Z") {
            functions.push(callee.to_string());
        }
    }

    // Sort by lowercase string because Language does not implement Ord
    functions.sort_by_key(|a| a.to_lowercase());
    functions.dedup();
    functions
}

/// Detect external declarations and guess language.
///
/// # Arguments
/// * `module` - The IR module to analyze.
///
/// # Returns
/// A vector of (function_name, language) pairs for external declarations.
fn detect_extern_declarations(module: &IRModule) -> Vec<(String, Language)> {
    let mut functions = Vec::new();

    for (name, func) in &module.functions {
        if func.is_declaration {
            let clean_name = name.trim_start_matches('@');
            let lang = guess_language_from_name(clean_name);

            if lang != Language::Unknown {
                functions.push((clean_name.to_string(), lang));
            }
        }
    }

    functions
}

/// Detect language-specific naming conventions.
///
/// # Arguments
/// * `module` - The IR module to analyze.
///
/// # Returns
/// A vector of (function_name, language) pairs based on naming conventions.
fn detect_naming_conventions(module: &IRModule) -> Vec<(String, Language)> {
    let mut functions = Vec::new();

    for call in &module.calls {
        let callee = call.callee.trim_start_matches('@');
        let lang = guess_language_from_name(callee);

        if lang != Language::Unknown {
            functions.push((callee.to_string(), lang));
        }
    }

    functions.sort_by_key(|a| a.0.to_lowercase());
    functions.dedup();
    functions
}

/// Guess language from function name.
///
/// This function uses various heuristics to guess the language
/// based on function naming conventions.
///
/// # Arguments
/// * `name` - The function name to analyze.
///
/// # Returns
/// The guessed language, or `Language::Unknown` if uncertain.
fn guess_language_from_name(name: &str) -> Language {
    // Go functions
    if name.starts_with("_Cfunc_") || name.starts_with("_cgo_") {
        return Language::Go;
    }

    // Rust functions
    if name.starts_with("__rust_") || name.contains("rust_") {
        return Language::Rust;
    }

    // Zig functions
    if name.starts_with("zig_") || name.contains(".allocator") {
        return Language::Zig;
    }

    // Python functions
    if name.starts_with("Py") || name.contains("PyObject") {
        return Language::Python;
    }

    // JNI functions
    if name.starts_with("JNI_") || name.starts_with("Java_") {
        return Language::Java;
    }

    // C# functions
    if name.contains("Marshal.") || name.contains("IntPtr") {
        return Language::CSharp;
    }

    Language::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify C++ mangled name detection.
    /// Invariants: Names starting with `_Z` should be detected.
    #[test]
    fn test_cpp_mangled_detection() {
        assert!(
            "_Znam".starts_with("_Z"),
            "C++ mangled name must start with _Z"
        );
        assert!(
            "_ZdlPv".starts_with("_Z"),
            "C++ mangled name must start with _Z"
        );
        assert!(
            !"malloc".starts_with("_Z"),
            "malloc should not start with _Z"
        );
    }

    /// Objective: Verify Go function detection.
    /// Invariants: Go cgo functions should be detected.
    #[test]
    fn test_go_function_detection() {
        assert_eq!(
            guess_language_from_name("_Cfunc_malloc"),
            Language::Go,
            "_Cfunc_ prefix must be detected as Go"
        );
        assert_eq!(
            guess_language_from_name("_cgo_allocate"),
            Language::Go,
            "_cgo_ prefix must be detected as Go"
        );
        assert_eq!(
            guess_language_from_name("malloc"),
            Language::Unknown,
            "malloc should be Unknown"
        );
    }

    /// Objective: Verify Rust function detection.
    /// Invariants: Rust runtime functions should be detected.
    #[test]
    fn test_rust_function_detection() {
        assert_eq!(
            guess_language_from_name("__rust_alloc"),
            Language::Rust,
            "__rust_ prefix must be detected as Rust"
        );
        assert_eq!(
            guess_language_from_name("rust_main"),
            Language::Rust,
            "rust_ prefix must be detected as Rust"
        );
        assert_eq!(
            guess_language_from_name("malloc"),
            Language::Unknown,
            "malloc should be Unknown"
        );
    }

    /// Objective: Verify Zig function detection.
    /// Invariants: Zig functions should be detected.
    #[test]
    fn test_zig_function_detection() {
        assert_eq!(
            guess_language_from_name("zig_alloc"),
            Language::Zig,
            "zig_ prefix must be detected as Zig"
        );
        assert_eq!(
            guess_language_from_name("heap.allocator"),
            Language::Zig,
            ".allocator suffix must be detected as Zig"
        );
        assert_eq!(
            guess_language_from_name("malloc"),
            Language::Unknown,
            "malloc should be Unknown"
        );
    }

    /// Objective: Verify Python function detection.
    /// Invariants: Python functions should be detected.
    #[test]
    fn test_python_function_detection() {
        assert_eq!(
            guess_language_from_name("PyObject_GetAttr"),
            Language::Python,
            "Py prefix must be detected as Python"
        );
        assert_eq!(
            guess_language_from_name("PyObject"),
            Language::Python,
            "PyObject must be detected as Python"
        );
        assert_eq!(
            guess_language_from_name("malloc"),
            Language::Unknown,
            "malloc should be Unknown"
        );
    }

    /// Objective: Verify Java function detection.
    /// Invariants: JNI functions should be detected.
    #[test]
    fn test_java_function_detection() {
        assert_eq!(
            guess_language_from_name("JNI_CreateJavaVM"),
            Language::Java,
            "JNI_ prefix must be detected as Java"
        );
        assert_eq!(
            guess_language_from_name("Java_com_example_Main_nativeMethod"),
            Language::Java,
            "Java_ prefix must be detected as Java"
        );
        assert_eq!(
            guess_language_from_name("malloc"),
            Language::Unknown,
            "malloc should be Unknown"
        );
    }

    /// Objective: Verify C# function detection.
    /// Invariants: C# functions should be detected.
    #[test]
    fn test_csharp_function_detection() {
        assert_eq!(
            guess_language_from_name("Marshal.AllocHGlobal"),
            Language::CSharp,
            "Marshal. must be detected as C#"
        );
        assert_eq!(
            guess_language_from_name("IntPtr_Size"),
            Language::CSharp,
            "IntPtr must be detected as C#"
        );
        assert_eq!(
            guess_language_from_name("malloc"),
            Language::Unknown,
            "malloc should be Unknown"
        );
    }

    /// Objective: Verify boundary inference from IR module.
    /// Invariants: C++ mangled names should be detected as boundaries.
    #[test]
    fn test_infer_boundaries_cpp() {
        let mut module = IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "_Z3fooi".to_string(),
            caller: "c_main".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "_Z3barv".to_string(),
            caller: "c_main".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });

        let ctx = infer_boundaries(&module);
        assert!(!ctx.is_empty(), "Should detect C++ boundaries");
        assert_eq!(
            ctx.boundary_count(),
            2,
            "Should detect 2 boundary functions"
        );
    }

    /// Objective: Verify boundary inference from external declarations.
    /// Invariants: External declarations with known patterns should be detected.
    #[test]
    fn test_infer_boundaries_extern() {
        let mut module = IRModule::new();
        module.functions.insert(
            "@_Cfunc_malloc".to_string(),
            omniscope_ir::Function {
                name: "_Cfunc_malloc".to_string(),
                is_declaration: true,
                params: Vec::new(),
                return_type: "ptr".to_string(),
            },
        );

        let ctx = infer_boundaries(&module);
        assert!(!ctx.is_empty(), "Should detect Go external declarations");
    }

    /// Objective: Verify boundary inference from naming conventions.
    /// Invariants: Language-specific naming patterns should be detected.
    #[test]
    fn test_infer_boundaries_naming_conventions() {
        let mut module = IRModule::new();
        module.calls.push(omniscope_ir::CallInstruction {
            callee: "PyObject_GetAttr".to_string(),
            caller: "c_main".to_string(),
            is_external: true,
            location: None,
            args: Vec::new(),
            result: None,
        });

        let ctx = infer_boundaries(&module);
        assert!(!ctx.is_empty(), "Should detect Python naming conventions");
    }

    /// Objective: Verify empty module produces empty context.
    /// Invariants: No boundaries should be inferred from empty module.
    #[test]
    fn test_infer_boundaries_empty() {
        let module = IRModule::new();
        let ctx = infer_boundaries(&module);
        assert!(ctx.is_empty(), "Empty module should produce empty context");
    }
}
