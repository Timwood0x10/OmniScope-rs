//! Container type inference for resource lifecycle analysis.
//!
//! This module provides inference of container types (Box, Vec, String, Rc, Arc, etc.)
//! from function names and IR instructions. Each container type has specific ownership
//! semantics and release pairing rules that affect how resources are tracked.
//!
//! # Design Principles
//!
//! 1. **Exact matching first**: Use exact function name matching before substring matching.
//! 2. **Language-aware**: Support both Rust and C++ container types.
//! 3. **Semantic correctness**: Each container type has well-defined ownership rules.
//! 4. **Extensible**: Easy to add new container types.

use omniscope_types::LanguageHint;
use tracing::trace;

/// Container types with distinct ownership semantics.
///
/// Each variant represents a specific container type that affects how resources
/// are tracked, transferred, and released. The variants are grouped by language
/// and ownership model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainerType {
    // ── Rust containers ──────────────────────────────────────────
    /// `Box<T>` - Exclusive ownership, single owner, deterministic drop.
    Box,
    /// `Vec<T>` - Dynamic array, owns elements, deterministic drop.
    Vec,
    /// `String` - Owned UTF-8 string, deterministic drop.
    String,
    /// `Rc<T>` - Reference counting, multiple owners, non-atomic.
    Rc,
    /// `Arc<T>` - Atomic reference counting, multiple owners, thread-safe.
    Arc,

    // ── C++ containers ───────────────────────────────────────────
    /// `std::unique_ptr<T>` - Exclusive ownership, single owner.
    UniquePtr,
    /// `std::shared_ptr<T>` - Shared ownership via reference counting.
    SharedPtr,

    // ── Raw pointers (language-agnostic) ─────────────────────────
    /// Raw pointer with no ownership semantics.
    RawPtr,
}

/// Ownership semantics for a container type.
///
/// Describes how the container manages the lifetime of its contained resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSemantics {
    /// Whether the container owns the resource (responsible for deallocation).
    pub owns_resource: bool,
    /// Whether the container can be copied (shared ownership).
    pub copyable: bool,
    /// Whether the container supports move semantics.
    pub movable: bool,
    /// The language this container type belongs to.
    pub language: LanguageHint,
    /// The typical deallocation function for this container.
    pub deallocation_function: &'static str,
}

/// Release pairing rule for container types.
///
/// Defines which release function is expected for a given allocation function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePairing {
    /// The allocation function name.
    pub allocate: &'static str,
    /// The expected deallocation function name.
    pub release: &'static str,
    /// The container type this pairing applies to.
    pub container: ContainerType,
}

/// Returns the ownership semantics for a container type.
///
/// # Examples
///
/// ```rust
/// use omniscope_semantics::resource::container_type::{ContainerType, container_semantics};
/// use omniscope_types::LanguageHint;
///
/// let box_semantics = container_semantics(ContainerType::Box);
/// assert!(box_semantics.owns_resource, "Box should own its resource");
/// assert_eq!(box_semantics.language, LanguageHint::Rust);
/// ```
pub fn container_semantics(container: ContainerType) -> ContainerSemantics {
    match container {
        // Rust containers
        ContainerType::Box => ContainerSemantics {
            owns_resource: true,
            copyable: false,
            movable: true,
            language: LanguageHint::Rust,
            deallocation_function: "drop_in_place",
        },
        ContainerType::Vec => ContainerSemantics {
            owns_resource: true,
            copyable: false,
            movable: true,
            language: LanguageHint::Rust,
            deallocation_function: "drop_in_place",
        },
        ContainerType::String => ContainerSemantics {
            owns_resource: true,
            copyable: false,
            movable: true,
            language: LanguageHint::Rust,
            deallocation_function: "drop_in_place",
        },
        ContainerType::Rc => ContainerSemantics {
            owns_resource: true,
            copyable: true,
            movable: true,
            language: LanguageHint::Rust,
            deallocation_function: "drop_in_place",
        },
        ContainerType::Arc => ContainerSemantics {
            owns_resource: true,
            copyable: true,
            movable: true,
            language: LanguageHint::Rust,
            deallocation_function: "drop_in_place",
        },

        // C++ containers
        ContainerType::UniquePtr => ContainerSemantics {
            owns_resource: true,
            copyable: false,
            movable: true,
            language: LanguageHint::Cpp,
            deallocation_function: "operator delete",
        },
        ContainerType::SharedPtr => ContainerSemantics {
            owns_resource: true,
            copyable: true,
            movable: true,
            language: LanguageHint::Cpp,
            deallocation_function: "operator delete",
        },

        // Raw pointers
        ContainerType::RawPtr => ContainerSemantics {
            owns_resource: false,
            copyable: true,
            movable: true,
            language: LanguageHint::C, // Default, can be any language
            deallocation_function: "free",
        },
    }
}

/// Returns the release pairing rules for common container types.
///
/// # Examples
///
/// ```rust
/// use omniscope_semantics::resource::container_type::release_pairings;
///
/// let pairings = release_pairings();
/// assert!(!pairings.is_empty(), "Should have release pairings");
/// ```
pub fn release_pairings() -> Vec<ReleasePairing> {
    vec![
        // Rust containers
        ReleasePairing {
            allocate: "alloc::vec::Vec::new",
            release: "drop_in_place",
            container: ContainerType::Vec,
        },
        ReleasePairing {
            allocate: "alloc::string::String::new",
            release: "drop_in_place",
            container: ContainerType::String,
        },
        ReleasePairing {
            allocate: "alloc::boxed::Box::new",
            release: "drop_in_place",
            container: ContainerType::Box,
        },
        ReleasePairing {
            allocate: "alloc::rc::Rc::new",
            release: "drop_in_place",
            container: ContainerType::Rc,
        },
        ReleasePairing {
            allocate: "alloc::sync::Arc::new",
            release: "drop_in_place",
            container: ContainerType::Arc,
        },
        // C++ containers
        ReleasePairing {
            allocate: "_Znwm", // operator new
            release: "_ZdlPv", // operator delete
            container: ContainerType::UniquePtr,
        },
        ReleasePairing {
            allocate: "_Znam", // operator new[]
            release: "_ZdaPv", // operator delete[]
            container: ContainerType::UniquePtr,
        },
        ReleasePairing {
            allocate: "operator new",
            release: "operator delete",
            container: ContainerType::UniquePtr,
        },
        ReleasePairing {
            allocate: "operator new[]",
            release: "operator delete[]",
            container: ContainerType::UniquePtr,
        },
    ]
}

/// Infers container type from a function name.
///
/// Uses exact matching first, then substring matching for common patterns.
/// Returns `None` if no container type can be inferred.
///
/// # Arguments
///
/// * `function_name` - The function name to analyze
///
/// # Returns
///
/// The inferred container type, or `None` if the function doesn't match any known container pattern.
///
/// # Examples
///
/// ```rust
/// use omniscope_semantics::resource::container_type::{infer_container_type, ContainerType};
///
/// // Rust containers
/// assert_eq!(infer_container_type("alloc::vec::Vec::new"), Some(ContainerType::Vec));
/// assert_eq!(infer_container_type("alloc::boxed::Box::new"), Some(ContainerType::Box));
/// assert_eq!(infer_container_type("alloc::string::String::new"), Some(ContainerType::String));
/// assert_eq!(infer_container_type("alloc::rc::Rc::new"), Some(ContainerType::Rc));
/// assert_eq!(infer_container_type("alloc::sync::Arc::new"), Some(ContainerType::Arc));
///
/// // C++ containers
/// assert_eq!(infer_container_type("_Znwm"), Some(ContainerType::UniquePtr));
/// assert_eq!(infer_container_type("operator new"), Some(ContainerType::UniquePtr));
///
/// // Unknown function
/// assert_eq!(infer_container_type("unknown_function"), None);
/// ```
pub fn infer_container_type(function_name: &str) -> Option<ContainerType> {
    // Fast path: exact matching for known functions
    if let Some(container) = exact_match(function_name) {
        trace!(
            function = function_name,
            container = ?container,
            "Exact match for container type"
        );
        return Some(container);
    }

    // Slow path: substring matching for common patterns
    if let Some(container) = substring_match(function_name) {
        trace!(
            function = function_name,
            container = ?container,
            "Substring match for container type"
        );
        return Some(container);
    }

    trace!(function = function_name, "No container type inferred");
    None
}

/// Exact matching for known function names.
fn exact_match(function_name: &str) -> Option<ContainerType> {
    match function_name {
        // Rust Vec
        "alloc::vec::Vec::new" | "alloc::vec::Vec::with_capacity" => Some(ContainerType::Vec),

        // Rust String
        "alloc::string::String::new" | "alloc::string::String::from" => Some(ContainerType::String),

        // Rust Box
        "alloc::boxed::Box::new" | "alloc::boxed::Box::new_uninit" => Some(ContainerType::Box),

        // Rust Rc
        "alloc::rc::Rc::new" | "alloc::rc::Rc::new_uninit" => Some(ContainerType::Rc),

        // Rust Arc
        "alloc::sync::Arc::new" | "alloc::sync::Arc::new_uninit" => Some(ContainerType::Arc),

        // C++ new/delete
        "_Znwm" | "_Znwj" | "operator new" => Some(ContainerType::UniquePtr),
        "_Znam" | "_Znaj" | "operator new[]" => Some(ContainerType::UniquePtr),
        "_ZdlPv" | "operator delete" => Some(ContainerType::UniquePtr),
        "_ZdaPv" | "operator delete[]" => Some(ContainerType::UniquePtr),

        // C++ shared_ptr
        "_ZNSt12__shared_ptr" | "std::shared_ptr" => Some(ContainerType::SharedPtr),

        // C++ unique_ptr
        "_ZNSt10unique_ptr" | "std::unique_ptr" => Some(ContainerType::UniquePtr),

        _ => None,
    }
}

/// Substring matching for common patterns.
fn substring_match(function_name: &str) -> Option<ContainerType> {
    // Rust container patterns
    if function_name.contains("Vec::new") || function_name.contains("Vec::with_capacity") {
        return Some(ContainerType::Vec);
    }

    if function_name.contains("String::new") || function_name.contains("String::from") {
        return Some(ContainerType::String);
    }

    if function_name.contains("Box::new") || function_name.contains("Box::new_uninit") {
        return Some(ContainerType::Box);
    }

    if function_name.contains("Rc::new") || function_name.contains("Rc::new_uninit") {
        return Some(ContainerType::Rc);
    }

    if function_name.contains("Arc::new") || function_name.contains("Arc::new_uninit") {
        return Some(ContainerType::Arc);
    }

    // C++ container patterns
    if function_name.contains("shared_ptr") {
        return Some(ContainerType::SharedPtr);
    }

    if function_name.contains("unique_ptr") {
        return Some(ContainerType::UniquePtr);
    }

    // Raw pointer patterns (allocation without container)
    if function_name == "malloc" || function_name == "calloc" || function_name == "realloc" {
        return Some(ContainerType::RawPtr);
    }

    if function_name == "__rust_alloc" || function_name == "__rust_alloc_zeroed" {
        return Some(ContainerType::RawPtr);
    }

    None
}

/// Infers container type from IR instruction context.
///
/// Analyzes the instruction and surrounding context to determine the container type.
/// This is more accurate than function name matching alone.
///
/// # Arguments
///
/// * `instruction` - The IR instruction to analyze
/// * `function_name` - The function containing the instruction
///
/// # Returns
///
/// The inferred container type, or `None` if inference fails.
pub fn infer_container_from_instruction(
    instruction: &str,
    function_name: &str,
) -> Option<ContainerType> {
    // First try function name inference
    if let Some(container) = infer_container_type(function_name) {
        return Some(container);
    }

    // Extract function name from instruction if it's a call
    if instruction.contains("call") {
        // Try to extract the called function name
        if let Some(called_func) = extract_called_function(instruction) {
            if let Some(container) = infer_container_type(called_func) {
                return Some(container);
            }
        }

        // Look for allocation calls
        if instruction.contains("malloc") || instruction.contains("calloc") {
            return Some(ContainerType::RawPtr);
        }

        if instruction.contains("__rust_alloc") {
            return Some(ContainerType::RawPtr);
        }

        if instruction.contains("operator new") {
            return Some(ContainerType::UniquePtr);
        }
    }

    // Look for type information in the instruction
    if instruction.contains("std::shared_ptr") {
        return Some(ContainerType::SharedPtr);
    }

    if instruction.contains("std::unique_ptr") {
        return Some(ContainerType::UniquePtr);
    }

    None
}

/// Extracts the called function name from an IR instruction.
///
/// # Arguments
///
/// * `instruction` - The IR instruction to parse
///
/// # Returns
///
/// The called function name, or `None` if parsing fails.
fn extract_called_function(instruction: &str) -> Option<&str> {
    // Look for patterns like "call ... @function_name(..."
    if let Some(call_pos) = instruction.find("call") {
        let after_call = &instruction[call_pos..];
        if let Some(at_pos) = after_call.find('@') {
            let func_start = at_pos + 1;
            let func_end = after_call[func_start..]
                .find('(')
                .unwrap_or(after_call.len() - func_start);
            let func_name = &after_call[func_start..func_start + func_end];
            // Remove any leading/trailing whitespace
            let func_name = func_name.trim();
            if !func_name.is_empty() {
                return Some(func_name);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_box_inference() {
        // Test exact match for Box::new
        assert_eq!(
            infer_container_type("alloc::boxed::Box::new"),
            Some(ContainerType::Box),
            "Should infer Box from alloc::boxed::Box::new"
        );

        // Test substring match
        assert_eq!(
            infer_container_type("alloc::boxed::Box::new_uninit"),
            Some(ContainerType::Box),
            "Should infer Box from alloc::boxed::Box::new_uninit"
        );
    }

    #[test]
    fn test_rust_vec_inference() {
        // Test exact match for Vec::new
        assert_eq!(
            infer_container_type("alloc::vec::Vec::new"),
            Some(ContainerType::Vec),
            "Should infer Vec from alloc::vec::Vec::new"
        );

        // Test substring match
        assert_eq!(
            infer_container_type("alloc::vec::Vec::with_capacity"),
            Some(ContainerType::Vec),
            "Should infer Vec from alloc::vec::Vec::with_capacity"
        );
    }

    #[test]
    fn test_rust_string_inference() {
        // Test exact match for String::new
        assert_eq!(
            infer_container_type("alloc::string::String::new"),
            Some(ContainerType::String),
            "Should infer String from alloc::string::String::new"
        );

        // Test substring match
        assert_eq!(
            infer_container_type("alloc::string::String::from"),
            Some(ContainerType::String),
            "Should infer String from alloc::string::String::from"
        );
    }

    #[test]
    fn test_rust_rc_inference() {
        // Test exact match for Rc::new
        assert_eq!(
            infer_container_type("alloc::rc::Rc::new"),
            Some(ContainerType::Rc),
            "Should infer Rc from alloc::rc::Rc::new"
        );

        // Test substring match
        assert_eq!(
            infer_container_type("alloc::rc::Rc::new_uninit"),
            Some(ContainerType::Rc),
            "Should infer Rc from alloc::rc::Rc::new_uninit"
        );
    }

    #[test]
    fn test_rust_arc_inference() {
        // Test exact match for Arc::new
        assert_eq!(
            infer_container_type("alloc::sync::Arc::new"),
            Some(ContainerType::Arc),
            "Should infer Arc from alloc::sync::Arc::new"
        );

        // Test substring match
        assert_eq!(
            infer_container_type("alloc::sync::Arc::new_uninit"),
            Some(ContainerType::Arc),
            "Should infer Arc from alloc::sync::Arc::new_uninit"
        );
    }

    #[test]
    fn test_cpp_unique_ptr_inference() {
        // Test exact match for C++ new
        assert_eq!(
            infer_container_type("_Znwm"),
            Some(ContainerType::UniquePtr),
            "Should infer UniquePtr from _Znwm (operator new)"
        );

        assert_eq!(
            infer_container_type("operator new"),
            Some(ContainerType::UniquePtr),
            "Should infer UniquePtr from operator new"
        );

        assert_eq!(
            infer_container_type("std::unique_ptr"),
            Some(ContainerType::UniquePtr),
            "Should infer UniquePtr from std::unique_ptr"
        );
    }

    #[test]
    fn test_cpp_shared_ptr_inference() {
        // Test exact match for C++ shared_ptr
        assert_eq!(
            infer_container_type("_ZNSt12__shared_ptr"),
            Some(ContainerType::SharedPtr),
            "Should infer SharedPtr from _ZNSt12__shared_ptr"
        );

        assert_eq!(
            infer_container_type("std::shared_ptr"),
            Some(ContainerType::SharedPtr),
            "Should infer SharedPtr from std::shared_ptr"
        );
    }

    #[test]
    fn test_raw_ptr_inference() {
        // Test C allocators
        assert_eq!(
            infer_container_type("malloc"),
            Some(ContainerType::RawPtr),
            "Should infer RawPtr from malloc"
        );

        assert_eq!(
            infer_container_type("calloc"),
            Some(ContainerType::RawPtr),
            "Should infer RawPtr from calloc"
        );

        assert_eq!(
            infer_container_type("__rust_alloc"),
            Some(ContainerType::RawPtr),
            "Should infer RawPtr from __rust_alloc"
        );
    }

    #[test]
    fn test_unknown_function() {
        // Test unknown function
        assert_eq!(
            infer_container_type("unknown_function"),
            None,
            "Should return None for unknown function"
        );

        assert_eq!(
            infer_container_type(""),
            None,
            "Should return None for empty string"
        );
    }

    #[test]
    fn test_container_semantics() {
        // Test Box semantics
        let box_semantics = container_semantics(ContainerType::Box);
        assert!(box_semantics.owns_resource, "Box should own its resource");
        assert!(!box_semantics.copyable, "Box should not be copyable");
        assert!(box_semantics.movable, "Box should be movable");
        assert_eq!(box_semantics.language, LanguageHint::Rust);

        // Test Rc semantics
        let rc_semantics = container_semantics(ContainerType::Rc);
        assert!(rc_semantics.owns_resource, "Rc should own its resource");
        assert!(rc_semantics.copyable, "Rc should be copyable");
        assert!(rc_semantics.movable, "Rc should be movable");
        assert_eq!(rc_semantics.language, LanguageHint::Rust);

        // Test RawPtr semantics
        let raw_ptr_semantics = container_semantics(ContainerType::RawPtr);
        assert!(
            !raw_ptr_semantics.owns_resource,
            "RawPtr should not own its resource"
        );
        assert!(raw_ptr_semantics.copyable, "RawPtr should be copyable");
        assert!(raw_ptr_semantics.movable, "RawPtr should be movable");
    }

    #[test]
    fn test_release_pairings() {
        let pairings = release_pairings();
        assert!(!pairings.is_empty(), "Should have release pairings");

        // Check that Vec pairing exists
        let vec_pairing = pairings.iter().find(|p| p.container == ContainerType::Vec);
        assert!(vec_pairing.is_some(), "Should have Vec pairing");
        let vec_pairing = vec_pairing.unwrap();
        assert_eq!(vec_pairing.allocate, "alloc::vec::Vec::new");
        assert_eq!(vec_pairing.release, "drop_in_place");
    }

    #[test]
    fn test_infer_container_from_instruction() {
        // Test instruction with malloc
        let instruction = "call i8* @malloc(i64 100)";
        assert_eq!(
            infer_container_from_instruction(instruction, "test_func"),
            Some(ContainerType::RawPtr),
            "Should infer RawPtr from malloc instruction"
        );

        // Test instruction with __rust_alloc
        let instruction = "call i8* @__rust_alloc(i64 100, i64 8)";
        assert_eq!(
            infer_container_from_instruction(instruction, "test_func"),
            Some(ContainerType::RawPtr),
            "Should infer RawPtr from __rust_alloc instruction"
        );

        // Test instruction with function name inference
        let instruction = "call void @alloc::boxed::Box::new(...)";
        assert_eq!(
            infer_container_from_instruction(instruction, "test_func"),
            Some(ContainerType::Box),
            "Should infer Box from instruction with Box::new"
        );
    }

    #[test]
    fn test_container_type_equality() {
        // Test that container types can be compared
        assert_eq!(ContainerType::Box, ContainerType::Box);
        assert_ne!(ContainerType::Box, ContainerType::Vec);
        assert_ne!(ContainerType::Rc, ContainerType::Arc);
    }

    #[test]
    fn test_container_type_debug() {
        // Test debug formatting
        let box_type = ContainerType::Box;
        let debug_str = format!("{:?}", box_type);
        assert_eq!(debug_str, "Box", "Debug format should be 'Box'");
    }

    #[test]
    fn test_infer_container_type_with_prefix() {
        // Test with various prefixes
        assert_eq!(
            infer_container_type("my_module::alloc::vec::Vec::new"),
            Some(ContainerType::Vec),
            "Should infer Vec with module prefix"
        );

        assert_eq!(
            infer_container_type("std::alloc::boxed::Box::new"),
            Some(ContainerType::Box),
            "Should infer Box with std prefix"
        );
    }

    #[test]
    fn test_infer_container_type_case_sensitivity() {
        // Test case sensitivity
        assert_eq!(
            infer_container_type("alloc::vec::vec::new"),
            None,
            "Should not infer Vec from lowercase vec"
        );

        assert_eq!(
            infer_container_type("ALLOC::VEC::VEC::NEW"),
            None,
            "Should not infer Vec from uppercase ALLOC::VEC"
        );
    }
}
