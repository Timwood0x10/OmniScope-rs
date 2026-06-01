//! Template instantiation pattern detection for C++.
//!
//! This module provides template-specific semantic analysis, including:
//! - Template instantiation detection
//! - STL container detection
//! - STL algorithm detection

use super::CppSemanticPattern;

/// Checks if a function name indicates a template instantiation.
///
/// # Objective
/// Detect template instantiation patterns in mangled C++ names. Templates
/// are identified by nested name indicators (I...E) in the Itanium ABI.
///
/// # Invariants
/// - Returns true for patterns containing I...E or IL.
/// - Returns false for non-template patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for template instantiation.
///
/// # Returns
/// `true` if the function is identified as a template instantiation, `false` otherwise.
pub fn is_template_instantiation(function_name: &str) -> bool {
    function_name.starts_with("_Z")
        && ((function_name.contains('I') && function_name.contains('E'))
            || function_name.contains("IL"))
}

/// Checks if a function name indicates an STL container operation.
///
/// # Objective
/// Detect STL container patterns in mangled C++ names. STL containers
/// include vector, deque, list, map, set, and their unordered variants.
///
/// # Invariants
/// - Returns true for vector, deque, list, map, set, unordered_map, unordered_set.
/// - Returns false for non-STL-container patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for STL container patterns.
///
/// # Returns
/// `true` if the function is identified as an STL container operation, `false` otherwise.
pub fn is_stl_container(function_name: &str) -> bool {
    function_name.starts_with("_Z")
        && (function_name.contains("6vector")
            || function_name.contains("5deque")
            || function_name.contains("4list")
            || function_name.contains("3map")
            || function_name.contains("3set")
            || function_name.contains("13unordered_map")
            || function_name.contains("13unordered_set"))
}

/// Checks if a function name indicates an STL algorithm operation.
///
/// # Objective
/// Detect STL algorithm patterns in mangled C++ names. STL algorithms
/// include sort, find, transform, and for_each.
///
/// # Invariants
/// - Returns true for sort, find, transform, for_each.
/// - Returns false for non-STL-algorithm patterns.
///
/// # Arguments
/// * `function_name` - The function name to check for STL algorithm patterns.
///
/// # Returns
/// `true` if the function is identified as an STL algorithm operation, `false` otherwise.
pub fn is_stl_algorithm(function_name: &str) -> bool {
    function_name.starts_with("_Z")
        && (function_name.contains("4sort")
            || function_name.contains("4find")
            || function_name.contains("9transform")
            || function_name.contains("6for_each"))
}

/// Detects template-related patterns from a function name.
///
/// # Objective
/// Collect all template-related semantic patterns from a function name.
/// This provides a convenient way to get all template patterns in one call.
///
/// # Arguments
/// * `function_name` - The function name to analyze for template patterns.
///
/// # Returns
/// A Vec of `CppSemanticPattern` containing detected template patterns.
pub fn detect_template_patterns(function_name: &str) -> Vec<CppSemanticPattern> {
    let mut patterns = Vec::new();

    if is_template_instantiation(function_name) {
        patterns.push(CppSemanticPattern::TemplateInstantiation);
    }
    if is_stl_container(function_name) {
        patterns.push(CppSemanticPattern::StlContainer);
    }
    if is_stl_algorithm(function_name) {
        patterns.push(CppSemanticPattern::StlAlgorithm);
    }

    patterns
}

/// Checks if a function uses templates.
///
/// # Objective
/// Determine whether a function uses any template patterns. This is
/// used for feature flag detection in function analysis.
///
/// # Arguments
/// * `function_name` - The function name to check for template usage.
///
/// # Returns
/// `true` if the function uses templates, `false` otherwise.
pub fn uses_templates(function_name: &str) -> bool {
    is_template_instantiation(function_name)
        || is_stl_container(function_name)
        || is_stl_algorithm(function_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_instantiation_detection() {
        // Template with I...E pattern
        assert!(
            is_template_instantiation("_ZNSt6vectorIiSaIiEE9push_backERKi"),
            "Template with I...E pattern must be detected"
        );
        // Template with IL pattern
        assert!(
            is_template_instantiation("_ZNSt6vectorILi1EE9push_backERKi"),
            "Template with IL pattern must be detected"
        );
        // Non-template
        assert!(
            !is_template_instantiation("_ZN5Class5methodEv"),
            "Non-template must not be detected"
        );
    }

    #[test]
    fn test_stl_container_detection() {
        // vector
        assert!(
            is_stl_container("_ZNSt6vectorIiSaIiEE9push_backERKi"),
            "vector must be detected as StlContainer"
        );
        // map
        assert!(
            is_stl_container("_ZNSt3mapIiiSt4lessIiESaISt4pairIKiiEEEixERS4_"),
            "map must be detected as StlContainer"
        );
        // unordered_map
        assert!(
            is_stl_container(
                "_ZNSt13unordered_mapIiiSt4hashIiESt8equal_toIiESaISt4pairIKiiEEEixERS6_"
            ),
            "unordered_map must be detected as StlContainer"
        );
        // set
        assert!(
            is_stl_container("_ZNSt3setIiSt4lessIiESaIiEE6insertERKi"),
            "set must be detected as StlContainer"
        );
        // Non-STL-container
        assert!(
            !is_stl_container("_ZN5Class5methodEv"),
            "Non-STL-container must not be detected"
        );
    }

    #[test]
    fn test_stl_algorithm_detection() {
        // sort
        assert!(
            is_stl_algorithm("_ZNSt4sortIPiEEvT_S1_"),
            "sort must be detected as StlAlgorithm"
        );
        // find
        assert!(
            is_stl_algorithm("_ZNSt4findIPiiEET_S1_S1_RKT0_"),
            "find must be detected as StlAlgorithm"
        );
        // transform
        assert!(
            is_stl_algorithm(
                "_ZNSt9transformIPiS0_N9__gnu_cxx5__ops15_Iter_less_iterEEET0_T_S4_S3_T1_"
            ),
            "transform must be detected as StlAlgorithm"
        );
        // for_each
        assert!(
            is_stl_algorithm("_ZNSt6for_eachIPiN9__gnu_cxx5__ops15_Iter_less_iterEEET0_T_S4_T1_"),
            "for_each must be detected as StlAlgorithm"
        );
        // Non-STL-algorithm
        assert!(
            !is_stl_algorithm("_ZN5Class5methodEv"),
            "Non-STL-algorithm must not be detected"
        );
    }

    #[test]
    fn test_detect_template_patterns() {
        // Template instantiation
        let patterns = detect_template_patterns("_ZNSt6vectorIiSaIiEE9push_backERKi");
        assert!(
            patterns.contains(&CppSemanticPattern::TemplateInstantiation),
            "TemplateInstantiation must be detected"
        );
        assert!(
            patterns.contains(&CppSemanticPattern::StlContainer),
            "StlContainer must be detected"
        );

        // STL algorithm
        let patterns = detect_template_patterns("_ZNSt4sortIPiEEvT_S1_");
        assert!(
            patterns.contains(&CppSemanticPattern::TemplateInstantiation),
            "TemplateInstantiation must be detected"
        );
        assert!(
            patterns.contains(&CppSemanticPattern::StlAlgorithm),
            "StlAlgorithm must be detected"
        );
    }

    #[test]
    fn test_uses_templates() {
        // vector
        assert!(
            uses_templates("_ZNSt6vectorIiSaIiEE9push_backERKi"),
            "vector must be detected as template"
        );
        // sort
        assert!(
            uses_templates("_ZNSt4sortIPiEEvT_S1_"),
            "sort must be detected as template"
        );
        // Non-template
        assert!(
            !uses_templates("_ZN5Class5methodEv"),
            "Non-template must not be detected"
        );
    }
}
