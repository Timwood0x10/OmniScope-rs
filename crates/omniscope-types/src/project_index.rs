//! # ProjectIndex
//!
//! Merged view of multiple ModuleSummary instances, enabling cross-module
//! symbol resolution and ownership propagation.
//!
//! ## Key Concepts
//! - Aggregates per-module analysis into a project-wide view
//! - Resolves symbols across modules (definition lookup)
//! - Detects ambiguous definitions (same symbol defined in multiple modules)
//! - Tracks cross-module call edges for ownership propagation

use std::collections::HashMap;

use crate::module_summary::{FunctionResourceSummary, ModuleSummary};

/// Aggregated view of multiple modules analysis results.
///
/// # Fields
/// * `modules` - All module summaries.
/// * `defs_by_symbol` - Symbol -> module indices where the symbol is defined.
/// * `decls_by_symbol` - Symbol -> module indices where the symbol is declared.
/// * `callers_by_symbol` - Symbol -> list of callers.
/// * `summaries_by_function` - Function -> resource summary (from merge).
/// * `boundary_edges` - (module_a, module_b) pairs for cross-module boundaries.
/// * `ambiguous_definitions` - Symbols defined in multiple modules.
#[derive(Debug, Clone)]
pub struct ProjectIndex {
    /// All module summaries.
    pub modules: Vec<ModuleSummary>,
    /// Symbol -> module indices where the symbol is defined.
    pub defs_by_symbol: HashMap<String, Vec<usize>>,
    /// Symbol -> module indices where the symbol is declared.
    pub decls_by_symbol: HashMap<String, Vec<usize>>,
    /// Symbol -> list of callers (function names).
    pub callers_by_symbol: HashMap<String, Vec<String>>,
    /// Function -> resource summary.
    pub summaries_by_function: HashMap<String, FunctionResourceSummary>,
    /// (module_a, module_b) pairs for cross-module boundaries.
    pub boundary_edges: Vec<(String, String)>,
    /// Symbols defined in multiple modules (cannot be reliably resolved).
    pub ambiguous_definitions: Vec<AmbiguousDefinition>,
}

/// Two modules define the same symbol — cannot be reliably resolved.
///
/// # Fields
/// * `symbol` - The ambiguous symbol name.
/// * `module_ids` - Module identifiers that all define this symbol.
/// * `languages` - Detected languages of the conflicting definitions.
#[derive(Debug, Clone)]
pub struct AmbiguousDefinition {
    /// The ambiguous symbol name.
    pub symbol: String,
    /// Module identifiers that all define this symbol.
    pub module_ids: Vec<String>,
    /// Detected languages of the conflicting definitions.
    pub languages: Vec<String>,
}

impl ProjectIndex {
    /// Creates a new, empty ProjectIndex.
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            defs_by_symbol: HashMap::new(),
            decls_by_symbol: HashMap::new(),
            callers_by_symbol: HashMap::new(),
            summaries_by_function: HashMap::new(),
            boundary_edges: Vec::new(),
            ambiguous_definitions: Vec::new(),
        }
    }

    /// Adds a module summary to the project index.
    ///
    /// This updates all indexing structures:
    /// - `defs_by_symbol` for each defined function
    /// - `decls_by_symbol` for each declaration
    /// - `callers_by_symbol` for each call edge
    /// - `summaries_by_function` for each function resource summary
    /// - Detects ambiguous definitions (same symbol in multiple modules)
    ///
    /// # Arguments
    /// * `summary` - The module summary to add.
    pub fn add_module(&mut self, summary: ModuleSummary) {
        let module_idx = self.modules.len();

        // Index defined functions
        for func_name in &summary.defined_functions {
            self.defs_by_symbol
                .entry(func_name.clone())
                .or_default()
                .push(module_idx);

            // Check for ambiguity: if this symbol was already defined
            // in a previously added module, record it as ambiguous.
            if self.defs_by_symbol[func_name].len() > 1 {
                self.promote_to_ambiguous(func_name);
            }
        }

        // Index declarations
        for decl in &summary.declarations {
            self.decls_by_symbol
                .entry(decl.clone())
                .or_default()
                .push(module_idx);
        }

        // Index call edges
        for edge in &summary.call_edges {
            self.callers_by_symbol
                .entry(edge.callee.clone())
                .or_default()
                .push(edge.caller.clone());
        }

        // Index function resource summaries
        for res_summary in &summary.resource_summaries {
            self.summaries_by_function
                .insert(res_summary.function.clone(), res_summary.clone());
        }

        // Collect boundary edges (module-level cross-language evidence)
        for evidence in &summary.boundary_evidence {
            let pair = (evidence.language_a.clone(), evidence.language_b.clone());
            if !self.boundary_edges.contains(&pair) {
                self.boundary_edges.push(pair);
            }
        }

        self.modules.push(summary);
    }

    /// Resolves the resource summary for a given function name.
    ///
    /// Returns `None` if the function is not in any module's resource
    /// summaries or if it has an ambiguous definition.
    ///
    /// # Arguments
    /// * `name` - The function name to resolve.
    ///
    /// # Returns
    /// The function's resource summary, if uniquely resolvable.
    pub fn resolve_function(&self, name: &str) -> Option<&FunctionResourceSummary> {
        if self.is_ambiguous(name) {
            return None;
        }
        self.summaries_by_function.get(name)
    }

    /// Returns true if the given symbol is defined in multiple modules
    /// (making it ambiguous for resolution).
    ///
    /// # Arguments
    /// * `name` - The symbol name to check.
    ///
    /// # Returns
    /// `true` if the symbol has an ambiguous definition.
    pub fn is_ambiguous(&self, name: &str) -> bool {
        self.ambiguous_definitions
            .iter()
            .any(|ad| ad.symbol == name)
    }

    /// Merges two project indices into a new one.
    ///
    /// Both indices' modules are concatenated and re-indexed.
    /// Ambiguities from both indices are preserved and new ones
    /// detected across the merged set.
    ///
    /// # Arguments
    /// * `other` - The other project index to merge with.
    ///
    /// # Returns
    /// A new ProjectIndex containing modules from both indices.
    pub fn merge(&self, other: &ProjectIndex) -> ProjectIndex {
        let mut merged = ProjectIndex::new();

        for module in &self.modules {
            merged.add_module(module.clone());
        }
        for module in &other.modules {
            merged.add_module(module.clone());
        }

        merged
    }

    /// Returns all function names across all modules.
    pub fn all_functions(&self) -> Vec<&str> {
        self.summaries_by_function
            .keys()
            .map(|s| s.as_str())
            .collect()
    }

    /// Returns all callers of a given callee function.
    ///
    /// # Arguments
    /// * `callee` - The callee function name.
    ///
    /// # Returns
    /// A vector of caller function names (deduplicated).
    pub fn callers_of(&self, callee: &str) -> Vec<&str> {
        self.callers_by_symbol
            .get(callee)
            .map(|callers| {
                let mut deduped: Vec<&str> = callers.iter().map(|s| s.as_str()).collect();
                deduped.sort();
                deduped.dedup();
                deduped
            })
            .unwrap_or_default()
    }

    /// Promotes a symbol to the ambiguous definitions list.
    ///
    /// Called internally when a previously-unique symbol is defined
    /// in a second (or later) module.
    fn promote_to_ambiguous(&mut self, symbol: &str) {
        // Collect module IDs for all modules that define this symbol.
        // Only consider modules that have already been added to self.modules
        // (the current module being added has not been pushed yet).
        let module_ids: Vec<String> = self
            .defs_by_symbol
            .get(symbol)
            .map(|indices| {
                indices
                    .iter()
                    .filter(|&&idx| idx < self.modules.len())
                    .map(|&idx| self.modules[idx].module_id.clone())
                    .collect()
            })
            .unwrap_or_default();

        // Include the current module being added (not yet in self.modules).
        let current_module_id = self.defs_by_symbol.get(symbol).and_then(|indices| {
            indices
                .iter()
                .find(|&&idx| idx >= self.modules.len())
                .map(|_| format!("module_{}", self.modules.len()))
        });

        // Collect languages from the resource summaries in those modules.
        let languages: Vec<String> = self
            .modules
            .iter()
            .filter(|m| m.defined_functions.contains(&symbol.to_string()))
            .flat_map(|m| {
                m.resource_summaries
                    .iter()
                    .filter(|rs| rs.function == symbol)
                    .flat_map(|rs| rs.language.clone())
            })
            .collect();

        // Check if already recorded.
        if !self
            .ambiguous_definitions
            .iter()
            .any(|ad| ad.symbol == symbol)
        {
            let mut all_module_ids = module_ids;
            if let Some(current_id) = current_module_id {
                all_module_ids.push(current_id);
            }

            self.ambiguous_definitions.push(AmbiguousDefinition {
                symbol: symbol.to_string(),
                module_ids: all_module_ids,
                languages,
            });
        }
    }
}

impl Default for ProjectIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_summary::{
        CallEdge, FunctionResourceSummary, ModuleSummary, ResourceAccess, ResourceAccessKind,
    };
    use crate::resource_family::FamilyId;

    /// Helper: creates a simple module summary for testing.
    fn make_test_module(
        module_id: &str,
        functions: Vec<&str>,
        declarations: Vec<&str>,
    ) -> ModuleSummary {
        let mut summary = ModuleSummary::new(module_id);
        summary
            .defined_functions
            .extend(functions.iter().map(|s| s.to_string()));
        summary
            .declarations
            .extend(declarations.iter().map(|s| s.to_string()));
        summary
    }

    /// Helper: creates a function resource summary for testing.
    fn make_resource_summary(
        function: &str,
        acquires_family: Option<FamilyId>,
        language: Option<&str>,
    ) -> FunctionResourceSummary {
        let mut rs = FunctionResourceSummary::new(function);
        if let Some(family) = acquires_family {
            rs.acquires.push(ResourceAccess {
                family,
                kind: ResourceAccessKind::ReturnValue,
                function: function.to_string(),
                location: 0,
            });
            rs.transfers_to_caller = true;
        }
        rs.language = language.map(|s| s.to_string());
        rs
    }

    /// Objective: Verify that a module can be added to a ProjectIndex
    /// and its symbols are correctly indexed.
    ///
    /// Invariants:
    /// - modules.len() must increment after add_module.
    /// - defs_by_symbol must contain the defined function.
    /// - decls_by_symbol must contain the declaration.
    ///
    /// Test Logic:
    /// 1. Create a module summary with one function definition
    /// 2. Add it to a ProjectIndex
    /// 3. Verify indexing
    #[test]
    fn test_project_index_add_module() {
        let mut index = ProjectIndex::new();
        let summary = make_test_module("mod1", vec!["alloc_func"], vec!["malloc", "free"]);

        index.add_module(summary);

        assert_eq!(index.modules.len(), 1, "Must have exactly 1 module");
        assert!(
            index.defs_by_symbol.contains_key("alloc_func"),
            "defs_by_symbol must contain 'alloc_func'"
        );
        assert!(
            index.decls_by_symbol.contains_key("malloc"),
            "decls_by_symbol must contain 'malloc'"
        );
        assert!(
            index.decls_by_symbol.contains_key("free"),
            "decls_by_symbol must contain 'free'"
        );
    }

    /// Objective: Verify that cross-module symbol resolution works.
    ///
    /// Invariants:
    /// - resolve_function must return the summary from module B when
    ///   the function is defined in module B.
    /// - resolve_function must return None for undefined functions.
    ///
    /// Test Logic:
    /// 1. Create module A (declares make_token) and module B (defines make_token)
    /// 2. Add both modules to ProjectIndex
    /// 3. Verify resolve finds the definition
    #[test]
    fn test_project_index_resolve() {
        let mut index = ProjectIndex::new();

        // Module A: only declares make_token
        let mut mod_a = make_test_module("consumer", vec!["caller"], vec!["make_token"]);
        mod_a.resource_summaries.push(make_resource_summary(
            "caller",
            Some(FamilyId::C_HEAP),
            Some("C"),
        ));
        index.add_module(mod_a);

        // Module B: defines make_token with a resource summary
        let mut mod_b = make_test_module("producer", vec!["make_token"], vec![]);
        mod_b.resource_summaries.push(make_resource_summary(
            "make_token",
            Some(FamilyId::C_HEAP),
            Some("C"),
        ));
        index.add_module(mod_b);

        // Should resolve to module B's summary
        let resolved = index.resolve_function("make_token");
        assert!(
            resolved.is_some(),
            "make_token must be resolvable from the project index"
        );
        assert!(
            resolved.unwrap().transfers_to_caller,
            "make_token must transfer ownership to caller"
        );

        // Non-existent function should return None
        assert!(
            index.resolve_function("nonexistent").is_none(),
            "Non-existent function must return None"
        );
    }

    /// Objective: Verify that ambiguous definitions are detected and
    /// marked so they don't produce high-confidence resolutions.
    ///
    /// Invariants:
    /// - is_ambiguous must return true when the same symbol is defined
    ///   in multiple modules.
    /// - resolve_function must return None for ambiguous symbols.
    ///
    /// Test Logic:
    /// 1. Create two modules, both defining the same symbol
    /// 2. Add both modules to ProjectIndex
    /// 3. Verify ambiguous detection
    #[test]
    fn test_project_index_ambiguous() {
        let mut index = ProjectIndex::new();

        // Module A defines make_token
        let mut mod_a = make_test_module("mod_a", vec!["make_token"], vec![]);
        mod_a.resource_summaries.push(make_resource_summary(
            "make_token",
            Some(FamilyId::C_HEAP),
            Some("C"),
        ));
        index.add_module(mod_a);

        // Module B also defines make_token (conflict!)
        let mut mod_b = make_test_module("mod_b", vec!["make_token"], vec![]);
        mod_b.resource_summaries.push(make_resource_summary(
            "make_token",
            Some(FamilyId::CPP_NEW_SCALAR),
            Some("C++"),
        ));
        index.add_module(mod_b);

        assert!(
            index.is_ambiguous("make_token"),
            "make_token must be ambiguous when defined in two modules"
        );
        assert!(
            index.resolve_function("make_token").is_none(),
            "resolve_function must return None for ambiguous symbols"
        );

        // Verify the ambiguous definition record
        assert_eq!(
            index.ambiguous_definitions.len(),
            1,
            "Must have exactly 1 ambiguous definition"
        );
        assert_eq!(
            index.ambiguous_definitions[0].symbol, "make_token",
            "Ambiguous symbol must be 'make_token'"
        );
        assert_eq!(
            index.ambiguous_definitions[0].module_ids.len(),
            2,
            "Must have 2 conflicting module IDs"
        );
    }

    /// Objective: Verify that callers_of returns deduplicated caller
    /// names for a given callee.
    ///
    /// Invariants:
    /// - Callers must be deduplicated.
    /// - Non-existent callee returns empty vec.
    ///
    /// Test Logic:
    /// 1. Create two modules with call edges to the same callee
    /// 2. Verify callers_of returns the correct list
    #[test]
    fn test_project_index_callers_of() {
        let mut index = ProjectIndex::new();

        let mut mod_a = make_test_module("mod_a", vec!["caller_a"], vec!["helper"]);
        mod_a.call_edges.push(CallEdge::new("caller_a", "helper"));
        index.add_module(mod_a);

        let mut mod_b = make_test_module("mod_b", vec!["caller_b"], vec!["helper"]);
        mod_b.call_edges.push(CallEdge::new("caller_b", "helper"));
        // Duplicate caller edge to test dedup
        mod_b.call_edges.push(CallEdge::new("caller_b", "helper"));
        index.add_module(mod_b);

        let callers = index.callers_of("helper");
        assert_eq!(
            callers.len(),
            2,
            "Must have exactly 2 unique callers of 'helper'"
        );
        assert!(
            callers.contains(&"caller_a"),
            "callers_of('helper') must include 'caller_a'"
        );
        assert!(
            callers.contains(&"caller_b"),
            "callers_of('helper') must include 'caller_b'"
        );

        assert!(
            index.callers_of("nonexistent").is_empty(),
            "callers_of for non-existent callee must return empty vec"
        );
    }

    /// Objective: Verify that merge correctly combines two project indices.
    ///
    /// Invariants:
    /// - Merged index must contain all modules from both sources.
    /// - All symbol indices must be correctly rebuilt.
    /// - Ambiguities from both sources must be preserved.
    ///
    /// Test Logic:
    /// 1. Create two separate ProjectIndex instances
    /// 2. Merge them
    /// 3. Verify the merged result
    #[test]
    fn test_project_index_merge() {
        let mut index_a = ProjectIndex::new();
        index_a.add_module(make_test_module("mod_a", vec!["func_a"], vec![]));

        let mut index_b = ProjectIndex::new();
        index_b.add_module(make_test_module("mod_b", vec!["func_b"], vec![]));

        let merged = index_a.merge(&index_b);

        assert_eq!(
            merged.modules.len(),
            2,
            "Merged index must contain 2 modules"
        );
        assert!(
            merged.defs_by_symbol.contains_key("func_a"),
            "Merged index must contain 'func_a'"
        );
        assert!(
            merged.defs_by_symbol.contains_key("func_b"),
            "Merged index must contain 'func_b'"
        );
    }

    /// Objective: Verify that all_functions returns all function names
    /// from all modules' resource summaries.
    ///
    /// Invariants:
    /// - all_functions must include functions from all modules.
    /// - Empty index returns empty vec.
    ///
    /// Test Logic:
    /// 1. Create index with two modules having resource summaries
    /// 2. Verify all_functions returns all names
    #[test]
    fn test_project_index_all_functions() {
        let mut index = ProjectIndex::new();

        let mut mod_a = make_test_module("mod_a", vec!["func_a"], vec![]);
        mod_a
            .resource_summaries
            .push(make_resource_summary("func_a", None, None));
        index.add_module(mod_a);

        let mut mod_b = make_test_module("mod_b", vec!["func_b"], vec![]);
        mod_b
            .resource_summaries
            .push(make_resource_summary("func_b", None, None));
        index.add_module(mod_b);

        let all_funcs = index.all_functions();
        assert_eq!(
            all_funcs.len(),
            2,
            "Must have exactly 2 functions across all modules"
        );
        assert!(
            all_funcs.contains(&"func_a"),
            "all_functions must include 'func_a'"
        );
        assert!(
            all_funcs.contains(&"func_b"),
            "all_functions must include 'func_b'"
        );

        // Empty index
        let empty = ProjectIndex::new();
        assert!(
            empty.all_functions().is_empty(),
            "Empty index must return empty functions list"
        );
    }
}
