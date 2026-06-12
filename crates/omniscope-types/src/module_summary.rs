//! # ModuleSummary
//!
//! Summary of a single IR module's analysis results, enabling cross-module
//! reasoning without requiring all IR files to be merged.
//!
//! ## Key Concepts
//! - A ModuleSummary is the "public API" of a module's analysis
//! - It exports function-level resource contracts and boundary evidence
//! - It does NOT contain the full IR body — only metadata/summaries
//! - Multiple ModuleSummary instances can be merged into a ProjectIndex

use serde::{Deserialize, Serialize};

use crate::resource_family::FamilyId;

/// Confidence level for a module summary entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Confidence {
    /// High confidence: directly observed from IR patterns or verified
    /// by multiple independent sources.
    High,
    /// Medium confidence: inferred from a single source or heuristic.
    Medium,
    /// Low confidence: speculative inference or conflicting evidence.
    Low,
}

impl Confidence {
    /// Returns a numeric score for ranking (0.0 – 1.0).
    pub fn score(&self) -> f32 {
        match self {
            Self::High => 1.0,
            Self::Medium => 0.6,
            Self::Low => 0.3,
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

/// Summary of a single IR module's analysis.
///
/// # Fields
/// * `module_id` - Unique module identifier (filename or content hash).
/// * `input_path` - Path to the original input file.
/// * `target_triple` - Target triple from the IR module.
/// * `defined_functions` - Functions defined in this module.
/// * `declarations` - External function declarations.
/// * `exports` - Exported symbols (with linkage type).
/// * `imports` - Imported symbols.
/// * `call_edges` - Call edges: caller -> callee.
/// * `resource_summaries` - Per-function resource contracts.
/// * `boundary_evidence` - Boundary evidence (FFI cross-language calls).
/// * `semantic_facts` - Semantic facts harvested by language adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleSummary {
    /// Unique module identifier (filename or content hash).
    pub module_id: String,
    /// Path to the original input file.
    pub input_path: Option<String>,
    /// Target triple from the IR module.
    pub target_triple: Option<String>,
    /// Functions defined in this module.
    pub defined_functions: Vec<String>,
    /// External function declarations (not defined in this module).
    pub declarations: Vec<String>,
    /// Exported symbols (with linkage type).
    pub exports: Vec<ExportEntry>,
    /// Imported symbols.
    pub imports: Vec<ImportEntry>,
    /// Call edges: caller -> callee.
    pub call_edges: Vec<CallEdge>,
    /// Per-function resource contracts.
    pub resource_summaries: Vec<FunctionResourceSummary>,
    /// Boundary evidence (FFI cross-language calls).
    pub boundary_evidence: Vec<BoundaryEvidenceEntry>,
    /// Semantic facts harvested by language adapters.
    pub semantic_facts: Vec<SemanticFactEntry>,
}

impl ModuleSummary {
    /// Creates a new ModuleSummary with the given module identifier.
    ///
    /// # Arguments
    /// * `module_id` - Unique module identifier.
    ///
    /// # Returns
    /// A new ModuleSummary with default (empty) fields.
    pub fn new(module_id: impl Into<String>) -> Self {
        Self {
            module_id: module_id.into(),
            input_path: None,
            target_triple: None,
            defined_functions: Vec::new(),
            declarations: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
            call_edges: Vec::new(),
            resource_summaries: Vec::new(),
            boundary_evidence: Vec::new(),
            semantic_facts: Vec::new(),
        }
    }
}

/// A function-level resource contract extracted from analysis.
///
/// # Fields
/// * `function` - Function name (mangled).
/// * `acquires` - Resources this function acquires (allocates).
/// * `releases` - Resources this function releases (frees).
/// * `transfers_to_caller` - Whether resources are transferred to caller via return value.
/// * `borrows_returned` - Whether borrowed pointers are returned to the caller.
/// * `callbacks_registered` - Callback functions registered (increasing refcount).
/// * `confidence` - Confidence level of this summary.
/// * `language` - Language of the function (detected).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionResourceSummary {
    /// Function name (mangled).
    pub function: String,
    /// Resources this function acquires (allocates).
    pub acquires: Vec<ResourceAccess>,
    /// Resources this function releases (frees).
    pub releases: Vec<ResourceAccess>,
    /// Whether resources are transferred to the caller via return value.
    pub transfers_to_caller: bool,
    /// Whether borrowed pointers are returned to the caller.
    pub borrows_returned: bool,
    /// Whether callbacks are registered (increasing refcount).
    pub callbacks_registered: Vec<String>,
    /// Confidence level of this summary.
    pub confidence: Confidence,
    /// Language of the function (detected).
    pub language: Option<String>,
}

impl FunctionResourceSummary {
    /// Creates a new FunctionResourceSummary for the given function.
    ///
    /// # Arguments
    /// * `function` - Function name (mangled).
    ///
    /// # Returns
    /// A new FunctionResourceSummary with default (empty) fields and
    /// `Confidence::Medium`.
    pub fn new(function: impl Into<String>) -> Self {
        Self {
            function: function.into(),
            acquires: Vec::new(),
            releases: Vec::new(),
            transfers_to_caller: false,
            borrows_returned: false,
            callbacks_registered: Vec::new(),
            confidence: Confidence::Medium,
            language: None,
        }
    }

    /// Returns true if this summary indicates the function acquires any resources.
    pub fn has_acquires(&self) -> bool {
        !self.acquires.is_empty()
    }

    /// Returns true if this summary indicates the function releases any resources.
    pub fn has_releases(&self) -> bool {
        !self.releases.is_empty()
    }
}

/// A resource access (acquire or release) at a specific point.
///
/// # Fields
/// * `family` - Resource family involved.
/// * `kind` - How the resource is accessed.
/// * `function` - Function name where access occurs.
/// * `location` - Instruction index or location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAccess {
    /// Resource family involved.
    pub family: FamilyId,
    /// How the resource is accessed.
    pub kind: ResourceAccessKind,
    /// Function name where access occurs.
    pub function: String,
    /// Instruction index or location.
    pub location: usize,
}

/// How a resource is accessed.
///
/// # Variants
/// * `ReturnValue` - Return value (caller receives ownership).
/// * `OutParam` - Out parameter (pointer-to-pointer).
/// * `Global` - Global/static variable.
/// * `Parameter` - Parameter (caller passes ownership to callee).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResourceAccessKind {
    /// Return value (caller receives ownership).
    ReturnValue,
    /// Out parameter (pointer-to-pointer).
    OutParam,
    /// Global/static variable.
    Global,
    /// Parameter (caller passes ownership to callee).
    Parameter,
}

/// Call edge between functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    /// Caller function name.
    pub caller: String,
    /// Callee function name.
    pub callee: String,
    /// Optional call site instruction index.
    pub call_site: Option<usize>,
}

impl CallEdge {
    /// Creates a new CallEdge.
    pub fn new(caller: impl Into<String>, callee: impl Into<String>) -> Self {
        Self {
            caller: caller.into(),
            callee: callee.into(),
            call_site: None,
        }
    }
}

/// An exported symbol entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    /// Symbol name.
    pub symbol: String,
    /// Linkage type (e.g., "external", "internal", "weak").
    pub linkage: String,
}

/// An imported symbol entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    /// Symbol name.
    pub symbol: String,
    /// Optional source module name.
    pub module: Option<String>,
}

/// Boundary evidence entry for FFI cross-language calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryEvidenceEntry {
    /// Function where the boundary is crossed.
    pub function: String,
    /// Source language.
    pub language_a: String,
    /// Target language.
    pub language_b: String,
    /// Kind of evidence (e.g., "cross_language_call", "foreign_extern").
    pub evidence_kind: String,
}

/// A semantic fact entry harvested by language adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticFactEntry {
    /// Function name.
    pub function: String,
    /// Kind of semantic fact.
    pub kind: String,
    /// Confidence level as a string ("high", "medium", "low").
    pub confidence: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify that ModuleSummary can be created and all fields
    /// are initialised to their default (empty) values.
    ///
    /// Invariants:
    /// - module_id must match the provided value.
    /// - All optional fields must be None.
    /// - All collection fields must be empty.
    ///
    /// Test Logic:
    /// 1. Create ModuleSummary with module_id "test_module"
    /// 2. Verify each field individually
    #[test]
    fn test_module_summary_creation() {
        let summary = ModuleSummary::new("test_module");

        assert_eq!(
            summary.module_id, "test_module",
            "module_id must match the constructor argument"
        );
        assert!(
            summary.input_path.is_none(),
            "input_path must be None by default"
        );
        assert!(
            summary.target_triple.is_none(),
            "target_triple must be None by default"
        );
        assert!(
            summary.defined_functions.is_empty(),
            "defined_functions must be empty by default"
        );
        assert!(
            summary.declarations.is_empty(),
            "declarations must be empty by default"
        );
        assert!(
            summary.exports.is_empty(),
            "exports must be empty by default"
        );
        assert!(
            summary.imports.is_empty(),
            "imports must be empty by default"
        );
        assert!(
            summary.call_edges.is_empty(),
            "call_edges must be empty by default"
        );
        assert!(
            summary.resource_summaries.is_empty(),
            "resource_summaries must be empty by default"
        );
        assert!(
            summary.boundary_evidence.is_empty(),
            "boundary_evidence must be empty by default"
        );
        assert!(
            summary.semantic_facts.is_empty(),
            "semantic_facts must be empty by default"
        );
    }

    /// Objective: Verify that FunctionResourceSummary correctly tracks
    /// transfers_to_caller for a factory function pattern.
    ///
    /// Invariants:
    /// - acquires must contain the allocated resource.
    /// - transfers_to_caller must be true.
    /// - has_acquires() must return true.
    /// - confidence must be Medium (default).
    ///
    /// Test Logic:
    /// 1. Create a FunctionResourceSummary for a factory function
    /// 2. Add a ResourceAccess for the acquired resource
    /// 3. Set transfers_to_caller = true
    /// 4. Verify all fields
    #[test]
    fn test_resource_summary_transfers_to_caller() {
        let mut summary = FunctionResourceSummary::new("make_token");

        summary.acquires.push(ResourceAccess {
            family: FamilyId::C_HEAP,
            kind: ResourceAccessKind::ReturnValue,
            function: "make_token".to_string(),
            location: 0,
        });
        summary.transfers_to_caller = true;

        assert!(
            summary.has_acquires(),
            "Factory function must have acquires"
        );
        assert_eq!(
            summary.acquires.len(),
            1,
            "Factory function must have exactly 1 acquire"
        );
        assert_eq!(
            summary.acquires[0].family,
            FamilyId::C_HEAP,
            "Acquired resource must be C_HEAP family"
        );
        assert_eq!(
            summary.acquires[0].kind,
            ResourceAccessKind::ReturnValue,
            "Acquired resource must be returned as ReturnValue"
        );
        assert!(
            summary.transfers_to_caller,
            "Factory function must transfer_to_caller"
        );
        assert!(
            !summary.has_releases(),
            "Factory function must not have releases"
        );
        assert!(
            !summary.borrows_returned,
            "Factory function must not have borrows_returned"
        );
        assert_eq!(
            summary.confidence,
            Confidence::Medium,
            "Default confidence must be Medium"
        );
    }

    /// Objective: Verify FunctionResourceSummary field defaults and
    /// complete field coverage.
    ///
    /// Invariants:
    /// - accepts must have releases.
    /// - borrows_returned must be true.
    /// - callbacks_registered must contain the registered callback.
    /// - language must be set.
    ///
    /// Test Logic:
    /// 1. Create a FunctionResourceSummary for a release + borrow function
    /// 2. Populate all fields
    /// 3. Verify each field
    #[test]
    fn test_function_resource_summary_fields() {
        let mut summary = FunctionResourceSummary::new("release_and_borrow");

        summary.acquires.push(ResourceAccess {
            family: FamilyId::C_HEAP,
            kind: ResourceAccessKind::ReturnValue,
            function: "release_and_borrow".to_string(),
            location: 1,
        });
        summary.releases.push(ResourceAccess {
            family: FamilyId::C_HEAP,
            kind: ResourceAccessKind::Parameter,
            function: "release_and_borrow".to_string(),
            location: 2,
        });
        summary.transfers_to_caller = true;
        summary.borrows_returned = true;
        summary.callbacks_registered = vec!["on_event".to_string()];
        summary.confidence = Confidence::High;
        summary.language = Some("C".to_string());

        assert!(
            summary.has_acquires(),
            "Must have acquires when acquires is non-empty"
        );
        assert!(
            summary.has_releases(),
            "Must have releases when releases is non-empty"
        );
        assert_eq!(
            summary.releases.len(),
            1,
            "Must have exactly 1 release entry"
        );
        assert_eq!(
            summary.releases[0].kind,
            ResourceAccessKind::Parameter,
            "Release must be through Parameter kind"
        );
        assert_eq!(
            summary.callbacks_registered,
            vec!["on_event"],
            "Must contain registered callback"
        );
        assert_eq!(
            summary.confidence,
            Confidence::High,
            "Confidence must be High"
        );
        assert_eq!(
            summary.language,
            Some("C".to_string()),
            "Language must be C"
        );
    }

    /// Objective: Verify that ResourceAccess tuples are correctly serialisable
    /// and the four ResourceAccessKind variants are distinguishable.
    ///
    /// Invariants:
    /// - All four ResourceAccessKind variants must be constructable.
    /// - PartialEq must distinguish between different variants.
    ///
    /// Test Logic:
    /// 1. Create ResourceAccess entries for each kind
    /// 2. Verify PartialEq distinguishes them
    #[test]
    fn test_resource_access_kind_variants() {
        let return_val = ResourceAccessKind::ReturnValue;
        let out_param = ResourceAccessKind::OutParam;
        let global = ResourceAccessKind::Global;
        let param = ResourceAccessKind::Parameter;

        assert_eq!(return_val, return_val, "Same variant must be equal");
        assert_ne!(
            return_val, out_param,
            "Different variants must not be equal"
        );
        assert_ne!(out_param, global, "Different variants must not be equal");
        assert_ne!(global, param, "Different variants must not be equal");
        assert_ne!(param, return_val, "Different variants must not be equal");
    }

    /// Objective: Verify that CallEdge is constructable with and without
    /// a call site index.
    ///
    /// Invariants:
    /// - CallEdge::new creates an edge without a call_site.
    /// - A manually constructed CallEdge with call_site retains the value.
    ///
    /// Test Logic:
    /// 1. Create CallEdge with new()
    /// 2. Verify call_site is None
    /// 3. Create CallEdge with call_site = Some(3)
    /// 4. Verify call_site is Some(3)
    #[test]
    fn test_call_edge_creation() {
        let edge = CallEdge::new("caller_func", "callee_func");

        assert_eq!(edge.caller, "caller_func", "Caller must match");
        assert_eq!(edge.callee, "callee_func", "Callee must match");
        assert!(
            edge.call_site.is_none(),
            "call_site must be None when using new()"
        );

        let edge_with_site = CallEdge {
            caller: "a".to_string(),
            callee: "b".to_string(),
            call_site: Some(3),
        };
        assert_eq!(
            edge_with_site.call_site,
            Some(3),
            "call_site must be Some(3)"
        );
    }

    /// Objective: Verify Confidence enum ordering and display.
    ///
    /// Invariants:
    /// - score() must return strictly decreasing values: High > Medium > Low.
    /// - Display must produce lowercase strings.
    ///
    /// Test Logic:
    /// 1. Verify score ordering
    /// 2. Verify Display output
    #[test]
    fn test_confidence_ordering() {
        assert!(
            Confidence::High.score() > Confidence::Medium.score(),
            "High confidence score must exceed Medium"
        );
        assert!(
            Confidence::Medium.score() > Confidence::Low.score(),
            "Medium confidence score must exceed Low"
        );
        assert_eq!(
            Confidence::High.to_string(),
            "high",
            "Display for High must be 'high'"
        );
        assert_eq!(
            Confidence::Medium.to_string(),
            "medium",
            "Display for Medium must be 'medium'"
        );
        assert_eq!(
            Confidence::Low.to_string(),
            "low",
            "Display for Low must be 'low'"
        );
    }

    /// Objective: Verify that ExportEntry and ImportEntry are constructable
    /// and their fields are accessible.
    ///
    /// Invariants:
    /// - ExportEntry must store symbol and linkage.
    /// - ImportEntry must store symbol and optional module.
    #[test]
    fn test_export_import_entries() {
        let export = ExportEntry {
            symbol: "my_function".to_string(),
            linkage: "external".to_string(),
        };
        assert_eq!(export.symbol, "my_function", "Export symbol must match");
        assert_eq!(export.linkage, "external", "Export linkage must match");

        let import = ImportEntry {
            symbol: "external_func".to_string(),
            module: Some("libc.so.6".to_string()),
        };
        assert_eq!(import.symbol, "external_func", "Import symbol must match");
        assert_eq!(
            import.module,
            Some("libc.so.6".to_string()),
            "Import module must match"
        );

        let import_no_module = ImportEntry {
            symbol: "unknown_func".to_string(),
            module: None,
        };
        assert!(
            import_no_module.module.is_none(),
            "Import.module must be None when not specified"
        );
    }

    /// Objective: Verify that BoundaryEvidenceEntry and SemanticFactEntry
    /// are constructable and their fields are correctly set.
    ///
    /// Invariants:
    /// - All fields must match the constructor values.
    #[test]
    fn test_boundary_and_semantic_entries() {
        let boundary = BoundaryEvidenceEntry {
            function: "ffi_bridge".to_string(),
            language_a: "Rust".to_string(),
            language_b: "C".to_string(),
            evidence_kind: "cross_language_call".to_string(),
        };
        assert_eq!(boundary.function, "ffi_bridge", "Function must match");
        assert_eq!(boundary.language_a, "Rust", "Language A must match");
        assert_eq!(boundary.language_b, "C", "Language B must match");
        assert_eq!(
            boundary.evidence_kind, "cross_language_call",
            "Evidence kind must match"
        );

        let fact = SemanticFactEntry {
            function: "make_token".to_string(),
            kind: "returns_owned".to_string(),
            confidence: "high".to_string(),
        };
        assert_eq!(fact.function, "make_token", "Fact function must match");
        assert_eq!(fact.kind, "returns_owned", "Fact kind must match");
        assert_eq!(fact.confidence, "high", "Fact confidence must match");
    }
}
