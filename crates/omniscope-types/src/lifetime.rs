//! Cross-function lifetime analysis types.
//!
//! These types represent the results of cross-function lifetime analysis
//! and are stored in `PassContext` for downstream passes (e.g.,
//! `IssueCandidateBuilderPass`) to consume.
//!
//! # Architecture
//!
//! ```text
//! CrossFunctionLifetimePass
//!   └── AnalysisResult (from CrossFunctionTracker)
//!         ├── LifetimeViolation  →  LifetimeViolationEntry  →  Issue
//!         └── ResourceFate       →  ResourceFateEntry       →  context store
//! ```

use crate::FamilyId;
use serde::{Deserialize, Serialize};

/// Cross-function lifetime analysis result stored in `PassContext`.
///
/// This is the public output of the `CrossFunctionLifetimePass`, consumed
/// by downstream passes and reporters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossFunctionLifetimeData {
    /// Resource fate entries per resource ID.
    pub resource_fates: Vec<ResourceFateEntry>,
    /// Lifetime violations detected during analysis.
    pub violations: Vec<LifetimeViolationEntry>,
    /// Number of functions analyzed.
    pub functions_analyzed: usize,
    /// Number of resource flows tracked across functions.
    pub flows_count: usize,
}

/// A single resource fate entry describing what happened to a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceFateEntry {
    /// The resource identifier.
    pub resource_id: u64,
    /// The resource family this resource belongs to.
    pub family: FamilyId,
    /// The fate summary for this resource.
    pub fate: ResourceFateSummary,
}

/// Summary of a resource's disposal outcome after analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceFateSummary {
    /// Resource was properly released in the named function.
    Released {
        /// Function where the release occurred.
        in_function: String,
    },
    /// Resource lives for the entire program lifetime.
    ProgramLifetime,
    /// Resource is stored in a global variable.
    GlobalState {
        /// Function where the global store occurred.
        stored_in: String,
    },
    /// Resource escaped to a number of other functions.
    Escaped {
        /// Number of distinct functions the resource escaped to.
        function_count: usize,
    },
    /// Resource fate could not be determined.
    Unknown,
}

/// A lifetime violation entry ready for conversion into an `Issue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifetimeViolationEntry {
    /// The resource identifier involved.
    pub resource_id: u64,
    /// The kind of violation.
    pub violation_type: ViolationKind,
    /// The function name where the violation occurs.
    pub location: String,
    /// Human-readable description of the violation.
    pub description: String,
}

/// Kinds of lifetime violations detected by cross-function analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationKind {
    /// Resource used after it was released (use-after-free).
    UseAfterFree,
    /// Resource was never released (leak).
    ResourceLeak,
    /// Resource was released twice (double-free).
    DoubleFree,
    /// Invalid ownership transfer across functions.
    InvalidOwnershipTransfer,
    /// Borrowed resource escaped the function scope.
    BorrowEscape,
}

impl CrossFunctionLifetimeData {
    /// Creates a new empty lifetime analysis result.
    pub fn new() -> Self {
        Self {
            resource_fates: Vec::new(),
            violations: Vec::new(),
            functions_analyzed: 0,
            flows_count: 0,
        }
    }

    /// Returns `true` when no violations were detected.
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }

    /// Returns the number of violations detected.
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }
}

impl Default for CrossFunctionLifetimeData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Objective: Verify that a new `CrossFunctionLifetimeData` is clean
    /// and contains default zero counts.
    /// Invariants: A freshly created instance has no violations, no fates,
    /// and zero for all numeric fields.
    #[test]
    fn test_empty_lifetime_data() {
        let data = CrossFunctionLifetimeData::new();
        assert!(data.is_clean(), "New lifetime data must be clean");
        assert_eq!(
            data.violation_count(),
            0,
            "New lifetime data must have zero violations"
        );
        assert!(
            data.resource_fates.is_empty(),
            "New lifetime data must have empty resource_fates"
        );
        assert_eq!(
            data.functions_analyzed, 0,
            "New lifetime data must have functions_analyzed == 0"
        );
        assert_eq!(
            data.flows_count, 0,
            "New lifetime data must have flows_count == 0"
        );
    }

    /// Objective: Verify that `ResourceFateEntry` and `LifetimeViolationEntry`
    /// can be constructed and stored in a `CrossFunctionLifetimeData`.
    /// Invariants: After adding entries, the counts reflect the additions.
    #[test]
    fn test_populated_lifetime_data() {
        let mut data = CrossFunctionLifetimeData::new();

        data.resource_fates.push(ResourceFateEntry {
            resource_id: 1,
            family: FamilyId::C_HEAP,
            fate: ResourceFateSummary::Released {
                in_function: "free_it".to_string(),
            },
        });

        data.violations.push(LifetimeViolationEntry {
            resource_id: 2,
            violation_type: ViolationKind::ResourceLeak,
            location: "leaky_func".to_string(),
            description: "Resource 2 created in leaky_func but never released".to_string(),
        });

        data.functions_analyzed = 5;
        data.flows_count = 12;

        assert!(!data.is_clean(), "Populated data must NOT be clean");
        assert_eq!(
            data.violation_count(),
            1,
            "Populated data must have 1 violation"
        );
        assert_eq!(
            data.resource_fates.len(),
            1,
            "Populated data must have 1 resource fate"
        );
        assert_eq!(
            data.functions_analyzed, 5,
            "Populated data must have functions_analyzed == 5"
        );
        assert_eq!(
            data.flows_count, 12,
            "Populated data must have flows_count == 12"
        );
    }

    /// Objective: Verify all `ViolationKind` variants are constructible.
    /// Invariants: Each variant carries its expected name.
    #[test]
    fn test_violation_kind_variants() {
        let uaf = ViolationKind::UseAfterFree;
        let leak = ViolationKind::ResourceLeak;
        let double_free = ViolationKind::DoubleFree;
        let invalid = ViolationKind::InvalidOwnershipTransfer;
        let escape = ViolationKind::BorrowEscape;

        // Verify they are distinct
        assert_ne!(uaf, leak, "UseAfterFree must differ from ResourceLeak");
        assert_ne!(
            double_free, invalid,
            "DoubleFree must differ from InvalidOwnershipTransfer"
        );
        assert_ne!(escape, uaf, "BorrowEscape must differ from UseAfterFree");
    }

    /// Objective: Verify all `ResourceFateSummary` variants are constructible.
    /// Invariants: Each variant carries its expected data.
    #[test]
    fn test_resource_fate_summary_variants() {
        let released = ResourceFateSummary::Released {
            in_function: "free".to_string(),
        };
        let program = ResourceFateSummary::ProgramLifetime;
        let global = ResourceFateSummary::GlobalState {
            stored_in: "store".to_string(),
        };
        let escaped = ResourceFateSummary::Escaped { function_count: 3 };
        let unknown = ResourceFateSummary::Unknown;

        // Match to verify data
        match released {
            ResourceFateSummary::Released { in_function } => {
                assert_eq!(
                    in_function, "free",
                    "Released fate must carry correct function name"
                );
            }
            _ => panic!("Expected Released variant"),
        }

        match escaped {
            ResourceFateSummary::Escaped { function_count } => {
                assert_eq!(
                    function_count, 3,
                    "Escaped fate must carry correct function count"
                );
            }
            _ => panic!("Expected Escaped variant"),
        }

        match global {
            ResourceFateSummary::GlobalState { stored_in } => {
                assert_eq!(
                    stored_in, "store",
                    "GlobalState fate must carry correct store function"
                );
            }
            _ => panic!("Expected GlobalState variant"),
        }

        assert_eq!(
            format!("{:?}", program),
            "ProgramLifetime",
            "ProgramLifetime debug format"
        );
        assert_eq!(format!("{:?}", unknown), "Unknown", "Unknown debug format");
    }
}
