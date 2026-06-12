//! Path evidence types for resource lifecycle analysis.
//!
//! Path evidence captures the control-flow-aware lifecycle of a
//! resource within a function. It is produced by the path-sensitive
//! leak analysis and consumed by the issue verifier.

use serde::{Deserialize, Serialize};

/// Path evidence for a resource's lifecycle within a function.
///
/// Captures the result of path-sensitive analysis over a function's
/// control flow graph (CFG) or linear instruction sequence.  Used by
/// `IssueVerifier` to decide whether a candidate has sufficient path
/// evidence for confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathEvidence {
    /// True if all paths from alloc to exit include a release.
    pub all_paths_release: bool,
    /// True if only some paths release the resource.
    pub some_paths_release: bool,
    /// True if release happens before use on all paths.
    pub release_before_use_paths: bool,
    /// True if duplicate release exists on some path (potential double-free).
    pub duplicate_release_paths: bool,
    /// True if some release sites are unreachable.
    pub unreachable_release_sites: bool,
    /// True if path budget was exhausted during analysis.
    pub budget_exhausted: bool,
    /// Count of distinct release paths found.
    pub release_path_count: usize,
    /// Count of use-after-free paths found (if any).
    pub uaf_path_count: usize,
}

impl PathEvidence {
    /// Creates a new `PathEvidence` with all fields defaulting to `false` / `0`.
    pub fn new() -> Self {
        Self {
            all_paths_release: false,
            some_paths_release: false,
            release_before_use_paths: false,
            duplicate_release_paths: false,
            unreachable_release_sites: false,
            budget_exhausted: false,
            release_path_count: 0,
            uaf_path_count: 0,
        }
    }

    /// Returns `true` if the resource is safely released on all analyzed paths.
    pub fn is_safe(&self) -> bool {
        self.all_paths_release && !self.budget_exhausted
    }

    /// Returns `true` if a double-free pattern is present.
    pub fn has_double_free(&self) -> bool {
        self.duplicate_release_paths
    }

    /// Returns `true` if a use-after-free pattern is present.
    pub fn has_uaf(&self) -> bool {
        self.uaf_path_count > 0 && !self.release_before_use_paths
    }
}

impl Default for PathEvidence {
    fn default() -> Self {
        Self::new()
    }
}
