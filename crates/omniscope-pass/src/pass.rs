//! Pass trait definition and infrastructure
//!
//! This module defines the core pass infrastructure for OmniScope analysis.

use omniscope_core::{Diagnostic, Fact, Issue, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Pass trait for analysis passes
pub trait Pass: Send + Sync {
    /// Returns the pass name
    fn name(&self) -> &'static str;

    /// Returns the pass kind
    fn kind(&self) -> PassKind;

    /// Returns the dependencies of this pass
    fn dependencies(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Runs the pass
    fn run(&self, ctx: &mut PassContext) -> Result<PassResult>;
}

/// Pass kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PassKind {
    /// Foundation pass (CFG, DFG, etc.)
    Foundation,
    /// Analysis pass (memory safety, FFI, etc.)
    Analysis,
    /// Transformation pass
    Transformation,
}

/// Pass result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassResult {
    /// Pass name
    pub name: String,
    /// Number of issues found
    pub issues_found: usize,
    /// Number of nodes analyzed
    pub nodes_analyzed: usize,
    /// Execution time in milliseconds
    pub duration_ms: u64,
    /// Additional statistics
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub stats: HashMap<String, usize>,
    /// Concrete issues detected by this pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<Issue>,
}

impl PassResult {
    /// Creates a new pass result
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            issues_found: 0,
            nodes_analyzed: 0,
            duration_ms: 0,
            stats: HashMap::new(),
            issues: Vec::new(),
        }
    }

    /// Sets the number of issues found
    pub fn with_issues(mut self, count: usize) -> Self {
        self.issues_found = count;
        self
    }

    /// Adds a concrete issue to this result.
    pub fn add_issue(&mut self, issue: Issue) {
        self.issues.push(issue);
        self.issues_found = self.issues.len();
    }

    /// Returns the concrete issues collected by this pass.
    pub fn get_issues(&self) -> &[Issue] {
        &self.issues
    }

    /// Sets the number of nodes analyzed
    pub fn with_nodes(mut self, count: usize) -> Self {
        self.nodes_analyzed = count;
        self
    }

    /// Sets the duration
    pub fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = ms;
        self
    }

    /// Adds a statistic
    pub fn add_stat(&mut self, key: impl Into<String>, value: usize) {
        self.stats.insert(key.into(), value);
    }
}

/// Pass context for sharing data between passes
pub struct PassContext {
    /// Shared data between passes
    shared: HashMap<String, Arc<dyn std::any::Any + Send + Sync>>,
    /// Diagnostics produced by passes
    diagnostics: Vec<Diagnostic>,
    /// Facts produced by passes
    facts: Vec<Fact>,
    /// Issues collected across all passes
    issues: Vec<Issue>,
    /// Issues suppressed by the SRT gate
    suppressed_issues: Vec<Issue>,
    /// Monotonic issue ID counter
    next_issue_id: u64,
}

impl PassContext {
    /// Creates a new pass context
    pub fn new() -> Self {
        Self {
            shared: HashMap::new(),
            diagnostics: Vec::new(),
            facts: Vec::new(),
            issues: Vec::new(),
            suppressed_issues: Vec::new(),
            next_issue_id: 1,
        }
    }

    /// Stores shared data
    pub fn store<T: 'static + Send + Sync>(&mut self, key: impl Into<String>, value: T) {
        self.shared.insert(key.into(), Arc::new(value));
    }

    /// Retrieves shared data
    pub fn get<T: 'static + Clone>(&self, key: &str) -> Option<T> {
        self.shared
            .get(key)
            .and_then(|arc| arc.downcast_ref::<T>().cloned())
    }

    /// Adds a diagnostic
    pub fn add_diagnostic(&mut self, diag: Diagnostic) {
        self.diagnostics.push(diag);
    }

    /// Adds a fact
    pub fn add_fact(&mut self, fact: Fact) {
        self.facts.push(fact);
    }

    /// Returns all diagnostics
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Returns all facts
    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }

    /// Returns the number of diagnostics
    pub fn diagnostic_count(&self) -> usize {
        self.diagnostics.len()
    }

    /// Returns the number of facts
    pub fn fact_count(&self) -> usize {
        self.facts.len()
    }

    /// Allocates the next unique issue ID.
    pub fn next_issue_id(&mut self) -> u64 {
        let id = self.next_issue_id;
        self.next_issue_id += 1;
        id
    }

    /// Emits an issue into the context, checking the SRT gate first.
    ///
    /// If SRT resolutions are available in the context (key "srt_resolutions"),
    /// the issue is checked against the SRT-based issue gate before being
    /// added to the issues list. Suppressed issues are stored separately
    /// for diagnostics.
    pub fn emit_issue(&mut self, issue: Issue) -> u64 {
        let id = issue.id;

        // Check SRT gate if resolutions are available
        let srt_resolutions: Option<
            std::collections::HashMap<String, Vec<omniscope_semantics::SemanticKind>>,
        > = self.get("srt_resolutions");

        if let Some(ref resolutions) = srt_resolutions {
            let gate_verdict =
                crate::resource::issue_gate::check_issue_with_kinds(&issue, resolutions);
            if !gate_verdict.is_allowed() {
                tracing::debug!(
                    "IssueGate suppressed {:?}: {} [{}]",
                    issue.kind,
                    issue.description,
                    gate_verdict.reason(),
                );
                self.suppressed_issues.push(issue);
                return id;
            }
        }

        self.issues.push(issue);
        id
    }

    /// Returns all suppressed issues (filtered by SRT gate).
    pub fn suppressed_issues(&self) -> &[Issue] {
        &self.suppressed_issues
    }

    /// Returns the number of suppressed issues.
    pub fn suppressed_issue_count(&self) -> usize {
        self.suppressed_issues.len()
    }

    /// Returns all collected issues.
    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }

    /// Returns the number of collected issues.
    pub fn issue_count(&self) -> usize {
        self.issues.len()
    }
}

impl Default for PassContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_result_creation() {
        let result = PassResult::new("test_pass")
            .with_issues(5)
            .with_nodes(100)
            .with_duration(50);

        assert_eq!(result.name, "test_pass");
        assert_eq!(result.issues_found, 5);
        assert_eq!(result.nodes_analyzed, 100);
        assert_eq!(result.duration_ms, 50);
    }

    #[test]
    fn test_pass_context() {
        let mut ctx = PassContext::new();

        ctx.store("test_value", 42u64);
        let value: Option<u64> = ctx.get("test_value");
        assert_eq!(value, Some(42));

        assert_eq!(ctx.diagnostic_count(), 0);
        assert_eq!(ctx.fact_count(), 0);
    }
}
