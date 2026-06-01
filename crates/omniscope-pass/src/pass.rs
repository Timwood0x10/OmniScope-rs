//! Pass trait definition and infrastructure
//!
//! This module defines the core pass infrastructure for OmniScope analysis.

use omniscope_core::{Diagnostic, Fact, Issue, MemoryPool, Result};
use omniscope_ir::IRModule;
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

/// Outcome of emitting an issue through the SRT gate.
///
/// Every call to `PassContext::emit_issue` returns this, so callers
/// know whether the issue passed the gate and can decide whether to
/// also record it in `PassResult.issues` (only if allowed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitOutcome {
    /// Issue passed the SRT gate and was recorded.
    Allowed { id: u64 },
    /// Issue was suppressed by the SRT gate.
    Suppressed { id: u64, reason: String },
}

impl EmitOutcome {
    /// Returns true if the issue was allowed through the gate.
    pub fn is_allowed(&self) -> bool {
        matches!(self, EmitOutcome::Allowed { .. })
    }

    /// Returns the issue ID regardless of the outcome.
    pub fn id(&self) -> u64 {
        match self {
            EmitOutcome::Allowed { id } | EmitOutcome::Suppressed { id, .. } => *id,
        }
    }
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

/// Pass context for sharing data between passes.
///
/// Uses `Arc<HashMap<...>>` for shared data to enable cheap cloning in parallel
/// execution. When a pass needs to write to shared data, it performs a
/// copy-on-write operation (clone the Arc).
///
/// Note: `Clone` is implemented manually because `MemoryPool` does not
/// implement `Clone`. Each clone receives a fresh empty pool.
pub struct PassContext {
    /// The IR module being analyzed — stored separately from `shared` so that
    /// passes can obtain a `&IRModule` reference without cloning, while still
    /// being able to call `store()` / `emit_issue()` later in the same `run()`.
    ir_module: Option<Arc<IRModule>>,
    /// Shared data between passes (wrapped in Arc for cheap cloning)
    shared: Arc<HashMap<String, Arc<dyn std::any::Any + Send + Sync>>>,
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
    /// Arena-based memory pool for temporary allocations during pass execution.
    ///
    /// Hot passes use this pool to reduce heap allocation overhead for
    /// temporary strings and data structures. The pool is reset at the
    /// start of each pass run to reclaim memory for the next pass.
    pool: MemoryPool,
}

impl Clone for PassContext {
    /// Clones the PassContext.
    ///
    /// This is a full clone that copies all data. For parallel execution,
    /// prefer `clone_for_parallel()` which shares read-only data via Arc.
    ///
    /// Note: `MemoryPool` does not implement `Clone`, so each clone
    /// receives a fresh empty pool.
    fn clone(&self) -> Self {
        Self {
            ir_module: self.ir_module.clone(),
            shared: self.shared.clone(),
            diagnostics: self.diagnostics.clone(),
            facts: self.facts.clone(),
            issues: self.issues.clone(),
            suppressed_issues: self.suppressed_issues.clone(),
            next_issue_id: self.next_issue_id,
            pool: MemoryPool::new(),
        }
    }
}

impl PassContext {
    /// Creates a new pass context
    pub fn new() -> Self {
        Self {
            ir_module: None,
            shared: Arc::new(HashMap::new()),
            diagnostics: Vec::new(),
            facts: Vec::new(),
            issues: Vec::new(),
            suppressed_issues: Vec::new(),
            next_issue_id: 1,
            pool: MemoryPool::new(),
        }
    }

    /// Returns a mutable reference to the arena-based memory pool.
    ///
    /// Passes should call `reset_pool()` before using the pool to ensure
    /// it is empty. After use, the pool memory is reclaimed when the
    /// pass finishes or when `reset_pool()` is called again.
    ///
    /// # Examples
    ///
    /// ```
    /// use omniscope_pass::pass::PassContext;
    ///
    /// let mut ctx = PassContext::new();
    /// ctx.reset_pool();
    /// let s = ctx.pool_mut().alloc_str("hello");
    /// assert_eq!(s, "hello");
    /// ```
    pub fn pool_mut(&mut self) -> &mut MemoryPool {
        &mut self.pool
    }

    /// Resets the memory pool, deallocating all arena memory.
    ///
    /// Call this at the start of a pass run to reclaim memory from
    /// the previous pass. All references previously allocated from
    /// the pool become invalid after this call.
    ///
    /// # Safety
    ///
    /// The caller must ensure no references derived from the pool are
    /// in use when this method is called.
    pub fn reset_pool(&mut self) {
        self.pool.reset();
    }

    /// Sets the IR module for analysis.
    ///
    /// This is the primary input for almost every analysis pass.
    /// Stored in a dedicated field (not `shared`) so that passes can
    /// obtain `&IRModule` via `get_ir_module()` without cloning, even
    /// when they also need to call `store()` / `emit_issue()` later.
    pub fn set_ir_module(&mut self, module: IRModule) {
        self.ir_module = Some(Arc::new(module));
    }

    /// Returns a reference to the IR module, if one has been set.
    ///
    /// This is the zero-clone alternative to `ctx.get::<IRModule>("ir_module")`.
    /// Because `ir_module` lives in a dedicated `Option<Arc<IRModule>>` field
    /// rather than the `shared` HashMap, the borrow on `self.ir_module` does
    /// not conflict with subsequent `&mut self` calls to `store()` or
    /// `emit_issue()`.
    pub fn get_ir_module(&self) -> Option<&IRModule> {
        self.ir_module.as_deref()
    }

    /// Returns `true` if an IR module has been set in this context.
    pub fn has_ir_module(&self) -> bool {
        self.ir_module.is_some()
    }

    /// Stores shared data
    ///
    /// Uses copy-on-write: if the shared HashMap is shared with other contexts,
    /// it will be cloned before modification.
    pub fn store<T: 'static + Send + Sync>(&mut self, key: impl Into<String>, value: T) {
        let shared = Arc::make_mut(&mut self.shared);
        shared.insert(key.into(), Arc::new(value));
    }

    /// Retrieves shared data
    pub fn get<T: 'static + Clone>(&self, key: &str) -> Option<T> {
        self.shared
            .get(key)
            .and_then(|arc| arc.downcast_ref::<T>().cloned())
    }

    /// Retrieves a reference to shared data without cloning.
    ///
    /// Use this for large collections (ContractGraph, SummaryStore, etc.)
    /// where cloning would be O(n) and wasteful.
    pub fn get_ref<T: 'static + Send + Sync>(&self, key: &str) -> Option<&T> {
        self.shared.get(key).and_then(|arc| arc.downcast_ref::<T>())
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
    /// This is the **single choke point** for all issue emission. Every pass
    /// MUST call `emit_issue` to report an issue — never push directly
    /// to `PassResult.issues` or any other collection. The SRT gate is
    /// enforced here, preventing ad-hoc suppression scattered across passes.
    ///
    /// If SRT resolutions are available in the context (key "srt_resolutions"),
    /// the issue is checked against the SRT-based issue gate before being
    /// added to the issues list. Suppressed issues are stored separately
    /// for diagnostics.
    ///
    /// Returns `EmitOutcome::Allowed` if the issue passes the gate,
    /// or `EmitOutcome::Suppressed(reason)` if the SRT gate suppresses it.
    pub fn emit_issue(&mut self, issue: Issue) -> EmitOutcome {
        let id = issue.id;

        // Check SRT gate if resolutions are available.
        // Use get_ref to avoid cloning the entire HashMap on every call —
        // this is called thousands of times per analysis run.
        let srt_resolutions = self
            .get_ref::<std::collections::HashMap<String, Vec<omniscope_semantics::SemanticKind>>>(
                "srt_resolutions",
            );

        if let Some(resolutions) = srt_resolutions {
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
                return EmitOutcome::Suppressed {
                    id,
                    reason: gate_verdict.reason().to_string(),
                };
            }
        }

        self.issues.push(issue);
        EmitOutcome::Allowed { id }
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

    /// Creates a lightweight clone for parallel execution.
    ///
    /// This method creates a new PassContext that shares the read-only data
    /// (ir_module and shared) with the original context via Arc references,
    /// but has empty collections for write-only data (diagnostics, facts,
    /// issues, suppressed_issues). The `next_issue_id` is copied from the
    /// original context.
    ///
    /// This is more efficient than a full clone when running passes in parallel,
    /// as it avoids copying potentially large vectors of diagnostics, facts,
    /// and issues that are only written to by individual passes.
    ///
    /// Each cloned context receives a fresh `MemoryPool` because the pool
    /// is not thread-safe (`Send` but not `Sync`) — each parallel pass
    /// needs its own arena.
    pub fn clone_for_parallel(&self) -> Self {
        Self {
            ir_module: self.ir_module.clone(), // Arc clone (cheap)
            shared: self.shared.clone(),       // HashMap clone, but values are Arc (cheap)
            diagnostics: Vec::new(),           // Empty - pass will produce its own
            facts: Vec::new(),                 // Empty - pass will produce its own
            issues: Vec::new(),                // Empty - pass will produce its own
            suppressed_issues: Vec::new(),     // Empty - pass will produce its own
            next_issue_id: self.next_issue_id, // Copy starting ID
            pool: MemoryPool::new(),           // Fresh pool for this thread
        }
    }

    /// Merges another PassContext into this one.
    ///
    /// Used by the parallel pass manager to collect results from
    /// per-pass local contexts back into the shared main context.
    /// Issues, suppressed issues, diagnostics, facts, and shared data
    /// are all appended/overwritten. The `next_issue_id` counter is
    /// advanced past the highest ID in the merged context to avoid
    /// collisions.
    ///
    /// The `MemoryPool` is **not** merged — each context keeps its own
    /// pool, and the `other` pool is dropped here, releasing its arena
    /// memory.
    pub fn merge(&mut self, other: PassContext) {
        // Append issues and suppressed issues
        self.issues.extend(other.issues);
        self.suppressed_issues.extend(other.suppressed_issues);

        // Append diagnostics and facts
        self.diagnostics.extend(other.diagnostics);
        self.facts.extend(other.facts);

        // Merge shared data (later writer wins for duplicate keys)
        // Use Arc::make_mut to get mutable access to our shared HashMap
        let shared = Arc::make_mut(&mut self.shared);
        for (key, value) in other.shared.iter() {
            shared.insert(key.clone(), Arc::clone(value));
        }

        // Inherit ir_module if we don't have one yet
        if self.ir_module.is_none() {
            self.ir_module = other.ir_module.clone();
        }

        // Advance issue ID counter past the highest used ID
        if other.next_issue_id > self.next_issue_id {
            self.next_issue_id = other.next_issue_id;
        }

        // other.pool is dropped here — its arena memory is reclaimed.
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

        assert_eq!(result.name, "test_pass", "Pass name should be test_pass");
        assert_eq!(result.issues_found, 5, "Issues found should be 5");
        assert_eq!(result.nodes_analyzed, 100, "Nodes analyzed should be 100");
        assert_eq!(result.duration_ms, 50, "Duration should be 50ms");
    }

    #[test]
    fn test_pass_context() {
        let mut ctx = PassContext::new();

        ctx.store("test_value", 42u64);
        let value: Option<u64> = ctx.get("test_value");
        assert_eq!(value, Some(42), "Should retrieve stored u64 value");

        assert_eq!(
            ctx.diagnostic_count(),
            0,
            "Initial diagnostic count should be 0"
        );
        assert_eq!(ctx.fact_count(), 0, "Initial fact count should be 0");
    }

    /// Objective: Verify that next_issue_id() returns strictly increasing values starting from 1.
    /// Invariants: Each call returns a u64 that is 1 greater than the previous.
    #[test]
    fn test_next_issue_id_is_monotonic() {
        let mut ctx = PassContext::new();
        let ids: Vec<u64> = (0..5).map(|_| ctx.next_issue_id()).collect();
        assert_eq!(
            ids,
            vec![1, 2, 3, 4, 5],
            "issue IDs must be sequential starting from 1"
        );
    }

    /// Objective: Verify that emit_issue without SRT resolutions adds the issue to the context.
    /// Invariants: The issue appears in ctx.issues() and not in suppressed_issues().
    #[test]
    fn test_emit_issue_without_srt() {
        use omniscope_core::{Issue, IssueKind, Severity};

        let mut ctx = PassContext::new();
        let issue = Issue::new(1, IssueKind::MemoryLeak, Severity::Warning, "test leak");
        let outcome = ctx.emit_issue(issue);

        assert!(
            outcome.is_allowed(),
            "issue must be allowed without SRT gate"
        );
        assert_eq!(outcome.id(), 1, "outcome ID must match the issue ID");
        assert_eq!(
            ctx.issues().len(),
            1,
            "context must contain exactly 1 emitted issue"
        );
        assert_eq!(
            ctx.suppressed_issues().len(),
            0,
            "no issues should be suppressed without SRT gate"
        );
        assert_eq!(
            ctx.issues()[0].kind,
            IssueKind::MemoryLeak,
            "emitted issue must retain its kind"
        );
    }

    /// Objective: Verify that PassResult::add_issue correctly tracks issues_found count.
    /// Invariants: issues_found equals the number of added issues, and get_issues returns all of them.
    #[test]
    fn test_pass_result_add_issue() {
        use omniscope_core::{Issue, IssueKind, Severity};

        let mut result = PassResult::new("test");
        result.add_issue(Issue::new(
            1,
            IssueKind::MemoryLeak,
            Severity::Warning,
            "leak 1",
        ));
        result.add_issue(Issue::new(
            2,
            IssueKind::InvalidFree,
            Severity::Error,
            "invalid free",
        ));
        result.add_issue(Issue::new(
            3,
            IssueKind::FfiUnsafeCall,
            Severity::Note,
            "ffi call",
        ));

        assert_eq!(
            result.issues_found, 3,
            "issues_found must equal 3 after adding 3 issues"
        );
        assert_eq!(
            result.get_issues().len(),
            3,
            "get_issues must return all 3 issues"
        );
        assert_eq!(
            result.get_issues()[0].kind,
            IssueKind::MemoryLeak,
            "first issue must be MemoryLeak"
        );
        assert_eq!(
            result.get_issues()[1].kind,
            IssueKind::InvalidFree,
            "second issue must be InvalidFree"
        );
        assert_eq!(
            result.get_issues()[2].kind,
            IssueKind::FfiUnsafeCall,
            "third issue must be FfiUnsafeCall"
        );
    }

    /// Objective: Verify that PassResult::add_stat correctly stores statistics.
    /// Invariants: Stats are stored in the stats HashMap with correct key-value pairs.
    #[test]
    fn test_pass_result_add_stat() {
        let mut result = PassResult::new("test");
        result.add_stat("allocations", 42);
        result.add_stat("branches", 100);

        assert_eq!(
            result.stats.get("allocations"),
            Some(&42),
            "allocations stat must be 42"
        );
        assert_eq!(
            result.stats.get("branches"),
            Some(&100),
            "branches stat must be 100"
        );
        assert_eq!(
            result.stats.len(),
            2,
            "stats must contain exactly 2 entries"
        );
    }

    /// Objective: Verify that PassContext can store and retrieve values of different types.
    /// Invariants: Each type-keyed value is independently stored and retrievable.
    #[test]
    fn test_pass_context_store_retrieve_different_types() {
        let mut ctx = PassContext::new();
        ctx.store("greeting", "hello".to_string());
        ctx.store("count", 42u64);

        let greeting: Option<String> = ctx.get("greeting");
        let count: Option<u64> = ctx.get("count");

        assert_eq!(
            greeting,
            Some("hello".to_string()),
            "must retrieve stored String"
        );
        assert_eq!(count, Some(42u64), "must retrieve stored u64");
    }

    /// Objective: Verify that requesting the wrong type for a stored key returns None.
    /// Invariants: Type mismatch in downcast_ref returns None rather than panicking.
    #[test]
    fn test_pass_context_get_wrong_type_returns_none() {
        let mut ctx = PassContext::new();
        ctx.store("value", 42u64);

        let wrong_type: Option<String> = ctx.get("value");
        assert_eq!(wrong_type, None, "requesting wrong type must return None");
    }

    /// Objective: Verify that diagnostic_count reflects the number of added diagnostics.
    /// Invariants: diagnostic_count() == 3 after adding 3 diagnostics.
    #[test]
    fn test_pass_context_diagnostic_count() {
        use omniscope_core::{Diagnostic, Severity};

        let mut ctx = PassContext::new();
        ctx.add_diagnostic(Diagnostic::new(1, Severity::Warning, "W001", "warning 1"));
        ctx.add_diagnostic(Diagnostic::new(2, Severity::Error, "E001", "error 1"));
        ctx.add_diagnostic(Diagnostic::new(3, Severity::Note, "N001", "note 1"));

        assert_eq!(
            ctx.diagnostic_count(),
            3,
            "diagnostic_count must be 3 after adding 3 diagnostics"
        );
    }

    /// Objective: Verify that fact_count reflects the number of added facts.
    /// Invariants: fact_count() == 2 after adding 2 facts.
    #[test]
    fn test_pass_context_fact_count() {
        use omniscope_core::{Fact, FactKind, FactLocation};

        let mut ctx = PassContext::new();
        let loc = FactLocation::new(std::path::PathBuf::from("test.rs"), 10);
        ctx.add_fact(Fact::new(1, FactKind::AllocSite, loc.clone()));
        ctx.add_fact(Fact::new(2, FactKind::DeallocSite, loc));

        assert_eq!(
            ctx.fact_count(),
            2,
            "fact_count must be 2 after adding 2 facts"
        );
    }
}
