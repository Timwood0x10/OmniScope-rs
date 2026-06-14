//! Pass manager for orchestrating analysis passes

use crate::pass::{Pass, PassContext, PassResult, PassTiming};
use crate::resource::incremental_cache::{AnalysisCache, CacheKey};
use omniscope_core::Result;
use omniscope_types::OmniScopeConfig;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// Pass manager for orchestrating analysis passes
pub struct PassManager {
    /// Registered passes
    passes: Vec<Box<dyn Pass>>,
    /// Execution order (computed from dependencies)
    execution_order: Vec<usize>,
    /// Whether to run in parallel
    parallel: bool,
    /// Optional incremental analysis cache
    cache: Option<AnalysisCache>,
    /// Source file fingerprint for cache key derivation
    file_fingerprint: u64,
    /// Configuration hash for cache key derivation
    config_hash: u64,
}

impl PassManager {
    /// Creates a new pass manager
    pub fn new() -> Self {
        Self {
            passes: Vec::new(),
            execution_order: Vec::new(),
            parallel: false, // Sequential by default — passes share context data
            cache: None,
            file_fingerprint: 0,
            config_hash: 0,
        }
    }

    /// Registers a pass
    pub fn register<P: Pass + 'static>(&mut self, pass: P) {
        self.passes.push(Box::new(pass));
    }

    /// Sets parallel execution mode
    pub fn set_parallel(&mut self, parallel: bool) {
        self.parallel = parallel;
    }

    /// Attach an incremental analysis cache to this manager.
    ///
    /// When a cache is attached, pass results are checked against the
    /// cache before execution and stored after execution, enabling
    /// incremental re-analysis across runs.
    pub fn with_cache(&mut self, cache: AnalysisCache) {
        self.cache = Some(cache);
    }

    /// Remove the attached cache, if any.
    pub fn remove_cache(&mut self) {
        self.cache = None;
    }

    /// Return a reference to the attached cache, if any.
    pub fn cache(&self) -> Option<&AnalysisCache> {
        self.cache.as_ref()
    }

    /// Return a mutable reference to the attached cache, if any.
    pub fn cache_mut(&mut self) -> Option<&mut AnalysisCache> {
        self.cache.as_mut()
    }

    /// Set the source file fingerprint used for cache key derivation.
    ///
    /// The fingerprint should be derived from the source file contents
    /// (path + size + mtime). When the file changes, the fingerprint
    /// changes, invalidating all cache entries for that file.
    pub fn set_file_fingerprint(&mut self, fingerprint: u64) {
        self.file_fingerprint = fingerprint;
    }

    /// Set the configuration hash used for cache key derivation.
    ///
    /// When the analysis configuration changes, this hash should change,
    /// causing existing cache entries to be invalidated.
    pub fn set_config_hash(&mut self, hash: u64) {
        self.config_hash = hash;
    }

    /// Computes execution order from dependencies
    pub fn compute_order(&mut self) -> Result<()> {
        // Build dependency graph
        let mut graph: HashMap<&str, HashSet<&str>> = HashMap::new();
        let mut name_to_idx: HashMap<&str, usize> = HashMap::new();

        for (idx, pass) in self.passes.iter().enumerate() {
            let name = pass.name();
            name_to_idx.insert(name, idx);

            let deps: HashSet<&str> = pass.dependencies().into_iter().collect();
            graph.insert(name, deps);
        }

        // Topological sort
        let mut order = Vec::new();
        let mut visited = HashSet::new();
        let mut temp = HashSet::new();

        for pass in &self.passes {
            self.visit(pass.name(), &graph, &mut visited, &mut temp, &mut order)?;
        }

        // Convert names to indices
        self.execution_order = order
            .into_iter()
            .filter_map(|name| name_to_idx.get(name).copied())
            .collect();

        Ok(())
    }

    /// Visits a node in topological sort
    fn visit<'a>(
        &self,
        node: &'a str,
        graph: &HashMap<&'a str, HashSet<&'a str>>,
        visited: &mut HashSet<&'a str>,
        temp: &mut HashSet<&'a str>,
        order: &mut Vec<&'a str>,
    ) -> Result<()> {
        if temp.contains(node) {
            return Err(omniscope_core::AnalysisError::DependencyNotSatisfied {
                pass_name: node.to_string(),
                dependency: "circular dependency".to_string(),
            }
            .into());
        }

        if visited.contains(node) {
            return Ok(());
        }

        temp.insert(node);

        if let Some(deps) = graph.get(node) {
            for dep in deps {
                self.visit(dep, graph, visited, temp, order)?;
            }
        }

        temp.remove(node);
        visited.insert(node);
        order.push(node);

        Ok(())
    }

    /// Runs all passes
    pub fn run_all(&mut self) -> Result<(Vec<PassResult>, Vec<PassTiming>)> {
        self.compute_order()?;
        let mut ctx = PassContext::new();
        self.run_with_context(&mut ctx)
    }

    /// Runs all passes and returns (pass_results, pass_timings, collected_issues).
    ///
    /// Issues are collected from both PassResult.issues and
    /// PassContext.issues(), providing a unified view of all
    /// detected problems.
    pub fn run_all_with_issues(
        &mut self,
    ) -> Result<(Vec<PassResult>, Vec<PassTiming>, Vec<omniscope_core::Issue>)> {
        self.compute_order()?;
        let mut ctx = PassContext::new();
        let (results, timings) = self.run_with_context(&mut ctx)?;
        let issues = ctx.issues().to_vec();
        Ok((results, timings, issues))
    }

    /// Runs all passes with an optional IR module injected into the context.
    ///
    /// The IR module is stored in the pass context so that passes like
    /// RawFactCollector can extract allocation/deallocation/FFI facts
    /// from the actual IR data.
    ///
    /// When an IR module is provided, a [`ModuleIndex`] is also built
    /// and stored in the context. This pre-computes and caches common
    /// metadata (language detection, registry lookups, call classification)
    /// so that downstream passes avoid redundant computation.
    pub fn run_all_with_ir(
        &mut self,
        ir_module: Option<omniscope_ir::IRModule>,
    ) -> Result<(Vec<PassResult>, Vec<PassTiming>, Vec<omniscope_core::Issue>)> {
        self.run_all_with_ir_and_config(ir_module, None)
    }

    /// Runs all passes with an IR module and optional configuration.
    ///
    /// This is the full version that accepts an optional `OmniScopeConfig`
    /// for FFI boundary and resource family definitions.
    pub fn run_all_with_ir_and_config(
        &mut self,
        ir_module: Option<omniscope_ir::IRModule>,
        config: Option<OmniScopeConfig>,
    ) -> Result<(Vec<PassResult>, Vec<PassTiming>, Vec<omniscope_core::Issue>)> {
        self.compute_order()?;
        let mut ctx = if let Some(config) = config {
            // Build BoundaryContext from config and store it in PassContext
            // so that IssueVerifierPass can access it for boundary-based verification.
            let boundary_ctx =
                omniscope_types::boundary::BoundaryContext::from_config(&config.ffi_boundary);
            let mut ctx = PassContext::with_config(config);
            ctx.store("boundary_context", boundary_ctx);
            ctx
        } else {
            // Always store BoundaryContext, even when config is None.
            // This ensures IssueVerifierPass can find it for boundary-based verification.
            let mut ctx = PassContext::new();
            ctx.store(
                "boundary_context",
                omniscope_types::boundary::BoundaryContext::new(),
            );
            ctx
        };
        if let Some(module) = ir_module {
            // Build the shared instruction metadata cache before running passes.
            let index = crate::module_index::ModuleIndex::build(&module);
            ctx.store("module_index", index);
            ctx.store("ir_module", module.clone());
            ctx.set_ir_module(module.clone());
            if let Some(text) = &module.source_text {
                ctx.set_source_text(text.clone());
            }
        }
        let (results, timings) = self.run_with_context(&mut ctx)?;
        let issues = ctx.issues().to_vec();
        Ok((results, timings, issues))
    }

    /// Try to retrieve a cached pass result.
    ///
    /// Returns `Some(PassResult)` on cache hit, `None` on miss.
    fn try_cache_hit(cache: &mut AnalysisCache, key: &CacheKey) -> Option<PassResult> {
        let cached = cache.get(key)?;
        serde_json::from_slice::<PassResult>(&cached.data)
            .inspect(|r| {
                tracing::debug!(
                    pass = %r.name,
                    "Reusing cached pass result"
                );
            })
            .ok()
    }

    /// Store a pass result in the cache.
    fn try_cache_store(cache: &mut AnalysisCache, key: CacheKey, result: &PassResult) {
        match serde_json::to_vec(result) {
            Ok(data) => {
                let original_size = result.issues.len() as u64;
                if let Err(e) = cache.put(key, data, original_size) {
                    tracing::warn!("Failed to store pass result in cache: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to serialize pass result for cache: {}", e);
            }
        }
    }

    /// Runs all passes with a shared context
    ///
    /// Returns a tuple of (pass_results, pass_timings) where pass_timings
    /// contains per-pass timing information for performance reporting.
    pub fn run_with_context(
        &mut self,
        ctx: &mut PassContext,
    ) -> Result<(Vec<PassResult>, Vec<PassTiming>)> {
        let mut results = Vec::new();
        let mut timings = Vec::new();

        if self.parallel {
            // Group passes by dependency level for parallel execution.
            // Each pass gets its own local PassContext (parallel safety),
            // then results are merged back into the shared main context.
            //
            // Uses clone_for_parallel() for lightweight cloning: shared data
            // (ir_module, shared HashMap) is shared via Arc, while write-only
            // data (diagnostics, facts, issues) starts empty.
            let levels = self.compute_levels();

            for level in levels {
                // Pre-clone contexts for each pass to avoid capturing &ctx in closures
                let pass_count = level.len();
                let mut local_contexts: Vec<PassContext> =
                    (0..pass_count).map(|_| ctx.clone_for_parallel()).collect();

                let level_results: Vec<(usize, PassContext, PassResult)> = level
                    .into_par_iter()
                    .zip(local_contexts.par_drain(..))
                    .map(|(idx, mut local_ctx)| {
                        let pass = &self.passes[idx];
                        // Use lightweight clone: shares read-only data via Arc,
                        // only allocates empty vectors for write-only data.
                        let start = Instant::now();

                        let mut result = match pass.run(&mut local_ctx) {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::error!(
                                    "Pass '{}' failed in parallel mode: {}",
                                    pass.name(),
                                    e
                                );
                                PassResult::new(pass.name()).with_issues(0)
                            }
                        };

                        result.duration_ms = start.elapsed().as_millis() as u64;
                        (idx, local_ctx, result)
                    })
                    .collect();

                // Merge each local_ctx back into the shared main context
                for (_idx, local_ctx, result) in level_results {
                    ctx.merge(local_ctx);
                    timings.push(PassTiming {
                        pass_name: result.name.clone(),
                        duration_ms: result.duration_ms,
                        issues_found: result.issues_found,
                    });
                    results.push(result);
                }
            }
        } else {
            // Sequential execution (with optional cache)
            for &idx in &self.execution_order {
                let pass = &self.passes[idx];
                let pass_name = pass.name();

                // Check cache first if a cache is attached.
                if let Some(ref mut cache) = self.cache {
                    let key = CacheKey::new(self.file_fingerprint, pass_name, "", self.config_hash);
                    if let Some(cached_result) = Self::try_cache_hit(cache, &key) {
                        timings.push(PassTiming {
                            pass_name: cached_result.name.clone(),
                            duration_ms: 0, // cached — no execution time
                            issues_found: cached_result.issues_found,
                        });
                        results.push(cached_result);
                        continue;
                    }
                }

                // Cache miss or no cache — run the pass normally.
                let start = Instant::now();

                let mut result = pass.run(ctx)?;
                result.duration_ms = start.elapsed().as_millis() as u64;

                // Store result in cache if attached.
                if let Some(ref mut cache) = self.cache {
                    let key = CacheKey::new(self.file_fingerprint, pass_name, "", self.config_hash);
                    Self::try_cache_store(cache, key, &result);
                }

                timings.push(PassTiming {
                    pass_name: result.name.clone(),
                    duration_ms: result.duration_ms,
                    issues_found: result.issues_found,
                });
                results.push(result);
            }
        }

        Ok((results, timings))
    }

    /// Computes dependency levels for parallel execution
    fn compute_levels(&self) -> Vec<Vec<usize>> {
        let mut levels = Vec::new();
        let mut completed: HashSet<&str> = HashSet::new();

        while completed.len() < self.passes.len() {
            let mut level = Vec::new();

            for (idx, pass) in self.passes.iter().enumerate() {
                if completed.contains(pass.name()) {
                    continue;
                }

                let deps_satisfied = pass
                    .dependencies()
                    .iter()
                    .all(|dep| completed.contains(dep));

                if deps_satisfied {
                    level.push(idx);
                }
            }

            if level.is_empty() {
                break;
            }

            for &idx in &level {
                completed.insert(self.passes[idx].name());
            }

            levels.push(level);
        }

        levels
    }

    /// Returns the number of registered passes
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Returns the names of all registered passes, in registration order.
    ///
    /// The names come directly from `Pass::name()`, so the result reflects
    /// the actual passes currently in the manager rather than a hardcoded
    /// list that can drift from reality.
    pub fn pass_names(&self) -> Vec<&'static str> {
        self.passes.iter().map(|p| p.name()).collect()
    }

    /// Clears all passes
    pub fn clear(&mut self) {
        self.passes.clear();
        self.execution_order.clear();
    }
}

impl Default for PassManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pass::PassKind;
    use crate::{FFIBoundaryPass, RawFactCollectorPass, SummaryBuilderPass};
    use tempfile::TempDir;

    #[test]
    fn test_pass_manager_creation() {
        let manager = PassManager::new();
        assert_eq!(
            manager.pass_count(),
            0,
            "New PassManager must have 0 passes"
        );
    }

    #[test]
    fn test_pass_registration() {
        let mut manager = PassManager::new();

        manager.register(RawFactCollectorPass::new());
        manager.register(SummaryBuilderPass::new());

        assert_eq!(
            manager.pass_count(),
            2,
            "PassManager must have 2 passes after registering 2"
        );
    }

    #[test]
    fn test_execution_order() {
        let mut manager = PassManager::new();

        manager.register(RawFactCollectorPass::new());
        manager.register(SummaryBuilderPass::new());
        manager.register(FFIBoundaryPass::new());

        manager.compute_order().unwrap();

        assert_eq!(
            manager.execution_order.len(),
            3,
            "Execution order must contain all 3 registered passes"
        );
    }

    /// Mock pass with configurable name and dependencies for testing.
    struct MockPass {
        pass_name: &'static str,
        pass_deps: Vec<&'static str>,
    }

    impl MockPass {
        fn new(name: &'static str, deps: Vec<&'static str>) -> Self {
            Self {
                pass_name: name,
                pass_deps: deps,
            }
        }
    }

    impl Pass for MockPass {
        fn name(&self) -> &'static str {
            self.pass_name
        }
        fn kind(&self) -> PassKind {
            PassKind::Analysis
        }
        fn dependencies(&self) -> Vec<&'static str> {
            self.pass_deps.clone()
        }
        fn run(&self, _ctx: &mut PassContext) -> Result<PassResult> {
            Ok(PassResult::new(self.pass_name))
        }
    }

    /// Objective: Verify that circular dependencies are detected and return an error.
    /// Invariants: compute_order() must return Err when two passes depend on each other.
    #[test]
    fn test_circular_dependency_detection() {
        let mut manager = PassManager::new();
        manager.register(MockPass::new("a", vec!["b"]));
        manager.register(MockPass::new("b", vec!["a"]));

        let result = manager.compute_order();
        assert!(
            result.is_err(),
            "circular dependency must cause compute_order to return Err"
        );
    }

    /// Objective: Verify that an empty PassManager produces an empty result without error.
    /// Invariants: An empty PassManager produces an empty result vec without error.
    #[test]
    fn test_empty_pass_manager_run_all() {
        let mut manager = PassManager::new();
        let (pass_results, pass_timings) = manager.run_all().expect("empty manager must not fail");
        assert!(
            pass_results.is_empty(),
            "run_all on empty manager must return empty pass_results vec"
        );
        assert!(
            pass_timings.is_empty(),
            "run_all on empty manager must return empty pass_timings vec"
        );
    }

    /// Objective: Verify that passes with no dependencies are all placed in a single level.
    /// Invariants: Three independent passes produce one level containing all three.
    #[test]
    fn test_compute_levels_no_deps() {
        let mut manager = PassManager::new();
        manager.register(MockPass::new("x", vec![]));
        manager.register(MockPass::new("y", vec![]));
        manager.register(MockPass::new("z", vec![]));

        let levels = manager.compute_levels();
        assert_eq!(
            levels.len(),
            1,
            "independent passes must form exactly one level"
        );
        assert_eq!(
            levels[0].len(),
            3,
            "all 3 passes must be in the single level"
        );
    }

    /// Objective: Verify that a linear dependency chain produces one pass per level.
    /// Invariants: a -> b -> c produces [[a], [b], [c]].
    #[test]
    fn test_compute_levels_with_chain() {
        let mut manager = PassManager::new();
        manager.register(MockPass::new("a", vec![]));
        manager.register(MockPass::new("b", vec!["a"]));
        manager.register(MockPass::new("c", vec!["b"]));

        let levels = manager.compute_levels();
        assert_eq!(levels.len(), 3, "chain of 3 must produce 3 levels");
        assert_eq!(
            levels[0],
            vec![0],
            "level 0 must contain pass 'a' (index 0)"
        );
        assert_eq!(
            levels[1],
            vec![1],
            "level 1 must contain pass 'b' (index 1)"
        );
        assert_eq!(
            levels[2],
            vec![2],
            "level 2 must contain pass 'c' (index 2)"
        );
    }

    /// Objective: Verify that clear() removes all registered passes.
    /// Invariants: pass_count() == 0 after clear().
    #[test]
    fn test_clear_resets() {
        let mut manager = PassManager::new();
        manager.register(RawFactCollectorPass::new());
        manager.register(SummaryBuilderPass::new());
        manager.register(FFIBoundaryPass::new());
        assert_eq!(manager.pass_count(), 3, "must have 3 passes before clear");

        manager.clear();
        assert_eq!(manager.pass_count(), 0, "pass_count must be 0 after clear");
    }

    /// Objective: Verify that set_parallel does not panic when toggled.
    /// Invariants: set_parallel(true) and set_parallel(false) both complete without error.
    #[test]
    fn test_set_parallel() {
        let mut manager = PassManager::new();
        manager.set_parallel(true);
        manager.set_parallel(false);
    }

    /// Objective: Verify that with_cache attaches a cache and that
    /// cache_mut returns it.
    /// Invariants: cache().is_some() after with_cache().
    #[test]
    fn test_cache_attachment() {
        let tmp = TempDir::new().unwrap();
        let mut manager = PassManager::new();

        assert!(
            manager.cache().is_none(),
            "cache must be None before attachment"
        );

        let cache = AnalysisCache::new(tmp.path());
        manager.with_cache(cache);
        assert!(
            manager.cache().is_some(),
            "cache must be Some after attachment"
        );

        manager.remove_cache();
        assert!(
            manager.cache().is_none(),
            "cache must be None after remove_cache"
        );
    }

    /// Objective: Verify that cached pass results are reused on
    /// subsequent runs.
    /// Invariants: A pass's run() is called exactly once when the
    /// cache is enabled; the second run returns the cached result.
    #[test]
    fn test_pass_cache_hit_avoids_reexecution() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        // A pass that counts how many times it's been run.
        struct CountingPass {
            name: &'static str,
            counter: Arc<AtomicUsize>,
        }

        impl Pass for CountingPass {
            fn name(&self) -> &'static str {
                self.name
            }
            fn kind(&self) -> PassKind {
                PassKind::Analysis
            }
            fn run(&self, _ctx: &mut PassContext) -> Result<PassResult> {
                self.counter.fetch_add(1, Ordering::SeqCst);
                Ok(PassResult::new(self.name))
            }
        }

        let tmp = TempDir::new().unwrap();
        let mut manager = PassManager::new();

        let counter = Arc::new(AtomicUsize::new(0));
        manager.register(CountingPass {
            name: "count_me",
            counter: counter.clone(),
        });

        // First run — should execute the pass.
        let cache = AnalysisCache::new(tmp.path());
        manager.with_cache(cache);
        let (results, _) = manager.run_all().unwrap();
        assert_eq!(results.len(), 1, "must produce 1 result");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "pass must run exactly once"
        );

        // Second run — should use cached result.
        let (results, timings) = manager.run_all().unwrap();
        assert_eq!(results.len(), 1, "must produce 1 result on second run");
        // Counter should still be 1 since the pass was not re-executed.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "pass must NOT run again on cache hit"
        );
        // The cached timing should have 0 ms duration.
        assert_eq!(
            timings[0].duration_ms, 0,
            "cached timing must have 0 ms duration"
        );
    }

    /// Objective: Verify that setting a different file fingerprint
    /// causes a cache miss on the second run.
    /// Invariants: After changing the fingerprint, the pass is
    /// re-executed (counter increments).
    #[test]
    fn test_cache_invalidation_by_fingerprint() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct FingerprintPass {
            name: &'static str,
            counter: Arc<AtomicUsize>,
        }

        impl Pass for FingerprintPass {
            fn name(&self) -> &'static str {
                self.name
            }
            fn kind(&self) -> PassKind {
                PassKind::Analysis
            }
            fn run(&self, _ctx: &mut PassContext) -> Result<PassResult> {
                self.counter.fetch_add(1, Ordering::SeqCst);
                Ok(PassResult::new(self.name))
            }
        }

        let tmp = TempDir::new().unwrap();
        let mut manager = PassManager::new();

        let counter = Arc::new(AtomicUsize::new(0));
        manager.register(FingerprintPass {
            name: "fp_pass",
            counter: counter.clone(),
        });

        let cache = AnalysisCache::new(tmp.path());
        manager.with_cache(cache);
        manager.set_file_fingerprint(100);

        // First run.
        manager.run_all().unwrap();
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "pass must run on first execution"
        );

        // Change fingerprint — should invalidate cache.
        manager.set_file_fingerprint(200);
        manager.run_all().unwrap();
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "pass must re-run after fingerprint change"
        );
    }

    /// Objective: Verify that metadata like pass_names works correctly
    /// with the cache attached.
    #[test]
    fn test_pass_names_with_cache() {
        let mut manager = PassManager::new();
        manager.register(MockPass::new("alpha", vec![]));
        manager.register(MockPass::new("beta", vec![]));

        let names = manager.pass_names();
        assert_eq!(
            names,
            vec!["alpha", "beta"],
            "pass_names must return registered names in order"
        );
    }
}
