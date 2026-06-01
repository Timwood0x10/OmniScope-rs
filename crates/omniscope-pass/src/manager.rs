//! Pass manager for orchestrating analysis passes

use crate::pass::{Pass, PassContext, PassResult};
use omniscope_core::Result;
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
}

impl PassManager {
    /// Creates a new pass manager
    pub fn new() -> Self {
        Self {
            passes: Vec::new(),
            execution_order: Vec::new(),
            parallel: false, // Sequential by default — passes share context data
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
    pub fn run_all(&mut self) -> Result<Vec<PassResult>> {
        self.compute_order()?;
        let mut ctx = PassContext::new();
        self.run_with_context(&mut ctx)
    }

    /// Runs all passes and returns (pass_results, collected_issues).
    ///
    /// Issues are collected from both PassResult.issues and
    /// PassContext.issues(), providing a unified view of all
    /// detected problems.
    pub fn run_all_with_issues(&mut self) -> Result<(Vec<PassResult>, Vec<omniscope_core::Issue>)> {
        self.compute_order()?;
        let mut ctx = PassContext::new();
        let results = self.run_with_context(&mut ctx)?;
        let issues = ctx.issues().to_vec();
        Ok((results, issues))
    }

    /// Runs all passes with an optional IR module injected into the context.
    ///
    /// The IR module is stored in the pass context so that passes like
    /// RawFactCollector can extract allocation/deallocation/FFI facts
    /// from the actual IR data.
    pub fn run_all_with_ir(
        &mut self,
        ir_module: Option<omniscope_ir::IRModule>,
    ) -> Result<(Vec<PassResult>, Vec<omniscope_core::Issue>)> {
        self.compute_order()?;
        let mut ctx = PassContext::new();
        if let Some(module) = ir_module {
            ctx.store("ir_module", module);
        }
        let results = self.run_with_context(&mut ctx)?;
        let issues = ctx.issues().to_vec();
        Ok((results, issues))
    }

    /// Runs all passes with a shared context
    pub fn run_with_context(&self, ctx: &mut PassContext) -> Result<Vec<PassResult>> {
        let mut results = Vec::new();

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
                    results.push(result);
                }
            }
        } else {
            // Sequential execution
            for &idx in &self.execution_order {
                let pass = &self.passes[idx];
                let start = Instant::now();

                let mut result = pass.run(ctx)?;
                result.duration_ms = start.elapsed().as_millis() as u64;
                results.push(result);
            }
        }

        Ok(results)
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

    /// Objective: Verify that run_all on an empty manager succeeds with no results.
    /// Invariants: An empty PassManager produces an empty result vec without error.
    #[test]
    fn test_empty_pass_manager_run_all() {
        let mut manager = PassManager::new();
        let results = manager.run_all().expect("empty manager must not fail");
        assert!(
            results.is_empty(),
            "run_all on empty manager must return empty vec"
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
}
