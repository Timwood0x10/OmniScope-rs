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
            parallel: true,
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

    /// Runs all passes with a shared context
    pub fn run_with_context(&self, ctx: &mut PassContext) -> Result<Vec<PassResult>> {
        let mut results = Vec::new();

        if self.parallel {
            // Group passes by dependency level for parallel execution
            let levels = self.compute_levels();

            for level in levels {
                let level_results: Vec<PassResult> = level
                    .into_par_iter()
                    .map(|idx| {
                        let pass = &self.passes[idx];
                        let mut local_ctx = PassContext::new();
                        let start = Instant::now();

                        let mut result = pass
                            .run(&mut local_ctx)
                            .unwrap_or_else(|_e| PassResult::new(pass.name()).with_issues(1));

                        result.duration_ms = start.elapsed().as_millis() as u64;
                        result
                    })
                    .collect();

                results.extend(level_results);
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
    use crate::{CFGPass, DFGPass, FFIBoundaryPass};

    #[test]
    fn test_pass_manager_creation() {
        let manager = PassManager::new();
        assert_eq!(manager.pass_count(), 0);
    }

    #[test]
    fn test_pass_registration() {
        let mut manager = PassManager::new();

        manager.register(CFGPass::new());
        manager.register(DFGPass::new());

        assert_eq!(manager.pass_count(), 2);
    }

    #[test]
    fn test_execution_order() {
        let mut manager = PassManager::new();

        manager.register(CFGPass::new());
        manager.register(DFGPass::new());
        manager.register(FFIBoundaryPass::new());

        manager.compute_order().unwrap();

        assert_eq!(manager.execution_order.len(), 3);
    }
}
