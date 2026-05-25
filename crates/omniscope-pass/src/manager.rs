//! Pass manager

use super::{Pass, PassResult};
use omniscope_core::Result;
use rayon::prelude::*;

pub struct PassManager {
    passes: Vec<Box<dyn Pass>>,
}

impl PassManager {
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    pub fn register<P: Pass + 'static>(&mut self, pass: P) {
        self.passes.push(Box::new(pass));
    }

    pub fn run_all(&self) -> Result<Vec<PassResult>> {
        self.passes.par_iter().map(|pass| pass.run()).collect()
    }
}

impl Default for PassManager {
    fn default() -> Self {
        Self::new()
    }
}
