//! Pass trait definition

use omniscope_core::Result;

pub trait Pass: Send + Sync {
    fn name(&self) -> &'static str;
    fn kind(&self) -> PassKind;
    fn run(&self) -> Result<PassResult>;
}

#[derive(Debug, Clone, Copy)]
pub enum PassKind {
    Foundation,
    Analysis,
    Transformation,
}

#[derive(Debug)]
pub struct PassResult {
    pub name: String,
    pub issues_found: usize,
}

impl PassResult {
    pub fn new(name: String) -> Self {
        Self {
            name,
            issues_found: 0,
        }
    }
}
