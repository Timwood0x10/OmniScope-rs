//! Semantic registry

use dashmap::DashMap;

pub struct SemanticRegistry {
    functions: DashMap<String, String>,
}

impl SemanticRegistry {
    pub fn new() -> Self {
        Self {
            functions: DashMap::new(),
        }
    }
}

impl Default for SemanticRegistry {
    fn default() -> Self {
        Self::new()
    }
}
