//! Semantic registry

use dashmap::DashMap;

pub struct SemanticRegistry {
    /// Function semantic information
    functions: DashMap<String, String>,
}

impl SemanticRegistry {
    pub fn new() -> Self {
        Self {
            functions: DashMap::new(),
        }
    }

    /// Registers a function with its semantic information
    pub fn register(&self, name: String, semantic: String) {
        self.functions.insert(name, semantic);
    }

    /// Looks up semantic information for a function
    pub fn lookup(&self, name: &str) -> Option<String> {
        self.functions.get(name).map(|v| v.clone())
    }
}

impl Default for SemanticRegistry {
    fn default() -> Self {
        Self::new()
    }
}
