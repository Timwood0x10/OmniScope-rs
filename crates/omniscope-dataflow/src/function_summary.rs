//! Function summary for inter-procedural analysis
//!
//! This module provides function summaries for efficient inter-procedural
//! dataflow analysis.

use crate::graph::MemoryLocation;
use omniscope_types::FunctionId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Function summary for inter-procedural analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    /// Function ID
    pub function_id: FunctionId,
    /// Function name
    pub name: String,
    /// Input parameters
    pub inputs: Vec<AbstractValue>,
    /// Output values
    pub outputs: Vec<AbstractValue>,
    /// Side effects
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub side_effects: Vec<SideEffect>,
    /// Modified memory locations
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub modified_locations: HashSet<String>,
    /// Read memory locations
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub read_locations: HashSet<String>,
}

impl FunctionSummary {
    /// Creates a new function summary
    pub fn new(function_id: FunctionId, name: impl Into<String>) -> Self {
        Self {
            function_id,
            name: name.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            side_effects: Vec::new(),
            modified_locations: HashSet::new(),
            read_locations: HashSet::new(),
        }
    }

    /// Adds an input parameter
    pub fn add_input(&mut self, value: AbstractValue) {
        self.inputs.push(value);
    }

    /// Adds an output value
    pub fn add_output(&mut self, value: AbstractValue) {
        self.outputs.push(value);
    }

    /// Adds a side effect
    pub fn add_side_effect(&mut self, effect: SideEffect) {
        self.side_effects.push(effect);
    }

    /// Marks a location as modified
    pub fn mark_modified(&mut self, location: impl Into<String>) {
        self.modified_locations.insert(location.into());
    }

    /// Marks a location as read
    pub fn mark_read(&mut self, location: impl Into<String>) {
        self.read_locations.insert(location.into());
    }

    /// Returns true if the function has side effects
    pub fn has_side_effects(&self) -> bool {
        !self.side_effects.is_empty() || !self.modified_locations.is_empty()
    }

    /// Returns true if the function is pure (no side effects)
    pub fn is_pure(&self) -> bool {
        !self.has_side_effects()
    }
}

/// Abstract value for summary
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AbstractValue {
    /// Unknown value
    Unknown,
    /// Constant value
    Constant(String),
    /// Parameter reference (index)
    Parameter(u32),
    /// Memory location
    Memory(MemoryLocation),
    /// Function call result
    CallResult(FunctionId, Box<AbstractValue>),
    /// Join of multiple values
    Join(Vec<AbstractValue>),
}

impl AbstractValue {
    /// Creates an unknown value
    pub fn unknown() -> Self {
        AbstractValue::Unknown
    }

    /// Creates a constant value
    pub fn constant(value: impl Into<String>) -> Self {
        AbstractValue::Constant(value.into())
    }

    /// Creates a parameter reference
    pub fn parameter(index: u32) -> Self {
        AbstractValue::Parameter(index)
    }

    /// Returns true if this is unknown
    pub fn is_unknown(&self) -> bool {
        matches!(self, AbstractValue::Unknown)
    }

    /// Returns true if this is a constant
    pub fn is_constant(&self) -> bool {
        matches!(self, AbstractValue::Constant(_))
    }
}

/// Side effect type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SideEffect {
    /// Memory write
    MemoryWrite {
        /// Location
        location: MemoryLocation,
        /// Value written
        value: AbstractValue,
    },
    /// Memory read
    MemoryRead {
        /// Location
        location: MemoryLocation,
    },
    /// Function call
    FunctionCall {
        /// Called function ID
        function_id: FunctionId,
        /// Arguments
        args: Vec<AbstractValue>,
    },
    /// Lock acquisition
    LockAcquire {
        /// Lock object
        lock: String,
    },
    /// Lock release
    LockRelease {
        /// Lock object
        lock: String,
    },
    /// Thread spawn
    ThreadSpawn {
        /// Entry function
        entry: FunctionId,
    },
}

/// Function summary cache
pub struct SummaryCache {
    /// Cached summaries
    summaries: HashMap<FunctionId, FunctionSummary>,
}

impl SummaryCache {
    /// Creates a new summary cache
    pub fn new() -> Self {
        Self {
            summaries: HashMap::new(),
        }
    }

    /// Adds a summary to the cache
    pub fn insert(&mut self, summary: FunctionSummary) {
        self.summaries.insert(summary.function_id, summary);
    }

    /// Gets a summary from the cache
    pub fn get(&self, function_id: FunctionId) -> Option<&FunctionSummary> {
        self.summaries.get(&function_id)
    }

    /// Returns the number of cached summaries
    pub fn count(&self) -> usize {
        self.summaries.len()
    }

    /// Clears the cache
    pub fn clear(&mut self) {
        self.summaries.clear();
    }
}

impl Default for SummaryCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_summary_creation() {
        let summary = FunctionSummary::new(1, "test_func");
        assert_eq!(summary.name, "test_func");
        assert!(summary.is_pure());
        assert!(!summary.has_side_effects());
    }

    #[test]
    fn test_function_summary_side_effects() {
        let mut summary = FunctionSummary::new(1, "test_func");

        summary.mark_modified("global_var");
        assert!(summary.has_side_effects());
        assert!(!summary.is_pure());
    }

    #[test]
    fn test_abstract_value() {
        let unknown = AbstractValue::unknown();
        assert!(unknown.is_unknown());
        assert!(!unknown.is_constant());

        let constant = AbstractValue::constant("42");
        assert!(constant.is_constant());
        assert!(!constant.is_unknown());
    }

    #[test]
    fn test_summary_cache() {
        let mut cache = SummaryCache::new();

        let summary = FunctionSummary::new(1, "test_func");
        cache.insert(summary);

        assert_eq!(cache.count(), 1);
        assert!(cache.get(1).is_some());
    }
}
