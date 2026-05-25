//! Source location tracking
//!
//! This module provides functionality for tracking source locations
//! from LLVM debug information.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Source location in the original code
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    /// File path
    pub file: PathBuf,
    /// Line number (1-based)
    pub line: u32,
    /// Column number (1-based, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// Function name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
}

impl SourceLocation {
    /// Creates a new source location
    pub fn new(file: PathBuf, line: u32) -> Self {
        Self {
            file,
            line,
            column: None,
            function: None,
        }
    }

    /// Adds column information
    pub fn with_column(mut self, column: u32) -> Self {
        self.column = Some(column);
        self
    }

    /// Adds function name
    pub fn with_function(mut self, function: String) -> Self {
        self.function = Some(function);
        self
    }

    /// Returns true if this location is valid
    pub fn is_valid(&self) -> bool {
        self.line > 0 && !self.file.as_os_str().is_empty()
    }

    /// Returns a display string for this location
    pub fn display(&self) -> String {
        let mut result = format!("{}:{}", self.file.display(), self.line);
        if let Some(col) = self.column {
            result.push_str(&format!(":{}", col));
        }
        if let Some(ref func) = self.function {
            result.push_str(&format!(" in {}", func));
        }
        result
    }
}

impl Default for SourceLocation {
    fn default() -> Self {
        Self {
            file: PathBuf::from("<unknown>"),
            line: 0,
            column: None,
            function: None,
        }
    }
}

/// Location manager for tracking and caching source locations
pub struct LocationManager {
    /// Location cache
    locations: Vec<SourceLocation>,
}

impl LocationManager {
    /// Creates a new location manager
    pub fn new() -> Self {
        Self {
            locations: Vec::new(),
        }
    }

    /// Adds a location and returns its index
    pub fn add(&mut self, location: SourceLocation) -> usize {
        let index = self.locations.len();
        self.locations.push(location);
        index
    }

    /// Gets a location by index
    pub fn get(&self, index: usize) -> Option<&SourceLocation> {
        self.locations.get(index)
    }

    /// Returns the number of locations
    pub fn count(&self) -> usize {
        self.locations.len()
    }

    /// Clears all locations
    pub fn clear(&mut self) {
        self.locations.clear();
    }
}

impl Default for LocationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_location_creation() {
        let loc = SourceLocation::new(PathBuf::from("test.rs"), 10)
            .with_column(5)
            .with_function("main".to_string());

        assert_eq!(loc.line, 10);
        assert_eq!(loc.column, Some(5));
        assert_eq!(loc.function, Some("main".to_string()));
        assert!(loc.is_valid());
    }

    #[test]
    fn test_source_location_display() {
        let loc = SourceLocation::new(PathBuf::from("test.rs"), 10)
            .with_column(5)
            .with_function("main".to_string());

        let display = loc.display();
        assert!(display.contains("test.rs"));
        assert!(display.contains("10"));
        assert!(display.contains("5"));
        assert!(display.contains("main"));
    }

    #[test]
    fn test_source_location_validity() {
        let valid = SourceLocation::new(PathBuf::from("test.rs"), 10);
        assert!(valid.is_valid());

        let invalid = SourceLocation::default();
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_location_manager() {
        let mut manager = LocationManager::new();

        let loc1 = SourceLocation::new(PathBuf::from("test.rs"), 10);
        let loc2 = SourceLocation::new(PathBuf::from("main.rs"), 20);

        let idx1 = manager.add(loc1);
        let idx2 = manager.add(loc2);

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(manager.count(), 2);

        let retrieved = manager.get(0).unwrap();
        assert_eq!(retrieved.line, 10);
    }
}
