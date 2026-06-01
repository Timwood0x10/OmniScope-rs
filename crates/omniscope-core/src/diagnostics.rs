//! Diagnostic system for OmniScope
//!
//! This module provides a comprehensive diagnostic system for reporting analysis results,
//! warnings, and errors. It supports concurrent aggregation and multiple output formats.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::instrument;

/// Unique identifier for diagnostics
pub type DiagnosticId = u64;

/// Severity level of a diagnostic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Internal error - analysis cannot continue
    Error,
    /// Warning - potential issue found
    Warning,
    /// Note - additional information
    Note,
    /// Help - suggestion for fixing
    Help,
}

impl Severity {
    /// Returns true if this is an error
    pub fn is_error(&self) -> bool {
        matches!(self, Severity::Error)
    }

    /// Returns true if this is a warning
    pub fn is_warning(&self) -> bool {
        matches!(self, Severity::Warning)
    }
}

/// Source location for a diagnostic
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
}

/// A single diagnostic message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Unique identifier
    pub id: DiagnosticId,
    /// Severity level
    pub severity: Severity,
    /// Diagnostic code (e.g., "E0001")
    pub code: String,
    /// Main message
    pub message: String,
    /// Source location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
    /// Additional notes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Help messages
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub helps: Vec<String>,
    /// Related locations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<RelatedLocation>,
}

/// A related location with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedLocation {
    /// Location
    pub location: SourceLocation,
    /// Message describing the relation
    pub message: String,
}

impl Diagnostic {
    /// Creates a new diagnostic
    pub fn new(
        id: DiagnosticId,
        severity: Severity,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id,
            severity,
            code: code.into(),
            message: message.into(),
            location: None,
            notes: Vec::new(),
            helps: Vec::new(),
            related: Vec::new(),
        }
    }

    /// Adds a source location
    pub fn with_location(mut self, location: SourceLocation) -> Self {
        self.location = Some(location);
        self
    }

    /// Adds a note
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// Adds a help message
    pub fn help(mut self, help: impl Into<String>) -> Self {
        self.helps.push(help.into());
        self
    }

    /// Adds a related location
    pub fn related(mut self, location: SourceLocation, message: impl Into<String>) -> Self {
        self.related.push(RelatedLocation {
            location,
            message: message.into(),
        });
        self
    }
}

/// Thread-safe diagnostic aggregator
#[derive(Debug)]
pub struct DiagnosticAggregator {
    /// All diagnostics
    diagnostics: DashMap<DiagnosticId, Diagnostic>,
    /// Diagnostics grouped by file
    by_file: DashMap<PathBuf, Vec<DiagnosticId>>,
    /// Diagnostics grouped by severity
    by_severity: DashMap<Severity, Vec<DiagnosticId>>,
    /// Next diagnostic ID
    next_id: AtomicU64,
}

impl DiagnosticAggregator {
    /// Creates a new diagnostic aggregator
    pub fn new() -> Self {
        Self {
            diagnostics: DashMap::new(),
            by_file: DashMap::new(),
            by_severity: DashMap::new(),
            next_id: AtomicU64::new(1),
        }
    }

    /// Emits a new diagnostic
    #[instrument(skip(self), fields(severity = ?diagnostic.severity, code = %diagnostic.code))]
    pub fn emit(&self, mut diagnostic: Diagnostic) -> DiagnosticId {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        diagnostic.id = id;

        // Index by file
        if let Some(ref location) = diagnostic.location {
            self.by_file
                .entry(location.file.clone())
                .or_default()
                .push(id);
        }

        // Index by severity
        self.by_severity
            .entry(diagnostic.severity)
            .or_default()
            .push(id);

        // Store diagnostic
        self.diagnostics.insert(id, diagnostic);

        id
    }

    /// Gets a diagnostic by ID
    pub fn get(&self, id: DiagnosticId) -> Option<Diagnostic> {
        self.diagnostics.get(&id).map(|r| r.clone())
    }

    /// Gets all diagnostics for a file
    pub fn by_file(&self, file: &PathBuf) -> Vec<Diagnostic> {
        self.by_file
            .get(file)
            .map(|ids| ids.iter().filter_map(|id| self.get(*id)).collect())
            .unwrap_or_default()
    }

    /// Gets all diagnostics of a severity
    pub fn by_severity(&self, severity: Severity) -> Vec<Diagnostic> {
        self.by_severity
            .get(&severity)
            .map(|ids| ids.iter().filter_map(|id| self.get(*id)).collect())
            .unwrap_or_default()
    }

    /// Gets all diagnostics
    pub fn all(&self) -> Vec<Diagnostic> {
        self.diagnostics.iter().map(|r| r.clone()).collect()
    }

    /// Returns the count of diagnostics
    pub fn count(&self) -> usize {
        self.diagnostics.len()
    }

    /// Returns the count of errors
    pub fn error_count(&self) -> usize {
        self.by_severity(Severity::Error).len()
    }

    /// Returns the count of warnings
    pub fn warning_count(&self) -> usize {
        self.by_severity(Severity::Warning).len()
    }

    /// Returns true if there are any errors
    pub fn has_errors(&self) -> bool {
        self.error_count() > 0
    }

    /// Clears all diagnostics
    pub fn clear(&self) {
        self.diagnostics.clear();
        self.by_file.clear();
        self.by_severity.clear();
    }
}

impl Default for DiagnosticAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostic_creation() {
        let diag = Diagnostic::new(1, Severity::Error, "E0001", "test error")
            .note("this is a note")
            .help("try this instead");

        assert_eq!(diag.id, 1, "Diagnostic should have correct ID");
        assert_eq!(
            diag.severity,
            Severity::Error,
            "Diagnostic should have Error severity"
        );
        assert_eq!(diag.code, "E0001", "Diagnostic should have correct code");
        assert_eq!(
            diag.message, "test error",
            "Diagnostic should have correct message"
        );
        assert_eq!(diag.notes.len(), 1, "Diagnostic should have one note");
        assert_eq!(
            diag.helps.len(),
            1,
            "Diagnostic should have one help message"
        );
    }

    #[test]
    fn test_source_location() {
        let loc = SourceLocation::new(PathBuf::from("test.rs"), 10)
            .with_column(5)
            .with_function("main".to_string());

        assert_eq!(
            loc.line, 10,
            "Source location should have correct line number"
        );
        assert_eq!(
            loc.column,
            Some(5),
            "Source location should have correct column"
        );
        assert_eq!(
            loc.function,
            Some("main".to_string()),
            "Source location should have correct function name"
        );
    }

    #[test]
    fn test_aggregator() {
        let aggregator = DiagnosticAggregator::new();

        let diag1 = Diagnostic::new(0, Severity::Error, "E0001", "error 1");
        let diag2 = Diagnostic::new(0, Severity::Warning, "W0001", "warning 1");

        let id1 = aggregator.emit(diag1);
        let id2 = aggregator.emit(diag2);

        assert_ne!(
            id1, id2,
            "Aggregator should assign different IDs to different diagnostics"
        );
        assert_eq!(
            aggregator.count(),
            2,
            "Aggregator should contain two diagnostics"
        );
        assert_eq!(
            aggregator.error_count(),
            1,
            "Aggregator should have one error"
        );
        assert_eq!(
            aggregator.warning_count(),
            1,
            "Aggregator should have one warning"
        );
        assert!(
            aggregator.has_errors(),
            "Aggregator should report that it has errors"
        );
    }

    #[test]
    fn test_aggregator_by_file() {
        let aggregator = DiagnosticAggregator::new();
        let file = PathBuf::from("test.rs");

        let diag = Diagnostic::new(0, Severity::Error, "E0001", "error")
            .with_location(SourceLocation::new(file.clone(), 10));

        aggregator.emit(diag);

        let diags = aggregator.by_file(&file);
        assert_eq!(
            diags.len(),
            1,
            "Aggregator should return one diagnostic for the file"
        );
    }

    #[test]
    fn test_severity_checks() {
        assert!(
            Severity::Error.is_error(),
            "Error severity should be recognized as error"
        );
        assert!(
            !Severity::Error.is_warning(),
            "Error severity should not be recognized as warning"
        );
        assert!(
            !Severity::Warning.is_error(),
            "Warning severity should not be recognized as error"
        );
        assert!(
            Severity::Warning.is_warning(),
            "Warning severity should be recognized as warning"
        );
    }
}
