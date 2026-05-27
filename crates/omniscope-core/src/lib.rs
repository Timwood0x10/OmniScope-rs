//! OmniScope Core - Foundation infrastructure for static analysis
//!
//! This crate provides the core infrastructure components used throughout
//! the OmniScope static analyzer, including:
//!
//! - Error handling and result types
//! - Diagnostic aggregation and reporting
//! - Fact storage for analysis findings
//! - Memory pooling for efficient allocation
//! - Performance profiling
//!
//! # Example
//!
//! ```rust
//! use omniscope_core::{DiagnosticAggregator, Diagnostic, Severity, SourceLocation};
//! use std::path::PathBuf;
//!
//! let aggregator = DiagnosticAggregator::new();
//!
//! let diag = Diagnostic::new(0, Severity::Warning, "W0001", "potential null pointer")
//!     .with_location(SourceLocation::new(PathBuf::from("test.rs"), 10));
//!
//! let id = aggregator.emit(diag);
//! assert!(aggregator.has_errors() == false);
//! ```

pub mod diagnostics;
pub mod error;
pub mod fact;
pub mod issue;
pub mod issue_candidate;
pub mod memory_pool;
pub mod profiler;
pub mod risk_score;
pub mod terminal_report;

// Re-exports for convenience
pub use diagnostics::{Diagnostic, DiagnosticAggregator, DiagnosticId, Severity, SourceLocation};
pub use error::{AnalysisError, ConfigError, DiagnosticError, IRLoadError, OmniScopeError, Result};
pub use fact::{Fact, FactId, FactKind, FactLocation, FactStore};
pub use issue::{
    BoundaryKind, Confidence, FFIBoundary, Issue, IssueId, IssueKind, IssueLocation, TraceEntry,
};
pub use issue_candidate::{CandidateId, IssueCandidate};
pub use memory_pool::MemoryPool;
pub use profiler::{MemorySample, Profiler, ScopedTimer, Span, SpanId, SpanStats};
pub use terminal_report::{
    format_language_arrow, format_verdict_badge, language_label, TerminalReporter,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_integration() {
        // Test error handling
        let err = OmniScopeError::Config(ConfigError::MissingRequired {
            key: "test".to_string(),
        });
        assert!(err.to_string().contains("Missing required configuration"));

        // Test diagnostics
        let aggregator = DiagnosticAggregator::new();
        let diag = Diagnostic::new(0, Severity::Error, "E0001", "test error");
        aggregator.emit(diag);
        assert!(aggregator.has_errors());

        // Test facts
        let fact_store = FactStore::new();
        let fact = Fact::new(
            0,
            FactKind::AllocSite,
            fact::FactLocation::new(std::path::PathBuf::from("test.rs"), 10),
        );
        fact_store.add(fact);
        assert_eq!(fact_store.count(), 1);

        // Test profiler
        let profiler = Profiler::new();
        {
            let _timer = ScopedTimer::new(&profiler, "test");
        }
        assert_eq!(profiler.all_spans().len(), 1);
    }
}
