//! Profiler for OmniScope
//!
//! This module provides performance profiling capabilities for analyzing
//! the time and memory usage of different analysis passes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Unique identifier for profiling spans
pub type SpanId = u64;

/// A profiling span representing a timed operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    /// Unique identifier
    pub id: SpanId,
    /// Span name
    pub name: String,
    /// Start time
    pub start_time: DateTime<Utc>,
    /// Duration
    pub duration: Duration,
    /// Memory allocated (bytes)
    pub memory_bytes: u64,
    /// Parent span ID (if nested)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<SpanId>,
    /// Additional metadata
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl Span {
    /// Creates a new span
    pub fn new(id: SpanId, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            start_time: Utc::now(),
            duration: Duration::ZERO,
            memory_bytes: 0,
            parent_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Adds metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Sets parent span
    pub fn with_parent(mut self, parent_id: SpanId) -> Self {
        self.parent_id = Some(parent_id);
        self
    }
}

/// Memory sample for tracking memory usage over time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySample {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Total memory allocated (bytes)
    pub total_bytes: u64,
    /// Memory in use (bytes)
    pub used_bytes: u64,
}

/// Performance profiler
#[derive(Debug)]
pub struct Profiler {
    /// Completed spans
    spans: DashMap<SpanId, Span>,
    /// Spans by name
    by_name: DashMap<String, Vec<SpanId>>,
    /// Memory samples
    memory_samples: DashMap<DateTime<Utc>, MemorySample>,
    /// Next span ID
    next_id: AtomicU64,
    /// Active spans (for nested profiling)
    active_spans: DashMap<SpanId, (Instant, String)>,
}

use dashmap::DashMap;

impl Profiler {
    /// Creates a new profiler
    pub fn new() -> Self {
        Self {
            spans: DashMap::new(),
            by_name: DashMap::new(),
            memory_samples: DashMap::new(),
            next_id: AtomicU64::new(1),
            active_spans: DashMap::new(),
        }
    }

    /// Starts a new profiling span
    pub fn start_span(&self, name: impl Into<String>) -> SpanId {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let name = name.into();
        self.active_spans.insert(id, (Instant::now(), name));
        id
    }

    /// Starts a nested span
    pub fn start_span_with_parent(&self, name: impl Into<String>, parent_id: SpanId) -> SpanId {
        let id = self.start_span(name);
        if let Some(mut span) = self.spans.get_mut(&id) {
            span.parent_id = Some(parent_id);
        }
        id
    }

    /// Ends a profiling span
    pub fn end_span(&self, id: SpanId) {
        if let Some((_, (start, name))) = self.active_spans.remove(&id) {
            let duration = start.elapsed();

            let mut span = Span::new(id, name);
            span.duration = duration;

            // Index by name
            self.by_name.entry(span.name.clone()).or_default().push(id);

            // Store span
            self.spans.insert(id, span);
        }
    }

    /// Records a memory sample
    pub fn record_memory(&self, total_bytes: u64, used_bytes: u64) {
        let timestamp = Utc::now();
        let sample = MemorySample {
            timestamp,
            total_bytes,
            used_bytes,
        };
        self.memory_samples.insert(timestamp, sample);
    }

    /// Gets a span by ID
    pub fn get_span(&self, id: SpanId) -> Option<Span> {
        self.spans.get(&id).map(|r| r.clone())
    }

    /// Gets all spans with a given name
    pub fn spans_by_name(&self, name: &str) -> Vec<Span> {
        self.by_name
            .get(name)
            .map(|ids| ids.iter().filter_map(|id| self.get_span(*id)).collect())
            .unwrap_or_default()
    }

    /// Gets all spans
    pub fn all_spans(&self) -> Vec<Span> {
        self.spans.iter().map(|r| r.clone()).collect()
    }

    /// Gets all memory samples
    pub fn memory_history(&self) -> Vec<MemorySample> {
        let mut samples: Vec<_> = self.memory_samples.iter().map(|r| r.clone()).collect();
        samples.sort_by_key(|a| a.timestamp);
        samples
    }

    /// Returns total profiling time
    pub fn total_time(&self) -> Duration {
        self.all_spans()
            .iter()
            .filter(|s| s.parent_id.is_none())
            .map(|s| s.duration)
            .sum()
    }

    /// Returns statistics for a span name
    pub fn stats(&self, name: &str) -> Option<SpanStats> {
        let spans = self.spans_by_name(name);
        if spans.is_empty() {
            return None;
        }

        let count = spans.len();
        let total: Duration = spans.iter().map(|s| s.duration).sum();
        let avg = total / count as u32;
        let max = spans.iter().map(|s| s.duration).max().unwrap_or_default();
        let min = spans.iter().map(|s| s.duration).min().unwrap_or_default();

        Some(SpanStats {
            name: name.to_string(),
            count,
            total,
            avg,
            max,
            min,
        })
    }

    /// Clears all profiling data
    pub fn clear(&self) {
        self.spans.clear();
        self.by_name.clear();
        self.memory_samples.clear();
        self.active_spans.clear();
    }
}

impl Default for Profiler {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for a set of spans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanStats {
    /// Span name
    pub name: String,
    /// Number of occurrences
    pub count: usize,
    /// Total duration
    pub total: Duration,
    /// Average duration
    pub avg: Duration,
    /// Maximum duration
    pub max: Duration,
    /// Minimum duration
    pub min: Duration,
}

/// RAII guard for scoped timing
pub struct ScopedTimer<'a> {
    /// Profiler reference
    profiler: &'a Profiler,
    /// Span ID
    span_id: SpanId,
}

impl<'a> ScopedTimer<'a> {
    /// Creates a new scoped timer
    pub fn new(profiler: &'a Profiler, name: &'static str) -> Self {
        let span_id = profiler.start_span(name);
        Self { profiler, span_id }
    }
}

impl<'a> Drop for ScopedTimer<'a> {
    fn drop(&mut self) {
        self.profiler.end_span(self.span_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_profiler_basic() {
        let profiler = Profiler::new();

        let id = profiler.start_span("test");
        thread::sleep(Duration::from_millis(10));
        profiler.end_span(id);

        let spans = profiler.spans_by_name("test");
        assert_eq!(spans.len(), 1);
        assert!(spans[0].duration >= Duration::from_millis(10));
    }

    #[test]
    fn test_scoped_timer() {
        let profiler = Profiler::new();

        {
            let _timer = ScopedTimer::new(&profiler, "scoped");
            thread::sleep(Duration::from_millis(10));
        }

        let spans = profiler.spans_by_name("scoped");
        assert_eq!(spans.len(), 1);
    }

    #[test]
    fn test_profiler_stats() {
        let profiler = Profiler::new();

        for _ in 0..3 {
            let id = profiler.start_span("test");
            thread::sleep(Duration::from_millis(5));
            profiler.end_span(id);
        }

        let stats = profiler.stats("test").unwrap();
        assert_eq!(stats.count, 3);
        assert!(stats.avg >= Duration::from_millis(5));
    }

    #[test]
    fn test_memory_recording() {
        let profiler = Profiler::new();

        profiler.record_memory(1024, 512);
        profiler.record_memory(2048, 1024);

        let history = profiler.memory_history();
        assert_eq!(history.len(), 2);
    }
}
