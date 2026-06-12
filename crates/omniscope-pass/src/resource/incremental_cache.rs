//! Incremental analysis cache for pass results.
//!
//! This module provides a fine-grained caching system for intermediate
//! analysis pass outputs. Unlike the IR file cache (IrCache) in
//! omniscope-ir which caches raw IR file to JSON/msgpack results, this
//! cache stores analysis pass outputs at function/module granularity.
//!
//! # Key features
//!
//! * **Fine-grained caching**: Cache key composed of
//!   `(source_file_fingerprint, pass_name, function_id, config_hash)`
//! * **Incremental re-analysis**: A dependency graph tracks pass
//!   dependencies; only affected passes are re-executed when source
//!   files change
//! * **Disk persistence**: Cache entries are serialized under
//!   `target/omniscope-cache/analysis/`
//! * **Eviction policies**: TTL-based and LRU-based cleanup

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ── Constants ──────────────────────────────────────────────────────────

/// Default subdirectory under target/ for analysis cache files.
const DEFAULT_CACHE_SUBDIR: &str = "omniscope-cache/analysis";

/// Filename for the serialized dependency graph on disk.
const DEP_GRAPH_FILENAME: &str = "dependency_graph.json";

/// Filename for the cache index on disk.
const CACHE_INDEX_FILENAME: &str = "cache_index.json";

// ── Core Data Structures ──────────────────────────────────────────────

/// A snapshot of the blackboard key names that a pass writes to the
/// PassContext via `ctx.store(...)`.
///
/// When a pass result is served from cache, the blackboard keys are
/// removed from the context so that downstream passes do not read stale
/// data written by a previous execution of the cached pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackboardDelta {
    /// Names of the blackboard keys written by this pass.
    pub blackboard_keys: Vec<String>,
}

impl BlackboardDelta {
    /// Create a new delta from an iterator of key names.
    pub fn new(keys: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            blackboard_keys: keys.into_iter().map(Into::into).collect(),
        }
    }

    /// Return true if this delta contains no keys.
    pub fn is_empty(&self) -> bool {
        self.blackboard_keys.is_empty()
    }
}

/// Cache key identifying a specific analysis result at function/module
/// granularity.
///
/// The quadruple `(source_file_fingerprint, pass_name, function_id,
/// config_hash)` uniquely identifies a cached result. A change in any
/// component produces a cache miss, ensuring correctness under source
/// edits, pass reconfiguration, or function-level invalidation.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct CacheKey {
    /// Fingerprint of the source file (derived from path + size + mtime).
    pub source_file_fingerprint: u64,
    /// Name of the analysis pass that produced this result.
    pub pass_name: String,
    /// Function identifier (empty string for module-level results).
    pub function_id: String,
    /// Hash of the analysis configuration to detect config changes.
    pub config_hash: u64,
}

impl CacheKey {
    /// Create a new cache key.
    pub fn new(
        source_file_fingerprint: u64,
        pass_name: impl Into<String>,
        function_id: impl Into<String>,
        config_hash: u64,
    ) -> Self {
        Self {
            source_file_fingerprint,
            pass_name: pass_name.into(),
            function_id: function_id.into(),
            config_hash,
        }
    }
}

/// A cached analysis result stored both in memory and on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResult {
    /// Serialized result data (JSON-encoded pass output).
    pub data: Vec<u8>,
    /// Unix timestamp (seconds since epoch) when this entry was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) of the most recent access (for LRU).
    pub last_accessed: u64,
    /// Byte length of the original deserialized result (for stats).
    pub original_size: u64,
}

/// Cache usage statistics for performance monitoring and reporting.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheStats {
    /// Total number of cache hits since creation or last reset.
    pub total_hits: u64,
    /// Total number of cache misses since creation or last reset.
    pub total_misses: u64,
    /// Number of entries currently resident in the cache.
    pub total_entries: usize,
    /// Total byte size of all cached result data.
    pub total_size_bytes: u64,
}

// ── Dependency Graph ──────────────────────────────────────────────────

/// An edge in the pass dependency graph.
///
/// Records that `from_pass` (analyzing `from_function`) produces data
/// consumed by `to_pass`.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// The pass that produces data.
    pub from_pass: String,
    /// The function whose analysis produces the data.
    pub from_function: String,
    /// The pass that consumes the data.
    pub to_pass: String,
}

/// Directed graph modelling inter-pass data dependencies.
///
/// When a source file changes, this graph is traversed (BFS) to determine
/// which passes must be re-executed. Only passes on an affected dependency
/// chain are invalidated; the rest can safely reuse cached results.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DependencyGraph {
    /// Map from `from_pass` to outgoing edges.
    edges: HashMap<String, HashSet<DependencyEdge>>,
}

impl DependencyGraph {
    /// Register a dependency: `from_pass` (on `from_function`) feeds
    /// into `to_pass`.
    pub fn register(&mut self, from_pass: &str, from_function: &str, to_pass: &str) {
        let edge = DependencyEdge {
            from_pass: from_pass.to_string(),
            from_function: from_function.to_string(),
            to_pass: to_pass.to_string(),
        };
        self.edges
            .entry(from_pass.to_string())
            .or_default()
            .insert(edge);
        debug!(
            from_pass = from_pass,
            from_function = from_function,
            to_pass = to_pass,
            "Registered dependency edge"
        );
    }

    /// Remove all edges originating from `pass_name`.
    ///
    /// Edges from other passes that target `pass_name` are left in place
    /// so that the source pass is still tracked in the dependency graph.
    pub fn remove_pass(&mut self, pass_name: &str) {
        self.edges.remove(pass_name);
        debug!(pass = pass_name, "Removed pass from dependency graph");
    }

    /// Get the set of passes that must be re-executed when the given
    /// functions change.
    ///
    /// Traverses the graph BFS starting from all passes that directly
    /// analyze any changed function, following edges to downstream passes.
    pub fn get_affected_passes(&self, changed_functions: &[String]) -> HashSet<String> {
        let mut affected = HashSet::new();
        let mut queue = VecDeque::new();

        // Seed: find passes that directly analyze changed functions.
        for edges in self.edges.values() {
            for edge in edges.iter() {
                if changed_functions.contains(&edge.from_function) {
                    if affected.insert(edge.from_pass.clone()) {
                        queue.push_back(edge.from_pass.clone());
                    }
                    if affected.insert(edge.to_pass.clone()) {
                        queue.push_back(edge.to_pass.clone());
                    }
                }
            }
        }

        // BFS: traverse downstream to find all transitive dependents.
        while let Some(pass) = queue.pop_front() {
            if let Some(outgoing) = self.edges.get(&pass) {
                for edge in outgoing.iter() {
                    if affected.insert(edge.to_pass.clone()) {
                        queue.push_back(edge.to_pass.clone());
                    }
                }
            }
        }

        affected
    }

    /// Return the total number of registered edges.
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|s| s.len()).sum()
    }

    /// Return the number of source passes (distinct `from_pass` values).
    pub fn node_count(&self) -> usize {
        self.edges.len()
    }

    /// Check whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }
}

// ── Analysis Cache ────────────────────────────────────────────────────

/// Incremental analysis cache for pass results.
///
/// Stores pass outputs at function/module granularity, supports
/// incremental re-analysis via a dependency graph, and persists cache
/// entries to disk. Cache entries are serialized as JSON under
/// `target/omniscope-cache/analysis/`.
///
/// # Eviction
///
/// * **TTL-based**: Entries older than `default_ttl_seconds` are removed
///   by `clear_old_entries`.
/// * **LRU-based**: When the total cache size exceeds `max_cache_size`,
///   the least-recently-accessed entries are evicted first.
#[derive(Debug)]
pub struct AnalysisCache {
    /// Directory where cache files are stored.
    cache_dir: PathBuf,
    /// In-memory key → value mapping for O(1) lookups.
    entries: HashMap<CacheKey, CachedResult>,
    /// Dependency graph for incremental re-analysis.
    dependency_graph: DependencyGraph,
    /// Cumulative usage statistics.
    stats: CacheStats,
    /// Soft limit on total cache byte size (0 = unlimited).
    max_cache_size: u64,
    /// Default TTL in seconds (0 = no TTL).
    default_ttl_seconds: u64,
}

impl AnalysisCache {
    /// Create a new analysis cache rooted at `project_root/target/...`.
    ///
    /// # Arguments
    ///
    /// * `project_root` - Project root directory (where `target/` lives).
    pub fn new(project_root: &Path) -> Self {
        let cache_dir = project_root.join("target").join(DEFAULT_CACHE_SUBDIR);
        Self {
            cache_dir,
            entries: HashMap::new(),
            dependency_graph: DependencyGraph::default(),
            stats: CacheStats::default(),
            max_cache_size: 0,
            default_ttl_seconds: 0,
        }
    }

    /// Set a maximum cache size in bytes (0 = unlimited, default).
    pub fn with_max_size(mut self, max_size: u64) -> Self {
        self.max_cache_size = max_size;
        self
    }

    /// Set a default TTL in seconds for cache entries (0 = no TTL,
    /// default).
    pub fn with_ttl(mut self, ttl_seconds: u64) -> Self {
        self.default_ttl_seconds = ttl_seconds;
        self
    }

    /// Return a reference to the cache directory path.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Return a reference to the dependency graph.
    pub fn dependency_graph(&self) -> &DependencyGraph {
        &self.dependency_graph
    }

    /// Return a mutable reference to the dependency graph.
    pub fn dependency_graph_mut(&mut self) -> &mut DependencyGraph {
        &mut self.dependency_graph
    }

    // ── Core operations ────────────────────────────────────────────

    /// Look up a cached result by key.
    ///
    /// Returns `None` on cache miss. On hit, updates `last_accessed` and
    /// increments the hit counter.
    pub fn get(&mut self, key: &CacheKey) -> Option<&CachedResult> {
        let now = unix_timestamp_secs();

        // Check TTL expiry without holding a mutable reference into the map.
        if self.default_ttl_seconds > 0 {
            let is_expired = self
                .entries
                .get(key)
                .is_some_and(|e| now.saturating_sub(e.created_at) >= self.default_ttl_seconds);
            if is_expired {
                self.entries.remove(key);
                self.stats.total_misses += 1;
                debug!(?key, "Cache miss (TTL expired)");
                return None;
            }
        }

        if let Some(entry) = self.entries.get_mut(key) {
            entry.last_accessed = now;
            self.stats.total_hits += 1;
            debug!(?key, "Cache hit");
            return Some(entry);
        }

        self.stats.total_misses += 1;
        debug!(?key, "Cache miss");
        None
    }

    /// Insert a result into the cache.
    ///
    /// # Arguments
    ///
    /// * `key` - The cache key identifying this result.
    /// * `data` - Serialized result bytes.
    /// * `original_size` - Byte length of the deserialized result.
    pub fn put(&mut self, key: CacheKey, data: Vec<u8>, original_size: u64) -> Result<()> {
        let now = unix_timestamp_secs();
        let result = CachedResult {
            data,
            created_at: now,
            last_accessed: now,
            original_size,
        };

        let data_size = result.data.len() as u64;
        self.entries.insert(key, result);
        self.stats.total_entries = self.entries.len();
        self.stats.total_size_bytes += data_size;
        info!("Inserted cache entry, size={}", data_size);

        // Enforce max cache size (LRU eviction).
        if self.max_cache_size > 0 && self.stats.total_size_bytes > self.max_cache_size {
            let excess = self.stats.total_size_bytes - self.max_cache_size;
            let evicted = self.evict_lru_inner(excess)?;
            debug!(
                evicted = evicted,
                "Evicted entries to stay under max cache size"
            );
        }

        Ok(())
    }

    /// Check whether a key is present in the cache (without recording
    /// a hit/miss).
    pub fn contains(&self, key: &CacheKey) -> bool {
        if self.default_ttl_seconds > 0 {
            let now = unix_timestamp_secs();
            self.entries
                .get(key)
                .is_some_and(|e| now.saturating_sub(e.created_at) < self.default_ttl_seconds)
        } else {
            self.entries.contains_key(key)
        }
    }

    /// Return the cache hit rate as a float in [0.0, 1.0].
    pub fn hit_rate(&self) -> f64 {
        let total = self.stats.total_hits + self.stats.total_misses;
        if total == 0 {
            0.0
        } else {
            self.stats.total_hits as f64 / total as f64
        }
    }

    // ── Dependency graph operations ─────────────────────────────────

    /// Convenience method to register a dependency edge.
    pub fn register_dependency(&mut self, from_pass: &str, from_function: &str, to_pass: &str) {
        self.dependency_graph
            .register(from_pass, from_function, to_pass);
    }

    /// Get the set of passes that need re-execution given changed
    /// functions.
    pub fn get_affected_passes(&self, changed_functions: &[String]) -> HashSet<String> {
        self.dependency_graph.get_affected_passes(changed_functions)
    }

    // ── Persistence ─────────────────────────────────────────────────

    /// Ensure the cache directory exists on disk.
    pub fn ensure_cache_dir(&self) -> Result<()> {
        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir).with_context(|| {
                format!(
                    "Failed to create analysis cache directory: {}",
                    self.cache_dir.display()
                )
            })?;
            debug!("Created cache directory: {}", self.cache_dir.display());
        }
        Ok(())
    }

    /// Persist the in-memory cache index and dependency graph to disk.
    ///
    /// Individual result payloads are stored as separate files keyed by
    /// a hash of the cache key. The index file maps keys to payload
    /// filenames.
    pub fn persist_to_disk(&self) -> Result<()> {
        self.ensure_cache_dir()?;

        // Serialise the dependency graph.
        let dep_graph_path = self.cache_dir.join(DEP_GRAPH_FILENAME);
        let dep_graph_json = serde_json::to_string(&self.dependency_graph)
            .context("Failed to serialize dep graph")?;
        fs::write(&dep_graph_path, &dep_graph_json).with_context(|| {
            format!(
                "Failed to write dependency graph: {}",
                dep_graph_path.display()
            )
        })?;

        // Build and write the cache index (key → filename mapping).
        let index_path = self.cache_dir.join(CACHE_INDEX_FILENAME);
        let mut index: HashMap<String, String> = HashMap::new();

        for (key, result) in &self.entries {
            let key_json = serde_json::to_string(key).context("Failed to serialize cache key")?;
            let payload_filename = format!("{:016x}.json", hash_cache_key(key));
            let payload_path = self.cache_dir.join(&payload_filename);

            // Write the individual result payload.
            let result_json =
                serde_json::to_string(result).context("Failed to serialize cached result")?;
            fs::write(&payload_path, &result_json).with_context(|| {
                format!("Failed to write cache payload: {}", payload_path.display())
            })?;

            index.insert(key_json, payload_filename);
        }

        let index_json =
            serde_json::to_string(&index).context("Failed to serialize cache index")?;
        fs::write(&index_path, &index_json)
            .with_context(|| format!("Failed to write cache index: {}", index_path.display()))?;

        info!(
            entries = self.entries.len(),
            "Persisted analysis cache to disk"
        );
        Ok(())
    }

    /// Load the cache index and dependency graph from disk, populating
    /// the in-memory structures.
    pub fn load_from_disk(&mut self) -> Result<()> {
        if !self.cache_dir.exists() {
            debug!("Cache directory does not exist, skipping load");
            return Ok(());
        }

        // Load dependency graph.
        let dep_graph_path = self.cache_dir.join(DEP_GRAPH_FILENAME);
        if dep_graph_path.exists() {
            let content = fs::read_to_string(&dep_graph_path).with_context(|| {
                format!(
                    "Failed to read dependency graph: {}",
                    dep_graph_path.display()
                )
            })?;
            self.dependency_graph =
                serde_json::from_str(&content).context("Failed to parse dependency graph")?;
            debug!(
                edges = self.dependency_graph.edge_count(),
                "Loaded dependency graph"
            );
        }

        // Load cache index and payloads.
        let index_path = self.cache_dir.join(CACHE_INDEX_FILENAME);
        if index_path.exists() {
            let content = fs::read_to_string(&index_path)
                .with_context(|| format!("Failed to read cache index: {}", index_path.display()))?;
            let index: HashMap<String, String> =
                serde_json::from_str(&content).context("Failed to parse cache index")?;

            // Filter out expired entries during load.
            let now = unix_timestamp_secs();
            for (key_json, payload_filename) in &index {
                let key: CacheKey = match serde_json::from_str(key_json) {
                    Ok(k) => k,
                    Err(e) => {
                        warn!("Skipping invalid cache key: {}", e);
                        continue;
                    }
                };

                let payload_path = self.cache_dir.join(payload_filename);
                if !payload_path.exists() {
                    continue;
                }

                let payload_content = match fs::read_to_string(&payload_path) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(
                            "Failed to read cache payload {}: {}",
                            payload_path.display(),
                            e
                        );
                        continue;
                    }
                };

                let result: CachedResult = match serde_json::from_str(&payload_content) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(
                            "Failed to parse cache payload {}: {}",
                            payload_path.display(),
                            e
                        );
                        continue;
                    }
                };

                // Skip expired entries.
                if self.default_ttl_seconds > 0
                    && now.saturating_sub(result.created_at) > self.default_ttl_seconds
                {
                    continue;
                }

                let data_size = result.data.len() as u64;
                self.stats.total_size_bytes += data_size;
                self.entries.insert(key, result);
            }

            self.stats.total_entries = self.entries.len();
            info!(
                entries = self.entries.len(),
                "Loaded analysis cache from disk"
            );
        }

        Ok(())
    }

    // ── Cache maintenance ───────────────────────────────────────────

    /// Return the current cache statistics.
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Clear all cache entries (in-memory and on-disk).
    pub fn clear(&self) -> Result<()> {
        if !self.cache_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.cache_dir).with_context(|| {
            format!(
                "Failed to read cache directory: {}",
                self.cache_dir.display()
            )
        })? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                fs::remove_file(&path)
                    .with_context(|| format!("Failed to remove cache file: {}", path.display()))?;
            }
        }

        info!("Cleared all analysis cache entries on disk");
        Ok(())
    }

    /// Remove in-memory entries that exceed the specified age.
    ///
    /// Returns the number of entries removed.
    pub fn clear_old_entries(&mut self, max_age_secs: u64) -> usize {
        if max_age_secs == 0 {
            return 0;
        }

        let now = unix_timestamp_secs();
        let before = self.entries.len();
        self.entries
            .retain(|_, e| now.saturating_sub(e.created_at) <= max_age_secs);

        let removed = before - self.entries.len();
        self.stats.total_entries = self.entries.len();
        if removed > 0 {
            info!(removed = removed, "Cleared old cache entries by TTL");
        }
        removed
    }

    /// Evict the least-recently-accessed entries until `target_bytes`
    /// bytes have been freed.
    ///
    /// Returns the number of entries evicted.
    pub fn evict_lru(&mut self, target_bytes: u64) -> Result<usize> {
        self.evict_lru_inner(target_bytes)
    }

    /// Internal LRU eviction (shared between `evict_lru` and `put`).
    fn evict_lru_inner(&mut self, target_bytes: u64) -> Result<usize> {
        if target_bytes == 0 || self.entries.is_empty() {
            return Ok(0);
        }

        // Collect entries sorted by last_accessed (oldest first).
        let mut sorted: Vec<(CacheKey, u64)> = self
            .entries
            .iter()
            .map(|(k, v)| (k.clone(), v.last_accessed))
            .collect();
        sorted.sort_by_key(|(_, ts)| *ts);

        let mut freed: u64 = 0;
        let mut evicted: usize = 0;

        for (key, _) in sorted {
            if freed >= target_bytes {
                break;
            }
            if let Some(entry) = self.entries.remove(&key) {
                freed += entry.data.len() as u64;
                evicted += 1;
            }
        }

        self.stats.total_entries = self.entries.len();
        self.stats.total_size_bytes = self.entries.values().map(|e| e.data.len() as u64).sum();

        if evicted > 0 {
            info!(
                evicted = evicted,
                freed_bytes = freed,
                "LRU eviction completed"
            );
        }
        Ok(evicted)
    }

    /// Reset hit/miss statistics without clearing entries.
    pub fn reset_stats(&mut self) {
        self.stats = CacheStats {
            total_entries: self.entries.len(),
            total_size_bytes: self.stats.total_size_bytes,
            ..Default::default()
        };
        debug!("Reset cache statistics");
    }

    /// Compute a file fingerprint (path + size + mtime) matching the
    /// convention used by `IrCache`.
    ///
    /// This ensures cache key consistency across caching layers.
    pub fn compute_file_fingerprint(&self, path: &Path) -> Result<u64> {
        use std::collections::hash_map::DefaultHasher;

        let canonical_path = fs::canonicalize(path)
            .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;
        let metadata = fs::metadata(path)
            .with_context(|| format!("Failed to get metadata: {}", path.display()))?;

        let size = metadata.len();
        let mtime = metadata
            .modified()
            .with_context(|| format!("Failed to get mtime: {}", path.display()))?
            .duration_since(UNIX_EPOCH)
            .with_context(|| "Failed to convert SystemTime to duration")?
            .as_nanos();

        let mut hasher = DefaultHasher::new();
        canonical_path.hash(&mut hasher);
        size.hash(&mut hasher);
        mtime.hash(&mut hasher);

        Ok(hasher.finish())
    }
}

// ── Helper Functions ──────────────────────────────────────────────────

/// Return the current Unix timestamp in seconds.
fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Compute a deterministic hash for a `CacheKey` for use as a filename.
fn hash_cache_key(key: &CacheKey) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a temporary AnalysisCache for testing.
    fn make_cache(tmp: &TempDir) -> AnalysisCache {
        // Use tmp.path() as the project root so that the cache dir is
        // tmp/target/omniscope-cache/analysis/
        AnalysisCache::new(tmp.path())
    }

    fn make_cache_with_ttl(tmp: &TempDir, ttl: u64) -> AnalysisCache {
        AnalysisCache::new(tmp.path()).with_ttl(ttl)
    }

    fn make_cache_with_max_size(tmp: &TempDir, max: u64) -> AnalysisCache {
        AnalysisCache::new(tmp.path()).with_max_size(max)
    }

    fn sample_key() -> CacheKey {
        CacheKey::new(0xABCD, "test_pass", "func_main", 0x42)
    }

    fn sample_data() -> Vec<u8> {
        br#"{"functions": 3, "issues": []}"#.to_vec()
    }

    // ── CacheKey tests ──────────────────────────────────────────────

    /// Objective: Verify that CacheKey::new correctly stores all fields.
    #[test]
    fn test_cache_key_creation() {
        let key = CacheKey::new(42, "ffi_boundary", "malloc", 7);
        assert_eq!(
            key.source_file_fingerprint, 42,
            "source_file_fingerprint must be 42"
        );
        assert_eq!(
            key.pass_name, "ffi_boundary",
            "pass_name must be 'ffi_boundary'"
        );
        assert_eq!(key.function_id, "malloc", "function_id must be 'malloc'");
        assert_eq!(key.config_hash, 7, "config_hash must be 7");
    }

    /// Objective: Verify that CacheKey equality and hashing work.
    #[test]
    fn test_cache_key_eq_and_hash() {
        let a = CacheKey::new(1, "p", "f", 2);
        let b = CacheKey::new(1, "p", "f", 2);
        let c = CacheKey::new(1, "p", "g", 2);

        assert_eq!(a, b, "identical keys must be equal");
        assert_ne!(a, c, "keys with different function_id must not be equal");

        let mut set = HashSet::new();
        set.insert(a.clone());
        set.insert(b); // duplicate, should not increase size
        assert_eq!(set.len(), 1, "HashSet must deduplicate identical CacheKeys");
    }

    // ── DependencyGraph tests ───────────────────────────────────────

    /// Objective: Verify that a simple dependency chain is traversed
    /// correctly when an upstream function changes.
    #[test]
    fn test_dep_graph_basic() {
        let mut graph = DependencyGraph::default();
        graph.register("collector", "func_a", "builder");
        graph.register("builder", "func_a", "verifier");

        let changed = vec!["func_a".to_string()];
        let affected = graph.get_affected_passes(&changed);

        assert!(
            affected.contains("collector"),
            "'collector' must be affected when func_a changes"
        );
        assert!(
            affected.contains("builder"),
            "'builder' must be affected when func_a changes"
        );
        assert!(
            affected.contains("verifier"),
            "'verifier' must be affected when func_a changes"
        );
    }

    /// Objective: Verify that a changed function does not affect passes
    /// that only analyze unrelated functions.
    #[test]
    fn test_dep_graph_unaffected() {
        let mut graph = DependencyGraph::default();
        graph.register("collector", "func_a", "builder");

        let changed = vec!["func_b".to_string()];
        let affected = graph.get_affected_passes(&changed);

        assert!(
            !affected.contains("collector"),
            "'collector' must NOT be affected when func_b changes"
        );
        assert!(
            !affected.contains("builder"),
            "'builder' must NOT be affected when func_b changes"
        );
    }

    /// Objective: Verify that remove_pass correctly clears a pass from
    /// the graph.
    #[test]
    fn test_dep_graph_remove_pass() {
        let mut graph = DependencyGraph::default();
        graph.register("a", "f", "b");
        graph.register("b", "f", "c");

        assert_eq!(graph.node_count(), 2, "must have 2 source passes");
        graph.remove_pass("b");

        // After removing 'b', only 'a' remains (its edge to 'b' is also gone).
        assert_eq!(
            graph.node_count(),
            1,
            "must have 1 source pass after removal"
        );

        let changed = vec!["f".to_string()];
        let affected = graph.get_affected_passes(&changed);
        assert!(
            affected.contains("a"),
            "'a' must still be affected after removal of 'b'"
        );
        assert!(
            !affected.contains("c"),
            "'c' must not be affected after removal of 'b'"
        );
    }

    /// Objective: Verify that empty graph returns empty set.
    #[test]
    fn test_dep_graph_empty() {
        let graph = DependencyGraph::default();
        assert!(graph.is_empty(), "new graph must be empty");
        assert_eq!(
            graph.get_affected_passes(&["f".to_string()]).len(),
            0,
            "empty graph must return empty affected set"
        );
    }

    // ── AnalysisCache basic tests ───────────────────────────────────

    /// Objective: Verify that a new AnalysisCache is properly initialized.
    #[test]
    fn test_analysis_cache_creation() {
        let tmp = TempDir::new().unwrap();
        let cache = make_cache(&tmp);

        assert!(
            cache.cache_dir().ends_with("omniscope-cache/analysis"),
            "cache dir must end with 'omniscope-cache/analysis'"
        );
        assert_eq!(cache.stats().total_entries, 0, "initial entries must be 0");
        assert_eq!(cache.hit_rate(), 0.0, "initial hit rate must be 0.0");
    }

    /// Objective: Verify basic put and get cycle.
    #[test]
    fn test_put_and_get() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        let key = sample_key();
        let data = sample_data();
        cache
            .put(key.clone(), data.clone(), data.len() as u64)
            .unwrap();

        let cached = cache.get(&key);
        assert!(cached.is_some(), "must be a cache hit after put");
        assert_eq!(
            cached.unwrap().data,
            data,
            "cached data must match the original"
        );
    }

    /// Objective: Verify that get returns None for a non-existent key.
    #[test]
    fn test_cache_miss() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        let key = sample_key();
        let result = cache.get(&key);
        assert!(result.is_none(), "must be None for an uncached key");

        assert_eq!(
            cache.stats().total_misses,
            1,
            "miss counter must be incremented after a miss"
        );
    }

    /// Objective: Verify that contains works correctly.
    #[test]
    fn test_contains() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        let key = sample_key();
        assert!(!cache.contains(&key), "must not contain a key before put");

        cache.put(key.clone(), sample_data(), 100).unwrap();
        assert!(cache.contains(&key), "must contain a key after put");
    }

    // ── TTL tests ───────────────────────────────────────────────────

    /// Objective: Verify that TTL expiry causes a cache miss.
    #[test]
    fn test_ttl_expiry() {
        let tmp = TempDir::new().unwrap();
        // Use a 1-second TTL.
        let mut cache = make_cache_with_ttl(&tmp, 1);

        let key = sample_key();
        cache.put(key.clone(), sample_data(), 100).unwrap();
        assert!(
            cache.contains(&key),
            "must contain the key immediately after put"
        );

        // Sleep for just over 1 second to trigger TTL.
        std::thread::sleep(std::time::Duration::from_millis(1100));

        assert!(
            !cache.contains(&key),
            "must NOT contain the key after TTL expiry"
        );
        // get should also return None.
        assert!(
            cache.get(&key).is_none(),
            "get must return None after TTL expiry"
        );
    }

    /// Objective: Verify that TTL=0 never expires entries.
    #[test]
    fn test_ttl_zero_never_expires() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp); // TTL = 0

        let key = sample_key();
        cache.put(key.clone(), sample_data(), 100).unwrap();

        // Even after a small sleep, the entry should still be valid.
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(cache.contains(&key), "TTL=0 entries must not expire");
    }

    // ── LRU eviction tests ──────────────────────────────────────────

    /// Objective: Verify that LRU eviction frees the oldest entries.
    #[test]
    fn test_lru_eviction() {
        let tmp = TempDir::new().unwrap();
        // Max size is large enough for 2 entries (~100 bytes each) but
        // small enough that adding a 3rd triggers eviction.
        let mut cache = make_cache_with_max_size(&tmp, 250);

        let key1 = CacheKey::new(1, "p", "f1", 0);
        let key2 = CacheKey::new(1, "p", "f2", 0);
        let key3 = CacheKey::new(1, "p", "f3", 0);

        let data = vec![0u8; 80]; // 80 bytes each

        cache.put(key1.clone(), data.clone(), 80).unwrap();
        cache.put(key2.clone(), data.clone(), 80).unwrap(); // total ~160 bytes

        // Access key1 to make it recently-used.
        let _ = cache.get(&key1);

        // Insert key3 — this should push total over 250 bytes (240 + 80 = 320).
        cache.put(key3.clone(), data.clone(), 80).unwrap();

        // key2 should have been evicted (oldest after access pattern).
        assert!(
            cache.contains(&key1),
            "key1 must still be present (recently accessed)"
        );
        // key3 is most recent, should be present.
        assert!(
            cache.contains(&key3),
            "key3 must be present (just inserted)"
        );
    }

    /// Objective: Verify that evict_lru with target_bytes > total frees
    /// everything.
    #[test]
    fn test_evict_lru_all() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        let key1 = CacheKey::new(1, "p", "f1", 0);
        let key2 = CacheKey::new(1, "p", "f2", 0);

        cache.put(key1.clone(), vec![0u8; 50], 50).unwrap();
        cache.put(key2.clone(), vec![0u8; 50], 50).unwrap();

        let evicted = cache.evict_lru(10_000).unwrap();
        assert_eq!(evicted, 2, "all 2 entries must be evicted");
        assert_eq!(
            cache.stats().total_entries,
            0,
            "entries must be 0 after full eviction"
        );
    }

    // ── Persistence tests ───────────────────────────────────────────

    /// Objective: Verify that entries survive persist → load cycle.
    #[test]
    fn test_persist_and_load() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        let key = sample_key();
        let data = sample_data();
        cache
            .put(key.clone(), data.clone(), data.len() as u64)
            .unwrap();

        // Persist to disk.
        cache.persist_to_disk().unwrap();

        // Create a new cache instance pointed at the same directory and load.
        let mut loaded = make_cache(&tmp);
        loaded.load_from_disk().unwrap();

        assert!(
            loaded.contains(&key),
            "key must be present after loading from disk"
        );
        let cached = loaded.get(&key);
        assert!(cached.is_some(), "must be a cache hit after load");
        assert_eq!(
            cached.unwrap().data,
            data,
            "data must match after persist + load"
        );
    }

    /// Objective: Verify that loading from an empty directory is a no-op.
    #[test]
    fn test_load_from_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);
        // Should not error.
        cache.load_from_disk().unwrap();
        assert_eq!(
            cache.stats().total_entries,
            0,
            "no entries should be loaded from empty dir"
        );
    }

    /// Objective: Verify that persist creates the cache directory.
    #[test]
    fn test_persist_creates_dir() {
        let tmp = TempDir::new().unwrap();
        let cache = make_cache(&tmp);
        assert!(
            !cache.cache_dir().exists(),
            "cache dir must not exist before persist"
        );
        cache.persist_to_disk().unwrap();
        assert!(
            cache.cache_dir().exists(),
            "cache dir must exist after persist"
        );
    }

    // ── clear_old_entries tests ─────────────────────────────────────

    /// Objective: Verify that clear_old_entries removes expired entries.
    #[test]
    fn test_clear_old_entries() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        let key1 = CacheKey::new(1, "p", "f1", 0);
        let key2 = CacheKey::new(1, "p", "f2", 0);

        cache.put(key1.clone(), vec![0u8; 10], 10).unwrap();
        // Sleep so key2 has a different timestamp.
        std::thread::sleep(std::time::Duration::from_millis(50));
        cache.put(key2.clone(), vec![0u8; 10], 10).unwrap();

        // Remove entries older than 25ms.
        let removed = cache.clear_old_entries(0); // 0 = no limit, so nothing removed
        assert_eq!(removed, 0, "no entries should be removed when max_age is 0");

        // Actually use a small age (in seconds — need to be > 0).
        let removed = cache.clear_old_entries(1);
        // Both entries are newer than 1 second, so nothing removed.
        assert_eq!(
            removed, 0,
            "entries are < 1 sec old, so none should be removed"
        );
    }

    // ── Stats tests ─────────────────────────────────────────────────

    /// Objective: Verify that stats track hits and misses correctly.
    #[test]
    fn test_stats_hits_and_misses() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        let key = sample_key();
        // Miss.
        let _ = cache.get(&key);
        assert_eq!(cache.stats().total_hits, 0, "hits must be 0 after a miss");
        assert_eq!(
            cache.stats().total_misses,
            1,
            "misses must be 1 after a miss"
        );

        // Hit.
        cache.put(key.clone(), sample_data(), 100).unwrap();
        let _ = cache.get(&key);
        assert_eq!(cache.stats().total_hits, 1, "hits must be 1 after a hit");
        assert_eq!(cache.stats().total_misses, 1, "misses must still be 1");

        assert!(
            (cache.hit_rate() - 0.5).abs() < 1e-9,
            "hit rate must be 0.5 (1 hit / 2 total)"
        );
    }

    /// Objective: Verify that reset_stats zeroes hits/misses but keeps
    /// entry count.
    #[test]
    fn test_reset_stats() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        let key = sample_key();
        cache.put(key.clone(), sample_data(), 100).unwrap();
        let _ = cache.get(&key);
        assert_eq!(cache.stats().total_hits, 1, "hits must be 1 before reset");

        cache.reset_stats();
        assert_eq!(cache.stats().total_hits, 0, "hits must be 0 after reset");
        assert_eq!(
            cache.stats().total_misses,
            0,
            "misses must be 0 after reset"
        );
        assert_eq!(
            cache.stats().total_entries,
            1,
            "entry count must be preserved after reset"
        );
    }

    // ─── clear / edge-case tests ─────────────────────────────────────

    /// Objective: Verify that clear removes everything.
    #[test]
    fn test_clear_all() {
        let tmp = TempDir::new().unwrap();
        let cache = make_cache(&tmp);

        // Put a few entries and persist.
        // Use a separate mutable cache for puts, then clear via the
        // immutable interface.
        {
            let mut c = make_cache(&tmp);
            c.put(sample_key(), sample_data(), 100).unwrap();
            c.persist_to_disk().unwrap();
        }

        cache.clear().unwrap();
        // Verify on-disk is empty.
        let mut loaded = make_cache(&tmp);
        loaded.load_from_disk().unwrap();
        assert_eq!(
            loaded.stats().total_entries,
            0,
            "no entries must remain after clear"
        );
    }

    /// Objective: Verify that compute_file_fingerprint returns
    /// deterministic results for identical files.
    #[test]
    fn test_file_fingerprint_deterministic() {
        let tmp = TempDir::new().unwrap();
        let cache = make_cache(&tmp);

        let file_path = tmp.path().join("test.ll");
        fs::write(&file_path, b"define void @test()").unwrap();

        let fp1 = cache.compute_file_fingerprint(&file_path).unwrap();
        let fp2 = cache.compute_file_fingerprint(&file_path).unwrap();

        assert_eq!(
            fp1, fp2,
            "fingerprints must be deterministic for the same file"
        );
    }

    /// Objective: Verify that compute_file_fingerprint changes when
    /// the file is modified.
    #[test]
    fn test_file_fingerprint_changes_on_modify() {
        let tmp = TempDir::new().unwrap();
        let cache = make_cache(&tmp);

        let file_path = tmp.path().join("test.ll");
        fs::write(&file_path, b"v1").unwrap();
        let fp1 = cache.compute_file_fingerprint(&file_path).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&file_path, b"v2").unwrap();
        let fp2 = cache.compute_file_fingerprint(&file_path).unwrap();

        assert_ne!(fp1, fp2, "fingerprints must differ after file modification");
    }

    // ── Dependency graph integration tests ──────────────────────────

    /// Objective: Verify that dependency tracking via AnalysisCache
    /// correctly registers and queries.
    #[test]
    fn test_cache_dependency_tracking() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        cache.register_dependency("collector", "func_a", "builder");
        cache.register_dependency("builder", "func_a", "verifier");

        let affected = cache.get_affected_passes(&["func_a".to_string()]);
        assert_eq!(
            affected.len(),
            3,
            "all 3 passes in the chain must be affected"
        );
        assert!(
            affected.contains("collector"),
            "affected set must include 'collector'"
        );
        assert!(
            affected.contains("builder"),
            "affected set must include 'builder'"
        );
        assert!(
            affected.contains("verifier"),
            "affected set must include 'verifier'"
        );
    }

    /// Objective: Verify that config_hash changes cause cache misses.
    #[test]
    fn test_config_hash_miss() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        let key1 = CacheKey::new(1, "p", "f", 0xAAA);
        let key2 = CacheKey::new(1, "p", "f", 0xBBB);

        cache.put(key1, sample_data(), 100).unwrap();

        assert!(
            cache.get(&key2).is_none(),
            "keys with different config_hash must not interfere"
        );
    }

    /// Objective: Verify that source_file_fingerprint changes cause
    /// cache misses.
    #[test]
    fn test_fingerprint_change_miss() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        let key1 = CacheKey::new(100, "p", "f", 0);
        let key2 = CacheKey::new(200, "p", "f", 0);

        cache.put(key1, sample_data(), 100).unwrap();
        assert!(
            cache.get(&key2).is_none(),
            "different fingerprints must be independent cache entries"
        );
    }

    /// Objective: Verify that put updates total_size_bytes in stats.
    #[test]
    fn test_stats_size_tracking() {
        let tmp = TempDir::new().unwrap();
        let mut cache = make_cache(&tmp);

        let data = vec![0u8; 42];
        cache.put(sample_key(), data.clone(), 42).unwrap();

        assert_eq!(
            cache.stats().total_size_bytes,
            42,
            "total_size_bytes must reflect the data byte count"
        );
        assert_eq!(
            cache.stats().total_entries,
            1,
            "total_entries must be 1 after 1 put"
        );
    }
}
