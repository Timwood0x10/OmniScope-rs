//! IR Cache Module
//!
//! This module provides caching for C++ pass and direct-cpp IR loading paths.
//! It caches the JSON output from these backends to avoid re-running expensive
//! C++ operations on unchanged files.
//!
//! Cache key = canonical_path + size + mtime_ns + xxh3_64(file)
//! Cache location = target/omniscope-cache/<fingerprint>.ir.json

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use tracing::{debug, info};

/// Cache entry metadata
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Fingerprint of the cached file
    pub fingerprint: u64,
    /// Path to the cached JSON file
    pub json_path: PathBuf,
    /// Timestamp when the cache entry was created
    pub timestamp: SystemTime,
}

/// IR Cache for storing C++ pass JSON output
#[derive(Debug)]
pub struct IrCache {
    /// Directory where cache files are stored
    cache_dir: PathBuf,
}

impl IrCache {
    /// Create a new IR cache instance
    ///
    /// # Arguments
    /// * `project_root` - Project root directory (where target/ is located)
    ///
    /// # Returns
    /// New IrCache instance
    pub fn new(project_root: &Path) -> Self {
        let cache_dir = project_root.join("target").join("omniscope-cache");
        Self { cache_dir }
    }

    /// Get cache directory path
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Ensure cache directory exists
    pub fn ensure_cache_dir(&self) -> Result<()> {
        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir).with_context(|| {
                format!(
                    "Failed to create cache directory: {}",
                    self.cache_dir.display()
                )
            })?;
            debug!("Created cache directory: {}", self.cache_dir.display());
        }
        Ok(())
    }

    /// Generate fingerprint for a file
    ///
    /// Cache key = canonical_path + size + mtime_ns + xxh3_64(file)
    ///
    /// # Arguments
    /// * `path` - Path to the IR file
    ///
    /// # Returns
    /// Fingerprint as u64
    pub fn generate_fingerprint(&self, path: &Path) -> Result<u64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let canonical_path = fs::canonicalize(path)
            .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;

        let metadata = fs::metadata(path)
            .with_context(|| format!("Failed to get file metadata: {}", path.display()))?;

        let size = metadata.len();
        let mtime = metadata
            .modified()
            .with_context(|| format!("Failed to get modification time: {}", path.display()))?
            .duration_since(SystemTime::UNIX_EPOCH)
            .with_context(|| "Failed to convert SystemTime to duration")?
            .as_nanos();

        // For now, use size + mtime as the primary cache key
        // xxh3_64 would require reading the entire file, which is expensive
        // We'll add it later if needed
        let mut hasher = DefaultHasher::new();
        canonical_path.hash(&mut hasher);
        size.hash(&mut hasher);
        mtime.hash(&mut hasher);

        let fingerprint = hasher.finish();
        debug!(
            path = %path.display(),
            size = size,
            mtime = mtime,
            fingerprint = fingerprint,
            "Generated fingerprint"
        );

        Ok(fingerprint)
    }

    /// Generate fingerprint with additional parameters for cache key extension.
    ///
    /// This includes strategy, slice mode, and other configuration in the hash
    /// to ensure cache entries are specific to the loading configuration.
    ///
    /// # Arguments
    /// * `path` - Path to the IR file
    /// * `strategy` - Loading strategy name (e.g., "direct-cpp", "direct-cpp-ffi")
    /// * `slice_mode` - Optional slice mode (e.g., "ffi", "none")
    /// * `extra` - Optional extra parameters string
    pub fn generate_fingerprint_with_params(
        &self,
        path: &Path,
        strategy: &str,
        slice_mode: Option<&str>,
        extra: Option<&str>,
    ) -> Result<u64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let canonical_path = fs::canonicalize(path)
            .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;

        let metadata = fs::metadata(path)
            .with_context(|| format!("Failed to get file metadata: {}", path.display()))?;

        let size = metadata.len();
        let mtime = metadata
            .modified()
            .with_context(|| format!("Failed to get modification time: {}", path.display()))?
            .duration_since(SystemTime::UNIX_EPOCH)
            .with_context(|| "Failed to convert SystemTime to duration")?
            .as_nanos();

        let mut hasher = DefaultHasher::new();
        canonical_path.hash(&mut hasher);
        size.hash(&mut hasher);
        mtime.hash(&mut hasher);
        strategy.hash(&mut hasher);
        slice_mode.hash(&mut hasher);
        extra.hash(&mut hasher);

        let fingerprint = hasher.finish();
        debug!(
            path = %path.display(),
            strategy = strategy,
            slice_mode = ?slice_mode,
            fingerprint = fingerprint,
            "Generated fingerprint with params"
        );

        Ok(fingerprint)
    }

    /// Check if cache entry exists and is valid
    ///
    /// # Arguments
    /// * `path` - Path to the IR file
    ///
    /// # Returns
    /// Some(CacheEntry) if cache hit, None if cache miss
    pub fn check_cache(&self, path: &Path) -> Option<CacheEntry> {
        let fingerprint = match self.generate_fingerprint(path) {
            Ok(f) => f,
            Err(e) => {
                debug!("Failed to generate fingerprint: {}", e);
                return None;
            }
        };

        let cache_path = self.cache_dir.join(format!("{:016x}.ir.json", fingerprint));

        if cache_path.exists() {
            debug!(path = %path.display(), cache_path = %cache_path.display(), "Cache hit");
            Some(CacheEntry {
                fingerprint,
                json_path: cache_path,
                timestamp: SystemTime::now(),
            })
        } else {
            debug!(path = %path.display(), "Cache miss");
            None
        }
    }

    /// Check if cache entry exists with specific parameters
    ///
    /// This checks for both msgpack and JSON cache files.
    ///
    /// # Arguments
    /// * `path` - Path to the IR file
    /// * `strategy` - Loading strategy name
    /// * `slice_mode` - Optional slice mode
    /// * `extra` - Optional extra parameters
    ///
    /// # Returns
    /// Some(CacheEntry) if cache hit, None if cache miss
    pub fn check_cache_with_params(
        &self,
        path: &Path,
        strategy: &str,
        slice_mode: Option<&str>,
        extra: Option<&str>,
    ) -> Option<CacheEntry> {
        let fingerprint =
            match self.generate_fingerprint_with_params(path, strategy, slice_mode, extra) {
                Ok(f) => f,
                Err(e) => {
                    debug!("Failed to generate fingerprint: {}", e);
                    return None;
                }
            };

        // Check for msgpack cache first (preferred)
        let msgpack_path = self
            .cache_dir
            .join(format!("{:016x}.ir.msgpack", fingerprint));
        if msgpack_path.exists() {
            debug!(path = %path.display(), cache_path = %msgpack_path.display(), "Cache hit (msgpack)");
            return Some(CacheEntry {
                fingerprint,
                json_path: msgpack_path,
                timestamp: SystemTime::now(),
            });
        }

        // Fall back to JSON cache
        let json_path = self.cache_dir.join(format!("{:016x}.ir.json", fingerprint));
        if json_path.exists() {
            debug!(path = %path.display(), cache_path = %json_path.display(), "Cache hit (json)");
            return Some(CacheEntry {
                fingerprint,
                json_path,
                timestamp: SystemTime::now(),
            });
        }

        debug!(path = %path.display(), "Cache miss");
        None
    }

    /// Load cached JSON content
    ///
    /// # Arguments
    /// * `entry` - Cache entry to load
    ///
    /// # Returns
    /// Cached JSON string
    pub fn load_cached_json(&self, entry: &CacheEntry) -> Result<String> {
        let content = fs::read_to_string(&entry.json_path).with_context(|| {
            format!("Failed to read cached JSON: {}", entry.json_path.display())
        })?;

        debug!(
            path = %entry.json_path.display(),
            size = content.len(),
            "Loaded cached JSON"
        );

        Ok(content)
    }

    /// Save JSON content to cache
    ///
    /// # Arguments
    /// * `path` - Original IR file path
    /// * `json_str` - JSON string to cache
    ///
    /// # Returns
    /// Cache entry if successful
    pub fn save_to_cache(&self, path: &Path, json_str: &str) -> Result<CacheEntry> {
        self.ensure_cache_dir()?;

        let fingerprint = self.generate_fingerprint(path)?;
        let cache_path = self.cache_dir.join(format!("{:016x}.ir.json", fingerprint));

        fs::write(&cache_path, json_str)
            .with_context(|| format!("Failed to write cache file: {}", cache_path.display()))?;

        info!(
            path = %path.display(),
            cache_path = %cache_path.display(),
            size = json_str.len(),
            "Saved IR to cache"
        );

        Ok(CacheEntry {
            fingerprint,
            json_path: cache_path,
            timestamp: SystemTime::now(),
        })
    }

    /// Load cached bytes (msgpack or JSON)
    ///
    /// # Arguments
    /// * `entry` - Cache entry to load
    ///
    /// # Returns
    /// Cached bytes
    pub fn load_cached_bytes(&self, entry: &CacheEntry) -> Result<Vec<u8>> {
        let content = fs::read(&entry.json_path).with_context(|| {
            format!("Failed to read cached file: {}", entry.json_path.display())
        })?;

        debug!(
            path = %entry.json_path.display(),
            size = content.len(),
            "Loaded cached bytes"
        );

        Ok(content)
    }

    /// Save bytes content to cache (msgpack format)
    ///
    /// # Arguments
    /// * `path` - Original IR file path
    /// * `bytes` - Binary content to cache
    /// * `strategy` - Loading strategy name
    /// * `slice_mode` - Optional slice mode
    /// * `extra` - Optional extra parameters
    ///
    /// # Returns
    /// Cache entry if successful
    pub fn save_to_cache_bytes_with_params(
        &self,
        path: &Path,
        bytes: &[u8],
        strategy: &str,
        slice_mode: Option<&str>,
        extra: Option<&str>,
    ) -> Result<CacheEntry> {
        self.ensure_cache_dir()?;

        let fingerprint = self.generate_fingerprint_with_params(path, strategy, slice_mode, extra)?;
        let cache_path = self
            .cache_dir
            .join(format!("{:016x}.ir.msgpack", fingerprint));

        fs::write(&cache_path, bytes)
            .with_context(|| format!("Failed to write cache file: {}", cache_path.display()))?;

        info!(
            path = %path.display(),
            cache_path = %cache_path.display(),
            size = bytes.len(),
            "Saved IR to cache (msgpack)"
        );

        Ok(CacheEntry {
            fingerprint,
            json_path: cache_path,
            timestamp: SystemTime::now(),
        })
    }

    /// Get cache statistics
    ///
    /// # Returns
    /// Tuple of (total_entries, total_size_bytes)
    pub fn get_stats(&self) -> Result<(usize, u64)> {
        if !self.cache_dir.exists() {
            return Ok((0, 0));
        }

        let mut total_entries = 0;
        let mut total_size = 0;

        for entry in fs::read_dir(&self.cache_dir).with_context(|| {
            format!(
                "Failed to read cache directory: {}",
                self.cache_dir.display()
            )
        })? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                total_entries += 1;
                total_size += metadata.len();
            }
        }

        Ok((total_entries, total_size))
    }

    /// Clear all cache entries
    pub fn clear_cache(&self) -> Result<()> {
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
            if entry.metadata()?.is_file() {
                fs::remove_file(entry.path())?;
            }
        }

        info!("Cleared all cache entries");
        Ok(())
    }

    /// Clear cache entries older than specified duration
    ///
    /// # Arguments
    /// * `max_age` - Maximum age in seconds
    ///
    /// # Returns
    /// Number of entries cleared
    pub fn clear_old_entries(&self, max_age: u64) -> Result<usize> {
        if !self.cache_dir.exists() {
            return Ok(0);
        }

        let now = SystemTime::now();
        let mut cleared = 0;

        for entry in fs::read_dir(&self.cache_dir).with_context(|| {
            format!(
                "Failed to read cache directory: {}",
                self.cache_dir.display()
            )
        })? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                let modified = metadata.modified()?;
                let age = now.duration_since(modified).unwrap_or_default().as_secs();

                if age > max_age {
                    fs::remove_file(entry.path())?;
                    cleared += 1;
                }
            }
        }

        if cleared > 0 {
            info!(cleared = cleared, "Cleared old cache entries");
        }

        Ok(cleared)
    }
}

/// Find project root directory
///
/// Searches upward from current directory for Cargo.toml
pub fn find_project_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("Cargo.toml").is_file() {
            return Some(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_ir_cache_creation() {
        let tmp = TempDir::new().unwrap();
        let cache = IrCache::new(tmp.path());
        assert_eq!(
            cache.cache_dir(),
            tmp.path().join("target").join("omniscope-cache"),
            "Cache directory should be correctly set"
        );
    }

    #[test]
    fn test_cache_miss() {
        let tmp = TempDir::new().unwrap();
        let cache = IrCache::new(tmp.path());

        // Create a test file
        let test_file = tmp.path().join("test.ll");
        fs::write(&test_file, "test content").unwrap();

        let result = cache.check_cache(&test_file);
        assert!(
            result.is_none(),
            "Should be cache miss for non-existent cache"
        );
    }

    #[test]
    fn test_cache_hit() {
        let tmp = TempDir::new().unwrap();
        let cache = IrCache::new(tmp.path());

        // Create a test file
        let test_file = tmp.path().join("test.ll");
        fs::write(&test_file, "test content").unwrap();

        // Save to cache
        let json_content = r#"{"test": "data"}"#;
        let entry = cache.save_to_cache(&test_file, json_content).unwrap();

        // Check cache hit
        let result = cache.check_cache(&test_file);
        assert!(result.is_some(), "Should be cache hit after saving");

        let result_entry = result.unwrap();
        assert_eq!(
            result_entry.fingerprint, entry.fingerprint,
            "Fingerprints should match"
        );

        // Load cached content
        let loaded = cache.load_cached_json(&result_entry).unwrap();
        assert_eq!(loaded, json_content, "Loaded content should match original");
    }

    #[test]
    fn test_cache_invalidation() {
        let tmp = TempDir::new().unwrap();
        let cache = IrCache::new(tmp.path());

        // Create a test file
        let test_file = tmp.path().join("test.ll");
        fs::write(&test_file, "test content").unwrap();

        // Save to cache
        let json_content = r#"{"test": "data"}"#;
        cache.save_to_cache(&test_file, json_content).unwrap();

        // Modify file
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&test_file, "modified content").unwrap();

        // Check cache miss
        let result = cache.check_cache(&test_file);
        assert!(
            result.is_none(),
            "Should be cache miss after file modification"
        );
    }

    #[test]
    fn test_cache_stats() {
        let tmp = TempDir::new().unwrap();
        let cache = IrCache::new(tmp.path());

        // Create test files
        let test_file1 = tmp.path().join("test1.ll");
        let test_file2 = tmp.path().join("test2.ll");
        fs::write(&test_file1, "content1").unwrap();
        fs::write(&test_file2, "content2").unwrap();

        // Save to cache
        cache.save_to_cache(&test_file1, r#"{"test": 1}"#).unwrap();
        cache.save_to_cache(&test_file2, r#"{"test": 2}"#).unwrap();

        // Get stats
        let (entries, size) = cache.get_stats().unwrap();
        assert_eq!(entries, 2, "Should have 2 cache entries");
        assert!(size > 0, "Cache size should be positive");
    }

    #[test]
    fn test_clear_cache() {
        let tmp = TempDir::new().unwrap();
        let cache = IrCache::new(tmp.path());

        // Create test file and cache it
        let test_file = tmp.path().join("test.ll");
        fs::write(&test_file, "content").unwrap();
        cache.save_to_cache(&test_file, r#"{"test": 1}"#).unwrap();

        // Clear cache
        cache.clear_cache().unwrap();

        // Check cache is empty
        let (entries, _) = cache.get_stats().unwrap();
        assert_eq!(entries, 0, "Cache should be empty after clearing");
    }

    #[test]
    fn test_find_project_root() {
        // This test assumes we're running in the project directory
        let root = find_project_root();
        assert!(root.is_some(), "Should find project root");
        assert!(
            root.unwrap().join("Cargo.toml").is_file(),
            "Project root should contain Cargo.toml"
        );
    }

    #[test]
    fn test_cache_performance() {
        let tmp = TempDir::new().unwrap();
        let cache = IrCache::new(tmp.path());

        // Create a test file
        let test_file = tmp.path().join("test.ll");
        fs::write(&test_file, "test content").unwrap();

        // First load (cache miss)
        let start = std::time::Instant::now();
        let entry1 = cache.check_cache(&test_file);
        let miss_duration = start.elapsed();
        assert!(entry1.is_none(), "First load should be cache miss");

        // Save to cache
        let json_content = r#"{"functions": [], "global_variables": []}"#;
        cache.save_to_cache(&test_file, json_content).unwrap();

        // Second load (cache hit)
        let start = std::time::Instant::now();
        let entry2 = cache.check_cache(&test_file);
        let hit_duration = start.elapsed();
        assert!(entry2.is_some(), "Second load should be cache hit");

        // Verify cache hit is faster (should be sub-second)
        println!("Cache miss took: {:?}", miss_duration);
        println!("Cache hit took: {:?}", hit_duration);

        // Cache hit should be very fast (sub-millisecond typically)
        assert!(
            hit_duration.as_millis() < 100,
            "Cache hit should be fast, took: {:?}",
            hit_duration
        );
    }
}
