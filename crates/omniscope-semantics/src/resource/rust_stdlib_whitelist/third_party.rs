//! Third-party crate function whitelist
//!
//! This module contains the whitelist for common Rust third-party crate functions
//! including serde, tokio, anyhow, thiserror, tracing, rayon, crossbeam,
//! bytes, regex, chrono, and reqwest.

use super::{RustStdlibWhitelist, WhitelistCategory};

impl RustStdlibWhitelist {
    /// Populates the whitelist with common third-party crate functions.
    ///
    /// # Objective
    /// Add functions from widely-used Rust ecosystem crates that are known
    /// to be safe from memory safety perspective. These crates are
    /// maintained by the Rust community and follow Rust's safety guarantees.
    ///
    /// # Invariants
    /// - All functions use Rust mangled names for precision.
    /// - Functions are organized by crate and semantic category.
    /// - Only functions with proven safety are included.
    /// - This method is called once during initialization.
    ///
    /// # Supported Crates
    /// - serde: serialization/deserialization (data transformation)
    /// - tokio: async runtime (task scheduling, not memory management)
    /// - anyhow/thiserror: error handling (control flow)
    /// - tracing: logging/tracing (observability)
    /// - rayon: parallel iterators (parallel processing)
    /// - crossbeam: concurrency primitives (thread-safe communication)
    /// - bytes: byte buffer management (container operations)
    /// - regex: regular expressions (pattern matching)
    /// - chrono: time operations (utility functions)
    /// - reqwest: HTTP client (I/O operations)
    pub fn populate_common_crates(&mut self) {
        // ============================================================
        // Section 1: Serde serialization/deserialization
        // Serde provides data transformation between formats.
        // These operations do not transfer memory ownership.
        // All serde functions are safe data transformations.
        // ============================================================
        self.add_function(
            "_ZN5serde10Serialize9serialize",
            WhitelistCategory::Serialization,
            false,
            "serde::Serialize::serialize() - Serializes value",
        );
        self.add_function(
            "_ZN5serde12Deserialize11deserialize",
            WhitelistCategory::Serialization,
            false,
            "serde::Deserialize::deserialize() - Deserializes value",
        );
        self.add_function(
            "_ZN5serde3ser14Serializer14serialize_bool",
            WhitelistCategory::Serialization,
            false,
            "Serializer::serialize_bool() - Serializes boolean",
        );
        self.add_function(
            "_ZN5serde3ser14Serializer14serialize_i32",
            WhitelistCategory::Serialization,
            false,
            "Serializer::serialize_i32() - Serializes i32",
        );
        self.add_function(
            "_ZN5serde3ser14Serializer15serialize_str",
            WhitelistCategory::Serialization,
            false,
            "Serializer::serialize_str() - Serializes string",
        );

        // ============================================================
        // Section 2: Tokio async runtime
        // Tokio provides async task scheduling and I/O operations.
        // These functions manage tasks, not memory ownership.
        // All tokio functions are safe runtime operations.
        // ============================================================
        self.add_function(
            "_ZN5tokio4task5spawn",
            WhitelistCategory::AsyncRuntime,
            false,
            "tokio::task::spawn() - Spawns async task",
        );
        self.add_function(
            "_ZN5tokio4task6spawn_blocking",
            WhitelistCategory::AsyncRuntime,
            false,
            "tokio::task::spawn_blocking() - Spawns blocking task",
        );
        self.add_function(
            "_ZN5tokio4task5yield_now",
            WhitelistCategory::AsyncRuntime,
            false,
            "tokio::task::yield_now() - Yields execution",
        );
        self.add_function(
            "_ZN5tokio5timer5sleep",
            WhitelistCategory::AsyncRuntime,
            false,
            "tokio::timer::sleep() - Sleeps for duration",
        );
        self.add_function(
            "_ZN5tokio5timer7timeout",
            WhitelistCategory::AsyncRuntime,
            false,
            "tokio::timer::timeout() - Adds timeout to future",
        );
        self.add_function(
            "_ZN5tokio2io5AsyncRead4read",
            WhitelistCategory::AsyncRuntime,
            false,
            "AsyncRead::read() - Async read operation",
        );
        self.add_function(
            "_ZN5tokio2io6AsyncWrite5write",
            WhitelistCategory::AsyncRuntime,
            false,
            "AsyncWrite::write() - Async write operation",
        );

        // ============================================================
        // Section 3: Anyhow error handling
        // Anyhow provides ergonomic error handling with context.
        // These operations are control flow, not resource management.
        // All anyhow functions are safe error handling operations.
        // ============================================================
        self.add_function(
            "_ZN6anyhow5Error3new",
            WhitelistCategory::ErrorHandling,
            false,
            "anyhow::Error::new() - Creates new error",
        );
        self.add_function(
            "_ZN6anyhow5Error7context",
            WhitelistCategory::ErrorHandling,
            false,
            "anyhow::Error::context() - Adds context to error",
        );
        self.add_function(
            "_ZN6anyhow6Result6unwrap",
            WhitelistCategory::ErrorHandling,
            false,
            "anyhow::Result::unwrap() - Unwraps result",
        );

        // ============================================================
        // Section 4: Thiserror derive macro functions
        // Thiserror provides derive macros for error types.
        // ============================================================
        self.add_function(
            "_ZN9thiserror5Error9from_source",
            WhitelistCategory::ErrorHandling,
            false,
            "thiserror::Error::from_source() - Creates error from source",
        );

        // ============================================================
        // Section 5: Log/tracing macros - observability
        // Tracing provides structured logging and span management.
        // These functions are observability utilities, not memory operations.
        // ============================================================
        self.add_function(
            "_ZN5tracing5event5event",
            WhitelistCategory::Utility,
            false,
            "tracing::event!() - Records tracing event",
        );
        self.add_function(
            "_ZN5tracing5span5span",
            WhitelistCategory::Utility,
            false,
            "tracing::span!() - Creates tracing span",
        );

        // ============================================================
        // Section 6: Rayon parallel iterators
        // Rayon provides parallel iteration for data parallelism.
        // These operations are safe parallel processing utilities.
        // ============================================================
        self.add_function(
            "_ZN5rayon4iter8Parallel4for_each",
            WhitelistCategory::Iterator,
            false,
            "rayon::ParallelIterator::for_each() - Parallel iteration",
        );
        self.add_function(
            "_ZN5rayon4iter8Parallel3map",
            WhitelistCategory::Iterator,
            false,
            "rayon::ParallelIterator::map() - Parallel mapping",
        );
        self.add_function(
            "_ZN5rayon4iter8Parallel7collect",
            WhitelistCategory::Iterator,
            false,
            "rayon::ParallelIterator::collect() - Parallel collection",
        );

        // ============================================================
        // Section 7: Crossbeam channel operations
        // Crossbeam provides concurrent communication primitives.
        // These are thread-safe channel operations for message passing.
        // All channel operations are safe concurrent utilities.
        // ============================================================
        // Create channel that fires after specified duration
        self.add_function(
            "_ZN8crossbeam7channel5after",
            WhitelistCategory::ThreadSync,
            false,
            "crossbeam::channel::after() - Creates channel timeout",
        );
        // Create channel that never fires (for blocking indefinitely)
        self.add_function(
            "_ZN8crossbeam7channel5never",
            WhitelistCategory::ThreadSync,
            false,
            "crossbeam::channel::never() - Creates never-ending channel",
        );
        // Create channel that fires at regular intervals
        self.add_function(
            "_ZN8crossbeam7channel4tick",
            WhitelistCategory::ThreadSync,
            false,
            "crossbeam::channel::tick() - Creates tick channel",
        );

        // ============================================================
        // Section 8: Bytes crate - byte buffer management
        // Bytes provides efficient byte buffer operations.
        // These are safe container operations for byte data.
        // ============================================================
        self.add_function(
            "_ZN5bytes6Bytes3new",
            WhitelistCategory::Container,
            false,
            "bytes::Bytes::new() - Creates empty bytes",
        );
        self.add_function(
            "_ZN5bytes6Bytes7with_capacity",
            WhitelistCategory::Container,
            false,
            "bytes::Bytes::with_capacity() - Creates with capacity",
        );

        // ============================================================
        // Section 9: Regex operations - pattern matching
        // Regex provides regular expression pattern matching.
        // These are safe string processing utilities.
        // ============================================================
        self.add_function(
            "_ZN5regex5Regex3new",
            WhitelistCategory::StringOps,
            false,
            "regex::Regex::new() - Compiles regex pattern",
        );
        self.add_function(
            "_ZN5regex5Regex5is_match",
            WhitelistCategory::StringOps,
            false,
            "regex::Regex::is_match() - Tests if string matches",
        );
        // Find first occurrence of regex pattern in string
        self.add_function(
            "_ZN5regex5Regex6find",
            WhitelistCategory::StringOps,
            false,
            "regex::Regex::find() - Finds first match",
        );

        // ============================================================
        // Section 10: Chrono time operations - time management
        // Chrono provides date and time manipulation utilities.
        // These are safe utility functions for time operations.
        // All chrono functions return owned values, no memory transfer.
        // ============================================================
        self.add_function(
            "_ZN5chrono6Utc3now",
            WhitelistCategory::Utility,
            false,
            "chrono::Utc::now() - Gets current UTC time",
        );
        // Create date from year, month, day with validation
        self.add_function(
            "_ZN5chrono9NaiveDate14from_ymd_opt",
            WhitelistCategory::Utility,
            false,
            "chrono::NaiveDate::from_ymd_opt() - Creates date",
        );

        // ============================================================
        // Section 11: Reqwest HTTP client - network I/O
        // Reqwest provides HTTP client operations for network requests.
        // These are safe I/O operations for HTTP communication.
        // Client operations return owned request builders.
        // ============================================================
        // Create new HTTP client with default configuration
        self.add_function(
            "_ZN7reqwest7Client3new",
            WhitelistCategory::IoOps,
            false,
            "reqwest::Client::new() - Creates HTTP client",
        );
        // Create GET request builder for fetching data
        self.add_function(
            "_ZN7reqwest7Client3get",
            WhitelistCategory::IoOps,
            false,
            "reqwest::Client::get() - Creates GET request",
        );
        // Create POST request builder for sending data
        self.add_function(
            "_ZN7reqwest7Client4post",
            WhitelistCategory::IoOps,
            false,
            "reqwest::Client::post() - Creates POST request",
        );
    }
}
