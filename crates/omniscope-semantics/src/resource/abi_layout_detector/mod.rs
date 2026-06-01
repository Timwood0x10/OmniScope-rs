//! ABI Layout Detector — Detects struct padding, alignment, and ABI compatibility issues.
//!
//! This module analyzes IR struct definitions to identify potential ABI-related
//! safety issues including:
//!
//! 1. **Struct Padding**: Detects unnecessary padding bytes between fields
//! 2. **Alignment Issues**: Identifies fields with suboptimal alignment
//! 3. **Field Ordering**: Checks for suboptimal field ordering that causes padding
//! 4. **Cross-Language ABI**: Detects ABI mismatches between different languages
//! 5. **Endianness Issues**: Detects potential endianness issues in cross-platform code
//! 6. **Bitfield Layout Issues**: Detects bitfield layout issues in packed structs
//!
//! # Examples
//!
//! ```rust
//! use omniscope_semantics::resource::abi_layout_detector::AbiLayoutDetector;
//!
//! let ir = r#"
//!   %struct.MyStruct = type { i8, i32 }
//!   define void @test_padding() {
//!     %s = alloca %struct.MyStruct
//!     ret void
//!   }
//! "#;
//!
//! let detector = AbiLayoutDetector::new();
//! let issues = detector.detect_issues(ir);
//! assert!(!issues.is_empty(), "Should detect padding issue");
//! ```

mod detector;
mod types;

#[cfg(test)]
mod tests;

// Re-export public types
pub use detector::AbiLayoutDetector;
pub use types::{AbiIssue, LanguageAbiRules, StructField, StructLayout};
