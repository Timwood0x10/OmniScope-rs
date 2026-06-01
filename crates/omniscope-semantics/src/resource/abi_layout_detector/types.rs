//! Data types for ABI layout detection.

use std::fmt;

/// Represents a field in a struct with its type and offset information.
#[derive(Debug, Clone, PartialEq)]
pub struct StructField {
    /// Field name (if available, otherwise index-based)
    pub name: String,
    /// LLVM IR type string (e.g., "i8", "i32", "ptr")
    pub type_str: String,
    /// Byte size of the field
    pub size: usize,
    /// Alignment requirement of the field
    pub alignment: usize,
    /// Offset within the struct (if known)
    pub offset: Option<usize>,
}

/// Represents a complete struct layout with fields and metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct StructLayout {
    /// Struct name (e.g., "struct.MyStruct")
    pub name: String,
    /// Fields in order
    pub fields: Vec<StructField>,
    /// Total size (if known)
    pub total_size: Option<usize>,
    /// Overall alignment
    pub alignment: usize,
    /// Whether the struct is packed (no padding)
    pub packed: bool,
}

/// ABI layout issue detected during analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum AbiIssue {
    /// Struct has padding between fields
    StructPadding {
        struct_name: String,
        padding_bytes: usize,
        field_before: String,
        field_after: String,
        offset: usize,
    },
    /// Field has suboptimal alignment
    AlignmentIssue {
        struct_name: String,
        field_name: String,
        field_alignment: usize,
        expected_alignment: usize,
        offset: usize,
    },
    /// Fields are in suboptimal order causing extra padding
    FieldOrdering {
        struct_name: String,
        current_order: Vec<String>,
        suggested_order: Vec<String>,
        wasted_bytes: usize,
    },
    /// Cross-language ABI mismatch
    CrossLanguageMismatch {
        struct_name: String,
        language1: String,
        language2: String,
        mismatch_details: String,
    },
    /// Struct is empty (zero-sized type)
    EmptyStruct { struct_name: String },
    /// Struct has excessive padding (more than 50% padding)
    ExcessivePadding {
        struct_name: String,
        total_size: usize,
        padding_bytes: usize,
        padding_ratio: f64,
    },
    /// Struct has endianness issues (cross-platform compatibility)
    EndiannessIssue {
        struct_name: String,
        field_name: String,
        field_type: String,
        issue_details: String,
    },
    /// Struct has bitfield layout issues
    BitfieldLayoutIssue {
        struct_name: String,
        field_name: String,
        bit_width: usize,
        issue_details: String,
    },
}

impl fmt::Display for AbiIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiIssue::StructPadding {
                struct_name,
                padding_bytes,
                field_before,
                field_after,
                offset,
            } => {
                write!(
                    f,
                    "Struct '{}' has {} bytes padding between field '{}' and '{}' at offset {}",
                    struct_name, padding_bytes, field_before, field_after, offset
                )
            }
            AbiIssue::AlignmentIssue {
                struct_name,
                field_name,
                field_alignment,
                expected_alignment,
                offset,
            } => {
                write!(
                    f,
                    "Field '{}' in struct '{}' has alignment {} but expected {} at offset {}",
                    field_name, struct_name, field_alignment, expected_alignment, offset
                )
            }
            AbiIssue::FieldOrdering {
                struct_name,
                current_order,
                suggested_order,
                wasted_bytes,
            } => {
                write!(
                    f,
                    "Struct '{}' has suboptimal field ordering: {:?} -> {:?} (would save {} bytes)",
                    struct_name, current_order, suggested_order, wasted_bytes
                )
            }
            AbiIssue::CrossLanguageMismatch {
                struct_name,
                language1,
                language2,
                mismatch_details,
            } => {
                write!(
                    f,
                    "Struct '{}' has ABI mismatch between {} and {}: {}",
                    struct_name, language1, language2, mismatch_details
                )
            }
            AbiIssue::EmptyStruct { struct_name } => {
                write!(f, "Struct '{}' is empty (zero-sized type)", struct_name)
            }
            AbiIssue::ExcessivePadding {
                struct_name,
                total_size,
                padding_bytes,
                padding_ratio,
            } => {
                write!(
                    f,
                    "Struct '{}' has excessive padding: {}/{} bytes ({:.1}%)",
                    struct_name,
                    padding_bytes,
                    total_size,
                    padding_ratio * 100.0
                )
            }
            AbiIssue::EndiannessIssue {
                struct_name,
                field_name,
                field_type,
                issue_details,
            } => {
                write!(
                    f,
                    "Struct '{}' has endianness issue in field '{}' ({}): {}",
                    struct_name, field_name, field_type, issue_details
                )
            }
            AbiIssue::BitfieldLayoutIssue {
                struct_name,
                field_name,
                bit_width,
                issue_details,
            } => {
                write!(
                    f,
                    "Struct '{}' has bitfield layout issue in field '{}' ({} bits): {}",
                    struct_name, field_name, bit_width, issue_details
                )
            }
        }
    }
}

/// Language-specific ABI rules and constraints.
#[derive(Debug, Clone)]
pub struct LanguageAbiRules {
    /// Default alignment for pointers
    pub pointer_alignment: usize,
    /// Whether to use packed structs by default
    pub default_packed: bool,
    /// Struct field reordering rules
    pub allow_field_reordering: bool,
}

impl Default for LanguageAbiRules {
    fn default() -> Self {
        Self {
            pointer_alignment: 8, // 64-bit systems
            default_packed: false,
            allow_field_reordering: true,
        }
    }
}
