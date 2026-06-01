//! ABI types for FFI analysis
//!
//! This module defines types related to Application Binary Interface (ABI)
//! for detecting FFI mismatches and safety issues.

use serde::{Deserialize, Serialize};

/// ABI type representation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AbiType {
    /// Integer type with size in bits
    Integer {
        /// Size in bits (8, 16, 32, 64, 128)
        bits: u32,
        /// Whether it's signed
        signed: bool,
    },

    /// Floating point type
    Float {
        /// Size in bits (32, 64)
        bits: u32,
    },

    /// Pointer type
    Pointer {
        /// Pointed type (None for void*)
        inner: Option<Box<AbiType>>,
        /// Whether it's mutable
        mutable: bool,
    },

    /// Array type
    Array {
        /// Element type
        element: Box<AbiType>,
        /// Size (None for dynamic)
        size: Option<usize>,
    },

    /// Struct type
    Struct {
        /// Field types
        fields: Vec<AbiType>,
        /// Whether it's packed
        packed: bool,
    },

    /// Function type
    Function {
        /// Parameter types
        params: Vec<AbiType>,
        /// Return type
        ret: Option<Box<AbiType>>,
        /// Calling convention
        convention: CallingConvention,
    },

    /// Void type
    Void,

    /// Unknown type
    Unknown,
}

impl AbiType {
    /// Returns the size in bytes (if known)
    pub fn size_bytes(&self) -> Option<usize> {
        match self {
            AbiType::Integer { bits, .. } => Some(*bits as usize / 8),
            AbiType::Float { bits } => Some(*bits as usize / 8),
            AbiType::Pointer { .. } => Some(8), // Assume 64-bit
            AbiType::Array { element, size } => {
                let elem_size = element.size_bytes()?;
                size.map(|s| s * elem_size)
            }
            AbiType::Void => Some(0),
            _ => None,
        }
    }

    /// Returns true if this is a pointer type
    pub fn is_pointer(&self) -> bool {
        matches!(self, AbiType::Pointer { .. })
    }

    /// Returns true if this is an integer type
    pub fn is_integer(&self) -> bool {
        matches!(self, AbiType::Integer { .. })
    }

    /// Returns true if this is a function type
    pub fn is_function(&self) -> bool {
        matches!(self, AbiType::Function { .. })
    }
}

/// Calling convention for functions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum CallingConvention {
    /// C calling convention
    #[default]
    C,
    /// Stdcall (Windows)
    Stdcall,
    /// Fastcall
    Fastcall,
    /// Vectorcall (Windows)
    Vectorcall,
    /// Rust calling convention
    Rust,
    /// Platform-specific
    Platform,
}

/// ABI mismatch information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiMismatch {
    /// Expected type
    pub expected: AbiType,
    /// Actual type
    pub actual: AbiType,
    /// Mismatch kind
    pub kind: MismatchKind,
}

/// Kind of ABI mismatch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MismatchKind {
    /// Size mismatch
    SizeMismatch,
    /// Alignment mismatch
    AlignmentMismatch,
    /// Signedness mismatch
    SignednessMismatch,
    /// Calling convention mismatch
    CallingConventionMismatch,
    /// Type mismatch
    TypeMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abi_type_size() {
        let i32_type = AbiType::Integer {
            bits: 32,
            signed: true,
        };
        assert_eq!(
            i32_type.size_bytes(),
            Some(4),
            "Expected values to be equal"
        );

        let f64_type = AbiType::Float { bits: 64 };
        assert_eq!(
            f64_type.size_bytes(),
            Some(8),
            "Expected values to be equal"
        );

        let ptr_type = AbiType::Pointer {
            inner: None,
            mutable: true,
        };
        assert_eq!(
            ptr_type.size_bytes(),
            Some(8),
            "Expected values to be equal"
        );
    }

    #[test]
    fn test_abi_type_checks() {
        let int_type = AbiType::Integer {
            bits: 32,
            signed: true,
        };
        assert!(int_type.is_integer(), "Expected condition to be true");
        assert!(!int_type.is_pointer(), "Expected condition to be true");

        let ptr_type = AbiType::Pointer {
            inner: None,
            mutable: false,
        };
        assert!(ptr_type.is_pointer(), "Expected condition to be true");
        assert!(!ptr_type.is_integer(), "Expected condition to be true");
    }
}
