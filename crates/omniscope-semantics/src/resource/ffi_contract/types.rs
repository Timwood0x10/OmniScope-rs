//! Types for FFI contract database.
//!
//! This module defines the core types used to describe FFI function contracts,
//! including contract types, ownership semantics, and source libraries.

use std::fmt;

use omniscope_types::FamilyId;

/// Type of FFI function contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContractType {
    /// Function allocates/creates a resource.
    Allocator,
    /// Function deallocates/destroys a resource.
    Deallocator,
    /// Function borrows a resource without transferring ownership.
    Borrower,
    /// Function transfers ownership to/from the caller.
    Transfer,
    /// Function that retains/increments reference count.
    Retainer,
    /// Function that releases/decrements reference count.
    Releaser,
}

impl fmt::Display for ContractType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractType::Allocator => write!(f, "allocator"),
            ContractType::Deallocator => write!(f, "deallocator"),
            ContractType::Borrower => write!(f, "borrower"),
            ContractType::Transfer => write!(f, "transfer"),
            ContractType::Retainer => write!(f, "retainer"),
            ContractType::Releaser => write!(f, "releaser"),
        }
    }
}

/// Ownership semantics for FFI functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnershipSemantics {
    /// Caller owns the resource and must free it.
    CallerOwns,
    /// Callee owns the resource; caller must not free it.
    CalleeOwns,
    /// Resource is borrowed; caller must not free it.
    Borrowed,
    /// Ownership is transferred from caller to callee.
    Transferred,
    /// Ownership is transferred from callee to caller.
    Received,
    /// Reference-counted; caller must manage reference.
    ReferenceCounted,
}

impl fmt::Display for OwnershipSemantics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OwnershipSemantics::CallerOwns => write!(f, "caller_owns"),
            OwnershipSemantics::CalleeOwns => write!(f, "callee_owns"),
            OwnershipSemantics::Borrowed => write!(f, "borrowed"),
            OwnershipSemantics::Transferred => write!(f, "transferred"),
            OwnershipSemantics::Received => write!(f, "received"),
            OwnershipSemantics::ReferenceCounted => write!(f, "reference_counted"),
        }
    }
}

/// Source library for FFI contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContractSource {
    /// OpenSSL library.
    OpenSSL,
    /// SQLite library.
    SQLite,
    /// Python C API.
    PythonCApi,
    /// Java Native Interface.
    JNI,
    /// POSIX standard library.
    Posix,
    /// GLib/GObject library.
    Glib,
    /// zlib compression library.
    Zlib,
    /// libuv event loop library.
    Libuv,
    /// Custom/unknown source.
    Custom,
}

impl fmt::Display for ContractSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractSource::OpenSSL => write!(f, "openssl"),
            ContractSource::SQLite => write!(f, "sqlite"),
            ContractSource::PythonCApi => write!(f, "python_capi"),
            ContractSource::JNI => write!(f, "jni"),
            ContractSource::Posix => write!(f, "posix"),
            ContractSource::Glib => write!(f, "glib"),
            ContractSource::Zlib => write!(f, "zlib"),
            ContractSource::Libuv => write!(f, "libuv"),
            ContractSource::Custom => write!(f, "custom"),
        }
    }
}

/// FFI function contract describing memory management semantics.
#[derive(Debug, Clone)]
pub struct FFIContract {
    /// Function name (without mangling).
    pub function_name: String,
    /// Type of contract.
    pub contract_type: ContractType,
    /// Paired release functions (for allocators).
    pub paired_release: Vec<String>,
    /// Ownership semantics.
    pub ownership: OwnershipSemantics,
    /// Whether this function is error-prone.
    pub error_prone: bool,
    /// Source library.
    pub source: ContractSource,
    /// Resource family (if known).
    pub family_id: Option<FamilyId>,
    /// Additional notes or documentation.
    pub notes: Option<String>,
}

impl FFIContract {
    /// Creates a new FFI contract.
    pub fn new(
        function_name: &str,
        contract_type: ContractType,
        paired_release: Vec<&str>,
        ownership: OwnershipSemantics,
        error_prone: bool,
        source: ContractSource,
    ) -> Self {
        Self {
            function_name: function_name.to_string(),
            contract_type,
            paired_release: paired_release.iter().map(|s| s.to_string()).collect(),
            ownership,
            error_prone,
            source,
            family_id: None,
            notes: None,
        }
    }

    /// Sets the resource family for this contract.
    pub fn with_family(mut self, family_id: FamilyId) -> Self {
        self.family_id = Some(family_id);
        self
    }

    /// Sets notes for this contract.
    pub fn with_notes(mut self, notes: &str) -> Self {
        self.notes = Some(notes.to_string());
        self
    }

    /// Returns true if this is an allocation function.
    pub fn is_allocator(&self) -> bool {
        self.contract_type == ContractType::Allocator
    }

    /// Returns true if this is a deallocation function.
    pub fn is_deallocator(&self) -> bool {
        self.contract_type == ContractType::Deallocator
    }

    /// Returns true if this function borrows a resource.
    pub fn is_borrower(&self) -> bool {
        self.contract_type == ContractType::Borrower
    }

    /// Returns true if this function transfers ownership.
    pub fn is_transfer(&self) -> bool {
        self.contract_type == ContractType::Transfer
    }

    /// Returns true if this function retains a reference.
    pub fn is_retainer(&self) -> bool {
        self.contract_type == ContractType::Retainer
    }

    /// Returns true if this function releases a reference.
    pub fn is_releaser(&self) -> bool {
        self.contract_type == ContractType::Releaser
    }

    /// Returns true if the caller owns the resource.
    pub fn caller_owns(&self) -> bool {
        self.ownership == OwnershipSemantics::CallerOwns
    }

    /// Returns true if the callee owns the resource.
    pub fn callee_owns(&self) -> bool {
        self.ownership == OwnershipSemantics::CalleeOwns
    }

    /// Returns true if the resource is borrowed.
    pub fn is_borrowed(&self) -> bool {
        self.ownership == OwnershipSemantics::Borrowed
    }

    /// Returns true if ownership is transferred.
    pub fn ownership_transferred(&self) -> bool {
        matches!(
            self.ownership,
            OwnershipSemantics::Transferred | OwnershipSemantics::Received
        )
    }

    /// Returns true if this is a reference-counted resource.
    pub fn is_reference_counted(&self) -> bool {
        self.ownership == OwnershipSemantics::ReferenceCounted
    }
}

impl fmt::Display for FFIContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}, {})",
            self.function_name, self.contract_type, self.source
        )
    }
}
