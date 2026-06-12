//! Types for may-alias analysis in resource contract detection.
//!
//! `FreeSite` describes a single free/release call site relevant to alias gating.
//! `AliasEvidence` records the result of alias analysis between two free sites.

/// Describes a single free/release call site relevant to alias gating.
#[derive(Debug, Clone)]
pub struct FreeSite {
    /// Enclosing function name (the caller that contains this free call).
    pub caller: String,
    /// Release callee symbol (e.g. `free`, `_ZdlPv`).
    pub callee: String,
    /// SSA register / global of the pointer argument, if recoverable.
    pub arg_register: Option<String>,
}

impl FreeSite {
    /// Convenience constructor.
    pub fn new(caller: impl Into<String>, callee: impl Into<String>, arg: Option<String>) -> Self {
        Self {
            caller: caller.into(),
            callee: callee.into(),
            arg_register: arg,
        }
    }
}

/// Evidence that two free sites may alias the same allocation.
#[derive(Debug, Clone)]
pub struct AliasEvidence {
    /// Human-readable description of why the sites are believed to alias.
    pub description: String,
}

impl AliasEvidence {
    /// Creates new alias evidence with a description.
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
        }
    }
}
