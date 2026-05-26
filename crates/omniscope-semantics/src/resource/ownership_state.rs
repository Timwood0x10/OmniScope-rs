//! Ownership state machine for tracking resource lifecycle.
//!
//! Each resource instance has an ownership state that transitions
//! through: Untracked -> Acquired -> (Released | Escaped | Transferred).
//! The state machine determines whether a release is valid, a leak
//! is possible, or a double-free has occurred.

use omniscope_types::{EscapeKind, FamilyId, PointerContract};

/// Current ownership state of a resource instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnershipState {
    /// Not yet tracked by the analysis.
    Untracked,
    /// Resource has been acquired (allocated/created).
    Acquired,
    /// Resource has been released (freed/destroyed).
    Released,
    /// Resource has escaped the current scope.
    Escaped(EscapeKind),
    /// Ownership has been transferred to another function/owner.
    Transferred,
    /// Resource is retained (refcount incremented).
    Retained,
    /// Resource is borrowed (not responsible for deallocation).
    Borrowed,
    /// Unknown state.
    Unknown,
}

/// A resource instance being tracked by the ownership state machine.
#[derive(Debug, Clone)]
pub struct ResourceInstance {
    /// Unique identifier for this instance.
    pub id: u64,
    /// The resource family this instance belongs to.
    pub family: FamilyId,
    /// Current ownership state.
    pub state: OwnershipState,
    /// Pointer contract at the point of acquisition.
    pub contract: PointerContract,
    /// The function that acquired this resource.
    pub acquired_in: Option<u64>,
    /// The function that released this resource (if any).
    pub released_in: Option<u64>,
}

impl ResourceInstance {
    /// Creates a new resource instance in the Acquired state.
    pub fn new(id: u64, family: FamilyId, contract: PointerContract) -> Self {
        Self {
            id,
            family,
            state: OwnershipState::Acquired,
            contract,
            acquired_in: None,
            released_in: None,
        }
    }

    /// Transitions the state machine based on an event.
    ///
    /// Returns `Ok(())` if the transition is valid, or `Err(OwnershipError)`
    /// if the transition is invalid (e.g. double release).
    pub fn transition(&mut self, event: OwnershipEvent) -> Result<(), OwnershipError> {
        match event {
            OwnershipEvent::Release { function } => {
                match self.state {
                    OwnershipState::Acquired | OwnershipState::Retained => {
                        self.state = OwnershipState::Released;
                        self.released_in = Some(function);
                        Ok(())
                    }
                    OwnershipState::Released => Err(OwnershipError::DoubleRelease {
                        instance: self.id,
                        family: self.family,
                    }),
                    OwnershipState::Borrowed => {
                        Err(OwnershipError::ReleaseBorrowed { instance: self.id })
                    }
                    OwnershipState::Escaped(_) => {
                        // Releasing an escaped resource — possible use-after-free
                        self.state = OwnershipState::Released;
                        self.released_in = Some(function);
                        Ok(())
                    }
                    _ => Ok(()),
                }
            }
            OwnershipEvent::Escape { kind } => {
                if self.state == OwnershipState::Acquired {
                    self.state = OwnershipState::Escaped(kind);
                }
                Ok(())
            }
            OwnershipEvent::Transfer => {
                if self.state == OwnershipState::Acquired {
                    self.state = OwnershipState::Transferred;
                }
                Ok(())
            }
            OwnershipEvent::Retain => {
                if self.state == OwnershipState::Acquired {
                    self.state = OwnershipState::Retained;
                }
                Ok(())
            }
        }
    }

    /// Returns true if this instance is a leak candidate
    /// (acquired but never released or escaped).
    pub fn is_leak_candidate(&self) -> bool {
        matches!(
            self.state,
            OwnershipState::Acquired | OwnershipState::Retained | OwnershipState::Unknown
        )
    }
}

/// Events that can transition the ownership state machine.
#[derive(Debug, Clone, Copy)]
pub enum OwnershipEvent {
    /// Resource is released.
    Release { function: u64 },
    /// Resource escapes with the given kind.
    Escape { kind: EscapeKind },
    /// Ownership is transferred.
    Transfer,
    /// Resource is retained (refcount increment).
    Retain,
}

/// Errors from invalid ownership state transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipError {
    /// Double release detected.
    DoubleRelease { instance: u64, family: FamilyId },
    /// Attempt to release a borrowed resource.
    ReleaseBorrowed { instance: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acquire_release_transition() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        assert!(
            instance.is_leak_candidate(),
            "Acquired resource is a leak candidate"
        );
        let result = instance.transition(OwnershipEvent::Release { function: 42 });
        assert!(
            result.is_ok(),
            "Release of acquired resource should succeed"
        );
        assert!(
            !instance.is_leak_candidate(),
            "Released resource is NOT a leak candidate"
        );
    }

    #[test]
    fn test_double_release_error() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Release { function: 42 })
            .unwrap();
        let result = instance.transition(OwnershipEvent::Release { function: 43 });
        assert!(result.is_err(), "Double release must be an error");
    }

    #[test]
    fn test_escape_transition() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        let result = instance.transition(OwnershipEvent::Escape {
            kind: EscapeKind::ReturnToCaller,
        });
        assert!(result.is_ok());
        assert!(
            !instance.is_leak_candidate(),
            "Escaped resource is NOT a leak candidate"
        );
    }

    #[test]
    fn test_release_borrowed_error() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Borrowed);
        instance.state = OwnershipState::Borrowed;
        let result = instance.transition(OwnershipEvent::Release { function: 42 });
        assert!(
            result.is_err(),
            "Releasing a borrowed resource must be an error"
        );
    }
}
