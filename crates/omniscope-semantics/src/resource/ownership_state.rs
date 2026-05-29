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
                    OwnershipState::Transferred => {
                        // Releasing a transferred resource — the new owner should release
                        Err(OwnershipError::InvalidTransition {
                            instance: self.id,
                            from_state: self.state,
                            event: "Release",
                        })
                    }
                    OwnershipState::Untracked | OwnershipState::Unknown => {
                        // Cannot release a resource whose state is unknown
                        Err(OwnershipError::InvalidTransition {
                            instance: self.id,
                            from_state: self.state,
                            event: "Release",
                        })
                    }
                }
            }
            OwnershipEvent::Escape { kind } => {
                match self.state {
                    OwnershipState::Acquired => {
                        self.state = OwnershipState::Escaped(kind);
                        Ok(())
                    }
                    OwnershipState::Escaped(_) => {
                        // Escape from already-escaped — update the kind
                        self.state = OwnershipState::Escaped(kind);
                        Ok(())
                    }
                    OwnershipState::Retained => {
                        // Retained resource can escape (e.g. stored in global after retain)
                        self.state = OwnershipState::Escaped(kind);
                        Ok(())
                    }
                    OwnershipState::Released => Err(OwnershipError::InvalidTransition {
                        instance: self.id,
                        from_state: self.state,
                        event: "Escape",
                    }),
                    OwnershipState::Transferred => Err(OwnershipError::InvalidTransition {
                        instance: self.id,
                        from_state: self.state,
                        event: "Escape",
                    }),
                    OwnershipState::Borrowed => Err(OwnershipError::InvalidTransition {
                        instance: self.id,
                        from_state: self.state,
                        event: "Escape",
                    }),
                    OwnershipState::Untracked | OwnershipState::Unknown => {
                        Err(OwnershipError::InvalidTransition {
                            instance: self.id,
                            from_state: self.state,
                            event: "Escape",
                        })
                    }
                }
            }
            OwnershipEvent::Transfer => {
                match self.state {
                    OwnershipState::Acquired => {
                        self.state = OwnershipState::Transferred;
                        Ok(())
                    }
                    OwnershipState::Retained => {
                        // Retained resource can be transferred (e.g. Py_Send after Py_INCREF)
                        self.state = OwnershipState::Transferred;
                        Ok(())
                    }
                    _ => Err(OwnershipError::InvalidTransition {
                        instance: self.id,
                        from_state: self.state,
                        event: "Transfer",
                    }),
                }
            }
            OwnershipEvent::Retain => {
                match self.state {
                    OwnershipState::Acquired => {
                        self.state = OwnershipState::Retained;
                        Ok(())
                    }
                    OwnershipState::Retained => {
                        // Already retained — idempotent (nested retain)
                        Ok(())
                    }
                    _ => Err(OwnershipError::InvalidTransition {
                        instance: self.id,
                        from_state: self.state,
                        event: "Retain",
                    }),
                }
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
    /// Invalid state transition attempted (e.g. Transfer from Released).
    InvalidTransition {
        instance: u64,
        from_state: OwnershipState,
        event: &'static str,
    },
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

    /// Objective: Verify that Transfer from Acquired transitions to Transferred.
    /// Invariants: After Transfer, state == Transferred and is_leak_candidate() == false.
    #[test]
    fn test_transfer_from_acquired() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        assert_eq!(
            instance.state,
            OwnershipState::Acquired,
            "Pre-condition: instance starts in Acquired state"
        );

        let result = instance.transition(OwnershipEvent::Transfer);
        assert!(result.is_ok(), "Transfer from Acquired must succeed");
        assert_eq!(
            instance.state,
            OwnershipState::Transferred,
            "Transfer from Acquired must transition to Transferred"
        );
        assert!(
            !instance.is_leak_candidate(),
            "Transferred resource is NOT a leak candidate"
        );
    }

    /// Objective: Verify that Retain from Acquired transitions to Retained.
    /// Invariants: After Retain, state == Retained and is_leak_candidate() == true (still needs release).
    #[test]
    fn test_retain_from_acquired() {
        let mut instance =
            ResourceInstance::new(1, FamilyId::PYTHON_OBJECT, PointerContract::Owned);
        assert_eq!(
            instance.state,
            OwnershipState::Acquired,
            "Pre-condition: instance starts in Acquired state"
        );

        let result = instance.transition(OwnershipEvent::Retain);
        assert!(result.is_ok(), "Retain from Acquired must succeed");
        assert_eq!(
            instance.state,
            OwnershipState::Retained,
            "Retain from Acquired must transition to Retained"
        );
        assert!(
            instance.is_leak_candidate(),
            "Retained resource IS still a leak candidate (needs corresponding release)"
        );
    }

    /// Objective: Verify that Release from Retained state succeeds (refcount decrement to zero).
    /// Invariants: After Release, state == Released and released_in is set.
    #[test]
    fn test_release_from_retained() {
        let mut instance =
            ResourceInstance::new(1, FamilyId::PYTHON_OBJECT, PointerContract::Owned);
        // Transition: Acquired -> Retained -> Released
        instance
            .transition(OwnershipEvent::Retain)
            .expect("Retain from Acquired must succeed");
        assert_eq!(
            instance.state,
            OwnershipState::Retained,
            "Pre-condition: instance is in Retained state"
        );

        let result = instance.transition(OwnershipEvent::Release { function: 99 });
        assert!(
            result.is_ok(),
            "Release from Retained must succeed (refcount drop to zero)"
        );
        assert_eq!(
            instance.state,
            OwnershipState::Released,
            "Release from Retained must transition to Released"
        );
        assert_eq!(
            instance.released_in,
            Some(99),
            "released_in must record the function ID of the release"
        );
        assert!(
            !instance.is_leak_candidate(),
            "Released resource is NOT a leak candidate"
        );
    }

    /// Objective: Verify that Release from Escaped state succeeds but signals
    /// potential use-after-free (the resource escaped, then someone released it).
    /// Invariants: After Release, state == Released even though it was Escaped.
    #[test]
    fn test_release_from_escaped() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        // Transition: Acquired -> Escaped -> Released
        instance
            .transition(OwnershipEvent::Escape {
                kind: EscapeKind::ReturnToCaller,
            })
            .expect("Escape from Acquired must succeed");
        assert!(
            matches!(instance.state, OwnershipState::Escaped(_)),
            "Pre-condition: instance is in Escaped state"
        );

        let result = instance.transition(OwnershipEvent::Release { function: 77 });
        assert!(
            result.is_ok(),
            "Release from Escaped must succeed (code allows it, though risky)"
        );
        assert_eq!(
            instance.state,
            OwnershipState::Released,
            "Release from Escaped must transition to Released (potential use-after-free)"
        );
        assert_eq!(
            instance.released_in,
            Some(77),
            "released_in must be set even for escaped-then-released resources"
        );
    }

    /// Objective: Verify that Escape from a Released state returns an error
    ///            (invalid transition — cannot escape a freed resource).
    /// Invariants: State remains Released after a failed Escape; the error
    ///            must be InvalidTransition.
    #[test]
    fn test_escape_from_released_is_error() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Release { function: 10 })
            .expect("Release from Acquired must succeed");
        assert_eq!(
            instance.state,
            OwnershipState::Released,
            "Pre-condition: instance is in Released state"
        );

        let result = instance.transition(OwnershipEvent::Escape {
            kind: EscapeKind::ReturnToCaller,
        });
        assert!(
            result.is_err(),
            "Escape from Released must return Err (invalid transition)"
        );
        assert_eq!(
            instance.state,
            OwnershipState::Released,
            "State must remain Released after failed Escape"
        );
    }

    /// Objective: Verify that Transfer from a Released state returns an error
    ///            (invalid transition — cannot transfer a freed resource).
    /// Invariants: State remains Released after a failed Transfer; the error
    ///            must be InvalidTransition.
    #[test]
    fn test_transfer_from_released_is_error() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Release { function: 10 })
            .expect("Release from Acquired must succeed");
        assert_eq!(
            instance.state,
            OwnershipState::Released,
            "Pre-condition: instance is in Released state"
        );

        let result = instance.transition(OwnershipEvent::Transfer);
        assert!(
            result.is_err(),
            "Transfer from Released must return Err (invalid transition)"
        );
        assert_eq!(
            instance.state,
            OwnershipState::Released,
            "State must remain Released after failed Transfer"
        );
    }

    /// Objective: Verify that Retain from a Released state returns an error
    ///            (invalid transition — cannot retain a freed resource).
    /// Invariants: State remains Released after a failed Retain; the error
    ///            must be InvalidTransition.
    #[test]
    fn test_retain_from_released_is_error() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Release { function: 10 })
            .expect("Release from Acquired must succeed");
        assert_eq!(
            instance.state,
            OwnershipState::Released,
            "Pre-condition: instance is in Released state"
        );

        let result = instance.transition(OwnershipEvent::Retain);
        assert!(
            result.is_err(),
            "Retain from Released must return Err (invalid transition)"
        );
        assert_eq!(
            instance.state,
            OwnershipState::Released,
            "State must remain Released after failed Retain"
        );
    }

    // ── Bug #2 fix: Escaped state preservation ──

    /// Objective: Verify that Escape event sets the state to Escaped (not Released),
    ///            preserving the EscapeKind information for downstream analysis.
    /// Invariants: After Escape, state == Escaped(kind), and the kind is retrievable.
    #[test]
    fn test_escape_preserves_escaped_state_not_released() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        let result = instance.transition(OwnershipEvent::Escape {
            kind: EscapeKind::ReturnToCaller,
        });
        assert!(result.is_ok(), "Escape from Acquired must succeed");
        assert!(
            matches!(
                instance.state,
                OwnershipState::Escaped(EscapeKind::ReturnToCaller)
            ),
            "Escape must set state to Escaped(ReturnToCaller), not Released"
        );
        assert!(
            !instance.is_leak_candidate(),
            "Escaped resource is NOT a leak candidate"
        );
    }

    /// Objective: Verify that Escape from an already-Escaped state updates the
    ///            EscapeKind (e.g. a resource that first escaped via FieldStore
    ///            then also via ReturnToCaller).
    /// Invariants: The new EscapeKind replaces the old one.
    #[test]
    fn test_escape_from_escaped_updates_kind() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Escape {
                kind: EscapeKind::FieldStore,
            })
            .expect("Escape from Acquired must succeed");
        assert!(
            matches!(
                instance.state,
                OwnershipState::Escaped(EscapeKind::FieldStore)
            ),
            "Pre-condition: state is Escaped(FieldStore)"
        );

        let result = instance.transition(OwnershipEvent::Escape {
            kind: EscapeKind::ReturnToCaller,
        });
        assert!(
            result.is_ok(),
            "Escape from Escaped must succeed (update kind)"
        );
        assert!(
            matches!(
                instance.state,
                OwnershipState::Escaped(EscapeKind::ReturnToCaller)
            ),
            "Escape from Escaped must update the kind to ReturnToCaller"
        );
    }

    /// Objective: Verify that Escape from Retained state succeeds (e.g. retaining
    ///            then storing in a global).
    /// Invariants: State transitions from Retained to Escaped.
    #[test]
    fn test_escape_from_retained() {
        let mut instance =
            ResourceInstance::new(1, FamilyId::PYTHON_OBJECT, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Retain)
            .expect("Retain from Acquired must succeed");

        let result = instance.transition(OwnershipEvent::Escape {
            kind: EscapeKind::GlobalStore,
        });
        assert!(result.is_ok(), "Escape from Retained must succeed");
        assert!(
            matches!(
                instance.state,
                OwnershipState::Escaped(EscapeKind::GlobalStore)
            ),
            "Escape from Retained must set state to Escaped(GlobalStore)"
        );
    }

    /// Objective: Verify that Transfer from Retained state succeeds (e.g. Py_Send
    ///            after Py_INCREF).
    /// Invariants: State transitions from Retained to Transferred.
    #[test]
    fn test_transfer_from_retained() {
        let mut instance =
            ResourceInstance::new(1, FamilyId::PYTHON_OBJECT, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Retain)
            .expect("Retain from Acquired must succeed");
        assert_eq!(
            instance.state,
            OwnershipState::Retained,
            "Pre-condition: state is Retained"
        );

        let result = instance.transition(OwnershipEvent::Transfer);
        assert!(result.is_ok(), "Transfer from Retained must succeed");
        assert_eq!(
            instance.state,
            OwnershipState::Transferred,
            "Transfer from Retained must transition to Transferred"
        );
    }

    /// Objective: Verify that Retain from already-Retained state is idempotent.
    /// Invariants: State stays Retained; no error.
    #[test]
    fn test_retain_from_retained_is_idempotent() {
        let mut instance =
            ResourceInstance::new(1, FamilyId::PYTHON_OBJECT, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Retain)
            .expect("Retain from Acquired must succeed");

        let result = instance.transition(OwnershipEvent::Retain);
        assert!(
            result.is_ok(),
            "Retain from Retained must succeed (idempotent)"
        );
        assert_eq!(
            instance.state,
            OwnershipState::Retained,
            "State must remain Retained after idempotent Retain"
        );
    }

    /// Objective: Verify that Release from Transferred state returns InvalidTransition.
    /// Invariants: A transferred resource should not be released by the old owner.
    #[test]
    fn test_release_from_transferred_is_error() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Transfer)
            .expect("Transfer from Acquired must succeed");

        let result = instance.transition(OwnershipEvent::Release { function: 99 });
        assert!(
            result.is_err(),
            "Release from Transferred must return Err (new owner should release)"
        );
        assert_eq!(
            instance.state,
            OwnershipState::Transferred,
            "State must remain Transferred after failed Release"
        );
    }

    /// Objective: Verify that Transfer from Transferred state returns InvalidTransition.
    /// Invariants: Cannot double-transfer a resource.
    #[test]
    fn test_transfer_from_transferred_is_error() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Transfer)
            .expect("Transfer from Acquired must succeed");

        let result = instance.transition(OwnershipEvent::Transfer);
        assert!(
            result.is_err(),
            "Transfer from Transferred must return Err (already transferred)"
        );
    }

    /// Objective: Verify that Escape from Borrowed state returns InvalidTransition.
    /// Invariants: A borrowed resource cannot escape (the borrower doesn't own it).
    #[test]
    fn test_escape_from_borrowed_is_error() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Borrowed);
        instance.state = OwnershipState::Borrowed;

        let result = instance.transition(OwnershipEvent::Escape {
            kind: EscapeKind::ReturnToCaller,
        });
        assert!(
            result.is_err(),
            "Escape from Borrowed must return Err (not owned)"
        );
    }

    /// Objective: Verify the full Acquired→Retained→Escaped→Released chain
    ///            preserves Escape information through the lifecycle.
    /// Invariants: After Escaped→Released, the resource is properly released
    ///            but the fact that it was once escaped is captured in released_in.
    #[test]
    fn test_retained_escape_release_chain() {
        let mut instance =
            ResourceInstance::new(1, FamilyId::PYTHON_OBJECT, PointerContract::Owned);

        // Acquired → Retained
        instance
            .transition(OwnershipEvent::Retain)
            .expect("Retain from Acquired must succeed");
        assert_eq!(instance.state, OwnershipState::Retained);

        // Retained → Escaped
        instance
            .transition(OwnershipEvent::Escape {
                kind: EscapeKind::Callback,
            })
            .expect("Escape from Retained must succeed");
        assert!(
            matches!(
                instance.state,
                OwnershipState::Escaped(EscapeKind::Callback)
            ),
            "State must be Escaped(Callback)"
        );

        // Escaped → Released (risky but allowed — signals potential use-after-free)
        instance
            .transition(OwnershipEvent::Release { function: 55 })
            .expect("Release from Escaped must succeed");
        assert_eq!(
            instance.state,
            OwnershipState::Released,
            "State must be Released after release of escaped resource"
        );
        assert_eq!(
            instance.released_in,
            Some(55),
            "released_in must be set even for escaped-then-released resources"
        );
    }

    /// Objective: Verify that all EscapeKind variants can be stored in the
    ///            Escaped state and correctly retrieved.
    /// Invariants: Each EscapeKind produces a distinguishable Escaped state.
    #[test]
    fn test_escape_kind_variants_preserved() {
        let kinds = [
            EscapeKind::ReturnToCaller,
            EscapeKind::OutParam,
            EscapeKind::FieldStore,
            EscapeKind::GlobalStore,
            EscapeKind::Callback,
            EscapeKind::Thread,
            EscapeKind::Container,
            EscapeKind::StaticLifetime,
            EscapeKind::Unknown,
        ];

        for (i, kind) in kinds.iter().enumerate() {
            let mut instance =
                ResourceInstance::new(i as u64, FamilyId::C_HEAP, PointerContract::Owned);
            let result = instance.transition(OwnershipEvent::Escape { kind: *kind });
            assert!(
                result.is_ok(),
                "Escape with kind {:?} must succeed from Acquired",
                kind
            );
            assert!(
                matches!(instance.state, OwnershipState::Escaped(k) if k == *kind),
                "State must be Escaped({:?}), got {:?}",
                kind,
                instance.state
            );
        }
    }
}
