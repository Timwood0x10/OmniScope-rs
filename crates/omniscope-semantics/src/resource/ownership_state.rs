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
    /// The function ID that acquired this resource.
    pub acquired_in: Option<u64>,
    /// The function ID that released this resource (if any).
    pub released_in: Option<u64>,
    /// The enclosing function name where this resource was created.
    /// Used for issue location reporting.
    pub function_name: String,
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
            function_name: String::new(),
        }
    }

    /// Creates a new resource instance in the Borrowed state.
    ///
    /// Used for stack-allocated or borrowed pointers that escape to
    /// C callbacks — no prior Acquire edge exists for them.
    pub fn new_borrowed(id: u64, family: FamilyId) -> Self {
        Self {
            id,
            family,
            state: OwnershipState::Borrowed,
            contract: PointerContract::Borrowed,
            acquired_in: None,
            released_in: None,
            function_name: String::new(),
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
            OwnershipEvent::Borrow => {
                match self.state {
                    OwnershipState::Acquired | OwnershipState::Retained => {
                        self.state = OwnershipState::Borrowed;
                        Ok(())
                    }
                    OwnershipState::Borrowed => {
                        // Already borrowed — idempotent
                        Ok(())
                    }
                    _ => Err(OwnershipError::InvalidTransition {
                        instance: self.id,
                        from_state: self.state,
                        event: "Borrow",
                    }),
                }
            }
            OwnershipEvent::ConditionalRelease { function } => {
                match self.state {
                    // Retained + ConditionalRelease → Acquired
                    // (refcount decrement, but resource may still be alive
                    // if other references exist — back to base state).
                    OwnershipState::Retained => {
                        self.state = OwnershipState::Acquired;
                        let _ = function; // not recorded as final release
                        Ok(())
                    }
                    // Acquired + ConditionalRelease → Released
                    // (only reference, so conditional release is definitive).
                    OwnershipState::Acquired => {
                        self.state = OwnershipState::Released;
                        self.released_in = Some(function);
                        Ok(())
                    }
                    // Escaped + ConditionalRelease → Released
                    // (risky, same semantics as unconditional Release).
                    OwnershipState::Escaped(_) => {
                        self.state = OwnershipState::Released;
                        self.released_in = Some(function);
                        Ok(())
                    }
                    // Already released — double release regardless of
                    // conditionality.
                    OwnershipState::Released => Err(OwnershipError::DoubleRelease {
                        instance: self.id,
                        family: self.family,
                    }),
                    OwnershipState::Borrowed => {
                        Err(OwnershipError::ReleaseBorrowed { instance: self.id })
                    }
                    OwnershipState::Transferred
                    | OwnershipState::Untracked
                    | OwnershipState::Unknown => Err(OwnershipError::InvalidTransition {
                        instance: self.id,
                        from_state: self.state,
                        event: "ConditionalRelease",
                    }),
                }
            }
        }
    }

    /// Returns true if this instance is a leak candidate
    /// (acquired or retained but never released or escaped).
    /// Unknown state is excluded because it represents an
    /// indeterminate ownership — treating it as a leak would
    /// produce false positives.
    pub fn is_leak_candidate(&self) -> bool {
        matches!(
            self.state,
            OwnershipState::Acquired | OwnershipState::Retained
        )
    }
}

/// Events that can transition the ownership state machine.
#[derive(Debug, Clone, Copy)]
pub enum OwnershipEvent {
    /// Resource is unconditionally released (freed/destroyed).
    Release { function: u64 },
    /// Resource is conditionally released (e.g. Py_DECREF, JNI DeleteLocalRef).
    ///
    /// The release only happens when the refcount reaches zero or the scope
    /// ends. For refcounted resources, this decrements the count but the
    /// resource may still be alive if other references exist.
    ConditionalRelease { function: u64 },
    /// Resource escapes with the given kind.
    Escape { kind: EscapeKind },
    /// Ownership is transferred.
    Transfer,
    /// Resource is retained (refcount increment).
    Retain,
    /// Resource becomes borrowed (returned as a borrowed reference).
    Borrow,
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

    /// Objective: 验证从 Acquired 状态到 Released 状态的转换
    ///
    /// Invariants:
    /// - 初始状态应为 Acquired，且是泄漏候选
    /// - Release 事件后状态应为 Released
    /// - 转换不应返回错误
    /// - Released 状态不再是泄漏候选
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

    /// Objective: 验证双重释放会返回 DoubleRelease 错误
    ///
    /// Invariants:
    /// - 第一次 Release 应成功，状态变为 Released
    /// - 第二次 Release 应返回 DoubleRelease 错误
    /// - 错误应包含实例 ID 和资源族信息
    #[test]
    fn test_double_release_error() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Release { function: 42 })
            .expect("ownership_state::test_double_release_error: first release transition should succeed");
        let result = instance.transition(OwnershipEvent::Release { function: 43 });
        assert!(result.is_err(), "Double release must be an error");
    }

    /// Objective: 验证从 Acquired 状态到 Escaped 状态的转换
    ///
    /// Invariants:
    /// - 初始状态应为 Acquired
    /// - Escape 事件后状态应为 Escaped(ReturnToCaller)
    /// - 转换不应返回错误
    /// - Escaped 状态不再是泄漏候选
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

    /// Objective: 验证释放借用的资源会返回 ReleaseBorrowed 错误
    ///
    /// Invariants:
    /// - 初始状态应为 Borrowed
    /// - Release 事件应返回 ReleaseBorrowed 错误
    /// - 状态应保持 Borrowed 不变
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
        instance.transition(OwnershipEvent::Retain).expect(
            "ownership_state::test_release_from_retained: Retain from Acquired must succeed",
        );
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
            .expect(
                "ownership_state::test_release_from_escaped: Escape from Acquired must succeed",
            );
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
            .expect("ownership_state::test_escape_from_released_is_error: Release from Acquired must succeed");
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
            .expect("ownership_state::test_transfer_from_released_is_error: Release from Acquired must succeed");
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
            .expect("ownership_state::test_retain_from_released_is_error: Release from Acquired must succeed");
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
            .expect("ownership_state::test_escape_from_escaped_updates_kind: Escape from Acquired must succeed");
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
        instance.transition(OwnershipEvent::Retain).expect(
            "ownership_state::test_escape_from_retained: Retain from Acquired must succeed",
        );

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
        instance.transition(OwnershipEvent::Retain).expect(
            "ownership_state::test_transfer_from_retained: Retain from Acquired must succeed",
        );
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
            .expect("ownership_state::test_retain_from_retained_is_idempotent: Retain from Acquired must succeed");

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
            .expect("ownership_state::test_release_from_transferred_is_error: Transfer from Acquired must succeed");

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
            .expect("ownership_state::test_transfer_from_transferred_is_error: Transfer from Acquired must succeed");

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
            .expect("ownership_state::test_retained_escape_release_chain: Retain from Acquired must succeed");
        assert_eq!(instance.state, OwnershipState::Retained);

        // Retained → Escaped
        instance
            .transition(OwnershipEvent::Escape {
                kind: EscapeKind::Callback,
            })
            .expect("ownership_state::test_retained_escape_release_chain: Escape from Retained must succeed");
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
            .expect("ownership_state::test_retained_escape_release_chain: Release from Escaped must succeed");
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

    // ── ConditionalRelease event tests ──

    /// Objective: Verify that ConditionalRelease from Retained transitions
    ///            back to Acquired (refcount decrement, but resource alive).
    /// Invariants: Retained + ConditionalRelease → Acquired; NOT Released.
    #[test]
    fn test_conditional_release_from_retained_to_acquired() {
        let mut instance =
            ResourceInstance::new(1, FamilyId::PYTHON_OBJECT, PointerContract::Owned);
        // Acquired → Retained
        instance
            .transition(OwnershipEvent::Retain)
            .expect("ownership_state::test_conditional_release_from_retained_to_acquired: Retain from Acquired must succeed");
        assert_eq!(instance.state, OwnershipState::Retained);

        // Retained → Acquired (refcount still > 0)
        let result = instance.transition(OwnershipEvent::ConditionalRelease { function: 10 });
        assert!(
            result.is_ok(),
            "ConditionalRelease from Retained must succeed"
        );
        assert_eq!(
            instance.state,
            OwnershipState::Acquired,
            "ConditionalRelease from Retained must go to Acquired, not Released"
        );
        assert!(
            instance.is_leak_candidate(),
            "Acquired after ConditionalRelease is still a leak candidate"
        );
    }

    /// Objective: Verify that ConditionalRelease from Acquired transitions
    ///            to Released (only reference, so decrement is definitive).
    /// Invariants: Acquired + ConditionalRelease → Released.
    #[test]
    fn test_conditional_release_from_acquired_to_released() {
        let mut instance =
            ResourceInstance::new(1, FamilyId::PYTHON_OBJECT, PointerContract::Owned);
        assert_eq!(instance.state, OwnershipState::Acquired);

        let result = instance.transition(OwnershipEvent::ConditionalRelease { function: 20 });
        assert!(
            result.is_ok(),
            "ConditionalRelease from Acquired must succeed"
        );
        assert_eq!(
            instance.state,
            OwnershipState::Released,
            "ConditionalRelease from Acquired must transition to Released"
        );
        assert_eq!(
            instance.released_in,
            Some(20),
            "released_in must be set for definitive ConditionalRelease"
        );
    }

    /// Objective: Verify the full Python refcount pattern:
    ///            Acquired → Retained → ConditionalRelease → Acquired
    ///            This models Py_INCREF / Py_DECREF where the object stays alive.
    /// Invariants: After the cycle, state == Acquired (object still alive).
    #[test]
    fn test_incr_decr_cycle_preserves_acquired() {
        let mut instance =
            ResourceInstance::new(1, FamilyId::PYTHON_OBJECT, PointerContract::Owned);

        // Py_INCREF
        instance.transition(OwnershipEvent::Retain).expect(
            "ownership_state::test_incr_decr_cycle_preserves_acquired: Retain must succeed",
        );
        assert_eq!(instance.state, OwnershipState::Retained);

        // Py_DECREF (refcount > 0 after decrement)
        instance
            .transition(OwnershipEvent::ConditionalRelease { function: 30 })
            .expect("ownership_state::test_incr_decr_cycle_preserves_acquired: ConditionalRelease from Retained must succeed");
        assert_eq!(
            instance.state,
            OwnershipState::Acquired,
            "After Py_INCREF/Py_DECREF cycle, object is still Acquired"
        );
        assert!(
            instance.is_leak_candidate(),
            "Still a leak candidate — needs a final release"
        );
    }

    /// Objective: Verify that ConditionalRelease from Released is DoubleRelease.
    /// Invariants: Already-released resource cannot be conditionally released.
    #[test]
    fn test_conditional_release_from_released_is_double_release() {
        let mut instance =
            ResourceInstance::new(1, FamilyId::PYTHON_OBJECT, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Release { function: 40 })
            .expect("ownership_state::test_conditional_release_from_released_is_double_release: Release must succeed");

        let result = instance.transition(OwnershipEvent::ConditionalRelease { function: 41 });
        assert!(
            result.is_err(),
            "ConditionalRelease from Released must fail"
        );
        assert_eq!(
            instance.state,
            OwnershipState::Released,
            "State must remain Released"
        );
    }

    /// Objective: Verify that ConditionalRelease from Borrowed is an error.
    /// Invariants: Borrowed resources cannot be released at all.
    #[test]
    fn test_conditional_release_from_borrowed_is_error() {
        let mut instance = ResourceInstance::new_borrowed(1, FamilyId::C_HEAP);
        let result = instance.transition(OwnershipEvent::ConditionalRelease { function: 42 });
        assert!(
            result.is_err(),
            "ConditionalRelease from Borrowed must fail"
        );
    }

    /// Objective: Verify that ConditionalRelease from Escaped transitions
    ///            to Released (same semantics as unconditional Release).
    /// Invariants: Escaped + ConditionalRelease → Released.
    #[test]
    fn test_conditional_release_from_escaped_to_released() {
        let mut instance = ResourceInstance::new(1, FamilyId::C_HEAP, PointerContract::Owned);
        instance
            .transition(OwnershipEvent::Escape {
                kind: EscapeKind::RawPointer,
            })
            .expect("ownership_state::test_conditional_release_from_escaped_to_released: Escape must succeed");

        let result = instance.transition(OwnershipEvent::ConditionalRelease { function: 50 });
        assert!(
            result.is_ok(),
            "ConditionalRelease from Escaped must succeed"
        );
        assert_eq!(instance.state, OwnershipState::Released);
    }

    // ── new_borrowed() factory method tests ──

    /// Objective: Verify that new_borrowed() creates an instance in Borrowed
    ///            state with Borrowed contract.
    /// Invariants: state == Borrowed, contract == Borrowed.
    #[test]
    fn test_new_borrowed_factory() {
        let instance = ResourceInstance::new_borrowed(42, FamilyId::C_HEAP);
        assert_eq!(instance.id, 42);
        assert_eq!(instance.family, FamilyId::C_HEAP);
        assert_eq!(instance.state, OwnershipState::Borrowed);
        assert_eq!(instance.contract, PointerContract::Borrowed);
        assert!(
            !instance.is_leak_candidate(),
            "Borrowed resource is NOT a leak candidate"
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
            EscapeKind::RawPointer,
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
