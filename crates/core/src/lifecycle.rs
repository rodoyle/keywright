//! The durable rotation state machine:
//! `PLANNED → APPROVED → PREPARED → DEPLOYED → VERIFIED → RETIRED`.
//!
//! Transitions are strictly ordered and terminal-state aware. The broker
//! persists these states durably and resumes from them after crashes.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Lifecycle state of a credential (rotation) operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RotationState {
    /// A rotation plan exists but has not been approved.
    Planned,
    /// Approved (by policy or human); material not yet generated.
    Approved,
    /// Replacement material generated and persisted encrypted.
    Prepared,
    /// Delivered to approved destinations.
    Deployed,
    /// Consumer verified the new credential through broker-controlled checks.
    Verified,
    /// Old credential retired after verification and overlap period.
    Retired,
}

impl RotationState {
    /// The single forward successor, if any.
    pub fn next(self) -> Option<RotationState> {
        match self {
            RotationState::Planned => Some(RotationState::Approved),
            RotationState::Approved => Some(RotationState::Prepared),
            RotationState::Prepared => Some(RotationState::Deployed),
            RotationState::Deployed => Some(RotationState::Verified),
            RotationState::Verified => Some(RotationState::Retired),
            RotationState::Retired => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        self.next().is_none()
    }

    /// Ordered states, for table-driven tests and audit rendering.
    pub fn all() -> [RotationState; 6] {
        [
            RotationState::Planned,
            RotationState::Approved,
            RotationState::Prepared,
            RotationState::Deployed,
            RotationState::Verified,
            RotationState::Retired,
        ]
    }
}

impl fmt::Display for RotationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RotationState::Planned => "PLANNED",
            RotationState::Approved => "APPROVED",
            RotationState::Prepared => "PREPARED",
            RotationState::Deployed => "DEPLOYED",
            RotationState::Verified => "VERIFIED",
            RotationState::Retired => "RETIRED",
        };
        f.write_str(s)
    }
}

/// A rejected state-machine transition, with the reason the broker records.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransitionError {
    #[error(
        "cannot transition from {from} to {to}: only forward single-step transitions are allowed"
    )]
    IllegalTransition {
        from: RotationState,
        to: RotationState,
    },
    #[error("state {0} is terminal; no further transitions")]
    Terminal(RotationState),
}

/// Apply one forward step, refusing anything illegal.
pub fn advance(from: RotationState) -> Result<RotationState, TransitionError> {
    match from.next() {
        Some(to) => Ok(to),
        None => Err(TransitionError::Terminal(from)),
    }
}

/// Check that `from → to` is the exact expected forward step.
pub fn assert_transition(from: RotationState, to: RotationState) -> Result<(), TransitionError> {
    match from.next() {
        Some(expected) if expected == to => Ok(()),
        Some(expected) => Err(TransitionError::IllegalTransition { from, to: expected }),
        None => Err(TransitionError::Terminal(from)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_chain_is_exact_and_complete() {
        let chain = [
            (RotationState::Planned, RotationState::Approved),
            (RotationState::Approved, RotationState::Prepared),
            (RotationState::Prepared, RotationState::Deployed),
            (RotationState::Deployed, RotationState::Verified),
            (RotationState::Verified, RotationState::Retired),
        ];
        for (from, to) in chain {
            assert_eq!(advance(from), Ok(to));
            assert_transition(from, to).unwrap();
        }
    }

    #[test]
    fn skips_and_backward_transitions_are_illegal() {
        assert!(assert_transition(RotationState::Planned, RotationState::Deployed).is_err());
        assert!(assert_transition(RotationState::Deployed, RotationState::Approved).is_err());
        assert!(assert_transition(RotationState::Planned, RotationState::Planned).is_err());
    }

    #[test]
    fn retired_is_terminal() {
        assert_eq!(
            advance(RotationState::Retired),
            Err(TransitionError::Terminal(RotationState::Retired))
        );
        assert!(RotationState::Retired.is_terminal());
    }

    #[test]
    fn walk_entire_lifecycle() {
        let mut s = RotationState::Planned;
        let mut steps = 0;
        while let Some(next) = s.next() {
            s = next;
            steps += 1;
        }
        assert_eq!(steps, 5);
        assert_eq!(s, RotationState::Retired);
    }

    #[test]
    fn serialization_matches_doc_vocabulary() {
        assert_eq!(
            serde_json::to_string(&RotationState::Planned).unwrap(),
            "\"PLANNED\""
        );
        assert_eq!(
            serde_json::to_string(&RotationState::Verified).unwrap(),
            "\"VERIFIED\""
        );
    }
}
