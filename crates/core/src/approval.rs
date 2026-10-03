//! Durable approval records for privileged operations.
//!
//! When policy does not auto-approve, the broker records a PENDING_APPROVAL
//! operation with a stable id. A human approves it through the CLI under an
//! admin identity; agents can never approve their own requests
//! (requester ≠ approver, enforced by role checks in the broker handlers).

use crate::outcome::OperationId;
use crate::role::Role;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("corrupt approval store: {0}")]
    Corrupt(String),
    #[error("operation {0} not found")]
    NotFound(String),
    #[error("operation {0} is not pending (already {1})")]
    NotPending(String, &'static str),
    #[error("agents cannot approve; an admin identity must approve {0}")]
    NotApprover(String),
}

/// What the operation will do, resolved by the broker — never raw agent input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OperationPlan {
    Provision {
        credential: String,
        version: u32,
    },
    Rotate {
        credential: String,
        from_version: u32,
    },
    Renew {
        credential: String,
    },
    Rekey {
        credential: String,
    },
}

/// A recorded operation awaiting (or having received) approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOp {
    pub id: OperationId,
    pub plan: OperationPlan,
    /// Role + identity of the requester, for the audit trail.
    pub requester_role: Role,
    pub requester_identity: String,
    /// Approved (by policy or human) or still pending.
    pub approved: bool,
    /// Unix seconds when recorded.
    pub created_at: u64,
}

impl PendingOp {
    /// Is this operation still awaiting a human decision?
    pub fn is_pending(&self) -> bool {
        !self.approved
    }
}

/// Durable store of approval records.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ApprovalStore {
    ops: BTreeMap<String, PendingOp>,
}

impl ApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Result<Self, ApprovalError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|e| ApprovalError::Corrupt(e.to_string()))
    }

    pub fn save(&self, path: &Path) -> Result<(), ApprovalError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    /// Record a pending (or policy-approved) operation. Stable ids are
    /// supplied by the caller (the broker's id mint).
    pub fn record(
        &mut self,
        id: OperationId,
        plan: OperationPlan,
        requester_role: Role,
        requester_identity: &str,
        already_approved: bool,
    ) -> &PendingOp {
        let op = PendingOp {
            id: id.clone(),
            plan,
            requester_role,
            requester_identity: requester_identity.to_string(),
            approved: already_approved,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        self.ops.insert(id.0.clone(), op);
        self.ops.get(&id.0).expect("just inserted")
    }

    pub fn get(&self, id: &str) -> Result<&PendingOp, ApprovalError> {
        self.ops
            .get(id)
            .ok_or_else(|| ApprovalError::NotFound(id.to_string()))
    }

    /// Approve a pending operation. Agents are refused here and at the
    /// handler layer; this is the durable record transition.
    pub fn approve(&mut self, id: &str, approver: Role) -> Result<(), ApprovalError> {
        if !approver.may_approve() {
            return Err(ApprovalError::NotApprover(id.to_string()));
        }
        let op = self
            .ops
            .get_mut(id)
            .ok_or_else(|| ApprovalError::NotFound(id.to_string()))?;
        if op.approved {
            return Err(ApprovalError::NotPending(id.to_string(), "approved"));
        }
        op.approved = true;
        Ok(())
    }

    /// All pending operations, ordered by id.
    pub fn pending(&self) -> Vec<&PendingOp> {
        self.ops.values().filter(|o| o.is_pending()).collect()
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(id: &str, role: Role) -> PendingOp {
        let mut store = ApprovalStore::new();
        store
            .record(
                OperationId::new(id),
                OperationPlan::Provision {
                    credential: "a/b".into(),
                    version: 1,
                },
                role,
                "pi-agent-1",
                false,
            )
            .clone()
    }

    #[test]
    fn record_then_approve_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ops.json");
        let mut store = ApprovalStore::new();
        store.record(
            OperationId::new("op-1"),
            OperationPlan::Rotate {
                credential: "x/y".into(),
                from_version: 1,
            },
            Role::Agent,
            "pi-agent-1",
            false,
        );
        store.save(&path).unwrap();

        let mut reloaded = ApprovalStore::load(&path).unwrap();
        assert_eq!(reloaded.pending().len(), 1);
        reloaded.approve("op-1", Role::Admin).unwrap();
        assert!(!reloaded.get("op-1").unwrap().is_pending());
        assert!(reloaded.pending().is_empty());

        // Idempotent refusal on double approval.
        assert!(matches!(
            reloaded.approve("op-1", Role::Admin),
            Err(ApprovalError::NotPending(_, _))
        ));
    }

    #[test]
    fn agents_cannot_approve() {
        let mut store = ApprovalStore::new();
        store.record(
            OperationId::new("op-2"),
            OperationPlan::Renew {
                credential: "c/d".into(),
            },
            Role::Agent,
            "pi-agent-1",
            false,
        );
        assert!(matches!(
            store.approve("op-2", Role::Agent),
            Err(ApprovalError::NotApprover(_))
        ));
        assert!(store.get("op-2").unwrap().is_pending());
    }

    #[test]
    fn unknown_operations_error() {
        let mut store = ApprovalStore::new();
        assert!(matches!(
            store.approve("ghost", Role::Admin),
            Err(ApprovalError::NotFound(_))
        ));
    }

    #[test]
    fn policy_approved_records_skip_pending() {
        let mut store = ApprovalStore::new();
        store.record(
            OperationId::new("op-3"),
            OperationPlan::Rekey {
                credential: "e/f".into(),
            },
            Role::Agent,
            "pi-agent-1",
            true,
        );
        assert!(!store.get("op-3").unwrap().is_pending());
        assert!(store.pending().is_empty());
        let _ = op; // silence helper-unused in this test variant
    }
}
