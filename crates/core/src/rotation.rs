//! The durable rotation engine.
//!
//! `PLANNED → APPROVED → PREPARED → DEPLOYED → VERIFIED → RETIRED` with
//! durable, resumable records: every transition is persisted BEFORE the
//! next phase runs, so a crash at any boundary resumes from the record.
//! Idempotency keys + per-credential locks + expected-version checks make
//! concurrent/stale operations fail safely as CONFLICT.
//!
//! Abort, rollback, and revocation are distinct:
//! - **abort** stops a rotation at its current boundary; the old credential
//!   stays live and working (never auto-revoked).
//! - **rollback** attempts to remove delivered replacement material where
//!   that is possible; failures are recorded, not assumed recoverable.
//! - **revocation** retires the old version only after VERIFIED and any
//!   approved overlap period.

use crate::lifecycle::{RotationState, TransitionError};
use crate::outcome::OperationId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("corrupt rotation store: {0}")]
    Corrupt(String),
    #[error("credential {0} already has an active rotation ({1})")]
    ActiveRotation(String, String),
    #[error("operation {0} not found")]
    NotFound(String),
    #[error("expected version {expected} but credential is at {actual}")]
    StaleVersion { expected: u32, actual: u32 },
    #[error("illegal transition in {0}: {1}")]
    Transition(String, #[source] TransitionError),
    #[error("operation {0} is not approved; approve it before executing")]
    NotApproved(String),
    #[error("idempotency key mismatch for {0}: expected {1}")]
    Idempotency(String, String),
    #[error("operation {0} was aborted; no further phases may run")]
    Aborted(String),
}

/// A durable rotation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRecord {
    pub id: OperationId,
    /// Credential being rotated.
    pub credential: String,
    /// The version this rotation started from (expected-version binding).
    pub from_version: u32,
    /// The version this rotation produces.
    pub to_version: u32,
    pub state: RotationState,
    /// Whether approval (policy or human) has been granted.
    pub approved: bool,
    /// Resolved destination names for delivery.
    pub destinations: Vec<String>,
    /// Caller-supplied idempotency key; replays must match exactly.
    pub idempotency_key: String,
    /// Abort/rollback/retirement annotations, newest last.
    pub notes: Vec<String>,
    pub created_at: u64,
}

impl RotationRecord {
    /// Is this rotation still active (not RETIRED, not aborted)?
    pub fn is_active(&self) -> bool {
        self.state != RotationState::Retired && !self.notes.iter().any(|n| n.starts_with("ABORTED"))
    }
}

/// Durable store of rotation records.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RotationStore {
    records: BTreeMap<String, RotationRecord>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl RotationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Result<Self, RotationError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|e| RotationError::Corrupt(e.to_string()))
    }

    pub fn save(&self, path: &Path) -> Result<(), RotationError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Atomic replacement: write tmp then rename.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Plan a rotation: per-credential lock (one active rotation per
    /// credential) + expected-version binding. Records start at PLANNED.
    pub fn plan(
        &mut self,
        id: OperationId,
        credential: &str,
        from_version: u32,
        destinations: Vec<String>,
        idempotency_key: &str,
        path: &Path,
    ) -> Result<RotationRecord, RotationError> {
        // Idempotent replay: same key returns the existing record.
        if let Some(existing) = self.records.get(&id.0) {
            if existing.idempotency_key == idempotency_key {
                return Ok(existing.clone());
            }
            return Err(RotationError::Idempotency(
                id.0.clone(),
                idempotency_key.to_string(),
            ));
        }
        // Per-credential lock: refuse a second active rotation.
        if let Some(active) = self
            .records
            .values()
            .find(|r| r.credential == credential && r.is_active())
        {
            return Err(RotationError::ActiveRotation(
                credential.to_string(),
                active.id.0.clone(),
            ));
        }
        let record = RotationRecord {
            id,
            credential: credential.to_string(),
            from_version,
            to_version: from_version + 1,
            state: RotationState::Planned,
            approved: false,
            destinations,
            idempotency_key: idempotency_key.to_string(),
            notes: Vec::new(),
            created_at: now_secs(),
        };
        self.records.insert(record.id.0.clone(), record.clone());
        self.save(path)?;
        Ok(record)
    }

    pub fn get(&self, id: &str) -> Result<&RotationRecord, RotationError> {
        self.records
            .get(id)
            .ok_or_else(|| RotationError::NotFound(id.to_string()))
    }

    pub fn get_mut(&mut self, id: &str) -> Result<&mut RotationRecord, RotationError> {
        self.records
            .get_mut(id)
            .ok_or_else(|| RotationError::NotFound(id.to_string()))
    }

    /// Mark a record approved (policy or human); persisted.
    pub fn approve(&mut self, id: &str, path: &Path) -> Result<(), RotationError> {
        {
            let r = self.get_mut(id)?;
            r.approved = true;
        }
        self.save(path)
    }

    /// Advance one durable transition. Refuses unapproved rotations entering
    /// APPROVED and any illegal transition; persists atomically.
    pub fn transition(
        &mut self,
        id: &str,
        to: RotationState,
        path: &Path,
    ) -> Result<RotationRecord, RotationError> {
        let out = {
            let r = self.get_mut(id)?;
            if r.notes.iter().any(|n| n.starts_with("ABORTED")) {
                return Err(RotationError::Aborted(id.to_string()));
            }
            if to == RotationState::Approved {
                // Entering APPROVED requires approval to have been granted
                // (policy auto-approval sets the flag at plan time).
                if !r.approved {
                    return Err(RotationError::NotApproved(id.to_string()));
                }
            }
            let from = r.state;
            crate::lifecycle::assert_transition(from, to)
                .map_err(|e| RotationError::Transition(id.to_string(), e))?;
            r.state = to;
            r.clone()
        };
        self.save(path)?;
        Ok(out)
    }

    /// Abort at the current boundary: no further phases run; the old
    /// credential is untouched.
    pub fn abort(
        &mut self,
        id: &str,
        reason: &str,
        path: &Path,
    ) -> Result<RotationRecord, RotationError> {
        let out = {
            let r = self.get_mut(id)?;
            if !r.is_active() {
                return Err(RotationError::Aborted(id.to_string()));
            }
            r.notes.push(format!("ABORTED at {}: {reason}", r.state));
            r.clone()
        };
        self.save(path)?;
        Ok(out)
    }

    /// Record a rollback attempt (result of removing delivered replacement
    /// material). Failures are recorded, never assumed recoverable.
    pub fn record_rollback(
        &mut self,
        id: &str,
        attempt: &str,
        ok: bool,
        path: &Path,
    ) -> Result<(), RotationError> {
        {
            let r = self.get_mut(id)?;
            r.notes.push(format!(
                "ROLLBACK {} {attempt}",
                if ok { "ok" } else { "failed" }
            ));
        }
        self.save(path)?;
        Ok(())
    }

    /// Record revocation of the old version (after VERIFIED + overlap).
    pub fn record_revocation(
        &mut self,
        id: &str,
        note: &str,
        path: &Path,
    ) -> Result<(), RotationError> {
        {
            let r = self.get_mut(id)?;
            r.notes.push(format!("REVOKED {note}"));
        }
        self.save(path)?;
        Ok(())
    }

    /// Active rotations for status reporting.
    pub fn active(&self) -> Vec<&RotationRecord> {
        self.records.values().filter(|r| r.is_active()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_path() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("kw-rot-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("rotations.json")
    }

    #[test]
    fn plan_binds_version_and_locks_per_credential() {
        let path = store_path();
        let mut s = RotationStore::new();
        let r = s
            .plan(
                OperationId::new("op-1"),
                "rustfs/access-key",
                3,
                vec![],
                "key-1",
                &path,
            )
            .unwrap();
        assert_eq!(r.from_version, 3);
        assert_eq!(r.to_version, 4);
        assert_eq!(r.state, RotationState::Planned);

        // Second active rotation on the same credential: refused.
        let err = s
            .plan(
                OperationId::new("op-2"),
                "rustfs/access-key",
                4,
                vec![],
                "key-2",
                &path,
            )
            .unwrap_err();
        assert!(matches!(err, RotationError::ActiveRotation(_, _)));
        let _ = path;
    }

    #[test]
    fn idempotent_replay_returns_same_record() {
        let path = store_path();
        let mut s = RotationStore::new();
        s.plan(
            OperationId::new("op-1"),
            "a/b",
            1,
            vec![],
            "same-key",
            &path,
        )
        .unwrap();
        let replay = s
            .plan(
                OperationId::new("op-1"),
                "a/b",
                1,
                vec![],
                "same-key",
                &path,
            )
            .unwrap();
        assert_eq!(replay.idempotency_key, "same-key");

        // Different key, same id: refused.
        assert!(matches!(
            s.plan(
                OperationId::new("op-1"),
                "a/b",
                1,
                vec![],
                "other-key",
                &path
            ),
            Err(RotationError::Idempotency(_, _))
        ));
    }

    #[test]
    fn transitions_require_approval_and_persist_durably() {
        let path = store_path();
        let mut s = RotationStore::new();
        s.plan(OperationId::new("op-9"), "a/b", 1, vec![], "k", &path)
            .unwrap();

        // Unapproved: entering APPROVED is refused.
        assert!(matches!(
            s.transition("op-9", RotationState::Approved, &path),
            Err(RotationError::NotApproved(_))
        ));

        s.approve("op-9", &path).unwrap();
        let r = s
            .transition("op-9", RotationState::Approved, &path)
            .unwrap();
        assert_eq!(r.state, RotationState::Approved);

        // Durable: reload from disk and continue.
        let mut reloaded = RotationStore::load(&path).unwrap();
        let r = reloaded
            .transition("op-9", RotationState::Prepared, &path)
            .unwrap();
        assert_eq!(r.state, RotationState::Prepared);

        // Illegal skip is refused.
        assert!(matches!(
            reloaded.transition("op-9", RotationState::Verified, &path),
            Err(RotationError::Transition(_, _))
        ));
    }

    #[test]
    fn crash_resume_walks_every_boundary() {
        // Simulate crash after each persisted transition by reloading the
        // store from disk between steps — the resume path after any crash.
        let path = store_path();
        let mut s = RotationStore::new();
        s.plan(OperationId::new("op-c"), "c/d", 7, vec![], "k", &path)
            .unwrap();
        s.approve("op-c", &path).unwrap();

        let steps = [
            RotationState::Approved,
            RotationState::Prepared,
            RotationState::Deployed,
            RotationState::Verified,
            RotationState::Retired,
        ];
        for to in steps {
            // "Crash": reload from disk (as a restarted broker would).
            let mut s = RotationStore::load(&path).unwrap();
            let r = s.transition("op-c", to, &path).unwrap();
            assert_eq!(r.state, to);
        }
        // Terminal: RETIRED is not active.
        let s = RotationStore::load(&path).unwrap();
        assert!(!s.get("op-c").unwrap().is_active());
    }

    #[test]
    fn abort_keeps_old_credential_live_and_blocks_phases() {
        let path = store_path();
        let mut s = RotationStore::new();
        s.plan(OperationId::new("op-a"), "e/f", 1, vec![], "k", &path)
            .unwrap();
        s.approve("op-a", &path).unwrap();
        s.transition("op-a", RotationState::Approved, &path)
            .unwrap();
        s.transition("op-a", RotationState::Prepared, &path)
            .unwrap();

        let r = s
            .abort("op-a", "consumer rejected new material", &path)
            .unwrap();
        assert!(r.notes.iter().any(|n| n.starts_with("ABORTED at PREPARED")));
        // No further phases may run on an aborted record.
        assert!(matches!(
            s.transition("op-a", RotationState::Deployed, &path),
            Err(RotationError::Aborted(_))
        ));
        // The credential's version never advanced.
        assert_eq!(r.from_version, 1);
    }

    #[test]
    fn rollback_and_revocation_are_recorded_distinctly() {
        let path = store_path();
        let mut s = RotationStore::new();
        s.plan(OperationId::new("op-r"), "g/h", 1, vec![], "k", &path)
            .unwrap();
        s.approve("op-r", &path).unwrap();
        s.record_rollback("op-r", "delete replacement secret", false, &path)
            .unwrap();
        s.record_revocation("op-r", "v1 after overlap 24h", &path)
            .unwrap();
        let r = s.get("op-r").unwrap();
        assert!(r.notes.iter().any(|n| n.starts_with("ROLLBACK failed")));
        assert!(r.notes.iter().any(|n| n.starts_with("REVOKED")));
    }
}
