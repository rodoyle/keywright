//! Metadata-only credential inventory.
//!
//! The inventory tracks [CredentialRef]s (never secret values) durably in
//! the broker's protected data dir. Agents read it through
//! credential.list/describe; the broker updates it as provisioning and
//! rotation progress.

use crate::refs::{CredentialKind, CredentialRef, CredentialVersion};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("corrupt inventory: {0}")]
    Corrupt(String),
    #[error("credential {0} not found")]
    NotFound(String),
}

/// Durable, metadata-only inventory of broker-managed credentials.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    creds: BTreeMap<String, CredentialRef>,
}

impl Inventory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a JSON file; a missing file yields an empty inventory.
    pub fn load(path: &Path) -> Result<Self, InventoryError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let bytes = std::fs::read(path)?;
        serde_json::from_slice(&bytes).map_err(|e| InventoryError::Corrupt(e.to_string()))
    }

    pub fn save(&self, path: &Path) -> Result<(), InventoryError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    /// Insert or update a credential reference.
    pub fn upsert(&mut self, cred: CredentialRef) {
        self.creds.insert(cred.id.clone(), cred);
    }

    /// Record a newly requested credential (id must be fresh).
    pub fn record_request(&mut self, id: &str, kind: CredentialKind) -> Result<(), InventoryError> {
        if self.creds.contains_key(id) {
            return Ok(()); // idempotent: an existing request stays as-is
        }
        self.creds
            .insert(id.to_string(), CredentialRef::new_request(id, kind));
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<&CredentialRef, InventoryError> {
        self.creds
            .get(id)
            .ok_or_else(|| InventoryError::NotFound(id.to_string()))
    }

    pub fn get_mut(&mut self, id: &str) -> Result<&mut CredentialRef, InventoryError> {
        self.creds
            .get_mut(id)
            .ok_or_else(|| InventoryError::NotFound(id.to_string()))
    }

    /// All references, metadata only, ordered by id.
    pub fn list(&self) -> Vec<&CredentialRef> {
        self.creds.values().collect()
    }

    /// Mark a credential as provisioned at its current version.
    pub fn mark_provisioned(&mut self, id: &str) -> Result<(), InventoryError> {
        let cred = self.get_mut(id)?;
        cred.provisioning = crate::refs::ProvisioningStatus::Provisioned;
        Ok(())
    }

    /// Advance the version after a completed rotation.
    pub fn advance_version(&mut self, id: &str) -> Result<CredentialVersion, InventoryError> {
        let cred = self.get_mut(id)?;
        cred.version = cred.version.next();
        Ok(cred.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refs::CredentialKind;

    #[test]
    fn inventory_persists_and_reloads_metadata_only() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("inv.json");
        let mut inv = Inventory::new();
        inv.record_request("rustfs/access-key", CredentialKind::Token)
            .unwrap();
        inv.save(&path).unwrap();

        let reloaded = Inventory::load(&path).unwrap();
        assert_eq!(
            reloaded.get("rustfs/access-key").unwrap().kind,
            CredentialKind::Token
        );

        // Metadata files never contain secret-valued fields. ("token" as a
        // CredentialKind enum value is legitimate metadata, not a secret.)
        let raw = std::fs::read_to_string(&path).unwrap();
        for banned in ["\"value\"", "\"secret\"", "\"material\"", "\"password\""] {
            assert!(!raw.contains(banned), "inventory leaked field {banned}");
        }
    }

    #[test]
    fn missing_file_loads_empty_and_missing_creds_error() {
        let tmp = tempfile::tempdir().unwrap();
        let inv = Inventory::load(&tmp.path().join("none.json")).unwrap();
        assert!(inv.list().is_empty());
        assert!(matches!(inv.get("nope"), Err(InventoryError::NotFound(_))));
    }

    #[test]
    fn record_request_is_idempotent_and_versions_advance() {
        let mut inv = Inventory::new();
        inv.record_request("a/b", CredentialKind::Password).unwrap();
        inv.record_request("a/b", CredentialKind::Password).unwrap();
        assert_eq!(inv.list().len(), 1);

        inv.mark_provisioned("a/b").unwrap();
        // lifecycle is still PLANNED, so not ready despite provisioning.
        assert!(!inv.get("a/b").unwrap().is_ready());
        let v = inv.advance_version("a/b").unwrap();
        assert_eq!(v, CredentialVersion(2));
    }
}
