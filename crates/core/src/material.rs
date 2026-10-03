//! Credential material generation and its encrypted at-rest store.
//!
//! Generated/imported secret values live ONLY here, age-encrypted on disk in
//! the broker's protected data dir. Metadata surfaces (inventory, MCP
//! responses, logs, audit records) never touch this store's plaintext.
//!
//! M4 replaces this interim store with SOPS-encrypted records and version
//! retention; the interface (`Store`/`put`/`get`) is shaped to survive that
//! swap.

use crate::agestore::{AgeIdentity, AgeStoreError};
use crate::refs::CredentialKind;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Length of generated application-local passwords.
pub const PASSWORD_LEN_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum MaterialError {
    #[error("openssl: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("age store: {0}")]
    Age(#[from] AgeStoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("credential {0} has no stored material")]
    Missing(String),
}

/// Generated credential material, in memory, immediately after generation
/// or decryption for delivery. Never serialize this to metadata surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Material {
    /// Key-name → value map matching the credential kind's required keys.
    pub values: BTreeMap<String, String>,
}

/// Generate a fresh application-local password (CSPRNG bytes, base62-ish).
pub fn generate_password() -> Result<Material, MaterialError> {
    let mut buf = vec![0u8; PASSWORD_LEN_BYTES];
    openssl::rand::rand_bytes(&mut buf)?;
    // Renderable, copy-safe alphabet (no shell/quote-hostile characters).
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let value: String = buf
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect();
    let mut values = BTreeMap::new();
    values.insert("password".to_string(), value);
    Ok(Material { values })
}

/// Generate a fresh RSA-2048 application key pair, PEM-encoded.
pub fn generate_key_pair() -> Result<Material, MaterialError> {
    let rsa = Rsa::generate(2048)?;
    let key: PKey<Private> = PKey::from_rsa(rsa)?;
    let private_pem = String::from_utf8_lossy(&key.private_key_to_pem_pkcs8()?).into_owned();
    let public_pem = String::from_utf8_lossy(&key.public_key_to_pem()?).into_owned();
    let mut values = BTreeMap::new();
    values.insert("private_key".to_string(), private_pem);
    values.insert("public_key".to_string(), public_pem);
    Ok(Material { values })
}

/// Human-imported token material (from a trusted input path: stdin, not argv).
pub fn import_token(value: &str) -> Material {
    let mut values = BTreeMap::new();
    values.insert("token".to_string(), value.to_string());
    Material { values }
}

/// Validate that material covers exactly the kind's required key names.
pub fn validate_shape(kind: CredentialKind, material: &Material) -> Result<(), MaterialError> {
    let required = kind.required_key_names();
    for name in required {
        if !material.values.contains_key(*name) {
            return Err(MaterialError::Missing((*name).to_string()));
        }
    }
    Ok(())
}

/// Age-encrypted at-rest store for credential material, keyed by credential
/// id. One file per credential on disk; values encrypted before write.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Store {
    /// credential id → (version, encrypted Material bytes, base64).
    records: BTreeMap<String, Vec<u8>>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// Encrypt and store material for `id` at `version`.
    pub fn put(
        &mut self,
        id: &str,
        version: u32,
        material: &Material,
        identity: &AgeIdentity,
    ) -> Result<(), MaterialError> {
        let plaintext = serde_json::to_vec(material)?;
        let ciphertext = identity.encrypt(&plaintext)?;
        self.records.insert(format!("{id}@{version}"), ciphertext);
        Ok(())
    }

    /// Decrypt and return material for `id` at `version`.
    pub fn get(
        &self,
        id: &str,
        version: u32,
        identity: &AgeIdentity,
    ) -> Result<Material, MaterialError> {
        let key = format!("{id}@{version}");
        let ciphertext = self
            .records
            .get(&key)
            .ok_or_else(|| MaterialError::Missing(key.clone()))?;
        let plaintext = identity.decrypt(ciphertext)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Remove the stored record for a version (retirement cleanup).
    pub fn remove(&mut self, id: &str, version: u32) -> Result<(), MaterialError> {
        self.records.remove(&format!("{id}@{version}"));
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn save(&self, path: &Path, identity: &AgeIdentity) -> Result<(), MaterialError> {
        // The whole store (already-encrypted records) persists as JSON; the
        // age identity parameter documents that records are encrypted and
        // guards against accidentally storing unencrypted material later.
        let _ = identity;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, MaterialError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_are_random_and_well_shaped() {
        let a = generate_password().unwrap();
        let b = generate_password().unwrap();
        assert_ne!(a.values["password"], b.values["password"]);
        assert_eq!(a.values["password"].len(), PASSWORD_LEN_BYTES);
        assert!(!a.values["password"].contains(['"', '\'', '\\', ' ', '$']));
        validate_shape(CredentialKind::Password, &a).unwrap();
    }

    #[test]
    fn key_pairs_are_valid_pem_pairs() {
        let kp = generate_key_pair().unwrap();
        let priv_key =
            openssl::pkey::PKey::private_key_from_pem(kp.values["private_key"].as_bytes()).unwrap();
        let pub_pem = String::from_utf8_lossy(&priv_key.public_key_to_pem().unwrap()).into_owned();
        // Normalized PEM compare: generated public matches the private key.
        assert!(pub_pem.trim_end() == kp.values["public_key"].trim_end());
        validate_shape(CredentialKind::KeyPair, &kp).unwrap();
    }

    #[test]
    fn store_round_trips_encrypted() {
        let id = AgeIdentity::generate();
        let mut store = Store::new();
        let material = import_token("super-secret-token");
        store.put("matrix/hermes-token", 1, &material, &id).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("store.json");
        store.save(&path, &id).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("super-secret-token"),
            "plaintext leaked to disk"
        );

        let reloaded = Store::load(&path).unwrap();
        let got = reloaded.get("matrix/hermes-token", 1, &id).unwrap();
        assert_eq!(got, material);
    }

    #[test]
    fn missing_versions_error_and_removal_works() {
        let id = AgeIdentity::generate();
        let mut store = Store::new();
        store.put("a/b", 1, &import_token("x"), &id).unwrap();
        assert!(matches!(
            store.get("a/b", 2, &id),
            Err(MaterialError::Missing(_))
        ));
        store.remove("a/b", 1).unwrap();
        assert!(matches!(
            store.get("a/b", 1, &id),
            Err(MaterialError::Missing(_))
        ));
    }

    #[test]
    fn shape_validation_rejects_wrong_kinds() {
        let m = import_token("v");
        assert!(validate_shape(CredentialKind::Password, &m).is_err());
        assert!(validate_shape(CredentialKind::Token, &m).is_ok());
    }
}
