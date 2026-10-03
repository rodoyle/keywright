//! Metadata-only credential references.
//!
//! These types deliberately carry **no secret material**. They are safe to
//! return to agent-facing surfaces (MCP responses, logs, audit records).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// The kind of credential a reference points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// Application-local password.
    Password,
    /// Asymmetric key pair (application key material).
    KeyPair,
    /// Opaque service-issued token (e.g. Matrix/Hermes access token).
    Token,
    /// X.509 certificate plus its application private key.
    TlsPair,
}

impl CredentialKind {
    /// Key names required inside the destination Secret for this kind.
    pub fn required_key_names(&self) -> &'static [&'static str] {
        match self {
            CredentialKind::Password => &["password"],
            CredentialKind::KeyPair => &["private_key", "public_key"],
            CredentialKind::Token => &["token"],
            CredentialKind::TlsPair => &["tls.crt", "tls.key"],
        }
    }
}

impl fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialKind::Password => write!(f, "password"),
            CredentialKind::KeyPair => write!(f, "key_pair"),
            CredentialKind::Token => write!(f, "token"),
            CredentialKind::TlsPair => write!(f, "tls_pair"),
        }
    }
}

/// Monotonic credential version. Versions start at 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CredentialVersion(pub u32);

impl CredentialVersion {
    pub fn initial() -> Self {
        CredentialVersion(1)
    }

    pub fn next(self) -> Self {
        CredentialVersion(self.0.saturating_add(1))
    }
}

impl fmt::Display for CredentialVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Where provisioning currently stands for a credential reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningStatus {
    /// Credential exists and is persisted encrypted.
    Provisioned,
    /// A provisioning request is recorded but no material exists yet.
    Requested,
    /// Automated issuance is unavailable; a human must import the secret.
    NeedsHumanImport,
    /// Present on the broker but not yet delivered to its destination.
    Undelivered,
    /// Delivery reported a failure; recorded, not rolled back silently.
    DeliveryFailed,
}

/// Expiry information, when the credential carries any.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expiry {
    /// Seconds since the Unix epoch.
    pub not_after: u64,
    /// Whether the broker has confirmed expiry with the issuer/cluster.
    pub confirmed: bool,
}

impl Expiry {
    pub fn from_unix_seconds(not_after: u64) -> Self {
        Expiry {
            not_after,
            confirmed: false,
        }
    }

    /// Seconds remaining until expiry; Err if the clock is before the epoch.
    pub fn seconds_remaining(&self) -> Result<u64, SystemTimeError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SystemTimeError)?;
        Ok(self.not_after.saturating_sub(now.as_secs()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("system clock is before the Unix epoch")]
pub struct SystemTimeError;

/// A metadata-only reference to a broker-managed credential.
///
/// Invariant: constructing or serializing this type never involves secret
/// values. Secret material lives only inside encrypted broker records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRef {
    /// Broker-controlled identifier, e.g. `rustfs/access-key`.
    pub id: String,
    pub kind: CredentialKind,
    pub version: CredentialVersion,
    pub lifecycle: crate::lifecycle::RotationState,
    pub provisioning: ProvisioningStatus,
    pub expiry: Option<Expiry>,
    /// Approved destinations (cluster/namespace/secret/key mappings), by name.
    pub destinations: Vec<String>,
}

impl CredentialRef {
    /// Create a fresh, unprovisioned reference for a new credential id.
    pub fn new_request(id: impl Into<String>, kind: CredentialKind) -> Self {
        CredentialRef {
            id: id.into(),
            kind,
            version: CredentialVersion::initial(),
            lifecycle: crate::lifecycle::RotationState::Planned,
            provisioning: ProvisioningStatus::Requested,
            expiry: None,
            destinations: Vec::new(),
        }
    }

    /// Metadata is "ready" when material is provisioned and lifecycle is idle.
    pub fn is_ready(&self) -> bool {
        self.provisioning == ProvisioningStatus::Provisioned
            && self.lifecycle == crate::lifecycle::RotationState::Verified
    }
}

/// Broker-controlled destination mapping: cluster, namespace, Secret, keys.
///
/// Agents never supply these free-form; they reference a mapping by name and
/// the broker resolves it from its protected configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub name: String,
    pub cluster: String,
    pub namespace: String,
    pub secret: String,
    /// Optional explicit key mapping; defaults derive from the credential kind.
    pub key_names: Option<Vec<String>>,
}

impl Destination {
    /// Resolved key names for a credential kind, honoring explicit overrides.
    ///
    /// An explicit mapping must cover exactly the required key names.
    pub fn resolved_key_names(
        &self,
        kind: CredentialKind,
    ) -> Result<Vec<String>, DestinationError> {
        match &self.key_names {
            None => Ok(kind
                .required_key_names()
                .iter()
                .map(|s| s.to_string())
                .collect()),
            Some(explicit) => {
                if explicit.len() != kind.required_key_names().len() {
                    return Err(DestinationError::KeyCountMismatch);
                }
                Ok(explicit.clone())
            }
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DestinationError {
    #[error("explicit key mapping does not match the required key names for this kind")]
    KeyCountMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_key_names_cover_common_secret_shapes() {
        assert_eq!(CredentialKind::Password.required_key_names(), &["password"]);
        assert_eq!(
            CredentialKind::TlsPair.required_key_names(),
            &["tls.crt", "tls.key"]
        );
    }

    #[test]
    fn versions_are_monotonic_and_saturating() {
        let v = CredentialVersion::initial();
        assert_eq!(v.to_string(), "v1");
        assert_eq!(v.next(), CredentialVersion(2));
        assert_eq!(
            CredentialVersion(u32::MAX).next(),
            CredentialVersion(u32::MAX)
        );
    }

    #[test]
    fn new_request_starts_requested_and_planned() {
        let r = CredentialRef::new_request("rustfs/access-key", CredentialKind::Token);
        assert_eq!(r.provisioning, ProvisioningStatus::Requested);
        assert!(!r.is_ready());
        assert_eq!(r.version, CredentialVersion::initial());
    }

    #[test]
    fn destination_defaults_follow_kind_and_overrides_are_validated() {
        let d = Destination {
            name: "rustfs".into(),
            cluster: "homelab".into(),
            namespace: "keywright-demo-rustfs".into(),
            secret: "rustfs-creds".into(),
            key_names: None,
        };
        assert_eq!(
            d.resolved_key_names(CredentialKind::TlsPair).unwrap(),
            vec!["tls.crt".to_string(), "tls.key".to_string()]
        );
        let mismatch = Destination {
            key_names: Some(vec!["one".into()]),
            ..d.clone()
        };
        assert_eq!(
            mismatch.resolved_key_names(CredentialKind::TlsPair),
            Err(DestinationError::KeyCountMismatch)
        );
    }

    #[test]
    fn credential_refs_serialize_without_secret_fields() {
        let r = CredentialRef::new_request("matrix/hermes-token", CredentialKind::Token);
        let json = serde_json::to_string(&r).unwrap();
        for banned in ["value", "secret", "token_value", "material"] {
            assert!(
                !json.contains(&format!("\"{banned}\"")),
                "serialized ref leaked field {banned}"
            );
        }
    }
}
