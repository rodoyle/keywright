//! Age-encrypted at-rest storage for transport material.
//!
//! `keywright install` generates an age identity in the broker's protected
//! data dir; everything sensitive (transport CA key, issued client keys) is
//! encrypted to that identity before touching disk. Backups of the identity
//! are a separate human responsibility (documented in install output).

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use age::{Decryptor, Encryptor};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum AgeStoreError {
    #[error("age operation failed: {0}")]
    Age(#[from] age::EncryptError),
    #[error("age decrypt failed: {0}")]
    Decrypt(#[from] age::DecryptError),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a valid age identity: {0}")]
    BadIdentity(String),
    #[error("not a valid age recipient: {0}")]
    BadRecipient(String),
    #[error("empty plaintext not permitted for key material")]
    EmptyPlaintext,
}

/// A newly generated or loaded age identity pair.
pub struct AgeIdentity {
    /// The identity (secret). Handle with care: never log, never return to agents.
    identity: Identity,
    /// The corresponding recipient (public), safe to store in config.
    pub recipient: Recipient,
}

/// Debug intentionally prints only the public recipient, never the secret
/// identity material.
impl std::fmt::Debug for AgeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgeIdentity")
            .field("recipient", &self.recipient_string())
            .finish_non_exhaustive()
    }
}

impl AgeIdentity {
    /// Generate a fresh age identity.
    pub fn generate() -> Self {
        let identity = Identity::generate();
        let recipient = identity.to_public();
        AgeIdentity {
            identity,
            recipient,
        }
    }

    pub fn recipient_string(&self) -> String {
        self.recipient.to_string()
    }

    /// Serialize the secret identity to its textual form, for protected at-rest
    /// storage only.
    pub fn identity_to_string(&self) -> String {
        self.identity.to_string().expose_secret().to_owned()
    }

    /// Load an identity from its textual form.
    pub fn from_string(s: &str) -> Result<Self, AgeStoreError> {
        let identity: Identity = s
            .trim()
            .parse()
            .map_err(|e: &str| AgeStoreError::BadIdentity(e.to_string()))?;
        let recipient = identity.to_public();
        Ok(AgeIdentity {
            identity,
            recipient,
        })
    }

    /// Encrypt bytes to this identity's recipient.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AgeStoreError> {
        encrypt_to(&self.recipient, plaintext)
    }

    /// Decrypt bytes encrypted to this identity's recipient.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AgeStoreError> {
        decrypt_with(&self.identity_to_string(), ciphertext)
    }
}

/// Encrypt plaintext to an age recipient string (e.g. from config).
pub fn encrypt_to(recipient: &Recipient, plaintext: &[u8]) -> Result<Vec<u8>, AgeStoreError> {
    if plaintext.is_empty() {
        return Err(AgeStoreError::EmptyPlaintext);
    }
    let encryptor = Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
        .map_err(AgeStoreError::Age)?;
    let mut writer = encryptor.wrap_output(Vec::new())?;
    writer.write_all(plaintext)?;
    writer.finish().map_err(|e| AgeStoreError::Age(e.into()))
}

/// Decrypt age ciphertext using an identity string.
pub fn decrypt_with(identity: &str, ciphertext: &[u8]) -> Result<Vec<u8>, AgeStoreError> {
    let parsed: Identity = identity
        .trim()
        .parse()
        .map_err(|e: &str| AgeStoreError::BadIdentity(e.to_string()))?;
    let decryptor = Decryptor::new(std::io::Cursor::new(ciphertext))?;
    let mut reader = decryptor.decrypt(std::iter::once(&parsed as &dyn age::Identity))?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

/// Parse a recipient from a config string.
pub fn parse_recipient(s: &str) -> Result<Recipient, AgeStoreError> {
    s.trim()
        .parse()
        .map_err(|e: &str| AgeStoreError::BadRecipient(e.to_string()))
}

/// Write a file with plaintext mode 0600 on unix (best effort) — private
/// identity material must never be world-readable.
pub fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), AgeStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            std::fs::remove_file(path)?; // avoid inheriting prior permissions/ACLs
        }
        std::fs::write(path, contents)?;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        std::fs::write(path, contents)?;
        // Restrict to the current owner via an inherited-deny for others is
        // done by `keywright install` ACL step; here we just write.
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trips() {
        let id = AgeIdentity::generate();
        let secret = b"transport-ca-key-material";
        let ct = id.encrypt(secret).unwrap();
        assert_ne!(ct.as_slice(), secret);
        // Ciphertext never contains the plaintext.
        assert!(!String::from_utf8_lossy(&ct).contains("transport-ca-key"));
        let pt = id.decrypt(&ct).unwrap();
        assert_eq!(pt, secret);
    }

    #[test]
    fn identity_serializes_and_reloads() {
        let id = AgeIdentity::generate();
        let s = id.identity_to_string();
        assert!(s.starts_with("AGE-SECRET-KEY-"));
        let reloaded = AgeIdentity::from_string(&s).unwrap();
        assert_eq!(reloaded.recipient_string(), id.recipient_string());
        let secret = b"x";
        assert_eq!(
            reloaded.decrypt(&id.encrypt(secret).unwrap()).unwrap(),
            secret
        );
    }

    #[test]
    fn wrong_identity_cannot_decrypt() {
        let a = AgeIdentity::generate();
        let b = AgeIdentity::generate();
        let ct = a.encrypt(b"secret").unwrap();
        assert!(b.decrypt(&ct).is_err());
    }

    #[test]
    fn empty_plaintext_rejected() {
        let id = AgeIdentity::generate();
        assert!(matches!(
            id.encrypt(b""),
            Err(AgeStoreError::EmptyPlaintext)
        ));
    }
}
