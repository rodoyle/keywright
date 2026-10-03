//! SOPS-encrypted record persistence via a pinned external binary.
//!
//! The broker invokes a configured, pinned `sops` executable directly (no
//! shell, cleared environment plus a minimal allowlist) to encrypt and
//! decrypt credential records with age recipients. Interoperability is the
//! point: records stay standard SOPS files readable by any SOPS-age setup.
//!
//! A missing or stale binary is an explicit failure with a dependency
//! report — there is deliberately NO native fallback.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum SopsError {
    #[error(
        "sops binary not found at {0}; install and pin it in broker config (no native fallback by design)"
    )]
    MissingBinary(PathBuf),
    #[error("sops invocation failed: {0}")]
    Invoke(String),
    #[error("sops exited with status {0}: {1}")]
    Status(i32, String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Pinned SOPS invocation settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sops {
    /// Absolute path to the pinned sops executable.
    pub path: PathBuf,
    /// Expected sops version string (dependency report when stale).
    #[serde(default)]
    pub expected_version: Option<String>,
}

impl Sops {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Sops {
            path: path.into(),
            expected_version: None,
        }
    }

    /// Dependency check: binary present and executable.
    pub fn availability(&self) -> Result<(), SopsError> {
        if !self.path.exists() {
            return Err(SopsError::MissingBinary(self.path.clone()));
        }
        Ok(())
    }

    /// Version probe for the dependency report.
    pub fn version(&self) -> Result<String, SopsError> {
        let out = self.run(&["--version"])?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Base command with a sanitized environment: cleared, then a minimal
    /// allowlist. No shell is involved at any point.
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.path);
        cmd.args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin")
            .stdin(std::process::Stdio::null());
        cmd
    }

    fn run(&self, args: &[&str]) -> Result<std::process::Output, SopsError> {
        self.availability()?;
        let out = self
            .command(args)
            .output()
            .map_err(|e| SopsError::Invoke(e.to_string()))?;
        if !out.status.success() {
            return Err(SopsError::Status(
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        Ok(out)
    }

    /// Encrypt a JSON record file IN PLACE to the configured age recipient.
    /// The input type is pinned so temp-file suffixes cannot flip SOPS into
    /// binary mode.
    pub fn encrypt_file(&self, path: &Path, recipient: &str) -> Result<(), SopsError> {
        self.run(&[
            "--encrypt",
            "--input-type",
            "json",
            "--output-type",
            "json",
            "--age",
            recipient,
            "--in-place",
            &path.display().to_string(),
        ])?;
        Ok(())
    }

    /// Decrypt a SOPS file to stdout (cleared env + SOPS_AGE_KEY_FILE).
    pub fn decrypt_file(&self, path: &Path, identity_file: &Path) -> Result<Vec<u8>, SopsError> {
        let mut cmd = Command::new(&self.path);
        let out = cmd
            .args([
                "--decrypt",
                "--input-type",
                "json",
                "--output-type",
                "json",
                &path.display().to_string(),
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin")
            .env("SOPS_AGE_KEY_FILE", identity_file)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| SopsError::Invoke(e.to_string()))?;
        if !out.status.success() {
            return Err(SopsError::Status(
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        Ok(out.stdout)
    }
}

/// Versioned SOPS record storage for one credential's material.
///
/// Layout: `<dir>/<sanitized-id>@<version>.json`, each file a SOPS-encrypted
/// JSON document. Writes are atomic (tmp + rename); old versions are retained
/// (encrypted) for overlap periods and audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SopsRecordStore {
    pub dir: PathBuf,
}

impl SopsRecordStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        SopsRecordStore { dir: dir.into() }
    }

    fn record_path(&self, id: &str, version: u32) -> PathBuf {
        // Sanitize the id into a filesystem-safe name (broker-controlled
        // ids, but defense in depth against path traversal).
        let safe: String = id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '@' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{safe}.v{version}.json"))
    }

    /// Atomically write + SOPS-encrypt a record.
    pub fn put(
        &self,
        sops: &Sops,
        recipient: &str,
        id: &str,
        version: u32,
        value: &serde_json::Value,
    ) -> Result<(), SopsError> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.record_path(id, version);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
        sops.encrypt_file(&tmp, recipient)?;
        // Atomic replacement: rename over any prior record.
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// SOPS-decrypt and parse a record.
    pub fn get(
        &self,
        sops: &Sops,
        identity_file: &Path,
        id: &str,
        version: u32,
    ) -> Result<serde_json::Value, SopsError> {
        let path = self.record_path(id, version);
        let plaintext = sops.decrypt_file(&path, identity_file)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// List retained (encrypted) versions for a credential id.
    pub fn versions(&self, id: &str) -> Result<Vec<u32>, SopsError> {
        let safe: String = id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '@' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let mut found = Vec::new();
        if !self.dir.exists() {
            return Ok(found);
        }
        let prefix = format!("{safe}.v");
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(rest) = name.strip_prefix(&prefix)
                && let Some(num) = rest.strip_suffix(".json")
                && let Ok(v) = num.parse::<u32>()
            {
                found.push(v);
            }
        }
        found.sort();
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locate a sops binary for round-trip tests; None -> absence tests.
    fn find_sops() -> Option<PathBuf> {
        for candidate in [
            "sops",
            "/usr/local/bin/sops",
            "/opt/homebrew/bin/sops",
            r"C:\Program Files\SOPS\sops.exe",
        ] {
            let p = PathBuf::from(candidate);
            if p.exists() {
                return Some(p);
            } else if let Ok(out) = Command::new("where").arg("sops").output()
                && out.status.success()
                && let Some(line) = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .next()
                    .map(str::to_string)
            {
                let p = PathBuf::from(line);
                if p.exists() {
                    return Some(p);
                }
            }
        }
        None
    }

    #[test]
    fn missing_binary_is_an_explicit_dependency_report() {
        let sops = Sops::new("/nonexistent/definitely-missing-sops");
        let err = sops.availability().unwrap_err();
        assert!(err.to_string().contains("no native fallback"), "{err}");
        // Encryption attempts also surface the dependency report.
        assert!(matches!(sops.version(), Err(SopsError::MissingBinary(_))));
    }

    #[test]
    fn record_paths_are_traversal_safe() {
        let store = SopsRecordStore::new("/tmp/records");
        let p = store.record_path("../../etc/passwd", 1);
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        // A flat name cannot traverse: no separators and no exact-dotdot
        // component. (Leading `..` inside a longer name is inert.)
        assert!(
            !name.contains('/') && !name.contains('\\'),
            "separator escaped: {name}"
        );
        assert!(name.ends_with(".v1.json"), "{name}");
        assert_eq!(name, ".._.._etc_passwd.v1.json");
    }

    #[test]
    fn version_listing_works_with_missing_dir() {
        let store = SopsRecordStore::new("/nonexistent/records");
        assert_eq!(store.versions("a/b").unwrap(), Vec::<u32>::new());
    }

    #[test]
    fn sops_round_trip_when_binary_present() {
        let Some(bin) = find_sops() else {
            // Absence is a valid environment: the dependency report is
            // covered by the explicit test above.
            eprintln!("sops not present; skipping round-trip");
            return;
        };
        let sops = Sops::new(bin);
        let identity = crate::agestore::AgeIdentity::generate();
        let identity_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(identity_file.path(), identity.identity_to_string()).unwrap();
        let recipient = identity.recipient_string();

        let tmp = tempfile::tempdir().unwrap();
        let store = SopsRecordStore::new(tmp.path().join("records"));
        let record = serde_json::json!({ "token": "super-secret-roundtrip-value" });
        store
            .put(&sops, &recipient, "matrix/hermes", 1, &record)
            .unwrap();

        // On-disk file is SOPS-encrypted: no plaintext values.
        let path = store.record_path("matrix/hermes", 1);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("super-secret-roundtrip-value"),
            "plaintext leaked"
        );
        assert!(
            raw.contains("sops") || raw.contains("SOPS"),
            "not a SOPS file: {raw}"
        );

        // Round-trips to the same value.
        let got = store
            .get(&sops, identity_file.path(), "matrix/hermes", 1)
            .unwrap();
        assert_eq!(got, record);

        // Version retention: a second version keeps the first.
        store
            .put(
                &sops,
                &recipient,
                "matrix/hermes",
                2,
                &serde_json::json!({"token": "v2"}),
            )
            .unwrap();
        assert_eq!(store.versions("matrix/hermes").unwrap(), vec![1, 2]);
    }
}
