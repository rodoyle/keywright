//! Canonical layout inside the broker's protected data dir, shared by the
//! CLI (install/enroll) and the broker (startup). The dir is owned by the
//! dedicated service account with OS ACLs denying the agent's user write
//! access.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DataDir {
    pub root: PathBuf,
}

impl DataDir {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DataDir { root: root.into() }
    }

    pub fn age_identity(&self) -> PathBuf {
        self.root.join("transport.agekey")
    }

    pub fn ca_cert(&self) -> PathBuf {
        self.root.join("transport-ca.pem")
    }

    pub fn ca_key_encrypted(&self) -> PathBuf {
        self.root.join("transport-ca.key.age")
    }

    pub fn server_cert(&self) -> PathBuf {
        self.root.join("broker-server.pem")
    }

    pub fn server_key_encrypted(&self) -> PathBuf {
        self.root.join("broker-server.key.age")
    }

    pub fn broker_config(&self) -> PathBuf {
        self.root.join("broker.json")
    }

    pub fn service_unit_dir(&self) -> PathBuf {
        self.root.join("service")
    }

    pub fn is_installed(&self) -> bool {
        self.broker_config().is_file()
    }
}

/// Default per-platform data dir location.
pub fn default_data_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/keywright")
    }
    #[cfg(windows)]
    {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
            .join("keywright")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("./keywright-data")
    }
}

/// Load a private, plaintext-on-disk identity file into memory.
pub fn read_identity_file(path: &Path) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)
}
