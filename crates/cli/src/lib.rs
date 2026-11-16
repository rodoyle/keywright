//! keywright CLI library: install, enroll, approve, import.
//!
//! The CLI is the human-controlled surface. `install` creates the broker's
//! protected data dir, generates the transport CA (age-encrypted at rest),
//! and emits platform service units. `enroll` issues client certificates
//! under a human's control. Privileged OS operations (service registration,
//! ACL application) only run when the CLI is invoked with sufficient
//! privileges; `--dry-run` covers generation logic for tests.

use keywright_core::agestore::{AgeIdentity, AgeStoreError};
use keywright_core::trust::{
    CaMaterial, IssuedCert, generate_transport_ca, issue_client_cert, issue_server_cert,
};
use std::path::{Path, PathBuf};

pub mod client;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("age store: {0}")]
    Age(#[from] AgeStoreError),
    #[error("trust: {0}")]
    Trust(#[from] keywright_core::trust::TrustError),
    #[error(
        "refusing to overwrite existing installation at {0}; move it aside or choose another data dir"
    )]
    AlreadyInstalled(PathBuf),
    #[error("missing installation at {0}; run `keywright install` first")]
    NotInstalled(PathBuf),
    #[error("a file expected to exist is missing: {0}")]
    Missing(String),
    #[error("broker client: {0}")]
    Client(#[from] client::ClientError),
}

pub use keywright_core::datadir::DataDir;

/// Everything `install` created, for reporting and tests.
#[derive(Debug)]
pub struct Installed {
    pub data_dir: PathBuf,
    pub recipient: String,
    pub dry_run: bool,
}

/// Perform the installation. With `dry_run`, material is written under
/// `data_dir` but no OS-level service registration or ACL commands run —
/// this is the mode tests use on all platforms.
pub fn install(data_dir: &DataDir, dry_run: bool) -> Result<Installed, CliError> {
    if data_dir.is_installed() {
        return Err(CliError::AlreadyInstalled(data_dir.root.clone()));
    }
    std::fs::create_dir_all(&data_dir.root)?;
    std::fs::create_dir_all(data_dir.service_unit_dir())?;

    // 1. Age identity for at-rest encryption (back this up separately!).
    let age_id = AgeIdentity::generate();
    keywright_core::agestore::write_private_file(
        &data_dir.age_identity(),
        age_id.identity_to_string().as_bytes(),
    )?;

    // 2. Transport CA; private key age-encrypted at rest.
    let ca = generate_transport_ca("keywright-transport")?;
    let ca_enc = age_id.encrypt(ca.key_pem.as_bytes())?;
    std::fs::write(data_dir.ca_cert(), &ca.cert_pem)?;
    std::fs::write(data_dir.ca_key_encrypted(), &ca_enc)?;

    // 3. Broker server certificate (loopback by default).
    let server = issue_server_cert(&ca, &["localhost"])?;
    let server_key_enc = age_id.encrypt(server.key_pem.as_bytes())?;
    std::fs::write(data_dir.server_cert(), &server.cert_pem)?;
    std::fs::write(data_dir.server_key_encrypted(), &server_key_enc)?;

    // 4. Broker config.
    let config = serde_json::json!({
        "bind": "127.0.0.1:7870",
        "data_dir": data_dir.root,
    });
    let config_bytes =
        serde_json::to_vec_pretty(&config).map_err(|e| CliError::Io(std::io::Error::other(e)))?;
    std::fs::write(data_dir.broker_config(), config_bytes)?;

    // 5. Service units (platform-appropriate).
    let units = service_units(&data_dir.root);
    for (name, contents) in units {
        std::fs::write(data_dir.service_unit_dir().join(name), contents)?;
    }

    if !dry_run {
        apply_platform_hardening(data_dir)?;
    }

    Ok(Installed {
        data_dir: data_dir.root.clone(),
        recipient: age_id.recipient_string(),
        dry_run,
    })
}

/// Issue a client certificate to `out_dir` using the installed transport CA.
/// The CA private key is decrypted only in memory, for the duration of the
/// issuance.
pub fn enroll(
    data_dir: &DataDir,
    common_name: &str,
    role: keywright_core::role::Role,
    out_dir: &Path,
) -> Result<IssuedCert, CliError> {
    if !data_dir.is_installed() {
        return Err(CliError::NotInstalled(data_dir.root.clone()));
    }
    let identity_pem = std::fs::read_to_string(data_dir.age_identity())
        .map_err(|_| CliError::Missing("transport.agekey".into()))?;
    let age_id = AgeIdentity::from_string(&identity_pem)?;

    let ca_enc = std::fs::read(data_dir.ca_key_encrypted())
        .map_err(|_| CliError::Missing("transport-ca.key.age".into()))?;
    let ca_key_pem = age_id.decrypt(&ca_enc)?;
    let ca_cert_pem = std::fs::read_to_string(data_dir.ca_cert())
        .map_err(|_| CliError::Missing("transport-ca.pem".into()))?;
    let ca = CaMaterial {
        cert_pem: ca_cert_pem,
        key_pem: String::from_utf8_lossy(&ca_key_pem).into_owned(),
    };

    let issued = issue_client_cert(&ca, common_name, role)?;
    std::fs::create_dir_all(out_dir)?;
    std::fs::write(out_dir.join("client.pem"), &issued.cert_pem)?;
    keywright_core::agestore::write_private_file(
        &out_dir.join("client.key"),
        issued.key_pem.as_bytes(),
    )?;
    Ok(issued)
}

/// Reissue the broker's server certificate from the transport CA. This is
/// the transport-credential recovery path when the server cert expires or
/// the broker cannot start.
pub fn recover_server_cert(data_dir: &DataDir) -> Result<IssuedCert, CliError> {
    if !data_dir.is_installed() {
        return Err(CliError::NotInstalled(data_dir.root.clone()));
    }
    let identity_pem = std::fs::read_to_string(data_dir.age_identity())
        .map_err(|_| CliError::Missing("transport.agekey".into()))?;
    let age_id = AgeIdentity::from_string(&identity_pem)?;
    let ca_enc = std::fs::read(data_dir.ca_key_encrypted())
        .map_err(|_| CliError::Missing("transport-ca.key.age".into()))?;
    let ca_key_pem = age_id.decrypt(&ca_enc)?;
    let ca_cert_pem = std::fs::read_to_string(data_dir.ca_cert())
        .map_err(|_| CliError::Missing("transport-ca.pem".into()))?;
    let ca = CaMaterial {
        cert_pem: ca_cert_pem,
        key_pem: String::from_utf8_lossy(&ca_key_pem).into_owned(),
    };

    let server = issue_server_cert(&ca, &["localhost"])?;
    let server_key_enc = age_id.encrypt(server.key_pem.as_bytes())?;
    // Atomic-ish: write to temp then rename over.
    let tmp = data_dir.server_cert().with_extension("pem.tmp");
    std::fs::write(&tmp, &server.cert_pem)?;
    std::fs::rename(&tmp, data_dir.server_cert())?;
    let tmp_key = data_dir.server_key_encrypted().with_extension("age.tmp");
    std::fs::write(&tmp_key, &server_key_enc)?;
    std::fs::rename(&tmp_key, data_dir.server_key_encrypted())?;
    Ok(server)
}

/// Load the broker's transport material at startup (decrypt server key).
pub fn load_transport_material(
    data_dir: &DataDir,
) -> Result<keywright_core::trust::CaMaterial, CliError> {
    if !data_dir.is_installed() {
        return Err(CliError::NotInstalled(data_dir.root.clone()));
    }
    let identity_pem = std::fs::read_to_string(data_dir.age_identity())
        .map_err(|_| CliError::Missing("transport.agekey".into()))?;
    let age_id = AgeIdentity::from_string(&identity_pem)?;
    let server_key_enc = std::fs::read(data_dir.server_key_encrypted())
        .map_err(|_| CliError::Missing("broker-server.key.age".into()))?;
    let server_key_pem = age_id.decrypt(&server_key_enc)?;
    let server_key_pem = String::from_utf8_lossy(&server_key_pem).into_owned();
    let server_cert_pem = std::fs::read_to_string(data_dir.server_cert())
        .map_err(|_| CliError::Missing("broker-server.pem".into()))?;
    let ca_cert_pem = std::fs::read_to_string(data_dir.ca_cert())
        .map_err(|_| CliError::Missing("transport-ca.pem".into()))?;
    // Reuse CaMaterial shape: cert = server cert, key = server key. The
    // broker's TransportMaterial::new separates these explicitly.
    let _ = ca_cert_pem;
    Ok(keywright_core::trust::CaMaterial {
        cert_pem: server_cert_pem,
        key_pem: server_key_pem,
    })
}

/// Platform service unit files, keyed by filename. All platforms get their
/// native unit written; only the matching one is registered.
pub fn service_units(data_dir: &Path) -> Vec<(&'static str, String)> {
    let bin = "keywright-broker";
    let root = data_dir.display();
    vec![
        (
            "keywright.service",
            format!(
                "[Unit]\nDescription=Keywright credential broker\nAfter=network.target\n\n\
                 [Service]\nType=simple\nUser=keywright\nGroup=keywright\n\
                 ExecStart=/usr/local/bin/{bin} --data-dir {root}\nRestart=on-failure\n\
                 NoNewPrivileges=yes\nProtectSystem=strict\nReadWritePaths={root}\n\n\
                 [Install]\nWantedBy=multi-user.target\n"
            ),
        ),
        (
            "com.keywright.broker.plist",
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
                 \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\">\n<dict>\n\
                 <key>Label</key><string>com.keywright.broker</string>\n\
                 <key>ProgramArguments</key>\n<array>\n\
                 <string>/usr/local/bin/{bin}</string>\n\
                 <string>--data-dir</string>\n<string>{root}</string>\n\
                 </array>\n\
                 <key>RunAtLoad</key><true/>\n\
                 <key>KeepAlive</key><true/>\n\
                 </dict>\n</plist>\n"
            ),
        ),
        (
            "keywright-windows-service.md",
            format!(
                "# Windows service registration\n\n\
                 sc.exe create Keywright binPath= \"C:\\Program Files\\keywright\\{bin}.exe \
                 --data-dir {root}\" start= auto\n\
                 sc.exe description Keywright \"Keywright credential broker\"\n\n\
                 The service account must own the data dir; apply ACLs with:\n\
                 icacls \"{root}\" /inheritance:r /grant:r \"NT SERVICE\\Keywright:(OI)(CI)F\"\n"
            ),
        ),
    ]
}

/// OS-level hardening: only meaningful when running with privileges.
fn apply_platform_hardening(data_dir: &DataDir) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Restrict the data dir to the owner (the installer running as root
        // will chown to the keywright service account separately).
        let mut perms = std::fs::metadata(&data_dir.root)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&data_dir.root, perms)?;
    }
    #[cfg(windows)]
    {
        // Windows ACL hardening is applied by the documented icacls command
        // in the service notes; running it programmatically requires
        // elevation, which install refuses to assume silently.
        let _ = data_dir;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = data_dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_creates_age_encrypted_layout_and_refuses_reinstall() {
        let tmp = tempfile::tempdir().unwrap();
        let dd = DataDir::new(tmp.path().join("data"));
        let installed = install(&dd, true).unwrap();
        assert!(installed.dry_run);
        assert!(dd.is_installed());
        // CA key is encrypted at rest: must not appear in plaintext.
        let ca_key_raw = std::fs::read(dd.ca_key_encrypted()).unwrap();
        let ca_key_text = String::from_utf8_lossy(&ca_key_raw);
        assert!(!ca_key_text.contains("PRIVATE KEY"));
        assert!(!ca_key_text.contains("-----BEGIN"));
        // Identity is private material, not plaintext CA keys.
        let identity = std::fs::read_to_string(dd.age_identity()).unwrap();
        assert!(identity.starts_with("AGE-SECRET-KEY-"));
        // Service units exist for all three platforms.
        for name in [
            "keywright.service",
            "com.keywright.broker.plist",
            "keywright-windows-service.md",
        ] {
            assert!(dd.service_unit_dir().join(name).is_file(), "missing {name}");
        }
        // Second install refuses.
        assert!(matches!(
            install(&dd, true),
            Err(CliError::AlreadyInstalled(_))
        ));
    }

    #[test]
    fn enroll_issues_role_certs_and_recovers_server_cert() {
        let tmp = tempfile::tempdir().unwrap();
        let dd = DataDir::new(tmp.path().join("data"));
        install(&dd, true).unwrap();

        let out = tmp.path().join("agent");
        let issued = enroll(&dd, "pi-agent-1", keywright_core::role::Role::Agent, &out).unwrap();
        assert!(out.join("client.pem").is_file());
        assert!(out.join("client.key").is_file());
        let parsed = keywright_core::trust::parse_cert(
            &std::fs::read_to_string(out.join("client.pem")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            keywright_core::trust::identity_from_cert(&parsed)
                .unwrap()
                .role,
            keywright_core::role::Role::Agent
        );
        let _ = issued;

        let recovered = recover_server_cert(&dd).unwrap();
        assert!(!recovered.cert_pem.is_empty());
    }

    #[test]
    fn enroll_requires_installation() {
        let tmp = tempfile::tempdir().unwrap();
        let dd = DataDir::new(tmp.path().join("nope"));
        assert!(matches!(
            enroll(&dd, "x", keywright_core::role::Role::Agent, tmp.path()),
            Err(CliError::NotInstalled(_))
        ));
    }

    #[test]
    fn service_units_reference_data_dir() {
        let units = service_units(Path::new("/var/lib/keywright"));
        for (_, contents) in &units {
            assert!(contents.contains("/var/lib/keywright"));
        }
        let linux = units
            .iter()
            .find(|(n, _)| *n == "keywright.service")
            .unwrap();
        assert!(linux.1.contains("User=keywright"));
    }
}
