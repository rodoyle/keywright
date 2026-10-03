//! keywright-broker binary entrypoint: loads transport material from the
//! protected data dir and serves the mTLS router.

use keywright_broker::server::{BrokerConfig, BrokerState, serve};
use keywright_broker::tls::TransportMaterial;
use keywright_core::agestore::AgeIdentity;
use keywright_core::datadir::{DataDir, default_data_dir};
use keywright_core::trust::{TrustError, parse_cert, parse_key};
use openssl::asn1::Asn1Time;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("trust: {0}")]
    Trust(#[from] TrustError),
    #[error("age store: {0}")]
    Age(#[from] keywright_core::agestore::AgeStoreError),
    #[error("broker: {0}")]
    Broker(#[from] keywright_broker::server::BrokerError),
    #[error("missing file: {0}")]
    Missing(String),
    #[error("bad config: {0}")]
    Config(String),
}

fn main() {
    if let Err(e) = run() {
        eprintln!("keywright-broker: {e}");
        std::process::exit(1);
    }
}

fn resolve_data_dir() -> DataDir {
    let root = std::env::args()
        .position(|a| a == "--data-dir")
        .and_then(|i| std::env::args().nth(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(default_data_dir);
    DataDir::new(root)
}

fn run() -> Result<(), StartupError> {
    let dd = resolve_data_dir();
    if !dd.is_installed() {
        return Err(StartupError::Missing(format!(
            "no broker installation at {}; run `keywright install` first",
            dd.root.display()
        )));
    }

    let identity_pem = std::fs::read_to_string(dd.age_identity())
        .map_err(|_| StartupError::Missing("transport.agekey".into()))?;
    let age_id = AgeIdentity::from_string(&identity_pem)?;

    let server_key_enc = std::fs::read(dd.server_key_encrypted())
        .map_err(|_| StartupError::Missing("broker-server.key.age".into()))?;
    let server_key_pem = String::from_utf8(age_id.decrypt(&server_key_enc)?)
        .map_err(|e| StartupError::Config(format!("decrypted server key is not UTF-8: {e}")))?;
    let server_cert_pem = std::fs::read_to_string(dd.server_cert())
        .map_err(|_| StartupError::Missing("broker-server.pem".into()))?;
    let ca_cert_pem = std::fs::read_to_string(dd.ca_cert())
        .map_err(|_| StartupError::Missing("transport-ca.pem".into()))?;

    // Fail loudly when the server cert is expired; recovery is a documented
    // CLI command (`keywright recover-transport`), not silent regeneration.
    let cert = parse_cert(&server_cert_pem)?;
    let now = Asn1Time::days_from_now(0).map_err(TrustError::OpenSsl)?;
    match cert.not_after().diff(&now) {
        Ok(d) if d.days < 0 => {
            return Err(StartupError::Config(format!(
                "broker server certificate expired ({}); \
                 run `keywright recover-transport` and restart",
                cert.not_after()
            )));
        }
        Err(_) => {
            return Err(StartupError::Config(
                "cannot determine server certificate validity window".into(),
            ));
        }
        _ => {}
    }
    parse_key(&server_key_pem)?;

    let config_json = std::fs::read_to_string(dd.broker_config())
        .map_err(|_| StartupError::Missing("broker.json".into()))?;
    let config: BrokerConfig = serde_json::from_str(&config_json)
        .map_err(|e| StartupError::Config(format!("broker.json: {e}")))?;

    let material = TransportMaterial::new(server_cert_pem, server_key_pem, ca_cert_pem);
    let state = Arc::new(BrokerState::load(dd, &config, age_id));
    let runtime = tokio::runtime::Runtime::new()?;
    let addr = runtime.block_on(serve(config, material, state))?;
    println!("keywright-broker listening on {addr} (mTLS required)");
    runtime.block_on(std::future::pending::<()>());
    Ok(())
}
