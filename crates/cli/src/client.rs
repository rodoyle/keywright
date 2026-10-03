//! Minimal mTLS HTTP client for the keywright CLI.
//!
//! Talks to the loopback broker with the enrolled client certificate.
//! Only the small request surface the human CLI needs: approve, import,
//! list, describe. The MCP adapter (M7) is the richer agent client.

use keywright_core::datadir::DataDir;
use openssl::ssl::{SslConnector, SslFiletype, SslMethod};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] openssl::error::ErrorStack),
    #[error("handshake refused: the broker rejected this client identity")]
    Handshake,
    #[error("missing client material: {0}")]
    MissingClient(String),
    #[error("http: unexpected status {0}")]
    Status(u16),
    #[error("bad response body: {0}")]
    Parse(String),
}

/// Connection settings derived from the installed layout.
#[derive(Debug, Clone)]
pub struct BrokerClient {
    pub addr: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: PathBuf,
}

impl BrokerClient {
    /// Build from an enrolled client dir plus the broker data dir.
    pub fn from_dirs(
        broker_data: &DataDir,
        client_dir: &Path,
        addr: String,
    ) -> Result<Self, ClientError> {
        let cert_path = client_dir.join("client.pem");
        let key_path = client_dir.join("client.key");
        if !cert_path.is_file() || !key_path.is_file() {
            return Err(ClientError::MissingClient(format!(
                "{} (run `keywright enroll`)",
                client_dir.display()
            )));
        }
        Ok(BrokerClient {
            addr,
            cert_path,
            key_path,
            ca_path: broker_data.ca_cert(),
        })
    }

    /// Read the broker bind address from its config.
    pub fn addr_from_config(broker_data: &DataDir) -> Result<String, ClientError> {
        let cfg = std::fs::read_to_string(broker_data.broker_config())?;
        let parsed: serde_json::Value =
            serde_json::from_str(&cfg).map_err(|e| ClientError::Parse(e.to_string()))?;
        parsed["bind"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| ClientError::Parse("bind missing from broker.json".into()))
    }

    /// Perform one HTTPS request; returns (status, body).
    pub fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), ClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        runtime.block_on(async {
            let mut builder = SslConnector::builder(SslMethod::tls())?;
            builder.set_certificate_file(&self.cert_path, SslFiletype::PEM)?;
            builder.set_private_key_file(&self.key_path, SslFiletype::PEM)?;
            builder.set_ca_file(&self.ca_path)?;

            let tcp = tokio::net::TcpStream::connect(&self.addr).await?;
            let ssl = builder.build().configure()?.into_ssl("localhost")?;
            let mut stream = tokio_openssl::SslStream::new(ssl, tcp)?;
            std::pin::Pin::new(&mut stream)
                .connect()
                .await
                .map_err(|_| ClientError::Handshake)?;

            let body_text = body.unwrap_or("");
            let req = format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_text.len(),
                body_text,
            );
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            stream.write_all(req.as_bytes()).await?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await?;
            let text = String::from_utf8_lossy(&buf).into_owned();
            let status = text
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or(ClientError::Handshake)?;
            let resp_body = text
                .split_once("\r\n\r\n")
                .map(|(_, b)| b.to_string())
                .unwrap_or_default();
            Ok((status, resp_body))
        })
    }
}

/// `keywright approve <op-id>`: approve a pending operation under the
/// enrolled (admin) identity.
pub fn approve(client: &BrokerClient, op_id: &str) -> Result<String, ClientError> {
    let body = serde_json::json!({ "op": op_id }).to_string();
    let (status, resp) = client.request("POST", "/admin/approve", Some(&body))?;
    Ok(render(status, &resp))
}

/// `keywright import`: read the secret from stdin (NEVER argv) and deliver
/// it to the broker's trusted import endpoint over mTLS.
pub fn import_from_stdin(client: &BrokerClient, id: &str) -> Result<String, ClientError> {
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        return Err(ClientError::Io(std::io::Error::other(
            "refusing to import an empty secret",
        )));
    }
    let body = serde_json::json!({ "id": id, "value": value }).to_string();
    let (status, resp) = client.request("POST", "/admin/import", Some(&body))?;
    Ok(render(status, &resp))
}

/// `keywright list`: metadata-only inventory from the agent surface.
pub fn list(client: &BrokerClient) -> Result<String, ClientError> {
    let (status, resp) = client.request("GET", "/credential/list", None)?;
    Ok(render(status, &resp))
}

fn render(status: u16, body: &str) -> String {
    if (200..300).contains(&status) {
        body.to_string()
    } else {
        format!("HTTP {status}: {body}")
    }
}
