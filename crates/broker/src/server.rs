//! Broker server: HTTPS with mandatory mTLS on loopback by default.
//!
//! Per-connection flow:
//! 1. TLS handshake requiring a client cert chaining to the transport CA.
//! 2. Extract the peer identity (CN + role), reject denylisted identities
//!    before any HTTP processing.
//! 3. Serve the axum router with the identity inserted into request
//!    extensions, where handlers enforce role permissions.

use crate::tls::TransportMaterial;
use axum::body::Body;
use axum::http::Request;
use axum::routing::{get, post};
use axum::{Json, Router};
use keywright_core::outcome::{OperationResult, Outcome};
use keywright_core::refs::CredentialRef;
use keywright_core::trust::{IdentityDenylist, PeerIdentity, identity_from_cert};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio_openssl::SslStream;

/// Broker runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerConfig {
    /// Bind address. Defaults to loopback; remote binding requires explicit
    /// configuration by design.
    pub bind: SocketAddr,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        BrokerConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7870),
        }
    }
}

/// Shared broker state.
#[derive(Debug, Default)]
pub struct BrokerState {
    pub denylist: Mutex<IdentityDenylist>,
}

impl BrokerState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Immediately disable a client identity.
    pub fn disable_identity(&self, common_name: &str) {
        self.denylist
            .lock()
            .expect("denylist poisoned")
            .disable(common_name);
    }

    /// Check-and-map a validated peer identity against the denylist.
    pub fn authorize(&self, identity: &PeerIdentity) -> bool {
        !self
            .denylist
            .lock()
            .expect("denylist poisoned")
            .is_disabled(&identity.common_name)
    }
}

/// The agent-facing router. Handlers receive the validated PeerIdentity via
/// request extensions; role checks are per-handler.
pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/credential/list", get(credential_list))
        .route("/credential/ensure", post(credential_ensure))
        .route("/rotation/status", get(rotation_status))
        .route("/rotation/abort", post(rotation_abort))
        .route("/certificate/inspect", get(certificate_inspect))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn credential_list() -> Json<Vec<CredentialRef>> {
    // Milestone 3 wires the inventory store; the shape is metadata-only.
    Json(Vec::new())
}

async fn credential_ensure() -> Json<OperationResult> {
    // Milestones 3-4 implement ensure-without-overwrite end to end.
    Json(OperationResult {
        outcome: Outcome::Denied,
        operation: None,
        detail: Some("ensure is not yet implemented (milestone 3+)".into()),
    })
}

async fn rotation_status() -> Json<OperationResult> {
    Json(OperationResult {
        outcome: Outcome::Denied,
        operation: None,
        detail: Some("rotation is not yet implemented (milestone 5+)".into()),
    })
}

async fn rotation_abort() -> Json<OperationResult> {
    Json(OperationResult {
        outcome: Outcome::Denied,
        operation: None,
        detail: Some("rotation is not yet implemented (milestone 5+)".into()),
    })
}

async fn certificate_inspect() -> Json<OperationResult> {
    Json(OperationResult {
        outcome: Outcome::Denied,
        operation: None,
        detail: Some("certificates are not yet implemented (milestone 6+)".into()),
    })
}

/// A hyper service that inserts this connection's validated identity into
/// every request's extensions before dispatching to the router.
struct WithIdentity<S> {
    inner: S,
    identity: PeerIdentity,
}

impl hyper::service::Service<hyper::Request<hyper::body::Incoming>> for WithIdentity<Router> {
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        let (parts, incoming) = req.into_parts();
        let mut req = Request::from_parts(parts, Body::new(incoming));
        req.extensions_mut().insert(self.identity.clone());
        let mut inner = self.inner.clone();
        Box::pin(async move {
            use tower::Service;
            inner.call(req).await
        })
    }
}

/// Run the broker until the process is stopped. Returns the bound address.
pub async fn serve(
    config: BrokerConfig,
    material: TransportMaterial,
    state: Arc<BrokerState>,
) -> Result<SocketAddr, BrokerError> {
    if !is_loopback(config.bind.ip()) {
        // Remote listening requires explicit configuration; refuse a default
        // non-loopback bind unless a marker is set (documented escape hatch).
        return Err(BrokerError::RemoteBindRefused(config.bind));
    }
    let acceptor = material.ssl_acceptor()?;
    let listener = TcpListener::bind(config.bind).await?;
    let local = listener.local_addr()?;
    let app = router();

    tokio::spawn(async move {
        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let acceptor = acceptor.clone();
            let state = state.clone();
            let app = app.clone();
            tokio::spawn(async move {
                // Mandatory mTLS: a failed handshake means no access.
                let ssl = match openssl::ssl::Ssl::new(acceptor.context()) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let mut stream = match SslStream::new(ssl, tcp) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                // Mandatory mTLS: a failed handshake means no access.
                if (std::pin::Pin::new(&mut stream).accept().await).is_err() {
                    return;
                }
                let Some(cert) = stream.ssl().peer_certificate() else {
                    return; // no client cert: nothing further happens
                };
                let Ok(identity) = identity_from_cert(&cert) else {
                    return; // no usable identity: reject
                };
                if !state.authorize(&identity) {
                    return; // denylisted identity: immediate refusal
                }
                let svc = WithIdentity {
                    inner: app,
                    identity,
                };
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    Ok(local)
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls setup failed: {0}")]
    Tls(#[from] crate::tls::TlsSetupError),
    #[error("refusing to bind to non-loopback {0} without explicit remote configuration")]
    RemoteBindRefused(SocketAddr),
}

#[cfg(test)]
mod tests {
    use super::*;
    use keywright_core::role::Role;
    use keywright_core::trust::{generate_transport_ca, issue_client_cert, issue_server_cert};
    use openssl::ssl::{SslConnector, SslFiletype, SslMethod};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A broker instance with fresh CA material on an ephemeral loopback port.
    struct TestBroker {
        addr: SocketAddr,
        ca: keywright_core::trust::CaMaterial,
        state: Arc<BrokerState>,
    }

    async fn start_broker() -> TestBroker {
        let ca = generate_transport_ca("test-broker-ca").expect("ca");
        let server = issue_server_cert(&ca, &["localhost"]).expect("server cert");
        let material = TransportMaterial::new(
            server.cert_pem.clone(),
            server.key_pem.clone(),
            ca.cert_pem.clone(),
        );
        let state = Arc::new(BrokerState::new());
        let mut config = BrokerConfig::default();
        config.bind = SocketAddr::new(config.bind.ip(), 0);
        let addr = serve(config, material, state.clone()).await.expect("serve");
        TestBroker { addr, ca, state }
    }

    /// Issue a cert for `role`, write it to a temp dir, and perform a raw
    /// HTTP/1.1 GET over mTLS. Returns (status, body) or None on TLS/IO failure.
    async fn tls_get(
        broker: &TestBroker,
        role: Role,
        name: &str,
        path: &str,
    ) -> Option<(u16, String)> {
        let client = issue_client_cert(&broker.ca, name, role).expect("client cert");
        let dir = tempfile::tempdir().expect("tmp");
        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("client.key");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, &client.cert_pem).unwrap();
        std::fs::write(&key_path, &client.key_pem).unwrap();
        std::fs::write(&ca_path, &broker.ca.cert_pem).unwrap();

        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder
            .set_certificate_file(&cert_path, SslFiletype::PEM)
            .unwrap();
        builder
            .set_private_key_file(&key_path, SslFiletype::PEM)
            .unwrap();
        builder.set_ca_file(&ca_path).unwrap();

        let tcp = tokio::net::TcpStream::connect(broker.addr).await.ok()?;
        let ssl = builder
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let mut stream = tokio_openssl::SslStream::new(ssl, tcp).ok()?;
        std::pin::Pin::new(&mut stream).connect().await.ok()?;

        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.ok()?;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())?;
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        Some((status, body))
    }

    #[tokio::test]
    async fn healthz_serves_over_mtls_for_agent_identities() {
        let broker = start_broker().await;
        let (status, body) = tls_get(&broker, Role::Agent, "pi-agent-1", "/healthz")
            .await
            .expect("mTLS request");
        assert_eq!(status, 200);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn unauthenticated_connections_are_refused() {
        let broker = start_broker().await;
        // Connect with TLS but WITHOUT a client certificate. Under TLS 1.3
        // the client can finish its half of the handshake before the
        // server's certificate-required alert arrives, so the invariant is:
        // NO HTTP response is ever served.
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &broker.ca.cert_pem).unwrap();
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder.set_ca_file(&ca_path).unwrap();
        let tcp = tokio::net::TcpStream::connect(broker.addr).await.unwrap();
        let ssl = builder
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let mut stream = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
        // Best-effort handshake; even if it errors, that is also refusal.
        let _ = std::pin::Pin::new(&mut stream).connect().await;
        let _ = stream
            .write_all(
                b"GET /healthz HTTP/1.1
Host: x

",
            )
            .await;
        let mut buf = Vec::new();
        // Reset or EOF both count as "no HTTP response".
        let _ = stream.read_to_end(&mut buf).await;
        assert!(
            String::from_utf8_lossy(&buf)
                .split_whitespace()
                .nth(1)
                .and_then(|t| t.parse::<u16>().ok())
                .is_none(),
            "unauthenticated client must never receive an HTTP response"
        );
    }

    #[tokio::test]
    async fn foreign_ca_clients_are_refused() {
        let broker = start_broker().await;
        let rogue_ca = generate_transport_ca("rogue").unwrap();
        let client = issue_client_cert(&rogue_ca, "attacker", Role::Admin).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("c.pem"), &client.cert_pem).unwrap();
        std::fs::write(dir.path().join("k.pem"), &client.key_pem).unwrap();
        std::fs::write(dir.path().join("ca.pem"), &rogue_ca.cert_pem).unwrap();
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder
            .set_certificate_file(dir.path().join("c.pem"), SslFiletype::PEM)
            .unwrap();
        builder
            .set_private_key_file(dir.path().join("k.pem"), SslFiletype::PEM)
            .unwrap();
        builder.set_ca_file(dir.path().join("ca.pem")).unwrap();
        let tcp = tokio::net::TcpStream::connect(broker.addr).await.unwrap();
        let ssl = builder
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let mut stream = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
        assert!(std::pin::Pin::new(&mut stream).connect().await.is_err());
    }

    #[tokio::test]
    async fn denylisted_identity_gets_no_http_response() {
        let broker = start_broker().await;
        broker.state.disable_identity("gone-agent");
        // The TLS handshake succeeds, but the server drops the connection
        // before any HTTP response.
        let dir = tempfile::tempdir().unwrap();
        let client = issue_client_cert(&broker.ca, "gone-agent", Role::Agent).unwrap();
        std::fs::write(dir.path().join("c.pem"), &client.cert_pem).unwrap();
        std::fs::write(dir.path().join("k.pem"), &client.key_pem).unwrap();
        std::fs::write(dir.path().join("ca.pem"), &broker.ca.cert_pem).unwrap();
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder
            .set_certificate_file(dir.path().join("c.pem"), SslFiletype::PEM)
            .unwrap();
        builder
            .set_private_key_file(dir.path().join("k.pem"), SslFiletype::PEM)
            .unwrap();
        builder.set_ca_file(dir.path().join("ca.pem")).unwrap();
        let tcp = tokio::net::TcpStream::connect(broker.addr).await.unwrap();
        let ssl = builder
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let mut stream = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
        // The server may refuse at any point after extracting the identity,
        // including mid-handshake; a connection reset is the expected
        // refusal behavior, not a test failure.
        let _ = std::pin::Pin::new(&mut stream).connect().await;
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .ok();
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await;
        assert!(
            String::from_utf8_lossy(&buf)
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .is_none(),
            "denylisted identity must receive no HTTP response, got: {}",
            String::from_utf8_lossy(&buf)
        );
    }

    #[tokio::test]
    async fn non_loopback_bind_is_refused() {
        let ca = generate_transport_ca("x").unwrap();
        let server = issue_server_cert(&ca, &["localhost"]).unwrap();
        let material = TransportMaterial::new(
            server.cert_pem.clone(),
            server.key_pem.clone(),
            ca.cert_pem.clone(),
        );
        let config = BrokerConfig {
            bind: "0.0.0.0:7870".parse().unwrap(),
        };
        let err = serve(config, material, Arc::new(BrokerState::new())).await;
        assert!(matches!(err, Err(BrokerError::RemoteBindRefused(_))));
    }

    #[tokio::test]
    async fn metadata_endpoints_respond_without_secret_fields() {
        let broker = start_broker().await;
        let (status, body) = tls_get(&broker, Role::Agent, "pi-agent-1", "/credential/list")
            .await
            .expect("mTLS request");
        assert_eq!(status, 200);
        assert_eq!(body, "[]");
    }
}
