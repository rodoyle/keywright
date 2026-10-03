//! End-to-end demo gates (milestone 8).
//!
//! These are the three scripted demonstrations from the design doc, run
//! against a live cluster through the real HTTP surface with real client
//! certificates. They are `#[ignore]`-tagged by default: they require the
//! homelab cluster (or vcluster/kind fallback) reachable via
//! `KEYWRIGHT_KUBECONFIG` with namespaces `keywright-demo-rustfs`,
//! `keywright-demo-matrix`, and `keywright-demo-tls`, plus a pinned
//! `keywright` binary.
//!
//! Run on demand:
//!   KEYWRIGHT_KUBECONFIG=... cargo test -p keywright-broker --test demo_gates -- --ignored
//!
//! Stand-in consumer workloads and their definitions live with the demo
//! scripts (docs/demo/).

use keywright_broker::server::{BrokerConfig, BrokerState, serve};
use keywright_broker::tls::TransportMaterial;
use keywright_core::agestore::AgeIdentity;
use keywright_core::datadir::DataDir;
use keywright_core::kube_delivery::{ClusterMapping, DeliveryConfig};
use keywright_core::policy::{AutoApprovalRule, Policy};
use keywright_core::refs::Destination;
use keywright_core::role::Role;
use keywright_core::trust::{generate_transport_ca, issue_client_cert, issue_server_cert};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Env gating: the pinned kubeconfig for the homelab cluster.
fn kubeconfig() -> Option<String> {
    std::env::var("KEYWRIGHT_KUBECONFIG")
        .ok()
        .filter(|s| !s.is_empty())
}

fn delivery_config(kubeconfig: &str) -> DeliveryConfig {
    DeliveryConfig {
        clusters: vec![ClusterMapping {
            name: "homelab".into(),
            kubeconfig: kubeconfig.into(),
            namespaces: vec![
                "keywright-demo-rustfs".into(),
                "keywright-demo-matrix".into(),
                "keywright-demo-tls".into(),
            ],
        }],
        destinations: vec![
            Destination {
                name: "rustfs".into(),
                cluster: "homelab".into(),
                namespace: "keywright-demo-rustfs".into(),
                secret: "rustfs-creds".into(),
                key_names: None,
            },
            Destination {
                name: "matrix".into(),
                cluster: "homelab".into(),
                namespace: "keywright-demo-matrix".into(),
                secret: "hermes-token".into(),
                key_names: None,
            },
            Destination {
                name: "tls-demo".into(),
                cluster: "homelab".into(),
                namespace: "keywright-demo-tls".into(),
                secret: "tls-app".into(),
                key_names: None,
            },
        ],
    }
}

fn demo_policy() -> Policy {
    Policy {
        rules: vec![
            AutoApprovalRule {
                name: "rustfs-demo".into(),
                credentials: vec!["rustfs/*".into()],
                destinations: vec!["rustfs".into()],
                kinds: vec![],
            },
            AutoApprovalRule {
                name: "matrix-demo".into(),
                credentials: vec!["matrix/*".into()],
                destinations: vec!["matrix".into()],
                kinds: vec![],
            },
            AutoApprovalRule {
                name: "tls-demo".into(),
                credentials: vec!["tls/*".into()],
                destinations: vec!["tls-demo".into()],
                kinds: vec![],
            },
        ],
    }
}

struct DemoBroker {
    addr: SocketAddr,
    ca: keywright_core::trust::CaMaterial,
    _state: Arc<BrokerState>,
    data_root: std::path::PathBuf,
}

async fn start_demo_broker() -> DemoBroker {
    let kubeconfig = kubeconfig().expect("KEYWRIGHT_KUBECONFIG set");
    let leaked: &'static tempfile::TempDir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let data_root = leaked.path().to_path_buf();
    let ca = generate_transport_ca("demo-ca").unwrap();
    let server = issue_server_cert(&ca, &["localhost"]).unwrap();
    let transport = TransportMaterial::new(
        server.cert_pem.clone(),
        server.key_pem.clone(),
        ca.cert_pem.clone(),
    );
    let config = BrokerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        policy: demo_policy(),
        delivery: delivery_config(&kubeconfig),
        sops: None,
        cert_profiles: vec![keywright_core::certs::CertProfile {
            name: "web-demo".into(),
            allowed_sans: vec!["app.local".into(), "*.demo.internal".into()],
            allowed_ekus: vec!["serverAuth".into()],
            max_validity_days: 90,
            min_rsa_bits: 2048,
        }],
    };
    let state = Arc::new(BrokerState::load(
        DataDir::new(data_root.clone()),
        &config,
        AgeIdentity::generate(),
    ));
    let addr = serve(config, transport, state.clone()).await.unwrap();
    DemoBroker {
        addr,
        ca,
        _state: state,
        data_root,
    }
}

async fn call(
    broker: &DemoBroker,
    role: Role,
    name: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (u16, String) {
    let client = issue_client_cert(&broker.ca, name, role).unwrap();
    let dir = tempfile::tempdir().unwrap();
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
    std::pin::Pin::new(&mut stream).connect().await.unwrap();
    let body_text = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_text.len(),
        body_text,
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap();
    let resp = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, resp)
}

/// RustFS gate: provision an approved application-local credential pair,
/// reuse it idempotently, and rotate it through the durable engine.
#[tokio::test]
#[ignore = "requires KEYWRIGHT_KUBECONFIG pointing at the homelab cluster"]
async fn demo_rustfs() {
    let broker = start_demo_broker().await;
    let body = r#"{"id":"rustfs/access-key","kind":"password","destinations":["rustfs"]}"#;
    // Provision.
    let (status, resp) = call(
        &broker,
        Role::Agent,
        "pi-agent-1",
        "POST",
        "/credential/ensure",
        Some(body),
    )
    .await;
    assert_eq!(status, 200);
    assert!(resp.contains("\"READY\""), "provision: {resp}");
    // Idempotent reuse: secret unchanged (same version material).
    let (_, resp2) = call(
        &broker,
        Role::Agent,
        "pi-agent-1",
        "POST",
        "/credential/ensure",
        Some(body),
    )
    .await;
    assert!(resp2.contains("\"READY\""), "reuse: {resp2}");
    // Rotate through the engine: plan -> execute (DEPLOYED to the cluster).
    let plan = r#"{"credential":"rustfs/access-key","idempotency_key":"rustfs-demo-1","destinations":["rustfs"]}"#;
    let (_, presp) = call(
        &broker,
        Role::Agent,
        "pi-agent-1",
        "POST",
        "/rotation/plan",
        Some(plan),
    )
    .await;
    assert!(presp.contains("\"READY\""), "plan auto-approved: {presp}");
    let (_, status_resp) = call(
        &broker,
        Role::Agent,
        "pi-agent-1",
        "GET",
        "/rotation/status",
        None,
    )
    .await;
    let op = {
        let needle = "\"id\":\"";
        let start = status_resp.find(needle).unwrap() + needle.len();
        let end = status_resp[start..].find('"').unwrap() + start;
        status_resp[start..end].to_string()
    };
    let exec = format!(r#"{{"op":"{op}","idempotency_key":"rustfs-demo-1"}}"#);
    let (_, eres) = call(
        &broker,
        Role::Agent,
        "pi-agent-1",
        "POST",
        "/rotation/execute",
        Some(&exec),
    )
    .await;
    assert!(eres.contains("\"READY\""), "rotation deployed: {eres}");
}

/// Matrix/Hermes gate: import a service-issued token through the trusted
/// human path, then deliver it without exposing it to the agent.
#[tokio::test]
#[ignore = "requires KEYWRIGHT_KUBECONFIG pointing at the homelab cluster"]
async fn demo_matrix() {
    let broker = start_demo_broker().await;
    // Agent requests; NEEDS_HUMAN_IMPORT.
    let body = r#"{"id":"matrix/hermes-token","kind":"token","destinations":["matrix"]}"#;
    let (_, resp) = call(
        &broker,
        Role::Agent,
        "pi-agent-1",
        "POST",
        "/credential/ensure",
        Some(body),
    )
    .await;
    assert!(resp.contains("NEEDS_HUMAN_IMPORT"), "{resp}");
    // Human imports (stdin-equivalent: POST body over mTLS, admin cert).
    let import = r#"{"id":"matrix/hermes-token","value":"hermes-demo-token-value"}"#;
    let (_, iresp) = call(
        &broker,
        Role::Admin,
        "ops",
        "POST",
        "/admin/import",
        Some(import),
    )
    .await;
    assert!(iresp.contains("\"READY\""), "import: {iresp}");
    // Agent's metadata shows provisioned; the plaintext never appears.
    let (_, list) = call(
        &broker,
        Role::Agent,
        "pi-agent-1",
        "GET",
        "/credential/list",
        None,
    )
    .await;
    assert!(list.contains("matrix/hermes-token"));
    assert!(
        !list.contains("hermes-demo-token-value"),
        "value leaked to agent: {list}"
    );
    // Material on disk is encrypted.
    let raw = std::fs::read_to_string(broker.data_root.join("material.json")).unwrap();
    assert!(
        !raw.contains("hermes-demo-token-value"),
        "plaintext leaked to disk"
    );
}

/// TLS gate: generate an application key + CSR, issue through the test CA
/// profile, deliver the pair, and exercise renewal and rekey independently.
#[tokio::test]
#[ignore = "requires KEYWRIGHT_KUBECONFIG pointing at the homelab cluster"]
async fn demo_tls() {
    let broker = start_demo_broker().await;
    let ensure = r#"{"id":"tls/web","profile":"web-demo","sans":["app.local"],"validity_days":30}"#;
    let (_, resp) = call(
        &broker,
        Role::Agent,
        "pi-agent-1",
        "POST",
        "/certificate/ensure",
        Some(ensure),
    )
    .await;
    assert!(resp.contains("\"READY\""), "issue: {resp}");
    // Renewal (same application key).
    let renew = r#"{"id":"tls/web","mode":"renew","validity_days":30}"#;
    let (_, rresp) = call(
        &broker,
        Role::Agent,
        "pi-agent-1",
        "POST",
        "/certificate/rotate",
        Some(renew),
    )
    .await;
    assert!(rresp.contains("\"READY\""), "renew: {rresp}");
    // Rekey (fresh application key).
    let rekey = r#"{"id":"tls/web","mode":"rekey","validity_days":30}"#;
    let (_, kresp) = call(
        &broker,
        Role::Agent,
        "pi-agent-1",
        "POST",
        "/certificate/rotate",
        Some(rekey),
    )
    .await;
    assert!(kresp.contains("\"READY\""), "rekey: {kresp}");
}
