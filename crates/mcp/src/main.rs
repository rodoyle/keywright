//! keywright-mcp: the agent-facing stdio MCP adapter.
//!
//! The agent runs this binary as a stdio MCP server; the adapter holds its
//! own low-privilege agent client certificate and forwards every operation
//! to the broker over mTLS loopback HTTPS. Structured outcomes (READY,
//! PENDING_APPROVAL, NEEDS_HUMAN_IMPORT, CONFLICT, DENIED, FAILED) pass
//! through verbatim with stable operation ids; the agent never sees secret
//! material — only metadata.

use keywright_cli::client::BrokerClient;
use keywright_core::datadir::{DataDir, default_data_dir};
use rmcp::handler::server::ServerHandler;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ServiceExt, tool, tool_handler, tool_router, transport::stdio};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

struct KeywrightAdapter {
    client: Arc<BrokerClient>,
    tool_router: ToolRouter<KeywrightAdapter>,
}

impl KeywrightAdapter {
    fn new() -> Self {
        let broker_data = DataDir::new(
            std::env::var("KEYWRIGHT_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| default_data_dir()),
        );
        let client_dir = std::env::var("KEYWRIGHT_CLIENT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./keywright-agent"));
        let addr = BrokerClient::addr_from_config(&broker_data)
            .expect("broker.json readable; run keywright install");
        let client = BrokerClient::from_dirs(&broker_data, &client_dir, addr)
            .expect("enrolled agent client material");
        KeywrightAdapter {
            client: Arc::new(client),
            tool_router: Self::tool_router(),
        }
    }

    async fn call(&self, method: &str, path: &str, body: Option<&str>) -> String {
        match self.client.request(method, path, body) {
            Ok((status, resp)) => format!("HTTP {status}: {resp}"),
            Err(e) => serde_json::json!({
                "outcome": "FAILED",
                "detail": e.to_string(),
            })
            .to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct EnsureParams {
    /// Broker-controlled credential id (e.g. "rustfs/access-key").
    id: String,
    /// Credential kind: password | key_pair | token | tls_pair.
    kind: String,
    /// Destination mapping names (broker-resolved; agents never pin targets).
    #[serde(default)]
    destinations: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct DescribeParams {
    id: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct RotationPlanParams {
    credential: String,
    /// Stable idempotency key; replays with the same key return the record.
    idempotency_key: String,
    #[serde(default)]
    destinations: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct RotationExecuteParams {
    /// The operation id from rotation_plan.
    op: String,
    idempotency_key: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct RotationAbortParams {
    op: String,
    reason: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct CertEnsureParams {
    id: String,
    /// Approved certificate profile name (profiles constrain SANs, EKUs,
    /// algorithms, validity, issuer).
    profile: String,
    sans: Vec<String>,
    validity_days: u32,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct CertRotateParams {
    id: String,
    /// "renew" keeps the application key; "rekey" generates a new one.
    mode: String,
    validity_days: u32,
}

#[tool_router]
impl KeywrightAdapter {
    #[tool(description = "List broker-managed credentials (metadata only, never values).")]
    async fn credential_list(&self) -> String {
        self.call("GET", "/credential/list", None).await
    }

    #[tool(description = "Describe one credential by id (metadata only).")]
    async fn credential_describe(&self, Parameters(p): Parameters<DescribeParams>) -> String {
        self.call("GET", &format!("/credential/describe?id={}", p.id), None)
            .await
    }

    #[tool(
        description = "Idempotently ensure a credential exists. Never overwrites existing credentials. Token kinds return NEEDS_HUMAN_IMPORT."
    )]
    async fn credential_ensure(&self, Parameters(p): Parameters<EnsureParams>) -> String {
        let body = serde_json::to_string(&p).unwrap_or_default();
        self.call("POST", "/credential/ensure", Some(&body)).await
    }

    #[tool(
        description = "Plan a rotation. Returns READY (auto-approved) or PENDING_APPROVAL with a stable operation id."
    )]
    async fn rotation_plan(&self, Parameters(p): Parameters<RotationPlanParams>) -> String {
        let body = serde_json::to_string(&p).unwrap_or_default();
        self.call("POST", "/rotation/plan", Some(&body)).await
    }

    #[tool(
        description = "Execute an approved rotation to DEPLOYED. Verification is broker-controlled and separate."
    )]
    async fn rotation_execute(&self, Parameters(p): Parameters<RotationExecuteParams>) -> String {
        let body = serde_json::to_string(&p).unwrap_or_default();
        self.call("POST", "/rotation/execute", Some(&body)).await
    }

    #[tool(description = "List active rotations (metadata).")]
    async fn rotation_status(&self) -> String {
        self.call("GET", "/rotation/status", None).await
    }

    #[tool(
        description = "Abort a rotation at its current boundary. The old credential stays live."
    )]
    async fn rotation_abort(&self, Parameters(p): Parameters<RotationAbortParams>) -> String {
        let body = serde_json::to_string(&p).unwrap_or_default();
        self.call("POST", "/rotation/abort", Some(&body)).await
    }

    #[tool(
        description = "Inspect certificate credential metadata (expiry, version, provisioning)."
    )]
    async fn certificate_inspect(&self, Parameters(p): Parameters<DescribeParams>) -> String {
        self.call("GET", &format!("/certificate/inspect?id={}", p.id), None)
            .await
    }

    #[tool(
        description = "Idempotently issue an application certificate under an approved profile."
    )]
    async fn certificate_ensure(&self, Parameters(p): Parameters<CertEnsureParams>) -> String {
        let body = serde_json::to_string(&p).unwrap_or_default();
        self.call("POST", "/certificate/ensure", Some(&body)).await
    }

    #[tool(description = "Rotate a certificate: renew (same application key) or rekey (new key).")]
    async fn certificate_rotate(&self, Parameters(p): Parameters<CertRotateParams>) -> String {
        let body = serde_json::to_string(&p).unwrap_or_default();
        self.call("POST", "/certificate/rotate", Some(&body)).await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for KeywrightAdapter {}

#[tokio::main]
async fn main() {
    let handler = KeywrightAdapter::new();
    // stdio transport: the agent speaks MCP on stdin/stdout.
    let server = handler
        .serve(stdio())
        .await
        .expect("stdio MCP server started");
    server.waiting().await.expect("server completed cleanly");
}
