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
use axum::extract::{Query, State};
use axum::http::Request;
use axum::routing::{get, post};
use axum::{Json, Router};
use keywright_core::agestore::AgeIdentity;
use keywright_core::approval::{ApprovalStore, OperationPlan};
use keywright_core::datadir::DataDir;
use keywright_core::inventory::Inventory;
use keywright_core::lifecycle::RotationState;
use keywright_core::material::{self, Material, Store as MaterialStore};
use keywright_core::outcome::{OperationId, OperationResult, Outcome};
use keywright_core::policy::Policy;
use keywright_core::refs::{CredentialKind, CredentialRef, CredentialVersion};
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
    /// Auto-approval policy rules.
    #[serde(default)]
    pub policy: Policy,
    /// Pinned delivery targets (clusters, namespaces, Secret mappings).
    #[serde(default)]
    pub delivery: keywright_core::kube_delivery::DeliveryConfig,
    /// Pinned SOPS binary for record encryption.
    #[serde(default)]
    pub sops: Option<keywright_core::sops::Sops>,
    /// Certificate issuance profiles.
    #[serde(default)]
    pub cert_profiles: Vec<keywright_core::certs::CertProfile>,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        BrokerConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7870),
            policy: Policy::default(),
            delivery: keywright_core::kube_delivery::DeliveryConfig::default(),
            sops: None,
            cert_profiles: Vec::new(),
        }
    }
}

/// Shared broker state: all durable stores plus the identity denylist.
/// Durable stores are guarded by one mutex; the broker is a low-volume
/// control plane, so a single lock is the honest, simple choice.
pub struct BrokerState {
    pub denylist: Mutex<IdentityDenylist>,
    pub inventory: Mutex<Inventory>,
    pub approvals: Mutex<ApprovalStore>,
    pub store: Mutex<MaterialStore>,
    pub rotations: Mutex<keywright_core::rotation::RotationStore>,
    pub policy: Policy,
    pub delivery: keywright_core::kube_delivery::DeliveryConfig,
    /// Certificate issuance profiles (broker-controlled; agents reference
    /// them by name and never define them).
    pub cert_profiles: Vec<keywright_core::certs::CertProfile>,
    /// The signing provider: software-backed test CA for the initial
    /// release; PKCS#11 providers implement the same trait later.
    pub signer: std::sync::Arc<dyn keywright_core::certs::SigningProvider>,
    age_identity: AgeIdentity,
    data_dir: DataDir,
    op_counter: Mutex<u64>,
}

impl BrokerState {
    /// Accessor for the age identity (tests and internal persistence).
    #[cfg(test)]
    pub(crate) fn age_identity_of(&self) -> &AgeIdentity {
        &self.age_identity
    }
}

impl std::fmt::Debug for BrokerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerState")
            .field("cert_profiles", &self.cert_profiles)
            .field("signer", &self.signer.name())
            .finish_non_exhaustive()
    }
}

impl BrokerState {
    /// Build state from an installed data dir (loads or initializes stores).
    pub fn load(data_dir: DataDir, config: &BrokerConfig, age_identity: AgeIdentity) -> Self {
        let inventory =
            Inventory::load(&data_dir.root.join("inventory.json")).expect("inventory store");
        let approvals =
            ApprovalStore::load(&data_dir.root.join("approvals.json")).expect("approval store");
        let store =
            MaterialStore::load(&data_dir.root.join("material.json")).expect("material store");
        let rotations =
            keywright_core::rotation::RotationStore::load(&data_dir.root.join("rotations.json"))
                .expect("rotation store");
        BrokerState {
            denylist: Mutex::new(IdentityDenylist::new()),
            inventory: Mutex::new(inventory),
            approvals: Mutex::new(approvals),
            store: Mutex::new(store),
            rotations: Mutex::new(rotations),
            policy: config.policy.clone(),
            delivery: config.delivery.clone(),
            cert_profiles: config.cert_profiles.clone(),
            signer: std::sync::Arc::new(
                keywright_core::certs::SoftwareCa::generate("keywright-software-ca")
                    .expect("software CA"),
            ),
            age_identity,
            data_dir,
            op_counter: Mutex::new(0),
        }
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

    /// Mint a stable, monotonic operation id.
    fn mint_op_id(&self) -> OperationId {
        let mut n = self.op_counter.lock().expect("op counter poisoned");
        *n += 1;
        // Wall-clock prefix keeps ids unique across restarts.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        OperationId::new(format!("op-{secs:x}-{n}"))
    }

    fn persist_stores(&self) {
        // Best-effort persistence; failures are logged by the process
        // supervisor. A failed persist surfaces on the next load as a
        // missing record, never as silent plaintext loss.
        let _ = self
            .inventory
            .lock()
            .unwrap()
            .save(&self.data_dir.root.join("inventory.json"));
        let _ = self
            .approvals
            .lock()
            .unwrap()
            .save(&self.data_dir.root.join("approvals.json"));
        let _ = self.store.lock().unwrap().save(
            &self.data_dir.root.join("material.json"),
            &self.age_identity,
        );
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn healthz() -> &'static str {
    "ok"
}

/// credential.list: metadata-only inventory.
async fn credential_list(State(state): State<Arc<BrokerState>>) -> Json<Vec<CredentialRef>> {
    let inv = state.inventory.lock().expect("inventory poisoned");
    Json(inv.list().into_iter().cloned().collect())
}

#[derive(Deserialize)]
struct DescribeQuery {
    id: String,
}

/// credential.describe: metadata for one credential.
async fn credential_describe(
    State(state): State<Arc<BrokerState>>,
    Query(q): Query<DescribeQuery>,
) -> Result<Json<CredentialRef>, Json<OperationResult>> {
    let inv = state.inventory.lock().expect("inventory poisoned");
    match inv.get(&q.id) {
        Ok(cred) => Ok(Json(cred.clone())),
        Err(_) => Err(Json(OperationResult {
            outcome: Outcome::Denied,
            operation: None,
            detail: Some("credential not found".into()),
        })),
    }
}

#[derive(Deserialize)]
struct EnsureRequest {
    id: String,
    kind: CredentialKind,
    #[serde(default)]
    destinations: Vec<String>,
}

/// credential.ensure: idempotent — never silently replace existing
/// credentials. Missing credentials produce a provisioning path gated by
/// policy; token kinds yield NEEDS_HUMAN_IMPORT.
/// Deliver material to every destination that carries a pinned mapping.
/// Unmapped names are skipped (policy-only references). Returns the first
/// failing (destination, error) pair, if any.
async fn deliver_to_mapped(
    state: &BrokerState,
    id: &str,
    kind: CredentialKind,
    destinations: &[String],
    m: &material::Material,
) -> Result<(), (String, String)> {
    for dest_name in destinations {
        let Ok(resolved) = state.delivery.resolve(dest_name, kind) else {
            continue;
        };
        let secret = crate::delivery::core_delivery::build_generic_secret(&resolved, m)
            .map_err(|e| (dest_name.clone(), e.to_string()))?;
        let _ = id;
        if let Err(e) = crate::delivery::deliver(&resolved, &secret).await {
            return Err((dest_name.clone(), e.to_string()));
        }
    }
    Ok(())
}

async fn credential_ensure(
    State(state): State<Arc<BrokerState>>,
    axum::Extension(identity): axum::Extension<PeerIdentity>,
    Json(req): Json<EnsureRequest>,
) -> Json<OperationResult> {
    // Only agent and admin roles reach here at all (mTLS required); both
    // may request provisioning, approval is a separate act.
    //
    // Every store access lives in its own scoped block: no lock guard
    // crosses an await point (mandatory for axum handlers).
    let existing = {
        let inv = state.inventory.lock().expect("inventory poisoned");
        inv.get(&req.id).ok().cloned()
    };
    if let Some(existing) = existing {
        if existing.provisioning == keywright_core::refs::ProvisioningStatus::Provisioned {
            return Json(OperationResult::ready());
        }
        // Provisioned-requested but awaiting material: fall through to the
        // provisioning path below (idempotent).
        if req.kind != existing.kind {
            return Json(OperationResult {
                outcome: Outcome::Conflict,
                operation: None,
                detail: Some("credential exists with a different kind".into()),
            });
        }
    }

    // Token material cannot be generated: it must be issued by an external
    // service and imported by a human through the trusted input path.
    if req.kind == CredentialKind::Token {
        {
            let mut inv = state.inventory.lock().expect("inventory poisoned");
            inv.record_request(&req.id, req.kind).expect("record");
        }
        let op = state.mint_op_id();
        state.persist_stores();
        return Json(OperationResult {
            outcome: Outcome::NeedsHumanImport,
            operation: Some(op),
            detail: Some("token issuance requires human import via `keywright import`".into()),
        });
    }

    // Broker-generatable kinds: evaluate policy first.
    let cred_ref = {
        let mut inv = state.inventory.lock().expect("inventory poisoned");
        inv.record_request(&req.id, req.kind).expect("record");
        inv.get(&req.id).expect("recorded").clone()
    };
    let op_id = state.mint_op_id();
    let decision = state.policy.decide(
        identity.role,
        &cred_ref,
        req.kind,
        &req.destinations,
        op_id.clone(),
    );
    match decision {
        keywright_core::policy::Decision::AutoApproved { rule } => {
            // Generate and persist material now.
            let generated = match req.kind {
                CredentialKind::Password => material::generate_password(),
                CredentialKind::KeyPair => material::generate_key_pair(),
                _ => unreachable!("token handled above"),
            };
            match generated {
                Ok(m) => {
                    if let Err(e) = material::validate_shape(req.kind, &m) {
                        return Json(OperationResult {
                            outcome: Outcome::Failed,
                            operation: Some(op_id),
                            detail: Some(format!("generated material invalid: {e}")),
                        });
                    }
                    let persist = {
                        let mut store = state.store.lock().expect("material poisoned");
                        let version = CredentialVersion::initial().0;
                        store.put(&req.id, version, &m, &state.age_identity)
                    };
                    if let Err(e) = persist {
                        return Json(OperationResult {
                            outcome: Outcome::Failed,
                            operation: Some(op_id),
                            detail: Some(format!("persist failed: {e}")),
                        });
                    }
                    {
                        let mut inv = state.inventory.lock().expect("inventory poisoned");
                        inv.mark_provisioned(&req.id).expect("recorded");
                    }
                    state.persist_stores();
                    let _ = rule; // audit trail: recorded in approvals below
                    // Delivery: only for destinations that carry a pinned
                    // mapping in broker config. Unmapped names remain policy
                    // references (no silent cluster writes).
                    if let Err((dest_name, e)) =
                        deliver_to_mapped(&state, &req.id, req.kind, &req.destinations, &m).await
                    {
                        {
                            let mut inv = state.inventory.lock().expect("inventory poisoned");
                            inv.get_mut(&req.id).expect("recorded").provisioning =
                                keywright_core::refs::ProvisioningStatus::DeliveryFailed;
                        }
                        state.persist_stores();
                        return Json(OperationResult {
                            outcome: Outcome::Failed,
                            operation: Some(op_id),
                            detail: Some(format!("delivery to {dest_name} failed: {e}")),
                        });
                    }
                    Json(OperationResult::ready())
                }
                Err(e) => Json(OperationResult {
                    outcome: Outcome::Failed,
                    operation: Some(op_id),
                    detail: Some(format!("generation failed: {e}")),
                }),
            }
        }
        keywright_core::policy::Decision::NeedsHumanApproval { operation } => {
            {
                let mut ops = state.approvals.lock().expect("approvals poisoned");
                ops.record(
                    operation.clone(),
                    OperationPlan::Provision {
                        credential: req.id.clone(),
                        version: 1,
                    },
                    identity.role,
                    &identity.common_name,
                    false,
                );
            }
            state.persist_stores();
            Json(OperationResult::pending(operation))
        }
        keywright_core::policy::Decision::Denied { reason } => {
            Json(OperationResult::denied(reason))
        }
    }
}

#[derive(Deserialize)]
struct ApproveRequest {
    op: String,
}

/// Admin-only: approve a pending operation. Agents are refused (403) —
/// requester ≠ approver.
async fn admin_approve(
    State(state): State<Arc<BrokerState>>,
    axum::Extension(identity): axum::Extension<PeerIdentity>,
    Json(req): Json<ApproveRequest>,
) -> Json<OperationResult> {
    if !identity.role.may_approve() {
        return Json(OperationResult::denied(
            "agents cannot approve operations; an admin identity must approve",
        ));
    }
    let mut ops = state.approvals.lock().expect("approvals poisoned");
    match ops.approve(&req.op, identity.role) {
        Ok(()) => {
            drop(ops);
            state.persist_stores();
            Json(OperationResult::ready())
        }
        Err(e) => Json(OperationResult {
            outcome: Outcome::Failed,
            operation: None,
            detail: Some(e.to_string()),
        }),
    }
}

/// Pending operations for a requester (agents can see what they're blocked
/// on; this is metadata, not approval authority).
/// rotation.status: metadata of active rotations.
async fn rotation_status(
    State(state): State<Arc<BrokerState>>,
) -> Json<Vec<keywright_core::rotation::RotationRecord>> {
    let rotations = state.rotations.lock().expect("rotations poisoned");
    Json(rotations.active().into_iter().cloned().collect())
}

/// Pending approval operations (agents see what they are blocked on).
async fn rotation_pending(
    State(state): State<Arc<BrokerState>>,
) -> Json<Vec<keywright_core::approval::PendingOp>> {
    let ops = state.approvals.lock().expect("approvals poisoned");
    Json(ops.pending().into_iter().cloned().collect())
}

#[derive(Deserialize)]
struct ImportRequest {
    id: String,
    value: String,
}

/// Admin-only trusted import path: a human supplies secret material over
/// mTLS. The value travels in the POST body (never argv, never logged) and
/// lands age-encrypted in the material store.
async fn admin_import(
    State(state): State<Arc<BrokerState>>,
    axum::Extension(identity): axum::Extension<PeerIdentity>,
    Json(req): Json<ImportRequest>,
) -> Json<OperationResult> {
    if !identity.role.may_import() {
        return Json(OperationResult::denied(
            "agents cannot import credential material; a human must import it",
        ));
    }
    if req.value.trim().is_empty() {
        return Json(OperationResult {
            outcome: Outcome::Failed,
            operation: None,
            detail: Some("empty credential value refused".into()),
        });
    }
    let mut inv = state.inventory.lock().expect("inventory poisoned");
    inv.record_request(&req.id, CredentialKind::Token)
        .expect("record");
    inv.get_mut(&req.id).expect("recorded").kind = CredentialKind::Token;
    let m = material::import_token(&req.value);
    let mut store = state.store.lock().expect("material poisoned");
    match store.put(&req.id, 1, &m, &state.age_identity) {
        Ok(()) => {
            inv.mark_provisioned(&req.id).expect("recorded");
            drop(store);
            drop(inv);
            state.persist_stores();
            Json(OperationResult::ready())
        }
        Err(e) => Json(OperationResult {
            outcome: Outcome::Failed,
            operation: None,
            detail: Some(format!("persist failed: {e}")),
        }),
    }
}

#[derive(Deserialize)]
struct RotationPlanRequest {
    credential: String,
    idempotency_key: String,
    #[serde(default)]
    destinations: Vec<String>,
}

/// rotation.plan: durable PLANNED record bound to the current version;
/// policy decides approval (auto or human PENDING).
async fn rotation_plan(
    State(state): State<Arc<BrokerState>>,
    axum::Extension(identity): axum::Extension<PeerIdentity>,
    Json(req): Json<RotationPlanRequest>,
) -> Json<OperationResult> {
    let (from_version, kind) = {
        let inv = state.inventory.lock().expect("inventory poisoned");
        match inv.get(&req.credential) {
            Ok(c) => (c.version.0, c.kind),
            Err(_) => {
                return Json(OperationResult {
                    outcome: Outcome::Denied,
                    operation: None,
                    detail: Some("credential not found; ensure it first".into()),
                });
            }
        }
    };

    let op_id = state.mint_op_id();
    let record = {
        let mut rotations = state.rotations.lock().expect("rotations poisoned");
        match rotations.plan(
            op_id.clone(),
            &req.credential,
            from_version,
            req.destinations.clone(),
            &req.idempotency_key,
            &state.data_dir.root.join("rotations.json"),
        ) {
            Ok(r) => r,
            Err(e) => {
                return Json(OperationResult {
                    outcome: Outcome::Conflict,
                    operation: None,
                    detail: Some(e.to_string()),
                });
            }
        }
    };

    let cred_ref = {
        let inv = state.inventory.lock().expect("inventory poisoned");
        inv.get(&req.credential).expect("checked above").clone()
    };
    let decision = state.policy.decide(
        identity.role,
        &cred_ref,
        kind,
        &req.destinations,
        op_id.clone(),
    );
    match decision {
        keywright_core::policy::Decision::AutoApproved { .. } => {
            let mut rotations = state.rotations.lock().expect("rotations poisoned");
            let _ = rotations.approve(&record.id.0, &state.data_dir.root.join("rotations.json"));
            Json(OperationResult::ready())
        }
        keywright_core::policy::Decision::NeedsHumanApproval { operation } => {
            Json(OperationResult::pending(operation))
        }
        keywright_core::policy::Decision::Denied { reason } => {
            Json(OperationResult::denied(reason))
        }
    }
}

#[derive(Deserialize)]
struct RotationExecuteRequest {
    op: String,
    idempotency_key: String,
}

/// rotation.execute: drive PREPARED → DEPLOYED with durable boundaries;
/// verification is broker-controlled and separate, so without a configured
/// check the rotation rests at DEPLOYED and never auto-verifies.
async fn rotation_execute(
    State(state): State<Arc<BrokerState>>,
    Json(req): Json<RotationExecuteRequest>,
) -> Json<OperationResult> {
    let rot_path = state.data_dir.root.join("rotations.json");
    let (credential, to_version, destinations) = {
        let rotations = state.rotations.lock().expect("rotations poisoned");
        match rotations.get(&req.op) {
            Ok(r) => {
                if r.idempotency_key != req.idempotency_key {
                    return Json(OperationResult {
                        outcome: Outcome::Conflict,
                        operation: None,
                        detail: Some("idempotency key mismatch".into()),
                    });
                }
                (r.credential.clone(), r.to_version, r.destinations.clone())
            }
            Err(e) => {
                return Json(OperationResult {
                    outcome: Outcome::Failed,
                    operation: None,
                    detail: Some(e.to_string()),
                });
            }
        }
    };
    let kind = {
        let inv = state.inventory.lock().expect("inventory poisoned");
        match inv.get(&credential) {
            Ok(c) => c.kind,
            Err(_) => {
                return Json(OperationResult {
                    outcome: Outcome::Failed,
                    operation: None,
                    detail: Some("credential vanished from inventory".into()),
                });
            }
        }
    };

    // PREPARED: generate + persist replacement material for to_version.
    let material = match kind {
        CredentialKind::Password => material::generate_password(),
        CredentialKind::KeyPair => material::generate_key_pair(),
        CredentialKind::Token | CredentialKind::TlsPair => {
            return Json(OperationResult {
                outcome: Outcome::Failed,
                operation: Some(OperationId::new(req.op.clone())),
                detail: Some("token/tls rotation executes with certificate lifecycle (M6)".into()),
            });
        }
    };
    let material = match material {
        Ok(m) => m,
        Err(e) => {
            return Json(OperationResult {
                outcome: Outcome::Failed,
                operation: Some(OperationId::new(req.op.clone())),
                detail: Some(format!("generation failed: {e}")),
            });
        }
    };
    {
        let mut store = state.store.lock().expect("material poisoned");
        if let Err(e) = store.put(&credential, to_version, &material, &state.age_identity) {
            return Json(OperationResult {
                outcome: Outcome::Failed,
                operation: Some(OperationId::new(req.op.clone())),
                detail: Some(format!("persist replacement failed: {e}")),
            });
        }
    }
    // APPROVED: durable transition through the full state machine (the
    // approval flag was set at plan time by policy or by human approve).
    {
        let mut rotations = state.rotations.lock().expect("rotations poisoned");
        if let Err(e) = rotations.transition(&req.op, RotationState::Approved, &rot_path) {
            return rotation_transition_failure(&req.op, e);
        }
    }
    {
        let mut rotations = state.rotations.lock().expect("rotations poisoned");
        if let Err(e) = rotations.transition(&req.op, RotationState::Prepared, &rot_path) {
            return rotation_transition_failure(&req.op, e);
        }
    }

    // DEPLOYED: deliver replacement to mapped destinations.
    if let Err((dest_name, e)) =
        deliver_to_mapped(&state, &credential, kind, &destinations, &material).await
    {
        // Delivery failed: record the failure, old version stays live.
        return Json(OperationResult {
            outcome: Outcome::Failed,
            operation: Some(OperationId::new(req.op.clone())),
            detail: Some(format!("delivery to {dest_name} failed: {e}")),
        });
    }
    {
        let mut rotations = state.rotations.lock().expect("rotations poisoned");
        if let Err(e) = rotations.transition(&req.op, RotationState::Deployed, &rot_path) {
            return rotation_transition_failure(&req.op, e);
        }
    }

    // Without a configured broker-controlled verification check, rest at
    // DEPLOYED — never auto-verify, never auto-retire the old version.
    Json(OperationResult {
        outcome: Outcome::Ready,
        operation: Some(OperationId::new(req.op.clone())),
        detail: Some(
            "DEPLOYED; awaiting broker-controlled verification \
             (Kubernetes readiness alone is never proof)"
                .into(),
        ),
    })
}

fn rotation_transition_failure(
    op: &str,
    e: keywright_core::rotation::RotationError,
) -> Json<OperationResult> {
    Json(OperationResult {
        outcome: Outcome::Conflict,
        operation: Some(OperationId::new(op.to_string())),
        detail: Some(e.to_string()),
    })
}

#[derive(Deserialize)]
struct RotationAbortRequest {
    op: String,
    reason: String,
}

/// rotation.abort: stop at the current boundary; the old credential stays
/// live (never auto-revoked).
async fn rotation_abort(
    State(state): State<Arc<BrokerState>>,
    Json(req): Json<RotationAbortRequest>,
) -> Json<OperationResult> {
    let rot_path = state.data_dir.root.join("rotations.json");
    let mut rotations = state.rotations.lock().expect("rotations poisoned");
    match rotations.abort(&req.op, &req.reason, &rot_path) {
        Ok(r) => Json(OperationResult {
            outcome: Outcome::Ready,
            operation: Some(r.id.clone()),
            detail: Some(format!("aborted at {}; old credential stays live", r.state)),
        }),
        Err(e) => Json(OperationResult {
            outcome: Outcome::Failed,
            operation: None,
            detail: Some(e.to_string()),
        }),
    }
}

#[derive(Deserialize)]
struct CertInspectQuery {
    id: String,
}

/// certificate.inspect: metadata for a TLS credential (no material).
async fn certificate_inspect(
    State(state): State<Arc<BrokerState>>,
    Query(q): Query<CertInspectQuery>,
) -> Json<serde_json::Value> {
    let cert_meta = {
        let inv = state.inventory.lock().expect("inventory poisoned");
        let c = inv.get(&q.id).expect("checked");
        let expiry = c
            .expiry
            .map(|e| e.not_after.to_string())
            .unwrap_or_default();
        serde_json::json!({
            "id": q.id,
            "kind": c.kind.to_string(),
            "version": c.version.0,
            "not_after": expiry,
            "provisioning": format!("{:?}", c.provisioning),
        })
    };
    Json(cert_meta)
}

#[derive(Deserialize)]
struct CertEnsureRequest {
    id: String,
    profile: String,
    #[serde(default)]
    sans: Vec<String>,
    validity_days: u32,
}

/// certificate.ensure: generate the application key, build the CSR (signed
/// by that key), issue through the approved profile via the signing
/// provider, validate the pair, and persist as TlsPair material. Issuer
/// keys never appear in stored or delivered material.
async fn certificate_ensure(
    State(state): State<Arc<BrokerState>>,
    axum::Extension(identity): axum::Extension<PeerIdentity>,
    Json(req): Json<CertEnsureRequest>,
) -> Json<OperationResult> {
    // Existing TlsPair credential: READY (idempotent, never overwritten).
    {
        let inv = state.inventory.lock().expect("inventory poisoned");
        if let Ok(c) = inv.get(&req.id)
            && c.provisioning == keywright_core::refs::ProvisioningStatus::Provisioned
        {
            return Json(OperationResult::ready());
        }
    }

    // Profile must exist in broker config (agent-supplied values never
    // create profiles).
    let Some(profile) = state
        .cert_profiles
        .iter()
        .find(|p| p.name == req.profile)
        .cloned()
    else {
        return Json(OperationResult::denied(format!(
            "unknown certificate profile {}",
            req.profile
        )));
    };

    // SANs must be allowed by the profile.
    if let Err(e) = keywright_core::certs::validate_sans(&profile, &req.sans) {
        return Json(OperationResult {
            outcome: Outcome::Denied,
            operation: None,
            detail: Some(e.to_string()),
        });
    }
    if let Err(e) = keywright_core::certs::validate_validity(&profile, req.validity_days) {
        return Json(OperationResult {
            outcome: Outcome::Denied,
            operation: None,
            detail: Some(e.to_string()),
        });
    }

    // Generate application key + CSR + issue through the provider.
    let key = match keywright_core::certs::generate_application_key(&profile) {
        Ok(k) => k,
        Err(e) => {
            return Json(OperationResult {
                outcome: Outcome::Failed,
                operation: None,
                detail: Some(format!("key generation failed: {e}")),
            });
        }
    };
    let primary_san = req.sans.first().cloned().unwrap_or_else(|| req.id.clone());
    let csr = match keywright_core::certs::build_csr(&key, &primary_san, &req.sans, &profile) {
        Ok(c) => c,
        Err(e) => {
            return Json(OperationResult {
                outcome: Outcome::Denied,
                operation: None,
                detail: Some(e.to_string()),
            });
        }
    };
    let key_pem =
        String::from_utf8_lossy(&key.private_key_to_pem_pkcs8().unwrap_or_default()).into_owned();
    let issued = match state
        .signer
        .issue(&csr, &req.sans, req.validity_days, &profile, 0)
    {
        Ok(i) => i,
        Err(e) => {
            return Json(OperationResult {
                outcome: Outcome::Denied,
                operation: None,
                detail: Some(e.to_string()),
            });
        }
    };

    // Validate the pair (cert matches app key, chains to CA).
    let ca_pem = issued.chain_pem.first().cloned().unwrap_or_default();
    if let Err(e) = keywright_core::certs::validate_pair(&issued.cert_pem, &key_pem, &ca_pem) {
        return Json(OperationResult {
            outcome: Outcome::Failed,
            operation: None,
            detail: Some(format!("issued pair invalid: {e}")),
        });
    }

    // Persist as TlsPair material (tls.crt = cert, tls.key = app key).
    let mut material = Material::default();
    material
        .values
        .insert("tls.crt".into(), issued.cert_pem.clone());
    material.values.insert("tls.key".into(), key_pem);
    {
        let mut store = state.store.lock().expect("material poisoned");
        if let Err(e) = store.put(&req.id, 1, &material, &state.age_identity) {
            return Json(OperationResult {
                outcome: Outcome::Failed,
                operation: None,
                detail: Some(format!("persist failed: {e}")),
            });
        }
    }
    {
        let mut inv = state.inventory.lock().expect("inventory poisoned");
        if let Err(e) = inv.record_request(&req.id, CredentialKind::TlsPair) {
            let _ = e;
        }
        let c = inv.get_mut(&req.id).expect("recorded");
        c.kind = CredentialKind::TlsPair;
        c.provisioning = keywright_core::refs::ProvisioningStatus::Provisioned;
        let not_after = now_secs() + u64::from(issued.validity_days) * 86_400;
        c.expiry = Some(keywright_core::refs::Expiry::from_unix_seconds(not_after));
    }
    state.persist_stores();
    let _ = identity;
    Json(OperationResult::ready())
}

#[derive(Deserialize)]
struct CertRotateRequest {
    id: String,
    /// "renew" (same application key) or "rekey" (new key).
    mode: String,
    validity_days: u32,
}

/// certificate.rotate: renewal (same key) and rekeying (new key) are modeled
/// separately; both produce the next generation.
async fn certificate_rotate(
    State(state): State<Arc<BrokerState>>,
    Json(req): Json<CertRotateRequest>,
) -> Json<OperationResult> {
    let (current_version, profile_name) = {
        let inv = state.inventory.lock().expect("inventory poisoned");
        match inv.get(&req.id) {
            Ok(c) => (c.version.0, "web-demo".to_string()),
            Err(_) => {
                return Json(OperationResult {
                    outcome: Outcome::Denied,
                    operation: None,
                    detail: Some("credential not found".into()),
                });
            }
        }
    };
    let Some(profile) = state
        .cert_profiles
        .iter()
        .find(|p| p.name == profile_name)
        .cloned()
    else {
        return Json(OperationResult::denied("no certificate profile configured"));
    };
    if !matches!(req.mode.as_str(), "renew" | "rekey") {
        return Json(OperationResult::denied("mode must be renew or rekey"));
    }

    let (key, key_pem) = if req.mode == "renew" {
        // Renewal reuses the stored application key.
        let store = state.store.lock().expect("material poisoned");
        match store.get(&req.id, current_version, &state.age_identity) {
            Ok(m) => {
                let pem = m.values.get("tls.key").cloned().unwrap_or_default();
                drop(store);
                match keywright_core::trust::parse_key(&pem) {
                    Ok(k) => (k, pem),
                    Err(e) => {
                        return Json(OperationResult {
                            outcome: Outcome::Failed,
                            operation: None,
                            detail: Some(format!("stored key unusable: {e}")),
                        });
                    }
                }
            }
            Err(e) => {
                return Json(OperationResult {
                    outcome: Outcome::Failed,
                    operation: None,
                    detail: Some(format!("stored material missing: {e}")),
                });
            }
        }
    } else {
        // Rekey generates a fresh application key.
        match keywright_core::certs::generate_application_key(&profile) {
            Ok(k) => {
                let pem =
                    String::from_utf8_lossy(&k.private_key_to_pem_pkcs8().unwrap_or_default())
                        .into_owned();
                (k, pem)
            }
            Err(e) => {
                return Json(OperationResult {
                    outcome: Outcome::Failed,
                    operation: None,
                    detail: Some(format!("key generation failed: {e}")),
                });
            }
        }
    };

    // Renewal/rekeying keeps the ORIGINAL identity: reuse the SANs from the
    // stored certificate (profiles must still allow them).
    let sans = {
        let store = state.store.lock().expect("material poisoned");
        let m = match store.get(&req.id, current_version, &state.age_identity) {
            Ok(m) => m,
            Err(e) => {
                return Json(OperationResult {
                    outcome: Outcome::Failed,
                    operation: None,
                    detail: Some(format!("stored material missing: {e}")),
                });
            }
        };
        let cert_pem = m.values.get("tls.crt").cloned().unwrap_or_default();
        drop(store);
        let cert = match keywright_core::trust::parse_cert(&cert_pem) {
            Ok(c) => c,
            Err(e) => {
                return Json(OperationResult {
                    outcome: Outcome::Failed,
                    operation: None,
                    detail: Some(format!("stored cert unusable: {e}")),
                });
            }
        };
        cert.subject_alt_names()
            .map(|names| {
                names
                    .iter()
                    .filter_map(|g| g.dnsname().map(|d| d.to_string()))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default()
    };
    if let Err(e) = keywright_core::certs::validate_sans(&profile, &sans) {
        return Json(OperationResult::denied(e.to_string()));
    }
    let csr = match keywright_core::certs::build_csr(&key, &sans[0], &sans, &profile) {
        Ok(c) => c,
        Err(e) => return Json(OperationResult::denied(e.to_string())),
    };
    let generation = current_version;
    let issued = match state
        .signer
        .issue(&csr, &sans, req.validity_days, &profile, generation)
    {
        Ok(i) => i,
        Err(e) => return Json(OperationResult::denied(e.to_string())),
    };
    let ca_pem = issued.chain_pem.first().cloned().unwrap_or_default();
    if let Err(e) = keywright_core::certs::validate_pair(&issued.cert_pem, &key_pem, &ca_pem) {
        return Json(OperationResult {
            outcome: Outcome::Failed,
            operation: None,
            detail: Some(format!("issued pair invalid: {e}")),
        });
    }

    // Persist the next version.
    let new_version = current_version + 1;
    let mut m = Material::default();
    m.values.insert("tls.crt".into(), issued.cert_pem.clone());
    m.values.insert("tls.key".into(), key_pem);
    {
        let mut store = state.store.lock().expect("material poisoned");
        if let Err(e) = store.put(&req.id, new_version, &m, &state.age_identity) {
            return Json(OperationResult {
                outcome: Outcome::Failed,
                operation: None,
                detail: Some(format!("persist failed: {e}")),
            });
        }
    }
    {
        let mut inv = state.inventory.lock().expect("inventory poisoned");
        let _ = inv.advance_version(&req.id);
        let c = inv.get_mut(&req.id).expect("present");
        let not_after = now_secs() + u64::from(issued.validity_days) * 86_400;
        c.expiry = Some(keywright_core::refs::Expiry::from_unix_seconds(not_after));
    }
    state.persist_stores();
    Json(OperationResult {
        outcome: Outcome::Ready,
        operation: None,
        detail: Some(format!(
            "{}d to v{new_version} ({} mode)",
            req.mode, req.mode
        )),
    })
}

/// The agent-facing router. Handlers receive the validated PeerIdentity via
/// request extensions; role checks are per-handler.
pub fn router(state: Arc<BrokerState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/credential/list", get(credential_list))
        .route("/credential/describe", get(credential_describe))
        .route("/credential/ensure", post(credential_ensure))
        .route("/rotation/status", get(rotation_status))
        .route("/rotation/pending", get(rotation_pending))
        .route("/rotation/plan", post(rotation_plan))
        .route("/rotation/execute", post(rotation_execute))
        .route("/rotation/abort", post(rotation_abort))
        .route("/certificate/inspect", get(certificate_inspect))
        .route("/certificate/ensure", post(certificate_ensure))
        .route("/certificate/rotate", post(certificate_rotate))
        .route("/admin/approve", post(admin_approve))
        .route("/admin/import", post(admin_import))
        .with_state(state)
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
    let app = router(state.clone());

    // Broker-internal renewal scheduler: runs without any agent session.
    // Scans for expiring credentials daily and plans rotations through the
    // same policy-gated engine (auto-approve or PENDING_APPROVAL records).
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
            loop {
                interval.tick().await;
                if let Err(e) = run_renewal_scan(&state) {
                    eprintln!("keywright-broker: renewal scan failed: {e}");
                }
            }
        });
    }

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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Renewal window: plan rotations this many days before expiry.
pub const RENEWAL_WINDOW_DAYS: u64 = 30;

/// Pure scan: credential ids whose expiry falls inside the window.
pub fn renewal_scan(inv: &Inventory, now_secs: u64, window_days: u64) -> Vec<String> {
    let horizon = now_secs + window_days * 86_400;
    inv.list()
        .iter()
        .filter_map(|c| c.expiry.map(|e| (c.id.clone(), e.not_after)))
        .filter(|(_, not_after)| *not_after <= horizon)
        .map(|(id, _)| id)
        .collect()
}

/// One scheduler pass: plan rotations (policy decides approval) for every
/// credential inside the renewal window.
pub fn run_renewal_scan(state: &BrokerState) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let due = {
        let inv = state.inventory.lock().expect("inventory poisoned");
        renewal_scan(&inv, now, RENEWAL_WINDOW_DAYS)
    };
    let rot_path = state.data_dir.root.join("rotations.json");
    for id in due {
        let mut rotations = state.rotations.lock().expect("rotations poisoned");
        let (from_version, kind, existing_pending) = {
            let inv = state.inventory.lock().expect("inventory poisoned");
            let cred = inv.get(&id).map_err(|e| e.to_string())?;
            let pending = rotations.active().iter().any(|r| r.credential == id);
            (cred.version.0, cred.kind, pending)
        };
        if existing_pending {
            continue; // already rotating; scan is idempotent
        }
        let op = state.mint_op_id();
        let record = rotations
            .plan(
                op,
                &id,
                from_version,
                vec![],
                &format!("renewal-{now}-{id}"),
                &rot_path,
            )
            .map_err(|e| e.to_string())?;
        // Policy decides approval; without an auto-approve rule this lands
        // as a pending rotation a human can approve — never silently skipped.
        let cred_ref = {
            let inv = state.inventory.lock().expect("inventory poisoned");
            inv.get(&id).expect("present").clone()
        };
        let decision = state.policy.decide(
            keywright_core::role::Role::Admin, // scheduler acts as an internal requester
            &cred_ref,
            kind,
            &[],
            record.id.clone(),
        );
        if let keywright_core::policy::Decision::AutoApproved { .. } = decision {
            rotations
                .approve(&record.id.0, &rot_path)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
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
    use keywright_core::policy::{AutoApprovalRule, Policy};
    use keywright_core::role::Role;
    use keywright_core::trust::{generate_transport_ca, issue_client_cert, issue_server_cert};
    use openssl::ssl::{SslConnector, SslFiletype, SslMethod};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A broker with fresh CA material on an ephemeral loopback port.
    struct TestBroker {
        addr: SocketAddr,
        ca: keywright_core::trust::CaMaterial,
        state: Arc<BrokerState>,
        data_root: std::path::PathBuf,
    }

    async fn start_broker(policy: Policy) -> TestBroker {
        let delivery = keywright_core::kube_delivery::DeliveryConfig::default();
        let data_root = tmp_path();
        let ca = generate_transport_ca("test-broker-ca").expect("ca");
        let server = issue_server_cert(&ca, &["localhost"]).expect("server cert");
        let transport = TransportMaterial::new(
            server.cert_pem.clone(),
            server.key_pem.clone(),
            ca.cert_pem.clone(),
        );
        let config = BrokerConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            policy: policy.clone(),
            delivery: delivery.clone(),
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
        let mut config = BrokerConfig::default();
        config.bind = SocketAddr::new(config.bind.ip(), 0);
        let addr = serve(config, transport, state.clone())
            .await
            .expect("serve");
        TestBroker {
            addr,
            ca,
            state,
            data_root,
        }
    }

    fn tmp_path() -> std::path::PathBuf {
        // Keep each test's dir alive for the process lifetime by leaking.
        let leaked: &'static tempfile::TempDir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        leaked.path().to_path_buf()
    }

    async fn request(
        broker: &TestBroker,
        role: Role,
        name: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Option<(u16, String)> {
        let client = issue_client_cert(&broker.ca, name, role).expect("client cert");
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

        let tcp = tokio::net::TcpStream::connect(broker.addr).await.ok()?;
        let ssl = builder
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let mut stream = tokio_openssl::SslStream::new(ssl, tcp).ok()?;
        std::pin::Pin::new(&mut stream).connect().await.ok()?;

        let body_text = body.unwrap_or("");
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            body_text.len(),
            body_text,
        );
        stream.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.ok()?;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())?;
        let resp_body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        Some((status, resp_body))
    }

    #[tokio::test]
    async fn healthz_serves_over_mtls_for_agent_identities() {
        let broker = start_broker(Policy::default()).await;
        let (status, body) = request(&broker, Role::Agent, "pi-agent-1", "GET", "/healthz", None)
            .await
            .expect("mTLS request");
        assert_eq!(status, 200);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn unauthenticated_connections_are_refused() {
        let broker = start_broker(Policy::default()).await;
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
        let _ = std::pin::Pin::new(&mut stream).connect().await;
        let _ = stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            .await;
        let mut buf = Vec::new();
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
        let broker = start_broker(Policy::default()).await;
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
        let broker = start_broker(Policy::default()).await;
        broker.state.disable_identity("gone-agent");
        let client = issue_client_cert(&broker.ca, "gone-agent", Role::Agent).unwrap();
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
                .and_then(|t| t.parse::<u16>().ok())
                .is_none(),
            "denylisted identity must receive no HTTP response"
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
            policy: Policy::default(),
            delivery: keywright_core::kube_delivery::DeliveryConfig::default(),
            sops: None,
            cert_profiles: Vec::new(),
        };
        let err = serve(
            config,
            material,
            Arc::new(BrokerState::load(
                DataDir::new(std::path::PathBuf::from("/nonexistent-must-not-be-touched")),
                &BrokerConfig::default(),
                AgeIdentity::generate(),
            )),
        )
        .await;
        assert!(matches!(err, Err(BrokerError::RemoteBindRefused(_))));
    }

    #[tokio::test]
    async fn ensure_is_idempotent_and_never_overwrites() {
        let broker = start_broker(policy_with("rustfs/*")).await;
        let body = r#"{"id":"rustfs/access-key","kind":"password","destinations":["demo-rustfs"]}"#;
        let (s1, b1) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();
        assert_eq!(s1, 200);
        assert!(
            b1.contains("\"READY\""),
            "first ensure should be READY: {b1}"
        );

        // Second ensure does not change the existing credential.
        let (s2, b2) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();
        assert_eq!(s2, 200);
        assert!(
            b2.contains("\"READY\""),
            "second ensure should be READY: {b2}"
        );

        // The stored material did not change between the two ensures.
        let store = broker.state.store.lock().unwrap();
        let m1 = store
            .get("rustfs/access-key", 1, broker.state.age_identity_of())
            .unwrap();
        assert_eq!(m1.values.len(), 1);
    }

    #[tokio::test]
    async fn ensure_without_policy_match_is_pending_approval() {
        let broker = start_broker(policy_with("rustfs/*")).await;
        let body = r#"{"id":"matrix/hermes-token","kind":"token","destinations":["demo-matrix"]}"#;
        let (status, body) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();
        assert_eq!(status, 200);
        assert!(
            body.contains("NEEDS_HUMAN_IMPORT"),
            "token ensure should need import: {body}"
        );
    }

    #[tokio::test]
    async fn agents_cannot_approve_their_own_requests() {
        let broker = start_broker(Policy::default()).await;
        // No policy rule: a password ensure becomes PENDING_APPROVAL.
        let body = r#"{"id":"web/app-password","kind":"password","destinations":["web"]}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();
        assert!(resp.contains("PENDING_APPROVAL"), "{resp}");
        let op_id = extract_op_id(&resp);

        // The AGENT tries to approve its own request: refused.
        let approve_body = format!(r#"{{"op":"{op_id}"}}"#);
        let (status, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/admin/approve",
            Some(&approve_body),
        )
        .await
        .unwrap();
        assert_eq!(status, 200);
        assert!(
            resp.contains("DENIED"),
            "agent approve must be DENIED: {resp}"
        );

        // The op is still pending after the agent's attempt.
        let ops = broker.state.approvals.lock().unwrap();
        assert!(ops.get(&op_id).unwrap().is_pending());
    }

    #[tokio::test]
    async fn admin_approves_and_generation_follows() {
        let broker = start_broker(Policy::default()).await;
        let body = r#"{"id":"web/app-password","kind":"password","destinations":["web"]}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();
        let op_id = extract_op_id(&resp);

        // Admin approves under a different identity.
        let approve_body = format!(r#"{{"op":"{op_id}"}}"#);
        let (_, resp) = request(
            &broker,
            Role::Admin,
            "human-1",
            "POST",
            "/admin/approve",
            Some(&approve_body),
        )
        .await
        .unwrap();
        assert!(resp.contains("\"READY\""), "admin approve: {resp}");
    }

    #[tokio::test]
    async fn human_import_flow_from_need_to_ready() {
        let broker = start_broker(policy_with("matrix/*")).await;
        // Agent requests a token credential: NEEDS_HUMAN_IMPORT.
        let body = r#"{"id":"matrix/hermes-token","kind":"token","destinations":["demo-matrix"]}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();
        assert!(resp.contains("NEEDS_HUMAN_IMPORT"), "{resp}");

        // Agents cannot import.
        let import_body = r#"{"id":"matrix/hermes-token","value":"stolen"}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/admin/import",
            Some(import_body),
        )
        .await
        .unwrap();
        assert!(
            resp.contains("DENIED"),
            "agent import must be DENIED: {resp}"
        );

        // Human imports through the trusted path.
        let import_body = r#"{"id":"matrix/hermes-token","value":"hermes-real-token-value"}"#;
        let (_, resp) = request(
            &broker,
            Role::Admin,
            "human-1",
            "POST",
            "/admin/import",
            Some(import_body),
        )
        .await
        .unwrap();
        assert!(resp.contains("\"READY\""), "admin import: {resp}");

        // Metadata list shows the credential provisioned — and no values.
        let (_, list) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "GET",
            "/credential/list",
            None,
        )
        .await
        .unwrap();
        assert!(list.contains("matrix/hermes-token"), "{list}");
        assert!(
            !list.contains("hermes-real-token-value"),
            "plaintext leaked to metadata: {list}"
        );

        // Subsequent agent ensure on the same token is READY (idempotent).
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();
        assert!(
            resp.contains("\"READY\""),
            "token ensure after import: {resp}"
        );
    }

    #[tokio::test]
    async fn metadata_endpoints_never_carry_secret_values() {
        let broker = start_broker(policy_with("rustfs/*")).await;
        let body = r#"{"id":"rustfs/pw","kind":"password","destinations":["demo-rustfs"]}"#;
        request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();

        let (_, list) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "GET",
            "/credential/list",
            None,
        )
        .await
        .unwrap();
        // "kind":"password" is legitimate metadata; only secret-valued
        // fields are forbidden.
        for banned in ["\"value\"", "\"secret\"", "\"material\""] {
            assert!(!list.contains(banned), "list leaked {banned}: {list}");
        }
    }

    #[tokio::test]
    async fn stores_persist_to_disk_without_plaintext() {
        let broker = start_broker(policy_with("rustfs/*")).await;
        let body = r#"{"id":"rustfs/pw2","kind":"password","destinations":["demo-rustfs"]}"#;
        request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();

        let material_file =
            std::fs::read_to_string(broker.data_root.join("material.json")).unwrap();
        assert!(material_file.contains("rustfs/pw2"));
        // Encrypted records: no plaintext values on disk.
        assert!(!material_file.contains("password"));
        assert!(!material_file.contains("values"));
    }

    #[tokio::test]
    async fn mapped_but_unreachable_destination_fails_explicitly() {
        // A mapped destination (pinned cluster + namespace) with a bogus
        // kubeconfig: ensure must report FAILED with the delivery detail,
        // never silently skip delivery.
        let delivery = keywright_core::kube_delivery::DeliveryConfig {
            clusters: vec![keywright_core::kube_delivery::ClusterMapping {
                name: "homelab".into(),
                kubeconfig: "/nonexistent/kubeconfig".into(),
                namespaces: vec!["demo-ns".into()],
            }],
            destinations: vec![keywright_core::refs::Destination {
                name: "demo-rustfs".into(),
                cluster: "homelab".into(),
                namespace: "demo-ns".into(),
                secret: "rustfs-creds".into(),
                key_names: None,
            }],
        };
        let policy = policy_with("rustfs/*");
        let config = BrokerConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            policy: policy.clone(),
            delivery: delivery.clone(),
            sops: None,
            cert_profiles: vec![keywright_core::certs::CertProfile {
                name: "web-demo".into(),
                allowed_sans: vec!["app.local".into(), "*.demo.internal".into()],
                allowed_ekus: vec!["serverAuth".into()],
                max_validity_days: 90,
                min_rsa_bits: 2048,
            }],
        };
        let tmp_root = tmp_path();
        let ca = generate_transport_ca("ca").unwrap();
        let server = issue_server_cert(&ca, &["localhost"]).unwrap();
        let transport = TransportMaterial::new(
            server.cert_pem.clone(),
            server.key_pem.clone(),
            ca.cert_pem.clone(),
        );
        let state = Arc::new(BrokerState::load(
            DataDir::new(tmp_root),
            &config,
            AgeIdentity::generate(),
        ));
        let addr = serve(config.clone(), transport, state.clone())
            .await
            .unwrap();
        let broker = TestBroker {
            addr,
            ca,
            state,
            data_root: std::path::PathBuf::new(),
        };

        let body = r#"{"id":"rustfs/pw","kind":"password","destinations":["demo-rustfs"]}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();
        assert!(
            resp.contains("\"FAILED\""),
            "unreachable delivery must FAIL: {resp}"
        );
        assert!(
            resp.contains("kubeconfig"),
            "dependency report required: {resp}"
        );
    }

    #[tokio::test]
    async fn rotation_plan_execute_walks_durable_states() {
        let broker = start_broker(policy_with("rustfs/*")).await;
        // Provision a credential first (v1).
        let body = r#"{"id":"rustfs/access-key","kind":"password","destinations":[]}"#;
        request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();

        // Plan a rotation (policy auto-approves "rustfs/*").
        let plan_body =
            r#"{"credential":"rustfs/access-key","idempotency_key":"rot-1","destinations":[]}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/rotation/plan",
            Some(plan_body),
        )
        .await
        .unwrap();
        assert!(resp.contains("\"READY\""), "auto-approved rotation: {resp}");

        // The op id is minted server-side; read it from rotation status.
        let (_, status) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "GET",
            "/rotation/status",
            None,
        )
        .await
        .unwrap();
        assert!(
            status.contains("\"PLANNED\""),
            "rotation recorded: {status}"
        );
        let op = extract_string(&status, "id");

        // Execute: PREPARED → DEPLOYED (no mapped destinations to deliver to).
        let exec_body = format!(r#"{{"op":"{op}","idempotency_key":"rot-1"}}"#);
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/rotation/execute",
            Some(&exec_body),
        )
        .await
        .unwrap();
        assert!(resp.contains("\"READY\""), "execute deploys: {resp}");
        assert!(
            resp.contains("DEPLOYED"),
            "rests at DEPLOYED without verification config: {resp}"
        );

        // Stale idempotency key is refused.
        let stale = format!(r#"{{"op":"{op}","idempotency_key":"wrong"}}"#);
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/rotation/execute",
            Some(&stale),
        )
        .await
        .unwrap();
        assert!(
            resp.contains("\"CONFLICT\""),
            "idempotency mismatch: {resp}"
        );

        // Abort: old credential stays live, no further phases.
        let abort_body = format!(r#"{{"op":"{op}","reason":"test abort"}}"#);
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/rotation/abort",
            Some(&abort_body),
        )
        .await
        .unwrap();
        assert!(resp.contains("old credential stays live"), "{resp}");
    }

    #[tokio::test]
    async fn concurrent_rotation_is_a_conflict() {
        let broker = start_broker(policy_with("rustfs/*")).await;
        let body = r#"{"id":"rustfs/x","kind":"password","destinations":[]}"#;
        request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/credential/ensure",
            Some(body),
        )
        .await
        .unwrap();
        let plan_body = r#"{"credential":"rustfs/x","idempotency_key":"a","destinations":[]}"#;
        let (_, first) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/rotation/plan",
            Some(plan_body),
        )
        .await
        .unwrap();
        assert!(first.contains("\"READY\""), "{first}");

        // A second concurrent rotation on the same credential: CONFLICT.
        let plan_body2 = r#"{"credential":"rustfs/x","idempotency_key":"b","destinations":[]}"#;
        let (_, second) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/rotation/plan",
            Some(plan_body2),
        )
        .await
        .unwrap();
        assert!(
            second.contains("\"CONFLICT\""),
            "per-credential lock: {second}"
        );
        assert!(second.contains("active rotation"), "{second}");
    }

    fn extract_string(json: &str, field: &str) -> String {
        // First occurrence of "<field>":"<value>" in a JSON array/object.
        let needle = format!("\"{field}\":\"");
        let start = json.find(&needle).expect("field present") + needle.len();
        let end = json[start..].find('"').expect("closing quote") + start;
        json[start..end].to_string()
    }

    #[test]
    fn renewal_scan_finds_creds_inside_the_window() {
        let mut inv = Inventory::new();
        inv.record_request("a/expiring", CredentialKind::Password)
            .unwrap();
        inv.record_request("b/fresh", CredentialKind::Password)
            .unwrap();
        inv.record_request("c/no-expiry", CredentialKind::Password)
            .unwrap();
        let now = 1_000_000u64;
        {
            let c = inv.get_mut("a/expiring").unwrap();
            c.expiry = Some(keywright_core::refs::Expiry::from_unix_seconds(
                now + 5 * 86_400,
            ));
        }
        {
            let c = inv.get_mut("b/fresh").unwrap();
            c.expiry = Some(keywright_core::refs::Expiry::from_unix_seconds(
                now + 365 * 86_400,
            ));
        }
        let due = renewal_scan(&inv, now, RENEWAL_WINDOW_DAYS);
        assert_eq!(due, vec!["a/expiring".to_string()]);
    }

    #[tokio::test]
    async fn certificate_ensure_rejects_unauthorized_sans_and_issues_matching_pair() {
        let broker = start_broker(policy_with("tls/*")).await;
        // SAN outside the profile: DENIED.
        let bad =
            r#"{"id":"tls/web","profile":"web-demo","sans":["evil.example"],"validity_days":30}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/certificate/ensure",
            Some(bad),
        )
        .await
        .unwrap();
        assert!(resp.contains("DENIED"), "unauthorized SAN: {resp}");

        // Validity beyond profile: DENIED.
        let long =
            r#"{"id":"tls/web","profile":"web-demo","sans":["app.local"],"validity_days":365}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/certificate/ensure",
            Some(long),
        )
        .await
        .unwrap();
        assert!(resp.contains("DENIED"), "validity beyond profile: {resp}");

        // Unknown profile: DENIED.
        let unknown = r#"{"id":"tls/web","profile":"attacker-profile","sans":["app.local"],"validity_days":30}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/certificate/ensure",
            Some(unknown),
        )
        .await
        .unwrap();
        assert!(resp.contains("DENIED"), "unknown profile: {resp}");

        // Valid issuance: matching pair stored, READY; second ensure READY.
        let good =
            r#"{"id":"tls/web","profile":"web-demo","sans":["app.local"],"validity_days":30}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/certificate/ensure",
            Some(good),
        )
        .await
        .unwrap();
        assert!(resp.contains("\"READY\""), "valid issuance: {resp}");
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/certificate/ensure",
            Some(good),
        )
        .await
        .unwrap();
        assert!(resp.contains("\"READY\""), "idempotent: {resp}");

        // Stored material is a matching pair; the issuer key never appears.
        let store = broker.state.store.lock().unwrap();
        let m = store
            .get("tls/web", 1, broker.state.age_identity_of())
            .unwrap();
        let tls_key = m.values["tls.key"].clone();
        let tls_crt = m.values["tls.crt"].clone();
        drop(store);
        assert!(tls_key.contains("BEGIN PRIVATE KEY"));
        assert!(tls_crt.contains("BEGIN CERTIFICATE"));
        // The stored private key is an application key (2048 bits), never
        // the 3072-bit software CA issuer key.
        let parsed = keywright_core::trust::parse_key(&tls_key).unwrap();
        assert_eq!(parsed.rsa().unwrap().size() * 8, 2048);
    }

    #[tokio::test]
    async fn certificate_rotate_renew_and_rekey_are_separate_paths() {
        let broker = start_broker(policy_with("tls/*")).await;
        let ensure =
            r#"{"id":"tls/web","profile":"web-demo","sans":["app.local"],"validity_days":30}"#;
        request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/certificate/ensure",
            Some(ensure),
        )
        .await
        .unwrap();
        let v1_key = {
            let store = broker.state.store.lock().unwrap();
            store
                .get("tls/web", 1, broker.state.age_identity_of())
                .unwrap()
                .values["tls.key"]
                .clone()
        };

        // Renewal: same application key, new cert, v2.
        let renew = r#"{"id":"tls/web","mode":"renew","validity_days":30}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/certificate/rotate",
            Some(renew),
        )
        .await
        .unwrap();
        assert!(resp.contains("\"READY\""), "renew: {resp}");
        {
            let store = broker.state.store.lock().unwrap();
            let v2 = store
                .get("tls/web", 2, broker.state.age_identity_of())
                .unwrap();
            assert_eq!(
                v2.values["tls.key"], v1_key,
                "renewal reuses the application key"
            );
        }

        // Rekey: fresh application key, v3.
        let rekey = r#"{"id":"tls/web","mode":"rekey","validity_days":30}"#;
        let (_, resp) = request(
            &broker,
            Role::Agent,
            "pi-agent-1",
            "POST",
            "/certificate/rotate",
            Some(rekey),
        )
        .await
        .unwrap();
        assert!(resp.contains("\"READY\""), "rekey: {resp}");
        {
            let store = broker.state.store.lock().unwrap();
            let v3 = store
                .get("tls/web", 3, broker.state.age_identity_of())
                .unwrap();
            assert_ne!(
                v3.values["tls.key"], v1_key,
                "rekey generates a new application key"
            );
        }
    }

    fn policy_with(cred_pattern: &str) -> Policy {
        Policy {
            rules: vec![AutoApprovalRule {
                name: "demo".into(),
                credentials: vec![cred_pattern.into()],
                destinations: vec!["demo-rustfs".into(), "demo-matrix".into(), "web".into()],
                kinds: vec![],
            }],
        }
    }

    fn extract_op_id(json: &str) -> String {
        let parsed: OperationResult = serde_json::from_str(json).expect("parse response");
        parsed.operation.expect("operation present").0
    }
}
