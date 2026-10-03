//! Direct Kubernetes Secret delivery through the pinned kube client.
//!
//! No kubectl shell-out; the kube crate reads the broker's dedicated
//! kubeconfig per cluster mapping. Delivery is create-or-verify idempotent:
//! an existing Secret with identical material is READY (never overwritten);
//! different material is a CONFLICT; anything else is created.

use k8s_openapi::api::core::v1::Secret as K8sSecret;
use keywright_core::kube_delivery::ResolvedDestination;

#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("kube config error: {0}")]
    Config(String),
    #[error("kube api error: {0}")]
    Api(String),
    #[error("secret exists with different material: refusing to overwrite (CONFLICT)")]
    Conflict,
}

/// Outcome of a delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// Secret created.
    Created,
    /// Secret already present with identical material (idempotent).
    AlreadyPresent,
}

/// Deliver (create or verify) a Secret at the pinned destination.
///
/// Cluster reachability is required: an unreachable cluster surfaces as an
/// explicit FAILED with the error detail — never a silent skip.
pub async fn deliver(
    resolved: &ResolvedDestination,
    secret: &K8sSecret,
) -> Result<DeliveryOutcome, DeliveryError> {
    let kubeconfig = std::fs::read_to_string(&resolved.kubeconfig)
        .map_err(|e| DeliveryError::Config(format!("kubeconfig {}: {e}", resolved.kubeconfig)))?;
    let parsed: kube::config::Kubeconfig = kube::config::Kubeconfig::from_yaml(&kubeconfig)
        .map_err(|e| DeliveryError::Config(format!("parse kubeconfig: {e}")))?;
    let config =
        kube::Config::from_custom_kubeconfig(parsed, &kube::config::KubeConfigOptions::default())
            .await
            .map_err(|e| DeliveryError::Config(e.to_string()))?;
    let client = kube::Client::try_from(config).map_err(|e| DeliveryError::Api(e.to_string()))?;
    let api: kube::Api<K8sSecret> = kube::Api::namespaced(client, &resolved.namespace);

    match api.get(&resolved.secret).await {
        Ok(existing) => {
            if secrets_equivalent(&existing, secret) {
                Ok(DeliveryOutcome::AlreadyPresent)
            } else {
                Err(DeliveryError::Conflict)
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            api.create(&kube::api::PostParams::default(), secret)
                .await
                .map_err(|e| DeliveryError::Api(e.to_string()))?;
            Ok(DeliveryOutcome::Created)
        }
        Err(e) => Err(DeliveryError::Api(e.to_string())),
    }
}

/// Byte-equality comparison of the data maps (metadata ignored).
fn secrets_equivalent(a: &K8sSecret, b: &K8sSecret) -> bool {
    let da = a.data.clone().unwrap_or_default();
    let db = b.data.clone().unwrap_or_default();
    if da.len() != db.len() {
        return false;
    }
    da.iter()
        .all(|(k, v)| db.get(k).is_some_and(|bv| bv.0 == v.0))
}

// Re-export for handler convenience.
pub use keywright_core::kube_delivery as core_delivery;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equivalent_secrets_match() {
        let mut data = std::collections::BTreeMap::new();
        data.insert("token".to_string(), k8s_openapi::ByteString(b"v".to_vec()));
        let a = K8sSecret {
            data: Some(data.clone()),
            ..Default::default()
        };
        let b = K8sSecret {
            data: Some(data),
            ..Default::default()
        };
        assert!(secrets_equivalent(&a, &b));

        let c = K8sSecret {
            data: None,
            ..Default::default()
        };
        assert!(!secrets_equivalent(&a, &c));
    }

    #[tokio::test]
    async fn unreachable_cluster_is_an_explicit_failure() {
        let resolved = ResolvedDestination {
            cluster: "homelab".into(),
            kubeconfig: "/nonexistent/kubeconfig".into(),
            namespace: "ns".into(),
            secret: "s".into(),
            key_names: vec![],
        };
        let secret = K8sSecret {
            ..Default::default()
        };
        let err = deliver(&resolved, &secret).await.unwrap_err();
        assert!(
            err.to_string().contains("kubeconfig"),
            "explicit dependency report: {err}"
        );
    }
}
