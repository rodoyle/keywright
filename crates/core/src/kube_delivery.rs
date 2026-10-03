//! Kubernetes Secret delivery: pure builders + destination pinning.
//!
//! The broker resolves agent-supplied destination *names* through its own
//! pinned mappings (cluster, namespace, Secret, key names). It never
//! inherits the caller's kube context and never accepts free-form
//! cluster/namespace values from agents.

use crate::material::Material;
use crate::refs::{CredentialKind, Destination, DestinationError};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("destination {0} is not in the broker's pinned mappings")]
    Unpinned(String),
    #[error("namespace {namespace} is not approved for cluster {cluster}")]
    UnapprovedNamespace { cluster: String, namespace: String },
    #[error("destination error: {0}")]
    Destination(#[from] DestinationError),
    #[error("material is missing key {0}")]
    MissingKey(String),
}

/// The broker's pinned cluster mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterMapping {
    pub name: String,
    /// Path to the broker's dedicated kubeconfig for this cluster.
    pub kubeconfig: String,
    /// Namespaces the broker may write Secrets into.
    pub namespaces: Vec<String>,
}

/// Broker configuration for all approved delivery targets.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeliveryConfig {
    pub clusters: Vec<ClusterMapping>,
    /// Destination mappings by name; agents reference these by name only.
    pub destinations: Vec<Destination>,
}

impl DeliveryConfig {
    pub fn destination(&self, name: &str) -> Result<&Destination, DeliveryError> {
        self.destinations
            .iter()
            .find(|d| d.name == name)
            .ok_or_else(|| DeliveryError::Unpinned(name.to_string()))
    }

    /// Validate that a destination's cluster + namespace are both pinned
    /// and approved. This is the enforcement point for "never inherit the
    /// caller's context, never accept unpinned targets".
    pub fn validate(&self, dest: &Destination) -> Result<(), DeliveryError> {
        let cluster = self
            .clusters
            .iter()
            .find(|c| c.name == dest.cluster)
            .ok_or_else(|| DeliveryError::Unpinned(dest.cluster.clone()))?;
        if !cluster.namespaces.iter().any(|ns| ns == &dest.namespace) {
            return Err(DeliveryError::UnapprovedNamespace {
                cluster: dest.cluster.clone(),
                namespace: dest.namespace.clone(),
            });
        }
        Ok(())
    }

    /// Fully resolve a destination name + credential kind into the exact
    /// Secret shape the broker will write.
    pub fn resolve(
        &self,
        dest_name: &str,
        kind: CredentialKind,
    ) -> Result<ResolvedDestination, DeliveryError> {
        let dest = self.destination(dest_name)?;
        self.validate(dest)?;
        let key_names = dest.resolved_key_names(kind)?;
        Ok(ResolvedDestination {
            cluster: dest.cluster.clone(),
            kubeconfig: self
                .clusters
                .iter()
                .find(|c| c.name == dest.cluster)
                .expect("validated above")
                .kubeconfig
                .clone(),
            namespace: dest.namespace.clone(),
            secret: dest.secret.clone(),
            key_names,
        })
    }
}

/// A fully pinned, validated destination ready for Secret delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDestination {
    pub cluster: String,
    pub kubeconfig: String,
    pub namespace: String,
    pub secret: String,
    pub key_names: Vec<String>,
}

/// Build a generic (Opaque) Kubernetes Secret from material.
pub fn build_generic_secret(
    resolved: &ResolvedDestination,
    material: &Material,
) -> Result<Secret, DeliveryError> {
    let mut data = std::collections::BTreeMap::new();
    for (i, key) in resolved.key_names.iter().enumerate() {
        let value = material
            .values
            .values()
            .nth(i)
            .ok_or_else(|| DeliveryError::MissingKey(key.clone()))?;
        data.insert(key.clone(), ByteString(value.clone().into_bytes()));
    }
    Ok(Secret {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(resolved.secret.clone()),
            namespace: Some(resolved.namespace.clone()),
            ..Default::default()
        },
        type_: Some("Opaque".to_string()),
        string_data: None,
        data: Some(data),
        ..Default::default()
    })
}

/// Build a kubernetes.io/tls Secret for TlsPair material (tls.crt / tls.key).
pub fn build_tls_secret(
    resolved: &ResolvedDestination,
    material: &Material,
) -> Result<Secret, DeliveryError> {
    let mut data = std::collections::BTreeMap::new();
    for key in resolved.key_names.iter() {
        let value = material
            .values
            .get(key)
            .ok_or_else(|| DeliveryError::MissingKey(key.clone()))?;
        data.insert(key.clone(), ByteString(value.clone().into_bytes()));
    }
    if !data.contains_key("tls.crt") || !data.contains_key("tls.key") {
        return Err(DeliveryError::MissingKey("tls.crt/tls.key".into()));
    }
    Ok(Secret {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(resolved.secret.clone()),
            namespace: Some(resolved.namespace.clone()),
            ..Default::default()
        },
        type_: Some("kubernetes.io/tls".to_string()),
        string_data: None,
        data: Some(data),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::material::import_token;

    fn config() -> DeliveryConfig {
        DeliveryConfig {
            clusters: vec![ClusterMapping {
                name: "homelab".into(),
                kubeconfig: "/etc/keywright/kubeconfig".into(),
                namespaces: vec!["keywright-demo-rustfs".into(), "keywright-demo-tls".into()],
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
                    name: "tls-demo".into(),
                    cluster: "homelab".into(),
                    namespace: "keywright-demo-tls".into(),
                    secret: "tls-app".into(),
                    key_names: None,
                },
            ],
        }
    }

    #[test]
    fn unknown_destinations_are_refused() {
        let cfg = config();
        assert!(matches!(
            cfg.destination("attacker-chosen"),
            Err(DeliveryError::Unpinned(_))
        ));
    }

    #[test]
    fn unapproved_namespaces_are_refused() {
        let cfg = config();
        let mut rogue = cfg.destinations[0].clone();
        rogue.namespace = "kube-system".into();
        assert!(matches!(
            cfg.validate(&rogue),
            Err(DeliveryError::UnapprovedNamespace { .. })
        ));
    }

    #[test]
    fn unapproved_clusters_are_refused() {
        let cfg = config();
        let mut rogue = cfg.destinations[0].clone();
        rogue.cluster = "other-cluster".into();
        assert!(matches!(
            cfg.validate(&rogue),
            Err(DeliveryError::Unpinned(_))
        ));
    }

    #[test]
    fn resolution_carries_the_dedicated_kubeconfig() {
        let cfg = config();
        let r = cfg.resolve("rustfs", CredentialKind::Token).unwrap();
        assert_eq!(r.kubeconfig, "/etc/keywright/kubeconfig");
        assert_eq!(r.namespace, "keywright-demo-rustfs");
        assert_eq!(r.key_names, vec!["token".to_string()]);
    }

    #[test]
    fn generic_secret_carries_material_under_mapped_keys() {
        let cfg = config();
        let r = cfg.resolve("rustfs", CredentialKind::Token).unwrap();
        let secret = build_generic_secret(&r, &import_token("tok-value")).unwrap();
        assert_eq!(secret.type_.as_deref(), Some("Opaque"));
        assert_eq!(secret.metadata.name.as_deref(), Some("rustfs-creds"));
        assert_eq!(
            secret.metadata.namespace.as_deref(),
            Some("keywright-demo-rustfs")
        );
        assert_eq!(
            secret.data.as_ref().unwrap()["token"].0,
            b"tok-value".to_vec()
        );
    }

    #[test]
    fn tls_secret_requires_both_pem_keys() {
        let cfg = config();
        let r = cfg.resolve("tls-demo", CredentialKind::TlsPair).unwrap();
        assert_eq!(
            r.key_names,
            vec!["tls.crt".to_string(), "tls.key".to_string()]
        );

        // Missing tls.key material: refused.
        let mut m = crate::material::Material {
            values: Default::default(),
        };
        m.values.insert("tls.crt".into(), "CERT".into());
        assert!(build_tls_secret(&r, &m).is_err());

        m.values.insert("tls.key".into(), "KEY".into());
        let secret = build_tls_secret(&r, &m).unwrap();
        assert_eq!(secret.type_.as_deref(), Some("kubernetes.io/tls"));
        assert_eq!(secret.data.as_ref().unwrap()["tls.crt"].0, b"CERT".to_vec());
    }
}
