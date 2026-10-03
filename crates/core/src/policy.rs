//! Policy engine: broker-controlled rules that decide whether an operation is
//! auto-approved (ACME-style, when conditions match) or must wait for human
//! approval. The agent can never modify policy; it is part of the broker's
//! protected configuration.

use crate::outcome::OperationId;
use crate::refs::{CredentialKind, CredentialRef};
use crate::role::Role;
use serde::{Deserialize, Serialize};

/// A requested operation, resolved by the broker before policy evaluation.
///
/// All fields come from broker-controlled mappings plus the *resolved* plan;
/// nothing here is raw agent input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationKind {
    /// Provision a new credential (or confirm an existing one).
    Ensure {
        credential: String,
        kind: CredentialKind,
    },
    /// Rotate an existing credential.
    Rotate {
        credential: String,
        from_version: u32,
    },
    /// Renew a certificate (same key material, new certificate).
    Renew { credential: String },
    /// Rekey a certificate (new key material).
    Rekey { credential: String },
}

/// One auto-approval rule.
///
/// If every condition matches, the operation is auto-approved; otherwise the
/// broker records PENDING_APPROVAL for human review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoApprovalRule {
    /// Human-readable rule name for the audit trail.
    pub name: String,
    /// Credential ids (or exact prefixes ending in `*`) this rule covers.
    pub credentials: Vec<String>,
    /// Destinations this rule covers, by mapping name.
    pub destinations: Vec<String>,
    /// Kinds this rule covers; empty = any.
    pub kinds: Vec<CredentialKind>,
}

/// Decision returned by the policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Policy matched: proceed without human approval.
    AutoApproved { rule: String },
    /// No rule matched: record PENDING_APPROVAL under this operation id.
    NeedsHumanApproval { operation: OperationId },
    /// Explicitly forbidden regardless of rules.
    Denied { reason: String },
}

/// Evaluate `kind` against a rule's `kinds` list; empty list = any kind.
fn kind_matches(rule: &AutoApprovalRule, kind: CredentialKind) -> bool {
    rule.kinds.is_empty() || rule.kinds.contains(&kind)
}

/// Credential id matches `exact` or `prefix*` patterns.
fn id_matches(patterns: &[String], id: &str) -> bool {
    patterns.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => id.starts_with(prefix),
        None => p == id,
    })
}

/// The ordered rule set plus the broker's identity-role resolution.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    pub rules: Vec<AutoApprovalRule>,
}

impl Policy {
    /// Decide a requested operation for a client with the given role.
    ///
    /// Agent-role requests are always evaluated against auto-approval rules;
    /// agents can never self-approve. Admins proposing operations also go
    /// through rules — approval is a distinct act from requesting.
    pub fn decide(
        &self,
        requester: Role,
        credential: &CredentialRef,
        kind: CredentialKind,
        destinations: &[String],
        operation: OperationId,
    ) -> Decision {
        // Any operation on a destination not in the rule's list can never be
        // auto-approved; destinations must appear in at least one rule.
        for rule in &self.rules {
            let creds_ok = id_matches(&rule.credentials, &credential.id);
            let kinds_ok = kind_matches(rule, kind);
            let dests_ok = destinations
                .iter()
                .all(|d| rule.destinations.iter().any(|rd| rd == d));
            if creds_ok && kinds_ok && dests_ok {
                return Decision::AutoApproved {
                    rule: rule.name.clone(),
                };
            }
        }
        match requester {
            // An agent cannot rescue itself into approval; only policy or a
            // human approval can.
            Role::Agent => Decision::NeedsHumanApproval { operation },
            // Admin requesters get a pending record too; they approve via the
            // separate approve command under the same admin identity.
            Role::Admin => Decision::NeedsHumanApproval { operation },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, creds: &[&str], dests: &[&str]) -> AutoApprovalRule {
        AutoApprovalRule {
            name: name.into(),
            credentials: creds.iter().map(|s| s.to_string()).collect(),
            destinations: dests.iter().map(|s| s.to_string()).collect(),
            kinds: vec![],
        }
    }

    fn cred(id: &str, kind: CredentialKind) -> CredentialRef {
        CredentialRef::new_request(id, kind)
    }

    #[test]
    fn matching_rule_auto_approves() {
        let policy = Policy {
            rules: vec![rule("rustfs-demo", &["rustfs/*"], &["homelab/demo-rustfs"])],
        };
        let d = policy.decide(
            Role::Agent,
            &cred("rustfs/access-key", CredentialKind::Token),
            CredentialKind::Token,
            &["homelab/demo-rustfs".to_string()],
            OperationId::new("op-1"),
        );
        assert_eq!(
            d,
            Decision::AutoApproved {
                rule: "rustfs-demo".into()
            }
        );
    }

    #[test]
    fn unmatched_requests_need_human_approval() {
        let policy = Policy {
            rules: vec![rule("rustfs", &["rustfs/*"], &["rustfs"])],
        };
        let d = policy.decide(
            Role::Agent,
            &cred("matrix/hermes-token", CredentialKind::Token),
            CredentialKind::Token,
            &["matrix-dest".to_string()],
            OperationId::new("op-2"),
        );
        assert_eq!(
            d,
            Decision::NeedsHumanApproval {
                operation: OperationId::new("op-2")
            }
        );
    }

    #[test]
    fn partial_destination_match_does_not_approve() {
        // If any requested destination is outside the rule, no auto-approval.
        let policy = Policy {
            rules: vec![rule("r", &["a/*"], &["approved"])],
        };
        let d = policy.decide(
            Role::Agent,
            &cred("a/one", CredentialKind::Password),
            CredentialKind::Password,
            &["approved".to_string(), "unapproved".to_string()],
            OperationId::new("op-3"),
        );
        assert!(matches!(d, Decision::NeedsHumanApproval { .. }));
    }

    #[test]
    fn kind_constraints_are_enforced() {
        let policy = Policy {
            rules: vec![AutoApprovalRule {
                name: "tls-only".into(),
                credentials: vec!["web/*".into()],
                destinations: vec!["tls-dest".into()],
                kinds: vec![CredentialKind::TlsPair],
            }],
        };
        let d = policy.decide(
            Role::Agent,
            &cred("web/cert", CredentialKind::Password),
            CredentialKind::Password,
            &["tls-dest".to_string()],
            OperationId::new("op-4"),
        );
        assert!(matches!(d, Decision::NeedsHumanApproval { .. }));
    }

    #[test]
    fn admins_also_go_through_rules_when_requesting() {
        // Requesting ≠ approving, even for admins.
        let policy = Policy::default();
        let d = policy.decide(
            Role::Admin,
            &cred("x/y", CredentialKind::Password),
            CredentialKind::Password,
            &[],
            OperationId::new("op-5"),
        );
        assert!(matches!(d, Decision::NeedsHumanApproval { .. }));
    }
}
