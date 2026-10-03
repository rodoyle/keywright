//! Client roles. The broker maps validated mTLS client identities to one of
//! these roles; permissions differ strictly between them.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Role attached to a validated client identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Agent-facing (MCP adapter) identity: request and observe, never approve.
    Agent,
    /// Human CLI identity: approve, import, enroll, administer.
    Admin,
}

impl Role {
    /// Whether this role may approve privileged operations. Requester ≠
    /// approver is enforced elsewhere; this is the capability flag.
    pub fn may_approve(self) -> bool {
        matches!(self, Role::Admin)
    }

    /// Whether this role may supply trusted human imports (secret material).
    pub fn may_import(self) -> bool {
        matches!(self, Role::Admin)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Agent => f.write_str("agent"),
            Role::Admin => f.write_str("admin"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agents_cannot_approve_or_import() {
        assert!(!Role::Agent.may_approve());
        assert!(!Role::Agent.may_import());
        assert!(Role::Admin.may_approve());
        assert!(Role::Admin.may_import());
    }
}
