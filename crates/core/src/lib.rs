//! Keywright core: domain types, policy engine, rotation state machine, and
//! encrypted storage shared by the broker, CLI, and MCP adapter.
//!
//! Nothing in this crate performs privileged I/O; it defines the vocabulary
//! and invariants that the broker enforces.

pub mod agestore;
pub mod approval;
pub mod datadir;
pub mod inventory;
pub mod kube_delivery;
pub mod lifecycle;
pub mod material;
pub mod outcome;
pub mod policy;
pub mod refs;
pub mod role;
pub mod rotation;
pub mod sops;
pub mod trust;

pub use lifecycle::{RotationState, TransitionError};
pub use outcome::Outcome;
pub use refs::{CredentialKind, CredentialRef, CredentialVersion, ProvisioningStatus};
pub use role::Role;
pub use trust::{CaMaterial, IdentityDenylist, IssuedCert, PeerIdentity};
