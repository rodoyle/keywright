//! Keywright core: domain types, policy engine, rotation state machine, and
//! encrypted storage shared by the broker, CLI, and MCP adapter.
//!
//! Nothing in this crate performs privileged I/O; it defines the vocabulary
//! and invariants that the broker enforces.

pub mod lifecycle;
pub mod outcome;
pub mod policy;
pub mod refs;
pub mod role;

pub use lifecycle::{RotationState, TransitionError};
pub use outcome::Outcome;
pub use refs::{CredentialKind, CredentialRef, CredentialVersion, ProvisioningStatus};
pub use role::Role;
