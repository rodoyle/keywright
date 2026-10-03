//! keywright-broker: the privileged broker server.
//!
//! The broker runs outside the agent's administrative control, serves HTTPS
//! with mandatory mTLS on loopback by default, and enforces broker policy,
//! approval, and destination pinning.

pub mod server;
pub mod tls;
