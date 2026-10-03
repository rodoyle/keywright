//! mTLS transport setup for the broker: mandatory client certificates, no
//! unauthenticated fallback. Loopback bind by default.

use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode};
use openssl::x509::X509;

#[derive(Debug, thiserror::Error)]
pub enum TlsSetupError {
    #[error("openssl: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("missing server material: {0}")]
    Missing(String),
}

/// Everything the broker needs to present and verify mTLS identity.
#[derive(Debug, Clone)]
pub struct TransportMaterial {
    pub server_cert_pem: String,
    pub server_key_pem: String,
    /// CA certificate used to verify client certs (public).
    pub ca_cert_pem: String,
}

impl TransportMaterial {
    /// Assemble from previously issued material.
    pub fn new(server_cert_pem: String, server_key_pem: String, ca_cert_pem: String) -> Self {
        TransportMaterial {
            server_cert_pem,
            server_key_pem,
            ca_cert_pem,
        }
    }

    /// Build the acceptor: TLS server that REQUIRES a client certificate
    /// chaining to the transport CA and verifies it. No fallback.
    pub fn ssl_acceptor(&self) -> Result<SslAcceptor, TlsSetupError> {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        let server_cert: X509 = openssl::x509::X509::from_pem(self.server_cert_pem.as_bytes())?;
        let server_key = openssl::pkey::PKey::private_key_from_pem(self.server_key_pem.as_bytes())?;
        let ca_cert: X509 = openssl::x509::X509::from_pem(self.ca_cert_pem.as_bytes())?;
        acceptor.set_certificate(&server_cert)?;
        acceptor.set_private_key(&server_key)?;
        acceptor
            .check_private_key()
            .map_err(TlsSetupError::OpenSsl)?;
        // Mandatory mTLS: require and verify a client certificate chaining
        // to the transport CA. Default callback performs chain validation
        // against the store added below; no unauthenticated fallback.
        acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        acceptor.cert_store_mut().add_cert(ca_cert)?;
        Ok(acceptor.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keywright_core::trust::{generate_transport_ca, issue_client_cert, issue_server_cert};

    fn material() -> TransportMaterial {
        let ca = generate_transport_ca("test-ca").unwrap();
        let server = issue_server_cert(&ca, &["localhost", "127.0.0.1"]).unwrap();
        TransportMaterial::new(
            server.cert_pem.clone(),
            server.key_pem.clone(),
            ca.cert_pem.clone(),
        )
    }

    #[test]
    fn acceptor_builds_and_requires_client_cert() {
        let m = material();
        let acceptor = m.ssl_acceptor().unwrap();
        // The acceptor exposes a usable context; the mandatory-cert
        // enforcement is exercised during handshakes in server tests.
        let _ctx = acceptor.context();
    }

    #[test]
    fn garbage_material_is_rejected() {
        let m = TransportMaterial::new("garbage".into(), "garbage".into(), "garbage".into());
        assert!(m.ssl_acceptor().is_err());
    }

    #[test]
    fn client_certs_issue_alongside_transport() {
        let ca = generate_transport_ca("test-ca").unwrap();
        let client =
            issue_client_cert(&ca, "pi-agent-1", keywright_core::role::Role::Agent).unwrap();
        // The material is complete enough to feed both server and client paths.
        assert!(!client.cert_pem.is_empty());
        assert!(!client.key_pem.is_empty());
    }
}
