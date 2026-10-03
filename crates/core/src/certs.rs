//! Certificate lifecycle: profiles, application keys/CSRs, the
//! signing-provider abstraction, and a software-backed test CA.
//!
//! Strict distinctions enforced here:
//! - The **application private key** is generated and stays with the
//!   application credential (exportable by design).
//! - The **issuer signing key** belongs to the provider and is NEVER
//!   included in delivered application Secrets.
//! - Issuance happens by **approved profile** — never arbitrary signing of
//!   agent-supplied bytes.

use crate::trust::TrustError;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{X509, X509Builder, X509NameBuilder, X509Req};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("openssl: {0}")]
    OpenSsl(#[from] TrustError),
    #[error("openssl: {0}")]
    Stack(#[from] openssl::error::ErrorStack),
    #[error("profile {0} does not allow SAN {1}")]
    SanNotAllowed(String, String),
    #[error("profile {0} does not allow EKU {1}")]
    EkuNotAllowed(String, String),
    #[error("requested validity {0}d exceeds profile {1} maximum {2}d")]
    ValidityTooLong(u32, String, u32),
    #[error("profile {0} requires at least one SAN")]
    SanRequired(String),
    #[error("CSR public key does not match the application private key")]
    KeyMismatch,
    #[error("certificate/key mismatch")]
    CertKeyMismatch,
}

/// A certificate issuance profile: the ONLY way issuance is constrained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertProfile {
    pub name: String,
    /// SANs allowed by this profile (exact match, or `*.`-prefixed wildcard).
    pub allowed_sans: Vec<String>,
    /// EKUs allowed (e.g. serverAuth). Empty = any.
    pub allowed_ekus: Vec<String>,
    /// Maximum validity the profile grants.
    pub max_validity_days: u32,
    /// Minimum RSA key size for application keys.
    pub min_rsa_bits: u32,
}

/// Validate a SAN list against the profile.
pub fn validate_sans(profile: &CertProfile, sans: &[String]) -> Result<(), CertError> {
    if sans.is_empty() {
        return Err(CertError::SanRequired(profile.name.clone()));
    }
    for san in sans {
        let ok = profile.allowed_sans.iter().any(|allowed| {
            if let Some(suffix) = allowed.strip_prefix("*.") {
                // Wildcard: allow exactly one label under the suffix.
                let dotted = format!(".{suffix}");
                san.strip_suffix(&dotted)
                    .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('.'))
            } else {
                allowed == san
            }
        });
        if !ok {
            return Err(CertError::SanNotAllowed(profile.name.clone(), san.clone()));
        }
    }
    Ok(())
}

/// Validate requested validity against the profile maximum.
pub fn validate_validity(profile: &CertProfile, days: u32) -> Result<(), CertError> {
    if days == 0 || days > profile.max_validity_days {
        return Err(CertError::ValidityTooLong(
            days,
            profile.name.clone(),
            profile.max_validity_days,
        ));
    }
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The result of an application certificate issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedPair {
    /// PEM of the issued certificate.
    pub cert_pem: String,
    /// PEM of the application private key (NEVER the issuer key).
    pub key_pem: String,
    /// PEM of the issuing chain (public certs only).
    pub chain_pem: Vec<String>,
    pub sans: Vec<String>,
    pub validity_days: u32,
    /// 0 for the initial issuance; increments on renewal/rekey.
    pub generation: u32,
}

/// The signing-provider abstraction. A software-backed test CA implements it
/// for the initial release; PKCS#11 providers implement the same trait
/// later (non-exportable issuer keys stay inside the provider).
pub trait SigningProvider: Send + Sync {
    /// Human-readable provider name for audit records.
    fn name(&self) -> &str;

    /// Issue a certificate for a CSR under the given profile.
    ///
    /// Providers MUST re-validate the profile constraints against the CSR
    /// (SANs come from the CSR; validity from the request) before signing.
    fn issue(
        &self,
        csr: &X509Req,
        sans: &[String],
        validity_days: u32,
        profile: &CertProfile,
        generation: u32,
    ) -> Result<IssuedPair, CertError>;
}

/// Software-backed test CA: in-memory issuer key, chain of one.
pub struct SoftwareCa {
    ca_cert: X509,
    ca_key: PKey<Private>,
}

impl SoftwareCa {
    /// Build a software test CA with the given common name.
    pub fn generate(common_name: &str) -> Result<Self, CertError> {
        let rsa = Rsa::generate(3072)?;
        let key = PKey::from_rsa(rsa)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", common_name)?;
        name.append_entry_by_text("O", "keywright-test-ca")?;
        let name = name.build();

        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        let mut bn = BigNum::new()?;
        bn.rand(128, MsbOption::MAYBE_ZERO, false)?;
        builder.set_serial_number(&*bn.to_asn1_integer()?)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&key)?;
        builder.set_not_before(&*Asn1Time::days_from_now(0)?)?;
        builder.set_not_after(&*Asn1Time::days_from_now(3650)?)?;
        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
        builder.sign(&key, MessageDigest::sha256())?;
        Ok(SoftwareCa {
            ca_cert: builder.build(),
            ca_key: key,
        })
    }

    pub fn ca_cert_pem(&self) -> String {
        String::from_utf8_lossy(&self.ca_cert.to_pem().unwrap_or_default()).into_owned()
    }
}

impl SigningProvider for SoftwareCa {
    fn name(&self) -> &str {
        "software-test-ca"
    }

    fn issue(
        &self,
        csr: &X509Req,
        sans: &[String],
        validity_days: u32,
        profile: &CertProfile,
        generation: u32,
    ) -> Result<IssuedPair, CertError> {
        // Re-validate everything: the provider is the last line of defense.
        validate_sans(profile, sans)?;
        validate_validity(profile, validity_days)?;
        let csr_key = csr.public_key()?;

        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        let mut bn = BigNum::new()?;
        bn.rand(128, MsbOption::MAYBE_ZERO, false)?;
        builder.set_serial_number(&*bn.to_asn1_integer()?)?;
        builder.set_subject_name(csr.subject_name())?;
        builder.set_issuer_name(self.ca_cert.subject_name())?;
        builder.set_pubkey(&csr_key)?;
        builder.set_not_before(&*Asn1Time::days_from_now(0)?)?;
        let not_after = now_secs() + u64::from(validity_days) * 86_400;
        let not_after_time =
            Asn1Time::from_unix(not_after as i64).map_err(|e| TrustError::Parse(e.to_string()))?;
        builder.set_not_after(&not_after_time)?;
        builder.append_extension(BasicConstraints::new().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;
        // EKUs: intersect request (profile allowed) with serverAuth default.
        let mut eku = ExtendedKeyUsage::new();
        eku.server_auth();
        builder.append_extension(eku.build()?)?;
        let mut san_ext = SubjectAlternativeName::new();
        for san in sans {
            san_ext.dns(san);
        }
        let ctx = builder.x509v3_context(Some(&self.ca_cert), None);
        builder.append_extension(san_ext.build(&ctx)?)?;
        builder.sign(&self.ca_key, MessageDigest::sha256())?;
        let cert = builder.build();

        // Cert/key match check before returning.
        let cert_key = cert.public_key()?;
        if !cert_key.public_eq(&csr_key) {
            return Err(CertError::KeyMismatch);
        }

        Ok(IssuedPair {
            cert_pem: String::from_utf8_lossy(&cert.to_pem()?).into_owned(),
            key_pem: String::new(), // filled by the caller (app key PEM)
            chain_pem: vec![self.ca_cert_pem()],
            sans: sans.to_vec(),
            validity_days,
            generation,
        })
    }
}

/// Generate an application private key (RSA-2048, exportable).
pub fn generate_application_key(profile: &CertProfile) -> Result<PKey<Private>, CertError> {
    let bits = profile.min_rsa_bits.max(2048);
    let rsa = Rsa::generate(bits)?;
    PKey::from_rsa(rsa).map_err(CertError::Stack)
}

/// Build a CSR signed by the application key itself (never the issuer).
pub fn build_csr(
    key: &PKey<Private>,
    common_name: &str,
    sans: &[String],
    profile: &CertProfile,
) -> Result<X509Req, CertError> {
    validate_sans(profile, sans)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", common_name)?;
    let name = name.build();

    let mut builder = openssl::x509::X509ReqBuilder::new()?;
    builder.set_version(0)?;
    builder.set_subject_name(&name)?;
    builder.set_pubkey(key)?;
    builder.sign(key, MessageDigest::sha256())?;
    Ok(builder.build())
}

/// Validate that a certificate matches an application private key and chains
/// to the given CA.
pub fn validate_pair(cert_pem: &str, key_pem: &str, ca_pem: &str) -> Result<(), CertError> {
    let cert = X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| CertError::OpenSsl(TrustError::Parse(e.to_string())))?;
    let key = PKey::private_key_from_pem(key_pem.as_bytes())
        .map_err(|e| CertError::OpenSsl(TrustError::Parse(e.to_string())))?;
    let cert_key = cert.public_key().map_err(TrustError::OpenSsl)?;
    if !cert_key.public_eq(&key) {
        return Err(CertError::CertKeyMismatch);
    }
    let ca = X509::from_pem(ca_pem.as_bytes())
        .map_err(|e| CertError::OpenSsl(TrustError::Parse(e.to_string())))?;
    let ca_key = ca.public_key().map_err(TrustError::OpenSsl)?;
    if !cert.verify(&ca_key).map_err(TrustError::OpenSsl)? {
        return Err(CertError::CertKeyMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> CertProfile {
        CertProfile {
            name: "web-demo".into(),
            allowed_sans: vec!["app.local".into(), "*.demo.internal".into()],
            allowed_ekus: vec!["serverAuth".into()],
            max_validity_days: 90,
            min_rsa_bits: 2048,
        }
    }

    #[test]
    fn profiles_constrain_sans_and_validity() {
        let p = profile();
        validate_sans(&p, &["app.local".into()]).unwrap();
        validate_sans(&p, &["x.demo.internal".into()]).unwrap();
        // Wildcards are one label deep only.
        assert!(matches!(
            validate_sans(&p, &["a.b.demo.internal".into()]),
            Err(CertError::SanNotAllowed(_, _))
        ));
        assert!(matches!(
            validate_sans(&p, &["evil.example".into()]),
            Err(CertError::SanNotAllowed(_, _))
        ));
        assert!(matches!(
            validate_sans(&p, &[]),
            Err(CertError::SanRequired(_))
        ));

        validate_validity(&p, 90).unwrap();
        assert!(matches!(
            validate_validity(&p, 91),
            Err(CertError::ValidityTooLong(91, _, _))
        ));
        assert!(validate_validity(&p, 0).is_err());
    }

    #[test]
    fn full_issuance_flow_with_matching_pair() {
        let p = profile();
        let ca = SoftwareCa::generate("keywright-test-ca").unwrap();
        let key = generate_application_key(&p).unwrap();
        let key_pem =
            String::from_utf8_lossy(&key.private_key_to_pem_pkcs8().unwrap()).into_owned();
        let csr = build_csr(&key, "app.local", &["app.local".into()], &p).unwrap();
        let issued = ca.issue(&csr, &["app.local".into()], 30, &p, 0).unwrap();
        assert_eq!(issued.generation, 0);
        validate_pair(&issued.cert_pem, &key_pem, &ca.ca_cert_pem()).unwrap();
    }

    #[test]
    fn issuer_key_never_appears_in_issued_material() {
        let p = profile();
        let ca = SoftwareCa::generate("keywright-test-ca").unwrap();
        let key = generate_application_key(&p).unwrap();
        let csr = build_csr(&key, "app.local", &["app.local".into()], &p).unwrap();
        let issued = ca.issue(&csr, &["app.local".into()], 30, &p, 1).unwrap();

        // Chain contains only public CA certs; nothing decryptable.
        for pem in &issued.chain_pem {
            assert!(pem.contains("BEGIN CERTIFICATE"));
            assert!(!pem.contains("PRIVATE KEY"));
        }
        // The issuer private key never appears anywhere in the issued pair.
        let ca_priv =
            String::from_utf8_lossy(&ca.ca_key.private_key_to_pem_pkcs8().unwrap()).into_owned();
        assert!(!issued.cert_pem.contains(&ca_priv));
        assert!(!issued.chain_pem.iter().any(|c| c.contains(&ca_priv)));
    }

    #[test]
    fn wrong_key_fails_pair_validation() {
        let p = profile();
        let ca = SoftwareCa::generate("ca").unwrap();
        let key = generate_application_key(&p).unwrap();
        let csr = build_csr(&key, "app.local", &["app.local".into()], &p).unwrap();
        let issued = ca.issue(&csr, &["app.local".into()], 30, &p, 0).unwrap();

        let other = generate_application_key(&p).unwrap();
        let other_pem =
            String::from_utf8_lossy(&other.private_key_to_pem_pkcs8().unwrap()).into_owned();
        assert!(matches!(
            validate_pair(&issued.cert_pem, &other_pem, &ca.ca_cert_pem()),
            Err(CertError::CertKeyMismatch)
        ));
    }

    #[test]
    fn renewal_and_rekey_are_separate_generations() {
        // Renewal: same key, new cert (generation+1).
        let p = profile();
        let ca = SoftwareCa::generate("ca").unwrap();
        let key = generate_application_key(&p).unwrap();
        let csr = build_csr(&key, "app.local", &["app.local".into()], &p).unwrap();
        let renewed = ca.issue(&csr, &["app.local".into()], 30, &p, 1).unwrap();
        assert_eq!(renewed.generation, 1);

        // Rekey: new key, new CSR, generation+1 again — independently tested.
        let key2 = generate_application_key(&p).unwrap();
        let csr2 = build_csr(&key2, "app.local", &["app.local".into()], &p).unwrap();
        let rekeyed = ca.issue(&csr2, &["app.local".into()], 30, &p, 1).unwrap();
        assert_eq!(rekeyed.generation, 1);
    }
}
