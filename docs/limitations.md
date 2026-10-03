# Known limitations (initial release)

Honest boundaries of the initial keywright release:

- **Out of scope by design**: HashiCorp Vault support, arbitrary signing
  APIs, exporting non-exportable keystore keys, universal token-issuer
  integrations, production root-CA administration, and a general-purpose
  Kubernetes deployment system.
- **PKCS#11**: extensibility is the tested `SigningProvider` trait with a
  software-backed test CA. Hardware token integration is future work; the
  trait keeps issuer keys inside the provider.
- **Verification (DEPLOYED → VERIFIED)**: requires broker-controlled
  verification checks; none are configured by default. Kubernetes readiness
  is never accepted as proof of rotation success. Rotations rest at
  DEPLOYED until a check is configured — by design, not a gap.
- **Retirement**: `REVOKED` retirement notes are recorded; fully automated
  overlap-period retirement timers land with the demo verification checks.
- **OS service registration**: unit files are emitted and documented; the
  actual `systemctl`/`launchctl`/`sc.exe` steps are human-run elevated
  commands (install deliberately refuses to assume privileges silently).
  `--dry-run` covers generation logic in CI.
- **Demo gates**: the three end-to-end demos (RustFS, Matrix/Hermes, TLS)
  are `#[ignore]` integration tests requiring `KEYWRIGHT_KUBECONFIG` and
  the `keywright-demo-*` namespaces — runnable on demand against the
  homelab cluster (or vcluster/kind fallback), not part of the default CI
  suite.
- **mTLS identity binding**: the client role travels in the certificate
  subject's OU (readable through the public openssl API; no generic X.509
  extension iteration is exposed). The binding is unforgeable in practice
  because only certificates chaining to the install-time transport CA are
  trusted.
- **The agent is not fully contained**: per the design doc, credential
  isolation is incomplete while the agent retains unrestricted control of
  credential-consuming workloads; the broker denies the agent plaintext
  values and signing authority, but workload compromise remains an
  external risk.
