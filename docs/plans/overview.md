## Draft goal

### Goal

Implement a cross-platform, reference-oriented credential lifecycle helper for coding agents and Kubernetes applications.

Provide a compiled Rust broker, human CLI, and agent-facing MCP adapter. The main agent discovers credential requirements and orchestrates approved provisioning and rotation without receiving plaintext credentials or unrestricted cryptographic authority.

Support Windows, macOS, and Linux. Use HTTPS with mandatory mTLS as the client/broker transport. Keep HashiCorp Vault out of scope.

### Architecture

```text
Pi agent → MCP adapter / CLI client
                    │
                    │ HTTPS + mandatory mTLS
                    ▼
Separately privileged Rust broker
  ├── Policy, approval, and metadata inventory
  ├── Durable credential and rotation records
  ├── SOPS-encrypted storage
  ├── Token and certificate lifecycle adapters
  ├── Cryptographic signing-provider abstraction
  └── Direct Kubernetes API delivery
```

The broker must run outside the agent’s administrative control, preferably outside the agent-managed Kubernetes cluster. The agent must not be able to modify broker policy, executables, encryption identities, privileged kubeconfigs, or provider configuration.

Compilation is a packaging choice, not a security boundary. The design must remain secure with implementation source visible.

### Implementation choices

- Use Rust for the broker, CLI, MCP adapter, policy engine, and lifecycle state machine.
- Use a direct Kubernetes API client rather than shelling out to `kubectl`.
- Preserve SOPS interoperability initially through a pinned, protected SOPS executable invoked without a shell.
- Use SOPS age recipients; use the Rust `age` library where native age functionality is needed. Do not add redundant outer rage encryption.
- Use OpenSSL bindings for certificate/key operations where appropriate.
- Abstract signing operations to permit future PKCS#11 or other C-ABI providers.
- Use native service identities and filesystem permissions/ACLs on each operating system.
- Keep the wire protocol platform-independent.

## Scope and requirements

### Credential inventory and provisioning

Implement metadata-only discovery of broker-managed credentials and approved Kubernetes destinations.

Return references, credential types, required key names, versions, lifecycle states, expiry information where available, and provisioning status. Never return secret values or raw Kubernetes Secret objects.

Support:

- Generation of application-local passwords and key pairs.
- Human import of existing API tokens through a trusted input path.
- Provider adapters for token issuance, inspection, and revocation.
- Explicit `NEEDS_HUMAN_IMPORT` responses when automated issuance is unavailable.
- Kubernetes generic Secret and TLS Secret delivery.
- Reuse of existing credentials by default; never silently replace them.

Treat arbitrary agent-provided paths, URLs, shell commands, issuer configuration, and signing-library paths as untrusted. Resolve credential references through broker-controlled mappings.

### Certificate lifecycle

Implement:

1. Generate an exportable application private key.
2. Construct and sign its CSR using that application key.
3. Obtain a certificate through an approved issuer.
4. Validate certificate/key matching, identity, validity, and chain against policy.
5. Persist the resulting credential encrypted.
6. Deliver the certificate/key pair to an approved Kubernetes Secret.
7. Activate and verify the consumer.

Maintain a strict distinction between application private keys and issuer signing keys.

Issuer keys may be non-exportable and accessed through a future PKCS#11 provider. Never attempt to export keystore issuer keys as application secrets.

Expose certificate issuance and rotation by approved profile—not arbitrary signing of agent-supplied bytes. Certificate profiles must constrain SANs, EKUs, algorithms, validity, and issuer.

Model renewal and rekeying separately. Scheduled renewal must not depend on an active agent session.

### Rotation orchestration

Implement a durable, resumable state machine:

```text
PLANNED → APPROVED → PREPARED → DEPLOYED → VERIFIED → RETIRED
```

Record failures and recovery actions without assuming every operation can be rolled back.

Required behavior:

- Bind approval to the resolved plan, current credential version, privileges, and destinations.
- Use idempotency keys, per-credential locking, and expected-version checks.
- Persist encrypted replacement material before delivery whenever possible.
- Reconcile credentials issued externally but not successfully persisted.
- Update producers and consumers in the required order.
- Verify the new credential through broker-controlled authenticated checks.
- Retire old credentials only after successful verification and any approved overlap period.
- Distinguish abort, rollback, and revocation.
- Never treat Kubernetes readiness alone as proof that rotation succeeded.

### Agent-facing operations

Use these names as an initial interface proposal:

```text
credential.list
credential.describe
credential.ensure
rotation.plan
rotation.execute
rotation.status
rotation.abort
certificate.inspect
certificate.ensure
certificate.rotate
```

Return structured outcomes:

```text
READY
PENDING_APPROVAL
NEEDS_HUMAN_IMPORT
CONFLICT
DENIED
FAILED
```

Every pending operation must provide a stable request/operation identifier so the agent can report blocked work and resume later.

## Security and operational controls

- Require mTLS for privileged endpoints; no unauthenticated fallback.
- Bind to loopback by default; remote listening requires explicit configuration.
- Validate server identity and map approved client identities to broker-controlled roles.
- Separate agent requester permissions from human approval permissions.
- Support immediate disabling of a client identity.
- Bootstrap transport credentials through a human-controlled installation/enrollment workflow.
- Provide recovery when transport credentials expire or the service cannot start.
- Apply HTTP/MCP origin protections where relevant.
- Give the broker a dedicated Kubernetes identity with namespace-scoped RBAC.
- Keep namespace creation, workload mutation, Secret deletion, and RBAC administration disabled unless explicitly required and approved.
- Pin cluster destinations; never inherit the caller’s current Kubernetes context.
- Protect policy, recipient configuration, destination mappings, executables, and provider-library paths from agent modification.
- Keep plaintext out of command arguments, agent tool inputs/results, logs, audit records, and ordinary temporary files.
- Sanitize subprocess environments and error output.
- Avoid unrestricted decryption, shell execution, raw signing, or arbitrary network-request endpoints.
- Use atomic encrypted-record replacement and encrypted version retention.
- Maintain an audit trail of requests, approvals, versions, targets, transitions, and outcomes.
- Back up encryption identities separately and test recovery.
- Do not claim complete credential isolation while the agent retains unrestricted control of credential-consuming workloads.

## Implementation loop

1. Inspect the target repository and existing Pi integration; record assumptions and unresolved choices.
2. Produce a short design document covering trust boundaries, API schemas, storage format, state machine, and platform service installation.
3. Implement the core broker and CLI with metadata inventory, trusted import, approval, and ensure-without-overwrite.
4. Add SOPS persistence and direct Kubernetes delivery.
5. Implement rotation planning, durable execution, recovery, and verification.
6. Implement software-backed certificate issuance and renewal/rekeying.
7. Add the MCP adapter and Pi integration guidance.
8. Test security boundaries and failure recovery on Windows, macOS, and Linux.
9. Audit each milestone against the acceptance criteria before marking it complete.

Keep changes reviewable. Do not silently expand scope to solve blocked requirements. Report missing issuer access or credentials as explicit dependencies.

## Acceptance and audit

The goal is complete when:

- Native binaries build and pass tests on Windows, macOS, and Linux.
- Agent inventory exposes metadata but no credential values.
- Missing credentials produce a provisioning request rather than unauthorized generation.
- Repeated `ensure` operations do not change existing credentials.
- Rotation requires approval or an explicit preapproved policy.
- Unauthorized clients cannot access broker operations.
- Agent clients cannot approve their own privileged requests.
- Secrets do not appear in process arguments, normal logs, API responses, or agent transcripts.
- Kubernetes writes use the approved cluster, namespace, Secret, and key mappings.
- Concurrent and stale-version operations fail safely.
- Crash-injection tests cover issuance, persistence, deployment, verification, and retirement boundaries.
- Failure to verify a replacement does not automatically revoke the working credential.
- Certificate issuance delivers a matching application key/certificate pair.
- Certificate profiles reject unauthorized identities and privileges.
- Issuer signing keys are never included in delivered application Secrets.
- Renewal and rekeying are independently tested.
- Backup restoration and transport-credential recovery are demonstrated.
- Documentation includes installation, enrollment, policy examples, Pi integration, rotation recovery, and known limitations.
- PKCS#11 extensibility is represented by a tested signing-provider interface; hardware integration is not required for the initial release.

Initial end-to-end demonstrations:

- RustFS: provision an approved application-local credential pair, reuse it idempotently, and rotate it through verified activation.
- Matrix/Hermes: import or obtain a service-issued token through an approved path, then deliver it without exposing it to the agent.
- TLS application: generate an application key and CSR, issue through a test CA, deliver the pair, and verify renewal and rekeying.

Out of scope for the initial release: Vault, arbitrary signing APIs, exporting non-exportable keystore keys, universal integrations for all token issuers, production root-CA administration, and a general-purpose Kubernetes deployment system.
