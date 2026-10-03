# Pi integration guide

This document walks a human through enrolling a Pi agent with the keywright
broker and wiring the MCP adapter into the agent's configuration.

## Prerequisites

- A `keywright` CLI binary built from this workspace
  (`cargo build --workspace --release`; installable binaries land in
  `target/release/`).
- A running keywright broker (see `docs/install.md` once written; today:
  `keywright install --dry-run --data-dir <dir>` then
  `keywright-broker --data-dir <dir>`).
- The pinned `sops` binary on PATH (or at the path in `broker.json`).

## 1. Install the broker (human, once)

```sh
keywright install --data-dir /var/lib/keywright
```

This creates the protected data dir, generates the age identity
(`transport.agekey`) and the transport CA (CA key age-encrypted at rest),
emits platform service units, and writes `broker.json`.

**Back up `transport.agekey` immediately** and store it somewhere safe and
separate; without it, encrypted material is unrecoverable.

## 2. Enroll identities (human)

The agent gets its own low-privilege identity; the human keeps an admin one:

```sh
# agent identity (used by the MCP adapter)
keywright enroll --name pi-agent --role agent --out ./keywright-agent

# admin identity (used by the human CLI for approve/import)
keywright enroll --name ops-admin --role admin --out ./keywright-admin
```

Role capabilities are bound into the certificate and enforced by the broker:
agents can request, list, and observe — never approve, never import.

## 3. Start the broker

```sh
keywright-broker --data-dir /var/lib/keywright
```

The broker binds loopback with mandatory mTLS. Agents cannot modify broker
policy, executables, encryption identities, or destination mappings.

## 4. Wire the MCP adapter into Pi

In the Pi project settings (`.pi/settings.json`), add:

```json
{
  "mcpServers": {
    "keywright": {
      "command": "/usr/local/bin/keywright-mcp",
      "env": {
        "KEYWRIGHT_DATA_DIR": "/var/lib/keywright",
        "KEYWRIGHT_CLIENT_DIR": "/path/to/keywright-agent"
      }
    }
  }
}
```

The adapter speaks MCP over stdio and forwards every operation to the broker
over mTLS loopback HTTPS using the enrolled agent certificate.

`command` must point at the **release** binary — never a debug build:

```sh
install -m 0755 target/release/keywright-mcp /usr/local/bin/keywright-mcp
```

(`keywright` and `keywright-broker` are installed the same way when they are
not left in `target/release/`.)

## 5. Agent workflow

The agent-facing tools (all metadata-only, structured outcomes):

| Tool | Purpose |
|---|---|
| `credential_list` / `credential_describe` | Discover credentials (never values) |
| `credential_ensure` | Idempotent provisioning (never overwrites; token kinds → `NEEDS_HUMAN_IMPORT`) |
| `rotation_plan` / `rotation_execute` / `rotation_status` / `rotation_abort` | Policy-gated rotation with stable operation ids |
| `certificate_inspect` / `certificate_ensure` / `certificate_rotate` | Profile-constrained certificate lifecycle |

Typical agent loop:

1. `credential_list` to discover what exists.
2. `credential_ensure` for what is missing.
   - `READY` — done (or already existed).
   - `PENDING_APPROVAL` — report the operation id to the human; the human
     runs `keywright approve <op-id>`.
   - `NEEDS_HUMAN_IMPORT` — the human runs
     `keywright import --id <credential>` and pastes the secret (stdin only).
3. `rotation_plan` → `rotation_execute` when rotation is required; check
   `rotation_status` when blocked.

## 6. Human operations

```sh
# Approve a pending operation (admin identity)
keywright approve <op-id> --client-dir ./keywright-admin

# Import a secret via the trusted stdin path (admin identity)
keywright import --id matrix/hermes-token --client-dir ./keywright-admin

# Metadata listing
keywright list --client-dir ./keywright-admin

# Transport recovery (expired broker server cert)
keywright recover-transport
```

## Known limitations (initial release)

- Verification steps (DEPLOYED → VERIFIED) require broker-controlled check
  configuration; Kubernetes readiness alone is never accepted as proof.
- PKCS#11 signing providers are represented by the tested `SigningProvider`
  trait; hardware integration is out of scope for the initial release.
- The MCP adapter performs blocking HTTP to the loopback broker per call;
  fine for a control plane, not a high-volume path.
