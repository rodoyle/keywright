# Installation, enrollment, and recovery

## Install (human, once, elevated)

```sh
keywright install --data-dir /var/lib/keywright
# Windows: keywright install  (defaults to %ProgramData%\keywright)
```

What install does:

1. Creates the data dir (restrictive permissions; owned by the service
   account once the platform service is registered).
2. Generates the **age identity** (`transport.agekey`) — the at-rest
   encryption key. **Back this up separately immediately**; encrypted
   material is unrecoverable without it.
3. Generates the **transport CA** (CA key age-encrypted as
   `transport-ca.key.age`; certificate in `transport-ca.pem`).
4. Issues the broker's **server certificate** (loopback; expires in a year).
5. Writes `broker.json` (bind address, policy rules, delivery mappings,
   cert profiles, pinned sops path).
6. Emits platform service units into `service/`:
   - Linux: `keywright.service` (systemd, `User=keywright`,
     `ProtectSystem=strict`)
   - macOS: `com.keywright.broker.plist` (launchd)
   - Windows: registration commands (`sc.exe create Keywright ...`) plus
     the icacls ACL line

`--dry-run` generates all material and units without OS registration (for
tests and rehearsals).

## Service registration

- **Linux**: copy `service/keywright.service` to `/etc/systemd/system/`,
  `systemctl enable --now keywright`, create the `keywright` user and
  `chown` the data dir.
- **macOS**: copy the plist to `/Library/LaunchDaemons/`,
  `launchctl load` it.
- **Windows**: run the `sc.exe create` command from
  `service/keywright-windows-service.md`, then apply the ACLs with the
  documented `icacls` line so only the service account can write the data
  dir.

The broker must run outside the agent's administrative control; the agent's
user must not be able to modify broker policy, executables, encryption
identities, or destination mappings.

## Enrollment (human)

```sh
keywright enroll --name pi-agent --role agent --out ./keywright-agent
keywright enroll --name ops-admin --role admin  --out ./keywright-admin
```

Roles are bound into the certificate and enforced by the broker: agents
request and observe; admins approve and import. Disabling an identity is
immediate (broker denylist) — edit `broker.json` deny list and restart, or
use the admin disable operation.

## Backup and restore

Back up, in this order of importance:

1. `transport.agekey` (age identity) — **without it nothing decrypts**.
   Store offline, separately from the data dir.
2. `broker.json` (policy, destinations, cert profiles).
3. The data dir's encrypted stores (`material.json`, `inventory.json`,
   `approvals.json`, `rotations.json`) — these are age/SOPS-encrypted.

Restore test: on a clean machine, place the age identity and stores into a
fresh data dir, run `keywright-broker --data-dir <dir>` — inventory lists
and material decrypts. The SOPS round-trip test in `core::sops` covers the
encrypted-record restore path mechanically.

## Transport-credential recovery

If the broker refuses to start because its server certificate expired:

```sh
keywright recover-transport
keywright-broker --data-dir /var/lib/keywright
```

`recover-transport` reissues the broker server certificate from the
transport CA (age identity required). If the transport CA itself expired,
re-run `keywright install` into a fresh data dir and re-enroll clients —
that is a deliberate re-bootstrap, not an automated rollback.

## Rotation recovery

Rotations are durable at every boundary. After a broker crash:

1. `rotation_status` (or `keywright list`) shows the record's persisted
   state (PLANNED / APPROVED / PREPARED / DEPLOYED).
2. Re-run `rotation_execute` with the same idempotency key — the engine
   resumes from the record, never skipping a boundary.
3. If the replacement cannot be verified, `rotation_abort` stops at the
   current boundary; the old credential stays live. Old material is retired
   (`REVOKED` note) only after VERIFIED plus any overlap period.
4. Delivery failures never auto-revoke the working credential.
