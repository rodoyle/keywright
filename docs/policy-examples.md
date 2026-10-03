# Policy examples

Auto-approval rules live in `broker.json` under `policy.rules`. ACME-style:
when all conditions match, the operation is auto-approved; anything else
records PENDING_APPROVAL for a human (`keywright approve <op-id>`).

```json
{
  "policy": {
    "rules": [
      {
        "name": "rustfs-demo",
        "credentials": ["rustfs/*"],
        "destinations": ["rustfs"],
        "kinds": []
      },
      {
        "name": "matrix-import",
        "credentials": ["matrix/*"],
        "destinations": ["matrix"],
        "kinds": ["token"]
      },
      {
        "name": "tls-strict",
        "credentials": ["tls/web"],
        "destinations": ["tls-demo"],
        "kinds": ["tls_pair"]
      }
    ]
  }
}
```

Semantics:

- `credentials`: exact ids or `prefix/*` patterns.
- `destinations`: mapping names; every requested destination must be
  covered by the rule, or there is no auto-approval.
- `kinds`: empty = any credential kind.
- Agents can never approve their own requests: unmatched requests return
  `PENDING_APPROVAL` with a stable operation id, and the `/admin/approve`
  endpoint requires an admin certificate. Admins *requesting* also go
  through the rules — approving is a separate act.

Delivery mappings pin the cluster, namespace, Secret name, and key names:

```json
{
  "delivery": {
    "clusters": [
      {
        "name": "homelab",
        "kubeconfig": "/etc/keywright/kubeconfig",
        "namespaces": ["keywright-demo-rustfs", "keywright-demo-tls"]
      }
    ],
    "destinations": [
      {
        "name": "rustfs",
        "cluster": "homelab",
        "namespace": "keywright-demo-rustfs",
        "secret": "rustfs-creds",
        "key_names": null
      }
    ]
  }
}
```

Agents reference destinations **by name only**; unpinned clusters or
namespaces are refused (`DeliveryError::Unpinned` / `UnapprovedNamespace`).

Certificate profiles constrain issuance:

```json
{
  "cert_profiles": [
    {
      "name": "web-demo",
      "allowed_sans": ["app.local", "*.demo.internal"],
      "allowed_ekus": ["serverAuth"],
      "max_validity_days": 90,
      "min_rsa_bits": 2048
    }
  ]
}
```

SANs outside the profile, validity beyond the maximum, unknown profiles,
and rekeying to a disallowed SAN are all DENIED — issuance never signs
arbitrary agent-supplied bytes.
