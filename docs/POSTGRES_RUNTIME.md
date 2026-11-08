# PostgreSQL production runtime

`PostgresRuntime::load` constructs the single-tenant HTTP state directly from
operator configuration. It does not call `AppState::dev`, generate signing keys
or administrator credentials, migrate the database, or substitute an in-memory
store after a configuration or database error.

All persistent protocol ports use the same PostgreSQL pool. The configuration
also selects the mounted ES256/RS256 signer, durable governance and security-event
queues, mounted administrator registry, external file-secret resolver, real
outbound HTTP transports, and TLS SMTP notifier. AWS STS and payments are disabled
in this profile. Archive export is disabled; hot security-event, fallback and SSF
records remain subject to the documented portable retention policy.

This composition and its local database tests do not establish installed
Kubernetes, conformance, key-rotation or backup/restore acceptance. Those gates
are recorded separately in the [delivery ledger](KUBERNETES_DELIVERY.md).

## Configuration and mounts

The runtime reads a bounded JSON file with `schema_version: 1`. Unknown fields
and unsupported enum values are errors. Every capability is an explicit boolean;
there is no environment fallback that enables a login placeholder or substitutes
development credentials.

Configuration contains mount paths and file names, not secret values:

| Field | Meaning |
| --- | --- |
| `host` | Exact HTTPS issuer host, without a scheme, path or port |
| `namespace` | Stable deployment identity for administrator checkpoints |
| `web_base_url` | HTTPS application URL used by browser navigation |
| `deployment_commit` | Forty lowercase hexadecimal source characters |
| `logical_region`, `jurisdiction` | Single-region governance residency configuration |
| `max_connections` | Per-process pool limit, from 1 through 64 |
| `database` | Protected mount root and leaf containing the PostgreSQL URL |
| `secrets` | Protected crypto mount and explicitly named HMAC/encryption files |
| `signing` | Protected signing mount and manifest leaf |
| `administrators` | Protected administrator mount and complete registry leaf |
| `external_secrets` | Dedicated external-secret mount, explicit reference-to-file bindings and retention statement leaf |
| `smtp` | Relay host, port, TLS mode, sender and nullable mounted credential/CA references |
| `phase`, `subject_type`, `dcr_mode` | Protocol phase, public/pairwise subjects and DCR admission policy |
| `capabilities` | Federation, passkey, CIBA delivery, BYOD, mTLS SVID, EMA, authorization and CIMD switches |
| `redirect_hosts`, `cimd_domains`, `ema_policies` | Explicit trust/policy inputs |
| `invitation_ttl_secs`, `grace_window_secs`, `password_workers` | Bounded invitation, refresh retry and password-work settings |

The external-secret root must be disjoint from database, signing, crypto and
administrator roots. Client-controlled secret references therefore cannot resolve
the issuer's private keys or its deployment credentials.

The HMAC files use standard base64 encoding of exactly 32 nonzero bytes. Server
and governance material must differ. Each encryption file contains
`{"active_kid":"current","keys":[{"kid":"current","key_base64":"..."}]}`:
replace the example material with standard base64 encoding of 32 nonzero bytes.
Notification admission and delivered-message observations share their encryption
purpose. Keep every key needed to decrypt retained records during encryption-key
rotation.

The administrator registry uses the
[mounted administrator format](MOUNTED_ADMIN_CREDENTIALS.md). Its checkpoint
namespace must remain stable across replicas and restarts. The external resolver
uses the [explicit mounted-secret bindings](MOUNTED_SECRETS.md).

Remote PostgreSQL connections require certificate and hostname verification
(`sslmode=verify-full`). Plaintext loopback connections are supported for isolated
local contracts. Duplicate URL parameters and socket/host overrides must not
weaken the configured connection policy. Supply a trusted root through the
PostgreSQL connection configuration for a private database CA.

SMTP uses required `implicit` TLS or `starttls`. Its `root_ca_key`,
`username_key` and `password_key` fields must be present, with JSON `null` for
unused values. Credentials require both username and password. Their non-null
values name entries in `external_secrets.bindings`; they are not plaintext
credentials.

## Startup and operations

Apply forward migrations as a separate deployment operation with a DDL-capable
database role. Ordinary HTTP and worker processes must use a role with only the
required runtime permissions. Allocate the total connection budget across
replicas, workers and migrations; `max_connections` is not a deployment-wide
limit.

The user authority validates the configured governance HMAC against persisted
directory authority. Mounted administrator loading validates the complete
registry and its durable lifecycle checkpoint. Missing, malformed or unavailable
required authority stops startup.

The signing ring preserves a complete previous generation after an invalid
reload, checks monotonic generations inside a running process and requires
publication before activation. This is not a durable cold-start rollback fence.
Operators must preserve the current signing manifest when restoring or replacing
pods and follow the [signing rotation procedure](MOUNTED_SIGNER.md).

Backups must include PostgreSQL authority and independently preserve the
operator-managed mounts. A database backup cannot reconstruct private keys.
Restoring old database or mount snapshots can also restore old lifecycle
authority; the backup/restore procedure and acceptance drill must address that
case before production qualification.
