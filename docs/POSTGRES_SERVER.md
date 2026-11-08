# PostgreSQL server entrypoints

Build the portable binary with:

```sh
cargo build -p agent-auth-http --features postgres --bin agent-auth-postgres --locked
```

The production modes are `serve-token CONFIG_PATH` and `serve-web CONFIG_PATH`.
They use the [production runtime configuration](POSTGRES_RUNTIME.md).
The development `agent-auth-server` remains a separate fixture.

The token process serves the existing token scope. The web process serves the
existing non-token scope. Both reject the unrestricted development route scope.
The web runtime can erase encrypted grace records but does not resolve or load
the grace decryption file. Its Secret projection must exclude that file;
different encryption purposes must use different key material.

## Listeners and readiness

| Environment setting | Default | Purpose |
| --- | --- | --- |
| `A_AUTH_BIND` | `0.0.0.0:8080` | Public protocol listener |
| `A_AUTH_MANAGEMENT_BIND` | `127.0.0.1:8081` | Web-process management listener |
| `A_AUTH_PROBE_BIND` | `0.0.0.0:8082` | Probe listener |

Ports must be distinct and nonzero. Terminate public HTTPS at a trusted ingress
and route exact `/token` requests to token processes. Route other public
protocol requests to web processes. Do not expose plain HTTP listeners directly
to the Internet.

The public listener returns 404 for management and SCIM paths, including when
the caller presents a valid administrator credential. The management listener
serves only those path families and retains their existing authentication.
An optional private management Service must have restricted network admission.
The default chart exposes no management Service and leaves its listener on
loopback.

`GET /health/live` reports process liveness. `GET /health/ready` returns 200 only
after the runtime check succeeds; otherwise it returns 503. Responses contain
no credentials or backend diagnostics. The runtime check verifies migration
authority, user HMAC authority, mounted administrator lifecycle and a valid
signing reload. Checks run every five seconds with a four-second caller budget.
An invalid signing publication preserves the previous immutable generation
and makes the process unready.

Public and management requests are rejected with 503 while the process is
unready or draining. After SIGTERM or SIGINT, readiness stays false, listeners
stop accepting work, and accepted HTTP requests have a thirty-second drain
budget. The process then closes its PostgreSQL pool.

Startup, access and shutdown events use JSON. Access events include method,
status and elapsed time; they omit request URLs, headers, cookies and bodies.
Existing handler audit events retain their current format.

## Migrations and delivery status

The `migrate CONFIG_PATH [RUNTIME_ROLE]` entrypoint reads only the database
credential mount and applies the embedded forward migrations. Give the Job its
separate DDL-capable database Secret. The optional existing runtime role receives
table DML and migration-metadata SELECT in a separate transaction after migration.
It must be a distinct login with no superuser, database-creation, role-creation,
role-membership, schema-creation or authority-table ownership privileges.
Identifiers use lowercase ASCII letters, digits and underscores. Failed grants
leave runtime startup closed until the operator fixes the role and retries.
HTTP processes never apply migrations or perform those grants.

Four Deployment modes run separate queues: `work-governance`, `work-events`,
`work-smtp` and `work-ssf`. They reuse the existing durable claim, admission,
retry, settlement and lease-fencing orchestrators. A failing queue does not
block a different queue's process. They have probe listeners and check authority
before each pass. A pass has a 240-second budget; SIGTERM prevents another pass
and lets the current pass settle before closing the pool. The chart permits
270 seconds for worker termination. A crash or timeout retains the existing
redelivery and SMTP uncertain-result behavior.

`job-retention`, `job-reclaim` and `job-recompute` run scheduled maintenance.
Reclamation and policy recomputation default to dry runs; the existing
`AGENT_AUTH_RECLAIM_ENABLED=1` and `AGENT_AUTH_RECOMPUTE_ENABLED=1` settings opt
into mutations. Retention uses the portable observation/attestation contract
and cannot assert that unknown external backups or logs have been erased.

S3-compatible archive export is disabled in this profile. The AWS tenant-key
provisioner and AWS Secrets Manager credential migration are inapplicable:
operators publish mounted key generations and complete administrator bundles.

The Helm sources are under `deploy/helm/a-auth`. They require an immutable image
digest, source commit and explicit runtime configuration. The token and web
Deployments use non-root users, read-only root filesystems, no privilege
escalation, dropped capabilities and no service-account token. Their crypto
projections explicitly include only the appropriate purpose files.

These sources are under active validation. Initial chart lint/rendering is
not installation evidence; actual TCP/shutdown, installed protocol,
conformance, GHCR and restore gates remain separate in the
[delivery ledger](KUBERNETES_DELIVERY.md).
