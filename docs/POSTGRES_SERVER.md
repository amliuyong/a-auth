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

Password rate limiting uses the TCP peer address supplied by the listener.
Forwarding headers cannot supply this trusted request extension. Behind a
reverse proxy, its connections share the peer-IP bucket; account, tenant and
deployment limits still apply. Configure ingress admission and capacity for
that shared bucket. This profile does not trust end-user IP assertions from
forwarding headers.

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

Chart 0.1.1 adds the existing browser bundle as a separate container in web
Pods. It serves only `/`, `/login`, `/invite`, `/consent`, `/recover`, `/account`,
`/approve`, `/error` and built assets. Other public protocol requests proxy to
the web process on loopback. `/admin`, `/scim` and `/token` remain closed on
this frontend; ingress routes exact `/token` to the token Service. The frontend
mounts only a bounded temporary directory and receives no database, signing,
crypto, administrator or external Secret mounts.

Set `frontend.image.digest` and `frontend.image.sourceCommit` to the published
browser image's immutable digest and source commit. The backend and frontend
have separate component identities; `runtime.deployment_commit` continues to
identify the backend image. `frontend.enabled=false` installs protocol APIs
without browser pages. Both containers must pass their readiness probes.
Frontend access logs omit paths, queries, headers, cookies and bodies. SIGQUIT
lets its accepted requests drain within the Pod termination budget.

Chart 0.1.2 uses separate Ingress resources for the exact token route and the
web prefix route. Set `ingress.tokenAnnotations` and `ingress.webAnnotations`
for the chosen controller. Traefik's default rule-length priority can select
the web prefix before the token route; configure explicit priorities:

```yaml
ingress:
  tokenAnnotations:
    traefik.ingress.kubernetes.io/router.priority: "100"
  webAnnotations:
    traefik.ingress.kubernetes.io/router.priority: "10"
```

Both resources use the configured host, Ingress class and TLS Secret. Verify
`POST /token` reaches the token Service through HTTPS after installation;
a rendered exact-path rule alone does not establish controller behavior.

For a built frontend image, exercise live routing, private-path exclusion,
same-origin POST forwarding, container permissions, log privacy and shutdown:

```sh
python3 scripts/qualify_kubernetes_frontend.py \
  --image ghcr.io/OWNER/a-auth-web@sha256:IMMUTABLE_DIGEST \
  --receipt /private/path/frontend-validation.json
```

This check needs Linux Docker and free loopback ports 8080/8083. It uses a local
HTTP fixture; installed TLS and browser acceptance require separate evidence.

Kubernetes Secret projection roots can have group/world writable Unix mode
bits while the kernel mounts them read-only. Mounted-secret and signer loaders
accept that directory case only after checking the opened descriptor's
read-only mount flag. Writable mounts still reject unsafe directory modes;
private-file permissions and confined-path checks remain required.

These sources are under active validation. Initial chart lint/rendering is
not installation evidence; actual TCP/shutdown, installed protocol,
conformance, GHCR and restore gates remain separate in the
[delivery ledger](KUBERNETES_DELIVERY.md).
