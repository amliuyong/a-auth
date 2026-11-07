# Kubernetes + PostgreSQL delivery (#142)

This is the implementation and acceptance ledger for
[issue #142](https://github.com/amliuyong/a-auth/issues/142). It does not
declare the Kubernetes deployment ready for production.
The [port inventory](KUBERNETES_PORTS.md) accounts for all 57 public capability
traits and distinguishes authority, transports, and excluded SaaS/Region paths.

## Required outcome

Deliver the existing single-tenant self-hosted protocol surface on Kubernetes,
with PostgreSQL 16 or later using standard PostgreSQL features. Retain the AWS
deployment and the existing port contracts and conformance gates. SaaS tenancy,
CloudFront, Lambda@Edge, and multi-Region replication are outside this issue.

## Implementation sequence

1. Versioned forward schema migrations and PostgreSQL port adapters. Preserve
   conditional writes, transaction atomicity, idempotency, lease fencing,
   credential epochs, and strongly consistent lifecycle queries.
2. Wire every self-hosted persistent port into a production `AppState`.
   Implement cross-port transactions for credential changes, invitation and
   recovery consumption, exchange failures, and revocation. Do not use
   development memory stores for production authority.
3. Mounted Secret/file signing keys with ES256 and RS256, overlapping public
   JWKS generations, and atomic rotation. Resolve external secrets from mounted
   files. Add SMTP and portable outbound OIDC transports.
4. Production HTTP listener, separate private management exposure, probes,
   graceful shutdown, and structured logs. PostgreSQL durable worker queue and
   Kubernetes Deployment/CronJob/Job entrypoints for all applicable background
   work. Optional S3-compatible archives or explicit archive disablement.
5. AWS-free feature build, non-root/read-only OCI image, Helm chart with secure
   defaults and NetworkPolicy examples, and GHCR publication by immutable digest.
6. Installation, configuration, backup/restore, and upgrade procedures. Execute
   the full acceptance campaign below before closing the issue.

## Acceptance ledger

`NOT_RUN` means the required evidence has not yet been obtained. Local port
tests do not establish cluster, deployment, or conformance acceptance.

| Requirement | Authoritative evidence needed | Status |
| --- | --- | --- |
| Every single-tenant storage port | Port inventory, production wiring, durable contract and cross-port tests | IN_PROGRESS |
| Conditional writes and transactions | Real PostgreSQL concurrency and failure-atomicity tests equivalent to existing memory/AWS tests | IN_PROGRESS |
| Forward migrations, standard PostgreSQL | Versioned SQL, repeat/concurrent migration tests, PostgreSQL 16 run | IN_PROGRESS |
| Secret/file signer and JWKS rotation | Independent ES256/RS256 verification across reload and retired-key removal | NOT_RUN |
| Server and background work | Probe/shutdown tests, worker redelivery/lease fencing, cluster execution | NOT_RUN |
| Secret resolver, SMTP, optional archives | Adapter tests and installed deployment evidence | NOT_RUN |
| Secure container and chart | Rendered manifests, authentication and reachability tests | NOT_RUN |
| kind + in-cluster PostgreSQL | Installed chart and all required protocol flows including enterprise IdP | NOT_RUN |
| EKS + external RDS PostgreSQL | Installed chart and all required protocol flows including enterprise IdP | NOT_RUN |
| Existing conformance gates | Exact-candidate Kubernetes run and comparison with AWS self-hosted results | NOT_RUN |
| memory/AWS/PostgreSQL contracts | Shared contracts across three adapters plus equivalent atomicity/idempotency coverage | IN_PROGRESS |
| Multi-replica code/refresh/replay/IAT | Concurrent requests to distinct replicas with exactly one successful effect | NOT_RUN |
| AWS-free dependency tree/runtime | Production feature dependency tree and runtime egress evidence | NOT_RUN |
| Backup/restore revocation safety | Recovery drill with grants, refresh families, replay history, and documented remediation | NOT_RUN |
| OCI image and chart on GHCR | Published immutable digests, readback, install commands | NOT_RUN |
| Review, PR, CI, merge, closure | Reviewed SHA, terminal checks, merge readback, closed issue, clean worktree removal | NOT_RUN |

## PostgreSQL adapter conventions

- Namespace tables under `a_auth`; bind all input parameters.
- Store authority in PostgreSQL, with unique composite tenant keys.
- Use a single conditional SQL statement or a transaction holding row locks for
  changes that depend on existing authority. Never split a read/decision/write
  across unlocked database operations.
- Require explicit migration execution. Embed migrations in the binary and use
  the migration framework's database lock and checksum validation.
- Migration sessions use a 60-second lock and 120-second statement budget and
  close after success, failure, or cancellation while retaining the pool
  permit. Runtime connections keep their 5-second lock and 15-second statement
  budgets.
- Retain consumed/revoked authority for the validity window; expiry is checked
  by the application, and garbage collection never determines token validity.
- Never put private signing keys or resolved external secrets into PostgreSQL.
- Do not include database URLs, credentials, cluster addresses, or AWS identity
  in tracked evidence.

## Current implementation frontier

The `postgres` feature currently provides `PostgresStore` implementations for
`ParStore`, `ReplayStore`, `InitialAccessTokenStore`, `ClientStore`, `CodeStore`,
`RefreshStore`, `GrantStore`, `PolicyVersionStore`, `PolicyArtifactStore`,
`JtiStore`, `AuthzSessionStore`, `RateLimitStore`, `FederationConfigStore`,
`FederationFlowStore`, `MagicLinkStore`, `WorkloadTrustStore`, `DomainMapStore`,
`PasskeyChallengeStore`, `DeviceStore`, `AdminAuthStore`, and
`AttributeNamespaceStore`. Twenty-one embedded forward
migrations create their authority tables and credential-free client reclaim
audit metadata.

The current shared suite passes 69 cases: twenty-one contracts run through each of
the memory, AWS, and PostgreSQL adapters, plus six PostgreSQL-specific
transaction/durability cases. AWS adapters run against a loopback DynamoDB
emulator; PostgreSQL adapters run against PostgreSQL 16. This does not establish
native AWS deployment acceptance.
The contracts include 16-way contention, tenant isolation, lease replacement
fencing, refresh version CAS, revocation, and credential metadata CAS. They
also check immutable policy artifacts, atomic policy-version increments,
immutable delegated JTI authority and monotonic revocation, authorization
session transitions and user binding, and token-bucket admission.
Federation and magic-link contracts verify complete callback bindings,
browser-bound one-time consumption, tenant-scoped configuration and cooldowns,
subject cleanup, and the default empty self-hosted tenant.
Domain registration admits one globally unique owner across tenants. Passkey
challenges preserve ceremony/RP/origin binding and cannot be consumed by a
foreign tenant. Device tests race sixteen consumers against sixteen decisions
and check that each has one winner while preserving poll and credential
metadata. Admin OIDC tests check configuration CAS, hashed flow/session
create-once behavior, binding identity and tenant-scoped erasure.
Namespace contracts race sixteen exact-audience claims and sixteen migration
checkpoints, check pending/active/retired authority, and replay cancellation
without reusing an operation ID. PostgreSQL locks a per-tenant catalog row,
including claims for names that are not yet bound. The durable snapshot stores
escaped JSON as text so valid operation IDs containing U+0000 round-trip.
Missing or malformed snapshot fields fail closed; fault injection verifies
that a truncated snapshot cannot become unbound authorization.
Memory and PostgreSQL share the extracted namespace transition rules.
Cross-table tests check that code/family creation updates the client authority
revision atomically, that failed conditions roll back the new row, and that
duplicate creation cannot resurrect consumed codes or revoked families.
The failed-exchange transaction consumes the authorization code and transitions
its bound session together. An injected failure in the second table write
proves rollback; stale caller timestamps cannot bypass commit-time expiry.
Separate-pool replay contention and pool reconnect tests check database
coordination and persistence. These are port tests; they do not prove HTTP
multi-replica behavior or a backup/restore drill.
A separate cold-start case creates a fresh database and runs twelve competing
migrators after a held advisory lock is released. It also checks that a
one-connection pool retains its migration permit, normal writes keep their
shorter timeout, and checksum failure cannot leak a lock into another pool.

The shared contracts also exposed existing adapter gaps. AWS Grant CAS now
rejects revoked authority even when supplied its current revision. Memory and
AWS policy artifacts reject conflicting writes to an existing version while
allowing identical retries. AWS JTI erasure includes delegated authority, and
PAR consumption uses a conditional deletion. Five additional runs of the PAR
concurrency case passed after this change.
AWS federation configuration now encodes the empty self-hosted tenant with a
reserved non-empty physical key; named-tenant keys and the logical tenant in
configuration JSON remain unchanged. The same encoding covers authorized
snapshot transactions and governance cleanup.
Full matrix contention also reproduced duplicate federation/Admin flow
consumption against the DynamoDB emulator. Both AWS deletions now require
the row to exist and map conditional failure to a miss. Five additional rounds
of both flow contracts passed; these observations do not establish a native
AWS race. Memory domain records now normalize their stored domain, and memory
Admin flow/session creation rejects overwriting existing hashed bindings.

Current local validation also passes 1,057 workspace library tests, 680 HTTP
library tests with both `postgres` and `aws`, and 33 RS attribute and federation
mapping regression tests. Earlier increments passed 64 BYOD, passkey, device,
and Admin SSO regression tests. Three library tests explicitly require native
AWS disposable tables and remain ignored/`NOT_RUN`. Development signing
fixtures now share cached key material while keeping signing counters and
fault injection independent between instances.

To run the complete matrix, set `A_AUTH_TEST_DATABASE_URL` to a dedicated
PostgreSQL 16+ test database and `A_AUTH_TEST_DYNAMODB_ENDPOINT` to a loopback
DynamoDB emulator, then run:

```bash
A_AUTH_TEST_AWS_ADAPTERS=1 bash scripts/test_postgres_contracts.sh
```

Without the AWS flag, the same runner executes the memory/PostgreSQL subset.
Missing required database configuration or an unavailable database fails the
run. The cold-start migration contract creates and removes its own temporary
database, so the dedicated test role needs `CREATEDB` and schema DDL privileges.
The runner defaults to two independent contracts at a time to fit a standard
100-connection PostgreSQL server alongside the cold-start drill. Individual
contracts retain their sixteen/thirty-two concurrent actors. `RUST_TEST_THREADS`
can override that harness bound; increasing it requires a suitable database
connection budget.
AWS contract writes are restricted to loopback. The CI job uses
digest-pinned PostgreSQL and DynamoDB emulator containers and runs the complete
matrix.
The protected `Required CI` policy includes the shared-contract job. A
regression test checks that its policy covers every declared CI check.
Exact conformance selectors follow the existing workflow policy: skipped on
pull requests, required on pushes and manual dispatch. Their skipped result
does not establish Kubernetes conformance acceptance.
An adapter dependency-tree check confirms that the `postgres` feature's normal
dependencies exclude AWS SDK/config and Lambda. The production binary and
runtime-egress checks remain pending.

The production server does not select PostgreSQL yet. Remaining work includes
every other self-hosted storage port, cross-port credential/user/session/grant
transactions, encrypted refresh grace responses, state dispatch and startup,
mounted signing keys, portable transports/notifications, workers, chart/image
delivery, and all acceptance campaigns in the ledger above. Keep the PR in
draft and the issue open until these requirements are implemented and verified.
