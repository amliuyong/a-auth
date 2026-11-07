# Kubernetes + PostgreSQL delivery (#142)

This is the implementation and acceptance ledger for
[issue #142](https://github.com/amliuyong/a-auth/issues/142). It does not
declare the Kubernetes deployment ready for production.

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
| memory/AWS/PostgreSQL contracts | Shared contracts across three adapters plus equivalent atomicity/idempotency coverage | NOT_RUN |
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
- Retain consumed/revoked authority for the validity window; expiry is checked
  by the application, and garbage collection never determines token validity.
- Never put private signing keys or resolved external secrets into PostgreSQL.
- Do not include database URLs, credentials, cluster addresses, or AWS identity
  in tracked evidence.

## Current implementation frontier

The `postgres` feature currently provides `PostgresStore` implementations for
`ParStore`, `ReplayStore`, `InitialAccessTokenStore`, `ClientStore`, `CodeStore`,
and `RefreshStore`. Six embedded forward migrations create their authority
tables and credential-free client reclaim audit metadata.

Real PostgreSQL 16 tests currently pass 15 cases: six contracts shared with the
memory adapter, plus three PostgreSQL-specific transaction/durability cases.
The contracts include 16-way contention, tenant isolation, lease replacement
fencing, refresh version CAS, revocation, and credential metadata CAS.
Cross-table tests check that code/family creation updates the client authority
revision atomically, that failed conditions roll back the new row, and that
duplicate creation cannot resurrect consumed codes or revoked families.
Separate-pool replay contention and pool reconnect tests check database
coordination and persistence. These are port tests; they do not prove HTTP
multi-replica behavior or a backup/restore drill.

To run these tests, set `A_AUTH_TEST_DATABASE_URL` to a dedicated PostgreSQL
16+ test database and run:

```bash
bash scripts/test_postgres_contracts.sh
```

The test runner fails if the database is unavailable or the variable is absent.
The CI job uses a digest-pinned PostgreSQL container and runs the same contracts.
An adapter dependency-tree check confirms that the `postgres` feature's normal
dependencies exclude AWS SDK/config and Lambda. The production binary and
runtime-egress checks remain pending.

Local foundation validation also passed all 1,056 workspace library tests,
PostgreSQL-feature Clippy for all targets, Rust formatting, Markdown lint,
and the workflow-security tests. Existing Clippy warnings remain outside the
added PostgreSQL files. These checks do not replace the AWS or Kubernetes
conformance gates.

The production server does not select PostgreSQL yet. Remaining work includes
every other self-hosted storage port, cross-port credential/user/session/grant
transactions, encrypted refresh grace responses, state dispatch and startup,
mounted signing keys, portable transports/notifications, workers, chart/image
delivery, and all acceptance campaigns in the ledger above. Keep the PR in
draft and the issue open until these requirements are implemented and verified.
