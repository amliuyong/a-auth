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
| Secret/file signer and JWKS rotation | Independent ES256/RS256 verification across reload and retired-key removal; installed replica rotation | IN_PROGRESS |
| Server and background work | Probe/shutdown tests, worker redelivery/lease fencing, cluster execution | IN_PROGRESS |
| Secret resolver | Confined-file adapter tests and installed deployment evidence | IN_PROGRESS |
| SMTP and optional archives | Adapter tests and installed deployment evidence | IN_PROGRESS |
| Secure container and chart | Rendered manifests, authentication and reachability tests | IN_PROGRESS |
| kind + in-cluster PostgreSQL | Installed chart and all required protocol flows including enterprise IdP | IN_PROGRESS |
| EKS + external RDS PostgreSQL | Installed chart and all required protocol flows including enterprise IdP | IN_PROGRESS |
| Existing conformance gates | Exact-candidate Kubernetes run; existing AWS baseline passed with 37 required passes and 14 approved exceptions | IN_PROGRESS |
| memory/AWS/PostgreSQL contracts | Shared contracts across three adapters plus equivalent atomicity/idempotency coverage | IN_PROGRESS |
| Multi-replica code/refresh/replay/IAT | Concurrent requests to distinct installed replicas with exactly one effect; shared refresh grace response | PASS |
| AWS-free dependency tree/runtime | Production dependency tree passed; bounded runtime API observations remain required | IN_PROGRESS |
| Backup/restore revocation safety | Post-revocation restore passed; stale-backup hazard and known-grant remediation drilled; complete authority reconciliation remains required | IN_PROGRESS |
| OCI image and chart on GHCR | Published immutable backend/frontend/chart digests, readback and both native installations | PASS |
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

`PostgresRuntime::load` now constructs all required self-hosted persistent
ports directly, with mounted signing and administrator authority, confined
external secrets, real HTTP transports and durable TLS SMTP notifications.
Startup validates the complete migration checksum authority without applying
DDL. Notification admission and management observations share their configured
encryption purpose. See the [production configuration reference](POSTGRES_RUNTIME.md).
`agent-auth-postgres` now supplies separate token/web, probe and private
management listeners, scoped grace capabilities, migration/runtime grants,
four durable queue-worker modes and three maintenance Job modes. Local real-TCP
tests exercise readiness loss/recovery and an accepted request draining across
SIGTERM. See [server entrypoints](POSTGRES_SERVER.md).

Native amd64 and arm64 backend and browser images at component commit
`0a9fb2efbd1a9f933f3d52656a242927d3139d70`, plus chart 0.1.2, have been
published on GHCR with immutable digest readbacks. Both kind with TLS
PostgreSQL 16 and EKS with private encrypted PostgreSQL 17 RDS have installed
the application and all forty-one migrations. Each environment runs two web
Pods, two token Pods and two replicas of each of the four workers. Separate
DDL and runtime database roles and restricted application Secret projections
remain in use.

Each installation passed eleven protocol checks through distinct Pod
port-forwards: discovery/source identity, dual-algorithm JWKS, public/private
management separation, one-time IAT contention, password onboarding, PKCE code
contention and terminal replay rejection, independent token signatures,
authenticated introspection, one refresh rotation with a shared grace response,
DPoP JTI contention using independent codes, and cross-replica refresh-family
revocation. An in-flight code exchange loser can return 503 while its lease
is held; a completed replay returns `invalid_grant`. These observations do
not establish official conformance.

Both environments also passed seven real Chromium browser checks over an
installed TLS Ingress: initial-password login and required change, authorization
session, Secure/HttpOnly cookie, consent and state-bound callback, PKCE token
exchange with independent ES256/RS256 verification, JavaScript execution and
component-source identity. The private qualification CA was independently
validated with curl; Chromium trusted the single certificate public-key pin.
The callback was captured by the test browser. Public WebPKI and an external
relying-party deployment are not established by this run.

This browser campaign found that Traefik's default rule-length priority routed
`/token` to the web frontend. Chart 0.1.2 splits the two Ingress
resources and supports separate controller annotations; explicit priorities
passed installed HTTPS routing and browser checks in both environments.
That chart version was published by immutable digest, pulled back with source
verification and installed in both environments. See the
[installation/upgrade guide](KUBERNETES_INSTALL.md) for artifact identities
and the [server reference](POSTGRES_SERVER.md) for routing configuration.

Both environments passed eight checks against a real existing Cognito OIDC
provider, using separate issue-owned app clients and a dedicated test user.
The mounted file resolver supplied each client secret; the browser exercised
upstream state/nonce/PKCE, password login, verified callback, a local secure
session, downstream consent/code exchange, independent ES256/RS256
verification and consumed-flow replay rejection. Authenticated management
readback confirmed the expected issuer/sub-derived local user. The test
email was operator-set as verified. This is real Cognito interoperability;
it does not establish Okta/Entra or enterprise SCIM acceptance.

The existing protected AWS conformance run
[42362005620](https://github.com/amliuyong/a-auth/actions/runs/42362005620)
passed for deployed component
`f63aac1a756e164de2c09454d8d7315f6ca98fca`: 37 required tests passed and
14 had approved, limited exceptions. Its approved profile is Basic OP Code,
with explicit non-claims for FAPI, OpenID Federation and blanket RFC 9700
certification. This baseline is a different deployment from the Kubernetes
candidate. Candidate hosted OIDF execution remains `NOT_RUN`.

Installed signing rotation passed in both environments: publish the new
EC/RSA pair, wait the actual 300-second cache interval, activate it on both
token replicas, preserve independent old/new verification during overlap,
wait the actual token lifetime plus cache interval, then remove retired key
IDs from both web replicas. Invalid-publication readiness/recovery remains a
separate installed check.

Both installations also restored a post-revocation PostgreSQL backup into
separate databases and passed four restored-HTTP checks, including unexpired
grant/refresh rejection and still-fresh DPoP replay rejection. An old-backup
drill demonstrated missing-revocation resurrection and reconciled the known
grant across replicas. The
[recovery guide](KUBERNETES_RECOVERY.md) requires containment and complete
post-backup authority reconciliation. Unidentified lost revocations remain
unknown; there is no automatic stale-snapshot rejection.

Each environment's two SMTP workers delivered one durable notification to a
TLS SMTP fixture, with one accepted message and no second acceptance on
reobservation. Worker crash/uncertain-result qualification remains separate.
Enterprise-provider scope, candidate official conformance and full AWS
comparison, invalid signing-publication recovery, runtime AWS API
observations, complete restore authority and background-work qualification
remain required.

`PostgresGovernanceResourceBackend` observes live authority and physically
retained records in the configured primary database. Operator-owned mounts
cannot be automatically deleted. Protected, short-lived operator statements
for external backups/logs carry an explicit attestation evidence basis;
missing statements leave retention pending. See
[PostgreSQL governance resources](POSTGRES_GOVERNANCE_RESOURCES.md).
Complete installed retention and recovery acceptance remain pending.

`BrandingStore::postgres` preserves deployment presentation across process
restarts with a persisted revision CAS and complete host/record validation.
`AdminCredentialResolver::mounted` loads one operator-owned single-tenant
bundle and persists secret-free owner/revision/lifetime/retirement checkpoints.
It rejects cold-start rollback and higher-revision resurrection of retired
credentials, bypasses plaintext registry caching and checks expiry after
database lock waits. See [mounted administrator credentials](MOUNTED_ADMIN_CREDENTIALS.md).
Production listeners and mounts are installed; complete administrator
lifecycle rotation/restore acceptance remains pending.

`FileSecretResolver` resolves only explicitly mapped references from a
dedicated mounted directory, reads current projected Secret generations and
confines descriptor-relative reads. See [mounted external client
secrets](MOUNTED_SECRETS.md) for bindings, permission limits and failure
behavior. Production startup and chart mounts are installed, and real
Cognito federation passed in both native environments.

The existing OIDC/JWKS, token exchange, CIBA, SSF and CIMD HTTP transports now
compile through `portable-http`, shared by AWS and PostgreSQL without AWS SDK
dependencies. Their existing trust, DNS pinning, bounds and refresh/response
rules are retained. See [portable outbound HTTP](PORTABLE_HTTP.md).
Production composition and real Cognito use are installed; full outbound
worker effects remain under qualification.

`MountedSignerRing` loads immutable ES256/RS256 file generations and
`TenantKeyService::mounted` resolves them per request with disabled SaaS
registry/command interfaces. See [mounted signing keys](MOUNTED_SIGNER.md) for
the manifest, permission and rotation contract. Local independent verification
and invalid-reload tests are separate from the installed positive rotation
above; installed invalid-publication readiness/recovery remains required.

The `postgres` feature currently provides `PostgresStore` implementations for
`ParStore`, `ReplayStore`, `InitialAccessTokenStore`, `ClientStore`, `CodeStore`,
`RefreshStore`, `GrantStore`, `PolicyVersionStore`, `PolicyArtifactStore`,
`JtiStore`, `AuthzSessionStore`, `RateLimitStore`, `FederationConfigStore`,
`FederationFlowStore`, `MagicLinkStore`, `WorkloadTrustStore`, `DomainMapStore`,
`PasskeyChallengeStore`, `DeviceStore`, `AdminAuthStore`,
`AttributeNamespaceStore`, `PasswordStore`, `SecurityEventStore`, and
`FederationAttributeMappingsStore`, `ScimGroupsStore`, `SessionStore`, and
`RecoveryStore` and `PasskeyStore`.
`PostgresInvitationStore` implements `InvitationStore` using the same pool and
configured user authority as `PostgresUsersStore`.
`PostgresMessageOutbox` implements `MessageOutbox` with explicitly configured
external encryption keys or a delete-only capability.
`PostgresGovernanceStore` implements all thirty-one `GovernanceStore` methods
using tenant-locked durable control snapshots and permanent suppression rows.
`PostgresCibaStore` implements all ten `CibaStore` methods with complete encrypted
request/callback snapshots and a delete-only capability.
`PostgresSsfStore` implements all thirteen `SsfStore` methods with generation-bound
streams, encrypted delivery/lease/history authority and durable worker claims.
`PostgresUsersStore` implements all twenty-five `UsersStore` methods with a
required external HMAC authority key.
`PostgresGraceStore` implements
`GraceStore` with an explicit external encryption key ring or a delete-only
capability. Forty-one embedded forward
migrations create their authority tables and credential-free client reclaim
audit metadata.

All thirty-five ports now have runtime enum variants and trait delegation.
The shared contracts select those variants rather than invoking the raw
PostgreSQL adapters. The production constructor is described above. Failed code exchange and encrypted
refresh finalization select their existing atomic helpers and reject stores
from different pool identities. User-authorized code issuance, active-client
Grant admission, password enrollment/rotation and operation-owned administrator
password reset now use PostgreSQL transactions as well. Recovery rotation,
consumption/receipt creation and passkey registration/deletion are wired too.
All seven existing governance data-plane operations now select PostgreSQL.

Client authority reads and locked writes require the complete stored typed
record, including nullable retirement fields, and its physical client ID.
Missing status fields cannot reactivate a retired client. Code creation and
Grant admission roll back when this client proof is invalid. Grant admission
locks the active client and commits its usage day/revision with the Grant.
Human code issuance locks the active, non-pending user and rechecks its
credential epoch before committing the code and client authority.

Password transactions follow directory, user, then credential lock order and
require the exact credential-change operation and epoch. Enrollment/rotation
commits the password version and releases the user fence atomically.
Administrator staging retains the owner on both authorities; completion
clears both markers together after authentication cleanup. Two independent
HTTP states/pools exercise enrollment/rotation and reset retry. Actual second
writes rejected by owned database constraints verify password rollback,
retained revocation fences and same-operation reset recovery. These mixed
development fixtures do not establish production AppState or deployment
acceptance.

Recovery rotation requires the exact user fence and contact email. Consumption
commits the code, user epoch, session generation, recovered session and complete
success receipt together. Same-operation retry rechecks current user, password
and session authority and returns the committed session. Expiry and freshness
decisions use the clock after waiting for locks. Sixteen same-operation HTTP
requests through two separate pools create one session/receipt. An actual
receipt-write rejection rolls back the code, user and session generation;
after repair, retry succeeds and blocked-user replay returns no cookie.

Passkey registration rechecks active user/epoch and the stored session's current
generation, expiry and recent authentication under directory/user/session locks.
Sixteen separate ceremonies through two pools persist their validated public
credentials. Deterministic held-row tests change user status or session
generation after HTTP preflight and prove the waiting transaction refuses
registration. Operation-owned deletion commits key removal and user-fence
completion together; an actual second-write rejection retains both the key and
revocation fence. These ceremonies use a test `fmt=none` authenticator and do
not establish hardware-authenticator or installed conformance acceptance.

Governance erasure locks the tenant directory and complete governance authority
before data rows. Destructive writes require the exact job, policy, lifecycle,
lease token/deadline and target epoch; user operations also bind the job's
canonical target and aliases. A final lease check after waiting for data locks
rolls back tentative effects when the lease expires. Every participating port
must use the same pool identity, and the user's stable authority key must match
the configured governance HMAC. User and tenant suppression are checked during
identity admission.

User cleanup commits credentials, sessions/generations, recovery receipts,
associated authorization sessions, refresh grace, notifications and group
membership together. Tenant cleanup preserves its durable stage cursor,
removes orphan protocol/configuration authority, and revokes SSF streams and
active deliveries while retaining tombstones and audit. Residual inventory
uses a database snapshot; SSF inventory validates encrypted authority too.
Four owned-database fixtures use independent pools to exercise HTTP-started
user erasure and tenant offboarding, permanent alias/tenant suppression,
foreign-pool and HMAC mismatch rejection, lease expiry during an observed SQL
row-lock wait, and actual late-write failures that roll back earlier deletes
or stream revocation. The fixtures use development control/transports and
explicit PostgreSQL data-plane composition. Production startup, native workers
and installed acceptance remain pending.

The [PostgreSQL governance queue](POSTGRES_GOVERNANCE_QUEUE.md) adds durable
wake-ups, bounded `SKIP LOCKED` claims, private lease capabilities and fenced
acknowledgment/retry/dead-letter operations. A wake-up enqueued during a lease
survives acknowledgment. Seven independent-pool fixtures cover contention,
locked-head progress, rollback, damaged commands, expiry and a worker crash
after a phase commit. Redelivery repairs the next wake-up without repeating the
phase or credential-epoch mutation. The batch rejects a foreign-pool
composition before claiming. Production polling/shutdown, retention scheduling,
dead-letter operations and installed qualification remain required.

The [PostgreSQL security event fallback](POSTGRES_SECURITY_EVENT_FALLBACK.md)
retains immutable ingress snapshots, fences event-ID rebinding and uses
bounded `SKIP LOCKED` claims with private settlement capabilities. Hot-ledger
persistence followed by queue acknowledgment repairs a crash between commits
without creating a second event. Both authorities share database availability;
this queue cannot durably cover a whole-PostgreSQL outage. Production
composition, polling/shutdown, retained queue cleanup, dead-letter operations
and installed qualification remain required.

Federated attribute reconciliation locks namespace, mapping and user authority
in that order. Owner purge locks the mapping registry before the user and
preserves the complete private user record. Configuration and mapping changes
share the mapping catalog lock, preventing issuer replacement or deletion
while mappings exist. Configuration reads validate the decoded tenant and
IdP against the physical row identity. Authorized administrator attribute
writes also lock namespace authority before the user, recheck the captured
authority and retain the raw attribute CAS and federation ownership rules.

The current shared suite contains 216 cases: thirty-five contracts run through each of
the memory, AWS, and PostgreSQL adapters, plus one hundred and eight PostgreSQL-specific
transaction/durability cases and three AWS recovery interleaving/compatibility
cases. AWS adapters run against a loopback DynamoDB
emulator; PostgreSQL adapters run against PostgreSQL 16. This does not establish
native AWS deployment acceptance.
The grace contract's KMS responses come from a loopback fixture. This does not
establish native KMS acceptance.
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
Password contracts check create-once provisioning, sixteen concurrent
temporary-password changes/resets, owner-marker round trips, completion of
pending revocation and version-conditional cleanup. Hashes live in their own
table and retain the existing non-serializable credential wrapper. The
PostgreSQL decoder validates the bounded PHC profile, and numeric versions
preserve the complete `u64` range. Raw password CAS does not complete the
remaining authorized user/password/session transaction work.
Grace response tokens and matching metadata use per-record AES-256-GCM
envelope encryption. Random data keys are wrapped by externally configured
keys; only key IDs, wrapped keys, nonces and ciphertext enter PostgreSQL.
Authentication binds the encryption format/purpose and family/version/expiry.
Tests reject moved or modified envelopes, retain exact cached responses across
separate pools, exercise mounted key overlap/retirement and check that a
delete-only instance cannot read or write even an absent entry.
The refresh finalization helper commits the owner/version-fenced increment and
encrypted cache together. An actual second-write constraint failure rolls back
the version and lease mutation; sixteen concurrent retries have one winner.
The helper rejects a grace instance from another store pool. Runtime enum
dispatch selects this transaction; production startup remains pending.
An expired real lease cannot be extended using a stale caller timestamp;
finalization checks the clock after acquiring the family row lock.
Security events use a global immutable event ID and validated typed envelope.
Sixteen concurrent admissions create one row. Duplicate ingress atomically
reconciles a compatible source-history suffix with the current delivery view;
older or equivalent retries contribute no additional attempts or transitions.
An injected update failure rolls back both delivery and its source receipt.
Late source evidence reopens an archived delivery for refresh without claiming
that an archive object was written. Tenant/time export skips corrupt rows with
`SECURITY_EVENT_INVALID` diagnostics and continues pagination through valid
neighbors; duplicate writes against corrupt authority still fail closed.
The memory adapter now applies the same source-history merge, following a
reproduced shared-contract failure. Durable fallback ingestion, archive workers
and their multiple-worker acceptance remain pending.
Federation attribute mappings share pure transition rules with memory and use
a locked PostgreSQL tenant catalog. Registry/mapping revisions fence updates;
enabled target ownership is unique across IdPs, and deleted mapping IDs remain
unavailable for reuse. Sixteen competing IdPs admit one target owner. Contracts
also check target release/reacquisition, issuer rebinding, the empty self-hosted
tenant, bounded registries and logical governance counts.
The complete JSON-text snapshot validates registry identities, target owners and
permanent markers together. Missing or inconsistent data fails closed on reads
and writes; it cannot become an empty registry. An actual second-write failure
rolls back initial catalog admission. Exhausted revisions preserve ownership.
Two additional domain regressions reproduced and corrected premature target
release in the original memory disable/delete transitions.
Raw mapping CRUD does not complete the required configuration, namespace and
user-authorized reconciliation transaction.
Canonical users have no expiry. PostgreSQL stores their private persistence
format separately from the non-serializable public user record. Physical
identities and aliases use `BYTEA`; escaped JSON text preserves NUL-bearing
attribute and operation identifiers and the full `u64` counter range.
Incomplete or inconsistent records fail closed without being overwritten.
Tenant directory locks fence absent canonical IDs and SCIM aliases.
SCIM creation commits the canonical user, unique visible aliases and immutable
POST receipt together; moving aliases with PUT retains the old POST receipt
and current user state. A single statement snapshot returns each SCIM page
with its exact total. User row locks fence credential owners, disable/enable,
attribute revision/generation and irreversible erasure. Version exhaustion and
an actual second-write failure preserve the previous authority.
Signed, expiring user cursors bind the tenant, normalized query, status filter
and continuation key; separate pools share only the explicit external key.
This authority key must remain stable for the lifetime of suppression records.
A persisted one-way check rejects a differently configured replica without
rebinding the database or storing the key. Runtime startup must call
`verify_authority` before readiness; admission repeats the check in its
transaction. Runtime roles must not update or delete this binding.
Suppression admission checks durable digests under the same logical tenant
directory fence, including the empty issuer tenant's `default` authority.
A reproduced race initially admitted an empty-tenant user before a suppression
writer committed; the shared fence now prevents that admission.
SCIM adoption checks the selected canonical identity as well as the proposed
ID, so another candidate cannot bypass its suppression.
The governance writer now publishes suppression under that same fence.
Destructive-job authorization now uses the transactions described above.
Production startup and installed acceptance remain pending.
Raw user lifecycle and attribute methods do not complete the
required credential/session and namespace-authorized transactions.
SCIM groups retain retired canonical IDs while releasing their active external
alias, members and role mapping together. Group mutations share the user
directory fence, including absent aliases and tenant-wide cleanup. A role is
explicitly configured; a group name never grants authority. No-op mutations and
mapping retries retain their version and timestamps. Membership batches check
every next version before writing and commit in one transaction. An actual
second-group update failure rolls back the complete batch and role authority.
Private persistence codecs validate the physical identity, sorted unique
members, mapping fields and retired state without making public group records
serializable. Missing or inconsistent data and exhausted versions fail closed.
The shared contract reproduced memory deletion and batch mutation before
version-exhaustion errors; both now preserve the complete previous state.
It also reproduced AWS empty-tenant cleanup deleting a named tenant's groups;
cleanup now applies the existing exact tenant-key predicate.
The authorized group/role, SSO configuration and user lifecycle transactions
remain pending.
Login sessions capture a durable user session generation. Reads and listings
use one statement snapshot to compare the captured generation with current
authority; expiry remains an application decision at the existing port seam.
Actor-owned deletion, retaining one session and consuming an actor for user-wide
revocation lock the directory, generation and relevant session rows. Generation
advancement and the retained-session update or actor deletion commit together.
Actual second-write failures preserve every previous session's authority.
Creation rejects overwriting a captured session ID. Observations never recreate
missing or generation-revoked sessions, and epoch cleanup preserves its exact boundary.
Private codecs require the complete record and compare its physical identity,
epoch, generation, expiry and observation timestamp; NUL identifiers and the
complete `u64` range round-trip.
The shared contract reproduced memory overwriting a captured ID, AWS independent
concurrent calls adopting the same successful revocation receipt, and AWS
observations updating a generation-revoked session. Memory rejects the existing
ID; AWS uses a separate invocation nonce while retaining one stable retry token
and fences observations with the generation in a transaction.
The complete matrix also reproduced a false AWS SCIM alias conflict when two
independent strong reads straddled one atomic create. A deterministic regression
captures that mixed snapshot. Alias classification now reads both rows in one
DynamoDB transaction with bounded retry for transaction contention. Primary and
standby HTTP runtime policies grant transaction reads on the exact user table;
the configuration tests inspect each role's inline and managed policies.
Password enrollment/rotation, administrator reset, recovery consumption/rotation
and passkey registration/deletion are wired as described above. Production
startup and installed acceptance remain pending.
Recovery code consumption locks the tenant directory and complete code set
within one transaction. It preserves the existing constant-time verifier,
failed-attempt limit, lockout boundary and regeneration behavior. Only HMAC
verifiers enter storage. Private codecs require every code-set and receipt
field and compare physical lookup, user, activation and receipt metadata;
NUL identities, `u32` attempt counts and `u64` credential epochs round-trip.
Actual rejected admission/consumption writes preserve the previous authority.
A failed second deletion rolls back both code-set and receipt cleanup.
The authorized credential/session transaction now creates those complete
success receipts. Production startup and installed recovery acceptance remain
pending.
Shared tests reproduced memory tenant cleanup leaving successful-operation
receipts behind; cleanup now removes both maps in the existing lock order.
Real loopback DynamoDB interleavings reproduced stale consumption adopting a
regenerated code set or recreating a deleted one. Each new set now has a random
generation, and both raw and authorized consumption require the row, version
and captured generation. Legacy records gain a generation on consumption.
Malformed generations and exhausted versions fail closed. Retries of an
ambiguous transaction retain the same generation and transaction payload.
Passkey credentials have no expiry. PostgreSQL locks the directory and complete
credential row for create-once admission, signature-counter CAS, owner-bound
rename/deletion and cleanup. Sixteen counter contenders have one winner;
sixteen concurrent renamers preserve that counter and the complete public
credential material. Actual rejected writes preserve admission, name and count.
The private codec requires every field, including the public model's legacy
defaulted name and registration time, and validates physical identity/counter
metadata. Truncated or rebound rows fail without being overwritten.
NUL-bearing records and full `u32` counter/`i64` registration limits round-trip.
Shared contracts reproduced memory and AWS accepting a counter decrease.
Assertion verification and all three stores now use one existing WebAuthn rule:
positive counters must advance; counterless zero-to-zero transitions remain
permitted. User/epoch/session-authorized registration and operation-owned
deletion are wired above. Production startup and installed authentication
acceptance remain pending.
Invitation issuance checks active local user identity, credential epoch and
password absence under the tenant directory fence. Password creation and
missing-password reset participate in that fence, following two reproduced
PostgreSQL races. Acceptance rechecks the complete invitation and user/password
authority, then creates the login session and consumes the verifier in one
transaction. Sixteen competing accepts create one `amr=["invite"]` session.
Resending invalidates the old verifier; wrong activation, tenant, expiry,
password or moved user authority cannot create a session.
An actual failed invitation deletion rolls back the session and its generation.
Failed resends and corrupt complete records preserve the previous authority;
private codecs require every field and match physical identity/epoch/expiry.
NUL locator and activation IDs and full `i64` timestamps round-trip.
Shared contracts reproduced memory and AWS session lifetime overflow; both now
return an error without consuming the invitation. Production invitation startup
and full installed credential lifecycle acceptance remain pending.
Delivery observations retain their immutable message identity and encrypted
complete payload. Per-record AES-256-GCM envelopes bind the outbox purpose,
tenant, message, kind, recipient and timestamps to external encryption authority.
Only ciphertext, wrapped data keys and query metadata enter PostgreSQL; retained
magic-link bodies have no plaintext database representation.
Authenticated but incomplete or rebound payloads, changed envelope metadata and
copied refresh-grace ciphertext fail closed without being overwritten.
Explicit key overlap permits old and new records; retired or wrong keys cannot
read them. A delete-only instance rejects reads and writes, including absent
selections, but can erase ciphertext without possessing the keys.
Tenant directory transactions fence observation admission and erasure.
Sixteen exact retries create one immutable row; captured IDs cannot acquire
another recipient. Rejected admission and deletion roll back the previous state.
Separate pools share observations and preserve NUL fields and full `i64` times.
Selection orders the complete tenant set before applying its limit.
Shared contracts reproduced memory limiting before sorting and AWS counting
the same concurrent deletion repeatedly. Memory now limits after sorting;
AWS recipient and tenant cleanup count successful conditional deletions.
The explicit observation writer and its test notification fixture do not
establish SMTP delivery.

[PostgreSQL SMTP notifications](POSTGRES_SMTP.md) add encrypted durable
admission, private bounded leases and a single-submission transition before
networking. Recovery-operation retries cannot rebind or duplicate delivery.
Required TLS validates relay certificates and hostnames, with bounded network
work and sanitized errors. A positive DATA receipt and encrypted observation
commit together; failed database recording can be retried without resubmitting.
Lost receipts and crashes after submission admission retain an unknown external
result and never reopen automatic submission. Local TLS tests combine two
PostgreSQL pools, 16 admissions and 16 workers to verify one submission and
no retry after a lost DATA receipt. Outbox and governance erasure remove pending
and in-flight notification authority; late observations cannot recreate it.
Production mounted SMTP configuration, polling/shutdown, operational status
reporting and native worker acceptance remain required.
Governance-authorized erasure now uses the transactions described above.
Governance transitions share the extracted domain rules with memory.
PostgreSQL locks the same tenant directory as identity admission before reading
or changing policy, job, lease, permit, continuation or external-action authority.
Changed control snapshots commit with a bounded generation; read-only queries
do not create authority. Job completion and its immutable evidence commit
together. Permanent suppression records live separately from the mutable
control snapshot and participate in the same admission fence.
Sixteen contenders share one lease, policy revision or continuation-token effect;
separate pools also coordinate without process-local authority.
Private complete snapshots reject missing, duplicate, unknown or rebound fields,
invalid evidence hashes and inconsistent permit aggregates without overwrite.
The forward suppression migration preserves existing rows while admitting
NUL-bearing keys and escaped records, full `u64` epochs and `i64` times.
SQL fault injection rolls back completion, evidence and initial directory
admission. Exhausted gate and snapshot generations retain the previous permit
set and count, including expired-permit pruning.
Shared tests reproduced memory retaining partial permit changes on errors and
AWS allowing an observed expired export to reappear after clock rollback.
Memory commits successful cloned transitions; AWS conditionally deletes expired
export authority while preserving a concurrently recreated live export.
All three stores reject an external action whose resource fingerprint does not
match its reference, following a reproduced memory/AWS contract failure.
The control snapshot rewrites tenant state on mutation; this does not establish
performance acceptance. Governance-authorized data-plane transactions are wired;
production startup and native worker acceptance remain required.
CIBA request snapshots use per-record encryption, including the per-request
notification credential, binding message, delivery destination and captured
password version. Authentication binds the CIBA purpose, tenant, request,
client, user, expiry and physical polling/decision/consumption metadata.
Private codecs require all seventeen fields, reject unknown or duplicate fields
and compare authenticated physical metadata. Modified envelopes, independently
authenticated incomplete/rebound payloads and moved outbox ciphertext fail
without overwrite. Key overlap permits old and new records; retired or wrong
keys fail closed. A delete-only capability cannot read, arm a throttle, issue
or mutate a request, but can erase ciphertext without decryption keys.
Tenant directory transactions serialize field CAS and request/throttle cleanup.
Sixteen pollers and concurrent sets of sixteen decisions and sixteen consumers
each have one winner while preserving unrelated fields.
Rejected mutations retain the original envelope; an actual second-delete
failure rolls back both request and throttle cleanup.
Separate pools preserve NUL-bearing identifiers and full timestamp/version
domains. Throttle admission uses wider arithmetic so boundary timestamps cannot
panic or change its inclusive expiry rule.
Shared tests reproduced memory window overflow, AWS TTL overflow and concurrent
AWS subject cleanup reporting sixteen requests as 256 removals.
Memory and AWS now use wider comparison arithmetic; AWS clamps only its
garbage-collection deadline. Subject cleanup counts successful conditional
deletions, rechecks the subject and separates the empty profile from named
tenant keys. This helper also serves device, recovery and authorization-session
cleanup. Encrypted issued push responses, durable callback dispatch/receipts,
production state, authorized credential/session transactions and native CIBA
worker acceptance remain required.
SSF stream admission retains the thirty-two-stream quota, including revoked
tombstones. Revision CAS preserves pause/resume/replacement activation, and
deliveries bind the event ID to its stream generation. PostgreSQL retains
complete delivery snapshots in per-record AES-256-GCM envelopes, including
subjects, verification state, signed SETs, lease credentials and retry history.
All twenty-seven fields and every six-field attempt are required, including
nullable values. Authentication binds the separate SSF purpose, tenant, stream,
generation, event, queue times, expiry, status and physical lease metadata.
Typed domain validation checks counters/history, signed-field combinations,
signed SET evidence and destination configuration. Authenticated incomplete,
rebound, inconsistent or wrong-purpose data fails without overwrite.
The existing AWS domain validator is shared with PostgreSQL; AWS's physical
index checks remain in its adapter.

SSF transactions acquire tenant directory fences before stream or delivery rows.
Due-row claims use `FOR UPDATE SKIP LOCKED`; a held delivery row is skipped in
favor of another due row. Two independent pools with sixteen actors claim
distinct deliveries, save a signed SET once, complete its receipt once and
admit one redrive. Expired owners cannot sign or finish after a replacement
lease; paused/revised/revoked streams block further signed SET admission.
Retries and redrives retain the same signed SET and complete attempt history.
Governance revocation commits stream tombstones and suppression of all active
deliveries together while retaining terminal audit. This retained-audit
transition requires the configured delivery encryption keys.

An exhausted later stream revision and actual delivery-write failures roll
back previous stream changes, claims or receipts. Key overlap decrypts old
authority and writes the active key; wrong or retired keys fail closed.
Shared tests also reproduced AWS version decoding through `i64` rejecting
`u64::MAX`; it now parses the complete unsigned domain directly.
Queue contracts use owned isolated PostgreSQL databases because due claims
span tenants. Directory fences serialize competing tenant transitions;
throughput and installed-worker acceptance remain unverified.
Production SSF push, signer resolution and portable worker execution still
require integration and native qualification.
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
Password version-exhaustion tests also reproduced existing memory hash
mutation before failure and unchecked AWS first-login arithmetic. All three
adapters now reject exhausted writes without changing the credential. An HTTP
regression checks that failed memory Admin reset staging retains the original
hash/metadata while keeping the already-started user revocation fence.
The grace contract also reproduced memory cleanup deleting another family
whose name shared a prefix. Cleanup now compares the exact family identity.

The full workspace library run at parent source
`7100dcf7101f275199711db15f9e035b76fd7806` passed 1,272 cases, including 688
HTTP library cases with both `postgres` and `aws`; three native AWS cases
were ignored/NOT_RUN. This historical result does not establish full-library
acceptance for subsequent source changes.
The recovery increment passes ten focused contract, rollback, codec and real
loopback DynamoDB interleaving/compatibility cases and 118 account, credential,
password, recovery, invitation, SCIM and session HTTP regressions.
Recovery library regressions also preserve ambiguous-commit reconciliation
and private receipt redaction.
The passkey increment passes five new port/fault cases, three challenge
regressions, 21 focused WebAuthn cryptographic tests and 108 passkey, account,
credential, governance, invitation, password and recovery HTTP regressions.
The group increment `34050c9670abf64d610fad85e41aa8a9baac47ae` passed
47 SCIM, Admin SSO and data-governance HTTP
regressions, along with six focused group contract/fault cases.
The session increment passes 118 HTTP regressions for login sessions, accounts,
credentials, passwords, recovery, invitations and SCIM.
It also passes seven focused session contract/fault cases,
five additional AWS-emulator SCIM contention rounds and all 277 infra tests.
Two effective-policy regressions cover transaction reads on primary and standby
user tables, including CDK's managed-policy overflow.
The user increment `70c592764cbdc90bf71fbfc4d14982bb0594ee36` passed 129
SCIM, Admin user, password/account/lifecycle and RS attribute/federation mapping
HTTP regressions and hosted CI.
The preceding mapping increment passed 682 HTTP library tests with both
`postgres` and `aws`, and 33 RS attribute/federation mapping HTTP regressions.
The security-event increment `c4bf77de6b236754118e1a7f35c468d7f27a65f7`
passed 31 security-event/SCIM HTTP regressions.
The grace increment `f5bdb5c7e64010b6beff5589804534a172538ad4` passed
114 code-flow/refresh/revocation HTTP regressions and hosted CI.
The password increment `f1b8604343396c7223174742937414c08c97f04d` passed
76 password login, account credential, credential lifecycle and
administrator-user regression tests. The preceding namespace
increment `28a3e0ed5e2edb70aeec2996f6b99fe5fb87d3ba` passed 1,057 workspace
library tests and 33 RS attribute/federation mapping regression tests. Earlier
increments passed 64 BYOD, passkey, device and Admin SSO regression tests.
Three library tests explicitly require native AWS disposable tables and remain
ignored/`NOT_RUN`. Development signing
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

## External encryption key files

The adapter API `EncryptionKeyring::from_file` reads one immutable snapshot
from a regular JSON file, including a Kubernetes Secret projection symlink.
The file must have no world access or group write permission; `0400`, `0440`
and `0600` are supported. Input is bounded to 64 KiB. Duplicate/unknown fields,
duplicate key IDs, missing active keys, invalid base64, non-32-byte keys and
all-zero keys fail closed. Errors omit file contents and paths.

```json
{
  "active_kid": "grace-v2",
  "keys": [
    {"kid": "grace-v1", "key_base64": "<base64 of 32 random bytes>"},
    {"kid": "grace-v2", "key_base64": "<base64 of 32 new random bytes>"}
  ]
}
```

Every token replica needs the same readable key set. Prepublish the new key
to all replicas before activating it, retain old keys while their encrypted
records remain necessary, and retire them only after that retention window.
Existing instances retain their loaded snapshot; replacing the mounted file
does not silently reload them. A missing retired key produces an authentication
error, never a plaintext or generated-key fallback.
Grace keys belong only to the token runtime. Other runtime paths can construct
`PostgresGraceStore::new_delete_only` for revocation cleanup. Keep keys used by
other durable encrypted state separate, and keep all private startup key roots
outside the dynamically resolved upstream client-secret root.
These are implemented adapter capabilities. Production startup, mount
isolation and cluster rotation acceptance remain pending.

The production server does not select PostgreSQL yet. Remaining work includes
startup for every enabled self-hosted port, qualification of the authorized
cross-port transactions in the production runtime, encrypted-state
and mounted-signer startup, portable transports/notifications, workers, chart/image
delivery, and all acceptance campaigns in the ledger above. Keep the PR in
draft and the issue open until these requirements are implemented and verified.
