# Data Governance

This document is the decision source of truth for data-governance behavior and
conformance row
`C12.7`. It defines the executable boundary for privacy export, user erasure,
tenant offboarding, retention exceptions, and data residency. Legal
applicability and the lawful basis for a particular tenant remain decisions for
the operator and counsel; the product must represent those decisions without
claiming that retained data was deleted.

## Invariants

1. Every operation is derived from the authenticated tenant. A tenant or user
   identifier in a path never selects a different storage partition.
2. Exports contain no password hash, recovery-code verifier, passkey public-key
   material, bearer verifier, client secret, registration token, session
   cookie, authorization code, refresh token, SET, private key, or secret
   reference.
3. User erasure removes live aliases, credentials, sessions, Grants,
   attributes, and Group memberships before the canonical identity row is
   removed. A keyed, non-plaintext pseudonymous suppression record remains
   outside recoverable business authority so an old backup cannot resurrect the
   identity or its aliases. It is still treated as protected data, not labelled
   non-PII.
4. A legal hold blocks each product-controlled destructive mutation, not only
   job start. Removing a hold resumes the same durable job; it does not create
   an untracked second operation. A hold does not silently override protocol
   TTL, S3 lifecycle, Backup expiry, or an already committed KMS deletion.
5. Immutable security events and shared recovery points are retention
   exceptions. Their presence produces `retention_pending`, never a false
   `completed` result.
6. A tenant request is executable only in its configured residency set and
   current active-writer Region. Residency jurisdiction, replica Regions,
   active-writer Region, and replay-artifact owner Region are separate facts.
7. Offboarding freezes new tenant mutations before deletion starts and is
   monotonic. The freeze is enforced by every authority writer, including
   background jobs; a retry or process restart resumes from durable state.
8. Every destructive operation is fenced by the current job lease, policy
   revision, tenant lifecycle revision, and user epoch where applicable.
   DynamoDB evaluates the fence in the data-write transaction. An external
   action requires a one-shot dispatch permit issued under the same fence.
9. Completion evidence is derived from fresh reads in every configured replica
   after cleanup and restore reconciliation. Attempt counters, GSI-only reads,
   and intended deletes are not evidence.

## Data Inventory And Retention

The durations below are product defaults, not claims about which law applies.
An operator may retain less where the underlying service supports it. A legal
hold may retain more, but must remain visible in governance state and evidence.

| Data class | Examples | Normal lifetime | Export | Erasure or offboarding |
|---|---|---:|---|---|
| Canonical identity and aliases | User row, email, SCIM `externalId`/`userName`, display name, RS attributes | Account lifetime | User and tenant | Physically delete the row and plaintext alias claims after dependent cleanup; retain only domain-separated canonical/alias suppression records |
| Authentication credentials | Password hash, passkey credential, recovery-code verifiers | Credential lifetime | Status and non-secret metadata only | Physically delete |
| Login and Admin sessions | Login session, Admin OIDC flow/session | Protocol expiry | Normalized device/time metadata only | Physically delete or invalidate before identity deletion |
| OAuth one-time state | Code, PAR, device/CIBA request, magic link, invitation verifier, plaintext magic-link cooldown alias, challenge, JTI, grace response | Protocol expiry/TTL, except legacy cooldown rows that have no TTL | Not exported | Physically delete every subject/alias-addressable row, including invitation verifiers, JTI mappings, and cooldown aliases; tenant offboarding purges the tenant partition |
| Refresh families | Family verifier state and replay boundary | Family lifetime | Status metadata only | Physically delete after revocation; never restore from backup |
| Grants | Consent, resource constraints, status | Grant lifetime | Full non-secret authorization record | Physically delete for user erasure and tenant offboarding |
| Directory Groups and roles | SCIM Group, membership index, fixed role mapping | Directory lifetime | Tenant export | Remove erased memberships; tenant offboarding deletes canonical, alias, membership, and mapping rows |
| OAuth clients and IATs | Client metadata, credential lifecycle, initial access ticket ledger | Client/tenant lifetime | Metadata and credential status only | Revoke and physically delete; never export verifier material |
| Tenant configuration | Federation, federation attribute mapping registries/target-owner indexes/permanent mapping-ID markers, workload trust, Admin OIDC, policy, domain bindings, SelfHosted RS attribute namespace registrations and exact-audience bindings | Tenant lifetime; removed-audience `Retired` bindings and federation mapping-ID markers persist while the tenant exists | Redacted tenant export; mapping registry export includes configuration/revisions but no ID-token claims or user attribute values; RS namespace registration export is required before any future SaaS enablement | Delete configuration and derived indexes, including all mapping registry/target-owner/marker rows; secret values use the separate metadata-only workflow below. `AttributeNamespacesTable` and `FederationAttributeMappingsTable` are currently SelfHosted-only and are included in PITR, AWS Backup, and standby replication. The namespace table MUST join tenant-offboarding cleanup/export before future SaaS enablement; the mapping table is already in tenant export, inventory, and fenced deletion |
| Tenant Secret dependencies | Tenant Admin credential sets, SCIM source/target credentials, federation client secrets, Admin OIDC client secret | Tenant lifetime plus configured Secrets Manager recovery window | Status and version metadata only; never value or secret reference | Revoke use and remove the authority reference. Delete only a Secret whose persisted ownership is `product_managed`; an `external` Secret remains operator-owned pending work and is never deleted by name inference |
| Tenant signing keys | EC/RSA registry and KMS keys | Tenant lifetime plus KMS deletion window | Key IDs/status only | Disable signing, remove registry authority, and schedule KMS deletion; evidence records the pending-deletion date |
| Governance suppression keys | Versioned HMAC key set used only by suppression writer/reconciler | At least as long as every referencing suppression row; a key referenced by a permanent row is permanent | Key IDs/status only | Retain while referenced; deny signing use outside suppression and reconciliation |
| Security-event hot ledger | Typed immutable event and delivery history | 400 days | Tenant-scoped; user export filters by canonical subject | Retain as justified audit evidence; no in-place mutation |
| Security-event archive and quarantine | Versioned S3 objects, Athena projection | 2,555 days | Investigation process, not bulk DSAR payload | Retain under the audit policy; lifecycle expiration is the deletion mechanism |
| Security-event emergency logs and incident queues | Credential-free emergency envelopes, DLQ and replay inputs | CloudWatch 2,555 days; SQS up to 14 days | Investigation process | Retain to configured lifecycle; evidence names each actual lifecycle source |
| SSF state | Stream revisions, permanent revoke tombstones, delivery attempts and outbox | Revoke tombstone permanent; delivery audit 400 days | Redacted tenant export | Suppress active streams and expire deletable deliveries; never delete or roll back receiver-revocation tombstones |
| Shared DynamoDB PITR/AWS Backup | Recoverable authority tables | 35 days; daily recovery point | Not exported | A user/tenant cannot be removed from an existing shared recovery point. Evidence records a conservative purge-not-before time of primary erasure plus 36 days |
| Governance suppression ledger | Tenant/user lifecycle epochs and versioned, domain-separated keyed target/alias digests | At least the maximum recovery window plus cutover margin; tenant offboarding suppression is permanent | Status only; digests never leave the reconciliation boundary | Never restored from an older recovery point; reconcile every restored authority table against it before cutover |
| Runtime and incident logs | Credential-free typed events and operational diagnostics | Explicit deployed log-group policy | Not part of product export | Lifecycle expiration; logs must not contain secret values |

Security events generated by the privacy operation itself start a new audit
retention period. Therefore a successful primary erasure normally ends in
`retention_pending` until those records expire. This is a terminal operational
result for the destructive workflow, but it is not equivalent to physical
absence from every retained copy.

Permanent tenant suppression records, SSF receiver-revocation tombstones, and
final governance evidence are non-rollback control records rather than retained
business authority. They remain explicitly enumerated in evidence and do not
make `completed` impossible after every live or recoverable business copy and
time-bounded retention exception has ended.

Every tenant Secret reference stores versioned ownership metadata beside the
configuration: `product_managed` or `external`, resource account/Region, and a
stable resource fingerprint. Agent Auth writes `product_managed` when it creates
the Secret. This release has no runtime adoption write path; ownership is
deployment-managed. A future owner-initiated move from `external` to
`product_managed` must use a step-up, audited CAS adoption that verifies the
matching resource and creates a new ownership revision; ownership cannot move
back implicitly. Existing references with no ownership metadata are `external`.
Offboarding never infers ownership from an ARN or name prefix. It may schedule
deletion only after the stored fingerprint still matches current metadata;
otherwise it removes the application reference and records operator-owned
pending work only until a read-only provider inspection confirms whether the
Secret remains present or is already absent. It then records that ownership
outcome as verified without reading or deleting the Secret value.

## Region Pinning And Failover

### Deployment contract

Every SaaS tenant configured by `AgentAuthStack` has an immutable residency
jurisdiction and an explicit non-empty set of allowed storage Regions. The
tenant set in this map exactly equals the issuer tenant set. For the Issue #29
active/passive profile the allowed set is `us-east-1` plus `us-west-2`; a
single-Region profile has one member. Synthesis rejects malformed, duplicate,
unsupported, or incomplete assignments.

The runtime receives the canonical residency map, the actual AWS Region, and
the replicated Region-control revision. Startup or request admission fails
closed when the local Region is not allowed, while normal mutation additionally
requires that Region to be the single active writer. Replay-sensitive state
retains the Region and activation-revision ownership defined by
`MULTI_REGION_FAILOVER.md`; governance does not reinterpret it as replicated
authority.

A failover changes active writer and replay owner. It does not change the
tenant's residency jurisdiction or allowed storage set. Adding or removing a
replica Region is a reviewed data-residency migration, not an incidental
traffic operation.

### Runtime contract

Tenant resolution occurs before governance authorization. The shared
`TenantMutationGate` requires the resolved tenant, local allowed Region, exact
Region-control revision, active-writer status, and active tenant lifecycle
revision before any authority write. Each ordinary HTTP mutation first acquires
a 120-second renewable permit in `GovernanceTable`; registration and the
aggregate active count change in one DynamoDB transaction. Completion releases
both atomically. Offboarding reaps only expired permits and freezes the same gate
with the lifecycle/job transaction only when the active count is zero, so a
machine restart delays freezing by at most one permit lease rather than leaving
an unbounded lock. Export reads may run only in the active writer so one manifest
cannot mix replica lag. The Issue #29 profile deploys
destructive governance workers only in the designated primary governance
Region, and they run only while that Region is also the active writer. During
reduced standby service, erasure/offboarding start and resume return `503`,
durable jobs remain paused, and no standby worker consumes destructive outbox
commands. Failback resumes the same fenced job after Region-control and
suppression state converge.

The governance policy/job table and suppression ledger are Global Tables in
the multi-Region profile. The archive and Backup plan remain primary-Region
resources; the standby does not create a second archive, backup, governance, or
offboarding worker. Live validation checks every table, bucket, backup, KMS key,
secret, and log ARN Region against the allowed set and verifies all replicas
converge before zero-count evidence.

## Export Contract

Governance adds purpose-specific Admin actions. `data.export.user` is available
to owner/admin sessions after recent strong authentication.
`data.export.tenant`, `data.erase`, `legal_hold.manage`, and
`tenant.offboard` are owner-only and require recent strong authentication.
Auditors retain security-event export but do not receive identity bulk export.
Break-glass use requires an explicit purpose header and confirmation and emits
the existing high-priority event plus a governance authorization event.
Responses carry:

- schema version;
- logical tenant;
- residency jurisdiction, active-writer Region, and Region-control revision;
- manifest creation and page generation times;
- explicit section name;
- records and an opaque section-specific continuation cursor.

`GET /admin/data-governance/users/{user_id}/export` returns one canonical
identity, aliases, attributes, passkey summaries, normalized login-session
metadata, Grant records, credential status, Group memberships, and a paginated
hot-ledger event projection. It never resolves the target by an untrusted email.

`POST /admin/data-governance/exports` creates a short-lived export manifest
bound to tenant, actor, purpose, policy revision, section set, and active Region
revision. `GET /admin/data-governance/exports/{id}?section=...` supports
independently paginated `users`, `clients`, `groups`, `role_mappings`, and
`security_events`; configuration sections use redacted views. Cursors are
authenticated, expire with the manifest, use immutable keyset ordering, and
are valid only for that tenant, export, section, and active Region revision.
The export is an explicitly labelled live keyset view, not a cross-table
snapshot; each record includes its source revision or update time.

A missing target is `404`. A target that exists in another tenant is
indistinguishable from a missing target. Malformed cursors are `400`; storage
failure is `503`, never an empty successful export.

## Legal Hold

`GET /admin/data-governance/policy` requires `legal_hold.manage` or
`data.export.tenant`. `PUT /admin/data-governance/policy` requires owner-only
`legal_hold.manage`, step-up, and an exact expected revision. The mutable field
is `legal_hold`; residency jurisdiction and allowed storage Regions are
deployment-owned, while active writer and activation revision belong to Region
control. None can be changed by this API.

The record stores:

- legal-hold state (`disabled`, `enabling`, or `enabled`);
- a non-empty, bounded reason when the hold is enabled;
- the external retention-exception capability boundary;
- actor and update time;
- monotonic revision.

The reason must not contain case details or personal data. Every change and
every blocked destructive attempt emits a typed security event. A hold is a
fence for product-controlled erasure/offboarding. It does not preserve expired
protocol artifacts or retroactively cancel an external action already committed
to S3, Backup, or KMS. The durable policy records the
`external_operator_managed` retention-exception capability boundary: this
release does not create or extend Object-Lock archives or hold-tagged recovery
points and never reports those external resources as held. Operators must
create and verify any such exception outside the service. Enabling a hold after
primary deletion does not restore data and cannot claim preservation that was
not completed.

The `disabled -> enabling` CAS conflicts with and prevents any new external
dispatch claim. The API reports `enabled` only after every claim issued before
that CAS reaches a verified terminal external outcome. Time expiry alone is
never proof of no side effect. Thus a successful hold response has a clear
quiescence point; an action claimed before `enabling` is visible as in-flight
rather than being falsely reported as blocked.

## Durable Jobs

The governance subsystem has two authorities:

- `GovernanceTable`, a Global Table containing tenant policy, tenant lifecycle,
  jobs, leases, outbox commands, export manifests, and immutable evidence;
- `GovernanceSuppressionTable`, a retained Global Table containing
  non-rollback tenant/user lifecycle epochs and domain-separated canonical/alias
  digests. It is excluded from ordinary authority restore and reconciles any
  pre-erasure backup before cutover.

Both tables remain current during recovery. They are excluded from
`RecoveryAuthorityTableNames` and the ordinary AWS Backup selection even
though PITR remains enabled for investigation. The read-only
`e2e/governance_restore_cutover_verify.sh` gate strongly reads every configured
control replica and every isolated restored business table, recomputes
suppression digests with the current versioned HMAC key, and refuses cutover
for any offboarded tenant, erased user/alias, dangling user reference, unknown
key version, or replica drift. It has no cleanup operation. Reconciliation
requires an isolated runtime that keeps these two current authorities while
pointing business adapters at the candidate tables; the existing leased and
fenced governance worker then resumes the durable job.

Job identifiers are opaque and deterministic per tenant, operation kind, and
target epoch. Repeating a start request returns the existing job.

Common states are:

| State | Meaning |
|---|---|
| `queued` | Durable intent exists; no destructive mutation has started |
| `blocked_legal_hold` | A hold was observed before the next destructive phase |
| `running` | One worker owns a bounded lease and is advancing a phase |
| `retryable` | The last attempt failed without proving the phase committed |
| `retention_pending` | Primary and derived live state are absent; justified retained copies remain |
| `completed` | No live or recoverable business authority or time-bounded retained copy remains; enumerated permanent non-authority control records may remain |

Every transition uses revision compare-and-swap and a bounded lease. Each
destructive adapter operation receives
`GovernanceFence { job_id, lease_token, job_revision, policy_revision,
tenant_revision, target_epoch }`. DynamoDB mutations transactionally
condition-check the governance policy/job and tenant/user suppression rows. A
worker that loses its lease therefore cannot issue another DynamoDB delete or
external dispatch permit. Ambiguous writes are reconciled by strongly rereading
primary authority before retrying.

KMS, S3, Backup, SQS, and Secrets Manager operations use durable outbox commands
whose state distinguishes prepared, claimed, externally committed, and
verified. A dispatcher must atomically move one command from `prepared` to
`claimed`; that DynamoDB transaction revalidates the exact job lease, no-hold
policy revision, tenant lifecycle, target epoch, command revision, and
idempotency key and writes a unique claim token and deadline. Only that claimant
may invoke the one named action on the one named resource, using the external
service's idempotency token or a resource-identity precondition.

The dispatcher strongly rereads the still-claimed token immediately before the
SDK call and must not call after its deadline or after the claim changes state.
The executor has a hard, externally enforced invocation bound no later than the
claim deadline; a local timer or lease expiry is not that bound. Claim expiry
does not return a command to `prepared`: only after that hard bound has passed
may a reconciler prove the external outcome and record `verified`, or prove no
side effect through the service idempotency/resource identity and permanently
tombstone the old claim token. An ambiguous outcome keeps the same claim and
idempotency identity until reconciled; it never authorizes a second logical
action. The hold-enabling transition drains all claims created before it and
never treats time or a local tombstone alone as quiescence. A delayed or
duplicate dispatcher therefore cannot outlive the externally enforced bound or
obtain a second valid claim.

Jobs retain only the target identifier needed for unfinished work. Before
identity deletion the worker writes the suppression epoch and digests. After
replica convergence, the raw target is removed from the job; suppression rows
retain only domain-separated canonical/alias digests and contain no plaintext
alias.

Suppression digests are HMAC-SHA-256, never unkeyed hashes. The input binds the
tenant, target class, alias kind, normalization version, and normalized value.
Tenant, key version, normalization version, and digest form the lookup
partition; the target epoch is an append-only sort key. Alias admission
currently uses exactly key version 1 and normalization version 1 and can query
every suppressed epoch without a table scan or advance knowledge of that epoch.
Those v1 inputs are permanent and MUST NOT be rotated or redefined. A future
rotation may ship only after runtime admission supports a key ring and evaluates
every still-referenced key and normalization version. Permanent tenant
suppressions therefore make the v1 verifier key and normalization rule
permanent.

Suppression writes are append-only conditional puts with monotonically
increasing epochs. Ordinary runtime and restore roles have no mutation access.
The dedicated suppression writer has no `UpdateItem`, `DeleteItem`, or
`BatchWriteItem` permission and exposes only the fenced conditional-put
operation; deletion protection, `Retain`, PITR, CloudTrail, Streams alarms, and
replica convergence checks detect infrastructure or replication drift. No
application path emits a Global Table delete for a suppression row.

### User erasure

`POST /admin/data-governance/users/{user_id}/erasure` requires owner-only
`data.erase` plus recent strong authentication. Starting or resuming performs
these monotonic phases:

1. strongly read the canonical user and create a new user suppression epoch;
2. transactionally publish the user mutation fence, tombstone the user, and
   advance the credential epoch;
3. condition every new authorization-code write on the canonical user still
   being active at the captured credential epoch, then physically delete or
   irrevocably invalidate every subject-linked
   authorization code, login/authorization/Admin session or flow, approved
   device/CIBA request, magic link, JTI mapping, passkey challenge,
   notification/grace entry, refresh family, Grant, passkey, recovery material,
   and password credential, plus every deterministic plaintext magic-link
   cooldown key for the user's aliases;
   authorization sessions bind the authenticated user before code issuance;
   the conditional code write and the erasure tombstone transaction serialize,
   so either issuance wins first and cleanup observes the code, or erasure wins
   and issuance fails closed. Cleanup and base-table evidence therefore never
   depend on the code still existing;
4. remove every SCIM Group membership and role-derived membership index;
5. append and verify canonical/alias suppression digests, then physically delete
   the identity row and plaintext email/SCIM alias claims under the user fence;
6. wait for Global Table convergence and verify fresh base-table zero/absent
   reads in every configured replica;
7. record audit and backup retention deadlines and enter
   `retention_pending`;
8. at the latest deadline, a retained scheduler strongly rechecks every replica,
   audit/backup lifecycle, external deletion, and suppression state, writes a
   new immutable completion-evidence revision, and moves to `completed` only
   when no time-bounded retained business copy remains.

The existing Admin `DELETE /admin/users/{id}` remains a security tombstone API;
it is not advertised as privacy erasure.

### Tenant offboarding

`POST /admin/data-governance/tenant/offboarding` requires owner-only
`tenant.offboard` and recent strong authentication. Its phases are:

1. atomically move the tenant from `active` to `offboarding`, replicate the
   tenant mutation fence, and issue a job-bound platform continuation
   capability; normal tenant mutations fail closed;
2. erase users using immutable-key keyset pages, persisting the exclusive start
   key and repeatedly consuming the first page where deletion could invalidate
   a cursor;
3. revoke/delete clients and IATs, Groups/mappings, federation connections and
   federation attribute mapping registry/target-owner/permanent-marker rows,
   workload configuration, Admin configuration/sessions, policies, domains, SSF
   streams/deliveries, every ownership-proven `product_managed` tenant Secret,
   and other tenant-owned primary/derived rows; permanent SSF revoke tombstones
   remain retained. An `external` Secret is never deleted by the product; the
   worker uses read-only provider inspection to record whether it remains
   present or is already absent before marking that ownership outcome verified;
4. after tenant Admin authority is removed, expose resume/status/evidence only
   through the platform control plane using the job-bound capability or
   break-glass recovery;
5. disable tenant signing and durably schedule/verify KMS key deletion;
6. query every inventory class and replica and require zero live rows or an
   explicit retained class;
7. write immutable final-state evidence and enter `retention_pending`;
8. move to `completed` only after retained audit, key/Secret deletion, and
   backup deadlines have actually passed and a fresh verification still
   succeeds.

The offboarding state never returns to `active`. Cancelling after the freeze is
not supported because partially deleted authorization state cannot be safely
reconstructed.

The job-bound continuation capability is a durable platform-control
authorization record, not a tenant bearer copied into the job. It binds one
tenant, job, capability revision, and only `status`, `resume`, and `evidence`;
it cannot start another job, change legal hold, or restore tenant authority.
After independent platform-operator authentication, the platform issuer creates
a signed token with exact governance-control audience, job/tenant IDs, allowed
action, capability revision, unique `jti`, and at most 15 minutes of lifetime.
Mutation `jti` digests are consumed once. The durable record supports explicit
revocation and revision rotation, and signing-key overlap never extends token
expiry. Entering `retention_pending` revokes destructive resume tokens until
the retained scheduler has work, but preserves issuance of read-only
status/evidence tokens. `completed` permanently revokes mutation authority;
platform-authenticated operators may continue to receive read-only tokens for
immutable evidence under its separate read revision. No plaintext token or
verifier is stored. This control plane remains usable after every tenant owner
session and credential has been removed.

The control-host API is:

- `POST /admin/control/data-governance/tenants/{tenant_id}/jobs/{job_id}/continuation-tokens`
  authenticates the independent platform credential, requires the explicit
  governance purpose and confirmation headers, and issues exactly one
  `status`, `resume`, or `evidence` token;
- `PUT /admin/control/data-governance/tenants/{tenant_id}/jobs/{job_id}/continuation`
  uses revision CAS to rotate or disable the read and resume authorities;
- `GET /admin/control/data-governance/tenants/{tenant_id}/jobs/{job_id}`,
  `POST .../resume`, and `GET .../evidence` accept only the corresponding
  job-bound continuation token, never the deleted tenant credential.

Tokens use the dedicated governance key with a domain-separated HMAC-SHA-256
signature. They bind the fixed governance-control issuer and audience, tenant,
job, action, action revision, random `jti`, issue time, and expiry. Their
maximum lifetime is 15 minutes. A resume `jti` digest is conditionally inserted
under the current durable resume revision before enqueueing and therefore
cannot be replayed; status and evidence tokens are read-only and reusable until
expiry or read-revision rotation. Responses containing a new token are
`Cache-Control: no-store`.

## Evidence

Before tenant Admin authority is removed,
`GET /admin/data-governance/jobs/{job_id}` returns job state and redacted phase
history under the purpose-specific tenant permission. Afterwards, job status
and evidence are available only through the platform control plane or audited
break-glass recovery. Evidence is available only after primary verification.
Until a job completes, job-related audit carries the opaque job ID as its
correlation operation ID. A control operation that changes governance or
continuation state first prepares the immutable event, then CAS-extends the job
retention anchor to its exact `occurred_at`, including during replica
verification, and only then persists it. The caller rereads that post-audit
revision before enqueueing an exact-revision worker command. Legal-hold changes
extend every affected post-primary job.

Read-only status observations remain security events under the normal audit
lifecycle but never mutate the observed job or its revision. Otherwise an
untrusted polling cadence could continually invalidate exact-revision worker
commands and prevent a destructive job from converging. Hot-ledger and S3
verification match retained control events covered by the anchor using the job
correlation ID, and match user-subject events directly. Status and evidence
accesses after final completion likewise remain ordinary security events; they
do not reopen the already completed erasure window.

Evidence contains:

- evidence schema `1.1`. Readers preserve canonical `1.0` action entries that
  predate typed lifecycle outcomes, but only `1.1` evidence proves completion;
- tenant, residency jurisdiction, active-writer Region,
  Region-control revision, operation kind, job ID, and deployment commit;
- start, primary-erasure, verification, and evidence timestamps;
- per-data-class and per-replica live counts from fresh base-table reads;
- alias-tombstone count without aliases or digests;
- security-event hot/archive/quarantine/emergency-log, queue, SSF, backup, and
  KMS/Secrets Manager retention states with the AWS lifecycle source used for
  each deadline. Every resource labels its evidence basis: runtime provider
  observations are distinct from declared CDK policy windows. Elapsed declared
  windows are never reported as provider-verified deletion; qualifying live
  evidence must query the AWS control plane. SQS completion requires active
  queues, non-tenant-key DLQs, and every in-flight or delayed message count to
  be zero in two consecutive samples at least ten seconds apart. A visible
  tenant-key DLQ message is allowed only when direct non-deleting inspection
  proves its exact command schema, source queue, non-offboarded tenant, and
  sent/request timestamps before the drill run. Inspection restores temporary
  visibility changes, and both samples must contain the same canonical message
  IDs, body hashes, and bounded timestamps;
- one opaque action ID, ownership class, and bounded lifecycle outcome for each
  external key or Secret action, without its resource reference or provider
  message. Product-managed Secret summaries aggregate only product-managed
  actions and retain the latest deletion deadline; externally owned outcomes
  are reported separately. Secrets Manager `DescribeSecret.DeletedDate` is the
  deletion-request timestamp, so runtime inspection adds the configured
  seven-day recovery window. A qualifying live drill independently binds that
  timestamp to the exact successful CloudTrail `DeleteSecret` event and uses
  its request window and response deletion deadline as provider proof;
- legal-hold state;
- SHA-256 of the canonical evidence payload.

Evidence contains no user identifier after erasure, no alias digest, no secret,
and no AWS account number. The hash excludes its own field and is stable for
the immutable evidence revision.

## Failure And Retry Semantics

- Cross-tenant paths return `404` or `401` according to the existing Admin
  boundary and emit a tenant-boundary event.
- A legal hold returns `409` with the durable blocked job.
- A revision or lease conflict returns the current job; it never starts
  parallel destructive work.
- A transient store failure returns `503` and leaves the job retryable at the
  last unproven phase.
- A permanent inventory mismatch leaves the tenant frozen and marks the job
  retryable with a non-sensitive error class. Operators fix the cause and
  resume; they do not edit the job row.
- Missing retained-resource metadata is a failure, not proof that retention
  ended.

## Implementation Boundary

HTTP handlers only authenticate the purpose-specific Admin action, validate
input, and call `GovernanceEngine`. The engine owns the state machine,
idempotency, lease renewal, retention calculations, evidence, and outbox.

`GovernanceBackend` is a purpose-built port, not a generic "purge tenant"
helper. It exposes:

- stable keyset export/inventory pages and strong base-table verification;
- user physical operations for subject-linked codes, login/authorization/Admin
  sessions and flows, device/CIBA requests, magic links and plaintext cooldown
  aliases, JTI mappings, challenges, notifications/grace entries, refresh
  families, Grants, credentials, Group membership, and identity/alias
  suppression;
- tenant physical operations for clients/IATs, Groups/mappings,
  federation/workload/Admin/policy/domain configuration, replay-state tables,
  product-managed Secrets, SSF suppression, and key registry shutdown;
- subject-indexed security-event export;
- per-replica probes plus Backup, S3, CloudWatch Logs, SQS, Secrets Manager,
  and KMS control-plane operations.

Every normal authority mutation path also uses the shared
`TenantMutationGate`; governance guarantees cannot be implemented solely inside
governance handlers. A request whose permit cannot be renewed is cancelled
before it can continue writing, while the old permit remains until its deadline
to cover already-issued storage calls. For DynamoDB, destructive governance
writes include the governance fence as a transaction condition. External
actions use the durable outbox contract above. HTTP `GET`/`HEAD` routes with
authority side effects, including session activity, challenge creation, flow
consumption, and legacy credential migration, are explicitly classified as
mutations; an unclassified matched read route fails closed behind the gate.

Every record class that can carry a canonical user ID must expose either a
deterministic primary key from the user's retained alias set or a tenant/user
inventory index plus a physical-delete operation. Issue #30 adds those access
paths where current ports have only point `get`/`put`, including JTI mappings
and a stable user owner on authorization sessions.
An index locates candidate primary keys only; deletion and zero-count evidence
strongly reread the base table. Protocol TTL is defense in depth and never
counts as erasure completion. Magic-link cooldown keys are deterministically
derived and deleted before plaintext aliases leave the job.

## Validation

Local validation must cover:

- user and tenant exports with two tenants containing colliding aliases;
- purpose-specific RBAC/step-up and break-glass confirmation;
- response and serialized-log scans proving secret values are absent;
- user erasure of aliases, credentials, sessions, refresh families, Grants,
  JTI mappings, invitation locators/verifiers, plaintext magic-link cooldown
  rows, other one-time subject-linked protocol state, attributes, and Group
  memberships;
- alias recreation rejection and idempotent job retry;
- failure injection and restart between every destructive phase;
- legal hold before start, hold removal and resume, and hold after primary
  deletion, including permit issuance versus hold-enable races;
- owner/admin/auditor authorization and cross-tenant rejection;
- invalid residency/replica maps, inactive-writer rejection, failover without
  residency drift, and all-replica erasure verification;
- restore of a pre-erasure backup followed by suppression-ledger reconciliation
  proving erased identity/tenant authority cannot revive, including canonical,
  email, SCIM alias, credential, Grant, and Group-member references;
- offboarding freeze, page resume, final zero-count evidence, and honest
  `retention_pending` output, platform-capability revocation/replay, and
  product-managed versus externally managed Secret ownership outcomes;
- mutation/offboarding races proving active permits delay the freeze, released
  permits allow the atomic freeze, expired permits recover after process loss,
  and no new permit is admitted after the freeze, including through
  authority-writing `GET` or `HEAD` requests;
- CDK assertions for the governance table, PITR/backup selection, Region
  configuration, IAM scope, retention, and alarms.

The live `configured-account/us-east-1` drill must run against `AgentAuthSaas` from the exact
deployed commit. If both stacks advance during a restart-safe run, an operator
must explicitly adopt the new deployment with a recorded reason. Adoption
requires unchanged StackIds, matching primary/recovery/standby commits,
forward Git ancestry, and byte-stable non-commit outputs; it preserves the
initial context and atomically appends the before/after output hashes and full
current output snapshots. Immutable service-evidence commits must fall between
the initial and active adopted commits. The drill also binds the
`AgentAuthSaasStandby` StackId, complete output hash, deployment commit,
imported authority map, and all 20 current
`RegionLocalTableNames` in `us-west-2`. It creates isolated t1/t2 fixtures
through product APIs, exports both, injects one retryable interruption,
exercises a legal hold, erases the user, offboards the disposable tenant, and
verifies DynamoDB, S3, AWS Backup, KMS, Secrets Manager, logs, queues, SSF, and
evidence Region/count/deadline claims. DynamoDB verification directly scans
every configured replica for erased-user and offboarded-tenant references, and
includes a paginated, strongly consistent deployment-total zero scan of every
standby Region-local table; tenant-filtered or replicated-authority zero counts
alone are insufficient. It also issues one invitation per fixture while
persisting only each locator, then performs direct strongly consistent reads
proving both rows absent after erasure/offboarding. Secrets Manager verification
consumes the exact bootstrap dependency inventory: every offboarded
`product_managed` Secret must be in its deletion window, while every `external`
Secret must still exist without a scheduled deletion. For each product-managed
Secret, the script requires one successful CloudTrail `DeleteSecret` event for
the exact ARN, a seven-day request window, and the corresponding response
deadline; the operator therefore needs `cloudtrail:LookupEvents`. The script
must be restart-safe and clean every disposable fixture it owns.

Qualifying claims require a live drill that verifies scoped export, legal-hold
release, retry/resume, user erasure, Region and replica constraints, final
tenant offboarding, and the governance-aware restore-cutover gate. Unit tests,
CDK synthesis, or a `retention_pending` document without cloud-resource
verification are insufficient.
