# Security Events

Issue #24 tracks delivery of
the internal security-event capability. This document is its decision source of
truth. Issue #25 consumes
that immutable ledger for the completed external SET/SSF transmitter; its
projection and delivery contract is defined in
[`SHARED_SIGNALS.md`](SHARED_SIGNALS.md).

## Envelope

Every event is immutable and uses schema version `1.0`:

```json
{
  "schema_version": "1.0",
  "event_id": "evt_...",
  "occurred_at": 1785415471,
  "tenant_id": "t1",
  "actor": { "kind": "admin", "id": "admin@example.com" },
  "subject": { "kind": "user", "id": "user:alice@example.com" },
  "category": "user_lifecycle",
  "action": "user.disable",
  "outcome": "success",
  "correlation": { "operation_id": "disable-generation-2" }
}
```

Actor and subject kinds, category, outcome, and correlation fields are typed. There
is no request-body or free-form metadata field. Identifier values remain opaque, so
callers MUST pass stable identifiers rather than passwords, recovery codes, bearer
tokens, client secrets, raw login-session cookies, WebAuthn assertions, or message
bodies. Sensitive-flow tests assert that live credential values do not enter the
serialized envelope. A session correlation, when needed, must be an irreversible
`session_fingerprint`, never a cookie value.
When an authentication attempt has no trustworthy target identity, the envelope
uses `{ "kind": "unknown", "id": "anonymous" }`; `subject` is never null.

The implemented categories cover:

- password, magic-link, passkey, recovery, federation, Admin OIDC, workload, and
  login-session authentication;
- Admin authorization and step-up outcomes;
- Admin and SCIM user lifecycle changes;
- passkey, password, recovery, client, IAT, and SCIM credential operations;
- Grant create, denied access, and explicit or system-triggered revoke outcomes,
  including policy recompute, user lifecycle, and final token-authority cleanup;
- client/key/secret lifecycle operations and break-glass use, including
  federation IdP and Admin OIDC configuration changes;
- explicit issuer/tenant-boundary denials.

## Durability Contract

Events use one stable ID across every retry and archive attempt. A duplicate ID
does not create a second event. Delivery attempts and transitions are recorded
separately from the immutable envelope.

The normal hot-ledger path retries transient failures and then submits the
complete typed ingress record to a durable fallback. Each hot-ledger or fallback
attempt has a 500 ms application deadline; all six attempts plus backoff consume
at most about 3.2 seconds of the Auth Lambda's 10-second runtime budget. If both
normal paths are unavailable, the Lambda runtime writes the base64url-encoded
typed ingress record to its seven-year retained log before completing the audit
call. This emergency record contains the same credential-free envelope and
accumulated delivery history, so a regional storage outage does not reduce the
event to an ID-only log. After the ledger and queue recover, operators use
`scripts/replay_security_event_emergency.sh` to dry-run a bounded incident
window and explicit tenant scope, then replay matching event IDs through the
normal ingress queue. The tool validates every decoded typed ingress before
deduplication, rejects an event ID that has conflicting retained immutable
envelopes, and selects a delivery snapshot only when its attempt count and
status-history prefix dominate every other retained copy. Log time breaks ties
only between equivalent snapshots; incomparable histories fail closed. An
existing hot row is skipped only when its `source_delivery_attempts` already
covers the retained attempt count and, when equal, its source-history status
sequence covers the retained snapshot. Otherwise the duplicate is sent through
the normal compare-and-swap history merge, including a failed transition
recorded after an ambiguous successful attempt. Rerunning recovery is therefore
idempotent without discarding an ambiguously committed delivery history.
Business batches of at most 16 events submit independent hot-ledger deliveries
concurrently. Larger batches first emit every complete, typed ingress envelope
to the seven-year retained runtime log, then use the durable ingress queue as
their primary path. SQS requests contain at most 10 events, run at most 16 at a
time, retry only transiently failed entries up to three times, and share a
3.5-second total batch deadline. Permanent entry failures go directly to their
retained emergency envelope without suppressing retries for neighboring
transient failures. A Lambda deadline or an unusually large batch therefore
cannot strand already-completed business mutations without a credential-free
recovery envelope. The ingress worker applies the same event-ID deduplication
and archive flow when moving these queued events into the hot ledger.

Hot events remain available for 400 days. Archived events and their delivery
history remain queryable for 2555 days. A failed archive row is retained for
2555 days rather than expiring with the hot ledger and is retried on a bounded
schedule until the deterministic archive write succeeds. The 14-day FIFO queue
is an alarmed incident copy, not the sole durable record. An ingress payload
that cannot enter the hot ledger is retried from the original SQS message using
its durable receive count. On each receive the worker reconstructs proven prior
failures from that count; SQS does not expose their original timestamps, so the
reconstructed transitions use the current observation time. The updated typed
ingress, including the reconstructed history, is written to a retained seven-year
quarantine before the source is acknowledged or placed on its incident queue.
Quarantine object keys and terminal FIFO deduplication use the stable source SQS
message ID, not the event ID. Distinct collision payloads therefore remain
separate evidence even though they claim the same event ID.
For a valid typed event that exhausts hot-ledger ingress, the worker also writes
the terminal `dead_lettered` delivery snapshot to the normal tenant-partitioned
archive prefix so it remains queryable through the same Glue/Athena table. This
terminal write uses `If-None-Match: *`; if a trusted archive already owns the
deterministic key, the worker preserves it and retains the conflicting ingress
only in quarantine and the incident queue.
Permanent store rejections, including reuse of an event ID with a different
envelope, never enter that trusted prefix: the exact ingress is retained only in
the quarantine bucket and incident queue, preventing an untrusted duplicate from
overwriting or duplicating the immutable archive.
Reconstruction retains at most 64 transition entries and rolls older receives
into the exact aggregate attempt count and last-attempt state, so a prolonged
quarantine or incident-queue outage cannot grow the terminal SQS payload without
bound.
The seven-year TTL is applied when the durable `dead_letter_pending` transition
is committed, before the incident message is sent. The five-minute scheduled
sweep first completes pending incident-message outboxes, then redrives durable
`dead_lettered` rows. Recurring redrive attempts increment the aggregate attempt
count and update the last-attempt time instead of growing history without bound;
the successful terminal `archived` transition is appended to history. If an
ambiguous hot-ledger write produces a fallback duplicate after the event was
archived, the worker merges the newer source history, marks
`archive_refresh_pending`, and claims a 60-second DynamoDB refresh lease before
reading the current delivery state and replacing the deterministic S3 object.
Every normal archive write first creates with `If-None-Match: *`. If the key
already exists, the worker reads its ETag, requires the same immutable event and
a prefix-compatible delivery revision, preserves a dominating object, or uses
`If-Match` to replace it with a strictly newer revision. A different immutable
event or divergent history fails closed. The bucket is versioned as additional
recovery protection. The final status update conditionally checks the observed
status, attempt count, exact history, and any refresh lease, and uses the
`archived_at` retained in the winning S3 object. The lease exceeds the worker's
30-second runtime, so an expired worker cannot overlap the next refresh
claimant or commit a stale object revision.
Batch and scheduled workers isolate failures per event. Scheduled recovery
queries and processes pages for pending, redrive, and refresh states concurrently,
skips malformed rows while retaining their attributed errors, and continues each
successful state query before returning the aggregate error. A slow status query,
large earlier class, or poisoned row therefore cannot prevent another class from
making progress during the same invocation.
Retained stream-failure notifications apply the same isolation at both levels:
one unreadable S3 failure object does not block neighboring notification records,
and one failed event reconciliation does not block later events from that object.

The AWS resource topology, IAM boundaries, object layout, retry schedule, and
failure-reconciliation path are deployment concerns documented in
`docs/DEPLOYMENT.md` section 9.

Delivery metadata is separate from the immutable event:

- current status: `pending`, `retrying`, `failed`, `dead_letter_pending`,
  `archive_refresh_pending`, `archived`, or `dead_lettered`;
- attempt count and last-attempt time;
- archive/dead-letter timestamps and archive key;
- transition history, including failed attempts, retries, and the final
  outcome.

## Query API

`GET /admin/security-events` requires tenant Admin read permission. Parameters:

- `from`: inclusive Unix timestamp, default 30 days before now;
- `through`: inclusive Unix timestamp, default now;
- `limit`: `1..=500`, default 100;
- `cursor`: opaque continuation value from `next_cursor`.

The response contains the authenticated tenant only and returns newest events
first before applying the limit. `next_cursor` is returned when another page
exists. Each item has an immutable `event` and mutable `delivery` view. This
endpoint is a paginated hot-ledger export, not the seven-year investigation
surface.
If one hot-ledger row is malformed, the adapter emits `SECURITY_EVENT_INVALID`
for the infrastructure alarm and returns the other validated rows rather than
hiding the entire page.

## Alarms

The stack creates five alarms:

- `AuthenticationFailures`: five denied/failed authentication events in five
  minutes;
- `InfrastructureErrors`: any invalid envelope construction, ledger/fallback
  storage exhaustion, Auth/Archive/Reclaim/Recompute Lambda error (including
  cold-start KMS initialization), terminal archive transition, or KMS signing
  error;
- `CrossTenantDenials`: any explicit tenant-boundary denial;
- `ArchiveBacklog`: DynamoDB stream iterator age or ingress queue age reaches 60
  seconds;
- `ArchiveDeadLetters`: any durable archive transition, archive DLQ message, or
  ingress DLQ message.

Missing data is treated as not breaching. Alarm actions remain deployment-specific.

## Validation

Local contract coverage includes:

- HTTP tests for successful and denied authentication, step-up, lifecycle,
  credential, Admin, Grant, federation/workload, and tenant-boundary events;
- DynamoDB adapter tests for conditional deduplication, TTL, tenant/time query,
  delivery metadata, and row/envelope consistency;
- batch-delivery tests proving the 16-event direct-write boundary and that a
  larger batch uses one-attempt durable ingress with stable unique event IDs;
- an emergency-replay contract test proving bounded tenant scope, complete typed
  envelope validation, retained and hot-ledger collision rejection, dominating
  snapshot selection, divergent-history rejection, duplicate-history
  reconciliation, explicit execution, and batch-recovery marker support;
- a controllable archive sink where the first write times out and the retry uses
  the same event ID and S3 key, plus monotonic object CAS, terminal-ingress
  recovery, exhaustion, and a failure between terminal send/status commit;
- CDK assertions for the source-message ingress retry path, FIFO incident queues,
  retained stream/ingress failure payloads, scheduled dead-letter redrive,
  `TRIM_HORIZON`, retention, Glue projection, resource-scoped Lake Formation IAM
  compatibility, and all five alarms.

Completion requires deployment validation with a configured AWS profile in
`us-east-1` against both `AgentAuthDev` and `AgentAuthSaas`: Auth-to-DynamoDB-to-S3,
SQS fallback ingestion, delivery history, Athena schema, terminal DLQ
payload/status handling, newest-first tenant query, and all five alarm metric
paths. Controlled local archive sinks prove S3 retry exhaustion and transition
recovery; cloud validation proves the deployed normal/fallback wiring and alarms.
`e2e/security_events.sh` also verifies that an unparseable ingress reaches the
ingress DLQ and retained quarantine, all three retained buckets carry the
seven-year lifecycle, the archive bucket retains current and noncurrent
versions for seven years, a late refresh produces multiple versions of the
same deterministic key, and all five alarms enter `ALARM` from real metric data
before returning to `OK`. Cleanup removes every registered fixture version and
delete marker rather than hiding test data behind a marker. Each alarm
transition is recorded independently, so the test does not require unrelated
five-minute metric windows to overlap. The backlog producer temporarily sets
the archive Lambda's reserved concurrency to zero; both the normal path and
cleanup trap retry restoration and verify the effective setting before
reporting success.
The fallback producer test temporarily points only the Auth Lambda's
`SECURITY_EVENTS_TABLE` at a nonexistent table, performs a real audited user
mutation, and proves the resulting typed ingress reaches the normal table through
the Lambda's configured SQS fallback. The cleanup trap restores the complete
original Lambda environment and verifies both table and queue bindings before
continuing. A second producer test makes both bindings unavailable, proves every
event from the request reaches the retained emergency log, restores the runtime,
binds the break-glass marker to the unique user event's Lambda invocation
boundary, and uses exact event IDs with the production replay tool to return both
events to the normal archive with their failed delivery histories intact.
