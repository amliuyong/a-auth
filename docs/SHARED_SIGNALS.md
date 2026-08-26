# Shared Signals Transmitter

Issue #25 adds an OpenID Shared Signals Framework 1.0 push transmitter on top
of the canonical security-event ledger. The ledger remains the only source of
account mutations. External delivery never replays or performs the underlying
account action.

The normative protocol sources are RFC 8417, RFC 8935, OpenID Shared Signals
Framework 1.0 Final, OpenID CAEP 1.0 Final, and OpenID RISC 1.0 Final.

## Protocol Profile

Agent Auth supports the HTTP push delivery method
`urn:ietf:rfc:8935`. A SET is an ES256 compact JWS with this protected header:

```json
{"alg":"ES256","kid":"<published-jwk-thumbprint>","typ":"secevent+jwt"}
```

The claims set contains:

- `iss`: the authoritative tenant issuer reconstructed from deployment
  configuration, never from receiver input;
- `iat`: the time the immutable SET was first constructed;
- `jti`: a stable identifier for one canonical event, stream ID, and immutable
  stream revision;
- `txn`: the canonical security-event ID, shared by SETs derived from the same
  underlying event;
- `aud`: the receiver audience fixed in the stream revision;
- `sub_id`: an RFC 9493 `iss_sub` subject containing the tenant issuer and
  canonical internal user ID, or, for one selected session, a `complex`
  subject containing that user, tenant, and a stable irreversible session
  fingerprint;
- `events`: exactly one supported event URI and its typed payload.

SSF 1.0 forbids `sub` and `exp` in these SETs. Delivery is time bounded by the
outbox retention and maximum retry age. Receivers MUST validate `iat` against
their acceptance window and retain `jti` replay state for at least that window.
The canonical `occurred_at` is carried as the event payload's
`event_timestamp`; it is not substituted for `iat`.

The public tenant metadata endpoint is
`/.well-known/ssf-configuration`. It publishes `spec_version=1_0`, the exact
tenant issuer, the tenant-visible `/jwks.json`, push delivery support, and
`default_subjects=ALL`. SSF stream-management endpoints are optional in SSF
1.0. Agent Auth provisions streams through its existing tenant Admin
`access.manage` boundary instead of adding a second receiver credential
domain.

## Event Projection

Projection is an exact allowlist over schema version, category, action,
successful outcome, and a canonical user subject. Prefix matching is
forbidden.

| Canonical action | External event | Payload |
| --- | --- | --- |
| `user.disable` | `https://schemas.openid.net/secevent/risc/event-type/account-disabled` | `event_timestamp` |
| `session.revoke` | `https://schemas.openid.net/secevent/caep/event-type/session-revoked` | `event_timestamp` |
| `credential.passkey.register` | `https://schemas.openid.net/secevent/caep/event-type/credential-change` | `credential_type=fido2-roaming`, `change_type=create`, `event_timestamp` |
| `credential.passkey.delete` | `https://schemas.openid.net/secevent/caep/event-type/credential-change` | `credential_type=fido2-roaming`, `change_type=delete`, `event_timestamp` |
| `credential.password.set` | `https://schemas.openid.net/secevent/caep/event-type/credential-change` | `credential_type=password`, `change_type=update`, `event_timestamp` |
| `credential.password.reset` | `https://schemas.openid.net/secevent/caep/event-type/credential-change` | `credential_type=password`, `change_type=update`, `event_timestamp` |
| `credential.recovery.rotate` | `https://schemas.openid.net/secevent/caep/event-type/credential-change` | `credential_type=agent-auth-recovery-code`, `change_type=update`, `event_timestamp` |

Denied, failed, no-op, list, rename, `session.revoke_others`, authentication,
client credential, IAT, SCIM bearer, delivery, and infrastructure events do not
produce external SETs. One `session.revoke` SET identifies only the selected
session through a keyed irreversible fingerprint inside a complex subject.
Raw cookie IDs and management handles are never exposed.

## Stream Lifecycle

Each stream belongs to exactly one tenant and has a non-reusable random
`stream_id`, monotonically increasing `revision`, audience, HTTPS push endpoint,
requested event set, transmitter-computed delivered event set, status, and
activation timestamp.

- create starts revision 1 in `enabled`;
- replace uses expected-revision CAS and increments the revision;
- pause prevents new outbox rows and new send leases;
- resume creates a new revision and activation watermark;
- revoke is a permanent tombstone; IDs are never recycled.

Pause increments the stream revision. Any pending or retrying delivery from the
previous enabled revision is therefore suppressed when the worker next
considers it; pause is not a promise to retain an old backlog for later send.
Resume increments the revision again and sets a new activation watermark, so it
starts a fresh delivery epoch and does not backfill events observed while
paused.

Each tenant may register at most 32 streams over the lifetime of its registry.
Revoked tombstones continue to count toward this quota, so repeated create and
revoke operations cannot create an unbounded stream scan. Quota enforcement and
stream creation commit in one transaction.

Admin reads require `tenant.read`. Create, endpoint/audience/event replacement,
pause, resume, verification, redrive, and revoke require `access.manage`, which
also applies the existing strong/recent Admin step-up policy. Every lifecycle
result is recorded as a tenant-scoped canonical security event without endpoint
credentials or SET contents.

The minimal profile does not store an HTTP authorization header. Receiver
authentication is the SET signature, exact issuer, audience, and published
JWKS. This avoids turning a tenant-controlled endpoint plus a privileged
Secrets Manager reference into a secret-exfiltration primitive.

## Durable Delivery

The durable tenant-partitioned outbox is also the delivery audit ledger. It is
the source of truth; a queue is not used as an authority.

1. The canonical event change feed accepts only new event inserts.
2. Exact projection selects eligible events.
3. Enabled streams are queried only within the event tenant. Events older than
   a stream's activation watermark are not backfilled.
4. A conditional write creates one delivery row keyed by tenant, stream ID,
   immutable stream revision, and canonical event ID.
5. A delivery worker queries due rows, conditionally acquires a bounded lease,
   rechecks the exact current stream revision and status, and constructs and
   persists the compact SET once.
6. Every retry reuses the persisted compact JWS, `jti`, `iat`, `kid`, audience,
   and payload.
7. The HTTPS adapter revalidates the endpoint, resolves every address, rejects
   any non-public address, pins the connection to a checked address, disables
   proxies and redirects, applies a three-second connect and ten-second total
   timeout, and limits responses to 100/16 KiB of headers and 64 KiB of body.
8. Only HTTP `202 Accepted` is success. Network ambiguity, timeout, 408, 429,
   and 5xx retry with bounded backoff. Other 4xx become terminal until an
   operator explicitly redrives after repairing the stream.
9. HTTP attempts retain timestamp, outcome, bounded HTTP status/error class,
   base64url `sha256:` SET digest, and signing `kid`. A signing failure recorded
   before a SET exists has no digest or `kid`. Exhaustion becomes a retained
   dead-letter state.
10. A source projection invocation that exhausts DynamoDB Stream retries is
    retained in S3 and replayed through a bounded SQS queue. Idempotent delivery
    keys make replay safe; a persistently invalid invocation enters an alarmed
    14-day DLQ instead of disappearing from the change feed.

Operator redrive reuses the immutable compact SET and is therefore allowed only
within 24 hours of its original `iat` (or delivery creation when signing never
completed). The redrive and every subsequent retry remain inside that same
absolute window. The 400-day row retention is an audit policy, not permission
to send a stale SET.

Receiver revocation linearizes at delivery-lease acquisition: it prevents any
attempt whose lease would be acquired after the revocation commit. One request
whose lease was acquired before revocation may complete, and the ledger makes
that ordering explicit.

## Verification

The Admin verification command enters the same outbox and worker as ordinary
events and sends
`https://schemas.openid.net/secevent/ssf/event-type/verification`. It never
bypasses signing, revision checks, retries, or audit history.

Interoperability tests use a controllable HTTP receiver that independently
validates the compact JWS against published JWKS, exact `typ`, issuer, audience,
stable `jti`, transaction ID, subject, event URI, and timestamps. The receiver
can accept then time out, reject, rate limit, or fail, and deduplicates accepted
SETs by `jti`. Tests also cover forged signatures, sending a valid tenant SET to
another tenant's target, exact replay, two-tenant isolation, stream revision
races, revocation, duplicate source records, retry exhaustion, and redrive.

AWS resources, alarms, key-rotation phase configuration, and the live
interoperability command are defined in
[`DEPLOYMENT.md`](DEPLOYMENT.md#10--shared-signals-transmitter).
