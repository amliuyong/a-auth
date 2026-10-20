# Provider credentials and broker assessment

Decision for [Issue #86](https://github.com/amliuyong/a-auth/issues/86),
2026-10-20: **defer a production credential Vault or broker until a named
consumer confirms the operation and custody requirements**. For evaluation,
select Google Calendar `events.list` on the consenting user's primary calendar.
The operation is real; its business demand and provider runtime acceptance are
unverified. No real user credential is obtained, no production Vault is created,
and no payment or wallet is connected.

## Candidate operation and demand

Candidate caller: an explicitly consented workload that reads the user's own
upcoming calendar events to prepare a scheduling recommendation. This is a
proposed use case, not a claimed customer requirement.

Google's [events.list reference](https://developers.google.com/workspace/calendar/api/v3/reference/events/list)
documents `GET https://www.googleapis.com/calendar/v3/calendars/{calendarId}/events`,
the `primary` calendar identifier and accepted authorization scopes. The candidate
requests `https://www.googleapis.com/auth/calendar.events.owned.readonly` for
events on the user's own primary calendar. It does not require event writes,
calendar administration or access to another user's shared calendar. A broader
scope must be evaluated separately rather than silently substituted.

Google [web-server OAuth documentation](https://developers.google.com/identity/protocols/oauth2/web-server)
describes offline authorization, refresh and revocation. The official references
were read on 2026-10-20; no Google OAuth application, account or API operation was
tested. Verify provider application review, offline-token availability and
actual granted scopes before choosing production custody.

The missing demand inputs are a named consumer and operator, task ownership,
provider-account linking, approved query/data limits, unattended duration,
revocation target, residency, traffic and support responsibility. API readability
does not establish user approval or consumer demand.

## Authority and interfaces

At source `58e1f290c5e56f711b29058599e1bdb7643d6011`, the Vault remains an
[open design question](DESIGN.md#11--开放问题下一轮头脑风暴).
Existing [workload consent](WORKLOAD_CONSENT.md) and
[bounded delegation](BOUNDED_DELEGATION.md) govern Agent Auth credentials, not
Google's independently issued credentials.

An identity-login consent, Agent Auth workload consent and Google Calendar API
consent are separate authorities. Logging in with an upstream provider is not
permission to call that provider's APIs.

A future provider connection would bind the authenticated authorization tenant,
canonical user, Agent Auth client, provider, provider OAuth client and an opaque
connection identifier established by an explicit user linking flow. Provider
identity must not be inferred from an email or a caller-supplied account ID.
The connection's recorded provider grant and an operation policy are separate
from the user's current Agent Auth Grant and actor allowlist.

Before each credential delivery or broker admission, validate the exact
issuer/resource and authenticated caller, current user/Grant/lifecycle authority,
client, actor, connection/provider and the intersection of consented scopes and
permitted operations. A valid platform JWT or matching actor alone is insufficient.
Do not encode a Google token as an Agent Auth access token or use the latter as
Google's credential.

Keep these responsibilities separate:

| Interface | Responsibility |
| --- | --- |
| Existing AS `/token` | Existing first-party token issuance, refresh and constrained exchange; no provider network call or credential retrieval is added |
| Provider linking | State/PKCE-bound consent, fixed provider OAuth endpoints, actual granted-scope validation and atomic connection establishment |
| Credential custodian | Encrypted durable versions, refresh attempt state and lifecycle fences; never a general URL proxy |
| Provider adapter | Allowlisted provider endpoints and operations, bounded requests, provider-specific expiry/refresh/revocation semantics |
| Consumer or broker | Current business authority, parameter limits, credential release or admitted operation, data minimization and cancellation |

The proposed Calendar adapter fixes `calendarId=primary`, allows a bounded time
window and response size, and permits only the reviewed read operation. Limits
remain to be agreed with the consumer. A caller cannot supply an arbitrary
endpoint, redirect destination or a Calendar write request.

## Delivery versus operation brokerage

| Mode | Advantage | Authority and revocation limit |
| --- | --- | --- |
| Deliver a provider access token to the authorized client | Simple provider SDK integration; consumer performs the API call | The custodian cannot enforce individual operations after release; already delivered credentials may remain valid until expiry or effective provider revocation |
| Broker a restricted operation without returning the token | Central operation/parameter checks, less credential exposure to workloads | Broker becomes a provider-data processor and availability dependency; each request needs fresh authority and explicit data/logging policy |

Today, custody remains with the original authorized provider OAuth client.
Do not hand its refresh token to a workload or a different client. If verified
demand requires centralized custody, prefer evaluating an operation broker for
this bounded read use case. This is not approval to implement it.

Provider grants may include previously approved broader scopes. Record the
actual result and constrain operations to the approved intersection. Do not
release a broader raw token while claiming it is operation-limited. Token
downscoping requires actual provider support; it cannot be simulated by changing
a local scope string.

## Encryption, privacy and operations

A future independent custody module should use envelope encryption: a fresh
data key encrypts each credential version; KMS wraps that key. Bind authenticated
encryption and KMS encryption context to the tenant, a pseudonymous user binding,
connection, provider, provider OAuth client and version. Swapping ciphertext or
a wrapped key between bindings must fail. Encryption context can appear in
KMS audit records; it must contain no credential or plaintext email. No
plaintext credential enters an AS UserRecord, Grant, token claim, URL, log or
ordinary export.

Only a dedicated custodian runtime may unwrap its scoped data keys; frontend,
workload and general management roles have no decrypt permission. Separate
connection metadata, ciphertext, immutable attempt/audit records and provider
application secret references. Tenant/connection-qualified lookups must not
fall back to a global email or provider-name lookup.

Rotate wrapping keys with retained key identifiers and a reviewed rewrap or
reencryption process, including rollback and stale-version handling. KMS
unavailability fails closed. Retention, legal hold, export metadata, erasure,
offboarding, replica cleanup and backup restore suppression need explicit
integration with [data governance](DATA_GOVERNANCE.md). Deleting a key must not
be substituted for evidence of provider revocation.

Audit connection creation, authority decisions, refresh attempts, metadata
versions, operation results and lifecycle state without tokens, authorization
codes or raw Calendar event content. Calendar results may reveal sensitive user
data even if credential material never leaves the custodian. Price decrypt
calls, credential storage/indexes, refresh traffic, reads per operation,
audit retention, replicas and operator support after traffic and residency are
known; no workload or cost figure is invented here.

## Expiry, concurrency and failure recovery

The following is a proposed contract, not a new runtime implementation:

| State or event | Required behavior |
| --- | --- |
| Active credential before expiry | Check connection and caller authority before every release or admitted operation |
| Refresh due | One fenced durable attempt per connection/version; persist dispatch state before the provider call |
| Refresh succeeds | Atomically commit expiry and returned credential version under the same lifecycle/version fence; replace a refresh token only if the provider returns one |
| Competing refresh or expired lease | A lease expiring does not prove the dispatched request failed; another worker cannot replay a potentially consumed credential |
| Response lost after dispatch | Record `UNKNOWN`; use a provider-supported recovery contract or require reauthorization, never unlimited old-token replay |
| Provider `invalid_grant` or withdrawn consent | Stop use and require explicit provider reauthorization |
| Rate limit or provider outage | Respect provider backoff; distinguish known safe read retries from uncertain credential mutation |
| Provider result arrives after local revocation | The lifecycle fence prevents committing or releasing it; retain the attempt and settle provider revocation separately |
| Authority or KMS unavailable | No offline fallback to previously cached permission or unwrapped credentials |

A local idempotency key and database fence cannot make a provider's refresh call
idempotent or cancel a request already sent. Google may retain a refresh token
rather than rotate it on every response; the adapter must use actual provider
behavior. Provider recovery remains **NOT_RUN** and must be qualified before
production custody.

## Revocation boundaries

Track four independent outcomes: stop new local use, remove local copies, revoke
with the provider, and settle already delivered credentials or running
operations. Local stop/delete is not evidence of upstream revocation.

When local authority is withdrawn, fence new release and admission immediately
under the chosen consistency contract. Before deleting the credential needed
for a pending provider revocation, retain it only in the fenced revocation
workflow; then remove it under the agreed retention policy. Lost revocation
responses remain `UNKNOWN` until provider evidence or an explicit recovery
decision settles them. Google revocation can affect the associated provider
grant/token set, so its scope must be understood before promising per-connection
isolation. Provider expiry and the consumer's cancellation mechanism bound
credentials and operations already released or started.

## Future acceptance and decision

All cases below are **NOT_RUN**. Controlled adapter tests and live provider
acceptance must be separate evidence:

| Controlled adapter case | Required observation |
| --- | --- |
| Cross-tenant user or connection | Reject before ciphertext decrypt or provider access |
| Wrong client, actor, Grant or provider | Reject before credential delivery or operation admission |
| Scope or operation expansion | Reject broader requests; do not expose a broader raw token |
| Two refresh workers | At most one reviewed provider dispatch for the same credential version |
| Response loss or crash after dispatch | Durable `UNKNOWN`; no blind reuse of an old refresh token |
| Revocation races with refresh response | No resurrection or release after the lifecycle fence |
| Ciphertext/context/version substitution | Decrypt or authority validation fails closed |
| Provider/KMS unavailable or rate-limited | Distinct bounded failure; no insecure fallback |
| Local deletion or provider revoke timeout | Distinct local/provider outcomes, with delivered-token limits preserved |

Live Google acceptance would require an explicitly authorized test account and
reviewed OAuth application: consent to the chosen scope, actual primary-calendar
read, expiry/refresh behavior, scope checks, revocation effect and cleanup. It
would not be replaced by a mock provider response. No such acceptance was run
for this design issue.

The decision is **defer centralized custody; retain authorized caller custody**.
Reopen when the missing demand and ownership inputs are supplied, then split
custodian authority/storage, provider adapter/recovery, lifecycle/governance and
real-provider acceptance into implementation issues. A future AWS HTTP service
must use authenticated API Gateway or ALB; Lambda Function URLs are forbidden
in every authentication mode.
