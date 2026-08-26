# Tenant-scoped SCIM 2.0 Users profile

This document is the normative Agent Auth contract for C12.2 and issue #18. It narrows
RFC 7643/7644 to an interoperable Users slice without claiming Bulk, sorting,
password changes, or the full filter grammar. The independently authorized Groups
and tenant-role mapping profile is [`SCIM_GROUPS.md`](SCIM_GROUPS.md).

## 1. Tenant and credential boundary

- Every enabled tenant exposes `https://<tenant-issuer-host>/scim/v2`. The tenant is
  derived once from the trusted request Host; no path, query, or body field may select
  another tenant.
- Every endpoint, including `ServiceProviderConfig`, requires
  `Authorization: Bearer <scim-credential>`.
- Each tenant has an owner-bound SCIM credential set with the same current/next,
  expiry, retirement, rollback, and warm-refresh guarantees as C12.1. SCIM and Admin
  owners use different Secrets Manager identities and credential usages. The registry
  rejects duplicate active or retired identifiers/values across both domains.
- An Admin credential on a SCIM route, a SCIM credential on an Admin route, or a
  credential presented on another tenant Host returns `401` with
  `WWW-Authenticate: Bearer`. Unknown resource identifiers remain tenant-local `404`.
- SCIM responses use `Content-Type: application/scim+json`. Bearers and raw
  `externalId` values are never logged.
- Successful SCIM bearer verification emits a tenant-scoped
  `SCIM_CREDENTIAL_USE` event rather than an Admin break-glass event. Successful
  create, replace, disable, and enable mutations emit a `SCIM_MUTATION` event with
  canonical user id; disable also records the session, refresh-family, and Grant
  cascade counts. These events never contain raw `externalId`.

## 2. Supported protocol surface

`GET /ServiceProviderConfig` reports:

- `patch.supported=true`
- `filter.supported=true`, `filter.maxResults=100`
- `bulk.supported=false`, `changePassword.supported=false`, `sort.supported=false`
- `etag.supported=false`
- one `oauthbearertoken` authentication scheme

The Users surface is:

- `POST /Users`
- `GET /Users/{id}`
- `GET /Users`
- `PUT /Users/{id}` as required by RFC 7644 section 3.5
- `PATCH /Users/{id}`

`POST` and `PUT` require the core User schema URI, a non-empty email-shaped
`userName`, and a non-empty `externalId`. `active` defaults to `true`; `displayName`
is optional. Server-assigned `id` is the opaque, random, stable canonical user id.
`meta.resourceType`, `created`, `lastModified`, and tenant-local `location` are
returned. Client-supplied read-only `id` and `meta` are ignored as required by SCIM.

Within one tenant, `externalId` is byte-for-byte unique and `userName` is
case-insensitively unique. Both are tenant-scoped aliases of the canonical id.
Different tenants may reuse either value. Alias claims and canonical creation or
update are one atomic write and do not rely on eventually consistent GSI uniqueness.

The first `POST` returns `201`, `Location`, and the full User. An exact retry of the
same `(tenant, externalId, normalized userName)` returns the same resource with `200`
and creates nothing. A crossed alias collision returns `409` with
`scimType=uniqueness`.

`PUT` replaces the supported writable attributes while preserving `id`. It may move
`externalId` or `userName`; old aliases cease resolving in the same atomic write.
It applies the same authoritative lifecycle transition when `active` changes. A
separate hashed create-idempotency claim is retained for every successful POST tuple
and survives alias moves. An initially inactive create keeps a one-time pending
lifecycle epoch in that claim until disable completes. Starting that lifecycle
condition-checks the pending claim and advances the canonical status/epoch in one
transaction. `PUT` and `PATCH` settle that pending transition before applying their
own alias and `active` intent, so a delayed inactive `POST` cannot disable a user
after a newer enable. After completion, delayed retries return current canonical
state without replaying old lifecycle intent or making old aliases visible to GET
filters.

`PATCH` requires the PatchOp schema and supports only `add` or `replace` of `active`,
either with `path: "active"` and a Boolean value or a pathless object containing
`active`. The operations are validated before mutation and reduce to one lifecycle
transition. Unsupported operations or paths return a SCIM `400` error.

`GET /Users` supports bounded `startIndex`/`count` pagination. Per RFC 7644,
`startIndex < 1` is interpreted as 1 and negative `count` as 0. Unfiltered
listing uses a tenant-partitioned, canonical-id-sorted index and materializes
only the requested page while returning an exact `totalResults`. Only these
filters are supported:

- `externalId eq "<value>"`
- `userName eq "<value>"`

The parser follows RFC 7644 grammar, including JSON string escaping. Attribute and
operator names are case-insensitive; values follow their schema case rules. Any
other expression returns `400` with `scimType=invalidFilter`; no match is a successful
ListResponse with `totalResults=0`.

All errors use the RFC 7644 Error schema and string HTTP status. The implementation
maps malformed bodies and values to `invalidSyntax`/`invalidValue`, unsupported
filters to `invalidFilter`, alias collisions to `uniqueness`, and unsupported PATCH
paths to `invalidPath`.

## 3. Canonical identity and lifecycle

Email, SCIM `externalId`, and SCIM `userName` are aliases, not identity keys. New SCIM
users receive a random canonical id. Existing non-tombstoned local users with the
same normalized email may be adopted only through an atomic alias claim; tombstones
are terminal and cannot be rebound.

`UserRecord` carries a monotonic `credential_epoch` and durable
`revocation_pending`. Session, refresh-family, and Grant records capture the current
epoch when created. Every consumption path compares the captured epoch with a strong
read of the active user; a mismatch is rejected. Legacy records default to epoch zero.

Admin and SCIM invoke one tenant-explicit lifecycle service:

1. Disable atomically sets `Disabled`, advances the epoch once, and sets
   `revocation_pending=true`.
2. It deletes login sessions, revokes refresh families and grace entries, then revokes
   Grants. Each physical cleanup is conditionally fenced to artifacts whose captured
   epoch predates the disable generation; a delayed worker cannot revoke artifacts
   created after re-enable. Retries resume the same epoch and repeat idempotent effects.
3. Completion clears `revocation_pending` only for that epoch.
4. Enable is allowed only for `Disabled` with completed revocation. It never decrements
   the epoch or recreates sessions, refresh families, Grants, or credentials. An
   already-Active snapshot returns idempotently without a write; `Disabled` to
   `Active` is a CAS on the observed epoch, so a stale enable cannot overwrite a
   newer disable. A legacy `Disabled` record whose missing generation reads as zero
   is atomically moved to generation one and cleaned before its first enable.
5. `Tombstoned` is terminal. `Active` and repeated completed transitions are
   idempotent.

This epoch closes the gate-to-write race: an artifact written after the disable scan
still carries the old epoch and remains unusable after re-enable.

## 4. Acceptance boundary

Router tests cover schemas, media types, errors, filter parsing, exact POST retry,
alias collision/move, PUT, PATCH, lifecycle failure/resume, tombstone behavior, and
the full provision-to-disable-to-re-enable path. Crash-recovery tests prove a newer
PUT/PATCH enable wins over a delayed initially inactive POST. The vertical test seeds
a login session, refresh family, and Grant and proves all three old artifacts remain
rejected. Tenant matrix tests cross credentials, ids, aliases, filters, and retries.

AWS acceptance verifies Secrets Manager separation, DynamoDB transactional claims,
tenant-scoped paged listing through the sparse, canonical-id-sorted
`scim_tenant-index` rather than a shared-table scan, user-scoped Session/Refresh
indexes for lifecycle cleanup, CloudFront forwarding of Authorization/PUT/PATCH,
and both Dev and SaaS deployments. The committed live script's `STACK_NAME` mode
also seeds epoch-bound session/refresh/Grant records through the deployed tables,
disables immediately without waiting for the three user indexes, strongly reads
any residual artifacts, and retries the same public SCIM disable after those
artifacts become index-visible. It proves the retry deletes/revokes them while
advancing and completing exactly one lifecycle epoch.
Completion additionally requires a committed live script plus one real Microsoft
Entra or Okta directory job proving provision, lookup, deprovision, and re-provision.

The protocol-level live acceptance is [`e2e/scim_users.sh`](../e2e/scim_users.sh).
It accepts a target Secret ARN (or a protected token file), exercises initially
inactive POST, inactive PUT, retry, disable, and re-enable through the public tenant
URL, and optionally runs the two-tenant credential/id/alias matrix. For example:

```bash
BASE_URL=https://t1.example.com \
STACK_NAME=AgentAuthSaas \
STORAGE_TENANT=t1 \
SCIM_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:t1 \
OTHER_BASE_URL=https://t2.example.com \
OTHER_SCIM_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:t2 \
./e2e/scim_users.sh
```

The script proves the deployed SCIM protocol and isolation behavior; it does not
replace the separate Entra or Okta provisioning-job evidence required above.

### Real Okta directory job

[`e2e/okta_scim_users.sh`](../e2e/okta_scim_users.sh) drives the remaining
third-party acceptance through an active Okta private SCIM integration. The
integration must target this tenant's `/scim/v2` base URL and enable `Create
Users` and `Deactivate Users`. The script creates an active disposable Okta
directory user, assigns it to the app, removes the assignment, and assigns it
again. It independently polls Agent Auth after every provider operation and
requires the active lifecycle `true -> false -> true` while preserving both the
canonical Agent Auth id and Okta-backed `externalId`.

```bash
OKTA_ORG_URL=https://example.okta.com \
OKTA_API_TOKEN_FILE=/secure/path/okta-api-token \
OKTA_APP_ID=0oaexample \
BASE_URL=https://issuer.example.com \
SCIM_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:scim \
PROFILE=default \
STACK_NAME=AgentAuthDev \
./e2e/okta_scim_users.sh
```

The Okta API token and SCIM bearer are passed through protected header files and
never placed in command arguments or evidence. The retained evidence contains
only the provider/product name, lifecycle statuses, timestamps, exact clean
source/deployed commit, harness hash, public issuer, and SHA-256 hashes of
provider and user identifiers. The script verifies the source commit against
the stack's `DeploymentCommit` and the issuer against its frontend output
before changing Okta. Unless `KEEP_OKTA_FIXTURE=1` is set, it verifies app
unassignment, disposable-user deletion, and the final inactive Agent Auth SCIM
state before writing successful evidence; an interrupted or failed run retains
no success claim and retries cleanup of a user id confirmed by the create
response on exit. It never deletes a user recovered only by login after an
ambiguous or rejected create. Evidence and its checksum are published from
mode-`0600` temporary files only after every lifecycle and cleanup check passes.
The harness also refuses to start if the generated disposable login or
requested evidence/checksum path already exists.
