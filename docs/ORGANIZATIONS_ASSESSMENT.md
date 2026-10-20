# Business organization assessment

Decision for [Issue #85](https://github.com/amliuyong/a-auth/issues/85),
2026-10-20: **defer an Agent Auth Organization model; keep business membership
and permission decisions in the consuming application**. The issue provides a
comparison with Logto, but no verified consumer currently supplies the required
same-issuer, multiple-organization scenario. This is an evidence gap, not a claim
that no customer could need it. No Organization runtime capability is introduced.
Organizations are not a prerequisite for the current SDK, onboarding, federation
or branding improvements.

## Demand and terminology

The demand source is the Logto comparison recorded in #85. There is no named
consumer, operator, production requirement, membership cardinality, revocation
target or migration owner in that issue or this delivery request.

For evaluation only, consider a user who belongs to **Blue** and **Green**
inside the same authorization tenant and calls the same reporting service.
The user can approve reports in Blue and only read reports in Green. This is a
synthetic scenario, not evidence of a customer request.

The [domain glossary](../CONTEXT.md) fixes the terminology:

| Domain | Authority and boundary | Existing contract |
| --- | --- | --- |
| Authorization tenant | Identity, issuer, keys, storage partition and management | Host-selected tenant; business organization input cannot select another tenant |
| Business organization | Consumer-owned members and permissions within a business boundary | No dedicated Organization contract is added by this assessment |
| SCIM Group | Tenant-local directory membership | Explicit Group-to-management-role mapping; no organization authority inferred |
| Tenant management role | Agent Auth management permissions | Fixed `owner`, `admin`, `auditor`, `member`; a business administrator gains no platform role |
| RS namespace | Audience-bound opaque business attributes | The AS stores values without interpreting a consumer's role strings |
| Grant | Consent for resources, scopes and constrained delegation | Resource/scope/actor authority; membership alone creates no consent |

Source inspection is pinned to
`58e1f290c5e56f711b29058599e1bdb7643d6011`:
[tenant selection](https://github.com/amliuyong/a-auth/blob/58e1f290c5e56f711b29058599e1bdb7643d6011/crates/http/src/tenant.rs),
[users and namespace attributes](https://github.com/amliuyong/a-auth/blob/58e1f290c5e56f711b29058599e1bdb7643d6011/crates/http/src/ports.rs#L1484),
[SCIM Groups and management roles](SCIM_GROUPS.md),
[Grant authority](https://github.com/amliuyong/a-auth/blob/58e1f290c5e56f711b29058599e1bdb7643d6011/crates/grant/src/lib.rs#L61)
and [delegation](BOUNDED_DELEGATION.md).

## Alternatives

| Choice | Benefits | Costs and limits |
| --- | --- | --- |
| Consumer owns organizations; optional RS attributes carry bounded presentation data | Reuses issuer/identity, preserves business ownership, no AS migration | Consumer maintains membership, authorization and its own revocation checks; an attribute is not a membership service |
| Agent Auth adds Organization and membership authority | Shared administration and templates across participating consumers | New lifecycle, isolation, invitation, SCIM mapping, policy, privacy and audit contracts; consumers still need action-level enforcement |

Prefer the first choice until a verified consumer needs the second. An RS
attribute may carry a consumer-defined value under its own namespace, but the
current per-user attribute map is bounded to 4096 serialized bytes. It is not
an unbounded organization directory, membership index or shared policy engine.
SelfHosted and SaaS expose different attribute-management capabilities; this
choice does not assume every deployment can write attributes.

Shared identity avoids separate accounts for Blue and Green. It also makes
organization participation sensitive: consumers must not expose all memberships
to unrelated clients or combine pairwise subjects through email. The consumer
binds identity to the verified issuer and its own audience-specific subject.
It shares data with another RS only through an explicitly reviewed relationship.

Shared role templates can reduce repeated configuration, but a broad template
change affects many organizations. Customer-specific roles provide local control
at the cost of more policy management. Neither model is selected for Agent Auth
without a consumer's concrete actions, inheritance rules and rollout requirements.

## Expected consumer behavior

These are proposed acceptance cases for a future consumer integration. They
have **NOT_RUN** status and do not describe newly implemented AS behavior.

| Event or attack | Expected decision |
| --- | --- |
| Join Blue | Authorized business workflow creates Blue membership; membership does not grant a new OAuth scope or Agent Auth management role |
| Leave Blue | New Blue business requests fail after the membership transaction commits; Green membership and authorized Green requests remain independent |
| Narrow Blue role | Previously permitted Blue actions fail against current business policy; retained offline JWT validity cannot restore the removed business permission |
| Switch Blue to Green | Organization selection is a request hint; validate current Green membership and Green action permissions without unioning Blue permissions |
| Request Green using only Blue membership | Reject even when issuer, audience, token signature and OAuth scope are valid |
| Grant or user revoked | Enforce existing online authority where immediate revocation is required, and independently check business membership |
| Workload tries an unapproved organization or action | Intersect current business permission with valid subject/Grant, resource, scopes and actor constraints; an `act` claim or allowlisted actor alone is insufficient |
| Machine-to-machine client acts without a user | Require explicit consumer-owned organization assignment and service action policy; do not invent a user membership |

Keep the resource/audience equal to the actual service. An organization identifier
does not replace the audience, tenant or issuer. Current SDKs verify token and
route policy; this assessment adds no organization claim, built-in membership
lookup or automatic role enforcement. A request header or arbitrary RS attribute
must not be accepted as independently verified organization authority.

Immediate business revocation needs fresh consumer authority checks with a
specified consistency and cache policy. Authenticated introspection checks the
AS's Grant/lifecycle/delegation authority; it does not read an external
organization database. Already running operations require the consumer's own
cancellation mechanism. See [bounded delegation](BOUNDED_DELEGATION.md).

## Compatibility, operations and reopening

The selected deferral changes no token, consent, discovery, schema, database,
index, key or deployment. There is no backfill, cloud mutation or runtime test
for this design-only issue. Existing SCIM Groups must not be renamed or migrated
into organizations: their 40-member bound and explicit platform-role mapping are
different contracts.

For a future dedicated model, demand validation must address:

- Organization membership, business roles, explicit organization context and
  M2M assignments; invitation expiration, authorized acceptance and exit.
- Explicit directory-to-organization mapping with lifecycle ownership, versioned
  role-template changes, local overrides and fail-closed concurrent removals.
- Tenant/organization-qualified indexes for member lookup, reverse user
  membership and bounded listing; no global email or Group-name lookup authority.
- Audit ownership and retention, user export/erasure, tenant offboarding, recovery
  and replay protection, consistent with [data governance](DATA_GOVERNANCE.md).
- Consumer migration, old-token behavior, staged rollout and rollback. A token
  claim alone cannot revoke a membership in an already issued offline token.

Costs remain unpriced because there is no workload or residency requirement.
Estimate from measured organization/member/role counts, item sizes, indexes,
read rate per business call, membership-change rate, retention, replicas and
PITR. Bidirectional membership indexes add write and storage work; synchronous
fresh checks add read latency and availability dependencies. Estimate template
fan-out and erase/recovery work separately. Do not reuse an existing tenant's
storage cost as an Organization estimate.

Reopen a design issue when a named consumer supplies the Blue/Green-equivalent
scenario, authoritative actions, ownership, privacy consent, cardinalities and
revocation targets. Only then select a model and split implementation issues
with positive, cross-organization, workload and revocation acceptance. This
assessment's completion does not claim runtime Organization support.
