# Tenant-scoped SCIM 2.0 Groups and tenant-role mapping

This document is the normative Agent Auth contract for the Groups portion of C12.3
and issue #19. The Users lifecycle contract remains in
[`SCIM_USERS.md`](SCIM_USERS.md). The profile implements the RFC 7643 Group resource
and the RFC 7644 CRUD/PATCH surface needed by directory provisioners, but does not
claim nested Groups, Bulk, sorting, or the full filter grammar.

## 1. Authorization domains

Agent Auth keeps three authorization domains separate:

1. A SCIM Group records tenant-local directory membership.
2. A tenant role protects the Agent Auth management plane and is one of `owner`,
   `admin`, `auditor`, or `member`.
3. An RS namespace attribute is opaque, audience-scoped business data. A value such
   as `role=owner` in an RS namespace is never a tenant role.

Every `/scim/v2/Groups` endpoint uses the tenant's owner-bound SCIM credential. The
role-mapping and effective-role endpoints use the separate tenant Admin credential:

- `GET /admin/scim/group-role-mappings`
- `PUT /admin/scim/group-role-mappings/{externalId}`
- `DELETE /admin/scim/group-role-mappings/{externalId}`
- `GET /admin/scim/effective-role/{userId}`

A SCIM bearer cannot call the mapping endpoints. A Group request containing `role`,
`roles`, or `tenantRole` is rejected; other ignored extension data cannot create a
mapping. A mapping can be created only for an active tenant-local Group that already
owns the exact `externalId`. Unknown and deleted Groups therefore cannot pre-stage or
retain privilege.

These Admin endpoints accept either the tenant break-glass credential or an OIDC
Admin session authorized for the action. Issue #20 added the short-lived session
and action-level RBAC described in [`ADMIN_SSO.md`](ADMIN_SSO.md). A SCIM bearer
still cannot enter the Admin authorization domain.

## 2. Group protocol

The supported surface is:

- `POST /scim/v2/Groups`
- `GET /scim/v2/Groups/{id}`
- `GET /scim/v2/Groups`
- `PUT /scim/v2/Groups/{id}`
- `PATCH /scim/v2/Groups/{id}`
- `DELETE /scim/v2/Groups/{id}`

`POST` and `PUT` require the core Group schema URI, a non-empty `externalId`, and a
non-empty `displayName`. `externalId` is byte-for-byte unique inside one tenant and
immutable after creation. Different tenants may reuse it. The server assigns a
random opaque Group `id`. Validation does not trim `externalId` or member ids.

Members are references to canonical tenant-local SCIM Users:

```json
{
  "value": "user:scim:opaque-id",
  "type": "User"
}
```

Nested Groups are not supported. A reference to an unknown, tombstoned, or
cross-tenant User returns `400 invalidValue`. A Disabled User may remain a directory
member, but effective-role resolution returns no role unless the canonical User is
currently Active with lifecycle cleanup complete.

One Group supports at most 40 unique members. This bound keeps a full replace, which
may remove 40 old rows and add 40 new rows, inside DynamoDB's 100-item transaction
limit. Exceeding it returns `400 tooMany`.

`PATCH` requires the PatchOp schema and supports:

- `add` or `replace` of `displayName`;
- `add`, `replace`, or `remove` of the complete `members` attribute;
- `remove` with `members[value eq "<canonical-user-id>"]`;
- pathless `add`/`replace` objects containing only supported attributes.

Unsupported paths, including platform-role attributes, fail before mutation.
Membership arrays are sorted and deduplicated. Repeating the same POST, PUT, PATCH,
mapping update, or DELETE has no additional effect. A no-op Group mutation does not
advance its internal version. Reusing an existing `externalId` with a different
canonical `displayName` or member set returns `409 uniqueness` rather than silently
discarding the conflicting request.

`GET /Groups` supports bounded `startIndex`/`count` pagination and only
`externalId eq "<value>"`. Unknown filters return `400 invalidFilter`.

Deleting a Group atomically tombstones the canonical id, removes the current
externalId claim, removes every membership index row, and removes its role mapping.
Repeating DELETE for that id returns `204`. The released externalId may later create
a new Group with a new id; a delayed DELETE for the old id cannot affect it.

## 3. Explicit role mapping

The mapping request is:

```json
{"role":"admin"}
```

Only the four fixed enum values are accepted. No Group name convention, unknown
Group, RS attribute, SCIM extension, or directory-supplied role string grants
management privilege.

Effective role is the highest explicitly mapped role among the active Groups that
contain the active User:

```text
owner > admin > auditor > member
```

The diagnostic effective-role response includes the selected role and every mapping
that contributed. An unmapped User has `role: null`. Removing membership, deleting a
mapping, or deleting the Group removes that contribution immediately. Disabling the
User returns `active: false`, `role: null`, and no contributing mappings.
Resolution strongly reads the canonical User before and after the membership query
and accepts a role only when the active credential epoch is unchanged. A concurrent
disable/enable therefore retries or fails closed instead of combining an old active
User observation with a newer mapping.

## 4. Persistence and isolation

`ScimGroupsTable` is separate from `UsersTable`. It stores:

- one canonical Group row;
- one hashed externalId claim row;
- one membership row per `(tenant, canonical user id, Group)`.

Creation, replacement, PATCH, deletion, and mapping changes use DynamoDB
transactions. Canonical mutation uses a version CAS. The role is copied onto
membership rows in the same mapping transaction, so effective-role lookup is a
strongly consistent query of one user's partition rather than a scan of all tenant
Groups. All physical keys include the tenant partition. The table has PITR, no TTL,
and a sparse `tenant_kind-index` for active Group listing.

The request Host selects the tenant before authentication. Credentials, Group ids,
externalId claims, member references, mappings, list results, and effective roles
are all tenant-local. Cross-tenant credentials return `401`; authenticated lookup of
another tenant's identifiers returns `404` or `400 invalidValue` without exposing the
other resource.

## 5. Acceptance boundary

Router tests cover Group create/read/filter/replace/PATCH/delete, exact retries,
unknown and cross-tenant members, SCIM/Admin credential separation, mapped and
unmapped users, mapping removal, Group deletion, fixed role priority, and RS
attribute non-interference. Adapter tests fix version idempotence, stable active-User
generation checks, and deletion semantics. IaC tests require the dedicated
encrypted/PITR table, sparse tenant index, runtime environment, IAM grant, and
CloudFormation output.

The live acceptance is [`e2e/scim_groups.sh`](../e2e/scim_groups.sh). It exercises
the public Dev or SaaS origin with real Secrets Manager credentials, exact PUT
retries, real DynamoDB mutation/mapping/delete races, and optionally the two-tenant
isolation matrix. SelfHosted acceptance persists and reads back an RS attribute
before proving it cannot grant a tenant role; SaaS acceptance verifies that the
SelfHosted-only attribute management endpoint remains unavailable:

```bash
AWS_PROFILE=default \
BASE_URL=https://t1.example.com \
STACK_NAME=AgentAuthSaas \
STORAGE_TENANT=t1 \
SCIM_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:t1-scim \
ADMIN_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:t1-admin \
OTHER_BASE_URL=https://t2.example.com \
OTHER_SCIM_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:t2-scim \
OTHER_ADMIN_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:t2-admin \
./e2e/scim_groups.sh
```

The combined Groups and Admin SSO slices close C12.3. The separate C12.2/#18
requirement still needs real Entra or Okta Users-job evidence.
