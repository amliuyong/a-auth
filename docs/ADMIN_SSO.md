# Tenant Admin OIDC SSO and action-level RBAC

This document is the normative runtime contract for issue #20 and the Admin
identity portion of C12.3. It applies to the SelfHosted Admin origin and each SaaS
tenant origin. The SaaS control origin remains platform break-glass only.

## 1. Identity and authorization boundary

Admin SSO never creates, links, or promotes a user from upstream claims. A successful
OIDC response must resolve to an existing tenant-local SCIM User that is Active,
has completed lifecycle cleanup, and belongs to an active SCIM Group with an
explicit role mapping. The upstream `role`, Group, or entitlement claims are not
authorization inputs.

The configured identity claim maps to exactly one existing field:

- `user_name`: only the upstream `email` claim; `email_verified` must be `true`;
- `user_id`: the canonical tenant-local SCIM User id.

The effective role is recomputed from
[`SCIM_GROUPS.md`](SCIM_GROUPS.md) on every Admin request. The fixed action matrix is:

| Role | Session status | Tenant read | Tenant write | Access/role/OIDC management |
|---|:---:|:---:|:---:|:---:|
| `member` | allow | deny | deny | deny |
| `auditor` | allow | allow | deny | deny |
| `admin` | allow | allow | allow | deny |
| `owner` | allow | allow | allow | allow |

An explicit `Authorization: Bearer ...` always selects the long-lived
bootstrap/break-glass domain. An invalid bearer never falls through to a browser
session. Break-glass retains full tenant authority so an operator can recover a
broken IdP or role mapping, but every successful use emits the existing
high-priority `ADMIN_BREAK_GLASS_USE` event.

## 2. OIDC configuration and secret ownership

`PUT /admin/oidc` is available only to an `owner` session or break-glass principal.
It uses `expected_revision` compare-and-swap; stale creates or updates return `409`.
`DELETE /admin/oidc?expected_revision=N` uses the same CAS rule. Every successful
config write also creates a new unpredictable binding. A management flow or
session remains valid only while both its config revision and binding match, so
deleting and recreating revision `1` cannot resurrect an old cookie or callback.

The redirect URI is derived from the authenticated public tenant origin and must
match exactly:

```text
https://<tenant-origin>/admin/sso/callback
```

The confidential client currently uses `client_secret_basic`, Authorization Code,
PKCE S256, OIDC nonce, and an RS256 ID token. Scopes must include `openid`. Issuer,
authorization endpoint, token endpoint, and JWKS URI are explicit so deployments
can use an approved provider without runtime discovery drift.

`strong_acr_values` is the tenant-specific exact allowlist of upstream ACR values
that may satisfy Agent Auth's canonical `urn:agent-auth:assurance:strong` class.
Unknown ACRs and all AMR strings remain baseline. The field may be empty when the
provider cannot supply trusted strong evidence, but that configuration cannot
satisfy an Admin step-up request. The complete policy is defined in
[`ASSURANCE_STEP_UP.md`](ASSURANCE_STEP_UP.md).

The client secret is stored separately in Secrets Manager and is never returned by
the Admin API. The accepted name is fixed by the request Host:

```text
SelfHosted: agent-auth/admin-oidc/default
SaaS t1:   agent-auth/admin-oidc/t1
SaaS t2:   agent-auth/admin-oidc/t2
```

The runtime IAM policy can read only `agent-auth/admin-oidc/*` (and the separate
federation prefix). The handler additionally requires the exact tenant-specific
name, preventing one tenant from selecting another tenant's secret. Create or
update the secret before saving the OIDC config.

## 3. Login and browser binding

`GET /admin/sso/start` creates a ten-minute one-time flow and redirects to the
configured authorization endpoint with `state`, `nonce`, PKCE S256, and
`prompt=login`. Existing query parameters on the configured endpoint are preserved.
When `acr_values=urn:agent-auth:assurance:strong` is requested, the endpoint also
forwards the configured upstream `strong_acr_values` and an effective `max_age`
that cannot exceed the deployment's strong-freshness policy. The flow stores the
canonical requirement, not the provider-specific ACR.

The server stores only an HMAC of `(state, browser nonce)`. The browser nonce is in
the HttpOnly, Secure, SameSite=Lax
`__Host-agent_auth_admin_oidc_flow` cookie. A callback therefore requires both the
state value and the browser that started the flow; state copied into another
browser is rejected. The flow is atomically consumed before token exchange.

Token exchange revalidates the public HTTPS endpoint, checks every DNS answer,
rejects private/reserved addresses, pins the connection to a checked address,
disables proxies and redirects, uses a three-second timeout, and caps the response
at 128 KiB. The callback validates the RS256 signature, issuer, audience, nonce,
time claims, identity claim, SCIM User, and Group role before creating a session.
For a step-up flow it additionally requires an exact allowlisted upstream `acr`
and a fresh `auth_time`. Provider clock skew up to 60 seconds is accepted and
clamped to the callback time; larger future values are rejected. Missing or stale evidence returns
`unmet_authentication_requirements` and creates no session.

The resulting `__Host-agent_auth_admin_session` cookie is HttpOnly, Secure,
SameSite=Lax, host-only, and valid for at most 15 minutes. The opaque value is
stored only as a domain-separated HMAC in DynamoDB.

## 4. Session revalidation, logout, and audit

Every Admin request performs strongly consistent checks for:

1. request Host and stored tenant equality;
2. unexpired session and unchanged OIDC config revision plus write binding;
3. Active SCIM User, unchanged `credential_epoch`, and no pending revocation;
4. unchanged current Group-derived role;
5. permission for the requested action class.

The `access.manage` action then requires fresh strong assurance. A low or stale
browser session receives an RFC 9470 `401` challenge with
`insufficient_user_authentication`, the canonical strong `acr_values`, and the
effective `max_age`. The rejected request has no mutation side effect. The SPA
uses that challenge to start a new Admin SSO flow and never guesses assurance
requirements from a generic `401`. Explicit break-glass bearer requests retain
their recovery semantics.

Deleting or changing the OIDC config, disabling the User, advancing its credential
epoch, removing Group membership/mapping, or changing the mapped role invalidates
the existing session on its next request. Role changes do not silently upgrade or
downgrade a previously issued session.

`POST /admin/logout` deletes the persistent session before clearing the cookie. If
the delete fails, it returns `503` and does not report logout success. The Admin SPA
waits for `204` before returning to the sign-in gate.

OIDC session creation and each action that reaches fixed-role authorization emit
`ADMIN_AUTHORIZATION` with tenant, canonical SCIM user id, fixed role, action, and
result. No session value, client secret, authorization code, or token is logged.

## 5. Deployment and rollback

Infrastructure ownership, rollout order, live acceptance, and rollback are defined
only in [`DEPLOYMENT.md` section 7](DEPLOYMENT.md).
The runtime contract above intentionally does not duplicate those procedures.
