# Authentication assurance and step-up

This document is the normative runtime contract for issue #21 and C12.4. It
defines Agent Auth's product-level assurance classes, trusted evidence mapping,
freshness policy, and step-up behavior for OAuth authorization and Tenant Admin.
These classes are not claims of NIST AAL conformance.

## 1. Internal assurance classes

Agent Auth exposes exactly two stable internal ACR values:

| Class | Canonical ACR | Evidence |
|---|---|---|
| Baseline | `urn:agent-auth:assurance:baseline` | Password, magic link, recovery, missing or untrusted upstream evidence |
| Strong | `urn:agent-auth:assurance:strong` | A verified local passkey event, or an exact upstream `acr` value in that tenant and IdP configuration's `strong_acr_values` allowlist |

A local passkey event is strong only when the authenticated session contains the
verified `webauthn` and hardware-key (`hwk`) method tuple. An upstream event is
strong only after signature and claim validation and an exact `acr` allowlist
match. Unknown `acr` values, an upstream copy of an Agent Auth internal ACR, and
all `amr` strings, including `mfa` and `otp`, remain baseline unless the upstream
`acr` itself is explicitly allowlisted.

The mapping is tenant-scoped because `FederationConfig` and Admin OIDC config are
stored and loaded within the request Host's tenant. A value trusted for one
tenant or IdP does not change another configuration.

## 2. Authorization request policy

OIDC discovery publishes both canonical values in `acr_values_supported`.
`/authorize` accepts a whitespace-separated `acr_values` preference list and
selects its first supported value. A non-empty list with no supported value
fails at the registered redirect URI with:

```text
error=unmet_authentication_requirements
```

The default policy requires strong assurance for a RAR detail containing the
action `transfer`. This policy overrides a caller's baseline preference. Strong
assurance is fresh for at most 300 seconds by default; a smaller caller
`max_age` is honored, while a larger value cannot relax the deployment policy.
Negative `max_age` is an `invalid_request`.

An absent, lower-class, or stale session is redirected into authentication with
the canonical strong ACR and effective `max_age` preserved. `prompt=none`
returns `unmet_authentication_requirements` when an existing session needs
step-up, and `login_required` when no login exists. A configured upstream IdP
receives its own allowlisted ACR preferences, `prompt=login`, and the effective
`max_age`; if it has no strong mapping, that path cannot claim to satisfy strong
assurance. The callback requires an upstream `auth_time` within that freshness
window. Up to 60 seconds of provider clock skew is accepted and clamped to the
callback time; a value further in the future is rejected. Local passkey
authentication can satisfy the same continuation.

The gate is enforced again on the consent decision, before authorization-code
or Grant creation. Browser-controlled continuation parameters therefore cannot
bypass the original assurance decision. Code redemption, refresh, token
exchange, and introspection preserve the canonical `acr` and normalized
`auth_time`; refresh does not manufacture a newer authentication event.

## 3. Tenant Admin step-up

The high-risk Admin action is `access.manage`. It covers Admin OIDC config and
SCIM Group role-mapping changes. Role authorization runs first, then an owner
browser session must also carry fresh strong assurance. A baseline or stale
session receives the RFC 9470 challenge:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication", error_description="A different and recent authentication level is required", acr_values="urn:agent-auth:assurance:strong", max_age="300"
```

The Admin SPA parses only this complete challenge and starts
`/admin/sso/start` with the requested canonical ACR and freshness. The start
endpoint maps strong to the tenant's configured upstream
`strong_acr_values`, includes `prompt=login`, and stores the canonical
requirement in the one-time flow. The callback requires:

1. a verified upstream `acr` that maps to strong;
2. an upstream `auth_time` no more than 60 seconds in the future, normalized to
   the callback time when skewed;
3. `auth_time` within the flow's effective `max_age`.

Missing or insufficient evidence returns `unmet_authentication_requirements`
and creates no Admin session. A successful callback stores only the canonical
ACR and upstream authentication time. Long-lived bearer credentials remain an
explicit bootstrap/break-glass domain and are not blocked by browser step-up.

## 4. Deployment policy

All Auth, Reclaim, and Recompute runtimes receive the same explicit environment:

```text
AGENT_AUTH_STRONG_MAX_AGE_SECS=300
AGENT_AUTH_HIGH_RISK_RAR_ACTIONS=transfer
AGENT_AUTH_HIGH_RISK_ADMIN_ACTIONS=access.manage
```

`AGENT_AUTH_STRONG_MAX_AGE_SECS` must be between 1 and 3600. Action variables
are comma-separated non-empty tokens; an explicitly empty value disables that
action set. Invalid policy prevents runtime initialization instead of silently
falling back.

Before enabling an upstream strong mapping, verify the provider's exact ACR
contract and `auth_time` behavior. Do not infer assurance from marketing labels
or `amr`. Rollback may remove the mapping or high-risk action through a reviewed
configuration deployment; it must not rewrite existing strong sessions as
baseline or vice versa.

## 5. Acceptance

- Router tests establish that baseline sessions cannot obtain a code for explicit strong
  `acr_values` or high-risk `transfer` RAR, including a direct consent bypass.
- Controlled OIDC tests establish that only an allowlisted upstream ACR elevates and that
  unknown ACR/AMR evidence remains baseline.
- The repository passkey E2E completes the public magic-link, WebAuthn
  registration, and WebAuthn authentication flow before asserting the resulting
  canonical strong session.
- Admin router tests establish the RFC 9470 challenge and no privileged mutation.
- Token, refresh, delegated-token, and introspection tests establish canonical
  `acr` and normalized `auth_time` propagation.

Live-environment results are not retained as repository conformance evidence.
Run the current acceptance gate before relying on a deployment-specific claim.
