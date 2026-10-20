# Enterprise OIDC templates and diagnostics

The administrator console offers version 1 guidance for Okta, Microsoft
Entra ID and generic OIDC. Each uses the existing federation API and protocol:
authorization code, PKCE S256, `client_secret_basic` and RS256 ID tokens.
Generic OIDC retains manual field entry. A template supplies guidance and
examples; switching it preserves every entered issuer, endpoint, secret
reference and strong ACR value.

Saving a configuration does not prove that the provider works. Draft
validation, supplied public metadata, server discovery/JWKS checks and a
real login are separate results.

## Configure a provider

Register a confidential application at the provider and allow the deployment's
exact `https://<issuer-host>/federation/callback` URI. Copy the public discovery
document for the authorization server you intend to trust.

| Template | Issuer selection | Official guide |
| --- | --- | --- |
| Okta v1 | Select the exact authorization server, for example `https://your-org.okta.com/oauth2/default`; copy its endpoints rather than infer them. | [Authorization code flow](https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/) |
| Entra ID v1 | Use the discovery document's exact tenant-specific v2.0 issuer. Do not use `common` or `organizations` as a tenant trust anchor. | [OIDC protocol](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) |
| Generic OIDC v1 | Use the exact issuer and endpoints of your configured authorization server. | [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) |

| Field | Meaning and review |
| --- | --- |
| IdP ID | A tenant-local identifier. The template form refuses an ID already shown in the loaded list; existing API update and attribute-mapping authority rules still apply. |
| Issuer | Exact value expected in the provider metadata and signed ID token. No surrounding whitespace, query or silent normalization. |
| Client ID | The confidential application's registered client ID. |
| Client secret reference | Enter the reference, not the secret. SaaS requires a Secrets Manager name under `agent-auth/federation/<tenant>/`, or an ARN with a name in that same namespace. Self-hosted deployments retain their existing reference names. The list and diagnostics do not echo the reference. |
| Authorization endpoint | The explicitly reviewed endpoint to which the browser is redirected. |
| Token endpoint | The explicitly reviewed endpoint used for the authorization-code exchange. |
| JWKS URI | The explicitly reviewed signing-key source. Metadata cannot replace this trust address. |
| Scopes | Must contain `openid`; add other scopes only for an explicit need. |
| Strong ACR values | Empty by default. List only ACR values explicitly approved to satisfy the tenant's strong-assurance policy. `amr`, a template and arbitrary upstream roles do not confer strong assurance or platform administration. |

Public HTTPS endpoints use port 443 and cannot contain credentials or
fragments. Private/reserved addresses and local hostnames are blocked before
network access. Lambda Function URLs are forbidden in every authentication
mode. Discovery and JWKS responses must be at most 64 KiB.
The template form requires a public DNS name. The existing manual API also
permits public IP literals subject to the same server network restrictions.

The console loads `GET /admin/federation` to obtain the authenticated tenant
and its existing IdP list. Self-hosted deployments return `default`; SaaS
deployments return the tenant authorized for the request host and admin
credential. It never falls back to `default` if that lookup fails. The older
explicit-tenant list endpoint remains available with the same tenant checks.

Create a new draft only after loading this list. To update a
registered trust, use the existing administrative API and review the complete
configuration explicitly. Changing an issuer with active attribute mappings
continues to return a conflict; template selection never bypasses mapping
ownership or reserved-field restrictions.

For SaaS, provision the provider secret in the authenticated tenant's
namespace before saving. Older SaaS references outside that namespace must
be replaced by an explicitly provisioned tenant-owned reference. Templates
never move, copy or resolve a secret. Saving and login both reject an invalid
reference; login rechecks the complete saved configuration before an upstream
redirect and again before secret resolution or code exchange. Invalid legacy
endpoints, including Function URLs, cannot be used through this login path.

## Read the checks

The draft's **Check draft and supplied metadata** button runs locally. Optional
public discovery JSON must exactly match the configured issuer,
authorization endpoint, token endpoint and JWKS URI. It does not contact the
provider, resolve secrets, fetch signing keys or execute login.

After saving, **Check provider** calls the authenticated tenant-scoped
`GET /admin/federation/{tenant_id}/{upstream_idp_id}/checks` endpoint. It takes
no URL parameter. The server derives the OIDC discovery URL from the saved
issuer and checks the saved JWKS URI only after every metadata field matches.
It never adopts remote endpoints or persists a provider-ready flag.

| Stage | PASS means | Failure or next step |
| --- | --- | --- |
| Format | Required fields, scopes and endpoint restrictions are valid. | `FAIL` identifies a configuration field. Review that field explicitly. |
| Network discovery | The bounded public document matches all four saved trust fields exactly. | `FAIL` identifies a mismatch or blocked/invalid response. `UNKNOWN` means DNS, HTTPS, capacity or provider availability prevented a conclusion. |
| JWKS | A structurally usable RS256 verification key exists at the saved URI. | Check the JWKS URI and RS256 keys on `FAIL`; resolve network availability on `UNKNOWN`. This is not a signed-token or login proof. |
| Real login | This endpoint never reports login PASS. | `NOT_RUN`: complete an actual authorization-code login and verify the callback independently. |

Later stages stay `NOT_RUN` when an earlier stage prevents them from running.
If the saved configuration changes during network checks, the API returns
409 and the console discards the stale result. Reload the configuration and
retry. Configuration-store failures return 503 rather than a successful
diagnostic response. Results are momentary and returned with `Cache-Control:
no-store`.

The network adapter bounds DNS and HTTP to three seconds each, rejects
redirects and proxies, checks every resolved IP and pins the connection to a
validated address. It sends no provider credentials during diagnostics.

## Validation boundaries

Shared versioned fixtures in `tests/fixtures/federation-templates.json`
exercise the configuration shape produced by all three templates. Controlled
OIDC acceptance uses in-memory discovery, signing keys and token exchange,
with real signed ID-token validation, nonce/state/PKCE, consent and downstream
code exchange. These controlled results establish the shared protocol path;
they do not prove access to a live provider application.

Real Okta login: **NOT_RUN**. Real Entra ID login: **NOT_RUN**.
Record provider-specific evidence separately when an actual application and
authorized test user are available. Do not describe either template as
verified against a live provider on the basis of saving or mock acceptance.
