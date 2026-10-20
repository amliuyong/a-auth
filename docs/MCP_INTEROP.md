# MCP client and library interop

Issue #89 tests published clients against the stock a-auth AS and a real
third-party `mcp-auth` resource server. These are local loopback TLS results,
separate from production/AWS and external IdP acceptance.

## Fixed runtime and configuration

On 2026-10-20 UTC, Node 22.23.3 ran `mcp-remote@0.15.2` and the actual
`mcpdo` CLI from MCP Inspector 2.11.0. Inspector browser GUI/CORS is NOT_RUN.
The RS uses `mcp-auth@0.2.0`, Express 5.2.1 and official MCP SDK 1.32.0.
The stable 0.2 library uses SDK v1; the SDK v2 beta is not this test's version.

AS source is `fc1d8ed8b4de1f416a8d7c0ecae75e2fd9cec2cf`, using unchanged
`AppState::dev("localhost")`: SelfHosted, P1, DEV_OPEN DCR, 900-second access
tokens. Its compiled executable SHA-256 is
`58383a57c8204f1b59ce0caec069a03099f8288683a98533228c26e87baf8ef5`.
The fixture creates a synthetic user through real HTTP administration, logs in
through the password endpoint and approves through the CSRF-bound consent API.
It does not use the development `login_user` shortcut or seed authority records.

The AS issuer is `https://localhost`; the protected resource is
`https://localhost:5544/mcp`, with `kb:read`. All listeners bind to loopback.
The AS TLS proxy binds 443 and immediately drops to the ordinary user.
A private test CA is scoped to each test process; certificate and hostname
verification stay enabled and system trust remains unchanged. A mismatched
TLS hostname was rejected in preflight. No Lambda Function URL is used.

The RS ran an independent byte-identical copy of
[the final example](../examples/mcp-auth/README.md). Its `server.mjs` SHA-256 is
`aaa561d64f05760f991fe232667224c6f3a8ebc55435ba7c1e48aebf1720ee76`.
Client cache/token files, TLS keys and synthetic user credentials are private
operational fixtures. Public records contain only product/configuration names,
status/presence flags and controlled outcomes.

## Results

The versioned [JSON record](interop/mcp-2026-10-20.json) binds client/library
results and redacted HTTP steps. Both clients completed a successful refresh
and protected call after the original 900-second access-token lifetime elapsed.

| Product | Initial protected call | Natural-expiry refresh | Renewed protected call |
| --- | --- | --- | --- |
| mcp-remote 0.15.2 | PASS | PASS, 21:37:15 UTC | PASS on final example |
| MCP Inspector mcpdo 2.11.0 | PASS | PASS, 21:40:39 UTC | PASS on final example |

Both refresh requests retained `resource` and had no DPoP header.
mcp-remote's actual cached session expiry advanced; its client/controller
stopped before Inspector's refresh, so the second refresh was independently
attributed to Inspector's real CLI call.

Both clients have completed 401 challenge → PRM → AS metadata → DEV_OPEN DCR →
code + S256 PKCE → real HTTP login/CSRF consent → protected tool call.
Both requested `offline_access` and supplied `resource`. CIMD is NOT_RUN.
DPoP was NOT_OBSERVED in these runs; this does not establish that either client
cannot support it.

The real `mcp-auth` middleware accepted the actual AS-issued client token,
rejected the same signed token under a wrong audience policy with 401, and
rejected a missing required scope with 403. Its published JWT verifier accepted
the valid issuer/signature/audience and rejected a different expected issuer
using the same signed token and actual AS JWKS, without editing claims.
The final example rejects verified JWTs carrying `cnf` rather than accepting
sender-bound tokens without proof. A synthetic post-verification HTTP policy
test first reproduced an unsafe 200, then verified 401/zero business calls for
valid-shaped, empty and null `cnf`, plus an accepted Bearer control. This policy
test is separate from actual-client/AS DPoP interoperability, which is NOT_RUN.
JWT verification remains offline; revocation can remain invisible until expiry.

`fetchServerConfig` plus `validateServerConfig` from the published library
passed all six metadata checks with no errors/warnings. The separately hosted
provider checker is NOT_RUN because a loopback issuer is not publicly
reachable; fetching its public website returned HTTP 403, which is not a
provider compatibility failure. No provider catalog submission was made.

First-attempt fixture failures are retained: the consent driver expected a
redirect status instead of the AS's JSON redirect response; the initial
Inspector driver omitted its parent process's test CA. Correcting the fixture
did not change AS/client validation. Inspector reused its private store after
the TLS fixture failure; mcp-remote used a new private cache.

Final cleanup PASS: the owned AS, TLS proxy, RS and Inspector daemon stopped;
all five fixture listener ports closed. Private credentials, client tokens,
cookies, logs and TLS keys were removed. The synthetic user/DCR/Grant state
was removed with the ephemeral in-memory AS. System trust and AWS resources
were not modified. Initial cleanup observation failures are retained separately
from the successful final absence checks.

## Reproduce and interpret

Use the locked [third-party example](../examples/mcp-auth/README.md) in a
separate project. Supply an actual HTTPS issuer/resource and normal client
callback/DCR policy, then follow the client's real discovery and browser
authorization flow. An unattended lab may drive the ordinary login/consent
HTTP endpoints with synthetic credentials; this is a test driver, not a new
OAuth client or an alternate authority path.

For refresh, request `offline_access`, keep the original client/store alive,
wait for actual access-token expiry and call the protected tool again.
Require a successful refresh grant and an accepted call with the renewed
client session. Do not alter TTL, cached expiry or token responses.
`npm run check-provider` runs the library's metadata checker, not the hosted
service or a production certification.

Production IAT-protected DCR, CIMD, SaaS, Inspector GUI/CORS, DPoP, external
IdPs and real AWS deployment remain NOT_RUN here. No compatibility relaxation
or new production policy is introduced. A future incompatibility needs its
own issue/security justification. Public provider-list submission needs a
publicly qualified deployment and separate user confirmation.
