# Independent onboarding examples

These private examples use the official MCP SDK 1.32.0, oauth4webapi 3.8.8
and the installed `agent_auth_rs` SDK 1.0.2 public entry. They are recipes, not a new
OAuth client SDK. Requires Node.js >=22.14.

## Prepare an independent project

Copy this directory outside the repository. In that copy:

```bash
npm ci
npm install --no-save /absolute/path/to/qualified/agent_auth_rs-1.0.2.tgz
```

The RS SDK peer is optional only so dependencies can be installed before
publication. Every server run requires the real SDK installation above.
The tarball must come from #79's clean source artifact qualification. No
workspace/source import or editable install is used.

Public registry installation remains **NOT_RUN** until #79 publishes and
verifies its registry receipt. After that, replace the second command with:

```bash
npm install --no-save agent_auth_rs@1.0.2
```

Open `/admin?tab=onboarding` at your current tenant. Select the appropriate
registered clients and copy its public configuration into `config.json`, or
fill in `config.example.json`. Client IDs and issuer/resource are public.
Never copy an Admin token, client secret or platform JWT into this file.

These recipes use public bearer CLI clients. Code + PKCE requires an HTTP
loopback redirect registered with that client, for example
`http://127.0.0.1:8765/callback`. Required DPoP client/actor profiles are not
offered by the console recipe; the server rejects sender-bound tokens instead
of accepting them without a proof.

## MCP Server

1. Choose the actual public HTTPS MCP endpoint as `resource`, with the exact
   issuer and required scopes. Do not substitute the server's internal listener
   URL for this audience.
2. Run `npm run server`. The listener binds `127.0.0.1:8790` (`PORT` overrides
   that port). Put it behind your HTTPS reverse proxy for the configured
   resource origin. The proxy must route the MCP resource path and its derived
   `/.well-known/oauth-protected-resource/...` path to this listener.
3. Request public PRM and confirm `resource` and `authorization_servers`.
   Calling the resource without a token must return 401 with
   `WWW-Authenticate` containing the correct `resource_metadata` URL.
4. Complete one of the CLI authorization paths below and run `npm run call`.
   The official MCP client initializes and calls the protected `identity` tool.
   A PASS summary confirms the call; it prints no token or subject.

If a gateway stage changes the public metadata path, set the optional
`resource_metadata_url` to its actual HTTPS PRM address. The server serves that
path and advertises it in the 401 challenge. Without this setting, it uses the
SDK's standard derived path. The PRM `resource` remains the protected public
endpoint. All three configured public URLs reject Lambda Function URLs.

For AWS hosting, Lambda Function URLs are forbidden in every authentication
mode. Use an authenticated API Gateway or ALB for protected HTTP routes, or
invoke Lambda through the AWS SDK. Do not enable a Function URL in a
third-party deployment template.

For online enforcement, register an ordinary `client_secret_basic` RS client
with `introspect_enabled=true` and `resource_ids=[resource]` through the Admin
client API/UI. Set `introspection_client_id` in public config and inject its
credential into `RS_INTROSPECTION_SECRET` through your runtime's secret store.
Set `online=true`; positive introspection caching is disabled. The console
does not retrieve or copy persistent credentials.

## Agent / CLI

The console offers only authorization flows advertised by current discovery.
The commands check discovery again before running:

```bash
npm run pkce
npm run call
```

Open the printed authorization URL, sign in normally and review the displayed
resource/scopes before approving. The loopback receiver verifies OAuth state,
uses S256 PKCE, redeems the code and atomically writes a mode-0600
`.session.json`. Tokens are not printed. A wrong-state callback is rejected
without consuming the waiting authorization. A bound authorization error
stops the command; a timeout is a failure.

If device flow is advertised and selected, replace `npm run pkce` with
`npm run device`. Open its verification URI and enter the user code; it obeys
the advertised poll interval and `slow_down`. The device code stays private.
Device authorization is ordinary CLI access and cannot add workload consent.

Refresh requires an advertised refresh grant and a refresh token from the
initial authorization. Request `offline_access` with the CLI's resource scopes
(for example, `read offline_access`) before authorizing if refresh is needed.
The server's required business scopes can remain `read` in its own config.
An existing session without a refresh token needs a new user authorization.

Run commands sequentially within one example project. The refresh command
serializes access to the original rotating refresh family:

```bash
npm run refresh
npm run call
```

Successful rotation commits the new credential atomically. A lost or
unparseable response is **UNKNOWN**, stops automatic retry and retains
`.session.json.lock`. Do not delete that lock to retry the old refresh token.
Recover through the issuer's documented bounded grace contract, or start a
new user authorization in a new private example directory. These examples
do not implement a production credential store or a cross-process recovery
service.

## Workload on behalf of a user

First register an actor-only workload client through `POST /admin/clients`:

```json
{"client_type":"workload","redirect_uris":[]}
```

Then register tenant OIDC trust through `POST /admin/workload-trust`. Supply
the actual runtime's `platform_issuer`, HTTPS `jwks_uri`, specific
`subject_pattern`, current `tenant_id`, unique `binding_id` and that workload
as `mapped_client_id`. Obtain these facts from your workload platform; no
sample private signing key or provider identity is assumed. The console reads
and checks existing trust with your Admin permissions.

Select that actor, the original CLI client and an RS introspection registration
bound to the resource. Copy configuration with `workload_actor` and
`online=true`. Configure the server's RS credential through its secret store.

```bash
npm run pkce
```

The authorization URL includes that actor. On the actual consent page, review
and explicitly approve resource, scopes and actor. Do not patch a Grant or
seed delegation records. Device flow cannot replace this step.

Obtain a fresh platform OIDC JWT for the selected workload. Its audience must
be this a-auth issuer, and its issuer/subject must match the registered trust.
Provide it via a private mode-0600 file referenced by `PLATFORM_TOKEN_FILE`.
Then:

```bash
npm run exchange
A_AUTH_TOKEN_FILE=.delegated.json npm run call
```

Exchange uses the fresh original user's access token and platform actor proof,
not an a-auth access token as actor authentication. It produces no refresh
token and stores the delegated token privately. The final protected call
checks `act.sub` against the selected actor after real RS verification.
For delayed execution, the original client refreshes first; the workload
does not become the refresh-token owner.

## Rejection and revocation checks

Record the command/stage, expected and actual status, elapsed time, and whether
the environment was controlled or a real workload provider. A READY listener
or a successful code redemption is not a completed protected call.

| Trigger | Expected result |
| --- | --- |
| No access token | 401 with PRM discovery challenge |
| Validly signed token with wrong issuer or resource audience | 401 |
| Missing a required scope | 403 |
| Sender-bound token without the supported proof profile | 401 |
| Platform actor outside the explicitly consented Grant | Exchange denied |
| Revoke the Grant through the signed-in user's `/account` | Subsequent refresh/exchange denied; delegated online checks reject |
| AS introspection unavailable | Protected online call fails closed with 503 |

Wrong-issuer/audience/scope tests require appropriately issued or controlled
fixture tokens; changing an unsigned JWT string tests signature rejection
alone. Never forge a provider outcome, write authority records or weaken
issuer/audience/consent checks for interoperability.

The server's offline mode can accept an already issued token until expiry
after revocation. Online checks use the authenticated current issuer and no
positive cache. Neither mode cancels a running business action. Real external
provider/workload interoperability remains a separate #89/provider acceptance.

Credentials and local configuration are ignored by Git. Delete private session,
delegated and platform-token files after testing. Keep sanitized results and
source/artifact digests separately from credentials.
