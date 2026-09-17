# User consent for workload delegation and deferred execution

Issue #52 adds an explicit, single-hop authorization path for applications such
as CoveAI. It uses the existing authorization-code flow, user consent, workload
OIDC authentication and RFC 8693 token exchange. The TypeScript resource-server
SDK remains a verifier/introspection SDK; an exchange client is not added.

## Provisioning and consent

A tenant administrator first registers each workload client and its platform
OIDC trust binding through the existing management APIs. Use distinct client
IDs for `analysis-runtime` and `ops-runtime`. The platform JWT authenticates the
workload; an ordinary a-auth access token cannot authenticate the actor.

The 3LO application includes the optional `workload_actor` parameter in its
`GET /authorize`, form `POST /authorize`, or P3 `POST /par` request:

```text
response_type=code
client_id=coveai
redirect_uri=https://coveai.example/callback
code_challenge=<S256 challenge>
code_challenge_method=S256
scope=openid db:read
resource=https://covedb.example
workload_actor=<registered analysis-runtime client ID>
state=<unpredictable application state>
```

Encode these as application/x-www-form-urlencoded parameters. The extension
requires P2 or later, one nonempty explicit resource, and one exact, active
workload client ID registered in the same tenant. A missing or ordinary client,
wildcard/SPIFFE prefix, empty actor, duplicate actor parameter, absent resource,
or multiple resources is rejected. Exact registered SPIFFE client IDs are
allowed; prefix authorization is outside this interface.

The consent page displays the server-validated workload ID together with the
resource and permissions. Approval explicitly acknowledges that actor, and the
CSRF token binds the entire authorization query. Changing the actor requires a
new context and user approval. An older frontend that cannot acknowledge actor
consent fails closed. `prompt=none` cannot add actor authority; the development
`login_user` shortcut cannot approve it either.

The authorization code persists the approved actor. Code redemption rechecks
its active workload registration, then creates the Grant and refresh family.
Both must persist before this authorization returns credentials. The Grant has
`actor_allowlist=[workload_actor]` and `max_act_chain=1`; the normal `may_act`,
resource, scope, user lifecycle and revocation checks remain in force. The
application cannot request a larger depth. `GET /grants` and `GET /grants/{id}`
expose the actor list and depth alongside the resource and expiry.

Do separate authorizations for the analysis and operations runtimes. An
analysis Grant should contain only the read scopes recognized by CoveDB; an
operations Grant contains the scopes the user agrees to delegate for writes.
a-auth consent grants identity delegation. CoveAI must still enforce approval
of the particular business action, and CoveDB must enforce its current Data
Grants, row policies and transaction conditions at execution time.

## Credentials for an action approved hours or days later

The original 3LO client securely retains its rotating refresh token and, when
applicable, its client-authentication credentials and DPoP private key. Prefer
a confidential backend client for unattended execution. The workload does not
become the refresh-token owner. Do not hand a refresh token to a different
client or use an exchange result as a refresh credential.

1. Complete the user consent and authorization-code exchange for the target
   resource. Ordinary access tokens last 900 seconds. New Grants expire after
   30 days; rotation does not renew that authorization expiry.
2. After business approval, the original 3LO client calls `POST /token` with
   `grant_type=refresh_token`, its current `refresh_token`, the same resource,
   and its registered client authentication. Public clients also identify their
   original `client_id`. DPoP-bound families require a fresh proof from the
   original bound key; there is no bearer downgrade.
3. Persist the returned refresh token atomically. Serialize refresh operations
   per family. Rotation invalidates the preceding version. Only the existing,
   bounded, identical-request grace mechanism can replay a committed rotation;
   other reuse revokes the family. A lost response must be recovered under
   that contract, not retried indefinitely with competing requests.
4. Obtain a fresh platform OIDC JWT for the selected workload, with the a-auth
   issuer as its audience. Exchange the refreshed user access token:

   ```text
   grant_type=urn:ietf:params:oauth:grant-type:token-exchange
   subject_token=<refreshed user access token>
   subject_token_type=urn:ietf:params:oauth:token-type:access_token
   actor_token=<fresh platform OIDC JWT>
   actor_token_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
   resource=https://covedb.example
   scope=db:read
   ```

5. CoveDB verifies its exact issuer and audience and performs authenticated
   online introspection. The delegated token contains the user subject and
   `act.sub=<registered workload client ID>`. It carries no refresh token.

The example above uses a bearer subject token. If the refreshed subject is
DPoP-bound, the exchange request must also prove possession of that **same**
key; a separate worker with only its own DPoP key cannot exchange it. Do not
assume that rotating refresh or possessing the platform JWT permits cross-key
rebinding. Arrange execution through the authorized key holder or require a
new user authorization under the intended supported credential profile.

Revoking the Grant blocks refresh and exchange, and makes existing delegated
tokens inactive under online introspection. Grant expiry, refresh-family
revocation/reuse, user disable/deletion, recovery or credential changes that
invalidate the originating authority also require fresh authorization.
Reenabling a user does not revive the old Grant/family. Removing or retiring
the actor blocks exchange. A login-session logout alone is not a replacement
for Grant revocation. Consult the specific lifecycle endpoint's revocation
scope when implementing a sign-out flow.

The following combinations are rejected:

- An expired original access token used directly as the exchange subject.
- A workload access token used instead of the platform JWT actor proof.
- A DPoP-bound subject presented without its original key proof, or with a
  different worker key.
- An actor absent from the Grant, a different resource, scope widening or a
  second delegation hop from this single-hop Grant.
- A `grant-ref` used as a standalone subject token. The existing grant-ref is a
  short-lived, user-minted, actor-bound **selector** supplied alongside a valid
  user access/ID token; it does not replace subject authentication or provide
  unattended credentials lasting days.

## Migration and rollout

No database edits, backfill, new table or privileged Grant patch is needed.
Existing codes without `workload_actor` create Grants with no actor authority;
existing Grants and families retain their stored constraints. Existing users
must give new explicit consent to authorize a workload. Device and CIBA flows
do not inherit this extension. The new query parameter must not be considered
supported until both backend and frontend are running the delivered revision.

Deploy matching backend and frontend artifacts to every active issuer. Mixed
backend versions can drop a new optional code field and produce unusable
delegation, so finish the rollout before accepting new workload consent. The
new backend requires explicit frontend acknowledgement to prevent old pages
from silently approving an undisplayed actor. The delivery PR pins the
reviewed source SHA and merge SHA for the CoveAI G1 integration record; this
source delivery alone does not establish AgentCore/CoveDB live acceptance.

## Validation

The HTTP acceptance suite creates Grant/family/JTI authority only through the
normal HTTP handlers. Fixtures configure test users, clients, platform trust
and signing keys; they never patch a Grant or JTI to enable exchange.

```bash
source ./scripts/rust_test_stack.sh
cargo test -p agent-auth-http --features aws --test workload_consent_e2e --locked
bash scripts/run_deferred_exchange_test.sh
```

The second command runs one isolated Linux process whose realtime clock
advances by 7,201 seconds after HTTP authorization. Monotonic timers and the
host clock are unchanged. It verifies the original access token has expired,
rejects that token, obtains a new subject using refresh, exchanges it, and
rejects the same path after HTTP Grant revocation. This is deterministic
elapsed-time integration evidence, not a claim that a live cloud deployment
was observed for two hours. CI runs this test explicitly despite its normal
`ignored` annotation.
