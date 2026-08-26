# Self-Service Login Session Management

Issue #22 adds an account-security surface for browser login sessions. It is
separate from OAuth authorization sessions under `/sessions` and from Grants or
refresh-token families.

## HTTP contract

All endpoints are same-origin, cookie-authenticated account endpoints:

| Method | Path | Behavior |
|---|---|---|
| `GET` | `/account/sessions` | Lists the signed-in user's unexpired login sessions |
| `DELETE` | `/account/sessions/{id}` | Revokes one opaque management handle |
| `DELETE` | `/account/sessions` | Revokes every login session except the current one |

The list returns normalized browser/platform labels and creation, last-used, and
expiry timestamps. It never returns the cookie credential or raw User-Agent.
The `id` is a tenant-bound AES-256-GCM management handle with a random nonce and
cannot be used to authenticate. Its key is domain-separated from the server
secret, and the tenant is authenticated as associated data. This lets the
single-session path recover the primary key without relying on an eventually
consistent GSI while keeping the active cookie credential out of the response.

Single-session revocation is deliberately idempotent. An absent, already
revoked, cross-user, or cross-tenant handle returns the same `204` response and
does not reveal whether the target exists. Revoking the current session also
clears its browser cookie. A DynamoDB transaction verifies that the actor and
target both still belong to the current session generation before deleting the
target, so an actor fenced out by a concurrent revoke-others operation cannot
delete the retained session. Transaction conflicts are retried with bounded
backoff on both revocation paths, and authority is re-read before retrying a
conditional single-session failure. A revoke-others request whose retained
session lost authority concurrently becomes an idempotent no-op.

## Revoke-others authority fence

The Sessions table GSI is eventually consistent, so deleting only the rows
visible in one query could leave a briefly authenticating cookie. Each session
therefore stores a per-user `session_generation`.

`DELETE /account/sessions` atomically advances the user's generation and moves
the retained current session to that generation in one DynamoDB transaction.
Every primary-key session lookup uses a strongly consistent read and accepts the
record only when its generation matches the current user generation. GSI-based
physical deletion is best-effort cleanup; a missed old row is already unable to
authenticate and remains subject to TTL garbage collection.

Legacy rows without `session_generation` are generation zero. Missing
`created_at`, `last_used_at`, or `device` fields fall back to `auth_time`,
`created_at`, and `Unknown device`, respectively.

## Audit and verification

List, single revoke, and revoke-others operations emit
`USER_SESSION_OPERATION` with `tenant`, `actor`, `action`, `target`, `result`,
and `affected`. The in-memory adapter reports an exact revoke-others count;
DynamoDB reports `affected=unknown` because its GSI cleanup is eventually
consistent even though the authority fence is immediate. Cookie credentials are
never logged.

Local verification:

```bash
cargo test -p agent-auth-http --test account_sessions_e2e
cd web
npm run test:e2e -- account-sessions.spec.ts
```

C12.5 conformance uses exact selectors rather than treating either whole file
as proof:

```bash
cargo test -p agent-auth-http --features aws --locked \
  --test account_sessions_e2e \
  list_revoke_and_keep_current_are_private_idempotent_and_audited -- --exact
cargo test -p agent-auth-http --features aws --locked \
  --test account_sessions_e2e \
  revoking_current_session_clears_cookie_and_rejects_next_request -- --exact
./scripts/run_web_conformance_exact_tests.sh
```

The first selector seeds an OAuth authorization session and proves that the
account list contains only browser login sessions. The exact conformance runner
also covers the production Dynamo generation-fence lost-response path.

Deployed Dev verification:

```bash
API_URL=https://<dev-host> STACK=AgentAuthDev \
AWS_PROFILE=default ./e2e/account_sessions.sh
```

For SaaS, use a tenant host and tenant Admin token, set `STACK=AgentAuthSaas`,
and set `EXPECTED_TENANT` to the tenant label. Supplying a second tenant through
`CROSS_TENANT_API_URL` and `CROSS_TENANT_ADMIN_TOKEN` also verifies that replaying
an opaque management handle cannot revoke the source tenant's session.
