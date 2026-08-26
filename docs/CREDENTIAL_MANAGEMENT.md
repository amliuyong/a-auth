# Self-Service Credential Management

Issue #23 completes the credential half of C12.5. The account surface exposes
only user-owned management metadata and keeps authentication material inside
the credential stores.

## HTTP contract

All endpoints are same-origin and authenticated by the browser login session.

| Method | Path | Behavior |
|---|---|---|
| `GET` | `/account/credentials` | Lists passkey metadata, password status, recovery status, and reauthentication freshness |
| `PATCH` | `/account/passkeys/{id}` | Renames one owned passkey |
| `DELETE` | `/account/passkeys/{id}` | Removes one owned passkey when another viable factor remains |
| `PUT` | `/account/password` | Enrolls a first local password or rotates an active one |
| `POST` | `/recovery/generate` | Replaces recovery material and returns the new codes once |

`GET /account/credentials` never returns the WebAuthn credential ID, public
key, sign counter, password hash, recovery-code hash, or any plaintext secret.
Passkeys use a random-nonce AES-256-GCM management handle bound to tenant and
user through authenticated associated data. Password state is reduced to
`not_configured`, `change_required`, or `active`.

## Reauthentication and identity eligibility

Every credential mutation requires a login whose `auth_time` is no more than
300 seconds old. A stale session receives:

```json
{
  "error": "reauthentication_required",
  "max_age": 300,
  "reauthenticate_url": "/login?next=%2Faccount"
}
```

Password enrollment operates only on the active user already named by the
session. It never creates a user or resolves arbitrary request-supplied email.
Only local password-capable identities with a valid email alias are eligible;
unknown, disabled, tombstoned, temporary-password, and federated-only
identities fail closed.

The same endpoint handles first enrollment and active rotation. Passwords use
the existing 12-128 byte policy, bounded Argon2id worker gate, independent
credential table, and version CAS. Reusing the active password is rejected.

## Mutation fence and lockout prevention

Password changes, passkey deletion, and recovery-code rotation first
conditionally advance the strongly read user `credential_epoch` and set
`revocation_pending=true`. The HTTP operation generates a cryptographically
random operation ID and persists it with that pending epoch. An ambiguous
`UpdateItem` response is reconciled by replaying and strongly reading the same
operation ID: the owner receives the already-started epoch, while another
operation cannot claim, complete, or abort the fence. The operation then
atomically consumes the actor session and advances the user's login-session
generation before changing credential material. Password, passkey, recovery,
session, authorization-code, and refresh paths fail closed while the first
fence is pending or when their captured epoch is stale. Exactly one concurrent
sensitive mutation can win.

The credential write and completion of the user fence are one commit:
DynamoDB uses `TransactWriteItems`, while the memory adapter holds the user and
credential locks through the whole update. A concurrent disable or tombstone
therefore either wins first and prevents the credential write, or observes the
already completed credential generation. Passkey registration also conditions
its final write on the active user epoch, current login-session generation,
authoritative session record, expiry, and reauthentication timestamp. A
registration ceremony started before any of those authorities changes cannot
commit afterward.

Administrative password reset participates in the same user authority fence.
Its temporary credential persists the same exact operation owner as the user
fence, is staged only while that owner is pending, and can be resumed without a
second password-version write only after re-establishing that owner. An
ambiguous staging transaction is accepted as committed only when strong reads
match the same user owner and the exact pending password hash and version. If
the transaction or reconciliation reads remain indeterminate, the handler
retains the user owner rather than releasing a possibly committed password
stage. The password and user pending markers are cleared together after
cleanup. A stale Admin retry cannot complete or abort a newer self-service
owner, and a legacy pending password row without an owner remains fail-closed.

Physical session, refresh-family, and grace-entry cleanup is best effort after
the authoritative epoch write. An eventually consistent GSI may omit a stale
row, but that row cannot authenticate because every authority path compares its
captured epoch with the strongly read user. A pending fence abandoned by a
crashed worker can be cleared after a 300-second lease only when its operation
marker exists; recovery conditionally removes that marker and never rolls the
epoch back, so artifacts from before the attempted mutation remain invalid.
Legacy pending rows without an operation marker stay fail-closed rather than
being released without provable ownership.

A final passkey cannot be removed unless at least one of these remains:

- another passkey usable by the current WebAuthn RP;
- an active, non-pending local password;
- an unused recovery code.

The check is enforced by the API and represented in the responsive account UI.
Deletion repeats the check inside the pending user fence. Recovery-code
consumption commits its code update and the same user epoch condition in one
DynamoDB transaction, so a recovery request cannot consume against a stale
pre-deletion snapshot. Concurrent recovery and final-passkey deletion therefore
linearize: recovery either wins before the pending fence and deletion observes
the consumed code, or it runs after deletion at the new epoch and returns an
authoritative session that can bind a replacement factor. Passkey primary-key
and recovery-record reads are strongly consistent; passkey GSI candidates are
confirmed against the primary table to suppress stale deleted rows. Renaming is
owner-scoped and does not expose or rotate credential material.

Passkey login also re-reads the credential after creating its candidate
session, then performs a final user/session authority check. A passkey removed
while an assertion is being verified therefore cannot establish a session in
the post-change generation.

Recovery rotation invalidates the old recovery set, clears the login cookie,
and returns the new plaintext codes with `Cache-Control: no-store`. A session
authenticated only with a recovery code must first have an active password or a
passkey for the current RP; otherwise rotation returns `409
last_viable_factor` without consuming the session or existing recovery codes.
The UI keeps the show-once codes visible after session revocation and until the
user explicitly confirms they were saved.

Successful recovery-code consumption, the user authority advance, the login
session generation advance, and creation of the recovered session share one
atomic commit. An old session, refresh family, or grace response missed by
physical cleanup still cannot authenticate, and a failed session write cannot
consume the user's recovery code.

Recovery-code consumption remains one-time even when the successful HTTP
response is lost. The client generates a canonical 32-byte base64url
`operation_id` and reuses it only for ambiguous retries of that recovery
attempt. The atomic recovery commit also writes a 60-second success result keyed
by a tenant-bound server HMAC of that ID and bound to the presented-code HMAC,
lookup, user, credential epoch, and recovered session. Neither the raw
operation ID nor the plaintext code is persisted.

The same operation and code can therefore recover the same `Set-Cookie`
response while that result and session remain authoritative. A different
operation, tenant, lookup, or code cannot retrieve it. Replay uses the session's
remaining lifetime and never extends it; a missing session, changed authority,
region-ownership change, or expired result returns the normal consumed-code
rejection. Recovery notification delivery is idempotent per operation, and
replay resumes best-effort cleanup without advancing `last_login_at`.

## Audit and verification

Credential operations emit tenant-scoped `USER_CREDENTIAL_OPERATION` events
with actor, action, kind, target, and result. Passwords, hashes, WebAuthn
credential IDs, public keys, and recovery-code storage values are excluded.

Local verification:

```bash
cargo test -p agent-auth-http --test account_credentials_e2e
cargo test -p agent-auth-http --test recovery_e2e
cd web
npm run test:e2e -- account-credentials.spec.ts
```

C12.5 conformance registers exact selectors for the account summary, the
uniform 300-second reauthentication gate, password lifecycle, passkey
management, last-factor races, passkey registration begin/finish, adapter
ownership fences, and the corresponding browser controls. Run the registered
set with:

```bash
./scripts/run_conformance_exact_tests.sh
./scripts/run_web_conformance_exact_tests.sh
python3 -m unittest scripts.tests.test_conformance_evidence_map
```

In particular,
`all_credential_mutations_require_recent_reauthentication` covers passkey
rename/delete, password set, and recovery rotation at the public HTTP boundary;
`passkey_registration_begin_and_finish_require_recent_reauthentication` proves
the registration challenge is not consumed by a stale finish.

Deployed verification:

```bash
API_URL=https://<host> STACK=AgentAuthDev \
USERS_TABLE=<name> PASSWORD_TABLE=<name> SESSION_TABLE=<name> \
PASSKEY_TABLE=<name> RECOVERY_TABLE=<name> MESSAGES_TABLE=<name> \
AWS_PROFILE=default ./e2e/account_credentials.sh
```

The live DynamoDB authority-race test invokes the production AWS adapters
directly and is opt-in because it writes disposable rows:

```bash
AGENT_AUTH_LIVE_DYNAMO_RACES=1 AWS_PROFILE=default AWS_REGION=us-east-1 \
USERS_TABLE=<name> SESSIONS_TABLE=<name> PASSWORD_TABLE=<name> \
PASSKEY_TABLE=<name> RECOVERY_TABLE=<name> \
cargo test -p agent-auth-http --features aws --lib \
  adapters::aws::live_credential_authority_tests -- --ignored
```

The same script accepts a SaaS tenant host and tenant Admin token. It exercises
the deployed HTTP handlers and DynamoDB adapters, including passwordless
first enrollment, stale-auth denial, session fencing, show-once recovery
rotation, recovery-only lockout prevention, passkey redaction/rename/delete,
and active password rotation.

The 2026-07-30 deployed runs are retained as historical environment context.
They are not registered as current C12.5 recorded references and do not replace
the exact repository selectors above.
