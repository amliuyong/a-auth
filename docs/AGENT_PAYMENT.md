# Single-transaction agent payment authorization

Issue #77 adds a contract for letting a user authorize one designated workload
to execute one payment whose content is fixed before consent. The executed
charge must equal the terms the user approved, and concurrent calls or
failure recovery for the same transaction must never start a second charge
attempt.

The design is the a-auth authorization base, a separate payment
authorization module and a payment execution adapter. This delivery
implements and accepts that contract with a **controlled (synthetic)
adapter**. No real payment channel has been selected or tested, and
production payment is **not** supported.

## Scope of the first phase

- One designated workload actor and one delegation hop.
- One payment resource, one currency, a registered funding source and payee.
- One fixed amount per intent, with explicit per-payment user approval.
- Recent, per-payment authorization only. Budgets, recurring payments,
  subscriptions, metered billing, shared budgets, multi-hop payment
  delegation, cross-currency, channel routing, wallets, refunds, chargebacks,
  partial payments and automatic retry attempts are out of scope.

A cumulative budget would need a separate atomic reserve/confirm/release
ledger, and an unknown payment result cannot release budget. It cannot be
added as a field in a token.

## Responsibilities

| Module | Facts and behavior it owns |
|---|---|
| a-auth | Trusted identity, explicit actor consent, admission and display of the payment detail, strong assurance, Grant/token issuance, revocation and online introspection |
| Payment module (`crates/payment`, `crates/http/src/payment`) | Immutable `PaymentIntent`, trusted funding-source and payee references, terms digest, authorization-to-transaction matching, single acceptance, execution state and recovery records |
| Payment execution adapter | Channel credentials, idempotent submission with the persisted key, authoritative query, callback verification, and checking amount, currency and payee against the attempt |

The payment module is a logically separate resource server with its own
audience (`PaymentConfig::resource`) and routes under `/payments`. It shares
this repository and process but no deployment stack. a-auth reads intents only
through the controlled internal interface `payment::consent::admit`, to admit,
display and bind a consent. Nothing on the `/token` path calls the channel or
touches the execution record.

`AppState::payments` is `None` in every deployed runtime of this delivery.
That disables the RAR profile, so `/authorize` rejects payment details, and
every `/payments` route answers `404`. Enabling the module for real requires a
selected channel and adapter, a funding-source/payee registration source, a
provisioned store table, and the channel acceptance described below.

Logging in or holding a Grant does not by itself give a user the right to debit
a bank card or corporate account. The funding-source registry records which
payer subject may use each source. The channel contract must additionally
verify the account authority. Workloads never hold channel keys or payment
secrets.

## Payment intent

`POST /payments/intents` freezes one payment before any authorization is
requested. The caller presents the 3LO client's own user token for the payment
resource with scope `payments:prepare`. That scope never permits execution. A
delegated token cannot prepare. The request body is:

```json
{
  "order_id": "order-2026-0001",
  "actor": "pay-runtime",
  "funding_source_id": "fs_visa_4242",
  "payee_id": "merchant_books",
  "amount_minor": "1999",
  "currency": "USD",
  "execute_before": 1798761600
}
```

Unknown members are rejected. In particular, the request cannot declare the
payer, tenant, client, payee name or fees. Identity comes only from the
trusted context:

- tenant from the request Host;
- payer from the token subject on the payment audience;
- client from the token's `client_id`.

The actor must be an active registered workload in the same tenant.

| Field | Rule |
|---|---|
| `amount_minor` | Decimal string `^[1-9][0-9]{0,17}$` in minor units, never a JSON number, at most `PaymentConfig::max_amount_minor`. It is the total the payment may charge; any fee or amount change needs a new intent and approval |
| `currency` | Must equal the configured currency; `currency_exponent` (0–4) is taken from configuration |
| `execute_before` | Later than now and no further than `max_execute_window_secs` (60–86400). It bounds the **first acceptance**; queries and recovery of an accepted attempt continue after it |
| funding source | Must exist in the registry, be active, be owned by the payer and use the configured currency |
| payee | Must exist in the registry and be active |

The display label of the funding source and the payee name, with their
registry versions, are copied from the registry, never from the agent. A
later registry change does not silently reroute an existing intent. Consent
and execution both require the frozen versions and labels to still be current
and fail otherwise.

The server generates `intent_id` (`pi_` followed by 256 random bits).
Intents are unique per tenant, trusted payee and business order. Preparing the
same order again with identical terms returns the existing intent (`200`).
Any other change returns `409`, including a different client, actor, payer,
amount or deadline. A different token or agent therefore cannot open a
parallel charge for the same order. The order may receive a new intent only
when the previous one expired or was cancelled without ever being accepted. An
accepted or unknown order can never be bypassed with a new intent.

## Canonical terms and digest

`terms_digest` is `base64url_nopad(SHA-256(canonical_bytes))`, 43
characters. The canonical bytes are the domain separator
`agent-auth:payment-terms:v1\0`, followed by each field below written as
`u32_be(len(utf8)) || utf8`:

1. `agent_auth_payment_v1`
2. `intent_id`
3. `tenant` (`default` in the single-tenant form)
4. `payer`
5. `client_id`
6. `actor`
7. `resource`
8. `order_id`
9. `funding_source.id`
10. `funding_source.version`
11. `funding_source.label`
12. `payee.id`
13. `payee.version`
14. `payee.name`
15. `amount_minor`
16. `currency`
17. `currency_exponent`
18. `execute_before`

Integers are written as canonical decimal ASCII. JSON serialization is never
hashed, so member order, whitespace or number formatting cannot change a
digest.

Value rules:

- Identifiers are 1–256 bytes of printable ASCII without spaces.
- `resource` is an absolute `https://` URI of at most 2048 bytes.
- Labels are 1–128 Unicode scalar values with no control characters and no
  leading or trailing whitespace.
- Versions are integers of at least 1.

[`specs/fixtures/agent_auth_payment_v1.json`](../specs/fixtures/agent_auth_payment_v1.json)
contains cross-language vectors: valid terms with their exact canonical
bytes and digest, including multi-byte labels, and invalid terms that every
implementation must reject. The vectors were produced by an independent
implementation. The Rust domain crate and both SDKs check them.

## Authorization profile `agent_auth_payment_v1`

The client requests consent with the authorization-code flow, PKCE, explicit
workload consent and a **reference** to the intent:

```text
response_type=code
client_id=coveai
scope=payments:execute
resource=https://payments.example
workload_actor=pay-runtime
authorization_details=[{"type":"agent_auth_payment_v1","intent_id":"pi_..."}]
```

The reference may also carry `locations: [<payment resource>]` and
`actions: ["execute"]`, and nothing else. `/authorize`, PAR continuations,
`/consent/context` and `/consent/decision` all load the intent and registry
and reject the request unless all of the following hold:

- phase is P2 or later and the payment module is enabled;
- the whole `authorization_details` array is exactly one reference, with no
  generic `agent_auth_rar_v1` entry and no second payment entry;
- `workload_actor` is present, and it equals the intent actor;
- `resource` is exactly the payment resource;
- the client and tenant equal the intent's;
- the intent is intact (its digest matches its terms), `PREPARED` and before
  `execute_before`;
- the frozen registry versions and labels are current;
- at consent, the signed-in user is the payer. The server compares the
  user's subject for the payment audience.

The client never supplies an amount, payee or URL. Unknown types, versions and
members fail closed. The generic `agent_auth_rar_v1` vocabulary is unchanged.

The profile always requires **strong** assurance, whatever the deployment's
`AGENT_AUTH_HIGH_RISK_RAR_ACTIONS` list says. The authentication must be fresh
at the approval itself: a strong authentication older than the strong
`max_age` (300 seconds by default) when the user clicks approve is rejected
with `unmet_authentication_requirements`. Strong assurance proves identity
only; it does not replace confirming the transaction.

Consent is always explicit and per payment. `prompt=none`, existing consent
and the development `login_user` shortcut cannot approve a payment. The
consent context returns a `payment` view with the exact amount, currency,
funding-source label, payee name, order, actor, deadline and digest. The page
states that only this one payment is authorized.

The CSRF token binds the session, the full authorization continuation and the
displayed terms digest. Both approve and deny must echo
`payment_terms_digest`, and approval additionally requires it to equal the
digest recomputed from the current intent. A page that does not acknowledge
the digest therefore cannot approve or deny a payment.

On approval, the authorization code and the Grant store only the server-built
**canonical detail**:

```json
{
  "type": "agent_auth_payment_v1",
  "locations": ["https://payments.example"],
  "actions": ["execute"],
  "intent_id": "pi_...",
  "terms_digest": "<43 characters>",
  "terms": {"tenant": "...", "payer": "...", "client_id": "...", "actor": "...",
            "resource": "...", "order_id": "...",
            "funding_source": {"id": "...", "version": 1, "label": "..."},
            "payee": {"id": "...", "version": 1, "name": "..."},
            "amount_minor": "1999", "currency": "USD", "currency_exponent": 2,
            "execute_before": 1798761600}
}
```

Code redemption, refresh and the first-hop token exchange carry this detail
unchanged. The Grant records `actor_allowlist=[actor]` and `max_act_chain=1`.
The designated workload performs the only exchange, using as the subject the
user's access token for the payment resource that the 3LO client obtained by
code redemption or refresh. A second delegation
hop, or an exchange by another actor, is refused. The payment's one-shot
state lives on the intent, never on a token `jti`, so re-exchange, refresh or
a new consent cannot reset it. A payment token never extends
`execute_before`.

## Interfaces

| Route | Caller | Purpose |
|---|---|---|
| `POST /payments/intents` | Payer's client token, `payments:prepare` | Freeze one intent (`201` new, `200` identical, `409` conflict) |
| `GET /payments/intents/{intent_id}` | Payer's client (`payments:prepare` or `payments:execute`) or the designated actor | Status; another party gets `404` |
| `POST /payments/intents/{intent_id}/cancel` | Payer's client, `payments:prepare` | `PREPARED` → `CANCELLED` |
| `POST /payments/intents/{intent_id}/execute` | Designated actor's delegated token | Accept and submit the single attempt |
| `POST /payments/intents/{intent_id}/reconcile` | Same as `GET` | Recover the persisted attempt; never a new attempt |
| `POST /payments/channel/callback` | Channel, signed `x-payment-signature` | Authenticated result for the persisted attempt |

The internal recovery task calls `payment::recovery::reconcile_intent` or
`reconcile_unsettled` with the persisted record only. Recovery does not need a
user token to remain valid, and it grants no right to start a transaction.
Every response is `Cache-Control: no-store`. Errors are
`{"error", "error_description"}` with Bearer challenges on `401` and
`insufficient_scope`.

### Execute

The request carries no amount, payee or funding source; execution reads the
intent. It performs an authenticated **online** authoritative check through the
same path as `/introspect`, limited to the payment audience and never cached.
That check covers signature, issuer, audience, expiry, Grant status and
expiry, user status and credential epoch, and the delegation lineage. Then it
requires:

- a user token (`sub_type=user`) that is not sender-constrained. A DPoP-bound
  token is refused instead of being downgraded to bearer;
- exactly one delegation hop, whose `act.sub` is the intent actor;
- `sub` equal to the payer, `payments:execute`, and `acr` strong;
- a Grant whose client is the intent client, with `actor_allowlist=[actor]`
  and `max_act_chain=1`;
- an `authorization_details` array that is exactly the one canonical detail
  for this intent, with equal terms and the recomputed digest. A missing
  detail, any additional generic entry, an unknown member or a scope-only
  token is rejected; the generic SDK fallback semantics are never used;
- before the first acceptance: now before `execute_before`, and current
  registry versions.

`execute_before`, Grant expiry and access-token expiry are checked
separately. Only then does a conditional write move the intent from
`PREPARED` to `ACCEPTED`. The write is conditional on the revision, the
status and `execute_before > now`, and it persists:

- the attempt id;
- the channel idempotency key, derived deterministically from the tenant and
  intent with a server-secret HMAC;
- the immutable terms digest;
- the authorization evidence;
- the idempotency retention deadline.

The channel is called only after that write. Concurrent or repeated executes
with a valid authorization return the existing record. They never derive
another key or call the channel again. A lost acceptance response returns
`503`, and the retry returns the persisted attempt. Issuance failures and
lost token responses never trigger a payment.

## Execution states and recovery

```text
PREPARED --valid authorization + conditional acceptance--> ACCEPTED
PREPARED --deadline / payer cancellation--------------> EXPIRED / CANCELLED
ACCEPTED -----------------------------------------------> PENDING / UNKNOWN / SUCCEEDED / FAILED
PENDING / UNKNOWN --authoritative channel result--------> SUCCEEDED / FAILED
```

`PREPARED` only means the terms are frozen. Consent is a separate fact that
execution verifies. There is no stored `approved=true` flag.

- A timeout, dropped connection or temporary 5xx is `UNKNOWN`. A channel that
  accepted but has not settled is `PENDING`.
- Only an authoritative channel report settles an attempt: `SUCCEEDED`, or
  `FAILED` for a definitive decline.
- Expiry and revocation never turn an unknown result into a failure.
- Recovery first queries the channel by the persisted key. Only an
  authoritative "no such transaction" inside the adapter's stated idempotency
  retention window allows resubmission, with the **same** key. Outside the
  window the attempt stays as it is and is flagged `needs_review`; there is
  never a new key. A query that fails changes nothing.
- These cases all recover through the same record: a crash before
  submission, a lost response after submission, and a callback that arrives
  first or more than once.
- Callbacks are verified and must name the persisted idempotency key; their
  transaction, amount, currency and payee must match the attempt.
- Updates are conditional and monotonic:
  - a duplicate callback is a no-op;
  - a late `pending` cannot reopen a final result;
  - contradictory final evidence, or a mismatching amount, currency, payee or
    transaction id, is kept as evidence and marks the attempt `needs_review`
    without changing its status.
- A final failure never creates a second attempt in this phase.

No claim of end-to-end exactly-once is made for arbitrary channels. The
contract relies on the channel's verifiable idempotent submission and query,
within its stated retention window.

## Revocation semantics

The online authoritative check runs immediately before the acceptance write
and is never served from a positive cache. A dependency failure during the
check rejects acceptance with `503`. A revoked or expired Grant, a disabled or
deleted user, or an expired intent cannot be used to accept.

The check and the acceptance are not one cross-system transaction. A
revocation that lands after the check can still meet an accepted attempt. The
attempt records both the check time and the acceptance time. Revocation does
not promise to cancel a charge: an accepted attempt is still queried, and
within the idempotency window resubmitted with its key, until it reaches a
confirmable state. Refunds and channel cancellation are separate business
actions outside this phase.

## Audit and data minimization

The intent record links the Grant, intent, attempt and channel transaction:

- the authorization evidence: Grant id, `SHA-256` of the delegated token's
  `jti`, actor, client, `acr`, `auth_time` and check time;
- the channel transaction id;
- a status history with timestamps and sources;
- every channel observation with its disposition.

It never stores raw tokens, payment secrets or full account numbers.
Funding-source labels are masked registry values. API views never expose the
idempotency key.

## SDK verification

Resource servers that execute payments use the strict verification path, not
`enforceRar` / `enforce_rar`:

- TypeScript: `verifyPaymentAuthorization(claims, {resource, intentId, actor, terms, termsDigest})`,
  plus `paymentTermsDigest` and `paymentTermsCanonicalBytes`.
- Python: `verify_payment_authorization(claims, resource=..., intent_id=..., actor=..., terms=..., terms_digest=...)`,
  plus `payment_terms_digest` and `payment_terms_canonical_bytes`.

Both require:

- an active token for exactly the payment audience;
- `payments:execute`;
- one delegation hop to the actor;
- `sub` equal to the payer;
- exactly one canonical detail with a recomputed digest.

Pass the persisted intent's terms or digest. Use online introspection without
a result cache. Never fall back to the generic RAR evaluation when the check
fails. In the generic path a payment entry remains an unknown type and is
denied.

## Validation

```bash
cargo test -p agent-auth-payment --locked
source ./scripts/rust_test_stack.sh
cargo test -p agent-auth-http --features aws --test payment_e2e --locked
A_AUTH_TEST_DYNAMODB_ENDPOINT=http://127.0.0.1:8000 \
  cargo test -p agent-auth-http --features aws --test payment_e2e --locked \
  payment_dynamodb_attempt_survives_runtime_restart -- --exact --ignored
```

The HTTP suite drives every authorization through the production handlers:

- prepare;
- per-payment strong consent;
- code redemption;
- the one-hop exchange;
- execute and query.

Fixtures configure users, strong authentication sessions, workload trust, the
platform JWKS and the synthetic registry and channel. They never patch a
Grant, code, token or intent to skip authorization. Fault injection in the
memory store and the controlled channel covers:

- lost acceptance responses;
- crashes before submission;
- lost submission responses, timeouts and 5xx responses;
- unreachable queries;
- duplicate, out-of-order, forged and contradictory callbacks.

The DynamoDB test repeats the conditional-write and restart-recovery evidence
against DynamoDB Local. TypeScript and Python SDK tests and the consent-page
Playwright test cover the verification and display contracts.

### Acceptance report

| Scope | Result | Evidence |
|---|---|---|
| Controlled adapter: authorization, execution and recovery contract | PASS | `payment_e2e` HTTP acceptance suite and `crates/payment` unit tests (C14.1–C14.8) |
| DynamoDB conditional writes and restart recovery | PASS (DynamoDB Local) | `payment_dynamodb_attempt_survives_runtime_restart` |
| Real payment channel | **NOT_RUN** | No channel has been selected or tested; production payment is not supported (C14.9) |

Before a real channel is connected, the following are still required:

- account-authority verification for funding sources;
- the channel's idempotency retention and its query and callback contracts;
- a registration source for funding sources and payees;
- a provisioned table;
- channel acceptance cases.

These must be reported separately from the controlled acceptance above.
