# OIDC email scope decision

Decision for [Issue #87](https://github.com/amliuyong/a-auth/issues/87),
2026-10-20: **continue without a built-in OIDC `email` disclosure scope**.
Preserve the existing pairwise privacy boundary and the bounded Basic OP waiver
rationale. Reducing two waiver bindings alone does not justify adding identity
disclosure without verified-email provenance, client policy and explicit consent.
This decision introduces no discovery, token, userinfo, client or storage change.

## Source evidence and tradeoff

Inspected source:
`58e1f290c5e56f711b29058599e1bdb7643d6011`.

| Current fact | Evidence and consequence |
| --- | --- |
| SaaS defaults to pairwise subjects unless explicitly configured otherwise | [Tenant subject resolution](https://github.com/amliuyong/a-auth/blob/58e1f290c5e56f711b29058599e1bdb7643d6011/crates/http/src/state.rs#L4353); a shared email can reconnect identities across unrelated clients or resources |
| UserRecord holds normalized email but no verification-source record | [UserRecord](https://github.com/amliuyong/a-auth/blob/58e1f290c5e56f711b29058599e1bdb7643d6011/crates/http/src/ports.rs#L1484); the presence of an email cannot establish `email_verified=true` |
| `/userinfo` returns the verified token subject | [Userinfo implementation](https://github.com/amliuyong/a-auth/blob/58e1f290c5e56f711b29058599e1bdb7643d6011/crates/http/src/userinfo.rs); it does not fetch an email or infer one from a pairwise subject |
| Discovery advertises the actual existing standard claims, without `scopes_supported` | [Metadata implementation](https://github.com/amliuyong/a-auth/blob/58e1f290c5e56f711b29058599e1bdb7643d6011/crates/discovery/src/metadata.rs#L231); an unsupported optional scope must not be advertised as implemented |
| The approved exception file contains 14 bindings through 2026-11-15 | [Exceptions](../.github/conformance/exceptions.json) and [#67](https://github.com/amliuyong/a-auth/issues/67); a design decision neither renews approval nor turns a skipped module into a pass |

Supporting `email` could improve standard-client convenience and remove
`oidcc-scope-email` and `oidcc-alternate-happy-flow` from the exception set after
real PASSED evidence. Issue #87 identifies those two potential improvements;
it does not establish that either module has passed on a new implementation.
`profile`, `phone`, `address`, `scope-all` and `claims-essential` remain outside
that proposed email work.

The cost is an additional identity-correlation channel, policy and consent
surface, provenance/migration model and lifecycle-sensitive userinfo lookup.
The issue and delivery request contain no confirmed consumer requiring that
disclosure. An existing directory or Admin ability to see an email is a different
authorization boundary; it does not grant ordinary OAuth clients disclosure.
Likewise, a consumer-defined resource scope named `email` does not itself enable
standard OIDC identity claims.

## Verification-source rules for any future proposal

These rules describe prerequisites, not implemented fields or claim behavior:

| Source | Acceptable verification assertion |
| --- | --- |
| Stored normalized email | No verification inference; no placeholder `true` |
| Admin-created or SCIM-provisioned email | Unverified unless a separate authorized proof establishes control of the exact address |
| Magic-link authentication | Consider verified only with durable evidence of successful, bound proof for the exact tenant/user/address and its current revision |
| Upstream federation | Require a verified assertion from explicitly trusted issuer/client/flow plus an approved mapping; an arbitrary `email_verified` field is insufficient |
| Email change, incompatible linking or stale provenance | Do not reuse the previous address's verification proof |

Unknown verification is never `true`. A future design must specify the
difference between unknown and known-unverified state rather than filling in a
value merely to satisfy a conformance module. Email disclosure also needs a
real, current address from its authorized source; a syntactically plausible
test value is not evidence.

If a verified consumer requirement reopens the work, require per-client
default-off policy, explicit email scope consent and visible disclosure
wording. Return `email` and truthful `email_verified` only from userinfo for an
authorized client and active scope/Grant/user binding. Preserve the code-flow
ID token's existing minimal identity claims.

The implementation proposal must cover client opt-out, scope absence, expired
or revoked authority, Disabled/Tombstoned users, incorrect tenant/issuer,
address changes and provenance races. It must not derive a canonical identity
by interpreting a pairwise subject or reuse an older token as proof of current
email authority. Migrate legacy email rows without inventing verification.

## Conformance and closure boundary

Keep the existing two rationales:

- `oidcc-scope-email`: the optional email scope is not advertised; the module
  is SKIPPED.
- `oidcc-alternate-happy-flow`: the flow depends on optional email scope;
  the module is SKIPPED.

The current file's approval expires at `2026-11-15T00:00:00Z`. The operator must
use the existing [external conformance process](EXTERNAL_CONFORMANCE.md) for
fresh binding-matched evidence and explicit time-bounded renewal when needed.
This assessment changes no approval, expiry, binding, exception digest, exact
selector or conformance count, and does not close #67.

For the selected non-support decision, email implementation tests, revised
discovery contracts and the two new official PASSED outcomes are
**NOT_APPLICABLE_TO_THIS_DECISION**, not PASS. A new external OIDF run is
**NOT_RUN**. Existing runtime/protocol claims remain governed by their own
issuer/deployment-bound evidence.

If support is reconsidered, first define the provenance and client/consent
contract, then implement and validate both discovery metadata surfaces,
userinfo/lifecycle/privacy cases and the fixed evidence pins. Deploy the
reviewed source and obtain actual PASSED outcomes for both official modules
before removing only those two waiver bindings. No local mock, hosted CI
waiver or document merge substitutes for that acceptance.
