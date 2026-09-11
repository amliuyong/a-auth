# Bounded delegation and online lineage

Issue #45 defines the following authorization and recovery contract.

- A registered, authenticated workload may exchange a user's token only under
  an active Grant. Default depth remains one; explicit Grants can permit up to
  eight actors.
- Every issued delegated token has a durable, tenant-partitioned JTI authority
  record, bound to the exact signed token by SHA-256. It records its parent,
  canonical subject binding, original authorization, selected Grant, resource,
  scopes, expiry and delegation constraints. No raw ancestor token is stored.
  The success response is withheld unless persistence and final authority
  checks succeed.
- A delegated subject can be exchanged only for the same resource and selected
  Grant. Omitted or empty scope inherits the parent scopes. Explicit scopes
  must be subsets of the parent and current Grant. Ancestor allowlists and
  depth limits continue to constrain descendants even if a Grant is widened.
  Cross-resource projection, `grant_ref`, RAR, PoP and network-restricted Grants on a subsequent hop are
  unsupported and rejected. First-hop grant-ref, RAR and DPoP remain supported.
- Child expiry is the minimum of the ordinary access-token expiry, parent
  token/mapping expiry and every governing Grant expiry. Expiry is exclusive:
  `now >= expires_at` is inactive, regardless of DynamoDB TTL garbage collection.
- Online exchange and authenticated RS introspection validate the stored chain,
  all governing Grants, user lifecycle/password authority and actor clients.
  Removing an ancestor, revoking its authorization, narrowing a constraint or
  losing authority storage prevents new exchange and new RS admission.
  Changes to network/RAR constraints invalidate the affected chain.
- The original OAuth client may submit a delegated access token to `POST
  /revoke` using its registered client authentication. Revocation is idempotent
  and keeps an immutable ancestor pointer plus a monotonic revoked flag.
  Revoking A invalidates A and all its descendants; a sibling remains valid.
  Unknown or another client's token remains an RFC 7009 success no-op.
  Storage failures return 503. Ordinary nondelegated access-token revocation
  retains the existing behavior.
- Introspection adds a versioned `delegation_lineage` object only after successful
  authority validation. `subject` is the resource-specific token subject;
  `actors` is oldest-first, while RFC 8693 `act` remains newest-first.
  Each hop identifies its authorization, effective scope and expiry.
  The result describes validity at `checked_at`; consumers must authenticate
  introspection, validate issuer/resource and avoid positive caching when
  immediate revocation is required.
- Existing delegated tokens without authority records remain usable only under
  their former offline JWT contract until expiry; online introspection and
  further exchange reject them. Root JTI rows need no backfill. DynamoDB stores
  the optional versioned record in the existing JTI table and uses strongly
  consistent regional reads. Delegation rows use a separate `delegation-v1`
  key prefix so older AS instances cannot load them as unconstrained root
  mappings. Memory storage remains a development adapter. Roll out all AS
  instances together; old writers do not produce usable lineage.
- No authorization result cancels an already running consumer operation.
  CoveDB retains its own Data Grants, execution cancellation and downstream
  credentials. Its current multi-actor rejection must remain until the pinned
  consumer integration passes real positive and negative acceptance cases.

Implementation validation and measured propagation evidence are recorded with
the delivery PR. Local HTTP/adapter results do not claim a cloud deployment.

## Resource server response

The following extension accompanies the normal `active`, `iss`, `sub`, `aud`,
`scope`, `client_id` and `act` fields. It is returned only by authenticated,
resource-bound introspection and is not a caller-supplied authorization grant.

```json
{
  "delegation_lineage": {
    "version": 1,
    "issuer": "https://auth.example.com",
    "subject": "resource-specific-user-subject",
    "resource": "https://mcp.example.com",
    "current_actor": "agent-b",
    "actors": ["agent-a", "agent-b"],
    "source_grant": "root-grant",
    "checked_at": 1800000000,
    "hops": [
      {
        "jti": "delegation-a",
        "parent_jti": "user-token",
        "actor": "agent-a",
        "auth_grant": "root-grant",
        "resource": "https://mcp.example.com",
        "scope": ["read"],
        "expires_at": 1800000060
      },
      {
        "jti": "delegation-b",
        "parent_jti": "delegation-a",
        "actor": "agent-b",
        "auth_grant": "root-grant",
        "resource": "https://mcp.example.com",
        "scope": ["read"],
        "expires_at": 1800000060
      }
    ]
  }
}
```

The current actor and effective permissions remain the token's top-level
authorization context. Nested RFC 8693 actors are provenance; the new extension
reports the AS's independent validation of the stored delegation constraints.
RSs must require a recognized version, matching issuer/subject/resource/current
actor, connected hop JTIs and an unexpired result. Use only the last hop's
effective scope, intersected with local Data Grants. Never union hop scopes.
An absent or unknown extension cannot authorize multi-actor admission.
Inactive responses contain only `{"active":false}`; authority errors are 5xx
and must not fall back to offline acceptance. TS/Python SDK raw `claims` retain
the additive extension.

## Migration and validation

No table, index or backfill is required. Existing JTI TTL and subject/tenant
erasure scans cover the new rows. Delegation records are immutable except for
monotonic revocation; expiry and revocation are checked on every online request.
Root tokens retain their existing JTI format. Legacy delegated tokens have no
recoverable record, so exchange and online introspection reject them; clients
obtain new tokens. Rolling back to an old AS also loses online lineage support.
Deployments using the Rust ports directly must initialize `JtiRecord.delegation`
to `None` on root tokens and implement `JtiStore::revoke_delegation`.

CI starts a pinned local DynamoDB container, runs real TCP `/token`,
`/introspect` and `/revoke` requests, recreates the HTTP runtime and production
JTI adapter between hops, and verifies tenant partitioning, the legacy key
boundary, revocation and store unavailability. Other authoritative stores and
signing keys are test adapters that remain available across the runtime restart.
This validates recovery of delegated JTI authority, not AWS disaster recovery.

Run the same recovery test against a local emulator:

```bash
export A_AUTH_TEST_DYNAMODB_ENDPOINT=http://127.0.0.1:8000
source ./scripts/rust_test_stack.sh
cargo test -p agent-auth-http --features aws --test workload_e2e --locked \
  multi_hop_dynamodb_authority_survives_runtime_restart -- --exact --ignored --nocapture
```

The PR's merge SHA is the consumer pin. CoveDB's upgrade must update its
introspection adapter to require this contract and independently rerun positive
and negative multi-hop cases before removing its existing rejection.
