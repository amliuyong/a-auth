# Portable outbound HTTP

`adapters::http_transport` contains the existing OIDC/JWKS, upstream token
exchange, CIBA callback and SSF push implementations shared by AWS and
PostgreSQL deployments. CIMD uses the same pinned HTTPS transport. The
`portable-http` feature enables these adapters and their runtime dispatch
without AWS SDKs. Both `aws` and `postgres` enable this feature.

Production PostgreSQL composition, worker entrypoints and installed enterprise
IdP acceptance remain pending under #142.

## Trust and request bounds

Endpoint values come from registered configuration and existing protocol
trust checks. The adapters retain their existing HTTPS/public-address rules,
including rejection of Lambda Function URLs. Callers must not supply an
unverified JWT `jku`/`x5u` or arbitrary request URL as a trust anchor.

The shared callback transport validates endpoint structure before DNS, checks
the complete bounded DNS answer for public addresses, and pins the HTTPS
connection to that validated answer. Redirects and environment proxies are
disabled. Mixed public/private answers fail closed. CIBA and SSF use this
transport; CIMD applies its existing trust policy and bounded response parser.

OIDC discovery and JWKS use bounded public-document fetching with validated
DNS and a pinned address, no proxy or redirect, a three-second request timeout
and a 64 KiB body limit. JWKS retains its cache capacity, key-count limits,
positive/negative cache and per-URI refresh lock. Concurrent cold fetches or
forced refreshes share one result; failed refreshes preserve existing cached
key authority according to the existing rules.

Upstream OIDC token exchange validates and pins the registered token endpoint,
uses a three-second timeout and bounds the response to 128 KiB. The mounted
client secret reaches only the exchange call. The caller still validates the
returned token's issuer, audience, signature and other OIDC claims.

SSF retains its response semantics: once headers arrive, the HTTP status
remains authoritative even when a response body is malformed, too large or
times out. The worker accepts exactly HTTP 202. Transport errors and SSRF
refusal remain distinct from a received status.

## Build and validation profiles

The existing `transport-test` feature retains its AWS-enabled test behavior.
`portable-transport-test` enables the same test TLS harness without AWS:

```bash
cargo test -p agent-auth-http --no-default-features \
  --features postgres,portable-transport-test --test portable_http --locked
cargo test -p agent-auth-http --no-default-features \
  --features postgres,portable-transport-test --lib \
  cimd::tests::http_transport_pins_tls_and_enforces_redirect_size_and_timeout \
  --locked -- --exact
```

These profiles exercise local transport behavior and runtime availability.
They do not establish deployed protocol conformance, production workers,
runtime egress acceptance or enterprise IdP qualification.
