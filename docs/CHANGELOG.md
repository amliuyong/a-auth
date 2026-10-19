# Changelog

All notable user-facing changes to Agent Auth will be documented in this file.

The project follows [Semantic Versioning](https://semver.org/) after the first
stable release. Until then, minor releases may include breaking changes to
configuration, APIs, deployment resources, or SDKs.

## [Unreleased]

### Added

- Single-transaction agent payment authorization (issue #77), disabled unless
  a payment resource is configured. A payer's client freezes one payment
  intent, the user approves exactly that payment with fresh strong assurance
  for one designated workload, and the workload executes it once through a
  one-hop exchange. The new `agent_auth_payment_v1` RAR profile, the
  `/payments` resource routes and the consent-page payment card are
  documented in [`AGENT_PAYMENT.md`](AGENT_PAYMENT.md). Acceptance uses a
  controlled synthetic channel only; no real payment channel is supported.
- `verifyPaymentAuthorization` (TypeScript) and
  `verify_payment_authorization` (Python) SDK checks for payment execution,
  with shared cross-language terms-digest vectors. Generic RAR enforcement is
  unchanged.
- A 60-second introduction video, linked from an animated preview at the top
  of the README.

### Changed

- New Agent Auth logo for the web UI favicon and the README.

## [1.0.0] - 2026-10-16

### Compatibility

- This is the first stable release. From `1.0.0`, Semantic Versioning covers
  the HTTP API described by `openapi/openapi.json`, including the OAuth 2.1
  and OpenID Connect endpoints it documents, and the public APIs of the
  TypeScript and Python resource-server SDKs.
- Deployment configuration (CDK stack properties, environment variables, and
  deployment topologies) and persisted data formats are outside that
  guarantee. Release notes call out changes to them; follow the linked
  runbooks before upgrading a deployment.
- The OpenAPI document's `info.version` now tracks the release version.

### Added

- EMA policies accept an optional `allowed_actor_subjects` allowlist so ID-JAGs
  that carry a single-level IdP actor, such as Okta Cross App Access agent
  assertions, can be exchanged. The default empty list keeps rejecting `act`;
  issued access tokens remain ordinary user tokens bound to the authenticated
  client and never carry the IdP actor.
- Okta Cross App Access acquisition helpers (`e2e/okta_xaa_login.py`,
  `e2e/okta_xaa_acquire.sh`) for the external EMA acceptance gate.
- Token exchange supports explicitly authorized, bounded same-resource
  delegation and exposes validated `delegation_lineage` through
  introspection. See [`BOUNDED_DELEGATION.md`](BOUNDED_DELEGATION.md).
- Users can authorize a registered workload actor on a Grant through consent,
  and administrators register actor-only workload clients over HTTP. See
  [`WORKLOAD_CONSENT.md`](WORKLOAD_CONSENT.md).
- Recorded sanitized live interoperability evidence from a real Okta SCIM
  directory job (C12.2) and a real Okta Cross App Access ID-JAG exchange
  (C13.8).

### Fixed

- Cached SaaS `/jwks.json` requests keep the managed origin authentication
  headers instead of failing with `403 untrusted_origin`.
- Tenant offboarding no longer makes SaaS administrator requests fail; the
  offboarded owners cannot authenticate, and governance history is retained.
- SaaS user detail stays readable when attribute namespaces are disabled.
- The EMA policy Secret reference now lives in the runtime bootstrap
  configuration document instead of the Lambda environment, so enabling EMA no
  longer pushes the SaaS runtime past the 4 KiB environment limit.

### Security

- Updated rustls to 0.23.46 and patched vulnerable npm dependencies:
  brace-expansion through aws-cdk-lib 2.273.0, js-yaml, source-map-js,
  smol-toml, and katex.
- The external release gate keeps the stable issuer off public run surfaces.
  The issuer is now the `CONFORMANCE_ISSUER` environment secret, dispatch
  takes only `deployment_version`, and issuer-bearing results are sealed in
  an encrypted artifact that operators decrypt before promotion. See
  [`EXTERNAL_CONFORMANCE.md`](EXTERNAL_CONFORMANCE.md#public-run-surface).

### Documentation

- The README now surfaces the current release, enforced conformance evidence,
  external release-gate semantics, and recorded third-party interoperability
  evidence.

### Release status

- This release publishes source archives only; Rust crates and SDK packages
  are not published to external registries.
- Project test results are not certification by the OpenID Foundation or
  another standards body.
- The external release gate passes the OIDF Basic OP code-flow plan with 14
  time-limited, owner-approved exceptions. They cover intentionally
  unsupported optional capabilities (optional scopes and the optional `name`
  claim, unsigned ID tokens, by-value Request Objects, and external
  `request_uri`) and modules whose official result requires screenshot or
  error-page review. Each approval lasts at most 30 days and is renewed
  against fresh evidence.
- FAPI, OpenID Federation, and RFC 9700 certification remain explicit
  non-claims.
- Optional ES256/RS256 pressure routing (C10.15, C10.18) and the claims-tier
  shared-key profile (C10.22b) are not enabled in the published profile.

## [0.5.0] - 2026-08-26

### Added

- First tagged public source release of the Rust OAuth 2.1 and OpenID Connect
  authorization server for agents, workloads, and MCP resource servers.
- AWS CDK deployment for local, self-hosted, and multi-tenant serverless
  topologies, including multi-Region recovery controls.
- React login, consent, account, and administration interfaces.
- TypeScript and Python resource-server SDKs.
- Capability specifications, exact conformance selectors, deployment
  runbooks, security guidance, and automated tests.

### Changed

- Long-running conformance checks now run after merge and on the scheduled
  release path instead of blocking pull requests.
- The README architecture overview now uses a repository-owned SVG with
  explicit trust boundaries and protocol flows.

### Fixed

- Stabilized the standby bootstrap revision so repeated CDK diffs do not
  report spurious Lambda environment changes.
- Made administration client-table columns resizable.
- Stabilized federation mapping mode selection in browser tests.

### Release status

- `0.5.0` is pre-1.0 software under active development. Review the conformance
  matrix, deployment design, and security assumptions before production use.
- Project test results are not certification by the OpenID Foundation or
  another standards body.
- External interoperability validation with Okta SCIM and a third-party
  enterprise IdP remains tracked in GitHub Issues 1 and 2.
- This release publishes source archives only; Rust crates and SDK packages
  are not published to external registries.

## Initial public import - 2026-08-26

- Imported the Rust authorization server, AWS CDK deployment, React
  administration and user interfaces, TypeScript and Python resource-server
  SDKs, capability specifications, conformance inventory, and runbooks into a
  clean public Git history at commit `3b406ce`.

[Unreleased]: https://github.com/amliuyong/a-auth/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/amliuyong/a-auth/compare/v0.5.0...v1.0.0
[0.5.0]: https://github.com/amliuyong/a-auth/releases/tag/v0.5.0
