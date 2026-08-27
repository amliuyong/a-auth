# Changelog

All notable user-facing changes to Agent Auth will be documented in this file.

The project follows [Semantic Versioning](https://semver.org/) after the first
stable release. Until then, minor releases may include breaking changes to
configuration, APIs, deployment resources, or SDKs.

## [Unreleased]

### Documentation

- The README now surfaces the current release, enforced conformance evidence,
  external release-gate semantics, and outstanding third-party
  interoperability work.

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

[Unreleased]: https://github.com/amliuyong/a-auth/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/amliuyong/a-auth/releases/tag/v0.5.0
