# MCP and Vite dependency patches

Issue [#105](https://github.com/amliuyong/a-auth/issues/105) updates the dependencies
flagged by GitHub alerts 60–65 on 2026-10-20.

| Dependency location | Patched lock version | Exposure |
| --- | --- | --- |
| Onboarding example MCP SDK | 1.32.0 | Example client/server runtime |
| TypeScript RS SDK MCP SDK | 1.32.0 | Development and integration tests |
| TypeScript RS SDK Vite | 8.3.4 | Vitest development dependency |
| Web Vite | 7.3.7 | Development/build tool |
| TypeScript RS SDK fast-uri | 3.1.9 | MCP development dependency |
| TypeScript RS SDK qs | 6.16.1 | MCP development dependency |

MCP SDK 1.32.0 fixes
[cross-origin redirect forwarding](https://github.com/advisories/GHSA-6prh-2h8m-c8cw)
and [experimental task session isolation](https://github.com/advisories/GHSA-22jm-h49p-29qw).
The example uses stateless MCP calls and does not enable experimental tasks.
The RS SDK's production dependency remains `jose`; MCP and Vite are development
dependencies of that package.

The redirect regression sends a synthetic custom header and tool argument
between two controlled loopback HTTP origins. Version 1.31.0 forwarded both to
the redirected origin; 1.32.0 rejects the request before that origin receives
any request. The example's `npm test` runs this boundary check in CI without
real credentials, an external issuer or AWS.

The [Vite advisory](https://github.com/advisories/GHSA-698v-4r3x-3vcv) concerns
Windows launch-editor escaping. The patched lock versions meet the published
fixed ranges. Linux build/test results do not reproduce or qualify the Windows
exploit.

The SDK's local audit also identified patched transitive development dependencies:
[fast-uri host normalization](https://github.com/advisories/GHSA-hrr3-gc8f-f4qj),
[qs comma parsing](https://github.com/advisories/GHSA-x5fp-wj9c-mxmx) and
[qs buffer detection](https://github.com/advisories/GHSA-4mjr-xmp4-gh2g).
Their lock updates stay within the existing dependency ranges.

Installed checks on 2026-10-20 passed: 144 SDK tests, 20 Web unit tests,
131 production-browser tests, and 13 controlled TLS checks using MCP 1.32.0
with the previously qualified RS artifact. All three local dependency audits
reported zero known findings. The 18 compiled RS runtime/type files matched
the qualified 1.0.1 artifact byte for byte; package development metadata changed.
Temporary TLS keys and synthetic session files were removed after the fixture.

The [onboarding report](ONBOARDING.md#受控验收记录) retains its original dependency
versions and artifact digest. Patched-client controlled tests provide separate
evidence; no new AWS or real-provider acceptance is implied. Existing SDK release
tags and registry artifacts are immutable. The changed npm development metadata
requires a new qualified patch release under Issue #79 before publication.
