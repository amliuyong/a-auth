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

## November 2026 backlog review

The compatible updates proposed by PRs #138, #144, #145, #146 and #147 retain
the existing public SDK versions and production dependency ranges:

| Dependency location | Updated lock version | Exposure |
| --- | --- | --- |
| Python RS SDK setuptools | 84.1.0 | Hashed build/test dependency |
| MCP-auth example body-parser | 2.4.0 | Express runtime dependency |
| Onboarding example body-parser | 2.4.0 | Example runtime dependency |
| TypeScript RS SDK Vitest and mocker | 4.1.12 | Development/test dependency |
| TypeScript RS SDK Hono Node server | 2.1.6 | MCP development dependency |

PR #139 proposes `mcp-auth` 1.0.0-beta.1, whose MCP 2 peer dependency and
configuration API break the former MCP 1 example. Issue #148 migrates the
example to that prerelease and official MCP server 2.4.0, Express adapter 2.0.2
and Node adapter 2.1.2. It updates the metadata checker to the library's current
API and retains exact issuer/resource verification, required scope and rejection
of every verified token carrying `cnf`.

The old library depends on Zod 3, which is affected by
[GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5)
without a Zod 3 fix. Both the migrated example and SDK development lock now use
Zod 4.6.7. The SDK also updates body-parser to 2.4.0 and ip-address to 10.7.6
within their existing ranges, addressing
[GHSA-27r3-jxmh-p828](https://github.com/advisories/GHSA-27r3-jxmh-p828) and
[GHSA-rxp7-6hxx-x8q5](https://github.com/advisories/GHSA-rxp7-6hxx-x8q5).
Their complete installed audits, including development dependencies, report
zero known advisories.

A controlled loopback TLS test uses the actual migrated middleware, discovery,
JWKS and signed JWT verification. It accepts a protected fixed tool call over
the SDK's stateless 2025-protocol fallback and rejects a wrong issuer, audience,
signature, expiry, missing expiry, empty subject, missing required scope and
sender-bound claims. It also tests successful provider metadata checking and
rejection of a provider lacking S256. This qualifies that boundary; the dated
MCP client/AS refresh results in [MCP interop](MCP_INTEROP.md) continue to name
their original versions.

The official
[braces advisory GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
was withdrawn on 2026-10-23 because it is not practically exploitable.
On 2026-11-08, the unchanged root lockfile's `npm audit --include=dev`
reported zero known advisories. This is an advisory withdrawal, not a patched
braces release: the locked version remains 3.0.3 and no downgrade, vendor patch
or audit suppression was applied. Issue #111 can therefore close with that
recorded disposition. Historical v1.1.0 audit results remain historical evidence.

Markdown lint continues to use the existing rules. The operator's untracked
`work/` evidence directory is excluded from repository documentation scans;
tracked source documents remain in scope.
