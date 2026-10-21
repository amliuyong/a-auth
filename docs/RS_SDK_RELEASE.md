# Resource-server SDK distribution

## Distribution status

Registry release **1.0.2 is published and verified** on npm and PyPI.
The public npm tarball, Python wheel and sdist match the qualified digests.
Separate clean projects installed each production-registry distribution and
passed 6 protected HTTP, 3 RAR and 4 DPoP checks per install.
The clean qualification includes the [MCP security patch](DEPENDENCY_PATCHES.md).
Existing 1.0.1 tags, artifacts and PyPI uploads remain historical.
The dated [1.0.2 publication record](releases/rs-sdk-1.0.2.json) binds
qualification, registry bytes and installation results to the exact source.

| Artifact | Version | Runtime | Public entry |
| --- | --- | --- | --- |
| npm `agent_auth_rs` | 1.0.2 (published, verified) | Node.js >=22.14, ESM | `agent_auth_rs` |
| Python wheel / sdist `agent_auth_rs` | 1.0.2 (published, verified) | Python >=3.10 | `agent_auth_rs` |

Both registries use the same unscoped SDK name without a personal prefix.
Python's distribution-name normalization treats `agent_auth_rs`,
`agent-auth-rs` and `agent.auth.rs` as the same project; Python imports remain
`agent_auth_rs`. PyPI displays
[`agent-auth-rs`](https://pypi.org/project/agent-auth-rs/1.0.2/);
registry verification uses PEP503 canonical identity while preserving exact
version, filenames and distribution digests.

The immutable
[`rs-sdk-v1.0.2`](https://github.com/amliuyong/a-auth/tree/rs-sdk-v1.0.2)
tag points to clean qualified source `3ad529fbc7e46fa6e79446b2fee51a768ce41d9d`,
reviewed and merged in [PR #114](https://github.com/amliuyong/a-auth/pull/114).
PyPI upload completed at 22:06 UTC on 2026-10-20. Initial JSON API readback
returned 404 while the public installation index already listed both files;
subsequent production JSON metadata and downloaded bytes matched qualification.
No repeat upload was required. Separate clean projects installed the wheel and
sdist from PyPI; each passed 6 protected HTTP, 3 RAR and 4 DPoP checks.
This owner-authorized bootstrap has no OIDC provenance attestation.

npm upload completed on 2026-10-21 after the owner authenticated in the
official npm browser flow on their Mac. No private security key was shared.
Initial readback returned 404 and the package page displayed the staged
placeholder `0.0.0-stage`; later public metadata resolved to `1.0.2`, with
`latest` pointing to that version. The tarball SHA-256 and `gitHead` match the
qualified source. No repeat upload or recovery code was used.
The public-installed [onboarding example](ONBOARDING.md) additionally passed
13 controlled TLS/MCP checks with MCP SDK 1.32.0.

The historical immutable
[`rs-sdk-v1.0.1`](https://github.com/amliuyong/a-auth/tree/rs-sdk-v1.0.1)
tag points to source `0c461abca125893b3133bf82d2af1d138589b966`,
reviewed and merged in [PR #94](https://github.com/amliuyong/a-auth/pull/94).
Its first literal-name comparison failed after upload; canonical readback
resolved Python distribution-name normalization without another upload.
The existing `rs-sdk-v1.0.0` source tag is immutable. Its
earlier selected names were not published: npm required additional 2FA, and
PyPI rejected `a-auth` as too similar to an existing project.

The package metadata now agrees with the repository's existing Apache-2.0
LICENSE. Both distributions carry the exact license text and direct runtime
dependency notices. The previous MIT metadata had no corresponding SDK license
grant. No verification API or token protocol changed.

## Independent installation and validation

Use Python 3.11+ for the qualification command. Build tools belong in a
disposable environment:

```bash
python3 -m venv /tmp/a-auth-sdk-build
/tmp/a-auth-sdk-build/bin/python -m pip install 'build>=1.2' 'twine>=6'
python3 scripts/qualify_rs_sdk_release.py \
  --build-python /tmp/a-auth-sdk-build/bin/python \
  --output /tmp/a-auth-sdk-artifacts
```

The output directory must be empty. The qualification command builds the npm
tarball, Python wheel and source distribution, checks metadata/file allowlists,
license bytes and notices, then installs each artifact into an independent
temporary project. It imports only public package entries, serves a protected
HTTP resource, and verifies valid access plus missing token, wrong issuer,
wrong audience, missing scope and offline grant-backed RAR rejection.

Installed-artifact checks also exercise RAR bounds/unknown types and independent
DPoP method/key/access-token binding. DPoP enforcement and replay caching remain
the resource server's responsibility. The installed SDK obtains no OAuth
credentials and does not automatically refresh or exchange tokens.

`qualification.json` records the source SHA, dirty-source flag, runtime
dependency versions, exact artifact SHA-256 digests and check results.
`SHA256SUMS` covers the three distributable files. A local dirty-source run is
useful during development but cannot qualify a registry release. Source-tree
SDK suites remain separate evidence.

Install the local artifacts into your application using the commands and
minimal verification examples in [TypeScript README](../sdk/ts/README.md) or
[Python README](../sdk/python/README.md). Do not import a workspace path.

Fixed-version registry installation commands are:

```bash
npm install --save-exact agent_auth_rs@1.0.2
python -m pip install agent_auth_rs==1.0.2
```

Both commands are verified against their production registries, with separate
Python wheel and sdist installs.
Node 22 and Python 3.12 are the
release qualification
workflow's selected runtimes; other supported versions require their own
runtime validation when relevant to a deployment.

## Publisher setup and protected release

The selected distributions are npm and PyPI `agent_auth_rs`. The npm publishing
identity is `amliuyong`; a credential-bearing PyPI upload establishes its actual
permission, not the mere presence of a configuration file.

Configure the release protections before a first publish:

1. Confirm the npm publishing identity and permission for the selected name,
   and the PyPI project permission before publishing. A registry 404 only
   establishes that there is no current public project; it does not guarantee
   that a registry will accept or grant the name. Do not put credentials in
   source, artifacts or issue comments.
2. Configure GitHub environments `rs-sdk-npm-release` and
   `rs-sdk-pypi-release`: restrict deployments to tags matching `rs-sdk-v*`.
   A repository with multiple release owners can additionally require an
   independent environment reviewer. The current repository has one owner;
   release protection uses the reviewed merge, restricted environments and
   immutable tags. Protect these release
   tags against updates and deletion through the repository's tag rules.
3. Configure npm trusted publishing for `amliuyong/a-auth`, workflow
   `rs-sdk-release.yml`, environment `rs-sdk-npm-release`. npm setup requires an
   existing package; a first release may need an owner-authorized bootstrap
   publish before configuring OIDC. That bootstrap must use the same clean
   qualified tarball, source identity and registry readback.
4. Configure a PyPI trusted or pending publisher with that repository/workflow
   and environment `rs-sdk-pypi-release`. A pending publisher supports a new
   project. Do not treat TestPyPI as a production PyPI release.
5. Merge reviewed release tooling, qualify a clean main commit, and create
   `rs-sdk-v1.0.2` at that exact commit. Dispatch the workflow at that tag:
   `gh workflow run rs-sdk-release.yml --ref rs-sdk-v1.0.2`.

The workflow checks that the tag matches both package versions, its source is
on main, and both actual GitHub environments have the required protections.
It fails closed if these prerequisites are missing. Build/install tests require
clean committed source and run without OIDC write permission. Separate publishing jobs receive only
their needed `id-token: write` permission and publish the already qualified
artifacts, with npm provenance and PyPI attestations. Actions use immutable
commit references. No standing registry token is stored by this workflow.

For an owner-authorized first release before trusted publishing is configured,
use `scripts/publish_rs_sdk_bootstrap.py`. It requires a clean qualified source
commit already merged into main, the exact tag present locally and remotely,
actual environment/tag protections, and unchanged artifact digests. It reads
the owner-provided credential file at runtime and never saves that credential
in the repository or workflow. The script must run with a Python environment
containing Twine for a PyPI upload:

```bash
/tmp/a-auth-sdk-build/bin/python scripts/publish_rs_sdk_bootstrap.py npm \
  --qualified /tmp/a-auth-sdk-artifacts --credentials ~/.npm_token \
  --receipt /tmp/npm-release.json
/tmp/a-auth-sdk-build/bin/python scripts/publish_rs_sdk_bootstrap.py pypi \
  --qualified /tmp/a-auth-sdk-artifacts --credentials /secure/path/.pypirc \
  --receipt /tmp/pypi-release.json
```

It verifies the npm publisher's identity and permission before upload. A new
personal scope must match that identity. Existing versions are never overwritten:
their registry bytes must match the retained qualification before recovery can
continue. A partial PyPI upload resumes only its missing, already-qualified
distribution. An ambiguous upload leaves `UNKNOWN_PENDING_READBACK`; inspect
the real registry before retrying. Successful upload is followed by the same
registry digest verifier used by the OIDC jobs. Bootstrap publication has no
OIDC provenance attestation; its receipt binds bytes to the immutable tag and
source commit instead.

The npm credential file must be an owned regular file with no group/other
permissions (for example, mode 0600). It may contain a raw `npm_...` token or
one labelled `token=`, `npm_token=`, `node_auth_token=` or `_authtoken=` entry.
Blank lines and comments are allowed. An optional `recovery_code=` entry is
ignored and never returned or forwarded to publishing. Account recovery codes
are not publish OTPs. Unknown entries, multiple tokens, invalid token format,
symlinks, oversized files and file replacement are rejected before registry
authentication. Keep credential and account material out of release evidence.

Each publishing job downloads and checks the exact qualified digests, publishes,
then reads registry metadata and all distribution bytes back over HTTPS.
`verify_rs_sdk_registry.py` compares SHA-256 with the installed artifacts,
checks fixed version identity, and verifies npm `gitHead`. Each receipt binds
registry/version/digests to the commit, release tag and workflow run.

An upload without successful readback is incomplete. If one registry succeeds
and the other fails, retain that partial receipt and rerun only the failed job
against the same retained qualified artifact. Do not overwrite an existing
version or silently rebuild a different artifact under the same version.
The two package registries do not provide an atomic cross-registry transaction.

After both receipts pass, read back and install the registry distributions in
clean projects, retain the installed checks and registry receipts, update the
README distribution status with the exact version/tag/run links, and close #79.
Hosted CI remains separate from registry publication and runtime acceptance.

## Compatibility and upgrades

The existing 1.x public API uses SemVer. Pin a version, record the resolved
dependencies, and run your protected-resource tests when upgrading. This release
adds packaging and publishing tooling, README/license/notices, Python typing
metadata, and an explicit Node runtime floor. It adds no OAuth client SDK.

Configure the exact issuer and resource identifier. The SDK validates public
JWKS/signature/expiry/audience and applies route policies; it consumes issued
pairwise subjects without deriving identities. RAR narrows access. Grant-backed
RAR requires authenticated introspection. Offline JWT verification can remain
valid until expiry after revocation and cannot cancel a running business call.

当前 1.0.2 的 npm/PyPI 发布、固定版本制品回读及三个独立安装均为 **PASS**。
本地打包验证与各 registry 的发布验收分开记录。源提交/tag、公开制品摘要与
安装验证已完成 #79 的分发验收。跳过的 exact selectors 不计 PASS；
postmerge main CI 为 WAIVED_BY_REQUESTER_NOT_PASS。

## Primary publisher references

- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
  requires npm >=11.5.1 and Node >=22.14.
- [npm staged publishing](https://docs.npmjs.com/staged-publishing/)
  explains the `0.0.0-stage` placeholder for a new staged package.
- [PyPI trusted publisher usage](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
- [PyPI pending publisher setup](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
- [PyPA publishing action](https://github.com/pypa/gh-action-pypi-publish)
