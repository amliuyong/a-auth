# Resource-server SDK distribution

## Distribution status

Registry release is **NOT_RUN**. The selected npm package is
`@amliuyong/a-auth`, and the selected PyPI project is `a-auth`. Local package
qualification and a successful GitHub source release do not establish a
registry release. Keep Issue #79 open until both registries have verified
receipts.

| Artifact | Version | Runtime | Public entry |
| --- | --- | --- | --- |
| npm `@amliuyong/a-auth` | 1.0.0 | Node.js >=22.14, ESM | `@amliuyong/a-auth` |
| Python wheel / sdist `a-auth` | 1.0.0 | Python >=3.10 | `agent_auth_rs` |

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

After registry receipts exist, independent fixed-version installation is:

```bash
npm install --save-exact @amliuyong/a-auth@1.0.0
python -m pip install a-auth==1.0.0
```

These registry commands currently describe the intended distribution, not a
successful release. Node 22 and Python 3.12 are the release qualification
workflow's selected runtimes; other supported versions require their own
runtime validation when relevant to a deployment.

## Publisher setup and protected release

The selected distributions are npm `@amliuyong/a-auth` and PyPI `a-auth`.
The unscoped npm name `a-auth` belongs to another maintainer. The npm publishing
identity is `amliuyong`; a credential-bearing PyPI upload establishes its actual
permission, not the mere presence of a configuration file.

Configure the release protections before a first publish:

1. Confirm ownership of the npm scope and PyPI project before reserving names
   or publishing. Do not put credentials in source, artifacts or issue comments.
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
   `rs-sdk-v1.0.0` at that exact commit. Dispatch the workflow at that tag:
   `gh workflow run rs-sdk-release.yml --ref rs-sdk-v1.0.0`.

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

当前真实 registry 发布为 **NOT_RUN**；本地打包、独立安装和公开入口验证与
发布验收分开记录。只有 npm/PyPI 的固定版本制品回读、摘要、源提交与安装验证
全部完成，才能更新“已发布”状态并关闭 #79。

## Primary publisher references

- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
  requires npm >=11.5.1 and Node >=22.14.
- [PyPI trusted publisher usage](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
- [PyPI pending publisher setup](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
- [PyPA publishing action](https://github.com/pypa/gh-action-pypi-publish)
