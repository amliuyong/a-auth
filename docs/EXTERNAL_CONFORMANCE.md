# External OAuth/OIDC conformance release gate

This document is the operational contract for Issue #27 and C12.8. The gate
combines two deliberately separate sources of evidence:

1. the official OpenID Foundation `oidcc-basic-certification-test-plan`; and
2. agent-auth-owned black-box regression probes for selected RFC 9700
   requirements.

The second item is not an OIDF suite and does not establish blanket OAuth
Security BCP certification. Passing the first item means the selected Basic OP
plan passed under the recorded suite version and variants. It does not make the
deployment "OpenID Certified" without the separate OIDF certification process.
Each project probe records a credential-free request summary, expected
behavior, applicability, and sanitized observed status/error. Client secrets,
registration tokens, authorization headers, and response bodies are never
written to the project result.

## Fixed OIDF contract

The workflow downloads the official runner at:

- ref: `release-v5.2.1`
- commit: `932b46f1e507871eb0b34621aaef65ff04442e6f`

It invokes the exact plan:

```text
oidcc-basic-certification-test-plan
[server_metadata=discovery]
[client_registration=dynamic_client]
```

Discovery and executable endpoint behavior are therefore exercised together.
The gate rejects another plan, static metadata, static client registration,
mixed suite versions, omitted plan modules, non-terminal modules, and any
result other than `PASSED` unless the exact failed test has an active approved
exception. An interrupted or otherwise incomplete module is an error and
cannot be waived.

Every JSON export member must have a matching OIDF `SHA256withRSA` signature.
The converter fetches the signing JWKS from the fixed suite origin, verifies
each member, and rejects missing, orphaned, malformed, or invalid signatures.
Every member's `exportedFrom` must be exactly
`https://www.certification.openid.net/`; a self-asserted alternate HTTPS
origin is not accepted.

FAPI 2.0 and OpenID Federation are separate profiles. They are absent from the
allowed claim list and remain unclaimed. The approved-claims artifact also
records explicit non-claims for FAPI, OpenID Federation, blanket RFC 9700
certification, real SCIM interoperability, and real EMA interoperability.

## GitHub environment

Create a GitHub environment named `conformance`. Configure its deployment
branch policy to allow only `main`, require release-operator review where the
repository plan supports it, and disable administrator bypass. Give only
release operators access to its secrets. The workflow fixes the suite endpoint
to `https://www.certification.openid.net/`; callers cannot redirect any secret
to another conformance host.

| Secret | Purpose |
| --- | --- |
| `OIDF_CONFORMANCE_TOKEN` | Bearer token issued by the official hosted OIDF conformance server. |
| `OIDF_BASIC_OP_CONFIG_JSON` | Complete OIDF plan configuration for the stable issuer, including two dynamic-client names, a dedicated tenant-scoped IAT in both client slots, and browser automation for the dedicated test user. |
| `CONFORMANCE_ARTIFACT_PASSPHRASE` | Single-line random passphrase of at least 32 characters used only to encrypt raw OIDF evidence. Store its recovery copy outside GitHub. |

Configure these non-secret environment variables for the daily stable
deployment run:

| Variable | Purpose |
| --- | --- |
| `CONFORMANCE_ISSUER` | Stable deployed HTTPS issuer. |
| `CONFORMANCE_DEPLOYMENT_VERSION` | Full Git commit actually deployed at that issuer; update it as part of deployment. |

Deploy the stable issuer with `AGENT_AUTH_DEPLOYMENT_COMMIT` set to the full
lowercase commit being built. `AgentAuthDev` then exposes that immutable value
as the CloudFormation `DeploymentCommit` output even though its production
recovery profile is disabled. Read the output after the stack reaches
`UPDATE_COMPLETE`, verify that the commit exists on `origin/main`, and use that
exact value for `CONFORMANCE_DEPLOYMENT_VERSION`:

```bash
set -euo pipefail
deployed_commit="$(
  aws cloudformation describe-stacks \
    --stack-name AgentAuthDev \
    --region us-east-1 \
    --profile "${AWS_PROFILE:-default}" \
    --query "Stacks[0].Outputs[?OutputKey=='DeploymentCommit'].OutputValue | [0]" \
    --output text
)"
[[ "$deployed_commit" =~ ^[0-9a-f]{40}$ ]]
git fetch origin main
git merge-base --is-ancestor "$deployed_commit" origin/main
gh variable set CONFORMANCE_DEPLOYMENT_VERSION \
  --env conformance \
  --body "$deployed_commit"
gh variable set CONFORMANCE_DEPLOYMENT_VERSION \
  --body "$deployed_commit"
```

An absent output is not evidence of a deployment version. Do not substitute
the current worktree SHA, another stack's output, or a branch tip.

The environment-scoped value is authoritative for the secret-bearing release
job. The same-named repository variable is a non-secret mirror used only by
the independent watchdog, which cannot read environment variables without
entering that environment. GitHub gives the environment-scoped value
precedence inside the release job. Update both scopes from the same verified
CloudFormation output before enabling or dispatching conformance.

The deployed discovery responses expose the same value in the
`x-agent-auth-deployment-commit` response header. The release workflow verifies
that live header against `CONFORMANCE_DEPLOYMENT_VERSION` before it reads the
protected OIDF configuration or creates any dynamic client. A stale environment
variable therefore fails closed instead of labeling live evidence with another
deployment's commit.

The repository variable `CONFORMANCE_SCHEDULE_ENABLED` must remain unset or
`false` until every variable and secret above is configured. Set it to `true`
only after a manual run for the same issuer and deployment reaches the OIDF
plan. The switch controls only scheduled runs; manual release gates always run
and fail closed on missing or invalid configuration. This switch must be a
repository variable, not an environment variable, because the job condition is
evaluated before the `conformance` environment is entered.

## Dedicated conformance runner

The release job targets a repository-scoped runner with all of these labels:

```text
self-hosted
Linux
ARM64
agent-auth-conformance
```

This runner is dedicated to the manual and scheduled conformance gate. Do not
reuse its custom label from `pull_request` workflows or general CI jobs. Keep
fork pull-request workflows disabled and restrict runner registration and host
access to repository administrators. Run the service under a dedicated system
account with a private home and work directory, no login shell, and no sudo,
Docker, cloud, or developer credentials. The host must provide Git, GnuPG,
`shred`, `curl`, and the standard archive/checksum tools; the workflow installs
its pinned Python runtime and dependencies.

On AWS hosts, the service boundary must also deny EC2/ECS instance metadata
addresses. The first workflow step fails closed if ambient AWS credential
variables are present or an IMDSv2 token can be obtained. A distinct service
account alone is insufficient because instance-profile credentials are
otherwise available to every local user.

The runner is persistent, so secret configuration and raw suite output must
remain under `RUNNER_TEMP`. The encryption step shreds those files on both
success and handled failure. After an interrupted host or runner process,
inspect and clear the job temp directory before retrying; never promote a
partial run as release evidence.

The workflow is defined only for manual and scheduled events on `main`; it does
not expose a secret-bearing `workflow_call` entry point. All third-party
Actions use full commit pins. The official runner's direct and transitive
Python dependencies and the project-owned cryptographic dependencies are
version- and SHA-256-pinned, and installed before the secret configuration is
exposed to a step or written to disk. The configuration is then validated
before use. Its
`server.discoveryUrl` must equal the selected issuer's
`/.well-known/openid-configuration`; `client`, `client2`, their
`initial_access_token` values, and at least one browser rule are mandatory.
The validation manifest records only which slots have an IAT; it never copies
the token value. The secret configuration itself is never copied to the
artifact directory or logs.

A dedicated test-user configuration can be generated without putting the
password or IAT on the command line. Issue a dedicated IAT through
`POST /admin/initial-access-tokens` with owner `oidf-conformance`, scope
`dcr:register`, `one_time=false`, a bounded rate such as 120 registrations per
minute, and an explicit expiry. Rotate the IAT before expiry and revoke the old
record after the protected GitHub secret is replaced.

```bash
umask 077
printf '%s\n' "$OIDF_TEST_PASSWORD" > /secure/path/oidf-test-password
printf '%s\n' "$OIDF_INITIAL_ACCESS_TOKEN" > /secure/path/oidf-initial-access-token
python3 scripts/build_oidf_basic_op_config.py \
  --issuer https://issuer.example.com \
  --email oidf-conformance@example.com \
  --password-file /secure/path/oidf-test-password \
  --initial-access-token-file /secure/path/oidf-initial-access-token \
  --output /secure/path/oidf-basic-op.json
python3 scripts/validate_oidf_config.py \
  --config /secure/path/oidf-basic-op.json \
  --issuer https://issuer.example.com \
  --summary /tmp/oidf-config-manifest.json \
  --normalized-config /secure/path/oidf-basic-op.json
gh secret set OIDF_BASIC_OP_CONFIG_JSON \
  --env conformance \
  < /secure/path/oidf-basic-op.json
```

The generator requires both input files to be mode `0600` and emits mode
`0600` JSON with stable login/consent DOM selectors, two dynamic-client names,
the same controlled IAT in both slots, the test user's `login_hint`, and an
optional login/consent sequence. Callback tasks match only the hosted
`/test/<module-id>/callback` path via
`https://www.certification.openid.net/test/*/callback*`; the final wildcard
accepts the authorization response query. Validation also removes the retired
`oidcc-response-type-missing` override from an older protected configuration
before that configuration reaches the runner. A higher-priority
`prompt=none` browser rule permits only that direct hosted callback; reaching
login or consent instead fails the module rather than hiding an
interactive-response defect. The ordinary rule waits for the consent context
to finish loading before clicking and satisfies the screenshot placeholders
used by the `prompt=login` and `max_age=1` modules. The remaining module
overrides capture the expected local error pages for the unregistered
`redirect_uri` test and the unsupported Request Object with a conflicting
redirect URI instead of incorrectly requiring a callback.

OIDF BrowserControl uses HtmlUnit rather than a full Chrome process. The
production web build therefore emits a `nomodule` legacy bundle with a Fetch
polyfill in addition to the normal module bundle. Removing that build path,
the stable DOM ids, or the ready markers break unattended hosted execution
even if Playwright remains green. CI runs a driver-level SPA smoke from login
through consent and callback with the Selenium and HtmlUnit versions used by
the official `release-v5.2.1` BrowserControl image. The pinned hosted workflow
remains the end-to-end BrowserControl acceptance path. The local smoke is
`web/scripts/run-oidf-htmlunit-smoke.sh`. A minimal structural shape is:

```json
{
  "description": "agent-auth stable release conformance",
  "server": {
    "discoveryUrl": "https://issuer.example.com/.well-known/openid-configuration"
  },
  "client": {
    "client_name": "agent-auth-oidf-primary",
    "initial_access_token": "<protected-initial-access-token>"
  },
  "client2": {
    "client_name": "agent-auth-oidf-secondary",
    "initial_access_token": "<protected-initial-access-token>"
  },
  "browser": [
    {
      "match": "https://issuer.example.com/authorize*",
      "tasks": [
        {
          "task": "Authenticate and decide consent",
          "match": "https://issuer.example.com/*",
          "commands": [
            ["wait", "id", "agent-auth-login-ready", 30],
            ["text", "id", "agent-auth-login-email", "<dedicated-test-email>"],
            ["text", "id", "agent-auth-login-password", "<replaceable-test-password>"],
            ["click", "id", "agent-auth-login-submit"]
          ]
        },
        {
          "task": "Verify hosted callback completed",
          "match": "https://www.certification.openid.net/test/*/callback*",
          "commands": [["wait", "id", "submission_complete", 30]]
        }
      ]
    }
  ]
}
```

The real secret must contain browser tasks that match the deployed login and
consent DOM, including module-specific overrides where the OIDF instructions
require a different user decision. Use a dedicated, non-privileged,
replaceable test user. OIDF exports can include submitted configuration and
HTTP traces, so artifact readers must be restricted even though the
credentials are disposable. The hosted suite log can also contain the IAT;
never generate or distribute its public plan/log link. Keep the ordinary
authenticated plan URL restricted to release operators.

## Release invocation

`.github/workflows/release-conformance.yml` is scheduled daily at 03:17 UTC
when `CONFORMANCE_SCHEDULE_ENABLED=true` and supports manual invocation from
`main`. The daily run checks the environment variables above; it does not
replace release enforcement. Before publishing a profile claim, a release
operator must dispatch the workflow with the exact deployed values and require
that run to pass:

```bash
gh workflow run release-conformance.yml \
  --ref main \
  -f issuer=https://issuer.example.com \
  -f deployment_version=0123456789abcdef0123456789abcdef01234567
```

`deployment_version` must be a full commit present in the repository. The
operator is responsible for obtaining that immutable commit from the deployment
record rather than guessing from a release branch. It must be reachable from
the workflow commit. Both manual and scheduled runs require `github.ref` and
`github.workflow_ref` to identify this workflow on `main`; the environment's
main-only deployment policy is an independent secret-release boundary.
The combined evidence records only `requested_claims`; it is not release
authorization. A passing gate creates schema-v2
`approved-profile-claims.json`, containing the exact issuer and deployment,
approved profile claims, explicit non-claims, validity deadline, and SHA-256
of the evidence and exact conformance policy. A failed or interrupted gate, or
failure to encrypt the retained raw evidence, leaves that file absent. A merge
to `main` is never authorization to publish a protocol claim.

Download `evidence.json` and `approved-profile-claims.json` from the same
successful workflow artifact, then validate them against the exact environment
being promoted:

```bash
python3 scripts/release_conformance.py validate-promotion \
  --approved-claims approved-profile-claims.json \
  --evidence evidence.json \
  --policy .github/conformance/policy.json \
  --expected-issuer https://issuer.example.com \
  --expected-deployment-version \
    0123456789abcdef0123456789abcdef01234567 \
  --required-claim oidc-basic-op-code
```

The command fails closed on an expired artifact, an evidence digest mismatch,
an issuer or full-commit mismatch, an unapproved required profile, changed
policy scope, or missing explicit non-claims. The workflow runs the same
validator before uploading its artifact. Dev and SaaS are separate promotion
decisions: never reuse one issuer's approved artifact for another issuer,
tenant shape, subject policy, signing-key profile, or feature configuration.

The workflow runs both suites even when one reports failures, then applies the
single policy in `.github/conformance/policy.json`. It retains for 30 days:

- the sanitized configuration manifest;
- deployment-commit preflight summaries captured before and after the live
  suites; both exact matches are embedded in the combined evidence digest;
- RFC 9700 project-regression results;
- plan id, combined evidence, gate summary, and, only on success, the approved
  profile-claims document; and
- one AES-256 encrypted archive containing official OIDF runner output, the
  signing JWKS, plan manifest, and raw JSON and HTML exports.

The plaintext raw evidence exists only under `RUNNER_TEMP` and is shredded
after encryption. The uploaded artifact contains `oidf-raw.tar.gpg` plus its
SHA-256 checksum, never plaintext exports. Verbose official-runner output is
redirected only to the encrypted archive and is not echoed to the Actions log.
To inspect an authorized download:

```bash
gpg --decrypt oidf-raw.tar.gpg | tar -xvf -
```

The raw OIDF exports are sensitive operational evidence. Keep the passphrase
separate from the artifact and do not publish decrypted files as release
assets without a separate redaction review.

## Exceptions

Exceptions live in `.github/conformance/exceptions.json` and therefore require
a reviewed pull request. An exception must target one exact failed required
test and include:

```json
{
  "suite_id": "oidf-basic-op-code",
  "test_id": "<exact generated test id>",
  "approved_by": "@amliuyong",
  "approved_at": "2026-08-01T00:00:00Z",
  "reason": "Specific bounded rationale",
  "issue_url": "https://github.com/amliuyong/a-auth/issues/<issue-number>",
  "expires_at": "2026-08-08T00:00:00Z"
}
```

The maximum approval window is 30 days. Expired, overlong, duplicate,
untracked, or unused exceptions fail closed. Exceptions cannot waive runner
interruption, missing modules, conversion errors, stale evidence, wrong
issuer/deployment version, or unapproved profile claims.

An exact active exception may waive only its original `failed` result; it does
not rewrite that result to `passed`. Its issue must contain this exact binding:

```markdown
<!-- agent-auth-conformance-waiver -->
- Suite: `oidf-basic-op-code`
- Test: `<exact generated test id>`
- Expires: `2026-08-08T00:00:00Z`
```

The allowlisted `approved_by` identity in
`.github/conformance/policy.json` must apply the
`conformance-waiver-approved` label after reviewing that binding.
`approved_at` must exactly match the GitHub label event timestamp. The workflow
verifies the issue is open in this repository, is not a pull request, still has
the label, and has a matching label audit event. Relabeling by another actor,
removing the label, changing the target/expiry, or self-asserting
`approved_by` fails closed. Every unwaived failure makes the gate fail.

Dynamic-client cleanup is explicitly non-waivable. The RFC 9700 probe performs
cleanup from a `finally` boundary whenever registration created a client. For
every official OIDF module that reaches dynamic registration, the converter
requires at least one signed `UnregisterDynamicallyRegisteredClient` `SUCCESS`
log entry. A module that ends before registration is recorded as
`not_required` with zero attempts only when its signed export contains exactly
one `INFO` cleanup entry with the suite's exact missing-`client` message,
`expected=client`, `mapped=null`, and no `CallDynamicRegistrationEndpoint`
event. A passing module cannot use `not_required`. Missing management
credentials, ambiguous or missing cleanup evidence, cross-origin management
URI, skipped cleanup after registration, or DELETE failure always fails the
gate.
On failure, cancellation, or an unexpected skipped job while the repository
schedule switch is enabled, a separate GitHub-hosted job with narrowly scoped
`issues: write` permission creates or updates an issue keyed by deployment
commit. It downloads the evidence artifact when available and links the
workflow run and gate summary. The tracker receives only Base64-encoded,
non-secret issuer and deployment metadata through job outputs; it does not
enter the secret-bearing `conformance` environment. The conformance job has
only `contents: read` and `issues: read`. An intentionally disabled schedule
does not create an issue.

`.github/workflows/release-conformance-monitor.yml` is an independent
GitHub-hosted watchdog scheduled every three hours. When the repository
schedule switch is enabled, it fails and creates or refreshes the single
`[conformance] continuous gate monitoring failure` issue if the deployment
version is absent or not a full commit, no scheduled run starts within 30
hours, the required external job is skipped, a scheduled run remains active
for at least three hours, or the latest successful scheduled evidence is at
least the policy's 24-hour maximum age. The watchdog reads Actions metadata but
uses the repository-scoped deployment-version mirror; it does not enter the
`conformance` environment or receive its secrets. Once no active finding
remains, it closes the open watchdog issue. Disabling the repository schedule
intentionally suppresses these findings.

## Runtime and restart behavior

The OIDF statement that its own regression suite runs at least once every 24
hours describes recurrence, not the duration of one plan. This workflow does
not wait 24 hours.

The official runner retries suite-server restarts within one job. If the
GitHub runner itself is lost, rerun the workflow as a new attempt. The hosted
OIDF plan may remain available, but a new release attempt must produce its own
complete export and gate summary; an interrupted prior attempt is never
treated as release evidence.
