# Replay-Safe Multi-Region Failover

This runbook is the implementation and operating contract for replay-safe
multi-Region recovery. It
covers an active/passive `AgentAuthSaas` deployment, Region-owned replay state,
traffic failover, failback, rollback, and evidence collection. It does not
replace the single-Region restore procedure in
[`DISASTER_RECOVERY.md`](DISASTER_RECOVERY.md).

The deployment is not active/active. Exactly one Region may admit requests.
The standby has no public edge and remains fail closed until the replicated
Region control state names it as the active writer.

## Objectives

| Objective | Target | Measurement |
|---|---:|---|
| Failover RTO | 15 minutes | Source quiesce through the public issuer serving the standby |
| Failback RTO | 15 minutes | Standby quiesce through the public issuer serving the primary |
| Authority RPO | 60 seconds | Client creation observed in the standby Global Table replica |
| Revocation RPO | 60 seconds | Standby Grant revocation observed in the primary replica |
| Replay quiescence | 330 seconds | Fixed, persisted interval before each activation |

The 330-second interval is not a 24-hour test. It is the maximum 300-second
`private_key_jwt` lifetime plus the accepted 30-second clock skew. The drill
performs this interval twice, so its hard minimum is 11 minutes plus deployment,
CloudFront, and assertion time. The separate tenant-key forward-retirement gate
remains a 24-hour test.

## State Ownership

### Replicated authority

The following durable authority is replicated with DynamoDB Global Tables:

- clients, users, password credentials, passkeys, and tenant key registry
- Grants, workload trust, federation configuration, and Admin OIDC configuration
- SCIM groups, domain mappings, and the security-event ledger

Global Tables provide eventual cross-Region convergence and per-item
last-writer-wins conflict resolution. They do not provide a cross-Region
transaction or a globally strong read. The service therefore relies on the
single-writer Region fence, not conflict resolution, for correctness. A write
observed from both Regions at the same Region-control revision is a split-brain
incident and invalidates the drill.

Concurrent operator writes to the same authority item during a drill are
prohibited. Different-item updates can be observed at different times. The
60-second RPO is measured separately for a new client and a Grant revocation.
Missing or stale authority fails closed at the request boundary.

### Region-local replay state

Each Region owns separate tables for authorization codes, IATs, refresh
families, sessions, magic links, invitations, recovery codes, AuthzSessions, CIBA/device
requests, grace responses, JTI mappings, federation flows, Admin flow/session
state, passkey challenges, PAR, rate limits, messages, and SSF delivery state.
These tables are never replicated or restored into another Region.

New replay-sensitive identifiers use:

```text
r1_<aws-region>_<activation-revision>_<opaque-value>
```

WebAuthn challenges base64url-encode that entire frame so every revision width
remains a valid browser `BufferSource`; ownership checks decode the frame before
matching it.

Redemption requires both the Region and activation revision to match the
currently admitted runtime. A failback uses a new revision, so artifacts from
an older activation of the same Region remain invalid. Client assertions, DPoP
proofs, SVIDs, workload assertions, and SigV4 proofs use their trusted issue
time and must not predate the current activation.

### Region control

`RegionControlTable` is itself a Global Table. The `control` row names the
state, active Region, and monotonic revision. A Region-specific row records
whether that Region is active and its activation time. A separate
`fence#<region>` row is updated in the same operator transaction and preserves
the Region row's revision, state, and activation time across Lambda cold starts.
The runtime reads all three rows in one local DynamoDB transaction and admits
traffic only when the Region row matches both the coordinator and its persistent
fence.

Every transition is a DynamoDB CAS transaction serialized through the primary
control Region:

1. Mark the current Region inactive, bind the transition to `RUN_ID`, and set
   the coordinator `quiescing`.
2. Wait until both replicas confirm that the source Region is inactive.
3. Wait 330 seconds from the persisted convergence observation.
4. Before a standby-to-primary transition, purge all standby Region-local
   tables and conditionally record the completed purge revision on the
   coordinator row.
5. Activate the target Region with a strictly higher revision. The activation
   CAS requires the persisted purge revision when the source is the standby.
6. Verify both replicas show exactly one coordinated writer.
7. Switch the CloudFront origin only after activation.

The primary DynamoDB control endpoint must remain reachable for a planned
transition. Do not move the CAS transaction to another Global Table replica
when it is unavailable: eventually consistent conditional writes in two
Regions do not provide global serialization. Keep both runtimes fail closed and
enter the incident recovery process instead of asserting a safe failover.

An absent row, revision rollback, same-revision mutation, replica skew, or
control read failure returns `503` and does not admit the request.

The fence also covers every primary process that can mutate authentication or
authorization authority: the API runtime, tenant-key provisioner, client
reclaimer, and authorization-policy recomputer. Each invocation
transaction-reads the coordinator and its Region row before its first write. An
inactive reclaimer or recomputer skips the scheduled pass. An inactive scheduled
key reconciliation skips fan-out, while an inactive SQS key command fails the
invocation so the command remains retryable instead of being acknowledged by
the wrong Region. All three background authority writers have a 300-second
Lambda timeout. The 330-second quiescence starts only after both replicas
confirm the source inactive, so every invocation admitted under the old
revision must finish or be terminated before target activation.

Security-event archive delivery metadata is owned by the single primary archive
worker, and SSF projection and push state is owned by the single primary SSF
worker. Neither worker is duplicated in the standby. Global Table replica
events may therefore continue through these primary workers while the primary
Region remains reachable, without creating a second authority writer or a
second outbound delivery worker.

## Deployment

### Preconditions

1. Use a configured AWS profile. The supported pair is primary `us-east-1` and
   standby `us-west-2`; production SaaS synthesis requires
   `SAAS_REPLICA_REGIONS=us-west-2` and rejects a missing or different pair so
   a later deployment cannot silently remove the primary admission fence.
2. Build all Lambda artifacts and deploy one reviewed commit to both Regions.
   Both stacks expose `DeploymentCommit`; the drill refuses a mismatch with
   either stack or local `HEAD`, and refuses tracked or untracked worktree
   changes.
3. The tenant issuer must be an exact alias on the deployed CloudFront
   distribution and use the `https://<tenant>.<zone>` origin form without a
   port, path, query, fragment, or credentials. The drill checks this before
   loading an Admin bearer and rechecks it on resume and rollback.
4. Complete the Issue #26 MRK readiness work. Every served tenant EC/RSA key
   must be a KMS multi-Region key with a proven replica in the standby Region.
5. Keep the existing SaaS domain, certificate, tenant, Admin secret source, and
   production recovery environment from [`INSTALL_DEPLOY.md`](INSTALL_DEPLOY.md).
6. Decide Admin OIDC continuity before the drill. Dynamic Secrets Manager
   references such as `agent-auth/admin-oidc/<tenant>` and
   `agent-auth/federation/<tenant>/<idp>` are not included in
   `ReplicatedRuntimeSecretArns`. SaaS user federation is disabled in the
   standby. If Admin OIDC must remain available, create or replicate every
   required exact-name Secret into the standby Region and validate its current
   value there; otherwise record Admin OIDC as a planned degraded capability.
   Never configure the standby with a primary-Region Secret ARN.
7. Run `cdk diff` first. Any replacement of an existing authority table,
   retained key, or retained Secret is a stop condition.

### Deploy the primary replication layer

Deploy the primary first without `SAAS_STANDBY_REGION`:

```bash
cd infra
export AWS_PROFILE=default
export CDK_DEFAULT_REGION=us-east-1
export CDK_DEFAULT_ACCOUNT="$(aws --profile default sts get-caller-identity \
  --query Account --output text)"
export SAAS_REPLICA_REGIONS=us-west-2
export AGENT_AUTH_DEPLOYMENT_COMMIT="$(git -C .. rev-parse HEAD)"

npx cdk diff AgentAuthSaas --profile default
npx cdk deploy AgentAuthSaas --profile default --require-approval never
npx cdk deploy AgentAuthSaasAuthorityReferenceMigration --exclusively \
  --profile default --require-approval never
```

Wait until every table named by `ReplicatedAuthorityTableNames` and every
runtime Secret replica is `ACTIVE` or `InSync`. The current business-authority
set has 16 tables, including the governance and attribute-authority tables. Do
not create the standby from guessed physical names. Read these primary outputs:

```bash
PRIMARY_OUTPUTS="$(aws --profile default --region us-east-1 cloudformation \
  describe-stacks --stack-name AgentAuthSaas --query 'Stacks[0].Outputs' \
  --output json)"

export SAAS_STANDBY_AUTHORITY_TABLES="$(jq -r \
  '.[] | select(.OutputKey=="ReplicatedAuthorityTableNames") | .OutputValue' \
  <<<"$PRIMARY_OUTPUTS")"
export SAAS_STANDBY_REGION_CONTROL_TABLE="$(jq -r \
  '.[] | select(.OutputKey=="RegionControlTableName") | .OutputValue' \
  <<<"$PRIMARY_OUTPUTS")"
PRIMARY_SECRET_ARNS="$(jq -r \
  '.[] | select(.OutputKey=="ReplicatedRuntimeSecretArns") | .OutputValue' \
  <<<"$PRIMARY_OUTPUTS")"
export SAAS_STANDBY_RUNTIME_SECRET_ARNS="$(jq -c --arg region us-west-2 '
  walk(
    if type == "string" and startswith("arn:") then
      split(":") | .[3]=$region | join(":")
    else . end
  )
' <<<"$PRIMARY_SECRET_ARNS")"
```

Secret replicas keep the source name and ARN suffix but have the standby
Region in the ARN. Passing primary-Region ARNs to the standby is invalid.
The map also includes `standby_bootstrap_config`: its SecretString is generated
by the primary stack with replica-local runtime references, while the outer
Secret ARN is converted to the standby Region by the same command above.

### Deploy the standby runtime

Keep the same SaaS configuration and set:

```bash
export SAAS_STANDBY_REGION=us-west-2

npx cdk diff AgentAuthSaasStandby --profile default
npx cdk deploy AgentAuthSaasStandby \
  --profile default --require-approval never
npx cdk deploy AgentAuthSaasStandbyAuthorityReferenceMigration --exclusively \
  --profile default --require-approval never
```

The standby imports every table named by `ReplicatedAuthorityTableNames` and the
replicated Secrets. After Issue #30 this includes both governance tables even
though the standby has no destructive governance worker; the mutation gate and
failback still require their current replicated fences. The standby creates only
Region-local replay/runtime tables, a regional API with separate TokenFn and
NonTokenFn runtimes, queues, event bus, logs, a TokenFn-only grace-envelope CMK,
and a distinct CIBA-notification CMK. It also retains the disabled legacy grace
key as a rollback tombstone; failover and rollback must never re-enable it. It
must not create CloudFront,
Route53, AWS Backup, credential migration, security archive, tenant-key
provisioner, or key-reconciliation resources.
Do not add `--exclusively`: the CDK dependency on `AgentAuthSaas` guarantees
that both origin-auth Secrets exist and replicate before a first standby
deployment.

The authority-reference migration stacks are intentionally separate from the
serving stacks. Deploy each only after its Region's serving stack reaches
`UPDATE_COMPLETE`; they backfill the Region-local Code/Refresh reference table
and publish the coverage markers that allow reclaim to make bounded strongly
consistent absence decisions. The migration provider checkpoints every bounded
page in the Region-local reference table, so retries resume from the last CAS
checkpoint while coverage remains absent. Coverage is bound to the Region's
exact deployment commit; stale markers from another release or rollback are
rejected fail closed. Migration state changes also persist an invocation start
order captured before the first control-plane read and an atomic,
single-use CloudFormation request marker. Delayed old execution environments
therefore cannot replace a newer rollback state, and at-least-once delivery
cannot reset a completed checkpoint. The live gate strongly reads the coverage,
durable completion state, and current-commit request marker. Do not combine
serving and migration phases with `cdk deploy --all`.

Before a drill, run `e2e/saas_origin_auth.sh`. Bare API Gateway requests with
only `X-Forwarded-Host` must return `403`; the live harness reads both managed
origin credentials into temporary mode-`0600` files and proves that either slot
reaches Region admission. Exactly one authenticated regional endpoint must
serve the tenant while the inactive endpoint returns `503`. See
[`SAAS_ORIGIN_AUTH.md`](./SAAS_ORIGIN_AUTH.md).

## Drill

Run from persistent encrypted storage:

```bash
AWS_PROFILE=default \
PRIMARY_REGION=us-east-1 \
STANDBY_REGION=us-west-2 \
PRIMARY_STACK=AgentAuthSaas \
STANDBY_STACK=AgentAuthSaasStandby \
SAAS_ZONE=example.com \
TENANT=t1 \
./e2e/region_failover.sh
```

The script prints a `RUN_ID` and stores mode-`0700` state under
`~/.agent-auth-failover-drills/<RUN_ID>`. Before changing the Region fence, it
downloads both deployed Auth Lambda packages, verifies AWS `CodeSha256`, and
requires each bootstrap and provenance manifest to match the clean local
deployment commit exactly. It then:

- creates a run-unique user and public client and measures authority replication
- captures unconsumed and consumed primary codes and invitations, a refresh
  token, an ID-token JTI, and the issuer JWKS
- quiesces the primary, activates the standby, then changes CloudFront
- requires unconsumed and consumed code, invitation, refresh, and JTI
  rejection; code/refresh/JTI evidence must report the explicit Region-owner
  failure rather than mere token expiry
- independently verifies primary and standby ES256 access tokens and RS256 ID
  tokens against the stable issuer JWKS, then repeats with newly issued tokens
  after failback
- revokes a Grant in the standby, measures propagation to the primary, and
  requires the standby refresh path to return the exact revoked-Grant error
- quiesces the standby, deletes every row from all 20 tables bound by the
  standby `RegionLocalTableNames` output, proves each table empty with
  consistent reads, activates the primary at a new revision, and restores
  CloudFront
- proves source and standby artifacts remain rejected after failback
- deletes the probe client, tombstones the probe user, and writes sanitized
  evidence

The Region-local purge is intentionally deployment-wide: authorization codes,
refresh families, sessions, recovery state, replay markers, pending messages,
and SSF delivery state created while the standby was active are invalid after
the activation revision changes. The purge reads each table's deployed
partition/sort key schema, projects only those keys, deletes at most 25 items
per request, retries DynamoDB `UnprocessedItems`, and does not persist raw keys
or item bodies in evidence.

No raw code, refresh token, access token, ID token, password, or Admin bearer is
written to `evidence.json`. Secret-bearing working files remain mode `0600` in
the local state directory.
Invitation bearers are subject to the same prohibition.

## Restart, Status, And Rollback

A host reboot does not restart either 330-second interval. All control
transactions are serialized through the primary control Region and bound to the
persisted `RUN_ID`. The interval starts only after both Global Table replicas
confirm the source Region is inactive; that observation time is persisted in
the encrypted run directory, not process uptime. Resume with the same command
and `RUN_ID`:

```bash
RUN_ID=<run-id> AWS_PROFILE=default SAAS_ZONE=example.com \
./e2e/region_failover.sh
```

The script serializes a run with `flock`, persists generated credentials before
network calls, recovers an ambiguously created client by its run-unique
redirect URI, and resumes from any of the four planned revisions. Elapsed
reboot time remains part of RTO/RPO. If the measured target is exceeded, the
run can restore service but cannot produce qualified evidence. Before resuming,
the script re-fetches both stacks by their persisted StackIds and revalidates
their Region, control-table, API, CloudFront, authority-table, Secret, and
deployment-commit outputs against the persisted context and a clean local
`HEAD`.

If the host stops during the Region-local purge, rerun with the same `RUN_ID`.
The next run starts from the remaining rows and writes the sanitized purge
receipt only after all 20 tables scan empty. Key-only batch files use a
process-local `0700` temporary directory and are removed on exit.
Quiescence clears any older purge revision from the coordinator. Primary
activation is therefore impossible through the drill CAS until the current
`RUN_ID` has both emptied the tables and persisted the matching purge revision.

Inspect without changing state:

```bash
ACTION=status RUN_ID=<run-id> AWS_PROFILE=default \
./e2e/region_failover.sh
```

Restore the primary from an active standby or a quiescing state:

```bash
ACTION=rollback RUN_ID=<run-id> AWS_PROFILE=default \
./e2e/region_failover.sh
```

Rollback never skips quiescence or standby Region-local cleanup. It advances to
fresh revisions, waits the full 330 seconds when the standby is active, purges
and verifies all standby local tables, activates the primary, verifies the
single writer, restores the CloudFront origin, and checks the public Region
header. Only after service is restored does it delete any fully or partially
initialized probe resources; a cleanup failure returns nonzero and requires
operator follow-up. A rollback terminates the planned drill revision sequence;
start a new `RUN_ID` for qualifying failover evidence.

If local state is lost, do not infer a passing state from AWS. Use operator
inspection and `ACTION=rollback` only with an intact context; otherwise perform
the state transitions manually under incident approval and start a new drill.

## Degraded Standby Operations

The standby is intentionally a reduced runtime. During standby service:

- freeze tenant signing-key lifecycle commands; the key provisioner and
  reconciliation schedule remain primary-only. The standby has no tenant-key
  command queue, and its lifecycle control endpoint returns `503` even while
  the standby Region serves normal authentication traffic
- freeze credential migrations, client reclamation, and authorization-policy
  recomputation
- treat security-event archival and SSF delivery as degraded; the standby has
  no archive worker or SSF delivery schedule. The primary-only workers can
  process replicated events while that Region remains reachable, but a primary
  Region outage pauses these pipelines until recovery. SSF registry/outbox
  state is Region-local, so the standby returns `503` for stream create,
  replace, pause, resume, revoke, verify, and delivery redrive; perform no SSF
  management changes until failback
- treat SaaS user federation as unavailable; the standby intentionally leaves
  the federation route disabled
- treat Admin OIDC as unavailable unless every configured tenant has the
  exact-name `agent-auth/admin-oidc/<tenant>` Secret in the standby Region.
  Authority configuration still replicates, but secret resolution is
  Region-local and fails closed when the local Secret is absent
- do not run backup/restore, user erasure, tenant offboarding, destructive
  governance resume, or destructive governance outbox consumption
- allow normal authentication and authority updates only after the Region
  control fence admits the standby

If a required MRK replica, suppression HMAC verifier key, replicated Secret,
Region-local Admin OIDC Secret, authority/governance row, or Region-control row
is unavailable, keep requests fail closed. Do not substitute primary Region
Secret ARNs, a single-Region KMS key, restored replay tables, or direct API
routing around the admission middleware.

## Evidence And Failure Conditions

Qualified evidence is:

```text
~/.agent-auth-failover-drills/<RUN_ID>/evidence.json
```

Publish only its digest and measured objectives. Preserve the full sanitized
file in the encrypted incident or release-evidence system.

Any of the following fails the drill:

- more or fewer than one coordinated active writer
- an inactive API admitting traffic or CloudFront switching before activation
- a missing, rolled-back, or same-revision-mutated Region-control row
- any source or standby code, invitation, refresh token, or JTI accepted after
  a switch, or any already consumed code or invitation accepted again
- JTI rejection attributed only to expiry when Region ownership is required
- a refresh token accepted after its Grant is revoked
- JWKS change, token signature verification failure, unavailable MRK replica,
  or single-Region signing key
- client or Grant replication over 60 seconds
- failover or failback over 15 minutes
- deployment/output drift, malformed authority/Secret inputs, or wrong account
- any row remaining in a standby Region-local table before primary activation
- CloudFront not restored to the primary after failback
- probe cleanup failure or raw replay artifacts in published evidence

Do not treat the multi-Region items or C11 conformance as complete
from unit tests or CDK synthesis. They require a successful live failover and
failback run from the reviewed deployment.
