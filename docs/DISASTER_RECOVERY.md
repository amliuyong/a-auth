# Single-Region Disaster Recovery

This runbook is the production recovery contract for C12.
It covers accidental deletion, destructive stack changes, and loss of a
DynamoDB authority table inside the deployed Region. Multi-Region traffic
failover, Global Tables, and multi-Region KMS keys are covered by the separate
multi-Region runbook.

The drill never calls `GetSecretValue`, reads protected DynamoDB credential
payloads, or points production traffic at a restored table. It verifies
credential presence/type/version metadata, records only
hashes/counts/timings, and removes the isolated tables.

The separate cutover verifier described below is intentionally more
privileged: it reads the current governance HMAC key into a process-local
`0700` temporary directory so it can compare restored aliases with the opaque
suppression ledger. It never prints the key, persists a digest, or has a
DynamoDB mutation path.

## Targets

| Objective | Target | Measurement |
|---|---:|---|
| Point-in-time RPO | 10 minutes | Worst `LatestRestorableDateTime` lag across every recoverable table |
| Isolated restore RTO | 4 hours | First PITR request through cleanup and all post-cleanup verification complete |
| Scheduled backup interval | 24 hours | Deployed AWS Backup rule at 05:00 UTC plus an on-demand recovery point |
| Backup retention | 35 days | Explicit PITR recovery period and AWS Backup lifecycle |

The measured RTO excludes incident detection, operator approval, and an
explicit production cutover. A drill that misses either target fails; the
target is not adjusted to make the run pass.

## Data Classes

`AgentAuthSaas` enables the production recovery profile by default.
`SAAS_PRODUCTION_RECOVERY=0` is only for disposable test stacks. A self-hosted
stack opts in with `AGENT_AUTH_PRODUCTION_RECOVERY=1`.

| Data class | Application retention | PITR | AWS Backup | Stack deletion | Recovery decision |
|---|---|---|---|---|---|
| Durable identity, authorization, configuration, and key registry | Business lifecycle; no TTL | Enabled, 35 days | Daily, 35 days | `Retain` | Restore and verify |
| Security-event hot ledger | 400-day `expires_at`; archive is authoritative after hot expiry | Enabled, 35 days | Daily, 35 days | `Retain` | Restore ledger and verify archive anchor |
| Mixed Admin auth table | `config#` is durable; `flow#`/`session#` use protocol expiry | Enabled, 35 days | Daily, 35 days | `Retain` | Restore, then purge every flow/session row |
| SSF stream registry, revoke tombstones, and delivery outbox | 400-day delivery audit; stream revoke tombstones are permanent | Enabled for investigation only | Excluded | `Retain` | Never roll back; recreate stream registrations after recovery |
| Governance policy/jobs and suppression ledger | Policy/job lifecycle; user suppression exceeds maximum restore window; tenant suppression is permanent | Enabled for investigation only | Excluded | `Retain` | Never roll back or replace with an older recovery point; reconcile restored authority against current suppression before cutover |
| Refresh-family and recovery-code ledgers | Current family/factor lifecycle; no safe rollback window | Enabled for investigation only | Excluded | `Delete` | Never attach a restored copy |
| Other one-time protocol and cache state | Protocol `expires_at`/`ttl` where applicable | Enabled for investigation only | Excluded | `Delete` | Recreate by rerunning the protocol |
| Security-event S3 archive | 2,555-day versioned lifecycle | Not applicable | Native retained storage | `Retain` | Verify restored ledger references retained objects |
| Stack-managed KMS keys, suppression HMAC verifier keys, and Secrets Manager secrets | Service lifecycle; suppression keys live at least as long as referencing rows; secret deletion recovery window remains the last resort | Not applicable | Not copied into table backup | `Retain` | Verify every referenced key/secret version and keep fail closed if unavailable |

### Recoverable authority

The following SaaS tables use `RETAIN`, keep PITR enabled, and are selected by
the 35-day daily AWS Backup plan:

- `ClientsTable`, `UsersTable`, `PasskeyTable`, and
  `PasswordCredentialsTable`
- `GrantsTable`, `WorkloadTrustTable`, and `FederationConfigTable`
- `ScimGroupsTable`, `DomainMapTable`, and `TenantKeysTable`
- `SecurityEventsTable`
- `AdminAuthTable`, subject to mandatory post-restore sanitization below

`AdminAuthTable` mixes durable `config#` rows with one-time `flow#` and
short-lived `session#` rows. A restored copy is not eligible for cutover until
every flow/session row has been deleted and only well-formed config rows
remain. The drill performs and verifies this sanitization on the isolated
copy.

The data-governance profile adds retained policy/job and suppression tables outside
this 12-table backup selection. A recovery must use the current, non-rollback
suppression ledger to remove any user whose suppression epoch is newer than the
restore point, purge every tenant already frozen/offboarded, and reject stale
alias rows before restored authority can be attached. Restoring an older copy
of the suppression ledger together with business authority is forbidden.

### Fail-closed state

The following tables keep PITR for operational investigation but use
CloudFormation `Delete` and are deliberately absent from AWS Backup:

- authorization codes, IATs, login/authz sessions, magic links, federation
  flows, PAR, CIBA/device requests, and passkey challenges
- `JtiTable`, grace responses, rate-limit leases, and notification messages
- `RefreshTable` and `RecoveryTable`

`RefreshTable` and `RecoveryTable` are persistent ledgers, but they are still
one-time/replay-sensitive state. Rolling either table back can revive a
revoked refresh family or an already consumed recovery code. Recovery
therefore invalidates these artifacts and requires a new authorization or
recovery-factor enrollment. They must never be attached to a restored runtime.

`SsfDeliveriesTable` is also excluded even though CloudFormation retains the
live table. It mixes permanent receiver-revocation tombstones and stream
revisions with sendable delivery rows. Rolling it back could reactivate a
revoked receiver or make a terminal delivery sendable again. During a real
recovery, keep SSF schedules/event sources disabled and recreate approved
stream registrations instead of attaching an older copy.

### Keys, secrets, archives, and derived resources

- Stack-managed ES256, RS256, token-grace, CIBA-notification, legacy-grace, and
  backup-vault KMS keys use `RETAIN`. The current token-grace and
  CIBA-notification keys remain `Enabled`; the pre-split legacy grace key is a
  rollback tombstone and must remain `Disabled` after the C3.4 cutover. Never
  re-enable it to recover the old monolithic runtime; roll forward instead.
  Tenant signing keys are referenced by the retained
  `TenantKeysTable`; every referenced key must be `Enabled`.
- Every HMAC key version referenced by the live governance suppression ledger is
  retained outside business-authority recovery and must be available to the
  suppression writer/reconciler. A missing version keeps restore cutover fail
  closed; restoring an older verifier-key set is forbidden.
- Stack-managed server, platform/tenant Admin, and SCIM Secrets Manager secrets
  use `RETAIN`. Metadata verification rejects pending deletion, requires exactly
  one `AWSCURRENT` version, and requires the Secret's KMS key (the
  `aws/secretsmanager` key when `KmsKeyId` is absent) to be `Enabled`. Every
  restored Admin OIDC configuration must name its tenant's fixed
  `agent-auth/admin-oidc/<tenant>` client secret. OIDC Federation
  `client_secret_ref` dependencies receive the same checks. IAM simulation
  checks that the deployed Auth role's identity policies allow
  `GetSecretValue` on each exact runtime dependency and, for a customer-managed
  Secret key, `kms:Decrypt` on that exact key. This evidence does not simulate
  resource policies, KMS key policies, Organizations SCPs, or every other
  effective-authorization layer. The drill itself never calls
  `GetSecretValue` or reads a secret value.
- Every federation configuration Secret reference is classified by the Issue
  #30 ownership record and checked with `DescribeSecret` in its configured
  Region. Product-managed references must resolve to the same resource
  fingerprint; external references remain operator-owned dependencies. The
  same metadata, KMS-key, and deployed-role permission checks apply without
  reading either value.
- Security-event archive and quarantine buckets already use native retained,
  versioned storage. The drill proves that a restored hot-ledger row still
  resolves to its archive object.
- Lambda functions, APIs, queues, schedules, alarms, and indexes are derived
  infrastructure. Recreate them from the reviewed commit instead of restoring
  runtime copies.

KMS and Secrets Manager are prerequisites, not data copied into DynamoDB
backup. If a required key is disabled/unrecoverable or a required secret
cannot be recovered from its deletion window, keep the service fail closed
and escalate; this single-Region runbook cannot replace the credential.

## Drill Preconditions

1. Install AWS CLI, `jq`, and Python 3 with `cryptography`; use a configured
   AWS profile, the target Region, and the intended stack.
2. Deploy the reviewed commit with the production recovery profile enabled and
   `AGENT_AUTH_DEPLOYMENT_COMMIT=$(git rev-parse HEAD)`. The stack output and
   clean local checkout must match exactly before the drill can qualify.
3. Run the Grant projection migration below. Ensure `t1` and `t2` each have an
   identity, and the Grants table contains at least one unexpired active Grant
   and one revoked Grant.
4. Ensure at least one archived security event predates the common PITR
   cutoff and each tenant key registry contains complete EC and RSA snapshots.
5. Do not rotate tenant keys, revoke the sampled Grants, mutate identity or
   credential authority, or modify Admin OIDC, client, workload trust,
   federation, SCIM Group, or domain configuration during the drill. These
   authority mutations intentionally make snapshot/source comparison fail.
6. Run from persistent encrypted storage. The state directory contains no
   secret or verifier values, but it does contain identity records, identifiers,
   and protected operational metadata and is mode `0700`.

Create missing fixtures through normal product APIs, not direct table writes,
then wait at least the 10-minute RPO target before starting the drill.

### Grant projection migration

Early Grant rows can predate the tenant-scoped `gv_tenant` and
`effective_pv` projections. Audit first; the default action does not write:

```bash
ACTION=plan STACK=AgentAuthSaas \
AWS_PROFILE=default REGION=us-east-1 \
./e2e/migrate_grant_projections.sh
```

Apply only after reviewing the candidate count:

```bash
ACTION=apply CONFIRM_STACK=AgentAuthSaas STACK=AgentAuthSaas \
AWS_PROFILE=default REGION=us-east-1 \
./e2e/migrate_grant_projections.sh
```

The migration validates every Grant-table row before writing. Each update is
atomic and binds the original `grant_json`, `user_id`, top-level `revision`
value or absence, and absence of both target fields. Re-running it is
idempotent. Wait at least the RPO target after the final write so the common
PITR cutoff includes the migrated projections.

## Execute

```bash
STACK=AgentAuthSaas \
ISSUER_T1=https://t1.example.com \
ISSUER_T2=https://t2.example.com \
AWS_PROFILE=default REGION=us-east-1 \
./e2e/backup_restore_drill.sh
```

The run validates the exact deployed backup selection, completes an on-demand
AWS Backup recovery point for `UsersTable`, chooses the minimum
`LatestRestorableDateTime` as one common cutoff, restores every recoverable
table at that exact instant, and verifies the supplied issuers exactly match
the deployed stack's tenant issuer map before checking:

- both issuers and tenant-disjoint EC/RSA JWKS before and after the restore
- complete user/canonical-alias/create-claim authority, including canonical
  reference integrity and exact `t1`/`t2` physical isolation
- passkey and password credential presence/type/version metadata without
  reading `cred_json` or password hashes; every credential owner must resolve
  to a canonical User in exactly one tenant, and each passkey physical
  `credential_id` must use the same tenant prefix as its `user_id`
- the complete Grant table, including recognized policy-version and immutable
  policy-artifact rows; every Grant's physical `grant_id`, `user_id`,
  `gv_tenant`, and `effective_pv` must match the logical `grant_json`, plus
  current active and revoked samples
- redacted client configuration plus exact workload trust, federation, SCIM
  Group, and domain configuration (including an exact empty set), followed by a
  final source rescan that rejects any in-drill configuration drift; client
  credential-set presence/type/version shape is compared without reading
  verifiers, and retained client-reclaim audit rows are compared in full
- tenant signing registry hashes, complete issuer JWK sets, and every
  referenced KMS key, including a real KMS `Sign` probe verified against the
  registry's exact published JWK and global ARN disjointness across tenants;
  each restored t1/t2 record is also resolved through the production
  `DynamoTenantKeyRegistry` and `TenantKeyService` path to produce independently
  verified, issuer-bound ES256 and RS256 signatures
- every current stack-managed signing, token-grace, CIBA-notification, and
  backup-vault KMS key is enabled; every retained legacy grace rollback
  tombstone is disabled and its key ID matches the reviewed cutover state
- the deployed CloudFormation template retains every stack-managed KMS key and
  Secret on deletion/replacement, plus live Secret metadata proving exactly one
  `AWSCURRENT` version and an enabled encryption key without reading values;
  runtime identity-policy simulation is checked against every exact referenced
  Secret and customer-managed encryption key
- tenant-bound Admin OIDC client-secret references and metadata
- OIDC Federation client-secret references and metadata
- exact Admin configuration after deleting restored flow/session rows
- hot-ledger to retained S3 audit continuity
- measured RPO and RTO

The daily backup and the on-demand recovery point prove vault writeability;
the isolated table restoration uses DynamoDB PITR because it is the primary
10-minute-RPO path. After isolated-table cleanup, the drill revalidates every
source identity/configuration/complete Grant snapshot, both sampled Grants,
tenant key registries, Admin configuration, audit anchor/archive, the on-demand
recovery point, issuers, Secrets, and KMS key state. Evidence is atomically
published only after this final gate.

## Resume After Restart

The script prints a `RUN_ID` and stores progress under
`~/.agent-auth-drills/<RUN_ID>`. After a machine reboot, rerun the same command
with that ID:

```bash
RUN_ID=<printed-run-id> STACK=AgentAuthSaas \
ISSUER_T1=https://t1.example.com \
ISSUER_T2=https://t2.example.com \
AWS_PROFILE=default REGION=us-east-1 \
./e2e/backup_restore_drill.sh
```

The first run persists the account, stack, deployed commit, issuers, recoverable
table set, source hashes, common cutoff, table source ARNs, backup job, target
map, and one restore receipt per table. Every target name is deterministically
derived from the complete `RUN_ID` and source table. A resumed run rejects any
deployment-context, account, source ARN, target-map, table ID, creation-time, or
cutoff change and reuses the original anchors. DynamoDB removes
`RestoreSummary` after a restored table becomes `ACTIVE`, so a reboot in the
narrow interval between accepted restore and local receipt persistence recovers
the receipt only from one exact, successful CloudTrail event bound to the
source ARN, target ARN, account, Region, semantic cutoff epoch, and current
table creation time. ISO and numeric CloudTrail timestamp representations are
normalized before comparison. Missing or ambiguous provenance fails closed;
the script allows up to 15 minutes for CloudTrail delivery. The operator
therefore needs `cloudtrail:LookupEvents`, `lambda:GetFunctionConfiguration`,
and `iam:SimulatePrincipalPolicy` in addition to the Backup, DynamoDB, KMS,
Secrets Manager, S3, CloudFormation, and STS permissions exercised by the
script. Elapsed restart time remains part of measured RTO. Losing the state
directory invalidates the RTO evidence; start a new drill rather than
reconstructing a passing result. In particular, any receipt or isolated target
without the original `restore-start-epoch` makes the run unrecoverable; the
script will not reset the RTO clock.

Only one `run` or `cleanup` process may hold a `RUN_ID`; concurrent attempts are
rejected before any table action. A `RUN_ID` that already has evidence is
complete and cannot be reused for another restore; start a new run instead.

If only the target map is lost after restore progress was recorded, cleanup
reconstructs it from the persisted deployment context and still requires the
original source ARN and cutoff provenance before deletion. Missing source or
cutoff metadata remains a hard failure.

## Cleanup And Rollback

Successful runs must delete every isolated restored table before they can
produce passing evidence. To clean up after a failure or reboot without
resuming verification:

```bash
ACTION=cleanup RUN_ID=<printed-run-id> \
AWS_PROFILE=default REGION=us-east-1 \
./e2e/backup_restore_drill.sh
```

The drill performs no traffic cutover, so rollback is deletion of the isolated
tables. Cleanup revalidates the current AWS account, deterministic target map,
source ARNs, receipt or CloudTrail restore provenance, and immutable DynamoDB
table identity before issuing any delete. A missing or damaged state file fails
closed and requires operator investigation; an empty state directory never
reports that deletion succeeded.
For a real incident:

1. Keep public token, recovery, and SSF delivery operations fail closed.
2. Restore under isolated names and run every verification in this runbook.
3. Purge all mixed-table flow/session rows and confirm no replay-state table
   is in the cutover set.
4. Obtain change approval, disable recovery-runtime writes to the isolated
   candidate, and keep public authorization disabled.
5. As the final pre-cutover gate, run the governance-aware verifier below
   against the isolated table
   map. If it rejects live authority, point an isolated recovery runtime at the
   candidate business tables while retaining the current Governance and
   Suppression tables, then resume the existing fenced governance jobs. Never
   clean the candidate with direct table deletes.
6. Change runtime references immediately after a passing gate. Rerun the gate
   after any candidate write, control-authority change, or operational delay.
7. If verification or cutover fails, restore the prior references, keep new
   authorization disabled, and delete the rejected tables with `ACTION=cleanup`.

Never overwrite an existing production table in place and never relax
issuer/tenant/replay checks to complete a recovery.

### Governance-aware cutover verifier

Create a JSON object that maps the 12 recoverable business-authority roles to
their isolated restored table names. It must contain exactly:
`clients`, `workload_trust`, `grants`, `federation_config`, `admin_auth`,
`passkeys`, `security_events`, `users`, `scim_groups`,
`password_credentials`, `domain_map`, and `tenant_keys`.

```bash
STACK=AgentAuthSaas \
AWS_PROFILE=default REGION=us-east-1 \
RESTORED_AUTHORITY_TABLES_FILE=/secure/incident/restored-tables.json \
EVIDENCE_FILE=/secure/incident/cutover-evidence.json \
./e2e/governance_restore_cutover_verify.sh
```

The script derives the current Governance and Suppression tables, tenant
residency, replica Regions, deployment commit, and governance HMAC Secret from
the deployed stack. It rejects a candidate that aliases a current table. It
then performs two strongly consistent scans of both control tables in every
configured replica, requires stable byte-equivalent authority, and strongly
scans each isolated business table with a metadata-only projection. After the
pure candidate checks finish, it strongly scans every control replica again
and fails if any byte changed across the full verification window. Evidence
records the end of that stability window; it is invalid after any candidate or
control-authority write and is not a reusable approval artifact.

The pure verifier recomputes every supported tenant, canonical user, email, and
SCIM alias suppression digest. It rejects an offboarding or tenant-suppressed
tenant with restored live authority, any restored suppressed user, dangling
credential/Grant/Group references, an incomplete scan, an unknown
normalization/key version, or malformed control authority. Retained security
events and a fully offboarded key-registry control row are counted but are not
misreported as live business authority. Passing evidence contains only counts,
commit/account/Region identity, the candidate-map digest, and input digests.

For the restore-cutover sub-gate of the production C12.7 acceptance, use the
restart-safe wrapper below after tenant offboarding has completed. It restores
the 12 current
business-authority tables at one common PITR cutoff under deterministic isolated
names, executes the deployed commit's verifier from a clean detached worktree,
and deletes every isolated table before publishing sanitized evidence. It never
changes runtime table references or production traffic.

```bash
CONFIRM_GOVERNANCE_CUTOVER=post-offboarding-current-authority \
AWS_PROFILE=default REGION=us-east-1 \
./e2e/governance_restore_cutover_live.sh

# Resume or perform fail-closed cleanup after an interrupted process.
RUN_ID=<run-id> \
CONFIRM_GOVERNANCE_CUTOVER=post-offboarding-current-authority \
AWS_PROFILE=default REGION=us-east-1 \
./e2e/governance_restore_cutover_live.sh

ACTION=cleanup RUN_ID=<run-id> \
AWS_PROFILE=default REGION=us-east-1 \
./e2e/governance_restore_cutover_live.sh

# Only after an ambiguous CLI failure, the 15-minute CloudTrail window, and
# independent operator review have all confirmed that AWS did not accept it:
ACTION=resolve-absent RUN_ID=<run-id> ROLE=<role> \
CONFIRM_AMBIGUOUS_ABSENCE=restore-not-accepted-after-cloudtrail-review \
AWS_PROFILE=default REGION=us-east-1 \
./e2e/governance_restore_cutover_live.sh
```

The wrapper requires the reviewed verifier files to be byte-identical between
the harness commit and the deployed stack commit. It persists one pre-request
intent and immutable TableId receipt per restore, recovering an accepted but
interrupted request only from one exact CloudTrail event. Its final evidence
binds both commits, both verifier hashes, the stack and source-map digests, all
restore receipts, the common cutoff, the inner verifier evidence hash, and
successful deletion of all 12 isolated tables. Before each delete it re-reads
the current stack and refuses any table that became a runtime reference. The
verification/deletion window is serialized against CloudFormation deployments
with a temporary deny-update stack policy; the original policy is persisted and
restored before PASS publication. If the stack previously had no policy, the
wrapper restores the equivalent explicit allow-all policy. Both policy changes
use the boto3 response request ID and require exactly one matching successful
CloudTrail event; concurrent policy changes prevent automatic restoration and
PASS publication. An unresolved
ambiguous restore remains fail-closed indefinitely; a negative timed
CloudTrail lookup alone never clears its intent. A failed verifier, ambiguous
AWS response, provenance mismatch, deployment drift, stack-policy restoration,
or cleanup failure removes the PASS evidence and exits nonzero. The operator
needs `cloudformation:GetStackPolicy` and `cloudformation:SetStackPolicy` in
addition to the existing restore/verifier permissions. This sub-gate does not
replace C12.7's separate export, erasure, residency, retention, and offboarding
evidence.

Run state is stored under
`~/.agent-auth-governance-cutover-live/<RUN_ID>/`; the sanitized approval file
is `final-evidence.json`. The directory also contains restricted restore intents,
receipts, and table identifiers and must remain mode `0700`.

`GovernanceTable` and `GovernanceSuppressionTable` are not members of
`RecoveryAuthorityTableNames` or the ordinary AWS Backup selection. PITR is
retained for investigation, but a recovery environment must continue to use
the current replicas. The verifier is a gate only; deletion remains exclusively
inside the lease/policy/tenant/user-fenced governance worker.

## Evidence And Failure Conditions

The successful evidence file is
`~/.agent-auth-drills/<RUN_ID>/evidence.json`. It contains only counts,
timings, commit identity, issuer URLs, and SHA-256 digests. Store it in the
encrypted incident system; publish only the evidence digest and measured
RTO/RPO in an issue or PR.

Any of the following fails the drill:

- backup plan, lifecycle, vault, or exact table selection drift
- backup selection tag conditions/exclusions or an on-demand recovery point
  not bound to this run's Users table, vault, role, lifecycle, and tag
- local/deployed commit mismatch, dirty drill checkout, or resumed deployment
  context mismatch
- supplied issuer mismatch with the deployed SaaS tenant issuer map
- current AWS account, persisted source ARN, or deterministic target-map
  mismatch
- a `DELETING` target whose persisted receipt and immutable table identity
  cannot still be proven
- missing PITR, RPO over 10 minutes, or RTO over 4 hours
- mixed restore cutoffs or an existing target with unexpected restore provenance
- missing or changed identity/credential metadata, dangling/cross-tenant
  credential ownership, complete Grant authority, active/revoked Grant
  fixtures, Admin config, required configuration, or archived audit anchor
- unavailable, rolled-back, or unapplied governance suppression state, any
  referenced suppression HMAC key version, or any restored row belonging to an
  erased user/offboarded tenant
- unknown AdminAuth record class or any flow/session row left after sanitizing
- tenant JWKS overlap, changed key registry, duplicate KMS reference, a KMS
  signature that does not match its published JWK, a restored tenant record
  that cannot resolve and sign through the production runtime path, disabled
  key, or unavailable/pending-deletion/no-`AWSCURRENT` required secret, disabled
  Secret encryption key, missing federation Secret dependency,
  ownership/fingerprint mismatch, or missing runtime Secret/KMS permission
- source/restored Grant mismatch, unknown Grant-table row, invalid Grant
  projection, lost revocation, broken tenant partition, in-drill authority
  drift, or missing archive object
- incomplete cleanup

Do not treat recovery readiness as complete from synth or unit tests alone.
Attach a successful live drill from the deployed commit to the applicable
release or operational record.
