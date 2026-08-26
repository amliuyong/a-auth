const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { spawnSync } = require('node:child_process');

const DRILL = path.resolve(__dirname, '../../e2e/data_governance_drill.sh');
const TENANT_KEY_DLQ_EVIDENCE = path.resolve(
  __dirname,
  '../../e2e/tenant_key_dlq_evidence.jq',
);
const drillSource = fs.readFileSync(DRILL, 'utf8');
const source = [
  drillSource,
  fs.readFileSync(TENANT_KEY_DLQ_EVIDENCE, 'utf8'),
].join('\n');

test('c11_1_data_governance_drill_tracks_current_region_local_topology', () => {
  for (const role of [
    'adminAuthRuntime',
    'authzSessions',
    'ciba',
    'clientAuthorityRefs',
    'codes',
    'device',
    'federationFlow',
    'grace',
    'initialAccessTokens',
    'invitations',
    'jti',
    'magicLinks',
    'messages',
    'par',
    'passkeyChallenges',
    'rateLimit',
    'recovery',
    'refresh',
    'sessions',
    'ssfDeliveries',
  ]) {
    assert.match(drillSource, new RegExp(`"${role}"`));
  }
  assert.match(
    drillSource,
    /\(\[.\[\]\] \| unique \| length\) == 20/,
  );
});

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function outputHash(outputs) {
  return createHash('sha256')
    .update(`${canonicalJson(outputs)}\n`)
    .digest('hex');
}

function stackDocument(stackId, outputs) {
  return {
    Stacks: [
      {
        StackId: stackId,
        StackStatus: 'UPDATE_COMPLETE',
        Outputs: Object.entries(outputs).map(([OutputKey, OutputValue]) => ({
          OutputKey,
          OutputValue,
        })),
      },
    ],
  };
}

function writeExecutable(file, body) {
  fs.writeFileSync(file, body, { mode: 0o755 });
}

function tenantKeyDlqInspectionFunctions() {
  const start = drillSource.indexOf('restore_tenant_key_dlq_visibility()');
  const end = drillSource.indexOf('\nverify_queues()', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  return drillSource.slice(start, end);
}

function runTenantKeyDlqInspection(
  t,
  {
    message,
    expectedVisible = 1,
    restoreFails = false,
    interruptDuringReceive = false,
  },
) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tenant-key-dlq-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const harness = path.join(root, 'harness.sh');
  const evidence = path.join(root, 'evidence.tsv');
  const calls = path.join(root, 'receive-count');
  const restores = path.join(root, 'restores.log');
  const response = JSON.stringify({
    Messages: [{ ...message, ReceiptHandle: 'receipt-1' }],
  });
  writeExecutable(
    harness,
    `#!/usr/bin/env bash
set -euo pipefail
WORK="$1"
evidence="$2"
calls="$3"
restores="$4"
expected="$5"
REPO_ROOT="${path.resolve(__dirname, '../..')}"
OFFBOARD_TENANT="t2"
ACTIVE_VISIBILITY_QUEUE=""
ACTIVE_VISIBILITY_HANDLES=""
printf '0\\n' >"$calls"
: >"$restores"
fail() {
  printf 'FAIL: %s\\n' "$*" >&2
  return 1
}
context_value() {
  [[ "$1" == ".created_at" ]]
  printf '1785843796\\n'
}
sleep() { :; }
mock_aws() {
  case " $* " in
    *" sqs receive-message "*)
      local count
      count="$(cat "$calls")"
      count=$((count + 1))
      printf '%s\\n' "$count" >"$calls"
      if [[ "$count" == "1" ]]; then
        if [[ "$MOCK_INTERRUPT_DURING_RECEIVE" == "1" ]]; then
          kill -TERM "$INSPECTION_PARENT_PID"
        fi
        printf '%s\\n' "$MOCK_MESSAGE"
      else
        printf '{"Messages":[]}\\n'
      fi
      ;;
    *" sqs change-message-visibility "*)
      printf '%s\\n' "$*" >>"$restores"
      [[ "$MOCK_RESTORE_FAILS" == "0" ]]
      ;;
    *)
      printf 'unexpected mock aws call: %s\\n' "$*" >&2
      return 64
      ;;
  esac
}
AWSQ=(mock_aws)
${tenantKeyDlqInspectionFunctions()}
INSPECTION_PARENT_PID="$$"
inspect_tenant_key_dlq_messages \
  "https://sqs.example.test/tenant-key-dlq" \
  "$expected" \
  "arn:aws:sqs:us-east-1:123456789012:tenant-key-operations" \
  "$evidence"
`,
  );
  const result = spawnSync(
    'bash',
    [harness, root, evidence, calls, restores, String(expectedVisible)],
    {
      encoding: 'utf8',
      env: {
        ...process.env,
        MOCK_MESSAGE: response,
        MOCK_RESTORE_FAILS: restoreFails ? '1' : '0',
        MOCK_INTERRUPT_DURING_RECEIVE: interruptDuringReceive ? '1' : '0',
      },
    },
  );
  return {
    result,
    evidence: fs.existsSync(evidence) ? fs.readFileSync(evidence, 'utf8') : '',
    receiveCount: Number(fs.readFileSync(calls, 'utf8')),
    restores: fs.readFileSync(restores, 'utf8'),
  };
}

function lineageHarness(t, { drift = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'governance-lineage-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, 'bin');
  const stateRoot = path.join(root, 'state');
  const runId = 'lineage-test';
  const stateDir = path.join(stateRoot, runId);
  fs.mkdirSync(bin);
  fs.mkdirSync(stateDir, { recursive: true });

  const oldCommit = '1'.repeat(40);
  const newCommit = '2'.repeat(40);
  const account = '123456789012';
  const primaryStackId =
    `arn:aws:cloudformation:us-east-1:${account}:` +
    'stack/AgentAuthSaas/primary-id';
  const standbyStackId =
    `arn:aws:cloudformation:us-west-2:${account}:` +
    'stack/AgentAuthSaasStandby/standby-id';
  const replicatedTables = { users: 'UsersTable' };
  const standbyTables = { invitations: 'InvitationsTable' };
  const oldPrimaryOutputs = {
    DeploymentCommit: oldCommit,
    RecoveryDeploymentCommit: oldCommit,
    StableResource: 'same-resource',
  };
  const currentPrimaryOutputs = {
    ...oldPrimaryOutputs,
    DeploymentCommit: newCommit,
    RecoveryDeploymentCommit: newCommit,
    StableResource: drift ? 'replacement-resource' : 'same-resource',
  };
  const oldStandbyOutputs = {
    ApiHost: 'standby.example.test',
    DeploymentCommit: oldCommit,
    ImportedAuthorityTableNames: JSON.stringify(replicatedTables),
    RegionId: 'us-west-2',
    RegionLocalTableNames: JSON.stringify(standbyTables),
  };
  const currentStandbyOutputs = {
    ...oldStandbyOutputs,
    DeploymentCommit: newCommit,
  };
  const dependency = (purpose, ownership) => ({
    purpose,
    secret_ref:
      `arn:aws:secretsmanager:us-east-1:${account}:secret:${purpose}`,
    ownership,
  });
  const dependencies = [
    dependency('tenant_admin', 'product_managed'),
    dependency('scim', 'product_managed'),
    dependency('tenant_admin_legacy_source', 'external'),
    dependency('scim_legacy_source', 'product_managed'),
  ];
  const context = {
    schema_version: 3,
    run_id: runId,
    stack: 'AgentAuthSaas',
    stack_id: primaryStackId,
    region: 'us-east-1',
    standby_stack: 'AgentAuthSaasStandby',
    standby_stack_id: standbyStackId,
    standby_region: 'us-west-2',
    account_id: account,
    deployment_commit: oldCommit,
    outputs_sha256: outputHash(oldPrimaryOutputs),
    standby_outputs_sha256: outputHash(oldStandbyOutputs),
    tenants: ['t1', 't2'],
    erasure_tenant: 't1',
    offboard_tenant: 't2',
    outputs: oldPrimaryOutputs,
    replicated_tables: replicatedTables,
    standby_region_local_tables: standbyTables,
    tenant_secret_dependencies: {
      t1: dependencies,
      t2: dependencies,
    },
  };
  const contextFile = path.join(stateDir, 'context.json');
  const originalContext = `${JSON.stringify(context, null, 2)}\n`;
  fs.writeFileSync(contextFile, originalContext);

  writeExecutable(
    path.join(bin, 'aws'),
    `#!/usr/bin/env bash
set -euo pipefail
case " $* " in
  *" sts get-caller-identity "*)
    printf '%s\\n' "$MOCK_CALLER"
    ;;
  *" cloudformation describe-stacks "*" AgentAuthSaasStandby "*)
    printf '%s\\n' "$MOCK_STANDBY_STACK"
    ;;
  *" cloudformation describe-stacks "*" AgentAuthSaas "*)
    printf '%s\\n' "$MOCK_PRIMARY_STACK"
    ;;
  *)
    printf 'unexpected aws invocation: %s\\n' "$*" >&2
    exit 64
    ;;
esac
`,
  );
  writeExecutable(
    path.join(bin, 'git'),
    `#!/usr/bin/env bash
set -euo pipefail
case " $* " in
  *" merge-base --is-ancestor "*) exit 0 ;;
  *" rev-parse HEAD "*) printf '%s\\n' "$MOCK_HEAD" ;;
  *" status --porcelain "*) exit 0 ;;
  *)
    printf 'unexpected git invocation: %s\\n' "$*" >&2
    exit 64
    ;;
esac
`,
  );

  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    ACTION: 'adopt-deployment',
    RUN_ID: runId,
    STATE_ROOT: stateRoot,
    AWS_PROFILE: 'ci-test',
    REGION: 'us-east-1',
    DEPLOYMENT_TRANSITION_REASON: 'test deployment transition',
    MOCK_CALLER: JSON.stringify({ Account: account }),
    MOCK_PRIMARY_STACK: JSON.stringify(
      stackDocument(primaryStackId, currentPrimaryOutputs),
    ),
    MOCK_STANDBY_STACK: JSON.stringify(
      stackDocument(standbyStackId, currentStandbyOutputs),
    ),
    MOCK_HEAD: newCommit,
  };
  return {
    env,
    stateDir,
    contextFile,
    originalContext,
    oldCommit,
    newCommit,
  };
}

test('data-governance drill is syntactically valid and binds both stacks', () => {
  const syntax = spawnSync('bash', ['-n', DRILL], { encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
  assert.match(
    source,
    /STANDBY_STACK="\$\{STANDBY_STACK:-AgentAuthSaasStandby\}"/,
  );
  assert.match(source, /STANDBY_REGION="\$\{STANDBY_REGION:-us-west-2\}"/);
  assert.match(source, /--arg schema_version "4"/);
  assert.match(source, /standby_stack_id:\s*\$standby_stack_id/);
  assert.match(source, /standby_outputs:\s*\$standby_outputs/);
  assert.match(source, /standby_outputs_sha256:\s*\$standby_outputs_sha256/);
  assert.match(source, /ImportedAuthorityTableNames/);
  assert.match(source, /standby Region-local table output is malformed/);
  assert.match(
    source,
    /standby stack outputs changed since RUN_ID initialization/,
  );
});

test('deployment transitions are explicit, ancestry-preserving, and resource-stable', () => {
  assert.match(source, /ACTION=adopt-deployment/);
  assert.match(source, /DEPLOYMENT_TRANSITION_REASON/);
  assert.match(
    source,
    /merge-base --is-ancestor "\$from_commit" "\$to_commit"/,
  );
  assert.match(
    source,
    /del\(\.DeploymentCommit, \.RecoveryDeploymentCommit\)/,
  );
  assert.match(source, /del\(\.DeploymentCommit\)/);
  assert.match(
    source,
    /primary stack resource outputs changed; refusing deployment transition/,
  );
  assert.match(
    source,
    /standby stack resource outputs changed; refusing deployment transition/,
  );
  assert.match(source, /previous_primary_outputs_sha256/);
  assert.match(source, /previous_standby_outputs_sha256/);
  assert.match(
    source,
    /\.DeploymentCommit = \$commit[\s\S]*legacy standby output hash cannot be reconstructed/,
  );
  assert.match(
    source,
    /validate_deployment_transitions "\$candidate_transitions"[\s\S]*atomic_write "\$DEPLOYMENT_TRANSITIONS"/,
  );
});

test('service and final evidence bind the complete deployment lineage', () => {
  assert.match(source, /verify_evidence_deployment_lineage\(\)/);
  assert.match(
    source,
    /merge-base --is-ancestor[\s\S]*"\$initial_commit" "\$evidence_commit"/,
  );
  assert.match(
    source,
    /merge-base --is-ancestor[\s\S]*"\$evidence_commit" "\$current_commit"/,
  );
  assert.match(source, /initial_deployment_commit:/);
  assert.match(source, /deployment_transitions:\s*\$transitions\[0\]/);
  assert.match(source, /service_evidence_deployment_commits:/);
});

test('adopt-deployment preserves schema-3 context and resumes from an atomic lineage record', (t) => {
  const harness = lineageHarness(t);
  const adopt = spawnSync('bash', [DRILL], {
    encoding: 'utf8',
    env: harness.env,
  });
  assert.equal(adopt.status, 0, `${adopt.stdout}\n${adopt.stderr}`);
  assert.match(adopt.stdout, /PASS: adopted ancestry-preserving deployment/);
  assert.equal(
    fs.readFileSync(harness.contextFile, 'utf8'),
    harness.originalContext,
  );

  const transitionsFile = path.join(
    harness.stateDir,
    'deployment-transitions.json',
  );
  const transitions = JSON.parse(fs.readFileSync(transitionsFile, 'utf8'));
  assert.equal(transitions.length, 1);
  assert.equal(transitions[0].from_commit, harness.oldCommit);
  assert.equal(transitions[0].to_commit, harness.newCommit);
  assert.equal(
    transitions[0].validation_scope,
    'legacy_schema3_hash_reconstruction',
  );

  const status = spawnSync('bash', [DRILL], {
    encoding: 'utf8',
    env: {
      ...harness.env,
      ACTION: 'status',
      DEPLOYMENT_TRANSITION_REASON: '',
    },
  });
  assert.equal(status.status, 0, `${status.stdout}\n${status.stderr}`);
  assert.match(status.stdout, /deployment_transitions=1/);
  assert.match(
    status.stdout,
    new RegExp(`active_deployment_commit=${harness.newCommit}`),
  );
});

test('adopt-deployment rejects resource-output drift without publishing lineage', (t) => {
  const harness = lineageHarness(t, { drift: true });
  const adopt = spawnSync('bash', [DRILL], {
    encoding: 'utf8',
    env: harness.env,
  });
  assert.notEqual(adopt.status, 0);
  assert.match(
    `${adopt.stdout}\n${adopt.stderr}`,
    /primary stack resource outputs changed; refusing deployment transition/,
  );
  assert.equal(
    fs.existsSync(path.join(harness.stateDir, 'deployment-transitions.json')),
    false,
  );
  assert.equal(
    fs.readFileSync(harness.contextFile, 'utf8'),
    harness.originalContext,
  );
});

test('data-governance drill persists only invitation locators and strongly proves deletion', () => {
  assert.match(source, /issue_governance_invitation\(\)/);
  assert.match(
    source,
    /response="\$WORK\/invitation-\$tenant\.json"/,
  );
  assert.doesNotMatch(source, /response="\$RESPONSES\/invitation-/);
  assert.match(source, /invitation_locators:\s*\{/);
  assert.match(source, /\.invitation_locators\[\$tenant\]/);
  assert.match(
    source,
    /dynamodb get-item[\s\S]*--consistent-read[\s\S]*--key "file:\/\/\$key"/,
  );
  assert.match(
    source,
    /\$tenant invitation locator remains after governance cleanup/,
  );
  assert.match(source, /"invitations\.tsv":\$invitations/);
});

test('invitation deletion accepts a normalized missing item and rejects residue', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'governance-invitation-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const absent = path.join(root, 'absent.json');
  const present = path.join(root, 'present.json');
  fs.writeFileSync(absent, '{"Item":null}\n');
  fs.writeFileSync(
    present,
    '{"Item":{"locator":{"S":"t1\\u001flocator"}}}\n',
  );

  const predicate = 'type == "object" and has("Item") and .Item == null';
  const check = (file) =>
    spawnSync('jq', ['-e', predicate, file], { encoding: 'utf8' });
  assert.equal(check(absent).status, 0);
  assert.notEqual(check(present).status, 0);
  assert.match(source, /--query '\{Item: Item\}'/);
  assert.match(
    source,
    /type == "object" and has\("Item"\) and \.Item == null/,
  );
});

test('c12_7_backup_verification_uses_calculated_35_day_deadline', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'governance-backup-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const valid = path.join(root, 'valid.json');
  const missingDeadline = path.join(root, 'missing-deadline.json');
  const wrongDays = path.join(root, 'wrong-days.json');
  const recoveryPoint = {
    Status: 'COMPLETED',
    Lifecycle: { DeleteAfterDays: 35 },
    CalculatedLifecycle: { DeleteAt: '2026-09-08T05:00:00+00:00' },
  };
  fs.writeFileSync(
    valid,
    `${JSON.stringify({ RecoveryPoints: [recoveryPoint] })}\n`,
  );
  fs.writeFileSync(
    missingDeadline,
    `${JSON.stringify({
      RecoveryPoints: [
        { ...recoveryPoint, CalculatedLifecycle: {} },
      ],
    })}\n`,
  );
  fs.writeFileSync(
    wrongDays,
    `${JSON.stringify({
      RecoveryPoints: [
        { ...recoveryPoint, Lifecycle: { DeleteAfterDays: 30 } },
      ],
    })}\n`,
  );

  const predicate = `
    all(
      .RecoveryPoints[] | select(.Status == "COMPLETED");
      (.Lifecycle.DeleteAfterDays == 35) and
      (.CalculatedLifecycle.DeleteAt | type == "string" and length > 0)
    )
  `;
  const check = (file) =>
    spawnSync('jq', ['-e', predicate, file], { encoding: 'utf8' });
  const verifyBackupStart = source.indexOf('verify_backup() {');
  const verifyBackupEnd = source.indexOf(
    '\nverify_kms() {',
    verifyBackupStart,
  );
  assert.notEqual(verifyBackupStart, -1);
  assert.notEqual(verifyBackupEnd, -1);
  const verifyBackup = source.slice(verifyBackupStart, verifyBackupEnd);

  assert.equal(check(valid).status, 0);
  assert.notEqual(check(missingDeadline).status, 0);
  assert.notEqual(check(wrongDays).status, 0);
  assert.equal(
    verifyBackup.match(/\.CalculatedLifecycle\.DeleteAt/g)?.length,
    2,
  );
  assert.doesNotMatch(verifyBackup, /\.DeletionDate/);
});

test('KMS verification accepts legacy keys in a configured Region', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'governance-kms-regions-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const valid = path.join(root, 'valid.json');
  const incomplete = path.join(root, 'incomplete.json');
  const outsideResidency = path.join(root, 'outside-residency.json');
  const context = {
    configured_regions: ['us-east-1', 'us-west-2'],
    t2_kms_key_arns: [
      'arn:aws:kms:us-east-1:123456789012:key/legacy-ec',
      'arn:aws:kms:us-east-1:123456789012:key/legacy-rsa',
    ],
  };
  fs.writeFileSync(valid, `${JSON.stringify(context)}\n`);
  fs.writeFileSync(
    incomplete,
    `${JSON.stringify({
      ...context,
      t2_kms_key_arns: context.t2_kms_key_arns.slice(0, 1),
    })}\n`,
  );
  fs.writeFileSync(
    outsideResidency,
    `${JSON.stringify({
      ...context,
      t2_kms_key_arns: [
        ...context.t2_kms_key_arns,
        'arn:aws:kms:eu-west-1:123456789012:key/outside-residency',
      ],
    })}\n`,
  );

  const predicate = `
    .configured_regions as $configured
    | (.t2_kms_key_arns | length >= 2) and
      all(
          .t2_kms_key_arns[];
          (split(":")[3]) as $region
          | (($configured | index($region)) != null)
        )
  `;
  const check = (file) =>
    spawnSync('jq', ['-e', predicate, file], { encoding: 'utf8' });
  const verifyKmsStart = source.indexOf('verify_kms() {');
  const verifyKmsEnd = source.indexOf(
    '\nverify_secrets() {',
    verifyKmsStart,
  );
  assert.notEqual(verifyKmsStart, -1);
  assert.notEqual(verifyKmsEnd, -1);
  const verifyKms = source.slice(verifyKmsStart, verifyKmsEnd);

  assert.equal(check(valid).status, 0);
  assert.notEqual(check(incomplete).status, 0);
  assert.notEqual(check(outsideResidency).status, 0);
  assert.match(
    verifyKms,
    /\.configured_regions as \$configured[\s\S]*index\(\$region\)/,
  );
  assert.doesNotMatch(
    verifyKms,
    /managed t2 KMS key Regions differ from configured Regions/,
  );
});

test('Secrets Manager verification proves the seven-day deadline from CloudTrail', () => {
  const secretArn =
    'arn:aws:secretsmanager:us-east-1:123456789012:secret:tenant-t2-AbCd';
  const deleteEvent = {
    eventSource: 'secretsmanager.amazonaws.com',
    eventName: 'DeleteSecret',
    eventTime: '2026-08-04T13:54:24Z',
    requestParameters: {
      secretId: secretArn,
      recoveryWindowInDays: 7,
    },
    responseElements: {
      arn: secretArn,
      deletionDate: '2026-08-11T13:54:24Z',
    },
  };
  const cloudTrail = {
    Events: [{ CloudTrailEvent: JSON.stringify(deleteEvent) }],
  };
  const predicate = `
    [
      .Events[].CloudTrailEvent
      | fromjson
      | select(
          .eventSource == "secretsmanager.amazonaws.com" and
          .eventName == "DeleteSecret" and
          .requestParameters.secretId == $arn and
          .requestParameters.recoveryWindowInDays == 7 and
          .responseElements.arn == $arn and
          (.responseElements.deletionDate | type == "string") and
          (.errorCode == null)
        )
      | .responseElements.deletionDate
    ]
    | if length == 1 then .[0] else error("missing exact deletion event") end
  `;
  const check = (document, arn = secretArn) =>
    spawnSync('jq', ['-er', '--arg', 'arn', arn, predicate], {
      encoding: 'utf8',
      input: `${JSON.stringify(document)}\n`,
    });

  assert.equal(
    check(cloudTrail).stdout.trim(),
    '2026-08-11T13:54:24Z',
  );
  assert.notEqual(
    check({
      Events: [
        {
          CloudTrailEvent: JSON.stringify({
            ...deleteEvent,
            requestParameters: {
              ...deleteEvent.requestParameters,
              recoveryWindowInDays: 30,
            },
          }),
        },
      ],
    }).status,
    0,
  );
  assert.notEqual(
    check(cloudTrail, `${secretArn}-different`).status,
    0,
  );

  const verifySecretsStart = source.indexOf('verify_secrets() {');
  const verifySecretsEnd = source.indexOf(
    '\nverify_logs() {',
    verifySecretsStart,
  );
  assert.notEqual(verifySecretsStart, -1);
  assert.notEqual(verifySecretsEnd, -1);
  const verifySecrets = source.slice(verifySecretsStart, verifySecretsEnd);

  assert.match(source, /secret_deletion_epoch\(\)/);
  assert.match(source, /cloudtrail lookup-events/);
  assert.match(source, /AttributeValue=DeleteSecret/);
  assert.match(
    source,
    /\.requestParameters\.recoveryWindowInDays == 7/,
  );
  assert.match(source, /\.responseElements\.deletionDate/);
  assert.match(verifySecrets, /secret_deletion_epoch/);
  assert.doesNotMatch(verifySecrets, /seven_day_deletion_epoch/);
});

test('c12_7_tenant_export_follows_opaque_continuation_cursors', () => {
  assert.match(source, /while \(\( page_number <= 100 \)\); do/);
  assert.match(source, /\.next_cursor \/\/ empty/);
  assert.match(source, /\$cursor \| @uri/);
  assert.match(
    source,
    /\[\[ "\$next_cursor" != "\$cursor" \]\][\s\S]*repeated its continuation cursor/,
  );
  assert.match(source, /any\(\.records\[\]; \.user_id == \$user\)/);
});

test('data-governance drill proves standby Region-local tenant data is absent', () => {
  assert.match(
    source,
    /standby_region_local_tables:\s*\$standby_region_local_tables/,
  );
  assert.match(source, /table_total_count "\$STANDBY_REGION" "\$table"/);
  assert.match(source, /--consistent-read --select COUNT/);
  assert.match(source, /--exclusive-start-key "\$start_key"/);
  assert.match(source, /standby_region_local\\t%s\\t%s\\t%s\\t%s/);
  assert.match(
    source,
    /Standby Region-local table \$role retains \$count deployment rows/,
  );
  assert.match(
    source,
    /\.standby_region_local_tables[\s\S]*to_entries \| sort_by\(\.key\)/,
  );
});

test('c12_7_offboarding_uses_strong_paginated_live_authority_counts', () => {
  assert.match(source, /--table-name "\$table" --consistent-read --no-paginate/);
  assert.match(source, /any\(\.\. \| strings/);
  assert.ok(
    source.includes('contains("\\"tenant_id\\":\\"" + $tenant + "\\"")'),
  );
  assert.match(source, /target_count\(\)/);
  assert.match(source, /select\(any\(\.\. \| strings; contains\(\$target\)\)\)/);
  assert.match(source, /target_count "\$region" "\$table" "\$t1_user"/);
  assert.match(
    source,
    /\$role retains \$user_count live t1 user references in \$region/,
  );
  assert.match(source, /target_count "\$REGION" "\$table" "\$t1_user"/);
  assert.match(
    source,
    /Region-local table \$table retains \$user_count live t1 user references/,
  );
});

test('c12_7_service_evidence_proves_zero_counts_in_every_replica', () => {
  assert.match(source, /\.payload\.replica_live_counts \| type == "object"/);
  assert.match(
    source,
    /\.payload\.replica_live_counts \| keys \| sort \| join\(","\)/,
  );
  assert.match(source, /\.verification_state == "provider_strong_read"/);
  assert.match(source, /\.verified_at \| type == "number"/);
  assert.match(source, /all\(\.live_counts\[\]; \. == 0\)/);
});

test('service evidence separates external Secret outcomes from product deadlines', () => {
  assert.match(source, /\.payload\.external_actions \| type == "array"/);
  assert.match(source, /\.outcome == "external_retained"/);
  assert.match(source, /\.outcome == "pending_deletion"/);
  assert.match(
    source,
    /\.secrets_manager_product_managed\.retention_until[\s\S]*\| max\)/,
  );
  assert.match(
    source,
    /\.payload\.retention_resources\.secrets_manager_external\.state[\s\S]*"verified"/,
  );
});

test('data-governance drill verifies every retained SQS message state', () => {
  assert.match(source, /TenantKeyOperationsQueueUrl TenantKeyOperationsDlqUrl/);
  assert.match(source, /ApproximateNumberOfMessagesDelayed/);
  assert.match(
    source,
    /\[\[ "\$visible" == "0" && "\$inflight" == "0" && "\$delayed" == "0" \]\]/,
  );
  assert.match(source, /outside the selected account\/Region/);
  assert.match(source, /for attempt in \$\(seq 1 60\)/);
  assert.match(
    source,
    /if ! is_done service-evidence-verified;[\s\S]*verify_service_evidence[\s\S]*if ! is_done queues-verified;[\s\S]*verify_queues[\s\S]*mark_done queues-verified[\s\S]*write_final_evidence/,
  );
});

test('tenant-key DLQ allowance is pre-run, non-offboarded, and fully inspected', () => {
  const sourceArn =
    'arn:aws:sqs:us-east-1:123456789012:tenant-key-operations';
  const createdAt = 1785843796;
  const message = {
    MessageId: 'e8fb4c0b-91c3-4408-98d3-3d85d4e7ac69',
    MD5OfBody: '3066c03c13ab8638d5ef0d2238c72223',
    Attributes: {
      SentTimestamp: '1785680728092',
      DeadLetterQueueSourceArn: sourceArn,
    },
    Body: JSON.stringify({
      tenant_id: 't1',
      action: 'rotate',
      operation_id: 'historical-rotation',
      requested_at: 1785680728,
    }),
  };
  const predicate = `
    include "tenant_key_dlq_evidence";
    tenant_key_dlq_messages_qualify(
      $source; $offboard; $created; $expected
    )
  `;
  const check = (candidate, expected = candidate.length) =>
    spawnSync(
      'jq',
      [
        '-e',
        '-L',
        path.dirname(TENANT_KEY_DLQ_EVIDENCE),
        '--arg',
        'source',
        sourceArn,
        '--arg',
        'offboard',
        't2',
        '--argjson',
        'created',
        String(createdAt),
        '--argjson',
        'expected',
        String(expected),
        predicate,
      ],
      {
        encoding: 'utf8',
        input: `${JSON.stringify(candidate)}\n`,
      },
    );

  assert.equal(check([message]).status, 0);
  const body = JSON.parse(message.Body);
  assert.notEqual(
    check([{ ...message, Body: JSON.stringify({ ...body, tenant_id: 't2' }) }])
      .status,
    0,
  );
  assert.notEqual(
    check([
      {
        ...message,
        Attributes: {
          ...message.Attributes,
          SentTimestamp: String(createdAt * 1000 + 1),
        },
      },
    ]).status,
    0,
  );
  assert.notEqual(
    check([
      {
        ...message,
        Body: JSON.stringify({ ...body, requested_at: createdAt }),
      },
    ]).status,
    0,
  );
  assert.notEqual(
    check([
      {
        ...message,
        Body: JSON.stringify({ ...body, unexpected: 'field' }),
      },
    ]).status,
    0,
  );
  assert.notEqual(
    check([
      {
        ...message,
        Attributes: {
          ...message.Attributes,
          DeadLetterQueueSourceArn: `${sourceArn}-different`,
        },
      },
    ]).status,
    0,
  );
  assert.notEqual(
    check([
      {
        ...message,
        Attributes: {
          ...message.Attributes,
          SentTimestamp: `0${message.Attributes.SentTimestamp}`,
        },
      },
    ]).status,
    0,
  );
  assert.notEqual(check([message, message]).status, 0);
  assert.notEqual(check([message], 2).status, 0);

  assert.match(source, /inspect_tenant_key_dlq_messages\(\)/);
  assert.match(
    source,
    /sqs receive-message[\s\S]*--visibility-timeout 60/,
  );
  assert.match(
    source,
    /sqs change-message-visibility[\s\S]*--visibility-timeout 0/,
  );
  assert.match(source, /while \(\( empty_receives < 2 \)\)/);
  assert.match(source, /--wait-time-seconds 10/);
  assert.match(
    source,
    /cleanup_process_files\(\)[\s\S]*restore_tenant_key_dlq_visibility/,
  );
  assert.match(
    source,
    /\.Body \| fromjson[\s\S]*keys \| sort[\s\S]*"tenant_id"/,
  );
  assert.match(source, /retained tenant-key DLQ count differs/);
  assert.match(source, /cmp -s "\$previous_candidate" "\$candidate"/);
});

test('tenant-key DLQ inspection restores messages and fails closed', (t) => {
  const message = {
    MessageId: 'e8fb4c0b-91c3-4408-98d3-3d85d4e7ac69',
    MD5OfBody: '3066c03c13ab8638d5ef0d2238c72223',
    Attributes: {
      SentTimestamp: '1785680728092',
      DeadLetterQueueSourceArn:
        'arn:aws:sqs:us-east-1:123456789012:tenant-key-operations',
    },
    Body: JSON.stringify({
      tenant_id: 't1',
      action: 'rotate',
      operation_id: 'historical-rotation',
      requested_at: 1785680728,
    }),
  };

  const accepted = runTenantKeyDlqInspection(t, { message });
  assert.equal(accepted.result.status, 0, accepted.result.stderr);
  assert.equal(accepted.receiveCount, 3);
  assert.match(accepted.restores, /receipt-1/);
  assert.equal(
    accepted.evidence,
    [
      'TenantKeyOperationsDlqMessage',
      message.MessageId,
      message.MD5OfBody,
      message.Attributes.SentTimestamp,
      '1785680728',
    ].join('\t') + '\n',
  );

  const t2Body = JSON.parse(message.Body);
  const rejected = runTenantKeyDlqInspection(t, {
    message: {
      ...message,
      Body: JSON.stringify({ ...t2Body, tenant_id: 't2' }),
    },
  });
  assert.notEqual(rejected.result.status, 0);
  assert.match(rejected.restores, /receipt-1/);

  const mismatch = runTenantKeyDlqInspection(t, {
    message,
    expectedVisible: 0,
  });
  assert.notEqual(mismatch.result.status, 0);
  assert.equal(mismatch.receiveCount, 1);
  assert.match(mismatch.restores, /receipt-1/);

  const restoreFailure = runTenantKeyDlqInspection(t, {
    message,
    restoreFails: true,
  });
  assert.notEqual(restoreFailure.result.status, 0);
  assert.equal(
    restoreFailure.restores.trim().split('\n').length,
    3,
  );

  const interrupted = runTenantKeyDlqInspection(t, {
    message,
    interruptDuringReceive: true,
  });
  assert.equal(interrupted.result.status, 143);
  assert.match(interrupted.restores, /receipt-1/);
});

test('c12_7_drill_declares_external_retention_exception_boundary', () => {
  assert.match(
    source,
    /\.retention_exception_capability == "external_operator_managed"/,
  );
});

test('c12_7_secret_cleanup_binds_persisted_ownership_metadata', () => {
  assert.match(
    source,
    /tenant_secret_dependencies:\s*\$tenant_secret_dependencies/,
  );
  assert.match(
    source,
    /\.tenant_secret_dependencies[\s\S]*to_entries \| sort_by\(\.key\)/,
  );
  assert.match(
    source,
    /"\$ownership" == "product_managed"[\s\S]*outcome="pending_deletion"/,
  );
  assert.match(
    source,
    /"\$ownership" == "external"[\s\S]*outcome="external_retained"/,
  );
  assert.match(
    source,
    /Secret dependency ownership counts differ from the qualifying profile/,
  );
});
