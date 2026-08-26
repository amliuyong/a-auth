const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const PASSKEY = fs.readFileSync(
  path.resolve(__dirname, '../../e2e/passkey_saas_isolation.sh'),
  'utf8',
);
const QUOTA = fs.readFileSync(
  path.resolve(__dirname, '../../e2e/tenant_sign_quota_live.sh'),
  'utf8',
);
const SUBJECT = fs.readFileSync(
  path.resolve(__dirname, '../../e2e/tenant_subject_profile_live.sh'),
  'utf8',
);

function assertFailClosedSecretScrub(source, trapText, firstSensitiveWrite) {
  const trap = source.indexOf(trapText);
  const sensitiveWrite = source.indexOf(firstSensitiveWrite);
  assert.ok(trap >= 0 && sensitiveWrite > trap);
  assert.match(source, /: >"\$file" && rm -f -- "\$file" \|\| exit 1/);
  assert.match(source, /rmdir "\$SECRETS" 2>\/dev\/null \|\| status=1/);
  assert.match(source, /\[\[ ! -e "\$SECRETS" \]\] \|\| status=1/);
  assert.match(source, /scrubbed=0[\s\S]*status=1/);
  assert.match(source, /trap '' INT TERM[\s\S]*trap - EXIT/);
  assert.match(
    source,
    /if \[\[ "\$scrubbed" == "1" \]\] && purge_work_files; then/,
  );
  assert.doesNotMatch(source, /rmdir "\$SECRETS" 2>\/dev\/null \|\| true/);
  assert.doesNotMatch(source, /"\$WORK\/(?:auth|bootstrap)\.json"/);
}

function assertSingleFinalPass(source, cleanupMarker, passText) {
  assert.equal(source.match(/PASS:/g)?.length, 1);
  const cleanup = source.lastIndexOf(cleanupMarker);
  const trapCleared = source.lastIndexOf('trap - EXIT INT TERM');
  const finalPass = source.lastIndexOf(passText);
  assert.ok(cleanup >= 0 && trapCleared > cleanup && finalPass > trapCleared);
}

test('passkey isolation accepts named tenant A/B inputs and records real user ids', () => {
  assert.match(PASSKEY, /TENANT_A_URL:-\$\{T1_URL:-\}/);
  assert.match(PASSKEY, /TENANT_B_URL:-\$\{T2_URL:-\}/);
  assert.match(PASSKEY, /T1_USER_ID="\$\(jq -er '\.user_id'/);
  assert.match(PASSKEY, /T2_USER_ID="\$\(jq -er '\.user_id'/);
  assert.match(PASSKEY, /tenant_ids: \[\$tenant_a, \$tenant_b\]/);
});

test('passkey isolation binds t3 and exact harness provenance without reusing t2', () => {
  assert.match(PASSKEY, /TENANT_B_ID="\$\{TENANT_B_ID:-t3\}"/);
  assert.match(PASSKEY, /permanently offboarded t2 tenant must never be reused/);
  assert.match(PASSKEY, /T1_HOST%%\.\*.*TENANT_A_ID/s);
  assert.match(PASSKEY, /T2_HOST%%\.\*.*TENANT_B_ID/s);
  assert.match(PASSKEY, /COMMITTED_SCRIPT_SHA256/);
  assert.match(PASSKEY, /passkey harness does not match the exact deployed commit/);
  assert.match(PASSKEY, /offboarded_t2_not_reused: "pass"/);
});

test('passkey fixture creation is recoverable and cleanup is stable', () => {
  const aIntent = PASSKEY.indexOf('USER_INTENT=1');
  const aPost = PASSKEY.indexOf('-X POST "$T1_URL/admin/users"');
  const bIntent = PASSKEY.indexOf('T2_USER_INTENT=1');
  const bPost = PASSKEY.indexOf('-X POST "$T2_URL/admin/users"');
  assert.ok(aIntent >= 0 && aIntent < aPost);
  assert.ok(bIntent >= 0 && bIntent < bPost);
  assert.match(PASSKEY, /recover_user_id/);
  assert.match(PASSKEY, /\/admin\/users.*q=\$EMAIL/s);
  assert.match(PASSKEY, /SECONDS - stable_started >= 15/);
  assert.match(PASSKEY, /\.status == "tombstoned"/);
  assert.match(PASSKEY, /\.active_grants == 0/);
  assert.match(PASSKEY, /\.passkeys == 0/);
  assert.match(PASSKEY, /scrub_secrets/);
  assert.match(PASSKEY, /sensitive_values_in_evidence: false/);
});

test('passkey gate installs cleanup before secrets and scrubs fail closed', () => {
  assertFailClosedSecretScrub(
    PASSKEY,
    'trap cleanup EXIT',
    "printf 'authorization: Bearer %s",
  );
  assertSingleFinalPass(
    PASSKEY,
    'rmdir "$WORK"',
    'PASS: C9.4 tenant passkey isolation evidence published',
  );
});

test('tenant sign quota gate binds deployment and harness to one exact commit', () => {
  assert.match(QUOTA, /DEPLOYED_COMMIT.*EXPECTED_COMMIT/s);
  assert.match(QUOTA, /HARNESS_COMMIT.*EXPECTED_COMMIT/s);
  assert.match(QUOTA, /live evidence requires a clean worktree/);
  assert.match(QUOTA, /AGENT_AUTH_KMS_TENANT_GATE_CAPACITY.*tonumber > 0/s);
});

test('tenant sign quota recovers ambiguous client creation and scrubs secrets', () => {
  assert.match(QUOTA, /REDIRECT_A="https:\/\/c10-14-a-\$RUN_ID\.invalid\/cb"/);
  assert.match(QUOTA, /REDIRECT_B="https:\/\/c10-14-b-\$RUN_ID\.invalid\/cb"/);
  assert.match(QUOTA, /recover_client_id/);
  assert.match(QUOTA, /--page-size 100/);
  const aIntent = QUOTA.indexOf('printf -v "$intent_var"');
  const createPost = QUOTA.indexOf('-X POST', QUOTA.indexOf('create_client()'));
  assert.ok(aIntent >= 0 && aIntent < createPost);
  assert.match(QUOTA, /SECONDS - stable_started >= 15/);
  assert.match(QUOTA, /SECRETS="\$WORK\/secrets"/);
  assert.match(QUOTA, /scrub_secrets/);
  assert.match(QUOTA, /sensitive_values_retained:false/);
});

test('tenant sign quota gate proves both tenants sign before isolating one bucket', () => {
  assert.match(QUOTA, /token_request "\$TENANT_A".*warm-a/s);
  assert.match(QUOTA, /token_request "\$TENANT_B".*warm-b/s);
  assert.match(QUOTA, /TENANT_A_BUCKET="kms-sign-tenant:\$TENANT_A"/);
  assert.match(QUOTA, /TENANT_B_BUCKET="kms-sign-tenant:\$TENANT_B"/);
  assert.match(QUOTA, /A_STATUS.*503/s);
  assert.match(QUOTA, /B_STATUS.*200/s);
  assert.match(QUOTA, /retry-after: \[1-9\]/i);
});

test('shared quota rows restore only under version ownership', () => {
  assert.match(QUOTA, /condition-expression 'version = :expected'/);
  assert.match(QUOTA, /A_FINAL_VERSION.*A_SEED_VERSION \+ 1/s);
  assert.match(QUOTA, /B_FINAL_VERSION.*B_BEFORE_VERSION \+ 1/s);
  assert.match(QUOTA, /restore_bucket_if_owned/);
  assert.match(QUOTA, /shared buckets restored byte-for-byte|restored byte-for-byte/i);
});

test('quota evidence is published after shared-state and fixture cleanup', () => {
  const restore = QUOTA.lastIndexOf('shared bucket was not restored byte-for-byte');
  const fixtureCleanup = QUOTA.lastIndexOf('temporary tenant quota fixtures did not cleanly converge');
  const evidence = QUOTA.indexOf('schema:"agent-auth-c10-14-evidence-v1"');
  assert.ok(restore >= 0 && fixtureCleanup > restore && evidence > fixtureCleanup);
  assert.match(QUOTA, /sensitive_values_in_evidence:false/);
});

test('tenant quota gate installs cleanup before snapshots and scrubs fail closed', () => {
  assertFailClosedSecretScrub(
    QUOTA,
    'trap cleanup EXIT',
    '--output json >"$SECRETS/auth.json"',
  );
  assertSingleFinalPass(
    QUOTA,
    'rmdir "$WORK"',
    'PASS: C10.14 tenant signing quota evidence published',
  );
});

test('subject profile gate binds bootstrap, deployment and harness commit', () => {
  assert.match(SUBJECT, /DEPLOYED_COMMIT.*EXPECTED_COMMIT/s);
  assert.match(SUBJECT, /rev-parse HEAD.*EXPECTED_COMMIT/s);
  assert.match(
    SUBJECT,
    /\.tenant_subject_types\[\$a\] == null[\s\S]*\.tenant_subject_types\[\$b\] == "public"/,
  );
  assert.match(SUBJECT, /live evidence requires a clean worktree/);
});

test('subject profile gate proves discovery and metadata differ by tenant', () => {
  assert.match(SUBJECT, /subject_types_supported == \["pairwise"\]/);
  assert.match(SUBJECT, /subject_types_supported == \["public"\]/);
  assert.match(SUBJECT, /MULTI_A_STATUS.*400/s);
  assert.match(SUBJECT, /MULTI_B_STATUS.*201/s);
  assert.match(
    SUBJECT,
    /EXTRA_PAIRWISE_INTENT=1[\s\S]*MULTI_A_STATUS=.*admin_request "\$TENANT_A"/,
  );
  assert.match(SUBJECT, /recover_client_id "\$TENANT_A" "\$WORK\/multi-a\.redirect"/);
  assert.match(SUBJECT, /extra-pairwise-client-absent\.json/);
});

test('subject profile gate uses a real authorization-code consent flow', () => {
  assert.match(SUBJECT, /\/authorize\?\$query/);
  assert.match(SUBJECT, /AUTHZ_SESSION_ID|authz_session_id/);
  assert.match(SUBJECT, /\/consent\/context\?\$consent_query/);
  assert.match(SUBJECT, /\/consent\/decision/);
  assert.match(SUBJECT, /grant_type":"authorization_code"/);
  assert.match(SUBJECT, /"\$SECRETS\/\$tenant-\$label-token\.json"/);
});

test('subject profile gate checks actual ID-token subjects', () => {
  assert.match(SUBJECT, /A_SUB.*USER_IDS\[\$TENANT_A\]/s);
  assert.match(SUBJECT, /A_SECOND_SUB.*USER_IDS\[\$TENANT_A\]/s);
  assert.match(SUBJECT, /B_SUB.*USER_IDS\[\$TENANT_B\]/s);
  assert.match(SUBJECT, /B_SECOND_SUB.*USER_IDS\[\$TENANT_B\]/s);
  assert.match(SUBJECT, /pairwise tenant exposed the canonical user identifier/);
  assert.match(SUBJECT, /pairwise tenant reused one subject across distinct sectors/);
  assert.match(SUBJECT, /public tenant did not issue its canonical user identifier/);
  assert.match(SUBJECT, /public tenant changed subject across distinct sectors/);
});

test('subject profile gate proves userinfo consistency for both sectors', () => {
  assert.match(SUBJECT, /run_code_flow "\$TENANT_A" primary/);
  assert.match(SUBJECT, /run_code_flow "\$TENANT_A" secondary/);
  assert.match(SUBJECT, /run_code_flow "\$TENANT_B" primary/);
  assert.match(SUBJECT, /run_code_flow "\$TENANT_B" secondary/);
  assert.match(SUBJECT, /\/userinfo"/);
  assert.match(SUBJECT, /userinfo subject differs from the ID token/);
  assert.match(SUBJECT, /pairwise_cross_sector_subjects_differ:"pass"/);
  assert.match(SUBJECT, /public_cross_sector_subjects_match:"pass"/);
  assert.match(SUBJECT, /id_token_and_userinfo_subjects_match:"pass"/);
});

test('subject profile evidence follows stable authority cleanup', () => {
  assert.match(SUBJECT, /SECONDS - stable_started >= 15/);
  assert.match(SUBJECT, /\.status == "tombstoned"/);
  assert.match(SUBJECT, /\.active_grants == 0/);
  const cleanup = SUBJECT.lastIndexOf('temporary authority cleanup was not verified');
  const evidence = SUBJECT.indexOf('schema:"agent-auth-c1-1b-evidence-v1"');
  assert.ok(cleanup >= 0 && evidence > cleanup);
  assert.match(SUBJECT, /sensitive_values_in_evidence:false/);
});

test('subject profile gate destroys all bearer and protocol secrets on every exit', () => {
  assert.match(SUBJECT, /SECRETS="\$WORK\/secrets"/);
  assert.match(SUBJECT, /--config "\$SECRETS\/\$tenant-admin\.curl"/);
  assert.match(SUBJECT, /"\$SECRETS\/\$tenant-\$label-token\.json"/);
  assertFailClosedSecretScrub(
    SUBJECT,
    'trap on_exit EXIT',
    'printf \'%s\' "$INITIAL_PASSWORD"',
  );
  assertSingleFinalPass(
    SUBJECT,
    'cleanup || fail "temporary authority cleanup did not converge"',
    'PASS: C1.1b tenant subject profile evidence published',
  );
  assert.match(SUBJECT, /sensitive_values_retained:false/);
  assert.match(SUBJECT, /COMMITTED_SCRIPT_SHA256/);
});
