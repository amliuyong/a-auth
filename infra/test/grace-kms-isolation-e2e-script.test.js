const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const SCRIPT = fs.readFileSync(
  path.resolve(__dirname, '../../e2e/grace_kms_isolation.sh'),
  'utf8',
);

test('live gate binds all three deployments and both runtimes to one artifact', () => {
  assert.match(SCRIPT, /DEV_STACK.*AgentAuthDev/);
  assert.match(SCRIPT, /SAAS_STACK.*AgentAuthSaas/);
  assert.match(SCRIPT, /STANDBY_STACK.*AgentAuthSaasStandby/);
  assert.match(SCRIPT, /validate_runtime.*AuthFnName non_token/);
  assert.match(SCRIPT, /validate_runtime.*TokenFnName token/);
  assert.match(SCRIPT, /CodeSha256/);
  assert.match(SCRIPT, /deployment-provenance\.json/);
  assert.match(SCRIPT, /cmp "\$unpacked\/bootstrap" "\$LOCAL_BOOTSTRAP"/);
  assert.match(SCRIPT, /agent-auth-c3-4-cutover-\$EXPECTED_COMMIT\.json/);
  assert.match(SCRIPT, /\.target_commit == \$commit/);
  assert.match(SCRIPT, /\.status == "prepared"/);
  assert.match(SCRIPT, /legacy_grace_key_id.*CUTOVER_STATE_FILE/s);
  assert.match(SCRIPT, /cutover_state_sha256:\$cutover_sha/);
});

test('live IAM proof denies Auth and allows Token on the grace key', () => {
  assert.match(SCRIPT, /aws iam simulate-principal-policy/);
  assert.match(SCRIPT, /kms:Decrypt kms:GenerateDataKey/);
  assert.match(SCRIPT, /auth-grace-simulation/);
  assert.match(SCRIPT, /token-grace-simulation/);
  assert.match(SCRIPT, /CibaNotificationEnvelopeKeyId/);
  assert.match(SCRIPT, /LegacyGraceEnvelopeKeyId/);
  assert.match(SCRIPT, /legacy grace key is not disabled/);
  assert.match(SCRIPT, /grace and CIBA keys are not distinct/);
});

test('direct Lambda events prove the route boundary', () => {
  assert.match(SCRIPT, /TokenFn exposed discovery/);
  assert.match(SCRIPT, /AuthFn exposed \/token/);
  assert.match(SCRIPT, /TokenFn did not handle \/token/);
  assert.match(SCRIPT, /--cli-binary-format raw-in-base64-out/);
});

test('grace replay evidence requires exact cached tokens and ciphertext-only storage', () => {
  assert.match(SCRIPT, /application_type:"web"/);
  assert.doesNotMatch(SCRIPT, /application_type:"native"/);
  const authorize = SCRIPT.indexOf(
    '"$DEV_ORIGIN/authorize?response_type=code&$AQ"',
  );
  const context = SCRIPT.indexOf(
    '"$DEV_ORIGIN/consent/context?$CONSENT_QUERY"',
  );
  assert.ok(authorize >= 0 && context > authorize);
  assert.match(SCRIPT, /AUTHZ_STATUS.*303/s);
  assert.match(SCRIPT, /location\.path == "\/consent"/);
  assert.match(SCRIPT, /params\.get\("authz_session_id", \[\]\)/);
  assert.match(
    SCRIPT,
    /USER_ID="\$\(jq -er '\.user_id \| select\(type == "string" and length > 0\)'/,
  );
  assert.doesNotMatch(
    SCRIPT,
    /consent\/context\?\$AQ/,
    'the live flow must not bypass /authorize session creation',
  );
  assert.match(SCRIPT, /cmp "\$WORK\/r1-projection\.json" "\$WORK\/replay-projection\.json"/);
  assert.match(SCRIPT, /has\("ciphertext"\) and has\("enc_dk"\) and has\("nonce"\)/);
  assert.match(
    SCRIPT,
    /keys - \[[\s\S]*"family_id"[\s\S]*"ciphertext"[\s\S]*"dpop_jkt"/,
  );
  assert.match(SCRIPT, /\.ciphertext\.B \| type == "string" and length > 0/);
  assert.match(SCRIPT, /current refresh token was invalidated by the grace replay/);
});

test('PASS is published only after client, user, grant, refresh, and grace cleanup', () => {
  const cleanup = SCRIPT.indexOf(
    'verify_cleanup || fail "temporary authority did not cleanly converge"',
  );
  const evidence = SCRIPT.indexOf('schema:"agent-auth-c3-4-evidence-v1"');
  assert.ok(cleanup >= 0 && evidence > cleanup);
  assert.match(SCRIPT, /ddb_absent "\$DEV_CLIENTS_TABLE"/);
  assert.match(SCRIPT, /recover_client_id "\$WORK\/client-recovery-scan\.json"/);
  assert.match(SCRIPT, /--projection-expression 'client_id,redirect_uris'/);
  assert.ok(
    SCRIPT.indexOf('USER_CREATED=1') <
      SCRIPT.indexOf('admin_request POST /admin/users'),
    'cleanup intent must precede user response parsing',
  );
  assert.ok(
    SCRIPT.indexOf('CLIENT_CREATED=1') <
      SCRIPT.indexOf('admin_request POST /admin/clients'),
    'cleanup intent must precede client response parsing',
  );
  assert.match(SCRIPT, /then "__absent__"/);
  assert.match(SCRIPT, /grants-after-cleanup/);
  assert.match(SCRIPT, /refresh-after-cleanup/);
  assert.match(SCRIPT, /grace-after-cleanup/);
  assert.match(SCRIPT, /for _ in \$\(seq 1 45\)/);
  assert.match(SCRIPT, /stable_absence_started_at=-1/);
  assert.match(SCRIPT, /now="\$SECONDS"/);
  assert.match(SCRIPT, /SECONDS - stable_absence_started_at >= 15/);
  assert.match(SCRIPT, /else\s+stable_absence_started_at=-1/s);
  assert.match(SCRIPT, /cleanup did not converge; recovery directory:/);
  assert.match(SCRIPT, /rm -f "\$EVIDENCE_FILE"/);
  assert.match(SCRIPT, /user_path="\$\(urlencode "\$USER_ID"\)"/);
  assert.match(SCRIPT, /"\$status" == "200"/);
  assert.match(SCRIPT, /\.status == "tombstoned"/);
  assert.match(SCRIPT, /\.active_grants == 0/);
  assert.match(SCRIPT, /\.sessions == 0/);
  assert.match(SCRIPT, /\.password_status == "not_configured"/);
  assert.match(SCRIPT, /\.has_recovery == false/);
  assert.match(
    SCRIPT,
    /STACK="\$DEV_STACK" REGION="\$PRIMARY_REGION" PROFILE="\$PROFILE"[\s\\]*\n\s*"\$ROOT\/e2e\/get-admin-token\.sh"/,
  );
  assert.doesNotMatch(
    SCRIPT,
    /get-admin-token\.sh"[\s\\]*\n\s*STACK=/,
  );
  assert.match(SCRIPT, /trap 'exit 130' INT/);
  assert.match(SCRIPT, /trap 'exit 143' TERM/);
  assert.match(SCRIPT, /remove_local_recovery_material/);
  assert.match(SCRIPT, /sensitive_values_in_evidence:false/);
});
