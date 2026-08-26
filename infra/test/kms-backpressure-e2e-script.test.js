const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const SCRIPT_PATH = path.resolve(__dirname, '../../e2e/kms_backpressure.sh');
const SCRIPT = fs.readFileSync(SCRIPT_PATH, 'utf8');

function bashFunctionBody(name) {
  const match = SCRIPT.match(new RegExp(`${name}\\(\\) \\{([\\s\\S]*?)\\n\\}`));
  assert.ok(match, `${name} function must exist`);
  return match[1];
}

test('C10.2 live gate binds the deployed and harness commits', () => {
  assert.match(SCRIPT, /EXPECTED_DEPLOYED_COMMIT=.*:\?set EXPECTED_DEPLOYED_COMMIT/);
  assert.match(SCRIPT, /status --porcelain/);
  assert.match(SCRIPT, /merge-base --is-ancestor/);
  assert.match(SCRIPT, /AGENT_AUTH_DEPLOYMENT_COMMIT == \$commit/);
  assert.match(SCRIPT, /KMS backpressure runtime changed after the deployed commit/);
  assert.match(SCRIPT, /secrets\.token_hex\(16\)/);
  assert.match(SCRIPT, /GLOBAL_KEY="global-kms-sign:test:\$RUN_ID"/);
});

test('C10.2 live gate applies and restores the exact Lambda environment', () => {
  const receipt = bashFunctionBody('receipt_environment_matches');
  const restore = bashFunctionBody('restore_lambda_environment');

  assert.match(SCRIPT, /--revision-id "\$ORIGINAL_REVISION"/);
  assert.match(SCRIPT, /AGENT_AUTH_KMS_GATE_TEST_RUN/);
  assert.match(SCRIPT, /jq -S --arg run "\$RUN_ID"/);
  assert.match(SCRIPT, /auth\.test\.update\.json/);
  assert.match(SCRIPT, /auth\.restore\.update\.json/);
  assert.match(SCRIPT, /receipt_environment_matches/);
  assert.match(SCRIPT, /env\.test-receipt\.json/);
  assert.match(SCRIPT, /env\.restore-receipt\.json/);
  assert.match(SCRIPT, /receipt does not contain the exact test environment/);
  assert.match(receipt, /canonical_environment[\s\S]*\|\| return 1/);
  assert.match(receipt, /cmp -s "\$rendered_env" "\$expected_env"/);
  assert.doesNotMatch(receipt, /RevisionId/);
  assert.match(
    restore,
    /if cmp -s "\$current_env" "\$WORK\/env\.before\.json"; then[\s\S]*receipt_environment_matches[\s\S]*\|\| return 1[\s\S]*LAMBDA_ENV_CHANGED=0/,
  );
  assert.match(
    restore,
    /cmp -s "\$current_env" "\$WORK\/env\.test\.json" \|\| return 1/,
  );
  assert.match(
    restore,
    /--revision-id "\$current_revision"[\s\S]*auth\.restore\.update\.pending\.json/,
  );
  assert.match(
    restore,
    /auth\.restore\.update\.json" "\$WORK\/env\.before\.json"[\s\S]*\|\| return 1[\s\S]*aws lambda wait function-updated/,
  );
  assert.match(
    restore,
    /LastUpdateStatus == "Successful"[\s\S]*cmp -s "\$current_env" "\$WORK\/env\.before\.json" \|\| return 1/,
  );
  assert.doesNotMatch(SCRIPT, /RevisionId[^;\n]*(?:==|!=)|(?:==|!=)[^;\n]*RevisionId/);
  assert.match(
    SCRIPT,
    /aws lambda wait function-updated[\s\S]*aws lambda get-function-configuration/,
  );
  assert.match(SCRIPT, /cmp -s "\$current_env" "\$WORK\/env\.test\.json"/);
  assert.match(SCRIPT, /LAMBDA_ENV_CHANGED=1\naws lambda update-function-configuration/);
  assert.match(SCRIPT, /restore_lambda_environment/);
  assert.match(SCRIPT, /failed to restore the exact original Lambda environment/);
  assert.match(SCRIPT, /lambda_environment_restored:true/);
});

test('C10.2 live gate proves exact proactive shedding', () => {
  assert.match(SCRIPT, /CAPACITY=2/);
  assert.match(SCRIPT, /REQUEST_COUNT=8/);
  assert.match(SCRIPT, /load-\$index\.ready/);
  assert.match(SCRIPT, /load\.start/);
  assert.match(SCRIPT, /pids\+=\("\$!"\)/);
  assert.match(SCRIPT, /\[\[ "\$ok_count" == "\$CAPACITY" \]\]/);
  assert.match(SCRIPT, /REQUEST_COUNT - CAPACITY/);
  assert.match(SCRIPT, /\^retry-after: \[1-9\]\[0-9\]\*/);
  assert.match(SCRIPT, /\.error == "temporarily_unavailable"/);
  assert.match(SCRIPT, /request \$index returned 500/);
  assert.match(SCRIPT, /\.Item\.version\.N == \$expected/);
  assert.match(SCRIPT, /\.Item\.tokens\.N == "0"/);
  assert.match(SCRIPT, /RECOVERY_STATUS=.*token_request recovery/);
});

test('C10.2 evidence is fail-closed on state restoration and cleanup', () => {
  const cleanup = SCRIPT.indexOf(
    'pass "temporary authority, CDN object, rate rows, and local credentials are absent"',
  );
  const evidence = SCRIPT.indexOf('result:"pass"');
  assert.ok(cleanup > 0);
  assert.ok(evidence > cleanup);
  assert.match(SCRIPT, /isolated signing test bucket already exists/);
  assert.match(SCRIPT, /delete_owned_global_bucket/);
  assert.match(SCRIPT, /isolated_test_bucket:true/);
  assert.match(SCRIPT, /isolated_test_bucket_removed:true/);
  assert.match(SCRIPT, /cleanup_stable=\$\(\(cleanup_stable \+ 1\)\)/);
  assert.match(SCRIPT, /cleanup_stable" -ge 15/);
  assert.match(SCRIPT, /CLEANUP_STATE_UNVERIFIED=1/);
  assert.match(SCRIPT, /temporary-state cleanup requires manual verification/);
  assert.match(SCRIPT, /GLOBAL_BUCKET_OWNED=0\nCLEANED=1/);
  assert.equal(
    (SCRIPT.match(/GLOBAL_BUCKET_OWNED=0/g) || []).length,
    2,
    'bucket ownership is released only at initialization and after stable cleanup',
  );
  assert.match(SCRIPT, /list-objects-v2/);
  assert.match(SCRIPT, /public-jwks-clean\.body/);
  assert.match(SCRIPT, /for _ in \$\(seq 1 90\)/);
  assert.match(SCRIPT, /RESOURCE="https:\/\/c10-2-\$RUN_ID\.invalid"/);
  assert.match(SCRIPT, /CLEANUP_RECOVERY_REQUIRED=1/);
  assert.match(SCRIPT, /protected snapshot retained at %s/);
  assert.match(SCRIPT, /trap cleanup EXIT/);
  assert.match(SCRIPT, /trap 'exit 130' INT/);
  assert.match(SCRIPT, /trap 'exit 143' TERM/);
  assert.match(SCRIPT, /rm -rf "\$WORK"\npass "temporary authority/);
  assert.doesNotMatch(
    SCRIPT.slice(evidence),
    /CLIENT_ID|BINDING_ID|ADMIN_SECRET_ARN|access_token|client_assertion/,
  );
});

test('C10.2 harness is executable', () => {
  assert.notEqual(fs.statSync(SCRIPT_PATH).mode & 0o111, 0);
});
