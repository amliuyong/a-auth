const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const SCRIPT_PATH = path.resolve(__dirname, '../../e2e/per_client_rate_limit.sh');
const SCRIPT = fs.readFileSync(SCRIPT_PATH, 'utf8');

test('C10.7 live gate binds deployed and harness commits', () => {
  assert.match(SCRIPT, /EXPECTED_DEPLOYED_COMMIT=.*:\?set EXPECTED_DEPLOYED_COMMIT/);
  assert.match(SCRIPT, /status --porcelain/);
  assert.match(SCRIPT, /merge-base --is-ancestor/);
  assert.match(SCRIPT, /AGENT_AUTH_DEPLOYMENT_COMMIT == \$commit/);
  assert.match(SCRIPT, /rate-limit runtime changed after the deployed commit/);
});

test('C10.7 live gate uses authenticated client identities and isolated buckets', () => {
  assert.match(SCRIPT, /mechanism:"spiffe_jwt"/);
  assert.match(SCRIPT, /grant_type=client_credentials/);
  assert.match(SCRIPT, /sys\.stdout\.write\(/);
  assert.match(SCRIPT, /tpk "\$CLIENT_A"/);
  assert.match(SCRIPT, /A_STATUS=.*token_request "\$TD_A" exhausted-a/);
  assert.match(SCRIPT, /\[\[ "\$A_STATUS" == "429" \]\]/);
  assert.match(SCRIPT, /retry-after: \[1-9\]\[0-9\]\*/);
  assert.match(SCRIPT, /\.error == "temporarily_unavailable"/);
  assert.match(SCRIPT, /B_STATUS=.*token_request "\$TD_B" isolated-b/);
  assert.match(SCRIPT, /\[\[ "\$B_STATUS" == "200" \]\]/);
});

test('C10.7 evidence is fail-closed on verified cleanup', () => {
  const cleanup = SCRIPT.indexOf(
    'pass "all temporary mutable test state and local credential files are absent"',
  );
  const evidence = SCRIPT.indexOf('result:"pass"');
  assert.ok(cleanup > 0);
  assert.ok(evidence > cleanup);
  assert.match(SCRIPT, /RESOURCE="https:\/\/c10-7-\$RUN_ID\.invalid"/);
  assert.match(SCRIPT, /for _ in \$\(seq 1 90\)/);
  assert.match(SCRIPT, /if cleanup_absent; then/);
  assert.match(SCRIPT, /best_effort_cleanup\n  sleep 1/);
  assert.match(SCRIPT, /\[\[ ! -s "\$response_file" \]\]/);
  assert.match(SCRIPT, /jq -e 'has\("Item"\) \| not'/);
  assert.match(SCRIPT, /list-objects-v2/);
  assert.match(SCRIPT, /public-jwks-clean\.body/);
  assert.match(SCRIPT, /mutable_test_state_cleanup_verified:true/);
  assert.match(SCRIPT, /rm -rf "\$WORK"\npass "all temporary mutable test state/);
  assert.doesNotMatch(
    SCRIPT.slice(evidence),
    /CLIENT_A|CLIENT_B|ADMIN_ARN|access_token|client_assertion/,
  );
});

test('C10.7 harness is executable', () => {
  assert.notEqual(fs.statSync(SCRIPT_PATH).mode & 0o111, 0);
});
