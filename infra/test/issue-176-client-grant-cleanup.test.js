const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const SAAS_PATH = path.resolve(__dirname, '../../e2e/saas_multi_tenant.sh');
const RECONCILE_PATH = path.resolve(
  __dirname,
  '../../e2e/reconcile_issue_176_client_grants.sh',
);
const SAAS = fs.readFileSync(SAAS_PATH, 'utf8');
const RECONCILE = fs.readFileSync(RECONCILE_PATH, 'utf8');

test('SaaS multi-tenant harness deletes its DCR client on every exit', () => {
  assert.match(SAAS, /trap cleanup EXIT/);
  assert.match(SAAS, /registration_access_token/);
  assert.match(SAAS, /authorization: Bearer %s/);
  assert.match(SAAS, /-H "@\$REG_HEADER" "https:\/\/\$T1\/register\/\$CID"/);
  assert.match(SAAS, /delete_status.*"204".*"404"/s);
  assert.match(SAAS, /read_status.*"404"/s);
  assert.doesNotMatch(SAAS, /\/tmp\/saas_/);
  assert.doesNotMatch(SAAS, /ok ".*client_id=\$CID|echo ".*registration_access_token/);
});

test('SaaS multi-tenant cleanup strongly verifies client and Grant absence', () => {
  assert.match(SAAS, /dynamodb get-item/);
  assert.match(SAAS, /--consistent-read/);
  assert.match(SAAS, /client_grant_count/);
  assert.match(SAAS, /grant_json/);
  assert.match(SAAS, /\[\[ "\$grants" == "0" \]\]/);
  assert.match(SAAS, /CLEANUP_COMPLETE=1/);
});

test('Issue 176 reconciliation selects only the proven six-by-two fingerprint', () => {
  assert.match(RECONCILE, /EXPECTED_CREATED_AT='\[[0-9,]+\]'/);
  assert.match(RECONCILE, /https:\/\/app\.example\.com\/cb/);
  assert.match(RECONCILE, /token_endpoint_auth_method\.S == "none"/);
  assert.match(RECONCILE, /oidc_sector_identifier\.S == "app\.example\.com"/);
  assert.match(RECONCILE, /select\(length == 6\)/);
  assert.match(RECONCILE, /length == 12/);
  assert.match(RECONCILE, /group_by\(\.client_id\)/);
  assert.match(RECONCILE, /all\(\.\[\]; length == 2\)/);
  assert.match(RECONCILE, /all-alice-grants\.json/);
  assert.match(RECONCILE, /outside the exact twelve-row historical fingerprint/);
  assert.match(RECONCILE, /canonical t1\/alice exists/);
});

test('Issue 176 reconciliation preserves the current Grant while indexing clients', () => {
  assert.match(
    RECONCILE,
    /\.client_id as \$client_id[\s\S]{0,120}\$clients \| index\(\$client_id\)/,
  );

  const result = spawnSync(
    'jq',
    [
      '-e',
      '--argjson',
      'clients',
      '["client-a","client-b"]',
      'all(.[]; .client_id as $client_id | ($clients | index($client_id)))',
    ],
    {
      encoding: 'utf8',
      input: '[{"client_id":"client-a"},{"client_id":"client-b"}]\n',
    },
  );
  assert.equal(result.status, 0, result.stderr);

  const missing = spawnSync(
    'jq',
    [
      '-e',
      '--argjson',
      'clients',
      '["client-a","client-b"]',
      'all(.[]; .client_id as $client_id | ($clients | index($client_id)))',
    ],
    {
      encoding: 'utf8',
      input: '[{"client_id":"client-a"},{"client_id":"client-c"}]\n',
    },
  );
  assert.equal(missing.status, 1, missing.stderr);
});

test('Issue 176 refresh cleanup preserves the current item while indexing clients', () => {
  assert.match(
    RECONCILE,
    /ltrimstr\(\$prefix\)\) as \$client_id[\s\S]{0,120}\$clients \| index\(\$client_id\)/,
  );

  const result = spawnSync(
    'jq',
    [
      '-er',
      '--arg',
      'prefix',
      't1\u001f',
      '--argjson',
      'clients',
      '["client-a"]',
      `[
        .Items[]?
        | select(.family_id.S | startswith($prefix))
        | select(.client_id.S | startswith($prefix))
        | (.client_id.S | ltrimstr($prefix)) as $client_id
        | select($clients | index($client_id))
        | select((.revoked.BOOL // false) == false)
      ] | length`,
    ],
    {
      encoding: 'utf8',
      input: JSON.stringify({
        Items: [
          {
            family_id: { S: 't1\u001ffamily-a' },
            client_id: { S: 't1\u001fclient-a' },
          },
          {
            family_id: { S: 't1\u001ffamily-b' },
            client_id: { S: 't1\u001fclient-b' },
          },
        ],
      }),
    },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), '1');
});

test('Issue 176 reconciliation uses the deployed deletion boundary and is restart-safe', () => {
  assert.match(RECONCILE, /EXPECTED_COMMIT must be a full lowercase Git SHA/);
  assert.match(RECONCILE, /deployment-provenance\.json/);
  assert.match(RECONCILE, /downloaded Auth package does not match AWS CodeSha256/);
  assert.match(RECONCILE, /STATE_DIR=.*\/var\/tmp/);
  assert.match(RECONCILE, /chmod 0600 "\$MANIFEST"/);
  assert.match(RECONCILE, /issue-176-reconciliation-v2/);
  assert.match(RECONCILE, /physical_grant_id/);
  assert.match(RECONCILE, /grant_json/);
  assert.match(RECONCILE, /\.completed_clients/);
  assert.match(RECONCILE, /revalidate_unfinished_client "\$client_id"/);
  assert.match(RECONCILE, /a tombstoned client owns a Grant outside its proven manifest subset/);
  assert.match(
    RECONCILE,
    /all\(\.\[\]; \. as \$current \| any\(\$expected\[\]; \. == \$current\)\)/,
  );
  assert.match(RECONCILE, /remaining_grants/);
  assert.match(RECONCILE, /x-agent-auth-expected-authority-revision/);
  assert.match(RECONCILE, /-X DELETE/);
  assert.match(RECONCILE, /"\$API_URL\/admin\/clients\/\$client_id"/);
  assert.match(RECONCILE, /\.deleted_grants == \$expected_deleted/);
  assert.match(RECONCILE, /remaining_attributable_grant_count/);
  assert.match(RECONCILE, /validate_current_alice_manifest_subset/);
  assert.match(RECONCILE, /remaining_alice_grant_count/);
  assert.doesNotMatch(
    RECONCILE,
    /dynamodb delete-item[\s\S]{0,250}(CLIENTS_TABLE|GRANTS_TABLE)/,
  );
});

test('Issue 176 PASS evidence follows strong cleanup and contains no raw IDs', () => {
  const finalVerification = RECONCILE.indexOf('active_refresh_count "$CLIENTS_JSON"');
  const evidence = RECONCILE.indexOf('result:"pass"');
  assert.ok(finalVerification > 0);
  assert.ok(evidence > finalVerification);
  assert.match(RECONCILE, /selected_clients:6/);
  assert.match(RECONCILE, /selected_active_grants:12/);
  assert.match(RECONCILE, /raw_identifiers_recorded:false/);
  assert.match(RECONCILE, /selection_sha256/);
  assert.doesNotMatch(
    RECONCILE.slice(evidence),
    /client_id|grant_id|ADMIN_ARN|current\.secret/,
  );
});

test('Issue 176 harnesses are executable', () => {
  assert.notEqual(fs.statSync(SAAS_PATH).mode & 0o111, 0);
  assert.notEqual(fs.statSync(RECONCILE_PATH).mode & 0o111, 0);
});
