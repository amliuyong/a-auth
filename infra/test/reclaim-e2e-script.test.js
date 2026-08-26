const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const SCRIPT_PATH = path.resolve(__dirname, '../../e2e/reclaim.sh');
const SCRIPT = fs.readFileSync(SCRIPT_PATH, 'utf8');
const RECLAIM_SOURCE = fs.readFileSync(
  path.resolve(__dirname, '../../crates/http/src/reclaim.rs'),
  'utf8',
);
const AWS_AUTHORITY_SOURCE = fs.readFileSync(
  path.resolve(__dirname, '../../crates/http/src/adapters/aws/credential_authority.rs'),
  'utf8',
);
const AUTHORITY_REFERENCE_SOURCE = fs.readFileSync(
  path.resolve(__dirname, '../../crates/http/src/adapters/aws/authority_refs.rs'),
  'utf8',
);

test('C10.5 live gate binds deployed and harness commits', () => {
  assert.match(SCRIPT, /EXPECTED_DEPLOYED_COMMIT=.*:\?set EXPECTED_DEPLOYED_COMMIT/);
  assert.match(SCRIPT, /status --porcelain/);
  assert.match(SCRIPT, /merge-base --is-ancestor/);
  assert.match(SCRIPT, /diff --quiet "\$DEPLOYED_COMMIT\.\.\$HARNESS_COMMIT"/);
  assert.match(SCRIPT, /AGENT_AUTH_DEPLOYMENT_COMMIT == \$commit/);
});

test('C10.5 live gate isolates the mutable candidate domain', () => {
  assert.match(SCRIPT, /CLIENT_PREFIX="c10-5-\$RUN_ID-"/);
  assert.match(SCRIPT, /AGENT_AUTH_RECLAIM_TEST_CLIENT_PREFIX:\$prefix/);
  assert.match(SCRIPT, /candidate_count="\$\(gsi_scoped_candidate_count\)"/);
  assert.match(SCRIPT, /\[\[ "\$candidate_count" == "3" \]\]/);
  assert.match(RECLAIM_SOURCE, /run_reclaim_pass_scoped/);
  assert.match(
    RECLAIM_SOURCE,
    /candidates\.retain\(\|\(_, client\)\| client\.client_id\.starts_with\(prefix\)\)/,
  );
  assert.doesNotMatch(SCRIPT, /events (?:disable|enable)-rule/);
});

test('C10.5 live gate seeds and removes refresh source and reference atomically', () => {
  assert.match(SCRIPT, /ClientAuthorityRefsTableName/);
  assert.match(SCRIPT, /refresh\\x1fclient-authority-refs-v1/);
  assert.match(SCRIPT, /refresh authority-reference coverage is incomplete/);
  assert.match(SCRIPT, /aws dynamodb transact-write-items/);
  assert.match(SCRIPT, /ConditionExpression:"attribute_not_exists\(family_id\)"/);
  assert.match(
    SCRIPT,
    /ConditionExpression:[\s\S]*"attribute_not_exists\(client_key\) AND attribute_not_exists\(reference_key\)"/,
  );
  assert.match(SCRIPT, /active refresh authority reference was mutated/);
  assert.match(SCRIPT, /authority-ref\.absent\.json/);
  assert.match(SCRIPT, /active_refresh_reference_observed:true/);
  assert.match(SCRIPT, /authority_reference_coverage_verified:true/);
});

test('C10.5 uses bounded strong base-table reads for active references', () => {
  const codeMethod = AWS_AUTHORITY_SOURCE.match(
    /async fn has_unexpired_by_client\([\s\S]*?\n    }\n\n    async fn delete_by_user/,
  )?.[0];
  const refreshMethod = AWS_AUTHORITY_SOURCE.match(
    /async fn has_active_family_by_client\([\s\S]*?\n    }\n\n    async fn delete_by_user/,
  )?.[0];
  assert.ok(codeMethod, 'code reclaim signal method not found');
  assert.ok(refreshMethod, 'refresh reclaim signal method not found');
  assert.match(codeMethod, /refs\.has_unexpired_code/);
  assert.match(refreshMethod, /refs\.has_active_refresh/);
  assert.match(AUTHORITY_REFERENCE_SOURCE, /\.query\(\)/);
  assert.match(AUTHORITY_REFERENCE_SOURCE, /\.consistent_read\(true\)/);
  assert.match(AUTHORITY_REFERENCE_SOURCE, /\.limit\(1\)/);
  assert.match(AUTHORITY_REFERENCE_SOURCE, /require_coverage/);
  assert.doesNotMatch(AUTHORITY_REFERENCE_SOURCE, /\.index_name\(/);
  assert.doesNotMatch(codeMethod, /\.scan\(\)/);
  assert.doesNotMatch(refreshMethod, /\.scan\(\)/);
  assert.doesNotMatch(
    SCRIPT,
    /--table-name "\$REFRESH_TABLE" --index-name client_id-index/,
  );
});

test('C10.5 live gate observes reclamation decisions and audit output', () => {
  assert.match(SCRIPT, /\.scanned == 3/);
  assert.match(SCRIPT, /\.tombstoned == 1/);
  assert.match(SCRIPT, /\.hard_deleted == 1/);
  assert.match(SCRIPT, /\.kept == 1/);
  assert.match(SCRIPT, /\.errored == 0/);
  assert.match(SCRIPT, /\.Item\.audit_of\.S == \$client/);
  assert.match(SCRIPT, /\.Item\.revoked\.BOOL == false/);
  assert.match(SCRIPT, /second reclaim pass was not idempotent/);
});

test('C10.5 invokes an immutable version after restoring the mutable target', () => {
  assert.match(SCRIPT, /lambda publish-version/);
  assert.match(SCRIPT, /--qualifier "\$TEST_VERSION"/);
  assert.match(SCRIPT, /published ReclaimFn version does not contain the exact test environment/);
  assert.match(
    SCRIPT,
    /restore_lambda_environment[\s\S]*seed_client "\$CLIENT_IDLE"/,
  );
  assert.match(SCRIPT, /test_scope_enabled == true/);
});

test('C10.5 evidence is fail-closed on exact restoration and cleanup', () => {
  assert.match(SCRIPT, /--revision-id "\$ORIGINAL_REVISION"/);
  assert.match(SCRIPT, /receipt_environment_matches/);
  assert.match(SCRIPT, /cmp -s "\$WORK\/env\.current\.json" "\$WORK\/env\.test\.json"/);
  assert.match(SCRIPT, /verify_control_plane_unchanged/);
  assert.match(SCRIPT, /delete_test_versions/);
  assert.match(SCRIPT, /delete_version "\$known_version"/);
  assert.match(SCRIPT, /version_absent "\$known_version"/);
  assert.match(SCRIPT, /ResourceNotFoundException/);
  assert.match(
    SCRIPT,
    /if \[\[ -n "\$known_version" \]\]; then[\s\S]*delete_version "\$known_version"[\s\S]*else[\s\S]*Description=='\$VERSION_DESCRIPTION'/,
  );
  assert.match(SCRIPT, /snapshot_schedule before/);
  assert.match(SCRIPT, /events list-targets-by-rule/);
  assert.match(SCRIPT, /sort_by\(\.Id\)/);
  assert.match(SCRIPT, /schedule_matches_baseline prepared/);
  assert.match(SCRIPT, /schedule_matches_baseline after/);
  assert.match(SCRIPT, /verify_test_state_absent/);
  assert.match(SCRIPT, /temporary_state_cleanup_verified:true/);
  assert.match(SCRIPT, /CLEANUP_RECOVERY_REQUIRED/);
  assert.match(SCRIPT, /protected snapshot retained/);
  assert.match(
    SCRIPT,
    /verify_control_plane_unchanged[\s\S]*delete_test_versions[\s\S]*delete_test_state[\s\S]*verify_test_state_absent[\s\S]*CLEANED=1[\s\S]*jq -n/,
  );
  assert.doesNotMatch(SCRIPT, /durable_audit_row_observed|atomic_audit/);
  assert.doesNotMatch(SCRIPT, /rm -rf/);
});

test('C10.5 harness is executable', () => {
  assert.equal(fs.statSync(SCRIPT_PATH).mode & 0o111, 0o111);
});
