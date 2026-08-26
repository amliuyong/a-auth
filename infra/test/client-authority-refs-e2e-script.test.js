const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const SCRIPT_PATH = path.resolve(
  __dirname,
  '../../e2e/client_authority_refs.sh',
);
const SCRIPT = fs.readFileSync(SCRIPT_PATH, 'utf8');
const LIVE_TEST = fs.readFileSync(
  path.resolve(
    __dirname,
    '../../crates/http/tests/authority_refs_live.rs',
  ),
  'utf8',
);

test('issue 162 live gate binds exact deployed code and migration coverage', () => {
  assert.match(SCRIPT, /local HEAD must equal EXPECTED_COMMIT/);
  assert.match(SCRIPT, /status --porcelain/);
  assert.match(SCRIPT, /Configuration\.CodeSha256/);
  assert.match(SCRIPT, /deployment-provenance\.json/);
  assert.match(SCRIPT, /AgentAuthDevAuthorityReferenceMigration/);
  assert.match(SCRIPT, /MigrationVersion/);
  assert.match(
    SCRIPT,
    /LOCAL_MIGRATION_ASSET=.*agent-auth-migrate-credentials/,
  );
  assert.match(
    SCRIPT,
    /LOCAL_GOVERNANCE_ASSET=.*agent-auth-governance-worker/,
  );
  assert.match(SCRIPT, /LOCAL_MIGRATION_BOOTSTRAP=.*\/bootstrap/);
  assert.match(SCRIPT, /LOCAL_GOVERNANCE_BOOTSTRAP=.*\/bootstrap/);
  assert.match(SCRIPT, /CREDENTIAL_MIGRATION_MODE == "authority_refs"/);
  assert.match(SCRIPT, /deployed migration bootstrap differs/);
  assert.match(SCRIPT, /deployed Governance bootstrap differs/);
  assert.match(SCRIPT, /ClientAuthorityRefsTableName/);
  assert.match(SCRIPT, /meta\\x1fcoverage/);
  assert.match(SCRIPT, /meta\\x1fmigration-request/);
  assert.match(SCRIPT, /client-authority-refs-v1/);
  assert.match(
    SCRIPT,
    /\.Item\.migration_version\.S == \$migration_version/,
  );
});

test('issue 162 live gate runs the isolated real AWS adapter suite', () => {
  assert.match(SCRIPT, /AGENT_AUTH_AUTHORITY_REFS_LIVE=1/);
  assert.match(SCRIPT, /--test authority_refs_live --features aws/);
  assert.match(SCRIPT, /--ignored --nocapture/);
  for (const assertion of [
    'legacy_backfill',
    'immediate_reference_visibility',
    'multiple_active_references',
    'expiry_exclusion',
    'cross_tenant_collision_isolation',
    'concurrent_revoke_create',
    'tombstone_creation_fence',
    'same_day_code_revision_fence',
    'same_day_refresh_revision_fence',
    'terminal_orphan_cleanup',
    'governance_adapter_cleanup',
    'temporary_tables_deleted',
  ]) {
    assert.match(SCRIPT, new RegExp(`${assertion}:true`));
    assert.match(LIVE_TEST, new RegExp(`"${assertion}": true`));
  }
  assert.match(LIVE_TEST, /delete_tables\(&db, &created\)/);
  assert.match(
    LIVE_TEST,
    /delete_all_by_tenant\(refresh_revision_tenant\)/,
  );
  assert.match(LIVE_TEST, /meta\\u\{1f\}coverage/);
  assert.match(LIVE_TEST, /meta\\u\{1f\}migration/);
  assert.match(LIVE_TEST, /Some\("complete"\.to_string\(\)\)/);
  assert.match(SCRIPT, /AGENT_AUTH_AUTHORITY_REFS_CLEANUP_MANIFEST/);
  assert.match(SCRIPT, /cleanup_live_tables/);
  assert.match(SCRIPT, /ResourceNotFoundException/);
  assert.match(SCRIPT, /durable_complete_checkpoint:true/);
  assert.match(SCRIPT, /cloudformation_request_marker:true/);
  assert.match(SCRIPT, /migration_metadata_stable_during_live:true/);
  assert.match(SCRIPT, /migration-requests-\$\{suffix\}\.json/);
  assert.match(SCRIPT, /migration_metadata before/);
  assert.match(SCRIPT, /migration_metadata after/);
  assert.match(SCRIPT, /migration-metadata-before\.json/);
  assert.match(SCRIPT, /migration-metadata-after\.json/);
});

test('issue 162 live gate is executable and does not expose temp table names', () => {
  assert.equal(fs.statSync(SCRIPT_PATH).mode & 0o111, 0o111);
  assert.doesNotMatch(SCRIPT, /set -x/);
  assert.doesNotMatch(SCRIPT, /table_name:\$|TableName:\$.*evidence/);
});
