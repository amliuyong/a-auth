const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { spawnSync } = require('node:child_process');

const HARNESS = path.resolve(__dirname, '../../e2e/saas_origin_auth.sh');
const source = fs.readFileSync(HARNESS, 'utf8');

test('SaaS origin-auth live harness is fail-closed and emits sanitized evidence', () => {
  const syntax = spawnSync('bash', ['-n', HARNESS], { encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
  assert.match(source, /EXPECTED_COMMIT must be a full lowercase Git SHA/);
  assert.match(source, /primary and standby must both run EXPECTED_COMMIT/);
  assert.match(source, /qualifying evidence requires a clean worktree/);
  assert.match(source, /deployment-provenance\.json/);
  assert.match(source, /deployed bootstrap differs from the exact local commit artifact/);
  assert.match(source, /get-distribution-config/);
  assert.match(source, /get-secret-value/);
  assert.match(source, /cmp -s "\$WORK\/primary-secret"/);
  assert.match(source, /cloudfront_overwrites_viewer_headers: "pass"/);
  assert.match(source, /cloudfront_configuration_contains_no_origin_secret: "pass"/);
  assert.match(source, /deployed_primary_artifact_matches_reviewed_source: "pass"/);
  assert.match(source, /deployed_standby_artifact_matches_reviewed_source: "pass"/);
  assert.match(source, /missing_direct_origin_credential_rejected: "pass"/);
  assert.match(source, /wrong_direct_origin_credential_rejected: "pass"/);
  assert.match(source, /primary_slot_accepted_in_both_regions: "pass"/);
  assert.match(source, /secondary_slot_accepted_in_both_regions: "pass"/);
  assert.match(source, /primary_api_host_sha256/);
  assert.match(source, /standby_api_host_sha256/);
  assert.doesNotMatch(
    source.slice(source.indexOf('EVIDENCE="$(')),
    /SecretString|primary-secret|secondary-secret/,
  );
});
