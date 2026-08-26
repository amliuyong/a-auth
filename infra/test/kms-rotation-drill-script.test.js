const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const DRILL = path.resolve(__dirname, '../../e2e/kms_rotation_drill.sh');
const source = fs.readFileSync(DRILL, 'utf8');
const emergency = source.match(
  /run_emergency_revoke\(\) \{[\s\S]*?^\}/m,
)?.[0];

test('c10_12_emergency_revoke_is_independent_zero_overlap_and_invalidates_jwks', () => {
  const syntax = spawnSync('bash', ['-n', DRILL], { encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
  assert.ok(emergency, 'emergency revoke must remain an independently testable function');
  assert.match(source, /^EMERGENCY_REVOKE="\$\{EMERGENCY_REVOKE:-0\}"$/m);
  assert.match(
    source,
    /EMERGENCY_REVOKE=1 and RETIRE_AFTER_WAIT=1 are mutually exclusive/,
  );
  assert.match(
    emergency,
    /set_signing_env "\$NEW_KEY" "\$NEW_KEY"/,
  );
  assert.match(emergency, /verify_token "\$TOK_OLD"[\s\S]*then[\s\S]*exit 1/);
  assert.match(
    emergency,
    /cloudfront create-invalidation[\s\S]*--paths '\/jwks\.json'/,
  );
  assert.match(
    emergency,
    /cloudfront wait invalidation-completed/,
  );
  assert.match(emergency, /audit_rotation emergency_revoke/);
  assert.doesNotMatch(emergency, /sleep "\$RETIRE_WAIT_SECS"/);

  const emergencyBranch = source.indexOf('if [ "$EMERGENCY_REVOKE" = "1" ]; then');
  const gracefulBranch = source.indexOf('if [ "$RETIRE_AFTER_WAIT" != "1" ]; then');
  assert.ok(emergencyBranch > 0, 'execute mode must expose the emergency branch');
  assert.ok(
    emergencyBranch < gracefulBranch,
    'emergency revoke must run before any graceful-retirement wait gate',
  );
});
