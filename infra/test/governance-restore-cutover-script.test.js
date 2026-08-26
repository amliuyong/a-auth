const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const SCRIPT = path.resolve(
  __dirname,
  '../../e2e/governance_restore_cutover_verify.sh',
);
const CORE = path.resolve(
  __dirname,
  '../../scripts/governance_restore_cutover_verify.py',
);

test('c12_7_restore_verifier_keeps_current_governance_authority', () => {
  const source = fs.readFileSync(SCRIPT, 'utf8');

  assert.match(
    source,
    /CURRENT_TABLES=.*ReplicatedAuthorityTableNames[\s\S]*CURRENT_GOVERNANCE=.*\.governance[\s\S]*CURRENT_SUPPRESSION=.*\.governance_suppression/,
  );
  assert.match(
    source,
    /candidate business authority aliases current or non-rollback control tables/,
  );
  assert.match(
    source,
    /Governance authority has not converged across configured replicas/,
  );
  assert.match(
    source,
    /suppression authority has not converged across configured replicas/,
  );
  assert.match(
    source,
    /Governance authority changed after candidate verification/,
  );
  assert.match(
    source,
    /suppression authority changed after candidate verification/,
  );
  assert.match(source, /control_stable_through/);
});

test('c12_7_restore_verifier_is_strong_read_and_mutation_free', () => {
  const source = fs.readFileSync(SCRIPT, 'utf8');
  const scanFunction = source.match(
    /scan_projection\(\) \{[\s\S]*?^\}/m,
  )[0];

  assert.match(scanFunction, /dynamodb scan/);
  assert.match(scanFunction, /--consistent-read/);
  assert.doesNotMatch(
    source,
    /dynamodb (?:put-item|update-item|delete-item|batch-write-item|transact-write-items)/,
  );
  assert.doesNotMatch(
    source,
    /(?:kms|secretsmanager) (?:schedule-key-deletion|delete-secret)/,
  );
});

test('c12_7_restore_verifier_scans_every_recoverable_business_role', () => {
  const source = fs.readFileSync(SCRIPT, 'utf8');
  const roles = [
    'admin_auth',
    'clients',
    'domain_map',
    'federation_config',
    'grants',
    'passkeys',
    'password_credentials',
    'scim_groups',
    'security_events',
    'tenant_keys',
    'users',
    'workload_trust',
  ];

  for (const role of roles) {
    assert.match(source, new RegExp(`(?:\\[|")${role}(?:"|\\])`));
  }
  assert.match(
    source,
    /python3 "\$VERIFY_CORE"[\s\S]*--manifest[\s\S]*--hmac-key "1=\$HMAC_KEY"/,
  );
  assert.ok(fs.existsSync(CORE));
});

test('c12_7_restore_evidence_is_atomic_and_excludes_key_material', () => {
  const source = fs.readFileSync(SCRIPT, 'utf8');

  assert.match(
    source,
    />"\$EVIDENCE_FILE\.current"[\s\S]*mv "\$EVIDENCE_FILE\.current" "\$EVIDENCE_FILE"/,
  );
  assert.match(source, /rm -rf "\$WORK"/);
  assert.doesNotMatch(
    fs.readFileSync(CORE, 'utf8'),
    /"hmac_key"|"suppression_digest"|"user_id":/,
  );
  assert.doesNotMatch(source, /account_id:/);
  assert.match(source, /account_sha256/);
});
