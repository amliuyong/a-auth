const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const SCRIPT = fs.readFileSync(
  path.resolve(__dirname, '../../e2e/grace_kms_cutover.sh'),
  'utf8',
);

test('cutover binds a clean exact commit and all three stack identities', () => {
  assert.match(SCRIPT, /TARGET_COMMIT.*git -C "\$ROOT" rev-parse HEAD/);
  assert.match(SCRIPT, /git -C "\$ROOT" status --porcelain/);
  assert.match(SCRIPT, /DEV_STACK.*AgentAuthDev/);
  assert.match(SCRIPT, /SAAS_STACK.*AgentAuthSaas/);
  assert.match(SCRIPT, /STANDBY_STACK.*AgentAuthSaasStandby/);
  assert.match(SCRIPT, /stack_id:\$stack_id/);
  assert.match(SCRIPT, /legacy_key_id:\$legacy_key_id/);
  assert.match(SCRIPT, /grace_table:\$grace_table/);
  assert.match(SCRIPT, /ciba_table:\$ciba_table/);
});

test('cutover resolves exact table outputs before local-resource fallback', () => {
  const resolver = SCRIPT.slice(
    SCRIPT.indexOf('resolve_table()'),
    SCRIPT.indexOf('describe_stack_identity()'),
  );
  assert.match(resolver, /stack_output_optional "\$stack_file" "\$output_key"/);
  assert.match(resolver, /if \[\[ -z "\$table" \]\]/);
  assert.match(resolver, /physical_table/);
  assert.match(resolver, /dynamodb describe-table/);
  assert.match(resolver, /TableStatus == "ACTIVE"/);
  assert.match(SCRIPT, /GraceTableName GraceTable/);
  assert.match(SCRIPT, /CibaTableName CibaTable/);
});

test('cutover resolves a standby legacy key when the old stack lacks an output', () => {
  assert.match(SCRIPT, /physical_legacy_key\(\)/);
  assert.match(SCRIPT, /ResourceType == "AWS::KMS::Key"/);
  assert.match(SCRIPT, /startsWith\("GraceEnvelopeKey"\)|startsWith\("GraceEnvelopeKey"\)/i);
  assert.match(
    SCRIPT,
    /legacy_key="\$\(physical_legacy_key[\s\S]*\$label-key-resources\.json/,
  );
  assert.match(SCRIPT, /kms describe-key/);
});

test('preflight validates all stack identities without durable state or KMS mutation', () => {
  const preflight = SCRIPT.indexOf('if [[ "$PREFLIGHT_ONLY" == "1" ]]');
  const stateWrite = SCRIPT.indexOf('install -m 0600 "$WORK/intent.json"');
  const disable = SCRIPT.indexOf('disable_legacy_key "$region" "$key_id"');
  assert.ok(preflight >= 0 && stateWrite > preflight && disable > preflight);
  assert.match(SCRIPT, /status:"preflight-pass"/);
});

test('disable intent is durable before the first KMS mutation', () => {
  const intent = SCRIPT.indexOf('.status = "disabling"');
  const disable = SCRIPT.indexOf('disable_legacy_key "$region" "$key_id"');
  assert.ok(intent >= 0 && disable > intent);
  assert.match(SCRIPT, /install -m 0600/);
  assert.match(SCRIPT, /kms disable-key/);
  assert.match(SCRIPT, /KeyMetadata\.KeyState.*Disabled/s);
  assert.doesNotMatch(SCRIPT, /kms enable-key/);
});

test('legacy ciphertext drains after key disable and cannot be deleted by the gate', () => {
  assert.match(SCRIPT, /expires_at > :now/);
  assert.match(SCRIPT, /attribute_exists\(cnt_ct\)/);
  assert.match(SCRIPT, /for _ in \$\(seq 1 900\)/);
  assert.match(SCRIPT, /stable >= 15/);
  assert.match(SCRIPT, /legacy ciphertext did not drain; keys remain disabled/);
  assert.doesNotMatch(SCRIPT, /dynamodb delete-item/);
  assert.doesNotMatch(SCRIPT, /dynamodb delete-table/);
});

test('prepared state requires disabled keys and zero active legacy ciphertext', () => {
  assert.match(SCRIPT, /\.status = "prepared"/);
  assert.match(SCRIPT, /\.legacy_keys_disabled = true/);
  assert.match(SCRIPT, /\.active_legacy_ciphertext = 0/);
  assert.match(SCRIPT, /\.active_legacy_ciphertext == 0/);
});
