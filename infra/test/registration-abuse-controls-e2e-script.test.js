const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const HARNESS_PATH = path.resolve(
  __dirname,
  '../../e2e/registration_abuse_controls.sh',
);
const BIN_PATH = path.resolve(
  __dirname,
  '../bin/agent-auth-infra.ts',
);
const HARNESS = fs.readFileSync(HARNESS_PATH, 'utf8');
const BIN = fs.readFileSync(BIN_PATH, 'utf8');

test('Dev and SaaS deploy the registration WAF explicitly', () => {
  assert.equal(
    (BIN.match(/registrationWafEnabled:\s*true/g) ?? []).length,
    2,
    'both deployable frontend stacks must enable C10.8 WAF protection',
  );
});

test('live gate binds both stacks and Auth artifacts to one exact commit', () => {
  assert.match(HARNESS, /EXPECTED_COMMIT.*git -C "\$ROOT" rev-parse HEAD/);
  assert.match(HARNESS, /worktree HEAD does not match EXPECTED_COMMIT/);
  assert.match(HARNESS, /validate_auth_artifact "\$DEV_FILE" dev/);
  assert.match(HARNESS, /validate_auth_artifact "\$SAAS_FILE" saas/);
  assert.match(HARNESS, /cmp "\$unpacked\/bootstrap" "\$LOCAL_BOOTSTRAP"/);
  assert.match(HARNESS, /deployed provenance does not bind the exact artifact/);
});

test('global bucket exercise is deterministic, cross-IP, and conditionally restored', () => {
  assert.match(HARNESS, /GLOBAL_KEY="global-register-quota"/);
  assert.match(HARNESS, /register_request dev-a "\$IP_A"/);
  assert.match(HARNESS, /register_request dev-b "\$IP_B"/);
  assert.match(HARNESS, /2001:db8:/);
  assert.match(HARNESS, /expected distinct per-IP bucket/);
  assert.match(HARNESS, /GLOBAL_EXPECTED_VERSION=\$\(\(GLOBAL_SEEDED_VERSION \+ 2\)\)/);
  assert.match(
    HARNESS,
    /#last = :future AND #version BETWEEN :seeded AND :expected/,
  );
  assert.match(
    HARNESS,
    /GLOBAL_SEEDED=1[\s\S]{0,300}aws dynamodb update-item/,
    'recovery intent must precede an ambiguous update request',
  );
  assert.match(
    HARNESS,
    /GLOBAL_SEEDED=1[\s\S]{0,200}aws dynamodb put-item/,
    'recovery intent must precede an ambiguous create request',
  );
  assert.match(HARNESS, /\.Item\.last_refill\.N == \$future/);
  assert.match(
    HARNESS,
    /\.Item\.version\.N \| tonumber\) <= \(\$expected \| tonumber\)/,
  );
  assert.doesNotMatch(
    HARNESS,
    /put-item[\s\S]{0,500}global\.before[\s\S]{0,500}--item[\s\S]{0,200}--condition-expression\s+['"]?attribute_exists/,
  );
  assert.match(HARNESS, /globally rejected registration created a client/);
});

test('SaaS probe proves CloudFront association and terminating WAF rule logs', () => {
  assert.match(HARNESS, /FrontendDistributionId/);
  assert.match(HARNESS, /DistributionConfig\.WebACLId/);
  assert.match(HARNESS, /aws wafv2 get-web-acl/);
  assert.match(HARNESS, /RegistrationIpRateLimit/);
  assert.match(HARNESS, /RegistrationHostRateLimit/);
  assert.match(HARNESS, /RegistrationAsnRateLimit/);
  assert.match(HARNESS, /has_register_scope/);
  assert.match(HARNESS, /def search_is\(\$plain\):/);
  assert.match(HARNESS, /\$plain \| @base64/);
  assert.match(
    HARNESS,
    /\.ByteMatchStatement\.SearchString \| search_is\("POST"\)/,
  );
  assert.match(
    HARNESS,
    /\.ByteMatchStatement\.SearchString \| search_is\("\/register"\)/,
  );
  assert.match(HARNESS, /SearchString[\s\S]{0,100}\| search_is\(\$probe\)/);
  assert.match(HARNESS, /PROBE="c10-8-\$EXPECTED_COMMIT"/);
  assert.match(HARNESS, /WAF_STATUS.*403/);
  assert.match(HARNESS, /terminatingRuleId == "RegistrationProbe"/);
  assert.match(HARNESS, /x-agent-auth-waf-probe/);
});

test('PASS evidence is published only after rate-state cleanup and absence checks', () => {
  const cleanup = HARNESS.indexOf(
    'cleanup || fail "temporary Dev rate-limit state did not cleanly restore"',
  );
  const absence = HARNESS.indexOf(
    'fail "temporary per-IP rate row remains"',
  );
  const evidence = HARNESS.indexOf('schema:"agent-auth-c10-8-evidence-v1"');
  assert.ok(cleanup >= 0 && absence > cleanup && evidence > absence);
  assert.match(HARNESS, /rm -f "\$EVIDENCE_FILE"/);
  assert.match(
    HARNESS,
    /if \[\[ "\$status" != "0" \]\]; then[\s\S]{0,100}rm -f "\$EVIDENCE_FILE"/,
  );
  assert.match(HARNESS, /local_credentials_created:false/);
});
