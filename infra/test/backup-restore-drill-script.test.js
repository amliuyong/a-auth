const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const test = require('node:test');

const DRILL = path.resolve(__dirname, '../../e2e/backup_restore_drill.sh');
const FILTERS = path.resolve(__dirname, '../../e2e/backup_restore_filters.jq');
const GRANT_MIGRATION = path.resolve(
  __dirname,
  '../../e2e/migrate_grant_projections.sh',
);
const VERIFY_SCIM_USER_KEYS = path.resolve(
  __dirname,
  '../../e2e/verify_scim_user_keys.py',
);
const VERIFY_KMS_JWK = path.resolve(
  __dirname,
  '../../e2e/verify_kms_jwk_signature.py',
);
const ACCOUNT = '123456789012';
const RUN_ID = 'cleanup-safety-test';
const TABLES = Array.from(
  { length: 12 },
  (_, index) => `AgentAuthTestTable${String(index + 1).padStart(2, '0')}`,
);

function targetName(source) {
  const digest = crypto.createHash('sha256').update(source).digest('hex');
  return `aa-dr-${RUN_ID}-${digest}`;
}

function writeExecutable(file, contents) {
  fs.writeFileSync(file, contents, { mode: 0o755 });
}

function prepareState(root, { account = ACCOUNT, tableMap } = {}) {
  const stateDir = path.join(root, 'state', RUN_ID);
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    path.join(stateDir, 'run-context.json'),
    `${JSON.stringify({
      account_id: account,
      stack_id:
        `arn:aws:cloudformation:us-east-1:${account}:` +
        'stack/AgentAuthSaas/00000000-0000-0000-0000-000000000000',
      deployment_commit: '0'.repeat(40),
      issuer_t1: 'https://t1.example.com',
      issuer_t2: 'https://t2.example.com',
      durable_tables: TABLES,
    })}\n`,
  );
  fs.writeFileSync(
    path.join(stateDir, 'pitr.tsv'),
    TABLES.map(
      (source) =>
        `${source}\t2026-08-01T00:00:00Z\t1\t` +
        `arn:aws:dynamodb:us-east-1:${account}:table/${source}`,
    ).join('\n') + '\n',
  );
  fs.writeFileSync(path.join(stateDir, 'restore-cutoff-epoch'), '1785542400\n');
  fs.writeFileSync(
    path.join(stateDir, 'table-map.tsv'),
    tableMap ??
      TABLES.map((source) => `${source}\t${targetName(source)}`).join('\n') +
        '\n',
  );
  return stateDir;
}

function runCleanup(root, awsBody) {
  const binDir = path.join(root, 'bin');
  fs.mkdirSync(binDir);
  writeExecutable(
    path.join(binDir, 'aws'),
    `#!/usr/bin/env bash\nset -euo pipefail\n${awsBody}\n`,
  );
  return spawnSync('bash', [DRILL], {
    cwd: path.dirname(DRILL),
    encoding: 'utf8',
    env: {
      ...process.env,
      ACTION: 'cleanup',
      RUN_ID,
      AWS_PROFILE: 'ci-test',
      REGION: 'us-east-1',
      STATE_ROOT: path.join(root, 'state'),
      CLOUDTRAIL_LOOKUP_SECS: '1',
      POLL_SECS: '1',
      PATH: `${binDir}:${process.env.PATH}`,
    },
  });
}

function callerAndMissingTablesAws() {
  return `
if [[ "$*" == *"sts get-caller-identity"* ]]; then
  printf '{"Account":"${ACCOUNT}"}\\n'
elif [[ "$*" == *"dynamodb describe-table"* ]]; then
  printf 'ResourceNotFoundException\\n' >&2
  exit 254
else
  printf 'unexpected aws call: %s\\n' "$*" >&2
  exit 2
fi`;
}

test('cleanup accepts only the deterministic full RUN_ID/source table map', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-map-'));
  try {
    const corrupted = TABLES.map((source, index) =>
      index === 0
        ? `${source}\tproduction-authority-table`
        : `${source}\t${targetName(source)}`,
    ).join('\n') + '\n';
    prepareState(root, { tableMap: corrupted });

    const result = runCleanup(root, callerAndMissingTablesAws());

    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, /not the deterministic/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('restore requests bind to the persisted source table ARN', () => {
  const script = fs.readFileSync(DRILL, 'utf8');
  assert.match(
    script,
    /restore-table-to-point-in-time[\s\S]*--source-table-arn "\$source_arn"/,
  );
  assert.doesNotMatch(
    script,
    /restore-table-to-point-in-time[\s\S]*--source-table-name/,
  );
  assert.match(
    script,
    /restore_response=.*restore-table-to-point-in-time[\s\S]*persist_restore_summary_receipt[\s\S]*"restore_api"/,
  );
});

test('live dependency checks require deployed Secret and KMS retention', () => {
  const script = fs.readFileSync(DRILL, 'utf8');
  assert.match(
    script,
    /cloudformation get-template[\s\S]*--template-stage Processed/,
  );
  assert.match(
    script,
    /select\(\.Type == "AWS::SecretsManager::Secret"\)[\s\S]*\.DeletionPolicy == "Retain" and \.UpdateReplacePolicy == "Retain"/,
  );
  assert.match(
    script,
    /select\(\.Type == "AWS::KMS::Key"\)[\s\S]*\.DeletionPolicy == "Retain" and \.UpdateReplacePolicy == "Retain"/,
  );
  assert.match(
    script,
    /verify_secret_dependency\(\)[\s\S]*VersionIdsToStages[\s\S]*index\("AWSCURRENT"\)[\s\S]*length == 1/,
  );
  assert.match(
    script,
    /verify_secret_dependency\(\)[\s\S]*KmsKeyId[\s\S]*alias\/aws\/secretsmanager[\s\S]*kms describe-key[\s\S]*KeyMetadata\.KeyState[\s\S]*Enabled/,
  );
  assert.match(
    script,
    /verify_secret_dependency "\$secret_id"[\s\S]*Admin OIDC client secret dependency[\s\S]*Federation client secret dependency[\s\S]*post-cleanup required secret dependency/,
  );
  assert.match(
    script,
    /verify_runtime_identity_policy_access\(\)[\s\S]*simulate-principal-policy[\s\S]*secretsmanager:GetSecretValue[\s\S]*--resource-arns "\$secret_arn"[\s\S]*KeyManager[\s\S]*CUSTOMER[\s\S]*kms:Decrypt[\s\S]*--resource-arns "\$key_arn"/,
  );
  assert.doesNotMatch(script, /secretsmanager get-secret-value/);
});

test('PITR lag is observed after each table response', () => {
  const script = fs.readFileSync(DRILL, 'utf8');
  const responseAt = script.indexOf('describe-continuous-backups');
  const loopStart = script.lastIndexOf(
    'for table in "${DURABLE_TABLES[@]}"; do',
    responseAt,
  );
  const loopEnd = script.indexOf('\n  done', responseAt);
  assert.ok(responseAt >= 0 && loopStart >= 0 && loopEnd > responseAt);
  const loop = script.slice(loopStart, loopEnd);
  const response = loop.indexOf('describe-continuous-backups');
  const observed = loop.indexOf('observed_at=$(date +%s)');
  const lag = loop.indexOf('lag=$(( observed_at - latest_epoch ))');
  assert.ok(response >= 0 && observed > response && lag > observed);
  assert.doesNotMatch(
    script.slice(Math.max(0, loopStart - 120), loopStart),
    /observed_at=\$\(date \+%s\)/,
  );
  assert.match(
    script.slice(loopEnd),
    /common_cutoff_observed_at=\$\(date \+%s\)[\s\S]*MAX_RPO_LAG=\$\(\( common_cutoff_observed_at - MIN_RESTORE_EPOCH \)\)[\s\S]*common-cutoff lag/,
  );
});

test('Grant restore anchors use the same no-newline hash boundary', () => {
  const script = fs.readFileSync(DRILL, 'utf8');

  assert.match(
    script,
    /grant_source_hash=\$\(sha256_text "\$grant_source_json"\)/,
  );
  assert.match(
    script,
    /grant_restored_json=\$\(jq -er '\.Item\.grant_json\.S'[\s\S]{0,80}<<<"\$grant_restored"\)/,
  );
  assert.match(
    script,
    /grant_restored_hash=\$\(sha256_text "\$grant_restored_json"\)/,
  );
  assert.match(
    script,
    /revoked_grant_source_hash=\$\(sha256_text "\$revoked_grant_source_json"\)/,
  );
  assert.match(
    script,
    /revoked_grant_restored_json=\$\(jq -er '\.Item\.grant_json\.S'[\s\S]{0,80}<<<"\$revoked_grant_restored"\)/,
  );
  assert.match(
    script,
    /revoked_grant_restored_hash=\$\(sha256_text "\$revoked_grant_restored_json"\)/,
  );
});

test('tenant key filters consume the decoded record object exactly once', () => {
  const record = {
    served_snapshot: {
      ec: {
        published: [
          {
            key_arn: 'arn:aws:kms:us-east-1:123456789012:key/ec',
            public_jwk: { kid: 'ec-key', x: 'x', y: 'y' },
          },
        ],
      },
      rsa: {
        published: [
          {
            key_arn: 'arn:aws:kms:us-east-1:123456789012:key/rsa',
            public_jwk: { kid: 'rsa-key', n: 'n', e: 'AQAB' },
          },
        ],
      },
    },
  };
  const input = JSON.stringify(record);
  const jwks = spawnSync(
    'jq',
    [
      '-L',
      path.dirname(FILTERS),
      '-c',
      'include "backup_restore_filters"; tenant_record_jwks',
    ],
    { encoding: 'utf8', input },
  );
  assert.equal(jwks.status, 0, jwks.stderr);
  assert.deepEqual(JSON.parse(jwks.stdout), [
    {
      alg: 'ES256',
      crv: 'P-256',
      kid: 'ec-key',
      kty: 'EC',
      use: 'sig',
      x: 'x',
      y: 'y',
    },
    { alg: 'RS256', e: 'AQAB', kid: 'rsa-key', kty: 'RSA', n: 'n', use: 'sig' },
  ]);

  const arns = spawnSync(
    'jq',
    [
      '-L',
      path.dirname(FILTERS),
      '-r',
      'include "backup_restore_filters"; tenant_record_key_arns',
    ],
    { encoding: 'utf8', input },
  );
  assert.equal(arns.status, 0, arns.stderr);
  assert.deepEqual(arns.stdout.trim().split('\n'), [
    'arn:aws:kms:us-east-1:123456789012:key/ec',
    'arn:aws:kms:us-east-1:123456789012:key/rsa',
  ]);

  const signingKeys = spawnSync(
    'jq',
    [
      '-L',
      path.dirname(FILTERS),
      '-c',
      'include "backup_restore_filters"; tenant_record_signing_keys',
    ],
    { encoding: 'utf8', input },
  );
  assert.equal(signingKeys.status, 0, signingKeys.stderr);
  assert.deepEqual(JSON.parse(signingKeys.stdout), [
    {
      key_arn: 'arn:aws:kms:us-east-1:123456789012:key/ec',
      public_jwk: {
        crv: 'P-256',
        kid: 'ec-key',
        kty: 'EC',
        x: 'x',
        y: 'y',
      },
      signing_algorithm: 'ECDSA_SHA_256',
    },
    {
      key_arn: 'arn:aws:kms:us-east-1:123456789012:key/rsa',
      public_jwk: { e: 'AQAB', kid: 'rsa-key', kty: 'RSA', n: 'n' },
      signing_algorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
    },
  ]);

  const script = fs.readFileSync(DRILL, 'utf8');
  assert.doesNotMatch(script, /fromjson[\s\S]{0,160}<<<"\$restored_record"/);
  assert.match(
    script,
    /restored_key_arns=\$\(jq[\s\S]*tenant_record_key_arns[\s\S]*<<<"\$restored_record"\)[\s\S]*\[\[ -n "\$restored_key_arns" \]\][\s\S]*mapfile -t RESTORED_KEY_ARNS[\s\S]*\$\{#RESTORED_KEY_ARNS\[@\]\} >= 2[\s\S]*for key_arn in "\$\{RESTORED_KEY_ARNS\[@\]\}"/,
  );
  assert.doesNotMatch(
    script,
    /done < <\(jq[\s\S]{0,160}tenant_record_key_arns/,
  );
  assert.match(
    script,
    /map\(\.key_arn\)[\s\S]*unique[\s\S]*kms sign[\s\S]*verify_kms_jwk_signature\.py/,
  );
  assert.match(
    script,
    /ALL_RESTORED_KEY_ARNS[\s\S]*restored_unique_key_arn_count[\s\S]*restored tenant registries share a KMS key reference/,
  );
});

test('KMS probe signatures must verify with the exact published JWK', () => {
  assert.match(
    fs.readFileSync(DRILL, 'utf8'),
    /python3 -c 'import cryptography'[\s\S]*Python cryptography package is required/,
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-jwk-'));
  try {
    const message = Buffer.from('agent-auth-dr-kms-probe');
    const messageFile = path.join(root, 'message');
    fs.writeFileSync(messageFile, message);
    for (const fixture of [
      {
        algorithm: 'ECDSA_SHA_256',
        key: crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
      },
      {
        algorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
        key: crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }),
      },
    ]) {
      const jwkFile = path.join(root, `${fixture.algorithm}.jwk.json`);
      const signatureFile = path.join(root, `${fixture.algorithm}.signature`);
      fs.writeFileSync(
        jwkFile,
        JSON.stringify(fixture.key.publicKey.export({ format: 'jwk' })),
      );
      fs.writeFileSync(
        signatureFile,
        crypto.sign('sha256', message, fixture.key.privateKey),
      );
      const verified = spawnSync(
        'python3',
        [
          VERIFY_KMS_JWK,
          '--algorithm',
          fixture.algorithm,
          '--jwk',
          jwkFile,
          '--signature',
          signatureFile,
          '--message',
          messageFile,
        ],
        { encoding: 'utf8' },
      );
      assert.equal(verified.status, 0, verified.stderr);

      fs.appendFileSync(signatureFile, 'corrupt');
      const rejected = spawnSync(
        'python3',
        [
          VERIFY_KMS_JWK,
          '--algorithm',
          fixture.algorithm,
          '--jwk',
          jwkFile,
          '--signature',
          signatureFile,
          '--message',
          messageFile,
        ],
        { encoding: 'utf8' },
      );
      assert.notEqual(rejected.status, 0);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runtime signer proof verifies JOSE encoding and issuer-bound claims', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-jws-'));
  try {
    const key = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = key.publicKey.export({ format: 'jwk' });
    jwk.kid = 'runtime-ec';
    const jwkFile = path.join(root, 'runtime.jwk.json');
    const messageFile = path.join(root, 'runtime.signing-input');
    fs.writeFileSync(jwkFile, JSON.stringify(jwk));
    const encode = (value) =>
      Buffer.from(JSON.stringify(value)).toString('base64url');
    const message = [
      encode({ alg: 'ES256', typ: 'at+jwt', kid: jwk.kid }),
      encode({
        iss: 'https://t1.example.com',
        sub: 'dr-probe:t1',
        aud: 'https://t1.example.com/dr-probe',
      }),
    ].join('.');
    const extracted = spawnSync('jq', ['-jer', '.ec.signing_input'], {
      input: JSON.stringify({ ec: { signing_input: message } }),
    });
    assert.equal(extracted.status, 0, extracted.stderr.toString());
    fs.writeFileSync(messageFile, extracted.stdout);
    assert.deepEqual(fs.readFileSync(messageFile), Buffer.from(message));
    let signature;
    do {
      signature = crypto
        .sign('sha256', Buffer.from(message), {
          key: key.privateKey,
          dsaEncoding: 'ieee-p1363',
        })
        .toString('base64url');
    } while (!signature.startsWith('-'));
    const args = [
      VERIFY_KMS_JWK,
      '--algorithm',
      'ECDSA_SHA_256',
      '--signature-format',
      'jose',
      '--jwk',
      jwkFile,
      `--signature-base64url=${signature}`,
      '--message',
      messageFile,
      '--expected-issuer',
      'https://t1.example.com',
      '--expected-subject',
      'dr-probe:t1',
      '--expected-jws-alg',
      'ES256',
    ];
    const verified = spawnSync('python3', args, { encoding: 'utf8' });
    assert.equal(verified.status, 0, verified.stderr);

    const wrongIssuer = [...args];
    wrongIssuer[wrongIssuer.indexOf('https://t1.example.com')] =
      'https://t2.example.com';
    const rejected = spawnSync('python3', wrongIssuer, { encoding: 'utf8' });
    assert.notEqual(rejected.status, 0);

    const script = fs.readFileSync(DRILL, 'utf8');
    assert.match(
      script,
      /jq -jer "\.\$\{algorithm\}\.signing_input" "\$runtime_probe"/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('restored tenant registry is exercised through the production signer path', () => {
  const script = fs.readFileSync(DRILL, 'utf8');
  assert.match(
    script,
    /for command in base64 cargo curl git python3[\s\S]*cargo run --quiet --locked --features aws[\s\S]*--manifest-path "\$REPO_ROOT\/Cargo\.toml"[\s\S]*--bin agent-auth-restored-tenant-signer-probe[\s\S]*"\$TENANT_KEYS_RESTORED" "\$tenant" "\$issuer"/,
  );
  assert.match(
    script,
    /--signature-format "\$signature_format"[\s\S]*--signature-base64url="\$runtime_signature"[\s\S]*--expected-issuer "\$issuer"[\s\S]*--expected-subject "dr-probe:\$tenant"/,
  );
  assert.match(script, /restored_issuer_runtime_signing: "passed"/);
  assert.doesNotMatch(script, /restored_issuer_signing_behavior/);
});

test('configuration snapshots sort every restored authority class', () => {
  const cases = [
    ['clients', [{ client_id: { S: 'b' } }, { client_id: { S: 'a' } }], 'a'],
    [
      'workload_trust',
      [{ binding_id: { S: 'b' } }, { binding_id: { S: 'a' } }],
      'a',
    ],
    [
      'federation',
      [
        { tenant_id: { S: 'b' }, upstream_idp_id: { S: 'a' } },
        { tenant_id: { S: 'a' }, upstream_idp_id: { S: 'b' } },
      ],
      'a',
    ],
    [
      'scim_groups',
      [
        { pk: { S: 'b' }, sk: { S: 'a' } },
        { pk: { S: 'a' }, sk: { S: 'b' } },
      ],
      'a',
    ],
    ['domain_map', [{ domain: { S: 'b' } }, { domain: { S: 'a' } }], 'a'],
  ];

  for (const [kind, items, first] of cases) {
    const result = spawnSync(
      'jq',
      [
        '-L',
        path.dirname(FILTERS),
        '-c',
        '--arg',
        'kind',
        kind,
        'include "backup_restore_filters"; canonical_configuration_items($kind)',
      ],
      { encoding: 'utf8', input: JSON.stringify({ Items: items }) },
    );
    assert.equal(result.status, 0, `${kind}: ${result.stderr}`);
    assert.equal(Object.values(JSON.parse(result.stdout)[0])[0].S, first, kind);
  }

  const script = fs.readFileSync(DRILL, 'utf8');
  const projection = script.match(
    /if \[\[ "\$kind" == "clients" \]\]; then[\s\S]*?--projection-expression\s+'([^']+)'/,
  );
  assert.ok(projection, 'client snapshot must use an explicit projection');
  const projectedFields = projection[1].split(',').sort();
  assert.deepEqual(
    projectedFields,
    [
      'allowed_resources',
      'allowed_scopes',
      'audit_of',
      'backchannel_client_notification_endpoint',
      'backchannel_token_delivery_mode',
      'client_id',
      'client_secret_credentials_version',
      'client_type',
      'created_at',
      'default_resource',
      'hard_deleted_at',
      'id_token_signed_response_alg',
      'introspect_enabled',
      'jwks',
      'jwks_uri',
      'last_used_day',
      'last_used_day_audit',
      'oidc_sector_identifier',
      'post_logout_redirect_uris',
      'prm_domains',
      'redirect_mode',
      'redirect_uris',
      'registration_token_credentials_version',
      'require_dpop',
      'resource_ids',
      'token_endpoint_auth_method',
      'token_endpoint_auth_signing_alg',
      'tombstoned_at',
    ].sort(),
  );
  assert.match(
    script,
    /write_configuration_snapshot[\s\S]*config-\$kind-final\.json[\s\S]*cmp -s[\s\S]*config-\$kind-source\.json[\s\S]*config-\$kind-final\.json/,
  );
  assert.match(
    script,
    /--select COUNT[\s\S]*attribute_exists\(client_secret\)[\s\S]*attribute_exists\(reg_token_hash\)[\s\S]*attribute_exists\(client_secret_credentials\)[\s\S]*attribute_exists\(client_secret_credentials_version\)[\s\S]*attribute_exists\(registration_token_credentials\)[\s\S]*attribute_exists\(registration_token_credentials_version\)/,
  );
  assert.match(
    script,
    /verify_client_credential_shape "\$CLIENTS_TABLE" "source"[\s\S]*verify_client_credential_shape "\$restored_table" "restored"[\s\S]*verify_client_credential_shape "\$source_table" "final source"/,
  );
  assert.match(
    script,
    /attribute_exists\(audit_of\)[\s\S]*attribute_not_exists\(hard_deleted_at\)[\s\S]*attribute_exists\(last_used_day_audit\)/,
  );
  assert.match(
    script,
    /config-federation-source\.json[\s\S]*\.oidc\.client_secret_ref[\s\S]*FEDERATION_SECRET_REFS[\s\S]*verify_secret_dependency/,
  );
});

test('identity snapshots cover all users and credential metadata only', () => {
  const cases = [
    [
      'users',
      [{ user_id: { S: 'b' } }, { user_id: { S: 'a' } }],
      'user_id',
    ],
    [
      'passkeys',
      [{ credential_id: { S: 'b' } }, { credential_id: { S: 'a' } }],
      'credential_id',
    ],
    [
      'password_credentials',
      [{ user_id: { S: 'b' } }, { user_id: { S: 'a' } }],
      'user_id',
    ],
  ];

  for (const [kind, items, key] of cases) {
    const result = spawnSync(
      'jq',
      [
        '-L',
        path.dirname(FILTERS),
        '-c',
        '--arg',
        'kind',
        kind,
        'include "backup_restore_filters"; canonical_identity_items($kind)',
      ],
      { encoding: 'utf8', input: JSON.stringify({ Items: items }) },
    );
    assert.equal(result.status, 0, `${kind}: ${result.stderr}`);
    assert.equal(JSON.parse(result.stdout)[0][key].S, 'a', kind);
  }

  const script = fs.readFileSync(DRILL, 'utf8');
  assert.match(
    script,
    /users\)[\s\S]*user_id,email,created_at,updated_at,last_login_at,#status,credential_epoch,revocation_pending,[\s\S]*record_type,alias_kind,alias_value,canonical_user_id,initial_lifecycle_epoch/,
  );
  assert.match(
    script,
    /passkeys\)[\s\S]*'credential_id,user_id,sign_count'/,
  );
  assert.match(
    script,
    /password_credentials\)[\s\S]*'user_id,must_change,revocation_pending,#version,updated_at'/,
  );
  assert.doesNotMatch(
    script.match(/write_identity_snapshot\(\) \{[\s\S]*?\n\}/)[0],
    /password_hash|cred_json/,
  );
  assert.match(
    script,
    /--select COUNT[\s\S]*attribute_not_exists\(cred_json\)[\s\S]*attribute_not_exists\(password_hash\)/,
  );
  assert.match(
    script,
    /identity-\$kind-source\.json[\s\S]*identity-\$kind-restored\.json[\s\S]*identity-\$kind-final\.json/,
  );
  assert.match(script, /identity_authority: "passed"/);
  assert.match(script, /credential_metadata: "passed"/);
});

test('Users ownership rejects cross-tenant and dangling alias references', () => {
  const canonical = {
    user_id: { S: 't1\u001fuser-1' },
    created_at: { N: '1785542400' },
  };
  const aliasValue = 'external-1';
  const aliasDigest = crypto
    .createHash('sha256')
    .update(aliasValue)
    .digest('base64url');
  const alias = {
    user_id: { S: `t1\u001fscim-alias:external:${aliasDigest}` },
    record_type: { S: 'scim_alias' },
    alias_kind: { S: 'external' },
    alias_value: { S: aliasValue },
    canonical_user_id: { S: 't1\u001fuser-1' },
  };
  const run = (items) => {
    const structural = spawnSync(
      'jq',
      [
        '-L',
        path.dirname(FILTERS),
        '-e',
        '--argjson',
        'tenants',
        '["t1","t2"]',
        'include "backup_restore_filters"; user_tenant_ownership_is_valid($tenants)',
      ],
      { encoding: 'utf8', input: JSON.stringify(items) },
    );
    if (structural.status !== 0) return structural;
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-users-'));
    try {
      const users = path.join(root, 'users.json');
      fs.writeFileSync(users, JSON.stringify(items));
      return spawnSync(
        'python3',
        [
          VERIFY_SCIM_USER_KEYS,
          '--users',
          users,
          '--tenants-json',
          '["t1","t2"]',
        ],
        { encoding: 'utf8' },
      );
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  };

  assert.equal(run([canonical, alias]).status, 0);
  assert.equal(
    run([
      canonical,
      { ...alias, canonical_user_id: { S: 't2\u001fuser-2' } },
    ]).status,
    1,
  );
  assert.equal(run([alias]).status, 1);
  assert.equal(
    run([
      canonical,
      {
        ...alias,
        user_id: {
          S: `t1\u001fscim-alias:external:${'A'.repeat(43)}`,
        },
      },
    ]).status,
    1,
  );
  assert.equal(
    run([
      canonical,
      {
        user_id: { S: `t1\u001fscim-create:${'A'.repeat(43)}` },
        record_type: { S: 'scim_create' },
        canonical_user_id: { S: 't1\u001fuser-1' },
      },
    ]).status,
    0,
  );
  assert.equal(
    run([
      canonical,
      {
        user_id: { S: `t1\u001fscim-create:${'A'.repeat(42)}B` },
        record_type: { S: 'scim_create' },
        canonical_user_id: { S: 't1\u001fuser-1' },
      },
    ]).status,
    1,
  );
  assert.equal(
    run([
      canonical,
      {
        user_id: { S: 't1\u001fscim-create:not-a-digest' },
        record_type: { S: 'scim_create' },
        canonical_user_id: { S: 't1\u001fuser-1' },
      },
    ]).status,
    1,
  );
  assert.equal(
    run([{ ...canonical, created_at: { S: '1785542400' } }]).status,
    1,
  );
  assert.equal(
    run([{ ...canonical, created_at: { N: 'not-a-number' } }]).status,
    1,
  );
  assert.equal(
    run([{ ...canonical, user_id: { S: 't1\u001f' } }]).status,
    1,
  );

  const script = fs.readFileSync(DRILL, 'utf8');
  assert.match(
    script,
    /verify_user_tenant_ownership[\s\S]*identity-\$kind-source\.json[\s\S]*identity-\$kind-restored\.json[\s\S]*identity-\$kind-final\.json/,
  );
});

test('credential ownership requires one tenant and a canonical User', () => {
  const users = [
    {
      user_id: { S: 't1\u001fuser-1' },
      created_at: { N: '1785542400' },
    },
    {
      user_id: { S: 't2\u001fuser-2' },
      created_at: { N: '1785542401' },
    },
  ];
  const run = (kind, credentials) =>
    spawnSync(
      'jq',
      [
        '-L',
        path.dirname(FILTERS),
        '-e',
        '--argjson',
        'users',
        JSON.stringify(users),
        '--argjson',
        'tenants',
        '["t1","t2"]',
        '--arg',
        'kind',
        kind,
        'include "backup_restore_filters"; credential_tenant_ownership_is_valid($users; $kind; $tenants)',
      ],
      { encoding: 'utf8', input: JSON.stringify(credentials) },
    );

  assert.equal(
    run('passkeys', [
      {
        credential_id: { S: 't1\u001fcredential-1' },
        user_id: { S: 't1\u001fuser-1' },
      },
    ]).status,
    0,
  );
  assert.equal(
    run('password_credentials', [
      { user_id: { S: 't2\u001fuser-2' } },
    ]).status,
    0,
  );
  assert.equal(
    run('passkeys', [
      {
        credential_id: { S: 't2\u001fcredential-1' },
        user_id: { S: 't1\u001fuser-1' },
      },
    ]).status,
    1,
  );
  assert.equal(
    run('password_credentials', [
      { user_id: { S: 't1\u001fmissing-user' } },
    ]).status,
    1,
  );

  const script = fs.readFileSync(DRILL, 'utf8');
  assert.match(
    script,
    /verify_identity_tenant_integrity[\s\S]*identity-users-source\.json[\s\S]*identity-passkeys-source\.json[\s\S]*identity-password_credentials-source\.json[\s\S]*identity-users-restored\.json[\s\S]*identity-users-final\.json[\s\S]*identity-users-post-cleanup\.json/,
  );
});

test('all Grant-table rows are classified and Grant projections are strict', () => {
  const logical = {
    grant_id: 'grant-1',
    user_id: 'user-1',
    status: 'active',
    effective_pv: 3,
    revision: 2,
    credential_epoch: 1,
  };
  const valid = {
    grant_id: { S: 't1\u001fgrant-1' },
    user_id: { S: 't1\u001fuser-1' },
    gv_tenant: { S: 't1\u001fgv' },
    effective_pv: { N: '3' },
    revision: { N: '2' },
    credential_epoch: { N: '1' },
    grant_json: { S: JSON.stringify(logical) },
  };
  const policyVersion = {
    grant_id: { S: 't1\u001fpolicy-version' },
    policy_version: { N: '3' },
  };
  const policyArtifact = {
    grant_id: { S: 't1\u001fpolicy-artifact#3' },
    policy_text: { S: 'permit(principal, action, resource);' },
    policy_digest: { S: 'a'.repeat(64) },
  };
  const run = (items) =>
    spawnSync(
      'jq',
      [
        '-L',
        path.dirname(FILTERS),
        '-e',
        '--argjson',
        'tenants',
        '["t1","t2"]',
        'include "backup_restore_filters"; canonical_grant_items($tenants)',
      ],
      {
        encoding: 'utf8',
        input: JSON.stringify({ Items: items }),
      },
    );

  const accepted = run([valid, policyVersion, policyArtifact]);
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.deepEqual(JSON.parse(accepted.stdout), [
    valid,
    policyArtifact,
    policyVersion,
  ]);
  assert.notEqual(
    run([{ ...valid, user_id: { S: 't2\u001fuser-1' } }]).status,
    0,
  );
  assert.notEqual(
    run([{ ...valid, grant_id: { S: 't1\u001fother' } }]).status,
    0,
  );
  assert.notEqual(
    run([{ ...valid, gv_tenant: { S: 't2\u001fgv' } }]).status,
    0,
  );
  assert.notEqual(
    run([{ ...valid, effective_pv: { N: '2' } }]).status,
    0,
  );
  assert.notEqual(
    run([{ ...valid, revision: { S: '2' } }]).status,
    0,
  );
  assert.notEqual(
    run([{ ...valid, credential_epoch: { S: '1' } }]).status,
    0,
  );
  assert.notEqual(
    run([{ ...valid, policy_version: { N: '3' } }]).status,
    0,
  );
  assert.notEqual(
    run([{ ...policyVersion, grant_json: { N: '123' } }]).status,
    0,
  );
  assert.notEqual(
    run([{ ...policyArtifact, grant_json: { N: '123' } }]).status,
    0,
  );
  assert.notEqual(
    run([{ grant_id: { S: 't1\u001funknown-metadata' } }]).status,
    0,
  );

  const script = fs.readFileSync(DRILL, 'utf8');
  assert.match(
    script,
    /write_grant_snapshot\(\)[\s\S]*--consistent-read[\s\S]*grant_id,user_id,gv_tenant,effective_pv,revision,credential_epoch,grant_json,policy_version,policy_text,policy_digest[\s\S]*canonical_grant_items/,
  );
  assert.match(
    script,
    /grants-source\.json[\s\S]*grants-restored\.json[\s\S]*cmp -s[\s\S]*grants-final\.json[\s\S]*grants-post-cleanup\.json/,
  );
});

test('legacy Grant projection migration is conditional and idempotent', () => {
  const logical = {
    grant_id: 'legacy-grant',
    user_id: 'user-1',
    effective_pv: 0,
    revision: 0,
    status: 'active',
  };
  const legacy = {
    grant_id: { S: 't1\u001flegacy-grant' },
    user_id: { S: 't1\u001fuser-1' },
    grant_json: { S: JSON.stringify(logical) },
  };
  const run = (item, filter) =>
    spawnSync(
      'jq',
      [
        '-L',
        path.dirname(FILTERS),
        '-e',
        '--argjson',
        'tenants',
        '["t1","t2"]',
        `include "backup_restore_filters"; ${filter}`,
      ],
      {
        encoding: 'utf8',
        input: JSON.stringify({ Items: [item] }),
      },
    );

  const planned = run(
    legacy,
    'grant_projection_migration_candidates($tenants)',
  );
  assert.equal(planned.status, 0, planned.stderr);
  assert.deepEqual(JSON.parse(planned.stdout), [
    {
      grant_id: 't1\u001flegacy-grant',
      user_id: 't1\u001fuser-1',
      gv_tenant: 't1\u001fgv',
      effective_pv: '0',
      revision: null,
      grant_json: JSON.stringify(logical),
    },
  ]);

  const migrated = {
    ...legacy,
    gv_tenant: { S: 't1\u001fgv' },
    effective_pv: { N: '0' },
  };
  const secondPlan = run(
    migrated,
    'grant_projection_migration_candidates($tenants)',
  );
  assert.equal(secondPlan.status, 0, secondPlan.stderr);
  assert.deepEqual(JSON.parse(secondPlan.stdout), []);
  assert.notEqual(
    run(
      { ...legacy, gv_tenant: { S: 't1\u001fgv' } },
      'grant_projection_migration_candidates($tenants)',
    ).status,
    0,
  );

  const migration = fs.readFileSync(GRANT_MIGRATION, 'utf8');
  assert.match(migration, /ACTION="\$\{ACTION:-plan\}"/);
  assert.match(
    migration,
    /ACTION=apply requires CONFIRM_STACK=%s/,
  );
  assert.match(
    migration,
    /grant_json = :grant_json AND user_id = :user_id AND attribute_not_exists\(gv_tenant\) AND attribute_not_exists\(effective_pv\)/,
  );
  assert.match(
    migration,
    /attribute_not_exists\(revision\)[\s\S]*revision = :revision/,
  );
  assert.match(
    migration,
    /SET gv_tenant = :gv_tenant, effective_pv = :effective_pv/,
  );
  assert.match(
    migration,
    /canonical_grant_items\(\$tenants\)[\s\S]*grant_projection_migration_candidates\(\$tenants\)/,
  );

  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'agent-auth-grant-migration-'),
  );
  try {
    const binDir = path.join(root, 'bin');
    const stateFile = path.join(root, 'migrated');
    const updateLog = path.join(root, 'updates.log');
    fs.mkdirSync(binDir);
    writeExecutable(
      path.join(binDir, 'aws'),
      `#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"cloudformation describe-stacks"* &&
      "$*" == *"GrantsTableName"* ]]; then
  printf 'TestGrants\\n'
elif [[ "$*" == *"cloudformation describe-stacks"* &&
        "$*" == *"RecoveryTenantIssuers"* ]]; then
  printf '%s\\n' '{"t1":"https://t1.example.com","t2":"https://t2.example.com"}'
elif [[ "$*" == *"dynamodb scan"* ]]; then
  if [[ -e "${stateFile}" ]]; then
    printf '%s\\n' '${JSON.stringify({ Items: [migrated] })}'
  else
    printf '%s\\n' '${JSON.stringify({ Items: [legacy] })}'
  fi
elif [[ "$*" == *"dynamodb update-item"* ]]; then
  printf '%s\\n' "$*" >>"${updateLog}"
  touch "${stateFile}"
  printf '{}\\n'
else
  printf 'unexpected aws call: %s\\n' "$*" >&2
  exit 2
fi
`,
    );
    const runMigration = (
      action,
      confirm = undefined,
      profile = 'ci-test',
      region = 'us-east-1',
    ) =>
      spawnSync('bash', [GRANT_MIGRATION], {
        cwd: path.dirname(GRANT_MIGRATION),
        encoding: 'utf8',
        env: {
          ...process.env,
          ACTION: action,
          AWS_PROFILE: profile,
          REGION: region,
          STACK: 'AgentAuthSaas',
          CONFIRM_STACK: confirm,
          XDG_RUNTIME_DIR: root,
          PATH: `${binDir}:${process.env.PATH}`,
        },
      });

    const plan = runMigration('plan');
    assert.equal(plan.status, 0, plan.stdout + plan.stderr);
    assert.match(plan.stdout, /migration candidates=1/);
    assert.equal(fs.existsSync(stateFile), false);

    const wrongRegion = runMigration(
      'apply',
      'AgentAuthSaas',
      'ci-test',
      'us-west-2',
    );
    assert.notEqual(wrongRegion.status, 0);
    assert.match(
      wrongRegion.stdout + wrongRegion.stderr,
      /requires REGION=us-east-1/,
    );
    assert.equal(fs.existsSync(stateFile), false);

    const apply = runMigration('apply', 'AgentAuthSaas');
    assert.equal(apply.status, 0, apply.stdout + apply.stderr);
    assert.match(apply.stdout, /conditionally migrated 1 Grant rows/);
    const update = fs.readFileSync(updateLog, 'utf8').trim();
    assert.match(update, /grant_json = :grant_json/);
    assert.match(update, /attribute_not_exists\(revision\)/);
    assert.match(update, /attribute_not_exists\(gv_tenant\)/);
    assert.match(update, /attribute_not_exists\(effective_pv\)/);

    const retry = runMigration('apply', 'AgentAuthSaas');
    assert.equal(retry.status, 0, retry.stdout + retry.stderr);
    assert.match(retry.stdout, /migration candidates=0/);
    assert.equal(
      fs.readFileSync(updateLog, 'utf8').trim().split('\n').length,
      1,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup, polling, RTO, and evidence publication fail closed', () => {
  const script = fs.readFileSync(DRILL, 'utf8');
  const waitTable = script.match(/wait_table_active\(\) \{[\s\S]*?\n\}/)[0];
  assert.match(waitTable, /describe_table_status "\$table"/);
  assert.doesNotMatch(waitTable, /\|\| true/);
  assert.match(
    script,
    /else\s+validate_restore_provenance "\$source" "\$target"\s+info "isolated table \$target is already deleting"/,
  );
  assert.match(script, /RTO_SECS >= 0/);
  assert.match(
    script,
    /restore-receipt-\*\.json[\s\S]*restore receipts exist without the original RTO start time[\s\S]*isolated restore target exists without the original RTO start time[\s\S]*restore-start-epoch\.current/,
  );
  assert.match(
    script,
    /cleanup_restored_tables[\s\S]*identity-\$kind-post-cleanup\.json[\s\S]*grant_final=[\s\S]*final_record=[\s\S]*admin-config-post-cleanup\.json[\s\S]*audit_final=[\s\S]*recovery_point_final=[\s\S]*verify_issuers final[\s\S]*post-cleanup source anchors and external dependencies remained stable/,
  );
  assert.match(
    script,
    /post-cleanup source anchors and external dependencies remained stable[\s\S]*VERIFIED_AT=\$\(date \+%s\)[\s\S]*RTO_SECS=/,
  );
  assert.match(
    script,
    />"\$EVIDENCE_FILE\.current"[\s\S]*mv "\$EVIDENCE_FILE\.current" "\$EVIDENCE_FILE"/,
  );
});

test('a completed RUN_ID cannot be reused for another drill', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-complete-'));
  try {
    const stateDir = path.join(root, 'state', RUN_ID);
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(stateDir, 'evidence.json'), '{}\n');
    const result = spawnSync('bash', [DRILL], {
      cwd: path.dirname(DRILL),
      encoding: 'utf8',
      env: {
        ...process.env,
        RUN_ID,
        AWS_PROFILE: 'ci-test',
        REGION: 'us-east-1',
        STATE_ROOT: path.join(root, 'state'),
        EVIDENCE_FILE: path.join(root, 'alternate-evidence.json'),
      },
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, /already has evidence/);
    assert.doesNotMatch(result.stdout + result.stderr, /run_id=/);
    assert.equal(fs.existsSync(path.join(root, 'alternate-evidence.json')), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup rejects a different AWS account before describing tables', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-account-'));
  try {
    prepareState(root);
    const result = runCleanup(
      root,
      `if [[ "$*" == *"sts get-caller-identity"* ]]; then
  printf '{"Account":"999999999999"}\\n'
else
  printf 'table action reached\\n' >&2
  exit 2
fi`,
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, /does not own RUN_ID/);
    assert.doesNotMatch(result.stdout + result.stderr, /table action reached/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup rejects a concurrent process for the same RUN_ID', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-lock-'));
  let holder;
  try {
    prepareState(root);
    const lockFile = path.join(root, 'state', `.${RUN_ID}.lock`);
    holder = spawn(
      'flock',
      ['-n', lockFile, 'bash', '-c', 'printf locked; sleep 30'],
      { detached: true, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    await new Promise((resolve, reject) => {
      holder.once('error', reject);
      holder.stdout.once('data', resolve);
      holder.once('exit', (status) => {
        reject(new Error(`lock holder exited early with status ${status}`));
      });
    });

    const result = runCleanup(root, callerAndMissingTablesAws());

    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, /another drill process is active/);
  } finally {
    if (holder?.pid) {
      process.kill(-holder.pid, 'SIGTERM');
    }
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup reconstructs a missing map from persisted restore context', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-missing-'));
  try {
    const stateDir = prepareState(root);
    fs.rmSync(path.join(stateDir, 'table-map.tsv'));
    fs.writeFileSync(path.join(stateDir, 'restore-start-epoch'), '1785542400\n');
    const result = runCleanup(root, callerAndMissingTablesAws());

    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /reconstructed deterministic table map/);
    assert.equal(
      fs.readFileSync(path.join(stateDir, 'table-map.tsv'), 'utf8'),
      TABLES.map((source) => `${source}\t${targetName(source)}`).join('\n') +
        '\n',
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup fails closed when map provenance cannot be reconstructed', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-damaged-'));
  try {
    const stateDir = prepareState(root);
    fs.rmSync(path.join(stateDir, 'table-map.tsv'));
    fs.rmSync(path.join(stateDir, 'pitr.tsv'));
    fs.writeFileSync(path.join(stateDir, 'restore-start-epoch'), '1785542400\n');
    const result = runCleanup(
      root,
      'printf "AWS must not be called with damaged state\\n" >&2; exit 2',
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, /pitr.tsv is incomplete/);
    assert.doesNotMatch(result.stdout + result.stderr, /AWS must not be called/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup does not delete a same-name table with wrong restore provenance', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-source-'));
  try {
    prepareState(root);
    const firstTarget = targetName(TABLES[0]);
    const deleteLog = path.join(root, 'delete.log');
    const result = runCleanup(
      root,
      `
if [[ "$*" == *"sts get-caller-identity"* ]]; then
  printf '{"Account":"${ACCOUNT}"}\\n'
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${firstTarget}"* &&
        "$*" == *"Table.TableStatus"* ]]; then
  printf 'ACTIVE\\n'
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${firstTarget}"* &&
        "$*" == *"--query Table --output json"* ]]; then
  printf '{"TableName":"${firstTarget}","TableArn":"arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/${firstTarget}","TableId":"00000000-0000-0000-0000-000000000001","CreationDateTime":"2026-08-01T00:00:01Z","RestoreSummary":{"SourceTableArn":"arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/wrong","RestoreInProgress":false,"RestoreDateTime":"2026-08-01T00:00:00Z"}}\\n'
elif [[ "$*" == *"dynamodb delete-table"* ]]; then
  printf '%s\\n' "$*" >>"${deleteLog}"
else
  printf 'ResourceNotFoundException\\n' >&2
  exit 254
fi`,
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, /does not match the persisted/);
    assert.equal(fs.existsSync(deleteLog), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup recovers ACTIVE restore provenance from CloudTrail', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-trail-'));
  try {
    prepareState(root);
    const source = TABLES[0];
    const target = targetName(source);
    const sourceArn =
      `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/${source}`;
    const deleteLog = path.join(root, 'delete.log');
    const deletedMarker = path.join(root, 'deleted');
    const targetArn =
      `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/${target}`;
    const tableId = '00000000-0000-0000-0000-000000000001';
    const cloudTrailEvent = JSON.stringify({
      eventTime: '2026-08-01T00:00:01Z',
      eventID: '00000000-0000-0000-0000-000000000001',
      eventSource: 'dynamodb.amazonaws.com',
      eventName: 'RestoreTableToPointInTime',
      awsRegion: 'us-east-1',
      recipientAccountId: ACCOUNT,
      requestParameters: {
        sourceTableArn: sourceArn,
        targetTableName: target,
        restoreDateTime: '2026-08-01T00:00:00Z',
      },
      resources: [
        { type: 'AWS::DynamoDB::Table', ARN: sourceArn },
        { type: 'AWS::DynamoDB::Table', ARN: targetArn },
      ],
      responseElements: null,
    });
    const lookup = JSON.stringify({
      Events: [
        {
          EventId: '00000000-0000-0000-0000-000000000001',
          EventName: 'RestoreTableToPointInTime',
          EventTime: '2026-08-01T00:00:01Z',
          CloudTrailEvent: cloudTrailEvent,
        },
      ],
    });
    const stateDir = path.join(root, 'state', RUN_ID);
    fs.writeFileSync(
      path.join(stateDir, 'restore-start-epoch'),
      '1785542400\n',
    );
    const result = runCleanup(
      root,
      `
if [[ "$*" == *"sts get-caller-identity"* ]]; then
  printf '{"Account":"${ACCOUNT}"}\\n'
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${target}"* &&
        "$*" == *"Table.TableStatus"* &&
        ! -e "${deletedMarker}" ]]; then
  printf 'ACTIVE\\n'
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${target}"* &&
        "$*" == *"--query Table --output json"* ]]; then
  printf '{"TableName":"${target}","TableArn":"${targetArn}","TableId":"${tableId}","CreationDateTime":"2026-08-01T00:00:01Z"}\\n'
elif [[ "$*" == *"cloudtrail lookup-events"* ]]; then
  printf '%s\\n' '${lookup}'
elif [[ "$*" == *"dynamodb delete-table"* &&
        "$*" == *"--table-name ${target}"* ]]; then
  printf '%s\\n' "$*" >>"${deleteLog}"
  touch "${deletedMarker}"
  printf '{}\\n'
elif [[ "$*" == *"dynamodb describe-table"* ]]; then
  printf 'ResourceNotFoundException\\n' >&2
  exit 254
else
  printf 'unexpected aws call: %s\\n' "$*" >&2
  exit 2
fi`,
    );

    assert.equal(
      result.status,
      0,
      JSON.stringify({
        error: result.error?.message,
        signal: result.signal,
        stdout: result.stdout,
        stderr: result.stderr,
        drillLog: fs.existsSync(path.join(stateDir, 'drill.log'))
          ? fs.readFileSync(path.join(stateDir, 'drill.log'), 'utf8')
          : null,
      }),
    );
    assert.match(result.stdout, /isolated restored tables deleted/);
    assert.equal(fs.readFileSync(deleteLog, 'utf8').trim().length > 0, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup rejects a table replaced after its restore receipt', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-replaced-'));
  try {
    const stateDir = prepareState(root);
    const source = TABLES[0];
    const target = targetName(source);
    const targetArn =
      `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/${target}`;
    const receipt = {
      schema_version: 1,
      provenance_source: 'restore_api',
      source_table_arn:
        `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/${source}`,
      target_table_name: target,
      target_table_arn: targetArn,
      target_table_id: '00000000-0000-0000-0000-000000000001',
      target_created_at: '2026-08-01T00:00:01Z',
      restore_date_time: '2026-08-01T00:00:00Z',
      region: 'us-east-1',
      account_id: ACCOUNT,
    };
    const receiptName = crypto
      .createHash('sha256')
      .update(source)
      .digest('hex');
    fs.writeFileSync(
      path.join(stateDir, `restore-receipt-${receiptName}.json`),
      `${JSON.stringify(receipt)}\n`,
    );
    const deleteLog = path.join(root, 'delete.log');
    const result = runCleanup(
      root,
      `
if [[ "$*" == *"sts get-caller-identity"* ]]; then
  printf '{"Account":"${ACCOUNT}"}\\n'
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${target}"* &&
        "$*" == *"Table.TableStatus"* ]]; then
  printf 'ACTIVE\\n'
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${target}"* &&
        "$*" == *"--query Table --output json"* ]]; then
  printf '{"TableName":"${target}","TableArn":"${targetArn}","TableId":"00000000-0000-0000-0000-000000000002","CreationDateTime":"2026-08-01T00:00:02Z"}\\n'
elif [[ "$*" == *"dynamodb delete-table"* ]]; then
  printf '%s\\n' "$*" >>"${deleteLog}"
else
  printf 'ResourceNotFoundException\\n' >&2
  exit 254
fi`,
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, /does not match the persisted/);
    assert.equal(fs.existsSync(deleteLog), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup rejects ambiguous CloudTrail restore provenance', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-ambiguous-'));
  try {
    const stateDir = prepareState(root);
    const source = TABLES[0];
    const target = targetName(source);
    const sourceArn =
      `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/${source}`;
    const targetArn =
      `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/${target}`;
    const event = {
      eventTime: '2026-08-01T00:00:01Z',
      eventID: '00000000-0000-0000-0000-000000000001',
      eventSource: 'dynamodb.amazonaws.com',
      eventName: 'RestoreTableToPointInTime',
      awsRegion: 'us-east-1',
      recipientAccountId: ACCOUNT,
      requestParameters: {
        sourceTableArn: sourceArn,
        targetTableName: target,
        restoreDateTime: '2026-08-01T00:00:00Z',
      },
      resources: [
        { type: 'AWS::DynamoDB::Table', ARN: sourceArn },
        { type: 'AWS::DynamoDB::Table', ARN: targetArn },
      ],
    };
    const lookup = JSON.stringify({
      Events: [
        { CloudTrailEvent: JSON.stringify(event) },
        {
          CloudTrailEvent: JSON.stringify({
            ...event,
            eventID: '00000000-0000-0000-0000-000000000002',
            requestParameters: {
              ...event.requestParameters,
              restoreDateTime: 1785542400,
            },
          }),
        },
      ],
    });
    fs.writeFileSync(
      path.join(stateDir, 'restore-start-epoch'),
      '1785542400\n',
    );
    const deleteLog = path.join(root, 'delete.log');
    const result = runCleanup(
      root,
      `
if [[ "$*" == *"sts get-caller-identity"* ]]; then
  printf '{"Account":"${ACCOUNT}"}\\n'
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${target}"* &&
        "$*" == *"Table.TableStatus"* ]]; then
  printf 'ACTIVE\\n'
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${target}"* &&
        "$*" == *"--query Table --output json"* ]]; then
  printf '{"TableName":"${target}","TableArn":"${targetArn}","TableId":"00000000-0000-0000-0000-000000000001","CreationDateTime":"2026-08-01T00:00:01Z"}\\n'
elif [[ "$*" == *"cloudtrail lookup-events"* ]]; then
  printf '%s\\n' '${lookup}'
elif [[ "$*" == *"dynamodb delete-table"* ]]; then
  printf '%s\\n' "$*" >>"${deleteLog}"
else
  printf 'ResourceNotFoundException\\n' >&2
  exit 254
fi`,
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, /multiple CloudTrail/);
    assert.equal(fs.existsSync(deleteLog), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup rejects CloudTrail provenance for a replacement table', () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'agent-auth-dr-trail-replaced-'),
  );
  try {
    const stateDir = prepareState(root);
    const source = TABLES[0];
    const target = targetName(source);
    const sourceArn =
      `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/${source}`;
    const targetArn =
      `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/${target}`;
    const event = {
      eventTime: '2026-08-01T00:00:01Z',
      eventID: '00000000-0000-0000-0000-000000000001',
      eventSource: 'dynamodb.amazonaws.com',
      eventName: 'RestoreTableToPointInTime',
      awsRegion: 'us-east-1',
      recipientAccountId: ACCOUNT,
      requestParameters: {
        sourceTableArn: sourceArn,
        targetTableName: target,
        restoreDateTime: '2026-08-01T00:00:00Z',
      },
      resources: [
        { type: 'AWS::DynamoDB::Table', ARN: sourceArn },
        { type: 'AWS::DynamoDB::Table', ARN: targetArn },
      ],
    };
    const lookup = JSON.stringify({
      Events: [{ CloudTrailEvent: JSON.stringify(event) }],
    });
    fs.writeFileSync(
      path.join(stateDir, 'restore-start-epoch'),
      '1785542400\n',
    );
    const deleteLog = path.join(root, 'delete.log');
    const result = runCleanup(
      root,
      `
if [[ "$*" == *"sts get-caller-identity"* ]]; then
  printf '{"Account":"${ACCOUNT}"}\\n'
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${target}"* &&
        "$*" == *"Table.TableStatus"* ]]; then
  printf 'ACTIVE\\n'
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${target}"* &&
        "$*" == *"--query Table --output json"* ]]; then
  printf '{"TableName":"${target}","TableArn":"${targetArn}","TableId":"00000000-0000-0000-0000-000000000002","CreationDateTime":"2026-08-01T00:01:00Z"}\\n'
elif [[ "$*" == *"cloudtrail lookup-events"* ]]; then
  printf '%s\\n' '${lookup}'
elif [[ "$*" == *"dynamodb delete-table"* ]]; then
  printf '%s\\n' "$*" >>"${deleteLog}"
else
  printf 'ResourceNotFoundException\\n' >&2
  exit 254
fi`,
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, /no matching restore event/);
    assert.equal(fs.existsSync(deleteLog), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup captures provenance before waiting for a CREATING table', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-creating-'));
  try {
    prepareState(root);
    const source = TABLES[0];
    const target = targetName(source);
    const sourceArn =
      `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/${source}`;
    const targetArn =
      `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/${target}`;
    const statusCount = path.join(root, 'status-count');
    const deletedMarker = path.join(root, 'deleted');
    const deleteLog = path.join(root, 'delete.log');
    const result = runCleanup(
      root,
      `
if [[ "$*" == *"sts get-caller-identity"* ]]; then
  printf '{"Account":"${ACCOUNT}"}\\n'
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${target}"* &&
        "$*" == *"Table.TableStatus"* &&
        ! -e "${deletedMarker}" ]]; then
  count=0
  [[ ! -s "${statusCount}" ]] || count=$(<"${statusCount}")
  count=$((count + 1))
  printf '%s\\n' "$count" >"${statusCount}"
  if (( count == 1 )); then printf 'CREATING\\n'; else printf 'ACTIVE\\n'; fi
elif [[ "$*" == *"dynamodb describe-table"* &&
        "$*" == *"--table-name ${target}"* &&
        "$*" == *"--query Table --output json"* ]]; then
  printf '{"TableName":"${target}","TableArn":"${targetArn}","TableId":"00000000-0000-0000-0000-000000000001","CreationDateTime":"2026-08-01T00:00:01Z","RestoreSummary":{"SourceTableArn":"${sourceArn}","RestoreInProgress":true,"RestoreDateTime":"2026-08-01T00:00:00Z"}}\\n'
elif [[ "$*" == *"dynamodb delete-table"* &&
        "$*" == *"--table-name ${target}"* ]]; then
  printf '%s\\n' "$*" >>"${deleteLog}"
  touch "${deletedMarker}"
  printf '{}\\n'
elif [[ "$*" == *"dynamodb describe-table"* ]]; then
  printf 'ResourceNotFoundException\\n' >&2
  exit 254
else
  printf 'unexpected aws call: %s\\n' "$*" >&2
  exit 2
fi`,
    );

    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /waiting for isolated table/);
    assert.match(result.stdout, /isolated restored tables deleted/);
    assert.equal(fs.readFileSync(deleteLog, 'utf8').trim().length > 0, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup without restore context cannot report deletion success', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-empty-'));
  try {
    fs.mkdirSync(path.join(root, 'state', RUN_ID), { recursive: true });
    const result = runCleanup(
      root,
      'printf "AWS must not be called without context\\n" >&2; exit 2',
    );

    assert.notEqual(result.status, 0);
    assert.match(
      result.stdout + result.stderr,
      /cleanup cannot confirm isolated deletion/,
    );
    assert.doesNotMatch(
      result.stdout + result.stderr,
      /AWS must not be called/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanup succeeds when deterministic targets no longer exist', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-dr-clean-'));
  try {
    prepareState(root);
    const result = runCleanup(root, callerAndMissingTablesAws());

    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /isolated restored tables deleted/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
