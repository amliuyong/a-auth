const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { spawnSync } = require('node:child_process');

const DRILL = path.resolve(__dirname, '../../e2e/region_failover.sh');
const INFRA_APP = path.resolve(__dirname, '../bin/agent-auth-infra.ts');
const source = fs.readFileSync(DRILL, 'utf8');
const infraAppSource = fs.readFileSync(INFRA_APP, 'utf8');

test('failover drill is syntactically valid and has a fixed 330-second fence', () => {
  const syntax = spawnSync('bash', ['-n', DRILL], { encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
  assert.match(source, /^QUIESCENCE_SECS=330$/m);
  assert.match(source, /^RTO_TARGET_SECS=900$/m);
  assert.match(source, /^RPO_TARGET_SECS=60$/m);
  assert.doesNotMatch(source, /QUIESCENCE_SECS="\$\{/);
  assert.doesNotMatch(source, /RTO_TARGET_SECS="\$\{/);
  assert.doesNotMatch(source, /RPO_TARGET_SECS="\$\{/);
  assert.match(source, /changed_at = :now/);
  assert.match(source, /assert_quiesced "\$source" "\$revision"/);
  assert.match(source, /persist_quiesce_started "\$source" "\$revision"/);
  assert.match(source, /assert_region_fence_matches/);
  assert.match(source, /"fence#" \+ \$source/);
  assert.match(source, /"fence#" \+ \$target/);
  assert.match(source, /deadline=\$\(\( observed_at \+ QUIESCENCE_SECS \)\)/);
  assert.match(
    source,
    /while :; do\n    activated_at="\$\(now_epoch\)"[\s\S]*transact-write-items/,
  );
  assert.match(
    source,
    /\.Item\.activation_not_before\.N \| tonumber/,
  );
});

test('failover drill persists identity, serializes runs, and supports recovery actions', () => {
  assert.match(source, /\.agent-auth-failover-drills/);
  assert.match(source, /flock -n 9/);
  assert.match(source, /run\) ;;/);
  assert.match(source, /status\|rollback/);
  assert.match(source, /ACTION=%s requires RUN_ID/);
  assert.match(source, /load_context_settings/);
  assert.match(source, /target-artifacts\.ready/);
  assert.match(source, /ambiguous client creation could not be recovered/);
  assert.match(source, /probe-cleanup\.ready/);
  assert.match(source, /context_value '\.probe\.redirect_uri'/);
  assert.match(source, /primary, standby, and local HEAD/);
  assert.match(source, /git -C "\$REPO_ROOT" status --porcelain/);
  assert.match(source, /--untracked-files=normal/);
  assert.match(source, /qualifying failover requires a clean worktree/);
  assert.match(source, /validate_local_auth_artifact/);
  assert.match(source, /validate_deployed_auth_artifact/);
  assert.match(source, /downloaded Auth package does not match AWS CodeSha256/);
  assert.match(source, /deployed Auth bootstrap differs from the exact local commit artifact/);
  assert.match(source, /deployed Auth artifacts changed since RUN_ID initialization/);
  assert.match(source, /primary_auth_code_sha256/);
  assert.match(source, /primary_auth_bootstrap_sha256/);
  assert.match(source, /standby_auth_code_sha256/);
  assert.match(source, /standby_auth_bootstrap_sha256/);
  assert.match(source, /validate_deployment_context/);
  assert.match(source, /origin_auth_secret_name/);
  assert.match(source, /origin_auth_secondary_secret_name/);
  assert.match(source, /ensure_origin_auth_header/);
  assert.match(
    source,
    /X-Agent-Auth-Origin-Auth-Primary:[\s\S]*X-Agent-Auth-Origin-Auth-Secondary:/,
  );
  assert.match(
    infraAppSource,
    /standbyStack\.addDependency\([\s\S]*saasStack,[\s\S]*origin-auth Secrets/,
  );
  const forwardedHostHeaders = [
    ...source.matchAll(/-H "X-Forwarded-Host: \$forwarded_host"/g),
    ...source.matchAll(/-H "X-Forwarded-Host: \$host"/g),
  ];
  assert.ok(forwardedHostHeaders.length > 0);
  for (const match of forwardedHostHeaders) {
    assert.match(
      source.slice(match.index, match.index + 180),
      /origin-auth\.headers/,
      `direct regional request at offset ${match.index} must authenticate the edge hop`,
    );
  }
  assert.match(source, /validated_issuer_host/);
  assert.match(
    source,
    /\.DistributionConfig\.Aliases\.Items[\s\S]*index\(\$host\) != null/,
  );
  assert.match(source, /issuer_host:\$issuer_host/);
  assert.match(source, /issuer host changed since RUN_ID initialization/);
  assert.match(
    source,
    /parsed\.scheme == "https"[\s\S]*parsed\.path == ""[\s\S]*parsed\.query == ""[\s\S]*parsed\.fragment == ""/,
  );
  assert.match(
    source,
    /if \[\[ "\$ACTION" == "rollback" \]\]; then\n  validate_deployment_context\n  rollback_to_primary\n  cleanup_probe/,
  );
  assert.match(source, /validate_persisted_probe/);
  assert.match(source, /\.run_id == \$run/);
  assert.match(source, /access token client mismatch/);
  assert.match(source, /ID token activation mismatch/);
  assert.match(source, /refresh token activation mismatch/);
  assert.match(source, /Python PyJWT and cryptography packages are required/);
  assert.match(
    source,
    /if \[\[ "\$ACTION" == "run" \]\]; then[\s\S]*SystemExit\(0 if algorithms\.has_crypto else 1\)/,
  );
  assert.doesNotMatch(source, /assert algorithms\.has_crypto/);
  assert.match(source, /verify_token_pair/);
  assert.match(source, /source-pair\.invitation/);
  assert.match(source, /stack identity changed since RUN_ID initialization/);
  assert.match(source, /outputs changed since RUN_ID initialization/);
  assert.match(source, /standby_region_local_tables/);
  assert.match(source, /standby Region-local table outputs changed/);
  assert.match(
    source,
    /CURRENT_REVISION=.*control_revision[\s\S]*if \(\( CURRENT_REVISION == INITIAL \)\); then[\s\S]*setup_probe[\s\S]*else\n  validate_persisted_probe/,
  );
  assert.match(source, /assert_coordinated_writer "\$PRIMARY_REGION"/);
});

test('failback purges every standby Region-local table before primary activation', () => {
  assert.match(source, /RegionLocalTableNames/);
  assert.match(source, /\.standby_region_local_tables \| length/);
  assert.match(source, /table_count" == "20"/);
  assert.match(source, /"clientAuthorityRefs"/);
  assert.match(source, /"invitations"/);
  assert.match(source, /dynamodb describe-table/);
  assert.match(source, /\.Table\.KeySchema\[\]\.AttributeName/);
  assert.match(source, /--projection-expression "\$projection"/);
  assert.match(source, /--consistent-read --no-paginate --limit 25/);
  assert.match(source, /dynamodb batch-write-item/);
  assert.match(source, /\.UnprocessedItems\[\$table\] \/\/ \[\] \| length/);
  assert.match(source, /verified_empty:true/);
  assert.match(
    source,
    /REMOVE standby_region_local_purge_revision, standby_region_local_purge_completed_at/,
  );
  assert.match(
    source,
    /standby_region_local_purge_revision = :revision/,
  );
  assert.match(
    source,
    /standby_region_local_purge_revision = :quiesce/,
  );

  const failback = source.slice(
    source.indexOf('if (( CURRENT_REVISION == FAILBACK_Q ))'),
    source.indexOf('if (( CURRENT_REVISION != FAILBACK_A ))'),
  );
  assert.match(
    failback,
    /wait_quiescence "\$STANDBY_REGION" "\$FAILBACK_Q"[\s\S]*purge_standby_region_local_tables[\s\S]*record_standby_region_local_purge "\$STANDBY_REGION" "\$FAILBACK_Q"[\s\S]*activate_region "\$PRIMARY_REGION"/,
  );
  const rollbackStart = source.indexOf('rollback_to_primary()');
  const rollback = source.slice(
    rollbackStart,
    source.indexOf('\nload_context_settings\n', rollbackStart),
  );
  assert.match(
    rollback,
    /wait_quiescence "\$source" "\$qrev"[\s\S]*purge_standby_region_local_tables[\s\S]*record_standby_region_local_purge[\s\S]*activate_region "\$primary"/,
  );
});

test('c11_1_failover_inventory_and_edge_routing_match_current_topology', () => {
  for (const role of [
    'admin_auth',
    'attribute_namespaces',
    'clients',
    'domain_map',
    'federation_attribute_mappings',
    'federation_config',
    'governance',
    'governance_suppression',
    'grants',
    'passkeys',
    'password_credentials',
    'scim_groups',
    'security_events',
    'tenant_keys',
    'users',
    'workload_trust',
  ]) {
    assert.match(source, new RegExp(`"${role}"`));
  }
  assert.match(source, /\(\[.\[\]\] \| unique \| length\) == 20/);

  const failover = source.slice(
    source.indexOf('if (( CURRENT_REVISION == FAILOVER_Q ))'),
    source.indexOf('if (( CURRENT_REVISION == FAILBACK_Q ))'),
  );
  assert.match(
    failover,
    /wait_quiescence "\$PRIMARY_REGION" "\$FAILOVER_Q"[\s\S]*activate_region "\$STANDBY_REGION"[\s\S]*assert_coordinated_writer "\$STANDBY_REGION"[\s\S]*switch_edge "\$\(context_value '\.standby_api_host'\)" standby[\s\S]*wait_region_header "\$ISSUER" "" "\$STANDBY_REGION"[\s\S]*assert_artifact_set_rejected/,
  );

  const failback = source.slice(
    source.indexOf('if (( CURRENT_REVISION == FAILBACK_Q ))'),
    source.indexOf('cleanup_probe\nwrite_evidence'),
  );
  assert.match(
    failback,
    /wait_quiescence "\$STANDBY_REGION" "\$FAILBACK_Q"[\s\S]*purge_standby_region_local_tables[\s\S]*record_standby_region_local_purge[\s\S]*activate_region "\$PRIMARY_REGION"[\s\S]*assert_coordinated_writer "\$PRIMARY_REGION"[\s\S]*switch_edge "\$\(context_value '\.primary_api_host'\)" primary[\s\S]*wait_region_header "\$ISSUER" "" "\$PRIMARY_REGION"[\s\S]*assert_artifact_set_rejected[\s\S]*assert_artifact_set_rejected/,
  );
});

test('Region-local purge handles composite keys and retries unprocessed deletes', () => {
  const functionStart = source.indexOf('purge_region_local_table()');
  const functionEnd = source.indexOf(
    '\npurge_standby_region_local_tables()',
    functionStart,
  );
  const purgeFunction = source.slice(functionStart, functionEnd);
  const runner = `
set -euo pipefail
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PROFILE=test
RTO_TARGET_SECS=30
scan_calls=0
batch_calls=0
now_epoch() { date -u +%s; }
fail() { printf 'FAIL: %s\\n' "$*" >&2; exit 1; }
pass() { :; }
sleep() { :; }
aws() {
  case " $* " in
    *" dynamodb describe-table "*)
      printf '%s\\n' '{"Table":{"TableName":"standby-table","TableStatus":"ACTIVE","TableArn":"arn:aws:dynamodb:us-west-2:123456789012:table/standby-table","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"},{"AttributeName":"sk","KeyType":"RANGE"}]}}'
      ;;
    *" dynamodb scan "*)
      scan_calls=$((scan_calls + 1))
      if [[ "$scan_calls" == 1 ]]; then
        printf '%s\\n' '{"Items":[{"pk":{"S":"a"},"sk":{"N":"1"},"payload":{"S":"must-not-delete-as-key"}},{"pk":{"S":"b"},"sk":{"N":"2"}}]}'
      else
        printf '%s\\n' '{"Items":[]}'
      fi
      ;;
    *" dynamodb batch-write-item "*)
      batch_calls=$((batch_calls + 1))
      local argument request=""
      for argument in "$@"; do
        [[ "$argument" == file://* ]] && request="\${argument#file://}"
      done
      jq -e '
        .RequestItems["standby-table"] | length >= 1 and
        all(.[]; (.DeleteRequest.Key | keys | sort) == ["pk","sk"])
      ' "$request" >/dev/null
      if [[ "$batch_calls" == 1 ]]; then
        printf '%s\\n' '{"UnprocessedItems":{"standby-table":[{"DeleteRequest":{"Key":{"pk":{"S":"a"},"sk":{"N":"1"}}}}]}}'
      else
        printf '%s\\n' '{"UnprocessedItems":{}}'
      fi
      ;;
    *)
      printf 'unexpected aws call: %s\\n' "$*" >&2
      return 1
      ;;
  esac
}
${purgeFunction}
purge_region_local_table us-west-2 composite standby-table
[[ "$TABLE_PURGED_COUNT" == 2 ]]
[[ "$scan_calls" == 2 ]]
[[ "$batch_calls" == 2 ]]
`;
  const result = spawnSync('bash', ['-c', runner], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('a fresh failover run reaches deployment context initialization', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'failover-fresh-'));
  const bin = path.join(directory, 'bin');
  const home = path.join(directory, 'home');
  fs.mkdirSync(bin);
  fs.mkdirSync(home);
  const fakeAws = path.join(bin, 'aws');
  fs.writeFileSync(
    fakeAws,
    `#!/usr/bin/env bash
if [[ "$*" == *"cloudformation describe-stacks"* ]]; then
  printf "FAKE_AWS_INITIALIZE_CONTEXT\\n" >&2
  exit 86
fi
printf "UNEXPECTED_FAKE_AWS_CALL: %s\\n" "$*" >&2
exit 87
`,
    { mode: 0o755 },
  );
  fs.writeFileSync(
    path.join(bin, 'python3'),
    '#!/usr/bin/env bash\n[[ "${1:-}" == "-c" ]]\n',
    { mode: 0o755 },
  );

  try {
    const run = spawnSync('bash', [DRILL], {
      cwd: path.resolve(__dirname, '../..'),
      encoding: 'utf8',
      env: {
        ...process.env,
        ACTION: 'run',
        AWS_PROFILE: 'ci-test',
        HOME: home,
        PATH: `${bin}:${process.env.PATH}`,
        RUN_ID: 'fresh-context',
        SAAS_ZONE: 'auth.example.com',
        STATE_ROOT: path.join(directory, 'state'),
      },
    });
    assert.equal(run.status, 86, run.stdout + run.stderr);
    assert.match(
      run.stdout + run.stderr,
      /FAKE_AWS_INITIALIZE_CONTEXT/,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('an absent inactive Region row is normalized before writer checks', () => {
  const reader = source.slice(
    source.indexOf('read_control_row()'),
    source.indexOf('\n\nassert_region_fence_matches()'),
  );
  assert.ok(reader.startsWith('read_control_row()'));
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'failover-empty-row-'));
  const fakeAws = path.join(directory, 'aws');
  const output = path.join(directory, 'row.json');
  fs.writeFileSync(fakeAws, '#!/usr/bin/env bash\nexit 0\n', { mode: 0o755 });

  try {
    const run = spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
PROFILE=default
context_value() { printf 'region-control-table'; }
fail() { printf 'FAIL: %s\\n' "$*" >&2; exit 1; }
${reader}
read_control_row us-west-2 us-west-2 "$1"
jq -e '(.Item.active.BOOL // false) == false' "$1" >/dev/null`,
        'empty-row-check',
        output,
      ],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          PATH: `${directory}:${process.env.PATH}`,
        },
      },
    );
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.deepEqual(JSON.parse(fs.readFileSync(output, 'utf8')), {});
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('issuer validation accepts only the exact deployed tenant alias', () => {
  const validator = source.slice(
    source.indexOf('validated_issuer_host()'),
    source.indexOf('\n\nfor command in aws'),
  );
  assert.ok(validator.startsWith('validated_issuer_host()'));
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'issuer-alias-'));
  const config = path.join(directory, 'distribution.json');
  const run = (issuer, tenant = 't1', aliases = ['t1.auth.example.com']) => {
    fs.writeFileSync(
      config,
      JSON.stringify({
        DistributionConfig: {
          Aliases: { Quantity: aliases.length, Items: aliases },
        },
      }),
    );
    return spawnSync(
      'bash',
      [
        '-c',
        `set -euo pipefail
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
${validator}
validated_issuer_host "$1" "$2" "$3"`,
        'issuer-validator',
        config,
        issuer,
        tenant,
      ],
      { encoding: 'utf8' },
    );
  };

  try {
    const valid = run('https://t1.auth.example.com');
    assert.equal(valid.status, 0, valid.stderr);
    assert.equal(valid.stdout, 't1.auth.example.com');
    for (const invalid of [
      run('http://t1.auth.example.com'),
      run('https://t1.auth.example.com/path'),
      run('https://t1.auth.example.com?query=1'),
      run('https://t1.auth.example.com:443'),
      run('https://admin@t1.auth.example.com'),
      run('https://t2.auth.example.com', 't1', ['t2.auth.example.com']),
      run('https://t1.auth.example.com', 't1', ['*.auth.example.com']),
      run('https://t1.other.example.com'),
    ]) {
      assert.notEqual(invalid.status, 0);
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('multi-region deployment accepts only the reviewed Region pair', () => {
  assert.match(
    source,
    /assert_supported_region_pair\(\)[\s\S]*PRIMARY_REGION.*us-east-1.*STANDBY_REGION.*us-west-2/,
  );
  assert.match(
    source,
    /load_context_settings\(\)[\s\S]*PRIMARY_REGION=.*primary_region[\s\S]*STANDBY_REGION=.*standby_region[\s\S]*assert_supported_region_pair/,
  );
  assert.match(
    infraAppSource,
    /region !== 'us-east-1' \|\| standbyRegion !== 'us-west-2'/,
  );
  assert.match(
    infraAppSource,
    /supports only primary us-east-1 and standby us-west-2/,
  );
});

test('every control transition advances revision and checks the prior state', () => {
  assert.match(source, /failover_quiesce:\(\$initial_revision\+1\)/);
  assert.match(source, /failover_active:\(\$initial_revision\+2\)/);
  assert.match(source, /failback_quiesce:\(\$initial_revision\+3\)/);
  assert.match(source, /failback_active:\(\$initial_revision\+4\)/);
  assert.match(
    source,
    /ConditionExpression:"#state = :active_state AND active_region = :source AND revision = :expected"/,
  );
  assert.match(
    source,
    /#state = :quiescing AND active_region = :source AND revision = :quiesce AND operation_id = :run/,
  );
  assert.match(
    source,
    /if \$source == \$standby[\s\S]*standby_region_local_purge_revision = :quiesce/,
  );
  assert.match(source, /operation_id = :run/);
  assert.match(
    source,
    /control_region="\$\(context_value '\.primary_region'\)"/,
  );
});

test('evidence contains hashes and measurements, never raw replay artifacts', () => {
  assert.match(source, /source_code_sha256/);
  assert.match(source, /target_code_sha256/);
  assert.match(source, /failover_rto_secs/);
  assert.match(source, /grant_revoke_rpo_secs/);
  assert.match(source, /git_commit:\$deployment_commit/);
  assert.match(source, /rejection did not prove the expected reason/);
  assert.match(source, /authorization code belongs to another Region/);
  assert.match(source, /code 无效或已使用/);
  assert.match(source, /refresh_token belongs to another Region/);
  assert.match(source, /invalid invitation/);
  assert.match(source, /源 Grant 已吊销或过期/);
  assert.match(source, /\.error == "invalid_grant"/);
  assert.match(source, /consumed_codes_rejected:true/);
  assert.match(source, /invitations_rejected:true/);
  assert.match(source, /issuer_tokens_verified:true/);
  assert.match(source, /artifact_classes_tested:4/);
  assert.match(source, /signature_stages_verified:3/);
  assert.match(source, /grant_revocation_blocks_refresh:true/);
  assert.match(source, /standby_region_local_tables_purged:true/);
  assert.doesNotMatch(source, /--data-urlencode "code=\$/);
  assert.doesNotMatch(source, /--data-urlencode "refresh_token=\$/);
  assert.doesNotMatch(source, /--data-urlencode "id_token_hint=\$/);
  assert.match(source, /printf '%s' "\$code" >"\$SECRETS_DIR\/\$label\.code"/);
  assert.match(
    source,
    /jq -erj '\.refresh_token' "\$output" >"\$SECRETS_DIR\/\$label\.refresh"/,
  );
  assert.match(
    source,
    /jq -erj '\.id_token' "\$token_file" >"\$id_token_file"/,
  );
  assert.doesNotMatch(
    source,
    /printf '%s\\n'[^>]*>"\$SECRETS_DIR\/\$label\.code"/,
  );
  const evidenceBlock = source.slice(
    source.indexOf('write_evidence()'),
    source.indexOf('show_status()'),
  );
  assert.doesNotMatch(evidenceBlock, /refresh_token:/);
  assert.doesNotMatch(evidenceBlock, /id_token:/);
  assert.doesNotMatch(evidenceBlock, /access_token:/);
  assert.doesNotMatch(evidenceBlock, /invitation_url:/);
});
