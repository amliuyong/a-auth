const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '../..');
const shell = fs.readFileSync(path.join(root, 'e2e/federation_assurance.sh'), 'utf8');
const driver = fs.readFileSync(
  path.join(root, 'e2e/federation_assurance_roundtrip.py'),
  'utf8',
);

test('C9.5 gate binds a clean exact commit to the deployed Auth artifact', () => {
  assert.match(shell, /git -C "\$ROOT" status --porcelain/);
  assert.match(shell, /DEPLOYED_COMMIT.*stack_output DeploymentCommit/s);
  assert.match(shell, /\[\[ "\$DEPLOYED_COMMIT" == "\$HEAD_COMMIT" \]\]/);
  assert.match(shell, /AGENT_AUTH_FEDERATION_ENABLED/);
  assert.match(shell, /ADMIN_URL="\$\(stack_output AdminUrl\)"/);
  assert.match(shell, /PUBLIC_ORIGIN="\$\{ADMIN_URL%\/admin\}"/);
  assert.match(shell, /CALLBACK_URL="\$PUBLIC_ORIGIN\/federation\/callback"/);
  assert.match(shell, /AS_URL="\$PUBLIC_ORIGIN"/);
  assert.doesNotMatch(shell, /CALLBACK_URL="\$API_URL\/federation\/callback"/);
  assert.doesNotMatch(shell, /AS_URL="\$API_URL"/);
  assert.match(shell, /CodeSha256/);
  assert.match(shell, /target\/lambda\/agent-auth-lambda/);
  assert.match(shell, /deployment-provenance\.json/);
  assert.match(shell, /\.bootstrap_sha256/);
  assert.match(shell, /cmp "\$AUTH_UNPACKED\/bootstrap" "\$LOCAL_BOOTSTRAP"/);
  assert.doesNotMatch(shell, /infra\/lambda-assets/);
});

test('C9.5 gate uses disposable Cognito and Agent Auth resources', () => {
  assert.match(shell, /create-user-pool-client/);
  assert.match(shell, /admin-create-user/);
  assert.match(shell, /admin-set-user-password/);
  assert.match(shell, /agent-auth\/federation\/c9-5-/);
  assert.match(shell, /PUT "\$API_URL\/admin\/federation"/);
  assert.match(shell, /attribute_not_exists\(client_id\)/);
});

test('C9.5 driver proves baseline, strong-negative, prompt, and max-age behavior', () => {
  assert.match(driver, /strong_without_trusted_acr_rejected/);
  assert.match(driver, /upstream_strong_parameters_forwarded/);
  assert.match(driver, /upstream_query\.get\("acr_values"\)/);
  assert.match(driver, /upstream_query\.get\("prompt"\)/);
  assert.match(driver, /upstream_query\.get\("max_age"\)/);
  assert.match(driver, /unmet_authentication_requirements/);
  assert.match(driver, /login_required/);
  assert.match(driver, /consent_required/);
  assert.match(driver, /prompt=login did not force reauthentication/);
  assert.match(driver, /max_age=0 did not force reauthentication/);
  assert.match(shell, /urn:agent-auth:assurance:baseline/);
});

test('C9.5 PASS requires verified cloud and local cleanup', () => {
  assert.match(driver, /persist_recovery\(flow_state=flow_state\)/);
  const beginFederation = driver.slice(
    driver.indexOf('def begin_federation'),
    driver.indexOf('def callback_baseline'),
  );
  assert.ok(
    beginFederation.indexOf('persist_recovery(flow_state=flow_state)') <
      beginFederation.indexOf('upstream_query.get("acr_values")'),
    'flow recovery must be persisted before upstream forwarding assertions',
  );
  assert.match(driver, /persist_recovery\(session_id=/);
  assert.match(shell, /RECOVERY_FILE="\$WORK\/recovery\.json"/);
  assert.match(shell, /delete_recovery_flows/);
  assert.match(shell, /--table-name "\$FEDERATION_FLOW_TABLE"/);
  assert.match(shell, /ddb_absent "\$FEDERATION_CONFIG_TABLE"/);
  assert.match(shell, /ddb_absent "\$FEDERATION_FLOW_TABLE"/);
  assert.match(
    shell,
    /if ! output="\$\(aws dynamodb get-item[\s\S]*?--output json\)"; then\s+return 1\s+fi/,
  );
  assert.match(shell, /\[\[ -z "\$output" \]\] && return 0/);
  assert.match(shell, /jq -e 'has\("Item"\) \| not'/);
  assert.match(shell, /DELETE_CONFIG_STATUS=/);
  assert.match(shell, /\[\[ "\$DELETE_CONFIG_STATUS" == "200" \]\]/);
  assert.match(shell, /cognito_client_absent/);
  assert.match(shell, /cognito_user_absent/);
  assert.match(shell, /secret_absent/);
  assert.match(shell, /ResourceNotFoundException/);
  assert.match(shell, /UserNotFoundException/);
  assert.match(shell, /rm -f "\$EVIDENCE_FILE"/);
  assert.match(shell, /local_credentials_removed_before_evidence:true/);
  assert.match(shell, /mutable_test_state_removed:true/);
});

test('C9.5 credentials are supplied through private files, not process arguments', () => {
  assert.match(shell, /--header "@\$ADMIN_HEADER_FILE"/);
  assert.match(
    shell,
    /jq -jer '\.UserPoolClient\.ClientSecret' "\$COGNITO_CLIENT_FILE" >"\$COGNITO_SECRET_FILE"/,
  );
  assert.match(shell, /--secret-string "file:\/\/\$COGNITO_SECRET_FILE"/);
  assert.match(shell, /--cli-input-json "file:\/\/\$PASSWORD_INPUT_FILE"/);
  assert.doesNotMatch(shell, /authorization: Bearer \$\(/);
  assert.doesNotMatch(shell, /--password "\$\(<"\$PASSWORD_FILE"\)"/);
});
