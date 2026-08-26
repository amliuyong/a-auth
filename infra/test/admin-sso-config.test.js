const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

test('c12_3_admin_oidc_durable_and_runtime_state_separation', () => {
  const app = new App();
  const stack = new AgentAuthStack(app, 'AdminSsoConfigTest', {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    credentialMigrationAssetPath: path.resolve(__dirname),
    deployFrontend: false,
    tenantResidency: tenantResidency(),
  });
  const template = Template.fromStack(stack).toJSON();
  const tables = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('AdminAuthTable') &&
      resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.equal(tables.length, 1, 'expected one dedicated Admin Auth table');
  const [tableId, table] = tables[0];
  assert.deepEqual(table.Properties.KeySchema, [
    { AttributeName: 'key', KeyType: 'HASH' },
  ]);
  assert.equal(table.Properties.BillingMode, 'PAY_PER_REQUEST');
  assert.equal(table.Properties.SSESpecification.SSEEnabled, true);
  assert.equal(
    table.Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled,
    true,
  );
  assert.deepEqual(table.Properties.TimeToLiveSpecification, {
    AttributeName: 'expires_at',
    Enabled: true,
  });

  const consumers = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.ADMIN_AUTH_TABLE,
  );
  assert.equal(consumers.length, 3);
  assert.deepEqual(
    consumers
      .map(([, consumer]) => consumer.Properties.Environment.Variables.SCOPE ?? 'governance')
      .sort(),
    ['governance', 'non_token', 'token'],
  );
  for (const [, consumer] of consumers) {
    assert.deepEqual(consumer.Properties.Environment.Variables.ADMIN_AUTH_TABLE, {
      Ref: tableId,
    });
  }
  assert.match(
    JSON.stringify(template.Resources),
    /secret:agent-auth\/admin-oidc\/\*/,
    'the non-token callback runtime may resolve the dedicated Admin OIDC secret prefix',
  );
  assert.deepEqual(template.Outputs.AdminAuthTableName.Value, { Ref: tableId });

  const runtimeTables = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('AdminAuthRuntimeTable') &&
      resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.equal(runtimeTables.length, 1, 'expected one Region-local Admin runtime table');
  const [runtimeTableId, runtimeTable] = runtimeTables[0];
  assert.deepEqual(runtimeTable.Properties.KeySchema, [
    { AttributeName: 'key', KeyType: 'HASH' },
  ]);
  assert.deepEqual(runtimeTable.Properties.TimeToLiveSpecification, {
    AttributeName: 'expires_at',
    Enabled: true,
  });
  for (const [, consumer] of consumers) {
    assert.deepEqual(
      consumer.Properties.Environment.Variables.ADMIN_AUTH_RUNTIME_TABLE,
      { Ref: runtimeTableId },
    );
  }
  assert.deepEqual(template.Outputs.AdminAuthRuntimeTableName.Value, {
    Ref: runtimeTableId,
  });

  const expectedRoles = consumers
    .map(([, consumer]) => consumer.Properties.Role['Fn::GetAtt'][0])
    .sort();
  for (const protectedTableId of [tableId, runtimeTableId]) {
    const grantedRoles = Object.values(template.Resources)
      .filter(
        (resource) =>
          resource.Type === 'AWS::IAM::ManagedPolicy' &&
          JSON.stringify(resource.Properties.PolicyDocument).includes(protectedTableId),
      )
      .flatMap((policy) => policy.Properties.Roles.map((role) => role.Ref))
      .filter((role, index, roles) => roles.indexOf(role) === index)
      .sort();
    assert.deepEqual(
      grantedRoles,
      expectedRoles,
      `no non-consumer IAM role may receive ${protectedTableId} permissions`,
    );
  }
});

test('all Rust runtimes receive the same explicit assurance policy', () => {
  const app = new App();
  const stack = new AgentAuthStack(app, 'AssurancePolicyConfigTest', {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    reclaimAssetPath: path.resolve(__dirname),
    recomputeAssetPath: path.resolve(__dirname),
    credentialMigrationAssetPath: path.resolve(__dirname),
    deployFrontend: false,
    tenantResidency: tenantResidency(),
  });
  const template = Template.fromStack(stack).toJSON();
  const runtimes = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.ADMIN_AUTH_TABLE,
  );
  assert.equal(
    runtimes.length,
    5,
    'Auth, Token, Governance, Reclaim, and Recompute must share policy',
  );
  assert.deepEqual(
    runtimes
      .map((runtime) => runtime.Properties.Environment.Variables.SCOPE)
      .filter(Boolean)
      .sort(),
    ['non_token', 'token'],
  );
  for (const runtime of runtimes) {
    const environment = runtime.Properties.Environment.Variables;
    assert.equal(environment.AGENT_AUTH_STRONG_MAX_AGE_SECS, '300');
    assert.equal(environment.AGENT_AUTH_HIGH_RISK_RAR_ACTIONS, 'transfer');
    assert.equal(
      environment.AGENT_AUTH_HIGH_RISK_ADMIN_ACTIONS,
      'access.manage',
    );
  }
});
