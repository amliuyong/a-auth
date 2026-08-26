const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

function passwordInfrastructure() {
  const app = new App();
  const stack = new AgentAuthStack(app, 'PasswordConfigTest', {
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
  const tableEntries = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('PasswordCredentialsTable') &&
      resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.equal(tableEntries.length, 1, 'expected one password credential table');
  const [tableId, table] = tableEntries[0];
  const authFunctions = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.SCOPE === 'non_token' &&
      resource.Properties?.Environment?.Variables?.PASSWORD_CREDENTIALS_TABLE,
  );
  assert.equal(authFunctions.length, 1, 'expected exactly one main Auth Lambda');
  return { template, tableId, table, authFunction: authFunctions[0][1] };
}

test('c9_8_password_credentials_use_persistent_encrypted_non_ttl_table', () => {
  const { template, tableId, table, authFunction } = passwordInfrastructure();
  assert.deepEqual(table.Properties.KeySchema, [
    { AttributeName: 'user_id', KeyType: 'HASH' },
  ]);
  assert.equal(table.Properties.BillingMode, 'PAY_PER_REQUEST');
  assert.equal(
    table.Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled,
    true,
  );
  assert.equal(table.Properties.SSESpecification.SSEEnabled, true);
  assert.equal(
    table.Properties.TimeToLiveSpecification,
    undefined,
    'password credentials must not expire through DynamoDB TTL',
  );
  assert.deepEqual(
    authFunction.Properties.Environment.Variables.PASSWORD_CREDENTIALS_TABLE,
    { Ref: tableId },
  );
  assert.equal(
    authFunction.Properties.Environment.Variables.AGENT_AUTH_PASSWORD_WORKERS,
    undefined,
  );
  assert.equal(
    authFunction.Properties.MemorySize,
    512,
    'Auth Lambda needs headroom above warm Argon2 allocator arenas',
  );
  assert.match(
    JSON.stringify(template.Resources),
    new RegExp(`"Fn::GetAtt":\\["${tableId}","Arn"\\]`),
    'Auth Lambda policy must reference the password table ARN',
  );
  assert.deepEqual(template.Outputs.PasswordCredentialsTableName.Value, {
    Ref: tableId,
  });
});
