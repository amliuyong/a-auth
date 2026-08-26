const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

test('UsersTable has a sparse tenant index for SCIM user listing', () => {
  const app = new App();
  const stack = new AgentAuthStack(app, 'ScimUsersIndexTest', {
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
  const table = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::DynamoDB::Table' &&
      resource.Properties?.GlobalSecondaryIndexes?.some(
        (index) => index.IndexName === 'email-index',
      ),
  );

  assert.ok(table, 'expected UsersTable');
  const scimIndex = table.Properties.GlobalSecondaryIndexes.find(
    (index) => index.IndexName === 'scim_tenant-index',
  );
  assert.ok(scimIndex, 'expected sparse SCIM tenant index');
  assert.deepEqual(scimIndex.KeySchema, [
    { AttributeName: 'scim_tenant', KeyType: 'HASH' },
    { AttributeName: 'user_id', KeyType: 'RANGE' },
  ]);
  assert.deepEqual(scimIndex.Projection, { ProjectionType: 'ALL' });
  assert.ok(
    table.Properties.AttributeDefinitions.some(
      (attribute) =>
        attribute.AttributeName === 'scim_tenant' &&
        attribute.AttributeType === 'S',
    ),
  );

  for (const [logicalPrefix, projectionType] of [
    ['RefreshTable', 'KEYS_ONLY'],
    ['SessionsTable', 'ALL'],
  ]) {
    const entry = Object.entries(template.Resources).find(
      ([logicalId, resource]) =>
        logicalId.startsWith(logicalPrefix) &&
        resource.Type === 'AWS::DynamoDB::Table',
    );
    assert.ok(entry, `expected ${logicalPrefix}`);
    const lifecycleIndex = entry[1].Properties.GlobalSecondaryIndexes.find(
      (index) => index.IndexName === 'user_id-index',
    );
    assert.ok(lifecycleIndex, `expected ${logicalPrefix} user lifecycle index`);
    assert.deepEqual(lifecycleIndex.KeySchema, [
      { AttributeName: 'user_id', KeyType: 'HASH' },
    ]);
    assert.deepEqual(lifecycleIndex.Projection, { ProjectionType: projectionType });
  }
});
