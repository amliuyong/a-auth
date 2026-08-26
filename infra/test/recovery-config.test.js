const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

test('recovery table expires only short-lived result items through expires_at', () => {
  const app = new App();
  const stack = new AgentAuthStack(app, 'RecoveryConfigTest', {
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
      logicalId.startsWith('RecoveryTable') &&
      resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.equal(tables.length, 1);
  const [, table] = tables[0];
  assert.deepEqual(table.Properties.KeySchema, [
    { AttributeName: 'user_lookup', KeyType: 'HASH' },
  ]);
  assert.deepEqual(table.Properties.TimeToLiveSpecification, {
    AttributeName: 'expires_at',
    Enabled: true,
  });
});
