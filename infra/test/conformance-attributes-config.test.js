const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');

function tableByPrefix(template, prefix) {
  const entry = Object.entries(template.Resources).find(
    ([logicalId, resource]) =>
      logicalId.startsWith(prefix) && resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.ok(entry, `expected DynamoDB table with prefix ${prefix}`);
  return entry[1];
}

test('c8_12_attribute_authority_tables_are_durable_without_ttl', () => {
  const app = new App();
  const assetPath = path.resolve(__dirname);
  const stack = new AgentAuthStack(app, 'C812AttributeDurabilityTest', {
    env: { account: '123456789012', region: 'us-east-1' },
    lambdaAssetPath: assetPath,
    securityEventArchiveAssetPath: assetPath,
    ssfDeliveryAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    deployFrontend: false,
  });
  const template = Template.fromStack(stack).toJSON();

  for (const prefix of [
    'UsersTable',
    'AttributeNamespacesTable',
    'FederationAttributeMappingsTable',
  ]) {
    const table = tableByPrefix(template, prefix);
    assert.equal(
      table.Properties.PointInTimeRecoverySpecification
        .PointInTimeRecoveryEnabled,
      true,
      `${prefix} must enable PITR`,
    );
    assert.equal(
      table.Properties.TimeToLiveSpecification,
      undefined,
      `${prefix} must not expire authority data through TTL`,
    );
  }
});
