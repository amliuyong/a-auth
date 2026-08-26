const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');

function synth() {
  const app = new App();
  const assetPath = path.resolve(__dirname);
  const stack = new AgentAuthStack(app, 'AttributeNamespacesTest', {
    env: { account: '123456789012', region: 'us-east-1' },
    lambdaAssetPath: assetPath,
    securityEventArchiveAssetPath: assetPath,
    ssfDeliveryAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    deployFrontend: false,
  });
  return Template.fromStack(stack).toJSON();
}

function resourceByPrefix(template, prefix, type) {
  const entry = Object.entries(template.Resources).find(
    ([logicalId, resource]) =>
      logicalId.startsWith(prefix) && resource.Type === type,
  );
  assert.ok(entry, `expected ${type} resource with prefix ${prefix}`);
  return entry;
}

test('attribute namespace registry is durable and wired only to the non-token runtime', () => {
  const template = synth();
  const [tableId, table] = resourceByPrefix(
    template,
    'AttributeNamespacesTable',
    'AWS::DynamoDB::Table',
  );
  assert.deepEqual(table.Properties.KeySchema, [
    { AttributeName: 'tenant_id', KeyType: 'HASH' },
    { AttributeName: 'lookup_key', KeyType: 'RANGE' },
  ]);
  assert.equal(
    table.Properties.PointInTimeRecoverySpecification
      .PointInTimeRecoveryEnabled,
    true,
  );
  assert.equal(table.Properties.TimeToLiveSpecification, undefined);
  assert.deepEqual(template.Outputs.AttributeNamespacesTableName.Value, {
    Ref: tableId,
  });

  const runtimeFunctions = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::Lambda::Function' &&
      ['non_token', 'token'].includes(
        resource.Properties.Environment?.Variables?.SCOPE,
      ),
  );
  assert.equal(runtimeFunctions.length, 2);
  const nonToken = runtimeFunctions.find(
    (runtime) =>
      runtime.Properties.Environment.Variables.SCOPE === 'non_token',
  );
  const token = runtimeFunctions.find(
    (runtime) => runtime.Properties.Environment.Variables.SCOPE === 'token',
  );
  assert.deepEqual(
    nonToken.Properties.Environment.Variables.ATTRIBUTE_NAMESPACES_TABLE,
    { Ref: tableId },
  );
  assert.deepEqual(
    token.Properties.Environment.Variables.ATTRIBUTE_NAMESPACES_TABLE,
    undefined,
  );

  const policies = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::IAM::Policy' ||
      resource.Type === 'AWS::IAM::ManagedPolicy',
  );
  const statements = policies.flatMap(
    (policy) => policy.Properties.PolicyDocument.Statement,
  );
  assert.ok(
    statements.some((statement) => {
      const actions = [statement.Action].flat();
      return (
        JSON.stringify(statement.Resource).includes(tableId) &&
        actions.includes('dynamodb:TransactGetItems')
      );
    }),
  );
  assert.ok(
    statements.some((statement) => {
      const actions = [statement.Action].flat();
      return (
        JSON.stringify(statement.Resource).includes(tableId) &&
        actions.includes('dynamodb:TransactWriteItems')
      );
    }),
  );
});
