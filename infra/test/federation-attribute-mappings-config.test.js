const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');

function synth() {
  const app = new App();
  const assetPath = path.resolve(__dirname);
  const stack = new AgentAuthStack(app, 'FederationAttributeMappingsTest', {
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

test('federation attribute mapping authority is durable and runtime-scoped', () => {
  const template = synth();
  const [tableId, table] = resourceByPrefix(
    template,
    'FederationAttributeMappingsTable',
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
  assert.deepEqual(
    template.Outputs.FederationAttributeMappingsTableName.Value,
    { Ref: tableId },
  );

  const runtimeFunctions = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::Lambda::Function' &&
      ['non_token', 'token'].includes(
        resource.Properties.Environment?.Variables?.SCOPE,
      ),
  );
  const nonToken = runtimeFunctions.find(
    (runtime) =>
      runtime.Properties.Environment.Variables.SCOPE === 'non_token',
  );
  const token = runtimeFunctions.find(
    (runtime) => runtime.Properties.Environment.Variables.SCOPE === 'token',
  );
  assert.deepEqual(
    nonToken.Properties.Environment.Variables
      .FEDERATION_ATTRIBUTE_MAPPINGS_TABLE,
    { Ref: tableId },
  );
  assert.equal(
    token.Properties.Environment.Variables
      .FEDERATION_ATTRIBUTE_MAPPINGS_TABLE,
    undefined,
  );
  const [, governanceWorker] = resourceByPrefix(
    template,
    'GovernanceWorkerFn',
    'AWS::Lambda::Function',
  );
  assert.equal(
    governanceWorker.Properties.Environment.Variables.WORKER,
    'governance',
  );
  assert.equal(
    governanceWorker.Properties.Environment.Variables
      .FEDERATION_ATTRIBUTE_MAPPINGS_TABLE,
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
        actions.includes('dynamodb:TransactWriteItems')
      );
    }),
  );
});
