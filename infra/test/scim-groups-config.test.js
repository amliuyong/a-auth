const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

test('c12_3_scim_groups_persistence_and_runtime_ownership', () => {
  const app = new App();
  const stack = new AgentAuthStack(app, 'ScimGroupsConfigTest', {
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
      logicalId.startsWith('ScimGroupsTable') &&
      resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.equal(tableEntries.length, 1, 'expected one SCIM Groups table');
  const [tableId, table] = tableEntries[0];
  assert.deepEqual(table.Properties.KeySchema, [
    { AttributeName: 'pk', KeyType: 'HASH' },
    { AttributeName: 'sk', KeyType: 'RANGE' },
  ]);
  const tenantIndex = table.Properties.GlobalSecondaryIndexes.find(
    (index) => index.IndexName === 'tenant_kind-index',
  );
  assert.deepEqual(tenantIndex.KeySchema, [
    { AttributeName: 'tenant_kind', KeyType: 'HASH' },
    { AttributeName: 'group_id', KeyType: 'RANGE' },
  ]);
  assert.deepEqual(tenantIndex.Projection, { ProjectionType: 'ALL' });
  assert.equal(
    table.Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled,
    true,
  );
  assert.equal(table.Properties.TimeToLiveSpecification, undefined);

  const consumers = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.SCIM_GROUPS_TABLE,
  );
  assert.equal(
    consumers.length,
    3,
    'only non-token, token, and governance Rust runtimes receive the Groups table',
  );
  for (const [, consumer] of consumers) {
    assert.deepEqual(
      consumer.Properties.Environment.Variables.SCIM_GROUPS_TABLE,
      { Ref: tableId },
    );
  }
  assert.deepEqual(
    consumers
      .map(([, consumer]) => consumer.Properties.Environment.Variables.SCOPE ?? 'governance')
      .sort(),
    ['governance', 'non_token', 'token'],
  );
  const expectedRoles = consumers
    .map(([, consumer]) => consumer.Properties.Role['Fn::GetAtt'][0])
    .sort();
  const grantedRoles = Object.values(template.Resources)
    .filter(
      (resource) =>
        resource.Type === 'AWS::IAM::ManagedPolicy' &&
        JSON.stringify(resource.Properties.PolicyDocument).includes(tableId),
    )
    .flatMap((policy) => policy.Properties.Roles.map((role) => role.Ref))
    .filter((role, index, roles) => roles.indexOf(role) === index)
    .sort();
  assert.deepEqual(
    grantedRoles,
    expectedRoles,
    'no non-consumer IAM role may receive SCIM Groups table permissions',
  );
  assert.deepEqual(template.Outputs.ScimGroupsTableName.Value, { Ref: tableId });
});
