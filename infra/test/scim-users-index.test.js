const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

test('SCIM users have a sparse listing index and transactional alias snapshot access', () => {
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

  const [usersId] = Object.entries(template.Resources).find(
    ([, resource]) => resource === table,
  );
  const runtimes = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::Lambda::Function' &&
      ['token', 'non_token'].includes(resource.Properties.Environment?.Variables?.SCOPE),
  );
  assert.equal(runtimes.length, 2);
  for (const runtime of runtimes) {
    const roleId = runtime.Properties.Role['Fn::GetAtt'][0];
    const statements = Object.values(template.Resources)
      .filter(
        (resource) =>
          ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'].includes(resource.Type) &&
          (resource.Properties.Roles ?? []).some((role) => role.Ref === roleId),
      )
      .flatMap((resource) => resource.Properties.PolicyDocument.Statement);
    assert.ok(
      statements.some(
        (statement) =>
          [statement.Action].flat().includes('dynamodb:TransactGetItems') &&
          JSON.stringify(statement.Resource).includes(usersId),
      ),
      'Each HTTP runtime must read SCIM aliases from a transaction snapshot',
    );
  }
});
