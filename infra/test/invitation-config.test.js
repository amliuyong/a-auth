const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

function functionRole(template, fn) {
  const roleId = fn.Properties.Role['Fn::GetAtt'][0];
  return [roleId, template.Resources[roleId]];
}

function policyStatementsForFunction(template, fn) {
  const [roleId, role] = functionRole(template, fn);
  const inlineStatements = (role.Properties.Policies ?? [])
    .flatMap((policy) => policy.PolicyDocument.Statement);
  const referencedManagedPolicies = new Set(
    (role.Properties.ManagedPolicyArns ?? [])
      .map((value) => value.Ref)
      .filter(Boolean),
  );
  const attachedStatements = Object.entries(template.Resources)
    .filter(
      ([logicalId, resource]) =>
        ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'].includes(resource.Type) &&
        (resource.Properties.Roles?.some((attachedRole) => attachedRole.Ref === roleId) ||
          referencedManagedPolicies.has(logicalId)),
    )
    .flatMap(([, resource]) => resource.Properties.PolicyDocument.Statement);
  return [...inlineStatements, ...attachedStatements];
}

function dynamoActionShape(action) {
  if (typeof action === 'string') {
    const normalized = action.toLowerCase();
    const isDynamo = normalized === '*' || normalized.startsWith('dynamodb:');
    return {
      isDynamo,
      isBroad: isDynamo && normalized.includes('*'),
    };
  }
  return {
    isDynamo: true,
    isBroad: true,
  };
}

function isExactTableArn(value, tableIds) {
  const getAtt = value?.['Fn::GetAtt'];
  return Array.isArray(getAtt)
    && getAtt.length === 2
    && tableIds.has(getAtt[0])
    && getAtt[1] === 'Arn';
}

function isAllowedDynamoResource(value, tableIds) {
  if (Array.isArray(value)) {
    return value.every((resource) => isAllowedDynamoResource(resource, tableIds));
  }
  if (isExactTableArn(value, tableIds)) return true;
  const join = value?.['Fn::Join'];
  const indexSuffix = Array.isArray(join?.[1]) ? join[1][1] : undefined;
  const wildcardIndexSuffix = ['/index/', '*'].join('');
  const isAllowedIndexSuffix =
    typeof indexSuffix === 'string'
    && indexSuffix.startsWith('/index/')
    && (indexSuffix === wildcardIndexSuffix || !indexSuffix.includes('*'));
  return Array.isArray(join)
    && join.length === 2
    && join[0] === ''
    && Array.isArray(join[1])
    && join[1].length === 2
    && isExactTableArn(join[1][0], tableIds)
    && isAllowedIndexSuffix;
}

function assertNoBroadDynamoAccess(template, authFunction) {
  const [, role] = functionRole(template, authFunction);
  const managedPolicyArns = role.Properties.ManagedPolicyArns ?? [];
  assert.equal(
    managedPolicyArns.length,
    1,
    'Auth Lambda must have only the basic execution managed policy',
  );
  const managedPolicyText = JSON.stringify(managedPolicyArns[0]);
  assert.match(managedPolicyText, /AWSLambdaBasicExecutionRole/);
  assert.doesNotMatch(managedPolicyText, /dynamodb/i);

  const statements = policyStatementsForFunction(template, authFunction);
  const tableIds = new Set(
    Object.entries(template.Resources)
      .filter(([, resource]) => resource.Type === 'AWS::DynamoDB::Table')
      .map(([logicalId]) => logicalId),
  );
  for (const statement of statements) {
    const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    const actionShapes = actions.map(dynamoActionShape);
    if (!actionShapes.some(({ isDynamo }) => isDynamo)) continue;
    assert.equal(
      actionShapes.some(({ isBroad }) => isBroad),
      false,
      'Auth Lambda must not have a wildcard DynamoDB action',
    );
    assert.equal(
      isAllowedDynamoResource(statement.Resource, tableIds),
      true,
      `Auth Lambda DynamoDB resources must be exact tables or their own index namespace: ${JSON.stringify(statement)}`,
    );
  }
}

function tableLogicalId(template, prefix) {
  const entry = Object.entries(template.Resources).find(
    ([logicalId, resource]) =>
      logicalId.startsWith(prefix) &&
      resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.ok(entry, `expected ${prefix} table`);
  return entry[0];
}

function invitationInfrastructure(invitationTtlSecs) {
  const app = new App();
  const stack = new AgentAuthStack(app, 'InvitationConfigTest', {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    credentialMigrationAssetPath: path.resolve(__dirname),
    invitationTtlSecs,
    deployFrontend: false,
    tenantResidency: tenantResidency(),
  });
  const template = Template.fromStack(stack).toJSON();
  const tableEntries = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('InvitationsTable') &&
      resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.equal(tableEntries.length, 1, 'expected one dedicated invitation table');
  const [tableId, table] = tableEntries[0];
  const authFunctions = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.SCOPE === 'non_token' &&
      resource.Properties?.Environment?.Variables?.INVITATIONS_TABLE,
  );
  assert.equal(authFunctions.length, 1, 'expected exactly one main Auth Lambda');
  return { template, tableId, table, authFunction: authFunctions[0][1] };
}

test('c9_11_invitation_uses_independent_encrypted_ttl_table_and_transaction_iam', () => {
  const { template, tableId, table, authFunction } = invitationInfrastructure(43_200);
  assert.deepEqual(table.Properties.KeySchema, [
    { AttributeName: 'locator', KeyType: 'HASH' },
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
  assert.deepEqual(authFunction.Properties.Environment.Variables.INVITATIONS_TABLE, {
    Ref: tableId,
  });
  assert.equal(
    authFunction.Properties.Environment.Variables.AGENT_AUTH_INVITATION_TTL_SECS,
    '43200',
  );
  assert.match(
    JSON.stringify(template.Resources),
    new RegExp(`"Fn::GetAtt":\\["${tableId}","Arn"\\]`),
    'Auth Lambda policy must reference the invitation table ARN',
  );
  assertNoBroadDynamoAccess(template, authFunction);
  const managedPolicyMutation = structuredClone(template);
  const [, mutatedRole] = functionRole(managedPolicyMutation, authFunction);
  mutatedRole.Properties.ManagedPolicyArns.push(
    'arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess',
  );
  assert.throws(
    () => assertNoBroadDynamoAccess(managedPolicyMutation, authFunction),
    /basic execution managed policy/,
  );
  const wildcardResourceMutation = structuredClone(template);
  const wildcardStatements = policyStatementsForFunction(
    wildcardResourceMutation,
    authFunction,
  );
  wildcardStatements.push({
    Action: 'dynamodb:GetItem',
    Effect: 'Allow',
    Resource: {
      'Fn::Sub': 'arn:${AWS::Partition}:dynamodb:${AWS::Region}:${AWS::AccountId}:table/*',
    },
  });
  const [roleId] = functionRole(wildcardResourceMutation, authFunction);
  wildcardResourceMutation.Resources.WildcardDynamoPolicy = {
    Type: 'AWS::IAM::Policy',
    Properties: {
      PolicyDocument: {
        Version: '2012-10-17',
        Statement: [wildcardStatements.at(-1)],
      },
      PolicyName: 'wildcard-dynamo',
      Roles: [{ Ref: roleId }],
    },
  };
  assert.throws(
    () => assertNoBroadDynamoAccess(wildcardResourceMutation, authFunction),
    /resources must be exact tables/,
  );
  const wildcardActionMutation = structuredClone(template);
  const [wildcardActionRoleId] = functionRole(wildcardActionMutation, authFunction);
  wildcardActionMutation.Resources.WildcardDynamoActionPolicy = {
    Type: 'AWS::IAM::Policy',
    Properties: {
      PolicyDocument: {
        Version: '2012-10-17',
        Statement: [{
          Action: { 'Fn::Join': ['', ['dynamodb:', '*']] },
          Effect: 'Allow',
          Resource: { 'Fn::GetAtt': [tableId, 'Arn'] },
        }],
      },
      PolicyName: 'wildcard-dynamo-action',
      Roles: [{ Ref: wildcardActionRoleId }],
    },
  };
  assert.throws(
    () => assertNoBroadDynamoAccess(wildcardActionMutation, authFunction),
    /wildcard DynamoDB action/,
  );
  const splitWildcardActionMutation = structuredClone(template);
  const [splitWildcardActionRoleId] = functionRole(
    splitWildcardActionMutation,
    authFunction,
  );
  splitWildcardActionMutation.Resources.SplitWildcardDynamoActionPolicy = {
    Type: 'AWS::IAM::Policy',
    Properties: {
      PolicyDocument: {
        Version: '2012-10-17',
        Statement: [{
          Action: { 'Fn::Join': ['', ['dynamo', 'db:*']] },
          Effect: 'Allow',
          Resource: { 'Fn::GetAtt': [tableId, 'Arn'] },
        }],
      },
      PolicyName: 'split-wildcard-dynamo-action',
      Roles: [{ Ref: splitWildcardActionRoleId }],
    },
  };
  assert.throws(
    () => assertNoBroadDynamoAccess(splitWildcardActionMutation, authFunction),
    /wildcard DynamoDB action/,
  );
  for (const [policyName, action] of [
    ['global-wildcard-action', '*'],
    ['case-insensitive-dynamo-wildcard', 'DynamoDB:*'],
  ]) {
    const literalWildcardMutation = structuredClone(template);
    const [literalWildcardRoleId] = functionRole(literalWildcardMutation, authFunction);
    literalWildcardMutation.Resources[policyName] = {
      Type: 'AWS::IAM::Policy',
      Properties: {
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [{
            Action: action,
            Effect: 'Allow',
            Resource: { 'Fn::GetAtt': [tableId, 'Arn'] },
          }],
        },
        PolicyName: policyName,
        Roles: [{ Ref: literalWildcardRoleId }],
      },
    };
    assert.throws(
      () => assertNoBroadDynamoAccess(literalWildcardMutation, authFunction),
      /wildcard DynamoDB action/,
    );
  }
  const unrelatedIndexMutation = structuredClone(template);
  const [unrelatedIndexRoleId] = functionRole(unrelatedIndexMutation, authFunction);
  unrelatedIndexMutation.Resources.UnrelatedDynamoIndexPolicy = {
    Type: 'AWS::IAM::Policy',
    Properties: {
      PolicyDocument: {
        Version: '2012-10-17',
        Statement: [{
          Action: 'dynamodb:GetItem',
          Effect: 'Allow',
          Resource: {
            'Fn::Join': [
              '',
              [{ 'Fn::GetAtt': ['UnrelatedTable', 'Arn'] }, '/index/*'],
            ],
          },
        }],
      },
      PolicyName: 'unrelated-dynamo-index',
      Roles: [{ Ref: unrelatedIndexRoleId }],
    },
  };
  assert.throws(
    () => assertNoBroadDynamoAccess(unrelatedIndexMutation, authFunction),
    /resources must be exact tables/,
  );
  const authStatements = policyStatementsForFunction(template, authFunction);
  const directInvitationStatements = authStatements.filter((statement) => {
    const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    return JSON.stringify(statement.Resource).includes(`"${tableId}","Arn"`)
      && !actions.includes('dynamodb:TransactWriteItems');
  });
  assert.equal(directInvitationStatements.length, 1);
  assert.deepEqual(directInvitationStatements[0].Resource, {
    'Fn::GetAtt': [tableId, 'Arn'],
  });
  assert.deepEqual(
    [...directInvitationStatements[0].Action].sort(),
    ['dynamodb:DeleteItem', 'dynamodb:GetItem', 'dynamodb:PutItem'],
  );
  const transactionStatements = authStatements
    .filter((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .includes('dynamodb:TransactWriteItems'),
    );
  const invitationTransactionStatements = transactionStatements.filter((statement) =>
    JSON.stringify(statement.Resource).includes(`"${tableId}","Arn"`),
  );
  assert.equal(invitationTransactionStatements.length, 1);
  const invitationTransaction = invitationTransactionStatements[0];
  assert.deepEqual(
    Array.isArray(invitationTransaction.Action)
      ? invitationTransaction.Action
      : [invitationTransaction.Action],
    ['dynamodb:TransactWriteItems'],
  );
  const expectedTransactionResources = [
    tableId,
    tableLogicalId(template, 'UsersTable'),
    tableLogicalId(template, 'PasswordCredentialsTable'),
    tableLogicalId(template, 'SessionsTable'),
  ].map((logicalId) => ({ 'Fn::GetAtt': [logicalId, 'Arn'] }));
  assert.deepEqual(invitationTransaction.Resource, expectedTransactionResources);
  assert.equal(
    JSON.stringify(invitationTransaction).includes('*'),
    false,
    'invitation transaction IAM must not contain wildcard actions or resources',
  );
  assert.deepEqual(template.Outputs.InvitationsTableName.Value, { Ref: tableId });
});

test('invitation validity rejects unsafe deployment values', () => {
  assert.throws(() => invitationInfrastructure(299), /invitationTtlSecs/);
  assert.throws(() => invitationInfrastructure(604_801), /invitationTtlSecs/);
});

test('default invitation validity uses the runtime default without an environment entry', () => {
  const { authFunction } = invitationInfrastructure(undefined);
  assert.equal(
    authFunction.Properties.Environment.Variables.AGENT_AUTH_INVITATION_TTL_SECS,
    undefined,
  );
});
