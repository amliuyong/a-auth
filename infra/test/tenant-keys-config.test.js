const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App, Aspects } = require('aws-cdk-lib');
const { Annotations, Match, Template } = require('aws-cdk-lib/assertions');
const { AwsSolutionsChecks } = require('cdk-nag');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

const TEST_ENV = { account: '123456789012', region: 'us-east-1' };

function createStack(app, env = TEST_ENV) {
  return new AgentAuthStack(app, 'TenantKeysConfigTest', {
    ...(env ? { env } : {}),
    webBaseUrl: 'https://c.auth.example.com',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    tenantKeyProvisionerAssetPath: path.resolve(__dirname),
    tenantKeyReplicaRegions: env ? ['us-west-2'] : [],
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    credentialMigrationAssetPath: path.resolve(__dirname),
    reclaimAssetPath: path.resolve(__dirname),
    recomputeAssetPath: path.resolve(__dirname),
    deployFrontend: false,
    saasZone: 'auth.example.com',
    saasControlHost: 'c.auth.example.com',
    customDomains: [
      'c.auth.example.com',
      't1.auth.example.com',
      't2.auth.example.com',
    ],
    tenantAdminSecretArns: {
      t1: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:legacy/t1-AbCd12',
      t2: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:legacy/t2-EfGh34',
    },
    tenantResidency: tenantResidency(['t1', 't2'], {
      primaryRegion: env?.region,
      replicaRegions: ['us-west-2'],
    }),
  });
}

function synth() {
  const app = new App();
  const stack = createStack(app);
  return Template.fromStack(stack).toJSON();
}

test('c10_13_saas_uses_durable_per_tenant_key_control_plane_without_shared_fallback', () => {
  const template = synth();
  const [tableId, table] = Object.entries(template.Resources).find(
    ([logicalId, resource]) =>
      logicalId.startsWith('TenantKeysTable') &&
      resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.ok(tableId);
  assert.equal(table.DeletionPolicy, 'Retain');
  assert.deepEqual(table.Properties.KeySchema, [
    { AttributeName: 'tenant_id', KeyType: 'HASH' },
  ]);

  const [queueId, queue] = Object.entries(template.Resources).find(
    ([logicalId, resource]) =>
      logicalId.startsWith('TenantKeyOperationsQueue') &&
      !logicalId.startsWith('TenantKeyOperationsQueuePolicy') &&
      resource.Type === 'AWS::SQS::Queue',
  );
  const [dlqId] = Object.entries(template.Resources).find(
    ([logicalId, resource]) =>
      logicalId.startsWith('TenantKeyOperationsDlq') &&
      resource.Type === 'AWS::SQS::Queue',
  );
  assert.ok(queueId);
  assert.ok(dlqId);
  assert.deepEqual(queue.Properties.RedrivePolicy.deadLetterTargetArn, {
    'Fn::GetAtt': [dlqId, 'Arn'],
  });

  const functions = Object.entries(template.Resources).filter(
    ([, resource]) => resource.Type === 'AWS::Lambda::Function',
  );
  const [provisionerId, provisioner] = functions.find(([, resource]) =>
    resource.Properties.Environment?.Variables?.TENANT_KEYS_TABLE &&
    resource.Properties.Environment?.Variables?.SAAS_TENANTS &&
    !resource.Properties.Environment?.Variables?.CODES_TABLE);
  assert.ok(provisionerId);
  assert.equal(provisioner.Properties.Timeout, 300);
  assert.equal(
    provisioner.Properties.Environment.Variables.SAAS_TENANTS,
    JSON.stringify(['t1', 't2']),
  );
  assert.equal(
    provisioner.Properties.Environment.Variables.TENANT_KEY_REPLICA_REGIONS,
    JSON.stringify(['us-west-2']),
  );
  assert.ok(
    provisioner.Properties.Environment.Variables
      .TENANT_KEY_OPERATIONS_QUEUE_URL,
  );
  assert.ok(provisioner.Properties.Environment.Variables.GOVERNANCE_TABLE);
  assert.ok(
    provisioner.Properties.Environment.Variables.GOVERNANCE_SUPPRESSION_TABLE,
  );
  const policies = Object.values(template.Resources)
    .filter((resource) => resource.Type === 'AWS::IAM::Policy')
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement);
  assert.ok(
    policies.some((statement) => {
      const actions = Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action];
      return (
        actions.includes('dynamodb:TransactWriteItems') &&
        JSON.stringify(statement.Resource).includes('GovernanceTable')
      );
    }),
  );
  assert.ok(
    policies.some((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .includes('tag:GetResources')),
  );
  const provisionerRoleId = provisioner.Properties.Role['Fn::GetAtt'][0];
  const provisionerPolicies = Object.values(template.Resources)
    .filter((resource) =>
      resource.Type === 'AWS::IAM::Policy' &&
      resource.Properties.Roles.some?.((role) =>
        role.Ref === provisionerRoleId));
  const provisionerStatements = provisionerPolicies.flatMap((resource) =>
    resource.Properties.PolicyDocument.Statement);
  const replicateKeyPolicies = provisionerPolicies.filter((resource) =>
    resource.Properties.PolicyDocument.Statement.some((statement) =>
        (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
          .includes('kms:ReplicateKey')));
  assert.equal(replicateKeyPolicies.length, 1);
  const replicateKeyStatements =
    replicateKeyPolicies[0].Properties.PolicyDocument.Statement.filter((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .includes('kms:ReplicateKey'));
  assert.deepEqual(replicateKeyStatements, [{
    Action: 'kms:ReplicateKey',
    Condition: {
      StringEquals: {
        'kms:CallerAccount': TEST_ENV.account,
        'kms:ReplicaRegion': ['us-west-2'],
      },
    },
    Effect: 'Allow',
    Resource: {
      'Fn::Join': [
        '',
        [
          'arn:',
          { Ref: 'AWS::Partition' },
          `:kms:${TEST_ENV.region}:${TEST_ENV.account}:key/*`,
        ],
      ],
    },
  }]);
  const replicaProbeStatements = provisionerStatements.filter((statement) => {
      const actions = Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action];
      return actions.includes('kms:GetPublicKey') &&
        actions.includes('kms:Sign') &&
        statement.Resource.some?.((resource) =>
          JSON.stringify(resource).includes('us-west-2'));
    });
  assert.equal(replicaProbeStatements.length, 1);
  const managedKeyStatements = policies.filter((statement) =>
    statement.Condition?.StringEquals?.[
      'aws:ResourceTag/agent-auth-managed'
    ] === 'true');
  assert.ok(managedKeyStatements.length >= 3);
  managedKeyStatements.forEach((statement) =>
    assert.deepEqual(
      statement.Condition.StringEquals[
        'aws:ResourceTag/agent-auth-deployment'
      ],
      { Ref: tableId },
    ));
  const cleanupPolicy = policies.find((statement) => {
    const actions = Array.isArray(statement.Action)
      ? statement.Action
      : [statement.Action];
    return actions.includes('kms:ScheduleKeyDeletion');
  });
  assert.deepEqual(cleanupPolicy.Action.sort(), [
    'kms:DescribeKey',
    'kms:ScheduleKeyDeletion',
  ]);
  assert.match(JSON.stringify(cleanupPolicy.Resource), /:kms:\*:/);
  assert.deepEqual(cleanupPolicy.Condition, {
    StringEquals: {
      'aws:ResourceTag/agent-auth-managed': 'true',
      'aws:ResourceTag/agent-auth-deployment': { Ref: tableId },
    },
  });
  assert.ok(
    policies.every((statement) =>
      !(Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .includes('kms:ListKeys')),
  );
  const createKeyPolicy = policies.find((statement) =>
    (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
      .includes('kms:CreateKey'));
  assert.deepEqual(createKeyPolicy.Condition.StringEquals['aws:RequestedRegion'], [
    'us-east-1',
    'us-west-2',
  ]);
  assert.deepEqual(
    createKeyPolicy.Condition.StringEquals[
      'aws:RequestTag/agent-auth-deployment'
    ],
    { Ref: tableId },
  );
  assert.deepEqual(createKeyPolicy.Condition.Null, {
    'aws:RequestTag/agent-auth-managed': 'false',
    'aws:RequestTag/agent-auth-deployment': 'false',
    'aws:RequestTag/agent-auth-tenant': 'false',
    'aws:RequestTag/agent-auth-operation': 'false',
    'aws:RequestTag/agent-auth-algorithm': 'false',
    'aws:RequestTag/agent-auth-generation': 'false',
  });
  const createServiceLinkedRolePolicy = policies.find((statement) =>
    (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
      .includes('iam:CreateServiceLinkedRole'));
  assert.match(
    JSON.stringify(createServiceLinkedRolePolicy.Resource),
    /aws-service-role\/mrk\.kms\.amazonaws\.com\/AWSServiceRoleForKeyManagementServiceMultiRegionKeys/,
  );
  assert.deepEqual(createServiceLinkedRolePolicy.Condition, {
    StringEquals: {
      'iam:AWSServiceName': 'mrk.kms.amazonaws.com',
    },
  });

  const auth = functions.find(([, resource]) =>
    resource.Properties.Environment?.Variables?.CODES_TABLE)[1];
  assert.ok(auth.Properties.Environment.Variables.TENANT_KEYS_TABLE);
  assert.ok(auth.Properties.Environment.Variables.TENANT_KEY_OPERATIONS_QUEUE_URL);
  assert.equal(auth.Properties.Environment.Variables.SIGNING_KEY_ID, undefined);
  assert.equal(auth.Properties.Environment.Variables.RSA_SIGNING_KEY_ID, undefined);

  const ssf = functions.find(([, resource]) =>
    resource.Properties.Environment?.Variables?.SSF_STREAM_FAILURE_BUCKET)[1];
  assert.ok(ssf.Properties.Environment.Variables.TENANT_KEYS_TABLE);
  assert.equal(ssf.Properties.Environment.Variables.SIGNING_KEY_ID, undefined);

  const reclaim = functions.find(([, resource]) =>
    resource.Properties.Environment?.Variables?.RECLAIM_IDLE_DAYS)[1];
  assert.ok(reclaim.Properties.Environment.Variables.TENANT_KEYS_TABLE);
  assert.ok(
    reclaim.Properties.Environment.Variables.TENANT_KEY_OPERATIONS_QUEUE_URL,
  );

  const recompute = functions.find(([, resource]) =>
    resource.Properties.Environment?.Variables?.AGENT_AUTH_RECOMPUTE_TENANTS)[1];
  assert.ok(recompute.Properties.Environment.Variables.TENANT_KEYS_TABLE);
  assert.ok(
    recompute.Properties.Environment.Variables.TENANT_KEY_OPERATIONS_QUEUE_URL,
  );

  const eventSource = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::Lambda::EventSourceMapping' &&
      resource.Properties.FunctionName?.Ref === provisionerId);
  assert.deepEqual(eventSource.Properties.FunctionResponseTypes, [
    'ReportBatchItemFailures',
  ]);

  const schedule = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::Events::Rule' &&
      resource.Properties.Description?.includes('tenant key sets'));
  assert.equal(schedule.Properties.ScheduleExpression, 'rate(1 minute)');

  const alarmNames = Object.values(template.Resources)
    .filter((resource) => resource.Type === 'AWS::CloudWatch::Alarm')
    .map((resource) => JSON.stringify(resource.Properties.AlarmName));
  assert.ok(alarmNames.some((name) => name.includes('TenantKeyOperationsBacklog')));
  assert.ok(alarmNames.some((name) => name.includes('TenantKeyOperationsDeadLetters')));
  assert.ok(template.Outputs.TenantKeysTableName);
  assert.ok(template.Outputs.TenantKeyProvisionerFnName);
});

test('SaaS tenant signing runtime policy passes the cdk-nag IAM wildcard gate', () => {
  const app = new App();
  const stack = createStack(app, TEST_ENV);
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  const signingKeyRuntimePolicy = stack.node.tryFindChild(
    'SigningKeyRuntimePolicy',
  );
  assert.ok(signingKeyRuntimePolicy);
  const signingKeyRuntimePolicyResource =
    signingKeyRuntimePolicy.node.defaultChild;
  assert.ok(signingKeyRuntimePolicyResource);

  Annotations.fromStack(stack).hasNoError(
    `/${signingKeyRuntimePolicyResource.node.path}`,
    Match.stringLikeRegexp('AwsSolutions-IAM5'),
  );
});
