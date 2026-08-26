const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

function policyStatementsForFunction(template, fn) {
  const roleId = fn.Properties.Role['Fn::GetAtt'][0];
  return Object.values(template.Resources)
    .filter(
      (resource) =>
        resource.Type === 'AWS::IAM::Policy' &&
        resource.Properties.Roles.some((role) => role.Ref === roleId),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement);
}

function ssfInfrastructure() {
  const app = new App();
  const assetPath = path.resolve(__dirname);
  const stack = new AgentAuthStack(app, 'SsfConfigTest', {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: assetPath,
    securityEventArchiveAssetPath: assetPath,
    ssfDeliveryAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    deployFrontend: false,
    tenantResidency: tenantResidency(),
  });
  const template = Template.fromStack(stack).toJSON();
  const [tableEntry] = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SsfDeliveriesTable') &&
      resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.ok(tableEntry, 'expected SSF table');
  const [tableId, table] = tableEntry;
  const [workerEntry] = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SsfDeliveryFn') &&
      resource.Type === 'AWS::Lambda::Function',
  );
  assert.ok(workerEntry, 'expected SSF delivery worker');
  return {
    template,
    tableId,
    table,
    workerId: workerEntry[0],
    worker: workerEntry[1],
  };
}

test('c12_6_ssf_table_is_tenant_partitioned_retained_and_due_indexed', () => {
  const { template, tableId, table } = ssfInfrastructure();
  assert.deepEqual(table.Properties.KeySchema, [
    { AttributeName: 'tenant_id', KeyType: 'HASH' },
    { AttributeName: 'record_key', KeyType: 'RANGE' },
  ]);
  assert.equal(table.Properties.BillingMode, 'PAY_PER_REQUEST');
  assert.equal(table.Properties.TimeToLiveSpecification.AttributeName, 'expires_at');
  assert.equal(
    table.Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled,
    true,
  );
  assert.equal(table.DeletionPolicy, 'Retain');
  assert.equal(table.UpdateReplacePolicy, 'Retain');
  const dueIndex = table.Properties.GlobalSecondaryIndexes.find(
    (index) => index.IndexName === 'due-index',
  );
  assert.deepEqual(dueIndex.KeySchema, [
    { AttributeName: 'due_partition', KeyType: 'HASH' },
    { AttributeName: 'due_at', KeyType: 'RANGE' },
  ]);
  assert.equal(dueIndex.Projection.ProjectionType, 'ALL');
  const historyIndex = table.Properties.GlobalSecondaryIndexes.find(
    (index) => index.IndexName === 'stream-created-at-index',
  );
  assert.deepEqual(historyIndex.KeySchema, [
    { AttributeName: 'stream_partition', KeyType: 'HASH' },
    { AttributeName: 'stream_created_at', KeyType: 'RANGE' },
  ]);
  assert.equal(historyIndex.Projection.ProjectionType, 'ALL');

  const auth = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.DOMAIN_MAP_TABLE,
  );
  assert.deepEqual(
    auth.Properties.Environment.Variables.SSF_DELIVERIES_TABLE,
    { Ref: tableId },
  );
  assert.deepEqual(template.Outputs.SsfDeliveriesTableName.Value, { Ref: tableId });
});

test('c12_6_ssf_worker_consumes_retries_replays_and_is_alarmed', () => {
  const { template, tableId, workerId, worker } = ssfInfrastructure();
  assert.deepEqual(worker.Properties.Architectures, ['arm64']);
  assert.equal(worker.Properties.Timeout, 300);
  assert.deepEqual(
    worker.Properties.Environment.Variables.SSF_DELIVERIES_TABLE,
    { Ref: tableId },
  );
  assert.ok(worker.Properties.Environment.Variables.SIGNING_KEY_ID);
  assert.deepEqual(
    worker.Properties.Environment.Variables.SIGNING_KEY_IDS_PUBLISHED,
    worker.Properties.Environment.Variables.SIGNING_KEY_ID,
  );
  const [failureBucketEntry] = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SsfStreamFailureBucket') &&
      resource.Type === 'AWS::S3::Bucket',
  );
  const [replayQueueEntry] = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SsfStreamFailureReplayQueue') &&
      resource.Type === 'AWS::SQS::Queue',
  );
  const [replayDlqEntry] = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SsfStreamFailureReplayDlq') &&
      resource.Type === 'AWS::SQS::Queue',
  );
  assert.ok(failureBucketEntry);
  assert.ok(replayQueueEntry);
  assert.ok(replayDlqEntry);
  assert.deepEqual(
    worker.Properties.Environment.Variables.SSF_STREAM_FAILURE_BUCKET,
    { Ref: failureBucketEntry[0] },
  );
  assert.deepEqual(replayQueueEntry[1].Properties.RedrivePolicy.deadLetterTargetArn, {
    'Fn::GetAtt': [replayDlqEntry[0], 'Arn'],
  });

  const mappings = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::Lambda::EventSourceMapping' &&
      resource.Properties.FunctionName.Ref === workerId,
  );
  assert.equal(mappings.length, 2);
  const mapping = mappings.find((candidate) => candidate.Properties.StartingPosition);
  const replayMapping = mappings.find(
    (candidate) => !candidate.Properties.StartingPosition,
  );
  assert.ok(mapping);
  assert.ok(replayMapping);
  assert.equal(mapping.Properties.StartingPosition, 'LATEST');
  assert.equal(mapping.Properties.BisectBatchOnFunctionError, true);
  assert.equal(mapping.Properties.MaximumRetryAttempts, 3);
  assert.equal(mapping.Properties.MaximumRecordAgeInSeconds, 86400);
  assert.deepEqual(mapping.Properties.FilterCriteria.Filters, [
    { Pattern: '{"eventName":["INSERT"]}' },
  ]);
  assert.ok(mapping.Properties.DestinationConfig.OnFailure.Destination['Fn::GetAtt']);
  assert.deepEqual(replayMapping.Properties.EventSourceArn, {
    'Fn::GetAtt': [replayQueueEntry[0], 'Arn'],
  });
  assert.equal(replayMapping.Properties.BatchSize, 1);

  const schedule = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::Events::Rule' &&
      resource.Properties.Description === 'Deliver due Shared Signals SET outbox rows',
  );
  assert.equal(schedule.Properties.ScheduleExpression, 'rate(1 minute)');

  const statements = policyStatementsForFunction(template, worker);
  const tableStatements = statements.filter((statement) =>
    JSON.stringify(statement.Resource).includes(tableId),
  );
  for (const action of [
    'dynamodb:ConditionCheckItem',
    'dynamodb:GetItem',
    'dynamodb:PutItem',
    'dynamodb:UpdateItem',
    'dynamodb:Query',
    'dynamodb:TransactWriteItems',
  ]) {
    assert.ok(
      tableStatements.some((statement) =>
        (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
          .includes(action),
      ),
      `SSF worker requires ${action}`,
    );
  }
  for (const action of [
    'dynamodb:DeleteItem',
    'dynamodb:Scan',
    'dynamodb:BatchWriteItem',
  ]) {
    assert.ok(
      tableStatements.every((statement) =>
        !(Array.isArray(statement.Action) ? statement.Action : [statement.Action])
          .includes(action),
      ),
      `SSF worker must not receive ${action}`,
    );
  }
  assert.ok(
    statements.some((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .includes('kms:Sign'),
    ),
    'SSF worker must sign SETs with the scoped EC key',
  );
  assert.ok(
    statements.some((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .some((action) => action.startsWith('s3:GetObject')) &&
      JSON.stringify(statement.Resource).includes(failureBucketEntry[0]),
    ),
    'SSF worker must read retained source-failure objects for replay',
  );

  const alarms = Object.values(template.Resources)
    .filter((resource) => resource.Type === 'AWS::CloudWatch::Alarm');
  const alarmNames = alarms.map(
    (resource) => JSON.stringify(resource.Properties.AlarmName),
  );
  assert.ok(alarmNames.some((name) => name.includes('SsfDeliveryFailures')));
  assert.ok(alarmNames.some((name) => name.includes('SsfDeliveryBacklog')));
  const failureAlarm = alarms.find((resource) =>
    JSON.stringify(resource.Properties.AlarmName).includes('SsfDeliveryFailures'));
  const backlogAlarm = alarms.find((resource) =>
    JSON.stringify(resource.Properties.AlarmName).includes('SsfDeliveryBacklog'));
  assert.ok(JSON.stringify(failureAlarm).includes(replayDlqEntry[0]));
  assert.ok(JSON.stringify(backlogAlarm).includes(replayQueueEntry[0]));
  const metricFilters = Object.values(template.Resources)
    .filter((resource) => resource.Type === 'AWS::Logs::MetricFilter')
    .map((resource) => resource.Properties);
  assert.ok(
    metricFilters.some(
      (filter) =>
        filter.FilterPattern.includes('ssf_delivery_backlog_age_seconds') &&
        filter.MetricTransformations.some(
          (transformation) =>
            transformation.MetricName === 'SsfDeliveryBacklogAgeSeconds' &&
            transformation.MetricValue === '$.ssf_delivery_backlog_age_seconds',
        ),
    ),
  );
  assert.ok(
    metricFilters.some(
      (filter) =>
        filter.FilterPattern.includes('SSF_DELIVERY_FAILURE') &&
        filter.FilterPattern.includes('result=terminal') &&
        filter.MetricTransformations.some(
          (transformation) =>
            transformation.MetricName === 'SsfDeliveryFailures',
        ),
    ),
    'terminal receiver failures must increment the SSF failure alarm metric',
  );
  assert.ok(template.Outputs.SsfDeliveryFnName);
  assert.ok(template.Outputs.SsfDeliveryScheduleName);
  assert.ok(template.Outputs.SsfStreamFailureBucketName);
  assert.ok(template.Outputs.SsfStreamFailureReplayQueueUrl);
  assert.ok(template.Outputs.SsfStreamFailureReplayDlqUrl);
});

test('Auth and SSF deploy the same explicit EC rotation phase with least-privilege IAM', () => {
  const app = new App();
  const assetPath = path.resolve(__dirname);
  const oldKey = 'arn:aws:kms:us-east-1:111122223333:key/11111111-1111-1111-1111-111111111111';
  const newKey = 'arn:aws:kms:us-east-1:111122223333:key/22222222-2222-2222-2222-222222222222';
  const stack = new AgentAuthStack(app, 'SsfRotationConfigTest', {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: assetPath,
    securityEventArchiveAssetPath: assetPath,
    ssfDeliveryAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    deployFrontend: false,
    tenantResidency: tenantResidency(),
    activeEcSigningKeyArn: newKey,
    publishedEcSigningKeyArns: [oldKey, newKey],
  });
  const template = Template.fromStack(stack).toJSON();
  const functions = Object.values(template.Resources).filter(
    (resource) => resource.Type === 'AWS::Lambda::Function',
  );
  const auth = functions.find(
    (resource) => resource.Properties?.Environment?.Variables?.DOMAIN_MAP_TABLE,
  );
  const worker = functions.find(
    (resource) => resource.Properties?.Environment?.Variables?.SSF_DELIVERIES_TABLE &&
      !resource.Properties?.Environment?.Variables?.DOMAIN_MAP_TABLE,
  );
  for (const runtime of [auth, worker]) {
    assert.equal(runtime.Properties.Environment.Variables.SIGNING_KEY_ID, newKey);
    assert.equal(
      runtime.Properties.Environment.Variables.SIGNING_KEY_IDS_PUBLISHED,
      `${oldKey},${newKey}`,
    );
    const statements = policyStatementsForFunction(template, runtime);
    const sign = statements.find((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .includes('kms:Sign'),
    );
    const getPublicKey = statements.find((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .includes('kms:GetPublicKey') &&
      JSON.stringify(statement.Resource).includes(oldKey),
    );
    assert.ok(
      (Array.isArray(sign.Resource) ? sign.Resource : [sign.Resource]).includes(newKey),
    );
    assert.ok(!JSON.stringify(sign.Resource).includes(oldKey));
    assert.ok(JSON.stringify(getPublicKey.Resource).includes(newKey));
  }
  assert.equal(template.Outputs.SigningKeyId.Value, newKey);
  assert.ok(template.Outputs.ManagedSigningKeyId);
});

test('EC rotation phase rejects incomplete, malformed, or inactive published sets', () => {
  const assetPath = path.resolve(__dirname);
  const props = {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: assetPath,
    securityEventArchiveAssetPath: assetPath,
    ssfDeliveryAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    deployFrontend: false,
    tenantResidency: tenantResidency(),
  };
  const active = 'arn:aws:kms:us-east-1:111122223333:key/22222222-2222-2222-2222-222222222222';
  assert.throws(
    () => new AgentAuthStack(new App(), 'MissingPublished', {
      ...props,
      activeEcSigningKeyArn: active,
    }),
    /必须同时设置/,
  );
  assert.throws(
    () => new AgentAuthStack(new App(), 'InactivePublished', {
      ...props,
      activeEcSigningKeyArn: active,
      publishedEcSigningKeyArns: [
        'arn:aws:kms:us-east-1:111122223333:key/11111111-1111-1111-1111-111111111111',
      ],
    }),
    /active 必须属于 published/,
  );
});
