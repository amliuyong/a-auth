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
        (
          resource.Type === 'AWS::IAM::Policy' ||
          resource.Type === 'AWS::IAM::ManagedPolicy'
        ) &&
        resource.Properties.Roles.some((role) => role.Ref === roleId),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement);
}

function securityEventInfrastructure() {
  const app = new App();
  const assetPath = path.resolve(__dirname);
  const stack = new AgentAuthStack(app, 'SecurityEventsConfigTest', {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: assetPath,
    securityEventArchiveAssetPath: assetPath,
    ssfDeliveryAssetPath: assetPath,
    reclaimAssetPath: assetPath,
    recomputeAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    deployFrontend: false,
    tenantResidency: tenantResidency(),
  });
  const template = Template.fromStack(stack).toJSON();
  const tableEntries = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SecurityEventsTable') &&
      resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.equal(tableEntries.length, 1, 'expected one security events table');
  const [tableId, table] = tableEntries[0];
  const archiveFunctions = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SecurityEventArchiveFn') &&
      resource.Type === 'AWS::Lambda::Function',
  );
  assert.equal(archiveFunctions.length, 1, 'expected one security event archive worker');
  const [archiveFunctionId, archiveFunction] = archiveFunctions[0];
  const authFunctions = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.SCOPE === 'non_token' &&
      resource.Properties?.Environment?.Variables?.DOMAIN_MAP_TABLE,
  );
  assert.equal(authFunctions.length, 1, 'expected exactly one main Auth Lambda');
  const stateFunctions = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.ADMIN_AUTH_TABLE,
  );
  assert.equal(
    stateFunctions.length,
    5,
    'expected Auth, Token, Governance, Reclaim, and Recompute Lambdas',
  );
  assert.deepEqual(
    stateFunctions
      .map(([, resource]) => resource.Properties.Environment.Variables.SCOPE)
      .filter(Boolean)
      .sort(),
    ['non_token', 'token'],
  );
  return {
    template,
    tableId,
    table,
    archiveFunctionId,
    archiveFunction,
    authFunctionId: authFunctions[0][0],
    authFunction: authFunctions[0][1],
    stateFunctions,
  };
}

test('c12_6_security_events_have_durable_hot_storage_and_tenant_time_export_index', () => {
  const {
    template,
    tableId,
    table,
    authFunction,
    stateFunctions,
  } = securityEventInfrastructure();
  assert.deepEqual(table.Properties.KeySchema, [
    { AttributeName: 'event_id', KeyType: 'HASH' },
  ]);
  assert.equal(table.Properties.BillingMode, 'PAY_PER_REQUEST');
  assert.equal(table.Properties.StreamSpecification.StreamViewType, 'NEW_IMAGE');
  assert.equal(table.Properties.TimeToLiveSpecification.AttributeName, 'expires_at');
  assert.equal(table.Properties.TimeToLiveSpecification.Enabled, true);
  assert.equal(
    table.Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled,
    true,
  );
  const index = table.Properties.GlobalSecondaryIndexes.find(
    (candidate) => candidate.IndexName === 'tenant_occurred_at-index',
  );
  assert.deepEqual(index.KeySchema, [
    { AttributeName: 'tenant_id', KeyType: 'HASH' },
    { AttributeName: 'occurred_at', KeyType: 'RANGE' },
  ]);
  const deliveryIndex = table.Properties.GlobalSecondaryIndexes.find(
    (candidate) => candidate.IndexName === 'delivery_status-index',
  );
  assert.deepEqual(deliveryIndex.KeySchema, [
    { AttributeName: 'delivery_status', KeyType: 'HASH' },
    { AttributeName: 'last_delivery_at', KeyType: 'RANGE' },
  ]);
  assert.deepEqual(
    authFunction.Properties.Environment.Variables.SECURITY_EVENTS_TABLE,
    { Ref: tableId },
  );
  assert.ok(
    authFunction.Properties.Environment.Variables.SECURITY_EVENT_INGRESS_QUEUE_URL,
    'Auth Lambda must have a durable fallback queue',
  );
  for (const [stateFunctionId, stateFunction] of stateFunctions) {
    assert.deepEqual(
      stateFunction.Properties.Environment.Variables.SECURITY_EVENTS_TABLE,
      { Ref: tableId },
      'every AppState runtime must receive the security-events table',
    );
    assert.ok(
      stateFunction.Properties.Environment.Variables.SSF_DELIVERIES_TABLE,
      'every AppState runtime must receive the durable SSF store',
    );
    assert.ok(
      stateFunction.Properties.Environment.Variables.SECURITY_EVENT_INGRESS_QUEUE_URL,
      'every AppState runtime must receive the security-event fallback queue',
    );
    const statements = policyStatementsForFunction(template, stateFunction);
    const eventTableStatements = statements.filter((statement) =>
      JSON.stringify(statement.Resource).includes(tableId),
    );
    for (const action of [
      'dynamodb:GetItem',
      'dynamodb:PutItem',
      'dynamodb:UpdateItem',
    ]) {
      assert.ok(
        eventTableStatements.some((statement) =>
          (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
            .includes(action),
        ),
        `${stateFunctionId} needs ${action} for durable security-event delivery`,
      );
    }
    assert.ok(
      statements.some(
        (statement) =>
          JSON.stringify(statement.Resource).includes('SecurityEventIngressQueue') &&
          (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
            .includes('sqs:SendMessage'),
      ),
      `${stateFunctionId} needs SQS fallback delivery`,
    );
  }
  assert.match(
    JSON.stringify(template.Resources),
    new RegExp(`"Fn::GetAtt":\\["${tableId}","Arn"\\]`),
    'Auth Lambda policy must reference the security events table ARN',
  );
  const tablePolicyStatements = policyStatementsForFunction(template, authFunction)
    .filter((statement) => JSON.stringify(statement.Resource).includes(tableId));
  for (const action of [
    'dynamodb:GetItem',
    'dynamodb:PutItem',
    'dynamodb:UpdateItem',
  ]) {
    assert.ok(
      tablePolicyStatements.some((statement) =>
        (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
          .includes(action),
      ),
      `Auth Lambda must have ${action} for idempotent security-event reconciliation`,
    );
  }
  assert.ok(
    tablePolicyStatements.some((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .includes('dynamodb:Query'),
    ),
    'Auth Lambda must be able to query the tenant/time index',
  );
  const destructiveActions = new Set([
    'dynamodb:BatchWriteItem',
    'dynamodb:DeleteItem',
  ]);
  assert.ok(
    tablePolicyStatements.every((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .every((action) => !destructiveActions.has(action)),
    ),
    'Auth Lambda must not be able to delete immutable security-event rows',
  );
  assert.deepEqual(template.Outputs.SecurityEventsTableName.Value, { Ref: tableId });
});

test('c12_6_archive_worker_is_retryable_idempotent_dead_lettered_and_retained', () => {
  const {
    template,
    tableId,
    archiveFunctionId,
    archiveFunction,
  } = securityEventInfrastructure();
  assert.deepEqual(archiveFunction.Properties.Architectures, ['arm64']);
  assert.deepEqual(
    archiveFunction.Properties.Environment.Variables.SECURITY_EVENTS_TABLE,
    { Ref: tableId },
  );
  assert.ok(archiveFunction.Properties.Environment.Variables.SECURITY_EVENT_ARCHIVE_BUCKET);
  assert.equal(
    archiveFunction.Properties.Environment.Variables.SECURITY_EVENT_INGRESS_QUEUE_URL,
    undefined,
    'the worker must retry the source message instead of self-requeueing',
  );
  assert.ok(archiveFunction.Properties.Environment.Variables.SECURITY_EVENT_INGRESS_DLQ_URL);
  assert.ok(
    archiveFunction.Properties.Environment.Variables
      .SECURITY_EVENT_INGRESS_FAILURE_BUCKET,
  );

  const mappings = Object.values(template.Resources).filter(
    (resource) => resource.Type === 'AWS::Lambda::EventSourceMapping',
  );
  const streamMapping = mappings.find(
    (mapping) =>
      mapping.Properties.FunctionName.Ref === archiveFunctionId &&
      mapping.Properties.StartingPosition,
  );
  assert.equal(streamMapping.Properties.BisectBatchOnFunctionError, true);
  assert.equal(streamMapping.Properties.StartingPosition, 'TRIM_HORIZON');
  assert.equal(streamMapping.Properties.MaximumRetryAttempts, 3);
  assert.equal(streamMapping.Properties.MaximumRecordAgeInSeconds, 86400);
  assert.deepEqual(streamMapping.Properties.FilterCriteria.Filters, [
    { Pattern: '{"eventName":["INSERT"]}' },
  ]);
  const failureDestination =
    streamMapping.Properties.DestinationConfig.OnFailure.Destination['Fn::GetAtt'][0];
  assert.ok(
    failureDestination.startsWith('SecurityEventStreamFailureBucket'),
    'discarded stream invocations must retain the full payload in S3',
  );
});

test('archive buckets and queues retain failures for durable recovery', () => {
  const {
    template,
    archiveFunctionId,
  } = securityEventInfrastructure();
  const mappings = Object.values(template.Resources).filter(
    (resource) => resource.Type === 'AWS::Lambda::EventSourceMapping',
  );
  const buckets = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SecurityEventArchiveBucket') &&
      resource.Type === 'AWS::S3::Bucket',
  );
  assert.equal(buckets.length, 1);
  const [, bucket] = buckets[0];
  assert.equal(bucket.DeletionPolicy, 'Retain');
  assert.equal(bucket.UpdateReplacePolicy, 'Retain');
  assert.equal(bucket.Properties.BucketEncryption.ServerSideEncryptionConfiguration.length, 1);
  assert.ok(bucket.Properties.PublicAccessBlockConfiguration.BlockPublicAcls);
  assert.equal(bucket.Properties.LifecycleConfiguration.Rules[0].ExpirationInDays, 2555);
  assert.equal(
    bucket.Properties.LifecycleConfiguration.Rules[0].NoncurrentVersionExpiration
      .NoncurrentDays,
    2555,
  );
  const failureBuckets = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SecurityEventStreamFailureBucket') &&
      resource.Type === 'AWS::S3::Bucket',
  );
  assert.equal(failureBuckets.length, 1);
  const [, failureBucket] = failureBuckets[0];
  assert.equal(failureBucket.DeletionPolicy, 'Retain');
  assert.equal(failureBucket.Properties.LifecycleConfiguration.Rules[0].ExpirationInDays, 2555);
  const ingressFailureBuckets = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SecurityEventIngressFailureBucket') &&
      resource.Type === 'AWS::S3::Bucket',
  );
  assert.equal(ingressFailureBuckets.length, 1);
  const [, ingressFailureBucket] = ingressFailureBuckets[0];
  assert.equal(ingressFailureBucket.DeletionPolicy, 'Retain');
  assert.equal(
    ingressFailureBucket.Properties.LifecycleConfiguration.Rules[0].ExpirationInDays,
    2555,
  );
  const failureNotification = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'Custom::S3BucketNotifications' &&
      resource.Properties.BucketName?.Ref === failureBuckets[0][0],
  );
  assert.ok(
    failureNotification?.Properties.NotificationConfiguration.QueueConfigurations.some(
      (notification) => notification.Events.includes('s3:ObjectCreated:*'),
    ),
    'new failed invocation objects must enter the durable reconciliation queue',
  );
  const redriveRule = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::Events::Rule' &&
      resource.Properties.Description?.includes('dead letters'),
  );
  assert.deepEqual(redriveRule.Properties.ScheduleExpression, 'rate(5 minutes)');
  assert.equal(
    redriveRule.Properties.Description,
    'Resume security-event pending outboxes, redrive dead letters, and refresh S3 archives',
  );

  const queues = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SecurityEvent') &&
      resource.Type === 'AWS::SQS::Queue',
  );
  assert.equal(
    queues.length,
    5,
    'expected ingress, stream-failure notification, and three terminal DLQ queues',
  );
  const [archiveDlqId, archiveDlq] = queues.find(([logicalId]) =>
    logicalId.startsWith('SecurityEventArchiveDlq'),
  );
  const [ingressDlqId, ingressDlq] = queues.find(([logicalId]) =>
    logicalId.startsWith('SecurityEventIngressDlq'),
  );
  const [ingressQueueId, ingressQueue] = queues.find(([logicalId]) =>
    logicalId.startsWith('SecurityEventIngressQueue'),
  );
  const [failureNotificationDlqId, failureNotificationDlq] = queues.find(([logicalId]) =>
    logicalId.startsWith('SecurityEventStreamFailureNotificationDlq'),
  );
  const [failureNotificationQueueId, failureNotificationQueue] = queues.find(
    ([logicalId]) =>
      logicalId.startsWith('SecurityEventStreamFailureNotificationQueue'),
  );
  assert.equal(archiveDlq.Properties.MessageRetentionPeriod, 1209600);
  assert.equal(archiveDlq.Properties.FifoQueue, true);
  assert.equal(ingressDlq.Properties.MessageRetentionPeriod, 1209600);
  assert.equal(ingressDlq.Properties.FifoQueue, true);
  assert.equal(ingressQueue.Properties.MessageRetentionPeriod, 1209600);
  assert.equal(failureNotificationDlq.Properties.MessageRetentionPeriod, 1209600);
  assert.equal(failureNotificationQueue.Properties.MessageRetentionPeriod, 1209600);
  assert.deepEqual(failureNotificationQueue.Properties.RedrivePolicy, {
    deadLetterTargetArn: { 'Fn::GetAtt': [failureNotificationDlqId, 'Arn'] },
    maxReceiveCount: 4,
  });
  const tlsDeniedQueueIds = new Set(
    Object.values(template.Resources)
      .filter((resource) => resource.Type === 'AWS::SQS::QueuePolicy')
      .flatMap((resource) => resource.Properties.PolicyDocument.Statement)
      .filter(
        (statement) =>
          statement.Effect === 'Deny' &&
          statement.Condition?.Bool?.['aws:SecureTransport'] === 'false',
      )
      .map((statement) => statement.Resource?.['Fn::GetAtt']?.[0])
      .filter((logicalId) => logicalId?.startsWith('SecurityEvent')),
  );
  assert.deepEqual(
    [...tlsDeniedQueueIds].sort(),
    [
      archiveDlqId,
      failureNotificationDlqId,
      failureNotificationQueueId,
      ingressDlqId,
      ingressQueueId,
    ].sort(),
    'all security-event queues must reject non-TLS requests',
  );
  assert.equal(
    ingressQueue.Properties.RedrivePolicy,
    undefined,
    'the worker must quarantine terminal ingress before acknowledging the source',
  );
  const ingressMapping = mappings.find(
    (mapping) =>
      mapping.Properties.FunctionName.Ref === archiveFunctionId &&
      mapping.Properties.EventSourceArn?.['Fn::GetAtt']?.[0] === ingressQueueId,
  );
  assert.equal(ingressMapping.Properties.BatchSize, 1);
  const failureNotificationMapping = mappings.find(
    (mapping) =>
      mapping.Properties.FunctionName.Ref === archiveFunctionId &&
      mapping.Properties.EventSourceArn?.['Fn::GetAtt']?.[0] ===
        failureNotificationQueueId,
  );
  assert.equal(failureNotificationMapping.Properties.BatchSize, 1);
  assert.ok(
    !mappings.some(
      (mapping) =>
        [archiveDlqId, failureNotificationDlqId].includes(
          mapping.Properties.EventSourceArn?.['Fn::GetAtt']?.[0],
        ),
    ),
    'terminal security-event DLQs must not be auto-consumed',
  );
});

test('archive catalog keeps projected tenant partitions and IAM compatibility', () => {
  const { template } = securityEventInfrastructure();
  const glueTableEntries = Object.entries(template.Resources).filter(
    ([, resource]) => resource.Type === 'AWS::Glue::Table',
  );
  assert.equal(glueTableEntries.length, 1, 'expected one Athena external table');
  const [glueTableId, glueTable] = glueTableEntries[0];
  assert.equal(glueTable.Properties.TableInput.Parameters['projection.enabled'], 'true');
  assert.ok(
    glueTable.Properties.TableInput.StorageDescriptor.Columns.some(
      (column) =>
        column.Name === 'delivery' &&
        column.Type.includes('history:array<struct<status:string,occurred_at:bigint>>'),
    ),
    'the seven-year Athena record must include delivery history',
  );
  assert.equal(
    glueTable.Properties.TableInput.Parameters['projection.tenant_id.type'],
    'injected',
  );
  assert.equal(glueTable.DeletionPolicy, 'Retain');
  assert.equal(glueTable.UpdateReplacePolicy, 'Retain');
  const glueDatabaseEntries = Object.entries(template.Resources).filter(
    ([, resource]) => resource.Type === 'AWS::Glue::Database',
  );
  assert.equal(glueDatabaseEntries.length, 1, 'expected one retained Glue database');
  const [glueDatabaseId, glueDatabase] = glueDatabaseEntries[0];
  assert.equal(glueDatabase.DeletionPolicy, 'Retain');
  assert.equal(glueDatabase.UpdateReplacePolicy, 'Retain');

  const catalogPermissions = Object.values(template.Resources).filter(
    (resource) => resource.Type === 'AWS::LakeFormation::PrincipalPermissions',
  );
  assert.equal(
    catalogPermissions.length,
    2,
    'Athena catalog must remain queryable when account-level Lake Formation defaults are empty',
  );
  assert.ok(
    catalogPermissions.every(
      (permission) =>
        permission.Properties.Principal.DataLakePrincipalIdentifier ===
          'IAM_ALLOWED_PRINCIPALS' &&
        permission.Properties.PermissionsWithGrantOption.length === 0,
    ),
    'catalog compatibility access must remain IAM-gated and non-delegable',
  );
  assert.ok(
    catalogPermissions.every(
      (permission) =>
        permission.DeletionPolicy === 'Retain' &&
        permission.UpdateReplacePolicy === 'Retain',
    ),
    'query permissions must remain with the retained catalog',
  );
  const databasePermission = catalogPermissions.find(
    (permission) => permission.Properties.Resource.Database,
  );
  assert.deepEqual(databasePermission.Properties.Permissions, ['ALL']);
  assert.deepEqual(databasePermission.Properties.Resource.Database, {
    CatalogId: { Ref: 'AWS::AccountId' },
    Name: { Ref: glueDatabaseId },
  });
  assert.ok(databasePermission.DependsOn.includes(glueDatabaseId));

  const tablePermission = catalogPermissions.find(
    (permission) => permission.Properties.Resource.Table,
  );
  assert.deepEqual(tablePermission.Properties.Permissions, ['ALL']);
  assert.deepEqual(tablePermission.Properties.Resource.Table, {
    CatalogId: { Ref: 'AWS::AccountId' },
    DatabaseName: { Ref: glueDatabaseId },
    Name: 'security_events',
  });
  assert.ok(tablePermission.DependsOn.includes(glueTableId));
});

test('c12_6_archive_iam_retained_logs_metrics_alarms_and_outputs_stay_complete', () => {
  const {
    template,
    tableId,
    archiveFunction,
  } = securityEventInfrastructure();
  const alarmNames = Object.values(template.Resources)
    .filter((resource) => resource.Type === 'AWS::CloudWatch::Alarm')
    .map((resource) => resource.Properties.AlarmName);
  for (const suffix of [
    'AuthenticationFailures',
    'InfrastructureErrors',
    'CrossTenantDenials',
    'ArchiveBacklog',
    'ArchiveDeadLetters',
  ]) {
    assert.ok(
      alarmNames.some((name) => name['Fn::Join'] || String(name).endsWith(suffix)),
      `missing ${suffix} alarm`,
    );
  }
  const infrastructureAlarm = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::CloudWatch::Alarm' &&
      JSON.stringify(resource.Properties.AlarmName).includes('InfrastructureErrors'),
  );
  assert.ok(infrastructureAlarm, 'expected InfrastructureErrors alarm');
  assert.equal(
    infrastructureAlarm.Properties.Metrics.filter(
      (metric) =>
        metric.MetricStat?.Metric?.Namespace === 'AWS/Lambda' &&
        metric.MetricStat?.Metric?.MetricName === 'Errors',
    ).length,
    7,
    'InfrastructureErrors must include Auth, Token, Governance, Archive, SSF, Reclaim, and Recompute errors',
  );
  const metricFilters = Object.values(template.Resources)
    .filter((resource) => resource.Type === 'AWS::Logs::MetricFilter')
    .map((resource) => JSON.stringify(resource.Properties));
  const securityMetricFilters = Object.values(template.Resources)
    .filter(
      (resource) =>
        resource.Type === 'AWS::Logs::MetricFilter' &&
        resource.Properties.MetricTransformations[0].MetricNamespace ===
          'AgentAuth/Security/SecurityEventsConfigTest',
    );
  assert.ok(securityMetricFilters.length > 0);
  assert.ok(
    securityMetricFilters.every(
      (resource) =>
        resource.Properties.MetricTransformations[0].Dimensions === undefined,
    ),
    'stack-scoped custom metrics must not use invalid literal dimensions',
  );
  const retainedRuntimeLogs = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::Logs::LogGroup' &&
      resource.Properties.RetentionInDays === 2557 &&
      resource.DeletionPolicy === 'Retain',
  );
  assert.equal(
    retainedRuntimeLogs.length,
    7,
    'Auth, Token, Governance, archive, SSF, Reclaim, and Recompute logs must remain queryable for seven years',
  );
  assert.ok(
    metricFilters.some(
      (filter) =>
        filter.includes('result=dead_letter_pending') &&
        filter.includes('ArchiveDeadLetters'),
    ),
    'dead-letter alarm must start at the durable pending transition',
  );
  assert.ok(
    metricFilters.some(
      (filter) =>
        filter.includes('result=dead_lettered') &&
        filter.includes('ArchiveDeadLetters'),
    ),
    'dead-letter alarm must retain the terminal transition as a fallback signal',
  );
  const archivePolicyStatements = policyStatementsForFunction(
    template,
    archiveFunction,
  ).filter((statement) =>
    JSON.stringify(statement.Resource).includes('SecurityEventArchiveBucket'),
  );
  assert.ok(
    archivePolicyStatements.some((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .includes('s3:PutObject'),
    ),
    'archive worker must conditionally replace a deterministic snapshot',
  );
  assert.ok(
    archivePolicyStatements.some((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
        .includes('s3:GetObject'),
    ),
    'archive worker must read the current object before an ETag-guarded replacement',
  );
  assert.ok(
    archivePolicyStatements.every((statement) =>
      JSON.stringify(statement.Resource).includes('security-events/*'),
    ),
    'archive object permissions must remain limited to the security-events prefix',
  );
  const archiveBuckets = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SecurityEventArchiveBucket') &&
      resource.Type === 'AWS::S3::Bucket',
  );
  assert.equal(archiveBuckets.length, 1, 'expected one security-event archive bucket');
  assert.equal(
    archiveBuckets[0][1].Properties.VersioningConfiguration.Status,
    'Enabled',
    'archive versions must remain recoverable after a conditional replacement',
  );
  assert.equal(
    archiveFunction.Properties.Timeout,
    30,
    'archive runtime must remain shorter than the 60-second refresh lease',
  );
  const archiveTablePolicyStatements = policyStatementsForFunction(
    template,
    archiveFunction,
  ).filter((statement) =>
    JSON.stringify(statement.Resource).includes(tableId),
  );
  for (const action of ['dynamodb:GetItem', 'dynamodb:UpdateItem']) {
    assert.ok(
      archiveTablePolicyStatements.some((statement) =>
        (Array.isArray(statement.Action) ? statement.Action : [statement.Action])
          .includes(action),
      ),
      `archive worker needs ${action} for refresh-lease fencing`,
    );
  }
  assert.ok(
    metricFilters.some(
      (filter) =>
        filter.includes('SECURITY_EVENT_INVALID') &&
        filter.includes('InfrastructureErrors'),
    ),
    'invalid event construction must page as an infrastructure error',
  );
  assert.ok(
    metricFilters.some(
      (filter) =>
        filter.includes('SECURITY_EVENT_FALLBACK') &&
        filter.includes('result=failed') &&
        filter.includes('InfrastructureErrors'),
    ),
    'fallback delivery failures must page as an infrastructure error',
  );
  assert.ok(
    metricFilters.some(
      (filter) =>
        filter.includes('SECURITY_EVENT_FALLBACK') &&
        filter.includes('result=timeout') &&
        filter.includes('InfrastructureErrors'),
    ),
    'fallback batch timeouts must page as an infrastructure error',
  );
  assert.ok(
    metricFilters.some(
      (filter) =>
        filter.includes('result=redrive_failed') &&
        filter.includes('InfrastructureErrors'),
    ),
    'persistent scheduled-redrive failures must page as infrastructure errors',
  );
  assert.ok(
    metricFilters.some(
      (filter) =>
        filter.includes('event_id=unvalidated') &&
        filter.includes('InfrastructureErrors'),
    ),
    'invalid ingress must page as an infrastructure error through its real producer path',
  );
  assert.ok(
    metricFilters.some(
      (filter) =>
        filter.includes('SECURITY_EVENT_INGRESS') &&
        filter.includes('result=dead_lettered') &&
        filter.includes('ArchiveDeadLetters'),
    ),
    'ingress terminal transitions must count toward the dead-letter alarm',
  );
  assert.ok(template.Outputs.SecurityEventArchiveBucketName);
  assert.ok(template.Outputs.SecurityEventArchiveDlqUrl);
  assert.ok(template.Outputs.SecurityEventIngressQueueUrl);
  assert.ok(template.Outputs.SecurityEventIngressDlqUrl);
  assert.ok(template.Outputs.SecurityEventStreamFailureNotificationQueueUrl);
  assert.ok(template.Outputs.SecurityEventStreamFailureNotificationDlqUrl);
  assert.ok(template.Outputs.SecurityEventStreamFailureBucketName);
});
