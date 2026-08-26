const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const path = require('node:path');
const test = require('node:test');
const { App, Aspects } = require('aws-cdk-lib');
const { Annotations, Match, Template } = require('aws-cdk-lib/assertions');
const { AwsSolutionsChecks } = require('cdk-nag');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');

function stack(overrides = {}, app = new App()) {
  const assetPath = path.resolve(__dirname);
  return new AgentAuthStack(app, 'DataGovernanceConfigTest', {
    env: { account: '123456789012', region: 'us-east-1' },
    webBaseUrl: 'https://c.auth.example.com',
    lambdaAssetPath: assetPath,
    securityEventArchiveAssetPath: assetPath,
    ssfDeliveryAssetPath: assetPath,
    tenantKeyProvisionerAssetPath: assetPath,
    governanceWorkerAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    deployFrontend: false,
    productionRecoveryEnabled: true,
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
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
    tenantKeyReplicaRegions: ['us-west-2'],
    tenantResidency: {
      t1: {
        jurisdiction: 'us',
        allowed_regions: ['us-east-1', 'us-west-2'],
        governance_region: 'us-east-1',
      },
      t2: {
        jurisdiction: 'us',
        allowed_regions: ['us-east-1', 'us-west-2'],
        governance_region: 'us-east-1',
      },
    },
    ...overrides,
  });
}

function resourceByPrefix(template, prefix, type) {
  const matches = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith(prefix) && resource.Type === type,
  );
  assert.equal(matches.length, 1, `expected one ${type} with prefix ${prefix}`);
  return matches[0];
}

function httpFunctionByScope(template, scope) {
  const matches = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.SCOPE === scope,
  );
  assert.equal(matches.length, 1, `expected one ${scope} HTTP Lambda`);
  return matches[0];
}

function replicasFor(template, tableLogicalId) {
  return Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'Custom::DynamoDBReplica' &&
      resource.Properties.TableName?.Ref === tableLogicalId,
  );
}

function policyStatementsForFunction(template, fn) {
  const roleId = fn.Properties.Role['Fn::GetAtt'][0];
  return Object.values(template.Resources)
    .filter(
      (resource) =>
        ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'].includes(
          resource.Type,
        ) &&
        resource.Properties.Roles?.some((role) => role.Ref === roleId),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement);
}

test('c12_7_governance_authorities_are_retained_protected_global_tables', () => {
  const template = Template.fromStack(stack()).toJSON();
  for (const prefix of ['GovernanceTable', 'GovernanceSuppressionTable']) {
    const [logicalId, table] = resourceByPrefix(
      template,
      prefix,
      'AWS::DynamoDB::Table',
    );
    assert.equal(table.DeletionPolicy, 'Retain');
    assert.equal(table.UpdateReplacePolicy, 'Retain');
    assert.equal(table.Properties.DeletionProtectionEnabled, true);
    assert.equal(
      table.Properties.PointInTimeRecoverySpecification
        .PointInTimeRecoveryEnabled,
      true,
    );
    assert.equal(
      table.Properties.PointInTimeRecoverySpecification.RecoveryPeriodInDays,
      35,
    );
    assert.equal(
      table.Properties.StreamSpecification.StreamViewType,
      'NEW_AND_OLD_IMAGES',
    );
    const replicas = replicasFor(template, logicalId);
    assert.equal(replicas.length, 1);
    assert.equal(replicas[0].Properties.Region, 'us-west-2');
  }

  const [, suppression] = resourceByPrefix(
    template,
    'GovernanceSuppressionTable',
    'AWS::DynamoDB::Table',
  );
  assert.deepEqual(suppression.Properties.KeySchema, [
    { AttributeName: 'pk', KeyType: 'HASH' },
    { AttributeName: 'epoch', KeyType: 'RANGE' },
  ]);
  assert.equal(suppression.Properties.TimeToLiveSpecification, undefined);
});

test('c12_7_runtime_receives_dedicated_governance_key_and_read_only_suppression', () => {
  const template = Template.fromStack(stack()).toJSON();
  const [governanceId] = resourceByPrefix(
    template,
    'GovernanceTable',
    'AWS::DynamoDB::Table',
  );
  const [suppressionId] = resourceByPrefix(
    template,
    'GovernanceSuppressionTable',
    'AWS::DynamoDB::Table',
  );
  const [hmacId, hmacSecret] = resourceByPrefix(
    template,
    'GovernanceHmacSecret',
    'AWS::SecretsManager::Secret',
  );
  const [bootstrapId, bootstrapSecret] = resourceByPrefix(
    template,
    'RuntimeBootstrapConfig',
    'AWS::SecretsManager::Secret',
  );
  assert.deepEqual(hmacSecret.Properties.ReplicaRegions, [
    { Region: 'us-west-2' },
  ]);
  assert.equal(bootstrapSecret.Properties.ReplicaRegions, undefined);
  const [, fn] = httpFunctionByScope(template, 'non_token');
  const env = fn.Properties.Environment.Variables;
  assert.deepEqual(env.GOVERNANCE_TABLE, { Ref: governanceId });
  assert.deepEqual(env.GOVERNANCE_SUPPRESSION_TABLE, { Ref: suppressionId });
  assert.deepEqual(env.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN, {
    Ref: bootstrapId,
  });
  const expectedBootstrapRevision = createHash('sha256')
    .update(JSON.stringify(bootstrapSecret.Properties.SecretString))
    .digest('hex')
    .slice(0, 16);
  assert.equal(env.AGENT_AUTH_BOOTSTRAP_REVISION, expectedBootstrapRevision);
  assert.equal(env.GOVERNANCE_HMAC_KEY, undefined);
  assert.equal(env.AGENT_AUTH_TENANT_RESIDENCY, undefined);
  assert.equal(env.TENANT_SECRET_DEPENDENCIES, undefined);
  const bootstrapDocument = JSON.stringify(
    bootstrapSecret.Properties.SecretString,
  );
  assert.match(bootstrapDocument, new RegExp(hmacId));
  assert.match(bootstrapDocument, /tenant_secret_dependencies/);
  assert.match(bootstrapDocument, /governance_hmac_secret_arn/);
  assert.match(bootstrapDocument, /tenant_residency/);
  assert.match(bootstrapDocument, /us-east-1/);
  assert.match(bootstrapDocument, /us-west-2/);
  assert.equal(
    env.AGENT_AUTH_DEPLOYMENT_COMMIT,
    '0123456789abcdef0123456789abcdef01234567',
  );
  const secretReadResources = policyStatementsForFunction(template, fn)
    .filter((statement) =>
      [statement.Action].flat().includes('secretsmanager:GetSecretValue'),
    )
    .map((statement) => JSON.stringify(statement.Resource))
    .join('\n');
  assert.match(secretReadResources, new RegExp(bootstrapId));
  assert.match(secretReadResources, new RegExp(hmacId));

  const suppressionStatements = policyStatementsForFunction(template, fn)
    .filter((statement) =>
      JSON.stringify(statement.Resource).includes(suppressionId),
    );
  assert.ok(suppressionStatements.length > 0);
  const suppressionActions = suppressionStatements.flatMap((statement) =>
    [statement.Action].flat(),
  );
  assert.ok(suppressionActions.includes('dynamodb:ConditionCheckItem'));
  for (const statement of suppressionStatements) {
    const actions = Array.isArray(statement.Action)
      ? statement.Action
      : [statement.Action];
    assert.equal(
      actions.some((action) =>
        /(?:Put|Update|Delete|BatchWrite)Item/.test(action)),
      false,
    );
  }
});

test('c12_7_durable_worker_advances_jobs_with_append_only_suppression_authority', () => {
  const template = Template.fromStack(stack()).toJSON();
  const [suppressionId] = resourceByPrefix(
    template,
    'GovernanceSuppressionTable',
    'AWS::DynamoDB::Table',
  );
  const [bootstrapId, bootstrapSecret] = resourceByPrefix(
    template,
    'RuntimeBootstrapConfig',
    'AWS::SecretsManager::Secret',
  );
  const [hmacId] = resourceByPrefix(
    template,
    'GovernanceHmacSecret',
    'AWS::SecretsManager::Secret',
  );
  const [queueId, queue] = resourceByPrefix(
    template,
    'GovernanceWorkerQueue',
    'AWS::SQS::Queue',
  );
  const [dlqId] = resourceByPrefix(
    template,
    'GovernanceWorkerDlq',
    'AWS::SQS::Queue',
  );
  assert.equal(queue.Properties.FifoQueue, true);
  assert.equal(queue.Properties.DelaySeconds, 15);
  assert.equal(queue.Properties.MessageRetentionPeriod, 14 * 24 * 60 * 60);
  assert.equal(queue.Properties.VisibilityTimeout, 6 * 60);
  assert.deepEqual(queue.Properties.RedrivePolicy, {
    deadLetterTargetArn: { 'Fn::GetAtt': [dlqId, 'Arn'] },
    maxReceiveCount: 5,
  });

  const [, authFn] = httpFunctionByScope(template, 'non_token');
  assert.deepEqual(authFn.Properties.Environment.Variables.GOVERNANCE_QUEUE_URL, {
    Ref: queueId,
  });
  const authStatements = policyStatementsForFunction(template, authFn);
  assert.ok(
    authStatements.some(
      (statement) =>
        JSON.stringify(statement.Resource).includes(queueId) &&
        [statement.Action].flat().includes('sqs:SendMessage'),
    ),
  );
  const [codesId] = resourceByPrefix(
    template,
    'CodesTable',
    'AWS::DynamoDB::Table',
  );
  const [usersId] = resourceByPrefix(
    template,
    'UsersTable',
    'AWS::DynamoDB::Table',
  );
  assert.ok(
    authStatements.some((statement) => {
      const resources = JSON.stringify(statement.Resource);
      return (
        [statement.Action].flat().includes('dynamodb:TransactWriteItems') &&
        resources.includes(codesId) &&
        resources.includes(usersId)
      );
    }),
    'AuthFn must transact atomically across authorization codes and users',
  );

  const [workerId, worker] = resourceByPrefix(
    template,
    'GovernanceWorkerFn',
    'AWS::Lambda::Function',
  );
  assert.equal(worker.Properties.Timeout, 300);
  assert.equal(
    worker.Properties.Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT,
    '0123456789abcdef0123456789abcdef01234567',
  );
  assert.deepEqual(
    worker.Properties.Environment.Variables.GOVERNANCE_QUEUE_URL,
    { Ref: queueId },
  );
  assert.ok(worker.Properties.Environment.Variables.INVITATIONS_TABLE);
  const [retentionConfigId, retentionConfigSecret] = resourceByPrefix(
    template,
    'GovernanceRetentionConfig',
    'AWS::SecretsManager::Secret',
  );
  assert.deepEqual(
    worker.Properties.Environment.Variables
      .GOVERNANCE_RETENTION_CONFIG_SECRET_ARN,
    { Ref: retentionConfigId },
  );
  assert.equal(
    worker.Properties.Environment.Variables.GOVERNANCE_RETENTION_CONFIG,
    undefined,
  );
  const expectedRuntimeBootstrapRevision = createHash('sha256')
    .update(JSON.stringify(bootstrapSecret.Properties.SecretString))
    .digest('hex')
    .slice(0, 16);
  const expectedWorkerBootstrapRevision = createHash('sha256')
    .update(expectedRuntimeBootstrapRevision)
    .update('\0')
    .update(JSON.stringify(retentionConfigSecret.Properties.SecretString))
    .digest('hex')
    .slice(0, 16);
  assert.equal(
    worker.Properties.Environment.Variables.AGENT_AUTH_BOOTSTRAP_REVISION,
    expectedWorkerBootstrapRevision,
  );
  const retentionConfig = JSON.stringify(
    retentionConfigSecret.Properties.SecretString,
  );
  for (const field of [
    'replicated_tables',
    'backup_vault_name',
    'recovery_table_arns',
    's3_buckets',
    'log_groups',
    'queue_urls',
  ]) {
    assert.match(retentionConfig, new RegExp(field));
  }
  for (const role of [
    'security_event_archive',
    'security_event_ingress_failures',
    'security_event_stream_failures',
    'ssf_stream_failures',
    'tenant_key_provisioner',
    'tenant_key_operations',
    'tenant_key_operations_dlq',
  ]) {
    assert.match(
      retentionConfig,
      new RegExp(role),
      `retention inventory must include ${role}`,
    );
  }
  for (const resourcePrefix of [
    'TenantKeyProvisionerLogGroup',
    'TenantKeyOperationsQueue',
    'TenantKeyOperationsDlq',
  ]) {
    assert.match(
      retentionConfig,
      new RegExp(resourcePrefix),
      `retention inventory must reference ${resourcePrefix}`,
    );
  }
  assert.ok(
    Object.values(template.Resources).some(
      (resource) =>
        resource.Type === 'AWS::Lambda::EventSourceMapping' &&
        resource.Properties.FunctionName.Ref === workerId &&
        resource.Properties.EventSourceArn['Fn::GetAtt'][0] === queueId &&
        resource.Properties.FunctionResponseTypes?.includes(
          'ReportBatchItemFailures',
        ),
    ),
  );

  const workerStatements = policyStatementsForFunction(template, worker);
  const workerActions = workerStatements.flatMap((statement) =>
    [statement.Action].flat(),
  );
  for (const action of [
    'dynamodb:Scan',
    'backup:ListRecoveryPointsByBackupVault',
    's3:ListBucketVersions',
    's3:GetObjectVersion',
    'logs:FilterLogEvents',
    'sqs:GetQueueAttributes',
  ]) {
    assert.ok(
      workerActions.includes(action),
      `governance worker must be allowed to call ${action}`,
    );
  }
  for (const prefix of [
    'GovernanceTable',
    'CodesTable',
    'ClientsTable',
    'InitialAccessTokensTable',
    'RefreshTable',
    'SessionsTable',
    'MagicLinkTable',
    'InvitationsTable',
    'RecoveryTable',
    'AuthzSessionsTable',
    'MessagesTable',
    'SsfDeliveriesTable',
    'WorkloadTrustTable',
    'CibaTable',
    'DeviceTable',
    'JtiTable',
    'GraceTable',
    'GrantsTable',
    'FederationConfigTable',
    'FederationFlowTable',
    'AdminAuthTable',
    'AdminAuthRuntimeTable',
    'UsersTable',
    'ScimGroupsTable',
    'PasswordCredentialsTable',
    'PasskeyTable',
    'PasskeyChallengeTable',
    'ParTable',
    'RateLimitTable',
    'DomainMapTable',
    'TenantKeysTable',
  ]) {
    const [tableId] = resourceByPrefix(
      template,
      prefix,
      'AWS::DynamoDB::Table',
    );
    assert.ok(
      workerStatements.some((statement) => {
        const actions = [statement.Action].flat();
        return (
          JSON.stringify(statement.Resource).includes(tableId) &&
          actions.includes('dynamodb:Scan') &&
          actions.includes('dynamodb:DeleteItem')
        );
      }),
      `governance worker must have read/write access to ${prefix}`,
    );
  }
  const describeKeyStatements = workerStatements.filter((statement) =>
    [statement.Action].flat().includes('kms:DescribeKey'),
  );
  assert.equal(describeKeyStatements.length, 1);
  assert.deepEqual(
    [describeKeyStatements[0].Action].flat(),
    ['kms:DescribeKey'],
  );
  assert.deepEqual(describeKeyStatements[0].Condition, {
    StringEquals: {
      'aws:ResourceTag/agent-auth-managed': 'true',
      'aws:ResourceTag/agent-auth-deployment': {
        Ref: resourceByPrefix(
          template,
          'TenantKeysTable',
          'AWS::DynamoDB::Table',
        )[0],
      },
    },
  });
  assert.match(
    JSON.stringify(describeKeyStatements[0].Resource),
    /kms:\*:123456789012:key\/\*/,
  );
  const [tenantKeyQueueId] = resourceByPrefix(
    template,
    'TenantKeyOperationsQueue',
    'AWS::SQS::Queue',
  );
  assert.ok(
    workerStatements.some(
      (statement) =>
        JSON.stringify(statement.Resource).includes(tenantKeyQueueId) &&
        [statement.Action].flat().includes('sqs:SendMessage'),
    ),
  );

  const secretStatements = workerStatements.filter((statement) =>
    [statement.Action]
      .flat()
      .some((action) => action.startsWith('secretsmanager:')),
  );
  const destructiveSecretStatements = secretStatements.filter((statement) =>
    [statement.Action].flat().includes('secretsmanager:DeleteSecret'),
  );
  assert.equal(destructiveSecretStatements.length, 1);
  assert.deepEqual(
    [destructiveSecretStatements[0].Action].flat().sort(),
    [
      'secretsmanager:DeleteSecret',
      'secretsmanager:DescribeSecret',
      'secretsmanager:RemoveRegionsFromReplication',
    ],
  );
  const secretResources = JSON.stringify(
    destructiveSecretStatements[0].Resource,
  );
  const productManagedSecretIds = Object.keys(template.Resources).filter(
    (logicalId) =>
      ['TenantAdminCredentialSet', 'ScimToken', 'ScimCredentialSet'].some(
        (prefix) => logicalId.startsWith(prefix),
      ),
  );
  assert.equal(productManagedSecretIds.length, 6);
  for (const logicalId of productManagedSecretIds) {
    assert.match(secretResources, new RegExp(logicalId));
  }
  assert.doesNotMatch(secretResources, /legacy\/t[12]-/);
  const externalDescribeResources = secretStatements
    .filter((statement) => {
      const actions = [statement.Action].flat();
      return (
        actions.includes('secretsmanager:DescribeSecret') &&
        !actions.includes('secretsmanager:DeleteSecret')
      );
    })
    .map((statement) => JSON.stringify(statement.Resource))
    .join('\n');
  assert.match(externalDescribeResources, /legacy\/t1-/);
  assert.match(externalDescribeResources, /legacy\/t2-/);
  assert.match(externalDescribeResources, /agent-auth\/federation/);
  assert.match(externalDescribeResources, /agent-auth\/admin-oidc/);
  assert.equal(
    workerStatements
      .flatMap((statement) => [statement.Action].flat())
      .includes('secretsmanager:GetSecretValue'),
    true,
  );
  const secretReadResources = secretStatements
    .filter((statement) =>
      [statement.Action].flat().includes('secretsmanager:GetSecretValue'),
    )
    .map((statement) => JSON.stringify(statement.Resource))
    .join('\n');
  assert.match(secretReadResources, new RegExp(bootstrapId));
  assert.match(secretReadResources, new RegExp(hmacId));
  assert.match(secretReadResources, new RegExp(retentionConfigId));

  const secretDependencies = JSON.stringify(
    bootstrapSecret.Properties.SecretString,
  );
  for (const value of [
    'tenant_admin',
    'scim',
    'tenant_admin_legacy_source',
    'scim_legacy_source',
    'product_managed',
    'external',
    'resource_account',
    'resource_region',
    'ownership_revision',
  ]) {
    assert.match(secretDependencies, new RegExp(value));
  }

  const suppressionStatements = workerStatements.filter((statement) =>
    JSON.stringify(statement.Resource).includes(suppressionId),
  );
  assert.ok(suppressionStatements.length > 0);
  const suppressionActions = suppressionStatements.flatMap((statement) =>
    [statement.Action].flat(),
  );
  assert.ok(suppressionActions.includes('dynamodb:PutItem'));
  assert.ok(suppressionActions.includes('dynamodb:GetItem'));
  assert.ok(suppressionActions.includes('dynamodb:Query'));
  assert.equal(
    suppressionActions.some((action) =>
      /(?:Update|Delete|BatchWrite)Item/.test(action),
    ),
    false,
  );
  resourceByPrefix(
    template,
    'GovernanceWorkerBacklogAlarm',
    'AWS::CloudWatch::Alarm',
  );
  resourceByPrefix(
    template,
    'GovernanceWorkerDeadLettersAlarm',
    'AWS::CloudWatch::Alarm',
  );
  const [, retentionRule] = resourceByPrefix(
    template,
    'GovernanceRetentionSchedule',
    'AWS::Events::Rule',
  );
  assert.equal(retentionRule.Properties.ScheduleExpression, 'rate(1 hour)');
});

test('c12_7_ordinary_backup_excludes_non_rollback_governance_authority', () => {
  const template = Template.fromStack(stack()).toJSON();
  const [governanceId] = resourceByPrefix(
    template,
    'GovernanceTable',
    'AWS::DynamoDB::Table',
  );
  const [suppressionId] = resourceByPrefix(
    template,
    'GovernanceSuppressionTable',
    'AWS::DynamoDB::Table',
  );
  const [, selection] = resourceByPrefix(
    template,
    'RecoveryBackupPlanDurableAuthorityTables',
    'AWS::Backup::BackupSelection',
  );
  const resources = JSON.stringify(
    selection.Properties.BackupSelection.Resources,
  );
  assert.doesNotMatch(resources, new RegExp(governanceId));
  assert.doesNotMatch(resources, new RegExp(suppressionId));
  resourceByPrefix(
    template,
    'GovernanceSystemErrorsAlarm',
    'AWS::CloudWatch::Alarm',
  );
  resourceByPrefix(
    template,
    'GovernanceSuppressionSystemErrorsAlarm',
    'AWS::CloudWatch::Alarm',
  );
  resourceByPrefix(
    template,
    'GovernanceReplicationLatencyuswest2Alarm',
    'AWS::CloudWatch::Alarm',
  );
});

test('c12_7_background_authority_writers_receive_governance_fence_iam', () => {
  const assetPath = path.resolve(__dirname);
  const template = Template.fromStack(
    stack({
      reclaimAssetPath: assetPath,
      recomputeAssetPath: assetPath,
    }),
  ).toJSON();
  const [governanceId] = resourceByPrefix(
    template,
    'GovernanceTable',
    'AWS::DynamoDB::Table',
  );
  const [suppressionId] = resourceByPrefix(
    template,
    'GovernanceSuppressionTable',
    'AWS::DynamoDB::Table',
  );
  const [bootstrapId] = resourceByPrefix(
    template,
    'RuntimeBootstrapConfig',
    'AWS::SecretsManager::Secret',
  );
  const [hmacId] = resourceByPrefix(
    template,
    'GovernanceHmacSecret',
    'AWS::SecretsManager::Secret',
  );
  for (const prefix of ['ReclaimFn', 'RecomputeFn']) {
    const [, fn] = resourceByPrefix(
      template,
      prefix,
      'AWS::Lambda::Function',
    );
    const env = fn.Properties.Environment.Variables;
    assert.deepEqual(env.GOVERNANCE_TABLE, { Ref: governanceId });
    assert.deepEqual(env.GOVERNANCE_SUPPRESSION_TABLE, { Ref: suppressionId });
    assert.ok(env.GOVERNANCE_QUEUE_URL);
    assert.ok(env.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN);
    assert.match(env.AGENT_AUTH_BOOTSTRAP_REVISION, /^[0-9a-f]{16}$/);
    assert.ok(env.INVITATIONS_TABLE);
    assert.equal(env.GOVERNANCE_HMAC_KEY, undefined);
    assert.equal(env.AGENT_AUTH_TENANT_RESIDENCY, undefined);
    assert.equal(env.TENANT_SECRET_DEPENDENCIES, undefined);
    assert.equal(
      env.AGENT_AUTH_DEPLOYMENT_COMMIT,
      '0123456789abcdef0123456789abcdef01234567',
    );
    const actions = policyStatementsForFunction(template, fn)
      .filter((statement) =>
        JSON.stringify(statement.Resource).includes(governanceId),
      )
      .flatMap((statement) => [statement.Action].flat());
    assert.ok(actions.includes('dynamodb:TransactWriteItems'));
    assert.ok(actions.includes('dynamodb:GetItem'));
    const secretReadResources = policyStatementsForFunction(template, fn)
      .filter((statement) =>
        [statement.Action].flat().includes('secretsmanager:GetSecretValue'),
      )
      .map((statement) => JSON.stringify(statement.Resource))
      .join('\n');
    assert.match(secretReadResources, new RegExp(bootstrapId));
    assert.match(secretReadResources, new RegExp(hmacId));
  }
});

test('bootstrap revision restarts every warm AppState runtime on residency drift', () => {
  const first = Template.fromStack(
    stack({
      reclaimAssetPath: path.resolve(__dirname),
      recomputeAssetPath: path.resolve(__dirname),
    }),
  ).toJSON();
  const second = Template.fromStack(
    stack({
      reclaimAssetPath: path.resolve(__dirname),
      recomputeAssetPath: path.resolve(__dirname),
      tenantResidency: {
        t1: {
          jurisdiction: 'north-america',
          allowed_regions: ['us-east-1', 'us-west-2'],
          governance_region: 'us-east-1',
        },
        t2: {
          jurisdiction: 'us',
          allowed_regions: ['us-east-1', 'us-west-2'],
          governance_region: 'us-east-1',
        },
      },
    }),
  ).toJSON();
  const revisions = (template) => ({
    NonTokenFn:
      httpFunctionByScope(template, 'non_token')[1].Properties.Environment
        .Variables.AGENT_AUTH_BOOTSTRAP_REVISION,
    TokenFn:
      httpFunctionByScope(template, 'token')[1].Properties.Environment.Variables
        .AGENT_AUTH_BOOTSTRAP_REVISION,
    GovernanceWorkerFn: resourceByPrefix(
      template,
      'GovernanceWorkerFn',
      'AWS::Lambda::Function',
    )[1].Properties.Environment.Variables.AGENT_AUTH_BOOTSTRAP_REVISION,
    ReclaimFn: resourceByPrefix(
      template,
      'ReclaimFn',
      'AWS::Lambda::Function',
    )[1].Properties.Environment.Variables.AGENT_AUTH_BOOTSTRAP_REVISION,
    RecomputeFn: resourceByPrefix(
      template,
      'RecomputeFn',
      'AWS::Lambda::Function',
    )[1].Properties.Environment.Variables.AGENT_AUTH_BOOTSTRAP_REVISION,
  });
  const firstRevisions = revisions(first);
  const secondRevisions = revisions(second);
  assert.equal(firstRevisions.NonTokenFn, firstRevisions.TokenFn);
  assert.equal(firstRevisions.NonTokenFn, firstRevisions.ReclaimFn);
  assert.equal(firstRevisions.NonTokenFn, firstRevisions.RecomputeFn);
  assert.equal(secondRevisions.NonTokenFn, secondRevisions.TokenFn);
  assert.equal(secondRevisions.NonTokenFn, secondRevisions.ReclaimFn);
  assert.equal(secondRevisions.NonTokenFn, secondRevisions.RecomputeFn);
  for (const prefix of Object.keys(firstRevisions)) {
    assert.match(firstRevisions[prefix], /^[0-9a-f]{16}$/);
    assert.notEqual(firstRevisions[prefix], secondRevisions[prefix]);
  }
});

test('governance worker passes AWS Solutions checks after IAM policy overflow', () => {
  const app = new App();
  const governanceStack = stack({}, app);
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

  Annotations.fromStack(governanceStack).hasNoError('*', Match.anyValue());
});

test('c12_7_residency_rejects_missing_tenants_and_undeployed_regions', () => {
  assert.throws(
    () =>
      stack({
        tenantResidency: {
          t1: {
            jurisdiction: 'us',
            allowed_regions: ['us-east-1', 'us-west-2'],
          },
        },
      }),
    /exactly match/,
  );
  assert.throws(
    () =>
      stack({
        tenantResidency: {
          t1: {
            jurisdiction: 'us',
            allowed_regions: ['us-east-1', 'eu-west-1'],
          },
          t2: {
            jurisdiction: 'us',
            allowed_regions: ['us-east-1', 'eu-west-1'],
          },
        },
      }),
    /exactly the deployed storage Regions/,
  );
});
