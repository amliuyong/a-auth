const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');

const DURABLE_TABLES = [
  'ClientsTable',
  'WorkloadTrustTable',
  'GrantsTable',
  'FederationConfigTable',
  'AdminAuthTable',
  'PasskeyTable',
  'SecurityEventsTable',
  'UsersTable',
  'AttributeNamespacesTable',
  'FederationAttributeMappingsTable',
  'ScimGroupsTable',
  'PasswordCredentialsTable',
  'DomainMapTable',
  'TenantKeysTable',
];

const TRANSIENT_TABLES = [
  'CodesTable',
  'ClientAuthorityRefsTable',
  'InitialAccessTokensTable',
  'RefreshTable',
  'SessionsTable',
  'MagicLinkTable',
  'RecoveryTable',
  'AuthzSessionsTable',
  'CibaTable',
  'DeviceTable',
  'GraceTable',
  'JtiTable',
  'FederationFlowTable',
  'AdminAuthRuntimeTable',
  'PasskeyChallengeTable',
  'ParTable',
  'RateLimitTable',
  'MessagesTable',
];

const NON_RESTORABLE_RETAINED_TABLES = [
  'SsfDeliveriesTable',
  'GovernanceTable',
  'GovernanceSuppressionTable',
];

const DEPLOYMENT_COMMIT = '0123456789abcdef0123456789abcdef01234567';

function synth(productionRecoveryEnabled, deploymentCommit) {
  const app = new App();
  const assetPath = path.resolve(__dirname);
  const stack = new AgentAuthStack(app, 'DisasterRecoveryConfigTest', {
    env: { account: '123456789012', region: 'us-east-1' },
    webBaseUrl: 'https://c.auth.example.com',
    lambdaAssetPath: assetPath,
    securityEventArchiveAssetPath: assetPath,
    ssfDeliveryAssetPath: assetPath,
    tenantKeyProvisionerAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    deployFrontend: false,
    productionRecoveryEnabled,
    tenantKeyReplicaRegions: productionRecoveryEnabled ? ['us-west-2'] : [],
    deploymentCommit: deploymentCommit ?? DEPLOYMENT_COMMIT,
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
  });
  return Template.fromStack(stack).toJSON();
}

function resourceByPrefix(template, prefix, type) {
  const matches = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith(prefix) && resource.Type === type,
  );
  assert.equal(matches.length, 1, `expected one ${type} with prefix ${prefix}`);
  return matches[0];
}

test('c12_7_production_recovery_retains_safe_authority_and_excludes_replay_state', () => {
  const template = synth(true);

  for (const prefix of DURABLE_TABLES) {
    const [, table] = resourceByPrefix(
      template,
      prefix,
      'AWS::DynamoDB::Table',
    );
    assert.equal(table.DeletionPolicy, 'Retain', `${prefix} must be retained`);
    assert.equal(
      table.UpdateReplacePolicy,
      'Retain',
      `${prefix} replacement must retain the original`,
    );
    assert.equal(
      table.Properties.PointInTimeRecoverySpecification
        .PointInTimeRecoveryEnabled,
      true,
      `${prefix} must keep PITR enabled`,
    );
    assert.equal(
      table.Properties.PointInTimeRecoverySpecification.RecoveryPeriodInDays,
      35,
      `${prefix} must keep 35 days of PITR history`,
    );
  }

  for (const prefix of TRANSIENT_TABLES) {
    const [, table] = resourceByPrefix(
      template,
      prefix,
      'AWS::DynamoDB::Table',
    );
    assert.equal(table.DeletionPolicy, 'Delete', `${prefix} must not be restored`);
    assert.equal(
      table.UpdateReplacePolicy,
      'Delete',
      `${prefix} replacement must not preserve replayable artifacts`,
    );
  }

  for (const prefix of NON_RESTORABLE_RETAINED_TABLES) {
    const [, table] = resourceByPrefix(
      template,
      prefix,
      'AWS::DynamoDB::Table',
    );
    assert.equal(table.DeletionPolicy, 'Retain');
    assert.equal(table.UpdateReplacePolicy, 'Retain');
  }

  for (const prefix of [
    'SigningKeyEs256',
    'SigningKeyRs256',
    'GraceEnvelopeKey',
    'TokenGraceEnvelopeKey',
    'CibaNotificationEnvelopeKey',
  ]) {
    const [, key] = resourceByPrefix(template, prefix, 'AWS::KMS::Key');
    assert.equal(key.DeletionPolicy, 'Retain', `${prefix} must be retained`);
    assert.equal(key.UpdateReplacePolicy, 'Retain');
  }

  const secrets = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      resource.Type === 'AWS::SecretsManager::Secret' &&
      (
        logicalId.startsWith('ServerSecret') ||
        logicalId.startsWith('GovernanceHmacSecret') ||
        logicalId.startsWith('AdminToken') ||
        logicalId.startsWith('AdminCredentialSet') ||
        logicalId.startsWith('TenantAdminCredentialSet') ||
        logicalId.startsWith('ScimToken') ||
        logicalId.startsWith('ScimCredentialSet')
      ),
  );
  assert.ok(secrets.length >= 8);
  for (const [logicalId, secret] of secrets) {
    assert.equal(secret.DeletionPolicy, 'Retain', `${logicalId} must be retained`);
    assert.equal(secret.UpdateReplacePolicy, 'Retain');
  }
});

test('c12_7_production_recovery_creates_scoped_35_day_daily_backup', () => {
  const template = synth(true);
  const [, vault] = resourceByPrefix(
    template,
    'RecoveryBackupVault',
    'AWS::Backup::BackupVault',
  );
  assert.equal(vault.DeletionPolicy, 'Retain');
  assert.ok(vault.Properties.EncryptionKeyArn);

  const [, plan] = resourceByPrefix(
    template,
    'RecoveryBackupPlan',
    'AWS::Backup::BackupPlan',
  );
  const [rule] = plan.Properties.BackupPlan.BackupPlanRule;
  assert.equal(rule.ScheduleExpression, 'cron(0 5 * * ? *)');
  assert.equal(rule.StartWindowMinutes, 60);
  assert.equal(rule.CompletionWindowMinutes, 240);
  assert.equal(rule.Lifecycle.DeleteAfterDays, 35);
  assert.deepEqual(rule.RecoveryPointTags, {
    'agent-auth-data-class': 'durable-authority',
  });

  const [, selection] = resourceByPrefix(
    template,
    'RecoveryBackupPlanDurableAuthorityTables',
    'AWS::Backup::BackupSelection',
  );
  assert.equal(
    selection.Properties.BackupSelection.Resources.length,
    DURABLE_TABLES.length,
  );
  const selected = JSON.stringify(
    selection.Properties.BackupSelection.Resources,
  );
  for (const prefix of DURABLE_TABLES) {
    const [logicalId] = resourceByPrefix(
      template,
      prefix,
      'AWS::DynamoDB::Table',
    );
    assert.match(selected, new RegExp(logicalId));
  }
  for (const prefix of TRANSIENT_TABLES) {
    const [logicalId] = resourceByPrefix(
      template,
      prefix,
      'AWS::DynamoDB::Table',
    );
    assert.doesNotMatch(selected, new RegExp(logicalId));
  }
  for (const prefix of NON_RESTORABLE_RETAINED_TABLES) {
    const [logicalId] = resourceByPrefix(
      template,
      prefix,
      'AWS::DynamoDB::Table',
    );
    assert.doesNotMatch(selected, new RegExp(logicalId));
  }

  const [roleLogicalId, role] = resourceByPrefix(
    template,
    'RecoveryBackupRole',
    'AWS::IAM::Role',
  );
  const managedPolicies = JSON.stringify(role.Properties.ManagedPolicyArns);
  assert.match(managedPolicies, /AWSBackupServiceRolePolicyForBackup/);
  assert.doesNotMatch(managedPolicies, /AWSBackupServiceRolePolicyForRestores/);
  assert.deepEqual(selection.Properties.BackupSelection.IamRoleArn, {
    'Fn::GetAtt': [roleLogicalId, 'Arn'],
  });

  const [backupKeyLogicalId] = resourceByPrefix(
    template,
    'RecoveryBackupKey',
    'AWS::KMS::Key',
  );
  const keyStatements = Object.values(template.Resources)
    .filter((resource) => resource.Type === 'AWS::IAM::Policy')
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement)
    .filter(
      (statement) =>
        JSON.stringify(statement.Resource) ===
        JSON.stringify({ 'Fn::GetAtt': [backupKeyLogicalId, 'Arn'] }),
    );
  assert.equal(keyStatements.length, 1);
  assert.deepEqual([...keyStatements[0].Action].sort(), [
    'kms:Decrypt',
    'kms:DescribeKey',
    'kms:Encrypt',
    'kms:GenerateDataKey',
    'kms:ReEncryptFrom',
    'kms:ReEncryptTo',
  ]);

  assert.ok(template.Outputs.RecoveryBackupVaultName);
  assert.ok(template.Outputs.RecoveryBackupPlanId);
  assert.ok(template.Outputs.RecoveryBackupRoleArn);
  assert.deepEqual(template.Outputs.RecoveryDeploymentCommit, {
    Value: DEPLOYMENT_COMMIT,
  });
  assert.ok(template.Outputs.RecoveryAuthorityTableNames);
  assert.deepEqual(template.Outputs.RecoveryTenantIssuers, {
    Value:
      '{"t1":"https://t1.auth.example.com","t2":"https://t2.auth.example.com"}',
  });
});

test('recovery resources remain opt-in outside the production profile', () => {
  const template = synth(false);
  assert.equal(
    Object.values(template.Resources).filter((resource) =>
      resource.Type.startsWith('AWS::Backup::')).length,
    0,
  );

  const [, clients] = resourceByPrefix(
    template,
    'ClientsTable',
    'AWS::DynamoDB::Table',
  );
  assert.equal(clients.DeletionPolicy, 'Delete');
  assert.equal(template.Outputs.RecoveryBackupVaultName, undefined);
});

test('single-region deployments export an explicitly provided commit', () => {
  const template = synth(false, DEPLOYMENT_COMMIT);
  assert.deepEqual(template.Outputs.DeploymentCommit, {
    Value: DEPLOYMENT_COMMIT,
  });
  assert.equal(template.Outputs.RegionId, undefined);
  assert.equal(template.Outputs.RecoveryDeploymentCommit, undefined);
});

test('an explicitly provided deployment commit must be an exact Git SHA', () => {
  assert.throws(
    () => synth(false, 'main'),
    /AGENT_AUTH_DEPLOYMENT_COMMIT must be a full lowercase Git SHA/,
  );
});

test('production recovery requires an exact deployment commit', () => {
  assert.throws(
    () => {
      const app = new App();
      new AgentAuthStack(app, 'MissingRecoveryCommitTest', {
        env: { account: '123456789012', region: 'us-east-1' },
        webBaseUrl: 'https://auth.example.com',
        lambdaAssetPath: path.resolve(__dirname),
        deployFrontend: false,
        productionRecoveryEnabled: true,
      });
    },
    /AGENT_AUTH_DEPLOYMENT_COMMIT/,
  );
});
