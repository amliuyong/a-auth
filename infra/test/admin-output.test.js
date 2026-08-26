const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

test(
  'c12_1_admin_credentials_use_owner_bound_target_secrets',
  assertOwnerBoundAdminCredentialTargets,
);

test('CloudFormation outputs the Admin URL and a token retrieval command', () => {
  const app = new App();
  const stack = new AgentAuthStack(app, 'AdminOutputTest', {
    webBaseUrl: 'https://auth.example.com/',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    tenantKeyProvisionerAssetPath: path.resolve(__dirname),
    credentialMigrationAssetPath: path.resolve(__dirname),
    deployFrontend: false,
    tenantResidency: tenantResidency(),
  });
  const template = Template.fromStack(stack).toJSON();
  const adminSecretIds = Object.entries(template.Resources)
    .filter(
      ([, resource]) =>
        resource.Type === 'AWS::SecretsManager::Secret' &&
        resource.Properties?.Description?.includes('platform admin break-glass'),
    )
    .map(([logicalId]) => logicalId);
  assert.equal(adminSecretIds.length, 1, 'expected one Admin token secret');
  const [adminSecretId] = adminSecretIds;
  const adminSecret = template.Resources[adminSecretId];
  const [legacyAdminSecretId] = Object.entries(template.Resources).find(
    ([, resource]) =>
      resource.Type === 'AWS::SecretsManager::Secret' &&
      resource.Properties?.Description?.includes('legacy admin console token'),
  );
  const [legacyScimSecretId] = Object.entries(template.Resources).find(
    ([, resource]) =>
      resource.Type === 'AWS::SecretsManager::Secret' &&
      resource.Properties?.Description?.includes('default legacy SCIM bearer'),
  );
  const [scimSecretId] = Object.entries(template.Resources).find(
    ([, resource]) =>
      resource.Type === 'AWS::SecretsManager::Secret' &&
      resource.Properties?.Description?.includes('default SCIM provisioning credential set'),
  );
  assert.notEqual(
    legacyAdminSecretId,
    adminSecretId,
    'legacy rollback source and active credential set must use different Secrets',
  );
  assert.equal(
    adminSecret.Properties.GenerateSecretString.PasswordLength,
    48,
  );
  assert.equal(
    adminSecret.Properties.GenerateSecretString.SecretStringTemplate,
    undefined,
  );

  const migrationFunctions = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.CREDENTIAL_MIGRATION_MODE ===
        'admin',
  );
  assert.equal(migrationFunctions.length, 1);
  const [[, migrationFunction]] = migrationFunctions;
  assert.equal(migrationFunction.Properties.Runtime, 'provided.al2023');
  assert.deepEqual(migrationFunction.Properties.Architectures, ['arm64']);
  assert.doesNotMatch(
    JSON.stringify(migrationFunction.Properties.Environment ?? {}),
    /SecretString|ADMIN_TOKEN/,
  );

  const authFunction = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.DOMAIN_MAP_TABLE,
  );
  assert.ok(authFunction, 'expected main Auth Lambda');
  const environment = authFunction.Properties.Environment.Variables;
  const [bootstrapConfigId, bootstrapConfig] = Object.entries(
    template.Resources,
  ).find(
    ([logicalId, resource]) =>
      logicalId.startsWith('RuntimeBootstrapConfig') &&
      resource.Type === 'AWS::SecretsManager::Secret',
  );
  assert.deepEqual(environment.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN, {
    Ref: bootstrapConfigId,
  });
  const bootstrapDocument = JSON.stringify(
    bootstrapConfig.Properties.SecretString,
  );
  assert.match(bootstrapDocument, new RegExp(adminSecretId));
  assert.match(bootstrapDocument, new RegExp(scimSecretId));
  assert.equal(environment.ADMIN_CREDENTIAL_SECRET_ARN, undefined);
  assert.equal(environment.SCIM_CREDENTIAL_SECRET_ARN, undefined);
  assert.equal(environment.SCIM_TENANT_SECRET_ARNS, undefined);
  assert.equal(environment.ADMIN_CREDENTIAL_CACHE_TTL_SECS, undefined);
  assert.equal(environment.ADMIN_TOKEN, undefined);
  assert.equal(environment.ADMIN_TOKENS_BY_TENANT, undefined);
  const [migrationResourceId, migrationResource] = Object.entries(template.Resources).find(
    ([, resource]) =>
      resource.Type === 'AWS::CloudFormation::CustomResource' &&
      resource.Properties?.MigrationVersion === 'admin-scim-credential-set-v3-copy',
  );
  assert.deepEqual(migrationResource.Properties.Credentials, [
    {
      SourceSecretArn: { Ref: legacyAdminSecretId },
      TargetSecretArn: { Ref: adminSecretId },
      Owner: { kind: 'platform' },
      CredentialId: 'platform-bootstrap-v1',
    },
    {
      SourceSecretArn: { Ref: legacyScimSecretId },
      TargetSecretArn: { Ref: scimSecretId },
      Owner: { kind: 'scim_tenant', tenant_id: 'default' },
      CredentialId: 'default-scim-bootstrap-v1',
    },
  ]);
  assert.ok(authFunction.DependsOn.includes(migrationResourceId));

  const migrationRoleId = migrationFunction.Properties.Role['Fn::GetAtt'][0];
  const migrationActions = Object.values(template.Resources)
    .filter(
      (resource) =>
        resource.Type === 'AWS::IAM::Policy' &&
        resource.Properties.Roles?.some((role) => role.Ref === migrationRoleId),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement)
    .flatMap((statement) =>
      Array.isArray(statement.Action) ? statement.Action : [statement.Action],
    );
  assert.ok(migrationActions.includes('secretsmanager:GetSecretValue'));
  assert.ok(migrationActions.includes('secretsmanager:PutSecretValue'));
  assert.ok(migrationActions.includes('secretsmanager:UpdateSecretVersionStage'));
  assert.deepEqual(
    migrationActions.filter(
      (action) =>
        action.startsWith('secretsmanager:') &&
        !['secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'].includes(
          action,
        ),
    ),
    ['secretsmanager:PutSecretValue', 'secretsmanager:UpdateSecretVersionStage'],
  );
  const migrationPolicy = JSON.stringify(
    Object.values(template.Resources)
      .filter(
        (resource) =>
          resource.Type === 'AWS::IAM::Policy' &&
          resource.Properties.Roles?.some((role) => role.Ref === migrationRoleId),
      )
      .flatMap((resource) => resource.Properties.PolicyDocument.Statement),
  );
  assert.match(migrationPolicy, new RegExp(legacyAdminSecretId));
  assert.match(migrationPolicy, new RegExp(adminSecretId));
  assert.match(migrationPolicy, new RegExp(legacyScimSecretId));
  assert.match(migrationPolicy, new RegExp(scimSecretId));
  const migrationWrites = Object.values(template.Resources)
    .filter(
      (resource) =>
        resource.Type === 'AWS::IAM::Policy' &&
        resource.Properties.Roles?.some((role) => role.Ref === migrationRoleId),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement)
    .filter((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes(
        'secretsmanager:PutSecretValue',
      ),
    );
  assert.deepEqual(migrationWrites.map((statement) => statement.Resource), [
    [{ Ref: adminSecretId }, { Ref: scimSecretId }],
  ]);
  const migrationStages = Object.values(template.Resources)
    .filter(
      (resource) =>
        resource.Type === 'AWS::IAM::Policy' &&
        resource.Properties.Roles?.some((role) => role.Ref === migrationRoleId),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement)
    .filter((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes(
        'secretsmanager:UpdateSecretVersionStage',
      ),
    );
  assert.equal(migrationStages.length, 1);
  assert.deepEqual(migrationStages[0].Condition, {
    StringEquals: {
      'secretsmanager:VersionStage': ['AWSCURRENT', 'AGENTAUTH_VALIDATED'],
    },
  });

  const authRoleId = authFunction.Properties.Role['Fn::GetAtt'][0];
  const authStatements = Object.values(template.Resources)
    .filter(
      (resource) =>
        ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'].includes(resource.Type) &&
        resource.Properties.Roles?.some((role) => role.Ref === authRoleId),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement);
  const authPolicy = JSON.stringify(authStatements);
  assert.match(authPolicy, new RegExp(adminSecretId));
  assert.match(authPolicy, new RegExp(scimSecretId));
  assert.match(authPolicy, /secretsmanager:UpdateSecretVersionStage/);
  const legacySourceDenies = authStatements.filter(
    (statement) =>
      statement.Effect === 'Deny' &&
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes(
        'secretsmanager:GetSecretValue',
      ),
  );
  assert.equal(legacySourceDenies.length, 1);
  assert.match(JSON.stringify(legacySourceDenies), new RegExp(legacyAdminSecretId));
  assert.match(JSON.stringify(legacySourceDenies), new RegExp(legacyScimSecretId));
  const allowedSecretReads = JSON.stringify(
    authStatements.filter(
      (statement) =>
        statement.Effect !== 'Deny' &&
        (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes(
          'secretsmanager:GetSecretValue',
        ),
    ),
  );
  assert.doesNotMatch(allowedSecretReads, new RegExp(legacyAdminSecretId));
  assert.doesNotMatch(allowedSecretReads, new RegExp(legacyScimSecretId));
  const federationOverflowPolicies = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::IAM::ManagedPolicy' &&
      JSON.stringify(resource.Properties?.PolicyDocument ?? {}).includes(
        'secret:agent-auth/federation/*',
      ),
  );
  assert.equal(
    federationOverflowPolicies.length,
    0,
    'admin credential permissions must not push the federation prefix into an unsuppressed overflow policy',
  );
  const stageStatements = authStatements.filter((statement) =>
    (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes(
      'secretsmanager:UpdateSecretVersionStage',
    ),
  );
  assert.equal(stageStatements.length, 1);
  assert.deepEqual(stageStatements[0].Condition, {
    StringEquals: {
      'secretsmanager:VersionStage': [
        'AGENTAUTH_VALIDATED',
        'AGENTAUTH_ROLLBACK_PENDING',
      ],
    },
  });

  assert.equal(template.Outputs.AdminUrl.Value, 'https://auth.example.com/admin');
  assert.deepEqual(template.Outputs.AdminSecretArn.Value, {
    Ref: adminSecretId,
  });

  const command = JSON.stringify(template.Outputs.AdminTokenCommand.Value);
  assert.match(command, /aws secretsmanager get-secret-value/);
  assert.match(command, /--secret-id/);
  assert.match(command, new RegExp(adminSecretId));
  assert.match(command, /AWS::Region/);
  assert.match(command, /--query SecretString --output text/);
  assert.match(command, /\.current\.secret/);
  assert.doesNotMatch(command, /resolve:secretsmanager|SecretString:/);
});

function assertOwnerBoundAdminCredentialTargets() {
  const app = new App();
  const stack = new AgentAuthStack(app, 'SaasAdminCredentialTest', {
    webBaseUrl: 'https://c.auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    tenantKeyProvisionerAssetPath: path.resolve(__dirname),
    credentialMigrationAssetPath: path.resolve(__dirname),
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
    tenantResidency: tenantResidency(['t1', 't2']),
    reclaimAssetPath: path.resolve(__dirname),
    recomputeAssetPath: path.resolve(__dirname),
  });
  const template = Template.fromStack(stack).toJSON();
  const migration = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::CloudFormation::CustomResource' &&
      resource.Properties?.MigrationVersion === 'admin-scim-credential-set-v3-copy',
  );
  assert.ok(migration);
  const credentials = migration.Properties.Credentials;
  assert.equal(credentials.length, 5);
  assert.equal(
    new Set(credentials.map((entry) => JSON.stringify(entry.SourceSecretArn))).size,
    5,
  );
  assert.equal(
    new Set(credentials.map((entry) => JSON.stringify(entry.TargetSecretArn))).size,
    5,
  );
  for (const entry of credentials) {
    assert.notDeepEqual(entry.SourceSecretArn, entry.TargetSecretArn);
  }

  const runtimeFunctions = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.USERS_TABLE,
  );
  assert.equal(
    runtimeFunctions.length,
    5,
    'expected Auth, Token, Governance, Reclaim, and Recompute Lambdas',
  );
  assert.deepEqual(
    runtimeFunctions
      .map(([, resource]) => resource.Properties.Environment.Variables.SCOPE)
      .filter(Boolean)
      .sort(),
    ['non_token', 'token'],
  );
  const [, authFunction] = runtimeFunctions.find(
    ([, resource]) =>
      resource.Properties.Environment.Variables.SCOPE === 'non_token',
  );
  assert.ok(authFunction);
  const [, recomputeFunction] = runtimeFunctions.find(
    ([, resource]) =>
      resource.Properties.Environment.Variables.AGENT_AUTH_RECOMPUTE_TENANTS,
  );
  assert.ok(recomputeFunction);
  assert.equal(
    recomputeFunction.Properties.Environment.Variables.AGENT_AUTH_RECOMPUTE_TENANTS,
    't1,t2',
  );
  const [bootstrapConfigId, bootstrapConfig] = Object.entries(
    template.Resources,
  ).find(
    ([logicalId, resource]) =>
      logicalId.startsWith('RuntimeBootstrapConfig') &&
      resource.Type === 'AWS::SecretsManager::Secret',
  );
  const bootstrapDocument = JSON.stringify(
    bootstrapConfig.Properties.SecretString,
  );
  const environment = authFunction.Properties.Environment.Variables;
  assert.deepEqual(environment.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN, {
    Ref: bootstrapConfigId,
  });
  for (const entry of credentials.filter((item) =>
    ['platform', 'tenant'].includes(item.Owner.kind),
  )) {
    assert.ok(bootstrapDocument.includes(JSON.stringify(entry.TargetSecretArn)));
    assert.ok(!bootstrapDocument.includes(JSON.stringify(entry.SourceSecretArn)));
  }
  for (const entry of credentials.filter((item) => item.Owner.kind === 'scim_tenant')) {
    assert.ok(bootstrapDocument.includes(JSON.stringify(entry.TargetSecretArn)));
    if (entry.SourceSecretArn.Ref?.startsWith('ScimToken')) {
      assert.ok(bootstrapDocument.includes(JSON.stringify(entry.SourceSecretArn)));
    }
  }
  assert.equal(environment.ADMIN_CREDENTIAL_SECRET_ARN, undefined);
  assert.equal(environment.TENANT_ADMIN_SECRET_ARNS, undefined);
  assert.equal(environment.SCIM_TENANT_SECRET_ARNS, undefined);
  assert.equal(environment.SCIM_CREDENTIAL_SECRET_ARN, undefined);
  assert.equal(environment.ADMIN_TOKEN, undefined);
  assert.equal(environment.ADMIN_TOKENS_BY_TENANT, undefined);
  for (const [, runtimeFunction] of runtimeFunctions) {
    const runtimeEnvironment = runtimeFunction.Properties.Environment.Variables;
    assert.deepEqual(
      runtimeEnvironment.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN,
      environment.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN,
    );
    assert.equal(runtimeEnvironment.ADMIN_CREDENTIAL_SECRET_ARN, undefined);
    assert.equal(runtimeEnvironment.TENANT_ADMIN_SECRET_ARNS, undefined);
    assert.equal(runtimeEnvironment.SCIM_TENANT_SECRET_ARNS, undefined);
    assert.equal(runtimeEnvironment.SCIM_CREDENTIAL_SECRET_ARN, undefined);
    assert.equal(runtimeEnvironment.AGENT_AUTH_FORM, 'saas');
    assert.equal(runtimeEnvironment.AGENT_AUTH_ZONE, 'auth.example.com');
    assert.equal(runtimeEnvironment.AGENT_AUTH_CONTROL_HOST, 'c.auth.example.com');
  }

  const migrationFunction = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.CREDENTIAL_MIGRATION_MODE ===
        'admin',
  );
  const migrationRoleId = migrationFunction.Properties.Role['Fn::GetAtt'][0];
  const migrationStatements = Object.values(template.Resources)
    .filter(
      (resource) =>
        resource.Type === 'AWS::IAM::Policy' &&
        resource.Properties.Roles?.some((role) => role.Ref === migrationRoleId),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement);
  const migrationWrites = JSON.stringify(
    migrationStatements.filter((statement) =>
      (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes(
        'secretsmanager:PutSecretValue',
      ),
    ),
  );
  for (const entry of credentials) {
    assert.ok(migrationWrites.includes(JSON.stringify(entry.TargetSecretArn)));
    assert.ok(!migrationWrites.includes(JSON.stringify(entry.SourceSecretArn)));
  }
  const migrationStages = migrationStatements.filter((statement) =>
    (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes(
      'secretsmanager:UpdateSecretVersionStage',
    ),
  );
  assert.equal(migrationStages.length, 1);
  assert.deepEqual(migrationStages[0].Condition, {
    StringEquals: {
      'secretsmanager:VersionStage': ['AWSCURRENT', 'AGENTAUTH_VALIDATED'],
    },
  });
  const migrationStagePolicy = JSON.stringify(migrationStages);
  for (const entry of credentials) {
    assert.ok(migrationStagePolicy.includes(JSON.stringify(entry.TargetSecretArn)));
    assert.ok(!migrationStagePolicy.includes(JSON.stringify(entry.SourceSecretArn)));
  }

  const authRoleId = authFunction.Properties.Role['Fn::GetAtt'][0];
  const authStatements = Object.values(template.Resources)
    .filter(
      (resource) =>
        ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'].includes(resource.Type) &&
        resource.Properties.Roles?.some((role) => role.Ref === authRoleId),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement);
  const authPolicy = JSON.stringify(authStatements);
  const allowedSecretReads = JSON.stringify(
    authStatements.filter(
      (statement) =>
        statement.Effect !== 'Deny' &&
        (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes(
          'secretsmanager:GetSecretValue',
        ),
    ),
  );
  const deniedSecretReads = JSON.stringify(
    authStatements.filter(
      (statement) =>
        statement.Effect === 'Deny' &&
        (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes(
          'secretsmanager:GetSecretValue',
        ),
    ),
  );
  for (const entry of credentials) {
    assert.ok(authPolicy.includes(JSON.stringify(entry.TargetSecretArn)));
    assert.ok(!allowedSecretReads.includes(JSON.stringify(entry.SourceSecretArn)));
    assert.ok(deniedSecretReads.includes(JSON.stringify(entry.SourceSecretArn)));
  }
}
