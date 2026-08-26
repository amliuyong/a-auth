const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App, Aspects } = require('aws-cdk-lib');
const { Annotations, Match, Template } = require('aws-cdk-lib/assertions');
const { AwsSolutionsChecks } = require('cdk-nag');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const {
  AgentAuthStandbyStack,
} = require('../dist/lib/agent-auth-standby-stack');

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
  'GovernanceTable',
  'GovernanceSuppressionTable',
];

const REGION_LOCAL_TABLES = [
  'CodesTable',
  'ClientAuthorityRefsTable',
  'InitialAccessTokensTable',
  'RefreshTable',
  'SessionsTable',
  'MagicLinkTable',
  'InvitationsTable',
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
  'SsfDeliveriesTable',
];

function synth(
  input = ['us-west-2'],
  productionRecoveryEnabled = true,
  stackId = 'MultiRegionConfigTest',
) {
  const overrides = Array.isArray(input)
    ? {
        tenantKeyReplicaRegions: input,
        productionRecoveryEnabled,
      }
    : input;
  const app = new App();
  const assetPath = path.resolve(__dirname);
  const stack = new AgentAuthStack(app, stackId, {
    env: { account: '123456789012', region: 'us-east-1' },
    webBaseUrl: 'https://c.auth.example.com',
    lambdaAssetPath: assetPath,
    securityEventArchiveAssetPath: assetPath,
    ssfDeliveryAssetPath: assetPath,
    tenantKeyProvisionerAssetPath: assetPath,
    reclaimAssetPath: assetPath,
    recomputeAssetPath: assetPath,
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
    byodEnabled: true,
    kmsTenantGateCapacity: 30,
    kmsTenantGateRefillPerSec: 20,
    ...overrides,
  });
  return Template.fromStack(stack).toJSON();
}

test('production SaaS cannot silently remove or redirect the Region fence', () => {
  assert.throws(
    () => synth([]),
    /production SaaS requires the replay-safe us-east-1\/us-west-2 Region fence/,
  );
  assert.throws(
    () => synth(['eu-west-1']),
    /multi-Region deployment supports only primary us-east-1 and standby us-west-2/,
  );
});

test('disposable multi-Region stacks cannot select another Region pair', () => {
  assert.throws(
    () => synth(['eu-west-1'], false),
    /multi-Region deployment supports only primary us-east-1 and standby us-west-2/,
  );
  assert.doesNotThrow(() => synth([], false));
});

function synthStandby(invitationTtlSecs, withNag = false) {
  const app = new App();
  const assetPath = path.resolve(__dirname);
  const authorityTableNames = Object.fromEntries(
    DURABLE_TABLES.map((prefix) => [
      prefix
        .replace(/Table$/, '')
        .replace(/[A-Z]/g, (letter, offset) =>
          `${offset > 0 ? '_' : ''}${letter.toLowerCase()}`),
      `primary-${prefix.toLowerCase()}`,
    ]),
  );
  authorityTableNames.passkeys = authorityTableNames.passkey;
  delete authorityTableNames.passkey;
  const stack = new AgentAuthStandbyStack(app, 'MultiRegionStandbyTest', {
    env: { account: '123456789012', region: 'us-west-2' },
    lambdaAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    webBaseUrl: 'https://c.auth.example.com',
    saasZone: 'auth.example.com',
    saasControlHost: 'c.auth.example.com',
    tenantIds: ['t1', 't2'],
    authorityTableNames,
    regionControlTableName: 'primary-region-control',
    cloudFrontOriginSecretName:
      'AgentAuthSaas/cloudfront-origin-auth',
    cloudFrontOriginSecondarySecretName:
      'AgentAuthSaas/cloudfront-origin-auth-secondary',
    saasOriginAuthRevision: 'rotation-7',
    runtimeSecretArns: {
      server:
        'arn:aws:secretsmanager:us-west-2:123456789012:secret:server-AbCd12',
      governance_hmac:
        'arn:aws:secretsmanager:us-west-2:123456789012:secret:governance-AbCd12',
      standby_bootstrap_config:
        'arn:aws:secretsmanager:us-west-2:123456789012:secret:bootstrap-AbCd12',
      platform_admin:
        'arn:aws:secretsmanager:us-west-2:123456789012:secret:admin-AbCd12',
      tenant_admin: {
        t1: 'arn:aws:secretsmanager:us-west-2:123456789012:secret:tenant-t1-AbCd12',
        t2: 'arn:aws:secretsmanager:us-west-2:123456789012:secret:tenant-t2-AbCd12',
      },
      scim: {
        t1: 'arn:aws:secretsmanager:us-west-2:123456789012:secret:scim-t1-AbCd12',
        t2: 'arn:aws:secretsmanager:us-west-2:123456789012:secret:scim-t2-AbCd12',
      },
    },
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
    passkeyEnabled: true,
    authzEnabled: true,
    policySet: 'permit(principal, action, resource);',
    byodEnabled: true,
    invitationTtlSecs,
    kmsTenantGateCapacity: 30,
    kmsTenantGateRefillPerSec: 20,
  });
  if (withNag) {
    Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  }
  return {
    stack,
    template: Template.fromStack(stack).toJSON(),
    authorityTableNames,
  };
}

function resourceByPrefix(template, prefix, type) {
  const matches = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith(prefix) && resource.Type === type,
  );
  assert.equal(matches.length, 1, `expected one ${type} with prefix ${prefix}`);
  return matches[0];
}

function policyStatementsForFunction(template, fn) {
  const roleId = fn.Properties.Role['Fn::GetAtt'][0];
  return Object.values(template.Resources)
    .filter(
      (resource) =>
        ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'].includes(resource.Type) &&
        resource.Properties.Roles?.some((role) => role.Ref === roleId),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement);
}

function materializedEnvironment(template, stackName, functionPrefix) {
  const account = '123456789012';
  const region = 'us-east-1';
  const generatedName = (logicalId) => `${stackName}-${logicalId}-${'X'.repeat(13)}`;
  const resolve = (value) => {
    if (typeof value === 'string') {
      return value;
    }
    if (value.Ref) {
      const resource = template.Resources[value.Ref];
      assert.ok(resource, `unresolved environment Ref ${value.Ref}`);
      switch (resource.Type) {
        case 'AWS::DynamoDB::Table':
          return resource.Properties.TableName ?? generatedName(value.Ref);
        case 'AWS::Events::EventBus':
          return resource.Properties.Name;
        case 'AWS::KMS::Key':
          return '00000000-0000-0000-0000-000000000000';
        case 'AWS::SecretsManager::Secret':
          return `arn:aws:secretsmanager:${region}:${account}:secret:${value.Ref}-${'X'.repeat(12)}-${'X'.repeat(6)}`;
        case 'AWS::SQS::Queue':
          return `https://sqs.${region}.amazonaws.com/${account}/${generatedName(value.Ref)}`;
        default:
          assert.fail(`unsupported environment Ref type ${resource.Type}`);
      }
    }
    if (value['Fn::Join']) {
      const [separator, parts] = value['Fn::Join'];
      return parts.map(resolve).join(separator);
    }
    if (value['Fn::GetAtt']) {
      const [logicalId, attribute] = value['Fn::GetAtt'];
      const resource = template.Resources[logicalId];
      if (resource?.Type === 'AWS::ApiGatewayV2::Api' && attribute === 'ApiEndpoint') {
        return `https://${'x'.repeat(10)}.execute-api.${region}.amazonaws.com`;
      }
      assert.fail(`unsupported environment GetAtt ${logicalId}.${attribute}`);
    }
    if (value['Fn::Split']) {
      const [separator, input] = value['Fn::Split'];
      return resolve(input).split(separator);
    }
    if (value['Fn::Select']) {
      const [index, values] = value['Fn::Select'];
      return resolve(values)[index];
    }
    assert.fail(`unsupported environment token ${JSON.stringify(value)}`);
  };

  const [, fn] = resourceByPrefix(
    template,
    functionPrefix,
    'AWS::Lambda::Function',
  );
  return Object.fromEntries(
    Object.entries(fn.Properties.Environment.Variables).map(([name, value]) => [
      name,
      name === 'SERVER_SECRET' ? 'X'.repeat(48) : resolve(value),
    ]),
  );
}

test('primary Auth Lambda environment retains deployment headroom', () => {
  const template = synth(['us-west-2'], true, 'AgentAuthSaas');
  for (const prefix of ['NonTokenFn', 'TokenFn']) {
    const environment = materializedEnvironment(
      template,
      'AgentAuthSaas',
      prefix,
    );
    const bytes = Buffer.byteLength(JSON.stringify(environment));
    assert.ok(
      bytes <= 3_950,
      `${prefix} Lambda environment is ${bytes} bytes; expected at most 3950`,
    );
  }
});

test('SaaS edge credentials are generated, replicated, and kept out of Lambda env', () => {
  const template = synth(['us-west-2'], true, 'AgentAuthSaas');
  const [primarySecretId, primarySecret] = resourceByPrefix(
    template,
    'CloudFrontOriginAuthSecret',
    'AWS::SecretsManager::Secret',
  );
  const [secondarySecretId, secondarySecret] = resourceByPrefix(
    template,
    'CloudFrontOriginAuthSecondarySecret',
    'AWS::SecretsManager::Secret',
  );
  assert.equal(
    primarySecret.Properties.Name,
    'AgentAuthSaas/cloudfront-origin-auth',
  );
  assert.equal(
    secondarySecret.Properties.Name,
    'AgentAuthSaas/cloudfront-origin-auth-secondary',
  );
  for (const secret of [primarySecret, secondarySecret]) {
    assert.equal(secret.Properties.GenerateSecretString.PasswordLength, 48);
    assert.deepEqual(secret.Properties.ReplicaRegions, [
      { Region: 'us-west-2' },
    ]);
  }

  const [, bootstrap] = resourceByPrefix(
    template,
    'RuntimeBootstrapConfig',
    'AWS::SecretsManager::Secret',
  );
  assert.match(
    JSON.stringify(bootstrap.Properties.SecretString),
    new RegExp(`passkey_origin_secret_arn.*${primarySecretId}`),
  );

  const [, authFn] = resourceByPrefix(
    template,
    'NonTokenFn',
    'AWS::Lambda::Function',
  );
  assert.equal(
    authFn.Properties.Environment.Variables
      .AGENT_AUTH_PASSKEY_ORIGIN_SECRET,
    undefined,
  );
  assert.equal(
    authFn.Properties.Environment.Variables
      .AGENT_AUTH_ORIGIN_AUTH_SECONDARY_SECRET_ARN,
    undefined,
  );
  assert.equal(
    authFn.Properties.Environment.Variables
      .AGENT_AUTH_ORIGIN_AUTH_REVISION,
    '1',
  );
  assert.ok(
    policyStatementsForFunction(template, authFn).some((statement) => {
      const actions = [statement.Action].flat();
      return (
        actions.includes('secretsmanager:GetSecretValue') &&
        JSON.stringify(statement.Resource).includes(primarySecretId)
      );
    }),
    'Auth Lambda must read the primary origin credential through Secrets Manager',
  );
  assert.ok(
    policyStatementsForFunction(template, authFn).some((statement) => {
      const actions = [statement.Action].flat();
      return (
        actions.includes('secretsmanager:GetSecretValue') &&
        JSON.stringify(statement.Resource).includes(secondarySecretId)
      );
    }),
    'Auth Lambda must read the secondary origin credential through Secrets Manager',
  );
});

test('SaaS CloudFront injects both slots without storing them in its distribution', () => {
  const template = synth({
    tenantKeyReplicaRegions: ['us-west-2'],
    deployFrontend: true,
    frontendAssetPath: path.resolve(__dirname),
    passkeyEnabled: true,
    saasOriginAuthRevision: 'rotation-7',
  });
  const [primarySecretId] = resourceByPrefix(
    template,
    'CloudFrontOriginAuthSecret',
    'AWS::SecretsManager::Secret',
  );
  const [secondarySecretId] = resourceByPrefix(
    template,
    'CloudFrontOriginAuthSecondarySecret',
    'AWS::SecretsManager::Secret',
  );
  const distribution = Object.values(template.Resources).find(
    (resource) => resource.Type === 'AWS::CloudFront::Distribution',
  );
  assert.ok(distribution);
  const originHeaders = Object.fromEntries(
    distribution.Properties.DistributionConfig.Origins
      .flatMap((origin) => origin.OriginCustomHeaders ?? [])
      .map((header) => [header.HeaderName, header.HeaderValue]),
  );
  assert.ok(
    Object.keys(originHeaders).every(
      (name) => !name.toLowerCase().startsWith('x-agent-auth-origin-auth'),
    ),
    'CloudFront distribution readers must not receive either long-lived credential',
  );
  const behavior =
    distribution.Properties.DistributionConfig.DefaultCacheBehavior;
  assert.equal(behavior.LambdaFunctionAssociations.length, 1);
  assert.equal(
    behavior.LambdaFunctionAssociations[0].EventType,
    'origin-request',
  );
  const edgeFunction = Object.entries(template.Resources).find(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties.Description ===
        'Inject managed SaaS origin credentials without storing them in CloudFront',
  );
  assert.ok(edgeFunction);
  const edgeCode = JSON.stringify(edgeFunction[1].Properties.Code);
  assert.match(edgeCode, new RegExp(primarySecretId));
  assert.match(edgeCode, new RegExp(secondarySecretId));
  assert.match(edgeCode, /rotation-7/);
  assert.match(edgeCode, /GetSecretValueCommand/);
  const edgePolicies = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::IAM::Policy' &&
      JSON.stringify(resource.Properties.PolicyDocument).includes(
        'secretsmanager:GetSecretValue',
      ),
  );
  assert.ok(
    edgePolicies.some((policy) => {
      const document = JSON.stringify(policy.Properties.PolicyDocument);
      return (
        document.includes(primarySecretId) &&
        document.includes(secondarySecretId)
      );
    }),
    'Lambda@Edge must have read access to exactly the two managed slots',
  );
});

test('standby runtime reads both replicated edge credentials and the same revision', () => {
  const { template } = synthStandby();
  const [, authFn] = resourceByPrefix(
    template,
    'NonTokenFn',
    'AWS::Lambda::Function',
  );
  assert.equal(
    authFn.Properties.Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT,
    '0123456789abcdef0123456789abcdef01234567',
  );
  assert.equal(
    authFn.Properties.Environment.Variables
      .AGENT_AUTH_ORIGIN_AUTH_REVISION,
    'rotation-7',
  );
  assert.equal(
    authFn.Properties.Environment.Variables
      .AGENT_AUTH_ORIGIN_AUTH_SECONDARY_SECRET_ARN,
    undefined,
  );
  const policy = policyStatementsForFunction(template, authFn)
    .filter((statement) =>
      [statement.Action]
        .flat()
        .includes('secretsmanager:GetSecretValue'),
    )
    .map((statement) => JSON.stringify(statement.Resource))
    .join('\n');
  assert.match(policy, /cloudfront-origin-auth(?!-secondary)/);
  assert.match(policy, /cloudfront-origin-auth-secondary/);
});

test('primary governance worker environment retains deployment headroom', () => {
  const template = synth(['us-west-2'], true, 'AgentAuthSaas');
  const environment = materializedEnvironment(
    template,
    'AgentAuthSaas',
    'GovernanceWorkerFn',
  );
  const bytes = Buffer.byteLength(JSON.stringify(environment));
  assert.equal(environment.GOVERNANCE_RETENTION_CONFIG, undefined);
  assert.match(
    environment.GOVERNANCE_RETENTION_CONFIG_SECRET_ARN,
    /^arn:aws:secretsmanager:/,
  );
  assert.ok(
    bytes <= 3_950,
    `Governance worker environment is ${bytes} bytes; expected at most 3950`,
  );
});

test('standby Auth Lambda environment retains deployment headroom', () => {
  const { template } = synthStandby();
  for (const prefix of ['NonTokenFn', 'TokenFn']) {
    const environment = materializedEnvironment(
      template,
      'MultiRegionStandbyTest',
      prefix,
    );
    const bytes = Buffer.byteLength(JSON.stringify(environment));
    assert.ok(
      bytes <= 3_950,
      `Standby ${prefix} Lambda environment is ${bytes} bytes; expected at most 3950`,
    );
  }
});

function replicasFor(template, tableLogicalId) {
  return Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'Custom::DynamoDBReplica' &&
      resource.Properties.TableName?.Ref === tableLogicalId,
  );
}

test('c11_1_primary_replicates_only_durable_authority_and_fence', () => {
  const template = synth();

  for (const prefix of DURABLE_TABLES) {
    const [logicalId, table] = resourceByPrefix(
      template,
      prefix,
      'AWS::DynamoDB::Table',
    );
    assert.equal(table.Properties.StreamSpecification.StreamViewType, 'NEW_AND_OLD_IMAGES');
    const replicas = replicasFor(template, logicalId);
    assert.equal(replicas.length, 1, `${prefix} must have exactly one replica`);
    assert.equal(replicas[0].Properties.Region, 'us-west-2');
  }

  for (const prefix of REGION_LOCAL_TABLES) {
    const [logicalId] = resourceByPrefix(
      template,
      prefix,
      'AWS::DynamoDB::Table',
    );
    assert.equal(
      replicasFor(template, logicalId).length,
      0,
      `${prefix} must remain Region-local`,
    );
  }

  const [controlId, control] = resourceByPrefix(
    template,
    'RegionControlTable',
    'AWS::DynamoDB::Table',
  );
  assert.equal(control.DeletionPolicy, 'Retain');
  assert.equal(control.UpdateReplacePolicy, 'Retain');
  assert.equal(replicasFor(template, controlId).length, 1);
});

test('c11_1_runtime_fence_contract', () => {
  const template = synth();
  const [controlId] = resourceByPrefix(
    template,
    'RegionControlTable',
    'AWS::DynamoDB::Table',
  );
  const [adminRuntimeId] = resourceByPrefix(
    template,
    'AdminAuthRuntimeTable',
    'AWS::DynamoDB::Table',
  );
  for (const prefix of ['NonTokenFn', 'TokenFn']) {
    const [, fn] = resourceByPrefix(
      template,
      prefix,
      'AWS::Lambda::Function',
    );
    const env = fn.Properties.Environment.Variables;
    assert.deepEqual(env.REGION_CONTROL_TABLE, { Ref: controlId });
    assert.deepEqual(env.ADMIN_AUTH_RUNTIME_TABLE, { Ref: adminRuntimeId });
  }

  const transactionPolicies = Object.values(template.Resources)
    .filter((resource) =>
      ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'].includes(resource.Type),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement)
    .filter(
      (statement) =>
        JSON.stringify(statement.Resource).includes(controlId) &&
        JSON.stringify(statement.Action).includes('dynamodb:TransactGetItems'),
    );
  assert.equal(
    transactionPolicies.length,
    6,
    'both HTTP runtimes and every authority-writing worker must transact-read Region control',
  );
});

test('c11_1_standby_region_local_contract', () => {
  const { template, authorityTableNames } = synthStandby();
  const tables = Object.entries(template.Resources).filter(
    ([, resource]) => resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.equal(tables.length, REGION_LOCAL_TABLES.length);
  for (const prefix of REGION_LOCAL_TABLES) {
    resourceByPrefix(template, prefix, 'AWS::DynamoDB::Table');
  }
  for (const prefix of DURABLE_TABLES) {
    assert.equal(
      tables.some(([logicalId]) => logicalId.startsWith(prefix)),
      false,
      `${prefix} must be imported instead of created`,
    );
  }

  const [, authFn] = resourceByPrefix(
    template,
    'NonTokenFn',
    'AWS::Lambda::Function',
  );
  const env = authFn.Properties.Environment.Variables;
  assert.equal(env.REGION_CONTROL_TABLE, 'primary-region-control');
  assert.equal(env.CLIENTS_TABLE, authorityTableNames.clients);
  assert.equal(env.GRANTS_TABLE, authorityTableNames.grants);
  assert.ok(env.CODES_TABLE.Ref?.startsWith('CodesTable'));
  assert.ok(env.REFRESH_TABLE.Ref?.startsWith('RefreshTable'));
  assert.ok(env.JTI_TABLE.Ref?.startsWith('JtiTable'));
  assert.ok(env.AUTH_REFS_TABLE.Ref?.startsWith('ClientAuthorityRefsTable'));
});

test('primary stack rejects unreviewed multi-Region pairs', () => {
  assert.throws(
    () => synth({ tenantKeyReplicaRegions: ['eu-west-1'] }),
    /supports only primary us-east-1 and standby us-west-2/,
  );
  assert.throws(
    () =>
      synth({
        env: { account: '123456789012', region: 'eu-central-1' },
      }),
    /supports only primary us-east-1 and standby us-west-2/,
  );
});

test('replica provider table grants stay below IAM managed-policy attachment quotas', () => {
  const template = synth();
  const generatedManagedPolicies = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::IAM::ManagedPolicy' &&
      JSON.stringify(resource.Properties.Description).includes(
        'DynamoDB replication managed policy for table',
      ),
  );
  assert.equal(generatedManagedPolicies.length, (DURABLE_TABLES.length + 1) * 2);
  for (const policy of generatedManagedPolicies) {
    assert.equal(
      policy.Properties.Roles,
      undefined,
      'CDK table-level managed policies must not attach to singleton provider roles',
    );
  }

  const sharedPolicies = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('DynamoDbReplicaProvider') &&
      resource.Type === 'AWS::IAM::Policy',
  );
  assert.equal(sharedPolicies.length, 2);

  const [onEventPolicy] = sharedPolicies
    .filter(([logicalId]) => logicalId.includes('OnEventTablePolicy'))
    .map(([, resource]) => resource);
  const [isCompletePolicy] = sharedPolicies
    .filter(([logicalId]) => logicalId.includes('IsCompleteTablePolicy'))
    .map(([, resource]) => resource);
  assert.ok(onEventPolicy);
  assert.ok(isCompletePolicy);
  assert.deepEqual(
    onEventPolicy.Properties.PolicyDocument.Statement[0].Action,
    'dynamodb:*',
  );
  assert.deepEqual(
    isCompletePolicy.Properties.PolicyDocument.Statement[0].Action,
    'dynamodb:DescribeTable',
  );
  assert.equal(onEventPolicy.Properties.Roles.length, 1);
  assert.equal(isCompletePolicy.Properties.Roles.length, 1);

  const [clientsId] = resourceByPrefix(
    template,
    'ClientsTable',
    'AWS::DynamoDB::Table',
  );
  const [regionControlId] = resourceByPrefix(
    template,
    'RegionControlTable',
    'AWS::DynamoDB::Table',
  );
  const onEventResources =
    onEventPolicy.Properties.PolicyDocument.Statement[0].Resource;
  const isIndexResourceFor = (logicalId) =>
    onEventResources.some((resource) => {
      const rendered = JSON.stringify(resource);
      return rendered.includes(logicalId) && rendered.includes('/index/*');
    });
  assert.equal(isIndexResourceFor(clientsId), true);
  assert.equal(isIndexResourceFor(regionControlId), false);

  const replicaResources = Object.values(template.Resources).filter(
    (resource) => resource.Type === 'Custom::DynamoDBReplica',
  );
  for (const replica of replicaResources) {
    assert.ok(
      replica.DependsOn.some((logicalId) =>
        logicalId.startsWith('DynamoDbReplicaProviderOnEventTablePolicy'),
      ),
    );
    assert.ok(
      replica.DependsOn.some((logicalId) =>
        logicalId.startsWith('DynamoDbReplicaProviderIsCompleteTablePolicy'),
      ),
    );
  }
});

test('replica creation waits for one bootstrap replica before fanning out', () => {
  const template = synth();
  const replicas = Object.entries(template.Resources).filter(
    ([, resource]) => resource.Type === 'Custom::DynamoDBReplica',
  );
  assert.equal(replicas.length, DURABLE_TABLES.length + 1);

  const bootstrapCandidates = replicas.filter(([candidateId]) =>
    replicas.every(
      ([replicaId, replica]) =>
        replicaId === candidateId ||
        replica.DependsOn?.includes(candidateId),
    ),
  );
  assert.equal(
    bootstrapCandidates.length,
    1,
    'one replica must finish bootstrapping the DynamoDB replication service role before the remaining replicas start',
  );
  assert.match(bootstrapCandidates[0][0], /^WorkloadTrustTableReplica/);
});

test('regional runtime is fenced and Admin runtime state uses its local table', () => {
  const template = synth();
  const [controlId] = resourceByPrefix(
    template,
    'RegionControlTable',
    'AWS::DynamoDB::Table',
  );
  const [adminConfigId] = resourceByPrefix(
    template,
    'AdminAuthTable',
    'AWS::DynamoDB::Table',
  );
  const [adminRuntimeId] = resourceByPrefix(
    template,
    'AdminAuthRuntimeTable',
    'AWS::DynamoDB::Table',
  );

  const authFunctions = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('NonTokenFn') &&
      resource.Type === 'AWS::Lambda::Function',
  );
  assert.equal(authFunctions.length, 1);
  const authEnv = authFunctions[0][1].Properties.Environment.Variables;
  assert.equal(authEnv.AGENT_AUTH_HOST, undefined);
  assert.equal(authEnv.AGENT_AUTH_REGION_ID, undefined);
  assert.deepEqual(authEnv.REGION_CONTROL_TABLE, { Ref: controlId });
  assert.deepEqual(authEnv.ADMIN_AUTH_TABLE, { Ref: adminConfigId });
  assert.deepEqual(authEnv.ADMIN_AUTH_RUNTIME_TABLE, { Ref: adminRuntimeId });

  const ssfFunctions = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith('SsfDeliveryFn') &&
      resource.Type === 'AWS::Lambda::Function',
  );
  assert.equal(ssfFunctions.length, 1);
  const ssfEnv = ssfFunctions[0][1].Properties.Environment.Variables;
  assert.equal(ssfEnv.AGENT_AUTH_REGION_ID, 'us-east-1');
  assert.equal(ssfEnv.REGION_CONTROL_TABLE, undefined);

  const policies = Object.values(template.Resources)
    .filter((resource) =>
      ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'].includes(resource.Type),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement);
  const transactionPolicies = policies.filter(
      (statement) =>
        JSON.stringify(statement.Resource).includes(controlId) &&
        JSON.stringify(statement.Action).includes('dynamodb:TransactGetItems'),
  );
  assert.equal(
    transactionPolicies.length,
    6,
    'Both HTTP runtimes and every authority-writing worker must transact-read Region control',
  );

  for (const prefix of [
    'TenantKeyProvisionerFn',
    'ReclaimFn',
    'RecomputeFn',
  ]) {
    const [, worker] = resourceByPrefix(
      template,
      prefix,
      'AWS::Lambda::Function',
    );
    const workerEnv = worker.Properties.Environment.Variables;
    assert.equal(workerEnv.AGENT_AUTH_REGION_ID, undefined);
    assert.deepEqual(workerEnv.REGION_CONTROL_TABLE, { Ref: controlId });
  }
});

test('control bootstrap is create-only revision one and outputs classify tables', () => {
  const template = synth();
  const [controlId] = resourceByPrefix(
    template,
    'RegionControlTable',
    'AWS::DynamoDB::Table',
  );
  const [, bootstrap] = resourceByPrefix(
    template,
    'RegionControlBootstrap',
    'Custom::AWS',
  );
  const create = JSON.stringify(bootstrap.Properties.Create);
  assert.match(create, /\\"action\\":\\"transactWriteItems\\"/);
  assert.match(create, /attribute_not_exists\(region_id\)/);
  assert.match(create, /\\"revision\\":\{\\"N\\":\\"1\\"\}/);
  assert.match(create, /\\"active\\":\{\\"BOOL\\":true\}/);
  assert.match(create, /fence#us-east-1/);
  assert.equal(bootstrap.Properties.Update, undefined);

  const [, bootstrapPolicy] = resourceByPrefix(
    template,
    'RegionControlBootstrapCustomResourcePolicy',
    'AWS::IAM::Policy',
  );
  assert.deepEqual(bootstrapPolicy.Properties.PolicyDocument.Statement, [
    {
      Action: 'dynamodb:PutItem',
      Effect: 'Allow',
      Resource: { 'Fn::GetAtt': [controlId, 'Arn'] },
    },
  ]);

  assert.deepEqual(template.Outputs.RegionId, { Value: 'us-east-1' });
  assert.deepEqual(template.Outputs.DeploymentCommit, {
    Value: '0123456789abcdef0123456789abcdef01234567',
  });
  assert.deepEqual(template.Outputs.FailoverReplicaRegions, {
    Value: '["us-west-2"]',
  });
  assert.ok(template.Outputs.RegionControlTableName);
  assert.ok(template.Outputs.ReplicatedAuthorityTableNames);
  assert.ok(template.Outputs.ReplicatedRuntimeSecretArns);
  assert.match(
    JSON.stringify(template.Outputs.ReplicatedRuntimeSecretArns),
    /standby_bootstrap_config/,
  );
  assert.ok(template.Outputs.RegionLocalTableNames);
  assert.ok(template.Outputs.AdminAuthRuntimeTableName);
  assert.ok(template.Outputs.PrimaryApiHost);
});

test('runtime Secrets replicate with authority while rollback sources stay primary-only', () => {
  const template = synth();
  const replicatedPrefixes = [
    'ServerSecret',
    'GovernanceHmacSecret',
    'StandbyRuntimeBootstrapConfig',
    'AdminCredentialSet',
    'TenantAdminCredentialSett1',
    'TenantAdminCredentialSett2',
    'ScimCredentialSett1',
    'ScimCredentialSett2',
  ];
  for (const prefix of replicatedPrefixes) {
    const [, secret] = resourceByPrefix(
      template,
      prefix,
      'AWS::SecretsManager::Secret',
    );
    assert.deepEqual(secret.Properties.ReplicaRegions, [
      { Region: 'us-west-2' },
    ]);
  }
  const [, standbyBootstrap] = resourceByPrefix(
    template,
    'StandbyRuntimeBootstrapConfig',
    'AWS::SecretsManager::Secret',
  );
  const standbyBootstrapDocument = JSON.stringify(
    standbyBootstrap.Properties.SecretString,
  );
  assert.match(standbyBootstrapDocument, /us-west-2/);
  assert.doesNotMatch(
    standbyBootstrapDocument,
    /secretsmanager:us-east-1/,
  );
  assert.doesNotMatch(standbyBootstrapDocument, /"Fn::Split":\["-"/);
  for (const prefix of ['AdminToken', 'ScimTokent1', 'ScimTokent2']) {
    const [, secret] = resourceByPrefix(
      template,
      prefix,
      'AWS::SecretsManager::Secret',
    );
    assert.equal(secret.Properties.ReplicaRegions, undefined);
  }
});

test('standby imports durable authority and creates only Region-local replay tables', () => {
  const { template, authorityTableNames } = synthStandby();
  const tables = Object.entries(template.Resources).filter(
    ([, resource]) => resource.Type === 'AWS::DynamoDB::Table',
  );
  assert.equal(tables.length, REGION_LOCAL_TABLES.length);
  for (const prefix of REGION_LOCAL_TABLES) {
    resourceByPrefix(template, prefix, 'AWS::DynamoDB::Table');
  }
  for (const prefix of DURABLE_TABLES) {
    assert.equal(
      tables.some(([logicalId]) => logicalId.startsWith(prefix)),
      false,
      `${prefix} must be imported instead of created`,
    );
  }

  const [authFnId, authFn] = resourceByPrefix(
    template,
    'NonTokenFn',
    'AWS::Lambda::Function',
  );
  assert.ok(authFnId);
  const env = authFn.Properties.Environment.Variables;
  assert.equal(env.AGENT_AUTH_HOST, undefined);
  assert.equal(env.AGENT_AUTH_REGION_ID, undefined);
  assert.equal(env.REGION_CONTROL_TABLE, 'primary-region-control');
  assert.equal(env.CLIENTS_TABLE, authorityTableNames.clients);
  assert.equal(env.GRANTS_TABLE, authorityTableNames.grants);
  assert.ok(env.INVITATIONS_TABLE.Ref?.startsWith('InvitationsTable'));
  assert.equal(env.AGENT_AUTH_INVITATION_TTL_SECS, undefined);
  assert.equal(env.SECURITY_EVENTS_TABLE, authorityTableNames.security_events);
  assert.equal(env.AGENT_AUTH_SSF_MANAGEMENT_ENABLED, '0');
  assert.equal(env.TENANT_KEYS_TABLE, authorityTableNames.tenant_keys);
  assert.equal(env.GOVERNANCE_TABLE, authorityTableNames.governance);
  assert.equal(
    env.GOVERNANCE_SUPPRESSION_TABLE,
    authorityTableNames.governance_suppression,
  );
  assert.equal(
    env.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN,
    'arn:aws:secretsmanager:us-west-2:123456789012:secret:bootstrap-AbCd12',
  );
  assert.match(env.AGENT_AUTH_BOOTSTRAP_REVISION, /^[0-9a-f]{16}$/);
  assert.equal(env.GOVERNANCE_HMAC_KEY, undefined);
  assert.equal(env.AGENT_AUTH_TENANT_RESIDENCY, undefined);
  assert.equal(env.AGENT_AUTH_TENANT_KEY_COMMANDS_DISABLED, '1');
  assert.equal(env.TENANT_KEY_OPERATIONS_QUEUE_URL, undefined);
  assert.deepEqual(template.Outputs.DeploymentCommit, {
    Value: '0123456789abcdef0123456789abcdef01234567',
  });
  assert.equal(env.ADMIN_CREDENTIAL_SECRET_ARN, undefined);
  assert.equal(env.SAAS_TENANTS, undefined);
  assert.equal(env.TENANT_ADMIN_SECRET_ARNS, undefined);
  assert.equal(env.SCIM_TENANT_SECRET_ARNS, undefined);
});

test('standby can atomically finalize codes and authorization sessions', () => {
  const { template } = synthStandby();
  const [, authFn] = resourceByPrefix(
    template,
    'NonTokenFn',
    'AWS::Lambda::Function',
  );
  const [codesId] = resourceByPrefix(
    template,
    'CodesTable',
    'AWS::DynamoDB::Table',
  );
  const [authzSessionsId] = resourceByPrefix(
    template,
    'AuthzSessionsTable',
    'AWS::DynamoDB::Table',
  );
  const transactionStatements = policyStatementsForFunction(template, authFn)
    .filter((statement) =>
      [statement.Action]
        .flat()
        .includes('dynamodb:TransactWriteItems'),
    );
  assert.ok(transactionStatements.length >= 1);
  const resources = JSON.stringify(
    transactionStatements.flatMap((statement) => [statement.Resource].flat()),
  );
  for (const tableId of [codesId, authzSessionsId]) {
    assert.match(
      resources,
      new RegExp(`"Fn::GetAtt":\\["${tableId}","Arn"\\]`),
      `standby transaction policy must include ${tableId}`,
    );
  }
});

test('standby security-event ingress has an encrypted bounded-retry DLQ', () => {
  const { template } = synthStandby();
  const [queueId, queue] = resourceByPrefix(
    template,
    'SecurityEventIngressQueue',
    'AWS::SQS::Queue',
  );
  const [dlqId, dlq] = resourceByPrefix(
    template,
    'SecurityEventIngressDlq',
    'AWS::SQS::Queue',
  );

  assert.ok(queueId);
  assert.equal(queue.Properties.SqsManagedSseEnabled, true);
  assert.equal(dlq.Properties.SqsManagedSseEnabled, true);
  assert.deepEqual(queue.Properties.RedrivePolicy, {
    deadLetterTargetArn: { 'Fn::GetAtt': [dlqId, 'Arn'] },
    maxReceiveCount: 5,
  });
  assert.ok(template.Outputs.SecurityEventIngressQueueUrl);
  assert.ok(template.Outputs.SecurityEventIngressDlqUrl);
});

test('standby runtime wildcard policies stay action, tag, and prefix constrained', () => {
  const { template } = synthStandby();
  const [, signingPolicy] = resourceByPrefix(
    template,
    'SigningKeyRuntimePolicy',
    'AWS::IAM::Policy',
  );
  const [, credentialPolicy] = resourceByPrefix(
    template,
    'AdminCredentialRuntimePolicy',
    'AWS::IAM::Policy',
  );
  const actions = (statement) =>
    Array.isArray(statement.Action) ? statement.Action : [statement.Action];

  assert.equal(signingPolicy.Properties.Roles.length, 2);
  assert.match(
    JSON.stringify(signingPolicy.Properties.Roles),
    /NonTokenFnServiceRole/,
  );
  assert.match(JSON.stringify(signingPolicy.Properties.Roles), /TokenFnServiceRole/);
  const [signingStatement] =
    signingPolicy.Properties.PolicyDocument.Statement;
  assert.deepEqual(new Set(actions(signingStatement)), new Set([
    'kms:GetPublicKey',
    'kms:Sign',
  ]));
  assert.equal(
    signingStatement.Condition.StringEquals[
      'aws:ResourceTag/agent-auth-managed'
    ],
    'true',
  );
  assert.match(
    JSON.stringify(signingStatement.Resource),
    /:kms:us-west-2:123456789012:key\/\*/,
  );

  assert.equal(credentialPolicy.Properties.Roles.length, 1);
  assert.match(
    JSON.stringify(credentialPolicy.Properties.Roles[0]),
    /NonTokenFnServiceRole/,
  );
  const credentialStatements =
    credentialPolicy.Properties.PolicyDocument.Statement;
  const dynamicSecretStatement = credentialStatements.find(
    (statement) =>
      actions(statement).includes('secretsmanager:GetSecretValue') &&
      JSON.stringify(statement.Resource).includes('agent-auth/federation/'),
  );
  assert.ok(dynamicSecretStatement);
  assert.deepEqual(dynamicSecretStatement.Resource, [
    'arn:aws:secretsmanager:us-west-2:123456789012:secret:agent-auth/federation/*',
    'arn:aws:secretsmanager:us-west-2:123456789012:secret:agent-auth/admin-oidc/*',
  ]);
  const versionStageStatement = credentialStatements.find((statement) =>
    actions(statement).includes('secretsmanager:UpdateSecretVersionStage'),
  );
  assert.ok(versionStageStatement);
  assert.deepEqual(
    versionStageStatement.Condition.StringEquals[
      'secretsmanager:VersionStage'
    ],
    ['AGENTAUTH_VALIDATED', 'AGENTAUTH_ROLLBACK_PENDING'],
  );
});

test('standby passes the AWS Solutions checks', () => {
  const { stack } = synthStandby(undefined, true);
  Annotations.fromStack(stack).hasNoError('*', Match.anyValue());
});

test('standby validates and propagates invitation validity', () => {
  const { template } = synthStandby(600);
  const [, authFn] = resourceByPrefix(
    template,
    'NonTokenFn',
    'AWS::Lambda::Function',
  );
  assert.equal(
    authFn.Properties.Environment.Variables.AGENT_AUTH_INVITATION_TTL_SECS,
    '600',
  );
  assert.throws(() => synthStandby(299), /invitationTtlSecs/);
  assert.throws(() => synthStandby(604_801), /invitationTtlSecs/);
});

test('standby has no edge, backup, irreversible migration, archive, or key-provisioner resources', () => {
  const { template } = synthStandby();
  const forbiddenTypes = new Set([
    'AWS::Backup::BackupPlan',
    'AWS::Backup::BackupSelection',
    'AWS::Backup::BackupVault',
    'AWS::CloudFront::Distribution',
    'AWS::S3::Bucket',
    'AWS::SecretsManager::Secret',
  ]);
  for (const resource of Object.values(template.Resources)) {
    assert.equal(
      forbiddenTypes.has(resource.Type),
      false,
      `standby must not create ${resource.Type}`,
    );
  }
  for (const logicalId of Object.keys(template.Resources)) {
    assert.doesNotMatch(
      logicalId,
      /(TenantKeyProvisioner|^CredentialMigration|RecoveryBackup|SecurityEventArchive|Frontend)/,
    );
    assert.doesNotMatch(logicalId, /^TenantKeyOperationsQueue/);
  }
  const lambdas = Object.entries(template.Resources).filter(
    ([, resource]) => resource.Type === 'AWS::Lambda::Function',
  );
  assert.equal(lambdas.length, 3);
  assert.ok(
    lambdas.some(([logicalId]) => logicalId.startsWith('NonTokenFn')),
  );
  assert.ok(lambdas.some(([logicalId]) => logicalId.startsWith('TokenFn')));
  assert.ok(
    lambdas.some(([logicalId]) =>
      logicalId.startsWith('AuthorityReferenceMigrationFn'),
    ),
  );
  assert.deepEqual(template.Outputs.RegionId, { Value: 'us-west-2' });
  assert.deepEqual(template.Outputs.RegionControlTableName, {
    Value: 'primary-region-control',
  });
});
