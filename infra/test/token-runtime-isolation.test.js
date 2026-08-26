const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App, Aspects } = require('aws-cdk-lib');
const { Annotations, Template } = require('aws-cdk-lib/assertions');
const { AwsSolutionsChecks } = require('cdk-nag');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const {
  AgentAuthStandbyStack,
} = require('../dist/lib/agent-auth-standby-stack');

const COMMIT = '0123456789abcdef0123456789abcdef01234567';

function primaryTemplate(withNag = false) {
  const app = new App();
  const assetPath = path.resolve(__dirname);
  const stack = new AgentAuthStack(app, 'TokenIsolationPrimary', {
    env: { account: '123456789012', region: 'us-east-1' },
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: COMMIT,
    lambdaAssetPath: assetPath,
    securityEventArchiveAssetPath: assetPath,
    ssfDeliveryAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    deployFrontend: false,
  });
  if (withNag) {
    Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  }
  return { stack, template: Template.fromStack(stack).toJSON() };
}

function standbyTemplate(withNag = false) {
  const app = new App();
  const assetPath = path.resolve(__dirname);
  const stack = new AgentAuthStandbyStack(app, 'TokenIsolationStandby', {
    env: { account: '123456789012', region: 'us-west-2' },
    lambdaAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    deploymentCommit: COMMIT,
    webBaseUrl: 'https://c.auth.example.com',
    saasZone: 'auth.example.com',
    saasControlHost: 'c.auth.example.com',
    tenantIds: ['t1'],
    authorityTableNames: {
      clients: 'primary-clients',
      workload_trust: 'primary-workload-trust',
      grants: 'primary-grants',
      federation_config: 'primary-federation-config',
      admin_auth: 'primary-admin-auth',
      passkeys: 'primary-passkeys',
      security_events: 'primary-security-events',
      users: 'primary-users',
      attribute_namespaces: 'primary-attribute-namespaces',
      federation_attribute_mappings: 'primary-federation-attribute-mappings',
      scim_groups: 'primary-scim-groups',
      password_credentials: 'primary-password-credentials',
      domain_map: 'primary-domain-map',
      tenant_keys: 'primary-tenant-keys',
      governance: 'primary-governance',
      governance_suppression: 'primary-governance-suppression',
    },
    regionControlTableName: 'primary-region-control',
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
      },
      scim: {
        t1: 'arn:aws:secretsmanager:us-west-2:123456789012:secret:scim-t1-AbCd12',
      },
    },
    cloudFrontOriginSecretName:
      'AgentAuthSaas/cloudfront-origin-auth',
    cloudFrontOriginSecondarySecretName:
      'AgentAuthSaas/cloudfront-origin-auth-secondary',
    saasOriginAuthRevision: 'rotation-7',
    tenantResidency: {
      t1: {
        jurisdiction: 'us',
        allowed_regions: ['us-east-1', 'us-west-2'],
        governance_region: 'us-east-1',
      },
    },
  });
  if (withNag) {
    Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  }
  return { stack, template: Template.fromStack(stack).toJSON() };
}

function resourceByPrefix(template, prefix, type) {
  const matches = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith(prefix) && resource.Type === type,
  );
  assert.equal(matches.length, 1, `expected one ${type} with prefix ${prefix}`);
  return matches[0];
}

function runtimeByScope(template, scope) {
  const matches = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.SCOPE === scope,
  );
  assert.equal(matches.length, 1, `expected one ${scope} runtime`);
  return matches[0];
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

function actions(statement) {
  return Array.isArray(statement.Action)
    ? statement.Action
    : [statement.Action];
}

function resources(statement) {
  return Array.isArray(statement.Resource)
    ? statement.Resource
    : [statement.Resource];
}

function hasKeyActions(statements, keyLogicalId, expectedActions) {
  return statements.some(
    (statement) =>
      expectedActions.every((action) => actions(statement).includes(action)) &&
      resources(statement).some((resource) =>
        JSON.stringify(resource).includes(keyLogicalId),
      ),
  );
}

function sensitiveKeyActions(statements, keyLogicalId) {
  const sensitiveActions = new Set(['kms:GenerateDataKey', 'kms:Decrypt']);
  return new Set(
    statements.flatMap((statement) => {
      const applies = resources(statement).some(
        (resource) =>
          resource === '*' ||
          JSON.stringify(resource).includes(keyLogicalId),
      );
      return applies
        ? actions(statement).filter((action) => sensitiveActions.has(action))
        : [];
    }),
  );
}

function actionsForResource(statements, resourceLogicalId) {
  return new Set(
    statements.flatMap((statement) => {
      const applies = resources(statement).some((resource) =>
        JSON.stringify(resource).includes(resourceLogicalId),
      );
      return applies ? actions(statement) : [];
    }),
  );
}

function assertRoutesAndKeys(template) {
  const [authId, authFn] = runtimeByScope(template, 'non_token');
  const [tokenId, tokenFn] = runtimeByScope(template, 'token');
  assert.match(authId, /^NonTokenFn/);
  const [legacyGraceKeyId] = resourceByPrefix(
    template,
    'GraceEnvelopeKey',
    'AWS::KMS::Key',
  );
  const [graceKeyId] = resourceByPrefix(
    template,
    'TokenGraceEnvelopeKey',
    'AWS::KMS::Key',
  );
  const [cibaKeyId] = resourceByPrefix(
    template,
    'CibaNotificationEnvelopeKey',
    'AWS::KMS::Key',
  );
  const [graceTableId] = resourceByPrefix(
    template,
    'GraceTable',
    'AWS::DynamoDB::Table',
  );
  assert.notEqual(legacyGraceKeyId, graceKeyId);
  assert.notEqual(legacyGraceKeyId, cibaKeyId);
  assert.notEqual(graceKeyId, cibaKeyId);
  assert.equal(authFn.Properties.Environment.Variables.GRACE_KMS_KEY_ID, undefined);
  assert.ok(tokenFn.Properties.Environment.Variables.GRACE_KMS_KEY_ID);
  assert.equal(
    authFn.Properties.Environment.Variables.CIBA_KMS,
    tokenFn.Properties.Environment.Variables.CIBA_KMS,
  );
  assert.match(authFn.Properties.Environment.Variables.CIBA_KMS, /^alias\/c-/);

  const authStatements = policyStatementsForFunction(template, authFn);
  const tokenStatements = policyStatementsForFunction(template, tokenFn);
  const keyActions = ['kms:GenerateDataKey', 'kms:Decrypt'];
  assert.equal(
    hasKeyActions(authStatements, legacyGraceKeyId, keyActions),
    false,
  );
  assert.equal(
    hasKeyActions(tokenStatements, legacyGraceKeyId, keyActions),
    false,
  );
  assert.deepEqual(
    [...sensitiveKeyActions(authStatements, graceKeyId)].sort(),
    [],
  );
  assert.deepEqual(
    [...sensitiveKeyActions(tokenStatements, graceKeyId)].sort(),
    [...keyActions].sort(),
  );
  assert.equal(hasKeyActions(authStatements, cibaKeyId, keyActions), true);
  assert.equal(hasKeyActions(tokenStatements, cibaKeyId, keyActions), true);
  assert.deepEqual(
    [...actionsForResource(authStatements, graceTableId)].sort(),
    ['dynamodb:DeleteItem', 'dynamodb:Query'],
  );
  const tokenGraceActions = actionsForResource(tokenStatements, graceTableId);
  for (const action of [
    'dynamodb:BatchWriteItem',
    'dynamodb:DeleteItem',
    'dynamodb:DescribeTable',
    'dynamodb:GetItem',
    'dynamodb:PutItem',
    'dynamodb:Query',
    'dynamodb:Scan',
    'dynamodb:UpdateItem',
  ]) {
    assert.equal(
      tokenGraceActions.has(action),
      true,
      `token runtime is missing ${action} on GraceTable`,
    );
  }

  assert.equal(
    authFn.Properties.Environment.Variables.SCOPE,
    'non_token',
  );
  assert.equal(
    tokenFn.Properties.Environment.Variables.SCOPE,
    'token',
  );

  const integrations = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::ApiGatewayV2::Integration',
  );
  const integrationFor = (fnId) => {
    const matches = integrations.filter(([, integration]) =>
      JSON.stringify(integration.Properties.IntegrationUri).includes(fnId),
    );
    assert.equal(matches.length, 1, `expected one integration for ${fnId}`);
    return matches[0][0];
  };
  const authIntegrationId = integrationFor(authId);
  const tokenIntegrationId = integrationFor(tokenId);
  const routeFor = (routeKey) => {
    const matches = Object.entries(template.Resources).filter(
      ([, resource]) =>
        resource.Type === 'AWS::ApiGatewayV2::Route' &&
        resource.Properties.RouteKey === routeKey,
    );
    assert.equal(matches.length, 1, `expected one ${routeKey} route`);
    return matches[0];
  };
  const [postTokenRouteId, postTokenRoute] = routeFor('POST /token');
  const [optionsTokenRouteId, optionsTokenRoute] = routeFor('OPTIONS /token');
  const [, proxyRoute] = routeFor('ANY /{proxy+}');
  assert.match(
    JSON.stringify(postTokenRoute.Properties.Target),
    new RegExp(tokenIntegrationId),
  );
  assert.match(
    JSON.stringify(optionsTokenRoute.Properties.Target),
    new RegExp(tokenIntegrationId),
  );
  assert.match(
    JSON.stringify(proxyRoute.Properties.Target),
    new RegExp(authIntegrationId),
  );
  const proxyDependencies = Array.isArray(proxyRoute.DependsOn)
    ? proxyRoute.DependsOn
    : [proxyRoute.DependsOn].filter(Boolean);
  assert.ok(proxyDependencies.includes(postTokenRouteId));
  assert.ok(proxyDependencies.includes(optionsTokenRouteId));
}

test('c3_4_primary_token_runtime_owns_grace_key_and_exact_routes', () => {
  assertRoutesAndKeys(primaryTemplate().template);
});

test('c3_4_standby_preserves_token_runtime_and_key_boundary', () => {
  assertRoutesAndKeys(standbyTemplate().template);
});

test('primary and standby token isolation pass cdk-nag', () => {
  for (const factory of [primaryTemplate, standbyTemplate]) {
    const { stack } = factory(true);
    const errors = Annotations.fromStack(stack).findError('*', '*');
    assert.deepEqual(errors, []);
  }
});
