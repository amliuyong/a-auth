const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

let stackCounter = 0;

function stackWith(overrides = {}) {
  const app = new App();
  stackCounter += 1;
  return new AgentAuthStack(app, `EmaConfig${stackCounter}`, {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    credentialMigrationAssetPath: path.resolve(__dirname),
    tenantResidency: tenantResidency(),
    deployFrontend: false,
    ...overrides,
  });
}

function emaDeployment(stack) {
  const template = Template.fromStack(stack).toJSON();
  const functions = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::Lambda::Function' &&
      ['non_token', 'token'].includes(
        resource.Properties?.Environment?.Variables?.SCOPE,
      ),
  );
  assert.deepEqual(
    functions
      .map((resource) => resource.Properties.Environment.Variables.SCOPE)
      .sort(),
    ['non_token', 'token'],
  );
  const secretEntries = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::SecretsManager::Secret' &&
      resource.Properties?.Description ===
        'Deployment-owned tenant-scoped EMA trust policy configuration',
  );
  assert.equal(secretEntries.length, 1);
  const [emaSecretId, emaSecret] = secretEntries[0];
  const secrets = [emaSecret];
  // The EMA Secret reference rides in the runtime bootstrap document, never in
  // the 4 KiB Lambda environment.
  for (const resource of functions) {
    assert.equal(
      resource.Properties.Environment.Variables.AGENT_AUTH_EMA_POLICIES_SECRET_ARN,
      undefined,
    );
    assert.ok(
      resource.Properties.Environment.Variables.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN,
    );
  }
  const bootstrap = Object.values(template.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::SecretsManager::Secret' &&
      resource.Properties?.Description ===
        'Deployment-owned Agent Auth governance and credential bootstrap configuration',
  );
  assert.equal(bootstrap.length, 1);
  const bootstrapDocument = JSON.stringify(bootstrap[0].Properties.SecretString);
  assert.match(bootstrapDocument, /ema_policies_secret_arn/);
  assert.ok(bootstrapDocument.includes(emaSecretId));
  return {
    environments: functions.map(
      (resource) => resource.Properties.Environment.Variables,
    ),
    environment: functions.find(
      (resource) =>
        resource.Properties.Environment.Variables.SCOPE === 'non_token',
    ).Properties.Environment.Variables,
    secretString: secrets[0].Properties.SecretString,
  };
}

test('EMA policy can be staged while capability remains disabled', () => {
  const policies = JSON.stringify([{ tenant: 'default', policy: { policy_id: 'test' } }]);
  const { environment, environments, secretString } = emaDeployment(
    stackWith({ emaPolicies: policies }),
  );
  assert.equal(secretString, policies);
  for (const runtimeEnvironment of environments) {
    assert.equal(runtimeEnvironment.AGENT_AUTH_EMA_POLICIES, undefined);
    assert.equal(runtimeEnvironment.AGENT_AUTH_EMA_ENABLED, undefined);
  }
  assert.equal(environment.SCOPE, 'non_token');
});

test('c13_1_ema_deployment_requires_and_injects_complete_runtime_configuration', () => {
  const policies = JSON.stringify([{ tenant: 'default', policy: { policy_id: 'test' } }]);
  const stack = stackWith({
    emaEnabled: true,
    emaPolicies: policies,
    phase: 'p2',
    deploymentCommit: 'a'.repeat(40),
  });
  const { environment, environments, secretString } = emaDeployment(stack);
  for (const runtimeEnvironment of environments) {
    assert.equal(runtimeEnvironment.AGENT_AUTH_EMA_ENABLED, '1');
    assert.equal(runtimeEnvironment.AGENT_AUTH_PHASE, 'p2');
    assert.equal(runtimeEnvironment.AGENT_AUTH_DEPLOYMENT_COMMIT, 'a'.repeat(40));
    assert.ok(runtimeEnvironment.JTI_TABLE);
  }
  assert.equal(secretString, policies);
  assert.equal(environment.AGENT_AUTH_EMA_POLICIES, undefined);
  assert.equal(environment.SCOPE, 'non_token');
  Template.fromStack(stack).hasOutput('DeploymentCommit', {
    Value: 'a'.repeat(40),
  });
  Template.fromStack(stack).hasOutput('AuthFnName', {});
  Template.fromStack(stack).hasOutput('TokenFnName', {});

  assert.throws(() => stackWith({ emaEnabled: true }), /requires non-empty emaPolicies/);
  assert.throws(() => stackWith({ emaPolicies: '{}' }), /non-empty JSON array/);
  assert.throws(
    () =>
      stackWith({
        emaPolicies: JSON.stringify([{ policy: 'x'.repeat(65_536) }]),
      }),
    /64 KiB Secrets Manager value limit/,
  );
  assert.throws(
    () =>
      stackWith({
        emaEnabled: true,
        emaPolicies: '[{}]',
        deploymentCommit: undefined,
      }),
    /full lowercase Git SHA/,
  );
  assert.throws(
    () => stackWith({ deploymentCommit: 'caller-reported' }),
    /full lowercase Git SHA/,
  );
  assert.throws(
    () =>
      stackWith({
        emaEnabled: true,
        emaPolicies: '[{}]',
        phase: 'p1',
        deploymentCommit: 'a'.repeat(40),
      }),
    /requires phase p2/,
  );
});
