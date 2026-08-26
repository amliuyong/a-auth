const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const {
  CredentialMigrationStack,
} = require('../dist/lib/credential-migration-stack');
const {
  devAuthConfig,
  saasAuthConfig,
} = require('../dist/lib/deployment-auth-config');
const { tenantResidency } = require('./tenant-residency-fixture');

function authEnvironment(props) {
  const app = new App();
  const stack = new AgentAuthStack(app, 'DcrLoginConfigTest', {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    credentialMigrationAssetPath: path.resolve(__dirname),
    deployFrontend: false,
    tenantResidency: tenantResidency(),
    ...props,
  });
  const template = Template.fromStack(stack).toJSON();
  const authFunctions = Object.entries(template.Resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.SCOPE === 'non_token' &&
      resource.Properties?.Environment?.Variables?.USERS_TABLE,
  );
  assert.equal(authFunctions.length, 1, 'expected exactly one main Auth Lambda');
  return authFunctions[0][1].Properties.Environment.Variables;
}

test('open DCR does not enable placeholder login', () => {
  const env = authEnvironment({ dcrMode: 'open' });
  assert.equal(env.AGENT_AUTH_DCR_MODE, 'open');
  assert.equal(env.AGENT_AUTH_ALLOW_LOGIN_PLACEHOLDER, undefined);
});

test('placeholder login does not configure DCR', () => {
  const env = authEnvironment({ allowLoginPlaceholder: true });
  assert.equal(env.AGENT_AUTH_ALLOW_LOGIN_PLACEHOLDER, '1');
  assert.equal(env.AGENT_AUTH_DCR_MODE, undefined);
  assert.equal(env.INITIAL_ACCESS_TOKENS, undefined);
  assert.ok(env.INITIAL_ACCESS_TOKENS_TABLE);
});

test('ticketed DCR uses the managed verifier ledger and no static plaintext set', () => {
  const env = authEnvironment({ dcrMode: 'initial_access_token' });
  assert.equal(env.AGENT_AUTH_DCR_MODE, 'initial_access_token');
  assert.ok(env.INITIAL_ACCESS_TOKENS_TABLE);
  assert.equal(env.INITIAL_ACCESS_TOKENS, undefined);
});

test('c12_1_irreversible_credential_migration_is_post_deploy', () => {
  const app = new App();
  const stack = new AgentAuthStack(app, 'CredentialMigrationTest', {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    credentialMigrationAssetPath: path.resolve(__dirname),
    deployFrontend: false,
    tenantResidency: tenantResidency(),
  });
  const migrationStack = new CredentialMigrationStack(
    app,
    'CredentialMigrationRunnerTest',
    { onEventHandler: stack.credentialMigrationHandler },
  );
  const template = Template.fromStack(stack).toJSON();
  const migrationTemplate = Template.fromStack(migrationStack).toJSON();
  const functions = Object.values(template.Resources).filter(
    (resource) => resource.Type === 'AWS::Lambda::Function',
  );
  const auth = functions.find(
    (resource) => resource.Properties?.Environment?.Variables?.USERS_TABLE,
  );
  const migration = functions.find(
    (resource) =>
      resource.Properties?.Environment?.Variables?.CLIENTS_TABLE &&
      !resource.Properties?.Environment?.Variables?.USERS_TABLE,
  );
  assert.ok(auth);
  assert.ok(migration);
  assert.equal(
    migration.Properties.Environment.Variables.SAAS_TENANTS,
    undefined,
  );
  assert.equal(
    auth.Properties.Environment.Variables.AGENT_AUTH_MIGRATE_LEGACY_CREDENTIALS,
    undefined,
  );
  const servingCustomResources = Object.values(template.Resources).filter(
    (resource) => resource.Type === 'AWS::CloudFormation::CustomResource',
  );
  assert.ok(
    servingCustomResources.some(
      (resource) =>
        resource.Properties?.MigrationVersion === 'admin-scim-credential-set-v3-copy',
    ),
    'serving stack may run only the rollback-safe Admin/SCIM Secret copy',
  );
  assert.equal(
    servingCustomResources.some(
      (resource) =>
        resource.Properties?.MigrationVersion === 'credential-verifier-v1',
    ),
    false,
    'irreversible client/DCR migration must stay out of the serving stack',
  );
  assert.equal(
    Object.values(migrationTemplate.Resources).filter(
      (resource) =>
        resource.Type === 'AWS::CloudFormation::CustomResource' &&
        resource.Properties?.MigrationVersion === 'credential-verifier-v1',
    ).length,
    1,
    'post-deploy stack must run exactly the irreversible credential verifier migration',
  );
});

test('deployment entry mapping isolates Dev settings from SaaS', () => {
  const env = {
    AGENT_AUTH_ALLOW_LOGIN_PLACEHOLDER: '1',
    AGENT_AUTH_DCR_MODE: 'initial_access_token',
  };
  assert.deepEqual(devAuthConfig(env), {
    allowLoginPlaceholder: true,
    dcrMode: 'initial_access_token',
  });
  assert.deepEqual(saasAuthConfig(env), {});
  assert.deepEqual(saasAuthConfig({ ...env, SAAS_ALLOW_LOGIN_PLACEHOLDER: '1' }), {});
});

test('deployment entry rejects unimplemented DCR modes', () => {
  assert.throws(
    () => devAuthConfig({ AGENT_AUTH_DCR_MODE: 'software_statement' }),
    /非法或尚未实现/,
  );
  assert.throws(
    () => authEnvironment({ dcrMode: 'software_statement' }),
    /CDK 仅允许已实现的 DCR 档/,
  );
});

test('SaaS stack rejects deployment-wide DCR and placeholder login', () => {
  const saas = {
    saasZone: 'auth.example.com',
    saasControlHost: 'c.auth.example.com',
  };
  assert.throws(
    () => authEnvironment({ ...saas, dcrMode: 'open' }),
    /SaaS Stack 禁止部署级 DCR\/占位登录配置/,
  );
  assert.throws(
    () => authEnvironment({ ...saas, allowLoginPlaceholder: true }),
    /SaaS Stack 禁止部署级 DCR\/占位登录配置/,
  );
});
