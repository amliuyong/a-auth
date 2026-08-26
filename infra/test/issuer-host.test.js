const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

function authEnvironment(options = {}) {
  const app = new App();
  const stack = new AgentAuthStack(app, 'IssuerHostTest', {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    credentialMigrationAssetPath: path.resolve(__dirname),
    deployFrontend: false,
    tenantResidency: tenantResidency(),
    ...options,
  });
  const resources = Template.fromStack(stack).toJSON().Resources;
  const authFunctions = Object.entries(resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.SCOPE === 'non_token' &&
      resource.Properties?.Environment?.Variables?.DOMAIN_MAP_TABLE,
  );
  assert.equal(authFunctions.length, 1, 'expected exactly one main Auth Lambda');
  const issuerHosts = Object.values(resources)
    .filter(
      (resource) =>
        resource.Type === 'AWS::Lambda::Function' &&
        resource.Properties?.Environment?.Variables?.AGENT_AUTH_HOST,
    )
    .map((resource) => resource.Properties.Environment.Variables.AGENT_AUTH_HOST);
  return {
    environment: authFunctions[0][1].Properties.Environment.Variables,
    issuerHosts,
  };
}

test('default SelfHosted deployment uses its public web host as AGENT_AUTH_HOST', () => {
  const { environment, issuerHosts } = authEnvironment({
    reclaimAssetPath: path.resolve(__dirname),
    recomputeAssetPath: path.resolve(__dirname),
  });

  assert.equal(environment.AGENT_AUTH_HOST, 'auth.example.com');
  assert.equal(
    issuerHosts.length,
    6,
    'expected Auth, Token, Governance, SSF, Reclaim, and Recompute Lambdas',
  );
  assert.ok(issuerHosts.every((host) => host === 'auth.example.com'));
});

test('custom-domain SelfHosted deployment uses its public domain as AGENT_AUTH_HOST', () => {
  const { environment, issuerHosts } = authEnvironment({
    webBaseUrl: 'https://login.example.com',
    customDomain: 'login.example.com',
    reclaimAssetPath: path.resolve(__dirname),
    recomputeAssetPath: path.resolve(__dirname),
  });

  assert.equal(environment.AGENT_AUTH_HOST, 'login.example.com');
  assert.equal(
    issuerHosts.length,
    6,
    'expected Auth, Token, Governance, SSF, Reclaim, and Recompute Lambdas',
  );
  assert.ok(issuerHosts.every((host) => host === 'login.example.com'));
});

test('SelfHosted deployment preserves an explicitly enabled tenant partition', () => {
  const { environment } = authEnvironment({
    enableTenantPartitioning: true,
  });

  assert.equal(environment.AGENT_AUTH_ENABLE_TENANT_PARTITIONING, '1');
});
