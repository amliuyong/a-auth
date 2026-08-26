const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const { tenantResidency } = require('./tenant-residency-fixture');

function authEnvironment(passkeyEnabled) {
  const app = new App();
  const stack = new AgentAuthStack(app, `Passkey${passkeyEnabled ? 'On' : 'Off'}`, {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    credentialMigrationAssetPath: path.resolve(__dirname),
    deployFrontend: false,
    tenantResidency: tenantResidency(),
    passkeyEnabled,
  });
  const resources = Template.fromStack(stack).toJSON().Resources;
  const authFunctions = Object.entries(resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.SCOPE === 'non_token' &&
      resource.Properties?.Environment?.Variables?.PASSKEY_TABLE,
  );
  assert.equal(authFunctions.length, 1, 'expected exactly one main Auth Lambda');
  return authFunctions[0][1].Properties.Environment.Variables;
}

test('passkey feature flag is wired into the main Lambda environment', () => {
  assert.equal(authEnvironment(true).AGENT_AUTH_PASSKEY_ENABLED, '1');
  assert.equal(authEnvironment(false).AGENT_AUTH_PASSKEY_ENABLED, undefined);
});
