const assert = require('node:assert/strict');
const test = require('node:test');
const { App, Aspects } = require('aws-cdk-lib');
const {
  Annotations,
  Match,
  Template,
} = require('aws-cdk-lib/assertions');
const { AwsSolutionsChecks } = require('cdk-nag');

const {
  EmaSimulatorStack,
} = require('../dist/lib/ema-simulator-stack');

function template() {
  const app = new App();
  const stack = new EmaSimulatorStack(app, 'EmaSimulatorTest', {
    agentAuthIssuers: [
      'https://auth.example.com',
      'https://t1.example.com/',
    ],
    simulatorCommit: 'a'.repeat(40),
  });
  return Template.fromStack(stack).toJSON();
}

test('EMA simulator provisions isolated Cognito, KMS, issuer, and RS resources', () => {
  const synthesized = template();
  const resources = Object.values(synthesized.Resources);

  const pools = resources.filter(
    (resource) => resource.Type === 'AWS::Cognito::UserPool',
  );
  assert.equal(pools.length, 1);
  assert.equal(pools[0].Properties.AdminCreateUserConfig.AllowAdminCreateUserOnly, true);

  const keys = resources.filter(
    (resource) => resource.Type === 'AWS::KMS::Key',
  );
  assert.equal(keys.length, 1);
  assert.equal(keys[0].Properties.KeySpec, 'ECC_NIST_P256');
  assert.equal(keys[0].Properties.KeyUsage, 'SIGN_VERIFY');
  assert.equal(keys[0].Properties.EnableKeyRotation, false);

  const secrets = resources.filter(
    (resource) => resource.Type === 'AWS::SecretsManager::Secret',
  );
  assert.equal(secrets.length, 2);
  const serializedSecrets = JSON.stringify(secrets);
  assert.doesNotMatch(serializedSecrets, /client_secret":"[^"]+/);
  assert.doesNotMatch(serializedSecrets, /password":"[^"]+/);

  const functions = resources.filter(
    (resource) => resource.Type === 'AWS::Lambda::Function',
  );
  assert.equal(functions.length, 2);
  const issuer = functions.find(
    (resource) =>
      resource.Properties.Environment.Variables.ASSERTION_CLIENT_ID,
  );
  const rs = functions.find(
    (resource) =>
      resource.Properties.Environment.Variables.RESOURCE &&
      !resource.Properties.Environment.Variables.ASSERTION_CLIENT_ID,
  );
  assert.ok(issuer);
  assert.ok(rs);
  assert.equal(
    issuer.Properties.Environment.Variables.ALLOWED_AGENT_AUTH_ISSUERS,
    'https://auth.example.com,https://t1.example.com',
  );
  assert.equal(
    rs.Properties.Environment.Variables.ALLOWED_AGENT_AUTH_ISSUERS,
    'https://auth.example.com,https://t1.example.com',
  );
  assert.equal(
    Object.hasOwn(
      issuer.Properties.Environment.Variables,
      'BROKER_CLIENT_SECRET',
    ),
    false,
  );

  assert.deepEqual(synthesized.Outputs.SimulatorCommit.Value, 'a'.repeat(40));
  for (const output of [
    'IssuerUrl',
    'JwksUrl',
    'ResourceUrl',
    'RsAllowUrl',
    'RsDenyUrl',
    'BrokerSecretArn',
    'TestUserPasswordSecretArn',
  ]) {
    assert.ok(synthesized.Outputs[output], `missing ${output}`);
  }
});

test('EMA simulator rejects an empty issuer allowlist and non-commit provenance', () => {
  const app = new App();
  assert.throws(
    () =>
      new EmaSimulatorStack(app, 'NoIssuers', {
        agentAuthIssuers: [],
        simulatorCommit: 'a'.repeat(40),
      }),
    /must not be empty/,
  );
  assert.throws(
    () =>
      new EmaSimulatorStack(app, 'BadCommit', {
        agentAuthIssuers: ['https://auth.example.com'],
        simulatorCommit: 'not-a-commit',
      }),
    /full lowercase Git SHA/,
  );
});

test('EMA simulator passes AWS Solutions checks', () => {
  const app = new App();
  const stack = new EmaSimulatorStack(app, 'EmaSimulatorNag', {
    agentAuthIssuers: ['https://auth.example.com'],
    simulatorCommit: 'a'.repeat(40),
  });
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  Annotations.fromStack(stack).hasNoError('*', Match.anyValue());
});
