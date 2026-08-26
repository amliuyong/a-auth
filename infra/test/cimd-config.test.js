const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const {
  devCimdConfig,
  saasCimdConfig,
} = require('../dist/lib/deployment-auth-config');
const { tenantResidency } = require('./tenant-residency-fixture');

function authEnvironment(props) {
  const app = new App();
  const tenantIds = Object.keys(props.tenantAdminSecretArns ?? { default: true });
  const stack = new AgentAuthStack(app, 'CimdConfigTest', {
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: '0123456789abcdef0123456789abcdef01234567',
    lambdaAssetPath: path.resolve(__dirname),
    securityEventArchiveAssetPath: path.resolve(__dirname),
    ssfDeliveryAssetPath: path.resolve(__dirname),
    tenantKeyProvisionerAssetPath: path.resolve(__dirname),
    credentialMigrationAssetPath: path.resolve(__dirname),
    deployFrontend: false,
    tenantResidency: tenantResidency(tenantIds),
    ...props,
  });
  const resources = Template.fromStack(stack).toJSON().Resources;
  const authFunctions = Object.entries(resources).filter(
    ([, resource]) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties?.Environment?.Variables?.SCOPE === 'non_token' &&
      resource.Properties?.Environment?.Variables?.CLIENTS_TABLE &&
      resource.Properties?.Environment?.Variables?.USERS_TABLE,
  );
  assert.equal(authFunctions.length, 1, 'expected exactly one main Auth Lambda');
  return authFunctions[0][1].Properties.Environment.Variables;
}

test('CIMD feature gate and global allowlist are wired into the main Lambda', () => {
  const enabled = authEnvironment({
    cimdEnabled: true,
    cimdAllowedDomains: ['clients.example.com', 'raw.githubusercontent.com'],
  });
  assert.equal(enabled.AGENT_AUTH_CIMD_ENABLED, '1');
  assert.equal(
    enabled.AGENT_AUTH_CIMD_ALLOWED_DOMAINS,
    'clients.example.com,raw.githubusercontent.com',
  );

  const disabled = authEnvironment({});
  assert.equal(disabled.AGENT_AUTH_CIMD_ENABLED, undefined);
  assert.equal(disabled.AGENT_AUTH_CIMD_ALLOWED_DOMAINS, undefined);
});

test('CIMD enablement fails synth without a trust policy', () => {
  assert.throws(
    () =>
      authEnvironment(
        devCimdConfig({
          AGENT_AUTH_CIMD_ENABLED: '1',
        }),
      ),
    /requires a non-empty global or tenant domain allowlist/,
  );
});

test('CIMD enablement fails synth before phase P1', () => {
  for (const phase of ['p0', 'p0.5', 'p0_5']) {
    assert.throws(
      () =>
        authEnvironment({
          phase,
          cimdEnabled: true,
          cimdAllowedDomains: ['clients.example.com'],
        }),
      /requires phase p1 or later/,
    );
  }
});

test('SaaS CIMD receives tenant policy only with tenant partitioning', () => {
  const saas = {
    saasZone: 'auth.example.com',
    saasControlHost: 'c.auth.example.com',
    customDomains: [
      't1.auth.example.com',
      't2.auth.example.com',
      'c.auth.example.com',
    ],
    tenantAdminSecretArns: {
      t1: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:t1-admin-AbCdEf',
      t2: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:t2-admin-AbCdEf',
    },
    cimdEnabled: true,
    cimdTenantAllowedDomains: {
      t1: ['client-one.example.com'],
      t2: ['client-two.example.com'],
    },
  };
  assert.throws(
    () => authEnvironment(saas),
    /SaaS CIMD requires enableTenantPartitioning=true/,
  );

  const enabled = authEnvironment({ ...saas, enableTenantPartitioning: true });
  assert.deepEqual(
    JSON.parse(enabled.AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS),
    saas.cimdTenantAllowedDomains,
  );
  assert.equal(enabled.AGENT_AUTH_ENABLE_TENANT_PARTITIONING, '1');
});

test('deployment config parses global and tenant CIMD policies', () => {
  const env = {
    AGENT_AUTH_CIMD_ENABLED: '1',
    AGENT_AUTH_CIMD_ALLOWED_DOMAINS:
      ' Clients.Example.com., raw.githubusercontent.com,clients.example.com ',
    AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS:
      '{"t1":["One.Example.com."],"t2":["two.example.com"]}',
  };
  assert.deepEqual(devCimdConfig(env), {
    cimdEnabled: true,
    cimdAllowedDomains: ['clients.example.com', 'raw.githubusercontent.com'],
  });
  assert.deepEqual(saasCimdConfig(env), {
    cimdEnabled: true,
    cimdAllowedDomains: ['clients.example.com', 'raw.githubusercontent.com'],
    cimdTenantAllowedDomains: {
      t1: ['one.example.com'],
      t2: ['two.example.com'],
    },
  });
  assert.throws(
    () =>
      saasCimdConfig({
        AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS: '{"t1":"not-an-array"}',
      }),
    /values must be string arrays/,
  );
});

test('tenant-only SaaS CIMD policy leaves the colocated Dev stack disabled', () => {
  const env = {
    AGENT_AUTH_CIMD_ENABLED: '1',
    SAAS_ZONE: 'auth.example.com',
    AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS:
      '{"t1":["client-one.example.com"],"t2":["client-two.example.com"]}',
  };
  const devConfig = devCimdConfig(env);
  assert.deepEqual(devConfig, {
    cimdEnabled: false,
    cimdAllowedDomains: [],
  });
  assert.equal(
    authEnvironment(devConfig).AGENT_AUTH_CIMD_ENABLED,
    undefined,
  );

  const saasConfig = saasCimdConfig(env);
  assert.equal(saasConfig.cimdEnabled, true);
  const enabled = authEnvironment({
    saasZone: env.SAAS_ZONE,
    saasControlHost: 'c.auth.example.com',
    customDomains: [
      't1.auth.example.com',
      't2.auth.example.com',
      'c.auth.example.com',
    ],
    tenantAdminSecretArns: {
      t1: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:t1-admin-AbCdEf',
      t2: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:t2-admin-AbCdEf',
    },
    enableTenantPartitioning: true,
    ...saasConfig,
  });
  assert.deepEqual(
    JSON.parse(enabled.AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS),
    {
      t1: ['client-one.example.com'],
      t2: ['client-two.example.com'],
    },
  );
});

test('deployment config rejects malformed CIMD domains before synth', () => {
  for (const domain of [
    'https://clients.example.com',
    '*.example.com',
    'clients.example.com:8443',
    '127.0.0.1',
    'bad domain.example',
    'bücher.example',
  ]) {
    assert.throws(
      () => devCimdConfig({ AGENT_AUTH_CIMD_ALLOWED_DOMAINS: domain }),
      /CIMD domain/,
      domain,
    );
    assert.throws(
      () =>
        saasCimdConfig({
          AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS: JSON.stringify({
            t1: [domain],
          }),
        }),
      /CIMD domain/,
      domain,
    );
  }
  assert.throws(
    () =>
      saasCimdConfig({
        AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS: '{"t1":[" "]}',
      }),
    /invalid CIMD domain/,
  );
});

test('direct stack props normalize valid CIMD domains and reject invalid ones', () => {
  const enabled = authEnvironment({
    cimdEnabled: true,
    cimdAllowedDomains: [' Clients.Example.com. ', 'clients.example.com'],
  });
  assert.equal(enabled.AGENT_AUTH_CIMD_ALLOWED_DOMAINS, 'clients.example.com');

  assert.throws(
    () =>
      authEnvironment({
        cimdEnabled: true,
        cimdAllowedDomains: ['https://clients.example.com'],
      }),
    /invalid CIMD domain/,
  );
});
