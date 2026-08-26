const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const {
  AgentAuthStandbyStack,
} = require('../dist/lib/agent-auth-standby-stack');

const COMMIT = '0123456789abcdef0123456789abcdef01234567';
const ACCOUNT = '123456789012';
const ASSET = path.resolve(__dirname);

function secretArn(region, name) {
  return `arn:aws:secretsmanager:${region}:${ACCOUNT}:secret:${name}-AbCd12`;
}

function residency() {
  return {
    t1: {
      jurisdiction: 'us',
      allowed_regions: ['us-east-1', 'us-west-2'],
      governance_region: 'us-east-1',
    },
    t3: {
      jurisdiction: 'us',
      allowed_regions: ['us-east-1', 'us-west-2'],
      governance_region: 'us-east-1',
    },
  };
}

function primaryProps(overrides = {}) {
  return {
    env: { account: ACCOUNT, region: 'us-east-1' },
    webBaseUrl: 'https://c.auth.example.com',
    deploymentCommit: COMMIT,
    lambdaAssetPath: ASSET,
    securityEventArchiveAssetPath: ASSET,
    ssfDeliveryAssetPath: ASSET,
    tenantKeyProvisionerAssetPath: ASSET,
    reclaimAssetPath: ASSET,
    recomputeAssetPath: ASSET,
    credentialMigrationAssetPath: ASSET,
    deployFrontend: false,
    saasZone: 'auth.example.com',
    saasControlHost: 'c.auth.example.com',
    customDomains: [
      'c.auth.example.com',
      't1.auth.example.com',
      't3.auth.example.com',
    ],
    tenantAdminSecretArns: {
      t1: secretArn('us-east-1', 'legacy/t1'),
      t3: secretArn('us-east-1', 'legacy/t3'),
    },
    tenantSubjectTypes: { t3: 'public' },
    tenantKeyReplicaRegions: ['us-west-2'],
    tenantResidency: residency(),
    ...overrides,
  };
}

function primaryTemplate(overrides = {}) {
  const app = new App();
  const stack = new AgentAuthStack(
    app,
    'TenantSubjectProfilePrimary',
    primaryProps(overrides),
  );
  return Template.fromStack(stack).toJSON();
}

function standbyTemplate(overrides = {}) {
  const app = new App();
  const stack = new AgentAuthStandbyStack(app, 'TenantSubjectProfileStandby', {
    env: { account: ACCOUNT, region: 'us-west-2' },
    lambdaAssetPath: ASSET,
    credentialMigrationAssetPath: ASSET,
    deploymentCommit: COMMIT,
    webBaseUrl: 'https://c.auth.example.com',
    saasZone: 'auth.example.com',
    saasControlHost: 'c.auth.example.com',
    tenantIds: ['t1', 't3'],
    tenantSubjectTypes: { t3: 'public' },
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
      server: secretArn('us-west-2', 'server'),
      governance_hmac: secretArn('us-west-2', 'governance'),
      standby_bootstrap_config: secretArn('us-west-2', 'bootstrap'),
      platform_admin: secretArn('us-west-2', 'admin'),
      tenant_admin: {
        t1: secretArn('us-west-2', 'tenant-t1'),
        t3: secretArn('us-west-2', 'tenant-t3'),
      },
      scim: {
        t1: secretArn('us-west-2', 'scim-t1'),
        t3: secretArn('us-west-2', 'scim-t3'),
      },
    },
    cloudFrontOriginSecretName: 'AgentAuthSaas/cloudfront-origin-auth',
    cloudFrontOriginSecondarySecretName:
      'AgentAuthSaas/cloudfront-origin-auth-secondary',
    saasOriginAuthRevision: 'rotation-7',
    tenantResidency: residency(),
    ...overrides,
  });
  return Template.fromStack(stack).toJSON();
}

function bootstrapDocument(template, prefix) {
  const matches = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith(prefix) &&
      resource.Type === 'AWS::SecretsManager::Secret',
  );
  assert.equal(matches.length, 1, `expected one ${prefix} Secret`);
  return JSON.stringify(matches[0][1].Properties.SecretString);
}

function adminCredentialMigrationEntries(template) {
  const migration = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::CloudFormation::CustomResource' &&
      resource.Properties?.MigrationVersion ===
        'admin-scim-credential-set-v3-copy',
  );
  assert.ok(migration, 'expected admin credential migration custom resource');
  return migration.Properties.Credentials;
}

test('primary and standby bootstraps carry the same tenant subject profiles', () => {
  const expected = /tenant_subject_types.*t3.*public/;
  const primary = primaryTemplate();
  assert.match(
    bootstrapDocument(primary, 'RuntimeBootstrapConfig'),
    expected,
  );
  assert.match(
    bootstrapDocument(primary, 'StandbyRuntimeBootstrapConfig'),
    expected,
  );
  assert.doesNotThrow(() => standbyTemplate());
});

test('primary and standby bootstraps carry the same redirect prefix host allowlist', () => {
  const allowlist = {
    t1: ['callbacks.example.com', 'login.example.com'],
  };
  const expected = /redirect_prefix_allowed_hosts.*t1.*callbacks\.example\.com.*login\.example\.com/;
  const primary = primaryTemplate({
    redirectPrefixAllowedHosts: allowlist,
  });
  assert.match(
    bootstrapDocument(primary, 'RuntimeBootstrapConfig'),
    expected,
  );
  assert.match(
    bootstrapDocument(primary, 'StandbyRuntimeBootstrapConfig'),
    expected,
  );
  assert.doesNotThrow(() =>
    standbyTemplate({ redirectPrefixAllowedHosts: allowlist }),
  );
});

test('redirect prefix host allowlists reject unknown tenants and malformed exact hosts', () => {
  assert.throws(
    () =>
      primaryTemplate({
        redirectPrefixAllowedHosts: { t9: ['callbacks.example.com'] },
      }),
    /redirectPrefixAllowedHosts/,
  );
  assert.throws(
    () =>
      standbyTemplate({
        redirectPrefixAllowedHosts: { t9: ['callbacks.example.com'] },
      }),
    /redirectPrefixAllowedHosts/,
  );
  assert.throws(
    () =>
      primaryTemplate({
        redirectPrefixAllowedHosts: {
          t1: ['Callbacks.Example.com', 'callbacks.example.com.'],
        },
      }),
    /redirectPrefixAllowedHosts/,
  );
  for (const hosts of ['callbacks.example.com', [42]]) {
    assert.throws(
      () =>
        primaryTemplate({
          redirectPrefixAllowedHosts: { t1: hosts },
        }),
      /redirectPrefixAllowedHosts/,
    );
  }
  for (const host of [
    'https://callbacks.example.com',
    '*.example.com',
    'callbacks.example.com/path',
    '127.0.0.1',
    '127.1',
    '-callbacks.example.com',
    'callbacks..example.com',
  ]) {
    assert.throws(
      () =>
        primaryTemplate({
          redirectPrefixAllowedHosts: { t1: [host] },
        }),
      /redirectPrefixAllowedHosts/,
    );
  }
});

test('SaaS rejects unknown tenants and invalid subject profile values', () => {
  assert.throws(
    () => primaryTemplate({ tenantSubjectTypes: { t9: 'public' } }),
    /tenantSubjectTypes/,
  );
  assert.throws(
    () => primaryTemplate({ tenantSubjectTypes: { t1: 'PUBLIC' } }),
    /tenantSubjectTypes/,
  );
  assert.throws(
    () => standbyTemplate({ tenantSubjectTypes: { t9: 'public' } }),
    /tenantSubjectTypes/,
  );
  assert.throws(
    () => primaryTemplate({ offboardedTenantIds: ['t9'] }),
    /offboardedTenantIds/,
  );
});

test('SelfHosted rejects tenant subject profiles', () => {
  assert.throws(
    () =>
      new AgentAuthStack(new App(), 'SelfHostedTenantSubjectProfile', {
        webBaseUrl: 'https://auth.example.com',
        deploymentCommit: COMMIT,
        lambdaAssetPath: ASSET,
        securityEventArchiveAssetPath: ASSET,
        ssfDeliveryAssetPath: ASSET,
        credentialMigrationAssetPath: ASSET,
        deployFrontend: false,
        tenantSubjectTypes: { t1: 'public' },
      }),
    /SelfHosted.*tenantSubjectTypes/,
  );
  assert.throws(
    () =>
      new AgentAuthStack(new App(), 'SelfHostedOffboardedTenant', {
        webBaseUrl: 'https://auth.example.com',
        deploymentCommit: COMMIT,
        lambdaAssetPath: ASSET,
        securityEventArchiveAssetPath: ASSET,
        ssfDeliveryAssetPath: ASSET,
        credentialMigrationAssetPath: ASSET,
        deployFrontend: false,
        offboardedTenantIds: ['t1'],
      }),
    /SelfHosted.*offboardedTenantIds/,
  );
  assert.throws(
    () =>
      new AgentAuthStack(new App(), 'SelfHostedRedirectPrefixTenant', {
        webBaseUrl: 'https://auth.example.com',
        deploymentCommit: COMMIT,
        lambdaAssetPath: ASSET,
        securityEventArchiveAssetPath: ASSET,
        ssfDeliveryAssetPath: ASSET,
        credentialMigrationAssetPath: ASSET,
        deployFrontend: false,
        redirectPrefixAllowedHosts: {
          t1: ['callbacks.example.com'],
        },
      }),
    /redirectPrefixAllowedHosts/,
  );
});

test('only explicitly offboarded tenant credential owners allow removed targets', () => {
  const credentials = adminCredentialMigrationEntries(
    primaryTemplate({ offboardedTenantIds: ['t1'] }),
  );
  const platform = credentials.find(
    (entry) => entry.Owner.kind === 'platform',
  );
  const tenantT1 = credentials.find(
    (entry) =>
      entry.Owner.kind === 'tenant' && entry.Owner.tenant_id === 't1',
  );
  const scimT1 = credentials.find(
    (entry) =>
      entry.Owner.kind === 'scim_tenant' && entry.Owner.tenant_id === 't1',
  );
  const tenantT3 = credentials.find(
    (entry) =>
      entry.Owner.kind === 'tenant' && entry.Owner.tenant_id === 't3',
  );
  const scimT3 = credentials.find(
    (entry) =>
      entry.Owner.kind === 'scim_tenant' && entry.Owner.tenant_id === 't3',
  );

  assert.equal(platform.AllowRemoved, undefined);
  assert.equal(tenantT1.AllowRemoved, true);
  assert.equal(scimT1.AllowRemoved, true);
  assert.equal(tenantT3.AllowRemoved, undefined);
  assert.equal(scimT3.AllowRemoved, undefined);
});
