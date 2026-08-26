const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { App } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');

const {
  AgentAuthStack,
  resolveMtlsTruststoreAssetPath,
} = require('../dist/lib/agent-auth-stack');

const COMMIT = '0123456789abcdef0123456789abcdef01234567';
const ASSET = path.resolve(__dirname);
const INFRA_ROOT = path.resolve(__dirname, '..');

function synthesize(id, overrides = {}) {
  const app = new App();
  const stack = new AgentAuthStack(app, id, {
    env: { account: '123456789012', region: 'us-east-1' },
    webBaseUrl: 'https://auth.example.com',
    deploymentCommit: COMMIT,
    lambdaAssetPath: ASSET,
    securityEventArchiveAssetPath: ASSET,
    ssfDeliveryAssetPath: ASSET,
    tenantKeyProvisionerAssetPath: ASSET,
    reclaimAssetPath: ASSET,
    recomputeAssetPath: ASSET,
    credentialMigrationAssetPath: ASSET,
    deployFrontend: false,
    mtlsDomain: 'mtls.auth.example.com',
    mtlsCertArn:
      'arn:aws:acm:us-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555',
    mtlsZoneId: 'Z0123456789ABC',
    mtlsZoneName: 'auth.example.com',
    mtlsSvidEnabled: true,
    phase: 'p3',
    ...overrides,
  });
  return Template.fromStack(stack).toJSON();
}

function resourcesOfType(template, type) {
  return Object.entries(template.Resources).filter(
    ([, resource]) => resource.Type === type,
  );
}

test(
  'c5_7_mtls_svid_uses_independent_apigw_truststore_and_self_hosted_gate',
  () => {
    const expectedTruststoreAsset = path.join(
      INFRA_ROOT,
      'assets',
      'mtls-truststore',
    );
    assert.equal(
      resolveMtlsTruststoreAssetPath(path.join(INFRA_ROOT, 'lib')),
      expectedTruststoreAsset,
      'ts-node source execution must resolve infra/assets',
    );
    assert.equal(
      resolveMtlsTruststoreAssetPath(path.join(INFRA_ROOT, 'dist', 'lib')),
      expectedTruststoreAsset,
      'compiled dist execution must resolve infra/assets',
    );

    const selfHosted = synthesize('MtlsSvidSelfHosted');
    const domains = resourcesOfType(
      selfHosted,
      'AWS::ApiGatewayV2::DomainName',
    );
    assert.equal(domains.length, 1);
    const [domainId, domain] = domains[0];
    assert.equal(domain.Properties.DomainName, 'mtls.auth.example.com');
    const domainJson = JSON.stringify(domain.Properties);
    assert.match(domainJson, /truststore\.pem/);
    assert.match(domainJson, /MtlsTruststore/);

    const truststores = Object.entries(selfHosted.Resources).filter(
      ([logicalId, resource]) =>
        logicalId.startsWith('MtlsTruststore') &&
        resource.Type === 'AWS::S3::Bucket',
    );
    assert.equal(truststores.length, 1);
    const truststore = truststores[0][1].Properties;
    assert.equal(truststore.VersioningConfiguration.Status, 'Enabled');
    assert.ok(truststore.BucketEncryption);
    assert.deepEqual(truststore.PublicAccessBlockConfiguration, {
      BlockPublicAcls: true,
      BlockPublicPolicy: true,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true,
    });

    const mappings = resourcesOfType(
      selfHosted,
      'AWS::ApiGatewayV2::ApiMapping',
    );
    assert.equal(mappings.length, 1);
    assert.match(JSON.stringify(mappings[0][1].Properties), new RegExp(domainId));

    const flaggedRuntimes = resourcesOfType(
      selfHosted,
      'AWS::Lambda::Function',
    ).filter(
      ([, resource]) =>
        resource.Properties?.Environment?.Variables
          ?.AGENT_AUTH_MTLS_SVID_ENABLED === '1',
    );
    assert.ok(
      flaggedRuntimes.some(
        ([, resource]) =>
          resource.Properties.Environment.Variables.SCOPE === 'token',
      ),
      'the token runtime must receive the mTLS SVID feature gate',
    );

    const distributions = resourcesOfType(
      selfHosted,
      'AWS::CloudFront::Distribution',
    );
    assert.ok(
      distributions.every(
        ([, resource]) =>
          !JSON.stringify(resource.Properties).includes(
            'mtls.auth.example.com',
          ),
      ),
      'the client-certificate endpoint must bypass CloudFront',
    );

    const disabled = synthesize('MtlsSvidDisabled', {
      mtlsSvidEnabled: false,
    });
    assert.equal(
      resourcesOfType(disabled, 'AWS::ApiGatewayV2::DomainName').length,
      0,
      'the deployment feature gate must suppress the mTLS domain',
    );
    assert.equal(
      resourcesOfType(disabled, 'AWS::S3::Bucket').filter(([logicalId]) =>
        logicalId.startsWith('MtlsTruststore'),
      ).length,
      0,
      'the disabled deployment must not create a dormant truststore',
    );
    assert.equal(
      resourcesOfType(disabled, 'AWS::Lambda::Function').filter(
        ([, resource]) =>
          resource.Properties?.Environment?.Variables
            ?.AGENT_AUTH_MTLS_SVID_ENABLED === '1',
      ).length,
      0,
      'the disabled deployment must not announce the runtime capability',
    );

    const belowPhase = synthesize('MtlsSvidBelowPhase', {
      phase: 'p2',
    });
    assert.equal(
      resourcesOfType(belowPhase, 'AWS::ApiGatewayV2::DomainName').length,
      0,
      'a P3 mTLS domain must not be created below P3',
    );
    assert.equal(
      resourcesOfType(belowPhase, 'AWS::Lambda::Function').filter(
        ([, resource]) =>
          resource.Properties?.Environment?.Variables
            ?.AGENT_AUTH_MTLS_SVID_ENABLED === '1',
      ).length,
      0,
      'a below-P3 runtime must not receive the mTLS feature announcement',
    );

    assert.throws(
      () =>
        synthesize('MtlsSvidIncomplete', {
          mtlsCertArn: undefined,
        }),
      /mTLS SVID deployment requires mtlsDomain, mtlsCertArn, mtlsZoneId, and mtlsZoneName/,
      'an enabled deployment must not announce mTLS without a complete endpoint',
    );

    const saas = synthesize('MtlsSvidSaas', {
      webBaseUrl: 'https://c.auth.example.com',
      saasZone: 'auth.example.com',
      saasControlHost: 'c.auth.example.com',
      customDomains: ['c.auth.example.com', 't1.auth.example.com'],
      tenantAdminSecretArns: {
        t1: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:tenant-t1-AbCd12',
      },
      tenantResidency: {
        t1: {
          jurisdiction: 'us',
          allowed_regions: ['us-east-1'],
          governance_region: 'us-east-1',
        },
      },
    });
    assert.equal(
      resourcesOfType(saas, 'AWS::ApiGatewayV2::DomainName').length,
      0,
      'SaaS must not synthesize the SelfHosted mTLS custom domain',
    );
    assert.equal(
      resourcesOfType(saas, 'AWS::Lambda::Function').filter(
        ([, resource]) =>
          resource.Properties?.Environment?.Variables
            ?.AGENT_AUTH_MTLS_SVID_ENABLED === '1',
      ).length,
      0,
      'SaaS must not announce the SelfHosted-only runtime capability',
    );
  },
);
