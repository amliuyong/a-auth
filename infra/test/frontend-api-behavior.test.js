const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { App, Aspects, Stack } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');
const { AwsSolutionsChecks } = require('cdk-nag');
const secretsmanager = require('aws-cdk-lib/aws-secretsmanager');

const {
  FrontendConstruct,
  originAuthEdgeCode,
} = require('../dist/lib/frontend-construct');

async function runEdgeHandler(secrets) {
  const reads = [];
  class GetSecretValueCommand {
    constructor(input) {
      this.input = input;
    }
  }
  class SecretsManagerClient {
    async send(command) {
      reads.push(command.input.SecretId);
      return { SecretString: secrets[command.input.SecretId] };
    }
  }
  const context = {
    exports: {},
    require(name) {
      assert.equal(name, '@aws-sdk/client-secrets-manager');
      return { GetSecretValueCommand, SecretsManagerClient };
    },
  };
  vm.runInNewContext(
    originAuthEdgeCode('primary-id', 'secondary-id', 'rotation-7'),
    context,
  );
  const request = {
    headers: {
      'x-agent-auth-origin-auth': [{ value: 'attacker' }],
      'x-agent-auth-origin-auth-primary': [{ value: 'attacker' }],
      'x-agent-auth-origin-auth-secondary': [{ value: 'attacker' }],
    },
  };
  const event = { Records: [{ cf: { request } }] };
  await context.exports.handler(event);
  await context.exports.handler(event);
  return { request, reads };
}

test('origin-request Lambda@Edge overwrites viewer credentials and caches both slots', async () => {
  const primary = 'primary-origin-secret-at-least-32-bytes';
  const secondary = 'secondary-origin-secret-at-least-32-bytes';
  const { request, reads } = await runEdgeHandler({
    'primary-id': primary,
    'secondary-id': secondary,
  });
  assert.deepEqual(reads, ['primary-id', 'secondary-id']);
  assert.equal(
    request.headers['x-agent-auth-origin-auth'][0].value,
    primary,
  );
  assert.equal(
    request.headers['x-agent-auth-origin-auth-primary'][0].value,
    primary,
  );
  assert.equal(
    request.headers['x-agent-auth-origin-auth-secondary'][0].value,
    secondary,
  );
  assert.equal(
    request.headers['x-agent-auth-origin-auth-revision'][0].value,
    'rotation-7',
  );
});

test('origin-request Lambda@Edge fails closed for short or identical slots', async () => {
  await assert.rejects(
    runEdgeHandler({
      'primary-id': 'short',
      'secondary-id': 'secondary-origin-secret-at-least-32-bytes',
    }),
    /missing or too short/,
  );
  const same = 'same-origin-secret-value-at-least-32-bytes';
  await assert.rejects(
    runEdgeHandler({ 'primary-id': same, 'secondary-id': same }),
    /must be distinct/,
  );
});

test('CloudFront forwards SCIM methods, credentials, and filters without caching', () => {
  const app = new App();
  const stack = new Stack(app, 'FrontendApiBehaviorTest', {
    env: { account: '123456789012', region: 'us-east-1' },
  });
  const primarySecret = new secretsmanager.Secret(stack, 'PrimarySecret');
  const secondarySecret = new secretsmanager.Secret(stack, 'SecondarySecret');
  new FrontendConstruct(stack, 'Frontend', {
    apiDomain: 'api.example.com',
    apiOriginAuth: {
      primarySecret,
      secondarySecret,
      revision: 'rotation-7',
    },
    assetPath: path.resolve(__dirname),
  });

  const template = Template.fromStack(stack).toJSON();
  const distribution = Object.values(template.Resources).find(
    (resource) => resource.Type === 'AWS::CloudFront::Distribution',
  );
  assert.ok(distribution);

  const behavior = distribution.Properties.DistributionConfig.DefaultCacheBehavior;
  const apiOrigin = distribution.Properties.DistributionConfig.Origins.find(
    (origin) => origin.DomainName === 'api.example.com',
  );
  assert.equal(
    apiOrigin.OriginCustomHeaders?.length ?? 0,
    0,
    'the distribution configuration must not disclose either origin credential',
  );
  assert.equal(behavior.LambdaFunctionAssociations.length, 1);
  assert.equal(
    behavior.LambdaFunctionAssociations[0].EventType,
    'origin-request',
  );
  assert.deepEqual(behavior.AllowedMethods, [
    'GET',
    'HEAD',
    'OPTIONS',
    'PUT',
    'PATCH',
    'POST',
    'DELETE',
  ]);
  assert.equal(
    behavior.CachePolicyId,
    '4135ea2d-6df8-44a3-9df3-4b5a84be39ad',
    'default API behavior must use the AWS managed CachingDisabled policy',
  );
  assert.equal(
    behavior.OriginRequestPolicyId,
    'b689b0a8-53d0-40ab-baf2-68738e2966ac',
    'default API behavior must forward Authorization, cookies, and query strings',
  );
  assert.ok(
    !distribution.Properties.DistributionConfig.CacheBehaviors.some((candidate) =>
      candidate.PathPattern.toLowerCase().startsWith('/scim'),
    ),
    'SCIM paths must remain on the uncached default API behavior',
  );
  const cacheBehaviors = distribution.Properties.DistributionConfig.CacheBehaviors;
  const inviteBehavior = cacheBehaviors.find(
    (candidate) => candidate.PathPattern.replace(/^\/+/, '') === 'invite',
  );
  assert.ok(inviteBehavior, '/invite must use an explicit SPA behavior');
  assert.notEqual(
    inviteBehavior.TargetOriginId,
    behavior.TargetOriginId,
    '/invite must target the S3 origin rather than the API origin',
  );
  assert.ok(
    inviteBehavior.FunctionAssociations?.some(
      (association) => association.EventType === 'viewer-request',
    ),
    '/invite must rewrite to the SPA shell',
  );
  assert.ok(
    !cacheBehaviors.some(
      (candidate) =>
        candidate.PathPattern.replace(/^\/+/, '') === 'login/invitation',
    ),
    '/login/invitation must remain on the uncached default API behavior',
  );
});

test('c10_9b_interactive_page_behaviors_attach_clickjacking_policy', () => {
  const app = new App();
  const stack = new Stack(app, 'C109bClickjackingPolicyTest', {
    env: { account: '123456789012', region: 'us-east-1' },
  });
  new FrontendConstruct(stack, 'Frontend', {
    apiDomain: 'api.example.com',
    assetPath: path.resolve(__dirname),
  });

  const resources = Template.fromStack(stack).toJSON().Resources;
  const [policyId, policy] = Object.entries(resources).find(
    ([, resource]) =>
      resource.Type === 'AWS::CloudFront::ResponseHeadersPolicy',
  );
  const security =
    policy.Properties.ResponseHeadersPolicyConfig.SecurityHeadersConfig;
  assert.equal(
    security.ContentSecurityPolicy.Override,
    true,
    'CloudFront must override any origin CSP for interactive pages',
  );
  assert.match(
    security.ContentSecurityPolicy.ContentSecurityPolicy,
    /(?:^|;\s*)frame-ancestors 'none'(?:;|$)/,
  );
  assert.deepEqual(security.FrameOptions, {
    FrameOption: 'DENY',
    Override: true,
  });

  const distribution = Object.values(resources).find(
    (resource) => resource.Type === 'AWS::CloudFront::Distribution',
  );
  const defaultBehavior =
    distribution.Properties.DistributionConfig.DefaultCacheBehavior;
  const cacheBehaviors =
    distribution.Properties.DistributionConfig.CacheBehaviors;
  for (const pathPattern of ['login', 'consent']) {
    const behavior = cacheBehaviors.find(
      (candidate) =>
        candidate.PathPattern.replace(/^\/+/, '') === pathPattern,
    );
    assert.ok(behavior, `/${pathPattern} must use an explicit SPA behavior`);
    assert.deepEqual(
      behavior.ResponseHeadersPolicyId,
      { Ref: policyId },
      `/${pathPattern} must attach the clickjacking response-header policy`,
    );
    assert.notDeepEqual(
      behavior.TargetOriginId,
      defaultBehavior.TargetOriginId,
      `/${pathPattern} must target the SPA origin rather than the API origin`,
    );
    assert.ok(
      behavior.FunctionAssociations?.some(
        (association) => association.EventType === 'viewer-request',
      ),
      `/${pathPattern} must route through the SPA page behavior`,
    );
  }
});

test('c10_16_jwks_cloudfront_ttl_matches_frozen_max_age', () => {
  const app = new App();
  const stack = new Stack(app, 'C1016JwksCachePolicyTest', {
    env: { account: '123456789012', region: 'us-east-1' },
  });
  const primarySecret = new secretsmanager.Secret(stack, 'PrimarySecret');
  const secondarySecret = new secretsmanager.Secret(stack, 'SecondarySecret');
  new FrontendConstruct(stack, 'Frontend', {
    apiDomain: 'api.example.com',
    apiOriginAuth: {
      primarySecret,
      secondarySecret,
      revision: 'rotation-7',
    },
    assetPath: path.resolve(__dirname),
  });

  const resources = Template.fromStack(stack).toJSON().Resources;
  const cachePolicyEntry = Object.entries(resources).find(
    ([, resource]) => resource.Type === 'AWS::CloudFront::CachePolicy',
  );
  assert.ok(cachePolicyEntry, 'the JWKS behavior must own an explicit cache policy');
  const [cachePolicyId, cachePolicy] = cachePolicyEntry;
  assert.equal(cachePolicy.Properties.CachePolicyConfig.MinTTL, 300);
  assert.equal(cachePolicy.Properties.CachePolicyConfig.DefaultTTL, 300);
  assert.equal(cachePolicy.Properties.CachePolicyConfig.MaxTTL, 300);
  assert.deepEqual(
    cachePolicy.Properties.CachePolicyConfig
      .ParametersInCacheKeyAndForwardedToOrigin.HeadersConfig,
    {
      HeaderBehavior: 'whitelist',
      Headers: ['x-forwarded-host'],
    },
    'SaaS tenant host must partition the cached JWKS and reach the issuer derivation path',
  );
  assert.deepEqual(
    cachePolicy.Properties.CachePolicyConfig
      .ParametersInCacheKeyAndForwardedToOrigin.CookiesConfig,
    { CookieBehavior: 'none' },
  );
  assert.deepEqual(
    cachePolicy.Properties.CachePolicyConfig
      .ParametersInCacheKeyAndForwardedToOrigin.QueryStringsConfig,
    { QueryStringBehavior: 'none' },
  );

  const distribution = Object.values(resources).find(
    (resource) => resource.Type === 'AWS::CloudFront::Distribution',
  );
  assert.ok(distribution);
  const config = distribution.Properties.DistributionConfig;
  const apiOrigin = config.Origins.find(
    (origin) => origin.DomainName === 'api.example.com',
  );
  assert.ok(apiOrigin, 'the synthesized distribution must contain the API origin');
  const jwksBehavior = config.CacheBehaviors.find(
    (candidate) =>
      candidate.PathPattern.replace(/^\/+/, '') === 'jwks.json',
  );
  assert.ok(jwksBehavior, '/jwks.json must use an explicit cache behavior');
  assert.deepEqual(jwksBehavior.CachePolicyId, { Ref: cachePolicyId });
  assert.equal(
    jwksBehavior.TargetOriginId,
    apiOrigin.Id,
    '/jwks.json must still use the API origin',
  );
  assert.deepEqual(jwksBehavior.AllowedMethods, ['GET', 'HEAD', 'OPTIONS']);
  assert.deepEqual(jwksBehavior.CachedMethods, ['GET', 'HEAD']);
  assert.equal(
    jwksBehavior.OriginRequestPolicyId,
    '59781a5b-3903-41f3-afcb-af62929ccde1',
    '/jwks.json must forward only the standard custom-origin CORS request headers',
  );
  assert.equal(jwksBehavior.FunctionAssociations?.length, 1);
  assert.equal(
    jwksBehavior.FunctionAssociations[0].EventType,
    'viewer-request',
  );
  assert.deepEqual(
    jwksBehavior.FunctionAssociations,
    config.DefaultCacheBehavior.FunctionAssociations,
    '/jwks.json must preserve viewer-host forwarding',
  );
  assert.equal(jwksBehavior.LambdaFunctionAssociations?.length, 1);
  assert.equal(
    jwksBehavior.LambdaFunctionAssociations[0].EventType,
    'origin-request',
  );
  assert.deepEqual(
    jwksBehavior.LambdaFunctionAssociations,
    config.DefaultCacheBehavior.LambdaFunctionAssociations,
    '/jwks.json must preserve managed SaaS origin authentication',
  );
});

test('origin-request Lambda@Edge passes AwsSolutions checks with a least-privilege role', () => {
  const app = new App();
  const stack = new Stack(app, 'FrontendOriginAuthNagTest', {
    env: { account: '123456789012', region: 'us-east-1' },
  });
  const primarySecret = new secretsmanager.Secret(stack, 'PrimarySecret');
  const secondarySecret = new secretsmanager.Secret(stack, 'SecondarySecret');
  new FrontendConstruct(stack, 'Frontend', {
    apiDomain: 'api.example.com',
    apiOriginAuth: {
      primarySecret,
      secondarySecret,
      revision: 'rotation-7',
    },
    assetPath: path.resolve(__dirname),
  });
  Aspects.of(stack).add(new AwsSolutionsChecks({ verbose: true }));

  assert.doesNotThrow(() => app.synth());
  const template = Template.fromStack(stack).toJSON();
  const edgeFunction = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::Lambda::Function' &&
      resource.Properties.Description ===
        'Inject managed SaaS origin credentials without storing them in CloudFront',
  );
  assert.ok(edgeFunction);
  assert.equal(edgeFunction.Properties.Runtime, 'nodejs24.x');

  const edgeRole = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::IAM::Role' &&
      resource.Properties.Description ===
        'Least-privilege execution role for SaaS origin authentication at Lambda@Edge',
  );
  assert.ok(edgeRole);
  assert.equal(edgeRole.Properties.ManagedPolicyArns, undefined);
  const trustPolicy = JSON.stringify(edgeRole.Properties.AssumeRolePolicyDocument);
  assert.match(trustPolicy, /edgelambda\.amazonaws\.com/);
  assert.match(trustPolicy, /lambda\.amazonaws\.com/);
});

test('registration WAF scopes IP, Host, ASN, and exact-commit probe rules to POST /register', () => {
  const app = new App();
  const stack = new Stack(app, 'FrontendRegistrationWafTest', {
    env: { account: '123456789012', region: 'us-east-1' },
  });
  const deploymentCommit = '0123456789abcdef0123456789abcdef01234567';
  new FrontendConstruct(stack, 'Frontend', {
    apiDomain: 'api.example.com',
    registrationWaf: { deploymentCommit },
    assetPath: path.resolve(__dirname),
  });
  Aspects.of(stack).add(new AwsSolutionsChecks({ verbose: true }));

  assert.doesNotThrow(() => app.synth());
  const template = Template.fromStack(stack).toJSON();
  const [webAclId, webAcl] = Object.entries(template.Resources).find(
    ([, resource]) => resource.Type === 'AWS::WAFv2::WebACL',
  );
  assert.equal(webAcl.Properties.Scope, 'CLOUDFRONT');
  assert.deepEqual(webAcl.Properties.DefaultAction, { Allow: {} });
  assert.equal(webAcl.Properties.Rules.length, 4);

  const byName = Object.fromEntries(
    webAcl.Properties.Rules.map((rule) => [rule.Name, rule]),
  );
  assert.equal(
    byName.RegistrationProbe.Statement.AndStatement.Statements[2]
      .ByteMatchStatement.SearchString,
    `c10-8-${deploymentCommit}`,
  );
  assert.equal(
    byName.RegistrationIpRateLimit.Statement.RateBasedStatement.AggregateKeyType,
    'IP',
  );
  assert.equal(
    byName.RegistrationHostRateLimit.Statement.RateBasedStatement.CustomKeys[0]
      .Header.Name,
    'host',
  );
  assert.deepEqual(
    byName.RegistrationAsnRateLimit.Statement.RateBasedStatement.CustomKeys,
    [{ ASN: {} }],
  );
  for (const rule of Object.values(byName)) {
    assert.equal(rule.Action.Block !== undefined, true);
    assert.equal(rule.VisibilityConfig.CloudWatchMetricsEnabled, true);
    assert.equal(rule.VisibilityConfig.SampledRequestsEnabled, false);
    const statements =
      rule.Statement.RateBasedStatement?.ScopeDownStatement?.AndStatement
        ?.Statements ?? rule.Statement.AndStatement.Statements;
    assert.ok(
      statements.some(
        (statement) =>
          statement.ByteMatchStatement?.FieldToMatch?.Method &&
          statement.ByteMatchStatement.SearchString === 'POST',
      ),
    );
    assert.ok(
      statements.some(
        (statement) =>
          statement.ByteMatchStatement?.FieldToMatch?.UriPath &&
          statement.ByteMatchStatement.SearchString === '/register',
      ),
    );
  }

  const distribution = Object.values(template.Resources).find(
    (resource) => resource.Type === 'AWS::CloudFront::Distribution',
  );
  assert.deepEqual(distribution.Properties.DistributionConfig.WebACLId, {
    'Fn::GetAtt': [webAclId, 'Arn'],
  });
  const logging = Object.values(template.Resources).find(
    (resource) => resource.Type === 'AWS::WAFv2::LoggingConfiguration',
  );
  assert.ok(logging);
  assert.equal(logging.Properties.LoggingFilter.DefaultBehavior, 'DROP');
  assert.deepEqual(logging.Properties.RedactedFields, [
    { SingleHeader: { Name: 'authorization' } },
    { SingleHeader: { Name: 'cookie' } },
    { SingleHeader: { Name: 'proxy-authorization' } },
    { SingleHeader: { Name: 'x-api-key' } },
    { QueryString: {} },
  ]);
  const logGroup = Object.values(template.Resources).find(
    (resource) =>
      resource.Type === 'AWS::Logs::LogGroup' &&
      resource.Properties.LogGroupName?.startsWith('aws-waf-logs-'),
  );
  assert.ok(logGroup);
});
