const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { App, Stack } = require('aws-cdk-lib');
const { Template } = require('aws-cdk-lib/assertions');
const secretsmanager = require('aws-cdk-lib/aws-secretsmanager');

const {
  FORWARD_HOST_FUNCTION_CODE,
  FrontendConstruct,
} = require('../dist/lib/frontend-construct');

function invoke(headers) {
  const event = { request: { headers: structuredClone(headers) } };
  return vm.runInNewContext(
    `${FORWARD_HOST_FUNCTION_CODE}; handler(event.request ? event : null)`,
    { event },
  );
}

test('default CloudFront host is forwarded and replaces a spoofed header', () => {
  const request = invoke({
    host: { value: 'example.cloudfront.net' },
    'x-forwarded-host': { value: 'attacker.example' },
  });

  assert.equal(request.headers['x-forwarded-host'].value, 'example.cloudfront.net');
});

test('c8_1b_forward_host_overwrites_spoofed_viewer_header', () => {
  const request = invoke({
    host: { value: 'auth.example.com' },
    'x-forwarded-host': { value: 'attacker.example' },
  });

  assert.equal(request.headers['x-forwarded-host'].value, 'auth.example.com');

  const app = new App();
  const stack = new Stack(app, 'C81bForwardHostTest', {
    env: { account: '123456789012', region: 'us-east-1' },
  });
  const primarySecret = new secretsmanager.Secret(stack, 'PrimarySecret');
  const secondarySecret = new secretsmanager.Secret(stack, 'SecondarySecret');
  new FrontendConstruct(stack, 'Frontend', {
    apiDomain: 'api.example.com',
    apiOriginAuth: {
      primarySecret,
      secondarySecret,
      revision: 'c8-1b',
    },
    assetPath: path.resolve(__dirname),
  });

  const resources = Template.fromStack(stack).toJSON().Resources;
  const functionEntry = Object.entries(resources).find(
    ([, resource]) =>
      resource.Type === 'AWS::CloudFront::Function' &&
      resource.Properties.FunctionCode === FORWARD_HOST_FUNCTION_CODE,
  );
  assert.ok(functionEntry, 'the exact ForwardHost function must be synthesized');
  const [functionId] = functionEntry;
  const distribution = Object.values(resources).find(
    (resource) => resource.Type === 'AWS::CloudFront::Distribution',
  );
  assert.ok(distribution, 'the CloudFront distribution must be synthesized');
  const defaultBehavior =
    distribution.Properties.DistributionConfig.DefaultCacheBehavior;
  assert.deepEqual(defaultBehavior.FunctionAssociations, [
    {
      EventType: 'viewer-request',
      FunctionARN: {
        'Fn::GetAtt': [functionId, 'FunctionARN'],
      },
    },
  ]);
  assert.equal(
    defaultBehavior.LambdaFunctionAssociations?.[0]?.EventType,
    'origin-request',
    'the API behavior must also enforce managed edge-to-origin authentication',
  );
});
